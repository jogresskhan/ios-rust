//! aes — Apple Hardware AES engine.
//!
//! Faithful port of ChefKiss Inferno `hw/misc/apple-silicon/aes.c` +
//! `include/hw/misc/apple-silicon/aes_reg.h` (AGPL-3.0): the command-FIFO
//! driven engine with 2 key slots, 4 IV slots, ECB/CBC/CTR block modes and
//! the AES-v3 security register block. The AES core itself is written
//! inline below (FIPS-197 verified; no external crates).
//!
//! The pre-port XTS surface ([`AesXts`], [`CensusXts`], the legacy
//! `AES_*` offsets) is kept for backward compatibility — upstream has no
//! XTS mode; that interface is research-scope (Dopamine/APFS volume-key
//! unwrap) and stays injectable via [`AesEngine::xts`].

use std::collections::VecDeque;

use vm_core::Device;

// ---------------------------------------------------------------------------
// Upstream register map (aes_reg.h) — the real AP-AES block on T8030+
// ---------------------------------------------------------------------------
pub const REG_AES_VERSION: u64 = 0x0000;
pub const REG_AES_CONFIG: u64 = 0x0004;
pub const REG_AES_CONTROL: u64 = 0x0008;
pub const AES_BLK_CONTROL_START: u32 = 1 << 0;
pub const AES_BLK_CONTROL_STOP: u32 = 1 << 1;
pub const AES_BLK_CONTROL_RESET: u32 = 1 << 2;
pub const AES_BLK_CONTROL_RESET_AES: u32 = 1 << 3;
pub const REG_AES_STATUS: u64 = 0x000C;
pub const REG_AES_KEY_ID: u64 = 0x0010;
pub const REG_AES_AXI_STATUS: u64 = 0x0014;
pub const REG_AES_INT_STATUS: u64 = 0x0018;
pub const REG_AES_INT_ENABLE: u64 = 0x001C;
pub const REG_AES_WATERMARKS: u64 = 0x0020;
pub const REG_AES_COMMAND_FIFO_STATUS: u64 = 0x0024;
pub const REG_AES_COMMAND_FIFO_COUNT: u64 = 0x002C;
pub const REG_AES_FLAG_COMMAND: u64 = 0x0030;
pub const REG_AES_SKG_KEY: u64 = 0x0034;
pub const REG_AES_CLEAR_FIFO: u64 = 0x0038;
pub const REG_AES_CLEAR_FIFO_RESET: u32 = 1 << 0;
pub const REG_AES_COMMAND_FIFO_S8000: u64 = 0x0100;
pub const REG_AES_COMMAND_FIFO: u64 = 0x0200;
pub const REG_AES_HISTORY_FIFO: u64 = 0x0400;
pub const COMMAND_FIFO_SIZE: u32 = 128;
pub const AES_BLK_REG_SIZE: u64 = 0x204;
const REG_WORDS: usize = (AES_BLK_REG_SIZE / 4) as usize + 1;

// INT_STATUS / INT_ENABLE bit fields (identical layout upstream)
pub const AES_INT_COMMAND_FIFO_LOW: u32 = 1 << 0;
pub const AES_INT_COMMAND_FIFO_OVERFLOW: u32 = 1 << 1;
pub const AES_INT_INVALID_COMMAND: u32 = 1 << 2;
pub const AES_INT_AXI_READ_RESPONSE_NOT_OKAY: u32 = 1 << 3;
pub const AES_INT_AXI_WRITE_RESPONSE_NOT_OKAY: u32 = 1 << 4;
pub const AES_INT_FLAG_COMMAND: u32 = 1 << 5;
pub const AES_INT_INVALID_DATA_LENGTH: u32 = 1 << 6;
pub const AES_INT_KEY_0_DISABLED: u32 = 1 << 7;
pub const AES_INT_KEY_1_DISABLED: u32 = 1 << 14;

// REG_AES_STATUS v5 layout (what apple_aes_reset seeds)
pub const AES_STATUS_V5_RESET: u32 = 0xFF80; // 6x text DPA-seeded, key-unwrap
                                              // DPA-seeded, GID + FairPlay
                                              // self-tests passed

// Command opcodes
pub const OPCODE_KEY: u32 = 0x01;
pub const OPCODE_IV: u32 = 0x02;
pub const OPCODE_DSB: u32 = 0x03;
pub const OPCODE_SKG: u32 = 0x04;
pub const OPCODE_DATA: u32 = 0x05;
pub const OPCODE_STORE_IV: u32 = 0x06;
pub const OPCODE_WRITE_REG: u32 = 0x07;
pub const OPCODE_FLAG: u32 = 0x08;

// block_mode_t
pub const BLOCK_MODE_ECB: u32 = 0;
pub const BLOCK_MODE_CBC: u32 = 1;
pub const BLOCK_MODE_CTR: u32 = 2;
// key_len_t
pub const KEY_LEN_128: u32 = 0;
pub const KEY_LEN_192: u32 = 1;
pub const KEY_LEN_256: u32 = 2;
// key_select_t
pub const KEY_SELECT_SOFTWARE: u32 = 0;
pub const KEY_SELECT_UID1: u32 = 1;
pub const KEY_SELECT_GID_AP_1: u32 = 2;
pub const KEY_SELECT_GID_AP_2: u32 = 3;
pub const KEY_SELECT_HDCP_0: u32 = 4;
pub const KEY_SELECT_HDCP_3: u32 = 7;
// key_func_t
pub const KEY_FUNC_NONE: u32 = 0;
pub const KEY_FUNC_LEGACY: u32 = 1;
pub const KEY_FUNC_FAIRPLAY_LEGACY: u32 = 2;
pub const KEY_FUNC_FAIRPLAY_H8F: u32 = 3;

// COMMAND_* field decoders (aes_reg.h macros)
pub fn command_opcode(x: u32) -> u32 {
    (x >> 28) & 0xF
}
pub fn key_command_key_context(x: u32) -> u32 {
    (x >> 27) & 0x1
}
pub fn key_command_key_select(x: u32) -> u32 {
    (x >> 24) & 0x7
}
pub fn key_command_key_length(x: u32) -> u32 {
    (x >> 22) & 0x3
}
pub const COMMAND_KEY_COMMAND_WRAPPED: u32 = 1 << 21;
pub const COMMAND_KEY_COMMAND_ENCRYPT: u32 = 1 << 20;
pub fn key_command_key_func(x: u32) -> u32 {
    (x >> 18) & 0x3
}
pub fn key_command_block_mode(x: u32) -> u32 {
    (x >> 16) & 0x3
}
pub fn key_command_command_id(x: u32) -> u32 {
    x & 0xFF
}
pub fn iv_command_iv_context(x: u32) -> u32 {
    (x >> 26) & 0x3
}
pub fn data_command_key_context(x: u32) -> u32 {
    (x >> 27) & 0x1
}
pub fn data_command_iv_context(x: u32) -> u32 {
    (x >> 25) & 0x3
}
pub fn data_command_length(x: u32) -> u32 {
    x & 0xFF_FFFF
}
pub fn data_upper_addr_source(x: u32) -> u32 {
    (x >> 16) & 0xFF
}
pub fn data_upper_addr_dest(x: u32) -> u32 {
    x & 0xFF
}
pub fn store_iv_command_context(x: u32) -> u32 {
    (x >> 26) & 0x3
}
pub fn store_iv_upper_addr_dest(x: u32) -> u32 {
    x & 0xFF
}
pub fn flag_id_code(x: u32) -> u32 {
    x & 0xFF
}
pub const COMMAND_FLAG_STOP_COMMANDS: u32 = 1 << 26;
pub const COMMAND_FLAG_SEND_INTERRUPT: u32 = 1 << 27;

pub fn key_size(len_code: u32) -> u32 {
    match len_code {
        KEY_LEN_128 => 128,
        KEY_LEN_192 => 192,
        KEY_LEN_256 => 256,
        _ => 0,
    }
}

// AES-v3 security register block (second MMIO window)
pub const REG_AES_V3_SECURITY_AES_DISABLE: u64 = 0x00;
pub const AES_V3_SECURITY_AES_DISABLE_UID: u32 = 1 << 0;
pub const AES_V3_SECURITY_AES_DISABLE_GID1: u32 = 2 << 1;
pub const REG_AES_V3_SECURITY_MCC_BOOTROM_DIS: u64 = 0x10;
pub const AES_V3_SECURITY_MCC_BOOTROM_DIS: u32 = 1 << 0;
pub const REG_AES_V3_SECURITY_GPIO_STRAPS: u64 = 0x20;
pub const AES_V3_SECURITY_GPIO_STRAPS_VALID: u32 = 1 << 31;
pub const REG_AES_V3_SECURITY_SET_ONLY: u64 = 0x30;
pub const REG_AES_V3_SECURITY_SEP: u64 = 0x34;
pub const AES_V3_SECURITY_SEP_FIRST_BOOT: u32 = 1 << 24;
pub const AES_V3_SECURITY_SEP_FIRST_AWAKE_BOOT: u32 = 1 << 25;

// ---------------------------------------------------------------------------
// Legacy (pre-port) register surface — kept for API compatibility. These
// offsets are NOT part of the upstream register file; the live Device impl
// only honors them in `legacy_mmio` mode (see AesEngine::new_legacy).
// ---------------------------------------------------------------------------
pub const AES_CTRL: u64 = 0x0000;
pub const AES_STATUS: u64 = 0x0004;
pub const AES_KEY_LO: u64 = 0x0008; // 8 words = 256-bit key
pub const AES_TWEAK_LO: u64 = 0x0028; // 2 words = 128-bit tweak
pub const AES_IN_ADDR: u64 = 0x0100;
pub const AES_OUT_ADDR: u64 = 0x0108;
pub const AES_SIZE: u64 = 0x0110;

// ---------------------------------------------------------------------------
// Real AES core (FIPS-197), std-only.
// ---------------------------------------------------------------------------
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

fn xtime(a: u8) -> u8 {
    // multiply by x in GF(2^8) with AES polynomial x^8+x^4+x^3+x+1
    (a << 1) ^ if a & 0x80 != 0 { 0x1B } else { 0x00 }
}

fn mul(a: u8, b: u8) -> u8 {
    let mut acc = 0u8;
    let mut a = a;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    acc
}

/// Software AES-128/192/256 block cipher (FIPS-197). `pub` so the machine
/// and tests can drive the raw primitive directly.
pub struct SoftwareAes {
    round_keys: [[u8; 16]; 15],
    rounds: usize,
}

impl SoftwareAes {
    /// `key` must be 16, 24 or 32 bytes.
    pub fn new(key: &[u8]) -> SoftwareAes {
        let nk = match key.len() {
            16 => 4usize,
            24 => 6,
            32 => 8,
            _ => panic!("SoftwareAes: invalid key length"),
        };
        let nr = nk + 6;
        let mut w = [[0u8; 4]; 60];
        for (i, word) in w.iter_mut().enumerate().take(nk) {
            word.copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in nk..4 * (nr + 1) {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = [
                    SBOX[temp[1] as usize] ^ rcon,
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }
            for j in 0..4 {
                w[i][j] = w[i - nk][j] ^ temp[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 15];
        for r in 0..=nr {
            for c in 0..4 {
                round_keys[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        SoftwareAes { round_keys, rounds: nr }
    }

    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }

    fn inv_sub_bytes(state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        // state is column-major: state[r + 4c]
        let s = *state;
        for r in 1..4 {
            for c in 0..4 {
                state[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
            }
        }
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let s = *state;
        for r in 1..4 {
            for c in 0..4 {
                state[r + 4 * c] = s[r + 4 * ((c + 4 - r) % 4)];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let col = [
                state[4 * c],
                state[4 * c + 1],
                state[4 * c + 2],
                state[4 * c + 3],
            ];
            state[4 * c] = mul(col[0], 2) ^ mul(col[1], 3) ^ col[2] ^ col[3];
            state[4 * c + 1] = col[0] ^ mul(col[1], 2) ^ mul(col[2], 3) ^ col[3];
            state[4 * c + 2] = col[0] ^ col[1] ^ mul(col[2], 2) ^ mul(col[3], 3);
            state[4 * c + 3] = mul(col[0], 3) ^ col[1] ^ col[2] ^ mul(col[3], 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let col = [
                state[4 * c],
                state[4 * c + 1],
                state[4 * c + 2],
                state[4 * c + 3],
            ];
            state[4 * c] = mul(col[0], 14) ^ mul(col[1], 11) ^ mul(col[2], 13) ^ mul(col[3], 9);
            state[4 * c + 1] = mul(col[0], 9) ^ mul(col[1], 14) ^ mul(col[2], 11) ^ mul(col[3], 13);
            state[4 * c + 2] = mul(col[0], 13) ^ mul(col[1], 9) ^ mul(col[2], 14) ^ mul(col[3], 11);
            state[4 * c + 3] = mul(col[0], 11) ^ mul(col[1], 13) ^ mul(col[2], 9) ^ mul(col[3], 14);
        }
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;
        Self::add_round_key(&mut state, &self.round_keys[0]);
        for r in 1..self.rounds {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[r]);
        }
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[self.rounds]);
        *block = state;
    }

    /// Decrypt one 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;
        Self::add_round_key(&mut state, &self.round_keys[self.rounds]);
        for r in (1..self.rounds).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[r]);
            Self::inv_mix_columns(&mut state);
        }
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[0]);
        *block = state;
    }
}

/// ECB/CBC/CTR chaining over [`SoftwareAes`] — exactly the block modes the
/// upstream engine supports (BLOCK_MODE_ECB/CBC/CTR).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockCipherMode {
    Ecb,
    Cbc,
    Ctr,
}

pub struct AesCipher {
    pub core: SoftwareAes,
    pub mode: BlockCipherMode,
    /// chaining IV; `qcrypto_cipher_setiv` before every DATA command
    pub iv: [u8; 16],
}

impl AesCipher {
    pub fn new(key: &[u8], mode: BlockCipherMode) -> AesCipher {
        AesCipher { core: SoftwareAes::new(key), mode, iv: [0; 16] }
    }

    /// In-place encrypt of `data` (len % 16 == 0 as upstream enforces).
    /// Returns the post-op IV (CBC/CTR chaining result) like
    /// `qcrypto_cipher_getiv`.
    pub fn encrypt(&mut self, data: &mut [u8]) -> [u8; 16] {
        match self.mode {
            BlockCipherMode::Ecb => {
                for chunk in data.chunks_exact_mut(16) {
                    let mut b: [u8; 16] = chunk.try_into().unwrap();
                    self.core.encrypt_block(&mut b);
                    chunk.copy_from_slice(&b);
                }
                self.iv
            }
            BlockCipherMode::Cbc => {
                let mut prev = self.iv;
                for chunk in data.chunks_exact_mut(16) {
                    let mut b: [u8; 16] = chunk.try_into().unwrap();
                    for i in 0..16 {
                        b[i] ^= prev[i];
                    }
                    self.core.encrypt_block(&mut b);
                    chunk.copy_from_slice(&b);
                    prev = b;
                }
                self.iv = prev;
                self.iv
            }
            BlockCipherMode::Ctr => {
                let mut ctr = self.iv;
                for chunk in data.chunks_exact_mut(16) {
                    let mut ks = ctr;
                    self.core.encrypt_block(&mut ks);
                    for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                        *d ^= k;
                    }
                    for i in (0..16).rev() {
                        ctr[i] = ctr[i].wrapping_add(1);
                        if ctr[i] != 0 {
                            break;
                        }
                    }
                }
                self.iv = ctr;
                self.iv
            }
        }
    }

    /// In-place decrypt; same chaining semantics as [`AesCipher::encrypt`].
    pub fn decrypt(&mut self, data: &mut [u8]) -> [u8; 16] {
        match self.mode {
            BlockCipherMode::Ecb => {
                for chunk in data.chunks_exact_mut(16) {
                    let mut b: [u8; 16] = chunk.try_into().unwrap();
                    self.core.decrypt_block(&mut b);
                    chunk.copy_from_slice(&b);
                }
                self.iv
            }
            BlockCipherMode::Cbc => {
                let mut prev = self.iv;
                for chunk in data.chunks_exact_mut(16) {
                    let mut b: [u8; 16] = chunk.try_into().unwrap();
                    let next = b;
                    self.core.decrypt_block(&mut b);
                    for i in 0..16 {
                        b[i] ^= prev[i];
                    }
                    chunk.copy_from_slice(&b);
                    prev = next;
                }
                self.iv = prev;
                self.iv
            }
            BlockCipherMode::Ctr => self.encrypt(data), // CTR symmetric
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy injectable XTS surface (unchanged public API)
// ---------------------------------------------------------------------------
pub trait AesXts: Send {
    /// Decrypt `data.len()` bytes in place; returns success.
    fn xts_decrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool;
    fn xts_encrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool;
}

/// Census-only backend: records the op but leaves data (honest: the
/// per-device AES key wall is documented in PARITY.md).
#[derive(Default)]
pub struct CensusXts {
    pub decrypts: u64,
    pub encrypts: u64,
}

impl AesXts for CensusXts {
    fn xts_decrypt(&mut self, _key: &[u8; 32], _tweak: &[u8; 16], _data: &mut [u8]) -> bool {
        self.decrypts += 1;
        false // key wall: cannot transform without real keys
    }
    fn xts_encrypt(&mut self, _key: &[u8; 32], _tweak: &[u8; 16], _data: &mut [u8]) -> bool {
        self.encrypts += 1;
        false
    }
}

/// Real software XTS (IEEE 1619) over the inline AES core: key[0..16] is the
/// data key, key[16..32] the tweak key. Research-scope (NOT an upstream
/// mode) but lets the ANS/APFS stack run end-to-end without keyswalls.
pub struct SoftwareXts {
    pub ops: u64,
}

impl Default for SoftwareXts {
    fn default() -> Self {
        SoftwareXts { ops: 0 }
    }
}

fn gf_mul_tweak(tweak: &mut [u8; 16]) {
    // multiply the tweak by x in GF(2^128)
    let mut carry = 0u8;
    for i in 0..16 {
        let b = tweak[15 - i];
        let new_carry = b >> 7;
        tweak[15 - i] = (b << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        tweak[15] ^= 0x87;
    }
}

impl AesXts for SoftwareXts {
    fn xts_encrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool {
        let data_core = SoftwareAes::new(&key[..16]);
        let tweak_core = SoftwareAes::new(&key[16..]);
        let mut t = *tweak;
        tweak_core.encrypt_block(&mut t);
        for chunk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = chunk.try_into().unwrap();
            for (x, y) in b.iter_mut().zip(t.iter()) {
                *x ^= y;
            }
            data_core.encrypt_block(&mut b);
            for (x, y) in b.iter_mut().zip(t.iter()) {
                *x ^= y;
            }
            chunk.copy_from_slice(&b);
            gf_mul_tweak(&mut t);
        }
        self.ops += 1;
        true
    }

    fn xts_decrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool {
        let data_core = SoftwareAes::new(&key[..16]);
        let tweak_core = SoftwareAes::new(&key[16..]);
        let mut t = *tweak;
        tweak_core.encrypt_block(&mut t);
        for chunk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = chunk.try_into().unwrap();
            for (x, y) in b.iter_mut().zip(t.iter()) {
                *x ^= y;
            }
            data_core.decrypt_block(&mut b);
            for (x, y) in b.iter_mut().zip(t.iter()) {
                *x ^= y;
            }
            chunk.copy_from_slice(&b);
            gf_mul_tweak(&mut t);
        }
        self.ops += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Engine state
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Default)]
struct AesCommand {
    command: u32,
    data: [u32; 9], // largest command: DSB = 1 + 8 words
    data_len: u32,
}

/// Upstream `AESKey` (aes.c): one of the two key contexts.
pub struct AesKeySlot {
    pub select: u32,
    /// key length in bytes (0 = unset)
    pub len: usize,
    pub key: [u8; 32],
    pub wrapped: bool,
    pub encrypt: bool,
    pub func: u32,
    /// block_mode_t code
    pub mode: u32,
    pub id: u8,
    pub disabled: bool,
    /// built cipher (None until a software key is programmed)
    pub cipher: Option<AesCipher>,
}

impl Default for AesKeySlot {
    fn default() -> Self {
        AesKeySlot {
            select: 0,
            len: 0,
            key: [0; 32],
            wrapped: false,
            encrypt: false,
            func: 0,
            mode: 0,
            id: 0,
            disabled: false,
            cipher: None,
        }
    }
}

pub struct AesEngine {
    // ---- legacy public fields (compat; see module docs) ----
    pub key: [u8; 32],
    pub tweak: [u8; 16],
    pub in_addr: u64,
    pub out_addr: u64,
    pub size: u64,
    pub ops: u64,
    pub xts: Box<dyn AesXts>,
    pub unknown_reads: u64,

    // ---- upstream state ----
    /// false (default): the real aes.c register file; true: the pre-port
    /// synthetic key/tweak/addr window (AES_CTRL..AES_SIZE).
    pub legacy_mmio: bool,
    /// raw aes_reg_t window (REG words, LE dwords)
    pub reg: [u32; REG_WORDS],
    pub keys: [AesKeySlot; 2],
    pub iv: [[u8; 16]; 4],
    pub queue: VecDeque<AesCommand>,
    /// in-flight command assembly (data_len > data_read means mid-command)
    pub command: u32,
    pub data: [u32; 9],
    pub data_len: u32,
    pub data_read: u32,
    pub stopped: bool,
    pub board_id: u32,
    pub commands_processed: u64,
    pub irq_level: bool,
    /// DMA hooks for OPCODE_DATA / OPCODE_STORE_IV (machine injects).
    pub dma_read: Option<Box<dyn FnMut(u64, &mut [u8]) + Send>>,
    pub dma_write: Option<Box<dyn FnMut(u64, &[u8]) + Send>>,
}

fn reg_index(off: u64) -> Option<usize> {
    if off % 4 == 0 {
        Some((off >> 2) as usize)
    } else {
        None
    }
}

impl AesEngine {
    pub fn new() -> Self {
        let mut e = AesEngine {
            key: [0; 32],
            tweak: [0; 16],
            in_addr: 0,
            out_addr: 0,
            size: 0,
            ops: 0,
            xts: Box::new(CensusXts::default()),
            unknown_reads: 0,
            legacy_mmio: false,
            reg: [0; REG_WORDS],
            keys: [AesKeySlot::default(), AesKeySlot::default()],
            iv: [[0; 16]; 4],
            queue: VecDeque::new(),
            command: 0,
            data: [0; 9],
            data_len: 0,
            data_read: 0,
            stopped: true,
            board_id: 0,
            commands_processed: 0,
            irq_level: false,
            dma_read: None,
            dma_write: None,
        };
        e.upstream_reset();
        e
    }

    /// Old synthetic-window behavior (AES_CTRL/AES_KEY_LO/... offsets).
    pub fn new_legacy() -> Self {
        let mut e = Self::new();
        e.legacy_mmio = true;
        e
    }

    /// `apple_aes_reset`: clear regs, seed v5 status bits, empty FIFO.
    pub fn upstream_reset(&mut self) {
        self.reg = [0; REG_WORDS];
        self.reg[(REG_AES_STATUS >> 2) as usize] = AES_STATUS_V5_RESET;
        self.command = 0;
        self.data = [0; 9];
        self.data_len = 0;
        self.data_read = 0;
        self.stopped = true;
        self.queue.clear();
        self.update_command_fifo_status();
    }

    fn update_irq(&mut self) {
        let enable = self.reg[(REG_AES_INT_ENABLE >> 2) as usize];
        let status = self.reg[(REG_AES_INT_STATUS >> 2) as usize];
        self.irq_level = enable & status != 0;
    }

    fn update_command_fifo_status(&mut self) {
        let level = (self.reg[(REG_AES_COMMAND_FIFO_STATUS >> 2) as usize] >> 8) & 0xFF;
        let watermarks = self.reg[(REG_AES_WATERMARKS >> 2) as usize] & 0x7F;
        let mut f = self.reg[(REG_AES_COMMAND_FIFO_STATUS >> 2) as usize];
        f &= !(0x0F | (0xFF << 8));
        let mut flags = 0u32;
        if level == 0 {
            flags |= 1 << 1; // empty
        }
        if level >= COMMAND_FIFO_SIZE {
            flags |= 1 << 2; // full
        }
        if level > COMMAND_FIFO_SIZE {
            flags |= 1 << 3; // overflow
        }
        let low = level < watermarks;
        f |= flags | (level << 8);
        self.reg[(REG_AES_COMMAND_FIFO_STATUS >> 2) as usize] = f;
        // int_status.command_fifo_low
        let is = (REG_AES_INT_STATUS >> 2) as usize;
        if low {
            self.reg[is] |= AES_INT_COMMAND_FIFO_LOW;
        } else {
            self.reg[is] &= !AES_INT_COMMAND_FIFO_LOW;
        }
        self.update_irq();
    }

    fn int_status_or(&mut self, bits: u32) {
        self.reg[(REG_AES_INT_STATUS >> 2) as usize] |= bits;
        self.update_irq();
    }

    fn key_disabled_bit(&self, ctx: u32) -> u32 {
        if ctx == 0 {
            AES_INT_KEY_0_DISABLED
        } else {
            AES_INT_KEY_1_DISABLED
        }
    }

    fn empty_fifo(&mut self) {
        self.queue.clear();
        let f = (REG_AES_COMMAND_FIFO_STATUS >> 2) as usize;
        self.reg[f] &= !(0xFF << 8); // level = 0
        self.update_command_fifo_status();
    }

    /// `aes_process_command` — executes one dequeued command synchronously
    /// (upstream runs it on a worker thread; behavior is identical).
    fn process_command(&mut self, cmd: &AesCommand) {
        let w = cmd.command;
        match command_opcode(w) {
            OPCODE_KEY => {
                let ctx = key_command_key_context(w) as usize;
                let select = key_command_key_select(w);
                let len_code = key_command_key_length(w);
                let mode = key_command_block_mode(w);
                let k = &mut self.keys[ctx];
                k.select = select;
                k.len = (key_size(len_code) / 8) as usize;
                k.wrapped = w & COMMAND_KEY_COMMAND_WRAPPED != 0;
                k.encrypt = w & COMMAND_KEY_COMMAND_ENCRYPT != 0;
                k.func = key_command_key_func(w);
                k.mode = mode;
                k.id = key_command_command_id(w) as u8;
                for (i, word) in cmd.data[1..].iter().take(k.len / 4).enumerate() {
                    k.key[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                if ctx == 1 {
                    self.reg[(REG_AES_KEY_ID >> 2) as usize] =
                        (self.reg[(REG_AES_KEY_ID >> 2) as usize] & 0xFF)
                            | ((k.id as u32) << 8);
                } else {
                    self.reg[(REG_AES_KEY_ID >> 2) as usize] =
                        (self.reg[(REG_AES_KEY_ID >> 2) as usize] & 0xFF00) | (k.id as u32);
                }
                if select != KEY_SELECT_SOFTWARE {
                    // hardware key select unsupported in the model
                    k.disabled = true;
                    k.cipher = None;
                    self.int_status_or(self.key_disabled_bit(ctx as u32));
                } else {
                    k.disabled = false;
                    k.cipher = match k.len {
                        16 | 24 | 32 => {
                            let mode = match mode {
                                BLOCK_MODE_CBC => BlockCipherMode::Cbc,
                                BLOCK_MODE_CTR => BlockCipherMode::Ctr,
                                _ => BlockCipherMode::Ecb,
                            };
                            Some(AesCipher::new(&k.key[..k.len], mode))
                        }
                        _ => None,
                    };
                }
            }
            OPCODE_IV => {
                let ctx = iv_command_iv_context(w) as usize;
                for i in 0..4 {
                    self.iv[ctx][i * 4..i * 4 + 4]
                        .copy_from_slice(&cmd.data[1 + i].to_le_bytes());
                }
            }
            OPCODE_DSB => {
                // upstream: no-op (documented DSB inputs not modeled)
            }
            OPCODE_DATA => {
                let key_ctx = data_command_key_context(w);
                let iv_ctx = data_command_iv_context(w) as usize;
                let len = data_command_length(w) as usize;
                let upper = cmd.data[1];
                let mut source = cmd.data[2] as u64;
                let mut dest = cmd.data[3] as u64;
                source |= (data_upper_addr_source(upper) as u64) << 32;
                dest |= (data_upper_addr_dest(upper) as u64) << 32;
                if len & 0xF != 0 {
                    self.int_status_or(AES_INT_INVALID_DATA_LENGTH);
                    return;
                }
                let slot = &self.keys[key_ctx as usize];
                if slot.disabled || slot.cipher.is_none() {
                    self.int_status_or(self.key_disabled_bit(key_ctx));
                    return;
                }
                let mut buf = vec![0u8; len];
                if let Some(rd) = self.dma_read.as_mut() {
                    rd(source, &mut buf);
                }
                let iv = self.iv[iv_ctx];
                let cipher = self.keys[key_ctx as usize].cipher.as_mut().unwrap();
                cipher.iv = iv;
                if self.keys[key_ctx as usize].encrypt {
                    cipher.encrypt(&mut buf);
                } else {
                    cipher.decrypt(&mut buf);
                }
                self.iv[iv_ctx] = cipher.iv;
                if let Some(wr) = self.dma_write.as_mut() {
                    wr(dest, &buf);
                }
            }
            OPCODE_STORE_IV => {
                let ctx = store_iv_command_context(w) as usize;
                let mut dest = cmd.data[1] as u64;
                dest |= (store_iv_upper_addr_dest(w) as u64) << 32;
                let iv = self.iv[ctx];
                if let Some(wr) = self.dma_write.as_mut() {
                    wr(dest, &iv);
                }
            }
            OPCODE_FLAG => {
                self.reg[(REG_AES_FLAG_COMMAND >> 2) as usize] = flag_id_code(w);
                if w & COMMAND_FLAG_STOP_COMMANDS != 0 {
                    self.stopped = true;
                }
                if w & COMMAND_FLAG_SEND_INTERRUPT != 0 {
                    self.int_status_or(AES_INT_FLAG_COMMAND);
                }
            }
            _ => {
                self.int_status_or(AES_INT_INVALID_COMMAND);
            }
        }
        self.commands_processed += 1;
    }

    /// Upstream COMMAND_FIFO write behavior: assemble the command words and
    /// dispatch when complete. `REG_AES_COMMAND_FIFO_S8000` and
    /// `REG_AES_COMMAND_FIFO` behave identically (aes.c).
    fn command_fifo_write(&mut self, val: u32) {
        if self.data_len > self.data_read {
            self.data[self.data_read as usize] = val;
            self.data_read += 1;
        } else {
            self.command = val;
            match command_opcode(val) {
                OPCODE_KEY => {
                    if key_command_key_select(val) == KEY_SELECT_SOFTWARE {
                        self.data_len = key_size(key_command_key_length(val)) / 8 / 4 + 1;
                    } else {
                        self.data_len = 1;
                    }
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                OPCODE_IV => {
                    self.data_len = 5; // command_iv_t
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                OPCODE_DSB => {
                    self.data_len = 9; // command_dsb_t
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                OPCODE_DATA => {
                    self.data_len = 4; // command_data_t
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                OPCODE_STORE_IV => {
                    self.data_len = 2; // command_store_iv_t
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                OPCODE_FLAG => {
                    self.data_len = 1;
                    self.data_read = 1;
                    self.data = [0; 9];
                    self.data[0] = val;
                }
                _ => {
                    self.int_status_or(AES_INT_INVALID_COMMAND);
                }
            }
        }

        if self.data_len > 0 && self.data_len <= self.data_read {
            let cmd = AesCommand {
                command: self.command,
                data: self.data,
                data_len: self.data_len,
            };
            self.command = 0;
            self.data = [0; 9];
            self.data_len = 0;
            self.data_read = 0;
            // level accounts *words* upstream (level += data_len on enqueue,
            // -= data_len after processing); net effect zero for a completed
            // command, but the transient window matters to the FIFO status.
            let f = (REG_AES_COMMAND_FIFO_STATUS >> 2) as usize;
            self.reg[f] = (self.reg[f] & !(0xFF << 8))
                | (((self.reg[f] >> 8) + cmd.data_len) & 0xFF) << 8;
            self.queue.push_back(cmd);
            if let Some(cmd) = self.queue.pop_front() {
                self.process_command(&cmd);
                let f = (REG_AES_COMMAND_FIFO_STATUS >> 2) as usize;
                let lvl = ((self.reg[f] >> 8) & 0xFF).wrapping_sub(cmd.data_len & 0xFF);
                self.reg[f] = (self.reg[f] & !(0xFF << 8)) | ((lvl & 0xFF) << 8);
            }
            self.update_command_fifo_status();
        }
    }

    /// Security-block read (second MMIO window, `aes_security_reg_read`).
    pub fn security_read(&self, addr: u64) -> u64 {
        match addr {
            REG_AES_V3_SECURITY_AES_DISABLE => {
                (AES_V3_SECURITY_AES_DISABLE_GID1 | AES_V3_SECURITY_AES_DISABLE_UID) as u64
            }
            REG_AES_V3_SECURITY_GPIO_STRAPS => {
                (self.board_id & 0x1F) as u64 | AES_V3_SECURITY_GPIO_STRAPS_VALID as u64
            }
            REG_AES_V3_SECURITY_SET_ONLY => 0,
            REG_AES_V3_SECURITY_SEP => {
                (AES_V3_SECURITY_SEP_FIRST_BOOT | AES_V3_SECURITY_SEP_FIRST_AWAKE_BOOT) as u64
            }
            REG_AES_V3_SECURITY_MCC_BOOTROM_DIS => AES_V3_SECURITY_MCC_BOOTROM_DIS as u64,
            _ => 0xFF,
        }
    }

    /// Legacy census path: run the injectable XTS backend over DMA.
    pub fn run(
        &mut self,
        mem_read: &mut dyn FnMut(u64, &mut [u8]),
        mem_write: &mut dyn FnMut(u64, &[u8]),
    ) -> bool {
        let mut buf = vec![0u8; self.size as usize];
        mem_read(self.in_addr, &mut buf);
        let ok = self.xts.xts_decrypt(&self.key, &self.tweak, &mut buf);
        mem_write(self.out_addr, &buf);
        self.ops += 1;
        ok
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("VERSION", REG_AES_VERSION),
            ("CONFIG", REG_AES_CONFIG),
            ("CONTROL", REG_AES_CONTROL),
            ("STATUS", REG_AES_STATUS),
            ("KEY_ID", REG_AES_KEY_ID),
            ("INT_STATUS", REG_AES_INT_STATUS),
            ("INT_ENABLE", REG_AES_INT_ENABLE),
            ("WATERMARKS", REG_AES_WATERMARKS),
            ("COMMAND_FIFO_STATUS", REG_AES_COMMAND_FIFO_STATUS),
            ("COMMAND_FIFO_COUNT", REG_AES_COMMAND_FIFO_COUNT),
            ("FLAG_COMMAND", REG_AES_FLAG_COMMAND),
            ("CLEAR_FIFO", REG_AES_CLEAR_FIFO),
            ("COMMAND_FIFO", REG_AES_COMMAND_FIFO),
            // legacy surface
            ("KEY", AES_KEY_LO),
            ("TWEAK", AES_TWEAK_LO),
            ("IN_ADDR", AES_IN_ADDR),
            ("OUT_ADDR", AES_OUT_ADDR),
            ("SIZE", AES_SIZE),
        ]
    }
}

impl Default for AesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for AesEngine {
    fn name(&self) -> &'static str {
        "aes"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if self.legacy_mmio {
            match off {
                AES_STATUS => 1, // idle/done
                AES_IN_ADDR => self.in_addr,
                AES_OUT_ADDR => self.out_addr,
                AES_SIZE => self.size,
                o if (AES_KEY_LO..AES_KEY_LO + 32).contains(&o) => {
                    let i = ((o - AES_KEY_LO) / 4) as usize;
                    u32::from_le_bytes(self.key[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                }
                o if (AES_TWEAK_LO..AES_TWEAK_LO + 16).contains(&o) => {
                    let i = ((o - AES_TWEAK_LO) / 4) as usize;
                    u32::from_le_bytes(self.tweak[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                }
                _ => {
                    self.unknown_reads += 1;
                    0
                }
            }
        } else {
            match reg_index(off) {
                Some(i) if off < AES_BLK_REG_SIZE => self.reg[i] as u64,
                _ => {
                    self.unknown_reads += 1;
                    0
                }
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if self.legacy_mmio {
            match off {
                AES_CTRL => {
                    if val & 1 == 1 {
                        self.ops += 1; // GO — actual DMA transform via run()
                    }
                }
                AES_IN_ADDR => self.in_addr = val,
                AES_OUT_ADDR => self.out_addr = val,
                AES_SIZE => self.size = val,
                o if (AES_KEY_LO..AES_KEY_LO + 32).contains(&o) => {
                    let i = ((o - AES_KEY_LO) / 4) as usize;
                    self.key[i * 4..i * 4 + 4].copy_from_slice(&(val as u32).to_le_bytes());
                }
                o if (AES_TWEAK_LO..AES_TWEAK_LO + 16).contains(&o) => {
                    let i = ((o - AES_TWEAK_LO) / 4) as usize;
                    self.tweak[i * 4..i * 4 + 4]
                        .copy_from_slice(&(val as u32).to_le_bytes());
                }
                _ => {}
            }
            return;
        }

        let Some(idx) = reg_index(off) else {
            self.unknown_reads += 1;
            return;
        };
        if off >= AES_BLK_REG_SIZE {
            self.unknown_reads += 1;
            return;
        }
        let val = val as u32;
        match off {
            REG_AES_VERSION | REG_AES_STATUS | REG_AES_KEY_ID | REG_AES_AXI_STATUS
            | REG_AES_COMMAND_FIFO_STATUS | REG_AES_COMMAND_FIFO_COUNT
            | REG_AES_FLAG_COMMAND | REG_AES_SKG_KEY => { /* read-only */ }
            REG_AES_INT_STATUS => {
                // write-1-to-clear, then re-evaluate IRQ
                self.reg[idx] &= !val;
                self.update_irq();
            }
            REG_AES_INT_ENABLE => {
                self.reg[idx] = val;
                self.update_irq();
            }
            REG_AES_WATERMARKS => {
                self.reg[idx] = val & 0x7F;
                self.update_command_fifo_status();
            }
            REG_AES_CONTROL => match val {
                AES_BLK_CONTROL_START => {
                    self.stopped = false; // worker start (commands still
                                          // processed synchronously)
                }
                AES_BLK_CONTROL_STOP => {
                    self.stopped = true;
                }
                AES_BLK_CONTROL_RESET => {
                    self.empty_fifo();
                }
                AES_BLK_CONTROL_RESET_AES => {
                    self.upstream_reset();
                }
                _ => {} // invalid control write: logged upstream
            },
            REG_AES_COMMAND_FIFO_S8000 | REG_AES_COMMAND_FIFO => {
                self.command_fifo_write(val);
            }
            REG_AES_CONFIG => { /* stored upstream; we keep the window */ 
                self.reg[idx] = val;
            }
            REG_AES_CLEAR_FIFO => {
                if val == REG_AES_CLEAR_FIFO_RESET {
                    self.empty_fifo();
                }
            }
            _ => { /* unknown reg write: logged upstream */ }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips197_aes128_single_block_via_command_fifo() {
        let mut eng = AesEngine::new();
        let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let plaintext = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mem = plaintext.to_vec();
        eng.dma_read = Some(Box::new(move |a, buf| {
            let _ = a;
            buf.copy_from_slice(&mem);
        }));
        let out = std::sync::Arc::new(std::sync::Mutex::new([0u8; 16]));
        let out2 = out.clone();
        eng.dma_write = Some(Box::new(move |a, buf| {
            let _ = a;
            let mut slot = out2.lock().unwrap();
            slot.copy_from_slice(buf);
        }));
        // KEY command: opcode 1, ctx0, software, 128-bit, encrypt, ECB
        let mut kw = 0u32;
        kw |= OPCODE_KEY << 28;
        kw |= KEY_LEN_128 << 22;
        kw |= COMMAND_KEY_COMMAND_ENCRYPT;
        kw |= BLOCK_MODE_ECB << 16;
        eng.write(REG_AES_COMMAND_FIFO, 4, kw as u64);
        for chunk in key.chunks_exact(4) {
            eng.write(REG_AES_COMMAND_FIFO, 4,
                u32::from_le_bytes(chunk.try_into().unwrap()) as u64);
        }
        // DATA command: len 16 from 0x1000 to 0x2000
        let mut dw = 0u32;
        dw |= OPCODE_DATA << 28;
        dw |= 16; // length
        eng.write(REG_AES_COMMAND_FIFO, 4, dw as u64);
        eng.write(REG_AES_COMMAND_FIFO, 4, 0); // upper addrs
        eng.write(REG_AES_COMMAND_FIFO, 4, 0x1000); // source
        eng.write(REG_AES_COMMAND_FIFO, 4, 0x2000); // dest
        assert_eq!(eng.commands_processed, 2);
        assert_eq!(*out.lock().unwrap(), [
            0x69u8, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a
        ]);
    }

    #[test]
    fn aes256_ecb_fips197_and_core_roundtrip() {
        // FIPS-197 C.3: AES-256, key 000102..1f, pt 00112233..eeff
        let key: Vec<u8> = (0u8..32).collect();
        let pt = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let core = SoftwareAes::new(&key);
        let mut b = pt;
        core.encrypt_block(&mut b);
        assert_eq!(b, [
            0x8eu8, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89
        ]);
        core.decrypt_block(&mut b);
        assert_eq!(b, pt);
    }

    #[test]
    fn cbc_ctr_modes_and_iv_chaining() {
        let key = [7u8; 16];
        let iv = [3u8; 16];
        let pt = [0x42u8; 32];
        let mut c = AesCipher::new(&key, BlockCipherMode::Cbc);
        c.iv = iv;
        let mut e = pt;
        c.encrypt(&mut e);
        assert_ne!(e, pt);
        let mut d = AesCipher::new(&key, BlockCipherMode::Cbc);
        d.iv = iv;
        d.decrypt(&mut e);
        assert_eq!(e, pt);
        // CTR
        let mut c2 = AesCipher::new(&key, BlockCipherMode::Ctr);
        c2.iv = iv;
        let mut e2 = pt;
        c2.encrypt(&mut e2);
        let mut d2 = AesCipher::new(&key, BlockCipherMode::Ctr);
        d2.iv = iv;
        d2.decrypt(&mut e2);
        assert_eq!(e2, pt);
    }

    #[test]
    fn register_map_behaviors() {
        let mut eng = AesEngine::new();
        // reset-seeded v5 status
        assert_eq!(eng.read(REG_AES_STATUS, 4), AES_STATUS_V5_RESET as u64);
        // read-only regs ignore writes
        eng.write(REG_AES_VERSION, 4, 0xdead);
        assert_eq!(eng.read(REG_AES_VERSION, 4), 0);
        // INT_STATUS is W1C and IRQ gating follows INT_ENABLE
        eng.write(REG_AES_INT_ENABLE, 4, AES_INT_INVALID_COMMAND as u64);
        eng.write(REG_AES_COMMAND_FIFO, 4, (0xFu32 << 28) as u64); // bad opcode
        assert_eq!(
            eng.read(REG_AES_INT_STATUS, 4) as u32 & AES_INT_INVALID_COMMAND,
            AES_INT_INVALID_COMMAND
        );
        assert!(eng.irq_level);
        eng.write(REG_AES_INT_STATUS, 4, AES_INT_INVALID_COMMAND as u64);
        assert!(!eng.irq_level);
        // control reset bits
        eng.write(REG_AES_COMMAND_FIFO, 4, ((OPCODE_KEY << 28) | (KEY_LEN_256 << 22) | 2) as u64);
        for i in 0..8u32 {
            eng.write(REG_AES_COMMAND_FIFO, 4, (0xA5A5_0000 | i) as u64);
        }
        assert_eq!(eng.commands_processed, 1);
        assert_eq!(eng.keys[0].len, 32);
        eng.write(REG_AES_CONTROL, 4, AES_BLK_CONTROL_RESET_AES as u64);
        assert_eq!(eng.read(REG_AES_STATUS, 4), AES_STATUS_V5_RESET as u64);
        assert_eq!(eng.commands_processed, 1);
        // security block reads
        assert_eq!(
            eng.security_read(REG_AES_V3_SECURITY_AES_DISABLE),
            (AES_V3_SECURITY_AES_DISABLE_GID1 | AES_V3_SECURITY_AES_DISABLE_UID) as u64
        );
        eng.board_id = 0x1A;
        assert_eq!(
            eng.security_read(REG_AES_V3_SECURITY_GPIO_STRAPS),
            (0x1A | AES_V3_SECURITY_GPIO_STRAPS_VALID) as u64
        );
        // hardware key select disables the slot and raises the key-disabled int
        eng.write(REG_AES_COMMAND_FIFO, 4, ((OPCODE_KEY << 28) | (KEY_SELECT_GID_AP_1 << 24)) as u64);
        assert!(eng.keys[0].disabled);
        assert_eq!(
            eng.read(REG_AES_INT_STATUS, 4) as u32 & AES_INT_KEY_0_DISABLED,
            AES_INT_KEY_0_DISABLED
        );
    }

    #[test]
    fn xts_backend_roundtrip_and_census_compat() {
        // Census (legacy default) still counts and fails honestly
        let mut eng = AesEngine::new();
        eng.size = 16;
        let mut noop = |_: u64, _: &mut [u8]| {};
        let mut noop_w = |_: u64, _: &[u8]| {};
        assert!(!eng.run(&mut noop, &mut noop_w));
        // SoftwareXts roundtrip
        eng.xts = Box::new(SoftwareXts::default());
        let key = [0x11u8; 32];
        let tweak = [0x22u8; 16];
        let mut data = vec![0x5Au8; 32];
        let orig = data.clone();
        assert!(eng.xts.xts_encrypt(&key, &tweak, &mut data));
        assert_ne!(data, orig);
        assert!(eng.xts.xts_decrypt(&key, &tweak, &mut data));
        assert_eq!(data, orig);
    }
}
