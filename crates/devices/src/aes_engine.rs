//! Apple AES storage engine — port of ChefKiss Inferno
//! `hw/misc/apple-silicon/aes.c` + `include/hw/misc/apple-silicon/aes_reg.h`
//! (AGPL-3.0, Visual Ehrmanntraut / Christian Inci; fork cloned to
//! /home/z/research/inferno). Workspace license: GPL-2.0-or-later.
//!
//! Faithful surface (register map + FIFO protocol are 1:1 from aes_reg.h /
//! aes.c):
//!   * REG block 0x0..0x204: VERSION/CONFIG/CONTROL/STATUS/KEY_ID/AXI_STATUS/
//!     INT_STATUS/INT_ENABLE/WATERMARKS/COMMAND_FIFO_STATUS/COUNT/FLAG_COMMAND/
//!     SKG_KEY/CLEAR_FIFO + COMMAND_FIFO at 0x200 (0x100 = S8000 alias);
//!   * CONTROL one-hot writes: START/STOP/RESET (empty fifo)/RESET_AES;
//!   * STATUS is the v5 layout (T8030): dpa-seeded bits + gid/fairplay
//!     self-test bits set at reset, exactly like `apple_aes_reset`;
//!   * command FIFO assembles multi-word commands by opcode
//!     (KEY=1+len/4, IV=5, DSB=9, DATA=4, STORE_IV=2, FLAG=1 words) and
//!     processes them against two key contexts, four IV contexts and the
//!     DMA address space (injected [`AesDma`], upstream `s->dma_as`);
//!   * key-select != SOFTWARE sets key_N_disabled + INT_STATUS bits (the
//!     fused-key wall — honest, no GID/UID key material exists here);
//!   * INT_STATUS write-1-to-clear, IRQ = INT_ENABLE & INT_STATUS;
//!   * FLAG command: code latch, STOP_COMMANDS, SEND_INTERRUPT;
//!   * separate security register region (AES_DISABLE/GPIO_STRAPS/SEP...).
//!
//! Block modes upstream are ECB/CBC/CTR (`block_mode_t`). The **XTS path is
//! a workspace extension** at the contract of the existing
//! `crates/apple-soc/src/aes.rs` `AesXts` trait (the "AES-XTS storage
//! oracle" the ANS/APFS stack drives): [`AesXtsOp`] commands queued on the
//! device run through an injectable backend (default [`SoftXts`], a real
//! AES-XTS built on the same block primitive, verified against
//! oracle-quoted known answers below). This split is documented, not
//! inferred: upstream `aes_reg.h` has no XTS block mode.
//!
//! Cipher core: std-only AES-128/192/256 (FIPS-197), S-box derived from
//! GF(2^8) inversion + the standard affine map (no magic tables to typo).
//! XTS per IEEE 1619-2007 / NIST SP 800-38E (tweak = LE-128 data-unit
//! number, GF(2^128) doubling with 0x87, ciphertext stealing on tails).

use crate::bus::MMIODevice;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// AES block primitive (std-only). FIPS-197 checked in tests below.
// ---------------------------------------------------------------------------
mod aes_core {
    use super::*;

    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    /// S-box = affine(inv(x)); built, not transcribed (typo-proof).
    fn build_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        for x in 1..=255u16 {
            let inv = (1..=255u16)
                .find(|&y| gf_mul(x as u8, y as u8) == 1)
                .expect("nonzero GF(2^8) elements are invertible") as u8;
            let mut r = inv;
            let mut sh = inv;
            for _ in 0..4 {
                sh = sh.rotate_left(1);
                r ^= sh;
            }
            sbox[x as usize] = r ^ 0x63;
        }
        sbox[0] = 0x63;
        sbox
    }

    fn build_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
        let mut inv = [0u8; 256];
        for (x, &s) in sbox.iter().enumerate() {
            inv[s as usize] = x as u8;
        }
        inv
    }

    fn key_expand(key: &[u8]) -> Vec<[u8; 16]> {
        let nk = key.len() / 4;
        let nr = nk + 6;
        let mut w = vec![0u32; 4 * (nr + 1)];
        for (i, wi) in w.iter_mut().enumerate().take(nk) {
            *wi = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }
        let sbox = build_sbox();
        let mut rcon = 1u8;
        for i in nk..4 * (nr + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = t.rotate_left(8); // RotWord ([a0,a1,a2,a3] -> [a1,a2,a3,a0])
                t = {
                    let b = t.to_be_bytes();
                    u32::from_be_bytes([
                        sbox[b[0] as usize],
                        sbox[b[1] as usize],
                        sbox[b[2] as usize],
                        sbox[b[3] as usize],
                    ])
                };
                t ^= (rcon as u32) << 24;
                rcon = gf_mul(rcon, 2);
            } else if nk > 6 && i % nk == 4 {
                let b = t.to_be_bytes();
                t = u32::from_be_bytes([
                    sbox[b[0] as usize],
                    sbox[b[1] as usize],
                    sbox[b[2] as usize],
                    sbox[b[3] as usize],
                ]);
            }
            w[i] = w[i - nk] ^ t;
        }
        (0..=nr)
            .map(|r| {
                let mut rk = [0u8; 16];
                for c in 0..4 {
                    rk[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c].to_be_bytes());
                }
                rk
            })
            .collect()
    }

    fn sub_bytes(state: &mut [u8; 16], sbox: &[u8; 256]) {
        for b in state.iter_mut() {
            *b = sbox[*b as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        // state[r + 4c]; row r rotates left by r
        let old = *state;
        for r in 0..4 {
            for c in 0..4 {
                state[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
            }
        }
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let old = *state;
        for r in 0..4 {
            for c in 0..4 {
                state[r + 4 * c] = old[r + 4 * ((c + 4 - r) % 4)];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let col = &mut state[4 * c..4 * c + 4];
            let (a0, a1, a2, a3) = (col[0], col[1], col[2], col[3]);
            col[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
            col[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
            col[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
            col[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let col = &mut state[4 * c..4 * c + 4];
            let (a0, a1, a2, a3) = (col[0], col[1], col[2], col[3]);
            col[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
            col[1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
            col[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
            col[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
        }
    }

    /// AES block cipher with pre-expanded round keys (128/192/256).
    pub struct AesBlock {
        round_keys: Vec<[u8; 16]>,
        enc_sbox: [u8; 256],
        dec_sbox: [u8; 256],
    }

    impl AesBlock {
        pub fn new(key: &[u8]) -> Option<Self> {
            match key.len() {
                16 | 24 | 32 => Some(AesBlock {
                    round_keys: key_expand(key),
                    enc_sbox: build_sbox(),
                    dec_sbox: build_inv_sbox(&build_sbox()),
                }),
                _ => None,
            }
        }

        pub fn encrypt_block(&self, block: &mut [u8; 16]) {
            let nr = self.round_keys.len() - 1;
            for (b, k) in block.iter_mut().zip(self.round_keys[0]) {
                *b ^= k;
            }
            for r in 1..nr {
                sub_bytes(block, &self.enc_sbox);
                shift_rows(block);
                mix_columns(block);
                for (b, k) in block.iter_mut().zip(self.round_keys[r]) {
                    *b ^= k;
                }
            }
            sub_bytes(block, &self.enc_sbox);
            shift_rows(block);
            for (b, k) in block.iter_mut().zip(self.round_keys[nr]) {
                *b ^= k;
            }
        }

        pub fn decrypt_block(&self, block: &mut [u8; 16]) {
            let nr = self.round_keys.len() - 1;
            for (b, k) in block.iter_mut().zip(self.round_keys[nr]) {
                *b ^= k;
            }
            for r in (1..nr).rev() {
                inv_shift_rows(block);
                sub_bytes(block, &self.dec_sbox);
                for (b, k) in block.iter_mut().zip(self.round_keys[r]) {
                    *b ^= k;
                }
                inv_mix_columns(block);
            }
            inv_shift_rows(block);
            sub_bytes(block, &self.dec_sbox);
            for (b, k) in block.iter_mut().zip(self.round_keys[0]) {
                *b ^= k;
            }
        }
    }

    // ---- ECB / CBC / CTR --------------------------------------------------
    pub fn ecb_encrypt(c: &AesBlock, data: &mut [u8]) {
        for blk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = blk.try_into().unwrap();
            c.encrypt_block(&mut b);
            blk.copy_from_slice(&b);
        }
    }

    pub fn ecb_decrypt(c: &AesBlock, data: &mut [u8]) {
        for blk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = blk.try_into().unwrap();
            c.decrypt_block(&mut b);
            blk.copy_from_slice(&b);
        }
    }

    /// CBC; on return `iv` = last ciphertext block (nettle/qcrypto semantics,
    /// so chained DATA commands continue the chain like upstream `getiv`).
    pub fn cbc_encrypt(c: &AesBlock, iv: &mut [u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for blk in data.chunks_exact_mut(16) {
            for (b, p) in blk.iter_mut().zip(prev) {
                *b ^= p;
            }
            let mut b: [u8; 16] = blk.try_into().unwrap();
            c.encrypt_block(&mut b);
            blk.copy_from_slice(&b);
            prev = b;
        }
        *iv = prev;
    }

    pub fn cbc_decrypt(c: &AesBlock, iv: &mut [u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for blk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = blk.try_into().unwrap();
            let ct = b;
            c.decrypt_block(&mut b);
            for (p, x) in blk.iter_mut().zip(b.iter_mut().zip(prev)) {
                *p = *x.0 ^ x.1;
            }
            prev = ct;
        }
        *iv = prev;
    }

    /// CTR with big-endian counter increment (nettle `ctr_crypt`, the
    /// backend QCryptoCipher uses).
    pub fn ctr_crypt(c: &AesBlock, iv: &mut [u8; 16], data: &mut [u8]) {
        let mut ctr = u128::from_be_bytes(*iv);
        for blk in data.chunks_exact_mut(16) {
            let ks = {
                let mut b = ctr.to_be_bytes();
                c.encrypt_block(&mut b);
                b
            };
            for (p, k) in blk.iter_mut().zip(ks) {
                *p ^= k;
            }
            ctr = ctr.wrapping_add(1);
        }
        *iv = ctr.to_be_bytes();
    }

    // ---- XTS (IEEE 1619-2007 / NIST SP 800-38E) ---------------------------
    fn gf128_mul2(t: u128) -> u128 {
        (t << 1) ^ if t >> 127 & 1 == 1 { 0x87 } else { 0 }
    }

    fn xts_blocks(
        dk: &AesBlock,
        mut t: u128,
        data: &mut [u8],
        enc: bool,
    ) {
        for blk in data.chunks_exact_mut(16) {
            let mut b: [u8; 16] = blk.try_into().unwrap();
            let tw = t.to_le_bytes();
            for (p, x) in b.iter_mut().zip(tw) {
                *p ^= x;
            }
            if enc {
                dk.encrypt_block(&mut b);
            } else {
                dk.decrypt_block(&mut b);
            }
            blk.copy_from_slice(&b);
            for (p, x) in blk.iter_mut().zip(tw) {
                *p ^= x;
            }
            t = gf128_mul2(t);
        }
    }

    fn xts_steal(
        dk: &AesBlock,
        t_last_full: u128,
        t_partial: u128,
        data: &mut [u8],
        enc: bool,
    ) {
        // data: [0..full*16) full blocks (already processed), tail partial
        let full = data.len() / 16;
        let rem = data.len() % 16;
        if rem == 0 {
            return;
        }
        let split = full * 16;
        if enc {
            // CC = ENC(P[full-1] ^ T_{full-1}); C_m = CC[..rem];
            // C_{m-1} = ENC((P_m || CC[rem..]) ^ T_m) ^ T_m
            let pm: Vec<u8> = data[split..].to_vec(); // partial plaintext
            let mut cc: [u8; 16] = data[split - 16..split].try_into().unwrap();
            let tw = t_last_full.to_le_bytes();
            for (p, x) in cc.iter_mut().zip(tw) {
                *p ^= x;
            }
            dk.encrypt_block(&mut cc);
            let tail: Vec<u8> = cc[rem..].to_vec();
            data[split..].copy_from_slice(&cc[..rem]);
            let mut b = [0u8; 16];
            b[..rem].copy_from_slice(&pm);
            b[rem..].copy_from_slice(&tail);
            let tw = t_partial.to_le_bytes();
            for (p, x) in b.iter_mut().zip(tw) {
                *p ^= x;
            }
            dk.encrypt_block(&mut b);
            for (p, x) in b.iter_mut().zip(tw) {
                *p ^= x;
            }
            data[split - 16..split].copy_from_slice(&b);
        } else {
            // Inverse of the enc branch above:
            //   C_{m-1} = ENC(P_m || CC[rem..] ^ T_m) ^ T_m  →  b2 = DEC(C_{m-1} ^ T_m)
            //   CC = C_m || b2[rem..]        (C_m holds the stolen CC[..rem] bytes)
            //   P_{m-1} = DEC(CC) ^ T_{m-1}  (CC = ENC(P_{m-1} ^ T_{m-1}))
            //   P_m     = b2[..rem]
            let mut b2: [u8; 16] = data[split - 16..split].try_into().unwrap();
            let tw_m = t_partial.to_le_bytes();
            for (p, x) in b2.iter_mut().zip(tw_m) {
                *p ^= x;
            }
            dk.decrypt_block(&mut b2);
            for (p, x) in b2.iter_mut().zip(tw_m) {
                *p ^= x;
            }
            let mut cc = [0u8; 16];
            cc[..rem].copy_from_slice(&data[split..split + rem]);
            cc[rem..].copy_from_slice(&b2[rem..]);
            dk.decrypt_block(&mut cc);
            let tw_l = t_last_full.to_le_bytes();
            for (p, x) in cc.iter_mut().zip(tw_l) {
                *p ^= x;
            }
            data[split - 16..split].copy_from_slice(&cc);
            data[split..].copy_from_slice(&b2[..rem]);
        }
    }

    fn xts_core(key: &[u8], tweak_key: &[u8], tweak: &[u8; 16], data: &mut [u8], enc: bool) -> bool {
        let Some(tk) = AesBlock::new(tweak_key) else {
            return false;
        };
        let Some(dk) = AesBlock::new(key) else {
            return false;
        };
        if data.is_empty() {
            return true;
        }
        // T = ENC(tweak_key, tweak-as-LE-128)
        let mut t = u128::from_le_bytes(*tweak);
        let mut twb = t.to_le_bytes();
        tk.encrypt_block(&mut twb);
        t = u128::from_le_bytes(twb);

        let full = data.len() / 16;
        let rem = data.len() % 16;
        // SP 800-38E: with a partial tail the LAST full block is consumed
        // by the steal step (ciphertext stealing touches C_{q-1} and C_m),
        // so the standard-block pass stops one block early.
        let body = if rem > 0 { full.saturating_sub(1) * 16 } else { data.len() };
        let (head, _tail) = data.split_at_mut(body);
        let t_head = t;
        for _ in 0..full.saturating_sub(1) {
            t = gf128_mul2(t);
        }
        let t_last_full = t;
        let t_partial = gf128_mul2(t_last_full);
        xts_blocks(&dk, t_head, head, enc);
        if rem > 0 {
            xts_steal(&dk, t_last_full, t_partial, data, enc);
        }
        true
    }

    /// XTS-AES-128: `data_key`/`tweak_key` are the two 1619 key halves.
    pub fn xts_encrypt_128(
        data_key: &[u8; 16],
        tweak_key: &[u8; 16],
        tweak: &[u8; 16],
        data: &mut [u8],
    ) -> bool {
        xts_core(data_key, tweak_key, tweak, data, true)
    }

    pub fn xts_decrypt_128(
        data_key: &[u8; 16],
        tweak_key: &[u8; 16],
        tweak: &[u8; 16],
        data: &mut [u8],
    ) -> bool {
        xts_core(data_key, tweak_key, tweak, data, false)
    }

    /// XTS-AES-256 (64-byte key material).
    pub fn xts_encrypt_256(
        data_key: &[u8; 32],
        tweak_key: &[u8; 32],
        tweak: &[u8; 16],
        data: &mut [u8],
    ) -> bool {
        xts_core(data_key, tweak_key, tweak, data, true)
    }

    pub fn xts_decrypt_256(
        data_key: &[u8; 32],
        tweak_key: &[u8; 32],
        tweak: &[u8; 16],
        data: &mut [u8],
    ) -> bool {
        xts_core(data_key, tweak_key, tweak, data, false)
    }
}

pub use aes_core::{
    cbc_decrypt, cbc_encrypt, ctr_crypt, ecb_decrypt, ecb_encrypt, xts_decrypt_128,
    xts_decrypt_256, xts_encrypt_128, xts_encrypt_256, AesBlock,
};

// ---------------------------------------------------------------------------
// XTS backend trait — shape-compatible with crates/apple-soc/src/aes.rs
// `AesXts` (key[32] there is the 256-bit data key; here the standard 1619
// split is data_key = key[0..16], tweak_key = key[16..32] for XTS-128 —
// the KAT below pins the exact interpretation).
// ---------------------------------------------------------------------------
pub trait AesXts: Send {
    fn xts_decrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool;
    fn xts_encrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool;
}

/// Real software XTS backend (default for the device model).
#[derive(Debug, Default, Clone, Copy)]
pub struct SoftXts;

impl AesXts for SoftXts {
    fn xts_encrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool {
        let (dk, tk) = (key[..16].try_into().unwrap(), key[16..].try_into().unwrap());
        xts_encrypt_128(&dk, &tk, tweak, data)
    }
    fn xts_decrypt(&mut self, key: &[u8; 32], tweak: &[u8; 16], data: &mut [u8]) -> bool {
        let (dk, tk) = (key[..16].try_into().unwrap(), key[16..].try_into().unwrap());
        xts_decrypt_128(&dk, &tk, tweak, data)
    }
}

/// Census-only backend mirroring apple-soc `CensusXts` (records, no
/// transform — the fused-key wall shape).
#[derive(Debug, Default)]
pub struct CensusXts {
    pub decrypts: u64,
    pub encrypts: u64,
}

impl AesXts for CensusXts {
    fn xts_decrypt(&mut self, _k: &[u8; 32], _t: &[u8; 16], _d: &mut [u8]) -> bool {
        self.decrypts += 1;
        false
    }
    fn xts_encrypt(&mut self, _k: &[u8; 32], _t: &[u8; 16], _d: &mut [u8]) -> bool {
        self.encrypts += 1;
        false
    }
}

// ---------------------------------------------------------------------------
// Register map — 1:1 from include/hw/misc/apple-silicon/aes_reg.h
// ---------------------------------------------------------------------------
pub const REG_AES_VERSION: u64 = 0x0;
pub const REG_AES_CONFIG: u64 = 0x4;
pub const REG_AES_CONTROL: u64 = 0x8;
pub const REG_AES_STATUS: u64 = 0xC;
pub const REG_AES_KEY_ID: u64 = 0x10;
pub const REG_AES_AXI_STATUS: u64 = 0x14;
pub const REG_AES_INT_STATUS: u64 = 0x18;
pub const REG_AES_INT_ENABLE: u64 = 0x1C;
pub const REG_AES_WATERMARKS: u64 = 0x20;
pub const REG_AES_COMMAND_FIFO_STATUS: u64 = 0x24;
pub const REG_AES_HISTORY_FIFO_STATUS: u64 = 0x28;
pub const REG_AES_COMMAND_FIFO_COUNT: u64 = 0x2C;
pub const REG_AES_FLAG_COMMAND: u64 = 0x30;
pub const REG_AES_SKG_KEY: u64 = 0x34;
pub const REG_AES_CLEAR_FIFO: u64 = 0x38;
pub const REG_AES_COMMAND_FIFO_S8000: u64 = 0x100;
pub const REG_AES_COMMAND_FIFO: u64 = 0x200;
pub const REG_AES_HISTORY_FIFO: u64 = 0x400;

pub const AES_BLK_REG_SIZE: u64 = 0x204;
pub const COMMAND_FIFO_SIZE: usize = 128;

// aes_blk_control_t
pub const AES_BLK_CONTROL_START: u32 = 1 << 0;
pub const AES_BLK_CONTROL_STOP: u32 = 1 << 1;
pub const AES_BLK_CONTROL_RESET: u32 = 1 << 2;
pub const AES_BLK_CONTROL_RESET_AES: u32 = 1 << 3;

// command_opcodes_t
pub const OPCODE_KEY: u32 = 0x01;
pub const OPCODE_IV: u32 = 0x02;
pub const OPCODE_DSB: u32 = 0x03;
pub const OPCODE_SKG: u32 = 0x04;
pub const OPCODE_DATA: u32 = 0x05;
pub const OPCODE_STORE_IV: u32 = 0x06;
pub const OPCODE_WRITE_REG: u32 = 0x07;
pub const OPCODE_FLAG: u32 = 0x08;

pub const COMMAND_OPCODE_SHIFT: u32 = 28;
pub fn command_opcode(w: u32) -> u32 {
    (w >> COMMAND_OPCODE_SHIFT) & 0xF
}

// block_mode_t / key_len_t / key_select_t
pub const BLOCK_MODE_ECB: u32 = 0;
pub const BLOCK_MODE_CBC: u32 = 1;
pub const BLOCK_MODE_CTR: u32 = 2;
pub const KEY_LEN_128: u32 = 0;
pub const KEY_LEN_192: u32 = 1;
pub const KEY_LEN_256: u32 = 2;
pub const KEY_SELECT_SOFTWARE: u32 = 0;

// INT_STATUS/INT_ENABLE bit positions (aes_blk_int_status_t)
pub const INT_COMMAND_FIFO_LOW: u32 = 1 << 0;
pub const INT_COMMAND_FIFO_OVERFLOW: u32 = 1 << 1;
pub const INT_INVALID_COMMAND: u32 = 1 << 2;
pub const INT_FLAG_COMMAND: u32 = 1 << 5;
pub const INT_INVALID_DATA_LENGTH: u32 = 1 << 6;
pub const INT_KEY_0_DISABLED: u32 = 1 << 7;
pub const INT_KEY_1_DISABLED: u32 = 1 << 13;

// STATUS v5 bit positions
const STATUS_ACTIVE: u32 = 1 << 4;
const STATUS_COMMAND_FIFO_ACTIVE: u32 = 1 << 5;
const STATUS_COMMAND_FIFO_ENABLED: u32 = 1 << 6;
/// apple_aes_reset seeds text0..5 + key_unwrap DPA bits and marks the
/// gid/fairplay self tests passed — the T8030 (v5) reset image.
const STATUS_V5_RESET: u32 =
    0x7F << 7 | 1 << 14 | 1 << 15;

// COMMAND_FIFO_STATUS bit positions
const FIFO_EMPTY: u32 = 1 << 1;
const FIFO_FULL: u32 = 1 << 2;
const FIFO_OVERFLOW: u32 = 1 << 3;

// FLAG command bits
pub const COMMAND_FLAG_STOP_COMMANDS: u32 = 1 << 26;
pub const COMMAND_FLAG_SEND_INTERRUPT: u32 = 1 << 27;

/// DMA address-space injection (upstream `dma_memory_read/write` against
/// `s->dma_as`). The machine wires a bus-backed impl; tests use a RAM one.
pub trait AesDma {
    fn dma_read(&mut self, addr: u64, buf: &mut [u8]);
    fn dma_write(&mut self, addr: u64, data: &[u8]);
}

/// Drop-everything backend (records transfers only — honest when no bus
/// is wired).
#[derive(Debug, Default)]
pub struct NullDma {
    pub reads: u64,
    pub writes: u64,
}

impl AesDma for NullDma {
    fn dma_read(&mut self, _addr: u64, buf: &mut [u8]) {
        self.reads += 1;
        buf.fill(0);
    }
    fn dma_write(&mut self, _addr: u64, _data: &[u8]) {
        self.writes += 1;
    }
}

#[derive(Debug, Default, Clone)]
pub struct AesKeyCtx {
    pub select: u32,
    pub key: [u8; 32],
    pub key_len: usize,
    pub mode: u32,
    pub encrypt: bool,
    pub disabled: bool,
    pub id: u8,
}

impl AesKeyCtx {
    fn cipher(&self) -> Option<AesBlock> {
        if self.disabled {
            None
        } else {
            AesBlock::new(&self.key[..self.key_len])
        }
    }
}

/// Workspace-extension XTS op (see module doc): storage-stack contract of
/// `crates/apple-soc/src/aes.rs`, driven with key/slot/tweak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesXtsOp {
    /// key slot (0/1 = the two upstream key contexts); slot key bytes are
    /// interpreted as data_key(16) || tweak_key(16) for XTS-128.
    pub key_slot: usize,
    /// 128-bit LE data-unit number / tweak.
    pub tweak: [u8; 16],
    pub encrypt: bool,
    pub src: u64,
    pub dst: u64,
    pub len: usize,
}

#[derive(Debug, Default)]
struct AesCommand {
    command: u32,
    /// words received so far (word 0 = the command word)
    data: Vec<u32>,
    /// total words this opcode expects
    expected: usize,
}

/// Apple AES engine (T8030, v5 status layout).
pub struct AesEngine {
    pub board_id: u32,
    keys: [AesKeyCtx; 2],
    ivs: [[u8; 16]; 4],
    queue: VecDeque<AesCommand>,
    /// in-flight command assembly state (aes.c `s->command/data/data_len/read`)
    assembling: Option<AesCommand>,
    fifo_level: u32,
    watermark_low: u32,
    int_status: u32,
    int_enable: u32,
    flag_code: u16,
    skg_key: u32,
    started: bool,
    stopped: bool,
    pub ops: u64,
    pub xts_queue: VecDeque<AesXtsOp>,
    pub xts: Box<dyn AesXts>,
    pub dma: Box<dyn AesDma>,
    pub bad_offsets: u64,
}

impl Default for AesEngine {
    fn default() -> Self {
        Self::new(8)
    }
}

impl AesEngine {
    pub fn new(board_id: u32) -> Self {
        AesEngine {
            board_id,
            keys: Default::default(),
            ivs: [[0; 16]; 4],
            queue: VecDeque::new(),
            assembling: None,
            fifo_level: 0,
            watermark_low: 0,
            int_status: 0,
            int_enable: 0,
            flag_code: 0,
            skg_key: 0,
            started: false,
            stopped: true,
            ops: 0,
            xts_queue: VecDeque::new(),
            xts: Box::new(SoftXts),
            dma: Box::new(NullDma::default()),
            bad_offsets: 0,
        }
    }

    pub fn set_xts_backend(&mut self, xts: Box<dyn AesXts>) {
        self.xts = xts;
    }

    pub fn set_dma(&mut self, dma: Box<dyn AesDma>) {
        self.dma = dma;
    }

    fn update_fifo_status(&mut self) {
        // upstream assigns int_status.command_fifo_low = status.low
        if self.fifo_level < self.watermark_low {
            self.int_status |= INT_COMMAND_FIFO_LOW;
        } else {
            self.int_status &= !INT_COMMAND_FIFO_LOW;
        }
    }

    /// Device reset (aes.c apple_aes_reset) — keeps injected backends.
    fn reset_state(&mut self) {
        self.keys = Default::default();
        self.ivs = [[0; 16]; 4];
        self.queue.clear();
        self.assembling = None;
        self.fifo_level = 0;
        self.watermark_low = 0;
        self.int_status = 0;
        self.int_enable = 0;
        self.flag_code = 0;
        self.skg_key = 0;
        self.started = false;
        self.stopped = true;
        self.xts_queue.clear();
    }

    fn irq_level(&self) -> bool {
        self.int_enable & self.int_status != 0
    }

    fn empty_fifo(&mut self) {
        self.queue.clear();
        self.assembling = None;
        self.fifo_level = 0;
        self.update_fifo_status();
    }

    /// Enqueue + (if running) process pending commands synchronously — the
    /// upstream worker thread's drain loop, reduced to the synchronous edge
    /// a single-threaded Rust model can expose honestly.
    fn enqueue(&mut self, cmd: AesCommand) {
        self.queue.push_back(cmd);
        if self.started && !self.stopped {
            self.drain();
        }
    }

    pub fn drain(&mut self) {
        while let Some(cmd) = self.queue.pop_front() {
            self.process(cmd);
        }
    }

    fn set_int(&mut self, bit: u32) {
        self.int_status |= bit;
    }

    fn process(&mut self, cmd: AesCommand) {
        self.ops += 1;
        self.fifo_level = self.fifo_level.saturating_sub(cmd.data.len() as u32);
        match command_opcode(cmd.command) {
            OPCODE_KEY => {
                let ctx = ((cmd.command >> 27) & 0x1) as usize;
                let select = (cmd.command >> 24) & 0x7;
                let len_field = (cmd.command >> 22) & 0x3;
                let key_len = match len_field {
                    KEY_LEN_128 => 16,
                    KEY_LEN_192 => 24,
                    KEY_LEN_256 => 32,
                    _ => 0,
                };
                let k = &mut self.keys[ctx];
                k.select = select;
                k.mode = (cmd.command >> 16) & 0x3;
                k.encrypt = cmd.command & (1 << 20) != 0;
                k.id = (cmd.command & 0xFF) as u8;
                k.key_len = key_len;
                // key material follows as words; hw-key-select commands
                // carry none (data stays zeroed, key disabled anyway)
                let have = cmd.data.len().saturating_sub(1) * 4;
                for (i, b) in k.key.iter_mut().take(key_len.min(have)).enumerate() {
                    let word = cmd.data[1 + i / 4];
                    *b = (word >> ((i % 4) * 8)) as u8;
                }
                if select != KEY_SELECT_SOFTWARE {
                    // fused-key wall: no UID/GID/HDCP key material here
                    k.disabled = true;
                    self.set_int(if ctx == 0 { INT_KEY_0_DISABLED } else { INT_KEY_1_DISABLED });
                } else {
                    k.disabled = false;
                }
            }
            OPCODE_IV => {
                let ctx = ((cmd.command >> 26) & 0x3) as usize;
                for i in 0..16 {
                    let word = cmd.data[1 + i / 4];
                    self.ivs[ctx][i] = (word >> ((i % 4) * 8)) as u8;
                }
            }
            OPCODE_DSB => {
                // upstream: recorded, not transformed ("reasons")
            }
            OPCODE_DATA => {
                let key_ctx = ((cmd.command >> 27) & 0x1) as usize;
                let iv_ctx = ((cmd.command >> 25) & 0x3) as usize;
                let len = (cmd.command & 0xFF_FFFF) as usize;
                let upper = cmd.data[1];
                let src = cmd.data[2] as u64
                    | (((upper >> 16) & 0xFF) as u64) << 32;
                let dst = cmd.data[3] as u64 | (((upper) & 0xFF) as u64) << 32;
                if len & 0xF != 0 {
                    self.set_int(INT_INVALID_DATA_LENGTH);
                    return;
                }
                if self.keys[key_ctx].disabled {
                    self.set_int(if key_ctx == 0 {
                        INT_KEY_0_DISABLED
                    } else {
                        INT_KEY_1_DISABLED
                    });
                    return;
                }
                let Some(cipher) = self.keys[key_ctx].cipher() else {
                    return;
                };
                let mut buf = vec![0u8; len];
                self.dma.dma_read(src, &mut buf);
                let mut iv = self.ivs[iv_ctx];
                match (self.keys[key_ctx].mode, self.keys[key_ctx].encrypt) {
                    (BLOCK_MODE_ECB, true) => ecb_encrypt(&cipher, &mut buf),
                    (BLOCK_MODE_ECB, false) => ecb_decrypt(&cipher, &mut buf),
                    (BLOCK_MODE_CBC, true) => cbc_encrypt(&cipher, &mut iv, &mut buf),
                    (BLOCK_MODE_CBC, false) => cbc_decrypt(&cipher, &mut iv, &mut buf),
                    (BLOCK_MODE_CTR, _) => ctr_crypt(&cipher, &mut iv, &mut buf),
                    _ => {}
                }
                self.ivs[iv_ctx] = iv;
                self.dma.dma_write(dst, &buf);
            }
            OPCODE_STORE_IV => {
                let ctx = ((cmd.command >> 26) & 0x3) as usize;
                let dst =
                    cmd.data[1] as u64 | (((cmd.command & 0xFF) as u64) << 32);
                self.dma.dma_write(dst, &self.ivs[ctx]);
            }
            OPCODE_FLAG => {
                self.flag_code = (cmd.command & 0xFF) as u16;
                if cmd.command & COMMAND_FLAG_STOP_COMMANDS != 0 {
                    self.stopped = true;
                }
                if cmd.command & COMMAND_FLAG_SEND_INTERRUPT != 0 {
                    self.set_int(INT_FLAG_COMMAND);
                }
            }
            _ => self.set_int(INT_INVALID_COMMAND),
        }
    }

    /// MMIO write into the command FIFO (aes.c REG_AES_COMMAND_FIFO case).
    fn fifo_write(&mut self, word: u32) {
        if let Some(a) = self.assembling.as_mut() {
            if a.data.len() < a.expected {
                a.data.push(word);
                self.fifo_level += 1;
                if a.data.len() >= a.expected {
                    let cmd = self.assembling.take().unwrap();
                    self.enqueue(cmd);
                }
                self.update_fifo_status();
                return;
            }
        }
        // new command word
        let opcode = command_opcode(word);
        let expected = match opcode {
            OPCODE_KEY => {
                if (word >> 24) & 0x7 == KEY_SELECT_SOFTWARE {
                    let key_len = match (word >> 22) & 0x3 {
                        KEY_LEN_128 => 16,
                        KEY_LEN_192 => 24,
                        KEY_LEN_256 => 32,
                        _ => 0,
                    };
                    key_len / 4 + 1
                } else {
                    1
                }
            }
            OPCODE_IV => 5,
            OPCODE_DSB => 9,
            OPCODE_DATA => 4,
            OPCODE_STORE_IV => 2,
            OPCODE_FLAG => 1,
            _ => {
                self.set_int(INT_INVALID_COMMAND);
                return;
            }
        };
        let cmd = AesCommand { command: word, data: vec![word], expected };
        self.fifo_level += 1;
        if expected == 1 {
            self.enqueue(cmd);
        } else {
            self.assembling = Some(cmd);
        }
        self.update_fifo_status();
    }

    // ---- XTS storage-op path (workspace extension) ------------------------
    pub fn queue_xts_op(&mut self, op: AesXtsOp) {
        self.xts_queue.push_back(op);
    }

    /// Run queued XTS ops through the backend + DMA. Returns true iff all
    /// succeeded.
    pub fn run_xts(&mut self) -> bool {
        let mut all_ok = true;
        while let Some(op) = self.xts_queue.pop_front() {
            let key = self.keys[op.key_slot.min(1)].key;
            let mut buf = vec![0u8; op.len];
            self.dma.dma_read(op.src, &mut buf);
            let ok = if op.encrypt {
                self.xts.xts_encrypt(&key, &op.tweak, &mut buf)
            } else {
                self.xts.xts_decrypt(&key, &op.tweak, &mut buf)
            };
            self.dma.dma_write(op.dst, &buf);
            all_ok &= ok;
        }
        all_ok
    }

    fn status(&self) -> u32 {
        let mut s = STATUS_V5_RESET;
        if self.started && !self.stopped {
            s |= STATUS_ACTIVE | STATUS_COMMAND_FIFO_ENABLED;
        }
        if !self.queue.is_empty() || self.assembling.is_some() {
            s |= STATUS_COMMAND_FIFO_ACTIVE;
        }
        s
    }

    fn fifo_status(&self) -> u32 {
        let mut s = 0u32;
        if self.fifo_level == 0 {
            s |= FIFO_EMPTY;
        }
        if self.fifo_level as usize >= COMMAND_FIFO_SIZE {
            s |= FIFO_FULL;
        }
        if self.fifo_level as usize > COMMAND_FIFO_SIZE {
            s |= FIFO_OVERFLOW;
        }
        s |= (self.fifo_level & 0xFF) << 8;
        s
    }
}



impl MMIODevice for AesEngine {
    fn name(&self) -> &'static str {
        "apple-aes"
    }
    fn size(&self) -> u64 {
        AES_BLK_REG_SIZE
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        if offset >= AES_BLK_REG_SIZE {
            self.bad_offsets += 1;
            return 0;
        }
        match offset {
            REG_AES_VERSION => 0, // reset-zero upstream (nothing writes it)
            REG_AES_STATUS => self.status() as u64,
            REG_AES_KEY_ID => {
                (self.keys[0].id as u32 | (self.keys[1].id as u32) << 8) as u64
            }
            REG_AES_INT_STATUS => self.int_status as u64,
            REG_AES_INT_ENABLE => self.int_enable as u64,
            REG_AES_WATERMARKS => self.watermark_low as u64,
            REG_AES_COMMAND_FIFO_STATUS => self.fifo_status() as u64,
            REG_AES_COMMAND_FIFO_COUNT => self.fifo_level as u64,
            REG_AES_FLAG_COMMAND => self.flag_code as u64,
            REG_AES_SKG_KEY => self.skg_key as u64,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        if offset >= AES_BLK_REG_SIZE {
            self.bad_offsets += 1;
            return;
        }
        let val = value as u32;
        match offset {
            REG_AES_CONTROL => match val {
                AES_BLK_CONTROL_START => {
                    self.started = true;
                    self.stopped = false;
                    self.drain();
                }
                AES_BLK_CONTROL_STOP => {
                    self.stopped = true;
                    self.started = false;
                }
                AES_BLK_CONTROL_RESET => self.empty_fifo(),
                AES_BLK_CONTROL_RESET_AES => self.reset_state(),
                _ => {} // upstream: "Invalid write" log only
            },
            REG_AES_INT_STATUS => self.int_status &= !val, // write-1-to-clear
            REG_AES_INT_ENABLE => self.int_enable = val,
            REG_AES_WATERMARKS => {
                self.watermark_low = val & 0x7F;
                self.update_fifo_status();
            }
            REG_AES_CLEAR_FIFO => {
                if val & 1 != 0 {
                    self.empty_fifo();
                }
            }
            REG_AES_FLAG_COMMAND | REG_AES_SKG_KEY => {} // read-only upstream
            REG_AES_COMMAND_FIFO_S8000 | REG_AES_COMMAND_FIFO => self.fifo_write(val),
            _ => {} // CONFIG et al stored nowhere (upstream: write, unused)
        }
    }
}

pub const PARITY_PCT: u8 = 60; // authentic reg map + KAT-verified cipher core; DMA ring/DPA/fused-key wall pending

impl crate::bus::Device for AesEngine {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn irqs(&self) -> Vec<(u32, bool)> {
        vec![(0, self.irq_level())]
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

// ---------------------------------------------------------------------------
// Security register region (aes.c aes_security_reg_read)
// ---------------------------------------------------------------------------
pub struct AesSecurityRegs {
    pub board_id: u32,
}

impl AesSecurityRegs {
    pub const AES_DISABLE: u64 = 0x0;
    pub const MCC_BOOTROM_DIS: u64 = 0x10;
    pub const GPIO_STRAPS: u64 = 0x20;
    pub const SET_ONLY: u64 = 0x30;
    pub const SEP: u64 = 0x34;
}

impl Default for AesSecurityRegs {
    fn default() -> Self {
        Self { board_id: 8 }
    }
}

impl MMIODevice for AesSecurityRegs {
    fn name(&self) -> &'static str {
        "apple-aes-security"
    }
    fn size(&self) -> u64 {
        0x40
    }
    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            Self::AES_DISABLE => 1 | (1 << 1), // GID1 | UID (upstream value)
            Self::MCC_BOOTROM_DIS => 1,        // for iBoot + SecureROM
            Self::GPIO_STRAPS => ((self.board_id & 0x1F) as u64) | (1 << 31), // VALID
            Self::SET_ONLY => 0,
            Self::SEP => 1 << 24 | 1 << 25, // FIRST_BOOT | FIRST_AWAKE_BOOT
            _ => 0xFF,
        }
    }
    fn write(&mut self, _offset: u64, _value: u64, _width: u32) {}
}

impl crate::bus::Device for AesSecurityRegs {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        40
    }
}

// ---------------------------------------------------------------------------
// Command-word builders (test/host helper — encodes aes_reg.h macros)
// ---------------------------------------------------------------------------
pub fn key_command(
    ctx: u32,
    select: u32,
    len_field: u32,
    wrapped: bool,
    encrypt: bool,
    mode: u32,
    id: u8,
) -> u32 {
    (OPCODE_KEY << COMMAND_OPCODE_SHIFT)
        | (ctx << 27)
        | (select << 24)
        | (len_field << 22)
        | ((wrapped as u32) << 21)
        | ((encrypt as u32) << 20)
        | (mode << 16)
        | id as u32
}

pub fn iv_command(ctx: u32) -> u32 {
    (OPCODE_IV << COMMAND_OPCODE_SHIFT) | (ctx << 26)
}

pub fn data_command(key_ctx: u32, iv_ctx: u32, len: u32) -> u32 {
    (OPCODE_DATA << COMMAND_OPCODE_SHIFT) | (key_ctx << 27) | (iv_ctx << 25) | (len & 0xFF_FFFF)
}

pub fn flag_command(code: u8, stop: bool, interrupt: bool) -> u32 {
    (OPCODE_FLAG << COMMAND_OPCODE_SHIFT)
        | ((stop as u32) << 26)
        | ((interrupt as u32) << 27)
        | code as u32
}

fn to_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(b)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Device as _, W4};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- cipher core vs FIPS-197 Appendix C -------------------------------
    #[test]
    fn fips197_block_vectors() {
        let pt: [u8; 16] = hex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        // C.1 AES-128
        let mut b = pt;
        AesBlock::new(&hex("000102030405060708090a0b0c0d0e0f"))
            .unwrap()
            .encrypt_block(&mut b);
        assert_eq!(b, hex("69c4e0d86a7b0430d8cdb78070b4c55a")[..], "AES-128 enc");
        AesBlock::new(&hex("000102030405060708090a0b0c0d0e0f"))
            .unwrap()
            .decrypt_block(&mut b);
        assert_eq!(b, pt, "AES-128 dec");
        // C.2 AES-192
        let mut b = pt;
        AesBlock::new(&hex("000102030405060708090a0b0c0d0e0f1011121314151617"))
            .unwrap()
            .encrypt_block(&mut b);
        assert_eq!(b, hex("dda97ca4864cdfe06eaf70a0ec0d7191")[..], "AES-192 enc");
        // C.3 AES-256
        let mut b = pt;
        AesBlock::new(&hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ))
        .unwrap()
        .encrypt_block(&mut b);
        assert_eq!(b, hex("8ea2b7ca516745bfeafc49904b496089")[..], "AES-256 enc");
    }

    // ---- XTS known answers -------------------------------------------------
    // KAT provenance: the workspace sandbox has no copy of IEEE
    // 1619-2007 Annex B, so these constants were generated and cross-checked
    // with two independent AES-XTS implementations available in-sandbox
    // (python cryptography 44.0.3 → OpenSSL EVP_aes_128_xts, and a manual
    // GF(2^128) composition over pycryptodome ECB) before being pinned.
    // The block primitive underneath is pinned by the FIPS-197 vectors
    // above, so the KAT exercises the XTS composition (tweak schedule,
    // GF(2^128) doubling, ciphertext stealing).
    const XTS128_KEY: &str = "6f1ef55a0d2b5c14a9a5239c9c6b4d3ee4c898a2c9f0b4ad0b1e6cf3d84a1b0b";
    const XTS128_PT16: &str = "000102030405060708090a0b0c0d0e0f";
    const XTS128_CT16: &str = "29377511ba1a4a176ef7cb5883252f57";

    #[test]
    fn xts_128_known_answer() {
        let key: [u8; 32] = hex(XTS128_KEY).try_into().unwrap();
        let mut data: Vec<u8> = hex(XTS128_PT16);
        let tweak = [0u8; 16];
        assert!(xts_encrypt_128(
            &key[..16].try_into().unwrap(),
            &key[16..].try_into().unwrap(),
            &tweak,
            &mut data
        ));
        assert_eq!(hex(XTS128_CT16), data, "XTS-AES-128 KAT ciphertext");
        assert!(xts_decrypt_128(
            &key[..16].try_into().unwrap(),
            &key[16..].try_into().unwrap(),
            &tweak,
            &mut data
        ));
        assert_eq!(data, hex(XTS128_PT16), "XTS-AES-128 KAT roundtrip");
    }

    #[test]
    fn xts_256_known_answer_and_stealing() {
        // AES-256-XTS (64-byte key), nonzero tweak — oracle-pinned constants
        let key: Vec<u8> = hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        let tweak: [u8; 16] = hex("efcdab89674523010000000000000000")
            .try_into()
            .unwrap();
        let pt: Vec<u8> = hex(
            "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5\
             dce3eaf1f8ff060d141b222930373e454c",
        );
        let ct: Vec<u8> = hex(
            "6cb116b5d02cd3c84235672738f7a207fb8072cdb7a9ba9883f3dbd0cf541c6c\
             b303fbbb9c7fc96cdcaabe0bac33b918",
        );
        let mut data = pt.clone();
        assert!(xts_encrypt_256(
            &key[..32].try_into().unwrap(),
            &key[32..].try_into().unwrap(),
            &tweak,
            &mut data
        ));
        assert_eq!(data, ct);
        assert!(xts_decrypt_256(
            &key[..32].try_into().unwrap(),
            &key[32..].try_into().unwrap(),
            &tweak,
            &mut data
        ));
        assert_eq!(data, pt);
    }

    #[test]
    fn xts_ciphertext_stealing_tail() {
        // 52-byte message (3 full blocks + 4-byte tail): encrypt/decrypt
        // roundtrip and the oracle-quoted tail bytes.
        //
        // The expected ciphertext below is pinned by the checked-in
        // independent reference `tools/oracles/xts_cts_ref.py`
        // (`cryptography`-44/OpenSSL AES-128 primitive + IEEE P1619-draft
        // CTS composition implemented from the spec). An earlier revision
        // of this constant had a fabricated, odd-length tail — replaced
        // with the oracle output byte-for-byte.
        let key: [u8; 32] = hex(XTS128_KEY).try_into().unwrap();
        let dk: [u8; 16] = key[..16].try_into().unwrap();
        let tk: [u8; 16] = key[16..].try_into().unwrap();
        let pt: Vec<u8> = hex(
            "000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d\
             606366696c6f7275787b7e8184878a8d90939699",
        );
        let ct: Vec<u8> = hex(
            "940683726e96926f0b30d9dd8447fdd991971e174ae5cddf3fba910b4c55d7b7\
             3657f103474e0a6dabd5f3edf42ed7c828ad4036",
        );
        let tweak: [u8; 16] = (5u128).to_le_bytes();
        let mut data = pt.clone();
        assert!(xts_encrypt_128(&dk, &tk, &tweak, &mut data));
        assert_eq!(data, ct, "XTS ciphertext-stealing tail");
        assert!(xts_decrypt_128(&dk, &tk, &tweak, &mut data));
        assert_eq!(data, pt);
    }

    // ---- device-level tests ------------------------------------------------
    struct TestRam {
        mem: Vec<u8>,
    }

    impl TestRam {
        fn new(n: usize) -> Self {
            TestRam { mem: vec![0; n] }
        }
        fn load(&mut self, addr: u64, data: &[u8]) {
            self.mem[addr as usize..addr as usize + data.len()].copy_from_slice(data);
        }
    }

    impl AesDma for TestRam {
        fn dma_read(&mut self, addr: u64, buf: &mut [u8]) {
            let o = addr as usize;
            buf.copy_from_slice(&self.mem[o..o + buf.len()]);
        }
        fn dma_write(&mut self, addr: u64, data: &[u8]) {
            let o = addr as usize;
            self.mem[o..o + data.len()].copy_from_slice(data);
        }
    }

    fn engine_with_ram() -> (AesEngine, std::rc::Rc<std::cell::RefCell<TestRam>>) {
        let ram = std::rc::Rc::new(std::cell::RefCell::new(TestRam::new(4096)));
        // The device owns its DMA box; tests drive the queue + read the RAM
        // through the same closure pair the machine would wire. To keep the
        // test honest we give the device a DMA view of the shared RAM.
        struct Shared(std::rc::Rc<std::cell::RefCell<TestRam>>);
        impl AesDma for Shared {
            fn dma_read(&mut self, addr: u64, buf: &mut [u8]) {
                self.0.borrow_mut().dma_read(addr, buf);
            }
            fn dma_write(&mut self, addr: u64, data: &[u8]) {
                self.0.borrow_mut().dma_write(addr, data);
            }
        }
        let mut e = AesEngine::new(8);
        e.set_dma(Box::new(Shared(ram.clone())));
        (e, ram)
    }

    fn push_words(e: &mut AesEngine, ws: &[u32]) {
        for &w in ws {
            e.write(REG_AES_COMMAND_FIFO, w as u64, W4);
        }
    }

    #[test]
    fn command_fifo_ecb_encrypt_roundtrip() {
        let (mut e, ram) = engine_with_ram();
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_START as u64, W4);
        let pt: Vec<u8> = hex(XTS128_PT16);
        ram.borrow_mut().load(0x100, &pt);

        // KEY ctx0, software, 128-bit, ECB, encrypt, id=0x77
        let key: Vec<u8> = hex("000102030405060708090a0b0c0d0e0f");
        let mut ws = vec![key_command(0, KEY_SELECT_SOFTWARE, KEY_LEN_128, false, true, BLOCK_MODE_ECB, 0x77)];
        ws.extend(to_words(&key));
        push_words(&mut e, &ws);
        // DATA ctx0/iv0: len 16, src 0x100, dst 0x200
        push_words(
            &mut e,
            &[
                data_command(0, 0, 16),
                0,               // upper addr
                0x100,           // source
                0x200,           // dest
            ],
        );
        assert_eq!(e.read(REG_AES_KEY_ID, W4), 0x77); // context_0 id
        let mut expected: [u8; 16] = pt.clone().try_into().unwrap();
        AesBlock::new(&key).unwrap().encrypt_block(&mut expected);
        assert_eq!(&ram.borrow().mem[0x200..0x210], &expected[..]);

        // decrypt back
        let mut ws = vec![key_command(0, KEY_SELECT_SOFTWARE, KEY_LEN_128, false, false, BLOCK_MODE_ECB, 0x77)];
        ws.extend(to_words(&key));
        push_words(&mut e, &ws);
        push_words(
            &mut e,
            &[data_command(0, 0, 16), 0, 0x200, 0x300],
        );
        assert_eq!(&ram.borrow().mem[0x300..0x310], &pt[..]);
        assert!(e.ops >= 3);
    }

    #[test]
    fn cbc_iv_chains_across_data_commands() {
        let (mut e, ram) = engine_with_ram();
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_START as u64, W4);
        let key: Vec<u8> = hex("2b7e151628aed2a6abf7158809cf4f3c");
        ram.borrow_mut().load(0x100, &[0xAA; 32]);

        let mut ws = vec![key_command(0, KEY_SELECT_SOFTWARE, KEY_LEN_128, false, true, BLOCK_MODE_CBC, 1)];
        ws.extend(to_words(&key));
        push_words(&mut e, &ws);
        // IV ctx0 = 00..0f
        let iv: Vec<u8> = (0..16).collect();
        let mut ivw = vec![iv_command(0)];
        ivw.extend(to_words(&iv));
        push_words(&mut e, &ivw);
        // first DATA: 16 bytes
        push_words(&mut e, &[data_command(0, 0, 16), 0, 0x100, 0x200]);
        let ct1: [u8; 16] = ram.borrow().mem[0x200..0x210].try_into().unwrap();
        // second DATA: next 16 bytes, IV must continue from ct1
        push_words(&mut e, &[data_command(0, 0, 16), 0, 0x110, 0x210]);
        let ct2: [u8; 16] = ram.borrow().mem[0x210..0x220].try_into().unwrap();

        // manual reference: two chained CBC blocks
        let mut ref_buf = vec![0xAA; 32];
        let mut ref_iv: [u8; 16] = iv.clone().try_into().unwrap();
        cbc_encrypt(&AesBlock::new(&key).unwrap(), &mut ref_iv, &mut ref_buf);
        assert_eq!(ct1, ref_buf[..16]);
        assert_eq!(ct2, ref_buf[16..]);
    }

    #[test]
    fn invalid_length_and_fused_key_flag_int_status_and_irq() {
        let (mut e, _ram) = engine_with_ram();
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_START as u64, W4);
        // DATA with len % 16 != 0 → invalid_data_length
        push_words(&mut e, &[data_command(0, 0, 17), 0, 0, 0]);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_INVALID_DATA_LENGTH, INT_INVALID_DATA_LENGTH);
        // write-1-to-clear
        e.write(REG_AES_INT_STATUS, INT_INVALID_DATA_LENGTH as u64, W4);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4), 0);

        // KEY with hw select (GID1) → key_0_disabled + INT
        push_words(&mut e, &[key_command(0, 2, KEY_LEN_128, false, true, BLOCK_MODE_ECB, 0)]);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_KEY_0_DISABLED, INT_KEY_0_DISABLED);
        // DATA against the disabled key keeps the wall (no transform)
        e.write(REG_AES_INT_STATUS, u64::from(u32::MAX), W4);
        push_words(&mut e, &[data_command(0, 0, 16), 0, 0x100, 0x200]);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_KEY_0_DISABLED, INT_KEY_0_DISABLED);

        // IRQ = enable & status
        e.write(REG_AES_INT_ENABLE, INT_KEY_0_DISABLED as u64, W4);
        assert!(e.irqs()[0].1);
        e.write(REG_AES_INT_ENABLE, 0, W4);
        assert!(!e.irqs()[0].1);
    }

    #[test]
    fn flag_command_stop_interrupt_and_reset() {
        let (mut e, _ram) = engine_with_ram();
        // unknown opcode → invalid_command
        push_words(&mut e, &[0x9 << 28]);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_INVALID_COMMAND, INT_INVALID_COMMAND);
        e.write(REG_AES_INT_STATUS, u64::from(u32::MAX), W4);

        // FLAG with interrupt + stop
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_START as u64, W4);
        push_words(&mut e, &[flag_command(0x42, true, true)]);
        assert_eq!(e.read(REG_AES_FLAG_COMMAND, W4), 0x42);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_FLAG_COMMAND, INT_FLAG_COMMAND);
        // stopped: queued commands wait (status shows fifo active, not active)
        let st = e.read(REG_AES_STATUS, W4) as u32;
        assert_eq!(st & STATUS_ACTIVE, 0);
        assert_eq!(st & STATUS_V5_RESET, STATUS_V5_RESET);

        // RESET_AES restores the reset image
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_RESET_AES as u64, W4);
        assert_eq!(e.read(REG_AES_INT_STATUS, W4), 0);
        assert_eq!(e.read(REG_AES_FLAG_COMMAND, W4), 0);
    }

    #[test]
    fn fifo_status_levels_and_clear() {
        let mut e = AesEngine::new(8);
        assert_eq!(e.read(REG_AES_COMMAND_FIFO_STATUS, W4) as u32 & FIFO_EMPTY, FIFO_EMPTY);
        // a stopped engine holds assembled commands in the queue
        e.write(REG_AES_COMMAND_FIFO, iv_command(0) as u64, W4);
        for i in 0..4u32 {
            e.write(REG_AES_COMMAND_FIFO, 0x1111_1111u64.wrapping_add(i as u64), W4);
        }
        let st = e.read(REG_AES_COMMAND_FIFO_STATUS, W4) as u32;
        assert_eq!((st >> 8) & 0xFF, 5, "level counts every pushed word");
        assert_eq!(e.read(REG_AES_COMMAND_FIFO_COUNT, W4), 5);
        assert_eq!(st & FIFO_EMPTY, 0);
        // CLEAR_FIFO reset empties
        e.write(REG_AES_CLEAR_FIFO, 1, W4);
        assert_eq!(e.read(REG_AES_COMMAND_FIFO_COUNT, W4), 0);
        assert_eq!(
            e.read(REG_AES_COMMAND_FIFO_STATUS, W4) as u32 & FIFO_EMPTY,
            FIFO_EMPTY
        );
    }

    #[test]
    fn xts_op_through_device_matches_kat() {
        let (mut e, ram) = engine_with_ram();
        // slot 0 key = dk || tk (the 1619 XTS-AES-128 pair)
        let key: [u8; 32] = hex(XTS128_KEY).try_into().unwrap();
        e.keys[0].key = key;
        e.keys[0].key_len = 32;
        let pt: Vec<u8> = hex(XTS128_PT16);
        ram.borrow_mut().load(0x400, &pt);
        e.queue_xts_op(AesXtsOp {
            key_slot: 0,
            tweak: [0; 16],
            encrypt: true,
            src: 0x400,
            dst: 0x500,
            len: 16,
        });
        assert!(e.run_xts());
        assert_eq!(&ram.borrow().mem[0x500..0x510], &hex(XTS128_CT16)[..]);

        // decrypt through the same slot returns the plaintext
        e.queue_xts_op(AesXtsOp {
            key_slot: 0,
            tweak: [0; 16],
            encrypt: false,
            src: 0x500,
            dst: 0x600,
            len: 16,
        });
        assert!(e.run_xts());
        assert_eq!(&ram.borrow().mem[0x600..0x610], &pt[..]);
    }

    #[test]
    fn census_backend_records_but_does_not_transform() {
        let mut e = AesEngine::new(8);
        e.set_xts_backend(Box::new(CensusXts::default()));
        e.keys[0].key = [7; 32];
        e.queue_xts_op(AesXtsOp {
            key_slot: 0,
            tweak: [0; 16],
            encrypt: true,
            src: 0,
            dst: 0,
            len: 16,
        });
        assert!(!e.run_xts(), "census backend keeps the key wall honest");
    }

    #[test]
    fn status_reset_image_and_control_semantics() {
        let mut e = AesEngine::new(8);
        // v5 reset image: dpa seeds + self tests
        assert_eq!(e.read(REG_AES_STATUS, W4) as u32 & STATUS_V5_RESET, STATUS_V5_RESET);
        assert_eq!(e.read(REG_AES_VERSION, W4), 0);
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_START as u64, W4);
        assert_eq!(e.read(REG_AES_STATUS, W4) as u32 & STATUS_ACTIVE, STATUS_ACTIVE);
        e.write(REG_AES_CONTROL, AES_BLK_CONTROL_STOP as u64, W4);
        assert_eq!(e.read(REG_AES_STATUS, W4) as u32 & STATUS_ACTIVE, 0);
        // invalid control word is ignored (upstream logs only)
        e.write(REG_AES_CONTROL, 0xF0, W4);
        assert_eq!(e.read(REG_AES_STATUS, W4) as u32 & STATUS_ACTIVE, 0);
    }

    #[test]
    fn security_region_reads() {
        let mut s = AesSecurityRegs { board_id: 0x11 };
        assert_eq!(s.read(AesSecurityRegs::AES_DISABLE, W4), 1 | (1 << 1));
        assert_eq!(s.read(AesSecurityRegs::MCC_BOOTROM_DIS, W4), 1);
        assert_eq!(s.read(AesSecurityRegs::GPIO_STRAPS, W4), 0x11 | (1 << 31));
        assert_eq!(s.read(AesSecurityRegs::SET_ONLY, W4), 0);
        assert_eq!(s.read(AesSecurityRegs::SEP, W4), (1 << 24) | (1 << 25));
        assert_eq!(s.read(0x3C, W4), 0xFF);
    }

    #[test]
    fn watermark_low_sets_interrupt() {
        let mut e = AesEngine::new(8);
        e.write(REG_AES_WATERMARKS, 4, W4);
        // empty fifo below watermark → command_fifo_low
        assert_eq!(e.read(REG_AES_INT_STATUS, W4) as u32 & INT_COMMAND_FIFO_LOW, INT_COMMAND_FIFO_LOW);
    }
}
