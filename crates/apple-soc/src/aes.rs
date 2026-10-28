//! Apple hardware AES accelerator (v3/v5 command-FIFO engine).
//!
//! Port of ChefKiss Inferno `hw/misc/apple-silicon/aes.c` + `aes_reg.h`.
//! This is *not* the old S5L `A_KEY`/`A_TWEAK` register file — on T8030 the
//! AES engine is programmed through a command FIFO (opcodes KEY / IV / DSB /
//! SKG / DATA / STORE_IV / WRITE_REG / FLAG) plus a second "security" MMIO
//! region (v3 GID/UID disable, GPIO straps, SEP boot state).
//!
//! Real AES crypto is out of scope for this port: DATA commands are decoded
//! faithfully and recorded, and ciphertext is passed through **untouched**
//! unless an [`AesXts`] implementation is injected (default stub only keeps
//! a parity census). Upstream threading (`aes_thread`) is replaced by
//! synchronous processing on the FIFO write — bit-exact for the driver
//! protocol, minus async timing.
//!
//! License: AGPL-3.0-or-later (derived work).

use vm_core::Device;

// ---------------------------------------------------------------------------
// aes_reg.h
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
pub const REG_AES_COMMAND_FIFO_COUNT: u64 = 0x2C;
pub const REG_AES_FLAG_COMMAND: u64 = 0x30;
pub const REG_AES_SKG_KEY: u64 = 0x34;
pub const REG_AES_CLEAR_FIFO: u64 = 0x38;
pub const REG_AES_COMMAND_FIFO_S8000: u64 = 0x100;
pub const REG_AES_COMMAND_FIFO: u64 = 0x200;
pub const REG_AES_HISTORY_FIFO: u64 = 0x400;

pub const AES_BLK_REG_SIZE: u64 = 0x204;
pub const COMMAND_FIFO_SIZE: u32 = 128;

// CONTROL bits.
pub const AES_BLK_CONTROL_START: u32 = 1 << 0;
pub const AES_BLK_CONTROL_STOP: u32 = 1 << 1;
pub const AES_BLK_CONTROL_RESET: u32 = 1 << 2;
pub const AES_BLK_CONTROL_RESET_AES: u32 = 1 << 3;

// v3 security region.
pub const REG_AES_V3_SECURITY_AES_DISABLE: u64 = 0x0;
pub const AES_V3_SECURITY_AES_DISABLE_UID: u32 = 1;
pub const AES_V3_SECURITY_AES_DISABLE_GID1: u32 = 2 << 1;
pub const REG_AES_V3_SECURITY_MCC_BOOTROM_DIS: u64 = 0x10;
pub const REG_AES_V3_SECURITY_GPIO_STRAPS: u64 = 0x20;
pub const AES_V3_SECURITY_GPIO_STRAPS_VALID: u32 = 1 << 31;
pub const REG_AES_V3_SECURITY_SET_ONLY: u64 = 0x30;
pub const REG_AES_V3_SECURITY_SEP: u64 = 0x34;
pub const AES_V3_SECURITY_SEP_FIRST_BOOT: u32 = 1 << 24;
pub const AES_V3_SECURITY_SEP_FIRST_AWAKE_BOOT: u32 = 1 << 25;

// Command opcodes.
pub const OPCODE_KEY: u32 = 0x01;
pub const OPCODE_IV: u32 = 0x02;
pub const OPCODE_DSB: u32 = 0x03;
pub const OPCODE_SKG: u32 = 0x04;
pub const OPCODE_DATA: u32 = 0x05;
pub const OPCODE_STORE_IV: u32 = 0x06;
pub const OPCODE_WRITE_REG: u32 = 0x07;
pub const OPCODE_FLAG: u32 = 0x08;

pub const fn command_opcode(word: u32) -> u32 {
    (word >> 28) & 0xF
}

// KEY command fields.
pub const fn key_context(w: u32) -> u32 {
    (w >> 27) & 0x1
}
pub const fn key_select(w: u32) -> u32 {
    (w >> 24) & 0x7
}
pub const fn key_length(w: u32) -> u32 {
    (w >> 22) & 0x3
}
pub const KEY_WRAPPED: u32 = 1 << 21;
pub const KEY_ENCRYPT: u32 = 1 << 20;
pub const fn key_func(w: u32) -> u32 {
    (w >> 18) & 0x3
}
pub const fn key_block_mode(w: u32) -> u32 {
    (w >> 16) & 0x3
}
pub const fn key_id(w: u32) -> u32 {
    w & 0xFF
}

// DATA command fields.
pub const fn data_key_context(w: u32) -> u32 {
    (w >> 27) & 0x1
}
pub const fn data_iv_context(w: u32) -> u32 {
    (w >> 25) & 0x3
}
pub const fn data_length(w: u32) -> u32 {
    w & 0xFF_FFFF
}
pub const fn upper_addr_source(w: u32) -> u32 {
    (w >> 16) & 0xFF
}
pub const fn upper_addr_dest(w: u32) -> u32 {
    w & 0xFF
}

// FLAG command fields.
pub const fn flag_id(w: u32) -> u32 {
    w & 0xFF
}
pub const FLAG_STOP_COMMANDS: u32 = 1 << 26;
pub const FLAG_SEND_INTERRUPT: u32 = 1 << 27;

pub const KEY_SELECT_SOFTWARE: u32 = 0;

// INT_STATUS bits (aes_blk_int_status_t).
pub const INT_COMMAND_FIFO_LOW: u32 = 1 << 0;
pub const INT_COMMAND_FIFO_OVERFLOW: u32 = 1 << 1;
pub const INT_INVALID_COMMAND: u32 = 1 << 2;
pub const INT_AXI_READ_RESPONSE_NOT_OKAY: u32 = 1 << 3;
pub const INT_AXI_WRITE_RESPONSE_NOT_OKAY: u32 = 1 << 4;
pub const INT_FLAG_COMMAND: u32 = 1 << 5;
pub const INT_INVALID_DATA_LENGTH: u32 = 1 << 6;
pub const INT_KEY_0_DISABLED: u32 = 1 << 7;
pub const INT_KEY_1_DISABLED: u32 = 1 << 14;

// STATUS (v5) bits we model.
pub const STS_COMMAND_FIFO_ENABLED: u32 = 1 << 6;
pub const STS_GID_SELF_TEST_PASSED: u32 = 1 << 14;
pub const STS_FAIRPLAY_SELF_TEST_PASSED: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// XTS injection point
// ---------------------------------------------------------------------------

/// Injectable AES-XTS core. The real hardware AES is out of scope for this
/// port; a future implementation (or software AES) plugs in here.
pub trait AesXts: Send {
    /// Decrypt `data` in place with `key` and the XTS `tweak`.
    fn xts_decrypt(&mut self, key: &[u8], tweak: &[u8], data: &mut [u8]);
}

/// Default no-op: ciphertext passes through untouched (parity census only).
#[derive(Default)]
pub struct XtsPassThrough {
    /// Number of decrypt calls issued through the stub.
    pub calls: u64,
}

impl AesXts for XtsPassThrough {
    fn xts_decrypt(&mut self, key: &[u8], tweak: &[u8], data: &mut [u8]) {
        // Ciphertext untouched — record for parity census.
        let _ = (key.len(), tweak.len(), data.len());
        self.calls += 1;
    }
}

/// One decoded OPCODE_DATA command (DMA in/out is the machine's job).
#[derive(Debug, Clone, Copy)]
pub struct AesDmaOp {
    pub source_addr: u64,
    pub dest_addr: u64,
    pub len: u32,
    pub key_context: u32,
    pub iv_context: u32,
    pub encrypt: bool,
}

// ---------------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------------

/// Apple AES accelerator. Two MMIO regions upstream (`reg[1]` main + `reg[3]`
/// security); in this port the security region hangs off the same span at
/// offset [`AES_SEC_REGION_OFF`] when attached with the ADT layout, or is
/// attached as its own region by the machine.
pub const AES_SEC_REGION_OFF: u64 = 0x10000;
pub const AES_SEC_REGION_SIZE: u64 = 0x100;

#[derive(Clone, Copy, Default)]
struct AesKeySlot {
    select: u32,
    len_words: u32,
    key: [u32; 8],
    func: u32,
    mode: u32,
    id: u32,
    encrypt: bool,
    disabled: bool,
}

pub struct AppleAes {
    /// Register file (raw u32 words, AES_BLK_REG_SIZE/4).
    pub reg: Vec<u32>,
    /// v3 security register region.
    pub sec: Vec<u32>,
    /// Board ID reported via GPIO straps (t8030 board_id = 4).
    pub board_id: u32,

    keys: [AesKeySlot; 2],
    /// IV contexts (4 × 16 bytes).
    pub iv: [[u32; 4]; 4],

    // command FIFO assembly state (aes.c AppleAESState fields)
    command: u32,
    data: Vec<u32>,
    data_read: u32,
    data_len: u32,
    /// FIFO level (command_fifo_status.level).
    fifo_level: u32,

    /// Injectable crypto core.
    pub xts: Option<Box<dyn AesXts>>,

    /// Decoded DATA commands awaiting machine-side DMA.
    pub pending_dma: Vec<AesDmaOp>,
    /// Executed-command census (opcode name → count).
    pub op_census: Vec<(&'static str, u32)>,
    /// Last flag-command id (REG_AES_FLAG_COMMAND).
    pub last_flag: u32,
    pub stopped: bool,
    pub int_line: bool,
}

impl AppleAes {
    pub fn new() -> Self {
        let mut aes = AppleAes {
            reg: vec![0u32; AES_BLK_REG_SIZE as usize / 4],
            sec: vec![0u32; AES_SEC_REGION_SIZE as usize / 4],
            board_id: 4,
            keys: [AesKeySlot::default(); 2],
            iv: [[0u32; 4]; 4],
            command: 0,
            data: Vec::new(),
            data_read: 0,
            data_len: 0,
            fifo_level: 0,
            xts: Some(Box::new(XtsPassThrough::default())),
            pending_dma: Vec::new(),
            op_census: Vec::new(),
            last_flag: 0,
            stopped: true,
            int_line: false,
        };
        aes.reset();
        aes
    }

    fn reset(&mut self) {
        self.reg = vec![0u32; AES_BLK_REG_SIZE as usize / 4];
        // apple_aes_reset: v5 status self-test/DPA bits pre-set.
        self.reg[REG_AES_STATUS as usize / 4] = STS_COMMAND_FIFO_ENABLED
            | STS_GID_SELF_TEST_PASSED
            | STS_FAIRPLAY_SELF_TEST_PASSED;
        // VERSION: v5-style (fld/major/minor)
        self.reg[REG_AES_VERSION as usize / 4] = 0x0005_0001;
        self.command = 0;
        self.data.clear();
        self.data_read = 0;
        self.data_len = 0;
        self.fifo_level = 0;
        self.keys = [AesKeySlot::default(); 2];
        self.iv = [[0u32; 4]; 4];
        self.stopped = true;
        self.update_fifo_status();
        self.update_irq();
    }

    fn census(&mut self, op: &'static str) {
        for e in self.op_census.iter_mut() {
            if e.0 == op {
                e.1 += 1;
                return;
            }
        }
        self.op_census.push((op, 1));
    }

    fn update_fifo_status(&mut self) {
        // aes_update_command_fifo_status (TODO read/write_pointer upstream)
        let mut st = self.reg[REG_AES_COMMAND_FIFO_STATUS as usize / 4];
        const EMPTY: u32 = 1 << 16;
        const FULL: u32 = 1 << 17;
        const OVERFLOW: u32 = 1 << 18;
        const LOW: u32 = 1 << 19;
        st &= !(EMPTY | FULL | OVERFLOW | LOW);
        if self.fifo_level == 0 {
            st |= EMPTY;
        }
        if self.fifo_level >= COMMAND_FIFO_SIZE {
            st |= FULL;
        }
        if self.fifo_level > COMMAND_FIFO_SIZE {
            st |= OVERFLOW;
        }
        let watermark = self.reg[REG_AES_WATERMARKS as usize / 4] & 0xFF;
        if self.fifo_level < watermark {
            st |= LOW;
        }
        self.reg[REG_AES_COMMAND_FIFO_STATUS as usize / 4] = st;
        if st & LOW != 0 {
            self.reg[REG_AES_INT_STATUS as usize / 4] |= INT_COMMAND_FIFO_LOW;
        }
        self.update_irq();
    }

    fn update_irq(&mut self) {
        let en = self.reg[REG_AES_INT_ENABLE as usize / 4];
        let st = self.reg[REG_AES_INT_STATUS as usize / 4];
        self.int_line = en & st != 0;
    }

    fn empty_fifo(&mut self) {
        self.data.clear();
        self.data_read = 0;
        self.data_len = 0;
        self.fifo_level = 0;
        self.update_fifo_status();
    }

    /// `aes_process_command` — synchronous port (upstream runs it on a thread).
    fn process_command(&mut self, cmd: &[u32]) {
        let header = cmd[0];
        match command_opcode(header) {
            OPCODE_KEY => {
                self.census("key");
                let ctx = key_context(header) as usize;
                let klen_words = match key_length(header) {
                    0 => 4, // 128-bit
                    1 => 6, // 192-bit
                    2 => 8, // 256-bit
                    _ => 4,
                };
                let slot = &mut self.keys[ctx];
                slot.select = key_select(header);
                slot.len_words = klen_words;
                slot.encrypt = header & KEY_ENCRYPT != 0;
                slot.func = key_func(header);
                slot.mode = key_block_mode(header);
                slot.id = key_id(header);
                for (i, w) in slot.key.iter_mut().enumerate().take(klen_words as usize)
                {
                    *w = cmd.get(1 + i).copied().unwrap_or(0);
                }
                // key_id register: context_0 | context_1
                let kid = self.reg[REG_AES_KEY_ID as usize / 4];
                let kid = if ctx == 1 {
                    (kid & 0xFF) | (slot.id << 8)
                } else {
                    (kid & 0xFF00) | slot.id
                };
                self.reg[REG_AES_KEY_ID as usize / 4] = kid;
                if slot.select != KEY_SELECT_SOFTWARE {
                    slot.disabled = true;
                    let s = self.reg[REG_AES_INT_STATUS as usize / 4];
                    self.reg[REG_AES_INT_STATUS as usize / 4] = if ctx == 1 {
                        s | INT_KEY_1_DISABLED
                    } else {
                        s | INT_KEY_0_DISABLED
                    };
                } else {
                    slot.disabled = false;
                    let s = self.reg[REG_AES_INT_STATUS as usize / 4];
                    self.reg[REG_AES_INT_STATUS as usize / 4] = if ctx == 1 {
                        s & !INT_KEY_1_DISABLED
                    } else {
                        s & !INT_KEY_0_DISABLED
                    };
                }
            }
            OPCODE_IV => {
                self.census("iv");
                let ctx = ((header >> 26) & 0x3) as usize;
                for i in 0..4 {
                    self.iv[ctx][i] = cmd.get(1 + i).copied().unwrap_or(0);
                }
            }
            OPCODE_DSB => {
                self.census("dsb");
                // DPA seed block: inputs recorded, no crypto.
            }
            OPCODE_SKG => {
                self.census("skg");
                // SKG (secure key generator): unsupported, no status change.
            }
            OPCODE_DATA => {
                self.census("data");
                let len = data_length(cmd.get(1).copied().unwrap_or(0));
                if len & 0xF != 0 {
                    self.reg[REG_AES_INT_STATUS as usize / 4] |=
                        INT_INVALID_DATA_LENGTH;
                    self.update_irq();
                    return;
                }
                let key_ctx = data_key_context(header) as usize;
                let iv_ctx = data_iv_context(header) as usize;
                if self.keys[key_ctx].disabled {
                    let s = self.reg[REG_AES_INT_STATUS as usize / 4];
                    self.reg[REG_AES_INT_STATUS as usize / 4] =
                        if key_ctx == 1 {
                            s | INT_KEY_1_DISABLED
                        } else {
                            s | INT_KEY_0_DISABLED
                        };
                    self.update_irq();
                    return;
                }
                let upper = cmd.get(2).copied().unwrap_or(0);
                let source = cmd.get(3).copied().unwrap_or(0) as u64
                    | (upper_addr_source(upper) as u64) << 32;
                let dest = cmd.get(4).copied().unwrap_or(0) as u64
                    | (upper_addr_dest(upper) as u64) << 32;
                self.pending_dma.push(AesDmaOp {
                    source_addr: source,
                    dest_addr: dest,
                    len,
                    key_context: key_ctx as u32,
                    iv_context: iv_ctx as u32,
                    encrypt: self.keys[key_ctx].encrypt,
                });
                // XTS hook exercised with the programmed key + IV; ciphertext
                // passes through untouched with the default stub.
                if let Some(xts) = self.xts.as_mut() {
                    let mut key_bytes = [0u8; 32];
                    let kw = self.keys[key_ctx].len_words as usize;
                    for (i, w) in self.keys[key_ctx].key[..kw].iter().enumerate()
                    {
                        key_bytes[i * 4..i * 4 + 4]
                            .copy_from_slice(&w.to_le_bytes());
                    }
                    let mut tweak = [0u8; 16];
                    for (i, w) in self.iv[iv_ctx].iter().enumerate() {
                        tweak[i * 4..i * 4 + 4]
                            .copy_from_slice(&w.to_le_bytes());
                    }
                    let mut scratch = vec![0u8; len as usize];
                    xts.xts_decrypt(&key_bytes, &tweak, &mut scratch);
                }
            }
            OPCODE_STORE_IV => {
                self.census("store-iv");
                let ctx = ((header >> 26) & 0x3) as usize;
                let upper = cmd.get(1).copied().unwrap_or(0) as u64;
                let dest = (upper & 0xFF) << 32
                    | (cmd.get(2).copied().unwrap_or(0) as u64);
                let mut iv_bytes = [0u8; 16];
                for (i, w) in self.iv[ctx].iter().enumerate() {
                    iv_bytes[i * 4..i * 4 + 4]
                        .copy_from_slice(&w.to_le_bytes());
                }
                // DMA write of the IV is machine-side: record it.
                self.pending_dma.push(AesDmaOp {
                    source_addr: 0,
                    dest_addr: dest,
                    len: 16,
                    key_context: 0,
                    iv_context: ctx as u32,
                    encrypt: false,
                });
            }
            OPCODE_WRITE_REG => {
                self.census("write-reg");
            }
            OPCODE_FLAG => {
                self.census("flag");
                self.last_flag = flag_id(header);
                self.reg[REG_AES_FLAG_COMMAND as usize / 4] =
                    flag_id(header) & 0xFF;
                if header & FLAG_STOP_COMMANDS != 0 {
                    self.stopped = true;
                }
                if header & FLAG_SEND_INTERRUPT != 0 {
                    self.reg[REG_AES_INT_STATUS as usize / 4] |=
                        INT_FLAG_COMMAND;
                    self.update_irq();
                }
            }
            _ => {
                self.census("invalid");
                self.reg[REG_AES_INT_STATUS as usize / 4] |=
                    INT_INVALID_COMMAND;
                self.update_irq();
            }
        }
    }

    /// Command-FIFO word write (REG_AES_COMMAND_FIFO / _S8000).
    fn fifo_write(&mut self, val: u32) {
        if self.data_len > self.data_read {
            self.data.push(val);
            self.data_read += 1;
        } else {
            self.command = val;
            self.data = vec![val];
            self.data_read = 1;
            self.data_len = match command_opcode(val) {
                OPCODE_KEY => {
                    if key_select(val) == KEY_SELECT_SOFTWARE {
                        // 1 header word + key words
                        match key_length(val) {
                            1 => 7,
                            2 => 9,
                            _ => 5,
                        }
                    } else {
                        1
                    }
                }
                OPCODE_IV => 5,
                OPCODE_DSB => 9,
                OPCODE_DATA => 5,
                OPCODE_STORE_IV => 3,
                OPCODE_FLAG => 1,
                _ => {
                    self.reg[REG_AES_INT_STATUS as usize / 4] |=
                        INT_INVALID_COMMAND;
                    self.update_irq();
                    1
                }
            };
        }

        if self.data_len <= self.data_read {
            // command complete: process inline (upstream queues to a thread)
            let cmd: Vec<u32> = self.data.clone();
            self.process_command(&cmd);
            self.command = 0;
            self.data.clear();
            self.data_read = 0;
            self.data_len = 0;
            self.fifo_level += 1;
            self.update_fifo_status();
        }
    }

    fn sec_read(&self, off: u64) -> u64 {
        match off {
            REG_AES_V3_SECURITY_AES_DISABLE => {
                (AES_V3_SECURITY_AES_DISABLE_GID1
                    | AES_V3_SECURITY_AES_DISABLE_UID) as u64
            }
            REG_AES_V3_SECURITY_MCC_BOOTROM_DIS => 1,
            REG_AES_V3_SECURITY_GPIO_STRAPS => {
                (self.board_id & 0x1F) as u64 | AES_V3_SECURITY_GPIO_STRAPS_VALID as u64
            }
            REG_AES_V3_SECURITY_SET_ONLY => 0,
            REG_AES_V3_SECURITY_SEP => {
                (AES_V3_SECURITY_SEP_FIRST_BOOT
                    | AES_V3_SECURITY_SEP_FIRST_AWAKE_BOOT) as u64
            }
            _ => 0xFF,
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("REG_AES_VERSION", REG_AES_VERSION),
            ("REG_AES_CONFIG", REG_AES_CONFIG),
            ("REG_AES_CONTROL", REG_AES_CONTROL),
            ("REG_AES_STATUS", REG_AES_STATUS),
            ("REG_AES_KEY_ID", REG_AES_KEY_ID),
            ("REG_AES_AXI_STATUS", REG_AES_AXI_STATUS),
            ("REG_AES_INT_STATUS", REG_AES_INT_STATUS),
            ("REG_AES_INT_ENABLE", REG_AES_INT_ENABLE),
            ("REG_AES_WATERMARKS", REG_AES_WATERMARKS),
            ("REG_AES_COMMAND_FIFO_STATUS", REG_AES_COMMAND_FIFO_STATUS),
            ("REG_AES_COMMAND_FIFO_COUNT", REG_AES_COMMAND_FIFO_COUNT),
            ("REG_AES_FLAG_COMMAND", REG_AES_FLAG_COMMAND),
            ("REG_AES_SKG_KEY", REG_AES_SKG_KEY),
            ("REG_AES_CLEAR_FIFO", REG_AES_CLEAR_FIFO),
            ("REG_AES_COMMAND_FIFO", REG_AES_COMMAND_FIFO),
            ("REG_AES_HISTORY_FIFO", REG_AES_HISTORY_FIFO),
            ("REG_AES_V3_SECURITY_AES_DISABLE", REG_AES_V3_SECURITY_AES_DISABLE),
            ("REG_AES_V3_SECURITY_GPIO_STRAPS", REG_AES_V3_SECURITY_GPIO_STRAPS),
            ("REG_AES_V3_SECURITY_SEP", REG_AES_V3_SECURITY_SEP),
            ("OPCODE_KEY", OPCODE_KEY),
            ("OPCODE_IV", OPCODE_IV),
            ("OPCODE_DATA", OPCODE_DATA),
            ("OPCODE_FLAG", OPCODE_FLAG),
        ]
    }
}

impl Device for AppleAes {
    fn name(&self) -> &'static str {
        "aes"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        if (AES_SEC_REGION_OFF..AES_SEC_REGION_OFF + AES_SEC_REGION_SIZE)
            .contains(&off)
        {
            return self.sec_read(off - AES_SEC_REGION_OFF);
        }
        if off >= AES_BLK_REG_SIZE {
            return 0;
        }
        match off {
            REG_AES_INT_STATUS
            | REG_AES_COMMAND_FIFO_STATUS
            | REG_AES_FLAG_COMMAND => self.reg[off as usize / 4] as u64,
            _ => self.reg[off as usize / 4] as u64,
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        if (AES_SEC_REGION_OFF..AES_SEC_REGION_OFF + AES_SEC_REGION_SIZE)
            .contains(&off)
        {
            // security region: write-ignored (set-only regs upstream)
            return;
        }
        if off >= AES_BLK_REG_SIZE {
            return;
        }
        let val = val as u32;
        match off {
            REG_AES_VERSION
            | REG_AES_STATUS
            | REG_AES_KEY_ID
            | REG_AES_AXI_STATUS
            | REG_AES_COMMAND_FIFO_STATUS
            | REG_AES_COMMAND_FIFO_COUNT
            | REG_AES_FLAG_COMMAND
            | REG_AES_SKG_KEY => { /* read-only */ }
            REG_AES_INT_STATUS => {
                // write-1-to-clear
                let cur = self.reg[REG_AES_INT_STATUS as usize / 4];
                self.reg[REG_AES_INT_STATUS as usize / 4] = cur & !val;
                self.update_irq();
            }
            REG_AES_INT_ENABLE => {
                self.reg[REG_AES_INT_ENABLE as usize / 4] = val;
                self.update_irq();
            }
            REG_AES_WATERMARKS => {
                self.reg[REG_AES_WATERMARKS as usize / 4] = val;
                self.update_fifo_status();
            }
            REG_AES_CONTROL => match val {
                AES_BLK_CONTROL_START => {
                    self.stopped = false;
                    self.census("start");
                }
                AES_BLK_CONTROL_STOP => {
                    self.stopped = true;
                }
                AES_BLK_CONTROL_RESET => self.empty_fifo(),
                AES_BLK_CONTROL_RESET_AES => self.reset(),
                _ => {
                    self.reg[REG_AES_INT_STATUS as usize / 4] |=
                        INT_INVALID_COMMAND;
                    self.update_irq();
                }
            },
            REG_AES_COMMAND_FIFO_S8000 | REG_AES_COMMAND_FIFO => {
                self.fifo_write(val);
            }
            REG_AES_CLEAR_FIFO => {
                if val == 1 {
                    self.empty_fifo();
                }
            }
            REG_AES_CONFIG => {
                self.reg[REG_AES_CONFIG as usize / 4] = val;
            }
            _ => {
                self.reg[off as usize / 4] = val;
            }
        }
    }
}

impl Default for AppleAes {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_then_data_op_census() {
        let mut aes = AppleAes::new();
        // KEY cmd: ctx0, software key, 128-bit, decrypt (bit20 = 0)
        let key_cmd: u32 = (OPCODE_KEY << 28) | (0 << 24) | (0 << 22);
        aes.write(REG_AES_COMMAND_FIFO, 4, key_cmd as u64);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x0102_0304);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x0506_0708);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x090A_0B0C);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x0D0E_0F10);
        assert_eq!(aes.op_census.iter().find(|(n, _)| *n == "key").unwrap().1, 1);
        assert!(!aes.keys[0].disabled);
        assert_eq!(aes.keys[0].key[0], 0x0102_0304);

        // DATA cmd: 32 bytes, source 0x100, dest 0x200 (no upper bits)
        let data_cmd: u32 = (OPCODE_DATA << 28) | (32 & 0xFF_FFFF);
        aes.write(REG_AES_COMMAND_FIFO, 4, data_cmd as u64);
        aes.write(REG_AES_COMMAND_FIFO, 4, 32); // length in dw1
        aes.write(REG_AES_COMMAND_FIFO, 4, 0); // upper addr
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x100); // source
        aes.write(REG_AES_COMMAND_FIFO, 4, 0x200); // dest

        assert_eq!(aes.pending_dma.len(), 1);
        let op = aes.pending_dma[0];
        assert_eq!(op.source_addr, 0x100);
        assert_eq!(op.dest_addr, 0x200);
        assert_eq!(op.len, 32);
        assert!(!op.encrypt);
    }

    #[test]
    fn flag_command_stops_and_interrupts() {
        let mut aes = AppleAes::new();
        aes.write(REG_AES_INT_ENABLE, 4, INT_FLAG_COMMAND as u64);
        let flag: u32 = (OPCODE_FLAG << 28) | FLAG_SEND_INTERRUPT | 0x5A;
        aes.write(REG_AES_COMMAND_FIFO, 4, flag as u64);
        assert_eq!(aes.last_flag, 0x5A);
        assert!(aes.int_line);
        // clear via INT_STATUS write
        aes.write(REG_AES_INT_STATUS, 4, INT_FLAG_COMMAND as u64);
        assert!(!aes.int_line);
    }

    #[test]
    fn security_region_v3() {
        let mut aes = AppleAes::new();
        aes.board_id = 0x4;
        assert_eq!(
            aes.read(AES_SEC_REGION_OFF + REG_AES_V3_SECURITY_AES_DISABLE, 4),
            (AES_V3_SECURITY_AES_DISABLE_GID1
                | AES_V3_SECURITY_AES_DISABLE_UID) as u64
        );
        assert_eq!(
            aes.read(AES_SEC_REGION_OFF + REG_AES_V3_SECURITY_GPIO_STRAPS, 4),
            0x4 | AES_V3_SECURITY_GPIO_STRAPS_VALID as u64
        );
        assert_eq!(
            aes.read(AES_SEC_REGION_OFF + REG_AES_V3_SECURITY_SEP, 4),
            (AES_V3_SECURITY_SEP_FIRST_BOOT
                | AES_V3_SECURITY_SEP_FIRST_AWAKE_BOOT) as u64
        );
        assert_eq!(aes.read(AES_SEC_REGION_OFF + 0x99, 4), 0xFF);
    }

    #[test]
    fn invalid_length_sets_interrupt() {
        let mut aes = AppleAes::new();
        aes.write(REG_AES_INT_ENABLE, 4, INT_INVALID_DATA_LENGTH as u64);
        // KEY first so key slot enabled
        aes.write(REG_AES_COMMAND_FIFO, 4, (OPCODE_KEY << 28) as u64);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        // DATA with length 17 (not multiple of 16)
        aes.write(REG_AES_COMMAND_FIFO, 4, (OPCODE_DATA << 28) as u64);
        aes.write(REG_AES_COMMAND_FIFO, 4, 17);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        aes.write(REG_AES_COMMAND_FIFO, 4, 0);
        assert!(aes.int_line);
        assert_eq!(aes.pending_dma.len(), 0);
    }
}
