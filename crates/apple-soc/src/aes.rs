//! aes — Apple AES-XTS hardware engine (port of hw/misc/apple-silicon/
//! aes.c). Register map + key/tweak store; the actual XTS transform is
//! injectable (research: plug a real core, or the sanctioned Dopamine
//! key path). Ops are recorded for the parity census.

use vm_core::Device;

pub const AES_CTRL: u64 = 0x0000;
pub const AES_STATUS: u64 = 0x0004;
pub const AES_KEY_LO: u64 = 0x0008; // 8 words = 256-bit key
pub const AES_TWEAK_LO: u64 = 0x0028; // 2 words = 128-bit tweak
pub const AES_IN_ADDR: u64 = 0x0100;
pub const AES_OUT_ADDR: u64 = 0x0108;
pub const AES_SIZE: u64 = 0x0110;

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

pub struct AesEngine {
    pub key: [u8; 32],
    pub tweak: [u8; 16],
    pub in_addr: u64,
    pub out_addr: u64,
    pub size: u64,
    pub ops: u64,
    pub xts: Box<dyn AesXts>,
    pub unknown_reads: u64,
}

impl AesEngine {
    pub fn new() -> Self {
        AesEngine {
            key: [0; 32],
            tweak: [0; 16],
            in_addr: 0,
            out_addr: 0,
            size: 0,
            ops: 0,
            xts: Box::new(CensusXts::default()),
            unknown_reads: 0,
        }
    }

    /// Run against a memory accessor (machine injects read/write closures).
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
            ("CTRL", AES_CTRL),
            ("STATUS", AES_STATUS),
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
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
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
                self.tweak[i * 4..i * 4 + 4].copy_from_slice(&(val as u32).to_le_bytes());
            }
            _ => {}
        }
    }
}
