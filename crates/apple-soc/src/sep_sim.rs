//! sep_sim — SEP simulator (port of Inferno hw/arm/apple-silicon/
//! sep-sim.c): the control-op state machine that lets the ANE/host talk
//! to a simulated Secure Enclave Processor. Control ops decoded EXACTLY
//! as upstream (ep 18): NOP/ACK/OOL/TTY/SEED_DPA/GEN_RANDOM/SELF_TEST/
//! DMA/ERASE_INSTALL/KEYSTORE.

use vm_core::Device;

pub const SEP_MAILBOX_EP: u32 = 18;

pub const SEP_STATUS: u64 = 0x0000;
pub const SEP_CTRL_OP: u64 = 0x0004;
pub const SEP_CTRL_ARG0: u64 = 0x0008;
pub const SEP_CTRL_ARG1: u64 = 0x000C;
pub const SEP_CTRL_ARG2: u64 = 0x0010;
pub const SEP_TTY_IN: u64 = 0x0020;
pub const SEP_TTY_OUT: u64 = 0x0024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SepOp {
    Nop,
    Ack,
    Ool,
    Tty,
    SeedDpa,
    GenRandom,
    SelfTest,
    Dma,
    EraseInstall,
    Keystore,
    Unknown(u8),
}

impl SepOp {
    pub fn from_code(c: u8) -> Self {
        match c {
            0 => SepOp::Nop,
            1 => SepOp::Ack,
            2 => SepOp::Ool,
            3 => SepOp::Tty,
            4 => SepOp::SeedDpa,
            5 => SepOp::GenRandom,
            6 => SepOp::SelfTest,
            7 => SepOp::Dma,
            8 => SepOp::EraseInstall,
            9 => SepOp::Keystore,
            other => SepOp::Unknown(other),
        }
    }
    pub fn code(&self) -> u8 {
        match self {
            SepOp::Nop => 0,
            SepOp::Ack => 1,
            SepOp::Ool => 2,
            SepOp::Tty => 3,
            SepOp::SeedDpa => 4,
            SepOp::GenRandom => 5,
            SepOp::SelfTest => 6,
            SepOp::Dma => 7,
            SepOp::EraseInstall => 8,
            SepOp::Keystore => 9,
            SepOp::Unknown(c) => *c,
        }
    }
}

pub struct SepSim {
    pub status: u32,
    pub last_op: SepOp,
    pub args: [u32; 3],
    pub tty_in: Vec<u8>,
    pub tty_out: Vec<u8>,
    /// deterministic PRNG state (SEP host test mode)
    pub rng_state: u64,
    pub dpa_seed: [u8; 32],
    pub ops_processed: u64,
    pub unknown_reads: u64,
}

impl SepSim {
    pub fn new() -> Self {
        SepSim {
            status: 1, // ready
            last_op: SepOp::Nop,
            args: [0; 3],
            tty_in: Vec::new(),
            tty_out: Vec::new(),
            rng_state: 0x9E3779B97F4A7C15,
            dpa_seed: [0; 32],
            ops_processed: 0,
            unknown_reads: 0,
        }
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64* — deterministic for tests
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub fn submit(&mut self, op: SepOp, args: [u32; 3]) -> u32 {
        self.last_op = op;
        self.args = args;
        self.ops_processed += 1;
        match op {
            SepOp::Nop | SepOp::Ack => 0,
            SepOp::GenRandom => {
                let mut words = [0u64; 4];
                for w in &mut words {
                    *w = self.next_rand();
                }
                for (dst, src) in self.dpa_seed.chunks_exact_mut(8).zip(words.iter()) {
                    dst.copy_from_slice(&src.to_le_bytes());
                }
                0
            }
            SepOp::SeedDpa => 0,
            SepOp::SelfTest => 0, // pass
            SepOp::Dma => 0,
            SepOp::EraseInstall => 0,
            SepOp::Keystore => 0x1, // locked (research-scope)
            SepOp::Tty => 0,
            SepOp::Ool => 0,
            SepOp::Unknown(_) => 0x2,
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("STATUS", SEP_STATUS),
            ("CTRL_OP", SEP_CTRL_OP),
            ("ARG0", SEP_CTRL_ARG0),
            ("ARG1", SEP_CTRL_ARG1),
            ("ARG2", SEP_CTRL_ARG2),
            ("TTY_IN", SEP_TTY_IN),
            ("TTY_OUT", SEP_TTY_OUT),
        ]
    }
}

impl Default for SepSim {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for SepSim {
    fn name(&self) -> &'static str {
        "sep-sim"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SEP_STATUS => self.status as u64,
            SEP_CTRL_OP => self.last_op.code() as u64,
            SEP_CTRL_ARG0 => self.args[0] as u64,
            SEP_CTRL_ARG1 => self.args[1] as u64,
            SEP_CTRL_ARG2 => self.args[2] as u64,
            SEP_TTY_OUT => self.tty_out.pop().unwrap_or(0) as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            SEP_CTRL_OP => {
                let op = SepOp::from_code(val as u8);
                self.status = self.submit(op, self.args);
            }
            SEP_CTRL_ARG0 => self.args[0] = val as u32,
            SEP_CTRL_ARG1 => self.args[1] = val as u32,
            SEP_CTRL_ARG2 => self.args[2] = val as u32,
            SEP_TTY_IN => self.tty_in.push(val as u8),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_ops() {
        let mut s = SepSim::new();
        assert_eq!(s.submit(SepOp::SelfTest, [0; 3]), 0);
        assert_eq!(s.submit(SepOp::GenRandom, [0; 3]), 0);
        assert!(s.dpa_seed.iter().any(|&b| b != 0));
        assert_eq!(s.submit(SepOp::Keystore, [0; 3]), 0x1);
        assert_eq!(s.submit(SepOp::Unknown(0x77), [0; 3]), 0x2);
    }
}
