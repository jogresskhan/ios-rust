//! spmi_pmu — SPMI bus controller + Apple PMU slave (port of Inferno
//! hw/misc/apple-silicon/spmi-pmu.c + t8030_create_spmi/pmu).
//! SPMI command decode → register-file PMU with ADC, gpio, keepalive.

use vm_core::Device;

pub const SPMI_STATUS: u64 = 0x0000;
pub const SPMI_CMD: u64 = 0x0004;
pub const SPMI_RSP0: u64 = 0x0008;
pub const SPMI_RSP1: u64 = 0x000C;
pub const SPMI_RSP2: u64 = 0x0010;

/// SPMI command encodings (port of C macros):
const CMD_EXT_WRITE: u8 = 0x00;
const CMD_RESET: u8 = 0x10;
const CMD_SLEEP: u8 = 0x11;
const CMD_WAKEUP: u8 = 0x12;
const CMD_AUTH: u8 = 0x13;
const CMD_MASTER_READ: u8 = 0x14;
const CMD_PAGE_ZERO: u8 = 0x60; // 0x60..=0x6F read reg
const CMD_EXT_READ: u8 = 0x20; // 0x20 | addr<<8
const CMD_REG_WRITE: u8 = 0xA0; // 0xA0..=0xAF write reg

/// The PMU slave register file (page 0 readable over SPMI).
pub struct PmuSlave {
    pub regs: [u8; 256],
    pub adc_mv: [u16; 8],
}

impl PmuSlave {
    pub fn new() -> Self {
        let mut r = PmuSlave { regs: [0; 256], adc_mv: [4000, 1500, 850, 1800, 3000, 1200, 900, 500] };
        // deterministic identity: pmu type + firmware marker
        r.regs[0] = 0xB0; // PMU SFE version
        r.regs[1] = 0x02;
        r.regs[0x31] = 0x1; // charging status
        r
    }
}

impl Default for PmuSlave {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SpmiPmu {
    pub slave: PmuSlave,
    rsp: [u8; 3],
    pub unknown_reads: u64,
}

impl SpmiPmu {
    pub fn new() -> Self {
        SpmiPmu { slave: PmuSlave::new(), rsp: [0; 3], unknown_reads: 0 }
    }

    fn execute(&mut self, cmd: u32) {
        let b = (cmd & 0xFF) as u8;
        match b {
            CMD_RESET | CMD_SLEEP | CMD_WAKEUP | CMD_AUTH | CMD_MASTER_READ => {}
            b if (CMD_PAGE_ZERO..CMD_PAGE_ZERO + 0x10).contains(&b) => {
                // read one reg at addr (enc in upper bits per SPMI spec)
                let addr = ((b - CMD_PAGE_ZERO) as usize) & 0xFF;
                let v = self.slave.regs[addr];
                self.rsp = [v, 0, 0];
            }
            b if b == CMD_EXT_READ => {
                let addr = ((cmd >> 8) & 0xFF) as usize;
                let v = self.slave.regs.get(addr).copied().unwrap_or(0);
                self.rsp = [v, 0, 0];
            }
            b if (CMD_REG_WRITE..CMD_REG_WRITE + 0x10).contains(&b) => {
                let addr = (b - CMD_REG_WRITE) as usize;
                let val = ((cmd >> 8) & 0xFF) as u8;
                self.slave.regs[addr] = val;
            }
            CMD_EXT_WRITE => {
                let addr = ((cmd >> 8) & 0xFF) as usize;
                let val = ((cmd >> 16) & 0xFF) as u8;
                if addr < 256 {
                    self.slave.regs[addr] = val;
                }
            }
            _ => {}
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("STATUS", SPMI_STATUS),
            ("CMD", SPMI_CMD),
            ("RSP0", SPMI_RSP0),
            ("RSP1", SPMI_RSP1),
            ("RSP2", SPMI_RSP2),
        ]
    }
}

impl Default for SpmiPmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for SpmiPmu {
    fn name(&self) -> &'static str {
        "spmi-pmu"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SPMI_STATUS => 0x1, // ready
            SPMI_RSP0 => self.rsp[0] as u64,
            SPMI_RSP1 => self.rsp[1] as u64,
            SPMI_RSP2 => self.rsp[2] as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == SPMI_CMD {
            self.execute(val as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_write_reg() {
        let mut d = SpmiPmu::new();
        let w = CMD_EXT_WRITE as u32 | (0x41 << 8) | (0xAB << 16);
        d.write(SPMI_CMD, 4, w as u64);
        let r = CMD_EXT_READ as u32 | (0x41 << 8);
        d.write(SPMI_CMD, 4, r as u64);
        assert_eq!(d.read(SPMI_RSP0, 1), 0xAB);
    }
}
