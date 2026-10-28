//! spmi_baseband — Apple SPMI Baseband slave (port of hw/misc/
//! apple-silicon/spmi-baseband.c).
//!
//! Upstream is an **SPMI slave**: a flat 0xFFFF-byte register file with an
//! auto-advancing 16-bit address pointer. The master issues
//! `SPMI_CMD_EXT_READ`/`EXT_READL`/`EXT_WRITE`/`EXT_WRITEL` (those return
//! 0 = accepted, every other opcode returns 1 = rejected) which latches
//! the address; `send` streams write data at the pointer, `recv` streams
//! reads. Per the C comment, `AppleBasebandI19::spmiTimerCallback` only
//! ever touches offset **0x147** with value **0x2f** — the send path checks
//! that pair (the IRQ raise is commented out upstream, so this port only
//! records the line, never asserts it).
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! The SPMI protocol (command/send/recv) is exposed as public methods
//! mirroring the QEMU SPMISlaveClass callbacks; the flat [`Device`] view
//! maps offsets 0x0..0xFFFE directly onto the register file (offsets ≥
//! 0xFFFF are outside the file and count as unknown).

use vm_core::Device;

/// Register file size (`uint8_t reg[0xFFFF]` upstream).
pub const SBC_REG_FILE_SIZE: usize = 0xFFFF;

/// The only register the baseband timer callback touches.
pub const SBC_REG_MAGIC: u64 = 0x147;
/// Value written there by `AppleBasebandI19::spmiTimerCallback`.
pub const SBC_MAGIC_VALUE: u8 = 0x2f;

/// SPMI opcodes accepted by `apple_spmi_baseband_command`
/// (values from hw/spmi/spmi.h).
pub const SPMI_CMD_EXT_WRITE: u8 = 0x00;
pub const SPMI_CMD_EXT_READ: u8 = 0x20;
pub const SPMI_CMD_EXT_WRITEL: u8 = 0x30;
pub const SPMI_CMD_EXT_READL: u8 = 0x38;

/// Apple SPMI Baseband (port of `AppleSPMIBasebandState`).
pub struct SpmiBaseband {
    /// Flat slave register file.
    pub reg: Vec<u8>,
    /// Auto-advancing address pointer (`uint16_t addr`).
    pub addr: u16,
    /// `qemu_irq` GPIO output; upstream never raises it (the check is
    /// commented out) — kept as plain line state for board wiring.
    pub irq: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl SpmiBaseband {
    pub fn new() -> Self {
        SpmiBaseband {
            reg: vec![0; SBC_REG_FILE_SIZE],
            addr: 0,
            irq: false,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Port of `apple_spmi_baseband_set_irq` (line state only; the board
    /// routes the GPIO output).
    pub fn set_irq(&mut self, value: bool) {
        self.irq = value;
    }

    /// Port of `apple_spmi_baseband_command`: latch the transfer address.
    /// Returns 0 for the EXT_* opcodes (accepted), 1 otherwise.
    pub fn spmi_command(&mut self, opcode: u8, addr: u16) -> i32 {
        self.addr = addr;
        match opcode {
            SPMI_CMD_EXT_READ | SPMI_CMD_EXT_READL | SPMI_CMD_EXT_WRITE | SPMI_CMD_EXT_WRITEL => 0,
            _ => 1,
        }
    }

    /// Port of `apple_spmi_baseband_send`: write `data` at the pointer and
    /// advance it. Returns the number of bytes consumed (= `data.len()`).
    pub fn spmi_send(&mut self, data: &[u8]) -> usize {
        let mut addr = self.addr as usize;
        for byte in data {
            if addr < SBC_REG_FILE_SIZE {
                self.reg[addr] = *byte;
            }
            addr += 1;
        }
        if self.addr == SBC_REG_MAGIC as u16 && self.reg[self.addr as usize] == SBC_MAGIC_VALUE {
            // "is this interrupt actually affecting anything?" — upstream
            // leaves the raise commented out, so we do not assert the line.
        }
        self.addr = addr as u16;
        data.len()
    }

    /// Port of `apple_spmi_baseband_recv`: read into `data` at the pointer
    /// and advance it. Returns the number of bytes produced.
    pub fn spmi_recv(&mut self, data: &mut [u8]) -> usize {
        let mut addr = self.addr as usize;
        for byte in data.iter_mut() {
            *byte = if addr < SBC_REG_FILE_SIZE { self.reg[addr] } else { 0 };
            addr += 1;
        }
        self.addr = addr as u16;
        data.len()
    }
}

impl Default for SpmiBaseband {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for SpmiBaseband {
    fn name(&self) -> &'static str {
        "apple-spmi-baseband"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if (off as usize) < SBC_REG_FILE_SIZE {
            return self.reg[off as usize] as u64;
        }
        self.unknown_reads += 1;
        0
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if (off as usize) < SBC_REG_FILE_SIZE {
            self.reg[off as usize] = val as u8;
            return;
        }
        self.unknown_writes += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_reg_and_spmi_transfer() {
        let mut d = SpmiBaseband::new();
        // Register-file roundtrip on the magic register.
        d.write(SBC_REG_MAGIC, 1, SBC_MAGIC_VALUE as u64);
        assert_eq!(d.read(SBC_REG_MAGIC, 1), SBC_MAGIC_VALUE as u64);

        // SPMI EXT_WRITEL stream at 0x147 writing the magic value.
        assert_eq!(d.spmi_command(SPMI_CMD_EXT_WRITEL, 0x147), 0);
        assert_eq!(d.spmi_send(&[SBC_MAGIC_VALUE]), 1);
        assert_eq!(d.addr, 0x148); // pointer advanced past the write
        assert_eq!(d.reg[0x147], SBC_MAGIC_VALUE);

        // SPMI EXT_READL reads it back through the pointer.
        assert_eq!(d.spmi_command(SPMI_CMD_EXT_READL, 0x147), 0);
        let mut buf = [0u8; 1];
        assert_eq!(d.spmi_recv(&mut buf), 1);
        assert_eq!(buf[0], SBC_MAGIC_VALUE);
        assert_eq!(d.addr, 0x148);

        // Unsupported opcode (e.g. SPMI_CMD_RESET = 0x10) is rejected.
        assert_eq!(d.spmi_command(0x10, 0x0), 1);
    }

    #[test]
    fn unknown_offsets_counted() {
        let mut d = SpmiBaseband::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        // Beyond the 0xFFFF register file.
        assert_eq!(d.read(0x1_FFFF, 1), 0);
        assert_eq!(d.unknown_reads, 1);
        d.write(0x1_FFFF, 1, 0xAA);
        assert_eq!(d.unknown_writes, 1);
        // In-file offsets never touch the counters.
        d.write(0x42, 1, 0x7);
        assert_eq!(d.read(0x42, 1), 0x7);
        assert_eq!(d.unknown_reads, 1);
        assert_eq!(d.unknown_writes, 1);
        // The IRQ line stays low (upstream never raises it).
        assert!(!d.irq);
    }
}
