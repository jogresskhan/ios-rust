//! tempsensor — Apple Temp Sensor (port of hw/misc/apple-silicon/
//! tempsensor.c).
//!
//! Upstream is a SysBus MMIO device whose register handlers are empty
//! stubs: `reg_read` returns the fill value `0xAFAFAFAF` for **every**
//! offset (the `default:` arm of an otherwise empty switch) and `reg_write`
//! discards everything. The MMIO region size and the IRQ routing come from
//! the ADT node at board-setup time; the IRQ line is never driven by the
//! model itself (kept here as a boolean line state).
//! The QEMU `MemoryRegionOps` restricts accesses to 32-bit words
//! (`valid/impl.min_access_size = max_access_size = 4`, `unaligned = false`);
//! this port mirrors that by counting any non-4-byte access as an unknown
//! (rejected) access.
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.

use vm_core::Device;

/// Fill value returned by every word-sized read (`0xAFAFAFAF` upstream).
pub const TEMPSENSOR_FILL: u64 = 0xAFAFAFAF;

/// QEMU `valid/impl.min_access_size` (and max): word accesses only.
pub const MMIO_ACCESS_SIZE: u8 = 4;

/// Apple Temp Sensor (port of `AppleTempSensorState`).
pub struct TempSensor {
    /// `qemu_irq` line reserved via `sysbus_init_irq` — never driven
    /// upstream; kept as plain line state for board wiring.
    pub irq: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl TempSensor {
    pub fn new() -> Self {
        TempSensor { irq: false, unknown_reads: 0, unknown_writes: 0 }
    }
}

impl Default for TempSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for TempSensor {
    fn name(&self) -> &'static str {
        "apple-temp-sensor"
    }
    fn read(&mut self, _off: u64, size: u8) -> u64 {
        if size == MMIO_ACCESS_SIZE {
            // Empty switch → default arm: 0xAFAFAFAF for every offset.
            return TEMPSENSOR_FILL;
        }
        // QEMU would reject the access (valid.max/min_access_size = 4).
        self.unknown_reads += 1;
        0
    }
    fn write(&mut self, _off: u64, size: u8, _val: u64) {
        if size != MMIO_ACCESS_SIZE {
            self.unknown_writes += 1;
        }
        // Word writes are silently discarded (empty write handler).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_value_on_word_reads() {
        let mut d = TempSensor::new();
        // Every offset returns the same fill value (stub `default:` arm).
        assert_eq!(d.read(0x0000, 4), TEMPSENSOR_FILL);
        assert_eq!(d.read(0x1234, 4), TEMPSENSOR_FILL);
        assert_eq!(d.read(u64::MAX - 4, 4), TEMPSENSOR_FILL);
        // Writes are discarded without error and without side effects.
        d.write(0x0000, 4, 0xFFFF_FFFF);
        d.write(0x0048, 4, 0);
        assert_eq!(d.unknown_writes, 0);
        // IRQ line is reserved but never asserted by the model.
        assert!(!d.irq);
    }

    #[test]
    fn subword_access_counts_unknown() {
        let mut d = TempSensor::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        // Sub-word / over-word accesses violate the QEMU valid-access
        // constraints (4 bytes only) → counted as unknown/rejected.
        assert_eq!(d.read(0x0, 1), 0);
        assert_eq!(d.read(0x0, 2), 0);
        assert_eq!(d.read(0x0, 8), 0);
        assert_eq!(d.unknown_reads, 3);
        d.write(0x0, 1, 0xFF);
        assert_eq!(d.unknown_writes, 1);
        // Word accesses never touch the counters.
        let _ = d.read(0x0, 4);
        d.write(0x0, 4, 1);
        assert_eq!(d.unknown_reads, 3);
        assert_eq!(d.unknown_writes, 1);
    }
}
