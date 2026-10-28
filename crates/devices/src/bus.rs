//! Device trait layer — the Rust equivalent of `MemoryRegionOps` + device init.

use qemu_util::queue::DeviceQueue;

/// A memory-mapped device: read/write dispatch at MMIO widths the Apple
/// peripherals actually use (1/4/8). `size` is the MMIO region length.
pub trait MMIODevice {
    fn name(&self) -> &'static str;
    fn size(&self) -> u64;

    fn read(&mut self, offset: u64, width: u32) -> u64;
    fn write(&mut self, offset: u64, value: u64, width: u32);
}

/// Common shell for devices that raise IRQs into the AIC.
pub trait Device {
    fn mmio(&mut self) -> &mut dyn MMIODevice;
    /// IRQ lines asserted toward the AIC (index, level).
    fn irqs(&self) -> Vec<(u32, bool)> {
        Vec::new()
    }
    /// Per-device parity weight (0-100) for the PARITY ledger feed.
    fn parity_pct(&self) -> u8;
}

/// The machine's address-decoded bus.
#[derive(Default)]
pub struct Bus {
    pub devices: DeviceQueue<Box<dyn MMIODevice + Send>>,
}

impl Bus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach(&mut self, base: u64, dev: Box<dyn MMIODevice + Send>) {
        self.devices.insert_tail(base, dev);
    }

    /// One MMIO access from the CPU: dispatch to the containing device.
    pub fn mmio_read(&mut self, addr: u64, width: u32) -> u64 {
        match self.devices.find_base_containing(addr, |d| d.size()) {
            Some(base) => self
                .devices
                .get_mut(base)
                .expect("base just found")
                .read(addr - base, width),
            None => 0, // unassigned RAZ — Inferno logs these; keep silent here
        }
    }

    pub fn mmio_write(&mut self, addr: u64, value: u64, width: u32) {
        if let Some(base) = self.devices.find_base_containing(addr, |d| d.size()) {
            self.devices
                .get_mut(base)
                .expect("base just found")
                .write(addr - base, value, width);
        }
    }
}

/// Widths as MemoryRegionOps defines them.
pub const W1: u32 = 8;
pub const W4: u32 = 32;
pub const W8: u32 = 64;
