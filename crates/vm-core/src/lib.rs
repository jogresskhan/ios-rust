//! vm-core — the foundation every ios-rust device and CPU backend builds on.
//!
//! Faithful Rust port of the QEMU device-model contract (MemoryRegion /
//! SysBusDevice) reduced to what the T8030 machine needs:
//! one flat physical bus, MMIO devices, IRQ lines, RAM regions and a
//! shared framebuffer the guest can paint into.

pub mod bus;
pub mod framebuffer;
pub mod irq;

pub use bus::{Bus, Ram};
pub use framebuffer::FrameBuffer;
pub use irq::IrqState;

/// A device on the T8030 physical bus (QEMU MemoryRegion equivalent).
///
/// Offsets are relative to the region base assigned by [`Bus::attach`].
/// `size` is 1, 2, 4 or 8 bytes; devices must tolerate any width and
/// ignore unsupported ones exactly like QEMU's `valid.min_access_size`
/// / `max_access_size` pair collapses to "store what fits".
pub trait Device: Send {
    fn name(&self) -> &'static str;

    /// MMIO read at region-relative offset.
    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = (off, size);
        0
    }

    /// MMIO write at region-relative offset.
    fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = (off, size, val);
    }

    /// Periodic callback (timers, fifos, vblank...).
    fn tick(&mut self, now_ns: u64) {
        let _ = now_ns;
    }

    /// RAM regions expose their bytes for bulk DMA/CPU loads.
    fn ram_mut(&mut self) -> Option<&mut Vec<u8>> {
        None
    }
}

/// A device that wants to observe the whole bus (DMA, IOMMU walkers).
pub trait DmaDevice: Device {
    /// Perform a DMA read against the platform bus (post-IOMMU translation
    /// is the device's responsibility via its DART).
    fn dma_read(&mut self, bus: &mut Bus, addr: u64, buf: &mut [u8]) {
        bus.read_raw(addr, buf);
    }
    fn dma_write(&mut self, bus: &mut Bus, addr: u64, data: &[u8]) {
        bus.write_raw(addr, data);
    }
}
