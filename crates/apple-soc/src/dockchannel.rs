//! dockchannel — Apple DockChannel UART (T8030 `/arm-io/dockchannel-uart`).
//!
//! Replaces the s3c-uart mis-model (attach-spec row 29 / §5.1): the node has
//! no `compatible`, `device_type="dockchannel"`, and TWO reg windows —
//! w0 `0x23D128000+0x10000` (config/IRQ page) and w1 `0x23D10C000+0x1000`
//! (FIFO page). It is the AOP-side dock/debug serial channel; the boot
//! console is uart0.
//!
//! **Measured upgrade over spec §5.1:** the spec (written pre-session-M)
//! assumed zero touches and prescribed RAZ. The first 48M-insn live census
//! (session N, `mmio-48m.log`) shows the kernel DOES touch w1 early — 8
//! accesses, `w,r` pairs at offsets 0x0/0x4/0x8/0xC. A pure-RAZ read would
//! break any config write-then-readback the driver does, so this model is a
//! **scratch R/W shim**: writes are stored per offset (and bytes pushed to a
//! dedicated sink for the FIFO-looking w1 low page), reads return the stored
//! word (0 if never written). No FIFO/IRQ/clock semantics — nothing measured
//! requires them yet. TX bytes go to a DEDICATED sink, never the console.
//!
//! Two [`DockChannelWindow`] boxes share one [`DockChannelCore`] via Arc so a
//! single logical device spans both windows (mirrors the pmgr 44-window
//! shape, attach-spec §4.2).

use std::sync::{Arc, Mutex};
use vm_core::Device;

/// Scratch core shared by both windows.
pub struct DockChannelCore {
    /// window-relative offset → last written word (0 = default read)
    scratch: std::collections::BTreeMap<u64, u32>,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
    /// Dedicated sink (NOT the console sink) — w1 FIFO-page byte writes land
    /// here so a later session can mine dockchannel debug output.
    pub sink: Arc<Mutex<Vec<u8>>>,
}

impl DockChannelCore {
    fn new(sink: Arc<Mutex<Vec<u8>>>) -> Self {
        DockChannelCore {
            scratch: std::collections::BTreeMap::new(),
            unknown_reads: 0,
            unknown_writes: 0,
            sink,
        }
    }

    fn read(&mut self, off: u64) -> u64 {
        match self.scratch.get(&off) {
            Some(v) => *v as u64,
            None => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, off: u64, val: u64, fifo_page: bool) {
        if fifo_page {
            // w1 low page = the FIFO data aperture (measured w/r pairs at
            // 0x0..0xC); every byte written there is TX output.
            if let Ok(mut s) = self.sink.lock() {
                for shift in [0, 8, 16, 24] {
                    let b = ((val >> shift) & 0xFF) as u8;
                    if b != 0 {
                        s.push(b);
                    }
                }
            }
        }
        self.scratch.insert(off, (val & 0xFFFF_FFFF) as u32);
        self.unknown_writes += 1;
    }
}

/// One bus window. `lin` is the byte offset of THIS window inside the node's
/// concatenated reg map (w0 → 0, w1 → 0x10000) so both windows see one
/// contiguous scratch space, exactly like the kernel's own two mappings.
/// Clone = another box over the SAME shared core (multi-window attach).
#[derive(Clone)]
pub struct DockChannelWindow {
    core: Arc<Mutex<DockChannelCore>>,
    lin: u64,
    fifo_page: bool,
}

impl DockChannelWindow {
    pub fn name(&self) -> &'static str {
        "dockchannel"
    }
}

impl Device for DockChannelWindow {
    fn name(&self) -> &'static str {
        "dockchannel"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        self.core.lock().unwrap().read(self.lin + off)
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        self.core.lock().unwrap().write(self.lin + off, val, self.fifo_page)
    }
}

/// Build the shared state + two window boxes for one dockchannel-uart node.
/// Order: (w0 config page box, w1 FIFO page box, sink).
pub fn new_pair(sink: Arc<Mutex<Vec<u8>>>) -> (DockChannelWindow, DockChannelWindow, Arc<Mutex<Vec<u8>>>) {
    let core = Arc::new(Mutex::new(DockChannelCore::new(sink.clone())));
    let w0 = DockChannelWindow { core: core.clone(), lin: 0, fifo_page: false };
    let w1 = DockChannelWindow { core, lin: 0x10000, fifo_page: true };
    (w0, w1, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    #[test]
    fn scratch_readback_and_dedicated_sink() {
        let sink = StdArc::new(StdMutex::new(Vec::new()));
        let (mut w0, mut w1, shared) = new_pair(sink.clone());
        // w1 config-style write + readback (scratch semantics — measured
        // w,r pairs at w1 offsets 0x0/0x4/0x8/0xC). 0x000000EE keeps the
        // FIFO-sink byte count predictable for the assert below.
        w1.write(0x0, 4, 0xEE);
        assert_eq!(w1.read(0x0, 4), 0xEE);
        // w0 and w1 share one core over CONCATENATED offsets: w1.write(0x8)
        // lands at concat 0x10000+0x8; w0 (lin=0) reads that same address.
        w1.write(0x8, 4, 0x11);
        assert_eq!(w0.read(0x10000 + 0x8, 4), 0x11);
        // never-written offset reads 0 (counted, not an abort).
        assert_eq!(w0.read(0x1234, 4), 0);
        // FIFO bytes land in the DEDICATED sink only: every w1 write pushes
        // its non-zero bytes (0xEE, then 0x11 from the scratch write, then x).
        w1.write(0x0, 4, b'x' as u64);
        assert_eq!(&*shared.lock().unwrap(), &[0xEE, 0x11, b'x']);
    }
}
