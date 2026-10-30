//! s3c_uart — Samsung S3C UART as integrated on Apple SoCs (console).
//! Port of Inferno `t8030_create_s3c_uart` + hw/char s3c model semantics.
//! TX bytes stream into a shared sink the frontend drains — the boot
//! serial console the user watches.

use std::sync::{Arc, Mutex};
use vm_core::Device;

/// RAM ceiling for the shared console sink (bytes). The sink used to be an
/// unbounded `Vec<u8>`: a kernel panic loop that re-prints its banner every
/// iteration keeps growing it for as long as the instruction budget runs —
/// on a long session that alone can fill host RAM (the "session OOM" bug).
/// 1 MiB of tail is orders of magnitude more than any boot report needs.
pub const CONSOLE_SINK_CAP: usize = 1 << 20;
/// Trim slack: the sink grows to CAP + SLACK before being cut back to CAP,
/// so a print storm pays one memmove per SLACK bytes instead of one per byte.
const CONSOLE_SINK_SLACK: usize = CONSOLE_SINK_CAP / 4;

/// Console bytes dropped by the cap (process-wide, for the boot report).
pub fn console_dropped_bytes() -> u64 {
    CONSOLE_DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

static CONSOLE_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub const ULCON: u64 = 0x0000;
pub const UCON: u64 = 0x0004;
pub const UFCON: u64 = 0x0008;
pub const UTRSTAT: u64 = 0x0010;
pub const UTXH: u64 = 0x0020;
pub const URXH: u64 = 0x0024;
pub const UBRDIV: u64 = 0x0028;

pub struct S3cUart {
    id: u32,
    pub sink: Arc<Mutex<Vec<u8>>>,
    rx: Vec<u8>,
    pub baud_div: u32,
    pub unknown_reads: u64,
}

impl S3cUart {
    pub fn new(id: u32, sink: Arc<Mutex<Vec<u8>>>) -> Self {
        S3cUart { id, sink, rx: Vec::new(), baud_div: 0, unknown_reads: 0 }
    }

    /// Host-side: feed guest RX (usbmux/keyboard).
    pub fn rx_push(&mut self, b: u8) {
        self.rx.push(b);
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("ULCON", ULCON),
            ("UCON", UCON),
            ("UFCON", UFCON),
            ("UTRSTAT", UTRSTAT),
            ("UTXH", UTXH),
            ("URXH", URXH),
            ("UBRDIV", UBRDIV),
        ]
    }
}

impl Device for S3cUart {
    fn name(&self) -> &'static str {
        "s3c-uart"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            ULCON => 0x3,      // 8N1
            UCON => 0x5,       // tx/rx enable
            UFCON => 0x7,      // fifo on
            UTRSTAT => 0x6,    // tx empty + tx buf empty (guest can always send)
            URXH => self.rx.first().copied().unwrap_or(0) as u64,
            UBRDIV => self.baud_div as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            UTXH => {
                if let Ok(mut s) = self.sink.lock() {
                    s.push((val & 0xFF) as u8);
                    if s.len() >= CONSOLE_SINK_CAP + CONSOLE_SINK_SLACK {
                        let excess = s.len() - CONSOLE_SINK_CAP;
                        s.drain(..excess);
                        CONSOLE_DROPPED.fetch_add(excess as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            URXH => {
                if !self.rx.is_empty() {
                    self.rx.remove(0);
                }
            }
            UBRDIV => self.baud_div = (val & 0xFFFF) as u32,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tx_streams_to_sink() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut u = S3cUart::new(0, sink.clone());
        u.write(UTXH, 1, b'X' as u64);
        u.write(UTXH, 1, b'Y' as u64);
        assert_eq!(&*sink.lock().unwrap(), b"XY");
    }

    #[test]
    fn sink_is_bounded_under_print_storms() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut u = S3cUart::new(0, sink.clone());
        // 3 MiB of guest console spam must not grow the sink past cap+slack.
        let n = 3 * CONSOLE_SINK_CAP;
        for i in 0..n {
            u.write(UTXH, 1, (i & 0xFF) as u64);
        }
        let len = sink.lock().unwrap().len();
        assert!(
            len <= CONSOLE_SINK_CAP + CONSOLE_SINK_SLACK,
            "sink grew to {len}"
        );
        assert!(console_dropped_bytes() >= (n - CONSOLE_SINK_CAP - CONSOLE_SINK_SLACK) as u64);
        // the newest bytes survive — the tail is what the report shows
        let tail = sink.lock().unwrap().clone();
        assert_eq!(tail[tail.len() - 1], ((n - 1) & 0xFF) as u8);
    }
}
