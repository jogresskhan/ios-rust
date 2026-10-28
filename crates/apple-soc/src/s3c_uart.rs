//! s3c_uart — Samsung S3C UART as integrated on Apple SoCs (console).
//! Port of Inferno `t8030_create_s3c_uart` + hw/char s3c model semantics.
//! TX bytes stream into a shared sink the frontend drains — the boot
//! serial console the user watches.

use std::sync::{Arc, Mutex};
use vm_core::Device;

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
}
