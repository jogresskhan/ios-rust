//! Apple UART — port of `hw/char/apple_uart.c`; this is the serial console the
//! lab16 glog files capture (restored/asr output on the guest side).

use crate::bus::{MMIODevice, W4};
use qemu_util::fifo::Fifo8;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct AppleUart {
    rx: Fifo8,
    tx: Fifo8,
    ctrl: u32,
}

/// Shared sink so the CLI can print the guest console live (glog equivalent).
pub type ConsoleSink = Arc<Mutex<Vec<u8>>>;

impl AppleUart {
    pub fn new() -> Self {
        Self { rx: Fifo8::new(1024), tx: Fifo8::new(1024), ctrl: 0 }
    }

    pub fn feed_input(&mut self, bytes: &[u8]) {
        let _ = self.rx.push_all(bytes);
    }

    pub fn attach_sink(_sink: &ConsoleSink) {
        // wiring point for the machine loop's console thread
    }
}

impl MMIODevice for AppleUart {
    fn name(&self) -> &'static str {
        "apple-uart"
    }
    fn size(&self) -> u64 {
        0x100
    }
    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            0x0 => self.rx.pop().unwrap_or(0) as u64, // UTXH/URXH window
            0x10 => {
                let status = (if self.tx.is_empty() { 1 << 0 } else { 0 })
                    | (if self.rx.is_empty() { 0 } else { 1 << 1 });
                status
            }
            0x20 => self.ctrl as u64,
            _ => 0,
        }
    }
    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            0x0 => {
                let _ = self.tx.push(value as u8); // engine taps this for the console log
            }
            0x20 => self.ctrl = value as u32,
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 55; // console path real; flow control/IRQ ladder pending

impl crate::bus::Device for AppleUart {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_collects_console() {
        let mut u = AppleUart::new();
        for b in b"Halo" {
            u.write(0x0, *b as u64, W4);
        }
        let mut s = String::new();
        while let Ok(b) = u.tx.pop() {
            s.push(b as char);
        }
        assert_eq!(s, "Halo");
    }
}
