//! s3c-uart — Apple Samsung S5L UART (the T8030 "s3c uart").
//!
//! Faithful Rust port of ChefKiss Inferno `hw/char/apple_uart.c`
//! (AGPL-3.0, © 2025-2026 Visual Ehrmanntraut). The register map,
//! reset values, FIFO semantics, trigger levels and the (upstream!)
//! quirk that UCON writes are never stored are all preserved.
//!
//! Machine wiring (t8030.c `t8030_create_s3c_uart`): base
//! `arm-io/uart0.reg[0] + reg[1] * port`, fifo size 15, channel 0.
//!
//! Host-side chardev replacement: UTXH writes append to
//! [`AppleUart::serial_out`] and raise [`AppleUart::serial_out_flag`];
//! guests receive input via [`AppleUart::rx_push`].

use std::collections::VecDeque;

use vm_core::Device;

// Offsets for UART registers relative to SFR base address for UARTn.
pub const ULCON: u64 = 0x0000; // Line Control
pub const UCON: u64 = 0x0004; // Control
pub const UFCON: u64 = 0x0008; // FIFO Control
pub const UMCON: u64 = 0x000C; // Modem Control
pub const UTRSTAT: u64 = 0x0010; // Tx/Rx Status
pub const UERSTAT: u64 = 0x0014; // UART Error Status
pub const UFSTAT: u64 = 0x0018; // FIFO Status
pub const UMSTAT: u64 = 0x001C; // Modem Status
pub const UTXH: u64 = 0x0020; // Transmit Buffer
pub const URXH: u64 = 0x0024; // Receive Buffer
pub const UBRDIV: u64 = 0x0028; // Baud Rate Divisor
pub const UFRACVAL: u64 = 0x002C; // Divisor Fractional Value

pub const APPLE_UART_REGS_MEM_SIZE: u64 = 0x3C;
const REG_WORDS: usize = (APPLE_UART_REGS_MEM_SIZE / 4) as usize;

// UART Control
pub const UCON_TXTHRESH_ENA: u32 = 1 << 13;
pub const UCON_RXTHRESH_ENA: u32 = 1 << 12;
pub const UCON_RXERR_ENA: u32 = 1 << 11;
pub const UCON_RXTIMEOUT_ENA: u32 = 1 << 9;
pub const UCON_TXMODE: u32 = 3 << 2;
pub const UCON_TXMODE_DMA: u32 = 3 << 2;
pub const UCON_TXMODE_IRQ: u32 = 1 << 2;
pub const UCON_RXMODE: u32 = 3 << 0;
pub const UCON_RXMODE_DMA: u32 = 3 << 0;
pub const UCON_RXMODE_IRQ: u32 = 1 << 0;

// UART FIFO Control
pub const UFCON_FIFO_ENABLE: u32 = 1 << 0;
pub const UFCON_RX_FIFO_RESET: u32 = 1 << 1;
pub const UFCON_TX_FIFO_RESET: u32 = 1 << 2;
pub const UFCON_TX_FIFO_TRIGGER_LEVEL_SHIFT: u32 = 6;
pub const UFCON_TX_FIFO_TRIGGER_LEVEL: u32 = 3 << UFCON_TX_FIFO_TRIGGER_LEVEL_SHIFT;
pub const UFCON_RX_FIFO_TRIGGER_LEVEL_SHIFT: u32 = 4;
pub const UFCON_RX_FIFO_TRIGGER_LEVEL: u32 = 3 << UFCON_RX_FIFO_TRIGGER_LEVEL_SHIFT;

// UART FIFO Status
pub const UFSTAT_RX_FIFO_COUNT: u32 = 0xf;
pub const UFSTAT_RX_FIFO_FULL: u32 = 1 << 8;
pub const UFSTAT_TX_FIFO_COUNT_SHIFT: u32 = 4;
pub const UFSTAT_TX_FIFO_COUNT: u32 = 0xf << UFSTAT_TX_FIFO_COUNT_SHIFT;
pub const UFSTAT_TX_FIFO_FULL: u32 = 1 << 9;

// UART Tx/Rx Status
pub const UTRSTAT_RX_TIMEOUT: u32 = 1 << 3;
pub const UTRSTAT_TX_THRESH: u32 = 1 << 5;
pub const UTRSTAT_RX_THRESH: u32 = 1 << 4;
pub const UTRSTAT_TX_EMPTY: u32 = 1 << 2;
pub const UTRSTAT_TX_BUFFER_EMPTY: u32 = 1 << 1;
pub const UTRSTAT_RX_BUFFER_DATA_READY: u32 = 1 << 0;

// UART Error Status
pub const UERSTAT_OVERRUN: u32 = 0x1;
pub const UERSTAT_PARITY: u32 = 0x2;
pub const UERSTAT_FRAME: u32 = 0x4;
pub const UERSTAT_BREAK: u32 = 0x8;

/// apple-silicon `t8030_create_s3c_uart` fifo size.
pub const T8030_UART_FIFO_SIZE: usize = 15;
const DEFAULT_UCLK_RATE: u64 = 24_000_000;

/// Apple S5L UART (one instance per port; t8030 instantiates 5).
#[derive(Debug)]
pub struct AppleUart {
    /// UART channel (trigger-level scale differs per channel). T8030
    /// always uses channel 0.
    pub channel: u32,
    /// Register file indexed like the C's `reg[I_(offset)]`.
    reg: [u32; REG_WORDS],
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    pub rx_fifo_size: usize,
    pub tx_fifo_size: usize,
    last_irq: u32,
    /// Bytes written by the guest to UTXH since the last `take_serial_out`.
    pub serial_out: Vec<u8>,
    /// Set when new bytes landed in `serial_out`; cleared by
    /// [`AppleUart::take_serial_out`].
    pub serial_out_flag: bool,
    /// word time in ns (C `wordtime`).
    pub wordtime: u64,
    now_ns: u64,
    rx_timeout_deadline: Option<u64>,
    pub irq_level: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

fn idx(offset: u64) -> usize {
    (offset / 4) as usize
}

impl AppleUart {
    /// `apple_uart_create(addr, 15, 0, chr, irq)` for every T8030 port.
    pub fn new_t8030() -> Self {
        Self::new(0, T8030_UART_FIFO_SIZE, T8030_UART_FIFO_SIZE)
    }

    pub fn new(channel: u32, rx_fifo_size: usize, tx_fifo_size: usize) -> Self {
        // C realize: rx/tx-size must be < 16 (UFSTAT encodes 4 bits).
        let rx_fifo_size = rx_fifo_size.min(15);
        let tx_fifo_size = tx_fifo_size.min(15);
        let mut u = AppleUart {
            channel,
            reg: [0; REG_WORDS],
            rx: VecDeque::with_capacity(rx_fifo_size),
            tx: VecDeque::with_capacity(tx_fifo_size),
            rx_fifo_size,
            tx_fifo_size,
            last_irq: 0,
            serial_out: Vec::new(),
            serial_out_flag: false,
            wordtime: 1_000_000_000 * 10 / 115_200, // C instance_init
            now_ns: 0,
            rx_timeout_deadline: None,
            irq_level: false,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        u.reset();
        u
    }

    /// `apple_uart_reset`: program the documented reset values.
    pub fn reset(&mut self) {
        self.reg = [0; REG_WORDS];
        self.reg[idx(UTRSTAT)] = 0x0000_0006; // TX_EMPTY | TX_BUFFER_EMPTY
        self.reg[idx(UTXH)] = 0x5c5c_5c5c; // WO, undefined reset value
        self.rx.clear();
        self.tx.clear();
        self.last_irq = 0;
    }

    /// `apple_uart_FIFO_trigger_level` (channel-dependent scale).
    fn fifo_trigger_level(&self, reg: u32) -> u32 {
        match self.channel {
            0 => reg * 32,
            1 | 4 => reg * 8,
            2 | 3 => reg * 2,
            _ => 0,
        }
    }

    fn tx_fifo_trigger_level(&self) -> u32 {
        let reg = (self.reg[idx(UFCON)] & UFCON_TX_FIFO_TRIGGER_LEVEL)
            >> UFCON_TX_FIFO_TRIGGER_LEVEL_SHIFT;
        self.fifo_trigger_level(reg)
    }

    fn rx_fifo_trigger_level(&self) -> u32 {
        // The C adds 1 to the register field before scaling.
        let reg = ((self.reg[idx(UFCON)] & UFCON_RX_FIFO_TRIGGER_LEVEL)
            >> UFCON_RX_FIFO_TRIGGER_LEVEL_SHIFT)
            + 1;
        self.fifo_trigger_level(reg)
    }

    /// `apple_uart_update_irq`.
    fn update_irq(&mut self) {
        let mut mask = UTRSTAT_RX_BUFFER_DATA_READY;
        if self.reg[idx(UFCON)] & UFCON_FIFO_ENABLE != 0 {
            let count = self.tx.len() as u32;

            if self.reg[idx(UCON)] & UCON_TXTHRESH_ENA != 0 {
                mask |= UTRSTAT_TX_THRESH | UTRSTAT_TX_EMPTY | UTRSTAT_TX_BUFFER_EMPTY;
                if count <= self.tx_fifo_trigger_level()
                    && self.last_irq & UTRSTAT_TX_THRESH == 0
                {
                    self.reg[idx(UTRSTAT)] |= UTRSTAT_TX_THRESH;
                }
            }

            let count = self.rx.len() as u32;
            if self.reg[idx(UCON)] & UCON_RXTHRESH_ENA != 0 {
                mask |= UTRSTAT_RX_THRESH;
                if count >= self.rx_fifo_trigger_level() {
                    self.reg[idx(UTRSTAT)] |= UTRSTAT_RX_THRESH;
                    self.rx_timeout_deadline = None;
                }
            }

            if self.reg[idx(UCON)] & UCON_RXTIMEOUT_ENA != 0 {
                mask |= UTRSTAT_RX_TIMEOUT;
            }
        }

        if self.reg[idx(UTRSTAT)] & mask != 0 {
            self.last_irq = self.reg[idx(UTRSTAT)] & mask;
            self.irq_level = true;
        } else {
            self.irq_level = false;
        }
    }

    /// `apple_uart_rx_timeout_set`.
    fn rx_timeout_set(&mut self) {
        if self.reg[idx(UCON)] & UCON_RXTIMEOUT_ENA != 0 {
            let timeout = ((self.reg[idx(UCON)] >> 12) & 0x0f) as u64 * self.wordtime;
            self.rx_timeout_deadline = Some(self.now_ns + timeout);
        } else {
            self.rx_timeout_deadline = None;
        }
    }

    /// `apple_uart_update_parameters` (result is informational here —
    /// there is no host serial line to reconfigure, but wordtime feeds
    /// the RX-timeout timer just like in the C).
    pub fn update_parameters(&mut self) {
        if self.reg[idx(UBRDIV)] == 0 {
            return;
        }
        let parity_bits = if self.reg[idx(ULCON)] & 0x20 != 0 { 1 } else { 0 };
        let stop_bits: u64 = if self.reg[idx(ULCON)] & 0x4 != 0 { 2 } else { 1 };
        let data_bits: u64 = (self.reg[idx(ULCON)] & 0x3) + 5;
        let uclk_rate = DEFAULT_UCLK_RATE;

        // Faithful to the C, including its precedence:
        // (16 * UBRDIV) & 0xffff + (UFRACVAL & 0x7) + 16.
        let speed = uclk_rate
            / (((16 * self.reg[idx(UBRDIV)]) & 0xffff
                + (self.reg[idx(UFRACVAL)] & 0x7)
                + 16) as u64);
        self.wordtime =
            1_000_000_000 * (data_bits + stop_bits + parity_bits) / speed.max(1);
    }

    /// `apple_uart_receive`: host → guest input.
    pub fn rx_push(&mut self, buf: &[u8]) {
        if self.reg[idx(UFCON)] & UFCON_FIFO_ENABLE != 0 {
            let free = self.rx_fifo_size.saturating_sub(self.rx.len());
            for &b in buf.iter().take(free) {
                self.rx.push_back(b);
            }
            self.rx_timeout_set();
        } else if !buf.is_empty() {
            self.reg[idx(URXH)] = buf[0] as u32;
        }
        self.reg[idx(UTRSTAT)] |= UTRSTAT_RX_BUFFER_DATA_READY;
        self.update_irq();
    }

    /// CHR_EVENT_BREAK: null byte + UERSTAT_BREAK.
    pub fn rx_break(&mut self) {
        self.rx.push_back(b'\0');
        self.reg[idx(UERSTAT)] |= UERSTAT_BREAK;
        self.update_irq();
    }

    /// Drain and return the guest's TX bytes, clearing the flag.
    pub fn take_serial_out(&mut self) -> Vec<u8> {
        self.serial_out_flag = false;
        std::mem::take(&mut self.serial_out)
    }

    pub fn tx_fifo_used(&self) -> usize {
        self.tx.len()
    }

    pub fn rx_fifo_used(&self) -> usize {
        self.rx.len()
    }
}

impl Device for AppleUart {
    fn name(&self) -> &'static str {
        "s3c-uart0"
    }

    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        match offset {
            UERSTAT => {
                // Read-only, read-to-clear.
                let res = self.reg[idx(UERSTAT)];
                self.reg[idx(UERSTAT)] = 0;
                self.update_irq();
                res as u64
            }
            UFSTAT => {
                // Read-only, computed.
                let mut v = (self.rx.len() as u32) & UFSTAT_RX_FIFO_COUNT;
                if self.rx.len() == self.rx_fifo_size {
                    v |= UFSTAT_RX_FIFO_FULL;
                }
                // The C never sets the TX fields of UFSTAT.
                v as u64
            }
            URXH => {
                let res;
                if self.reg[idx(UFCON)] & UFCON_FIFO_ENABLE != 0 {
                    if let Some(b) = self.rx.pop_front() {
                        res = b as u32;
                    } else {
                        res = 0;
                    }
                    if self.rx.is_empty() {
                        self.reg[idx(UTRSTAT)] &= !UTRSTAT_RX_BUFFER_DATA_READY;
                    } else {
                        self.reg[idx(UTRSTAT)] |= UTRSTAT_RX_BUFFER_DATA_READY;
                    }
                } else {
                    self.reg[idx(UTRSTAT)] &= !UTRSTAT_RX_BUFFER_DATA_READY;
                    res = self.reg[idx(URXH)];
                }
                self.update_irq();
                res as u64
            }
            UTXH => 0, // write-only
            _ => {
                if offset < APPLE_UART_REGS_MEM_SIZE && offset % 4 == 0 {
                    self.reg[idx(offset)] as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
        }
    }

    fn write(&mut self, offset: u64, _size: u8, val: u64) {
        let val = val as u32;
        match offset {
            ULCON | UBRDIV | UFRACVAL => {
                self.reg[idx(offset)] = val;
                self.update_parameters();
            }
            UFCON => {
                self.reg[idx(UFCON)] = val;
                if val & UFCON_RX_FIFO_RESET != 0 {
                    self.rx.clear();
                    self.reg[idx(UFCON)] &= !UFCON_RX_FIFO_RESET;
                }
                if val & UFCON_TX_FIFO_RESET != 0 {
                    self.tx.clear();
                    self.reg[idx(UFCON)] &= !UFCON_TX_FIFO_RESET;
                }
            }
            UTXH => {
                // Backend is always "connected" (serial_out vec).
                self.reg[idx(UTRSTAT)] &=
                    !(UTRSTAT_TX_EMPTY | UTRSTAT_TX_BUFFER_EMPTY);
                let ch = val as u8;
                self.serial_out.push(ch);
                self.serial_out_flag = true;
                self.tx.push_back(ch);
                if self.tx.len() > self.tx_fifo_size {
                    self.tx.pop_front();
                }
                self.reg[idx(UTRSTAT)] |= UTRSTAT_TX_EMPTY | UTRSTAT_TX_BUFFER_EMPTY;
                self.update_irq();
            }
            UTRSTAT => {
                let val = val & UTRSTAT_TX_EMPTY;
                self.reg[idx(UTRSTAT)] &= !val;
                self.update_irq();
            }
            UERSTAT => {
                self.reg[idx(UERSTAT)] &= !val;
                self.update_irq();
            }
            UFSTAT | UMSTAT | URXH => {
                // read-only in the C (trace only)
                self.unknown_writes += 1;
            }
            UCON => {
                // NOTE: faithful to upstream apple_uart.c — UCON is *not*
                // stored (upstream stores it nowhere); only the IRQ view
                // is refreshed.
                self.unknown_writes += 1;
                self.update_irq();
            }
            _ => {
                if offset < APPLE_UART_REGS_MEM_SIZE && offset % 4 == 0 {
                    self.reg[idx(offset)] = val;
                } else {
                    self.unknown_writes += 1;
                }
            }
        }
    }

    fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        // `apple_uart_timeout_int`.
        if let Some(deadline) = self.rx_timeout_deadline {
            if now_ns >= deadline
                && (self.reg[idx(UTRSTAT)] & UTRSTAT_RX_BUFFER_DATA_READY != 0
                    || self.reg[idx(UCON)] & UCON_RXTIMEOUT_ENA != 0)
            {
                self.reg[idx(UTRSTAT)] |= UTRSTAT_RX_TIMEOUT;
                self.update_irq();
            }
        }
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("ULCON", ULCON),
        ("UCON", UCON),
        ("UFCON", UFCON),
        ("UMCON", UMCON),
        ("UTRSTAT", UTRSTAT),
        ("UERSTAT", UERSTAT),
        ("UFSTAT", UFSTAT),
        ("UMSTAT", UMSTAT),
        ("UTXH", UTXH),
        ("URXH", URXH),
        ("UBRDIV", UBRDIV),
        ("UFRACVAL", UFRACVAL),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utxh_pushes_serial_out() {
        let mut u = AppleUart::new_t8030();
        for b in b"Hi\n" {
            u.write(UTXH, 4, *b as u64);
        }
        assert_eq!(u.take_serial_out(), b"Hi\n".to_vec());
        assert!(!u.serial_out_flag);
        // TX is treated as instantly drained (like the C's blocking write).
        assert_eq!(
            u.read(UTRSTAT, 4) as u32 & (UTRSTAT_TX_EMPTY | UTRSTAT_TX_BUFFER_EMPTY),
            UTRSTAT_TX_EMPTY | UTRSTAT_TX_BUFFER_EMPTY
        );
    }

    #[test]
    fn rx_fifo_roundtrip() {
        let mut u = AppleUart::new_t8030();
        u.write(UFCON, 4, UFCON_FIFO_ENABLE as u64);
        u.rx_push(&[0x41, 0x42, 0x43]);
        assert!(u.irq_level, "RX data ready raises IRQ");
        assert_eq!(u.read(UFSTAT, 4) as u32 & 0xf, 3);
        assert_eq!(u.read(URXH, 4), 0x41);
        assert_eq!(u.read(URXH, 4), 0x42);
        assert_eq!(u.read(URXH, 4), 0x43);
        assert_eq!(
            u.read(UTRSTAT, 4) as u32 & UTRSTAT_RX_BUFFER_DATA_READY,
            0,
            "empty fifo clears ready"
        );
    }

    #[test]
    fn fifo_reset_and_uerstat_w1c() {
        let mut u = AppleUart::new_t8030();
        u.write(UFCON, 4, UFCON_FIFO_ENABLE as u64);
        u.rx_push(&[1, 2]);
        u.write(UFCON, 4, UFCON_FIFO_ENABLE | UFCON_RX_FIFO_RESET);
        assert_eq!(u.rx_fifo_used(), 0);
        u.rx_break(); // sets UERSTAT_BREAK
        assert_eq!(u.read(UERSTAT, 4), UERSTAT_BREAK as u64);
        u.rx_break();
        u.write(UERSTAT, 4, UERSTAT_BREAK as u64); // W1C
        assert_eq!(u.read(UERSTAT, 4), 0);
    }

    #[test]
    fn reset_values_match_c() {
        let u = AppleUart::new_t8030();
        assert_eq!(u.reg[idx(UTRSTAT)], 6);
        assert_eq!(u.reg[idx(UTXH)], 0x5c5c_5c5c);
    }
}
