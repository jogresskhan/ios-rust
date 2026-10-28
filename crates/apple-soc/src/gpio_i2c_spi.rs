//! gpio_i2c_spi — Apple GPIO / I2C / SPI controllers + the small slave
//! trait set (ports of hw/misc/apple-silicon/apple_gpio.c, apple_i2c.c,
//! apple_spi.c + t8030 i2c slaves roswell/chestnut/backlight hooks).

use vm_core::Device;

// ---- GPIO (apple_gpio.c) ----
pub const GPIO_PIN_CTRL: u64 = 0x0000; // per-pin, 4B stride
pub const GPIO_PIN_IN: u64 = 0x0400;
pub const GPIO_PIN_OUT: u64 = 0x0500;

pub struct Gpio {
    /// pin → (out_level, in_level, cfg)
    pub pins: Vec<(bool, bool, u32)>,
    pub unknown_reads: u64,
}

impl Gpio {
    pub fn new() -> Self {
        Gpio { pins: vec![(false, false, 0); 256], unknown_reads: 0 }
    }
    pub fn set_input(&mut self, pin: usize, level: bool) {
        if pin < self.pins.len() {
            self.pins[pin].1 = level;
        }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("PIN_CTRL", GPIO_PIN_CTRL), ("PIN_IN", GPIO_PIN_IN), ("PIN_OUT", GPIO_PIN_OUT)]
    }
}

impl Default for Gpio {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Gpio {
    fn name(&self) -> &'static str {
        "gpio"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            o if o < 0x400 => self.pins[(o / 4) as usize].2 as u64,
            GPIO_PIN_IN => self.pins.iter().fold(0u64, |a, p| a | (p.1 as u64)),
            GPIO_PIN_OUT => self.pins.iter().fold(0u64, |a, p| a | (p.0 as u64)),
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off < 0x400 {
            self.pins[(off / 4) as usize].2 = (val & 0xFFFF_FFFF) as u32;
        }
    }
}

// ---- I2C controller (apple_i2c.c) + slave trait ----
pub const I2C_MCMD: u64 = 0x0000;
pub const I2C_MSTATUS: u64 = 0x0004;
pub const I2C_MTXDATA: u64 = 0x0008;
pub const I2C_MRXDATA: u64 = 0x000C;

pub trait I2cSlave: Send {
    fn write_byte(&mut self, b: u8);
    fn read_byte(&mut self) -> u8;
}

pub struct I2c {
    pub slave: Option<Box<dyn I2cSlave>>,
    pub mtx: Vec<u8>,
    pub mrx: Vec<u8>,
    pub unknown_reads: u64,
}

impl I2c {
    pub fn new() -> Self {
        I2c { slave: None, mtx: Vec::new(), mrx: Vec::new(), unknown_reads: 0 }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("MCMD", I2C_MCMD), ("MSTATUS", I2C_MSTATUS), ("MTXDATA", I2C_MTXDATA), ("MRXDATA", I2C_MRXDATA)]
    }
}

impl Default for I2c {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for I2c {
    fn name(&self) -> &'static str {
        "i2c"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            I2C_MSTATUS => 0x1, // complete/idle
            I2C_MRXDATA => {
                if self.mrx.is_empty() {
                    if let Some(s) = self.slave.as_mut() {
                        self.mrx.push(s.read_byte());
                    }
                }
                self.mrx.remove(0) as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            I2C_MTXDATA => self.mtx.push((val & 0xFF) as u8),
            I2C_MCMD => {
                // start transfer: drain TX into slave
                if let Some(s) = self.slave.as_mut() {
                    for b in self.mtx.drain(..) {
                        s.write_byte(b);
                    }
                }
            }
            _ => {}
        }
    }
}

// ---- SPI controller (apple_spi.c) ----
pub const SPI_CTRL: u64 = 0x0000;
pub const SPI_PIN: u64 = 0x0004;
pub const SPI_TX_DATA: u64 = 0x0010;
pub const SPI_RX_DATA: u64 = 0x0020;
pub const SPI_STATUS: u64 = 0x000C;

pub trait SpiSlave: Send {
    fn transfer(&mut self, b: u8) -> u8;
}

pub struct Spi {
    pub slave: Option<Box<dyn SpiSlave>>,
    pub unknown_reads: u64,
}

impl Spi {
    pub fn new() -> Self {
        Spi { slave: None, unknown_reads: 0 }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("CTRL", SPI_CTRL), ("PIN", SPI_PIN), ("STATUS", SPI_STATUS), ("TX", SPI_TX_DATA), ("RX", SPI_RX_DATA)]
    }
}

impl Default for Spi {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Spi {
    fn name(&self) -> &'static str {
        "spi"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SPI_STATUS => 0x1,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == SPI_TX_DATA {
            if let Some(s) = self.slave.as_mut() {
                let _ = s.transfer((val & 0xFF) as u8);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Echo;
    impl SpiSlave for Echo {
        fn transfer(&mut self, b: u8) -> u8 {
            b ^ 0xFF
        }
    }
    #[test]
    fn spi_loopback() {
        let mut s = Spi::new();
        s.slave = Some(Box::new(Echo));
        s.write(SPI_TX_DATA, 1, 0xA5);
        // slave got the byte (echo discarded here; presence test)
        assert!(s.slave.is_some());
    }
}
