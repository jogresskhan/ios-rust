//! nvram — Apple NVRAM variable store (port of hw/misc/apple-silicon/
//! apple_nvram.c): chrp-nvram layout, variable = name\0…\0value.

use vm_core::Device;

pub const NVRAM_SIZE: usize = 0x8000;

pub struct Nvram {
    pub data: Vec<u8>,
    pub unknown_reads: u64,
}

impl Nvram {
    pub fn new() -> Self {
        Nvram { data: vec![0u8; NVRAM_SIZE], unknown_reads: 0 }
    }

    /// Set `name=value` in the store (research convenience API).
    pub fn set_var(&mut self, name: &str, value: &[u8]) {
        let mut blob = name.as_bytes().to_vec();
        blob.push(0);
        blob.extend_from_slice(value);
        blob.push(0);
        // find free area at end marker (simple linear scan for zeros)
        if let Some(pos) = self
            .data
            .windows(blob.len())
            .position(|w| w.iter().all(|&b| b == 0))
        {
            self.data[pos..pos + blob.len()].copy_from_slice(&blob);
        }
    }

    pub fn get_var(&self, name: &str) -> Option<Vec<u8>> {
        let pat = name.as_bytes();
        let mut i = 0;
        while i + pat.len() + 1 < self.data.len() {
            if &self.data[i..i + pat.len()] == pat && self.data[i + pat.len()] == 0 {
                let start = i + pat.len() + 1;
                let end = self.data[start..].iter().position(|&b| b == 0)? + start;
                return Some(self.data[start..end].to_vec());
            }
            i += 1;
        }
        None
    }

    pub fn load(&mut self, blob: &[u8]) {
        let n = blob.len().min(self.data.len());
        self.data[..n].copy_from_slice(&blob[..n]);
    }

    pub fn save(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("DATA", 0x0), ("SIZE", NVRAM_SIZE as u64)]
    }
}

impl Default for Nvram {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Nvram {
    fn name(&self) -> &'static str {
        "nvram"
    }
    fn ram_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.data)
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        let o = off as usize;
        if o < NVRAM_SIZE {
            self.data[o] as u64
        } else {
            self.unknown_reads += 1;
            0
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        let o = off as usize;
        if o < NVRAM_SIZE {
            self.data[o] = val as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn var_roundtrip() {
        let mut n = Nvram::new();
        n.set_var("boot-args", b"debug=0x14e");
        assert_eq!(n.get_var("boot-args").unwrap(), b"debug=0x14e");
    }
}
