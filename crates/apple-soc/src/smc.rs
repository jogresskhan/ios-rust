//! smc — Apple SMC (System Management Controller) — port of
//! hw/misc/apple-silicon/smc.c (LGPL-2.1 origins, Alexander Graf QEMU SMC
//! lineage + Inferno port): 4-char key protocol over mailbox regs.

use vm_core::Device;

pub const SMC_STATUS: u64 = 0x0000;
pub const SMC_CMD_RESULT: u64 = 0x0004;
pub const SMC_CMD: u64 = 0x0008;
pub const SMC_RSP_DATA: u64 = 0x000C;
pub const SMC_KEY: u64 = 0x0010;

const CMD_READ_KEY: u64 = 0x10;
const CMD_WRITE_KEY: u64 = 0x11;
const CMD_GET_KEY_BY_INDEX: u64 = 0x12;

#[derive(Default)]
pub struct Smc {
    keys: std::collections::BTreeMap<[u8; 4], Vec<u8>>,
    key_order: Vec<[u8; 4]>,
    cur_key: [u8; 4],
    cur_index: u32,
    rsp: u32,
    result: u32,
    pub unknown_reads: u64,
}

fn key4(v: u64) -> [u8; 4] {
    [
        (v & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
    ]
}

impl Smc {
    pub fn new() -> Self {
        let mut s = Smc {
            keys: std::collections::BTreeMap::new(),
            key_order: Vec::new(),
            cur_key: [0; 4],
            cur_index: 0,
            rsp: 0,
            result: 0,
            unknown_reads: 0,
        };
        // deterministic defaults from the C model
        s.keys.insert(*b"RMde", b"AppleSE" .to_vec());
        s.key_order.push(*b"RMde");
        s.keys.insert(*b"MSLD", vec![0]);
        s.key_order.push(*b"MSLD");
        s
    }

    pub fn set_key(&mut self, k: &[u8; 4], v: Vec<u8>) {
        if !self.keys.contains_key(k) {
            self.key_order.push(*k);
        }
        self.keys.insert(*k, v);
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("STATUS", SMC_STATUS),
            ("CMD_RESULT", SMC_CMD_RESULT),
            ("CMD", SMC_CMD),
            ("RSP_DATA", SMC_RSP_DATA),
            ("KEY", SMC_KEY),
        ]
    }
}

impl Device for Smc {
    fn name(&self) -> &'static str {
        "smc"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SMC_STATUS => 0x10, // ready
            SMC_CMD_RESULT => self.result as u64,
            SMC_RSP_DATA => self.rsp as u64,
            SMC_KEY => u32::from_le_bytes(self.cur_key) as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            SMC_KEY => self.cur_key = key4(val),
            SMC_CMD => match val {
                CMD_READ_KEY => {
                    self.result = match self.keys.get(&self.cur_key) {
                        Some(v) if !v.is_empty() => {
                            self.rsp = v[0] as u32;
                            0
                        }
                        Some(_) => 0,
                        None => 0x84, // not found
                    };
                }
                CMD_GET_KEY_BY_INDEX => {
                    if let Some(k) = self.key_order.get(self.cur_index as usize) {
                        self.cur_key = *k;
                        self.result = 0;
                    } else {
                        self.result = 0x84;
                    }
                }
                CMD_WRITE_KEY => {
                    self.keys.insert(self.cur_key, vec![(val >> 8) as u8]);
                    self.result = 0;
                }
                _ => self.result = 0x85,
            },
            SMC_RSP_DATA => self.cur_index = (val & 0xFFFF) as u32,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_read() {
        let mut s = Smc::new();
        s.write(SMC_KEY, 4, u32::from_le_bytes(*b"RMde") as u64);
        s.write(SMC_CMD, 4, CMD_READ_KEY);
        assert_eq!(s.read(SMC_CMD_RESULT, 4), 0);
        assert_eq!(s.read(SMC_RSP_DATA, 4), b'A' as u64);
    }
}
