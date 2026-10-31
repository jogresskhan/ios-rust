//! Debug: single-step the kernel's SHA-512 compress prologue; dump GPRs +
//! selected vregs per instruction (run --nocapture --ignored). The repro
//! that isolated bug #48.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};

struct Ram(Vec<u8>);
impl MemAccess for Ram {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let mut v = [0u8; 8];
        for k in 0..size as usize {
            v[k] = self.0.get((addr + k as u64) as usize).copied().unwrap_or(0);
        }
        u64::from_le_bytes(v)
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        let b = val.to_le_bytes();
        for k in 0..size as usize {
            if let Some(slot) = self.0.get_mut((addr + k as u64) as usize) {
                *slot = b[k];
            }
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        u32::from_le_bytes(self.0[(addr as usize)..(addr as usize) + 4].try_into().unwrap())
    }
}

include!("fips_sha512_words.rs");

const PAGE: u64 = 0x10000;
const ENTRY: u64 = PAGE;
const KPAGE: u64 = 0x40000;
const STATE: u64 = 0x8000;
const DATA: u64 = 0x50000;
const STACK: u64 = 0x60000;
const HALT: u64 = 0x70000;

fn lanes(cpu: &Interpreter, r: u8) -> [u64; 2] {
    let v = cpu.v.v[r as usize];
    [v as u64, (v >> 64) as u64]
}

#[test]
#[ignore]
fn step_dump() {
    let mut ram = vec![0u8; 0x80000];
    let f = PAGE as usize;
    ram[f..f + COMPRESS.len() * 4].copy_from_slice(
        &COMPRESS.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>(),
    );
    let k = (KPAGE + 0x640) as usize;
    ram[k..k + KTABLE.len()].copy_from_slice(&KTABLE);
    let d = DATA as usize;
    ram[d..d + 128].copy_from_slice(&INNER_STREAM[..128]);
    let s = STATE as usize;
    ram[s..s + 64].copy_from_slice(&IV);
    ram[HALT as usize..HALT as usize + 4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.x[0] = STATE;
    cpu.x[1] = 1;
    cpu.x[2] = DATA;
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu.set_reset_vector(ENTRY);

    for step in 0..220u64 {
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 1, max_ns: 1_000_000_000 });
        if res.stop != StopReason::Budget {
            println!("step {step}: stop={:?} pc={:#x}", res.stop, cpu.pc);
            break;
        }
        print!("step {:3} pc={:#010x} sp={:#x}", step + 1, cpu.pc, cpu.sp);
        for r in [0u8, 1, 2, 3, 4, 5] {
            let l = lanes(&cpu, r);
            print!(" v{r}={:016x}`{:016x}", l[1], l[0]);
        }
        for g in [3u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] {
            print!(" x{g}={:016x}", cpu.x[g as usize]);
        }
        println!();
    }
}
