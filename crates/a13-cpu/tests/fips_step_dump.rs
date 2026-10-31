//! Debug: single-step the kernel's real SHA-1 vng compress prologue and
//! dump vector/GPR state after every instruction (run with --nocapture).
//! Compare against scripts/step_model.py (Python reference of the same
//! choreography).

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
        u32::from_le_bytes(
            self.0[(addr as usize)..(addr as usize) + 4]
                .try_into()
                .unwrap(),
        )
    }
}

include!("fips_hmac_kat_words.rs");

const PAGE: u64 = 0x2000;
const ENTRY: u64 = PAGE + 0x730;
const STATE: u64 = 0x1000;
const DATA: u64 = 0x11000;
const STACK: u64 = 0x18000;
const HALT: u64 = 0x19000;

fn lanes(cpu: &Interpreter, r: u8) -> [u32; 4] {
    let v = cpu.v.v[r as usize];
    [
        v as u32,
        (v >> 32) as u32,
        (v >> 64) as u32,
        (v >> 96) as u32,
    ]
}

/// Debug tool (run with `cargo test -p a13-cpu --test fips_step_dump -- --nocapture --ignored`):
/// single-steps the kernel's real SHA-1 vng compress and dumps vector/GPR
/// state after every instruction — the probe that isolated bug #46 (the
/// ld1 {v0..v3} interleaved-layout corruption).
#[test]
#[ignore]
fn step_dump() {
    let mut ram = vec![0u8; 0x20000];
    let kfn = (PAGE + 0x6f0) as usize;
    ram[kfn..kfn + COMPRESS.len() * 4].copy_from_slice(
        &COMPRESS.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>(),
    );
    let d = DATA as usize;
    ram[d..d + 64].copy_from_slice(&INNER_STREAM[..64]);
    let s = STATE as usize;
    ram[s..s + 20].copy_from_slice(&IV);
    ram[HALT as usize..HALT as usize + 4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.x[0] = STATE;
    cpu.x[1] = 1;
    cpu.x[2] = DATA;
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu.set_reset_vector(ENTRY);

    for step in 0..40u64 {
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 1, max_ns: 1_000_000_000 });
        if res.stop != StopReason::Budget {
            println!("step {step}: stop={:?} pc={:#x}", res.stop, cpu.pc);
            break;
        }
        print!(
            "step {:2} pc={:#010x} x0={:#x} x1={:#x} x2={:#x} x3={:#x} sp={:#x}",
            step + 1, cpu.pc, cpu.x[0], cpu.x[1], cpu.x[2], cpu.x[3], cpu.sp
        );
        for r in [0u8, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21] {
            let l = lanes(&cpu, r);
            print!(" v{r}={:08x}{:08x}{:08x}{:08x}", l[3], l[2], l[1], l[0]);
        }
        println!();
    }
}
