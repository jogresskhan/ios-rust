//! Micro: ext v18.16b, v4.16b, v5.16b, #8 + add v0.2d, v0.2d, v18.2d —
//! the two SHA-512 schedule words that build W16, with reference values.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};

include!("fips_sha512_words.rs");

struct Ram(Vec<u8>);
impl MemAccess for Ram {
    fn load(&mut self, _a: u64, _s: u8) -> u64 {
        0
    }
    fn store(&mut self, _a: u64, _s: u8, _v: u64) {}
    fn fetch32(&mut self, a: u64) -> u32 {
        u32::from_le_bytes(self.0[(a as usize)..(a as usize) + 4].try_into().unwrap())
    }
}

fn set_q(cpu: &mut Interpreter, r: u8, lanes: [u64; 2]) {
    cpu.v.v[r as usize] = (lanes[1] as u128) << 64 | lanes[0] as u128;
}
fn get_q(cpu: &Interpreter, r: u8) -> [u64; 2] {
    let v = cpu.v.v[r as usize];
    [v as u64, (v >> 64) as u64]
}

#[test]
fn ext_and_add_micro() {
    // words read from the kernel image at 0x82e68e0 / 0x82e690c
    let off_e = (0xF0 / 4) as usize; // ext v18.16b, v4.16b, v5.16b, #8 (0x82e68e0-0x82e67f0=0xF0)
    let off_a = (0x11C / 4) as usize; // add v0.2d, v0.2d, v18.2d
    let w_ext = COMPRESS[off_e];
    let w_add = COMPRESS[off_a];
    println!("ext word {w_ext:08x}, add word {w_add:08x}");

    let mut ram = vec![0u8; 0x1000];
    let code = [w_ext, w_add, 0xD440_0000u32];
    ram[0x100..0x10C].copy_from_slice(&code.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>());

    // W values from the ipad block (reference)
    let w: [u64; 16] = [
        0x225401c4f40a0a53, 0x140656057256791f, 0x60a4f1d62ee390be, 0xa6507ed5c8e239a2,
        0x245575ac6b982b2e, 0x30a728618870933b, 0xc3f8f7d678a57210, 0x677d2fd95729e173,
        0xdb3ba384dcbd3735, 0xb65b9a7a353e9e1a, 0x10ae63645de94e76, 0xe839bb7935dc69c2,
        0x3b1ee377662f3999, 0xcfbd872ccbd83636, 0x3636363636363636, 0x3636363636363636,
    ];
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    set_q(&mut cpu, 0, [w[0], w[1]]);
    set_q(&mut cpu, 1, [w[2], w[3]]);
    set_q(&mut cpu, 4, [w[8], w[9]]);
    set_q(&mut cpu, 5, [w[10], w[11]]);
    cpu.set_reset_vector(0x100);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 10, max_ns: 60_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted, "stop={res:?}");
    let v18 = get_q(&cpu, 18);
    let v0 = get_q(&cpu, 0);
    println!("v18 = {:016x}`{:016x} (want w9`w10)", v18[1], v18[0]);
    println!("v0  = {:016x}`{:016x} (want w0+w9`w1+w10)", v0[1], v0[0]);
    assert_eq!(v18, [w[9], w[10]], "ext must produce (W9, W10)");
    let want0 = w[0].wrapping_add(w[9]);
    let want1 = w[1].wrapping_add(w[10]);
    assert_eq!(v0, [want0, want1], "add .2d must add both lanes");
}


