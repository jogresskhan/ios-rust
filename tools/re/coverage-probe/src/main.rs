//! kc-probe: honest coverage probe of the a13-cpu against REAL iOS 14.3
//! T8030 kernelcache bytes (18C66). Decode sweep + single-insn exec probe.

use a13_cpu::decode::decode;
use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, InterpBudget, MemAccess, StopReason};
use vm_core::{Bus, Device, Ram};

struct BusMem(Bus);
impl MemAccess for BusMem {
    fn load(&mut self, addr: u64, size: u8) -> u64 { self.0.read(addr, size) }
    fn store(&mut self, addr: u64, size: u8, val: u64) { self.0.write(addr, size, val) }
    fn fetch32(&mut self, addr: u64) -> u32 { self.0.read(addr, 4) as u32 }
}

fn main() {
    let kc = std::env::args().nth(1).expect("usage: kc-probe <kernelcache>");
    let raw = std::fs::read(&kc).unwrap();
    let img = kernelcache::decompress(&raw).unwrap();
    println!("decompressed: {} bytes", img.len());

    let text = kernelcache::sections::find_section(&img, "__TEXT_EXEC", "__text")
        .expect("no __TEXT_EXEC.__text");
    let anchor = kernelcache::sections::find_section(&img, "__TEXT", "__cstring")
        .or_else(|| kernelcache::sections::sections(&img).into_iter().find(|s| s.segment == "__TEXT"))
        .expect("no __TEXT anchor");
    let base = anchor.addr - anchor.offset;
    let va0 = base + text.offset;
    let code = &img[text.offset as usize..(text.offset + text.size) as usize];
    let n = code.len() / 4;
    println!(
        "__TEXT_EXEC.__text: VA {:#x}..{:#x}, {} words",
        va0, va0 + text.size, n
    );

    // ---- 1) decode sweep (linear) ----
    let mut dec = 0u64;
    let mut unk = 0u64;
    let mut cur_run = 0u64;
    let mut data_runs = 0u64;
    let mut data_words = 0u64;
    let mut top_run = 0u64;
    let mut top_run_va = 0u64;
    for i in 0..n {
        let w = u32::from_le_bytes(code[i * 4..i * 4 + 4].try_into().unwrap());
        if decode(va0 + (i as u64) * 4, w).is_some() {
            dec += 1;
            if cur_run > 0 {
                if cur_run >= 16 { data_runs += 1; data_words += cur_run; }
                if cur_run > top_run { top_run = cur_run; top_run_va = va0 + ((i as u64) - cur_run) * 4; }
                cur_run = 0;
            }
        } else {
            unk += 1;
            cur_run += 1;
        }
    }
    if cur_run >= 16 { data_runs += 1; data_words += cur_run; }
    println!(
        "decode sweep: {dec}/{n} decodable = {:.2}% (unknown {unk})",
        dec as f64 * 100.0 / n as f64
    );
    println!(
        "unknown runs >=16 words (literal pools / tables): {data_runs} runs, {data_words} words; longest run {top_run} words @ {top_run_va:#x}"
    );

    // ---- 2) single-insn exec probe (sampled) ----
    let stride: usize = (n / 20000).max(1);
    let mut sampled = 0u64;
    let mut exec_ok = 0u64;
    let mut unknown = 0u64;
    let mut stops: std::collections::HashMap<String, u64> = Default::default();
    let pause = 0x8_2000_0000u64;
    for i in (0..n).step_by(stride) {
        let w = u32::from_le_bytes(code[i * 4..i * 4 + 4].try_into().unwrap());
        let mut bus = Bus::new();
        let mut ram = Ram::new("probe", 0x1000);
        if let Some(d) = ram.ram_mut() {
            d[..4].copy_from_slice(&w.to_le_bytes());
        }
        bus.attach(0x1_0000_0000, 0x1000, Box::new(ram));
        let mut pausep = Ram::new("pause", 0x1000);
        if let Some(d) = pausep.ram_mut() {
            d[..4].copy_from_slice(&0xD440_0000u32.to_le_bytes()); // HLT
        }
        bus.attach(pause, 0x1000, Box::new(pausep));
        let mut cpu = Interpreter::new(Box::new(BusMem(bus)));
        cpu.set_reset_vector(0x1_0000_0000);
        cpu.x[30] = pause; // LR -> pause page
        let res = cpu.run(InterpBudget { max_insn: 1, max_ns: 10_000_000 });
        sampled += 1;
        match res.stop {
            StopReason::UnknownInsn { .. } => unknown += 1,
            other => {
                exec_ok += 1;
                *stops.entry(format!("{other:?}")).or_default() += 1;
            }
        }
    }
    println!(
        "exec probe (stride {stride}, {sampled} samples): executed {exec_ok} = {:.1}%, UnknownInsn {unknown}",
        exec_ok as f64 * 100.0 / sampled as f64
    );
    let mut v: Vec<_> = stops.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, c) in v.iter().take(6) {
        println!("  stop {k}: {c}");
    }
}
