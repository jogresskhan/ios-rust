//! boot-real — THE REAL FIRST BOOT.
//!
//! No synthetic stages: the actual Apple XNU 18C66 kernel, loaded the way
//! iBoot loads it, handed off the way iBoot hands it off, and executed
//! instruction-by-instruction by the pure-Rust A13 core until the kernel
//! either prints over the UART or hits an honest stop.
//!
//! Handoff contract (extracted from the real binary — see
//! `tools/re/macho/entry_probe.py`; every constant below is measured, not
//! guessed):
//!
//! * kernel loaded at DRAM base (`physBase`), MMU OFF, PC = load PA of the
//!   `LC_UNIXTHREAD` entry (`__start` → `b` into `start`)
//! * `x0` = physical `boot_args` pointer
//! * `start` reads `boot_args` `virtBase@[0x8]`, `physBase@[0x10]`,
//!   `memSize@[0x18]` (and `[0x2d0]`), builds 16 KB-granule bootstrap
//!   tables in DRAM, programs TCR/TTBR1/MAIR, flips `SCTLR_EL1.M`
//!   (0x3454_593D|0x40000000) and `ret`s into virtual `start_first_cpu`
//!   at `virtBase + 0xB7C288`
//! * TCR the kernel programs (read from `__DATA_CONST[0x77020c8]`):
//!   `0x0008_0022_6519_A519` → T0SZ=T1SZ=25 (39-bit VA), TG0/TG1 = 16 KB,
//!   IPS = 40-bit PA
//! * MIDR must read as 0x611F0120 (variant≠0 avoids the stepping halt)
//! * `s3_4_c15_c0_4` bit 1 must read as set (boot-stage poll)

use std::path::Path;

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, InterpBudget, MemAccess, RunResult, StopReason};
use apple_soc::t8030::{T8030Machine, DEFAULT_DRAM_MB};
use img4::im4p::Im4p;
use macho::header::MachHeader;
use restore::lzfse;
use vm_core::{Bus, Ram};

pub const BOOT_REAL_ID: &str = "boot-real v1 (real XNU 18C66 handoff → first boot)";

// ---- the handoff constants (measured on the real 18C66 T8030 image) ----
// LOAD_PA must satisfy LOAD_PA ≡ LINK_BASE (mod 32 MB): start.s builds its
// bootstrap maps as 32 MB L2 blocks with the block *index* taken from the
// VA side and the block *base* from the PA side, so the two bases have to
// agree inside one block or every VA→PA translation skews by the delta.
const LOAD_PA: u64 = 0x8_0100_4000; // = DRAM base + (LINK_BASE & 0x1FFFFFF)
const LINK_BASE: u64 = 0xFFFF_FFF0_0700_4000; // kernel __TEXT link VA
const TOP_OF_KERNEL_DATA: u64 = 0x8_0400_0000;
const DT_PA: u64 = 0x8_0400_0000;
const BA_PA: u64 = 0x8_0410_0000;
const MEM_SIZE: u64 = 0x1_0000_0000; // 4 GiB (iPhone12,1)
const PAUSE_PA: u64 = 0x8_0900_0000; // HLT canary page
/// LC_SEGMENT_64 / LC_UNIXTHREAD.
const LC_SEGMENT_64: u32 = 0x19;
const LC_UNIXTHREAD: u32 = 0x5;
const UNIXTHREAD_PC_OFF: usize = 0x110;

pub struct BootRealReport {
    pub image_bytes: usize,
    pub link_base: u64,
    pub entry_link_va: u64,
    pub entry_pa: u64,
    pub bootargs_pa: u64,
    pub dt_pa: u64,
    pub dt_bytes: usize,
    pub res: RunResult,
    pub serial: Vec<u8>,
    pub mmu_config: String,
    pub mmu_walks: u64,
    pub mmu_tlb_hits: u64,
    pub mmu_faults: u64,
    pub unknown_sysreg_reads: u64,
    pub unknown_sysreg_writes: u64,
    pub unknown_sysreg_list: Vec<String>,
    pub trace: Vec<String>,
    pub devices_attached: usize,
    pub adt_peripherals: usize,
    pub fault_chain: Vec<(u32, u64, u64)>,
    pub regs_dump: String,
    /// Post-mortem: bytes at thread_starts PA, bootstrap L2 tables.
    pub mem_probe: Vec<String>,
    pub last_sp_change: Option<(u64, u32, u64)>,
}

fn u32le(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("u32 OOB at {off:#x}"));
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

fn u64le(buf: &[u8], off: usize) -> Result<u64, String> {
    if off + 8 > buf.len() {
        return Err(format!("u64 OOB at {off:#x}"));
    }
    Ok(u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()))
}

/// Top-level Mach-O scan: segments + entry point (the kernelcache is one
/// contiguous MH_EXECUTE prelinked image).
fn parse_kernel(img: &[u8]) -> Result<(u64, u64, Vec<(String, u64, u64)>), String> {
    let hdr = MachHeader::parse(img)?;
    let mut segs = Vec::new();
    let mut entry = 0u64;
    let mut off = 32usize;
    for _ in 0..hdr.ncmds {
        let cmd = u32le(img, off)?;
        let cmdsize = u32le(img, off + 4)? as usize;
        match cmd {
            LC_SEGMENT_64 => {
                let name: String = img[off + 8..off + 24]
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect();
                let vmaddr = u64le(img, off + 24)?;
                let _vmsize = u64le(img, off + 32)?;
                segs.push((name, vmaddr, cmdsize as u64));
            }
            LC_UNIXTHREAD => {
                if cmdsize >= UNIXTHREAD_PC_OFF + 8 {
                    entry = u64le(img, off + UNIXTHREAD_PC_OFF)?;
                }
            }
            _ => {}
        }
        off += cmdsize;
    }
    Ok((segs.first().map(|s| s.1).unwrap_or(0), entry, segs))
}

/// boot_args for arm64 — the layout the real start.s loads: virtBase@0x8,
/// physBase@0x10, memSize@0x18, topOfKernelData@0x20, DeviceTreeP@0x28,
/// DeviceTreeLen@0x30, …, a kernel-read field at 0x2d0.
fn build_boot_args(virt_base: u64, phys_base: u64, dt_pa: u64, dt_len: u32) -> Vec<u8> {
    let mut ba = vec![0u8; 0x2E0];
    let put = |buf: &mut Vec<u8>, off: usize, v: u64| {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };
    ba[0..2].copy_from_slice(&0u16.to_le_bytes()); // Rev
    ba[2..4].copy_from_slice(&2u16.to_le_bytes()); // Version
    put(&mut ba, 0x08, virt_base);
    put(&mut ba, 0x10, phys_base);
    put(&mut ba, 0x18, MEM_SIZE);
    put(&mut ba, 0x20, TOP_OF_KERNEL_DATA);
    put(&mut ba, 0x28, dt_pa);
    ba[0x30..0x34].copy_from_slice(&dt_len.to_le_bytes());
    // everything else (video, flags, cmdline, [0x2d0]) stays zero
    ba
}

struct BusMem(Bus);
impl MemAccess for BusMem {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        self.0.read(addr, size)
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        self.0.write(addr, size, val);
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        self.0.read(addr, 4) as u32
    }
}

/// Decode a canonical sysreg encoding back to `s<op0+?>_<op1>_c<CRn>_c<CRm>_<op2>`
/// for the report.
fn sysreg_name(enc: u16) -> String {
    let op0raw = (enc >> 14) & 1;
    let op1 = (enc >> 11) & 7;
    let crn = (enc >> 7) & 0xF;
    let crm = (enc >> 3) & 0xF;
    let op2 = enc & 7;
    format!("s3_{op1}_c{crn}_c{crm}_{op2} / s{op0raw}_{op1}_c{crn}_c{crm}_{op2}")
}

/// Run the real first boot. `dir` holds the staged kernelcache + DeviceTree.
pub fn run(dir: &Path, max_insn: u64) -> Result<BootRealReport, String> {
    println!("{BOOT_REAL_ID}");

    // ---- 1) real kernelcache → decompressed Mach-O ----
    let kc_path = dir.join("kernelcache.release.iphone12b");
    let raw = std::fs::read(&kc_path).map_err(|e| format!("read {}: {e}", kc_path.display()))?;
    let img = kernelcache::decompress(&raw)?;
    let (link_base, entry, segs) = parse_kernel(&img)?;
    if entry == 0 {
        return Err("kernelcache: no LC_UNIXTHREAD entry".into());
    }
    println!(
        "[load] kernelcache: {} B Mach-O · link base {:#x} · {} segments · entry {:#x}",
        img.len(),
        link_base,
        segs.len(),
        entry
    );

    // ---- 2) real DeviceTree (IM4P → LZFSE → flat ADT) ----
    let dt_path = dir.join("DeviceTree.n104ap.im4p");
    let dt_raw = std::fs::read(&dt_path).map_err(|e| format!("read devicetree: {e}"))?;
    let im4p = Im4p::parse(&dt_raw).map_err(|e| format!("devicetree IM4P: {e}"))?;
    let dt_blob = if lzfse::is_lzfse(&im4p.data) {
        lzfse::decompress(&im4p.data, None).map_err(|e| format!("devicetree LZFSE: {e}"))?
    } else {
        im4p.data.clone()
    };
    let adt = adt::AdtNode::parse(&dt_blob).map_err(|e| format!("ADT: {e}"))?;
    let adt_peripherals = adt.find("arm-io").map(|n| n.children.len()).unwrap_or(0);

    // ---- 3) machine assembly (iBoot equivalent) ----
    let mut machine = T8030Machine::new(DEFAULT_DRAM_MB);
    let devices_attached = machine.attach_from_adt(&adt);
    let serial = machine.serial.clone();
    let mut bus = std::mem::replace(&mut machine.bus, Bus::new());

    bus.write_raw(LOAD_PA, &img);
    bus.write_raw(DT_PA, &dt_blob);
    let ba = build_boot_args(LINK_BASE, LOAD_PA, DT_PA, dt_blob.len() as u32);
    bus.write_raw(BA_PA, &ba);

    // HLT canary page (a stray RET lands here and halts cleanly)
    let mut pause = Ram::new("boot-pause", 0x1000);
    pause.data[..4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    bus.attach(PAUSE_PA, 0x1000, Box::new(pause));

    // ---- 4) CPU state: the iBoot→xnu handoff ----
    let entry_pa = LOAD_PA + (entry - link_base);
    let mut cpu = Interpreter::new(Box::new(BusMem(bus)));
    cpu.set_reset_vector(entry_pa);
    cpu.x[0] = BA_PA; // boot_args pointer (physical, MMU off)
    cpu.x[30] = PAUSE_PA;
    cpu.sp = 0;
    cpu.trace_enabled = true;

    println!(
        "[handoff] PC = {entry_pa:#x} (load PA) · x0 = {BA_PA:#x} (boot_args) · MMU off · \
         EL1 · DAIF masked by the kernel itself"
    );
    println!(
        "[contract] virtBase = {LINK_BASE:#x} · physBase = {LOAD_PA:#x} · memSize = {MEM_SIZE:#x} · \
         DeviceTree @ {DT_PA:#x} · MIDR = 0x611f0120"
    );

    // ---- 5) execute the real kernel ----
    let res = cpu.run(InterpBudget {
        max_insn,
        // ~25 MIPS model (40 ns/insn) + headroom — the ns budget must never
        // bind before the instruction budget on long real-kernel scans.
        max_ns: max_insn.saturating_mul(40).saturating_add(4_000_000_000),
    });

    let out = serial.lock().map(|s| s.clone()).unwrap_or_default();
    let trace: Vec<String> = cpu
        .trace
        .iter()
        .map(|(pc, w, regs, nzcv)| {
            format!(
                "{pc:#x}: {w:#010x} nzcv={nzcv:04b} x9={:x} x10={:x} x12={:x} x13={:x} x16={:x} x22={:x} sp={:x} lr={:x}",
                regs[9], regs[10], regs[12], regs[13], regs[16], regs[22],
                cpu.sp, regs[30]
            )
        })
        .collect();
    let unknown_sysreg_list = cpu
        .unknown_sysreg_seen
        .iter()
        .map(|&e| sysreg_name(e))
        .collect();

    Ok(BootRealReport {
        image_bytes: img.len(),
        link_base,
        entry_link_va: entry,
        entry_pa,
        bootargs_pa: BA_PA,
        dt_pa: DT_PA,
        dt_bytes: dt_blob.len(),
        mmu_config: cpu.mmu.config_str(),
        mmu_walks: cpu.mmu.walks,
        mmu_tlb_hits: cpu.mmu.tlb_hits,
        mmu_faults: cpu.mmu.faults,
        unknown_sysreg_reads: cpu.unknown_sysreg_reads,
        unknown_sysreg_writes: cpu.unknown_sysreg_writes,
        unknown_sysreg_list,
        trace,
        serial: out,
        res,
        devices_attached,
        adt_peripherals,
        fault_chain: cpu.mmu.last_fault_chain.clone(),
        regs_dump: cpu.dump_state(),
        last_sp_change: cpu.last_sp_change,
        mem_probe: {
            let mut probe = Vec::new();
            // thread_starts PA (first 16 B) — file says 0x0, 0x6e4000, …
            let ts_pa = LOAD_PA + (0x76E7B8C - 0x7004000); // file offset 0x6e3b8c
            let mut buf = [0u8; 16];
            cpu.mem().read_bytes(ts_pa, &mut buf);
            probe.push(format!("thread_starts@{ts_pa:#x}: {:02x?}", buf));
            // bootstrap L2' table (x25 + 0xC000) first 8 descriptors
            let l2p = LOAD_PA + 0x700000 + 0xC000;
            let mut buf2 = [0u8; 64];
            cpu.mem().read_bytes(l2p, &mut buf2);
            for k in 0..8 {
                let d = u64::from_le_bytes(buf2[k * 8..k * 8 + 8].try_into().unwrap());
                probe.push(format!("L2'[{k}] @ {:#x} = {d:#018x}", l2p + (k * 8) as u64));
            }
            // L1' (x25 + 0x4000) entries 0..16
            let l1p = LOAD_PA + 0x700000 + 0x4000;
            let mut buf3 = [0u8; 128];
            cpu.mem().read_bytes(l1p, &mut buf3);
            for k in 0..16 {
                let d = u64::from_le_bytes(buf3[k * 8..k * 8 + 8].try_into().unwrap());
                if d != 0 {
                    probe.push(format!("L1'[{k}] = {d:#018x}"));
                }
            }
            probe
        },
    })
}

/// Print the report honestly (verdict language mirrors PARITY.md).
pub fn print_report(r: &BootRealReport) {
    let stop = match &r.res.stop {
        StopReason::UnknownInsn { pc, insn } => format!("UnknownInsn {insn:#010x} @ {pc:#x}"),
        StopReason::TranslationFault { pc, va, kind, detail } => {
            format!("TranslationFault({kind}, {detail}) va={va:#x} pc={pc:#x}")
        }
        other => format!("{other:?}"),
    };
    println!();
    println!("real-kernel stop: {} after {} insns", stop, r.res.executed);
    println!(
        "MMU: {} · walks {} · tlb hits {} · faults {}",
        r.mmu_config, r.mmu_walks, r.mmu_tlb_hits, r.mmu_faults
    );
    println!(
        "unknown sysregs: {} reads / {} writes{}",
        r.unknown_sysreg_reads,
        r.unknown_sysreg_writes,
        if r.unknown_sysreg_list.is_empty() {
            String::new()
        } else {
            format!(" · {}", r.unknown_sysreg_list.join(", "))
        }
    );
    if !r.serial.is_empty() {
        let text: String = r
            .serial
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) || b == b'\n' { b as char } else { '.' })
            .collect();
        println!("UART output ({} B): {:?}", r.serial.len(), text);
    } else {
        println!("UART output: (none yet)");
    }
    if !r.trace.is_empty() {
        println!("last instructions:");
        for t in r.trace.iter().rev().take(48).collect::<Vec<_>>().iter().rev() {
            println!("    {t}");
        }
    }
    for line in &r.mem_probe {
        println!("{line}");
    }
    if let Some((spc, _, spv)) = &r.last_sp_change {
        println!("last SP change: pc={spc:#x} → sp={spv:#x}");
    } else {
        println!("last SP change: (none — SP never written after handoff)");
    }
    if !r.regs_dump.is_empty() {
        println!("{}", r.regs_dump.trim_end());
    }
    if !r.fault_chain.is_empty() {
        println!("fault descriptor chain (level, desc_addr, desc):");
        for (lvl, addr, desc) in &r.fault_chain {
            println!("    L{lvl} @ {addr:#x} = {desc:#018x}");
        }
    }
    let clean = r.res.stopped_cleanly();
    println!();
    println!("first-boot verdict (honest):");
    println!(
        "  {} real handoff: iBoot-equivalent state → real 18C66 `start` ({} insns retired)",
        if r.res.executed > 0 { "✅" } else { "❌" },
        r.res.executed
    );
    println!(
        "  {} MMU: {} walk(s) through the kernel's own tables",
        if r.mmu_walks > 0 { "✅" } else { "— (never armed)" },
        r.mmu_walks
    );
    println!(
        "  {} UART banner: {}",
        if !r.serial.is_empty() { "✅" } else { "❌ not reached yet" },
        if !r.serial.is_empty() { "kernel bytes on the wire" } else { "no kernel output yet" }
    );
    println!("  stop: {stop} · clean: {clean}");
}
