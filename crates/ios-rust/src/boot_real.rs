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
use apple_soc::t8030::{effective_dram_mb, T8030Machine};
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

/// iBoot-equivalent staging layout, computed from the REAL image/blob sizes
/// (REAL-DATA BUG #22: the first cut hardcoded TOP_OF_KERNEL_DATA = DT_PA =
/// 0x8_0400_0000 — but the 45.7 MB kernel image ends at PA 0x803AC8488, so
/// end_kern ≈ 0x803AD000 and the DT blob sat exactly AT topOfKernelData,
/// one step outside the physmap region arm_vm_init maps for it
/// ([end_kern, topOfKernelData), arm_vm_init.c:1471). The kernel's
/// PE_slide_devicetree then landed deviceTreeHead on the region START
/// (0x8030AD000), SecureDT parsed garbage 0xF53000 bytes away from the real
/// blob and panicked "Device tree pointer outside of device tree region"
/// (string 0xfffffff0073adec0, hit at pc 0xfffffff007a585d0 after
/// 8,135,422 insns — the panic path itself faults on TPIDR_EL1=0).
/// xnu's contract (arm_vm_init.c + pe_init.c, verified against the vendored
/// xnu-7195.121.3 source): deviceTreeP is the blob's bootstrap-map KVA
/// (blob_pa + virtBase − physBase); when the DT lives ABOVE the kernel text
/// (kvtophys(head) ≥ kvtophys(&_mh_execute_header) — SecureDTIsLockedDown
/// false), arm_vm_init slides the head onto the blob's final physmap VA,
/// which only lands correctly if the blob is INSIDE [end_kern,
/// topOfKernelData). So: kernel image → page-aligned end_kern → DT blob →
/// boot_args page → topOfKernelData = the page after boot_args.
///
/// REAL-DATA BUG #25 (tools/re/notes/m4-dt-rebase-re.md): end_kern is NOT
/// round_page(file bytes) — the kernel computes it from its own VA image
/// span: `end_kern = round_page(getlastaddr())` = round_page(max
/// (vmaddr+vmsize)), writer `str` @0x7b83758 into [0x7702568], measured
/// value 0xFFFFFFF009C60000 (0xB3000 above the file-backed end 0x9BAD000
/// KVA). Staging the DT at page(file-end) put the blob BELOW end_kern, so
/// arm_vm_physmap_init built tail entry e[DT].len = phystokv(top)−end_kern
/// = −0x7C000 (wraps 0xFFFFFFFFFFF84000) and the SecureDTIsLockedDown==
/// false rebase (PE_slide_devicetree, site 0x7b83f54) slid the DT head onto
/// e[4].va−0xB3000 — the __PRELINK_INFO window — so SecureDT parsed non-DT
/// bytes and panicked "Device tree pointer outside of device tree region"
/// (the 21,270-cycle exception storm followed, zeroing 24 MB of image).
/// Fix: stage at the VA-span end under the bootstrap identity
/// PA = VA − LINK_BASE + LOAD_PA ⇒ dt_pa 0x803C60000, e[DT].len positive,
/// head' = deviceTreeP = 0xFFFFFFF009C60000, rebase lands on the real blob.
struct StagedLayout {
    /// PA the kernel image is loaded at (= LOAD_PA).
    load_pa: u64,
    /// round_page(LOAD_PA + image bytes) — xnu `end_kern` PA side.
    end_kern_pa: u64,
    /// PA of the DeviceTree blob (inside [end_kern_pa, top_of_kernel_data)).
    dt_pa: u64,
    /// PA of boot_args (page after the DT blob).
    ba_pa: u64,
    /// Highest physical address used by the kernel data area — what
    /// boot_args.topOfKernelData carries (boot.h: "Highest physical address
    /// used in kernel data area").
    top_of_kernel_data: u64,
}

impl StagedLayout {
    /// `va_image_end` = max(vmaddr+vmsize) over the kernel's LC_SEGMENT_64s
    /// (what the kernel's getlastaddr() returns); `image_bytes` keeps the
    /// floor so a hypothetical file-backed tail can never be overwritten.
    /// ALL rounding is 16K: ARM64 xnu runs ARM_PGSHIFT=14, so the kernel's
    /// `round_page(getlastaddr())` is a 16K round — measured end_kern
    /// 0xFFFFFFF009C60000 = round16K(0x9C5C488); a 4K round (0x9C5D000)
    /// would stage the DT BELOW end_kern again (bug #25 re-spawned) and
    /// leaves the physmap tail entry un-pageable (len not a 16K multiple).
    fn compute(image_bytes: usize, va_image_end: u64, dt_bytes: usize) -> StagedLayout {
        let page = |x: u64| (x + 0x3FFF) & !0x3FFF;
        let kern_end_va = page(va_image_end.max(LINK_BASE + image_bytes as u64));
        let end_kern_pa = LOAD_PA + (kern_end_va - LINK_BASE);
        let dt_pa = end_kern_pa;
        let ba_pa = page(dt_pa + dt_bytes as u64);
        let top_of_kernel_data = page(ba_pa + 0x2E0);
        StagedLayout { load_pa: LOAD_PA, end_kern_pa, dt_pa, ba_pa, top_of_kernel_data }
    }

    /// The blob's kernel-side virtual address under the bootstrap map:
    /// VA = PA + virtBase − physBase (the identity every xnu arm64
    /// boot-time pointer follows; arm_vm_physmap_slide subtracts
    /// gVirtBase − gPhysBase to get the PA side). deviceTreeP carries this
    /// value; PE_slide_devicetree then converts it to the final physmap VA.
    fn dt_va(&self) -> u64 {
        LINK_BASE + (self.dt_pa - self.load_pa)
    }
}
fn mem_size() -> u64 {
    // 4 GiB (iPhone12,1) by default; IOS_RUST_DRAM_MB shrinks the window
    // for small sandboxes (bootargs memSize follows, see put(ba, 0x18)).
    effective_dram_mb() * 1024 * 1024
}
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
    /// THE M3 acceptance metric: insns retired with translated
    /// fetch/load/store (executed − mmu_live_from). None = MMU never armed.
    pub mmu_live_insns: Option<u64>,
    /// Translated accesses served (walks + TLB hits).
    pub mmu_accesses: u64,
    /// Per-kind walk-fault tally [fetch, load, store] + leaf histogram.
    pub mmu_fault_kinds: [u64; 3],
    pub mmu_leaf_levels: [u64; 4],
    /// MAIR attribute measurement (M3 bullet 1, recorded not enforced).
    pub attr_device_pages: u64,
    pub attr_normal_pages: u64,
    pub device_on_ram: u64,
    pub normal_on_mmio: u64,
    /// Bus silent-zero reads / dropped writes (unmapped MMIO) — surfaced
    /// because a wrong-but-alive kernel path is the worst failure class.
    pub bus_unmapped_reads: u64,
    pub bus_unmapped_writes: u64,
    /// Synthesized ESR_EL1/FAR_EL1 at the terminal stop (0/0 if none).
    pub esr_el1: u64,
    pub far_el1: u64,
    pub unknown_sysreg_reads: u64,
    pub unknown_sysreg_writes: u64,
    pub unknown_sysreg_list: Vec<String>,
    pub trace: Vec<String>,
    pub devices_attached: usize,
    pub adt_peripherals: usize,
    pub fault_chain: Vec<(u32, u64, u64)>,
    pub regs_dump: String,
    // --- M4 metrics ---
    /// Exceptions delivered to the guest's VBAR_EL1 (sync aborts + FIQ + IRQ).
    pub exc_taken: u64,
    pub fiq_taken: u64,
    pub irq_taken: u64,
    /// Synchronous aborts vectored (subset of exc_taken).
    pub sync_aborts: u64,
    /// M4-M: AT instructions executed (kvtophys sites now return real PAs).
    pub at_ops: u64,
    /// M4-M: AUT of build-signed pointers — accept-and-strip, counted.
    pub pac_aut_unverified: u64,
    /// M4-M: pc/word/lr/sp of a BRK/SVC/HVC/SMC terminal stop.
    pub panic_site: Option<(u64, u32, u64, u64)>,
    pub wfi_count: u64,
    pub wfi_wakeups: u64,
    /// Last delivered exception (kind, esr, far, elr).
    pub last_exception: Option<(&'static str, u64, u64, u64)>,
    /// GXF context register was seeded (provenance: kernel per-cpu base).
    pub gxf_ctx_seeded: bool,
    /// The discovered cpu_data[0] KVA (and its raw fields) for the report.
    pub cpu_data0_report: Vec<String>,
    /// M4 debug: (pc, addr, val) stores of boot-stack-range VAs.
    pub stack_write_log: Vec<(u64, u64, u64)>,
    // --- M4-b percpu-blocker diagnostics ---
    /// First 8 vectored sync aborts (insn, elr, far, esr) — the storm origin.
    pub first_aborts: Vec<(u64, u64, u64, u64)>,
    /// M5-O: FP chain of the FIRST vectored data abort + TPIDR_EL1 there.
    pub abort_backtrace: Vec<(u64, u64)>,
    pub abort_frames: Vec<[u64; 6]>,
    pub abort_tpidr: u64,
    /// Last 24 vectored sync aborts (insn, elr, far, esr) — the loop shape.
    pub last_aborts: Vec<(u64, u64, u64, u64)>,
    pub sync_abort_total: u64,
    /// cpu_stack_alloc fingerprint stores: (pc, va, val) into __DATA.
    pub data_stores: Vec<(u64, u64, u64)>,
    pub data_store_count: u64,
    /// 48-bit-truncated kernel-VA stores (REAL-DATA BUG probe).
    pub poison_stores: Vec<(u64, u64, u64)>,
    pub poison_count: u64,
    /// panic() entries: (insn, x0 fmt, x1, x2, x3), first 64 + total count.
    pub panic_calls: Vec<(u64, u64, u64, u64, u64, u64)>,
    pub panic_call_count: u64,
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
fn parse_kernel(img: &[u8]) -> Result<(u64, u64, Vec<(String, u64, u64, u64, u64)>), String> {
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
                let vmsize = u64le(img, off + 32)?;
                let fileoff = u64le(img, off + 40)?;
                let filesize = u64le(img, off + 48)?;
                segs.push((name, vmaddr, vmsize, fileoff, filesize));
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

/// boot_args for arm64 — the layout the real 18C66 binary loads (measured,
/// see tools/re/notes/m4-aic-timer-re.md + m4-dt-gate-re.md + boot.h):
/// virtBase@0x8, physBase@0x10, memSize@0x18, topOfKernelData@0x20 (u64 each),
/// Video (6×u64) @0x28..0x58, machineType@0x58, **deviceTreeP@0x60,
/// deviceTreeLength@0x68**, CommandLine[608]@0x70, bootFlags@0x2d0,
/// memSizeActual@0x2d8. REAL-DATA BUG #20: the M2-era builder wrote the DT
/// pointer at +0x28 (inside Video) — PE_init_platform reads +0x60/+0x68,
/// so every DT global shipped zero and /cpus enumeration faulted on NULL
/// after 8,135,842 insns.
fn build_boot_args(
    virt_base: u64,
    phys_base: u64,
    top_of_kernel_data: u64,
    dt_va: u64,
    dt_len: u32,
) -> Vec<u8> {
    let mut ba = vec![0u8; 0x2E0];
    let put = |buf: &mut Vec<u8>, off: usize, v: u64| {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };
    // Revision 2 / Version 2 — what real iBoot ships (kBootArgsRevision2 =
    // the rev that makes bootFlags@0x2d0 valid; the kernel reads bootFlags
    // unconditionally in the early CPU-start paths, 0x8168110/0x8168238).
    ba[0..2].copy_from_slice(&2u16.to_le_bytes()); // Revision
    ba[2..4].copy_from_slice(&2u16.to_le_bytes()); // Version
    put(&mut ba, 0x08, virt_base);
    put(&mut ba, 0x10, phys_base);
    put(&mut ba, 0x18, mem_size());
    put(&mut ba, 0x20, top_of_kernel_data);
    // Video @0x28..0x58 stays zero (no framebuffer handoff)
    put(&mut ba, 0x58, 0); // machineType
    put(&mut ba, 0x60, dt_va); // deviceTreeP — kernel VA the boot maps cover
    ba[0x68..0x6C].copy_from_slice(&dt_len.to_le_bytes()); // deviceTreeLength
    // CommandLine[608]@0x70 stays zero
    put(&mut ba, 0x2D0, 0); // bootFlags (dark-boot bit clear)
    put(&mut ba, 0x2D8, mem_size()); // memSizeActual
    ba
}

/// iBoot-equivalent DeviceTree staging: real iBoot marks the core it
/// executes on `state = "running"` before the xnu jump. The IPSW blob is
/// the pre-patch template — ALL 6 /cpus nodes ship b"waiting\0" (measured
/// on DeviceTree.n104ap; xnu's ml_is_boot_cpu picks the node whose state
/// is "running", machine_routines.c:924, tools/re/notes/m4-dt-gate-re.md
/// §6/E14 — with asserts compiled out the enumerator otherwise runs all 6
/// and dies on `topology_info.boot_cpu->cpu_id`). We boot on cpu0 (reg 0,
/// first child in pre-order), so flip exactly the FIRST "waiting\0" —
/// same 8-byte length, nothing else in the blob changes. Returns the
/// number of "waiting" nodes seen (6 = the real n104ap shape).
fn patch_boot_cpu_running(dt: &mut [u8]) -> usize {
    const WAITING: &[u8] = b"waiting\0";
    let n = dt.windows(WAITING.len()).filter(|w| *w == WAITING).count();
    if n > 0 {
        if let Some(pos) = dt.windows(WAITING.len()).position(|w| w == WAITING) {
            dt[pos..pos + WAITING.len()].copy_from_slice(b"running\0");
        }
    }
    n
}

/// REAL-DATA BUG #25 fix — iBoot-equivalent DeviceTree placeholder
/// processing. The IPSW blob ships 87 properties whose length word has
/// bit31 SET (measured: regulatory-model-number, serial-number,
/// mac-address-*, *-color … — every one an identity/metadata string whose
/// data is a SysCfg REFERENCE like b"syscfg/SrNm/0x20,zeroes/"). On real
/// hardware iBoot resolves those from the SysCfg partition before the
/// kernel ever sees the tree; the raw kernel-side DT walker
/// (0xfffffff008136fd4) adds the RAW length (bit31 set → 0x80000011) and
/// its own bounds check panics
/// "Device tree pointer outside of device tree region" (0x…73adec0 — the
/// M4 blocker, measured at insn 8,135,397). We have no SysCfg device, so
/// the honest iBoot-equivalent-without-SysCfg transform: CLEAR the flag
/// bit on the staged copy — the kernel reads each property's own in-blob
/// reference bytes (no values invented, the limit is visible in the
/// banner if the kernel prints them). Structure per crates/adt
/// (parse_flat): node = {u32 nprops, u32 nchildren}, prop = {name[32],
/// u32 len, data[len] 4-aligned}, children pre-order. Returns the number
/// of flags cleared; the walk must consume the blob EXACTLY.
fn dt_clear_placeholder_flags(dt: &mut [u8]) -> Result<usize, String> {
    const PLACEHOLDER: u32 = 1 << 31;
    let mut cleared = 0usize;
    fn walk(dt: &mut [u8], off: usize, cleared: &mut usize) -> Result<usize, String> {
        if off + 8 > dt.len() {
            return Err(format!("ADT node header past end @ {off:#x}"));
        }
        let rd = |dt: &[u8], p: usize| -> u32 { u32::from_le_bytes(dt[p..p + 4].try_into().unwrap()) };
        let nprops = rd(dt, off) as usize;
        let nchildren = rd(dt, off + 4) as usize;
        let mut p = off + 8;
        for _ in 0..nprops {
            if p + 36 > dt.len() {
                return Err(format!("ADT prop header past end @ {p:#x}"));
            }
            let raw = rd(dt, p + 32);
            let len = (raw & 0x7FFF_FFFF) as usize;
            if raw & PLACEHOLDER != 0 {
                dt[p + 32..p + 36].copy_from_slice(&(len as u32).to_le_bytes());
                *cleared += 1;
            }
            p = (p + 36 + len + 3) & !3;
        }
        for _ in 0..nchildren {
            p = walk(dt, p, cleared)?;
        }
        Ok(p)
    }
    let end = walk(dt, 0, &mut cleared)?;
    if end != dt.len() {
        return Err(format!("ADT walk consumed {end} of {} bytes", dt.len()));
    }
    Ok(cleared)
}

/// Extent of the node at `off` (its header + props + full subtree), using
/// the same record math as `dt_clear_placeholder_flags`' walk.
fn walk_extent(dt: &[u8], off: usize) -> usize {
    let rd = |p: usize| -> u32 { u32::from_le_bytes(dt[p..p + 4].try_into().unwrap()) };
    let nprops = rd(off) as usize;
    let nchildren = rd(off + 4) as usize;
    let mut p = off + 8;
    for _ in 0..nprops {
        let len = (rd(p + 32) & 0x7FFF_FFFF) as usize;
        p = (p + 36 + len + 3) & !3;
    }
    for _ in 0..nchildren {
        p = walk_extent(dt, p);
    }
    p
}

// --- M5-P: iBoot-equivalent /chosen/lock-regs populate (REAL-DATA BUG #41) ---
//
// The kernel's AMCC lock-regs bring-up (parser 0x…7b7c390, caller
// 0x…7b7c0a0 — reached at insn 22,688,176 after bug #40 fell) requires:
//   /chosen/lock-regs/amcc:  aperture-count (<17, u32), aperture-size
//   (u32 ≠ 0), plane-count (<17, u32), plane-stride (u32, optional),
//   aperture-phys-addr (count×8 B, ≤ 0x80), cache-status-reg-offset/mask/
//   value (u32 ×3); /chosen/lock-regs/amcc/amcc-ctrr-a: page-size-shift
//   (u32) + lower-limit/upper-limit/lock/enable/disable -reg-offset/mask/
//   value (u32 each). Missing 'aperture-count' panicked the kernel's OWN
//   "lock-regs: cannot find required property 'aperture-count'".
// The IPSW EDT ships the node STUB-EMPTY (name + AAPL,phandle only) — on
// real hardware iBoot fills the runtime aperture geometry before the
// jump. The honest emulator equivalent: synthesize ONE self-consistent
// aperture (count=1, 16 KB window, plane=1) over a RAM PA at the DRAM
// midpoint, page-size-shift=14 (T8030's 16K pages), and all reg offsets/
// masks/values = 0 (the kernel samples [aperture+offset] per plane and
// requires CONSISTENCY across planes only — with count=1/plane=1 the
// check is trivially satisfied; sampled 0 → zero-size lock region).
// Honesty note: real iBoot AMCC geometry is hardware state we do not
// model — the synthesized values are documented emulator choices, not
// measured hardware numbers.

/// Offset of the direct child of `node_off` whose name prop == `want`.
fn dt_find_child(dt: &[u8], node_off: usize, want: &str) -> Option<usize> {
    let rd = |p: usize| -> u32 { u32::from_le_bytes(dt[p..p + 4].try_into().unwrap()) };
    let nprops = rd(node_off) as usize;
    let nchildren = rd(node_off + 4) as usize;
    let mut p = node_off + 8;
    for _ in 0..nprops {
        let len = (rd(p + 32) & 0x7FFF_FFFF) as usize;
        p = (p + 36 + len + 3) & !3;
    }
    for _ in 0..nchildren {
        let child = p;
        // child name = first prop "name"
        let cnprops = rd(child) as usize;
        let mut q = child + 8;
        let mut name: Option<String> = None;
        for _ in 0..cnprops {
            if dt.len() >= q + 5 && &dt[q..q + 5] == b"name\x00" {
                let vlen = (rd(q + 32) & 0x7FFF_FFFF) as usize;
                let v = &dt[q + 36..(q + 36 + vlen).min(dt.len())];
                let v = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
                name = Some(String::from_utf8_lossy(v).into_owned());
            }
            let len = (rd(q + 32) & 0x7FFF_FFFF) as usize;
            q = (q + 36 + len + 3) & !3;
        }
        if name.as_deref() == Some(want) {
            return Some(child);
        }
        p = walk_extent(dt, child);
    }
    None
}

/// Byte offset just past `node_off`'s own property list (= first child /
/// node end).
fn dt_props_end(dt: &[u8], node_off: usize) -> usize {
    let rd = |p: usize| -> u32 { u32::from_le_bytes(dt[p..p + 4].try_into().unwrap()) };
    let nprops = rd(node_off) as usize;
    let mut p = node_off + 8;
    for _ in 0..nprops {
        let len = (rd(p + 32) & 0x7FFF_FFFF) as usize;
        p = (p + 36 + len + 3) & !3;
    }
    p
}

/// Append one property (name[32] + u32 len + data, 4-aligned) at `at`,
/// bumping `node_off`'s nprops. Data is padded to 4 bytes by the caller.
fn dt_append_prop(dt: &mut Vec<u8>, at: usize, node_off: usize, name: &str, data: &[u8]) {
    assert!(name.len() < 32, "prop name too long: {name}");
    let mut rec = vec![0u8; 32];
    rec[..name.len()].copy_from_slice(name.as_bytes());
    rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
    rec.extend_from_slice(data);
    while rec.len() % 4 != 0 {
        rec.push(0);
    }
    let nprops = u32::from_le_bytes(dt[node_off..node_off + 4].try_into().unwrap());
    dt.splice(at..at, rec);
    dt[node_off..node_off + 4].copy_from_slice(&(nprops + 1).to_le_bytes());
}

/// Populate /chosen/lock-regs/{amcc,amcc-ctrr-a} with the aperture config
/// the kernel's lock-regs parser requires (see the block comment above).
/// `aperture_pa` = the one aperture's physical address (RAM-backed).
/// Returns the number of properties written.
fn dt_populate_amcc_lockregs(dt: &mut Vec<u8>, aperture_pa: u64) -> Result<usize, String> {
    let rd = |p: usize| -> u32 { u32::from_le_bytes(dt[p..p + 4].try_into().unwrap()) };
    // root → chosen → lock-regs → amcc (pre-order path walk).
    // Measured: the iOS 14.3 (18C66) EDT ships the subtree STUB-EMPTY
    // (name + AAPL,phandle only); the iOS 13.7 (17H35) EDT does NOT ship
    // it at all — the RE addresses in this file are pinned to 18C66, so
    // an older EDT is a fixture mismatch, not a staging bug.
    let mut off = 0usize;
    for want in ["chosen", "lock-regs", "amcc"] {
        off = dt_find_child(dt, off, want).ok_or_else(|| {
            format!(
                "lock-regs populate: /{want} node not found \
                 (boot-real is pinned to the iOS 14.3 18C66 EDT, which ships \
                 /chosen/lock-regs stub-empty — an older EDT lacks the node)"
            )
        })?;
    }
    let amcc = off;

    let u32le = |v: u32| v.to_le_bytes().to_vec();
    let mut written = 0usize;

    // amcc props — inserted BEFORE its first child (amcc-ctrr-a).
    let at = dt_props_end(dt, amcc);
    // order: append sequentially; each dt_append_prop bumps at by rec len,
    // so track the cursor manually.
    let mut cur = at;
    for (name, data) in [
        ("aperture-count", u32le(1)),
        ("aperture-size", u32le(0x4000)),
        ("plane-count", u32le(1)),
        ("plane-stride", u32le(0x4000)),
        ("aperture-phys-addr", aperture_pa.to_le_bytes().to_vec()),
        ("cache-status-reg-offset", u32le(0)),
        ("cache-status-reg-mask", u32le(0)),
        ("cache-status-reg-value", u32le(0)),
    ] {
        dt_append_prop(dt, cur, amcc, name, &data);
        cur += (32 + 4 + data.len() + 3) & !3;
        written += 1;
    }

    // amcc-ctrr-a props — RE-FIND the child (the amcc splice shifted every
    // later byte), then append at its end (the node has no children).
    let ctrr = dt_find_child(dt, amcc, "amcc-ctrr-a")
        .ok_or_else(|| "lock-regs populate: amcc-ctrr-a node not found".to_string())?;
    let at = dt_props_end(dt, ctrr);
    let mut cur = at;
    for (name, data) in [
        ("page-size-shift", u32le(14)),
        ("lower-limit-reg-offset", u32le(0)),
        ("lower-limit-reg-mask", u32le(0)),
        ("upper-limit-reg-offset", u32le(0)),
        ("upper-limit-reg-mask", u32le(0)),
        ("lock-reg-offset", u32le(0)),
        ("lock-reg-mask", u32le(0)),
        ("lock-reg-value", u32le(0)),
        ("enable-reg-offset", u32le(0)),
        ("enable-reg-mask", u32le(0)),
        ("enable-reg-value", u32le(0)),
        ("disable-reg-offset", u32le(0)),
        ("disable-reg-mask", u32le(0)),
        ("disable-reg-value", u32le(0)),
    ] {
        dt_append_prop(dt, cur, ctrr, name, &data);
        cur += (32 + 4 + data.len() + 3) & !3;
        written += 1;
    }
    Ok(written)
}


/// REAL-DATA BUG #36 fix — iBoot-equivalent `random-seed` staging. The real
/// kernel reads **/chosen/random-seed** (measured RE: the seed helper
/// 0x…81383ac does `SecureDTLookupEntry(0, "/chosen")` with the path string
/// @0x…73ae1a0, then `SecureDTGetProperty(entry, "random-seed")` with the
/// name @0x…73adf81, requiring ≥ 0x40 bytes — "Expected %lu seed bytes from
/// bootloader, but got %u" fired at insn 8,418,563 in the first post-#35
/// boot). On real hardware iBoot fills it with entropy gathered from the
/// hardware RNG (Secure Enclave/sepo RNG) before the kernel jump. The IPSW
/// DeviceTree template ships NO such property (measured: absent from the
/// decoded blob — it is an iBoot-side addition, not an IPSW one), so the
/// honest emulator equivalent is to stage the property exactly like iBoot
/// would, with a DETERMINISTIC 64-byte value (sha256 of a fixed label,
/// doubled). Honesty note: this is emulated entropy — a fixed, reproducible
/// seed, NOT hardware randomness; a real-RNG source stays a tracked gap.
/// Property layout per crates/adt (parse_flat): {name[32], u32 len,
/// data[len] 4-aligned}; node = {u32 nprops, u32 nchildren}; children
/// pre-order. The /chosen node is created (appended as the LAST root
/// child, the blob grown) when absent — child order is not semantic.
fn dt_insert_random_seed(dt: &mut Vec<u8>) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    // 64 deterministic bytes: two SHA-256 blocks over a fixed label.
    let mut h = Sha256::new();
    h.update(b"ios-rust emulator boot random-seed v1");
    let h1 = h.finalize_reset();
    h.update(&h1);
    h.update(b"ios-rust emulator boot random-seed v1");
    let h2 = h.finalize();
    let seed: Vec<u8> = h1.iter().copied().chain(h2.iter().copied()).collect();
    assert_eq!(seed.len(), 64);

    const NAME_LEN: usize = 32;
    let rd = |b: &[u8], p: usize| -> u32 {
        u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
    };
    if dt.len() < 8 {
        return Err("ADT too small for a root node".into());
    }
    // ---- locate the /chosen child of the root (pre-order walk) ----
    let nprops_root = rd(dt, 0) as usize;
    let nchildren_root = rd(dt, 4) as usize;
    let mut p = 8usize;
    for _ in 0..nprops_root {
        let len = (rd(dt, p + 32) & 0x7FFF_FFFF) as usize;
        p = (p + 36 + len + 3) & !3;
    }
    let mut chosen: Option<(usize, usize)> = None; // (node_off, node_end)
    for _ in 0..nchildren_root {
        let node_off = p;
        let cnprops = rd(dt, node_off) as usize;
        let _cnchildren = rd(dt, node_off + 4) as usize;
        let mut q = node_off + 8;
        let mut is_chosen = false;
        for _ in 0..cnprops {
            if &dt[q..q + 5] == b"name\x00" && dt[q + 5] == 0 {
                // the node's "name" property: value = "chosen"
                let vlen = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
                let v = &dt[q + 36..q + 36 + vlen];
                let v = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
                is_chosen = v == b"chosen";
            }
            let len = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
            q = (q + 36 + len + 3) & !3;
        }
        // measure the node's extent: its own subtree (children pre-order)
        let mut end = q;
        for _ in 0.._cnchildren {
            end = walk_extent(dt, end);
        }
        if is_chosen {
            chosen = Some((node_off, end));
            break;
        }
        p = end;
    }
    let mut prop = Vec::with_capacity(36 + 64);
    let mut name = [0u8; NAME_LEN];
    name[..11].copy_from_slice(b"random-seed");
    prop.extend_from_slice(&name);
    prop.extend_from_slice(&64u32.to_le_bytes());
    prop.extend_from_slice(&seed);

    match chosen {
        Some((node_off, node_end)) => {
            println!(
                "[stage] random-seed: /chosen found @ blob+{:#x} (extent {:#x}), root children {}",
                node_off, node_end, nchildren_root
            );
            // insert/replace random-seed inside /chosen's own prop list
            let cnprops = rd(dt, node_off) as usize;
            let mut q = node_off + 8;
            let mut existing: Option<(usize, usize)> = None;
            for _ in 0..cnprops {
                if &dt[q..q + 11] == b"random-seed" && dt[q + 11] == 0 {
                    existing = Some((q, rd(dt, q + 32) as usize));
                }
                let len = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
                q = (q + 36 + len + 3) & !3;
            }
            if let Some((off, raw_len)) = existing {
                let val = &dt[off + 36..off + 36 + (raw_len & 0x7FFF_FFFF)];
                println!(
                    "[stage] random-seed: existing prop @ blob+{off:#x} raw_len={raw_len:#x} val[:16]={:02x?}",
                    &val[..val.len().min(16)]
                );
            }
            match existing {
                Some((off, len)) if len == 64 => {
                    // REAL-DATA BUG #36, measured: the IPSW template ships the
                    // property as 64 ZERO bytes — on real hardware iBoot
                    // overwrites them with entropy before the kernel jump,
                    // and the kernel's read helper (0x…81383ac) treats an
                    // all-zero seed as "bootloader didn't fill it" (it counts
                    // original zero bytes and returns 0 on all-zero — the
                    // panic we measured). Stage = overwrite the zero template
                    // with the deterministic emulated entropy, in place.
                    let val = &mut dt[off + 36..off + 36 + 64];
                    if val.iter().all(|&b| b == 0) {
                        val.copy_from_slice(&seed);
                        println!(
                            "[stage] random-seed: zero template @ blob+{off:#x} → 64 B deterministic entropy staged"
                        );
                    } else {
                        println!("[stage] random-seed: already filled (non-zero) — blob untouched");
                    }
                    Ok(())
                }
                Some((off, len)) => {
                    println!("[stage] random-seed: replacing wrong-size ({len}) prop");
                    let old_end = (off + 36 + len + 3) & !3;
                    dt.splice(off..old_end, prop);
                    Ok(())
                }
                None => {
                    println!("[stage] random-seed: inserting into /chosen props");
                    dt.splice(q..q, prop);
                    dt[node_off..node_off + 4]
                        .copy_from_slice(&((cnprops as u32) + 1).to_le_bytes());
                    Ok(())
                }
            }
        }
        None => {
            println!(
                "[stage] random-seed: /chosen ABSENT — appending node (root children {})",
                nchildren_root
            );
            // /chosen absent — append a new node as the LAST root child and
            // bump the root's nchildren.
            let mut node = Vec::with_capacity(8 + prop.len());
            node.extend_from_slice(&1u32.to_le_bytes()); // nprops
            node.extend_from_slice(&0u32.to_le_bytes()); // nchildren
            node.extend_from_slice(&prop);
            dt.extend_from_slice(&node);
            dt[4..8].copy_from_slice(&((nchildren_root as u32) + 1).to_le_bytes());
            Ok(())
        }
    }
}


/// M4-M: insert (or replace) a u64 `/chosen/<name>` property — the generic
/// form of dt_insert_random_seed's mechanics. iBoot adds dram-base/dram-size
/// to /chosen before the kernel jump (arm_init panics without them — the
/// kernel-named blocker at insn 11,419,858). Values are the machine's real
/// DRAM geometry so every staged memory description stays consistent.
fn dt_insert_chosen_u64(dt: &mut Vec<u8>, prop_name: &str, val: u64) -> Result<(), String> {
    assert!(prop_name.len() < 32, "prop name too long");
    const NAME_LEN: usize = 32;
    let rd = |b: &[u8], p: usize| -> u32 {
        u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
    };
    if dt.len() < 8 {
        return Err("ADT too small for a root node".into());
    }
    let nprops_root = rd(dt, 0) as usize;
    let nchildren_root = rd(dt, 4) as usize;
    let mut p = 8usize;
    for _ in 0..nprops_root {
        let len = (rd(dt, p + 32) & 0x7FFF_FFFF) as usize;
        p = (p + 36 + len + 3) & !3;
    }
    let mut chosen: Option<(usize, usize)> = None;
    for _ in 0..nchildren_root {
        let node_off = p;
        let cnprops = rd(dt, node_off) as usize;
        let _cnchildren = rd(dt, node_off + 4) as usize;
        let mut q = node_off + 8;
        let mut is_chosen = false;
        for _ in 0..cnprops {
            if &dt[q..q + 5] == b"name\x00" && dt[q + 5] == 0 {
                let vlen = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
                let v = &dt[q + 36..q + 36 + vlen];
                let v = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
                is_chosen = v == b"chosen";
            }
            let len = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
            q = (q + 36 + len + 3) & !3;
        }
        let mut end = q;
        for _ in 0.._cnchildren {
            end = walk_extent(dt, end);
        }
        if is_chosen {
            chosen = Some((node_off, end));
            break;
        }
        p = end;
    }
    let mut prop = Vec::with_capacity(36 + 8);
    let mut name = [0u8; NAME_LEN];
    name[..prop_name.len()].copy_from_slice(prop_name.as_bytes());
    prop.extend_from_slice(&name);
    prop.extend_from_slice(&8u32.to_le_bytes());
    prop.extend_from_slice(&val.to_le_bytes());

    match chosen {
        Some((node_off, _node_end)) => {
            let cnprops = rd(dt, node_off) as usize;
            let mut q = node_off + 8;
            let mut existing: Option<(usize, usize)> = None;
            for _ in 0..cnprops {
                let key = &dt[q..q + prop_name.len()];
                let nul = dt[q + prop_name.len()];
                if key == prop_name.as_bytes() && nul == 0 {
                    existing = Some((q, rd(dt, q + 32) as usize));
                }
                let len = (rd(dt, q + 32) & 0x7FFF_FFFF) as usize;
                q = (q + 36 + len + 3) & !3;
            }
            match existing {
                Some((off, len)) if len == 8 => {
                    dt[off + 36..off + 44].copy_from_slice(&val.to_le_bytes());
                    Ok(())
                }
                Some((off, len)) => {
                    let old_end = (off + 36 + len + 3) & !3;
                    dt.splice(off..old_end, prop);
                    Ok(())
                }
                None => {
                    dt.splice(q..q, prop);
                    dt[node_off..node_off + 4]
                        .copy_from_slice(&((cnprops as u32) + 1).to_le_bytes());
                    Ok(())
                }
            }
        }
        None => {
            // /chosen absent — append (the random-seed pass would have
            // created it first; this ordering keeps us robust anyway).
            let mut node = Vec::with_capacity(8 + 2 * prop.len());
            node.extend_from_slice(&2u32.to_le_bytes());
            node.extend_from_slice(&0u32.to_le_bytes());
            node.extend_from_slice(&prop);
            dt.extend_from_slice(&node);
            dt[4..8].copy_from_slice(&((nchildren_root as u32) + 1).to_le_bytes());
            Ok(())
        }
    }
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

    // iBoot-equivalent boot-CPU staging (see patch_boot_cpu_running): the
    // IPSW template ships all 6 /cpus nodes "waiting"; flip cpu0 → running.
    let mut dt_blob = dt_blob;
    let waiting_nodes = patch_boot_cpu_running(&mut dt_blob);
    println!(
        "[stage] DeviceTree boot-cpu: {waiting_nodes} \"waiting\" nodes, first (cpu0) → \"running\""
    );
    // REAL-DATA BUG #25 (see dt_clear_placeholder_flags): clear the 87
    // bit31 placeholder-length flags iBoot would have resolved from SysCfg.
    let placeholders = dt_clear_placeholder_flags(&mut dt_blob)
        .map_err(|e| format!("DT placeholder pass: {e}"))?;
    println!(
        "[stage] DeviceTree placeholders: {placeholders} bit31 length flags cleared \
         (iBoot SysCfg pass — values stay the blob's own reference bytes)"
    );
    // REAL-DATA BUG #36 (see dt_insert_random_seed): iBoot stages a 64-byte
    // /random-seed property the kernel hard-requires; the IPSW template
    // ships none. Deterministic emulated entropy, documented in the fn.
    dt_insert_random_seed(&mut dt_blob)?;
    println!("[stage] DeviceTree random-seed: 64 B staged (deterministic emulated entropy)");
    // M4-M (kernel-named blocker): arm_init's memory-domain setup reads
    // /chosen/dram-base + /chosen/dram-size (u64 each, SecureDTGetProperty
    // at 0x…7b80d34/d60) and panics "Unable to find 'dram-base' entry in
    // the 'chosen' DT node" (fmt 0x…73676f4, panic at insn 11,419,858 —
    // the GDB-trap 0xE7FFDEFF path). The IPSW template ships neither prop
    // (iBoot adds them). Stage the machine's REAL DRAM geometry — the
    // same window the DRAM region is attached at and boot_args.memSize
    // describes — so every memory description stays consistent.
    let dram_mb = effective_dram_mb();
    let dram_base: u64 = 0x8_0000_0000;
    let dram_size: u64 = dram_mb as u64 * 1024 * 1024;
    dt_insert_chosen_u64(&mut dt_blob, "dram-base", dram_base)?;
    dt_insert_chosen_u64(&mut dt_blob, "dram-size", dram_size)?;
    println!(
        "[stage] DeviceTree dram-base/dram-size: {dram_base:#x}/{dram_size:#x} staged (machine DRAM geometry)"
    );

    // ---- M5-P: iBoot-equivalent /chosen/lock-regs aperture populate ----
    // The kernel's AMCC bring-up (parser 0x…7b7c390) requires aperture
    // properties the IPSW EDT stub doesn't carry (REAL-DATA BUG #41 —
    // "lock-regs: cannot find required property 'aperture-count'" at insn
    // 22,688,176). One aperture over a RAM PA at the DRAM midpoint.
    let aperture_pa = dram_base + (dram_size / 2) & !0x3FFF;
    let lockregs_props = dt_populate_amcc_lockregs(&mut dt_blob, aperture_pa)?;
    println!(
        "[stage] DeviceTree /chosen/lock-regs populated: {lockregs_props} props staged \
         (1×16KB aperture @ {aperture_pa:#x}, page-size-shift 14, reg locks 0)"
    );

    // ---- 3) machine assembly (iBoot equivalent) ----
    // Staging layout computed from the REAL sizes (BUG #22 — see
    // StagedLayout): image → end_kern → DT blob → boot_args page →
    // topOfKernelData.
    // REAL-DATA BUG #25: end_kern from the kernel's own VA span, not the
    // file size (see StagedLayout::compute doc).
    let va_image_end = segs
        .iter()
        .map(|s| s.1 + s.2)
        .max()
        .unwrap_or(LINK_BASE + img.len() as u64);
    let layout = StagedLayout::compute(img.len(), va_image_end, dt_blob.len());
    println!(
        "[stage] end_kern {:#x} · DT @ {:#x} ({} B, bootstrap-KVA {:#x}) · boot_args @ {:#x} · topOfKernelData {:#x}",
        layout.end_kern_pa,
        layout.dt_pa,
        dt_blob.len(),
        layout.dt_va(),
        layout.ba_pa,
        layout.top_of_kernel_data
    );
    let mut machine = T8030Machine::new(effective_dram_mb());
    let devices_attached = machine.attach_from_adt(&adt);
    let serial = machine.serial.clone();
    let machine_irq_line = machine.irq_line.clone();
    let mut bus = std::mem::replace(&mut machine.bus, Bus::new());

    // REAL-DATA BUG #35 (session L, 2026-10-30): per-segment staging at the
    // VA-implied PA (PA = VA − LINK_BASE + LOAD_PA — the mapping the
    // kernel's own start.s tables implement). The old flat
    // `write_raw(LOAD_PA, &img)` staged the FILE contiguously, which is
    // only equivalent while fileoff == vmaddr − LINK_BASE. That identity
    // breaks at __DATA's BSS (vmsize > filesize): every segment after it
    // (__BOOTDATA, __PRELINK_INFO) landed 0xB0000 BELOW its VA-implied PA,
    // so the kernel's tables resolved __BOOTDATA VAs onto __PRELINK_INFO
    // plist bytes — the init-entry cursor @0x…9b031e8 read "<key>UID"
    // ASCII (measured: FAR 0x4449553e79656b3c) and the entry calls
    // deranged. Segments BEFORE the BSS are byte-identical under both
    // schemes (fileoff == vmaddr − LINK_BASE there), so this is a strict
    // generalization, verified by the boot contract below.
    for (name, vmaddr, vmsize, fileoff, filesize) in segs.iter() {
        // Skip zero-size prelink placeholders and segments below the link
        // base (__PRELINK_TEXT vmaddr 0xfffffff004004000 < LINK_BASE — the
        // old-style bare kernel ships them zero-size; start.s maps nothing
        // there and the real iBoot stages nothing either).
        if *vmsize == 0 || *filesize == 0 || *vmaddr < link_base {
            continue;
        }
        let seg_pa = LOAD_PA + (vmaddr - link_base);
        let fo = *fileoff as usize;
        let fsz = *filesize as usize;
        bus.write_raw(seg_pa, &img[fo..fo + fsz]);
        let _ = name;
    }
    // REAL-DATA BUG #26 — iBoot-equivalent BSS zero-fill. The flat
    // `write_raw` above stages the whole FILE, but segments with
    // vmsize > filesize (BSS) must be ZERO beyond their file bytes. The
    // real image's __DATA has a 0x63638-byte BSS tail; our flat write put
    // the next file bytes there — the embedded IOCatalogue personalities
    // plist text (b"pple.iokit.IOUSBHostFami...") — so the kernel's DT
    // cursor global at BSS 0x…9adf638 read plist ASCII as a POINTER and
    // the IOCatalogue path deref-faulted (far = 0x696d614674736f48,
    // measured @ insn 8,148,893 — the post-bug-#25 blocker).
    for (name, vmaddr, vmsize, _fileoff, filesize) in segs.iter() {
        if vmsize > filesize {
            let bss_pa = LOAD_PA + (vmaddr + filesize - link_base);
            let n = (vmsize - filesize) as usize;
            bus.write_raw(bss_pa, &vec![0u8; n]);
            println!(
                "[stage] BSS zero-fill: {name} vm {vmaddr:#x} · {} B beyond file bytes",
                n
            );
        }
    }
    bus.write_raw(layout.dt_pa, &dt_blob);
    let ba = build_boot_args(
        LINK_BASE,
        LOAD_PA,
        layout.top_of_kernel_data,
        layout.dt_va(),
        dt_blob.len() as u32,
    );
    bus.write_raw(layout.ba_pa, &ba);

    // HLT canary page (a stray RET lands here and halts cleanly)
    let mut pause = Ram::new("boot-pause", 0x1000);
    pause.data[..4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    bus.attach(PAUSE_PA, 0x1000, Box::new(pause));

    // ---- 4) CPU state: the iBoot→xnu handoff ----
    let entry_pa = LOAD_PA + (entry - link_base);
    let mut cpu = Interpreter::new(Box::new(BusMem(bus)));
    // M4: bind the machine's AIC→CPU shared IRQ line.
    cpu.irq_line = Some(machine_irq_line);
    cpu.set_reset_vector(entry_pa);
    cpu.x[0] = layout.ba_pa; // boot_args pointer (physical, MMU off)
    cpu.x[30] = PAUSE_PA;
    cpu.sp = 0;
    cpu.trace_enabled = true;
    // M4: give the cpu_data[0] discovery scan the kernel's __DATA window
    // (PA = load PA + segment offset from the link base).
    if let Some((_, data_va, _, _, _)) = segs.iter().find(|(n, _, _, _, _)| n == "__DATA") {
        let pa = LOAD_PA + (data_va - link_base);
        cpu.cpu_data_scan = Some((pa, pa + 0x300_000));
    }
    // KVA identity for the discovery seed: VA = PA + virtBase − physBase.
    cpu.kva_base = LINK_BASE - LOAD_PA;
    // M4-b: PA aliases for VA store-watches — pre-MMU stores use PHYSICAL
    // addresses, post-MMU the same global is the KVA. Watch both forms.
    {
        let pa_aliases: Vec<u64> = cpu
            .watch_store_vas
            .iter()
            .map(|&kva| LOAD_PA + (kva.wrapping_sub(LINK_BASE)))
            .collect();
        cpu.watch_store_vas.extend(pa_aliases);
    }
    // M4-b guardrail: an exception entry with SP below __TEXT_EXEC means
    // the exception stack descended into the kernel image (named stop).
    if let Some((_, text_exec_va, _, _, _)) = segs.iter().find(|(n, _, _, _, _)| *n == "__TEXT_EXEC") {
        cpu.text_floor_kva = Some(*text_exec_va);
    }
    // M4 debug: capture the kernel's boot-stack-pointer stores (cpu_data
    // init fingerprint) — printed in the report.
    cpu.stack_write_watch = true;
    // M4-b: xnu panic() wrapper (measured: 0x…987b99c → bl panic_impl
    // 0x…7a58588) — capture the ORIGINAL panic's format args; the storm
    // is its recursion, so the first entry names the true root cause.
    cpu.panic_watch_pc = Some(LINK_BASE + (0x987b99c - 0x7004000));

    println!(
        "[handoff] PC = {entry_pa:#x} (load PA) · x0 = {:#x} (boot_args) · MMU off · \
         EL1 · DAIF masked by the kernel itself",
        layout.ba_pa
    );
    let mem_size = mem_size();
    println!(
        "[contract] virtBase = {LINK_BASE:#x} · physBase = {LOAD_PA:#x} · memSize = {mem_size:#x} · \
         DeviceTree @ {:#x} · MIDR = 0x611f0120",
        layout.dt_pa
    );

    // ---- 5) execute the real kernel ----
    // Attr-misroute tallies need the DRAM window END: DRAM lives at
    // DRAM_BASE (0x8_0000_0000 on T8030) .. DRAM_BASE + mem_size — NOT at
    // [0, mem_size); the first run mis-tallied every kernel physmap PA as
    // normal→MMIO because ram_top was the size, not the window end.
    cpu.mmu.ram_top = apple_soc::t8030::DRAM_BASE + mem_size;
    let res = cpu.run(InterpBudget {
        max_insn,
        // ~25 MIPS model (40 ns/insn) + headroom — the ns budget must never
        // bind before the instruction budget on long real-kernel scans.
        max_ns: max_insn.saturating_mul(40).saturating_add(16_000_000_000),
    });
    let stop_pc: Option<u64> = match res.stop {
        StopReason::UnknownInsn { pc, .. } => Some(pc),
        StopReason::TranslationFault { pc, .. } => Some(pc),
        StopReason::ExceptionRecursion { elr, .. } => Some(elr),
        _ => None,
    };

    // M5-P stop-memdump: when the run stopped via IOS_RUST_STOP_PC_RANGE,
    // dump 0x40 bytes at each of x0/x1/x2 (the KAT memcmp computed/expected
    // pointers land there) — bounded, report-only, zero behavior drift.
    if std::env::var("IOS_RUST_STOP_DUMP_MEM").ok().as_deref() == Some("1") {
        // M5-R addendum: also dump 0x40 B at sp and sp+0x20 — the fipspost
        // KAT computed buffer lives at sp+0x20 of the memcmp frame, which
        // the fail-branch stop can't reach through x0 (memcmp clobbers it).
        let mut extra = vec![cpu.sp, cpu.sp + 0x20];
        extra.sort_unstable();
        extra.dedup();
        for sp_va in extra {
            if sp_va == 0 {
                continue;
            }
            let mut buf = [0u8; 0x40];
            let mut line = format!("M5-R stop-framedump sp @ {sp_va:#x}:");
            let mut got = 0usize;
            for (off, chunk) in buf.chunks_mut(8).enumerate() {
                if let Ok(pa) = cpu.debug_walk(
                    sp_va + (off * 8) as u64,
                    a13_cpu::mmu::XlateKind::Load,
                ) {
                    cpu.mem().read_bytes(pa, chunk);
                    got += chunk.len();
                }
            }
            if got == 0 {
                line.push_str(" <unmapped>");
            } else {
                for (k, b) in buf.iter().take(got).enumerate() {
                    if k % 16 == 0 {
                        line.push_str(&format!("\n    +{:02x}:", k));
                    }
                    line.push_str(&format!(" {b:02x}"));
                }
            }
            println!("{line}");
        }
        for (i, reg) in [0usize, 1, 2, 19].iter().enumerate() {
            let va = cpu.x[*reg];
            if va == 0 {
                continue;
            }
            let mut buf = [0u8; 0x40];
            let mut line = format!("M5-P stop-memdump x{i} @ {va:#x}:");
            let mut got = 0usize;
            for (off, chunk) in buf.chunks_mut(8).enumerate() {
                if let Ok(pa) =
                    cpu.debug_walk(va + (off * 8) as u64, a13_cpu::mmu::XlateKind::Load)
                {
                    cpu.mem().read_bytes(pa, chunk);
                    got += chunk.len();
                }
            }
            if got == 0 {
                line.push_str(" <unmapped>");
            } else {
                for (k, b) in buf.iter().take(got).enumerate() {
                    if k % 16 == 0 {
                        line.push_str(&format!("\n    +{:02x}:", k));
                    }
                    line.push_str(&format!(" {b:02x}"));
                }
            }
            println!("{line}");
        }
    }

    let out = serial.lock().map(|s| s.clone()).unwrap_or_default();
    let trace: Vec<String> = cpu
        .trace
        .iter()
        .map(|(pc, w, regs, nzcv)| {
            format!(
                "{pc:#x}: {w:#010x} nzcv={nzcv:04b} x9={:x} x10={:x} x12={:x} x13={:x} x16={:x} x18={:x} x22={:x} sp={:x} lr={:x}",
                regs[9], regs[10], regs[12], regs[13], regs[16], regs[18], regs[22],
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
        bootargs_pa: layout.ba_pa,
        dt_pa: layout.dt_pa,
        dt_bytes: dt_blob.len(),
        mmu_config: cpu.mmu.config_str(),
        mmu_walks: cpu.mmu.walks,
        mmu_tlb_hits: cpu.mmu.tlb_hits,
        mmu_faults: cpu.mmu.faults,
        mmu_live_insns: res
            .mmu_live_from
            .map(|from| res.executed.saturating_sub(from)),
        mmu_accesses: cpu.mmu.walks + cpu.mmu.tlb_hits,
        mmu_fault_kinds: cpu.mmu.fault_kinds,
        mmu_leaf_levels: cpu.mmu.leaf_at_level,
        attr_device_pages: cpu.mmu.attr_device_pages,
        attr_normal_pages: cpu.mmu.attr_normal_pages,
        device_on_ram: cpu.mmu.device_on_ram,
        normal_on_mmio: cpu.mmu.normal_on_mmio,
        bus_unmapped_reads: vm_core::bus::unmapped_reads(),
        bus_unmapped_writes: vm_core::bus::unmapped_writes(),
        esr_el1: cpu.sys.esr_el1,
        far_el1: cpu.sys.far_el1,
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
        exc_taken: cpu.exc_taken,
        fiq_taken: cpu.fiq_taken,
        at_ops: cpu.at_ops,
        pac_aut_unverified: cpu.pac_aut_unverified,
        panic_site: cpu.last_panic,
        irq_taken: cpu.irq_taken,
        sync_aborts: cpu.sync_aborts,
        wfi_count: cpu.wfi_count,
        wfi_wakeups: cpu.wfi_wakeups,
        last_exception: cpu.last_exception,
        gxf_ctx_seeded: cpu.gxf_ctx_seeded,
        cpu_data0_report: {
            let mut out = Vec::new();
            if let Some(pa) = cpu.cpu_data0_addr {
                let va = pa.wrapping_add(cpu.kva_base);
                out.push(format!(
                    "cpu_data[0] @ PA {pa:#x} · KVA {va:#x} · tpidr {:#x}",
                    cpu.sys.tpidr_el1
                ));
                for (name, off) in [
                    ("active_thread", 0x0u64),
                    ("cpu_number?", 0x8),
                    ("intstack_top+0x4f8", 0x4f8),
                    ("depth+0x500", 0x500),
                ] {
                    let mut b = [0u8; 8];
                    cpu.mem().read_bytes(pa + off, &mut b);
                    out.push(format!(
                        "  cpu_data[0]+{name} = {:#018x}",
                        u64::from_le_bytes(b)
                    ));
                }
            } else if cpu.sys.tpidr_el1 != 0 {
                // M4-K: the guard-chain dump — the kernel's own tpidr is set;
                // follow the exception-stack-guard chain [tpidr+0x4f8] → +0x28
                // and the intstack-switch field [tpidr+0x498].
                let tpidr = cpu.sys.tpidr_el1;
                out.push(format!(
                    "cpu_data[0]: not scanned · tpidr {tpidr:#x} (set by the kernel)"
                ));
                let (spsel, stopsp, vbar) = (cpu.sp_sel, cpu.sp, cpu.sys.vbar_el1);
                out.push(format!(
                    "  vector state at stop: SPSel={} · sp {:#x} · VBAR {:#x}",
                    spsel, stopsp, vbar
                ));
                let mut rd = |va: u64| -> u64 {
                    let pa = va.wrapping_sub(cpu.kva_base);
                    let mut b = [0u8; 8];
                    cpu.mem().read_bytes(pa, &mut b);
                    u64::from_le_bytes(b)
                };
                let intstack = rd(tpidr + 0x4f8);
                let switch_sp = rd(tpidr + 0x498);
                out.push(format!(
                    "  guard chain: [tpidr+0x4f8] = {intstack:#x} · [tpidr+0x498] (irq-switch sp) = {switch_sp:#x}"
                ));
                if intstack != 0 {
                    let bound = rd(intstack + 0x28);
                    let base = rd(intstack + 0x20);
                    let switch_top = rd(intstack + 0x10);
                    let irq_sp = rd(tpidr + 0x498);
                    out.push(format!(
                        "  exc-stack descriptor @{intstack:#x}: [+0x10] (stub switch target) = {switch_top:#x} · [+0x20] = {base:#x} · [+0x28] (guard bound) = {bound:#x} · [tpidr+0x498] = {irq_sp:#x} · sp at stop {:#x}",
                        cpu.sp
                    ));
                }
            } else {
                out.push(format!(
                    "cpu_data[0]: never discovered · tpidr {:#x}{}",
                    cpu.sys.tpidr_el1,
                    if cpu.sys.tpidr_el1 != 0 {
                        " (set by the kernel itself — no seed needed)"
                    } else {
                        ""
                    }
                ));
            }
            out
        },
        stack_write_log: cpu.stack_writes.iter().copied().collect(),
        first_aborts: cpu.first_aborts.clone(),
        abort_backtrace: cpu.abort_backtrace.clone(),
        abort_frames: cpu.abort_frames.iter().map(|w| *w).collect(),
        abort_tpidr: cpu.abort_tpidr,
        last_aborts: cpu.abort_log.iter().rev().take(24).rev().copied().collect(),
        sync_abort_total: cpu.sync_aborts,
        data_stores: cpu.data_stores.iter().copied().collect(),
        data_store_count: cpu.data_store_count,
        poison_stores: cpu.poison_stores.iter().copied().collect(),
        poison_count: cpu.poison_count,
        panic_calls: cpu.panic_calls.iter().copied().collect(),
        panic_call_count: cpu.panic_call_count,
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
            // M4-L (#32): FULL descriptor scan of the CURRENT TTBR0/TTBR1
            // tables — every nonzero entry in the first 16 KiB (2048 slots)
            // of each table, so "the kernel never filled the physmap L1
            // entry" is MEASURED, not inferred. Cap 80 lines/table.
            for (name, ttbr) in [("TTBR1", cpu.mmu.ttbr_bases().1), ("TTBR0", cpu.mmu.ttbr_bases().0)] {
                let base = ttbr & 0x0000_FFFF_FFFF_FFF8;
                let mut shown = 0;
                for slot in 0..2048u64 {
                    let addr = base + slot * 8;
                    let mut b = [0u8; 8];
                    cpu.mem().read_bytes(addr, &mut b);
                    let d = u64::from_le_bytes(b);
                    if d != 0 {
                        shown += 1;
                        probe.push(format!("{name}[{slot}] @ {addr:#x} = {d:#018x}"));
                        if shown >= 80 {
                            probe.push(format!("{name}: … (more nonzero entries exist)"));
                            break;
                        }
                    }
                }
                if shown == 0 {
                    probe.push(format!("{name} table @ {base:#x}: ALL ZERO (2048 slots)"));
                }
            }
            // M4-L (#32): physmap page-table mechanism globals — the L2
            // array ptr, bump cursor, ptov_table head. File ships 0; the
            // kernel must init them before granular_prot can fill tables.
            for (label, gva) in [
                ("[0x7701d10] L2-array ptr", 0xfffffff007701d10u64),
                ("[0x7701cf8] L2 free head", 0xfffffff007701cf8),
                ("[0x7702460] L2 bump cursor", 0xfffffff007702460),
                ("[0x7702450] gPhysBase", 0xfffffff007702450),
                ("[0x7702458] gVirtBase", 0xfffffff007702458),
                ("[0x7702568] end_kern", 0xfffffff007702568),
            ] {
                // kernel VA → PA via the load map: PA = gva − link_base + LOAD_PA
                let gpa = gva - 0xfffffff007004000 + LOAD_PA;
                let mut b = [0u8; 8];
                cpu.mem().read_bytes(gpa, &mut b);
                let v = u64::from_le_bytes(b);
                probe.push(format!("{label} @PA {gpa:#x} = {v:#x}"));
            }
            // ptov_table entries (stride 0x18 from 0x7702128 per the commit
            // stores measured at insn 8.13M)
            for k in 0..8 {
                let gpa = LOAD_PA + (0x7702128 + k * 0x18 - 0x7004000);
                let mut b = [0u8; 24];
                cpu.mem().read_bytes(gpa, &mut b);
                let (pa, va, len) = (
                    u64::from_le_bytes(b[0..8].try_into().unwrap()),
                    u64::from_le_bytes(b[8..16].try_into().unwrap()),
                    u64::from_le_bytes(b[16..24].try_into().unwrap()),
                );
                if pa != 0 || va != 0 || len != 0 {
                    probe.push(format!("ptov[{k}] pa={pa:#x} va={va:#x} len={len:#x}"));
                }
            }
            // M4-L (#36): the kernel's own DT globals — did SecureDTInit see
            // the staged blob (with random-seed) at all?
            for (label, gva) in [
                ("DTRootNode [0x7744988]", 0xfffffff007744988u64),
                ("DTInitialized [0x7744998]", 0xfffffff007744998),
                ("DTEnd [0x7744990]", 0xfffffff007744990),
                ("DTSize [0x77449a0]", 0xfffffff0077449a0),
                ("SecureDTIsLockedDown flag? [0x7701a78]", 0xfffffff007701a78),
            ] {
                let gpa = LOAD_PA + (gva - 0xfffffff007004000);
                let mut b = [0u8; 8];
                cpu.mem().read_bytes(gpa, &mut b);
                probe.push(format!("{label} = {:#x}", u64::from_le_bytes(b)));
            }
            // stop-pc re-walk under the final table state: separates "the
            // kernel remapped this page" from "our walker misread it".
            if let Some(pc) = stop_pc {
                match cpu.debug_walk(pc, a13_cpu::mmu::XlateKind::Fetch) {
                    Ok(pa) => {
                        let mut b = [0u8; 16];
                        cpu.mem().read_bytes(pa, &mut b);
                        probe.push(format!(
                            "stop-pc walk: {pc:#x} → PA {pa:#x} bytes {:02x?} (chain {:?})",
                            b,
                            cpu.mmu.last_fault_chain
                        ));
                    }
                    Err(e) => probe.push(format!("stop-pc walk: {pc:#x} → {e}")),
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
        StopReason::Wfi => "Wfi (idle park, no armed timer deadline)".to_string(),
        StopReason::ExceptionRecursion { detail, elr, far, cycles } => format!(
            "ExceptionRecursion({detail}) elr={elr:#x} far={far:#x} cycles={cycles} \
             — guardrail: the guest re-entered the same exception or its \
             exception stack descended into __TEXT_EXEC"
        ),
        other => format!("{other:?}"),
    };
    println!();
    println!(
        "real-kernel stop: {} after {} insns",
        stop, r.res.executed
    );
    // M4-M: honest counters — AT ops (kvtophys sites) + the panic site.
    println!(
        "M4-m AT ops: {} · pac-aut-unverified: {} · panic site: {}",
        r.at_ops,
        r.pac_aut_unverified,
        match r.panic_site {
            Some((pc, word, lr, sp)) => {
                format!("pc={pc:#x} word={word:#010x} lr={lr:#x} sp={sp:#x}")
            }
            None => "none".to_string(),
        }
    );
    println!(
        "MMU: {} · walks {} · tlb hits {} · faults {} (fetch {} / load {} / store {}) · leafs L0 {} L1 {} L2 {} L3 {}",
        r.mmu_config,
        r.mmu_walks,
        r.mmu_tlb_hits,
        r.mmu_faults,
        r.mmu_fault_kinds[0],
        r.mmu_fault_kinds[1],
        r.mmu_fault_kinds[2],
        r.mmu_leaf_levels[0],
        r.mmu_leaf_levels[1],
        r.mmu_leaf_levels[2],
        r.mmu_leaf_levels[3]
    );
    match r.mmu_live_insns {
        Some(live) => println!(
            "MMU live: {} of {} insns translated (accesses {}, hit-rate {:.1}%)",
            live,
            r.res.executed,
            r.mmu_accesses,
            if r.mmu_accesses > 0 {
                r.mmu_tlb_hits as f64 * 100.0 / r.mmu_accesses as f64
            } else {
                0.0
            }
        ),
        None => println!("MMU live: never armed"),
    }
    println!(
        "attrs (MAIR, recorded not enforced): device pages {} / normal pages {} · \
         misroute device→RAM {} · normal→MMIO {}",
        r.attr_device_pages, r.attr_normal_pages, r.device_on_ram, r.normal_on_mmio
    );
    println!(
        "bus unmapped (silent-zero reads / dropped writes): {} / {}",
        r.bus_unmapped_reads, r.bus_unmapped_writes
    );
    if r.esr_el1 != 0 || r.far_el1 != 0 {
        println!(
            "synthesized at stop: FAR_EL1 = {:#x} · ESR_EL1 = {:#x} (EC {:#05b} · WnR {} · DFSC {:#04b})",
            r.far_el1,
            r.esr_el1,
            (r.esr_el1 >> 26) & 0x3F,
            (r.esr_el1 >> 6) & 1,
            r.esr_el1 & 0x3F
        );
    }
    // --- M4 metrics ---
    println!(
        "M4 exceptions: delivered {} (sync aborts {} · FIQ {} · IRQ {}) · WFI {} (wakeups {}) · GXF ctx seeded {}",
        r.exc_taken,
        r.sync_aborts,
        r.fiq_taken,
        r.irq_taken,
        r.wfi_count,
        r.wfi_wakeups,
        r.gxf_ctx_seeded
    );
    if let Some((kind, esr, far, elr)) = &r.last_exception {
        println!(
            "M4 last exception: {} · ESR {:#x} · FAR {:#x} · ELR {:#x}",
            kind, esr, far, elr
        );
    }

    for line in &r.cpu_data0_report {
        println!("{line}");
    }
    if !r.stack_write_log.is_empty() {
        println!("boot-stack-pointer stores (first {}):", r.stack_write_log.len());
        for (pc, addr, val) in r.stack_write_log.iter() {
            println!("    pc={pc:#x} → [{addr:#x}] = {val:#x}");
        }
    }
    // --- M4-b percpu-blocker diagnostics ---
    if !r.panic_calls.is_empty() || r.panic_call_count > 0 {
        println!(
            "M4-b panic() calls: {} total (first {}):",
            r.panic_call_count,
            r.panic_calls.len()
        );
        for (insn, x0, x1, x2, x3, lr) in r.panic_calls.iter().take(12) {
            println!("    insn={insn} x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} lr={lr:#x}");
        }
    } else {
        println!("M4-b panic() calls: none");
    }
    if !r.first_aborts.is_empty() {
        println!("M4-b first sync aborts:");
        for (insn, elr, far, esr) in &r.first_aborts {
            println!("    insn={insn} elr={elr:#x} far={far:#x} esr={esr:#x}");
        }
        println!("M4-b last sync aborts (of {}):", r.sync_abort_total);
        for (insn, elr, far, esr) in &r.last_aborts {
            println!("    insn={insn} elr={elr:#x} far={far:#x} esr={esr:#x}");
        }
    }
    if !r.abort_backtrace.is_empty() {
        println!(
            "M5-O first-abort FP chain (tpidr_el1={:#x} — xnu arm64 current_thread()):",
            r.abort_tpidr
        );
        for (i, (fp, lr)) in r.abort_backtrace.iter().enumerate() {
            let w = r.abort_frames.get(i).copied().unwrap_or([0; 6]);
            println!(
                "    #{i:02} fp={fp:#x} lr={lr:#x} | [fp-8]={:>#18x} [fp-10]={:>#18x} [fp-18]={:>#18x} [fp-20]={:>#18x} [fp-28]={:>#18x}",
                w[1], w[2], w[3], w[4], w[5]
            );
        }
    }
    if !r.data_stores.is_empty() {
        println!(
            "M4-b __DATA←stack-VA stores ({} total, first {}):",
            r.data_store_count,
            r.data_stores.len()
        );
        for (pc, addr, val) in r.data_stores.iter().take(48) {
            println!("    pc={pc:#x} → [{addr:#x}] = {val:#x}");
        }
    }
    if !r.poison_stores.is_empty() {
        println!(
            "M4-b POISON stores (48-bit-truncated kernel VAs, {} total, first {}):",
            r.poison_count,
            r.poison_stores.len()
        );
        for (pc, addr, val) in r.poison_stores.iter() {
            println!("    pc={pc:#x} → [{addr:#x}] = {val:#x}");
        }
    }
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
        let dropped = apple_soc::s3c_uart::console_dropped_bytes();
        let note = if dropped > 0 {
            format!(" (console cap held RAM bounded — {dropped} early byte(s) dropped, showing the tail)"
            )
        } else {
            String::new()
        };
        println!("UART output ({} B){note}: {:?}", r.serial.len(), text);
    } else {
        println!("UART output: (none yet)");
    }
    if !r.trace.is_empty() {
        let depth = if std::env::var("IOS_RUST_TRACE_DEEP").is_ok() { 2048 } else { 48 };
        println!("last instructions:");
        for t in r.trace.iter().rev().take(depth).collect::<Vec<_>>().iter().rev() {
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
        "  {} M3 gate: MMU live for {} insns (acceptance ≥ 1,000,000, translated fetch/load/store)",
        match r.mmu_live_insns {
            Some(live) if live >= 1_000_000 => "✅",
            Some(_) => "❌",
            None => "— (never armed)",
        },
        r.mmu_live_insns
            .map(|l| l.to_string())
            .unwrap_or_else(|| "0".to_string())
    );
    println!(
        "  {} UART banner: {}",
        if !r.serial.is_empty() { "✅" } else { "❌ not reached yet" },
        if !r.serial.is_empty() { "kernel bytes on the wire" } else { "no kernel output yet" }
    );
    println!("  stop: {stop} · clean: {clean}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REAL-DATA BUG #25 golden, pinned to the REAL 18C66 n104ap numbers:
    /// file 45,778,056 B; VA span end (getlastaddr) = 0xFFFFFFF009C5C488
    /// (round_page → 0xFFFFFFF009C60000); DT blob 0x35C2C B. The old
    /// file-size staging gave dt_pa 0x803BAD000 — BELOW the kernel's own
    /// end_kern ⇒ e[DT].len wrapped negative ⇒ DT head slid onto
    /// __PRELINK_INFO ⇒ the "Device tree pointer outside of device tree
    /// region" panic + 21,270-cycle exception storm (24 MB zeroed).
    #[test]
    fn staged_layout_uses_va_span_end_kern() {
        const IMG: usize = 45_778_056;
        const VA_END: u64 = 0xFFFF_FFF0_09C5_C488; // __LINKEDIT end
        const DT: usize = 0x35C2C; // 220,204 B real ADT
        let l = StagedLayout::compute(IMG, VA_END, DT);
        // end_kern_va = page(0xFFFFFFF009C5C488) = 0xFFFFFFF009C60000;
        // PA = VA − LINK_BASE + LOAD_PA.
        assert_eq!(l.end_kern_pa, 0x8_03C6_0000, "end_kern must follow the kernel's own VA span (bug #25)");
        assert_eq!(l.dt_pa, 0x8_03C6_0000, "DT blob stages AT end_kern");
        // e[DT].len = top − end_kern must be POSITIVE and 16K-multipled
        // (old layout: −0x7C000 wrapped).
        let e_dt_len = l.top_of_kernel_data - l.end_kern_pa;
        assert!(e_dt_len > DT as u64, "physmap tail entry must cover the blob: len={e_dt_len:#x}");
        assert_eq!(e_dt_len & 0x3FFF, 0, "physmap len must be a whole 16K page");
        assert_eq!(l.top_of_kernel_data & 0x3FFF, 0, "topOfKernelData 16K-aligned");
        // deviceTreeP (bootstrap KVA) = 0xFFFFFFF009C60000, the value the
        // rebase must re-derive (head' = e[DT].va, no wrap).
        assert_eq!(l.dt_va(), 0xFFFF_FFF0_09C6_0000);
        // Image must not be clobbered: file end below end_kern.
        assert!(LOAD_PA + IMG as u64 <= l.end_kern_pa);
        // Old-behavior regression guard: the file-size round-up alone
        // (0x803BAD000) must NOT be the staged base anymore.
        assert_ne!(l.dt_pa, (LOAD_PA + IMG as u64 + 0xFFF) & !0xFFF);
    }
}
