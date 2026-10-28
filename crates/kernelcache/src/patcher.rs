//! patcher — port of hw/arm/apple-silicon/{kernel_patches,patcher,mem}.c
//!
//! The ChefKiss Inferno boot-time XNU patcher chain (upstream AGPL-3.0-or-
//! later, Copyright Visual Ehrmanntraut) that turns a stock T8030 XNU into
//! the "inferno" kernel: AMFI/trust-cache/codesigning bypasses, APFS
//! snapshot + root-mount unlocks, hactivation, kprintf, AMX disable, …
//!
//! Layout (1:1 with the C files):
//! * engine (patcher.c) — [`PatchRange`]: masked byte-pattern find,
//!   `find_replace`, word-wise [`PatchRange::find_next_insn`] /
//!   [`PatchRange::find_prev_insn`], arm64 encoders (NOP/RET/RETAB/PACIBSP,
//!   proper `movz`/`movk` builders);
//! * table (kernel_patches.c) — [`T8030_PATCH_GROUPS`]: every patch the C
//!   applies as data — `PatchAttempt { name, pattern, mask, align, body }`
//!   with `Body::Replace` / `Body::Callback`, grouped by target image and
//!   section, including the `if (!find_replace(A)) find_replace(B)`
//!   fallback variants (ordered `attempts` arrays);
//! * mem.c — [`boot_va_to_offset`]: the boot VA window translation,
//!   adapted to byte slices (the C maps through the QEMU globals
//!   `g_virt_base`/`g_phys_base`/`g_virt_slide`).
//!
//! Boot-pipeline API: [`apply_t8030_patches`] walks the table over a
//! decompressed kernelcache and returns an honest [`PatchReport`]
//! (`applied`/`missed`) instead of the C's `error_report` logging.
//!
//! Honest deviations from the C engine:
//! * the C scans raw host pointers and may read past a range's end (its
//!   ranges live in mapped RAM); here every read/write is bounds-checked
//!   and an out-of-range probe simply does not match;
//! * the C dereferences NULL ranges when a KEXT image is missing (it
//!   assumes apfs/AMFI/SEPManager/Image4 are always prelinked); here a
//!   missing image/section is reported as `missed`, never a panic;
//! * `apple_boot_va_to_ptr` returns a QEMU RAM pointer; the port returns a
//!   byte-slice offset — `dram_base` is the boot VA that byte 0 of the
//!   image corresponds to (slide folded out);
//! * mem.c `allocate_ram`/carveout allocator are QEMU MemoryRegion + DT
//!   machinery, not needed by a byte-slice patcher — not ported;
//! * KEXT lookup ports both upstream finders (fileset entries by bundle id
//!   for MH_FILESET; the `__kmod_info`/`__kmod_start` arrays and the
//!   `__info` XML plist scan for old-style kernelcaches; `strtoull`
//!   base-0 covers 0x/decimal/octal load addresses).

use macho::fileset::load_fileset;

// ---------------------------------------------------------------------------
// Instruction constants + arm64 encoders (kernel_patches.c / patcher.h)
// ---------------------------------------------------------------------------

/// `nop`.
pub const NOP: u32 = 0xD503_201F;
/// `ret`.
pub const RET: u32 = 0xD65F_03C0;
/// `retab` (PAC'd return — used when the patched fn had a `pacibsp`).
pub const RETAB: u32 = 0xD65F_0FFF;
/// `pacibsp` — the C finds function starts by this prologue.
pub const PACIBSP: u32 = 0xD503_237F;
/// `mov w0, #0` (= `movz(0, 0, 0, false)`).
pub const MOV_W0_0: u32 = 0x5280_0000;

/// Encode `movz Wd/Xd, #imm16, lsl #<shift>` (`sf64` selects the 64-bit
/// form; `shift` is the lsl amount — 0/16/32/48). The C's MOV_W0_0_BYTES
/// and friends are these encodings spelled as bytes.
pub fn movz(rd: u32, imm16: u32, shift: u32, sf64: bool) -> u32 {
    let base = if sf64 { 0xD280_0000 } else { 0x5280_0000 };
    debug_assert_eq!(shift % 16, 0, "shift is the lsl amount (0/16/32/48)");
    base | ((shift / 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)
}

/// Encode `movk Wd/Xd, #imm16, lsl #<shift>` (keeps the other halves).
pub fn movk(rd: u32, imm16: u32, shift: u32, sf64: bool) -> u32 {
    let base = if sf64 { 0xF280_0000 } else { 0x7280_0000 };
    debug_assert_eq!(shift % 16, 0, "shift is the lsl amount (0/16/32/48)");
    base | ((shift / 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)
}

/// `extract32(x, pos, len)` (qemu/bitops.h).
fn extract32(x: u32, pos: u32, len: u32) -> u32 {
    (x >> pos) & ((!0u32) >> (32 - len))
}

// ---------------------------------------------------------------------------
// mem.c — the boot VA window, adapted to byte slices
// ---------------------------------------------------------------------------

/// Port of mem.c `vtop_bases` (checked): `va - virt_base + phys_base`.
pub fn vtop_bases(va: u64, phys_base: u64, virt_base: u64) -> Option<u64> {
    va.checked_sub(virt_base)?.checked_add(phys_base)
}

/// Port of mem.c `ptov_bases` (checked): `pa - phys_base + virt_base`.
pub fn ptov_bases(pa: u64, phys_base: u64, virt_base: u64) -> Option<u64> {
    pa.checked_sub(phys_base)?.checked_add(virt_base)
}

/// Port of boot.c `apple_boot_fixup_slide_va` with the slide folded out
/// (a byte slice has no ASLR): canonicalise a (possibly truncated) VA
/// into the `0xFFFF…` boot window.
pub fn boot_fixup_slide_va(va: u64) -> u64 {
    0xFFFF_0000_0000_0000 | va
}

/// Port of `apple_boot_va_to_ptr` over a byte slice: translate a boot VA
/// into an offset into the kernel image. `dram_base` is the boot VA that
/// byte 0 of the slice corresponds to (the C engine's `ptov(g_phys_base)`);
/// returns `None` when `va` sits below the image base.
pub fn boot_va_to_offset(va: u64, dram_base: u64) -> Option<usize> {
    let va = boot_fixup_slide_va(va);
    let base = boot_fixup_slide_va(dram_base);
    usize::try_from(va.checked_sub(base)?).ok()
}

// ---------------------------------------------------------------------------
// Engine — port of patcher.c
// ---------------------------------------------------------------------------

/// One patchable region — port of `CKPatcherRange` over a byte slice.
///
/// The C keeps `addr` (boot VA), `length`, `ptr`, `name`; the port keeps
/// the same fields with `data: &mut [u8]` standing in for `ptr`/`length`.
pub struct PatchRange<'a> {
    /// Boot VA of `data[0]` (0 when the caller has no VA for the slice).
    pub addr: u64,
    /// Range name (C stores the segment name; the port carries
    /// `"<image> <seg>.<sect>"` for diagnostics).
    pub name: String,
    /// The patchable bytes.
    pub data: &'a mut [u8],
}

impl<'a> PatchRange<'a> {
    /// `ck_patcher_range_from_ptr` equivalent.
    pub fn new(name: impl Into<String>, addr: u64, data: &'a mut [u8]) -> Self {
        PatchRange { addr, name: name.into(), data }
    }

    /// `ldl_le_p` (bounds-checked): little-endian u32 at `off`.
    pub fn ldl_le(&self, off: usize) -> Option<u32> {
        self.data.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// `stl_le_p` (bounds-checked): write little-endian u32 at `off`.
    /// Out-of-range writes are dropped (the C would write through the raw
    /// pointer); every caller probes with `find_*_insn` first.
    pub fn stl_le(&mut self, off: usize, val: u32) {
        if let Some(b) = self.data.get_mut(off..off + 4) {
            b.copy_from_slice(&val.to_le_bytes());
        }
    }

    /// First offset of `pattern` (optionally masked) at or after `from`,
    /// scanned at `align` granularity (`0` = byte-granular, like the C).
    pub fn find_from(
        &self,
        pattern: &[u8],
        mask: Option<&[u8]>,
        align: usize,
        from: usize,
    ) -> Option<usize> {
        let step = align.max(1);
        if pattern.is_empty() || self.data.len() < pattern.len() {
            return None;
        }
        debug_assert_eq!(pattern.len() % step, 0, "C asserts len %% align == 0");
        if let Some(mask) = mask {
            debug_assert_eq!(mask.len(), pattern.len());
            debug_assert!(pattern.iter().zip(mask).all(|(&p, &m)| p & m == p));
        }
        let mut i = from.min(self.data.len() - pattern.len() + 1);
        while i + pattern.len() <= self.data.len() {
            let hit = pattern.iter().enumerate().all(|(k, &p)| {
                let d = self.data[i + k];
                match mask {
                    Some(m) => d & m[k] == p,
                    None => d == p,
                }
            });
            if hit {
                return Some(i);
            }
            i += step;
        }
        None
    }

    /// `ck_patcher_find_callback`: scan for `pattern`/`mask` and run `cb`
    /// on every candidate (first `true` wins). Returns whether some match
    /// applied — the C's info/error_report pair becomes this bool.
    pub fn find_where<F>(&mut self, pattern: &[u8], mask: Option<&[u8]>, align: usize, mut cb: F) -> bool
    where
        F: FnMut(&mut Self, usize) -> bool,
    {
        let step = align.max(1);
        let mut from = 0;
        while let Some(off) = self.find_from(pattern, mask, align, from) {
            if cb(self, off) {
                return true;
            }
            from = off + step;
        }
        false
    }

    /// `ck_patcher_find_replace`: replace `replace_len`(= `repl.len()`)
    /// bytes at `replace_off` inside the first applying match. With a
    /// `repl_mask` the replacement is OR-merged like the C
    /// (`(old & mask) | repl`).
    #[allow(clippy::too_many_arguments)]
    pub fn find_replace(
        &mut self,
        pattern: &[u8],
        mask: Option<&[u8]>,
        align: usize,
        repl: &[u8],
        repl_mask: Option<&[u8]>,
        replace_off: usize,
    ) -> bool {
        let replace_len = repl.len();
        if replace_off + replace_len > pattern.len() {
            // C: assert_cmphex(replace_off + replace_len, <=, len)
            return false;
        }
        self.find_where(pattern, mask, align, |r, off| {
            let at = off + replace_off;
            match repl_mask {
                None => r.data[at..at + replace_len].copy_from_slice(&repl[..replace_len]),
                Some(m) => {
                    for i in 0..replace_len {
                        r.data[at + i] = (r.data[at + i] & m[i]) | repl[i];
                    }
                }
            }
            true
        })
    }

    /// `ck_patcher_find_next_insn`: scan up to `num` words from `from`
    /// forwards for `insn & mask`, skipping the first `skip` matches.
    /// Returns the byte offset of the match (None when the scan leaves
    /// the range — the C would read past it).
    pub fn find_next_insn(&self, from: usize, num: u32, insn: u32, mask: u32, skip: u32) -> Option<usize> {
        debug_assert_eq!(insn & mask, insn, "C asserts insn is pre-masked");
        let mut skip = skip;
        for i in 0..num {
            let off = from + i as usize * 4;
            if off + 4 > self.data.len() {
                break;
            }
            if self.ldl_le(off).unwrap() & mask == insn {
                if skip == 0 {
                    return Some(off);
                }
                skip -= 1;
            }
        }
        None
    }

    /// `ck_patcher_find_prev_insn`: scan up to `num` words from `from`
    /// backwards for `insn & mask`, skipping the first `skip` matches.
    pub fn find_prev_insn(&self, from: usize, num: u32, insn: u32, mask: u32, skip: u32) -> Option<usize> {
        debug_assert_eq!(insn & mask, insn, "C asserts insn is pre-masked");
        let mut skip = skip;
        for i in 0..num {
            let Some(off) = from.checked_sub(i as usize * 4) else { break };
            if off + 4 > self.data.len() {
                continue;
            }
            if self.ldl_le(off).unwrap() & mask == insn {
                if skip == 0 {
                    return Some(off);
                }
                skip -= 1;
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Table types — kernel_patches.c as data
// ---------------------------------------------------------------------------

/// Which image a patch group targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Image {
    /// The XNU kernel (`com.apple.kernel` fileset entry / top-level image).
    Kernel,
    /// A KEXT by bundle id (fileset entry id / prelink CFBundleIdentifier).
    Kext(&'static str),
}

/// What is written once the prologue pattern matches.
#[derive(Clone, Copy)]
pub enum Body {
    /// `find_replace`: write `repl` (optionally OR-merged through
    /// `repl_mask`) at `off` inside the match — length is `repl.len()`,
    /// exactly the C's `replace_len = sizeof(repl)`.
    Replace { repl: &'static [u8], repl_mask: Option<&'static [u8]>, off: usize },
    /// `find_callback`: a ported C callback — `(range, match_offset)`.
    Callback(fn(&mut PatchRange, usize) -> bool),
}

/// One find+patch attempt (a `ck_patcher_find_*` call in the C).
#[derive(Clone, Copy)]
pub struct PatchAttempt {
    /// Upstream report name.
    pub name: &'static str,
    /// Function/sequence prologue bytes to find.
    pub pattern: &'static [u8],
    /// Match mask (None = exact bytes).
    pub mask: Option<&'static [u8]>,
    /// Scan alignment (4 for instruction patterns, 0 for cstrings).
    pub align: usize,
    /// The patch body.
    pub body: Body,
}

/// One logical patch: the primary attempt first, then the fallback
/// variants the C tries with `if (!find_…)`. Order inside `attempts`
/// encodes the fallback chain.
#[derive(Clone, Copy)]
pub struct PatchEntry {
    pub attempts: &'static [PatchAttempt],
}

/// Alternate (image, segment, section) when a group's own section is
/// absent — the `if (x == NULL) x = …` fallbacks in `ck_patch_kernel`.
pub struct GroupFallback {
    pub image: Image,
    pub segment: &'static str,
    pub section: &'static str,
}

/// A per-image patch group: where to patch and which entries to run.
pub struct PatchGroup {
    pub name: &'static str,
    pub image: Image,
    pub segment: &'static str,
    pub section: &'static str,
    pub fallback: Option<GroupFallback>,
    pub entries: &'static [PatchEntry],
}

/// Honest result of a patch run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchReport {
    /// Attempt names that matched and applied.
    pub applied: Vec<String>,
    /// Attempt names whose pattern was not found / did not apply.
    pub missed: Vec<String>,
}

impl PatchReport {
    /// Every attempted patch (applied + missed).
    pub fn total(&self) -> usize {
        self.applied.len() + self.missed.len()
    }
}

// ---------------------------------------------------------------------------
// Callbacks — ports of the static ck_kp_*_callback functions
// ---------------------------------------------------------------------------

const PACIBSP_M: u32 = 0xFFFF_FFFF;

/// `ck_kp_root_auth_callback`: return 0 from the auth check.
fn root_auth_callback(r: &mut PatchRange, off: usize) -> bool {
    match r.find_prev_insn(off, 30, PACIBSP, PACIBSP_M, 0) {
        Some(func_start) => {
            r.stl_le(func_start, MOV_W0_0);
            r.stl_le(func_start + 4, RET);
            true
        }
        None => {
            // old logic: `mov w0, #1; ret` — patch the mov to return 0
            match r.find_next_insn(off, 4, RET, PACIBSP_M, 0) {
                Some(ret) if ret >= 4 => {
                    r.stl_le(ret - 4, MOV_W0_0);
                    true
                }
                _ => false,
            }
        }
    }
}

/// `ck_kp_root_hash_callback`: return 0 from the root-hash check.
fn root_hash_callback(r: &mut PatchRange, off: usize) -> bool {
    let Some(start) = r.find_prev_insn(off, 0x40, PACIBSP, PACIBSP_M, 0) else {
        return false;
    };
    r.stl_le(start, MOV_W0_0);
    r.stl_le(start + 4, RET);
    true
}

/// `ck_kp_tc_callback`: AMFI trust-cache prototype rewrites (cdhash-param
/// switch). Requires the two words before the match to be inspected, so
/// `off < 8` (unreadable in the slice model) is a miss.
fn tc_callback(r: &mut PatchRange, off: usize) -> bool {
    if off < 8 {
        return false;
    }
    let prev_add = |o: usize| r.ldl_le(o).map(|v| v & 0xFF00_0000) == Some(0x9100_0000);
    if !prev_add(off - 4) && !prev_add(off - 8) {
        return false;
    }
    let Some(ldrb) = r.find_next_insn(off, 256, 0x3940_2C00, 0xFFFF_FC00, 0) else {
        return false;
    };
    let cdhash_param = extract32(r.ldl_le(ldrb).unwrap_or(0), 5, 5);
    let mut start = off;
    match r.find_prev_insn(off, 10, 0x9100_03FD, 0xFF80_03FF, 0) {
        None => {} // AMFI (Leaf): the match is already the start
        Some(frame) => {
            start = match r.find_prev_insn(frame, 10, 0xA9A0_03E0, 0xFFE0_03E0, 0) {
                Some(s) => s,
                None => match r.find_prev_insn(frame, 10, 0xD100_03FF, 0xFF80_03FF, 0) {
                    Some(s) => s,
                    None => return false, // failed to find AMFI start
                },
            };
        }
    }
    let pac = r.find_prev_insn(start, 5, PACIBSP, PACIBSP_M, 0).is_some();
    match cdhash_param {
        0 => {
            if let Some(adrp) = r.find_prev_insn(start, 10, 0x9000_0008, 0x9F00_001F, 0) {
                start = adrp;
            }
            r.stl_le(start, movz(0, 0x101, 0, false)); // mov w0, 0x101
            r.stl_le(start + 4, if pac { RETAB } else { RET });
            true
        }
        1 => {
            r.stl_le(start, movz(0, 2, 0, false)); // mov w0, 2
            r.stl_le(start + 4, 0x3900_0040); // strb w0, [x2]
            r.stl_le(start + 8, movz(0, 1, 0, false)); // mov w0, 1
            r.stl_le(start + 12, 0x3900_0060); // strb w0, [x3]
            r.stl_le(start + 16, movz(0, 1, 0, false)); // mov w0, 1
            r.stl_le(start + 20, if pac { RETAB } else { RET });
            true
        }
        _ => false, // found unexpected AMFI prototype
    }
}

/// `ck_kp_tc_ios16_callback`.
fn tc_ios16_callback(r: &mut PatchRange, off: usize) -> bool {
    let Some(start) = r.find_prev_insn(off, 100, PACIBSP, PACIBSP_M, 0) else {
        return false;
    };
    r.stl_le(start, movz(0, 0x101, 0, false)); // mov w0, 0x101
    r.stl_le(start + 4, RET);
    true
}

/// `ck_kp_amfi_sha1_callback`: turn `cmp w0, #2` into `cmp w0, w0`.
fn amfi_sha1_callback(r: &mut PatchRange, off: usize) -> bool {
    let Some(cmp) = r.find_next_insn(off, 0x10, 0x7100_081F, 0xFFFF_FFFF, 0) else {
        return false;
    };
    r.stl_le(cmp, 0x6B00_001F); // cmp w0, w0
    true
}

/// `ck_kp_amfi_tc_callback`: TrustCache query always succeeds.
fn amfi_tc_callback(r: &mut PatchRange, off: usize) -> bool {
    let Some(start) = r.find_prev_insn(off, 0x20, PACIBSP, PACIBSP_M, 0) else {
        return false;
    };
    r.stl_le(start, movz(0, 1, 0, true)); // mov x0, #1
    r.stl_le(start + 4, 0xB400_0042); // cbz x2, #0x8
    r.stl_le(start + 8, 0xF900_0040); // str x0, [x2]
    r.stl_le(start + 12, RET);
    true
}

/// `ck_kp_img4_callback`: return 0 (unsigned firmware OK).
fn img4_callback(r: &mut PatchRange, off: usize) -> bool {
    let Some(start) = r.find_prev_insn(off, 200, PACIBSP, PACIBSP_M, 0) else {
        return false;
    };
    r.stl_le(start, MOV_W0_0);
    r.stl_le(start + 4, RET);
    true
}

/// `ck_kp_mac_mount_callback`: NOP the MNT_UNION branch, force the
/// MNT_ROOTFS check to read xzr.
fn mac_mount_callback(r: &mut PatchRange, off: usize) -> bool {
    let tbnz = match r.find_prev_insn(off, 0x40, 0x3728_0000, 0xFFFE_0000, 0) {
        Some(i) => Some(i),
        None => r.find_next_insn(off, 0x40, 0x3728_0000, 0xFFFE_0000, 0),
    };
    let Some(inst) = tbnz else { return false };
    r.stl_le(inst, NOP); // allow MNT_UNION mounts

    // `ldrb w8, [x?, #0x71]`, or the `add x8, x8/16, #0x70` +
    // `ldr w8, [x8, #0x1]` pair, around the match.
    let site = match r
        .find_prev_insn(off, 0x40, 0x3941_C408, 0xFFFF_FC1F, 0)
        .or_else(|| r.find_next_insn(off, 0x40, 0x3941_C408, 0xFFFF_FC1F, 0))
    {
        Some(i) => Some(i),
        None => match r.find_prev_insn(off, 0x40, 0x9101_C008, 0xFFFF_FCFF, 0) {
            Some(i) if r.ldl_le(i + 4) == Some(0x3940_0508) => Some(i + 4),
            _ => None,
        },
    };
    let Some(inst) = site else { return false };
    r.stl_le(inst, 0xAA1F_03E8); // mov x8, xzr
    true
}

/// `ck_kp_kprintf_callback`: NOP the cbnz / make the cbz unconditional.
fn kprintf_callback(r: &mut PatchRange, off: usize) -> bool {
    let cmp = off + 12;
    let Some(inst) = r.ldl_le(cmp) else { return false };
    if inst & (1 << 24) != 0 {
        r.stl_le(cmp, NOP); // cbnz → nop
    } else {
        r.stl_le(cmp, 0x1400_0000 | extract32(inst, 5, 19)); // cbz → b
    }
    true
}

/// `ck_kp_amx_common`: NOP the store to gAMXVersion.
fn amx_common(r: &mut PatchRange, off: usize, newer: bool) -> bool {
    let (num, skip) = if newer { (6, 0) } else { (10, 1) };
    let Some(store) = r.find_prev_insn(off, num, 0xB800_0000, 0xFEC0_0000, skip) else {
        return false;
    };
    r.stl_le(store, NOP);
    true
}

/// `ck_kp_amx_callback`.
fn amx_callback(r: &mut PatchRange, off: usize) -> bool {
    r.stl_le(off, movz(9, 0x800, 0, false)); // mov w9, #0x800
    amx_common(r, off, false)
}

/// `ck_kp_amx_new_callback`: remove the AMX support bit from the movk.
fn amx_new_callback(r: &mut PatchRange, off: usize) -> bool {
    if let Some(v) = r.ldl_le(off + 4) {
        r.stl_le(off + 4, v & !(0x800 << 5)); // movk w?, #0x900, lsl #0x10
    }
    amx_common(r, off, false)
}

/// `ck_kp_amx_newer_callback`.
fn amx_newer_callback(r: &mut PatchRange, off: usize) -> bool {
    amx_common(r, off, true)
}

// ---------------------------------------------------------------------------
// The T8030 patch table — every ck_kp_*_patch of kernel_patches.c
// ---------------------------------------------------------------------------

// --- prologue patterns (bytes exactly as upstream, LE instruction words) ---

static PAT_ROOT_AUTH: [u8; 12] = [
    0x08, 0xE0, 0x40, 0x39, // ldrb w8, [x?, #0x38]
    0x08, 0x00, 0x00, 0x37, // tbnz w8, #0x5, #?
    0x00, 0x0A, 0x80, 0x52, // mov w?, #0x50
];
static PAT_ROOT_AUTH_MASK: [u8; 12] = [
    0x1F, 0xFC, 0xFF, 0xFF, 0x1F, 0x00, 0x00, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF,
];
static PAT_ROOT_RW: [u8; 20] = [
    0x00, 0x00, 0x00, 0x94, // bl ?
    0x00, 0x00, 0x70, 0x37, // tbnz w0, 0xE, ?
    0xA0, 0x03, 0x40, 0xB9, // ldr x?, [x29/sp, ?]
    0x00, 0x78, 0x1F, 0x12, // and w?, w?, 0xFFFFFFFE
    0xA0, 0x03, 0x00, 0xB9, // str x?, [x29/sp, ?]
];
static PAT_ROOT_RW_MASK: [u8; 20] = [
    0x00, 0x00, 0x00, 0xFC, 0x1F, 0x00, 0xF8, 0xFF, 0xA0, 0x03, 0xFE, 0xFF, 0x00, 0xFC, 0xFF,
    0xFF, 0xA0, 0x03, 0xC0, 0xFF,
];
static PAT_ROOT_RW_NEW: [u8; 16] = [
    0x00, 0x00, 0x00, 0x94, // bl ?
    0x00, 0x00, 0x70, 0x37, // tbnz w0, 0xE, ?
    0x00, 0x00, 0x80, 0x52, // mov w0, #0
    0x00, 0x00, 0x00, 0x14, // bl ?
];
static PAT_ROOT_RW_NEW_MASK: [u8; 16] = [
    0x00, 0x00, 0x00, 0xFC, 0x1F, 0x00, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0xFC,
];
static PAT_ROOT_HASH: [u8; 12] = [
    0x88, 0x62, 0x40, 0xF9, // ldr x8, [x20, #0xC0]
    0x08, 0x89, 0x47, 0x79, // ldrh w8, [x8, #0x3C4]
    0x1F, 0x11, 0x00, 0x71, // cmp w8, #0x4
];
static PAT_AMFI_SHA1: [u8; 4] = [0x02, 0x00, 0xD0, 0x36]; // tbz w2, 0x1A, ?
static PAT_AMFI_SHA1_MASK: [u8; 4] = [0x1F, 0x00, 0xF8, 0xFF];
static PAT_AMFI_TC: [u8; 20] = [
    0xE0, 0x03, 0x00, 0x91, // mov x0, sp
    0xE1, 0x03, 0x13, 0xAA, // mov x1, x19
    0x00, 0x00, 0x00, 0x94, // bl trustCacheQueryGetFlags
    0x9F, 0x02, 0x00, 0x71, // cmp w20, 0
    0xE0, 0x17, 0x9F, 0x1A, // cset w0, eq
];
static PAT_AMFI_TC_MASK: [u8; 20] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFC, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
static PAT_SCOT: [u8; 12] = [
    0x00, 0x04, 0x00, 0xF9, // str x?, [x?, #0x8]
    0x08, 0x04, 0x80, 0x52, // mov w8, #0x20
    0x08, 0x10, 0x00, 0xB9, // str w8, [x?, #0x10]
];
static PAT_SCOT_MASK: [u8; 12] = [
    0x00, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xFC, 0xFF, 0xFF,
];
static PAT_SCOT_NEW: [u8; 12] = [
    0x00, 0x00, 0x1E, 0xF8, // stur x?, [x?, #-0x20]
    0x08, 0x04, 0x80, 0x52, // mov w8, #0x20
    0x08, 0x80, 0x1E, 0xB8, // stur w8, [x?, #-0x18]
];
static PAT_SCOT_NEW_MASK: [u8; 12] = [
    0x00, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xFC, 0xFF, 0xFF,
];
static PAT_IMG4: [u8; 4] = [0x21, 0x09, 0x43, 0xB2]; // orr x1, x9, #0xe000000000000000
static PAT_MAC_MOUNT: [u8; 4] = [0xE9, 0x2F, 0x1F, 0x32]; // orr w9, wzr, 0x1FFE
static PAT_MAC_MOUNT_NEW: [u8; 4] = [0xC9, 0xFF, 0x83, 0x12]; // movz w/x9, 0x1FFE/-0x1FFF
static PAT_MAC_MOUNT_NEW_MASK: [u8; 4] = [0xFF, 0xFF, 0xFF, 0x3F];
static PAT_KPRINTF: [u8; 16] = [
    0xAA, 0x43, 0x00, 0x91, // add x10, fp, #0x10
    0xEA, 0x07, 0x00, 0xF9, // str x10, [sp, #0x8]
    0x08, 0x00, 0x00, 0x2A, // orr w8, w?, w?
    0x08, 0x00, 0x00, 0x34, // cbz w8, #?
];
static PAT_KPRINTF_MASK: [u8; 16] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xFC, 0xE0, 0xFF, 0x1F, 0x00, 0x00,
    0xFE,
];
static PAT_KPRINTF_NEW: [u8; 24] = [
    0x08, 0x01, 0x40, 0x39, // ldrb w8, [x8, #0x?]
    0x08, 0x00, 0x00, 0x36, // tbz w8, #0, #?
    0xA0, 0x43, 0x00, 0x91, // add x?, fp, #0x10
    0xE0, 0x17, 0x00, 0xF9, // str x?, [sp, #0x28]
    0xE0, 0xA3, 0x00, 0x91, // add x?, sp, #0x28
    0x00, 0x00, 0x00, 0x14, // b #?
];
static PAT_KPRINTF_NEW_MASK: [u8; 24] = [
    0xFF, 0x03, 0xC0, 0xFF, 0x1F, 0x00, 0x00, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF,
    0xFF, 0xE0, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFC,
];
static PAT_AMX_NEW: [u8; 12] = [
    0x00, 0x90, 0x87, 0x52, // mov w?, #0x3C80
    0x00, 0x20, 0xA1, 0x72, // movk w?, #0x900, lsl #0x10
    0x00, 0x40, 0x00, 0x2A, // orr w?, w?, w?, lsl #0x10
];
static PAT_AMX_NEW_MASK: [u8; 12] = [
    0xE0, 0xFF, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF, 0x00, 0xFC, 0xE0, 0xFF,
];
static PAT_AMX: [u8; 8] = [
    0xE9, 0x83, 0x05, 0x32, // mov w9, #0x8000800
    0x09, 0x00, 0x00, 0xAA, // orr x9, x?, x?
];
static PAT_AMX_MASK: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xFC, 0xE0, 0xFF];
static PAT_AMX_NEWER: [u8; 8] = [
    0x0A, 0xF1, 0x1C, 0xD5, // msr amx_config_el1, x?
    0xDF, 0x3F, 0x03, 0xD5, // isb
];
static PAT_AMX_NEWER_MASK: [u8; 8] = [0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
static PAT_SNAPSHOT: [u8; 21] = *b"com.apple.os.update-\0";
static PAT_HACT: [u8; 9] = *b"\0release\0";
static PAT_CS: [u8; 8] = [
    0x00, 0x00, 0x18, 0x36, // tbz w?, #3, #?
    0x00, 0x00, 0x80, 0x52, // mov w?, #0
];
static PAT_CS_MASK: [u8; 8] = [0x00, 0x00, 0xF8, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF];
static PAT_CS_ALT: [u8; 12] = [
    0x00, 0x00, 0x18, 0x36, // tbz w?, #3, #?
    0x10, 0x02, 0x17, 0xAA, // mov x?, x?
    0x00, 0x00, 0x80, 0x52, // mov w?, #0
];
static PAT_CS_ALT_MASK: [u8; 12] = [
    0x00, 0x00, 0xF8, 0xFF, 0x10, 0xFE, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF,
];
static PAT_TC: [u8; 12] = [
    0x00, 0x02, 0x80, 0x52, // mov w?, 0x16
    0x00, 0x00, 0x00, 0xD3, // lsr ?
    0x00, 0x00, 0x00, 0x9B, // madd ?
];
static PAT_TC_MASK: [u8; 12] = [
    0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF,
];
static PAT_TC_IOS16: [u8; 4] = [0xC0, 0xCF, 0x9D, 0xD2]; // mov w?, 0xEE7E
static PAT_TC_IOS16_MASK: [u8; 4] = [0xC0, 0xFF, 0xFF, 0xFF];
static PAT_PMAP_CS: [u8; 12] = [
    0x00, 0x00, 0x00, 0x94, // bl #?
    0x00, 0x00, 0x00, 0x35, // cbnz w0, #?
    0x88, 0x63, 0x80, 0x92, // mov x8, #0xfffffffffffffce3
];
static PAT_PMAP_CS_MASK: [u8; 12] = [
    0x00, 0x00, 0x00, 0xFC, 0x1F, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

// --- replacement bodies ---

static REPL_MOV_W0_0: [u8; 4] = [0x00, 0x00, 0x80, 0x52]; // MOV_W0_0_BYTES
static REPL_NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5]; // NOP_BYTES
static REPL_NOP6: [u8; 24] = [
    0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03,
    0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,
];
static REPL_MOV_NOP: [u8; 8] = [0x00, 0x00, 0x80, 0x52, 0x1F, 0x20, 0x03, 0xD5];
static REPL_SCOT: [u8; 4] = [0x28, 0x00, 0xA0, 0x52]; // mov w8, #0x10000
static REPL_SNAPSHOT: [u8; 21] = *b"shitcode.os.bullshit\0";
static REPL_HACT: [u8; 8] = *b"profile\0";

// --- attempts (primary first, fallback variants after) — 23 total ---

const fn att(
    name: &'static str,
    pattern: &'static [u8],
    mask: Option<&'static [u8]>,
    align: usize,
    body: Body,
) -> PatchAttempt {
    PatchAttempt { name, pattern, mask, align, body }
}

const fn repl(repl: &'static [u8], off: usize) -> Body {
    Body::Replace { repl, repl_mask: None, off }
}

static ATT_ROOT_AUTH: [PatchAttempt; 1] = [att(
    "bypass root authentication",
    &PAT_ROOT_AUTH,
    Some(&PAT_ROOT_AUTH_MASK),
    4,
    Body::Callback(root_auth_callback),
)];
static ATT_ROOT_RW: [PatchAttempt; 2] = [
    att("allow mounting root as R/W", &PAT_ROOT_RW, Some(&PAT_ROOT_RW_MASK), 4, repl(&REPL_MOV_W0_0, 4)),
    att(
        "allow mounting root as R/W (new)",
        &PAT_ROOT_RW_NEW,
        Some(&PAT_ROOT_RW_NEW_MASK),
        4,
        repl(&REPL_MOV_W0_0, 4),
    ),
];
static ATT_ROOT_HASH: [PatchAttempt; 1] = [att(
    "bypass root hash authentication",
    &PAT_ROOT_HASH,
    None,
    4,
    Body::Callback(root_hash_callback),
)];
static ATT_SNAPSHOT: [PatchAttempt; 1] = [att(
    "disable APFS snapshots",
    &PAT_SNAPSHOT,
    None,
    0,
    repl(&REPL_SNAPSHOT, 0),
)];
static ATT_AMFI_SHA1: [PatchAttempt; 1] = [att(
    "allow SHA1 signatures in AMFI",
    &PAT_AMFI_SHA1,
    Some(&PAT_AMFI_SHA1_MASK),
    4,
    Body::Callback(amfi_sha1_callback),
)];
static ATT_AMFI_TC: [PatchAttempt; 1] = [att(
    "all binaries in TrustCache (AMFI)",
    &PAT_AMFI_TC,
    Some(&PAT_AMFI_TC_MASK),
    4,
    Body::Callback(amfi_tc_callback),
)];
static ATT_SCOT: [PatchAttempt; 2] = [
    att(
        "increase SCOT size to 0x10000 to use it as TRAC",
        &PAT_SCOT,
        Some(&PAT_SCOT_MASK),
        4,
        repl(&REPL_SCOT, 4),
    ),
    att(
        "increase SCOT size to 0x10000 to use it as TRAC (new)",
        &PAT_SCOT_NEW,
        Some(&PAT_SCOT_NEW_MASK),
        4,
        repl(&REPL_SCOT, 4),
    ),
];
static ATT_IMG4: [PatchAttempt; 1] = [att(
    "allow unsigned firmware in img4_firmware_evaluate",
    &PAT_IMG4,
    None,
    4,
    Body::Callback(img4_callback),
)];
static ATT_MAC_MOUNT: [PatchAttempt; 2] = [
    att(
        "allow remounting rootfs, union mounts (old)",
        &PAT_MAC_MOUNT,
        None,
        4,
        Body::Callback(mac_mount_callback),
    ),
    att(
        "allow remounting rootfs, union mounts (new)",
        &PAT_MAC_MOUNT_NEW,
        Some(&PAT_MAC_MOUNT_NEW_MASK),
        4,
        Body::Callback(mac_mount_callback),
    ),
];
static ATT_KPRINTF: [PatchAttempt; 2] = [
    att(
        "force enable kprintf",
        &PAT_KPRINTF,
        Some(&PAT_KPRINTF_MASK),
        4,
        Body::Callback(kprintf_callback),
    ),
    att(
        "force enable kprintf (new)",
        &PAT_KPRINTF_NEW,
        Some(&PAT_KPRINTF_NEW_MASK),
        4,
        repl(&REPL_NOP6, 0),
    ),
];
static ATT_AMX: [PatchAttempt; 3] = [
    att("disable AMX (new)", &PAT_AMX_NEW, Some(&PAT_AMX_NEW_MASK), 4, Body::Callback(amx_new_callback)),
    att("disable AMX", &PAT_AMX, Some(&PAT_AMX_MASK), 4, Body::Callback(amx_callback)),
    att(
        "disable AMX (newer)",
        &PAT_AMX_NEWER,
        Some(&PAT_AMX_NEWER_MASK),
        4,
        Body::Callback(amx_newer_callback),
    ),
];
static ATT_CS: [PatchAttempt; 2] = [
    att("bypass code signature checks", &PAT_CS, Some(&PAT_CS_MASK), 4, repl(&REPL_NOP, 0)),
    att(
        "bypass code signature checks (alt)",
        &PAT_CS_ALT,
        Some(&PAT_CS_ALT_MASK),
        4,
        repl(&REPL_NOP, 0),
    ),
];
static ATT_HACT: [PatchAttempt; 1] = [att("enable hactivation", &PAT_HACT, None, 0, repl(&REPL_HACT, 1))];
static ATT_TC: [PatchAttempt; 2] = [
    att("all binaries in trustcache", &PAT_TC, Some(&PAT_TC_MASK), 4, Body::Callback(tc_callback)),
    att(
        "all binaries in trustcache (iOS 16+)",
        &PAT_TC_IOS16,
        Some(&PAT_TC_IOS16_MASK),
        4,
        Body::Callback(tc_ios16_callback),
    ),
];
static ATT_PMAP_CS: [PatchAttempt; 1] = [att(
    "bypass pmap_cs_enforce",
    &PAT_PMAP_CS,
    Some(&PAT_PMAP_CS_MASK),
    4,
    repl(&REPL_MOV_NOP, 0),
)];

// --- entries (15 logical patches) ---

static E_ROOT_AUTH: PatchEntry = PatchEntry { attempts: &ATT_ROOT_AUTH };
static E_ROOT_RW: PatchEntry = PatchEntry { attempts: &ATT_ROOT_RW };
static E_ROOT_HASH: PatchEntry = PatchEntry { attempts: &ATT_ROOT_HASH };
static E_SNAPSHOT: PatchEntry = PatchEntry { attempts: &ATT_SNAPSHOT };
static E_AMFI_SHA1: PatchEntry = PatchEntry { attempts: &ATT_AMFI_SHA1 };
static E_AMFI_TC: PatchEntry = PatchEntry { attempts: &ATT_AMFI_TC };
static E_SCOT: PatchEntry = PatchEntry { attempts: &ATT_SCOT };
static E_IMG4: PatchEntry = PatchEntry { attempts: &ATT_IMG4 };
static E_MAC_MOUNT: PatchEntry = PatchEntry { attempts: &ATT_MAC_MOUNT };
static E_KPRINTF: PatchEntry = PatchEntry { attempts: &ATT_KPRINTF };
static E_AMX: PatchEntry = PatchEntry { attempts: &ATT_AMX };
static E_CS: PatchEntry = PatchEntry { attempts: &ATT_CS };
static E_HACT: PatchEntry = PatchEntry { attempts: &ATT_HACT };
static E_TC: PatchEntry = PatchEntry { attempts: &ATT_TC };
static E_PMAP_CS: PatchEntry = PatchEntry { attempts: &ATT_PMAP_CS };

// --- groups (8 patch targets, mirroring ck_patch_kernel) — 1:1 with upstream

const fn group(
    name: &'static str,
    image: Image,
    segment: &'static str,
    section: &'static str,
    fallback: Option<GroupFallback>,
    entries: &'static [PatchEntry],
) -> PatchGroup {
    PatchGroup { name, image, segment, section, fallback, entries }
}

const fn fb(image: Image, segment: &'static str, section: &'static str) -> Option<GroupFallback> {
    Some(GroupFallback { image, segment, section })
}

/// Every patch the C applies to the T8030 XNU, grouped by target image and
/// section: 8 groups / 15 logical patches / 23 find attempts.
pub static T8030_PATCH_GROUPS: &[PatchGroup] = &[
    group(
        "com.apple.filesystems.apfs",
        Image::Kext("com.apple.filesystems.apfs"),
        "__TEXT_EXEC",
        "__text",
        None,
        &[E_ROOT_AUTH, E_ROOT_RW, E_ROOT_HASH],
    ),
    group(
        "com.apple.filesystems.apfs __TEXT.__cstring",
        Image::Kext("com.apple.filesystems.apfs"),
        "__TEXT",
        "__cstring",
        fb(Image::Kernel, "__TEXT", "__cstring"),
        &[E_SNAPSHOT],
    ),
    group(
        "com.apple.driver.AppleMobileFileIntegrity",
        Image::Kext("com.apple.driver.AppleMobileFileIntegrity"),
        "__TEXT_EXEC",
        "__text",
        None,
        &[E_AMFI_SHA1, E_AMFI_TC],
    ),
    group(
        "com.apple.driver.AppleSEPManager",
        Image::Kext("com.apple.driver.AppleSEPManager"),
        "__TEXT_EXEC",
        "__text",
        None,
        &[E_SCOT],
    ),
    group(
        "com.apple.security.AppleImage4",
        Image::Kext("com.apple.security.AppleImage4"),
        "__TEXT_EXEC",
        "__text",
        None,
        &[E_IMG4],
    ),
    group(
        "com.apple.kernel",
        Image::Kernel,
        "__TEXT_EXEC",
        "__text",
        None,
        &[E_MAC_MOUNT, E_KPRINTF, E_AMX, E_CS],
    ),
    group(
        "com.apple.kernel __TEXT.__const",
        Image::Kernel,
        "__TEXT",
        "__const",
        None,
        &[E_HACT],
    ),
    group(
        "com.apple.kernel __PPLTEXT",
        Image::Kernel,
        "__PPLTEXT",
        "__text",
        fb(Image::Kernel, "__TEXT_EXEC", "__text"),
        &[E_TC, E_PMAP_CS],
    ),
];

// ---------------------------------------------------------------------------
// Image resolution — ck_kp_find_image_header + ck_patch_kernel's lookups
// ---------------------------------------------------------------------------

/// Located section: `addr` = boot VA, `off..off+len` = bytes in the image.
struct RangeLoc {
    addr: u64,
    off: usize,
    len: usize,
}

fn u64le(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// NUL-terminated string at `off` (C uses a `char kname[256]`).
fn cstr_at(img: &[u8], off: usize) -> Option<String> {
    let rest = img.get(off..)?;
    let end = rest.iter().position(|&b| b == 0)?.min(255);
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// Byte search (`strstr`) from `from`.
fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// `strtoull(s, 0, 0)`: 0x-hex, leading-0 octal, else decimal.
fn parse_u64_base0(b: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?.trim_start();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        return u64::from_str_radix(&digits, 16).ok();
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() > 1 && digits.starts_with('0') {
        u64::from_str_radix(&digits[1..], 8).ok()
    } else {
        digits.parse().ok()
    }
}

/// Fileset entries as `(entry_id, fileoff, end)` triples.
fn fileset_entries(img: &[u8]) -> Vec<(String, usize, usize)> {
    let Ok(fs) = load_fileset(img) else { return Vec::new() };
    let mut out = Vec::new();
    for e in &fs.entries {
        let mut end = img.len();
        for other in &fs.entries {
            if other.fileoff > e.fileoff {
                end = end.min(other.fileoff as usize);
            }
        }
        if (e.fileoff as usize) < end {
            out.push((e.entry_id.clone(), e.fileoff as usize, end));
        }
    }
    out
}

/// Locate (segment, section) within `[base, end)`. Section file offsets are
/// interpreted relative to `base` first (fileset entries), then absolute.
fn section_loc(img: &[u8], base: usize, end: usize, segment: &str, section: &str) -> Option<RangeLoc> {
    let s = crate::sections::find_section(&img[base..end], segment, section)?;
    let size = s.size as usize;
    let rel = base.checked_add(s.offset as usize)?;
    if rel.checked_add(size)? <= end.min(img.len()) {
        return Some(RangeLoc { addr: s.addr, off: rel, len: size });
    }
    let abs = s.offset as usize;
    if abs.checked_add(size)? <= img.len() {
        return Some(RangeLoc { addr: s.addr, off: abs, len: size });
    }
    None
}

/// The com.apple.kernel fileset entry bounds.
fn kernel_entry(img: &[u8]) -> Option<(usize, usize)> {
    fileset_entries(img)
        .into_iter()
        .find(|(id, _, _)| id == "com.apple.kernel" || id.ends_with("kernel"))
        .map(|(_, b, e)| (b, e))
}

/// Prefer the VA translation (the C patches through
/// `apple_boot_va_to_ptr(sec->addr)`); keep the file-offset view when the
/// slice has no VA window for this section.
fn reloc_via_va(img: &[u8], loc: RangeLoc, dram_base: u64) -> RangeLoc {
    match boot_va_to_offset(loc.addr, dram_base) {
        Some(off) if off.checked_add(loc.len).is_some_and(|e| e <= img.len()) => {
            RangeLoc { off, ..loc }
        }
        _ => loc,
    }
}

/// `ck_kp_find_image_header` for pre-fileset kernelcaches:
/// `__PRELINK_INFO.__kmod_info`/`__kmod_start` arrays, with the `__info`
/// XML plist scan as fallback. Returns the file offset of the KEXT's
/// Mach-O header (the C returns a VA→ptr).
fn find_kext_header_off(img: &[u8], bundle_id: &str, dram_base: u64) -> Option<usize> {
    if let Some(info) = crate::sections::find_section(img, "__PRELINK_INFO", "__kmod_info") {
        let io = info.offset as usize;
        let ilen = info.size as usize;
        if io + ilen <= img.len() {
            if let Some(start) = crate::sections::find_section(img, "__PRELINK_INFO", "__kmod_start") {
                let so = start.offset as usize;
                for i in 0..(ilen / 8) {
                    let Some(info_va) = u64le(img, io + i * 8) else { continue };
                    let Some(base) = boot_va_to_offset(info_va, dram_base) else { continue };
                    let Some(name) = cstr_at(img, base + 0x10) else { continue };
                    if name == bundle_id {
                        let Some(start_va) = u64le(img, so + i * 8) else { continue };
                        if let Some(off) = boot_va_to_offset(start_va, dram_base) {
                            return Some(off);
                        }
                    }
                }
            }
        }
    }

    // The `__PRELINK_INFO.__info` XML path: find the dict whose
    // CFBundleIdentifier matches, read its _PrelinkExecutableLoadAddr.
    let info = crate::sections::find_section(img, "__PRELINK_INFO", "__info")?;
    let o = info.offset as usize;
    let d = img.get(o..o.checked_add(info.size as usize)?)?;
    let p = find_sub(d, b"PrelinkInfoDictionary", 0)?;
    let mut last = find_sub(d, b"<array>", p)? + 7;
    loop {
        let mut end = find_sub(d, b"</dict>", last)?;
        // Skip nested dicts (the C's nested_dict/end_dict walk).
        let mut nested = find_sub(d, b"<dict>", last + 1);
        while let Some(nd) = nested {
            if nd > end {
                break;
            }
            nested = find_sub(d, b"<dict>", nd + 1);
            end = find_sub(d, b"</dict>", end + 1)?;
        }
        let dict = &d[last..end];
        if let Some(ident) = find_sub(dict, b"CFBundleIdentifier", 0) {
            if let Some(v) = find_sub(dict, b"<string>", ident) {
                let vs = v + 8;
                if let Some(ve) = find_sub(dict, b"</string>", vs) {
                    if &dict[vs..ve] == bundle_id.as_bytes() {
                        let a = find_sub(dict, b"_PrelinkExecutableLoadAddr", 0)?;
                        let a = find_sub(dict, b"<integer", a)?;
                        let a = find_sub(dict, b">", a)? + 1;
                        let va = parse_u64_base0(&dict[a..])?;
                        return boot_va_to_offset(va, dram_base);
                    }
                }
            }
        }
        last = find_sub(d, b"<dict>", end)?;
    }
}

/// Resolve a group's (image, segment, section) to patchable bytes.
fn resolve_image(
    img: &[u8],
    image: Image,
    segment: &str,
    section: &str,
    fileset: bool,
    dram_base: u64,
) -> Option<RangeLoc> {
    if fileset {
        match image {
            Image::Kernel => {
                if let Some((b, e)) = kernel_entry(img) {
                    if let Some(loc) = section_loc(img, b, e, segment, section) {
                        return Some(loc);
                    }
                }
                // The C also probes the top-level collection header
                // (`ck_kp_find_section_range(hdr, …)` for __PPLTEXT).
                section_loc(img, 0, img.len(), segment, section)
            }
            Image::Kext(id) => {
                let (b, e) = fileset_entries(img)
                    .into_iter()
                    .find(|(x, _, _)| x == id)
                    .map(|(_, b, e)| (b, e))?;
                section_loc(img, b, e, segment, section)
            }
        }
    } else {
        match image {
            Image::Kernel => {
                let loc = section_loc(img, 0, img.len(), segment, section)?;
                Some(reloc_via_va(img, loc, dram_base))
            }
            Image::Kext(id) => {
                let hdr = find_kext_header_off(img, id, dram_base)?;
                let loc = section_loc(img, hdr, img.len(), segment, section)?;
                Some(reloc_via_va(img, loc, dram_base))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Boot-pipeline entry point
// ---------------------------------------------------------------------------

/// Apply every T8030 XNU patch the C engine applies (`ck_patch_kernel`) to
/// a decompressed kernelcache and report honestly which ones matched.
///
/// `dram_base` is the boot VA that `kernel[0]` corresponds to (only used
/// for pre-fileset images, whose ranges resolve through
/// [`boot_va_to_offset`]). Missing images/sections are reported as
/// `missed` — never a panic, unlike the C's NULL-range deref.
pub fn apply_t8030_patches(kernel: &mut [u8], dram_base: u64) -> PatchReport {
    let mut report = PatchReport::default();
    let fileset = crate::sections::is_fileset(kernel);
    for group in T8030_PATCH_GROUPS {
        let loc = resolve_image(kernel, group.image, group.segment, group.section, fileset, dram_base)
            .or_else(|| {
                group
                    .fallback
                    .as_ref()
                    .and_then(|f| resolve_image(kernel, f.image, f.segment, f.section, fileset, dram_base))
            });
        let Some(loc) = loc else {
            for entry in group.entries {
                for a in entry.attempts {
                    report.missed.push(a.name.to_string());
                }
            }
            continue;
        };
        let name = format!("{} {}.{}", group.name, group.segment, group.section);
        let mut range = PatchRange::new(name, loc.addr, &mut kernel[loc.off..loc.off + loc.len]);
        for entry in group.entries {
            let mut applied = false;
            for att in entry.attempts {
                let ok = match att.body {
                    Body::Replace { repl, repl_mask, off } => {
                        range.find_replace(att.pattern, att.mask, att.align, repl, repl_mask, off)
                    }
                    Body::Callback(cb) => range.find_where(att.pattern, att.mask, att.align, cb),
                };
                if ok {
                    report.applied.push(att.name.to_string());
                    applied = true;
                    break;
                }
            }
            if !applied {
                for a in entry.attempts {
                    report.missed.push(a.name.to_string());
                }
            }
        }
    }
    report
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MH_EXECUTE: u32 = 2;
    const MH_FILESET: u32 = 12;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_FILESET_ENTRY: u32 = 0x8000_0035;
    /// Typical T8030 kernel VA window base (the VA `kernel[0]` maps to).
    const BASE: u64 = 0xFFFF_FE00_0700_4000;

    fn put32(img: &mut [u8], off: usize, v: u32) {
        img[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(img: &mut [u8], off: usize, v: u64) {
        img[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn putname(img: &mut [u8], off: usize, name: &str) {
        let b = name.as_bytes();
        img[off..off + b.len()].copy_from_slice(b);
    }
    fn insn(img: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(img[off..off + 4].try_into().unwrap())
    }

    fn macho_header(img: &mut [u8], filetype: u32, ncmds: usize, sizeofcmds: usize) {
        put32(img, 0, 0xFEED_FACF);
        put32(img, 4, 0x0100_000C); // MH_CPUTYPE_ARM64
        put32(img, 12, filetype);
        put32(img, 16, ncmds as u32);
        put32(img, 20, sizeofcmds as u32);
    }

    /// One LC_SEGMENT_64 with a single named section (cmdsize 152).
    fn seg_cmd(img: &mut [u8], off: usize, seg: &str, sect: &str, vmaddr: u64, fileoff: u64, size: u64) {
        put32(img, off, LC_SEGMENT_64);
        put32(img, off + 4, 152);
        putname(img, off + 8, seg);
        put64(img, off + 24, vmaddr);
        put64(img, off + 32, size);
        put64(img, off + 40, fileoff);
        put64(img, off + 48, size);
        put32(img, off + 64, 1); // nsects
        let s = off + 72;
        putname(img, s, sect);
        putname(img, s + 16, seg);
        put64(img, s + 32, vmaddr);
        put64(img, s + 40, fileoff);
        put64(img, s + 48, size);
    }

    /// T8030-style kernel collection: a `com.apple.kernel` fileset entry
    /// whose `__TEXT_EXEC.__text` carries the mac-mount prologue and whose
    /// `__TEXT.__const` carries the hactivation string, plus an
    /// `com.apple.filesystems.apfs` entry whose `__TEXT_EXEC.__text`
    /// carries the root-hash prologue (each at a known VA).
    fn synthetic_fileset() -> Vec<u8> {
        let mut img = vec![0u8; 0x2000];
        macho_header(&mut img, MH_FILESET, 2, 128);
        for (i, id) in ["com.apple.kernel", "com.apple.filesystems.apfs"].iter().enumerate() {
            let fe = 32 + i * 64;
            put32(&mut img, fe, LC_FILESET_ENTRY);
            put32(&mut img, fe + 4, 64); // cmdsize must cover the entry_id
            put64(&mut img, fe + 8, BASE + i as u64 * 0x10_0000);
            put64(&mut img, fe + 16, 0x1000 + i as u64 * 0x800);
            put32(&mut img, fe + 24, 32);
            putname(&mut img, fe + 32, &format!("{id}\0"));
        }

        // com.apple.kernel entry at 0x1000
        let e = 0x1000;
        macho_header(&mut img[e..], MH_EXECUTE, 2, 304);
        seg_cmd(&mut img[e..], 32, "__TEXT_EXEC", "__text", BASE, 0x200, 0x200);
        seg_cmd(&mut img[e..], 32 + 152, "__TEXT", "__const", BASE + 0x400, 0x400, 0x100);
        let text = e + 0x200;
        // mac-mount context: tbnz (MNT_UNION), ldrb (MNT_ROOTFS), orr marker
        put32(&mut img, text + 0x20, 0x3728_0001);
        put32(&mut img, text + 0x24, 0x3941_C408);
        img[text + 0x28..text + 0x2C].copy_from_slice(&PAT_MAC_MOUNT);
        // hactivation release-variant marker in __const
        img[e + 0x410..e + 0x419].copy_from_slice(&PAT_HACT);

        // com.apple.filesystems.apfs entry at 0x1800: pacibsp prologue then
        // the root-hash sequence the C finds in apfs's __TEXT_EXEC.__text
        let a = 0x1800;
        macho_header(&mut img[a..], MH_EXECUTE, 1, 152);
        seg_cmd(&mut img[a..], 32, "__TEXT_EXEC", "__text", BASE + 0x10_0000, 0x100, 0x100);
        let atext = a + 0x100;
        put32(&mut img, atext, PACIBSP);
        img[atext + 4..atext + 16].copy_from_slice(&PAT_ROOT_HASH);
        img
    }

    /// (a) synthetic kernel image → patches apply with the exact expected
    /// encodings (prologue → mov w0, #0 + ret; branch → NOP; ldrb →
    /// mov x8, xzr; "\0release" → "\0profile").
    #[test]
    fn synthetic_fileset_kernel_patches_apply() {
        let mut kc = synthetic_fileset();
        let rep = apply_t8030_patches(&mut kc, BASE);

        assert!(rep.applied.contains(&"bypass root hash authentication".to_string()));
        assert!(rep.applied.contains(&"enable hactivation".to_string()));
        assert!(rep.applied.contains(&"allow remounting rootfs, union mounts (old)".to_string()));
        assert!(rep.missed.contains(&"bypass root authentication".to_string()));
        assert!(rep.missed.contains(&"bypass pmap_cs_enforce".to_string()));

        let text = 0x1200; // kernel entry(0x1000) + __text fileoff(0x200)
        assert_eq!(insn(&kc, text + 0x20), NOP); // tbnz → nop
        assert_eq!(insn(&kc, text + 0x24), 0xAA1F_03E8); // ldrb → mov x8, xzr
        assert_eq!(&kc[0x1410..0x1419], b"\0profile\0");
        let atext = 0x1900; // apfs entry(0x1800) + __text fileoff(0x100)
        assert_eq!(insn(&kc, atext), MOV_W0_0); // pacibsp → mov w0, #0
        assert_eq!(insn(&kc, atext + 4), RET); // → ret
    }

    /// (c) a kernel lacking every prologue reports `missed`, never
    /// `applied` (and never panics).
    #[test]
    fn missing_prologues_report_missed() {
        let mut kc = synthetic_fileset();
        for region in [0x1200..0x1400, 0x1900..0x1A00] {
            for off in region.step_by(4) {
                put32(&mut kc, off, NOP);
            }
        }
        for b in &mut kc[0x1400..0x1500] {
            *b = 0;
        }
        let rep = apply_t8030_patches(&mut kc, BASE);
        assert!(rep.applied.is_empty());
        assert_eq!(rep.missed.len(), 23);
        assert!(rep.missed.contains(&"bypass root hash authentication".to_string()));
        assert!(rep.missed.contains(&"enable hactivation".to_string()));
        assert!(rep.missed.contains(&"allow mounting root as R/W (new)".to_string()));
    }

    /// (b) NOP/RET/… constants + movz/movk encoders against fixed u32s
    /// (each value also appears in an upstream pattern/callback).
    #[test]
    fn arm64_encoders_match_upstream_constants() {
        assert_eq!(NOP, 0xD503_201F);
        assert_eq!(RET, 0xD65F_03C0);
        assert_eq!(RETAB, 0xD65F_0FFF);
        assert_eq!(PACIBSP, 0xD503_237F);
        assert_eq!(MOV_W0_0, 0x5280_0000);
        assert_eq!(MOV_W0_0, movz(0, 0, 0, false));
        assert_eq!(movz(9, 0x800, 0, false), 0x5281_0009); // mov w9, #0x800
        assert_eq!(movz(0, 0x101, 0, false), 0x5280_2020); // mov w0, 0x101
        assert_eq!(movz(0, 2, 0, false), 0x5280_0040);
        assert_eq!(movz(0, 1, 0, false), 0x5280_0020);
        assert_eq!(movz(8, 1, 16, false), 0x52A0_0028); // mov w8, #0x10000
        assert_eq!(movz(0, 1, 0, true), 0xD280_0020); // mov x0, #1
        assert_eq!(movz(0, 0xEE7E, 0, true), 0xD29D_CFC0); // iOS16 tc probe
        assert_eq!(movk(0, 0x900, 16, false), 0x72A1_2000); // movk w?, #0x900, lsl #16
    }

    /// (d) boot VA window translation roundtrip (mem.c ports).
    #[test]
    fn boot_va_window_translation() {
        assert_eq!(boot_va_to_offset(BASE + 0x1234, BASE), Some(0x1234));
        assert_eq!(boot_va_to_offset(BASE, BASE), Some(0));
        assert_eq!(boot_va_to_offset(BASE - 4, BASE), None);
        // low VAs canonicalise into the boot window
        assert_eq!(boot_va_to_offset(0x1234, 0x1000), Some(0x234));
        // vtop_bases / ptov_bases roundtrip
        let (phys, virt) = (0x8000_0000u64, BASE);
        let pa = vtop_bases(BASE + 0x40, phys, virt).unwrap();
        assert_eq!(pa, phys + 0x40);
        assert_eq!(ptov_bases(pa, phys, virt).unwrap(), BASE + 0x40);
        assert_eq!(boot_fixup_slide_va(0x1234), 0xFFFF_0000_0000_1234);
    }

    /// Engine: masked find honours align; find_replace OR-merges through a
    /// replacement mask (the `(old & mask) | repl` path).
    #[test]
    fn find_mask_align_and_masked_replace() {
        let mut data = vec![0u8; 0x40];
        put32(&mut data, 0x08, 0x3940_2C08);
        put32(&mut data, 0x30, 0x3940_2C0A);
        let r = PatchRange::new("t", 0x1000, &mut data);
        // don't-care bits zeroed in the pattern (the C's precondition)
        let pat = [0x00, 0x2C, 0x40, 0x39];
        let mask = [0x00, 0xFC, 0xFF, 0xFF]; // any Rt
        assert_eq!(r.find_from(&pat, Some(&mask), 4, 0), Some(0x08));
        assert_eq!(r.find_from(&pat, Some(&mask), 4, 0x0C), Some(0x30));

        let mut data2 = vec![0u8; 0x40];
        data2[0x09..0x0D].copy_from_slice(&[0x08, 0x2C, 0x40, 0x39]);
        let r2 = PatchRange::new("t", 0, &mut data2);
        assert_eq!(r2.find_from(&pat, Some(&mask), 4, 0), None);
        assert_eq!(r2.find_from(&pat, Some(&mask), 0, 0), Some(0x09));

        // cmp w0, #2 → clear bit 0 through a replacement mask
        let mut data3 = vec![0u8; 0x40];
        put32(&mut data3, 0x10, 0x7100_081F);
        let mut r3 = PatchRange::new("t", 0, &mut data3);
        assert!(r3.find_replace(
            &[0x1F, 0x08, 0x00, 0x71],
            None,
            4,
            &[0x00],
            Some(&[0xFE]),
            0
        ));
        assert_eq!(r3.ldl_le(0x10), Some(0x7100_081E));
    }

    /// Engine: find_next_insn / find_prev_insn word scans with skip.
    #[test]
    fn find_next_prev_insn_scans() {
        let mut data = vec![0u8; 0x80];
        let words = [0xA9A0_03E0u32, 0xD100_03FF, RET, PACIBSP, RET];
        for (i, v) in words.iter().enumerate() {
            put32(&mut data, i * 4, *v);
        }
        let r = PatchRange::new("t", 0, &mut data);
        assert_eq!(r.find_next_insn(0, 8, RET, 0xFFFF_FFFF, 0), Some(8));
        assert_eq!(r.find_next_insn(0, 8, RET, 0xFFFF_FFFF, 1), Some(16));
        assert_eq!(r.find_next_insn(0, 2, RET, 0xFFFF_FFFF, 0), None);
        assert_eq!(r.find_prev_insn(16, 4, RET, 0xFFFF_FFFF, 0), Some(16));
        assert_eq!(r.find_prev_insn(16, 4, RET, 0xFFFF_FFFF, 1), Some(8));
        assert_eq!(r.find_prev_insn(16, 8, PACIBSP, 0xFFFF_FFFF, 0), Some(12));
        // word scans never leave the slice
        assert_eq!(r.find_next_insn(0x7C, 4, RET, 0xFFFF_FFFF, 0), None);
    }

    /// Old-style (pre-fileset) kernelcache: the `__info` XML finder locates
    /// the apfs KEXT by bundle id and the root-hash patch applies through
    /// boot_va_to_offset.
    #[test]
    fn legacy_prelink_xml_finds_apfs_kext() {
        let mut img = vec![0u8; 0x1000];
        // Outer kernel Mach-O at file 0 with __PRELINK_INFO.__info.
        macho_header(&mut img, MH_EXECUTE, 1, 152);
        seg_cmd(&mut img, 32, "__PRELINK_INFO", "__info", BASE + 0x200, 0x200, 0x200);
        let xml = format!(
            concat!(
                "<?xml version=\"1.0\"?><plist><dict>",
                "<key>_PrelinkInfoDictionary</key><array><dict>",
                "<key>CFBundleIdentifier</key><string>com.apple.filesystems.apfs</string>",
                "<key>_PrelinkExecutableLoadAddr</key><integer>{}</integer>",
                "</dict></array></dict></plist>"
            ),
            BASE + 0x600
        );
        img[0x200..0x200 + xml.len()].copy_from_slice(xml.as_bytes());

        // apfs KEXT Mach-O at file 0x600 (VA BASE + 0x600): pacibsp
        // prologue then the root-hash sequence in its __TEXT_EXEC.__text.
        let kx = 0x600;
        macho_header(&mut img[kx..], MH_EXECUTE, 1, 152);
        seg_cmd(&mut img[kx..], 32, "__TEXT_EXEC", "__text", BASE + 0x700, 0x100, 0x100);
        put32(&mut img, 0x700, PACIBSP);
        img[0x704..0x710].copy_from_slice(&PAT_ROOT_HASH);

        let rep = apply_t8030_patches(&mut img, BASE);
        assert!(rep.applied.contains(&"bypass root hash authentication".to_string()));
        assert!(rep.missed.contains(&"bypass root authentication".to_string()));
        assert_eq!(insn(&img, 0x700), MOV_W0_0);
        assert_eq!(insn(&img, 0x704), RET);
    }

    /// The full 1:1 table shape: 8 groups, 15 entries, 23 attempts.
    #[test]
    fn table_shape_matches_upstream() {
        assert_eq!(T8030_PATCH_GROUPS.len(), 8);
        let entries: usize = T8030_PATCH_GROUPS.iter().map(|g| g.entries.len()).sum();
        let attempts: usize = T8030_PATCH_GROUPS
            .iter()
            .flat_map(|g| g.entries)
            .map(|e| e.attempts.len())
            .sum();
        assert_eq!(entries, 15);
        assert_eq!(attempts, 23);
        // every fallback chain runs its primary first
        for g in T8030_PATCH_GROUPS {
            for e in g.entries {
                assert!(!e.attempts.is_empty());
            }
        }
    }
}
