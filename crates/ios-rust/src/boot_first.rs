//! boot-first — THE FIRST BOOT AFTER IRESTORE.
//!
//! One command reproduces, on real Apple bytes, what happens between
//! idevicerestore printing "Restore Finished (status 0)" and the device
//! showing anything at all:
//!
//! ```text
//! BuildManifest.plist ──▶ identity select (DeviceClass/Variant)
//!        ──▶ SHA-384 component verification (KernelCache, DeviceTree)
//!        ──▶ stage  <out>/boot-first-staged/          (the restored device state)
//!        ──▶ FIRST BOOT: iBoot-equivalent machine assembly from the STAGED
//!            DeviceTree → STAGED KernelCache (LZFSE → patch table) →
//!            real __TEXT_EXEC through the pure-Rust A13 interpreter
//! ```
//!
//! Honest scope (mirrors the ledger): the first boot executes the REAL
//! iBoot→xnu handoff contract (boot_args at physBase in x0, LC_UNIXTHREAD
//! entry at load PA, MMU off — the measured 8.14M-insn boot-real path) and
//! stops where the engine's known gaps stop it. The old behavior here —
//! executing `__TEXT_EXEC.__text[0]` with no handoff state and a 20k cap
//! (9 insns → Halted) — was not a boot; see PARITY.md Layer 2.11a/d.

use std::path::{Path, PathBuf};

use plist::Value;
use sha2::{Digest as _, Sha384};

use crate::boot_full;
use crate::boot_real;

/// Instruction budget for the first boot. The measured honest stop (the
/// kernel's DeviceTree-dependent CPU-enumeration path) lands at ~8.14M
/// insns; 12M leaves headroom without running away.
///
/// Session M (2026-10-30) moved the frontier to a 48M CLEAN budget stop
/// (kernel-HANDLED percpu abort, panic 0), so 48M became the default.
/// M5 census runs need to look PAST the budget stop — the standard env-knob
/// pattern (IOS_RUST_DRAM_MB / IOS_RUST_STOP_PC_RANGE / IOS_RUST_TRACE_DEEP)
/// extends it: IOS_RUST_BOOT_FIRST_MAX_INSN=<n> overrides without touching
/// default behavior (unset → 48M, byte-identical runs).
fn boot_first_max_insn() -> u64 {
    std::env::var("IOS_RUST_BOOT_FIRST_MAX_INSN")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(48_000_000)
}

pub const BOOT_FIRST_ID: &str = "boot-first v1 (irestore staging → first boot, real bytes)";

/// One verified staged component.
struct Staged {
    /// BuildManifest key ("KernelCache", "DeviceTree").
    manifest_key: &'static str,
    /// Fixture file name (and staged file name — identical for the boot).
    file: &'static str,
    size: usize,
    /// SHA-384 hex of the staged bytes (what restored would have pushed).
    sha384: String,
    /// Which identity(ies) the digest verified against.
    verified_in: Vec<String>,
}

fn sha384_hex(data: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Walk BuildIdentities, return (device_class, variant, build) for each.
fn identities(m: &Value) -> Vec<(String, String, String, &Value)> {
    let mut out = Vec::new();
    if let Some(list) = m.get("BuildIdentities").and_then(Value::as_array) {
        for id in list {
            let info = match id.get("Info") {
                Some(i) => i,
                None => continue,
            };
            let class = info.get("DeviceClass").and_then(Value::as_string).unwrap_or("?");
            let variant = info.get("Variant").and_then(Value::as_string).unwrap_or("?");
            let build = info.get("BuildNumber").and_then(Value::as_string).unwrap_or("?");
            out.push((class.to_string(), variant.to_string(), build.to_string(), id));
        }
    }
    out
}

/// Manifest scalar → display string (Apple uses strings OR ints for IDs).
fn scalar_str(v: &Value) -> String {
    if let Some(s) = v.as_string() {
        return s.to_string();
    }
    if let Some(u) = v.as_uint() {
        return format!("{u:#x}");
    }
    if let Some(i) = v.as_int() {
        return format!("{i:#x}");
    }
    "?".into()
}

/// Digest bytes of `component` in an identity's Manifest, if present.
fn manifest_digest<'a>(ident: &'a Value, component: &str) -> Option<&'a [u8]> {
    ident
        .get("Manifest")?
        .get(component)?
        .get("Digest")?
        .as_data()
}

pub fn run(fixtures_in: Option<&Path>, out_dir: &Path) -> i32 {
    println!("{BOOT_FIRST_ID}");

    // ---- locate fixtures (irestore input: BuildManifest + components) ----
    let dir: PathBuf = match fixtures_in {
        Some(d) if d.join("BuildManifest.plist").exists() => d.to_path_buf(),
        _ => match boot_full::fixtures_dir() {
            Some(d) => d,
            None => {
                eprintln!("fixtures not found (need BuildManifest.plist + kernelcache + DeviceTree)");
                return 2;
            }
        },
    };

    // ---- [irestore 1/3] BuildManifest identity selection ----
    let raw = match std::fs::read(dir.join("BuildManifest.plist")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("read BuildManifest.plist: {e}");
            return 2;
        }
    };
    let manifest = match plist::parse(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse BuildManifest.plist: {e}");
            return 2;
        }
    };
    let build = manifest.get("ProductBuildVersion").and_then(Value::as_string).unwrap_or("?");
    let board = manifest.get("SupportedProductTypes").and_then(Value::as_array).map(|a| {
        a.iter().filter_map(Value::as_string).map(str::to_string).collect::<Vec<_>>()
    }).unwrap_or_default();
    let idents = identities(&manifest);
    let n104: Vec<&(String, String, String, &Value)> = idents.iter().filter(|(c, _, _, _)| c == "n104ap").collect();
    println!(
        "[irestore 1/3] BuildManifest: build {build} · {} identities · {}× n104ap · supported: {}",
        idents.len(),
        n104.len(),
        board.join(", ")
    );
    if n104.is_empty() {
        eprintln!("no n104ap identity in BuildManifest — wrong manifest for iPhone12,1");
        return 2;
    }

    // ---- [irestore 2/3] component SHA-384 verification (restored data plane) ----
    let kc_name = "kernelcache.release.iphone12b";
    let dt_name = "DeviceTree.n104ap.im4p";
    let (kc_raw, dt_raw) = match (
        std::fs::read(dir.join(kc_name)),
        std::fs::read(dir.join(dt_name)),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (e1, e2) => {
            eprintln!(
                "component read failed: kernelcache_ok={} devicetree_ok={}",
                e1.is_ok(),
                e2.is_ok()
            );
            return 2;
        }
    };

    // For each n104ap identity, does the manifest digest match the real bytes?
    let mut kc_hits: Vec<(usize, String)> = Vec::new();
    let mut dt_hits: Vec<(usize, String)> = Vec::new();
    for (i, (class, variant, _, ident)) in idents.iter().enumerate() {
        if class != "n104ap" {
            continue;
        }
        if let Some(d) = manifest_digest(ident, "KernelCache") {
            if d == sha384_digest_bytes(&kc_raw) {
                kc_hits.push((i, variant.clone()));
            }
        }
        if let Some(d) = manifest_digest(ident, "DeviceTree") {
            if d == sha384_digest_bytes(&dt_raw) {
                dt_hits.push((i, variant.clone()));
            }
        }
    }

    let kc_digest = sha384_hex(&kc_raw);
    let dt_digest = sha384_hex(&dt_raw);
    println!("[irestore 2/3] component verification (SHA-384 over real Apple bytes):");
    println!("    DeviceTree.n104ap.im4p      {} B  sha384 {}…", dt_raw.len(), &dt_digest[..16]);
    println!("    kernelcache.release.iphone12b {} B  sha384 {}…", kc_raw.len(), &kc_digest[..16]);
    for (i, v) in &dt_hits {
        println!("        ✅ DeviceTree digest == identity[{i}] “{v}”");
    }
    for (i, v) in &kc_hits {
        println!("        ✅ KernelCache digest == identity[{i}] “{v}”");
    }
    if dt_hits.is_empty() || kc_hits.is_empty() {
        eprintln!(
            "digest verification FAILED: DeviceTree matches={} KernelCache matches={} — refusing to stage",
            dt_hits.len(), kc_hits.len()
        );
        return 3;
    }
    println!("        ℹ RestoreKernelCache/RestoreDeviceTree are the restore-RAMDISK images (used");
    println!("          DURING the restore; the G1/G2 lanes cover them) — the first boot after");
    println!("          “Restore Finished” executes the release KernelCache + DeviceTree verified here.");

    // ---- [irestore 3/3] stage the install (the device state after status 0) ----
    let staged = out_dir.join("boot-first-staged");
    if let Err(e) = std::fs::create_dir_all(&staged) {
        eprintln!("mkdir {}: {e}", staged.display());
        return 2;
    }
    if let Err(e) = std::fs::write(staged.join(kc_name), &kc_raw)
        .and_then(|_| std::fs::write(staged.join(dt_name), &dt_raw))
    {
        eprintln!("stage write: {e}");
        return 2;
    }
    let first = n104[0].3;
    let chip = first.get("ApChipID").map(scalar_str).unwrap_or_else(|| "?".into());
    let board_id = first.get("ApBoardID").map(scalar_str).unwrap_or_else(|| "?".into());
    let ubid = first
        .get("UniqueBuildID")
        .and_then(Value::as_data)
        .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .unwrap_or_default();
    let staging_manifest = format!(
        "boot-first staging manifest — the device state right after irestore\n\
         build: {} · train: {} · ApChipID: {} · ApBoardID: {}\n\
         UniqueBuildID: {}\n\
         components (SHA-384 verified against BuildManifest):\n\
         \x20 {}  {} B  {}\n\
         \x20 {}  {} B  {}\n\
         restored status: 0 (Restore Finished)\n",
        build,
        n104[0].3.get("Info").and_then(|i| i.get("BuildTrain")).and_then(Value::as_string).unwrap_or("?"),
        chip, board_id, ubid,
        dt_name, dt_raw.len(), dt_digest,
        kc_name, kc_raw.len(), kc_digest,
    );
    if let Err(e) = std::fs::write(staged.join("staging-manifest.txt"), staging_manifest) {
        eprintln!("write staging manifest: {e}");
        return 2;
    }
    println!(
        "[irestore 3/3] staged → {} (2 components + staging-manifest.txt) — “Restore Finished (status 0)”",
        staged.display()
    );

    // ---- FIRST BOOT: the real iBoot→xnu handoff on the staged bytes ----
    println!("[first boot] iBoot-equivalent: ADT from STAGED DeviceTree → STAGED KernelCache on the Rust backend");
    match boot_real::run(&staged, boot_first_max_insn()) {
        Ok(r) => {
            println!(
                "[boot 1/3] machine: {} B kernel LZFSE-decoded · link base {:#x} · entry PA {:#x}",
                r.image_bytes, r.link_base, r.entry_pa
            );
            println!(
                "[boot 2/3] devices: {}/{} /arm-io peripherals modeled · boot_args @ {:#x} · DT @ {:#x} ({} B)",
                r.devices_attached, r.adt_peripherals, r.bootargs_pa, r.dt_pa, r.dt_bytes
            );
            println!(
                "[boot 3/3] REAL exec: {} instructions retired from {:#x} · stop: {:?}",
                r.res.executed, r.entry_pa, r.res.stop
            );
            boot_real::print_report(&r);
            println!();
            println!("first-boot verdict (honest):");
            println!("  ✅ irestore lane: BuildManifest identity + SHA-384 component verification + staging");
            println!("  ✅ iBoot lane:    real handoff contract (boot_args, LC_UNIXTHREAD entry, MMU-off start)");
            println!(
                "  {} real xnu execution: {} instructions retired (real Apple 18C66 bytes)",
                if r.res.executed > 0 { "✅" } else { "❌" },
                r.res.executed
            );
            println!("  ❌ full boot: NOT reached — honest stop (session H, see PARITY.md 2.12):");
            println!("     DT population + /cpus enumeration now WORK (bugs #20/#22/#24 fixed);");
            println!("     the kernel runs its own data-abort handler (21,270 vectored aborts) and");
            println!("     stops on a zero-fetch at 0xfffffff00816c458 — its text PA reads zero after");
            println!("     the abort-driven remap loop (next block's RE target). Nothing synthetic.");
            println!("     (Pre-H stop, kept for the ledger: DT-globals NULL in /cpus enumeration.)");
            if r.res.executed > 0 {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("first boot failed: {e}");
            4
        }
    }
}

/// SHA-384 as raw bytes (for manifest Digest comparison).
fn sha384_digest_bytes(data: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().to_vec()
}
