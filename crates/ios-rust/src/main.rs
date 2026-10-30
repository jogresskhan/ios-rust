//! ios-rust — THE one binary of the workspace.
//!
//! "one rust workspace and lib used in one binary": every crate is a library;
//! this bin is the only executable, and it is the QEMU-binary replacement for
//! the T8030 flow:
//!
//!   ios-rust run [-M apple-t8030] -kernel … -dtb … -serial file:…   (QEMU drop-in subset)
//!   ios-rust restore <ipsw>       restore+install pipeline (IM4P/manifest/variants)
//!   ios-rust boot <ipsw>          restore → install → boot-to-homescreen ladder
//!   ios-rust parity               print the 100%-parity ledger status
//!   ios-rust vault <list|get|put|usage>   research-S3 operations
//!   ios-rust selftest             run the workspace test invariants

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use devices::bus::MMIODevice;
use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, InterpBudget, MemAccess, StopReason};
use apple_soc::t8030::{effective_dram_mb, T8030Machine};
use vm_core::Bus;
use ipsw::im4p::Im4p;
use ipsw::ramdisk_variants::{BISECTION_VERDICT_74, RamdiskVariant};
use sha2::Digest as _;
use soc_t8030;
use vault::VaultClient;
use virt::{machine_boot, Machine, MachineConfig, QemuCli, QEMU_COMPAT_VERSION};

mod boot_full;
mod boot_first;
mod boot_real;
mod host_restore;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[1..]),
        Some("restore") => cmd_restore(&args[1..]),
        Some("boot") => cmd_boot(&args[1..]),
        Some("parity") => cmd_parity(),
        Some("vault") => cmd_vault(&args[1..]),
        Some("selftest") => cmd_selftest(),
        Some("dsc") => cmd_dsc(&args[1..]),
        Some("kc") => cmd_kernelcache(&args[1..]),
        Some("adt") => cmd_adt(&args[1..]),
        Some("devices") => cmd_devices(&args[1..]),
        Some("vulns") => cmd_vulns(&args[1..]),
        Some("dc") => cmd_devicecheck(&args[1..]),
        Some("xnu") => cmd_xnu(&args[1..]),
        Some("host") => cmd_host(&args[1..]),
        Some("boot-full") => {
            // boot-full [ipsw] [out-dir] — a directory arg is the out-dir
            let (ipsw, out_dir) = match args.get(1) {
                Some(a) if Path::new(a).is_dir() => (args.get(2).map(PathBuf::from), PathBuf::from(a)),
                Some(a) => (Some(PathBuf::from(a)), args.get(2).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))),
                None => (None, PathBuf::from(".")),
            };
            boot_full::run(ipsw.as_deref(), &out_dir)
        }
        Some("boot-first") => {
            // boot-first [fixtures-dir] [out-dir] — irestore staging → first boot
            let mut fixtures = None;
            let mut out_dir = PathBuf::from(".");
            for a in &args[1..] {
                let p = Path::new(a);
                if p.is_dir() {
                    if p.join("BuildManifest.plist").exists() && fixtures.is_none() {
                        fixtures = Some(p.to_path_buf());
                    } else {
                        out_dir = p.to_path_buf();
                    }
                }
            }
            boot_first::run(fixtures.as_deref(), &out_dir)
        }
        Some("boot-real") => {
            // boot-real [fixtures-dir] [max-insn] — the REAL first boot
            let mut fixtures = None;
            let mut max_insn: u64 = 48_000_000;
            for a in &args[1..] {
                let p = Path::new(a);
                if p.is_dir() {
                    fixtures = Some(p.to_path_buf());
                } else if let Ok(n) = a.parse::<u64>() {
                    max_insn = n;
                }
            }
            match boot_full::fixtures_dir()
                .map(|d| boot_real::run(&d, max_insn))
            {
                Some(Ok(r)) => {
                    boot_real::print_report(&r);
                    0
                }
                Some(Err(e)) => {
                    eprintln!("boot-real failed: {e}");
                    4
                }
                None => {
                    eprintln!("fixtures not found");
                    2
                }
            }
        }
        Some("sandbox") => cmd_sandbox(&args[1..]),
        _ => {
            eprintln!(
                "ios-rust {} — single-binary T8030 emulator + restore pipeline\n\n\
                 commands:\n  run      qemu-system-aarch64 compatible subset (-M apple-t8030 …)\n  restore  parse + ramdisk-variant IPSW pipeline\n  boot     restore → install → homescreen ladder (honest status)\n  boot-full  ipsw → full-root → real-kernel → springboard (fixtures-aware)\n  boot-first  irestore staging (SHA-384 verify) → FIRST BOOT on real bytes
  boot-real  the REAL first boot: real XNU handoff → real MMU → real exec\n  parity   100%-parity ledger status\n  vault    research-S3 (list/get/put/usage)\n  selftest invariants\n  dsc      dyld shared cache reader (info/images/rebase/symbols/a2o/o2a)\n  kc       kernelcache (info/version/kexts) — LZSS/LZFSE decode\n  devices  device database + ipsw.me catalog (list/lookup/board/cpuid/t8030/ipsw-me)\n  vulns    iOS vulnerability research KB (list/show/search/mitigations/frida/tools)\n  dc       DeviceCheck token internals (demo/constants/entitlements)\n  xnu      XNU ARM64 ABI KB (syscalls/traps/errno/boot/boot-order/abi)\n  host     Linux host integration (check/deps/qemu)",
                env!("CARGO_PKG_VERSION")
            );
            2
        }
    };
    std::process::exit(code);
}

/// `run` — QEMU-replacement entry. Parses the flag subset, assembles the
/// machine, reports the honest exec status (TCG port pending).
fn cmd_run(args: &[String]) -> i32 {
    let cli = match QemuCli::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("flag error: {e}");
            return 2;
        }
    };
    println!("{QEMU_COMPAT_VERSION}");
    let cfg = MachineConfig {
        kernel: cli.kernel.clone(),
        dtb: cli.dtb.clone(),
        append: cli.append.clone(),
        drives: cli.drives.clone(),
    };
    let mut m = Machine::new(cfg);
    let report = machine_boot::boot(&mut m);
    println!("{report}");
    if let Some(serial) = &cli.serial_file {
        println!("console sink: {}", serial.display());
    }
    if cli.machine.as_deref() != Some(soc_t8030::MACHINE_NAME)
        && cli.machine.as_deref() != Some(soc_t8030::SOC_CODE)
    {
        eprintln!(
            "warning: machine '{:?}' differs from the workspace target {}",
            cli.machine,
            soc_t8030::MACHINE_NAME
        );
        return 1;
    }
    0
}

/// `restore` — parse the IPSW artifacts the lane stages, print per-variant
/// matrix + the run #74 verdict; `--file x.im4p` parses an actual container.
fn cmd_restore(_args: &[String]) -> i32 {
    println!(
        "restore pipeline — SoC {} ({}), ramdisk bisection matrix:",
        soc_t8030::SOC_NAME,
        soc_t8030::SOC_CODE
    );
    if let Ok(path) = std::env::var("IOS_RUST_IM4P") {
        if let Ok(buf) = std::fs::read(&path) {
            match Im4p::parse(&buf) {
                Ok(p) => println!(
                    "IM4P {}: type={:?} bytes={} ramdisk={} kernel={}",
                    path,
                    std::str::from_utf8(&p.fourcc_type).unwrap_or("?"),
                    p.data.len(),
                    p.is_ramdisk(),
                    p.is_kernel()
                ),
                Err(e) => println!("IM4P parse error: {e}"),
            }
        }
    }
    println!("host restore stack: {} (e2e mock-proven; see parity ledger)", host_restore::STACK_ID);
    for v in RamdiskVariant::diag_order() {
        let i = v.info();
        println!("  {:10} {} → run#74: {}", i.id, i.description, i.verdict74);
    }
    println!("verdict: {BISECTION_VERDICT_74}");
    0
}

/// `boot` — the IPSW→GUI→homescreen ladder, honestly reported.
/// With no IPSW argument it runs the **engine smoke**: the real T8030
/// machine (bus + AIC + UART + WDT + DART + ADP) driven by the real A13
/// interpreter over real MMIO, printing `IOS` to the serial console and
/// painting the framebuffer → BMP (the GUI path, CI-verifiable).
fn cmd_boot(args: &[String]) -> i32 {
    let ipsw = args.first().map(PathBuf::from);
    println!(
        "boot ladder for {}: fetch → restore → install → homescreen",
        ipsw.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<ipsw>".into())
    );
    let mut m = Machine::new(MachineConfig::default());
    let report = machine_boot::boot(&mut m);
    println!("{report}");

    // ---- engine smoke: real machine + real CPU over the real bus ----
    println!("engine smoke: T8030 machine + a13 interpreter");
    let mut machine = T8030Machine::new(effective_dram_mb());
    machine.attach_fallback();
    let serial = machine.serial.clone();
    let mut bus = std::mem::replace(&mut machine.bus, Bus::new());

    struct BusMem(Bus, Arc<Mutex<[u64; 3]>>); // [loads, stores, uart_stores]
    impl MemAccess for BusMem {
        fn load(&mut self, addr: u64, size: u8) -> u64 {
            if let Ok(mut s) = self.1.lock() { s[0] += 1; }
            self.0.read(addr, size)
        }
        fn store(&mut self, addr: u64, size: u8, val: u64) {
            if let Ok(mut s) = self.1.lock() {
                s[1] += 1;
                if addr == 0x2_3520_0020 {
                    s[2] += 1;
                }
            }
            self.0.write(addr, size, val);
        }
        fn fetch32(&mut self, addr: u64) -> u32 {
            self.0.read(addr, 4) as u32
        }
    }

    // Guest program: write "IOS\n" to UART0 TX (0x235200020), then HLT.
    // Hand-verified A64 encodings (see a13-cpu decode tests).
    let uart_tx: u64 = 0x2_3520_0020; // UART0 (0x235200000) + UTXH (0x20)
    let mut code: Vec<u32> = Vec::new();
    let put = |c: &mut Vec<u32>, w: u32| c.push(w);
    for ch in b"IOS\n" {
        // movz w0, #ch        (32-bit, sf=0)
        put(&mut code, 0x52800000u32 | ((*ch as u32) << 5)); // movz w0, #ch
        // movz x1, #uart[15:0]
        put(&mut code, 0xD2800000u32 | (((uart_tx & 0xFFFF) as u32) << 5) | 1);
        // movk x1, #uart[31:16], lsl #16
        put(&mut code, 0xF2A00000u32 | ((((uart_tx >> 16) & 0xFFFF) as u32) << 5) | 1);
        // movk x1, #uart[47:32], lsl #32
        put(&mut code, 0xF2C00000u32 | ((((uart_tx >> 32) & 0xFFFF) as u32) << 5) | 1);
        // str w0, [x1]
        put(&mut code, 0xB9000020);
    }
    put(&mut code, 0xD4400000); // hlt #0

    let mut img = vec![0u8; 0x1000];
    for (i, w) in code.iter().enumerate() {
        img[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    bus.write_raw(0x8_0010_0000, &img); // DRAM_BASE + 1 MiB = 0x800100000
    let stats = Arc::new(Mutex::new([0u64; 3]));
    let mut cpu = Interpreter::new(Box::new(BusMem(bus, stats.clone())));
    cpu.set_reset_vector(0x8_0010_0000);
    let res = cpu.run(InterpBudget { max_insn: 200, max_ns: 1_000_000_000 });
    let st = *stats.lock().unwrap();
    println!("  bus: loads={} stores={} uart_hits={}", st[0], st[1], st[2]);
    let out = serial.lock().map(|s| s.clone()).unwrap_or_default();
    let serial_ok = out == b"IOS\n";
    println!(
        "  cpu: executed={} stop={:?} serial={:?} → {}",
        res.executed,
        res.stop,
        String::from_utf8_lossy(&out),
        if serial_ok && res.stop == StopReason::Halted { "PASS" } else { "FAIL" }
    );

    // GUI path: paint the framebuffer (frontend of the ADP v4 path) → BMP
    if let Ok(mut fb) = machine.fb.lock() {
        for y in 0..fb.height {
            for x in 0..fb.width {
                let d = ((y * fb.width + x) * 4) as usize;
                let t = (x + y) as u8;
                fb.rgba[d] = 0x18 + t / 8; // R
                fb.rgba[d + 1] = 0x10 + t / 12; // G
                fb.rgba[d + 2] = 0x2A; // B
                fb.rgba[d + 3] = 0xFF;
            }
        }
        fb.sequence += 1;
    }
    let fb_snapshot = machine.fb.lock().map(|f| f.clone());
    if let Ok(fb) = fb_snapshot {
        match vm_core::framebuffer::write_bmp(&fb, "t8030-frame.bmp") {
            Ok(()) => println!("  gui: framebuffer painted {}x{} → t8030-frame.bmp", fb.width, fb.height),
            Err(e) => println!("  gui: bmp dump failed: {e}"),
        }
    }
    println!("gate status: G1 restore-ramdisk ✅ (C lane) | engine smoke = {} | G2 ASR stage = frontier | G3 install = pending | G4 homescreen = pending",
        if serial_ok { "PASS" } else { "FAIL" });
    if serial_ok { 0 } else { 1 }
}

/// `sandbox` — SandBlaster port: binary sandbox profile → SBPL.
fn cmd_sandbox(args: &[String]) -> i32 {
    match args.first() {
        Some(path) => match std::fs::read(path) {
            Ok(bin) => match sandbox::reverse_sandbox(&bin, sandbox::ops::SB_OPS) {
                Ok(sbpl) => {
                    print!("{sbpl}");
                    0
                }
                Err(e) => {
                    eprintln!("sandbox decompile failed: {e}");
                    2
                }
            },
            Err(e) => {
                eprintln!("read {path}: {e}");
                2
            }
        },
        None => {
            println!(
                "sandbox — SandBlaster port (cellebrite-labs/sandblaster → Rust)\n\
                 usage: ios-rust sandbox <binary-profile>\n\
                 ops table: {} known operations",
                sandbox::ops::SB_OPS.len()
            );
            0
        }
    }
}

/// `parity` — the ledger status (mirror of PARITY.md headline).
fn cmd_parity() -> i32 {
    println!("parity ledger — workspace target: 100% (see PARITY.md for per-item gates)");
    let rows: &[(&str, u8)] = &[
        ("libqemuutil port (19 modules)", 100),
        ("SoC definition (T8030/CPU/ISA)", 100),
        ("bus + MMIO dispatch (2 impls)", 100),
        ("A13 decoder (named-ISA + goldens)", 90),
        ("A13 interpreter (20 ISA groups exec)", 85),
        ("A13 GXF registers", 40),
        ("HVF/KVM accel backends", 0),
        ("ADT parse/build (drives device map)", 90),
        ("Mach-O fileset loader", 40),
        ("IMG4/IM4P (real dtr/IM4M DER proven)", 90),
        ("AIC v2 (irq map + iack)", 55),
        ("S3C UART console", 55),
        ("Apple WDT", 60),
        ("DART 4-level walk", 55),
        ("SART", 50),
        ("PMGR gates", 45),
        ("SPMI + PMU", 50),
        ("NVRAM store", 55),
        ("SMC key protocol", 50),
        ("GPIO/I2C/SPI", 45),
        ("ANS2/NVMe admin queues", 75),
        ("AES engine (reg map + cmd FIFO + AES core)", 90),
        ("SEP simulator control-ops", 90),
        ("SEP real-firmware core (sep.c 5673L)", 0),
        ("ADP v4 display + fb swap", 50),
        ("ADP v2 display pipe", 75),
        ("MIPI-DSI (1:1 of upstream stub)", 90),
        ("Type-C/OTG session (ATC container)", 75),
        ("APCIE (LTSSM/MSI/RID-SID/ECAM)", 75),
        ("AOP + RTKit rings", 45),
        ("MCA audio (SIO/DMA/MCLK)", 90),
        ("Scaler (irq/lock/frame/format)", 75),
        ("Buttons (HID/SMC transitions)", 75),
        ("MultiTouch SPI (HBPP+LL stack)", 75),
        ("Roswell CP-auth relay", 75),
        ("PMU D2255 (RTC/alarm/IRQ)", 75),
        ("SPMI baseband slave", 75),
        ("A7IOP core (v2+v4 regs)", 75),
        ("A7IOP mailbox (FIFO doorbells)", 75),
        ("Mic tempsensor (I2C)", 75),
        ("Baseband XMM7660 (PCIe)", 75),
        ("apple-soc: Inferno stub 1:1 rows (tempsensor/chestnut/fan53740/lm_backlight)", 60),
        ("apple-soc: full device inventory (39 rows, test-enforced)", 100),
        ("T8030 machine assembly (real-ADT attach, 59/105 modeled)", 90),
        ("Real-kernel boot stage (first function RETs clean)", 75),
        ("Kernel patcher chain (real-KC proven: 6 patches applied)", 90),
        ("IPSW: IM4P/manifest/variants", 100),
        ("Restore stage painter", 40),
        ("plist (libplist XML subset, real-Apple-proven)", 95),
        ("usbmuxhost (usbmuxd client)", 90),
        ("restored protocol client (0xF27E)", 75),
        ("ASR client (asr.c parity + SHA-1)", 75),
        ("authinstall (real ApImg4Ticket parse)", 75),
        ("APFS reader+writer subset", 60),
        ("host restore pipeline (usbmux→restored→ASR)", 75),
        ("Vault integration (research-S3)", 100),
        ("LZFSE decode (real 39 MB Apple bytes)", 90),
        ("APFS mount (real images; AES-XTS wall)", 0),
        ("AES-XTS real keys", 0),
        ("GUI window (feature gui)", 0),
        ("dsc: dyld cache reader (ipsw pkg/dyld core)", 65),
        ("dsc: slide-info rebase walkers v2-v5", 70),
        ("dsc: PrebuiltLoaders + launch closures", 0),
        ("dsc: patch-info walkers", 0),
        ("kernelcache: LZSS decode (xnu mkext port)", 75),
        ("Real Apple fixtures gate (T8030 KC + ADT + live TSS)", 100),
        ("kernelcache: version + prelink KEXT list (232 real kexts)", 90),
        ("kernelcache: KEXT extraction (chained fixups)", 0),
        ("TSS RestoreRequestRules engine + 4CC map", 75),
        ("device DB (ipsw_db format) + ipsw.me client", 80),
        ("vuln-db research KB (18 CVEs + lineage)", 100),
        ("DeviceCheck token pipeline (devicecheckd RE)", 60),
        ("XNU ARM64 ABI KB (423 syscalls + boot ABI)", 100),
        ("host-linux integration (check/deps/qemu ref)", 70),
    ];
    let total: u64 = rows.iter().map(|(_, p)| *p as u64).sum();
    let avg = total as f64 / rows.len() as f64;
    for (name, pct) in rows {
        println!("  {:3}%  {name}", pct);
    }
    let devs = apple_soc::inventory::DEVICES;
    let ported = apple_soc::inventory::ported_count();
    let dtotal = devs.len();
    let davg = apple_soc::inventory::avg_pct();
    println!(
        "workspace model parity: {avg:.1}% (honest ledger; 100% = every gate flipped)"
    );
    println!(
        "apple-soc devices: {ported}/{dtotal} ported (avg {davg:.1}%) — see apple_soc::inventory"
    );
    0
}

/// `vault` — research-S3 operations via the research-vault service.
fn cmd_vault(args: &[String]) -> i32 {
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let client = match VaultClient::from_env() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vault: {e}");
                return 2;
            }
        };
        match args.first().map(|s| s.as_str()) {
            Some("usage") | Some("list") => {
                let usage = client.usage().await.ok();
                if let Some(u) = usage {
                    println!("vault: {} objects, {} ({}% of quota)", u["objects"], u["human"], u["pctUsed"]);
                }
                let prefix = args.get(1).cloned().unwrap_or_default();
                for k in client.list(&prefix).await.unwrap_or_default() {
                    println!("{k}");
                }
                0
            }
            Some("get") => {
                let (key, out) = match (args.get(1), args.get(2)) {
                    (Some(k), Some(o)) => (k.clone(), o.clone()),
                    (Some(k), None) => (k.clone(), "download.bin".into()),
                    _ => {
                        eprintln!("vault get <key> [out]");
                        return 2;
                    }
                };
                // Without manifest sha, do an unverified raw get:
                let r = client.raw_get(&key).await;
                match r {
                    Ok(resp) if resp.status().is_success() => {
                        let bytes = resp.bytes().await.unwrap_or_default().to_vec();
                        tokio::fs::write(&out, &bytes).await.unwrap();
                        let mut h = sha2::Sha256::new();
                        h.update(&bytes);
                        println!("saved {out} ({} bytes) sha256={}", bytes.len(), hex::encode(h.finalize()));
                        0
                    }
                    Ok(resp) => {
                        eprintln!("get failed: HTTP {}", resp.status());
                        1
                    }
                    Err(e) => {
                        eprintln!("get failed: {e}");
                        1
                    }
                }
            }
            Some("put") => {
                let (file, key) = match (args.get(1), args.get(2)) {
                    (Some(f), Some(k)) => (f.clone(), k.clone()),
                    (Some(f), None) => (f.clone(), f.clone()),
                    _ => {
                        eprintln!("vault put <file> [key]");
                        return 2;
                    }
                };
                match tokio::fs::read(&file).await {
                    Ok(data) => match client.put(&key, data).await {
                        Ok(_) => {
                            println!("uploaded {key}");
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    },
                    Err(e) => {
                        eprintln!("read {file}: {e}");
                        1
                    }
                }
            }
            _ => {
                eprintln!("vault <list|get|put|usage>");
                2
            }
        }
    })
}

/// `selftest` — the invariants a release must keep (fast, no network).
fn cmd_selftest() -> i32 {
    let bitops_ok = {
        let v = 0xDEAD_BEEF_u32;
        qemu_util::bitops::extract32(v, 16, 8) == 0xAD
            && qemu_util::bitops::extract32(v, 24, 8) == 0xDE
    };
    let mut fifo = qemu_util::fifo::Fifo8::new(4);
    let fifo_ok = fifo.push_all(&[1, 2, 3]).is_ok() && fifo.pop().unwrap() == 1;
    let im4p_ok = Im4p::parse(&Im4p::build(b"rdsk", b"t", b"xyz")).is_ok();
    let bus_probe = {
        let mut d = devices::wdt::Wdt::default();
        d.write(devices::wdt::REG_WDT_CTRL, 0b100, devices::bus::W4);
        d.reset_requested
    };
    let host_ok = host_restore::smoke();
    let all = bitops_ok && fifo_ok && im4p_ok && bus_probe && host_ok;
    println!("selftest: bitops={} fifo={} im4p={} wdt={} hoststack={} → {}", bitops_ok, fifo_ok, im4p_ok, bus_probe, host_ok, if all { "PASS" } else { "FAIL" });
    if all { 0 } else { 1 }
}

/// `dsc` — dyld shared cache reader (port of blacktop/ipsw pkg/dyld core).
///
///   dsc info <cache>            header + mappings + members summary
///   dsc images <cache> [filter] image list (install paths)
///   dsc rebase <cache> [limit]  slide-info walk (v2/v3/v4/v5 rebase list)
///   dsc symbols <cache> [limit] local symbols (.symbols file aware)
///   dsc a2o <cache> <vmaddr>    VM address → file offset
///   dsc o2a <cache> <offset>    file offset (member 0) → VM address
fn cmd_dsc(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("dsc <info|images|rebase|symbols|a2o|o2a> <cache> [args]");
        return 2;
    };
    let Some(path) = args.get(1) else {
        eprintln!("dsc {cmd}: missing <cache> path");
        return 2;
    };
    let cache = match dsc::Dsc::open(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dsc: {e}");
            return 1;
        }
    };
    match cmd.as_str() {
        "info" => {
            for (k, v) in cache.summary() {
                println!("{k:>16}: {v}");
            }
            println!("       mappings:");
            for (mi, m) in cache.mappings() {
                println!(
                    "  [{mi}] {:16} {:#x}..{:#x} file {:#x} {} slide={}",
                    m.name,
                    m.address,
                    m.address + m.size,
                    m.file_offset,
                    m.max_prot.as_str(),
                    m.has_slide_info
                );
            }
            if !cache.subcaches.is_empty() {
                println!("       subcaches:");
                for (i, sc) in cache.subcaches.iter().enumerate() {
                    println!(
                        "  [{}] {} vm_offset {:#x} suffix \"{}\"",
                        i, dsc::file::uuid_str(&sc.uuid), sc.cache_vm_offset, sc.suffix
                    );
                }
            }
            0
        }
        "images" => {
            let filter = args.get(2).map(|s| s.to_lowercase());
            let mut n = 0usize;
            for im in cache.images() {
                if let Some(f) = &filter {
                    if !im.path.to_lowercase().contains(f) {
                        continue;
                    }
                }
                println!("[{:4}] {:#018x}  {}", im.index, im.address, im.path);
                n += 1;
            }
            println!("{} images", n);
            0
        }
        "rebase" => {
            match cache.rebases() {
                Ok((rebases, skipped)) => {
                    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(32);
                    println!(
                        "slide-info walk: {} rebases (skipped pages/chains: {})",
                        rebases.len(),
                        skipped
                    );
                    for r in rebases.iter().take(limit) {
                        println!(
                            "  file {:#011x} vm {:#014x} → {:#014x} (raw {:#018x})",
                            r.cache_file_offset, r.cache_vm_address, r.target, r.raw
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("dsc rebase: {e}");
                    1
                }
            }
        }
        "symbols" => {
            match cache.local_symbols() {
                Ok(Some(syms)) => {
                    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
                    println!("local symbols: {}", syms.len());
                    for s in syms.iter().take(limit) {
                        println!(
                            "  dylib {:#x}  {:#014x}  {}",
                            s.dylib_offset, s.n_value, s.name
                        );
                    }
                    0
                }
                Ok(None) => {
                    println!("dsc: no local symbols in this cache");
                    0
                }
                Err(e) => {
                    eprintln!("dsc symbols: {e}");
                    1
                }
            }
        }
        "a2o" => {
            let Some(addr) = args.get(2).and_then(|s| parse_num(s)) else {
                eprintln!("dsc a2o <cache> <vmaddr>");
                return 2;
            };
            match cache.get_offset(addr) {
                Some((mi, off)) => {
                    println!("member {mi} ({}) file offset {:#x}", cache.members[mi].path, off);
                    0
                }
                None => {
                    eprintln!("dsc: {addr:#x} not in any mapping");
                    1
                }
            }
        }
        "o2a" => {
            let Some(off) = args.get(2).and_then(|s| parse_num(s)) else {
                eprintln!("dsc o2a <cache> <file-offset>");
                return 2;
            };
            match cache.get_vmaddr(0, off) {
                Some(a) => {
                    println!("{a:#x}");
                    0
                }
                None => {
                    eprintln!("dsc: offset {off:#x} not in member 0 mappings");
                    1
                }
            }
        }
        _ => {
            eprintln!("dsc <info|images|rebase|symbols|a2o|o2a> <cache> [args]");
            2
        }
    }
}

/// `adt` — flat DeviceTree diagnostics for the M5 device census.
///
///   adt windows <im4p>        list every node's reg windows (leaf path + compat)
///   adt find <im4p> <addr>    which node owns the physical address (M5 UNMAPPED naming)
///
/// IM4P → (LZFSE) → flat ADT, same extraction path as boot_real.
fn cmd_adt(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("adt <windows|find> <devicetree-im4p> [addr]");
        return 2;
    };
    let Some(path) = args.get(1) else {
        eprintln!("adt {cmd}: missing <devicetree-im4p>");
        return 2;
    };
    let raw = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("adt: cannot read {path}: {e}");
            return 1;
        }
    };
    let im4p = match img4::im4p::Im4p::parse(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("adt: IM4P parse: {e}");
            return 1;
        }
    };
    let blob = if restore::lzfse::is_lzfse(&im4p.data) {
        match restore::lzfse::decompress(&im4p.data, None) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("adt: LZFSE: {e}");
                return 1;
            }
        }
    } else {
        im4p.data.clone()
    };
    let root = match adt::AdtNode::parse(&blob) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("adt: flat parse: {e}");
            return 1;
        }
    };

    fn walk(node: &adt::AdtNode, prefix: &str, f: &mut dyn FnMut(&str, &adt::AdtNode)) {
        let path = format!("{prefix}/{}", node.name);
        for c in &node.children {
            walk(c, &path, f);
        }
        f(&path, node);
    }

    match cmd.as_str() {
        "dump" => {
            // M5-P diagnostic: full recursive node/property dump (names +
            // sizes, printable values) — the tool that found /chosen/
            // lock-regs missing its aperture-count property.
            fn dump(node: &adt::AdtNode, depth: usize) {
                let ind = "  ".repeat(depth);
                println!("{ind}{} ({})", node.name, node.props.len());
                for p in &node.props {
                    let printable = p
                        .data
                        .iter()
                        .all(|b| (0x20..0x7f).contains(b) || *b == 0);
                    if printable && !p.data.is_empty() {
                        let s: String = p
                            .data
                            .iter()
                            .filter(|b| **b != 0)
                            .map(|b| *b as char)
                            .collect();
                        println!("{ind}  {} = {:?} ({} bytes)", p.name, s, p.data.len());
                    } else {
                        println!("{ind}  {} ({} bytes)", p.name, p.data.len());
                    }
                }
                for c in &node.children {
                    dump(c, depth + 1);
                }
            }
            dump(&root, 0);
            0
        }
        "windows" => {
            let mut rows: Vec<(String, Vec<(u64, u64)>, Vec<String>)> = Vec::new();
            walk(&root, "", &mut |path, n| {
                let reg = n.reg_entries();
                if !reg.is_empty() {
                    rows.push((path.to_string(), reg, n.compatible()));
                }
            });
            rows.sort_by_key(|(_, reg, _)| reg.first().copied().unwrap_or((u64::MAX, 0)));
            for (path, reg, compat) in &rows {
                let wins: Vec<String> =
                    reg.iter().map(|(a, s)| format!("{a:#x}+{s:#x}")).collect();
                println!(
                    "{:<44} {}  compat={}",
                    path,
                    wins.join(" "),
                    compat.first().cloned().unwrap_or_else(|| "-".into())
                );
            }
            println!("{} reg-bearing nodes", rows.len());
            0
        }
        "find" => {
            let Some(addr_s) = args.get(2) else {
                eprintln!("adt find: missing <addr>");
                return 2;
            };
            let addr = parse_num(addr_s).unwrap_or_else(|| {
                eprintln!("adt find: bad addr {addr_s}");
                0
            });
            let mut hits = 0;
            walk(&root, "", &mut |path, n| {
                for (base, size) in n.reg_entries() {
                    if addr >= base && addr < base + size.max(1) {
                        let compat = n.compatible();
                        println!(
                            "{path}  window {base:#x}+{size:#x}  (off {:#x})  compat={}",
                            addr - base,
                            compat.join(";")
                        );
                        hits += 1;
                    }
                }
            });
            if hits == 0 {
                println!("no ADT node window contains {addr:#x}");
                1
            } else {
                0
            }
        }
        _ => {
            eprintln!("adt <windows|find> <devicetree-im4p> [addr]");
            2
        }
    }
}

/// `kc` — kernelcache analysis (LZSS/LZFSE decode, version, KEXTs).
///
///   kc info <file>        decompress + full summary (compression/version/kexts)
///   kc version <file>     Darwin kernel version strings only
///   kc kexts <file>       __PRELINK_INFO.__info inventory
fn cmd_kernelcache(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("kc <info|version|kexts|dump> <kernelcache-file>");
        return 2;
    };
    let Some(path) = args.get(1) else {
        eprintln!("kc {cmd}: missing <file>");
        return 2;
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("kc: cannot read {path}: {e}");
            return 1;
        }
    };
    let info = match kernelcache::analyze(&data) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("kc: {e}");
            return 1;
        }
    };
    let comp = match info.compression {
        Some(kernelcache::Compression::Lzfse) => "LZFSE",
        Some(kernelcache::Compression::Lzss) => "LZSS (complzss)",
        Some(kernelcache::Compression::None) => "uncompressed",
        None => "?",
    };
    match cmd.as_str() {
        "info" => {
            println!("decompressed: {} bytes ({})", info.size, comp);
            println!("fileset kernel collection: {}", info.is_fileset);
            if let Some(v) = &info.version {
                println!("version: Darwin {} @ {}", v.darwin, v.date);
                println!("         xnu-{} ({} {} {})", v.xnu, v.build_type, v.arch, v.cpu);
                if let Some(cv) = &v.clang_version {
                    println!("         toolchain: {cv}");
                }
            } else {
                println!("version: (not found)");
            }
            println!("kexts: {}", info.kexts.len());
            for k in info.kexts.iter().take(24) {
                println!(
                    "  {:48} {:16} {}",
                    k.bundle_id,
                    k.version,
                    k.bundle_path
                );
            }
            0
        }
        "version" => match &info.version {
            Some(v) => {
                println!("Darwin Kernel Version {}: {}; root:xnu-{}/{}_{}_{}",
                    v.darwin, v.date, v.xnu, v.build_type, v.arch, v.cpu);
                if let Some(cv) = &v.clang_version {
                    println!("Apple LLVM {cv}");
                }
                0
            }
            None => {
                eprintln!("kc: no version string found");
                1
            }
        },
        "kexts" => {
            for k in &info.kexts {
                println!("{} ({})", k.bundle_id, k.name);
                if !k.bundle_path.is_empty() {
                    println!("  path: {}", k.bundle_path);
                }
                if let Some(addr) = k.load_addr {
                    println!("  load_addr: {:#x}", addr);
                }
                if !k.os_bundle_libraries.is_empty() {
                    println!("  libs: {}", k.os_bundle_libraries.iter().map(|(a, b)| format!("{a}={b}")).collect::<Vec<_>>().join(" "));
                }
            }
            0
        }
        "dump" => {
            // kc dump <file> [out] — write the DECOMPRESSED Mach-O image so
            // Python RE probes (capstone et al.) see the real bytes.
            let img = match kernelcache::decompress(&data) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("kc dump: {e}");
                    return 1;
                }
            };
            let out = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| format!("{}.decompressed", path));
            if let Err(e) = std::fs::write(&out, &img) {
                eprintln!("kc dump: write {out}: {e}");
                return 1;
            }
            println!("{}: {} bytes → {}", path, img.len(), out);
            0
        }
        _ => {
            eprintln!("kc <info|version|kexts|dump> <file>");
            2
        }
    }
}

/// `devices` — the embedded device database + ipsw.me catalog.
///
///   devices list                 every product type in the DB
///   devices t8030                the A13/T8030 family (the workspace target)
///   devices lookup <type>        e.g. devices lookup iPhone12,1
///   devices board <board>        e.g. devices board N104AP
///   devices cpuid <cpid>         e.g. devices cpuid 0x8030
///   devices ipsw-me <identifier> live ipsw.me firmware list (network)
fn cmd_devices(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("devices <list|t8030|lookup|board|cpuid|ipsw-me> [args]");
        return 2;
    };
    match cmd.as_str() {
        "list" => {
            let db = devices_db::db::db();
            let mut ids: Vec<_> = db.keys().collect();
            ids.sort();
            for id in ids {
                let d = &db[id];
                println!("{:16} {:28} {} board(s)", id, d.name, d.boards.len());
            }
            0
        }
        "t8030" => {
            for (ptype, dev, board) in devices_db::db::t8030_devices() {
                println!(
                    "{:12} {:24} {} {} cpuid {} bdid {} arch {}",
                    ptype, dev.name, board.cpu, board.platform, board.cpuid, board.board_id, board.arch
                );
            }
            0
        }
        "lookup" => {
            let Some(ptype) = args.get(1) else {
                eprintln!("devices lookup <ProductType>");
                return 2;
            };
            match devices_db::db::lookup(ptype) {
                Some(d) => {
                    println!("{} — {}", ptype, d.name);
                    for (b, bd) in &d.boards {
                        println!(
                            "  {:8} {} cpuid {} bdid {} platform {} ({}) arch {}",
                            b, bd.cpu, bd.cpuid, bd.board_id, bd.platform, bd.platform_name, bd.arch
                        );
                    }
                    0
                }
                None => {
                    eprintln!("devices: unknown product type {ptype}");
                    1
                }
            }
        }
        "board" => {
            let Some(board) = args.get(1) else {
                eprintln!("devices board <BoardConfig>");
                return 2;
            };
            match devices_db::db::by_board(board) {
                Some((ptype, d, bd)) => {
                    println!("{} = {} ({} {} {} cpuid {})", board, ptype, d.name, bd.cpu, bd.platform, bd.cpuid);
                    0
                }
                None => {
                    eprintln!("devices: unknown board {board}");
                    1
                }
            }
        }
        "cpuid" => {
            let Some(cpuid) = args.get(1) else {
                eprintln!("devices cpuid <CPID>");
                return 2;
            };
            let rows = devices_db::db::by_cpuid(cpuid);
            if rows.is_empty() {
                eprintln!("devices: no boards with cpuid {cpuid}");
                return 1;
            }
            for (ptype, board, bd) in rows {
                println!("{:14} {:10} {} {}", ptype, board, bd.cpu, bd.platform);
            }
            0
        }
        "ipsw-me" => {
            let Some(identifier) = args.get(1) else {
                eprintln!("devices ipsw-me <identifier> (network)");
                return 2;
            };
            let rt = tokio::runtime::Runtime::new().expect("tokio");
            let res = rt.block_on(devices_db::ipsw_me::IpswMeClient::new().device(identifier));
            match res {
                Ok(dev) => {
                    println!("{} ({}) — {} firmwares", dev.identifier, dev.name, dev.firmwares.len());
                    for f in dev.firmwares.iter().rev().take(12) {
                        println!(
                            "  {:8} {:10} signed={} {}",
                            f.version, f.build_id, f.signed, f.url
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("devices: ipsw.me fetch failed: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("devices <list|t8030|lookup|board|cpuid|ipsw-me> [args]");
            2
        }
    }
}

/// `vulns` — the iOS vulnerability research knowledge base.
///
///   vulns list [kind]        all entries (optionally Kernel/IOKit/Daemon/Learning)
///   vulns show <cve|slug>    one entry in full
///   vulns search <term>      substring search
///   vulns mitigations        XNU zone-allocator hardening timeline
///   vulns frida              FRIDA/r2frida technique catalog
///   vulns tools              pentest tooling index
///   vulns json               full KB as JSON
fn cmd_vulns(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("vulns <list|show|search|mitigations|frida|tools|json> [args]");
        return 2;
    };
    match cmd.as_str() {
        "list" => {
            let kind = args.get(1).map(|s| s.to_lowercase());
            let entries = match kind.as_deref() {
                Some("kernel") => vuln_db::by_kind(vuln_db::ComponentKind::Kernel),
                Some("iokit") => vuln_db::by_kind(vuln_db::ComponentKind::IOKit),
                Some("daemon") => vuln_db::by_kind(vuln_db::ComponentKind::Daemon),
                Some("learning") => vuln_db::by_kind(vuln_db::ComponentKind::Learning),
                _ => vuln_db::all().iter().collect(),
            };
            for e in entries {
                println!(
                    "{:28} {:8} {:44} {}",
                    e.id,
                    e.year,
                    truncate(&e.title, 44),
                    e.component
                );
            }
            0
        }
        "show" => {
            let Some(id) = args.get(1) else {
                eprintln!("vulns show <id>");
                return 2;
            };
            match vuln_db::by_cve(id) {
                Some(e) => {
                    println!("{} — {}", e.id, e.title);
                    println!("component: {} ({:?})", e.component, e.kind);
                    println!("class:     {}", e.bug_class);
                    println!("affected:  {}", e.affected);
                    println!("primitive: {}", e.primitive);
                    println!("summary:   {}", e.summary);
                    if !e.techniques.is_empty() {
                        println!("techniques:");
                        for t in e.techniques {
                            println!("  - {t}");
                        }
                    }
                    println!("sources:");
                    for s in e.sources {
                        println!("  - {s}");
                    }
                    0
                }
                None => {
                    eprintln!("vulns: no entry {id}");
                    1
                }
            }
        }
        "search" => {
            let Some(term) = args.get(1) else {
                eprintln!("vulns search <term>");
                return 2;
            };
            for e in vuln_db::search(term) {
                println!("{:28} {}", e.id, truncate(&e.title, 60));
            }
            0
        }
        "mitigations" => {
            for m in vuln_db::mitigations() {
                println!("{}: {}", m.era, m.hardening);
                println!("  defeated by: {}", m.defeated_by);
            }
            0
        }
        "frida" => {
            for f in vuln_db::frida_notes() {
                println!("{:32} {}", f.topic, f.detail);
            }
            0
        }
        "tools" => {
            for t in vuln_db::tools() {
                println!("{:28} {}", t.name, t.what);
                println!("{:28} {}", "", t.url);
            }
            0
        }
        "json" => {
            println!("{}", vuln_db::export_json());
            0
        }
        _ => {
            eprintln!("vulns <list|show|search|mitigations|frida|tools|json> [args]");
            2
        }
    }
}

/// `dc` — DeviceCheck token internals (port of the devicecheckd RE).
///
///   dc demo            generate a token end-to-end (ECDH+HKDF+AES-GCM)
///   dc constants       endpoints / keys / error domains
///   dc entitlements    the embedded devicecheckd entitlements plist
fn cmd_devicecheck(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("dc <demo|constants|entitlements>");
        return 2;
    };
    match cmd.as_str() {
        "demo" => match devicecheck::demo_token() {
            Ok(tok) => {
                println!("token: {} bytes", tok.len());
                let view = devicecheck::token::parse_token(&tok);
                match view {
                    Ok(v) => {
                        println!("  version/type byte: {:#x}", v.version_byte);
                        println!("  tag: {}", hex::encode(v.tag));
                        println!("  ephemeral pk: {}…", hex::encode(&v.ephemeral_pk[..8]));
                        println!("  payload len: {}", v.payload_len);
                    }
                    Err(e) => {
                        eprintln!("dc: roundtrip parse failed: {e}");
                        return 1;
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("dc demo failed: {e}");
                1
            }
        },
        "constants" => {
            println!("mach service:      {}", devicecheck::constants::XPC_MACH_SERVICE);
            println!("MESU catalog:      {}", devicecheck::constants::MESU_CATALOG_URL);
            println!("humbug BAA:        {}", devicecheck::constants::HUMBUG_BAA_URL);
            println!("humbug UA:         {}", devicecheck::constants::HUMBUG_USER_AGENT);
            println!("keychain service:  {}", devicecheck::constants::KEYCHAIN_SERVICE);
            println!("fallback pubkey:   {}…", &devicecheck::constants::FALLBACK_SERVER_PUBKEY_HEX[..32]);
            println!("error domain:      {}", devicecheck::constants::FETCH_ERROR_DOMAIN);
            0
        }
        "entitlements" => {
            println!("{}", devicecheck::entitlements::DEVICECHECKD_ENTITLEMENTS_XML);
            0
        }
        _ => {
            eprintln!("dc <demo|constants|entitlements>");
            2
        }
    }
}

/// `xnu` — the XNU ARM64 ABI knowledge base.
///
///   xnu syscalls [n]      BSD table (names + numbers)
///   xnu traps [n]         Mach trap table (negative x16 values)
///   xnu errno             Darwin errno values
///   xnu boot              boot_args layout + known boot args
///   xnu boot-order        the early-boot call order (arm_init → lockdown)
///   xnu abi               SVC ABI constants
fn cmd_xnu(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("xnu <syscalls|traps|errno|boot|boot-order|abi> [n]");
        return 2;
    };
    let limit: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
    match cmd.as_str() {
        "syscalls" => {
            println!("BSD syscall table ({} entries; svc #0, x16 = number):", xnu::syscalls::BSD_SYSCALLS.len());
            for (n, name) in xnu::syscalls::BSD_SYSCALLS.iter().take(limit) {
                println!("  {n:>4}  {name}");
            }
            0
        }
        "traps" => {
            println!("Mach trap table ({} entries; x16 = NEGATIVE value):", xnu::mach_traps::MACH_TRAPS.len());
            for (n, name) in xnu::mach_traps::MACH_TRAPS.iter().take(limit) {
                println!("  {n:>4}  {name}");
            }
            0
        }
        "errno" => {
            for (n, name) in xnu::errno::ERRNOS.iter().take(limit) {
                println!("  {n:>4}  {name}");
            }
            0
        }
        "boot" => {
            println!("boot_args: {} bytes (kBootArgsVersion2/Rev2 = 2)", xnu::boot::BOOT_ARGS_SIZE);
            println!("known boot args: {}", xnu::boot::BOOT_ARGS_KNOWN.join(" "));
            println!("restore lane defaults: rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort");
            0
        }
        "boot-order" => {
            println!("ARM64 early boot call order (xnu-7195.141.2):");
            for (i, call) in xnu::boot::ARM64_BOOT_CALL_ORDER.iter().enumerate() {
                println!("  {:3}. {}", i + 1, call);
            }
            0
        }
        "abi" => {
            println!("svc #0 = {:#x}", xnu::abi::D_ARM64_INSN_SVC_0);
            println!("syscall register = x{}", xnu::abi::D_ARM64_SYSCALL_REGISTER);
            println!("platform syscall = {:#x}", xnu::abi::PLATFORM_SYSCALL_TRAP_NO);
            println!("VM_FLAGS_ANYWHERE = {:#x}", xnu::abi::VM_FLAGS_ANYWHERE);
            0
        }
        _ => {
            eprintln!("xnu <syscalls|traps|errno|boot|boot-order|abi> [n]");
            2
        }
    }
}

/// `host` — Linux host integration (deps/capabilities/QEMU reference).
///
///   host check        capability report (KVM, RAM, APFS module, tools)
///   host deps         dependency manifest + install recipes
///   host qemu         the reference darwin-vm QEMU command
fn cmd_host(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("host <check|deps|qemu>");
        return 2;
    };
    match cmd.as_str() {
        "check" => {
            let c = host_linux::check::check();
            print!("{}", c.report());
            if c.kvm { 0 } else { 1 }
        }
        "deps" => {
            println!("apt packages ({}):", host_linux::deps::APT_PACKAGES.len());
            println!("{}", host_linux::deps::apt_install_cmd(&[]));
            println!("\nblacktop/ipsw install:\n{}", host_linux::deps::IPSW_INSTALL_RECIPE);
            println!("\nldid (ad-hoc signing):\n{}", host_linux::deps::LDID_INSTALL_RECIPE);
            println!("\nAPFS kernel module:\n{}", host_linux::deps::APFS_MODULE_RECIPE);
            println!("\nqemu-sptm build:\n{}", host_linux::deps::QEMU_BUILD_RECIPE);
            0
        }
        "qemu" => {
            print!("{}", host_linux::qemu::print_reference());
            0
        }
        _ => {
            eprintln!("host <check|deps|qemu>");
            2
        }
    }
}

fn parse_num(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok()
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n).collect();
        format!("{cut}…")
    }
}
