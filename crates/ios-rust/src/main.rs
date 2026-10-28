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

use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use devices::bus::MMIODevice;
use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, InterpBudget, MemAccess, StopReason};
use apple_soc::t8030::{T8030Machine, DEFAULT_DRAM_MB};
use vm_core::Bus;
use ipsw::im4p::Im4p;
use ipsw::ramdisk_variants::{BISECTION_VERDICT_74, RamdiskVariant};
use sha2::Digest as _;
use soc_t8030;
use vault::VaultClient;
use virt::{machine_boot, Machine, MachineConfig, QemuCli, QEMU_COMPAT_VERSION};

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
        _ => {
            eprintln!(
                "ios-rust {} — single-binary T8030 emulator + restore pipeline\n\n\
                 commands:\n  run      qemu-system-aarch64 compatible subset (-M apple-t8030 …)\n  restore  parse + ramdisk-variant IPSW pipeline\n  boot     restore → install → homescreen ladder (honest status)\n  parity   100%-parity ledger status\n  vault    research-S3 (list/get/put/usage)\n  selftest invariants",
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
fn cmd_restore(args: &[String]) -> i32 {
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
    let mut machine = T8030Machine::new(DEFAULT_DRAM_MB);
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

/// `parity` — the ledger status (mirror of PARITY.md headline).
fn cmd_parity() -> i32 {
    println!("parity ledger — workspace target: 100% (see PARITY.md for per-item gates)");
    let rows: &[(&str, u8)] = &[
        ("libqemuutil port (19 modules)", 100),
        ("SoC definition (T8030/CPU/ISA)", 100),
        ("bus + MMIO dispatch (2 impls)", 100),
        ("A13 decoder (verified subset)", 75),
        ("A13 interpreter (exec loop)", 60),
        ("A13 GXF registers", 40),
        ("HVF/KVM accel backends", 0),
        ("ADT parse/build (drives device map)", 90),
        ("Mach-O fileset loader", 40),
        ("IMG4/IM4P", 75),
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
        ("ANS2/NVMe admin queues", 40),
        ("AES-XTS engine (key wall)", 35),
        ("SEP simulator control-ops", 45),
        ("ADP v4 display + fb swap", 50),
        ("MIPI-DSI (faithful stub)", 15),
        ("Type-C/OTG session", 35),
        ("APCIE ECAM", 30),
        ("AOP + RTKit rings", 45),
        ("MCA audio (map only)", 20),
        ("Scaler (map only)", 20),
        ("IPSW: IM4P/manifest/variants", 100),
        ("Restore stage painter", 40),
        ("plist (libplist XML subset)", 90),
        ("usbmuxhost (usbmuxd client)", 90),
        ("restored protocol client (0xF27E)", 75),
        ("ASR client (asr.c parity + SHA-1)", 75),
        ("authinstall (TSS/IM4M subset)", 60),
        ("APFS reader+writer subset", 60),
        ("host restore pipeline (usbmux→restored→ASR)", 75),
        ("Vault integration (research-S3)", 100),
        ("LZFSE decode (vendored C)", 75),
        ("APFS mount (real images; AES-XTS wall)", 0),
        ("AES-XTS real keys", 0),
        ("GUI window (feature gui)", 0),
    ];
    let total: u64 = rows.iter().map(|(_, p)| *p as u64).sum();
    let avg = total as f64 / rows.len() as f64;
    for (name, pct) in rows {
        println!("  {:3}%  {name}", pct);
    }
    println!("workspace model parity: {avg:.1}% (honest ledger; 100% = every gate flipped)");
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
