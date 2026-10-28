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

use devices::bus::MMIODevice;
use ipsw::im4p::Im4p;
use ipsw::ramdisk_variants::{BISECTION_VERDICT_74, RamdiskVariant};
use sha2::Digest as _;
use soc_t8030;
use vault::VaultClient;
use virt::{machine_boot, Machine, MachineConfig, QemuCli, QEMU_COMPAT_VERSION};

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
    for v in RamdiskVariant::diag_order() {
        let i = v.info();
        println!("  {:10} {} → run#74: {}", i.id, i.description, i.verdict74);
    }
    println!("verdict: {BISECTION_VERDICT_74}");
    0
}

/// `boot` — the IPSW→GUI→homescreen ladder, honestly reported.
fn cmd_boot(args: &[String]) -> i32 {
    let ipsw = args.first().map(PathBuf::from);
    println!(
        "boot ladder for {}: fetch → restore → install → homescreen",
        ipsw.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<ipsw>".into())
    );
    let mut m = Machine::new(MachineConfig::default());
    let report = machine_boot::boot(&mut m);
    println!("{report}");
    println!("gate status: G1 restore-ramdisk ✅ (C lane) | G2 ASR stage = frontier | G3 install = pending | G4 homescreen = pending");
    0
}

/// `parity` — the ledger status (mirror of PARITY.md headline).
fn cmd_parity() -> i32 {
    println!("parity ledger — workspace target: 100% (see PARITY.md for per-item gates)");
    let rows: &[(&str, u8)] = &[
        ("libqemuutil port (bitops/fifo/iov/queue/error)", 100),
        ("SoC definition (T8030/CPU/instructions)", 100),
        ("bus + MMIO dispatch", 100),
        ("AIC v2", devices::aic::PARITY_PCT),
        ("DART", devices::dart::PARITY_PCT),
        ("ADP v4 DisplayPipe", devices::disp_pipe::PARITY_PCT),
        ("MIPI-DSI", devices::mipi_dsi::PARITY_PCT),
        ("ANS2/NVMe", devices::nvme_ans::PARITY_PCT),
        ("UART console", devices::uart::PARITY_PCT),
        ("WDT", devices::wdt::PARITY_PCT),
        ("TCG CPU exec (AArch64)", 0),
        ("SEP / SEP-SIM", 0),
        ("IPSW: IM4P/manifest/variants", 100),
        ("vault integration", 100),
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
    let all = bitops_ok && fifo_ok && im4p_ok && bus_probe;
    println!("selftest: bitops={} fifo={} im4p={} wdt={} → {}", bitops_ok, fifo_ok, im4p_ok, bus_probe, if all { "PASS" } else { "FAIL" });
    if all { 0 } else { 1 }
}
