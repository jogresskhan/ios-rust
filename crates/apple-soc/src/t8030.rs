//! t8030 — the T8030 (A13 Bionic) machine.
//!
//! Ports Inferno `hw/arm/apple-silicon/t8030.c` machine assembly to Rust:
//! fixed memory regions from the C defines (SROM/SRAM/DRAM/SEPROM/AMCC)
//! plus **ADT-driven peripheral discovery**: `attach_from_adt` walks the
//! IPSW devicetree `/arm-io` children and attaches each Rust device model
//! at its real MMIO base — the "one IPSW" boot contract. A fallback map
//! covers headless smoke tests.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use vm_core::{Bus, Device, Ram};

use crate::{
    aic::{Aic, AicTimebase},
    aes::AesEngine,
    ans2_nvme::Ans2Nvme,
    aop::Aop,
    apcie::Apcie,
    dart::Dart,
    dapf::Dapf,
    displaypipe::AdpV4,
    dockchannel,
    gpio_i2c_spi::{Gpio, I2c, Spi},
    mca::Mca,
    mipi_dsi::MipiDsi,
    nvram::Nvram,
    pmgr,
    rtkit::RtkitDevice,
    s3c_uart::S3cUart,
    sart::Sart,
    scaler::Scaler,
    sep_sim::SepSim,
    smc::Smc,
    spmi_pmu::SpmiPmu,
    typec_otg::TypecOtg,
    wdt::AppleWdt,
};

pub const TARGET_SOC: &str = "T8030";
pub const TARGET_DEVICE: &str = "D79AP"; // iPhone 11

// From t8030.c defines:
pub const SROM_BASE: u64 = 0x100000000; // line 120
pub const SRAM_BASE: u64 = 0x19C000000; // line 123
pub const DRAM_BASE: u64 = 0x800000000; // line 126
pub const SEPROM_BASE: u64 = 0x240000000; // line 128
pub const AMCC_BASE: u64 = 0x200000000; // line 147

/// Default guest visible DRAM (iPhone 11: 4 GB).
pub const DEFAULT_DRAM_MB: u64 = 4096;

/// Guest-visible DRAM size, overridable for small sandboxes via
/// IOS_RUST_DRAM_MB (256..=4096 MiB). The bootargs memSize field follows
/// this value so the guest's physical allocator stays inside the window.
pub fn effective_dram_mb() -> u64 {
    std::env::var("IOS_RUST_DRAM_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&m| (256..=4096).contains(&m))
        .unwrap_or(DEFAULT_DRAM_MB)
}

/// Headless test map — REAL n104ap (18C66) bases from the ADT census
/// (tools/re/notes/m5-adt-census.md; the old values were pre-census guesses,
/// several wrong: wdt/ans/sart/pmgr/gpio were D79AP-era or invented).
/// `attach_from_adt` overrides at runtime with the IPSW's real map.
pub const FALLBACK_MAP: &[(&str, u64, u64)] = &[
    // (name, base, size) — measured on DeviceTree.n104ap (iOS 14.2)
    ("aic", 0x23B100000, 0x8000),
    ("aic-timebase", 0x23B108000, 0x1000),
    ("uart0", 0x235200000, 0x4000),
    ("wdt", 0x23D2B0000, 0x4000),
    ("ans2-nvme", 0x277400000, 0xC000),
    ("adp-v4", 0x230000000, 0x2FC000),
    ("mipi-dsi", 0x230400000, 0xC0000),
    ("sart", 0x27AC50000, 0x8000),
    ("pmgr", 0x23B000000, 0x100000),
    ("gpio", 0x23C100000, 0x100000),
    ("smc", 0x23E400000, 0x20000),
];

pub struct T8030Machine {
    pub bus: Bus,
    pub fb: vm_core::framebuffer::FrameSink,
    pub serial: Arc<Mutex<Vec<u8>>>,
    /// Dedicated dockchannel sink (attach-spec §5.1: NEVER the console sink).
    pub dockchannel_sink: Arc<Mutex<Vec<u8>>>,
    pub adt: Option<adt::AdtNode>,
    pub devices_attached: Vec<(&'static str, u64, u64)>,
    pub unimplemented_devices: Vec<(String, u64, u64, Vec<String>)>,
    pub display: AdpV4,
    pub dram_mb: u64,
    /// M4: the AIC→CPU shared IRQ line (the Interpreter polls this).
    pub irq_line: Arc<AtomicBool>,
}

impl T8030Machine {
    pub fn new(dram_mb: u64) -> Self {
        let mut bus = Bus::new();
        let serial: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let dockchannel_sink: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let fb = vm_core::framebuffer::new_sink(2436, 1125); // D79AP panel
        // Fixed regions (t8030.c define order)
        bus.attach(SROM_BASE, 0x20_0000, Box::new(Ram::new("srom", 0x20_0000)));
        bus.attach(SRAM_BASE, 0x80_0000, Box::new(Ram::new("sram", 0x80_0000)));
        bus.attach(SEPROM_BASE, 0x200_0000, Box::new(Ram::new("seprom", 0x200_0000)));
        bus.attach(
            DRAM_BASE,
            dram_mb * 1024 * 1024,
            Box::new(Ram::new("dram", dram_mb * 1024 * 1024)),
        );
        let display = AdpV4::new(2436, 1125, fb.clone());
        T8030Machine {
            bus,
            fb,
            serial,
            dockchannel_sink,
            adt: None,
            devices_attached: Vec::new(),
            unimplemented_devices: Vec::new(),
            display,
            dram_mb,
            irq_line: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Attach the fallback (synthesized) peripheral map for headless runs.
    pub fn attach_fallback(&mut self) {
        for (name, base, size) in FALLBACK_MAP {
            // pmgr = the 44-window shared-core device (attach-spec §4) —
            // handled after the loop, not as a single-window box.
            if *name == "pmgr" {
                continue;
            }
            let dev: Box<dyn Device> = match *name {
                "aic" => {
                    let mut a = Aic::new();
                    a.set_irq_line(self.irq_line.clone());
                    Box::new(a)
                }
                "aic-timebase" => Box::new(AicTimebase { counter: 0 }),
                "uart0" => Box::new(S3cUart::new(0, self.serial.clone())),
                "wdt" => Box::new(AppleWdt::new()),
                "ans2-nvme" => Box::new(Ans2Nvme::new()),
                "adp-v4" => Box::new(self.display.clone_device()),
                "mipi-dsi" => Box::new(MipiDsi::new()),
                "sart" => Box::new(Sart::new()),
                "gpio" => Box::new(Gpio::new()),
                other => {
                    self.unimplemented_devices
                        .push((other.to_string(), *base, *size, Vec::new()));
                    continue;
                }
            };
            self.bus.attach(*base, *size, dev);
            self.devices_attached.push((name_static(name), *base, *size));
        }
        // Fallback pmgr: the spec's 44-window table, no clock-gates seeds.
        let (core, _windows) = pmgr::new_44_window(&[]);
        let mut lin = 0u64;
        for &(wb, ws) in pmgr::PMGR_WINDOWS {
            let mut w = pmgr::PmgrWindow { core: core.clone(), lin };
            let dn = w.name();
            self.bus.attach(wb, ws, Box::new(w));
            self.devices_attached.push((dn, wb, ws));
            lin += ws;
        }
    }

    /// ADT-driven discovery: walk `/arm-io` children, match compatible
    /// strings, attach at real bases. Returns the count attached.
    pub fn attach_from_adt(&mut self, adt: &adt::AdtNode) -> usize {
        let mut count = 0usize;
        let Some(armio) = adt.find("arm-io") else {
            return 0;
        };
        // M5-M fix (first live MMIO census, 2026-10-30): the kernel emits
        // its FIRST device accesses at the TRANSLATED arm-io bases
        // (console UART0 write @0x235200000 — real SoC base) while this
        // attach used the RAW ADT reg (0x35200000). The arm-io `ranges`
        // property maps child windows into the SoC address space; for
        // n104ap every <0x1_00000000 child lives at parent +0x2_00000000
        // (session-H #21 pinned from the real ranges bytes). Translate
        // through the real property, fall back to the pinned rule.
        let translate = |base: u64| -> u64 { translate_armio_child(armio, base) };
        let children = armio.children.clone();
        for child in &children {
            let compat = child.compatible();
            let reg = child.reg_entries();
            let Some((base, size)) = reg.first().copied() else {
                continue;
            };
            let base = translate(base);
            let name = compat
                .first()
                .cloned()
                .unwrap_or_else(|| child.name.clone());
            let kind = classify(&name, &compat, &child.name);
            match kind {
                Some(k) => {
                    // M5 multi-window kinds (attach-spec §4/§5.1): one logical
                    // device spanning ALL the node's reg windows.
                    if k == "pmgr" {
                        // clock-gates of THIS node seed the boot gates
                        // (defect-(e) fix, attach-spec §4.4).
                        let cg = child
                            .prop_bytes("clock-gates")
                            .map(|b| {
                                b.chunks_exact(4)
                                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                                    .collect::<Vec<u32>>()
                            })
                            .unwrap_or_default();
                        let (core, _spec_windows) = pmgr::new_44_window(&cg);
                        // The kernel addresses pmgr by the concatenated offset
                        // over the ADT's OWN window order/sizes — compute `lin`
                        // from the translated windows, not the spec table.
                        let wins: Vec<(u64, u64)> = child
                            .reg_entries()
                            .iter()
                            .map(|&(b, s)| (translate(b), if s == 0 { 0x1000 } else { s }))
                            .collect();
                        let table: &[(u64, u64)] = if wins.len() == pmgr::PMGR_WINDOWS.len() {
                            &wins
                        } else {
                            // ADT disagrees with the spec's 44-window table —
                            // attach the spec table verbatim (translated bases).
                            pmgr::PMGR_WINDOWS
                        };
                        let mut lin = 0u64;
                        for &(wb, ws) in table {
                            let mut w = pmgr::PmgrWindow { core: core.clone(), lin };
                            let dn = w.name();
                            self.bus.attach(wb, ws, Box::new(w));
                            self.devices_attached.push((dn, wb, ws));
                            lin += ws;
                        }
                        count += 1;
                        continue;
                    }
                    if k == "dockchannel" {
                        let (w0, w1, _sink) =
                            dockchannel::new_pair(self.dockchannel_sink.clone());
                        let wins: Vec<(u64, u64)> = child
                            .reg_entries()
                            .iter()
                            .map(|&(b, s)| (translate(b), if s == 0 { 0x1000 } else { s }))
                            .collect();
                        // w0 = config page, w1 = FIFO page (ADT order); the
                        // two boxes share one core. Extra windows (none on
                        // n104ap) alias w0's behavior.
                        for (i, &(wb, ws)) in wins.iter().enumerate() {
                            let dev: Box<dyn Device> = match i {
                                0 => Box::new(w0.clone()),
                                1 => Box::new(w1.clone()),
                                _ => Box::new(w0.clone()),
                            };
                            let dn = if i == 1 { w1.name() } else { w0.name() };
                            self.bus.attach(wb, ws, dev);
                            self.devices_attached.push((dn, wb, ws));
                        }
                        count += 1;
                        continue;
                    }
                    let dev: Box<dyn Device> = match k {
                        "aic" => {
                            let mut a = Aic::new();
                            a.set_irq_line(self.irq_line.clone());
                            Box::new(a)
                        }
                        "aic-timebase" => Box::new(AicTimebase { counter: 0 }),
                        "s3c-uart" => Box::new(S3cUart::new(0, self.serial.clone())),
                        "apple-wdt" => Box::new(AppleWdt::new()),
                        "dart" => Box::new(Dart::new("dart-adp")),
                        "sart" => Box::new(Sart::new()),
                        "dapf" => Box::new(Dapf::new()),
                        "spmi-pmu" => Box::new(SpmiPmu::new()),
                        "ans2-nvme" => Box::new(Ans2Nvme::new()),
                        "rtkit" => Box::new(RtkitDevice::new("rtkit")),
                        "adp-v4" => Box::new(self.display.clone_device()),
                        "mipi-dsi" => Box::new(MipiDsi::new()),
                        "typec-otg" => Box::new(TypecOtg::new()),
                        "apcie" => Box::new(Apcie::new()),
                        "aop" => Box::new(Aop::new()),
                        "aes" => Box::new(AesEngine::new()),
                        "sep-sim" => Box::new(SepSim::new()),
                        "smc" => Box::new(Smc::new()),
                        "nvram" => Box::new(Nvram::new()),
                        "mca" => Box::new(Mca::new()),
                        "scaler" => Box::new(Scaler::new()),
                        "gpio" => Box::new(Gpio::new()),
                        "i2c" => Box::new(I2c::new()),
                        "spi" => Box::new(Spi::new()),
                        other => {
                            vm_core::bus::mmio_log_line(&format!(
                                "#unimpl-class,{},{:#x},{:#x},{}",
                                child.name,
                                base,
                                size,
                                compat.join(";")
                            ));
                            self.unimplemented_devices
                                .push((other.to_string(), base, size, compat.clone()));
                            continue;
                        }
                    };
                    let dev_name = dev.name();
                    // M5 attach-spec §2: per-window exact sizes — 0x1000 floor
                    // only for zero-size windows (no more blanket rounding that
                    // grew e.g. 0x18-byte mca-switch pages into 0x1000 shadows).
                    let eff_size = if size == 0 { 0x1000 } else { size };
                    self.bus.attach(base, eff_size, dev);
                    self.devices_attached.push((dev_name, base, eff_size));
                    count += 1;
                }
                None => {
                    // M5 census: record the unmodeled node's real window so
                    // tools/re/reports/m5_mmio_census.py can name UNMAPPED
                    // hits (no-op unless IOS_RUST_MMIO_LOG is set).
                    vm_core::bus::mmio_log_line(&format!(
                        "#unimpl,{},{:#x},{:#x},{}",
                        child.name,
                        base,
                        size,
                        compat.join(";")
                    ));
                    self.unimplemented_devices
                        .push((child.name.clone(), base, size, compat.clone()));
                }
            }
        }
        self.adt = Some(adt.clone());
        count
    }

    pub fn load_image(&mut self, addr: u64, img: &[u8]) {
        self.bus.write_raw(addr, img);
    }

    pub fn set_display_mem_reader(&mut self, reader: Box<dyn FnMut(u64) -> u64 + Send>) {
        self.display.mem_read = Some(reader);
    }

    pub fn drain_serial(&self) -> Vec<u8> {
        self.serial.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "T8030 machine (device {})\n  DRAM: {} MB\n  regions attached: {}\n",
            TARGET_DEVICE,
            self.dram_mb,
            self.bus.region_count()
        );
        for (name, base, size) in self.bus.region_summary() {
            s.push_str(&format!("    {name:<14} @ 0x{base:010X} (+0x{size:X})\n"));
        }
        if !self.unimplemented_devices.is_empty() {
            s.push_str(&format!(
                "  unimplemented nodes: {}\n",
                self.unimplemented_devices.len()
            ));
        }
        s
    }
}

/// DisplayPipe needs Clone-ish sharing into the bus: cheap manual clone of
/// the controller state (sink shared by Arc).
impl AdpV4 {
    fn clone_device(&self) -> AdpV4 {
        AdpV4 {
            width: self.width,
            height: self.height,
            fb_addr: 0,
            swaps: 0,
            sink: self.sink.clone(),
            mem_read: None,
            unknown_reads: 0,
        }
    }
}

/// M5-M: translate a raw `/arm-io/<child>` reg base into the SoC address
/// space via the arm-io `ranges` property (u64 triples: child, parent,
/// size — the real n104ap property). Falls back to the session-H #21
/// pinned rule when the property is absent or has no matching window:
/// children below 0x1_00000000 live at parent +0x2_00000000, higher
/// windows are identity. Ground truth for this rule: the kernel's first
/// live MMIO (console UART0 at 0x235200000 = ADT 0x35200000 + 0x2_00000000).
fn translate_armio_child(armio: &adt::AdtNode, base: u64) -> u64 {
    if let Some(r) = armio.prop_bytes("ranges") {
        let mut k = 0usize;
        while k + 24 <= r.len() {
            let child = u64::from_le_bytes(r[k..k + 8].try_into().unwrap());
            let parent = u64::from_le_bytes(r[k + 8..k + 16].try_into().unwrap());
            let size = u64::from_le_bytes(r[k + 16..k + 24].try_into().unwrap());
            if base >= child && base < child.wrapping_add(size) {
                return parent + (base - child);
            }
            k += 24;
        }
    }
    if base < 0x1_0000_0000 {
        base + 0x2_0000_0000
    } else {
        base
    }
}

fn classify(compat_first: &str, compat_all: &[String], node_name: &str) -> Option<&'static str> {
    let hay = format!("{}|{}|{}", compat_first, compat_all.join(","), node_name);
    let h = hay.to_lowercase();
    let m = |p: &str| h.contains(p);
    // M5 attach-spec row 29 / §5.1: dockchannel-uart has NO compatible and a
    // DIFFERENT protocol than S3C UART (the old arm mis-modeled it as a
    // second S3cUart, corrupting the console sink). Name is the only key.
    if node_name.contains("dockchannel") {
        return Some("dockchannel");
    }
    // M5 §5.2: DAPF = DART address filter (dapf-disp0/dapf-aop) — must win
    // over the disp/adp AND dart AND aop arms (it is none of those).
    if m("dapf") {
        return Some("dapf");
    }
    // the aic-timebase node shares the aic compatible — split on its
    // device_type="timer" name FIRST (sub-agent census: it was being
    // misclassified as a second AIC).
    if node_name.contains("timebase") || (m("aic") && m("timer")) {
        Some("aic-timebase")
    } else if m("aic") {
        Some("aic")
    } else if m("uart") || m("s3c") {
        Some("s3c-uart")
    } else if m("wdt") {
        Some("apple-wdt")
    } else if m("dart") {
        Some("dart")
    } else if m("sart") {
        Some("sart")
    } else if m("pmgr") {
        Some("pmgr")
    } else if m("spmi") {
        Some("spmi-pmu")
    } else if m("nvme") || m("ans") {
        Some("ans2-nvme")
    } else if m("rtkit") {
        Some("rtkit")
    } else if m("disp") || m("adp") || m("dpa") {
        Some("adp-v4")
    } else if m("mipi") {
        Some("mipi-dsi")
    } else if m("typec") || m("otg") || m("usb") {
        Some("typec-otg")
    } else if m("pcie") {
        Some("apcie")
    } else if m("aop") {
        Some("aop")
    } else if m("aes") || m("crypto") {
        Some("aes")
    } else if m("sep") {
        Some("sep-sim")
    } else if m("smc") {
        Some("smc")
    } else if m("nvram") {
        Some("nvram")
    } else if m("mca") || m("audio") {
        Some("mca")
    } else if m("scaler") || m("dither") {
        Some("scaler")
    } else if m("gpio") {
        Some("gpio")
    } else if m("i2c") {
        Some("i2c")
    } else if m("spi") {
        Some("spi")
    } else {
        None
    }
}

fn name_static(s: &str) -> &'static str {
    // FALLBACK_MAP names are 'static; re-anchor them.
    FALLBACK_MAP
        .iter()
        .find(|(n, _, _)| *n == s)
        .map(|(n, _, _)| *n)
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_map_attaches() {
        // 256 MiB: unit tests don't need real DRAM size; DEFAULT (4 GiB)
        // OOMs the 3 GiB CI sandbox (the runtime knob IOS_RUST_DRAM_MB
        // exists for the same reason).
        let mut m = T8030Machine::new(256);
        m.attach_fallback();
        assert!(m.bus.region_count() > 10);
        assert!(m.summary().contains("T8030"));
    }

    #[test]
    fn adt_discovery_attaches_aic() {
        // 256 MiB: unit tests don't need real DRAM size; DEFAULT (4 GiB)
        // OOMs the 3 GiB CI sandbox (the runtime knob IOS_RUST_DRAM_MB
        // exists for the same reason).
        let mut m = T8030Machine::new(256);
        let n = m.attach_from_adt(&sample_root());
        assert_eq!(n, 1);
        // real base from the tree
        assert_eq!(
            m.devices_attached.iter().find(|(nm, _, _)| *nm == "apple-aic-v1").unwrap().1,
            0x23B100000
        );
    }

    fn sample_root() -> adt::AdtNode {
        let mut root = adt::AdtNode::default();
        let mut armio = adt::AdtNode { name: "arm-io".into(), ..Default::default() };
        let mut aic = adt::AdtNode { name: "aic".into(), ..Default::default() };
        aic.set_prop_string("compatible", "aic,1\0");
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x23B100000u64.to_le_bytes());
        reg.extend_from_slice(&0x8000u64.to_le_bytes());
        aic.set_prop_bytes("reg", reg);
        armio.children.push(aic);
        root.children.push(armio);
        root
    }
}
