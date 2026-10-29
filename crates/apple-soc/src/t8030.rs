//! t8030 — the T8030 (A13 Bionic) machine.
//!
//! Ports Inferno `hw/arm/apple-silicon/t8030.c` machine assembly to Rust:
//! fixed memory regions from the C defines (SROM/SRAM/DRAM/SEPROM/AMCC)
//! plus **ADT-driven peripheral discovery**: `attach_from_adt` walks the
//! IPSW devicetree `/arm-io` children and attaches each Rust device model
//! at its real MMIO base — the "one IPSW" boot contract. A fallback map
//! covers headless smoke tests.

use std::sync::{Arc, Mutex};

use vm_core::{Bus, Device, Ram};

use crate::{
    aic::Aic,
    aes::AesEngine,
    ans2_nvme::Ans2Nvme,
    aop::Aop,
    apcie::Apcie,
    dart::Dart,
    displaypipe::AdpV4,
    gpio_i2c_spi::{Gpio, I2c, Spi},
    mca::Mca,
    mipi_dsi::MipiDsi,
    nvram::Nvram,
    pmgr::Pmgr,
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

/// Headless test map. Bases are the well-known T8030/D79AP values;
/// `attach_from_adt` overrides at runtime with the IPSW's real map.
pub const FALLBACK_MAP: &[(&str, u64, u64)] = &[
    // (name, base, size) — from xnu T8030 D79AP devicetree (ADT wins at runtime)
    ("aic", 0x23B100000, 0x8000),
    ("uart0", 0x235200000, 0x4000),
    ("wdt", 0x235290000, 0x4000),
    ("dart-ans", 0x233228000, 0x8000),
    ("ans2-nvme", 0x27BCC4000, 0x10000),
    ("adp-v4", 0x228200000, 0x8000),
    ("mipi-dsi", 0x228430000, 0x4000),
    ("sart", 0x23321C000, 0x4000),
    ("pmgr", 0x23B070000, 0x8000),
    ("gpio", 0x23D100000, 0x4000),
];

pub struct T8030Machine {
    pub bus: Bus,
    pub fb: vm_core::framebuffer::FrameSink,
    pub serial: Arc<Mutex<Vec<u8>>>,
    pub adt: Option<adt::AdtNode>,
    pub devices_attached: Vec<(&'static str, u64, u64)>,
    pub unimplemented_devices: Vec<(String, u64, u64, Vec<String>)>,
    pub display: AdpV4,
    pub dram_mb: u64,
}

impl T8030Machine {
    pub fn new(dram_mb: u64) -> Self {
        let mut bus = Bus::new();
        let serial: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
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
            adt: None,
            devices_attached: Vec::new(),
            unimplemented_devices: Vec::new(),
            display,
            dram_mb,
        }
    }

    /// Attach the fallback (synthesized) peripheral map for headless runs.
    pub fn attach_fallback(&mut self) {
        for (name, base, size) in FALLBACK_MAP {
            let dev: Box<dyn Device> = match *name {
                "aic" => Box::new(Aic::new(640)),
                "uart0" => Box::new(S3cUart::new(0, self.serial.clone())),
                "wdt" => Box::new(AppleWdt::new()),
                "dart-ans" => Box::new(Dart::new("dart-ans")),
                "ans2-nvme" => Box::new(Ans2Nvme::new()),
                "adp-v4" => Box::new(self.display.clone_device()),
                "mipi-dsi" => Box::new(MipiDsi::new()),
                "sart" => Box::new(Sart::new()),
                "pmgr" => Box::new(Pmgr::new()),
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
    }

    /// ADT-driven discovery: walk `/arm-io` children, match compatible
    /// strings, attach at real bases. Returns the count attached.
    pub fn attach_from_adt(&mut self, adt: &adt::AdtNode) -> usize {
        let mut count = 0usize;
        let Some(armio) = adt.find("arm-io") else {
            return 0;
        };
        let children = armio.children.clone();
        for child in &children {
            let compat = child.compatible();
            let reg = child.reg_entries();
            let Some((base, size)) = reg.first().copied() else {
                continue;
            };
            let name = compat
                .first()
                .cloned()
                .unwrap_or_else(|| child.name.clone());
            let kind = classify(&name, &compat, &child.name);
            match kind {
                Some(k) => {
                    let dev: Box<dyn Device> = match k {
                        "aic" => Box::new(Aic::new(640)),
                        "s3c-uart" => Box::new(S3cUart::new(0, self.serial.clone())),
                        "apple-wdt" => Box::new(AppleWdt::new()),
                        "dart" => Box::new(Dart::new("dart-adp")),
                        "sart" => Box::new(Sart::new()),
                        "pmgr" => Box::new(Pmgr::new()),
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
                            self.unimplemented_devices
                                .push((other.to_string(), base, size, compat.clone()));
                            continue;
                        }
                    };
                    let dev_name = dev.name();
                    self.bus.attach(base, size.max(0x1000), dev);
                    self.devices_attached.push((dev_name, base, size.max(0x1000)));
                    count += 1;
                }
                None => {
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

fn classify(compat_first: &str, compat_all: &[String], node_name: &str) -> Option<&'static str> {
    let hay = format!("{}|{}|{}", compat_first, compat_all.join(","), node_name);
    let h = hay.to_lowercase();
    let m = |p: &str| h.contains(p);
    if m("aic") {
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
        let mut m = T8030Machine::new(DEFAULT_DRAM_MB);
        m.attach_fallback();
        assert!(m.bus.region_count() > 10);
        assert!(m.summary().contains("T8030"));
    }

    #[test]
    fn adt_discovery_attaches_aic() {
        let mut m = T8030Machine::new(DEFAULT_DRAM_MB);
        let n = m.attach_from_adt(&sample_root());
        assert_eq!(n, 1);
        // real base from the tree
        assert_eq!(
            m.devices_attached.iter().find(|(nm, _, _)| *nm == "aic").unwrap().1,
            0x23B100000
        );
    }

    fn sample_root() -> adt::AdtNode {
        let mut root = adt::AdtNode::default();
        let mut armio = adt::AdtNode { name: "arm-io".into(), ..Default::default() };
        let mut aic = adt::AdtNode { name: "aic".into(), ..Default::default() };
        aic.set_prop_string("compatible", "aic,1\0");
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x23B100000u64.to_be_bytes());
        reg.extend_from_slice(&0x8000u64.to_be_bytes());
        aic.set_prop_bytes("reg", reg);
        armio.children.push(aic);
        root.children.push(armio);
        root
    }
}
