//! inventory — the COMPLETE apple-soc device registry ("find all apple-soc").
//!
//! Every Apple device model that exists in the ChefKiss Inferno tree
//! (`hw/{arm,misc,display,intc,block,audio,pci-host,usb}/apple-silicon/`)
//! is listed here with its Rust counterpart and an honest parity percent
//! (same rubric as the workspace ledger: 100 proven · 90 impl+verified ·
//! 75 implemented · 60 done-once · 50 partial · 40 reg-map · 30 map-only ·
//! 15 faithful stub · 0 missing).
//!
//! This is the single source of truth for "have we found all apple-soc?"
//! — the test below fails if a crate module is missing from the table, and
//! PARITY.md / parity.json / the `ios-rust parity` CLI mirror these rows.
//! 39 rows: 35 ported + kernel patcher (75), 3 honest zeros (apfs key wall,
//! SEP real-fw core, A9/s8000 machine).

/// One apple-soc device row.
pub struct DeviceRow {
    /// T8030 device name (ADT `/arm-io` child name).
    pub device: &'static str,
    /// Inferno C source (or "—" when upstream has no model).
    pub upstream: &'static str,
    /// Rust module in this crate (or "—" when not ported).
    pub rust_module: &'static str,
    /// Honest parity percent (see crate docs for the rubric).
    pub pct: u8,
    /// One-line status note; gates to flip live in PARITY.md.
    pub note: &'static str,
}

/// The complete T8030 (A13) device inventory.
///
/// Rows marked `pct = 0` are the honest remainders: the SEP real-firmware
/// core (upstream sep.c is a 5673-line SePOS executor) and the kernel
/// patcher chain are still C-engine-only.
pub const DEVICES: &[DeviceRow] = &[
    // ---- interrupt / core plumbing ------------------------------------
    DeviceRow { device: "aic", upstream: "hw/intc/apple_aic.c", rust_module: "aic", pct: 55,
        note: "v2 enable/pending/INFO + iack; gate: golden IPI routing + preemption" },
    DeviceRow { device: "pmgr", upstream: "hw/arm/apple-silicon/t8030-config.c.inc",
        rust_module: "pmgr", pct: 45,
        note: "clock gates; voltage-state tables ported; gate: guest walk parity" },
    DeviceRow { device: "dart-*", upstream: "hw/arm/apple-silicon/dart.c", rust_module: "dart",
        pct: 55, note: "TCR/TTBR + 4-level walker; gate: replay captured PTE walks" },
    DeviceRow { device: "sart", upstream: "hw/arm/apple-silicon/sart.c", rust_module: "sart",
        pct: 50, note: "SEP DMA trust zones; gate: assign/restore ladder capture" },
    DeviceRow { device: "wdt", upstream: "hw/misc/apple_wdt.c (top-level hw/misc)",
        rust_module: "wdt", pct: 60, note: "timeout sequencing gate open" },
    DeviceRow { device: "gpio/i2c/spi", upstream: "hw/gpio/apple-silicon/*",
        rust_module: "gpio_i2c_spi", pct: 45, note: "pinctrl + i2c bus + spi1 controller" },
    // ---- console / input ------------------------------------------------
    DeviceRow { device: "uart0", upstream: "hw/char/apple_uart.c", rust_module: "s3c_uart",
        pct: 55, note: "console; gate: flow control + IRQ ladder" },
    DeviceRow { device: "buttons", upstream: "hw/misc/apple-silicon/buttons.c",
        rust_module: "buttons", pct: 75,
        note: "F1-F10 QKeyCodes, SMC HID transitions; wire-up point: Smc HID API" },
    DeviceRow { device: "multi-touch", upstream: "hw/arm/apple-silicon/mt-spi.c",
        rust_module: "mt_spi", pct: 75,
        note: "HBPP+LL SPI stack, touch reports, CRC16, tick timers; plug: spi1" },
    // ---- display ---------------------------------------------------------
    DeviceRow { device: "adp-v4", upstream: "hw/display/apple_displaypipe_v4.c",
        rust_module: "displaypipe", pct: 50,
        note: "frame contract + fb swap; gate: real guest trace (M3a probe)" },
    DeviceRow { device: "adp-v2", upstream: "hw/display/apple_displaypipe_v2.c",
        rust_module: "displaypipe_v2", pct: 75,
        note: "backend/frontend regs, VFTG ladder, commit paints FrameSink" },
    DeviceRow { device: "mipi-dsi", upstream: "hw/display/synopsys_mipi_dsim.c",
        rust_module: "mipi_dsi", pct: 90,
        note: "1:1 port of the full 187-line upstream stub surface" },
    DeviceRow { device: "scaler", upstream: "hw/display/apple_scaler.c", rust_module: "scaler",
        pct: 75, note: "IRQ W1C, config lock, frame tick, format decode; 1:1 blit" },
    DeviceRow { device: "lm-backlight", upstream: "hw/arm/apple-silicon/lm-backlight.c",
        rust_module: "lm_backlight", pct: 60,
        note: "1:1 port of upstream I2C stub (rx=0/tx=ACK)" },
    // ---- storage ----------------------------------------------------------
    DeviceRow { device: "ans2", upstream: "hw/block/apple-silicon/ans.c", rust_module: "ans2_nvme",
        pct: 75, note: "vendor block + NVMe admin/IO queues; gate: PRP walker" },
    DeviceRow { device: "aes", upstream: "hw/misc/apple-silicon/aes.c", rust_module: "aes",
        pct: 90, note: "full reg map + command FIFO, inline AES-128/192/256 ECB/CBC/CTR; FIPS-197 tested" },
    DeviceRow { device: "apfs wall", upstream: "— (per-device AES-XTS keys)",
        rust_module: "—", pct: 0,
        note: "real-image mount blocked on per-device key wall (honest zero)" },
    // ---- coprocessors -----------------------------------------------------
    DeviceRow { device: "aop", upstream: "hw/misc/apple-silicon/aop.c", rust_module: "aop",
        pct: 45, note: "RTKit IOP shim; deepens via a7iop mailbox below" },
    DeviceRow { device: "a7iop core", upstream: "hw/misc/apple-silicon/a7iop/{core,regs-v2,regs-v4}.c",
        rust_module: "a7iop", pct: 75,
        note: "CPU start/status, v2+v4 reg tables, AKF int groups" },
    DeviceRow { device: "a7iop mailbox", upstream: "hw/misc/apple-silicon/a7iop/mailbox/*",
        rust_module: "a7iop_mailbox", pct: 75,
        note: "15-deep FIFO doorbells, int-mask gating, status queue, SEP timers" },
    DeviceRow { device: "rtkit", upstream: "hw/misc/apple-silicon/a7iop/rtkit.c",
        rust_module: "rtkit", pct: 45, note: "ring protocol; gate: carve/attach capture" },
    DeviceRow { device: "smc", upstream: "hw/misc/apple-silicon/smc.c", rust_module: "smc",
        pct: 50, note: "key protocol; gate: full key-table diff" },
    DeviceRow { device: "sep-sim", upstream: "hw/arm/apple-silicon/sep-sim.c",
        rust_module: "sep_sim", pct: 90,
        note: "wire format, 26 endpoints, bootstrap, keystore IPC byte-level" },
    DeviceRow { device: "sep (real fw)", upstream: "hw/arm/apple-silicon/sep.c",
        rust_module: "—", pct: 0,
        note: "5673-line SePOS executor — the C engine's superpower; next wave" },
    // ---- pmu / sensors / power -------------------------------------------
    DeviceRow { device: "pmu-d2255", upstream: "hw/misc/apple-silicon/pmu-d2255.c",
        rust_module: "pmu_d2255", pct: 75,
        note: "0x8800 reg file, RTC latch 32768 Hz, alarm->IRQ, identity block" },
    DeviceRow { device: "spmi-pmu", upstream: "hw/misc/apple-silicon/spmi-pmu.c",
        rust_module: "spmi_pmu", pct: 50, note: "SPMI master; gate: real PMIC traffic" },
    DeviceRow { device: "spmi-baseband", upstream: "hw/misc/apple-silicon/spmi-baseband.c",
        rust_module: "spmi_baseband", pct: 75,
        note: "SPMI slave 0xFFFF reg file, magic 0x147/0x2f check" },
    DeviceRow { device: "tempsensor", upstream: "hw/misc/apple-silicon/tempsensor.c",
        rust_module: "tempsensor", pct: 60,
        note: "1:1 port — upstream is itself a 0xAFAFAFAF fill stub" },
    DeviceRow { device: "mic-tempsensor", upstream: "hw/misc/apple-silicon/mic_tempsensor.c",
        rust_module: "mic_tempsensor", pct: 75,
        note: "I2C addr pointer + ID/STATUS/VALUE regs, FINISH rewind" },
    DeviceRow { device: "chestnut", upstream: "hw/misc/apple-silicon/chestnut.c",
        rust_module: "chestnut", pct: 60,
        note: "1:1 port of upstream I2C display-PMU stub" },
    DeviceRow { device: "fan53740", upstream: "hw/misc/apple-silicon/fan53740.c",
        rust_module: "fan53740", pct: 60,
        note: "1:1 port of upstream I2C buck stub (C defines no registers)" },
    // ---- usb / pcie / audio ------------------------------------------------
    DeviceRow { device: "roswell", upstream: "hw/misc/apple-silicon/roswell.c",
        rust_module: "roswell", pct: 75,
        note: "CP-auth relay: GET_DEVICE_INFO 0xDEADBEEF, EXTENDED 'CKRosw'" },
    DeviceRow { device: "typec/otg", upstream: "hw/usb/apple_typec.c + apple_otg.c",
        rust_module: "typec_otg", pct: 75,
        note: "ATC container PHY/DWC3/DWC2 passthrough + OTG widget maps" },
    DeviceRow { device: "apcie", upstream: "hw/pci-host/apcie.c", rust_module: "apcie",
        pct: 75, note: "LTSSM, MSI banks, RID->SID map, ECAM decode" },
    DeviceRow { device: "mca", upstream: "hw/audio/apple-silicon/mca.c", rust_module: "mca",
        pct: 90, note: "SIO units + DMA FIFO + MCLK, refill quirk, voice-enable" },
    DeviceRow { device: "baseband", upstream: "hw/misc/apple-silicon/baseband.c",
        rust_module: "baseband", pct: 75,
        note: "XMM 7660 PCIe: identity ROM, image doorbell, context parse" },
    // ---- misc --------------------------------------------------------------
    DeviceRow { device: "nvram", upstream: "— (nvram nodes in ADT)", rust_module: "nvram",
        pct: 55, note: "store; gate: real NVRAM blob replay" },
    // ---- ported late wave -------------------------------------------------
    DeviceRow { device: "kernel patcher", upstream: "hw/arm/apple-silicon/{kernel_patches,patcher,mem}.c",
        rust_module: "kernelcache::patcher", pct: 75,
        note: "port done: engine + full T8030 table (8 groups/15 patches/23 finds, 1529 LOC); gate: real-KC run" },
    DeviceRow { device: "a9/s8000 machine", upstream: "hw/arm/apple-silicon/{a9,s8000}.c",
        rust_module: "—", pct: 0,
        note: "A9 (T8010-class) machine — out of T8030 scope; listed for completeness" },
];

/// Devices Inferno models that are macOS-host-specific (not part of the
/// T8030 guest SoC): the hw/display/apple-gfx*.m macOS paravirt GFX and
/// hw/misc/applesmc.c x86 AppleSMC. Listed so "all apple-soc" searches
/// never lose them.
pub const OUT_OF_SCOPE: &[(&str, &str)] = &[
    ("hw/display/apple-gfx{,-mmio,-pci}.m", "macOS host paravirt graphics (not a guest device)"),
    ("hw/misc/applesmc.c", "x86 AppleSMC — unrelated to the ARM SoC SMC"),
    ("hw/vmapple/", "macOS 'vmapple' platform — not T8030"),
];

/// Crate modules that are infrastructure rather than devices (excluded from
/// the DEVICES table but part of the crate).
pub const INFRA_MODULES: &[&str] = &["t8030"];

/// Aggregate: average device parity across DEVICES.
pub fn avg_pct() -> f64 {
    if DEVICES.is_empty() {
        return 0.0;
    }
    DEVICES.iter().map(|d| d.pct as u64).sum::<u64>() as f64 / DEVICES.len() as f64
}

/// Count of ported devices (rust_module != "—").
pub fn ported_count() -> usize {
    DEVICES.iter().filter(|d| d.rust_module != "—").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_crate_module_appears_in_inventory() {
        // The modules declared in lib.rs (kept in sync by hand; if you add a
        // device module, add a DeviceRow).
        let modules = [
            "aic", "buttons", "roswell", "mic_tempsensor", "tempsensor",
            "spmi_baseband", "chestnut", "fan53740", "lm_backlight",
            "ans2_nvme", "apcie", "aes", "aop", "a7iop", "a7iop_mailbox",
            "displaypipe_v2", "pmu_d2255", "dart", "gpio_i2c_spi", "mca",
            "mipi_dsi", "nvram", "pmgr", "rtkit", "s3c_uart", "sart",
            "scaler", "sep_sim", "smc", "spmi_pmu", "t8030", "typec_otg",
            "wdt", "mt_spi", "baseband", "displaypipe",
        ];
        for m in modules {
            let listed = m == "t8030" // infra
                || DEVICES.iter().any(|d| d.rust_module == m);
            assert!(listed, "module {m} missing from inventory::DEVICES");
        }
    }

    #[test]
    fn no_row_above_100_and_zeros_are_honest() {
        for d in DEVICES {
            assert!(d.pct <= 100, "{} pct > 100", d.device);
            if d.pct == 0 {
                assert!(d.rust_module == "—", "{} claims 0 but has a module", d.device);
            }
        }
        // the honest zeros of the inventory
        assert!(DEVICES.iter().any(|d| d.device == "sep (real fw)" && d.pct == 0));
        assert!(DEVICES.iter().any(|d| d.device == "kernel patcher" && d.pct == 75));
    }

    #[test]
    fn aggregate_sanity() {
        assert!(ported_count() >= 30, "ported {}", ported_count());
        let avg = avg_pct();
        assert!(avg > 55.0 && avg <= 100.0, "avg {avg}");
    }
}
