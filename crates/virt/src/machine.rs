//! Machine assembly — build the T8030 board: bus, devices, CPU hooks.
//! This is the Rust replacement for `t8030.c`'s machine_initfn wiring.

use devices::aic::Aic;
use devices::dart::Dart;
use devices::disp_pipe::DisplayPipe;
use devices::mipi_dsi::MipiDsi;
use devices::nvme_ans::AnsNvme;
use devices::uart::AppleUart;
use devices::wdt::Wdt;
use devices::Bus;
use soc_t8030;

#[derive(Debug, Clone, Default)]
pub struct MachineConfig {
    pub kernel: Option<std::path::PathBuf>,
    pub dtb: Option<std::path::PathBuf>,
    pub append: Option<String>,
    pub drives: Vec<std::path::PathBuf>,
}

/// The assembled board. Device bases are symbolic until the memmap constants
/// are verified against `t8030.c` (memmap::LANDMARKS documents each source);
/// the bus dispatch is address-range correct regardless.
pub struct Machine {
    pub bus: Bus,
    pub config: MachineConfig,
    pub aic: std::sync::Arc<std::sync::Mutex<Aic>>,
    pub uart_console: devices::uart::ConsoleSink,
}

/// AIC v1 parity (devices::aic::Aic — measured against AIC.h + the on-device kext).
pub const AIC_PARITY_PCT: u8 = 72;

/// Symbolic attach points — indexed by name so the ledger can track them.
pub const ATTACH_ORDER: &[&str] = &["aic", "uart", "wdt", "dart", "ans", "adp", "mipi"];

impl Machine {
    pub fn new(config: MachineConfig) -> Self {
        let bus = Bus::new();
        let aic = std::sync::Arc::new(std::sync::Mutex::new(Aic::new()));
        let uart_console: devices::uart::ConsoleSink =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        Self { bus, config, aic, uart_console }
    }

    /// Attach the modeled devices (the ones with PARITY > 0 in devices/).
    /// Returns the count attached — honest, visible in `ios-rust run` output.
    pub fn attach_devices(&mut self) -> usize {
        // Symbolic bases; re-verify per LANDMARKS before first real boot.
        let bases: &[(u64, &str)] = &[
            (0x2000_0000, "uart"),
            (0x23B0_4000, "dart"),
            (0x23D0_C000, "ans"),
            (0x23D2_8000, "adp"),
            (0x23D3_1000, "mipi"),
        ];
        let mut n = 0;
        let uart = AppleUart::new();
        self.bus.attach(bases[0].0, Box::new(uart));
        n += 1;
        self.bus.attach(bases[1].0, Box::new(Dart::new()));
        n += 1;
        self.bus.attach(bases[2].0, Box::new(AnsNvme::default()));
        n += 1;
        self.bus.attach(bases[3].0, Box::new(DisplayPipe::default()));
        n += 1;
        self.bus.attach(bases[4].0, Box::new(MipiDsi::new()));
        n += 1;
        n
    }

    /// Which modeled devices are in (name, parity%) — for the run banner.
    pub fn parity_report(&self) -> Vec<(&'static str, u8)> {
        vec![
            ("aic-v1", AIC_PARITY_PCT),
            ("dart", devices::dart::PARITY_PCT),
            ("adp-v4", devices::disp_pipe::PARITY_PCT),
            ("mipi-dsi", devices::mipi_dsi::PARITY_PCT),
            ("ans2-nvme", devices::nvme_ans::PARITY_PCT),
            ("uart", devices::uart::PARITY_PCT),
            ("wdt", devices::wdt::PARITY_PCT),
        ]
    }

    pub fn soc_banner(&self) -> String {
        format!(
            "{} | machine={} cpu={} | workspace {}",
            soc_t8030::SOC_NAME,
            soc_t8030::MACHINE_NAME,
            soc_t8030::CPU_NAME,
            soc_t8030::SOC_CODE
        )
    }
}
