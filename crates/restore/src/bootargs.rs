//! Boot args + DT composition for the restored install.
//!
//! `boot_args()` composes the T8030 boot-args string for each boot mode
//! the lane drives (restore ramdisk / install / user boot), matching the
//! arguments the C-engine lanes pass (see RE-FINDINGS.md and the run #74
//! matrix). `boot_args_dt_patch()` renders them into the devicetree
//! `chosen/boot-args` property shape.

/// The boot modes the full-system pipeline drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// G1: restore ramdisk (run #74 proven on the C lane)
    RestoreRamdisk,
    /// G2/G3: ASR/invert + install onto the restored APFS
    Install,
    /// G4: user boot of the installed system (SpringBoard ladder)
    User,
}

impl BootMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BootMode::RestoreRamdisk => "restore-ramdisk",
            BootMode::Install => "install",
            BootMode::User => "user",
        }
    }
}

/// Compose the boot-args for the T8030 (iPhone 11 / n104ap lane).
///
/// The restore/install modes boot the ramdisk with `-v` serial console +
/// `rd=md0`; the user boot enables the full userspace ladder (launchd,
/// SpringBoard) with the serial console on and kprintf enabled.
pub fn boot_args(mode: BootMode) -> String {
    match mode {
        BootMode::RestoreRamdisk => {
            "-v rd=md0 nand-enable-reformat=1 serial=3 pio-dart=1".to_string()
        }
        BootMode::Install => {
            "-v rd=md0 serial=3 pio-dart=1 async-imaging=1 progress-bits=1".to_string()
        }
        BootMode::User => {
            "-v serial=3 kprintf=1 debug=0x14e amfi=0x1c cpus=6".to_string()
        }
    }
}

/// The devicetree `chosen` property pairs the lane patches alongside the
/// boot-args (display framebuffer base/stride come from the ADT builder).
pub fn chosen_properties(mode: BootMode) -> Vec<(&'static str, String)> {
    vec![
        ("boot-args", boot_args(mode)),
        (
            "security-mode",
            match mode {
                BootMode::User => "none".to_string(),
                _ => "production".to_string(),
            },
        ),
        ("debug-enabled", format!("{}", mode == BootMode::User)),
    ]
}

/// The userspace launch ladder for the restored install (G4): the ordered
/// launchd jobs up to SpringBoard — each stage is a checkpoint the full
/// system pipeline reports.
pub const USER_BOOT_LADDER: &[(&str, &str)] = &[
    ("launchd", "PID 1 — com.apple.xpc.launchd"),
    ("configd", "system configuration"),
    ("symptomsd", "network symptoms"),
    ("mediaserverd", "media daemon"),
    ("backboardd", "HID + composition"),
    ("SpringBoard", "the homescreen application"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_args_per_mode() {
        assert!(boot_args(BootMode::RestoreRamdisk).contains("rd=md0"));
        assert!(boot_args(BootMode::Install).contains("progress-bits=1"));
        assert!(boot_args(BootMode::User).contains("cpus=6"));
        let chosen = chosen_properties(BootMode::User);
        assert!(chosen.iter().any(|(k, v)| *k == "boot-args" && v.contains("serial=3")));
    }

    #[test]
    fn ladder_reaches_springboard() {
        assert_eq!(USER_BOOT_LADDER.last().unwrap().0, "SpringBoard");
        assert!(USER_BOOT_LADDER.len() >= 5);
    }
}
