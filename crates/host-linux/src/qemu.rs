//! qemu — reference command builder for the darwin-vm QEMU machine (`-M darwin`).
//!
//! This is the runnable baseline the ios-rust stack replaces with its own
//! `-M apple-t8030` machine; keeping the argv contract in one place makes the
//! firmware layout and boot-args expectations explicit.
//!
//! Parity: see PARITY.md row `host-linux`.
//! Source: ios-emulator-linux darwin-vm run scripts (distilled)

/// Default XNU boot args used by the darwin-vm reference scripts.
pub const DEFAULT_BOOT_ARGS: &str = "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort";

/// The firmware/ directory contract the darwin VM expects on disk.
pub const FIRMWARE_CONTRACT: &[&str] = &[
    "firmware/bootkc = kernelcache.release.<kc>",
    "firmware/dtree = DeviceTree.<board> (dt_fixup.py -nvram nvram.bin)",
    "firmware/ramdisk.dmg = `ipsw extract --dmg rdisk` output",
    "firmware/ramdisk.tc = trust cache built from ldid -h cdhashes",
    "firmware/info = DEVNAME + URL",
];

/// Everything `-M darwin` needs to boot: the boot kernelcache, fixed device
/// tree, ramdisk image + trust cache, and optionally the SPTM/TXM pair used
/// on SPTM-era chips (A15/M2 and later — the A13/T8030 path leaves both `None`).
#[derive(Debug, Clone)]
pub struct DarwinVmConfig {
    /// QEMU binary, e.g. "qemu-system-aarch64".
    pub qemu_bin: String,
    /// firmware/bootkc — kernelcache.release.<kc>.
    pub bootkc: String,
    /// firmware/dtree — DeviceTree.<board> after dt_fixup.py.
    pub dtree: String,
    /// firmware/ramdisk.tc — trust cache from ldid -h cdhashes.
    pub trust_cache: String,
    /// firmware/ramdisk.dmg — `ipsw extract --dmg rdisk` output.
    pub ramdisk: String,
    /// SPTM image (SPTM-era chips only).
    pub sptm: Option<String>,
    /// TXM image (SPTM-era chips only).
    pub txm: Option<String>,
    /// XNU boot args ([`DEFAULT_BOOT_ARGS`] by default).
    pub boot_args: String,
    /// Guest RAM, e.g. "8G".
    pub mem: String,
    /// Extra TCP serial endpoints; each port appends a
    /// `-chardev socket,id=sN,...` + `-serial chardev:sN` pair.
    pub qemuports: Vec<u16>,
}

impl Default for DarwinVmConfig {
    fn default() -> Self {
        Self {
            qemu_bin: "qemu-system-aarch64".to_string(),
            bootkc: "firmware/bootkc".to_string(),
            dtree: "firmware/dtree".to_string(),
            trust_cache: "firmware/ramdisk.tc".to_string(),
            ramdisk: "firmware/ramdisk.dmg".to_string(),
            sptm: None,
            txm: None,
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            mem: "8G".to_string(),
            qemuports: Vec::new(),
        }
    }
}

impl DarwinVmConfig {
    /// Full argv for `Command::new` / `exec`, in QEMU CLI order:
    /// -M darwin, -bootkc/-dtree/-tc/-ramdisk, optional -sptm/-txm, -args,
    /// -nographic/-serial mon:stdio, -m, then one -chardev/-serial pair per port.
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(24);
        argv.push(self.qemu_bin.clone());
        argv.push("-M".to_string());
        argv.push("darwin".to_string());
        argv.push("-bootkc".to_string());
        argv.push(self.bootkc.clone());
        argv.push("-dtree".to_string());
        argv.push(self.dtree.clone());
        argv.push("-tc".to_string());
        argv.push(self.trust_cache.clone());
        argv.push("-ramdisk".to_string());
        argv.push(self.ramdisk.clone());
        if let Some(sptm) = &self.sptm {
            argv.push("-sptm".to_string());
            argv.push(sptm.clone());
        }
        if let Some(txm) = &self.txm {
            argv.push("-txm".to_string());
            argv.push(txm.clone());
        }
        argv.push("-args".to_string());
        argv.push(self.boot_args.clone());
        argv.push("-nographic".to_string());
        argv.push("-serial".to_string());
        argv.push("mon:stdio".to_string());
        argv.push("-m".to_string());
        argv.push(self.mem.clone());
        for (i, port) in self.qemuports.iter().enumerate() {
            argv.push("-chardev".to_string());
            argv.push(format!(
                "socket,id=s{},host=localhost,server=on,wait=off,port={}",
                i, port
            ));
            argv.push("-serial".to_string());
            argv.push(format!("chardev:s{}", i));
        }
        argv
    }
}

/// Quote an argv element for display in a copy-pasteable shell command.
fn shell_quote(s: &str) -> String {
    let safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b',' | b'=' | b':')
    });
    if safe && !s.is_empty() {
        s.to_string()
    } else {
        format!("\"{}\"", s)
    }
}

/// The full runnable reference command plus the operational notes:
/// firmware contract, boot-log expectations and the portability gotchas
/// (ldid ad-hoc flags, ext4-not-NTFS firmware dir, ARM64+KVM vs x86_64 TCG,
/// and how this maps onto ios-rust's own `-M apple-t8030`).
pub fn print_reference() -> String {
    let cfg = DarwinVmConfig::default();
    let argv = cfg.to_argv();
    let cmd = argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");

    let mut out = String::new();
    out.push_str("reference darwin-vm command (QEMU fork with the darwin machine):\n\n");
    out.push_str(&format!("  {}\n\n", cmd));
    out.push_str("firmware contract:\n");
    for line in FIRMWARE_CONTRACT {
        out.push_str(&format!("  - {line}\n"));
    }
    out.push_str("\nnotes:\n");
    out.push_str("  - waitForSEPEndpoint spam on the serial console during early boot is normal;\n");
    out.push_str("    the SEP endpoint handshake retries until the ramdisk SEP pieces are up.\n");
    out.push_str("  - quit QEMU with Ctrl-A x (Ctrl-A c toggles between monitor and console).\n");
    out.push_str("  - sign boot pieces ad hoc with `ldid -Cadhoc`: it sets CodeDirectory flags 0x2\n");
    out.push_str("    (CS_ADHOC), which TXM/AMFI require on SPTM chips; plain `-S` is rejected there.\n");
    out.push_str("  - keep the firmware/ directory on a native ext4 filesystem; NTFS/exFAT via\n");
    out.push_str("    FUSE breaks the mmap/permission behavior the VM relies on.\n");
    out.push_str("  - ARM64 host + KVM is the supported fast path; x86_64 hosts are TCG-only and slow.\n");
    out.push_str("  - `-M darwin` belongs to the darwin-vm QEMU fork; ios-rust replaces it with its\n");
    out.push_str("    own `-M apple-t8030` machine — this builder is the reference contract.\n");
    out.push_str("  - extra TCP serial endpoints: set qemuports (e.g. [5000, 5001]) to append\n");
    out.push_str("    per-port -chardev socket / -serial chardev:sN pairs.\n");
    out
}
