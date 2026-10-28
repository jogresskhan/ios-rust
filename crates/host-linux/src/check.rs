//! check — Linux host capability probe: KVM, RAM, disk, APFS module, required tools.
//!
//! Everything is std-only: /proc and /dev are read directly, `df` is invoked once
//! for the free-space number and $PATH is scanned by hand for the toolchain.
//!
//! Parity: see PARITY.md row `host-linux`.
//! Source: ios-emulator-linux scripts/00-install-deps.sh + environment preflight (distilled)

use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Tools the restore/emulation workflow needs on $PATH.
pub const REQUIRED_TOOLS: &[&str] = &[
    "ipsw",
    "ldid",
    "qemu-system-aarch64",
    "jq",
    "git",
    "python3",
];

/// RAM floor for a comfortable 8G darwin VM.
pub const MIN_RAM_GB: f64 = 8.0;
/// Disk floor for building QEMU + storing an extracted IPSW.
pub const MIN_DISK_GB: f64 = 20.0;

/// One $PATH tool lookup result.
#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub name: &'static str,
    pub found: bool,
    pub path: Option<String>,
}

/// Aggregate host capability snapshot.
#[derive(Debug, Clone)]
pub struct HostCheck {
    /// /dev/kvm exists and is openable read+write.
    pub kvm: bool,
    /// Empty when [`HostCheck::kvm`] is true, otherwise a human hint.
    pub kvm_reason: String,
    /// `std::env::consts::ARCH` — aarch64 is the preferred (KVM) host.
    pub arch: String,
    /// MemTotal from /proc/meminfo, kB converted to GB.
    pub ram_gb: f64,
    /// `df -P -B1 .` available bytes converted to GB (0.0 when unavailable).
    pub disk_free_gb: f64,
    /// `apfs` word found in /proc/filesystems (linux-apfs-rw module loaded).
    pub apfs_module: bool,
    /// One entry per [`REQUIRED_TOOLS`], in order.
    pub tools: Vec<ToolStatus>,
}

/// Probe the host once and return the aggregate snapshot.
pub fn check() -> HostCheck {
    let (kvm, kvm_reason) = check_kvm();
    HostCheck {
        kvm,
        kvm_reason,
        arch: std::env::consts::ARCH.to_string(),
        ram_gb: read_ram_gb(),
        disk_free_gb: disk_free_gb(),
        apfs_module: apfs_module_loaded(),
        tools: REQUIRED_TOOLS
            .iter()
            .map(|name| {
                let path = find_in_path(name);
                ToolStatus {
                    name,
                    found: path.is_some(),
                    path,
                }
            })
            .collect(),
    }
}

/// /dev/kvm must exist AND be openable read+write (KVM ioctls need write access).
fn check_kvm() -> (bool, String) {
    let path = Path::new("/dev/kvm");
    if !path.exists() {
        return (false, "no /dev/kvm — TCG fallback, slow".to_string());
    }
    match OpenOptions::new().read(true).write(true).open(path) {
        // Dropping the handle immediately; existence + openability is all we test.
        Ok(_) => (true, String::new()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            (false, "permission denied — add user to kvm group".to_string())
        }
        Err(e) => (false, format!("cannot open /dev/kvm: {e}")),
    }
}

/// Parse MemTotal (kB) out of /proc/meminfo into GB. Returns 0.0 when unreadable.
fn read_ram_gb() -> f64 {
    let Ok(meminfo) = fs::read_to_string("/proc/meminfo") else {
        return 0.0;
    };
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: "MemTotal:       32879688 kB"
            if let Some(kb) = rest.trim().split_whitespace().next() {
                if let Ok(kb) = kb.parse::<f64>() {
                    return kb / 1024.0 / 1024.0;
                }
            }
        }
    }
    0.0
}

/// `df -P -B1 .` — parse the available-bytes column (field 4 of the data row).
/// Returns 0.0 when df fails, so the caller sees the warning instead of a panic.
fn disk_free_gb() -> f64 {
    let output = match Command::new("df").arg("-P").arg("-B1").arg(".").output() {
        Ok(o) if o.status.success() => o,
        _ => return 0.0,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().nth(1) {
        if let Some(available) = line.split_whitespace().nth(3) {
            if let Ok(bytes) = available.parse::<f64>() {
                return bytes / 1_000_000_000.0;
            }
        }
    }
    0.0
}

/// True when /proc/filesystems carries a bare `apfs` word, i.e. the
/// linux-apfs-rw module is loaded (build recipe: [`crate::deps::APFS_MODULE_RECIPE`]).
fn apfs_module_loaded() -> bool {
    let Ok(list) = fs::read_to_string("/proc/filesystems") else {
        return false;
    };
    list.lines()
        .any(|line| line.split_whitespace().any(|token| token == "apfs"))
}

/// Scan $PATH in order for an executable file (mode & 0o111).
fn find_in_path(name: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        // A empty PATH entry means the current directory by convention.
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate: PathBuf = Path::new(dir).join(name);
        if let Ok(meta) = fs::metadata(&candidate) {
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

impl HostCheck {
    /// First tool lookup failure with its path hint (used by the report).
    fn missing_tools(&self) -> Vec<&ToolStatus> {
        self.tools.iter().filter(|t| !t.found).collect()
    }

    /// Formatted multi-line report ending in a verdict line
    /// (`READY` or `NOT READY` with the warning list).
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str("host-linux capability report\n");
        out.push_str("----------------------------\n");
        if self.kvm {
            out.push_str("KVM         : available (/dev/kvm openable read+write)\n");
        } else {
            out.push_str(&format!("KVM         : UNAVAILABLE — {}\n", self.kvm_reason));
        }
        match self.arch.as_str() {
            "aarch64" => out.push_str(
                "arch        : aarch64 — KVM-accelerated darwin VM supported (preferred)\n",
            ),
            "x86_64" => out.push_str(
                "arch        : x86_64 — TCG emulation only (no darwin KVM), slow\n",
            ),
            other => out.push_str(&format!("arch        : {other}\n")),
        }
        out.push_str(&format!("RAM         : {:.1} GB (min {:.1} GB)\n", self.ram_gb, MIN_RAM_GB));
        out.push_str(&format!(
            "disk free   : {:.1} GB (min {:.1} GB)\n",
            self.disk_free_gb, MIN_DISK_GB
        ));
        if self.apfs_module {
            out.push_str("APFS module : loaded (apfs in /proc/filesystems)\n");
        } else {
            out.push_str(
                "APFS module : not loaded — build linux-apfs-rw (see deps::APFS_MODULE_RECIPE)\n",
            );
        }
        out.push_str("tools       :\n");
        for tool in &self.tools {
            match (&tool.found, &tool.path) {
                (true, Some(p)) => out.push_str(&format!("  [ok]      {} -> {}\n", tool.name, p)),
                (true, None) => out.push_str(&format!("  [ok]      {}\n", tool.name)),
                (false, _) => out.push_str(&format!("  [MISSING] {}\n", tool.name)),
            }
        }

        let mut warnings: Vec<String> = Vec::new();
        if !self.kvm {
            warnings.push(format!("KVM: {}", self.kvm_reason));
        }
        if self.ram_gb < MIN_RAM_GB {
            warnings.push(format!(
                "RAM: {:.1} GB < {:.1} GB needed for an 8G darwin VM",
                self.ram_gb, MIN_RAM_GB
            ));
        }
        if self.disk_free_gb < MIN_DISK_GB {
            warnings.push(format!(
                "disk: {:.1} GB free < {:.1} GB needed for QEMU + an extracted IPSW",
                self.disk_free_gb, MIN_DISK_GB
            ));
        }
        for tool in self.missing_tools() {
            warnings.push(format!("tool {} not on $PATH", tool.name));
        }

        if warnings.is_empty() {
            out.push_str("verdict     : READY — host can build and boot the darwin VM\n");
        } else {
            out.push_str(&format!(
                "verdict     : NOT READY — {} warning(s):\n",
                warnings.len()
            ));
            for w in &warnings {
                out.push_str(&format!("  - {w}\n"));
            }
        }
        out
    }
}
