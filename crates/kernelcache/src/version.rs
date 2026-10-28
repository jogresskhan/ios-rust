//! version — the Darwin kernel version string scan.
//!
//! ipsw `GetVersion` reads `__TEXT.__const` of the fileset entry named
//! `"kernel"` (kernel collections, iOS 15+) or of the plain kernel image
//! and scans NUL-terminated ASCII strings for:
//!
//! ```text
//! Darwin Kernel Version <darwin>: <date>; root:xnu-<xnu>/<type>_<arch>_<cpu>
//! Apple LLVM <version> (clang-<clang>) [<flags>]
//! ```
//!
//! Parity: blacktop/ipsw `pkg/kernelcache/kernelcache.go:500 GetVersion`
//! (regexes hand-parsed here — no regex dependency).

/// Parsed kernel version info.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelVersion {
    /// e.g. `"20.6.0"`.
    pub darwin: String,
    /// e.g. `"Wed Jun 23 00:26:31 PDT 2021"`.
    pub date: String,
    /// e.g. `"7195.141.2~5"`.
    pub xnu: String,
    /// `RELEASE` / `DEBUG` / `DEVELOPMENT`.
    pub build_type: String,
    /// e.g. `"ARM64"`.
    pub arch: String,
    /// e.g. `"T8030"` — the SoC the kernel was built for.
    pub cpu: String,
    /// e.g. `"13.2.1"` from the LLVM line.
    pub clang_version: Option<String>,
    /// Comma-split flag list from the LLVM line.
    pub clang_flags: Vec<String>,
}

/// True for printable ASCII (the version strings are plain ASCII).
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// Extract NUL-terminated printable strings of length >= 16.
fn ascii_strings(data: &[u8], min_len: usize) -> impl Iterator<Item = &str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..=data.len() {
        if i == data.len() || data[i] == 0 || !printable(data[i]) {
            if i > start && i - start >= min_len && start < data.len() {
                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    out.push(s);
                }
            }
            start = i + 1;
        }
    }
    out.into_iter()
}

/// Parse one `Darwin Kernel Version …` line.
pub fn parse_darwin_line(s: &str) -> Option<KernelVersion> {
    let rest = s.strip_prefix("Darwin Kernel Version ")?;
    let colon = rest.find(": ")?;
    let darwin = rest[..colon].trim().to_string();
    let after_date = &rest[colon + 2..];
    let root = after_date.find("; root:")?;
    let date = after_date[..root].trim().to_string();
    let tail = after_date[root + 7..].trim();
    // tail: "xnu-<xnu>/<type>_<arch>_<cpu>"
    let tail = tail.strip_prefix("xnu").unwrap_or(tail);
    let (xnu_part, type_arch_cpu) = match tail.find('/') {
        Some(idx) => (tail[..idx].to_string(), &tail[idx + 1..]),
        None => (tail.to_string(), tail),
    };
    // The xnu capture keeps any trailing "~N" build tag (ipsw regex `.*`).
    let xnu = xnu_part
        .trim_start_matches('-')
        .trim()
        .to_string();
    let mut parts = type_arch_cpu.split('_');
    let build_type = parts.next().unwrap_or("").to_string();
    let arch = parts.next().unwrap_or("").to_string();
    let cpu = parts.next().unwrap_or("").to_string();
    if darwin.is_empty() || build_type.is_empty() {
        return None;
    }
    Some(KernelVersion {
        darwin,
        date,
        xnu,
        build_type,
        arch,
        cpu,
        clang_version: None,
        clang_flags: Vec::new(),
    })
}

/// Parse one `Apple LLVM …` line.
pub fn parse_llvm_line(s: &str) -> Option<(String, Vec<String>)> {
    let rest = s.strip_prefix("Apple LLVM ")?;
    let paren = rest.find(" (clang-")?;
    let llvm_version = rest[..paren].trim().to_string();
    let after = &rest[paren + 8..]; // skip " (clang-"
    let close = after.find(')')?;
    let clang_version = after[..close].trim().to_string();
    let bracket = after[close + 1..].trim_start();
    let flags: Vec<String> = bracket
        .strip_prefix('[')
        .and_then(|b| b.strip_suffix(']'))
        .map(|b| b.split("\", ").map(|f| f.trim().trim_matches('"').to_string()).collect())
        .unwrap_or_default();
    Some((format!("{llvm_version} (clang-{clang_version})"), flags))
}

/// Scan a decompressed kernel image for the version strings.
///
/// When `img` is an MH_FILESET kernel collection the entry named `kernel`
/// is scanned (falling back to every entry and the top-level image).
pub fn kernel_version(img: &[u8]) -> Option<KernelVersion> {
    if crate::sections::is_fileset(img) {
        let entries = crate::sections::fileset_entry_images(img);
        for (id, bytes) in &entries {
            if id == "com.apple.kernel" || id.ends_with("kernel") {
                if let Some(v) = scan_once(bytes) {
                    return Some(v);
                }
            }
        }
    }
    scan_once(img)
}

fn scan_once(img: &[u8]) -> Option<KernelVersion> {
    // __TEXT.__const first (where the strings actually live), then the raw
    // image as a fallback for unusual layouts.
    let const_data: Option<Vec<u8>> = crate::sections::section_bytes(img, "__TEXT", "__const")
        .map(|b| b.to_vec());
    for probe in const_data.iter().map(|b| b.as_slice()).chain(std::iter::once(img)) {
        let mut found: Option<KernelVersion> = None;
        for s in ascii_strings(probe, 24) {
            if found.is_none() {
                if let Some(mut v) = parse_darwin_line(s) {
                    if let Some((cv, cf)) = ascii_strings(probe, 16)
                        .find_map(parse_llvm_line)
                    {
                        v.clang_version = Some(cv);
                        v.clang_flags = cf;
                    }
                    found = Some(v);
                }
            } else {
                break;
            }
        }
        if found.is_some() {
            return found;
        }
    }
    None
}
