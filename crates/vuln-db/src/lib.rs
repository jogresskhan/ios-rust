//! vuln-db — embedded iOS vulnerability-research knowledge base.
//!
//! A distilled, data-only corpus of public iOS security research: the kernel
//! heap exploitation lineage (XNU zone allocator, 2012-2017), IPC/XPC and
//! daemon bugs, IOKit user-client drivers, plus the tooling/technique index
//! from the ansjdnakjdnajkd/iOS pentest cheatsheet. Curated from the
//! IdanBanani/iOS-Vulnerability-Research corpus of conference decks and
//! PoCs. The emulator uses this as research context for its
//! security-relevant subsystems (kernel heap, IPC, IOKit drivers); this
//! crate contains documentation and metadata only — no exploit code.
//!
//! Where an Apple advisory attribution is known to be misleading (e.g.
//! "IOKit" fixes that were really the ProvInfoIOKit driver or the XNU
//! kernel heap), both the advisory label and the real component are
//! recorded on the entry.
//!
//! Parity: 18 vuln-lineage entries (CVEs plus no-CVE design-bug and
//! Learning rows), 6 XNU zone-allocator mitigation notes (iOS 5..10),
//! 10 Frida/r2frida technique notes, 34 pentest tooling references.
//! Source: IdanBanani/iOS-Vulnerability-Research (conference decks/PoCs);
//! ansjdnakjdnajkd/iOS (pentest cheatsheet).

pub mod data;

use serde::Serialize;

/// Subsystem classification for a [`VulnEntry`].
///
/// Serialized as the lowercase string form ([`ComponentKind::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentKind {
    /// XNU kernel proper (Mach VM, zalloc/kalloc, BSD).
    Kernel,
    /// IOKit drivers and user clients.
    IOKit,
    /// System daemons reached over XPC/MIG (cfprefsd, bluetoothd, ...).
    Daemon,
    /// Other userspace frameworks and services.
    Userspace,
    /// WebKit and web-content attack surface.
    WebKit,
    /// Learning/curriculum rows (no emulator component).
    Learning,
}

impl ComponentKind {
    /// Lowercase stable string form, matching the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ComponentKind::Kernel => "kernel",
            ComponentKind::IOKit => "iokit",
            ComponentKind::Daemon => "daemon",
            ComponentKind::Userspace => "userspace",
            ComponentKind::WebKit => "webkit",
            ComponentKind::Learning => "learning",
        }
    }
}

/// One vulnerability or exploit lineage in the knowledge base.
///
/// `id` is a short slug (a CVE ID where one exists, e.g. "CVE-2019-7287",
/// otherwise a descriptive slug like "xpc-mig-design"). All strings are
/// documentation distilled from the cited public sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VulnEntry {
    /// Short slug, e.g. "CVE-2019-7287" or "xpc-mig-design".
    pub id: &'static str,
    /// One-line technical title.
    pub title: &'static str,
    /// Real affected component, including the advisory label where the two
    /// disagree (e.g. "ProvInfoIOKit driver ... Apple advisory said 'IOKit'").
    pub component: &'static str,
    /// Subsystem classification.
    pub kind: ComponentKind,
    /// Bug class, e.g. "OOB memmove (controlled length)", "UAF / refcount".
    pub bug_class: &'static str,
    /// Affected/fixed iOS versions, or "n/a" for research rows.
    pub affected: &'static str,
    /// The exploitation primitive in one line.
    pub primitive: &'static str,
    /// Technical summary (2-5 sentences).
    pub summary: &'static str,
    /// Bullet techniques (heap feng shui, sprays, races, ...).
    pub techniques: &'static [&'static str],
    /// Talk/blog references the entry was distilled from.
    pub sources: &'static [&'static str],
    /// Publication year of the primary source.
    pub year: u16,
}

/// XNU zone-allocator hardening timeline row (iOS 5..10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MitigationNote {
    /// OS era, e.g. "iOS 9 (2015-2016)".
    pub era: &'static str,
    /// What Apple hardened in this generation.
    pub hardening: &'static str,
    /// How that hardening was defeated or what it cost attackers.
    pub defeated_by: &'static str,
}

/// Frida / r2frida technique catalog row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FridaNote {
    /// Technique or operation, e.g. "r2frida :dtf".
    pub topic: &'static str,
    /// What it does and when to reach for it.
    pub detail: &'static str,
}

/// Pentest tooling index row (from the ansjdnakjdnajkd/iOS cheatsheet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ToolRef {
    /// Tool name.
    pub name: &'static str,
    /// Canonical project/home URL.
    pub url: &'static str,
    /// One-line description of what the tool is for.
    pub what: &'static str,
}

/// Serializable snapshot shape used by [`export_json`].
#[derive(Serialize)]
struct DbExport<'a> {
    vulns: &'a [VulnEntry],
    mitigations: &'a [MitigationNote],
    frida: &'a [FridaNote],
    tools: &'a [ToolRef],
}

/// All vulnerability entries, in corpus order.
pub fn all() -> &'static [VulnEntry] {
    data::VULNS
}

/// Look up an entry by id slug (CVE or design-bug name), case-insensitive.
pub fn by_cve(cve: &str) -> Option<&'static VulnEntry> {
    data::VULNS
        .iter()
        .find(|v| v.id.eq_ignore_ascii_case(cve))
}

/// All entries for one subsystem kind.
pub fn by_kind(k: ComponentKind) -> Vec<&'static VulnEntry> {
    data::VULNS.iter().filter(|v| v.kind == k).collect()
}

/// Substring search across id, title, component and summary
/// (case-insensitive; empty term matches everything).
pub fn search(term: &str) -> Vec<&'static VulnEntry> {
    let needle = term.to_ascii_lowercase();
    data::VULNS
        .iter()
        .filter(|v| {
            [v.id, v.title, v.component, v.summary]
                .iter()
                .any(|h| h.to_ascii_lowercase().contains(&needle))
        })
        .collect()
}

/// XNU zone-allocator hardening timeline (iOS 5..10).
pub fn mitigations() -> &'static [MitigationNote] {
    data::MITIGATIONS
}

/// Frida/r2frida technique catalog.
pub fn frida_notes() -> &'static [FridaNote] {
    data::FRIDA_NOTES
}

/// Pentest tooling index.
pub fn tools() -> &'static [ToolRef] {
    data::TOOLS
}

/// Row counts: (vulns, mitigations, frida notes, tools).
pub fn stats() -> (usize, usize, usize, usize) {
    (data::VULNS.len(), data::MITIGATIONS.len(), data::FRIDA_NOTES.len(), data::TOOLS.len())
}

/// Pretty-printed JSON export of the whole knowledge base.
pub fn export_json() -> String {
    let export = DbExport {
        vulns: data::VULNS,
        mitigations: data::MITIGATIONS,
        frida: data::FRIDA_NOTES,
        tools: data::TOOLS,
    };
    serde_json::to_string_pretty(&export).expect("static knowledge-base data serializes")
}
