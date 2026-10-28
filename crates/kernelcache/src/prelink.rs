//! prelink — the KEXT inventory from `__PRELINK_INFO.__info`.
//!
//! The (XML) plist in `__PRELINK_INFO.__info` carries an
//! `_PrelinkInfoDictionary` array; every element describes one prelinked
//! KEXT/bundle. ipsw decodes it into `PrelinkInfo`/`CFBundle`
//! (`pkg/kernelcache/kext.go`); this module keeps the subset that
//! describes the KEXT and its load address.
//!
//! Parity: blacktop/ipsw `pkg/kernelcache/kext.go` (PrelinkInfo /
//! CFBundle) over `restore::plist_lite` XML parsing.

use restore::plist_lite::Plist;

/// One prelinked KEXT/bundle description (CFBundle subset).
#[derive(Debug, Clone, Default)]
pub struct Kext {
    /// `CFBundleIdentifier` (e.g. `com.apple.driver.AppleARMPlatform`).
    pub bundle_id: String,
    /// `CFBundleName`.
    pub name: String,
    /// `CFBundleVersion`.
    pub version: String,
    /// `CFBundleExecutable`.
    pub executable: String,
    /// `_PrelinkBundlePath`.
    pub bundle_path: String,
    /// `_PrelinkExecutableRelativePath`.
    pub relative_path: String,
    /// `_PrelinkExecutableLoadAddr` (when present).
    pub load_addr: Option<u64>,
    /// `OSBundleLibraries` (dependency → version).
    pub os_bundle_libraries: Vec<(String, String)>,
    /// `OSBundleRequired` (Root/Console/Network-Root/…).
    pub os_bundle_required: String,
    /// `IOKitPersonalities` names (drivers' declared personalities).
    pub iokit_personalities: Vec<String>,
}

fn as_str(p: &Plist) -> Option<String> {
    match p {
        Plist::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_uint(p: &Plist) -> Option<u64> {
    match p {
        Plist::UInt(v) => Some(*v),
        _ => None,
    }
}

fn parse_one_bundle(dict: &std::collections::BTreeMap<String, Plist>) -> Kext {
    let mut k = Kext {
        bundle_id: dict.get("CFBundleIdentifier").and_then(as_str).unwrap_or_default(),
        name: dict.get("CFBundleName").and_then(as_str).unwrap_or_default(),
        version: dict.get("CFBundleVersion").and_then(as_str).unwrap_or_default(),
        executable: dict.get("CFBundleExecutable").and_then(as_str).unwrap_or_default(),
        bundle_path: dict.get("_PrelinkBundlePath").and_then(as_str).unwrap_or_default(),
        relative_path: dict
            .get("_PrelinkExecutableRelativePath")
            .and_then(as_str)
            .unwrap_or_default(),
        load_addr: dict.get("_PrelinkExecutableLoadAddr").and_then(as_uint),
        os_bundle_required: dict.get("OSBundleRequired").and_then(as_str).unwrap_or_default(),
        ..Default::default()
    };
    if let Some(Plist::Dict(libs)) = dict.get("OSBundleLibraries") {
        k.os_bundle_libraries = libs.iter().filter_map(|(k, v)| as_str(v).map(|v| (k.clone(), v))).collect();
    }
    if let Some(Plist::Dict(per)) = dict.get("IOKitPersonalities") {
        k.iokit_personalities = per.keys().cloned().collect();
    }
    k
}

/// Parse the `__PRELINK_INFO.__info` plist bytes (trailing NULs are
/// trimmed, matching ipsw) into the KEXT list.
pub fn parse_prelink_info(info_bytes: &[u8]) -> Result<Vec<Kext>, String> {
    let trimmed: &[u8] = {
        let end = info_bytes.iter().rposition(|&b| b != 0).map(|p| p + 1).unwrap_or(0);
        &info_bytes[..end]
    };
    let xml = std::str::from_utf8(trimmed)
        .map_err(|_| "prelink: __info is not UTF-8 XML plist".to_string())?;
    let parsed = restore::plist_lite::from_xml(xml)?;
    let mut out = Vec::new();
    // Shape: dict { _PrelinkInfoDictionary: [ {CFBundle…}, … ] } — but some
    // builds put the array at top level; accept both.
    let arr: Vec<Plist> = match &parsed {
        Plist::Dict(d) => match d.get("_PrelinkInfoDictionary") {
            Some(Plist::Array(a)) => a.clone(),
            other => other.cloned().into_iter().collect(),
        },
        Plist::Array(a) => a.clone(),
        _ => Vec::new(),
    };
    for item in arr {
        match item {
            Plist::Dict(d) => out.push(parse_one_bundle(&d)),
            _ => continue,
        }
    }
    Ok(out)
}

/// Enumerate the KEXTs of a decompressed kernel image.
///
/// Plain kernels (`MH_EXECUTE`) carry `__PRELINK_INFO.__info` at top
/// level; kernel collections carry it inside the `com.apple.kernel`
/// entry. Both are tried.
pub fn kexts(img: &[u8]) -> Result<Vec<Kext>, String> {
    let mut imgs: Vec<Vec<u8>> = Vec::new();
    if crate::sections::is_fileset(img) {
        for (id, bytes) in crate::sections::fileset_entry_images(img) {
            if id == "com.apple.kernel" || id.ends_with("kernel") || id.contains("pmap") {
                imgs.push(bytes);
            }
        }
    }
    imgs.push(img.to_vec());
    for probe in &imgs {
        if let Some(info) = crate::sections::section_bytes(probe, "__PRELINK_INFO", "__info") {
            return parse_prelink_info(info);
        }
    }
    Ok(Vec::new())
}
