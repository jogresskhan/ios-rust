//! Real BuildManifest test — the actual BuildManifest.plist shipped in the
//! T8030 (iPhone 11) iOS 13.7 17H35 IPSW from Apple's CDN.
//! Gated: set IOS_RUST_FIXTURES=<dir>; skipped otherwise.

#[test]
fn real_buildmanifest_parse() {
    let Some(dir) = std::env::var_os("IOS_RUST_FIXTURES").map(std::path::PathBuf::from) else {
        return;
    };
    let Ok(buf) = std::fs::read(dir.join("BuildManifest.plist")) else {
        eprintln!("skip: no BuildManifest fixture");
        return;
    };
    let m = ipsw::manifest::parse_plist_xml(&buf).expect("real BuildManifest parses");
    let board = m.get("BoardConfig").and_then(|v| v.as_str());
    let build = m.get("ProductBuildVersion").and_then(|v| v.as_str());
    println!("real BuildManifest: BoardConfig={board:?} build={build:?}");
    assert_eq!(build, Some("17H35"));
    // BuildIdentities: one per board (n841ap = XR/T8020, n104ap = 11/T8030)
    let ids = m.get("BuildIdentities").and_then(|v| v.as_array());
    let n = ids.map(|a| a.len()).unwrap_or(0);
    println!("BuildIdentities: {n}");
    assert!(n >= 2, "shared XR/11 IPSW has >=2 build identities, got {n}");
    // the T8030 identity must carry the sep + kernelcache digests
    let t8030 = ids.and_then(|a| {
        a.iter().find(|id| {
            id.get("Info").and_then(|i| i.get("DeviceClass")).and_then(|c| c.as_str())
                == Some("n104ap")
        })
    });
    assert!(t8030.is_some(), "n104ap (T8030) build identity present");
    let id = t8030.unwrap();
    for comp in ["KernelCache", "SEP", "DeviceTree"] {
        let has = id.get("Manifest").and_then(|mm| mm.get(comp)).is_some();
        assert!(has, "T8030 identity must have {comp} digest");
    }
    println!("real BuildManifest parse: OK (T8030 identity with KC/SEP/DT digests)");
}
