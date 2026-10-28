//! Real-fixture tests — run against actual Apple T8030 (iPhone 11) firmware
//! downloaded from Apple's CDN (iOS 13.7 17H35).
//! Gated: set IOS_RUST_FIXTURES=<dir> to enable; skipped otherwise.
//!
//! These tests are the "real-KC gates" from PARITY.md:
//! * kernelcache decode (LZFSE) on real Apple bytes
//! * version strings + __PRELINK_INFO.__info KEXT inventory on real bytes
//! * the ChefKiss kernel_patches.c T8030 patch table on real bytes
//! * ADT (devicetree) parse on the real DeviceTree.n104ap.im4p
//! * img4/IM4P parse of the real BuildManifest

use std::path::PathBuf;

fn fixtures_dir() -> Option<PathBuf> {
    std::env::var_os("IOS_RUST_FIXTURES").map(PathBuf::from)
}

/// The real T8030 kernelcache: decompress + summarize.
#[test]
fn real_kc_decode_and_metadata() {
    let Some(dir) = fixtures_dir() else { return };
    let Ok(data) = std::fs::read(dir.join("kernelcache.release.iphone12b")) else {
        eprintln!("skip: no T8030 kernelcache fixture");
        return;
    };
    let img = kernelcache::decompress(&data).expect("real KC must decompress");
    assert_eq!(&img[..4], &[0xcf, 0xfa, 0xed, 0xfe], "MH_MAGIC_64");
    assert!(!kernelcache::sections::is_fileset(&img), "iOS 13 A13 = prelinked kernel, not fileset");

    let ver = kernelcache::version::kernel_version(&img).expect("real version strings");
    assert_eq!(ver.cpu, "T8030", "must be the A13 cache, not the XR one");
    assert_eq!(ver.darwin, "19.6.0");
    assert!(ver.xnu.starts_with("6153.142.1"), "xnu-6153.142.1~8");

    let kexts = kernelcache::prelink::kexts(&img).expect("real __info is XML plist");
    println!("real T8030 KC: {} decompressed, Darwin {}, {} kexts listed",
        img.len(), ver.darwin, kexts.len());
    assert!(kexts.len() > 50, "iOS 13.7 prelink info lists ~100+ kexts, got {}", kexts.len());
    // a few kexts that must exist on an iPhone 11
    for want in ["com.apple.iokit.IOStorageFamily", "com.apple.driver.AppleSMC"] {
        assert!(kexts.iter().any(|k| k.bundle_id == want), "missing kext {want}");
    }
}

/// The ChefKiss T8030 patch table applied to REAL Apple kernel bytes.
/// The patchers look up functions by prologue bytes; a RELEASE cache will
/// not contain every patch (some are for the ramdisk/DEBUG builds), so the
/// gate is: the pipeline runs, reports honestly, and patches what matches.
#[test]
fn real_kc_apply_t8030_patches() {
    let Some(dir) = fixtures_dir() else { return };
    let Ok(data) = std::fs::read(dir.join("kernelcache.release.iphone12b")) else {
        eprintln!("skip: no T8030 kernelcache fixture");
        return;
    };
    let mut img = kernelcache::decompress(&data).expect("decompress");
    let report = kernelcache::apply_t8030_patches(&mut img, 0x800000000);
    println!("applied: {} · missed: {}", report.applied.len(), report.missed.len());
    for a in &report.applied {
        println!("  ✅ {a}");
    }
    for m in &report.missed {
        println!("  ── {m}");
    }
    // The gate: the engine walks the real bytes without panic and the
    // boot/AMFI prologue finders behave on real data. A RELEASE T8030
    // cache must match at least the string patches (kprintf/release→profile
    // style) and/or prologue-anchored patches; require > 0.
    assert!(
        !report.applied.is_empty(),
        "real T8030 cache should match at least one T8030 patch"
    );
}

/// The real devicetree of the T8030 (n104ap) parses as an ADT.
#[test]
fn real_devicetree_adt() {
    let Some(dir) = fixtures_dir() else { return };
    let Ok(data) = std::fs::read(dir.join("DeviceTree.n104ap.im4p")) else {
        eprintln!("skip: no devicetree fixture");
        return;
    };
    // IM4P unwrap (DER 'dtr' container, as shipped in the IPSW)
    let payload = {
        let im4p = img4::im4p::Im4p::parse(&data).expect("real devicetree IM4P parses");
        assert_eq!(im4p.fourcc, "dtre", "devicetree fourcc");
        im4p.data
    };
    let adt = adt::AdtNode::parse(&payload).expect("real devicetree parses as ADT");
    assert_eq!(adt.name.trim_end_matches('\0'), "device-tree", "ADT root name");
    // /arm-io must exist and carry the T8030 peripherals
    let armio = adt.children.iter().find(|c| c.name.starts_with("arm-io"))
        .expect("arm-io node present");
    println!("real ADT: root {:?}, {} children under /arm-io", adt.name, armio.children.len());
    assert!(armio.children.len() > 20, "T8030 arm-io has ~100 peripherals");
    // T8030 identity: /arm-io "compatible" names the chip (ARM,T8030)
    let compat = armio
        .props
        .iter()
        .find(|p| p.name == "compatible")
        .map(|p| String::from_utf8_lossy(&p.data).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    println!("arm-io compatible: {compat:?}");
    assert!(compat.to_lowercase().contains("t8030"), "arm-io compatible must name T8030, got {compat:?}");
    let chip_rev = armio.props.iter().find(|p| p.name == "chip-revision").and_then(|p| p.as_u32());
    println!("chip-revision: {chip_rev:?}");
}
