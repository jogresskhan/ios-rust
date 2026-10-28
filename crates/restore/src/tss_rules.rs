//! tss_rules — the RestoreRequestRules engine + BuildManifest component
//! 4CC map.
//!
//! Apple's signing server does not blindly trust the digests the host
//! sends: every BuildManifest component carries `Info.RestoreRequestRules`
//! — condition/action pairs that decide whether the request gets the
//! `EPRO` (production) / `ESEC` (security-mode) personalization bits.
//! `libauthinstall` applies them host-side when assembling the TSS
//! request; ipsw `pkg/tss/tss.go applyRestoreRequestRules` documents the
//! exact semantics, ported here verbatim over [`crate::plist_lite::Plist`].
//!
//! Parity: libauthinstall `tss_populate` + ipsw `pkg/tss/tss.go:122`
//! (conditions: ApRawProductionMode/ApCurrentProductionMode → ApProductionMode,
//! ApRawSecurityMode → ApSecurityMode, ApRequiresImage4 → always true,
//! ApDemotionPolicyOverride → DemotionPolicy, ApInRomDFU → ApInRomDFU;
//! unknown condition ⇒ rule not fulfilled; actions copied as bools).
//!
//! The component 4CC table is ipsw `pkg/img4/img4.go ComponentFourCCs`
//! (which mirrors libauthinstall / idevicerestore `component_4cc`).

use crate::plist_lite::Plist;
use std::collections::BTreeMap;

/// BuildManifest component name → IM4P 4CC (ipsw `ComponentFourCCs`).
pub const COMPONENT_FOURCCS: &[(&str, &str)] = &[
    ("ACIBT", "acib"),
    ("ACIBTLPEM", "lpbt"),
    ("ACIWIFI", "aciw"),
    ("ANE", "anef"),
    ("ANS", "ansf"),
    ("AOP", "aopf"),
    ("AVE", "avef"),
    ("Alamo", "almo"),
    ("Ap,ANE1", "ane1"),
    ("Ap,ANE2", "ane2"),
    ("Ap,ANE3", "ane3"),
    ("Ap,AudioAccessibilityBootChime", "auac"),
    ("Ap,AudioBootChime", "aubt"),
    ("Ap,AudioPowerAttachChime", "aupr"),
    ("Ap,BootabilityBrainTrustCache", "trbb"),
    ("Ap,CIO", "ciof"),
    ("Ap,HapticAssets", "hpas"),
    ("Ap,LocalBoot", "lobo"),
    ("Ap,LocalPolicy", "lpol"),
    ("Ap,NextStageIM4MHash", "nsih"),
    ("Ap,RecoveryOSPolicyNonceHash", "ronh"),
    ("Ap,RestoreANE1", "ran1"),
    ("Ap,RestoreANE2", "ran2"),
    ("Ap,RestoreANE3", "ran3"),
    ("Ap,RestoreCIO", "rcio"),
    ("Ap,RestoreTMU", "rtmu"),
    ("Ap,Scorpius", "scpf"),
    ("Ap,SystemVolumeCanonicalMetadata", "msys"),
    ("Ap,TMU", "tmuf"),
    ("Ap,VolumeUUID", "vuid"),
    ("Ap,rOSLogo1", "rlg1"),
    ("Ap,rOSLogo2", "rlg2"),
    ("AppleLogo", "logo"),
    ("AudioCodecFirmware", "acfw"),
    ("BatteryCharging", "glyC"),
    ("BatteryCharging0", "chg0"),
    ("BatteryCharging1", "chg1"),
    ("BatteryFull", "batF"),
    ("BatteryLow0", "bat0"),
    ("BatteryLow1", "bat1"),
    ("BatteryPlugin", "glyP"),
    ("CFELoader", "cfel"),
    ("CrownFirmware", "crwn"),
    ("DCP", "dcpf"),
    ("Dali", "dali"),
    ("DeviceTree", "dtre"),
    ("Diags", "diag"),
    ("EngineeringTrustCache", "dtrs"),
    ("ExtDCP", "edcp"),
    ("GFX", "gfxf"),
    ("Hamm", "hamf"),
    ("Homer", "homr"),
    ("ISP", "ispf"),
    ("InputDevice", "ipdf"),
    ("KernelCache", "krnl"),
    ("LLB", "illb"),
    ("LeapHaptics", "lphp"),
    ("Liquid", "liqd"),
    ("LoadableTrustCache", "ltrs"),
    ("LowPowerWallet0", "lpw0"),
    ("LowPowerWallet1", "lpw1"),
    ("LowPowerWallet2", "lpw2"),
    ("MacEFI", "mefi"),
    ("MtpFirmware", "mtpf"),
    ("Multitouch", "mtfw"),
    ("NeedService", "nsrv"),
    ("OS", "rosi"),
    ("OSRamdisk", "osrd"),
    ("PEHammer", "hmmr"),
    ("PERTOS", "pert"),
    ("PHLEET", "phlt"),
    ("PMP", "pmpf"),
    ("PersonalizedDMG", "pdmg"),
    ("RBM", "rmbt"),
    ("RTP", "rtpf"),
    ("Rap,SoftwareBinaryDsp1", "sbd1"),
    ("Rap,RTKitOS", "rkos"),
    ("Rap,RestoreRTKitOS", "rrko"),
    ("RecoveryMode", "recm"),
    ("RestoreANS", "rans"),
    ("RestoreDCP", "rdcp"),
    ("RestoreDeviceTree", "rdtr"),
    ("RestoreExtDCP", "recp"),
    ("RestoreKernelCache", "rkrn"),
    ("RestoreLogo", "rlgo"),
    ("RestoreRTP", "rrtp"),
    ("RestoreRamDisk", "rdsk"),
    ("RestoreSEP", "rsep"),
    ("RestoreTrustCache", "rtsc"),
    ("SCE", "scef"),
    ("SCE1Firmware", "sc1f"),
    ("SEP", "sepi"),
    ("SIO", "siof"),
    ("StaticTrustCache", "trst"),
    ("SystemLocker", "lckr"),
    ("SystemVolume", "isys"),
    ("WCHFirmwareUpdater", "wchf"),
    ("ftap", "ftap"),
    ("ftsp", "ftsp"),
    ("iBEC", "ibec"),
    ("iBSS", "ibss"),
    ("iBoot", "ibot"),
    ("iBootData", "ibdt"),
    ("iBootDataStage1", "ibd1"),
    ("iBootTest", "itst"),
    ("rfta", "rfta"),
    ("rfts", "rfts"),
    ("Ap,DCP2", "dcp2"),
    ("Ap,RestoreSecureM3Firmware", "rsm3"),
    ("Ap,RestoreSecurePageTableMonitor", "rspt"),
    ("Ap,RestoreTrustedExecutionMonitor", "rtrx"),
    ("Ap,RestorecL4", "rxcl"),
    ("BaseSystem", "bsys"),
    ("Ap,SecurePageTableMonitor", "sptm"),
    ("Ap,TrustedExecutionMonitor", "trxm"),
    ("Ap,BaseSystemTrustCache", "bstc"),
    ("Ap,SCodec", "strc"),
    ("BaseSystemVolume", "csys"),
    ("Cryptex1,AppTrustCache", "trca"),
    ("Cryptex1,AppOS", "caos"),
    ("Cryptex1,AppVolume", "casy"),
    ("Cryptex1,DiskImage", "gdmg"),
    ("Cryptex1,Info", "ginf"),
    ("Cryptex1,RosettaOS", "cros"),
    ("Cryptex1,RosettaTrustCache", "trcr"),
    ("Cryptex1,RosettaVolume", "crsy"),
    ("Cryptex1,Seal", "gtgv"),
    ("Cryptex1,SystemOS", "csos"),
    ("Cryptex1,SystemTrustCache", "trcs"),
    ("Cryptex1,SystemVolume", "cssy"),
    ("Cryptex1,TrustCache", "gtcd"),
    ("Ap,RestoreDCP2", "rdc2"),
];

/// Look up the IM4P 4CC of a BuildManifest component name.
pub fn component_fourcc(component: &str) -> Option<&'static str> {
    COMPONENT_FOURCCS
        .iter()
        .find(|(name, _)| *name == component)
        .map(|(_, tag)| *tag)
}

/// The rule-evaluation parameters (libauthinstall's "parameters" dict).
#[derive(Debug, Clone, Default)]
pub struct RestoreParameters {
    /// `ApProductionMode` (also read for ApRawProductionMode /
    /// ApCurrentProductionMode conditions).
    pub production_mode: bool,
    /// `ApSecurityMode` (read for ApRawSecurityMode).
    pub security_mode: bool,
    /// `DemotionPolicy` (read for ApDemotionPolicyOverride).
    pub demotion_policy: Option<String>,
    /// `ApInRomDFU`.
    pub in_rom_dfu: bool,
}

fn plist_bool(b: bool) -> Plist {
    Plist::Bool(b)
}

fn equal_bool(p: &Plist, b: bool) -> bool {
    matches!(p, Plist::Bool(v) if *v == b)
}

/// Apply one component's `RestoreRequestRules` to its entry dict, exactly
/// like ipsw/libauthinstall:
/// * conditions map onto rule parameters (`ApRequiresImage4` is always
///   fulfilled because the IMG4 flow always uses Image4);
/// * an unknown condition name marks the whole rule unfulfilled;
/// * when conditions hold, every `Actions` bool is copied into the entry
///   (`EPRO`, `ESEC`, …).
pub fn apply_restore_request_rules(
    entry: &mut BTreeMap<String, Plist>,
    rules: &[Plist],
    params: &RestoreParameters,
) {
    for rule in rules {
        let Plist::Dict(rule_map) = rule else { continue };
        let Some(Plist::Dict(conditions)) = rule_map.get("Conditions") else {
            continue;
        };
        let mut fulfilled = true;
        for (cond_key, cond_value) in conditions {
            let param: Plist = match cond_key.as_str() {
                "ApRawProductionMode" | "ApCurrentProductionMode" => {
                    plist_bool(params.production_mode)
                }
                "ApRawSecurityMode" => plist_bool(params.security_mode),
                // IMG4-only request: always satisfied.
                "ApRequiresImage4" => Plist::Bool(true),
                "ApDemotionPolicyOverride" => match &params.demotion_policy {
                    Some(p) => Plist::Str(p.clone()),
                    None => Plist::Str(String::new()),
                },
                "ApInRomDFU" => plist_bool(params.in_rom_dfu),
                // Unknown condition ⇒ rule not fulfilled.
                _ => {
                    fulfilled = false;
                    break;
                }
            };
            let ok = match (&param, cond_value) {
                (Plist::Bool(a), Plist::Bool(b)) => a == b,
                (Plist::Str(a), Plist::Str(b)) => a == b,
                (Plist::UInt(a), Plist::UInt(b)) => a == b,
                _ => false,
            };
            if !ok {
                fulfilled = false;
                break;
            }
        }
        if fulfilled {
            if let Some(Plist::Dict(actions)) = rule_map.get("Actions") {
                for (action_key, action_value) in actions {
                    if matches!(action_value, Plist::Bool(_)) {
                        entry.insert(action_key.clone(), action_value.clone());
                    }
                }
            }
        }
    }
}

/// Build one TSS component entry (`Digest` + rule-applied `EPRO`/`ESEC`)
/// from the BuildManifest manifest component info.
///
/// * `digest` — the component's `Digest` bytes.
/// * `info` — the BuildManifest `Manifest[name].Info` dict (optional).
pub fn build_component_entry(
    digest: &[u8],
    info: Option<&Plist>,
    params: &RestoreParameters,
) -> BTreeMap<String, Plist> {
    let mut entry: BTreeMap<String, Plist> = BTreeMap::new();
    entry.insert("Digest".into(), Plist::Data(digest.to_vec()));
    if let Some(Plist::Dict(info)) = info {
        if let Some(Plist::Array(rules)) = info.get("RestoreRequestRules") {
            apply_restore_request_rules(&mut entry, rules, params);
        }
    }
    entry
}

/// Assemble the full per-component TSS request dict from a BuildManifest
/// `Manifest` (name → {Digest, Info{RestoreRequestRules,…}}) with the
/// rule engine applied. Component order is canonical (BTreeMap sort).
pub fn build_request_components(
    manifest: &BTreeMap<String, Plist>,
    params: &RestoreParameters,
) -> BTreeMap<String, Plist> {
    let mut req: BTreeMap<String, Plist> = BTreeMap::new();
    for (name, comp) in manifest {
        let Plist::Dict(comp) = comp else { continue };
        let digest = match comp.get("Digest") {
            Some(Plist::Data(d)) => d.clone(),
            _ => continue,
        };
        let info = comp.get("Info");
        req.insert(
            name.clone(),
            Plist::Dict(build_component_entry(&digest, info, params)),
        );
    }
    req
}

/// True when a component entry got `EPRO=true` after rule application —
/// the personalization gate the lane reports.
pub fn entry_is_epro(entry: &BTreeMap<String, Plist>) -> bool {
    entry.get("EPRO").map(|p| equal_bool(p, true)).unwrap_or(false)
}

/// True when a component entry got `ESEC=true` after rule application.
pub fn entry_is_esec(entry: &BTreeMap<String, Plist>) -> bool {
    entry.get("ESEC").map(|p| equal_bool(p, true)).unwrap_or(false)
}
