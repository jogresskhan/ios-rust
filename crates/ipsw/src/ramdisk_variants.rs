//! Ramdisk variant matrix — the M2 bisection, as first-class library code.
//! Mirrors `lanes/t8030-inferno/scripts/ios14-diag.sh` semantics exactly so
//! the Rust emulator path reproduces the same experiment (and its verdicts).

/// The 8 variants: what they contain and what run #74 measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamdiskVariant {
    V0Stock,
    V7Raw,
    V5Convert,
    V1Full,
    V3Bins,
    V2Plist,
    V8Rewrap,
    V4Fresh,
}

pub struct VariantInfo {
    pub id: &'static str,
    pub description: &'static str,
    /// Run 40593862961 measured verdict (partial artifact).
    pub verdict74: &'static str,
}

impl RamdiskVariant {
    pub fn info(&self) -> VariantInfo {
        match self {
            Self::V0Stock => VariantInfo {
                id: "v0-stock",
                description: "staged im4p untouched (control)",
                verdict74: "PASS verify_storage + full 5GB push",
            },
            Self::V7Raw => VariantInfo {
                id: "v7-raw",
                description: "pyimg4 payload saved raw, hdiutil never touches it",
                verdict74: "PASS verify_storage + full 5GB push",
            },
            Self::V5Convert => VariantInfo {
                id: "v5-convert",
                description: "hdiutil convert UDRW + attach rw + detach, no file changes",
                verdict74: "ASR-CONNECT-FAIL (0x065B asr_and_invert_image)",
            },
            Self::V1Full => VariantInfo {
                id: "v1-full",
                description: "convert + replace usbcfwflasher/peppytool + rewrite syslogd config",
                verdict74: "ASR-CONNECT-FAIL (0x065B asr_and_invert_image)",
            },
            Self::V3Bins => VariantInfo {
                id: "v3-bins",
                description: "convert + ONLY the two binaries",
                verdict74: "PASS verify_storage + full 5GB push",
            },
            Self::V2Plist => VariantInfo {
                id: "v2-plist",
                description: "convert + ONLY the plist rewrite",
                verdict74: "cancelled mid-copy ~70%",
            },
            Self::V8Rewrap => VariantInfo {
                id: "v8-rewrap",
                description: "v1 image rewrapped as im4p (rdsk) — distinguishes container from content",
                verdict74: "not reached",
            },
            Self::V4Fresh => VariantInfo {
                id: "v4-fresh",
                description: "brand-new hdiutil HFSX volume with stock files + our mods",
                verdict74: "not reached",
            },
        }
    }

    /// Build order used by ios14-diag.sh (run #74 partial coverage).
    pub fn diag_order() -> Vec<Self> {
        vec![
            Self::V0Stock,
            Self::V7Raw,
            Self::V5Convert,
            Self::V1Full,
            Self::V3Bins,
            Self::V2Plist,
            Self::V8Rewrap,
            Self::V4Fresh,
        ]
    }

    /// Refocused set (commit 2156ae0) — ASR-stage discriminators.
    pub fn refocused_set() -> Vec<Self> {
        vec![Self::V0Stock, Self::V1Full, Self::V5Convert, Self::V4Fresh]
    }
}

/// Bisection conclusion of run #74, codified.
pub const BISECTION_VERDICT_74: &str =
    "PREMISE REFUTED: every variant that reached verify_storage_for_update \
     PASSED (incl. stock); ramdisk modifications are not the blocker. The \
     frontier is the ASR-connection stage (0x065B) and post-push stages.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_and_verdict() {
        assert_eq!(RamdiskVariant::diag_order().len(), 8);
        assert_eq!(RamdiskVariant::refocused_set().len(), 4);
        assert!(BISECTION_VERDICT_74.contains("REFUTED"));
        assert!(RamdiskVariant::V0Stock.info().verdict74.contains("PASS"));
        assert!(RamdiskVariant::V1Full.info().verdict74.contains("0x065B"));
    }
}
