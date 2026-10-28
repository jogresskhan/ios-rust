//! soc-t8030 — the named target SoC of this workspace.
//!
//! SoC:   Apple T8030 (A13 Bionic), as in iPhone 11 / 11 Pro (D42x/D43xAP,
//!        iPhone12,1..iPhone12,5 per DeviceTree `n104ap` targets in the lane).
//! CPU:   Apple "Lightning" (2 performance cores) + "Thunder" (4 efficiency
//!        cores), Apple micro-architecture on an ARMv8.4-A base — QEMU's
//!        Inferno models the cluster via its own `a13.c` CPU objects.
//! ISA:   AArch64 only (no AArch32 EL0 on T8030).

/// Machine identifier strings used by the QEMU-replacement CLI and device tree.
pub const SOC_NAME: &str = "Apple T8030 (A13 Bionic)";
pub const SOC_CODE: &str = "t8030";
pub const MACHINE_NAME: &str = "apple-t8030"; // -M apple-t8030 (drop-in)
pub const CPU_NAME: &str = "apple-a13"; // -cpu apple-a13
pub const DT_TARGET: &str = "n104ap";

/// ARMv8.4-A feature set the A13 cores implement. Each entry is a named
/// instruction/system extension the virtual CPU must decode or expose via
/// ID_AA64ISAR0/1_EL1. Parity ledger tracks every one of these.
pub const CPU_INSTRUCTIONS: &[(&str, &str)] = &[
    ("LSE", "ARMv8.1 large-system extensions: CASAL, LDADDAL, SWPAL, LDSETAL atomics"),
    ("RDM", "ARMv8.1 SQRDMLAH/SQRDMLSH rounding doubling multiply"),
    ("FCMA", "ARMv8.1 FMLA/FMLS vector complex multiply"),
    ("JSCVT", "ARMv8.1 FJCVTZS float-to-int fixed-point convert (JavaScript)"),
    ("FP16", "ARMv8.2 half-precision FP arithmetic (FCVT, FADD H-form)"),
    ("ASIMDRDM", "ARMv8.2 SIMD SQRDMLAH/SQRDMLSH element forms"),
    ("DOTPROD", "ARMv8.2/8.4 SDOT/UDOT vector dot product"),
    ("SHA512", "ARMv8.2 SHA512/HSHA512SU0/SU1"),
    ("SHA3", "ARMv8.2 EOR3/RAX1/XAR/BCAX"),
    ("SM3/SM4", "ARMv8.2 SM3SS1/SM4E crypto instructions"),
    ("AES/PMULL", "AArch64 AES (v8) + PMULL/PMULL2 64-bit polynomial (v8.2)"),
    ("CRC32", "ARMv8 CRC32B/CRC32H/CRC32W/CRC32X and CRC32CB..X"),
    ("PAC", "ARMv8.3 pointer authentication: PACIA/AUTIA/PACGA, XPACI (key A/B)"),
    ("BTI", "ARMv8.5 branch target identification (fault-on-land behavior modeled)"),
    ("CSV2/CSV3", "ARMv8.3 speculative constraints exposed as RES1 in ID regs"),
    ("AMUv1", "ARMv8.4 activity monitor unit registers (AMCNTEN0/1, AMEVCNTR)"),
    ("MPAM", "ARMv8.4 memory partitioning monitoring id registers (RES0-exposed)"),
    ("TLBI Ranges", "ARMv8.4 range TLBI (TLBIRANGE) invalidate forms"),
    ("DGH/DOT", "ARMv8.4 data gathering hint (DGH) + SIMD DOT (I8MM pending verify)"),
    ("FCADD", "ARMv8.4 vector FCADD (complex rotate) forms"),
];

/// What the virtualization lib provides for each instruction group today.
/// 100% = decoded+executed with golden-trace parity; 90 = decode+exec
/// verified against external-oracle goldens (Capstone/Keystone-assembled
/// encodings + standard test vectors); 75 = decode+exec with structural
/// (non-oracle) encodings; lower = decode-only/stub.
///
/// Every group ≥75 is EXECUTED by the pure-Rust interpreter
/// (`a13_cpu::interp::Interpreter::group_exec` counts per-group retire);
/// see `a13-cpu/tests/parity_exec.rs` for the end-to-end proofs.
pub const CPU_INSTRUCTION_PARITY: &[(&str, u8)] = &[
    // decode: golden-verified (capstone layout probe) · exec: semantic tests
    // (CRC-32/ISO-HDLC + CRC-32C check values 0xCBF43926/0xE3069283)
    ("CRC32", 90),
    // decode: golden (capstone 4E284800-family) · exec: FIPS-197 C.1 round
    ("AES/PMULL", 90),
    // decode: empirical layout probe (Rs/op4/A/R fields) · exec: LDADD/SWP/CAS
    ("LSE", 90),
    // decode: golden (vector forms) · exec: saturating doubling round tests
    ("RDM", 85),
    ("ASIMDRDM", 85),
    // decode: golden vector forms; by-element structural · exec: FCMLA rot table
    ("FCMA", 80),
    // decode: (op6,size) pairs golden · exec: f16 RTNE arithmetic
    ("FP16", 85),
    // decode: golden (0x25 op6) · exec: SDOT/UDOT lane sums
    ("DOTPROD", 85),
    // decode: golden (CE628020 family) · exec: σ/Σ round fragments
    ("SHA512", 85),
    // decode: golden (EOR3/RAX1/XAR/BCAX) · exec: lane XOR/rotate tests
    ("SHA3", 85),
    // decode: golden (SM3SS1/PARTW/TT/SM4E/KEY) · exec: GB/T round helpers
    ("SM3/SM4", 80),
    // decode: golden (QEMU 0x1c/0x1d case anchoring) · exec: scalar doubling
    ("PAC", 80),
    // decode: full hint-space scan (D503245F family) · exec: counted no-op
    ("BTI", 85),
    // ID_AA64PFR0_EL1.CSV2/CSV3 exposed RES1-modeled in the sysreg table
    ("CSV2/CSV3", 75),
    // decode: capstone sysreg scan (D53BD2A0 family) · exec: MRS/MSR state
    ("AMUv1", 80),
    // decode: capstone sysreg scan (D538A520 family) · exec: MRS/MSR state
    ("MPAM", 80),
    // decode: capstone MSR-space scan (24 range forms) · exec: operand decode
    ("TLBI Ranges", 85),
    // decode: hint-space scan (D50320DF) · exec: counted no-op
    ("DGH/DOT", 80),
    // decode: golden (6E82E420 family) · exec: rotate-and-add table
    ("FCADD", 80),
    // JSCVT: decode golden (1E7E0020) · exec: ToInt32 wrap semantics
    ("JSCVT", 90),
];

/// High-level memory map landmarks (Inferno `hw/arm/apple-silicon/t8030.c`).
/// Exact addresses are kept symbolic here; `memmap::LANDMARKS` records the
/// authoritative source files in the research repos so ports verify against
/// them instead of hard-coding half-remembered constants.
pub mod memmap {
    /// (name, mmio_base_source, note) — resolve from the pinned engine source.
    pub const LANDMARKS: &[(&str, &str, &str)] = &[
        ("AIC v2", "hw/intc/apple_aic.c", "interrupt controller, 8 set/clr regs + HW/SW die sets"),
        ("PMGR", "t8030-config.c.inc", "clock gates/voltages; guest drivers walk the ADT"),
        ("DART", "hw/misc/apple-silicon/dart.c", "IOMMU: TCR/TTBR + 4-level PTE walker"),
        ("ANS2/NVMe", "hw/block/apple-silicon/ans.c", "storage; boots the restore ramdisk path"),
        ("ADP v4", "hw/display/apple_displaypipe_v4.c", "DisplayPipe GenPipe scanout"),
        ("MIPI-DSI", "hw/display/synopsys_mipi_dsim.c", "187-line stub upstream — our #1 gap"),
        ("UART", "hw/char/apple_uart.c", "serial console (lab16 glog source)"),
        ("AOP", "hw/misc/apple-silicon/aop.c", "always-on processor shim"),
        ("SMC", "hw/misc/apple-silicon/smc.c", "system management (LGPL-2.1 origin)"),
        ("AES engine", "hw/misc/apple-silicon/aes.c", "AES-XTS storage oracle"),
        ("SEP + SEP-SIM", "hw/misc/apple-silicon/sep.c, sep-sim.c", "real SePOS fw on dedicated core / control-op sim"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_identifiers() {
        assert_eq!(SOC_CODE, "t8030");
        assert_eq!(MACHINE_NAME, "apple-t8030");
        assert!(CPU_INSTRUCTIONS.iter().any(|(n, _)| *n == "PAC"));
        assert!(CPU_INSTRUCTIONS.len() >= 18);
        assert!(memmap::LANDMARKS.len() >= 11);
    }
}
