//! baseband — Apple iPhone 11 (T8030) baseband, Intel XMM "7660" PCIe
//! device (port of hw/misc/apple-silicon/baseband.c): three PCI BARs
//! (boot-stage / image-doorbell / RTI control register files), the DART
//! window + image download state machine, the context0 shared-memory
//! descriptor (which carries the IPC ring layout: CR/TR × HIA/TIA base
//! addresses, entry counts, doorbells and MSI vectors), the identity ROM
//! reads on BAR1 and the SMC `gP07`/`gP09`/`gP11` power/vector keys.
//!
//! Mirrored honestly from upstream:
//! * BAR0: `0x80` `ICEBBBTIDevice::updateImageDoorbell` (boot stage latch +
//!   image DMA + IRQ), `0x90` `ICEBBRTIDevice::updateControl` (bit0 engage,
//!   bit1 initCheck/context parse), `0xa0` sleep control (ignored upstream).
//! * BAR1 reads: boot stage (`0x0`), identity ROM `0x4..0x3c`
//!   (`custom_baseband0_t`: chip id 0x68, "SNUM…", cert id, "HASH…"),
//!   exit code (`0x60` = 1), MSI interrupt (`0x64..0x70` = 0), image size
//!   (`0x88`), status (`0x8c`), capability (`0xac` = 0).
//! * BAR1 writes: image address/size (`0x80/0x84/0x88`), context address
//!   (`0x90/0x94`), DART window base/limit (`0x98..0xa4`) — including the
//!   upstream quirk that the *high* half writes also OR into the low half.
//! * BAR2: completely unhandled upstream (reads/writes dropped).
//! * `baseband_bar1_rti_states_t` (DEAD/UNINIT/INIT/RUNNING/RECOVERY/ERROR)
//!   and the reset defaults of `apple_baseband_device_qdev_reset_hold`.
//! * GPIO: `baseband-gpio-coredump` input, `baseband-gpio-reset_det-out`
//!   output (level semantics: 0 means "reset detected", 1 means "alive").
//! * SMC keys gP07 (bb_on), gP09 (pmu_exton / vector enable / vector type /
//!   pmu_exton_config), gP11 (actually amfm — always BAD_FUNC_PARAMETER).
//!
//! What upstream does *not* implement (and therefore neither do we): the
//! actual IPC ring walking / SPI client protocol. The rings exist here as
//! the parsed `BasebandContext0` descriptor + DMA addresses only, exactly
//! like the C model which merely reads and logs the context.
//!
//! License: AGPL-3.0-or-later (upstream ChefKiss Inferno is AGPL-3.0).

use vm_core::{Bus, Device, DmaDevice};

// ---------------------------------------------------------------------------
// BAR geometry (baseband.c:59-69)
//
// s8000: 0x1000/0x1000 (qualcomm); t8015: 0x1000/0x400 (intel);
// t8030: 0x1000/0x1000/0x2000 (intel) — bar2 might be for msi-x.
// ---------------------------------------------------------------------------
pub const BAR0_SIZE: u64 = 0x1000;
pub const BAR1_SIZE: u64 = 0x1000;
pub const BAR2_SIZE: u64 = 0x2000;

/// Container layout of `apple_baseband_device_pci_realize`: the three BARs
/// are mapped *in reverse* into one container region ("the bars need to be
/// mapped in reverse" — baseband.c:1117-1135): bar2 @0x0, bar1 @0x2000,
/// bar0 @0x3000.
pub const BAR2_OFF: u64 = 0x0000;
pub const BAR1_OFF: u64 = 0x2000;
pub const BAR0_OFF: u64 = 0x3000;
pub const CONTAINER_SIZE: u64 = BAR2_SIZE + BAR1_SIZE + BAR0_SIZE; // 0x4000

/// `APCIE_ROOT_COMMON_ADDRESS` (hw/pci-host/apcie.h) + `BASEBAND_BAR_SUB_ADDR`
/// (`0x40000000`, baseband.c:1095) — where the container is mapped in the
/// system address space.
pub const APCIE_ROOT_COMMON_ADDRESS: u64 = 0x6_0000_0000;
pub const BASEBAND_BAR_SUB_ADDR: u64 = 0x4000_0000;
pub const BASEBAND_MMIO_BASE: u64 = APCIE_ROOT_COMMON_ADDRESS + BASEBAND_BAR_SUB_ADDR;

// PCI identity (baseband.c:1205-1213)
pub const PCI_VENDOR_ID: u16 = 0x8086; // PCI_VENDOR_ID_INTEL (t8015 && t8030)
/// intel x-gold product ids are model number plus 0; t8030
pub const PCI_DEVICE_ID: u16 = 0x7660;
pub const PCI_REVISION: u8 = 0x01;
pub const PCI_CLASS_ID: u16 = 0x0d40;

// ---------------------------------------------------------------------------
// BAR0 (RTI/BTI control)
// ---------------------------------------------------------------------------
/// `ICEBBBTIDevice::updateImageDoorbell`
pub const BAR0_IMAGE_DOORBELL: u64 = 0x80;
/// `ICEBBRTIDevice::updateControl`
pub const BAR0_CONTROL: u64 = 0x90;
pub const BAR0_CONTROL_ENGAGE: u64 = 1 << 0;
pub const BAR0_CONTROL_INIT_CHECK: u64 = 1 << 1;
/// `ICEBBRTIDevice::updateSleepControl` (ignored upstream)
pub const BAR0_SLEEP_CONTROL: u64 = 0xa0;

// ---------------------------------------------------------------------------
// BAR1 (RTI status/parameter file)
// ---------------------------------------------------------------------------
/// boot stage
pub const BAR1_BOOT_STAGE: u64 = 0x00;
/// `custom_baseband0_t` identity ROM (first/last readable offset)
pub const BAR1_IDENTITY_FIRST: u64 = 0x04;
pub const BAR1_IDENTITY_LAST: u64 = 0x3c;
/// `ICEBBRTIDevice::getImageResponse` / `ICEBBBTIDevice::getExitCode`
pub const BAR1_EXIT_CODE: u64 = 0x60;
/// `ICEBBBTIDevice::msiInterrupt` (`0x64 ... 0x70`)
pub const BAR1_MSI_INTERRUPT_FIRST: u64 = 0x64;
pub const BAR1_MSI_INTERRUPT_LAST: u64 = 0x70;
/// `ICEBBRTIDevice::getImageSize`
pub const BAR1_IMAGE_SIZE: u64 = 0x88;
/// `ICEBBRTIDevice::getStatus`
pub const BAR1_STATUS: u64 = 0x8c;
/// `ICEBBRTIDevice::getCapability`
pub const BAR1_CAPABILITY: u64 = 0xac;

// BAR1 writes
/// `ICEBBBTIDevice::updateImageAddr` (low)
pub const BAR1_IMAGE_ADDR_LO: u64 = 0x80;
/// `ICEBBBTIDevice::updateImageAddr` (high)
pub const BAR1_IMAGE_ADDR_HI: u64 = 0x84;
/// `ICEBBBTIDevice::updateImageSize`
pub const BAR1_IMAGE_SIZE_W: u64 = 0x88;
/// `ICEBBRTIDevice::updateContextAddr` (low)
pub const BAR1_CONTEXT_ADDR_LO: u64 = 0x90;
/// `ICEBBRTIDevice::updateContextAddr` (high)
pub const BAR1_CONTEXT_ADDR_HI: u64 = 0x94;
/// `ICEBBRTIDevice::updateWindowBase` (DART window base low)
pub const BAR1_WINDOW_BASE_LO: u64 = 0x98;
/// `ICEBBRTIDevice::updateWindowBase` (DART window base high)
pub const BAR1_WINDOW_BASE_HI: u64 = 0x9c;
/// `ICEBBRTIDevice::updateWindowLimit` (DART window limit low)
pub const BAR1_WINDOW_LIMIT_LO: u64 = 0xa0;
/// `ICEBBRTIDevice::updateWindowLimit` (DART window limit high; "fixed zero")
pub const BAR1_WINDOW_LIMIT_HI: u64 = 0xa4;

// ---------------------------------------------------------------------------
// RTI states (baseband_bar1_rti_states_t, baseband.c:93-101).
// All indexes are + 1 inside iOS, because e.g. dead is actually -1.
// ---------------------------------------------------------------------------
pub const STATE_DEAD: u32 = 0xFFFF_FFFF;
pub const STATE_UNINIT: u32 = 0;
pub const STATE_INIT: u32 = 1;
pub const STATE_RUNNING: u32 = 2;
pub const STATE_RECOVERY: u32 = 3;
pub const STATE_ERROR: u32 = 4;

// ---------------------------------------------------------------------------
// baseband_context0_t (baseband.c:125-155) — packed, 0x68 bytes.
//
// possible definitions: CR: Completion Ring, TR: Transfer Ring,
// TIA/HIA: ring head/tail interrupt areas (?), MCR/MTR: multi-… rings.
// IA entry size: 0x2 ; MTR/MCR entry size: 0x10.
// ---------------------------------------------------------------------------
pub const CONTEXT0_VERSION: u16 = 0x1;
pub const CONTEXT0_SIZE: u16 = 0x68;
pub const IA_ENTRY_SIZE: u32 = 0x2;
pub const MTR_MCR_ENTRY_SIZE: u32 = 0x10;

/// The IPC ring/shared-memory descriptor iOS programs via BAR1
/// `updateContextAddr` + BAR0 `updateControl` bit1 (initCheck).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BasebandContext0 {
    pub version: u16,
    pub size: u16,
    pub config: u32,
    pub peripheral_info_address: u64,
    /// CR HIA ring base
    pub cr_hia_address: u64,
    /// TR TIA ring base
    pub tr_tia_address: u64,
    /// CR TIA ring base
    pub cr_tia_address: u64,
    /// TR HIA ring base
    pub tr_hia_address: u64,
    pub cr_ia_entries: u16,
    pub tr_ia_entries: u16,
    pub mcr_address_low: u32,
    pub mcr_address_high: u32,
    pub mtr_address_low: u32,
    pub mtr_address_high: u32,
    pub mtr_entries: u16,
    pub mcr_entries: u16,
    pub mtr_doorbell: u16,
    pub mcr_doorbell: u16,
    pub mtr_msi: u16,
    pub mcr_msi: u16,
    pub mtr_header_size: u8,
    pub mtr_footer_size: u8,
    pub mcr_header_size: u8,
    pub mcr_footer_size: u8,
    /// bit0: out-of-order, bit1: in-place
    pub bit0_out_of_order__bit1_in_place: u16,
    pub peripheral_info_msi: u16,
    pub scratch_pad_address: u64,
    pub scratch_pad_size: u32,
    pub field_64: u32,
}

impl BasebandContext0 {
    pub fn zeroed() -> Self {
        Self::default()
    }

    /// Parse the little-endian, packed 0x68-byte structure (QEMU
    /// `dma_memory_read` into the struct).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < CONTEXT0_SIZE as usize {
            return None;
        }
        let u16at =
            |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32at = |o: usize| {
            u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
        };
        let u64at = |o: usize| {
            u64::from_le_bytes([
                b[o],
                b[o + 1],
                b[o + 2],
                b[o + 3],
                b[o + 4],
                b[o + 5],
                b[o + 6],
                b[o + 7],
            ])
        };
        Some(BasebandContext0 {
            version: u16at(0x00),
            size: u16at(0x02),
            config: u32at(0x04),
            peripheral_info_address: u64at(0x08),
            cr_hia_address: u64at(0x10),
            tr_tia_address: u64at(0x18),
            cr_tia_address: u64at(0x20),
            tr_hia_address: u64at(0x28),
            cr_ia_entries: u16at(0x30),
            tr_ia_entries: u16at(0x32),
            mcr_address_low: u32at(0x34),
            mcr_address_high: u32at(0x38),
            mtr_address_low: u32at(0x3c),
            mtr_address_high: u32at(0x40),
            mtr_entries: u16at(0x44),
            mcr_entries: u16at(0x46),
            mtr_doorbell: u16at(0x48),
            mcr_doorbell: u16at(0x4a),
            mtr_msi: u16at(0x4c),
            mcr_msi: u16at(0x4e),
            mtr_header_size: b[0x50],
            mtr_footer_size: b[0x51],
            mcr_header_size: b[0x52],
            mcr_footer_size: b[0x53],
            bit0_out_of_order__bit1_in_place: u16at(0x54),
            peripheral_info_msi: u16at(0x56),
            scratch_pad_address: u64at(0x58),
            scratch_pad_size: u32at(0x60),
            field_64: u32at(0x64),
        })
    }

    /// Serialize back (packed little-endian).
    pub fn to_bytes(&self) -> [u8; CONTEXT0_SIZE as usize] {
        fn w16(b: &mut [u8], o: usize, v: u16) {
            b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn w32(b: &mut [u8], o: usize, v: u32) {
            b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn w64(b: &mut [u8], o: usize, v: u64) {
            b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
        let mut b = [0u8; CONTEXT0_SIZE as usize];
        w16(&mut b, 0x00, self.version);
        w16(&mut b, 0x02, self.size);
        w32(&mut b, 0x04, self.config);
        w64(&mut b, 0x08, self.peripheral_info_address);
        w64(&mut b, 0x10, self.cr_hia_address);
        w64(&mut b, 0x18, self.tr_tia_address);
        w64(&mut b, 0x20, self.cr_tia_address);
        w64(&mut b, 0x28, self.tr_hia_address);
        w16(&mut b, 0x30, self.cr_ia_entries);
        w16(&mut b, 0x32, self.tr_ia_entries);
        w32(&mut b, 0x34, self.mcr_address_low);
        w32(&mut b, 0x38, self.mcr_address_high);
        w32(&mut b, 0x3c, self.mtr_address_low);
        w32(&mut b, 0x40, self.mtr_address_high);
        w16(&mut b, 0x44, self.mtr_entries);
        w16(&mut b, 0x46, self.mcr_entries);
        w16(&mut b, 0x48, self.mtr_doorbell);
        w16(&mut b, 0x4a, self.mcr_doorbell);
        w16(&mut b, 0x4c, self.mtr_msi);
        w16(&mut b, 0x4e, self.mcr_msi);
        b[0x50] = self.mtr_header_size;
        b[0x51] = self.mtr_footer_size;
        b[0x52] = self.mcr_header_size;
        b[0x53] = self.mcr_footer_size;
        w16(&mut b, 0x54, self.bit0_out_of_order__bit1_in_place);
        w16(&mut b, 0x56, self.peripheral_info_msi);
        w64(&mut b, 0x58, self.scratch_pad_address);
        w32(&mut b, 0x60, self.scratch_pad_size);
        w32(&mut b, 0x64, self.field_64);
        b
    }

    pub fn mcr_address(&self) -> u64 {
        self.mcr_address_low as u64 | ((self.mcr_address_high as u64) << 32)
    }

    pub fn mtr_address(&self) -> u64 {
        self.mtr_address_low as u64 | ((self.mtr_address_high as u64) << 32)
    }
}

// ---------------------------------------------------------------------------
// custom_baseband0_t (baseband.c:551-560) — 60 bytes of identity ROM.
// ---------------------------------------------------------------------------
pub const BASEBAND_IDENTITY_SIZE: usize = 60;
/// n104/d421/d431/j172/j418/d79 (iPhone 11, …) per libTelephonyUtilDynamic
pub const BASEBAND_CHIP_ID: u8 = 0x68;
/// iPhone 11 value from the wiki
pub const BASEBAND_CERT_ID: u32 = 524_245_983;

/// `custom_baseband0_t` as it is served on BAR1 `0x4 ... 0x3c`
/// (reads start at `addr - 4`, i.e. the struct begins at BAR offset 0x4).
pub fn identity_bytes() -> [u8; BASEBAND_IDENTITY_SIZE] {
    let mut b = [0u8; BASEBAND_IDENTITY_SIZE];
    // unkn0 (0x0) = 0 ; chip_id (0x2) ; unkn1 (0x3) = 0 ; pad0 zeros
    b[0x2] = BASEBAND_CHIP_ID;
    b[0xa..0x16].copy_from_slice(b"SNUMSNUMSNUM"); // ChipSerialNo/SNUM
    b[0x16..0x1a].copy_from_slice(&BASEBAND_CERT_ID.to_le_bytes()); // CertID
    b[0x1a..0x36].copy_from_slice(b"HASHHASHHASHHASHHASHHASHHASH"); // PKHASH
    // pad1 zeros
    b
}

// ---------------------------------------------------------------------------
// HMAP / L1SS PCIe capabilities (baseband.c:104-123, 235-250).
// Upstream *disables* both at reset ("HMAP might not actually be required"),
// so they are structured here but never installed by default.
// ---------------------------------------------------------------------------
pub const HMAP_CAP_SIZE: usize = 0x70;
pub const HMAP_VSEC_ID: u16 = 0x24;

#[derive(Clone, Copy, Debug, Default)]
pub struct HmapCap {
    pub vsec_id: u16,
    pub field_c_0x300f6: u32,
    /// MSI address, 4 KiB aligned, OR 0x3
    pub field_40_msi_address: u64,
    /// MSI address AND 0xffc
    pub field_4c_msi_address: u32,
    /// arg2: DART window virt, 4 KiB aligned, OR 0x3
    pub field_60_dart_window_virt: u64,
    /// arg3: 4 KiB aligned
    pub field_68_arg3: u64,
}

// ---------------------------------------------------------------------------
// SMC keys (baseband.c:685-974 + apple_baseband_create 1009-1021)
// ---------------------------------------------------------------------------
pub const SMC_RESULT_SUCCESS: u8 = 0x00;
pub const SMC_RESULT_BAD_COMMAND: u8 = 0x82;
pub const SMC_RESULT_BAD_PARAMETER: u8 = 0x83;
pub const SMC_RESULT_BAD_ARGUMENT_ERROR: u8 = 0x89;
pub const SMC_RESULT_BAD_FUNC_PARAMETER: u8 = 0xC0;

pub const SMC_KEY_GP07: [u8; 4] = *b"gP07";
pub const SMC_KEY_GP09: [u8; 4] = *b"gP09";
pub const SMC_KEY_GP11: [u8; 4] = *b"gP11";

/// function-bb_on: `AppleBasebandPlatform::setPowerOnBBPMUPinGated` (bit0 ==
/// enable)
pub const SMC_GPO7_BB_ON: u32 = 0x0080_0000;
/// bb_on write value with bit0 set (enable)
pub const SMC_GPO7_BB_ON_ENABLE: u32 = SMC_GPO7_BB_ON + 1;
/// function-pmu_exton
pub const SMC_GPO9_PMU_EXTON: u32 = 0x0200_0000;
/// `AppleSMCPMU::getVectorType`
pub const SMC_GPO9_GET_VECTOR_TYPE: u32 = 0x0600_0000;
/// disableVectorHard/IENA
pub const SMC_GPO9_DISABLE_VECTOR_HARD: u32 = 0x0400_0000;
/// enableVector/IENA
pub const SMC_GPO9_ENABLE_VECTOR: u32 = 0x0400_0001;
/// function-pmu_exton_config: `AppleBasebandPlatform::pmuExtOnConfigGated`
pub const SMC_GPO9_PMU_EXTON_CONFIG: u32 = 0x0700_0000;
/// pmu_exton_config write value with bit0 set (pull-down enabled)
pub const SMC_GPO9_PMU_EXTON_CONFIG_1: u32 = SMC_GPO9_PMU_EXTON_CONFIG + 1;

/// GPIO names (baseband.h)
pub const BASEBAND_GPIO_COREDUMP: &str = "baseband-gpio-coredump";
pub const BASEBAND_GPIO_RESET_DET_OUT: &str = "baseband-gpio-reset_det-out";

// ---------------------------------------------------------------------------
// Device state (AppleBasebandDeviceState, baseband.c:157-186)
// ---------------------------------------------------------------------------
pub struct Baseband {
    /// Latched by BAR0 `updateImageDoorbell`; read back on BAR1 `0x0`.
    pub boot_stage: u32,
    /// `ICEBBRTIDevice::getStatus` (BAR1 `0x8c`); engage sets 0x2.
    pub status: u32,
    /// Last value written to BAR0 `updateSleepControl` (upstream ignores it).
    pub sleep_control: u32,
    pub context_addr: u64,
    pub window_base_addr: u64,
    pub window_limit_addr: u64,
    pub image_addr: u64,
    pub image_size: u32,
    /// `image_ptr` — the firmware image DMA-read on the image doorbell.
    pub image: Vec<u8>,
    /// Set when `update_image_doorbell` wants a DMA fetch
    /// ([`Baseband::fetch_image_dma`]) but no bus was available.
    pub image_dma_requested: bool,
    pub context0: BasebandContext0,
    /// Context passed the version/size validation.
    pub context_valid: bool,
    /// Set by BAR0 `updateControl` bit1 (initCheck) until a context parse
    /// ([`Baseband::parse_context_dma`]) services it.
    pub context_parse_requested: bool,
    pub gpio_coredump_val: bool,
    pub gpio_reset_det_val: bool,
    /// Outgoing `baseband-gpio-reset_det-out` level (0 == reset detected).
    pub reset_det_out: bool,
    pub reset_det_edges: u64,
    pub msi_enabled: bool,
    /// Legacy INTx line level (only meaningful when `!msi_enabled`).
    pub irq_level: bool,
    /// MSI doorbell pending (only meaningful when `msi_enabled`).
    pub msi_pending: bool,
    pub irq_assertions: u64,
    /// SMC `gP07` function-bb_on power state.
    pub bb_on: bool,
    /// SMC `gP09` pmu_exton_config bit0 (pull-down enabled).
    pub pmu_exton_config_pulldown: bool,
    /// HMAP vendor-specific capability (upstream keeps it disabled).
    pub hmap: Option<HmapCap>,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Baseband {
    pub fn new() -> Self {
        Baseband {
            boot_stage: STATE_UNINIT,
            status: 0,
            sleep_control: 0,
            context_addr: 0,
            window_base_addr: 0,
            window_limit_addr: 0,
            image_addr: 0,
            image_size: 0,
            image: Vec::new(),
            image_dma_requested: false,
            context0: BasebandContext0::zeroed(),
            context_valid: false,
            context_parse_requested: false,
            gpio_coredump_val: false,
            gpio_reset_det_val: false,
            reset_det_out: false,
            reset_det_edges: 0,
            msi_enabled: false,
            irq_level: false,
            msi_pending: false,
            irq_assertions: 0,
            bb_on: false,
            pmu_exton_config_pulldown: false,
            hmap: None,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// `apple_baseband_device_qdev_reset_hold`.
    pub fn reset(&mut self) {
        // PCI_COMMAND = MEMORY | MASTER (config space, modeled as a flagless
        // no-op here).
        self.gpio_coredump_val = false;
        self.gpio_reset_det_val = false;
        self.set_reset_det(false); // 0 means 1 == reset detected

        self.boot_stage = STATE_UNINIT;
        self.status = 0x0;
        self.context_addr = 0x0;
        self.window_base_addr = 0x0;
        self.window_limit_addr = 0x0;
        self.image_addr = 0x0;
        self.image_size = 0x0;
        self.image.clear();
        self.image_dma_requested = false;
        self.context0 = BasebandContext0::zeroed();
        self.context_valid = false;
        self.context_parse_requested = false;
    }

    // -- IRQ / GPIO plumbing -------------------------------------------------

    /// `apple_baseband_set_irq`: MSI path only fires on rising level,
    /// INTx tracks the level.
    pub fn set_irq(&mut self, level: bool) {
        if self.msi_enabled {
            if level {
                self.msi_pending = true;
                self.irq_assertions += 1;
            }
        } else {
            if level && !self.irq_level {
                self.irq_assertions += 1;
            }
            self.irq_level = level;
        }
    }

    /// `baseband_gpio_coredump` — platform input gpio.
    pub fn gpio_coredump_input(&mut self, level: bool) {
        self.gpio_coredump_val = level;
    }

    /// `baseband_gpio_set_reset_det` — device drives the reset_det gpio out
    /// (0 means 1 == reset detected ; 1 means 0 == alive).
    pub fn set_reset_det(&mut self, level: bool) {
        if self.gpio_reset_det_val != level {
            self.reset_det_edges += 1;
        }
        self.gpio_reset_det_val = level;
        self.reset_det_out = level;
    }

    // -- BAR0 ------------------------------------------------------------------

    pub fn bar0_read(&mut self, _addr: u64, _size: u8) -> u64 {
        // Upstream: every BAR0 read returns 0 — nothing is handled.
        self.unknown_reads += 1;
        0
    }

    pub fn bar0_write(&mut self, addr: u64, data: u64) {
        match addr {
            BAR0_IMAGE_DOORBELL => {
                // ICEBBBTIDevice::updateImageDoorbell — new boot stage
                self.boot_stage = data as u32;
                self.update_image_doorbell();
                self.set_irq(true);
            }
            BAR0_CONTROL => {
                // ICEBBRTIDevice::updateControl
                // bit0: ICEBBRTIDevice::engage
                if data & BAR0_CONTROL_ENGAGE != 0 {
                    self.status = 0x2;
                    self.boot_stage = 0x3;
                }
                // bit1: ICEBBRTIDevice::initCheck → print/parse context info
                if data & BAR0_CONTROL_INIT_CHECK != 0 {
                    self.context_parse_requested = true;
                }
            }
            BAR0_SLEEP_CONTROL => {
                // updateSleepControl: upstream does nothing; we latch the
                // value for visibility.
                self.sleep_control = data as u32;
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    // -- BAR1 ------------------------------------------------------------------

    pub fn bar1_read(&mut self, addr: u64, _size: u8) -> u64 {
        let val: u32 = match addr {
            BAR1_BOOT_STAGE => self.boot_stage,
            BAR1_IDENTITY_FIRST..=BAR1_IDENTITY_LAST => {
                // `ldl_le_p(custom_baseband0 + addr - 0x4)`
                let t = identity_bytes();
                let off = (addr - 4) as usize;
                u32::from_le_bytes([t[off], t[off + 1], t[off + 2], t[off + 3]])
            }
            BAR1_EXIT_CODE => {
                // successExitCode: 0x1 (IOACIPCBTIDevice also accepts 0x10)
                0x1
            }
            BAR1_MSI_INTERRUPT_FIRST..=BAR1_MSI_INTERRUPT_LAST => 0x0,
            BAR1_IMAGE_SIZE => self.image_size,
            BAR1_STATUS => self.status,
            BAR1_CAPABILITY => 0x0,
            _ => {
                self.unknown_reads += 1;
                0
            }
        };
        val as u64
    }

    pub fn bar1_write(&mut self, addr: u64, data: u64) {
        let v = data & u32::MAX as u64;
        match addr {
            BAR1_IMAGE_ADDR_LO => {
                self.image_addr = (self.image_addr & 0xFFFF_FFFF_0000_0000) | v;
            }
            BAR1_IMAGE_ADDR_HI => {
                self.image_addr =
                    (self.image_addr & 0x0000_0000_FFFF_FFFF) | (v << 32);
            }
            BAR1_IMAGE_SIZE_W => {
                self.image_size = data as u32;
            }
            BAR1_CONTEXT_ADDR_LO => {
                self.context_addr =
                    (self.context_addr & 0xFFFF_FFFF_0000_0000) | v;
            }
            BAR1_CONTEXT_ADDR_HI => {
                self.context_addr =
                    (self.context_addr & 0x0000_0000_FFFF_FFFF) | (v << 32);
            }
            BAR1_WINDOW_BASE_LO | BAR1_WINDOW_BASE_HI => {
                // Upstream quirk (baseband.c:529-536): the *high* half write
                // also updates the low half — mirrored faithfully.
                self.window_base_addr =
                    (self.window_base_addr & 0xFFFF_FFFF_0000_0000) | v;
            }
            BAR1_WINDOW_LIMIT_LO | BAR1_WINDOW_LIMIT_HI => {
                // Same upstream quirk on the window limit (baseband.c:537-545).
                self.window_limit_addr =
                    (self.window_limit_addr & 0xFFFF_FFFF_0000_0000) | v;
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    // -- BAR2 ------------------------------------------------------------------

    pub fn bar2_read(&mut self, _addr: u64, _size: u8) -> u64 {
        self.unknown_reads += 1;
        0
    }

    pub fn bar2_write(&mut self, _addr: u64, _data: u64) {
        self.unknown_writes += 1;
    }

    // -- doorbell / context ----------------------------------------------------

    /// `apple_baseband_device_update_image_doorbell` — drops the stale image
    /// and records the fetch intent. The DMA itself is performed by
    /// [`Baseband::fetch_image_dma`] once the machine hands us a bus.
    pub fn update_image_doorbell(&mut self) {
        self.image.clear();
        self.image_dma_requested = false;
        if self.image_addr != 0 && self.image_size != 0 {
            self.image_dma_requested = true;
        }
    }

    /// DMA half of `apple_baseband_device_update_image_doorbell`
    /// (`dma_memory_read` of `image_size` bytes at `image_addr`).
    pub fn fetch_image_dma(&mut self, bus: &mut Bus) -> bool {
        self.image_dma_requested = false;
        if self.image_addr == 0 || self.image_size == 0 {
            return false;
        }
        let mut buf = vec![0u8; self.image_size as usize];
        DmaDevice::dma_read(self, bus, self.image_addr, &mut buf);
        self.image = buf;
        true
    }

    /// `apple_baseband_device_print_context_info` — validates and stores the
    /// context0 descriptor from a DMA snapshot (upstream asserts
    /// `version == 0x1 && size == 0x68`).
    pub fn parse_context_bytes(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        if version != CONTEXT0_VERSION
            || size != CONTEXT0_SIZE
            || (bytes.len() as u16) < size
        {
            return false;
        }
        match BasebandContext0::from_bytes(&bytes[..size as usize]) {
            Some(c) => {
                self.context0 = c;
                self.context_valid = true;
                true
            }
            None => false,
        }
    }

    /// DMA version of [`Baseband::parse_context_bytes`] against the platform
    /// bus (services `context_parse_requested`).
    pub fn parse_context_dma(&mut self, bus: &mut Bus) -> bool {
        self.context_parse_requested = false;
        if self.context_addr == 0 {
            return false;
        }
        let mut hdr = [0u8; 4];
        DmaDevice::dma_read(self, bus, self.context_addr, &mut hdr);
        let version = u16::from_le_bytes([hdr[0], hdr[1]]);
        let size = u16::from_le_bytes([hdr[2], hdr[3]]);
        if version != CONTEXT0_VERSION || size != CONTEXT0_SIZE {
            return false;
        }
        let mut buf = vec![0u8; size as usize];
        DmaDevice::dma_read(self, bus, self.context_addr, &mut buf);
        self.parse_context_bytes(&buf)
    }

    // -- SMC keys (smc_key_gP07/gP09/gP11_*) ------------------------------------

    /// SMC key read. `value` is the u32 "sub-value" the host passes in
    /// (`ldl_le_p(in)`); `Ok(None)` means SUCCESS with no data written
    /// (upstream leaves `data->data` untouched).
    pub fn smc_read(&mut self, key: [u8; 4], value: u32) -> Result<Option<u32>, u8> {
        match key {
            SMC_KEY_GP07 => Err(SMC_RESULT_BAD_FUNC_PARAMETER), // no read cases
            SMC_KEY_GP09 => match value {
                SMC_GPO9_PMU_EXTON => Ok(None), // pmu_exton
                SMC_GPO9_GET_VECTOR_TYPE => {
                    // 0x0/0x1 == "Level", else "Edge" (upstream returns 0x2)
                    Ok(Some(0x2))
                }
                _ => Err(SMC_RESULT_BAD_FUNC_PARAMETER),
            },
            // gP11 is actually for amfm (wifi/bluetooth-pcie bridge)
            SMC_KEY_GP11 => Err(SMC_RESULT_BAD_FUNC_PARAMETER),
            _ => Err(SMC_RESULT_BAD_ARGUMENT_ERROR),
        }
    }

    /// SMC key write.
    pub fn smc_write(&mut self, key: [u8; 4], value: u32) -> Result<(), u8> {
        match key {
            SMC_KEY_GP07 => match value {
                SMC_GPO7_BB_ON | SMC_GPO7_BB_ON_ENABLE => {
                    // setPowerOnBBPMUPinGated: bit0 == enable
                    self.bb_on = value & 1 != 0;
                    Ok(())
                }
                _ => Err(SMC_RESULT_BAD_FUNC_PARAMETER),
            },
            SMC_KEY_GP09 => match value {
                SMC_GPO9_DISABLE_VECTOR_HARD => Ok(()), // disableVectorHard
                SMC_GPO9_ENABLE_VECTOR => Ok(()),       // enableVector
                SMC_GPO9_PMU_EXTON_CONFIG | SMC_GPO9_PMU_EXTON_CONFIG_1 => {
                    // pmuExtOnConfigGated: bit0 == pull-down enabled.
                    // Upstream only records it (the reset_det pulsing is
                    // `#if 0` in the C).
                    self.pmu_exton_config_pulldown = value & 1 != 0;
                    Ok(())
                }
                _ => Err(SMC_RESULT_BAD_FUNC_PARAMETER),
            },
            // gP11 is actually for amfm (wifi/bluetooth-pcie bridge)
            SMC_KEY_GP11 => Err(SMC_RESULT_BAD_FUNC_PARAMETER),
            _ => Err(SMC_RESULT_BAD_ARGUMENT_ERROR),
        }
    }

    /// `apple_baseband_add_pcie_cap_hmap` — structured but never installed
    /// (upstream comments it out at reset: "HMAP might not actually be
    /// required").
    pub fn add_hmap_capability(&mut self, msi_address: u64, dart_window_virt: u64, arg3: u64) {
        self.hmap = Some(HmapCap {
            vsec_id: HMAP_VSEC_ID,
            field_c_0x300f6: 0x300f6,
            field_40_msi_address: msi_address | 0x3,
            field_4c_msi_address: (msi_address & 0xffc) as u32,
            field_60_dart_window_virt: dart_window_virt | 0x3,
            field_68_arg3: arg3,
        });
    }
}

impl Default for Baseband {
    fn default() -> Self {
        Self::new()
    }
}

/// The container region registered at `BASEBAND_MMIO_BASE` (bar2 @0x0,
/// bar1 @0x2000, bar0 @0x3000 — see `apple_baseband_device_pci_realize`).
impl Device for Baseband {
    fn name(&self) -> &'static str {
        "baseband"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        match off {
            o if o < BAR1_OFF => self.bar2_read(o, size),
            o if o < BAR0_OFF => self.bar1_read(o - BAR1_OFF, size),
            o if o < CONTAINER_SIZE => self.bar0_read(o - BAR0_OFF, size),
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        match off {
            o if o < BAR1_OFF => self.bar2_write(o, val),
            o if o < BAR0_OFF => self.bar1_write(o - BAR1_OFF, val),
            o if o < CONTAINER_SIZE => self.bar0_write(o - BAR0_OFF, val),
            _ => {
                self.unknown_writes += 1;
            }
        }
        let _ = size; // impl.min_access_size = 4 upstream; width ignored
    }
}

/// DMA-capable (image download + context parse go through the bus).
impl DmaDevice for Baseband {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use vm_core::Ram;

    #[test]
    fn reset_defaults_and_identity_rom_reads() {
        let mut bb = Baseband::new();

        // reset values (qdev_reset_hold)
        assert_eq!(bb.boot_stage, STATE_UNINIT);
        assert_eq!(bb.status, 0);
        assert!(!bb.irq_level && !bb.msi_pending);
        assert_eq!(bb.name(), "baseband");

        // BAR1 boot stage read
        assert_eq!(bb.bar1_read(BAR1_BOOT_STAGE, 4), 0);

        // identity ROM: `ldl_le_p(baseband0 + addr - 4)`
        // offset 0x0 of the struct = unkn0(0) + chip_id(0x68 @0x2)
        assert_eq!(bb.bar1_read(0x4, 4), 0x0068_0000);
        // offset 0x6 = pad0 tail (serial "SNUM…" starts at struct offset
        // 0xa, i.e. BAR offset 0xe)
        assert_eq!(bb.bar1_read(0xa, 4), 0);
        assert_eq!(bb.bar1_read(0xe, 4), u32::from_le_bytes(*b"SNUM") as u64);
        // offset 0x16 = cert id
        assert_eq!(bb.bar1_read(0x1a, 4), BASEBAND_CERT_ID as u64);
        // offset 0x1a = "HASH"
        assert_eq!(bb.bar1_read(0x1e, 4), u32::from_le_bytes(*b"HASH") as u64);
        // last readable dword (offset 0x38)
        assert_eq!(bb.bar1_read(BAR1_IDENTITY_LAST, 4), 0);

        // fixed status reads
        assert_eq!(bb.bar1_read(BAR1_EXIT_CODE, 4), 0x1); // success exit code
        assert_eq!(bb.bar1_read(0x64, 4), 0x0); // msiInterrupt
        assert_eq!(bb.bar1_read(0x70, 4), 0x0);
        assert_eq!(bb.bar1_read(BAR1_CAPABILITY, 4), 0x0);

        // image size write→read roundtrip
        bb.bar1_write(BAR1_IMAGE_SIZE_W, 0x1234);
        assert_eq!(bb.bar1_read(BAR1_IMAGE_SIZE, 4), 0x1234);

        // unhandled offsets count as unknown (BAR2 is entirely unhandled)
        assert_eq!(bb.bar1_read(0x74, 4), 0);
        assert_eq!(bb.unknown_reads, 1);
        bb.bar2_read(0x10, 4);
        assert_eq!(bb.unknown_reads, 2);
    }

    #[test]
    fn boot_flow_image_doorbell_engage_and_context_parse() {
        let mut bb = Baseband::new();

        // image address/size programming (BAR1 0x80/0x84/0x88)
        bb.bar1_write(BAR1_IMAGE_ADDR_LO, 0x0000_1000);
        bb.bar1_write(BAR1_IMAGE_ADDR_HI, 0x0000_0064);
        assert_eq!(bb.image_addr, 0x0064_0000_1000);
        bb.bar1_write(BAR1_IMAGE_SIZE_W, 8);
        assert_eq!(bb.image_size, 8);

        // DART window base/limit — upstream quirk (baseband.c:529-545): both
        // halves clear the high word and OR the value into the *low* half, so
        // a HI write clobbers the previously written LO value.
        bb.bar1_write(BAR1_WINDOW_BASE_LO, 0x1234_5678);
        bb.bar1_write(BAR1_WINDOW_BASE_HI, 0x0000_00AB);
        assert_eq!(bb.window_base_addr, 0xAB);
        bb.bar1_write(BAR1_WINDOW_LIMIT_LO, 0x9ABC_DEF0);
        bb.bar1_write(BAR1_WINDOW_LIMIT_HI, 0x0000_00CD);
        assert_eq!(bb.window_limit_addr, 0xCD);

        // context address
        bb.bar1_write(BAR1_CONTEXT_ADDR_LO, 0x0000_2000);
        bb.bar1_write(BAR1_CONTEXT_ADDR_HI, 0x0000_0064);
        assert_eq!(bb.context_addr, 0x0064_0000_2000);

        // context0 snapshot served from RAM
        let mut ctx = BasebandContext0::zeroed();
        ctx.version = CONTEXT0_VERSION;
        ctx.size = CONTEXT0_SIZE;
        ctx.cr_hia_address = 0x6400_0010_00;
        ctx.cr_ia_entries = 0x20;
        ctx.mtr_entries = 0x40;
        ctx.mtr_doorbell = 0x7;
        let ctx_bytes = ctx.to_bytes();

        // RAM backend for the DMA plumbing
        let mut ram = Ram::new("dram", 0x10000);
        ram.load_at(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]);
        ram.load_at(0x2000, &ctx_bytes);
        let mut bus = Bus::new();
        bus.attach(0x6400_0000_00, 0x10000, Box::new(ram));

        // BAR0 image doorbell: latch boot stage, (re-)request image DMA,
        // assert IRQ — then service the DMA fetch.
        bb.bar0_write(BAR0_IMAGE_DOORBELL, 0x1);
        assert_eq!(bb.boot_stage, 0x1);
        assert_eq!(bb.irq_assertions, 1);
        assert!(bb.irq_level && !bb.msi_enabled);
        assert!(bb.image_dma_requested);
        assert!(bb.fetch_image_dma(&mut bus));
        assert_eq!(bb.image, vec![0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]);

        // engage (updateControl bit0): status = 0x2, boot_stage = 0x3
        bb.bar0_write(BAR0_CONTROL, BAR0_CONTROL_ENGAGE);
        assert_eq!(bb.status, 0x2);
        assert_eq!(bb.boot_stage, 0x3);

        // initCheck (bit1) requests the context parse
        bb.bar0_write(BAR0_CONTROL, BAR0_CONTROL_INIT_CHECK);
        assert!(bb.context_parse_requested);
        assert!(bb.parse_context_dma(&mut bus));
        assert!(!bb.context_parse_requested);
        assert!(bb.context_valid);
        assert_eq!(bb.context0.cr_hia_address, 0x6400_0010_00);
        assert_eq!(bb.context0.cr_ia_entries, 0x20);
        assert_eq!(bb.context0.mtr_entries, 0x40);
        assert_eq!(bb.context0.mtr_doorbell, 0x7);
        assert_eq!(bb.context0.mcr_address(), 0);

        // bad version/size rejected (upstream asserts)
        let mut bad = ctx_bytes;
        bad[0] = 0x99;
        assert!(!bb.parse_context_bytes(&bad));

        // sleep control is latched (upstream ignores it)
        bb.bar0_write(BAR0_SLEEP_CONTROL, 0x55);
        assert_eq!(bb.sleep_control, 0x55);
    }

    #[test]
    fn container_alias_layout_device_readwrite() {
        let mut bb = Baseband::new();

        // bar1 alias at container 0x2000: image size roundtrip
        Device::write(&mut bb, BAR1_OFF + BAR1_IMAGE_SIZE_W, 4, 0xCAFE);
        assert_eq!(Device::read(&mut bb, BAR1_OFF + BAR1_IMAGE_SIZE, 4), 0xCAFE);

        // bar1 alias: boot stage after BAR0 doorbell (bar0 @0x3000)
        Device::write(&mut bb, BAR0_OFF + BAR0_IMAGE_DOORBELL, 4, 0x2);
        assert_eq!(Device::read(&mut bb, BAR1_OFF + BAR1_BOOT_STAGE, 4), 0x2);
        assert_eq!(Device::read(&mut bb, BAR1_OFF + BAR1_STATUS, 4), 0);

        // bar2 alias at container 0x0: unhandled upstream
        assert_eq!(Device::read(&mut bb, 0x10, 4), 0);
        Device::write(&mut bb, 0x10, 4, 0x1234);
        assert_eq!(bb.unknown_reads, 1);
        assert_eq!(bb.unknown_writes, 1);

        // BAR0 reads always return 0; unhandled BAR0 writes count
        assert_eq!(Device::read(&mut bb, BAR0_OFF + 0x40, 4), 0);
        Device::write(&mut bb, BAR0_OFF + 0x40, 4, 0);
        assert_eq!(bb.unknown_writes, 2);

        // beyond the container
        assert_eq!(Device::read(&mut bb, CONTAINER_SIZE + 8, 4), 0);
        assert_eq!(bb.unknown_reads, 3);
    }

    #[test]
    fn smc_power_keys_and_vector_types() {
        let mut bb = Baseband::new();

        // gP07 function-bb_on
        assert_eq!(bb.smc_write(SMC_KEY_GP07, SMC_GPO7_BB_ON_ENABLE), Ok(()));
        assert!(bb.bb_on);
        assert_eq!(bb.smc_write(SMC_KEY_GP07, SMC_GPO7_BB_ON), Ok(()));
        assert!(!bb.bb_on);
        assert_eq!(
            bb.smc_write(SMC_KEY_GP07, 0x1234),
            Err(SMC_RESULT_BAD_FUNC_PARAMETER)
        );

        // gP09 reads
        assert_eq!(bb.smc_read(SMC_KEY_GP09, SMC_GPO9_PMU_EXTON), Ok(None));
        assert_eq!(bb.smc_read(SMC_KEY_GP09, SMC_GPO9_GET_VECTOR_TYPE), Ok(Some(0x2)));
        assert_eq!(
            bb.smc_read(SMC_KEY_GP09, 0x9999),
            Err(SMC_RESULT_BAD_FUNC_PARAMETER)
        );

        // gP09 writes: vector enable/disable + pmu_exton_config
        assert_eq!(bb.smc_write(SMC_KEY_GP09, SMC_GPO9_DISABLE_VECTOR_HARD), Ok(()));
        assert_eq!(bb.smc_write(SMC_KEY_GP09, SMC_GPO9_ENABLE_VECTOR), Ok(()));
        assert_eq!(
            bb.smc_write(SMC_KEY_GP09, SMC_GPO9_PMU_EXTON_CONFIG_1),
            Ok(())
        );
        assert!(bb.pmu_exton_config_pulldown);

        // gP11 is amfm — always rejected
        assert_eq!(
            bb.smc_write(SMC_KEY_GP11, 0x1),
            Err(SMC_RESULT_BAD_FUNC_PARAMETER)
        );
        assert_eq!(
            bb.smc_read(SMC_KEY_GP11, 0x1),
            Err(SMC_RESULT_BAD_FUNC_PARAMETER)
        );

        // unknown key
        assert_eq!(
            bb.smc_write(*b"XXXX", 0),
            Err(SMC_RESULT_BAD_ARGUMENT_ERROR)
        );
    }

    #[test]
    fn gpio_reset_det_and_msi_ladder() {
        let mut bb = Baseband::new();

        // INTx path tracks the level
        bb.set_irq(true);
        assert!(bb.irq_level);
        assert_eq!(bb.irq_assertions, 1);
        bb.set_irq(true);
        assert_eq!(bb.irq_assertions, 1); // no re-assert on held level
        bb.set_irq(false);
        assert!(!bb.irq_level);

        // MSI path fires on every level=true call (msi_notify), not only on
        // edges
        bb.msi_enabled = true;
        bb.set_irq(true);
        assert!(bb.msi_pending);
        assert_eq!(bb.irq_assertions, 2);
        bb.set_irq(true);
        assert_eq!(bb.irq_assertions, 3);
        bb.msi_enabled = false;

        // reset_det gpio edges (0 == reset detected, 1 == alive)
        bb.set_reset_det(true);
        assert!(bb.reset_det_out && bb.gpio_reset_det_val);
        assert_eq!(bb.reset_det_edges, 1);
        bb.set_reset_det(true);
        assert_eq!(bb.reset_det_edges, 1);
        bb.set_reset_det(false);
        assert_eq!(bb.reset_det_edges, 2);
        bb.gpio_coredump_input(true);
        assert!(bb.gpio_coredump_val);

        // reset clears everything (qdev_reset_hold)
        bb.boot_stage = STATE_RUNNING;
        bb.status = 0x2;
        bb.image_size = 0x100;
        bb.set_reset_det(true);
        bb.reset();
        assert_eq!(bb.boot_stage, STATE_UNINIT);
        assert_eq!(bb.status, 0);
        assert_eq!(bb.image_size, 0);
        assert!(bb.image.is_empty());
        assert!(!bb.reset_det_out && !bb.gpio_reset_det_val);
        assert_eq!(bb.context0, BasebandContext0::zeroed());
        assert!(!bb.context_valid);
    }

    #[test]
    fn context0_layout_roundtrip() {
        let mut c = BasebandContext0::zeroed();
        c.version = CONTEXT0_VERSION;
        c.size = CONTEXT0_SIZE;
        c.config = 0x1234_5678;
        c.peripheral_info_address = 0x1111_1111_1111_1111;
        c.cr_hia_address = 0x2222_2222_2222_2222;
        c.tr_tia_address = 0x3333_3333_3333_3333;
        c.cr_tia_address = 0x4444_4444_4444_4444;
        c.tr_hia_address = 0x5555_5555_5555_5555;
        c.cr_ia_entries = 0x10;
        c.tr_ia_entries = 0x20;
        c.mcr_address_low = 0x6666_6666;
        c.mcr_address_high = 0x7777_7777;
        c.mtr_address_low = 0x8888_8888;
        c.mtr_address_high = 0x9999_9999;
        c.mtr_entries = 0x30;
        c.mcr_entries = 0x40;
        c.mtr_doorbell = 0x5;
        c.mcr_doorbell = 0x6;
        c.mtr_msi = 0x11;
        c.mcr_msi = 0x12;
        c.mtr_header_size = 0x13;
        c.mtr_footer_size = 0x14;
        c.mcr_header_size = 0x15;
        c.mcr_footer_size = 0x16;
        c.bit0_out_of_order__bit1_in_place = 0x2;
        c.peripheral_info_msi = 0x17;
        c.scratch_pad_address = 0xaaaa_aaaa_aaaa_aaaa;
        c.scratch_pad_size = 0x1000;
        c.field_64 = 0x64;

        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), 0x68);
        assert_eq!(&bytes[0..2], &CONTEXT0_VERSION.to_le_bytes());
        assert_eq!(&bytes[2..4], &CONTEXT0_SIZE.to_le_bytes());
        // packed offsets
        assert_eq!(&bytes[0x10..0x18], &0x2222_2222_2222_2222u64.to_le_bytes());
        assert_eq!(&bytes[0x58..0x60], &0xaaaa_aaaa_aaaa_aaaau64.to_le_bytes());
        assert_eq!(&bytes[0x64..0x68], &0x64u32.to_le_bytes());

        assert_eq!(BasebandContext0::from_bytes(&bytes), Some(c));
        assert_eq!(c.mcr_address(), 0x7777_7777_6666_6666);
        assert_eq!(c.mtr_address(), 0x9999_9999_8888_8888);

        // too-short buffer rejected
        assert_eq!(BasebandContext0::from_bytes(&bytes[..0x10]), None);

        // HMAP capability stays structured/inert like upstream
        let mut bb = Baseband::new();
        assert!(bb.hmap.is_none());
        bb.add_hmap_capability(0xF700_0000, 0x8000_0000, 0x1000);
        let h = bb.hmap.unwrap();
        assert_eq!(h.vsec_id, HMAP_VSEC_ID);
        assert_eq!(h.field_40_msi_address, 0xF700_0000 | 0x3);
        assert_eq!(h.field_60_dart_window_virt, 0x8000_0000 | 0x3);
    }
}
