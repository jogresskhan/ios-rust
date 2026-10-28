//! apcie — Apple PCIe root complex.
//!
//! Port of ChefKiss Inferno `hw/pci-host/apcie.c` (AGPL-3.0): the Apple
//! port-controller register file (LTSSM enable, port config, link status
//! with L2 handshake, port interrupt status/mask, MSI vector register +
//! address, hot-reset semantics, RID→SID map), the root-common register
//! block with its init-sequence side effects, the root PHY enable bits,
//! the MSI doorbell bank and the ECAM bus/dev/fn decode. The synthesized
//! root-port config space from the original port is preserved (legacy
//! `cfg` map at offsets the port file does not claim).
//!
//! Region mapping for the flat [`Device`] window: 0x0000..0x0800 keeps the
//! legacy root-port config behavior; every upstream port-register offset
//! (0x80 LTSSM … 0x828-0x924 RID/SID) takes precedence where it exists.

use std::collections::BTreeMap;

use vm_core::Device;

pub const APCIE_ECAM_BASE_OFF: u64 = 0x0000; // relative window base

// --- port register offsets (apple_pcie_port_config_read/write) ---
pub const PORT_LTSSM_ENABLE: u64 = 0x080; // bit0 = LTSSM enable
pub const PORT_LINKSTS_S8000: u64 = 0x088; // S800x link status
pub const PORT_PME_TO_ACK: u64 = 0x08C;
pub const PORT_LAST_INTERRUPT: u64 = 0x100; // pcielint / getPortInterrupts
pub const PORT_INTERRUPT_MASK: u64 = 0x104;
pub const PORT_MSI_UNKNOWN0: u64 = 0x128;
pub const PORT_HOTRESET: u64 = 0x13C; // bit8 = hot reset
pub const PORT_MSI_ADDR_LO: u64 = 0x168;
pub const PORT_MSI_INTR0_ENABLE: u64 = 0x124; // msiVectors
pub const PORT_LINKSTS_T8030: u64 = 0x208; // getLinkUp / isLinkInL2
pub const PORT_LINKCDMSTS: u64 = 0x210; // W1C
pub const PORT_CFG_PORT_CONFIG: u64 = 0x800; // bit0 = enable port
pub const PORT_CFG_PORT_STATUS: u64 = 0x804; // bit0 = port status ready
pub const PORT_CFG_REFCLK_CONFIG: u64 = 0x810;
pub const PORT_CFG_ROOTPORT_PERST: u64 = 0x814;
pub const PORT_RID_SID_MAP_BASE: u64 = 0x828;
pub const PORT_RID_SID_MAP_END: u64 = 0x924; // exclusive
pub const PORT_RID_SID_MAP_SLOTS: usize = ((PORT_RID_SID_MAP_END - PORT_RID_SID_MAP_BASE) / 4) as usize;

// interrupt bits observed in PORT_LAST_INTERRUPT (comments in apcie.c)
pub const PORT_IRQ_LINK_UP: u32 = 0x1000;
pub const PORT_IRQ_LINK_DOWN: u32 = 0x4000;

// MSI doorbell: interrupt index is data % 8
pub const APCIE_NUM_MSI_BANKS: usize = 8;

// --- root-common block (apple_pcie_root_common_read/write) ---
pub const ROOT_COMMON_REFCLK_GOOD: u64 = 0x028; // reads 0x10 (refclk good)
pub const ROOT_COMMON_MAGIC_1AC: u64 = 0x1AC; // reads 1 (S8000)
pub const ROOT_COMMON_MAGIC_22C: u64 = 0x22C; // reads 1 (S8000)
pub const ROOT_COMMON_INIT_KEY: u64 = 0x004; // write 0x11 kicks the init seq
pub const ROOT_COMMON_INIT_KEY_VAL: u64 = 0x11;
pub const ROOT_COMMON_CLKREQ: u64 = 0x038; // write 1 raises clkreq GPIOs

// --- root PHY block (apple_pcie_host_root_phy_read/write) ---
pub const ROOT_PHY_ENABLE: u64 = 0x0;
pub const ROOT_PHY_REFCLK_BUFFER: u64 = 0x10000;

// --- LTSSM debug block ---
pub const LTSSM_DEBUG_STATUS: u64 = 0x30;
pub const LTSSM_DEBUG_KICK: u64 = 0x38; // write bit0 → status 0x1000 (link up)
pub const LTSSM_STATUS_LINK_UP: u32 = 0x1000;

/// ECAM decode exactly as `apple_pcie_root_conf_access`: function = (addr %
/// 0x8000) / 0x1000, device = addr / 0x8000, bus = device / 32.
pub fn decode_ecam(addr: u64) -> (u8, u8, u8) {
    let function = ((addr % 0x8000) / 0x1000) as u8;
    let device = addr / 0x8000;
    let bus = (device / 32) as u8;
    let dev = (device % 32) as u8;
    (bus, dev, function)
}

/// One PCIe port controller (`ApplePCIEPort` registers).
#[derive(Debug)]
pub struct ApciePort {
    pub bus_nr: u8,
    pub ltssm_enable: u32,
    pub pme_to_ack: u32,
    pub last_interrupt: u32,
    pub interrupt_mask: u32,
    pub msi_unknown0: u32,
    pub hotreset: u32,
    pub msi_base: u64,
    pub msi_vectors: u32,
    /// per-bank enable masks updated by PORT_MSI_INTR0_ENABLE writes
    pub msi_enable_mask: [u32; APCIE_NUM_MSI_BANKS],
    pub linkcdmsts: u32,
    pub cfg_port_config: u32,
    pub cfg_refclk_config: u32,
    pub cfg_rootport_perst: u32,
    pub rid_sid_map: [u32; PORT_RID_SID_MAP_SLOTS],
    pub is_link_in_l2: bool,
}

impl Default for ApciePort {
    fn default() -> Self {
        ApciePort {
            bus_nr: 0,
            ltssm_enable: 0,
            pme_to_ack: 0,
            last_interrupt: 0,
            interrupt_mask: 0,
            msi_unknown0: 0,
            hotreset: 0,
            msi_base: 0,
            msi_vectors: 0,
            msi_enable_mask: [0; APCIE_NUM_MSI_BANKS],
            linkcdmsts: 0,
            cfg_port_config: 0,
            cfg_refclk_config: 0,
            cfg_rootport_perst: 0,
            rid_sid_map: [0; PORT_RID_SID_MAP_SLOTS],
            is_link_in_l2: false,
        }
    }
}

pub struct Apcie {
    /// cfg addr → dword (root port + bridges synthesized) — legacy surface
    pub cfg: BTreeMap<u64, u32>,
    pub config_cycles: u64,
    pub unknown_reads: u64,

    // upstream state
    pub port: ApciePort,
    /// false = T8030-style link status (0x208); true = S8000-style (0x88)
    pub chip_is_s8000: bool,
    /// root-common register file (sparse)
    pub root_common_regs: BTreeMap<u64, u32>,
    pub root_phy_enabled: u32,
    pub root_refclk_buffer_enabled: u32,
    /// MSI doorbell counters (bank = data % 8)
    pub msi_fired: [u64; APCIE_NUM_MSI_BANKS],
    /// port IRQ line level (set_own_irq)
    pub irq_level: bool,
    /// LTSSM debug status (0x30)
    pub ltssm_status: u32,
    /// clkreq GPIO value (set by the 0x38 root-common write)
    pub clkreq_gpio: bool,
}

impl Apcie {
    pub fn new() -> Self {
        let mut c = Apcie {
            cfg: BTreeMap::new(),
            config_cycles: 0,
            unknown_reads: 0,
            port: ApciePort { bus_nr: 1, ..Default::default() },
            chip_is_s8000: false,
            root_common_regs: BTreeMap::new(),
            root_phy_enabled: 0,
            root_refclk_buffer_enabled: 0,
            msi_fired: [0; APCIE_NUM_MSI_BANKS],
            irq_level: false,
            ltssm_status: 0,
            clkreq_gpio: false,
        };
        // Root port vendor/device (Apple, ANS2-attached)
        c.cfg.insert(0x00, 0x1420_0000 | (0x14 << 16));
        c.cfg.insert(0x04, 0x0010_0407); // status|command: mem+bus master
        c.cfg.insert(0x08, 0x0604_0000); // class: PCI bridge
        c
    }

    // ---- root-common block ----

    /// `apple_pcie_root_common_read`
    pub fn root_common_read(&mut self, addr: u64) -> u64 {
        match addr {
            0x24 => 0xFFFF_FFFF, // TODO upstream: for T8015
            0x28 => 0x10,        // refclk good; for T8030
            0x1AC => 0x1,        // for S8000
            0x22C => 0x1,        // for S8000
            _ => self.root_common_regs.get(&addr).copied().unwrap_or(0) as u64,
        }
    }

    /// `apple_pcie_root_common_write`
    pub fn root_common_write(&mut self, addr: u64, data: u32) {
        match addr {
            0x4 => {
                if data as u64 == ROOT_COMMON_INIT_KEY_VAL {
                    self.root_common_regs.insert(0x114, 0x100);
                    self.root_common_regs.insert(0x2C, 0x1); // for S8000/N66AP
                    self.root_common_regs.insert(0x12C, 0x1);
                }
            }
            0x38 => {
                if data == 1 {
                    // for S8000/N66AP
                    let v = self.root_common_regs.get(&0x2C).copied().unwrap_or(0);
                    self.root_common_regs.insert(0x2C, v | 0x10);
                    self.clkreq_gpio = true; // apcie_port_gpio_set_clkreq(1)
                }
            }
            0x114 => {
                // upstream: 0x101 write has S8003-specific side effects
            }
            _ => {}
        }
        self.root_common_regs.insert(addr, data);
    }

    // ---- root PHY block ----

    /// `apple_pcie_host_root_phy_read`
    pub fn root_phy_read(&self, addr: u64) -> u64 {
        match addr {
            ROOT_PHY_ENABLE => self.root_phy_enabled as u64,
            ROOT_PHY_REFCLK_BUFFER => self.root_refclk_buffer_enabled as u64,
            _ => 0,
        }
    }

    /// `apple_pcie_host_root_phy_write`: enable bits propagate
    /// (bit0→bit2, bit1→bit3; refclk: bit0→bit2, bit1→bit1 i.e. no-op).
    pub fn root_phy_write(&mut self, addr: u64, mut data: u32) {
        match addr {
            ROOT_PHY_ENABLE => {
                if data & (1 << 0) != 0 {
                    data |= 1 << 2;
                }
                if data & (1 << 1) != 0 {
                    data |= 1 << 3;
                }
                self.root_phy_enabled = data;
            }
            ROOT_PHY_REFCLK_BUFFER => {
                if data & (1 << 0) != 0 {
                    data |= 1 << 2;
                }
                if data & (1 << 1) != 0 {
                    data |= 1 << 1; // yes, REALLY bit1
                }
                self.root_refclk_buffer_enabled = data;
            }
            _ => {}
        }
    }

    // ---- port block ----

    fn is_port_enabled(&self) -> bool {
        self.port.cfg_port_config & 1 != 0
    }

    /// `apple_pcie_port_config_read`; None when the offset is not a port
    /// register (the legacy root-port config space answers instead).
    pub fn port_read(&mut self, addr: u64) -> Option<u64> {
        match addr {
            PORT_LTSSM_ENABLE => Some(self.port.ltssm_enable as u64),
            PORT_PME_TO_ACK => Some(self.port.pme_to_ack as u64),
            PORT_LAST_INTERRUPT => {
                // don't reset the value here, iOS clears it via W1C
                Some(self.port.last_interrupt as u64)
            }
            PORT_INTERRUPT_MASK => Some(self.port.interrupt_mask as u64),
            PORT_MSI_ADDR_LO => Some(self.port.msi_base as u64),
            PORT_MSI_INTR0_ENABLE => Some(self.port.msi_vectors as u64),
            PORT_MSI_UNKNOWN0 => Some(self.port.msi_unknown0 as u64),
            PORT_HOTRESET => Some(self.port.hotreset as u64),
            PORT_LINKSTS_S8000 if self.chip_is_s8000 => {
                let link_up = self.port.ltssm_enable & 1 != 0;
                let v = link_up as u64 | ((self.port.is_link_in_l2 as u64) << 6);
                self.port.is_link_in_l2 = false;
                Some(v)
            }
            PORT_LINKSTS_T8030 if !self.chip_is_s8000 => {
                let link_up = self.is_port_enabled();
                let v = link_up as u64 | ((self.port.is_link_in_l2 as u64) << 6);
                self.port.is_link_in_l2 = false;
                Some(v)
            }
            PORT_LINKCDMSTS => Some(self.port.linkcdmsts as u64),
            PORT_CFG_PORT_CONFIG => Some(self.port.cfg_port_config as u64),
            PORT_CFG_PORT_STATUS => Some(self.is_port_enabled() as u64),
            PORT_CFG_REFCLK_CONFIG => Some(self.port.cfg_refclk_config as u64),
            PORT_CFG_ROOTPORT_PERST => Some(self.port.cfg_rootport_perst as u64),
            PORT_RID_SID_MAP_BASE..PORT_RID_SID_MAP_END => {
                let sid_0 = ((addr - PORT_RID_SID_MAP_BASE) >> 2) as usize;
                Some(self.port.rid_sid_map[sid_0] as u64)
            }
            _ => None,
        }
    }

    /// `apple_pcie_port_config_write`; returns true when handled.
    pub fn port_write(&mut self, addr: u64, data: u32) -> bool {
        match addr {
            PORT_LTSSM_ENABLE => {
                self.port.ltssm_enable = data;
                if data & 1 != 0 {
                    // link-up interrupt
                    self.port.last_interrupt |= PORT_IRQ_LINK_UP;
                    self.set_own_irq(true);
                }
                true
            }
            PORT_PME_TO_ACK => {
                // t8030 writes 0x11, s8000 0x31; bit4+bit0 ⇒ L2 entry
                self.port.pme_to_ack = data;
                if data & (1 << 4) != 0 && data & (1 << 0) != 0 {
                    self.port.is_link_in_l2 = true;
                }
                self.port.pme_to_ack &= !((1 << 5) | (1 << 0));
                true
            }
            PORT_LAST_INTERRUPT => {
                // clearLinkUpInterrupt/clearPortInterrupts (W1C, not xor)
                self.port.last_interrupt &= !data;
                self.set_own_irq(false);
                true
            }
            PORT_INTERRUPT_MASK => {
                self.port.interrupt_mask = data;
                true
            }
            PORT_MSI_UNKNOWN0 => {
                self.port.msi_unknown0 = data;
                true
            }
            PORT_HOTRESET => {
                self.port.hotreset = data;
                if data & 0x100 != 0 {
                    self.port.last_interrupt |= PORT_IRQ_LINK_DOWN;
                    self.set_own_irq(true);
                }
                true
            }
            PORT_LINKCDMSTS => {
                self.port.linkcdmsts &= !data;
                true
            }
            PORT_CFG_PORT_CONFIG => {
                self.port.cfg_port_config = data;
                true
            }
            PORT_CFG_REFCLK_CONFIG => {
                self.port.cfg_refclk_config = data;
                true
            }
            PORT_CFG_ROOTPORT_PERST => {
                self.port.cfg_rootport_perst = data;
                true
            }
            PORT_MSI_ADDR_LO => {
                self.port.msi_base = (self.port.msi_base & 0xFFFF_FFFF_0000_0000) | data as u64;
                true
            }
            PORT_MSI_INTR0_ENABLE => {
                // 0x31: 8 vectors, 0x51: 32, 0x21: 4, 0x11: 2, 0x1: 1 …
                self.port.msi_vectors = data;
                let enable = data & 1 != 0;
                let vectors = 1u32 << ((data & 0xF0) >> 4);
                let vector_mask = (1u32.checked_shl(vectors).unwrap_or(0)).wrapping_sub(1);
                if enable {
                    self.port.msi_enable_mask[0] |= vector_mask;
                } else {
                    self.port.msi_enable_mask[0] &= !vector_mask;
                }
                true
            }
            PORT_RID_SID_MAP_BASE..PORT_RID_SID_MAP_END => {
                let sid_0 = ((addr - PORT_RID_SID_MAP_BASE) >> 2) as usize;
                self.port.rid_sid_map[sid_0] = data;
                true
            }
            _ => false,
        }
    }

    /// `apple_pcie_set_own_irq`
    fn set_own_irq(&mut self, level: bool) {
        // handling this, it might trigger interrupts on unmask otherwise
        self.port.last_interrupt &= !self.port.interrupt_mask;
        self.irq_level = level;
    }

    /// MSI doorbell write (`apple_pcie_port_msi_write`): the interrupt
    /// index is `data % 8`.
    pub fn msi_write(&mut self, data: u32) {
        let index = (data % 8) as usize;
        self.msi_fired[index] += 1;
    }

    /// LTSSM debug block (`apple_pcie_port_config_ltssm_debug_*`).
    pub fn ltssm_debug_read(&self, addr: u64) -> u64 {
        match addr {
            LTSSM_DEBUG_STATUS => self.ltssm_status as u64,
            _ => 0,
        }
    }
    pub fn ltssm_debug_write(&mut self, addr: u64, data: u32) {
        if addr == LTSSM_DEBUG_KICK && data & 1 != 0 {
            self.ltssm_status = LTSSM_STATUS_LINK_UP;
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("ECAM", APCIE_ECAM_BASE_OFF),
            ("PORT_LTSSM_ENABLE", PORT_LTSSM_ENABLE),
            ("PORT_LINKSTS_T8030", PORT_LINKSTS_T8030),
            ("PORT_PME_TO_ACK", PORT_PME_TO_ACK),
            ("PORT_LAST_INTERRUPT", PORT_LAST_INTERRUPT),
            ("PORT_INTERRUPT_MASK", PORT_INTERRUPT_MASK),
            ("PORT_HOTRESET", PORT_HOTRESET),
            ("PORT_MSI_ADDR_LO", PORT_MSI_ADDR_LO),
            ("PORT_MSI_INTR0_ENABLE", PORT_MSI_INTR0_ENABLE),
            ("PORT_LINKCDMSTS", PORT_LINKCDMSTS),
            ("PORT_CFG_PORT_CONFIG", PORT_CFG_PORT_CONFIG),
            ("PORT_CFG_REFCLK_CONFIG", PORT_CFG_REFCLK_CONFIG),
            ("PORT_CFG_ROOTPORT_PERST", PORT_CFG_ROOTPORT_PERST),
            ("PORT_RID_SID_MAP", PORT_RID_SID_MAP_BASE),
        ]
    }
}

impl Default for Apcie {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Apcie {
    fn name(&self) -> &'static str {
        "apcie"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        // off here is the port/window-relative config offset (the machine
        // maps the ECAM/port window onto this device)
        self.config_cycles += 1;
        if let Some(v) = self.port_read(off) {
            return v;
        }
        self.cfg.get(&(off & !0x3)).copied().unwrap_or(0xFFFF_FFFF) as u64
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if self.port_write(off, val as u32) {
            return;
        }
        if off == 0x04 {
            self.cfg.insert(0x04, (val & 0xFFFF) as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_common_magic_reads_and_init_sequence() {
        let mut a = Apcie::new();
        assert_eq!(a.root_common_read(0x24), 0xFFFF_FFFF);
        assert_eq!(a.root_common_read(0x28), 0x10); // refclk good (T8030)
        assert_eq!(a.root_common_read(0x1AC), 1); // S8000
        assert_eq!(a.root_common_read(0x22C), 1); // S8000
        // the 0x11 init sequence
        a.root_common_write(0x4, 0x11);
        assert_eq!(a.root_common_read(0x114), 0x100);
        assert_eq!(a.root_common_read(0x2C), 0x1);
        assert_eq!(a.root_common_read(0x12C), 0x1);
        // 0x38 = 1: clkreq GPIOs raised + 0x2C |= 0x10
        a.root_common_write(0x38, 1);
        assert!(a.clkreq_gpio);
        assert_eq!(a.root_common_read(0x2C), 0x11);
        // generic store
        a.root_common_write(0x1000, 0xABCD);
        assert_eq!(a.root_common_read(0x1000), 0xABCD);
        // PHY enable bit propagation
        a.root_phy_write(ROOT_PHY_ENABLE, 0b011);
        assert_eq!(a.root_phy_enabled, 0b1111);
        a.root_phy_write(ROOT_PHY_REFCLK_BUFFER, 0b01);
        assert_eq!(a.root_refclk_buffer_enabled, 0b101);
    }

    #[test]
    fn port_enable_link_up_and_interrupt_flow() {
        let mut a = Apcie::new();
        // enable the port then bring the LTSSM up
        a.write(PORT_CFG_PORT_CONFIG, 4, 1);
        a.write(PORT_LTSSM_ENABLE, 4, 1);
        assert!(a.irq_level);
        assert_eq!(a.read(PORT_LAST_INTERRUPT, 4) as u32 & PORT_IRQ_LINK_UP, PORT_IRQ_LINK_UP);
        // T8030 link status: linkup follows port enable; L2 bit transient
        let lsts = a.read(PORT_LINKSTS_T8030, 4);
        assert_eq!(lsts & 1, 1);
        assert_eq!(a.read(PORT_CFG_PORT_STATUS, 4), 1);
        // PME→ACK handshake with L2 entry semantics (0x31: bits4+0)
        a.write(PORT_PME_TO_ACK, 4, 0x31);
        assert!(a.port.is_link_in_l2);
        assert_eq!(a.read(PORT_PME_TO_ACK, 4), 0x10); // bits 5|0 cleared
        // hot reset raises link-down interrupt
        a.write(PORT_HOTRESET, 4, 0x100);
        assert_eq!(
            a.read(PORT_LAST_INTERRUPT, 4) as u32 & PORT_IRQ_LINK_DOWN,
            PORT_IRQ_LINK_DOWN
        );
        // W1C clears and drops the line
        let pending = a.read(PORT_LAST_INTERRUPT, 4) as u32;
        a.write(PORT_LAST_INTERRUPT, 4, pending as u64);
        assert!(!a.irq_level);
        assert_eq!(a.read(PORT_LAST_INTERRUPT, 4), 0);
        // LTSSM debug kick
        a.ltssm_debug_write(LTSSM_DEBUG_KICK, 1);
        assert_eq!(a.ltssm_debug_read(LTSSM_DEBUG_STATUS), LTSSM_STATUS_LINK_UP as u64);
        // linkcdmsts is W1C
        a.port.linkcdmsts = 0xFF;
        a.write(PORT_LINKCDMSTS, 4, 0x0F);
        assert_eq!(a.read(PORT_LINKCDMSTS, 4), 0xF0);
    }

    #[test]
    fn msi_decode_rid_sid_map_and_legacy_cfg() {
        let mut a = Apcie::new();
        // MSI vector enable: 0x31 → 8 vectors enabled
        a.write(PORT_MSI_INTR0_ENABLE, 4, 0x31);
        assert_eq!(a.port.msi_vectors, 0x31);
        assert_eq!(a.port.msi_enable_mask[0], 0xFF);
        // disable path clears the mask
        a.write(PORT_MSI_INTR0_ENABLE, 4, 0x30);
        assert_eq!(a.port.msi_enable_mask[0], 0);
        // MSI address
        a.write(PORT_MSI_ADDR_LO, 4, 0xFFFF_F000);
        assert_eq!(a.read(PORT_MSI_ADDR_LO, 4), 0xFFFF_F000);
        // doorbell: data % 8 selects the bank
        a.msi_write(0xB); // bank 3
        assert_eq!(a.msi_fired[3], 1);
        assert_eq!(a.msi_fired[0], 0);
        // RID→SID map roundtrip
        a.write(PORT_RID_SID_MAP_BASE + 8, 4, 0x8001_0203);
        assert_eq!(a.read(PORT_RID_SID_MAP_BASE + 8, 4), 0x8001_0203);
        assert_eq!(a.port.rid_sid_map[2], 0x8001_0203);
        // ECAM decode matches upstream macros
        assert_eq!(decode_ecam(0x0000_1000), (0, 0, 1));
        assert_eq!(decode_ecam(0x0010_0000), (1, 0, 0));
        assert_eq!(decode_ecam(0x0010_8000), (1, 1, 0));
        // legacy root-port config surface intact
        assert_eq!(a.read(0x00, 4) as u32, 0x1420_0000 | (0x14 << 16));
        a.write(0x04, 4, 0x7);
        assert_eq!(a.read(0x04, 4), 0x7);
        // unclaimed config dword reads 0xFFFFFFFF like a real bus
        assert_eq!(a.read(0x40, 4), 0xFFFF_FFFF);
    }
}
