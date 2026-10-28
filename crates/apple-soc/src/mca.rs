//! mca — Apple Multi-Channel Audio (Music Codec Assistant).
//!
//! Faithful port of ChefKiss Inferno `hw/audio/apple-silicon/mca.c`
//! (AGPL-3.0): the three register spaces — SmartIO MCA units (0x4000
//! stride: unit control, clock gen, sync gen, RXA/TXA/RXB/TXB serial
//! units, MCLK pin, interrupts), MCA DMA (0x4000 stride: config with
//! TX/RX pad + channel counts, FIFO status, FIFO in/out with the 0x3C
//! "refill" quirk) and the master-clock config registers (4-byte stride,
//! FREQ/BUSY/ENABLED). Upstream only handles RXB/TXB config + TXB unit
//! control on the SIO side; everything else is documented-but-unwired and
//! reads 0 — this port reproduces exactly that.
//!
//! NOTE: "MCA" here is the audio controller (what the ADT node is); there
//! is no memory-controller-arbiter model upstream (checked `rg -l MCA
//! hw/` — the only hit is hw/audio/apple-silicon/mca.c).
//!
//! The pre-port synthetic CTRL/STATUS/CLKGATE offsets are kept working
//! for backward compatibility (legacy surface, marked below).

use std::collections::VecDeque;

use vm_core::Device;

// ---------------------------------------------------------------------------
// MMIO index 0: SmartIO MCA (MCA_SIO_REG_STRIDE = 0x4000)
// ---------------------------------------------------------------------------
pub const MCA_SIO_REG_STRIDE: u64 = 0x4000;

pub const REG_SIO_UNIT_CTL: u64 = 0x0;
pub const SIO_UNIT_CTL_ENABLE: u32 = 1 << 0;
pub const SIO_UNIT_CTL_RESET: u32 = 1 << 1;

// Clock Generator
pub const CLK_GEN_REG_BASE: u64 = 0x000;
pub const REG_CLK_GEN_CFG: u64 = 0x4;
pub fn clk_gen_cfg_mclk_divider(v: u32) -> u32 {
    (v >> 8) & 0xF
}

// Sync Generator
pub const SYNC_GEN_REG_BASE: u64 = 0x100;
pub const REG_SYNC_GEN_CLK_CFG: u64 = 0x4;
pub fn sync_gen_clk_cfg_clk_sel(v: u32) -> u32 {
    v & 0xF
}
pub const REG_SYNC_GEN_HI_PERIOD: u64 = 0x8;
pub const REG_SYNC_GEN_LO_PERIOD: u64 = 0xC;

// RX{A,B}/TX{A,B}
pub const RXA_REG_BASE: u64 = 0x200;
pub const TXA_REG_BASE: u64 = 0x300;
pub const RXB_REG_BASE: u64 = 0x400;
pub const TXB_REG_BASE: u64 = 0x500;
pub const REG_TX_CFG: u64 = 0x4;
pub const REG_RX_CFG: u64 = 0x8;
pub fn xfer_cfg_channel_count(v: u32) -> u32 {
    v & 0xF
}
pub fn xfer_cfg_width(v: u32) -> u32 {
    (v >> 6) & 0x7
}
pub const XFER_CFG_WIDTH_8: u32 = 0;
pub const XFER_CFG_WIDTH_16: u32 = 1;
pub const XFER_CFG_WIDTH_20: u32 = 2;
pub const XFER_CFG_WIDTH_24: u32 = 3;
pub const XFER_CFG_WIDTH_32: u32 = 4;
pub const XFER_CFG_BCLK_POLARITY: u32 = 1 << 10;
pub const XFER_CFG_LSB_FIRST: u32 = 1 << 11;
pub const XFER_CFG_NO_FEEDBACK: u32 = 1 << 15;
pub fn xfer_cfg_clk_sel(v: u32) -> u32 {
    (v >> 16) & 0x7
}
pub const XFER_CFG_CLK_SEL_DEFAULT: u32 = 0;
pub const XFER_CFG_CLK_SEL_MASTER: u32 = 7;
pub const REG_TX_CHANNEL_MASK: u64 = 0xC;
pub const REG_RX_CHANNEL_MASK: u64 = 0x10;

// Master Clock Pin
pub const MCLK_PIN_REG_BASE: u64 = 0x600;
pub const REG_MCLK_PIN_CLK_SEL: u64 = 0x4;
pub fn mclk_pin_clk_sel_i2s_clock(v: u32) -> u32 {
    v & 0x7
}
pub const MCLK_PIN_CLK_SEL_I2S_CLOCK_24MHZ: u32 = 0x1;
pub const MCLK_PIN_CLK_SEL_I2S_CLOCK_12MHZ: u32 = 0x6;
pub const REG_MCLK_PIN_DATA_SEL: u64 = 0x8;

// Interrupts
pub const INT_REG_BASE: u64 = 0x700;
pub const REG_INT_STS: u64 = 0x0;
pub const INT_STS_RXA_FRAME_ERR: u32 = 1 << 0;
pub const INT_STS_RXA_OVERFLOW: u32 = 1 << 1;
pub const INT_STS_RXB_FRAME_ERR: u32 = 1 << 2;
pub const INT_STS_RXB_OVERFLOW: u32 = 1 << 3;
pub const INT_STS_TXA_FRAME_ERR: u32 = 1 << 4;
pub const INT_STS_TXA_UNDERFLOW: u32 = 1 << 5;
pub const INT_STS_TXB_FRAME_ERR: u32 = 1 << 6;
pub const INT_STS_TXB_UNDERFLOW: u32 = 1 << 7;
pub const INT_STS_TXA_FIFO_OVERFLOW: u32 = 1 << 9;
pub const INT_STS_RXA_FIFO_UNDERFLOW: u32 = 1 << 11;
pub const INT_STS_TXB_FIFO_OVERFLOW: u32 = 1 << 13;
pub const INT_STS_RXB_FIFO_UNDERFLOW: u32 = 1 << 15;
pub const REG_INT_MASK: u64 = 0x4;

// precomputed SIO offsets for match patterns
const SIO_RXB_RX_CFG: u64 = RXB_REG_BASE + REG_RX_CFG;
const SIO_TXB_TX_CFG: u64 = TXB_REG_BASE + REG_TX_CFG;
const SIO_TXB_UNIT_CTL: u64 = TXB_REG_BASE + REG_SIO_UNIT_CTL;

// ---------------------------------------------------------------------------
// MMIO index 1: MCA DMA (MCA_DMA_REG_STRIDE = 0x4000)
// ---------------------------------------------------------------------------
pub const MCA_DMA_REG_STRIDE: u64 = 0x4000;

pub const REG_MCA_DMA_CFG: u64 = 0x0;
pub fn dma_cfg_tx_pad(v: u32) -> u32 {
    v & 0x1F
}
pub fn dma_cfg_tx_channel_count(v: u32) -> u32 {
    (v >> 5) & 0x3
}
pub const DMA_CFG_CHANNEL_COUNT_1: u32 = 0;
pub const DMA_CFG_CHANNEL_COUNT_2: u32 = 1;
pub const DMA_CFG_CHANNEL_COUNT_4: u32 = 2;
pub const DMA_CFG_CHANNEL_COUNT_8: u32 = 3;
pub fn dma_cfg_rx_pad(v: u32) -> u32 {
    (v >> 8) & 0x1F
}
pub fn dma_cfg_rx_channel_count(v: u32) -> u32 {
    (v >> 13) & 0x3
}
pub const REG_MCA_DMA_FIFO_STATUS: u64 = 0x8;
pub fn dma_fifo_status_tx_count(v: u32) -> u32 {
    v & 0x7F
}
pub fn dma_fifo_status_rx_count(v: u32) -> u32 {
    (v & 0x7F) << 16
}
pub const REG_MCA_DMA_FIFO_INOUT: u64 = 0xC;
const DMA_FIFO_DEPTH: usize = 0x40;

// ---------------------------------------------------------------------------
// MMIO index 2: Master Clock Config (MCLK_CFG_REG_STRIDE = 0x4)
// ---------------------------------------------------------------------------
pub const MCLK_CFG_REG_STRIDE: u64 = 0x4;
pub const REG_MCLK_CFG: u64 = 0x0;
pub fn mclk_cfg_freq(v: u32) -> u32 {
    (v >> 24) & 0x3
}
pub const MCLK_CFG_FREQ_24MHZ: u32 = 0x0;
pub const MCLK_CFG_FREQ_12MHZ: u32 = 0x2;
pub const MCLK_CFG_FREQ_6MHZ: u32 = 0x3;
pub const MCLK_CFG_BUSY: u32 = 1 << 30;
pub const MCLK_CFG_ENABLED: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// Legacy synthetic surface (pre-port; kept for compat — NOT upstream
// offsets). The Device impl honors these only on SIO cluster 0 offsets
// 0x0/0x4/0x8, which upstream leaves unhandled (reads 0) except that we
// persist CLKGATE for the legacy test surface.
// ---------------------------------------------------------------------------
pub const MCA_CTRL: u64 = 0x0000;
pub const MCA_STATUS: u64 = 0x0004;
pub const MCA_CLKGATE: u64 = 0x0008;

/// One SIO cluster's wired state (`AppleMCACluster`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SioCluster {
    pub txb_config: u32,
    pub rxb_config: u32,
    pub txb_control: u32,
}

/// One DMA cluster's state (`AppleMCADMA`; fifo32 depth 0x40).
#[derive(Debug, Default)]
pub struct DmaCluster {
    pub config: u32,
    pub fifo: VecDeque<u32>,
}

pub struct Mca {
    /// number of SIO clusters (derived from the ADT `reg` size upstream;
    /// T8030 exposes 8)
    pub sio_cluster_count: u32,
    pub dma_cluster_count: u32,
    pub mclk_cluster_count: u32,
    pub sio_clusters: Vec<SioCluster>,
    pub dma_clusters: Vec<DmaCluster>,
    pub mclk_clusters: Vec<u32>,
    /// legacy synthetic register (cluster 0 offset 0x8)
    pub clkgate: u32,
    /// set when TXB unit control enables the audio out (cluster 5 quirk)
    pub voice_active: bool,
    pub unknown_reads: u64,
}

impl Mca {
    pub fn new() -> Self {
        Mca {
            sio_cluster_count: 8,
            dma_cluster_count: 8,
            mclk_cluster_count: 8,
            sio_clusters: vec![SioCluster::default(); 8],
            dma_clusters: (0..8).map(|_| DmaCluster::default()).collect(),
            mclk_clusters: vec![0; 8],
            clkgate: 0,
            voice_active: false,
            unknown_reads: 0,
        }
    }

    /// SIO region read (`apple_mca_sio_reg_read`): only the three wired
    /// offsets return data; everything else reads 0.
    pub fn sio_read(&mut self, addr: u64) -> u64 {
        let index = (addr / MCA_SIO_REG_STRIDE) as usize;
        let off = addr % MCA_SIO_REG_STRIDE;
        let Some(c) = self.sio_clusters.get(index) else {
            return 0;
        };
        match off {
            SIO_RXB_RX_CFG => c.rxb_config as u64,
            SIO_TXB_TX_CFG => c.txb_config as u64,
            SIO_TXB_UNIT_CTL => c.txb_control as u64,
            _ => 0,
        }
    }

    /// SIO region write (`apple_mca_sio_reg_write`).
    pub fn sio_write(&mut self, addr: u64, val: u32) {
        let index = (addr / MCA_SIO_REG_STRIDE) as usize;
        let off = addr % MCA_SIO_REG_STRIDE;
        let Some(c) = self.sio_clusters.get_mut(index) else {
            return;
        };
        match off {
            SIO_RXB_RX_CFG => c.rxb_config = val,
            SIO_TXB_TX_CFG => c.txb_config = val,
            SIO_TXB_UNIT_CTL => {
                if index == 5 {
                    // the audio-out cluster: unit enable gates the voice
                    self.voice_active = val & SIO_UNIT_CTL_ENABLE != 0;
                }
                c.txb_control = val;
            }
            _ => {}
        }
    }

    /// DMA region read (`apple_mca_dma_reg_read`), including the 0x3C
    /// used-entries refill quirk (upstream pushes 4 zeros when exactly
    /// 0x3C words are queued — an underrun workaround).
    pub fn dma_read(&mut self, addr: u64) -> u64 {
        let index = (addr / MCA_DMA_REG_STRIDE) as usize;
        let off = addr % MCA_DMA_REG_STRIDE;
        let Some(c) = self.dma_clusters.get_mut(index) else {
            return 0;
        };
        match off {
            REG_MCA_DMA_CFG => c.config as u64,
            REG_MCA_DMA_FIFO_STATUS => {
                let used = c.fifo.len();
                if used == 0x3C {
                    for _ in 0..4 {
                        if c.fifo.len() < DMA_FIFO_DEPTH {
                            c.fifo.push_back(0);
                        }
                    }
                }
                dma_fifo_status_tx_count(used as u32) as u64
            }
            _ => 0,
        }
    }

    /// DMA region write (`apple_mca_dma_reg_write`): CFG stores, FIFO_INOUT
    /// pushes (bounded at depth 0x40 like fifo32).
    pub fn dma_write(&mut self, addr: u64, val: u32) {
        let index = (addr / MCA_DMA_REG_STRIDE) as usize;
        let off = addr % MCA_DMA_REG_STRIDE;
        let Some(c) = self.dma_clusters.get_mut(index) else {
            return;
        };
        match off {
            REG_MCA_DMA_CFG => c.config = val,
            REG_MCA_DMA_FIFO_INOUT => {
                if c.fifo.len() < DMA_FIFO_DEPTH {
                    c.fifo.push_back(val);
                }
            }
            _ => {}
        }
    }

    /// MCLK region read (stride 4): only REG_MCLK_CFG exists.
    pub fn mclk_read(&mut self, addr: u64) -> u64 {
        let index = (addr / MCLK_CFG_REG_STRIDE) as usize;
        match addr % MCLK_CFG_REG_STRIDE {
            REG_MCLK_CFG => self.mclk_clusters.get(index).copied().unwrap_or(0) as u64,
            _ => 0,
        }
    }

    /// MCLK region write.
    pub fn mclk_write(&mut self, addr: u64, val: u32) {
        let index = (addr / MCLK_CFG_REG_STRIDE) as usize;
        if addr % MCLK_CFG_REG_STRIDE == REG_MCLK_CFG {
            if let Some(m) = self.mclk_clusters.get_mut(index) {
                *m = val;
            }
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("SIO_UNIT_CTL", REG_SIO_UNIT_CTL),
            ("CLK_GEN_CFG", REG_CLK_GEN_CFG),
            ("SYNC_GEN_CLK_CFG", SYNC_GEN_REG_BASE + REG_SYNC_GEN_CLK_CFG),
            ("TXB_TX_CFG", TXB_REG_BASE + REG_TX_CFG),
            ("RXB_RX_CFG", RXB_REG_BASE + REG_RX_CFG),
            ("INT_STS", INT_REG_BASE + REG_INT_STS),
            ("INT_MASK", INT_REG_BASE + REG_INT_MASK),
            ("DMA_CFG", REG_MCA_DMA_CFG),
            ("DMA_FIFO_STATUS", REG_MCA_DMA_FIFO_STATUS),
            ("DMA_FIFO_INOUT", REG_MCA_DMA_FIFO_INOUT),
            ("MCLK_CFG", REG_MCLK_CFG),
        ]
    }
}

impl Default for Mca {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Mca {
    fn name(&self) -> &'static str {
        "mca"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        // legacy synthetic CLKGATE rides on raw offset 0x8 (upstream leaves
        // cluster-0 offset 0x8 unhandled, so this is compat-only)
        if off == MCA_CLKGATE {
            return self.clkgate as u64;
        }
        if off == MCA_STATUS {
            return 0;
        }
        // otherwise: upstream SIO-region decode (cluster 0 base)
        self.sio_read(off)
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == MCA_CLKGATE {
            self.clkgate = val as u32;
            return;
        }
        self.sio_write(off, val as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sio_txb_config_and_voice_enable_quirk() {
        let mut m = Mca::new();
        // TXB config on cluster 0
        m.sio_write(TXB_REG_BASE + REG_TX_CFG, 0x0004_0041);
        assert_eq!(m.sio_read(TXB_REG_BASE + REG_TX_CFG), 0x0004_0041);
        // RXB config on cluster 3
        let a3 = 3 * MCA_SIO_REG_STRIDE;
        m.sio_write(a3 + RXB_REG_BASE + REG_RX_CFG, 0x51);
        assert_eq!(m.sio_read(a3 + RXB_REG_BASE + REG_RX_CFG), 0x51);
        assert_eq!(m.sio_clusters[3].rxb_config, 0x51);
        // unhandled offset reads 0 (REG_TX_CHANNEL_MASK etc.)
        assert_eq!(m.sio_read(TXB_REG_BASE + REG_TX_CHANNEL_MASK), 0);
        // cluster 5 unit ctl gates the voice
        assert!(!m.voice_active);
        let a5 = 5 * MCA_SIO_REG_STRIDE;
        m.sio_write(a5 + TXB_REG_BASE + REG_SIO_UNIT_CTL, SIO_UNIT_CTL_ENABLE);
        assert!(m.voice_active);
        assert_eq!(m.sio_read(a5 + TXB_REG_BASE + REG_SIO_UNIT_CTL), SIO_UNIT_CTL_ENABLE as u64);
        // cluster 1 enable does NOT gate the voice
        let a1 = 1 * MCA_SIO_REG_STRIDE;
        m.sio_write(a1 + TXB_REG_BASE + REG_SIO_UNIT_CTL, SIO_UNIT_CTL_ENABLE);
        assert!(m.voice_active); // still set from cluster 5 (audible until reset)
        m.sio_write(a5 + TXB_REG_BASE + REG_SIO_UNIT_CTL, SIO_UNIT_CTL_RESET);
        assert!(!m.voice_active);
        // XFER_CFG decode helpers match the C macros
        let v = 0x0007_08C3; // clk_sel=7 (master), lsb_first, width 3 (24), 3 ch
        assert_eq!(xfer_cfg_channel_count(v), 3);
        assert_eq!(xfer_cfg_width(v), XFER_CFG_WIDTH_24);
        assert!(v & XFER_CFG_LSB_FIRST != 0);
        assert_eq!(xfer_cfg_clk_sel(v), XFER_CFG_CLK_SEL_MASTER);
    }

    #[test]
    fn dma_fifo_status_and_refill_quirk() {
        let mut m = Mca::new();
        // config store + field decode
        m.dma_write(REG_MCA_DMA_CFG, (2 << 5) | (0x11 << 8) | (1 << 13) | 0x3);
        assert_eq!(m.dma_read(REG_MCA_DMA_CFG), ((2 << 5) | (0x11 << 8) | (1 << 13) | 0x3) as u64);
        assert_eq!(dma_cfg_tx_channel_count(m.dma_read(REG_MCA_DMA_CFG) as u32), DMA_CFG_CHANNEL_COUNT_4);
        assert_eq!(dma_cfg_rx_channel_count(m.dma_read(REG_MCA_DMA_CFG) as u32), DMA_CFG_CHANNEL_COUNT_2);
        // push 0x3C words then read status: upstream pushes 4 more zeros
        for i in 0..0x3Cu32 {
            m.dma_write(REG_MCA_DMA_FIFO_INOUT, i);
        }
        assert_eq!(m.dma_clusters[0].fifo.len(), 0x3C);
        let status = m.dma_read(REG_MCA_DMA_FIFO_STATUS) as u32;
        assert_eq!(dma_fifo_status_tx_count(status), 0x3C);
        assert_eq!(m.dma_clusters[0].fifo.len(), 0x40); // refilled to depth
        // drain: fifo pops happen via the audio path; here verify bound
        for _ in 0..8 {
            m.dma_write(REG_MCA_DMA_FIFO_INOUT, 0);
        }
        assert_eq!(m.dma_clusters[0].fifo.len(), 0x40);
        // second cluster untouched
        assert_eq!(m.dma_read(MCA_DMA_REG_STRIDE + REG_MCA_DMA_FIFO_STATUS), 0);
    }

    #[test]
    fn mclk_freq_config_and_legacy_surface() {
        let mut m = Mca::new();
        m.mclk_write(2 * MCLK_CFG_REG_STRIDE, MCLK_CFG_ENABLED | MCLK_CFG_BUSY | (MCLK_CFG_FREQ_12MHZ << 24));
        let v = m.mclk_read(2 * MCLK_CFG_REG_STRIDE) as u32;
        assert_eq!(mclk_cfg_freq(v), MCLK_CFG_FREQ_12MHZ);
        assert!(v & MCLK_CFG_ENABLED != 0);
        assert!(v & MCLK_CFG_BUSY != 0);
        // untouched cluster reads 0
        assert_eq!(m.mclk_read(0), 0);
        // legacy synthetic surface still functional
        m.write(MCA_CLKGATE, 4, 0x7);
        assert_eq!(m.read(MCA_CLKGATE, 4), 0x7);
        assert_eq!(m.read(MCA_STATUS, 4), 0);
    }
}
