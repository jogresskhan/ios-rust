//! mt_spi — Apple MultiTouch SPI device (port of hw/arm/apple-silicon/
//! mt-spi.c): the HID-over-SPI touchscreen/trackpad *slave* hanging off the
//! `spi1` controller of the T8030 (A13), with an active-low IRQ routed into
//! AOP GPIO (`t8030_create_mt_spi`).
//!
//! This is not an MMIO block: it is an SSI bus peripheral whose entire
//! register file *is* the wire protocol. Everything below mirrors the C
//! model faithfully:
//!
//! * HBPP command layer (`HBPP_PACKET_*`): RESET→REQ_BOOT handshake,
//!   NOP→ACK_NOP, INT_ACK (drains `pending_hbpp` into TX), MEM_READ,
//!   MEM_RMW, REQ_CAL, DATA (capacity renegotiation + ACK_DATA).
//! * Low-level (LL) packet layer (`LL_PACKET_*`): 0xDEADBEEF preamble,
//!   0x204-byte frames, CRC-16 trailer, NO_DATA / CONTROL / ACK replies,
//!   `pending_fw` FIFO of firmware→host packets.
//! * HID control layer (`HID_CONTROL_PACKET_*`): GET/SET FEATURE_REPORT
//!   with the multitouch identity reports (family id, basic device info,
//!   sensor surface desc, sensor region param/desc).
//! * Touch input path: mouse events → scaled surface coordinates →
//!   `HID_REPORT_BINARY_PATH_OR_IMAGE` (0x44) lossless-output transfer
//!   packets with the PATH_STAGE ladder
//!   (MAKE_TOUCH → TOUCHING → BREAK_TOUCH → OUT_OF_RANGE).
//!
//! Upstream has no keyboard/virtual-key report path in mt-spi.c (only the
//! `HID_REPORT_BUTTONS` report id exists and falls into the default
//! GET_FEATURE case) — mirrored honestly.
//!
//! License: AGPL-3.0-or-later (upstream ChefKiss Inferno is AGPL-3.0).

use std::collections::VecDeque;

use vm_core::Device;

// ---------------------------------------------------------------------------
// HBPP command layer (mt-spi.c:135-154)
//
// HBPP Command:
//   u8 packet_type
//   u1 unk0
//   u3 packet_size? // 0 = Empty
//   u4 unk1
// ---------------------------------------------------------------------------
pub const HBPP_PACKET_RESET: u8 = 0x00;
pub const HBPP_PACKET_NOP: u8 = 0x18;
pub const HBPP_PACKET_INT_ACK: u8 = 0x1A;
pub const HBPP_PACKET_MEM_READ: u8 = 0x1C;
pub const HBPP_PACKET_MEM_RMW: u8 = 0x1E;
pub const HBPP_PACKET_REQ_CAL: u8 = 0x1F;
pub const HBPP_PACKET_DATA: u8 = 0x30;

pub const HBPP_PACKET_REQ_BOOT: u16 = 0x011F;
pub const HBPP_PACKET_ACK_RD_REQ: u16 = 0x394C;
pub const HBPP_PACKET_ACK_NOP: u16 = 0x7948;
pub const HBPP_PACKET_CAL_DONE: u16 = 0x6949;
pub const HBPP_PACKET_ACK_DATA: u16 = 0xC14B;
pub const HBPP_PACKET_ACK_WR_REQ: u16 = 0xD14A;

// ---------------------------------------------------------------------------
// LL (low-level) packet layer (mt-spi.c:156-169)
// ---------------------------------------------------------------------------
pub const LL_PACKET_PREAMBLE: u32 = 0xDEAD_BEEF;
pub const LL_PACKET_LEN: u16 = 0x204;

pub const LL_PACKET_LOSSLESS_OUTPUT: u8 = 0x10;
pub const LL_PACKET_LOSSY_OUTPUT: u8 = 0x11;
pub const LL_PACKET_LOSSLESS_INPUT: u8 = 0x20;
pub const LL_PACKET_LOSSY_INPUT: u8 = 0x21;
pub const LL_PACKET_CONTROL: u8 = 0x40;
pub const LL_PACKET_NO_DATA: u8 = 0x80;

pub const LL_PACKET_ERROR: u32 = 0xB365_5245;
pub const LL_PACKET_ACK: u32 = 0xD568_27AC;
pub const LL_PACKET_NAK: u32 = 0x0E4F_B139;
pub const LL_PACKET_BUSY: u32 = 0xF8E5_179C;

/// First (lowest) bytes of the 32-bit host response tags, as matched by
/// `apple_mt_spi_handle_fw` (`LL_PACKET_* & 0xFF`).
pub const LL_PACKET_ERROR_TAG: u8 = (LL_PACKET_ERROR & 0xFF) as u8; // 'E'
pub const LL_PACKET_ACK_TAG: u8 = (LL_PACKET_ACK & 0xFF) as u8;
pub const LL_PACKET_NAK_TAG: u8 = (LL_PACKET_NAK & 0xFF) as u8;
pub const LL_PACKET_BUSY_TAG: u8 = (LL_PACKET_BUSY & 0xFF) as u8;

// ---------------------------------------------------------------------------
// HID control / transfer layer (mt-spi.c:171-199)
// ---------------------------------------------------------------------------
pub const HID_CONTROL_PACKET_GET_RESULT_DATA: u8 = 0x10;
pub const HID_CONTROL_PACKET_SET_RESULT_DATA: u8 = 0x20;
pub const HID_CONTROL_PACKET_GET_INPUT_REPORT: u8 = 0x30;
pub const HID_CONTROL_PACKET_GET_OUTPUT_REPORT: u8 = 0x31;
pub const HID_CONTROL_PACKET_GET_FEATURE_REPORT: u8 = 0x32;
pub const HID_CONTROL_PACKET_SET_INPUT_REPORT: u8 = 0x50;
pub const HID_CONTROL_PACKET_SET_OUTPUT_REPORT: u8 = 0x51;
pub const HID_CONTROL_PACKET_SET_FEATURE_REPORT: u8 = 0x52;

pub const HID_TRANSFER_PACKET_INPUT: u8 = 0x10;
pub const HID_TRANSFER_PACKET_OUTPUT: u8 = 0x20;

pub const HID_PACKET_STATUS_SUCCESS: u8 = 0;
pub const HID_PACKET_STATUS_BUSY: u8 = 1;
pub const HID_PACKET_STATUS_ERROR: u8 = 2;
pub const HID_PACKET_STATUS_ERROR_ID_MISMATCH: u8 = 3;
pub const HID_PACKET_STATUS_ERROR_UNSUPPORTED: u8 = 4;
pub const HID_PACKET_STATUS_ERROR_INCORRECT_LENGTH: u8 = 5;

pub const HID_REPORT_BINARY_PATH_OR_IMAGE: u8 = 0x44;
pub const HID_REPORT_SENSOR_REGION_PARAM: u8 = 0xA1;
pub const HID_REPORT_SENSOR_REGION_DESC: u8 = 0xD0;
pub const HID_REPORT_FAMILY_ID: u8 = 0xD1;
pub const HID_REPORT_BASIC_DEVICE_INFO: u8 = 0xD3;
pub const HID_REPORT_BUTTONS: u8 = 0xD7;
pub const HID_REPORT_SENSOR_SURFACE_DESC: u8 = 0xD9;
pub const HID_REPORT_POWER_STATS: u8 = 0x72;
pub const HID_REPORT_POWER_STATS_DESC: u8 = 0x73;
pub const HID_REPORT_STATUS: u8 = 0x7F;

// ---------------------------------------------------------------------------
// Multitouch identity (mt-spi.c:201-208)
// ---------------------------------------------------------------------------
pub const MT_FAMILY_ID: u8 = 0xC3; // maybe 0xc2?
pub const MT_LITTLE_ENDIAN: u8 = 1;
pub const MT_ROWS: u8 = 31;
pub const MT_COLUMNS: u8 = 15;
/// `bswap16(0x292)`
pub const MT_BCD_VER: u16 = 0x292u16.swap_bytes();
/// display_width/828 * 7.8
pub const MT_SENSOR_SURFACE_WIDTH: i32 = 6458;
/// display_height/1792 * 7.8
pub const MT_SENSOR_SURFACE_HEIGHT: i32 = 13977;

// ---------------------------------------------------------------------------
// Touch path stages (mt-spi.c:210-217)
// ---------------------------------------------------------------------------
pub const PATH_STAGE_NOT_TRACKING: u8 = 0;
pub const PATH_STAGE_START_IN_RANGE: u8 = 1;
pub const PATH_STAGE_HOVER_IN_RANGE: u8 = 2;
pub const PATH_STAGE_MAKE_TOUCH: u8 = 3;
pub const PATH_STAGE_TOUCHING: u8 = 4;
pub const PATH_STAGE_BREAK_TOUCH: u8 = 5;
pub const PATH_STAGE_LINGER_IN_RANGE: u8 = 6;
pub const PATH_STAGE_OUT_OF_RANGE: u8 = 7;

// Input plumbing constants (QEMU ui/input.h, ui/console.h).
pub const INPUT_EVENT_ABS_MIN: i32 = 0x0000;
pub const INPUT_EVENT_ABS_MAX: i32 = 0x7FFF;
pub const MOUSE_EVENT_LBUTTON: i32 = 0x01;

pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
/// QEMU `SCALE_MS`
pub const SCALE_MS: u64 = 1_000_000;

/// MT SPI slave IRQ gpio name (`APPLE_MT_SPI_IRQ "mt-irq"` in mt-spi.h).
pub const APPLE_MT_SPI_IRQ: &str = "mt-irq";

// ---------------------------------------------------------------------------
// CRC-16 (port of util/crc16.c — CRC-16/ARC, reflected poly 0xA001)
// ---------------------------------------------------------------------------
const CRC16_POLY: u16 = 0xA001;

const fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u16;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ CRC16_POLY } else { crc >> 1 };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// `crc16(0, buf, len)` from QEMU's util/crc16.c (table-driven byte-wise).
pub fn crc16(crc: u16, data: &[u8]) -> u16 {
    const TABLE: [u16; 256] = crc16_table();
    let mut crc = crc;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ b as u16) & 0xFF) as usize];
    }
    crc
}

// ---------------------------------------------------------------------------
// AppleMTSPIBuffer (mt-spi.c:36-41) — a growable byte buffer with a
// consumer cursor. `capacity` is tracked separately from `data` so the
// `is_full()` semantics (len == capacity) match upstream exactly.
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default)]
pub struct Buf {
    pub data: Vec<u8>,
    pub capacity: u32,
    pub len: u32,
    pub read_pos: u32,
}

impl Buf {
    pub fn new() -> Self {
        Buf::default()
    }

    /// `apple_mt_spi_buf_free`
    pub fn free(&mut self) {
        *self = Buf::default();
    }

    /// `apple_mt_spi_buf_ensure_capacity`
    pub fn ensure_capacity(&mut self, bytes: usize) {
        if self.len as usize + bytes > self.capacity as usize {
            self.capacity = self.len + bytes as u32;
        }
    }

    /// `apple_mt_spi_buf_set_capacity` (upstream asserts capacity >= old)
    pub fn set_capacity(&mut self, capacity: u32) {
        assert!(capacity >= self.capacity, "set_capacity shrink");
        self.capacity = capacity;
    }

    /// `apple_mt_spi_buf_set_len` — fill from `len` up to `len_new` with `val`.
    pub fn set_len(&mut self, val: u8, len_new: u32) {
        assert!(len_new >= self.len, "set_len shrink");
        self.ensure_capacity((len_new - self.len) as usize);
        while self.len < len_new {
            self.data.push(val);
            self.len += 1;
        }
    }

    /// `apple_mt_spi_buf_is_empty`
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `apple_mt_spi_buf_get_pos` — position of the last written byte.
    pub fn get_pos(&self) -> u32 {
        assert!(!self.is_empty(), "get_pos on empty buffer");
        self.len - 1
    }

    /// `apple_mt_spi_buf_is_full`
    pub fn is_full(&self) -> bool {
        !self.is_empty() && self.len == self.capacity
    }

    /// `apple_mt_spi_buf_pos_at_start`
    pub fn pos_at_start(&self) -> bool {
        self.get_pos() == 0
    }

    /// `apple_mt_spi_buf_read_pos_at_end`
    pub fn read_pos_at_end(&self) -> bool {
        self.read_pos + 1 == self.len
    }

    /// `apple_mt_spi_buf_push_byte`
    pub fn push_byte(&mut self, val: u8) {
        self.ensure_capacity(1);
        self.data.push(val);
        self.len += 1;
    }

    /// `apple_mt_spi_buf_push_word` — `stw_le_p` (little-endian).
    pub fn push_word(&mut self, val: u16) {
        self.ensure_capacity(2);
        self.data.extend_from_slice(&val.to_le_bytes());
        self.len += 2;
    }

    /// `apple_mt_spi_buf_push_dword` — `stl_le_p` (little-endian).
    pub fn push_dword(&mut self, val: u32) {
        self.ensure_capacity(4);
        self.data.extend_from_slice(&val.to_le_bytes());
        self.len += 4;
    }

    /// `apple_mt_spi_buf_push_crc16`
    pub fn push_crc16(&mut self) {
        assert!(!self.is_empty(), "push_crc16 on empty buffer");
        let c = crc16(0, &self.data[..self.len as usize]);
        self.push_word(c);
    }

    /// `apple_mt_spi_buf_append` (consumes `other`, like the C free-after).
    pub fn append(&mut self, other: Buf) {
        let mut other = other;
        if !other.is_empty() {
            self.ensure_capacity(other.len as usize);
            self.data.extend_from_slice(&other.data[..other.len as usize]);
            self.len += other.len;
        }
        other.free();
    }

    /// `apple_mt_spi_buf_pop` — returns 0 when empty; frees when drained.
    pub fn pop(&mut self) -> u8 {
        if self.is_empty() {
            return 0;
        }
        let ret = self.data[self.read_pos as usize];
        if self.read_pos_at_end() || self.is_empty() {
            self.free();
        } else {
            self.read_pos += 1;
        }
        ret
    }

    /// `apple_mt_spi_buf_read_byte`
    pub fn read_byte(&self, off: usize) -> u8 {
        self.data[off]
    }

    /// `apple_mt_spi_buf_read_word` — NOTE: upstream reads this one
    /// **big-endian** (`lduw_be_p`), even though pushes are LE.
    pub fn read_word(&self, off: usize) -> u16 {
        u16::from_be_bytes([self.data[off], self.data[off + 1]])
    }

    /// `apple_mt_spi_buf_read_dword` = word(off) | word(off+2) << 16.
    pub fn read_dword(&self, off: usize) -> u32 {
        self.read_word(off) as u32 | ((self.read_word(off + 2) as u32) << 16)
    }
}

// ---------------------------------------------------------------------------
// AppleMTSPILLPacket (mt-spi.c:58-62)
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default)]
pub struct LlPacket {
    pub buf: Buf,
    pub packet_type: u8,
}

/// `apple_mt_spi_hbpp_packet_hdr_len`
pub fn hbpp_packet_hdr_len(val: u8) -> u32 {
    match val {
        HBPP_PACKET_RESET => 0x4,
        HBPP_PACKET_NOP => 0x2,
        HBPP_PACKET_INT_ACK => 0x2,
        HBPP_PACKET_MEM_READ => 0x8,
        HBPP_PACKET_MEM_RMW => 0x10,
        HBPP_PACKET_REQ_CAL => 0x2,
        HBPP_PACKET_DATA => 0xA,
        _ => {
            // warn_report("Unknown HBPP packet type 0x%X")
            0x2
        }
    }
}

// ---------------------------------------------------------------------------
// Device state (mt-spi.c:77-101)
// ---------------------------------------------------------------------------
pub struct MtSpi {
    /// TX towards the host (the SPI controller of the SoC).
    pub tx: Buf,
    /// RX from the host — bytes clocked in via [`MtSpi::spi_transfer`].
    pub rx: Buf,
    /// HBPP replies waiting for the host's INT_ACK.
    pub pending_hbpp: Buf,
    /// Firmware (device→host) packets queued for the next LL frame.
    pub pending_fw: VecDeque<LlPacket>,
    pub frame: u8,
    // QEMU timers — modeled as deadlines evaluated in [`Device::tick`].
    pub timer_deadline: Option<u64>,
    pub end_timer_deadline: Option<u64>,
    pub x: i16,
    pub y: i16,
    pub prev_x: i16,
    pub prev_y: i16,
    pub prev_ts: u64,
    pub btn_state: i32,
    pub prev_btn_state: i32,
    pub display_width: u32,
    pub display_height: u32,
    /// IRQ of the Multi Touch Controller is **active low**: `true` here means
    /// the line is *asserted* (qemu_irq_lower), `false` = inactive
    /// (qemu_irq_raise).
    pub irq_active: bool,
    /// Unhandled HBPP/LL/HID protocol traffic (upstream warn_report /
    /// error_report sites).
    pub unknown_packets: u64,
    /// mt-spi is an SSI bus slave, not an MMIO block; these fire if someone
    /// attaches it to the physical bus and pokes it anyway.
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl MtSpi {
    /// `display_width`/`display_height` are the machine props
    /// (`qdev_prop_set_uint32(device, "display_width", ...)`, iPhone 11:
    /// 828×1792).
    pub fn new(display_width: u32, display_height: u32) -> Self {
        MtSpi {
            tx: Buf::new(),
            rx: Buf::new(),
            pending_hbpp: Buf::new(),
            pending_fw: VecDeque::new(),
            frame: 0,
            timer_deadline: None,
            end_timer_deadline: None,
            x: 0,
            y: 0,
            prev_x: 0,
            prev_y: 0,
            prev_ts: 0,
            btn_state: 0,
            prev_btn_state: 0,
            display_width,
            display_height,
            irq_active: false,
            unknown_packets: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    pub fn set_display_size(&mut self, width: u32, height: u32) {
        self.display_width = width;
        self.display_height = height;
    }

    /// Wire level fed into the AOP GPIO irq input (active-low device IRQ:
    /// `false` = device is asking for attention... see `irq_active`).
    pub fn irq_line_level(&self) -> bool {
        !self.irq_active
    }

    // -- buffer plumbing (mt-spi.c:366-378) ----------------------------------

    fn push_pending_hbpp_word(&mut self, val: u16) {
        self.pending_hbpp.push_word(val);
        // qemu_irq_lower(s->irq): active
        self.irq_active = true;
    }

    fn push_pending_hbpp_dword(&mut self, val: u32) {
        self.pending_hbpp.push_dword(val);
        self.irq_active = true;
    }

    // -- HBPP layer (mt-spi.c:380-481) ---------------------------------------

    fn handle_hbpp_data(&mut self) {
        if !self.rx.is_full() {
            return;
        }
        let payload_len = self.rx.read_word(2) as u32 * 4;
        let new_rx_capacity =
            hbpp_packet_hdr_len(HBPP_PACKET_DATA) + payload_len + 4;
        if self.rx.capacity == new_rx_capacity {
            self.push_pending_hbpp_word(HBPP_PACKET_ACK_DATA);
        } else {
            self.rx.set_capacity(new_rx_capacity);
        }
    }

    fn handle_hbpp_mem_rmw(&mut self) {
        if self.rx.is_full() {
            self.push_pending_hbpp_word(HBPP_PACKET_ACK_WR_REQ);
        }
    }

    fn handle_hbpp(&mut self) {
        let packet_type = self.rx.read_byte(0);

        if self.rx.pos_at_start() {
            self.rx.set_capacity(hbpp_packet_hdr_len(packet_type));
        }

        match packet_type {
            HBPP_PACKET_RESET => {
                if self.rx.is_full() {
                    self.push_pending_hbpp_word(HBPP_PACKET_REQ_BOOT);
                }
            }
            HBPP_PACKET_NOP => {
                if self.rx.pos_at_start() && self.tx.is_empty() {
                    self.tx.push_word(HBPP_PACKET_ACK_NOP);
                }
            }
            HBPP_PACKET_INT_ACK => {
                if self.rx.pos_at_start() {
                    let pending = std::mem::take(&mut self.pending_hbpp);
                    self.tx.append(pending);
                }
            }
            HBPP_PACKET_MEM_READ => {
                if self.rx.pos_at_start() {
                    self.pending_hbpp.ensure_capacity(2 + 4 + 2);
                    self.push_pending_hbpp_word(HBPP_PACKET_ACK_RD_REQ);
                    self.push_pending_hbpp_dword(0x0000_0000); // value
                    self.push_pending_hbpp_word(0x0000); // crc16 of value
                }
            }
            HBPP_PACKET_MEM_RMW => self.handle_hbpp_mem_rmw(),
            HBPP_PACKET_REQ_CAL => {
                if self.rx.pos_at_start() {
                    self.push_pending_hbpp_word(HBPP_PACKET_CAL_DONE);
                }
            }
            HBPP_PACKET_DATA => self.handle_hbpp_data(),
            _ => {
                // error_report("Unknown packet type 0x%02X")
                self.unknown_packets += 1;
            }
        }
    }

    // -- LL layer (mt-spi.c:483-773) -----------------------------------------

    fn push_ll_hdr(
        buf: &mut Buf,
        ll_type: u8,
        interface: u8,
        payload_off: u16,
        payload_remaining: u16,
        payload_length: u16,
    ) {
        buf.ensure_capacity(8);
        buf.push_byte(ll_type);
        buf.push_byte(interface);
        buf.push_word(payload_off);
        buf.push_word(payload_remaining);
        buf.push_word(payload_length);
    }

    fn pad_ll_packet(buf: &mut Buf) {
        buf.set_len(0, (LL_PACKET_LEN - 4 - 2) as u32);
    }

    fn push_no_data(buf: &mut Buf) {
        Self::push_ll_hdr(buf, LL_PACKET_NO_DATA, 0, 0, 0, 0);
        Self::pad_ll_packet(buf);
        buf.push_crc16();
    }

    /// `apple_mt_spi_ll_read_payload_byte` — the payload sits behind the
    /// preamble (4) + LL header (8).
    fn ll_read_payload_byte(&self, off: usize) -> u8 {
        self.rx.data[4 + 8 + off]
    }

    fn push_hid_hdr(
        buf: &mut Buf,
        hid_type: u8,
        report_id: u8,
        packet_status: u8,
        frame_number: u8,
        length_requested: u16,
        payload_length: u16,
    ) {
        buf.ensure_capacity(8);
        buf.push_byte(hid_type);
        buf.push_byte(report_id);
        buf.push_byte(packet_status);
        buf.push_byte(frame_number);
        buf.push_word(length_requested);
        buf.push_word(payload_length);
    }

    fn push_report_hdr(
        buf: &mut Buf,
        hid_type: u8,
        report_id: u8,
        packet_status: u8,
        frame_number: u8,
        payload_length: u16,
    ) {
        buf.ensure_capacity(9);
        Self::push_hid_hdr(
            buf,
            hid_type,
            report_id,
            packet_status,
            frame_number,
            0,
            payload_length + 1, // + sizeof(report_id)
        );
        buf.push_byte(report_id);
    }

    fn push_report_byte(
        buf: &mut Buf,
        hid_type: u8,
        report_id: u8,
        packet_status: u8,
        frame_number: u8,
        val: u8,
    ) {
        Self::push_report_hdr(
            buf,
            hid_type,
            report_id,
            packet_status,
            frame_number,
            1,
        );
        buf.push_byte(val);
    }

    fn handle_get_feature(&mut self) {
        let report_id = self.ll_read_payload_byte(1);
        let frame_number = self.ll_read_payload_byte(3);

        let mut packet =
            LlPacket { buf: Buf::new(), packet_type: LL_PACKET_CONTROL };
        let buf = &mut packet.buf;

        match report_id {
            HID_REPORT_FAMILY_ID => {
                buf.ensure_capacity(9 + 1 + 2);
                Self::push_report_byte(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    MT_FAMILY_ID,
                );
            }
            HID_REPORT_BASIC_DEVICE_INFO => {
                buf.ensure_capacity(9 + 5 + 2);
                Self::push_report_hdr(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    5,
                );
                buf.push_byte(MT_LITTLE_ENDIAN);
                buf.push_byte(MT_ROWS);
                buf.push_byte(MT_COLUMNS);
                buf.push_word(MT_BCD_VER);
            }
            HID_REPORT_SENSOR_SURFACE_DESC => {
                buf.ensure_capacity(9 + 16 + 2);
                Self::push_report_hdr(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    16,
                );
                buf.push_dword(MT_SENSOR_SURFACE_WIDTH as u32);
                buf.push_dword(MT_SENSOR_SURFACE_HEIGHT as u32);
                // these values might need to be different, especially
                // considering the values inside HID_REPORT_SENSOR_REGION_DESC
                buf.push_word(0);
                buf.push_word(0);
                buf.push_word(MT_SENSOR_SURFACE_WIDTH as u16);
                buf.push_word(MT_SENSOR_SURFACE_HEIGHT as u16);
            }
            HID_REPORT_SENSOR_REGION_PARAM => {
                buf.ensure_capacity(9 + 6 + 2);
                Self::push_report_hdr(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    6,
                );
                buf.push_word(0x0);
                buf.push_word(0x7);
                buf.push_word(0x200);
            }
            HID_REPORT_SENSOR_REGION_DESC => {
                buf.ensure_capacity(9 + 22 + 2);
                Self::push_report_hdr(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    22, // 1 + 7*3
                );
                buf.push_byte(3); // region count

                buf.push_byte(1); // type Multitouch
                buf.push_byte(0); // start_row
                buf.push_byte(30); // rows
                buf.push_byte(1); // row_skip
                buf.push_byte(0); // start_col
                buf.push_byte(14); // cols
                buf.push_byte(0); // hardware_coloffset

                buf.push_byte(8); // type CommonMode
                buf.push_byte(0); // start_row
                buf.push_byte(30); // rows
                buf.push_byte(1); // row_skip
                buf.push_byte(14); // start_col
                buf.push_byte(1); // cols
                buf.push_byte(0); // hardware_coloffset

                buf.push_byte(11); // type Unknown
                buf.push_byte(30); // maybe rows?
                buf.push_byte(1); // maybe row_skip?
                buf.push_byte(1); // unknown
                buf.push_byte(0); // unknown
                // maybe ignored? offsets 0x14/0x15 > size 0x14
                buf.push_byte(15);
                buf.push_byte(0);
            }
            _ => {
                Self::push_report_byte(
                    buf,
                    HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                    report_id,
                    HID_PACKET_STATUS_SUCCESS,
                    frame_number,
                    0,
                );
            }
        }
        buf.push_crc16();
        self.pending_fw.push_back(packet);
    }

    fn handle_set_feature(&mut self) {
        let report_id = self.ll_read_payload_byte(1);
        let frame_number = self.ll_read_payload_byte(3);

        let mut packet =
            LlPacket { buf: Buf::new(), packet_type: LL_PACKET_CONTROL };
        Self::push_hid_hdr(
            &mut packet.buf,
            HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
            report_id,
            HID_PACKET_STATUS_SUCCESS,
            frame_number,
            0,
            0,
        );
        packet.buf.push_crc16();
        self.pending_fw.push_back(packet);
    }

    fn handle_control(&mut self) {
        let control_type = self.ll_read_payload_byte(0);

        match control_type {
            HID_CONTROL_PACKET_GET_FEATURE_REPORT => self.handle_get_feature(),
            HID_CONTROL_PACKET_SET_FEATURE_REPORT => self.handle_set_feature(),
            _ => {
                // warn_report("Unknown HID packet type 0x%X")
                self.unknown_packets += 1;
            }
        }
    }

    fn handle_fw_packet(&mut self) {
        if self.rx.get_pos() == 4 {
            self.rx.set_capacity(LL_PACKET_LEN as u32);

            let mut buf = Buf::new();
            match self.pending_fw.pop_front() {
                None => Self::push_no_data(&mut buf),
                Some(packet) => {
                    Self::push_ll_hdr(
                        &mut buf,
                        packet.packet_type,
                        0,
                        0,
                        0,
                        packet.buf.len as u16,
                    );
                    buf.append(packet.buf);
                    Self::pad_ll_packet(&mut buf);
                    buf.push_crc16();
                }
            }

            self.tx.append(buf);
        }

        if !self.rx.is_full() {
            return;
        }

        let packet_type = self.rx.read_byte(4);

        match packet_type {
            LL_PACKET_NO_DATA => {}
            LL_PACKET_CONTROL => self.handle_control(),
            _ => {
                // warn_report("Unknown LL packet type 0x%X")
                self.unknown_packets += 1;
            }
        }
    }

    fn handle_fw(&mut self) {
        if self.rx.pos_at_start() {
            self.rx.set_capacity(4 * 2);
            // Push the preamble; the host is clocking it in and hears the
            // echo byte-by-byte.
            self.tx.push_dword(LL_PACKET_PREAMBLE);
        }

        if self.rx.get_pos() < 4 {
            return;
        }

        let packet_type = self.rx.read_byte(4);

        match packet_type {
            LL_PACKET_ERROR_TAG | LL_PACKET_ACK_TAG | LL_PACKET_NAK_TAG
            | LL_PACKET_BUSY_TAG => {
                if self.rx.get_pos() == 4 {
                    self.tx.push_dword(LL_PACKET_ACK);
                }
            }
            _ => self.handle_fw_packet(),
        }
    }

    // -- SSI transfer (mt-spi.c:775-806) -------------------------------------

    /// `apple_mt_spi_transfer` — one byte of the SPI bus transaction.
    pub fn spi_transfer(&mut self, val: u8) -> u8 {
        self.rx.push_byte(val);

        if self.rx.read_byte(0) == (LL_PACKET_PREAMBLE & 0xFF) as u8 {
            self.handle_fw();
        } else {
            self.handle_hbpp();
        }

        if self.rx.is_full() {
            self.rx.free();
        }

        let ret = self.tx.pop();

        // Both pending queues empty ⇒ IRQ inactive (raised; active-low line).
        self.irq_active =
            !(self.pending_hbpp.is_empty() && self.pending_fw.is_empty());

        ret
    }

    /// Clock a whole host→device byte stream, collecting the device replies.
    /// Test/GUI convenience over [`MtSpi::spi_transfer`].
    pub fn clock(&mut self, bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(|&b| self.spi_transfer(b)).collect()
    }

    // -- touch input path (mt-spi.c:808-1001) ---------------------------------

    /// `qemu_input_scale_axis` (ui/input.c).
    fn scale_axis(
        value: i32,
        min_in: i32,
        max_in: i32,
        min_out: i32,
        max_out: i32,
    ) -> i32 {
        let range_in = max_in as i64 - min_in as i64;
        let range_out = max_out as i64 - min_out as i64;
        if range_in < 1 {
            return (min_out as i64 + range_out / 2) as i32;
        }
        ((value as i64 - min_in as i64) * range_out / range_in
            + min_out as i64) as i32
    }

    /// `apple_mt_spi_send_path_update` — queue a
    /// HID_REPORT_BINARY_PATH_OR_IMAGE lossless-output transfer packet.
    fn send_path_update(&mut self, ts: u64, path_stage: u8) {
        let mut packet = LlPacket {
            buf: Buf::new(),
            packet_type: LL_PACKET_LOSSLESS_OUTPUT,
        };

        let ts_delta = ts.saturating_sub(self.prev_ts).max(1); // prevent div-by-zero
        self.prev_ts = ts;

        let x_delta = self.x as i32 - self.prev_x as i32;
        let y_delta = self.y as i32 - self.prev_y as i32;

        let buf = &mut packet.buf;
        buf.ensure_capacity(9 + 27 + 20 + 2);
        Self::push_report_hdr(
            buf,
            HID_TRANSFER_PACKET_OUTPUT,
            HID_REPORT_BINARY_PATH_OR_IMAGE,
            HID_PACKET_STATUS_SUCCESS,
            self.frame,
            (27 + 20) as u16,
        );
        buf.push_byte(self.frame);
        buf.push_byte(28); // Header Len
        buf.push_byte(0);
        buf.push_dword((ts / SCALE_MS) as u32);
        buf.push_byte(0);
        buf.push_byte(0);
        buf.push_byte(0);
        buf.push_byte(0);
        buf.push_word(0);
        buf.push_word(0); // Image Len
        buf.push_byte(1); // Path Count
        buf.push_byte(20); // Path Len
        buf.push_word(0);
        buf.push_word(0);
        buf.push_word(0);
        buf.push_byte(0);
        buf.push_byte(0);
        buf.push_byte(0);
        buf.push_byte(0);

        // Path 0
        buf.push_byte(1); // Path ID
        buf.push_byte(path_stage);
        buf.push_byte(1); // Finger ID
        buf.push_byte(1); // Hand ID
        buf.push_word(self.x as u16);
        buf.push_word(self.y as u16);
        // Upstream computes ABS(delta) / ts_delta * 1000 with ts_delta in
        // nanoseconds — integer division first, so this is nearly always 0.
        buf.push_word(
            ((x_delta.abs() as u64 / ts_delta as u64) * 1000) as u16,
        );
        buf.push_word(
            ((y_delta.abs() as u64 / ts_delta as u64) * 1000) as u16,
        );
        buf.push_word(660); // rad0
        buf.push_word(580); // rad1
        buf.push_word(19317); // angle/orientation
        buf.push_word(100); // rad multiplier (maybe force?)
        // iOS computes contact density by itself (see upstream comment).

        buf.push_crc16();

        if self.frame < 0xFF {
            self.frame += 1;
        } else {
            self.frame = 0;
        }

        self.pending_fw.push_back(packet);
        // qemu_irq_lower(s->irq): active
        self.irq_active = true;
    }

    /// Shared press/release edge logic of `apple_mt_spi_mouse_event`.
    fn touch_edges(&mut self, buttons_state: i32, now_ns: u64) {
        self.prev_btn_state = self.btn_state;
        self.btn_state = buttons_state;

        if self.prev_btn_state & MOUSE_EVENT_LBUTTON == 0
            && self.btn_state & MOUSE_EVENT_LBUTTON != 0
        {
            // aio_bh_schedule_oneshot → runs synchronously here
            self.send_path_update(now_ns, PATH_STAGE_MAKE_TOUCH);
            self.end_timer_deadline = None;
            self.timer_deadline = Some(now_ns + NANOSECONDS_PER_SECOND / 10);
        } else if self.prev_btn_state & MOUSE_EVENT_LBUTTON != 0
            && self.btn_state & MOUSE_EVENT_LBUTTON == 0
        {
            self.send_path_update(now_ns, PATH_STAGE_BREAK_TOUCH);
            self.timer_deadline = None;
            self.end_timer_deadline =
                Some(now_ns + NANOSECONDS_PER_SECOND / 10);
        }
    }

    /// `apple_mt_spi_mouse_event` — QEMU mouse handler. `dx`/`dy` are
    /// absolute tablet coords in [INPUT_EVENT_ABS_MIN, INPUT_EVENT_ABS_MAX],
    /// scaled onto the sensor surface.
    pub fn mouse_event(
        &mut self,
        dx: i32,
        dy: i32,
        buttons_state: i32,
        now_ns: u64,
    ) {
        self.prev_x = self.x;
        self.prev_y = self.y;
        self.x = Self::scale_axis(
            dx,
            INPUT_EVENT_ABS_MIN,
            INPUT_EVENT_ABS_MAX,
            0,
            MT_SENSOR_SURFACE_WIDTH,
        ) as i16;
        let mut y = Self::scale_axis(
            INPUT_EVENT_ABS_MAX - dy,
            INPUT_EVENT_ABS_MIN,
            INPUT_EVENT_ABS_MAX,
            0,
            MT_SENSOR_SURFACE_HEIGHT,
        );
        // Hardcoded calibration on y-axis (±1 pixel for display_height 1792).
        y -= Self::scale_axis(
            16,
            0,
            self.display_height as i32,
            0,
            MT_SENSOR_SURFACE_HEIGHT,
        );
        self.y = y as i16;
        self.touch_edges(buttons_state, now_ns);
    }

    /// GUI/test entry point: absolute sensor-surface coordinates instead of
    /// raw tablet values (skips `mouse_event`'s scaling + y calibration but
    /// keeps the same press/release edge logic and PATH_STAGE ladder).
    pub fn submit_touch_report(
        &mut self,
        x: i16,
        y: i16,
        buttons_state: i32,
        now_ns: u64,
    ) {
        self.prev_x = self.x;
        self.prev_y = self.y;
        self.x = x;
        self.y = y;
        self.touch_edges(buttons_state, now_ns);
    }

    /// `apple_mt_spi_reset_enter` (+ `reset_hold` irq raise) — machine reset.
    pub fn reset(&mut self) {
        self.timer_deadline = None;
        self.end_timer_deadline = None;

        self.btn_state = 0;
        self.prev_btn_state = 0;
        self.prev_x = 0;
        self.prev_y = 0;
        self.x = 0;
        self.y = 0;
        self.prev_ts = 0;
        self.frame = 0;

        self.tx.free();
        self.rx.free();
        self.pending_hbpp.free();
        self.pending_fw.clear();

        // reset_hold: qemu_irq_raise(s->irq) — inactive
        self.irq_active = false;
    }
}

impl Default for MtSpi {
    fn default() -> Self {
        // Upstream defaults the display props to 0; the machine sets them.
        MtSpi::new(0, 0)
    }
}

/// Plug the multitouch device into the spi1 controller
/// ([`crate::gpio_i2c_spi::Spi`]) exactly like `ssi_realize_and_unref`.
impl crate::gpio_i2c_spi::SpiSlave for MtSpi {
    fn transfer(&mut self, b: u8) -> u8 {
        self.spi_transfer(b)
    }
}

impl Device for MtSpi {
    fn name(&self) -> &'static str {
        "mt_spi"
    }

    /// Not MMIO-mapped (SSI bus slave): any bus access is unknown traffic.
    fn read(&mut self, _off: u64, _size: u8) -> u64 {
        self.unknown_reads += 1;
        0
    }

    fn write(&mut self, _off: u64, _size: u8, _val: u64) {
        self.unknown_writes += 1;
    }

    /// Drives the repeat timer (`NANOSECONDS_PER_SECOND / 20` while the left
    /// button is held) and the end timer (`NANOSECONDS_PER_SECOND / 10` after
    /// release) — ports of `apple_mt_spi_timer_tick` /
    /// `apple_mt_spi_end_timer_tick`.
    fn tick(&mut self, now_ns: u64) {
        if self.timer_deadline.is_some_and(|d| now_ns >= d) {
            self.timer_deadline = None;
            // apple_mt_spi_timer_tick
            if self.prev_x != self.x || self.prev_y != self.y {
                self.send_path_update(now_ns, PATH_STAGE_TOUCHING);
            }
            if self.btn_state & MOUSE_EVENT_LBUTTON != 0 {
                self.timer_deadline =
                    Some(now_ns + NANOSECONDS_PER_SECOND / 20);
            }
        }

        if self.end_timer_deadline.is_some_and(|d| now_ns >= d) {
            self.end_timer_deadline = None;
            // apple_mt_spi_end_timer_tick
            self.send_path_update(now_ns, PATH_STAGE_OUT_OF_RANGE);
            self.prev_ts = 0;
            self.prev_x = 0;
            self.prev_y = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a full host→device LL frame (0x204 bytes).
    fn ll_frame(ll_type: u8, interface: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(LL_PACKET_LEN as usize);
        frame.extend_from_slice(&LL_PACKET_PREAMBLE.to_le_bytes());
        frame.push(ll_type);
        frame.push(interface);
        frame.extend_from_slice(&0u16.to_le_bytes()); // payload_off
        frame.extend_from_slice(&0u16.to_le_bytes()); // payload_remaining
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.extend_from_slice(payload);
        frame.resize(LL_PACKET_LEN as usize, 0);
        frame
    }

    #[test]
    fn crc16_known_vector_and_buffer_reset_semantics() {
        // CRC-16/ARC check value ("123456789" → 0xBB3D), matches QEMU's table.
        assert_eq!(crc16(0, b"123456789"), 0xBB3D);
        // incremental == one-shot
        let full = crc16(0, b"123456789");
        let split = crc16(crc16(0, b"1234"), b"56789");
        assert_eq!(full, split);

        // Buffer reset values (mt-spi.c buffer zero state)
        let mut b = Buf::new();
        assert!(b.is_empty());
        assert!(!b.is_full());
        assert_eq!(b.pop(), 0); // pop on empty buffer

        // is_full only when len == capacity (set_capacity + set_len path)
        b.push_byte(0xAA);
        b.set_capacity(4);
        assert!(!b.is_full());
        b.set_len(0, 4);
        assert!(b.is_full());
        assert_eq!(b.read_word(0), 0xAA00); // big-endian read, like upstream

        // pop drains byte-by-byte and frees on the last one
        assert_eq!(b.pop(), 0xAA);
        assert_eq!(b.pop(), 0x00);
        assert_eq!(b.pop(), 0x00);
        assert_eq!(b.pop(), 0x00);
        assert!(b.is_empty());
        assert_eq!(b.capacity, 0);

        // Device reset state (apple_mt_spi_reset_enter/reset_hold)
        let mut dev = MtSpi::new(828, 1792);
        dev.frame = 0x7F;
        dev.irq_active = true;
        dev.reset();
        assert_eq!(dev.frame, 0);
        assert!(!dev.irq_active);
        assert!(dev.tx.is_empty() && dev.rx.is_empty());
        assert!(dev.pending_fw.is_empty());
        assert_eq!(dev.name(), "mt_spi");
        assert_eq!(dev.irq_line_level(), true); // active-low: idle line high
    }

    #[test]
    fn hbpp_reset_then_int_ack_delivers_req_boot() {
        let mut dev = MtSpi::new(828, 1792);

        // HBPP RESET (4-byte packet): device answers by queueing REQ_BOOT.
        let replies = dev.clock(&[HBPP_PACKET_RESET, 0, 0, 0]);
        assert!(replies.iter().all(|&b| b == 0)); // nothing on the wire yet
        assert_eq!(dev.pending_hbpp.data, HBPP_PACKET_REQ_BOOT.to_le_bytes());
        assert!(dev.irq_active, "IRQ must be active while HBPP is pending");

        // INT_ACK (2-byte packet): drains pending_hbpp into the TX stream.
        let replies = dev.clock(&[HBPP_PACKET_INT_ACK, 0]);
        assert_eq!(replies, HBPP_PACKET_REQ_BOOT.to_le_bytes().to_vec());
        assert!(dev.pending_hbpp.is_empty());
        assert!(!dev.irq_active, "IRQ deasserts once both queues drained");
    }

    #[test]
    fn hbpp_req_cal_mem_read_and_nop_ladder() {
        let mut dev = MtSpi::default();

        // REQ_CAL → CAL_DONE (0x6949) queued in pending_hbpp, delivered on
        // the next INT_ACK.
        let replies = dev.clock(&[HBPP_PACKET_REQ_CAL, 0]);
        assert_eq!(replies, vec![0, 0]);
        assert_eq!(dev.pending_hbpp.data, HBPP_PACKET_CAL_DONE.to_le_bytes());
        assert!(dev.irq_active);
        let replies = dev.clock(&[HBPP_PACKET_INT_ACK, 0]);
        assert_eq!(replies, HBPP_PACKET_CAL_DONE.to_le_bytes().to_vec());
        assert!(!dev.irq_active);

        // MEM_READ → ACK_RD_REQ + value(0) + crc(0), held until INT_ACK.
        dev.clock(&[HBPP_PACKET_MEM_READ, 0, 0, 0, 0, 0, 0, 0]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&HBPP_PACKET_ACK_RD_REQ.to_le_bytes());
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(dev.pending_hbpp.data, expected);
        assert!(dev.irq_active);

        // NOP only answers on the first (type) byte and only when TX is
        // empty: ACK_NOP (0x7948) lands directly in the TX stream.
        let mut dev2 = MtSpi::default();
        let replies = dev2.clock(&[HBPP_PACKET_NOP]);
        assert_eq!(replies, vec![0x48]); // low byte of ACK_NOP, LE
        assert_eq!(dev2.tx.data, HBPP_PACKET_ACK_NOP.to_le_bytes());

        // Unknown HBPP packet type counts as unknown protocol traffic
        // (upstream error_report()s once per received byte of the packet).
        let mut dev3 = MtSpi::default();
        dev3.clock(&[0xEE, 0xEE]);
        assert_eq!(dev3.unknown_packets, 2);
    }

    #[test]
    fn ll_get_feature_family_id_response_flow() {
        let mut dev = MtSpi::new(828, 1792);

        // Frame 1: CONTROL / GET_FEATURE_REPORT / FAMILY_ID (0xD1)
        let payload = [
            HID_CONTROL_PACKET_GET_FEATURE_REPORT,
            HID_REPORT_FAMILY_ID,
            0x00, // unused
            0x42, // frame_number
        ];
        let replies = dev.clock(&ll_frame(LL_PACKET_CONTROL, 0, &payload));
        // preamble echo
        assert_eq!(&replies[..4], &LL_PACKET_PREAMBLE.to_le_bytes());
        // pending_fw empty at frame start ⇒ NO_DATA response on the wire
        assert_eq!(replies[4], LL_PACKET_NO_DATA);
        // ... and the feature response is queued once the frame completed
        assert_eq!(dev.pending_fw.len(), 1);
        let queued = dev.pending_fw.front().unwrap();
        assert_eq!(queued.packet_type, LL_PACKET_CONTROL);
        assert!(dev.irq_active);

        // Frame 2: just the LL type byte is enough to flush the queued
        // response into TX (upstream flushes at `get_pos == 4`); clock some
        // trailing zeros to read the response header out of the stream.
        let mut probe = vec![0xEF, 0xBE, 0xAD, 0xDE, LL_PACKET_NO_DATA];
        probe.resize(32, 0);
        let replies = dev.clock(&probe);
        assert_eq!(&replies[..4], &LL_PACKET_PREAMBLE.to_le_bytes());
        // LL header: CONTROL, interface 0, off 0, remaining 0, len 12
        assert_eq!(
            &replies[4..12],
            &[0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00]
        );
        // HID report header: SET_OUTPUT_REPORT, FAMILY_ID, SUCCESS, frame
        // 0x42, len_req 0, payload_length 2, then report_id + value 0xC3
        assert_eq!(
            &replies[12..22],
            &[
                HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                HID_REPORT_FAMILY_ID,
                HID_PACKET_STATUS_SUCCESS,
                0x42,
                0x00,
                0x00,
                0x02,
                0x00,
                HID_REPORT_FAMILY_ID,
                MT_FAMILY_ID,
            ]
        );
        assert!(dev.pending_fw.is_empty());
    }

    #[test]
    fn ll_basic_device_info_and_unknown_report_defaults() {
        let mut dev = MtSpi::default();

        let payload = [
            HID_CONTROL_PACKET_GET_FEATURE_REPORT,
            HID_REPORT_BASIC_DEVICE_INFO,
            0,
            0x11,
        ];
        dev.clock(&ll_frame(LL_PACKET_CONTROL, 0, &payload));
        let queued = dev.pending_fw.front().unwrap().buf.clone();
        // report hdr(9): type,id,status,frame,len_req(0),payload_len(6)+id
        assert_eq!(
            &queued.data[..9],
            &[
                HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                HID_REPORT_BASIC_DEVICE_INFO,
                HID_PACKET_STATUS_SUCCESS,
                0x11,
                0x00,
                0x00, // length_requested
                0x06,
                0x00, // payload_length = 5 + report_id
                HID_REPORT_BASIC_DEVICE_INFO,
            ][..]
        );
        // content: little-endian flag, rows 31, cols 15, bcd 0x292 bswapped
        assert_eq!(
            &queued.data[9..14],
            &[MT_LITTLE_ENDIAN, MT_ROWS, MT_COLUMNS, 0x02, 0x92][..]
        );
        assert_eq!(queued.len, 16); // hdr(9) + content(5) + crc(2)

        // Unknown report id → 1-byte zero report (upstream default case).
        let mut dev2 = MtSpi::default();
        let payload = [
            HID_CONTROL_PACKET_GET_FEATURE_REPORT,
            HID_REPORT_BUTTONS, // no dedicated handler upstream
            0,
            0x00,
        ];
        dev2.clock(&ll_frame(LL_PACKET_CONTROL, 0, &payload));
        let queued = dev2.pending_fw.front().unwrap().buf.clone();
        assert_eq!(queued.data[8], HID_REPORT_BUTTONS);
        assert_eq!(queued.data[9], 0); // single zero byte payload
        assert_eq!(queued.len, 12); // hdr(9)+val(1)+crc(2)

        // SET_FEATURE_REPORT path answers with an empty 8-byte HID header.
        let mut dev3 = MtSpi::default();
        let payload = [
            HID_CONTROL_PACKET_SET_FEATURE_REPORT,
            HID_REPORT_STATUS,
            0,
            0x33,
        ];
        dev3.clock(&ll_frame(LL_PACKET_CONTROL, 0, &payload));
        let queued = dev3.pending_fw.front().unwrap().buf.clone();
        assert_eq!(
            &queued.data[..4],
            &[
                HID_CONTROL_PACKET_SET_OUTPUT_REPORT,
                HID_REPORT_STATUS,
                HID_PACKET_STATUS_SUCCESS,
                0x33,
            ][..]
        );
        assert_eq!(queued.len, 10); // hdr(8) + crc(2)
    }

    #[test]
    fn touch_stage_ladder_irq_and_frame_wrap() {
        let mut dev = MtSpi::new(828, 1792);
        let t0 = 1_000_000_000;

        // press → MAKE_TOUCH
        dev.submit_touch_report(1000, 2000, MOUSE_EVENT_LBUTTON, t0);
        assert_eq!(dev.pending_fw.len(), 1);
        assert!(dev.irq_active);
        let pkt = dev.pending_fw.back().unwrap();
        assert_eq!(pkt.packet_type, LL_PACKET_LOSSLESS_OUTPUT);
        let p = &pkt.buf;
        // report hdr(9, incl. report id) + 27+20 content + crc16(2)
        assert_eq!(p.len, 9 + 27 + 20 + 2);
        assert_eq!(p.data[0], HID_TRANSFER_PACKET_OUTPUT);
        assert_eq!(p.data[1], HID_REPORT_BINARY_PATH_OR_IMAGE);
        assert_eq!(p.data[3], 0); // frame 0
        assert_eq!(&p.data[6..8], &48u16.to_le_bytes()); // 27+20+report_id
        assert_eq!(p.data[9], 0); // frame byte
        assert_eq!(p.data[10], 28); // header len
        assert_eq!(p.data[24], 1); // path count
        assert_eq!(p.data[25], 20); // path len
        assert_eq!(p.data[36], 1); // path id
        assert_eq!(p.data[37], PATH_STAGE_MAKE_TOUCH);
        assert_eq!(&p.data[40..42], &1000u16.to_le_bytes()); // x
        assert_eq!(&p.data[42..44], &2000u16.to_le_bytes()); // y
        assert_eq!(&p.data[48..50], &660u16.to_le_bytes()); // rad0
        assert_eq!(&p.data[50..52], &580u16.to_le_bytes()); // rad1
        assert_eq!(&p.data[52..54], &19317u16.to_le_bytes()); // angle
        assert_eq!(&p.data[54..56], &100u16.to_le_bytes()); // rad multiplier
        assert_eq!(dev.frame, 1);

        // move while held → no press/release edge, but the repeat timer
        // fires TOUCHING after 1/10 s.
        dev.submit_touch_report(1100, 2000, MOUSE_EVENT_LBUTTON, t0 + 50_000_000);
        assert_eq!(dev.pending_fw.len(), 1);
        dev.tick(t0 + 100_000_000);
        assert_eq!(dev.pending_fw.len(), 2);
        assert_eq!(
            dev.pending_fw.back().unwrap().buf.data[37],
            PATH_STAGE_TOUCHING
        );
        // still held ⇒ timer re-armed for another 1/20 s
        dev.tick(t0 + 120_000_000); // not reached yet (deadline t0+150ms)
        assert_eq!(dev.pending_fw.len(), 2);
        // coords must move again or no TOUCHING is generated
        dev.submit_touch_report(1200, 2000, MOUSE_EVENT_LBUTTON, t0 + 140_000_000);
        dev.tick(t0 + 150_000_000);
        assert_eq!(dev.pending_fw.len(), 3);
        assert_eq!(
            dev.pending_fw.back().unwrap().buf.data[37],
            PATH_STAGE_TOUCHING
        );

        // release → BREAK_TOUCH, end timer arms OUT_OF_RANGE after 1/10 s
        dev.submit_touch_report(1200, 2000, 0, t0 + 200_000_000);
        assert_eq!(
            dev.pending_fw.back().unwrap().buf.data[37],
            PATH_STAGE_BREAK_TOUCH
        );
        assert_eq!(dev.pending_fw.len(), 4);
        assert!(dev.timer_deadline.is_none());
        assert_eq!(dev.end_timer_deadline, Some(t0 + 300_000_000));
        dev.tick(t0 + 299_999_999);
        assert_eq!(dev.pending_fw.len(), 4);
        dev.tick(t0 + 300_000_000);
        assert_eq!(dev.pending_fw.len(), 5);
        assert_eq!(
            dev.pending_fw.back().unwrap().buf.data[37],
            PATH_STAGE_OUT_OF_RANGE
        );
        assert_eq!((dev.prev_x, dev.prev_y, dev.prev_ts), (0, 0, 0));

        // frame counter wraps 0xFF → 0
        dev.frame = 0xFF;
        dev.submit_touch_report(5, 5, MOUSE_EVENT_LBUTTON, t0 + 400_000_000);
        assert_eq!(dev.frame, 0);
    }

    #[test]
    fn mouse_event_scaling_and_y_calibration() {
        let mut dev = MtSpi::new(828, 1792);
        let t0 = 2_000_000_000;

        // Far right: x maps onto the full 6458 surface.
        dev.mouse_event(INPUT_EVENT_ABS_MAX, 0, 0, t0);
        assert_eq!(dev.x, MT_SENSOR_SURFACE_WIDTH as i16);
        // dy=0 ⇒ "max - dy" scales to the full height, minus the hardcoded
        // 16px y calibration: 13977 - 16*13977/1792 = 13977 - 124 = 13853.
        assert_eq!(dev.y, 13853);

        // dy=ABS_MAX ⇒ y = 0 - 124 (i16 like upstream's int16_t)
        dev.mouse_event(INPUT_EVENT_ABS_MAX, INPUT_EVENT_ABS_MAX, 0, t0);
        assert_eq!(dev.y, -124);

        // Left button edge press queues MAKE_TOUCH (IRQ active).
        dev.mouse_event(0x4000, 0x4000, MOUSE_EVENT_LBUTTON, t0);
        assert!(dev.irq_active);
        assert_eq!(
            dev.pending_fw.back().unwrap().buf.data[37],
            PATH_STAGE_MAKE_TOUCH
        );
        assert_eq!(dev.timer_deadline, Some(t0 + NANOSECONDS_PER_SECOND / 10));

        // The SSI glue: MtSpi plugs into the spi1 controller as a slave.
        let _slave: &mut dyn crate::gpio_i2c_spi::SpiSlave = &mut dev;
        dev.spi_transfer(0x00); // HBPP garbage byte must not panic
    }
}
