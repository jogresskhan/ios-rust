//! buttons — Apple iPhone 11 buttons (port of hw/misc/apple-silicon/buttons.c).
//!
//! Upstream is **not** an MMIO device: it is a QEMU input handler that maps
//! host F1..F10 keys onto SMC HID buttons and exposes four SMC keys
//! (`bVUP`, `bVDN`, `bHLD`, `bRIN`, all UINT32-LE) plus the static
//! `bPHD` FLAG key ("powered by hold button" = true).
//! This port keeps the exact state machine (`states: u16` bitmask) and the
//! BUTTON_READER semantics (`bVUP`/`bVDN`/`bHLD` read `pressed == 0`,
//! i.e. 0 when the button is down, `bRIN` reads `ringer != 0`).
//! The upstream SMC call `apple_smc_send_hid_button()` is surfaced as the
//! `smc_hid_events` counter + `last_event_*` fields (the Rust `Smc` model
//! has no HID key API yet — wire-up point documented in `handle_key`).
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! For the flat-bus [`Device`] view (QEMU has no MMIO region here) the SMC
//! keys are mapped to documented pseudo-offsets: 0x00 `bVUP`, 0x04 `bVDN`,
//! 0x08 `bHLD`, 0x0C `bRIN`, 0x10 `bPHD`.

use vm_core::Device;

/// QKeyCode enum indices for F1..F10 (from QEMU `qapi/ui.json` `QKeyCode`,
/// identical order upstream; `unmapped` = 0, `f1` = 62).
pub const QKEY_F1: u32 = 62;
pub const QKEY_F2: u32 = 63;
pub const QKEY_F3: u32 = 64;
pub const QKEY_F4: u32 = 65;
pub const QKEY_F5: u32 = 66;
pub const QKEY_F6: u32 = 67;
pub const QKEY_F7: u32 = 68;
pub const QKEY_F8: u32 = 69;
pub const QKEY_F9: u32 = 70;
pub const QKEY_F10: u32 = 71;

/// Port of `AppleSMCHIDButton` (hw/misc/apple-silicon/smc.h).
pub const BUTTON_FORCE_SHUTDOWN: u8 = 0;
pub const BUTTON_HOLD: u8 = 1;
pub const BUTTON_VOL_UP: u8 = 2;
pub const BUTTON_VOL_DOWN: u8 = 3;
pub const BUTTON_RINGER: u8 = 4;
pub const BUTTON_HELP: u8 = 5;
pub const BUTTON_MENU: u8 = 6;
pub const BUTTON_HELP_DOUBLE: u8 = 7;
pub const BUTTON_HALL_EFFECT_1: u8 = 8;
pub const BUTTON_HALL_EFFECT: u8 = 9;
pub const BUTTON_COUNT: u8 = 10;

/// SMC key FourCCs registered by `apple_buttons_create` ('bVUP' … 'bPHD').
pub const SMC_KEY_BVUP: u32 = u32::from_be_bytes(*b"bVUP");
pub const SMC_KEY_BVDN: u32 = u32::from_be_bytes(*b"bVDN");
pub const SMC_KEY_BHLD: u32 = u32::from_be_bytes(*b"bHLD");
pub const SMC_KEY_BRIN: u32 = u32::from_be_bytes(*b"bRIN");
pub const SMC_KEY_BPHD: u32 = u32::from_be_bytes(*b"bPHD");

/// `bPHD` static payload: "powered by hold button" flag, always true.
pub const POWERED_BY_HOLD_BTN: u32 = 1;

/// Bus-view offsets for the SMC keys (see module docs).
pub const BUS_KEY_BVUP: u64 = 0x00;
pub const BUS_KEY_BVDN: u64 = 0x04;
pub const BUS_KEY_BHLD: u64 = 0x08;
pub const BUS_KEY_BRIN: u64 = 0x0C;
pub const BUS_KEY_BPHD: u64 = 0x10;

/// Apple iPhone 11 button state (port of `AppleButtonsState`).
pub struct AppleButtons {
    /// u16 bitmask of currently-pressed/toggled buttons (one bit per
    /// [`BUTTON_COUNT`] HID button), cleared on reset (qdev reset_hold).
    pub states: u16,
    /// Count of `qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER)` calls.
    pub wake_requests: u64,
    /// Count of `apple_smc_send_hid_button()` calls (upstream pushes the
    /// event into the SMC; we record it until `Smc` grows a HID API).
    pub smc_hid_events: u64,
    pub last_event_button: Option<u8>,
    pub last_event_down: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl AppleButtons {
    pub fn new() -> Self {
        AppleButtons {
            states: 0,
            wake_requests: 0,
            smc_hid_events: 0,
            last_event_button: None,
            last_event_down: false,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    fn send_hid_button(&mut self, button: u8, down: bool) {
        // Upstream: apple_smc_send_hid_button(smc, button, down).
        self.smc_hid_events += 1;
        self.last_event_button = Some(button);
        self.last_event_down = down;
    }

    fn set_state(&mut self, button: u8, down: bool) {
        if down {
            self.states |= 1 << button;
        } else {
            self.states &= !(1 << button);
        }
    }

    /// Port of `apple_buttons_handle_event`: qcode → HID button, with the
    /// ringer (F2) toggle-on-press special case.
    pub fn handle_key(&mut self, qcode: u32, down: bool) {
        // qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, NULL)
        self.wake_requests += 1;

        let button = match qcode {
            QKEY_F1 => BUTTON_FORCE_SHUTDOWN,
            QKEY_F2 => {
                // Ringer: act on press only, toggle the latched state.
                if down {
                    let b = BUTTON_RINGER;
                    if self.states & (1 << b) != 0 {
                        self.states &= !(1 << b);
                    } else {
                        self.states |= 1 << b;
                    }
                    self.send_hid_button(b, self.states & (1 << b) != 0);
                }
                return;
            }
            QKEY_F3 => BUTTON_VOL_DOWN,
            QKEY_F4 => BUTTON_VOL_UP,
            QKEY_F5 => BUTTON_HOLD,
            QKEY_F6 => BUTTON_MENU,
            QKEY_F7 => BUTTON_HELP,
            QKEY_F8 => BUTTON_HELP_DOUBLE,
            QKEY_F9 => BUTTON_HALL_EFFECT_1,
            QKEY_F10 => BUTTON_HALL_EFFECT,
            _ => return, // not a button key: no wakeup state change either
        };

        // Common path: only report state *transitions*.
        if (self.states & (1 << button) != 0) != down {
            self.set_state(button, down);
            self.send_hid_button(button, down);
        }
    }

    /// Port of the four `BUTTON_READER` SMC key functions + `bPHD`.
    /// Returns the UINT32-LE payload for known keys, `None` otherwise.
    /// Note the C macro arms: `bVUP`/`bVDN`/`bHLD` compute
    /// `(states & BIT(btn)) == 0` (1 when NOT pressed) while `bRIN`
    /// computes `(states & BIT(btn)) != 0` (1 when the ringer is latched).
    pub fn smc_read_key(&self, key: u32) -> Option<u32> {
        match key {
            SMC_KEY_BVUP => Some(((self.states & (1 << BUTTON_VOL_UP)) == 0) as u32),
            SMC_KEY_BVDN => Some(((self.states & (1 << BUTTON_VOL_DOWN)) == 0) as u32),
            SMC_KEY_BHLD => Some(((self.states & (1 << BUTTON_HOLD)) == 0) as u32),
            SMC_KEY_BRIN => Some(((self.states & (1 << BUTTON_RINGER)) != 0) as u32),
            SMC_KEY_BPHD => Some(POWERED_BY_HOLD_BTN),
            _ => None,
        }
    }

    /// Port of `apple_buttons_qdev_reset_hold`: clear all button states.
    pub fn reset(&mut self) {
        self.states = 0;
    }
}

impl Default for AppleButtons {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for AppleButtons {
    fn name(&self) -> &'static str {
        "apple-buttons"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        // Not an MMIO device upstream; documented SMC-key bus view instead.
        let key = match off {
            BUS_KEY_BVUP => SMC_KEY_BVUP,
            BUS_KEY_BVDN => SMC_KEY_BVDN,
            BUS_KEY_BHLD => SMC_KEY_BHLD,
            BUS_KEY_BRIN => SMC_KEY_BRIN,
            BUS_KEY_BPHD => SMC_KEY_BPHD,
            _ => {
                self.unknown_reads += 1;
                return 0;
            }
        };
        self.smc_read_key(key).unwrap_or(0) as u64
    }
    fn write(&mut self, off: u64, _size: u8, _val: u64) {
        // The C model exposes no writable interface at all.
        let _ = off;
        self.unknown_writes += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smc_key_readers_and_transitions() {
        let mut d = AppleButtons::new();
        // Reset-value assert: nothing pressed, ringer switch off.
        assert_eq!(d.states, 0);
        // BUTTON_READER arms: bVUP reads `(bit == 0)` → 1 when unpressed;
        // bRIN reads `(bit != 0)` → 0 while the ringer is unset.
        assert_eq!(d.smc_read_key(SMC_KEY_BVUP), Some(1));
        assert_eq!(d.smc_read_key(SMC_KEY_BRIN), Some(0));
        assert_eq!(d.smc_read_key(SMC_KEY_BPHD), Some(1));

        // Volume-up press (F4): bVUP reads 0 while held, 1 when released.
        d.handle_key(QKEY_F4, true);
        assert_eq!(d.smc_read_key(SMC_KEY_BVUP), Some(0));
        assert_eq!(d.smc_hid_events, 1);
        d.handle_key(QKEY_F4, false);
        assert_eq!(d.smc_read_key(SMC_KEY_BVUP), Some(1));
        // Repeat release must not emit a second SMC event.
        d.handle_key(QKEY_F4, false);
        assert_eq!(d.smc_hid_events, 2);

        // Ringer toggles only on press (F2); bRIN mirrors the latched bit.
        d.handle_key(QKEY_F2, true);
        assert_eq!(d.smc_read_key(SMC_KEY_BRIN), Some(1));
        d.handle_key(QKEY_F2, false); // release ignored for the ringer
        d.handle_key(QKEY_F2, true);
        assert_eq!(d.smc_read_key(SMC_KEY_BRIN), Some(0));

        // Reset clears the bitmask (port of reset_hold).
        d.handle_key(QKEY_F5, true);
        assert!(d.states != 0);
        d.reset();
        assert_eq!(d.states, 0);
    }

    #[test]
    fn unknown_offsets_counted() {
        let mut d = AppleButtons::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        assert_eq!(d.read(0x99, 4), 0);
        assert_eq!(d.unknown_reads, 1);
        d.write(0x99, 4, 0xdead);
        assert_eq!(d.unknown_writes, 1);
        // Known key offsets never hit the counters.
        let _ = d.read(BUS_KEY_BHLD, 4);
        assert_eq!(d.unknown_reads, 1);
    }
}
