//! interval_timer — libqemuutil port (`qemu/include/qemu/timer.h` periodic
//! timer subset, as used by machine tick loops).
//!
//! QEMU's `QEMUTimer` fires at an absolute deadline and is re-armed by the
//! callback; the common device-model pattern for a fixed-period timer
//! (`timer_mod_ns(ts, now + interval)` inside the callback) collapses to:
//! `due(now)` -> fire + `advance(now)`. This module implements exactly that
//! with a virtual monotonic clock so tests are deterministic and the T8030
//! tick loop can drive it without a host dependency.

/// Fixed-period scheduler on a virtual nanosecond clock.
#[derive(Debug, Clone)]
pub struct IntervalTimer {
    interval_ns: u64,
    /// Next absolute deadline (ns). A timer starts disarmed (deadline 0
    /// means "fires on the first advance").
    next_due: u64,
    /// Fire count since construction (diagnostics / tick loops).
    fires: u64,
}

impl IntervalTimer {
    /// Create a timer with the given period; it fires on the first `advance`
    /// with `now >= 0` unless [`IntervalTimer::reset`] anchors it later.
    pub fn new(interval_ns: u64) -> Self {
        assert!(interval_ns > 0, "interval must be non-zero");
        IntervalTimer { interval_ns, next_due: 0, fires: 0 }
    }

    /// Period in nanoseconds.
    pub fn interval(&self) -> u64 {
        self.interval_ns
    }

    /// Absolute next deadline (QEMU `timer_expire_time_ns`).
    pub fn next_due(&self) -> u64 {
        self.next_due
    }

    /// Number of fires so far.
    pub fn fires(&self) -> u64 {
        self.fires
    }

    /// Re-arm with the deadline `now + interval` (QEMU `timer_mod_ns`).
    pub fn reset(&mut self, now_ns: u64) {
        self.next_due = now_ns + self.interval_ns;
    }

    /// Is the deadline reached at `now_ns`?
    pub fn due(&self, now_ns: u64) -> bool {
        now_ns >= self.next_due
    }

    /// Advance the schedule past `now_ns`: keeps the periodic grid where
    /// possible (catching up in whole intervals in O(1)) but never schedules
    /// a deadline in the past, so a slow caller cannot spin forever.
    /// Returns the number of missed firings that were coalesced.
    pub fn advance(&mut self, now_ns: u64) -> u64 {
        if !self.due(now_ns) {
            return 0;
        }
        self.fires += 1;
        // Whole intervals behind the grid — closed form instead of a catch-up
        // loop so a huge virtual-time jump cannot spin.
        let behind = now_ns.saturating_sub(self.next_due);
        let steps = behind / self.interval_ns; // coalesced periods
        let next = match self
            .next_due
            .checked_add(steps.saturating_add(1).saturating_mul(self.interval_ns))
        {
            Some(n) if n > now_ns => n,
            _ => now_ns.saturating_add(self.interval_ns),
        };
        self.next_due = next;
        steps
    }

    /// Consume one period unconditionally (`due` + `advance` for callers
    /// that know the tick arrived).
    pub fn tick(&mut self, now_ns: u64) {
        if self.next_due > now_ns {
            self.next_due = now_ns + self.interval_ns;
        } else {
            let _ = self.advance(now_ns);
        }
        self.fires += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_every_interval() {
        let mut t = IntervalTimer::new(100);
        assert!(t.due(0)); // anchored at 0 by default
        assert_eq!(t.advance(0), 1); // fires once, next due at 100
        assert_eq!(t.next_due(), 100);
        assert!(!t.due(50));
        assert_eq!(t.advance(50), 0);
        assert!(t.due(100));
        assert_eq!(t.advance(100), 1);
        assert_eq!(t.next_due(), 200);
        assert_eq!(t.fires(), 2);
    }

    #[test]
    fn catches_up_in_whole_intervals() {
        let mut t = IntervalTimer::new(100);
        t.advance(0);
        // A jump of 350ns past due: grid preserved (100->200->300->400).
        let missed = t.advance(450);
        assert_eq!(t.next_due(), 500);
        assert!(missed >= 1);
        assert_eq!(t.fires(), 2); // one fire for this advance call
        // Coalesced periods are reported so callers can emulate bursts.
        assert!(missed == 3 || missed == 4);
    }

    #[test]
    fn huge_jump_never_spins() {
        let mut t = IntervalTimer::new(10);
        t.reset(0);
        let missed = t.advance(u64::MAX - 5);
        assert!(missed > 0);
        assert!(t.next_due() > u64::MAX - 5);
        assert_eq!(t.next_due(), u64::MAX); // saturating re-anchor
    }

    #[test]
    fn reset_anchors_and_tick() {
        let mut t = IntervalTimer::new(1000);
        t.reset(5_000);
        assert_eq!(t.next_due(), 6_000);
        assert!(!t.due(5_999));
        t.tick(6_000);
        assert_eq!(t.next_due(), 7_000);
        assert_eq!(t.fires(), 1);
    }
}
