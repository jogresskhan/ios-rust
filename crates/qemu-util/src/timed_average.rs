//! timed_average — libqemuutil port (`qemu/util/timed-average.c`).
//!
//! Upstream: "QEMU timed average computation", Copyright (C) Nodalink, EURL.
//! 2014 (Benoît Canet) / Copyright (C) Igalia, S.L. 2015 (Alberto Garcia),
//! GPL-2.0-or-later. Algorithm, verbatim from the upstream comment:
//!
//! > Create two windows with a certain expiration period, and offsetted by
//! > period / 2. Each time you want to account a new value, do it in both
//! > windows. The minimum / maximum / average values are always returned
//! > from the oldest window.
//!
//! The requested period is scaled by 4/3 upstream so returned statistics sit
//! in `[2/3·period, 4/3·period)`. This port generalises the two windows to
//! `max_periods` windows staggered by `period / n` (n = max(2, max_periods))
//! — with the QEMU default of 2 windows it is bit-for-bit the upstream
//! algorithm. Statistics always come from the oldest (earliest-expiring)
//! window and `min` reports 0 for an empty window, exactly like
//! `timed_average_min` upstream.

/// One averaging window — QEMU `TimedAverageWindow`.
#[derive(Debug, Clone)]
struct Window {
    min: u64,
    max: u64,
    sum: u64,
    count: u64,
    expiration: u64,
}

impl Window {
    fn new() -> Self {
        Window { min: u64::MAX, max: 0, sum: 0, count: 0, expiration: 0 }
    }

    fn reset(&mut self) {
        self.min = u64::MAX;
        self.max = 0;
        self.sum = 0;
        self.count = 0;
    }
}

/// Windowed min/max/avg — QEMU `TimedAverage`.
#[derive(Debug, Clone)]
pub struct TimedAverage {
    /// Scaled period in nanoseconds (upstream `ta->period`).
    period: u64,
    /// Requested `max_periods` (kept for API parity; QEMU always runs two
    /// overlapping windows, which is the faithful default here too).
    max_periods: u32,
    windows: Vec<Window>,
}

impl TimedAverage {
    /// QEMU `timed_average_init` with the caller-supplied clock replaced by
    /// the virtual `now_ns` the caller threads through every call.
    ///
    /// `max_periods` selects how many overlapping windows are maintained
    /// (QEMU uses two; values < 2 are clamped to 2).
    pub fn new(period_ns: u64, max_periods: u32) -> Self {
        let n = (max_periods as usize).max(2);
        // Upstream: ta->period = period * 4 / 3 so returned stats live in
        // [2/3·period, 4/3·period).
        let period = period_ns.checked_mul(4).map(|p| p / 3).unwrap_or(u64::MAX).max(1);
        let mut windows = vec![Window::new(); n];
        // Pre-anchor relative to t=0; call `start_at` for a real clock.
        for (i, w) in windows.iter_mut().enumerate() {
            w.expiration = period * (i as u64 + 1) / n as u64;
        }
        TimedAverage { period, max_periods, windows }
    }

    /// Anchor both windows to a concrete start time (`init` equivalent).
    pub fn start_at(&mut self, now_ns: u64) {
        let n = self.windows.len();
        for (i, w) in self.windows.iter_mut().enumerate() {
            w.reset();
            w.expiration = now_ns + self.period * (i as u64 + 1) / n as u64;
        }
    }

    /// Keep a window on its periodic grid — QEMU `update_expiration`.
    fn update_expiration(w: &mut Window, now: u64, period: u64) {
        let p = period as i128;
        let elapsed = ((now as i128 - w.expiration as i128) % p) as u64;
        w.expiration = now + (period - elapsed);
    }

    /// QEMU `check_expirations`: reset+reschedule expired windows and put
    /// the oldest (earliest-expiring) one at index 0.
    fn check_expirations_at(&mut self, now: u64) {
        debug_assert!(self.period != 0);
        for i in 0..self.windows.len() {
            if self.windows[i].expiration <= now {
                self.windows[i].reset();
                Self::update_expiration(&mut self.windows[i], now, self.period);
            }
        }
        // current = oldest window (QEMU keeps an index; we swap-to-front so
        // `windows[0]` is always the reported one).
        for i in 1..self.windows.len() {
            if self.windows[i].expiration < self.windows[0].expiration {
                self.windows.swap(i, 0);
            }
        }
    }

    /// QEMU `timed_average_account`: the value lands in every window.
    pub fn account_at(&mut self, value: u64, now_ns: u64) {
        self.check_expirations_at(now_ns);
        for w in &mut self.windows {
            w.sum = w.sum.saturating_add(value);
            w.count += 1;
            if value < w.min {
                w.min = value;
            }
            if value > w.max {
                w.max = value;
            }
        }
    }

    /// QEMU `timed_average_min` (0 for an empty window).
    pub fn min_at(&mut self, now_ns: u64) -> u64 {
        self.check_expirations_at(now_ns);
        let w = &self.windows[0];
        if w.min < u64::MAX {
            w.min
        } else {
            0
        }
    }

    /// QEMU `timed_average_max`.
    pub fn max_at(&mut self, now_ns: u64) -> u64 {
        self.check_expirations_at(now_ns);
        self.windows[0].max
    }

    /// QEMU `timed_average_avg` (0 when no values were accounted).
    pub fn avg_at(&mut self, now_ns: u64) -> u64 {
        self.check_expirations_at(now_ns);
        let w = &self.windows[0];
        if w.count > 0 {
            w.sum / w.count
        } else {
            0
        }
    }

    /// QEMU `timed_average_sum(elapsed)`: sum over the oldest window plus
    /// the elapsed time inside it.
    pub fn sum_at(&mut self, now_ns: u64) -> (u64, u64) {
        self.check_expirations_at(now_ns);
        let w = &self.windows[0];
        let remaining = w.expiration.saturating_sub(now_ns);
        let elapsed = self.period.saturating_sub(remaining);
        (w.sum, elapsed)
    }

    /// Requested period scale (diagnostics).
    pub fn max_periods(&self) -> u32 {
        self.max_periods
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_min_max_avg() {
        let mut ta = TimedAverage::new(1_000_000_000, 2);
        ta.start_at(0);
        for v in [10u64, 20, 30] {
            ta.account_at(v, 1);
        }
        assert_eq!(ta.min_at(1), 10);
        assert_eq!(ta.max_at(1), 30);
        assert_eq!(ta.avg_at(1), 20);
        let (sum, _elapsed) = ta.sum_at(1);
        assert_eq!(sum, 60);
    }

    #[test]
    fn empty_window_reports_zero() {
        let mut ta = TimedAverage::new(1_000, 2);
        ta.start_at(0);
        assert_eq!(ta.min_at(1), 0);
        assert_eq!(ta.max_at(1), 0);
        assert_eq!(ta.avg_at(1), 0);
        // QEMU doc: min of empty window is 0, not UINT64_MAX.
    }

    #[test]
    fn window_expiration_resets_stats() {
        let mut ta = TimedAverage::new(1_000, 2); // scaled to 1333ns
        ta.start_at(0);
        ta.account_at(100, 1);
        assert_eq!(ta.avg_at(2), 100);
        // Far past both windows' expirations: everything reset.
        assert_eq!(ta.avg_at(10_000), 0);
        assert_eq!(ta.max_at(10_000), 0);
    }

    #[test]
    fn oldest_window_is_reported() {
        // With two windows the stats switch to the other window after the
        // first one expires — the upstream wnd0/wnd1 alternation.
        let mut ta = TimedAverage::new(1_000, 2);
        ta.start_at(0);
        ta.account_at(7, 1);
        // Before any expiry both windows carry 7.
        assert_eq!(ta.min_at(1), 7);
        // After both expire, values are forgotten.
        assert_eq!(ta.min_at(5_000), 0);
        ta.account_at(9, 5_001);
        assert_eq!(ta.min_at(5_002), 9);
        assert_eq!(ta.max_at(5_002), 9);
    }
}
