//! throttle — libqemuutil port (`qemu/util/throttle.c` + `qemu/include/qemu/throttle.h`, subset).
//!
//! Upstream: QEMU block throttling, Copyright (C) Nodalink, EURL. 2013-2014
//! (Benoît Canet), GPL-2.0-or-later. QEMU models each direction as a
//! `LeakyBucket` with an average rate and a current level; `throttle_compute`
//! refills the bucket by `avg * elapsed` and refuses work when the bucket is
//! empty. This subset keeps exactly that token/leaky-bucket behaviour with a
//! burst window (`interval_ns` == upstream bucket `max` capacity expressed as
//! a time window) and a monotonic virtual-clock interface so tests are
//! deterministic.

/// Leaky-bucket rate limiter — QEMU `LeakyBucket` + `ThrottleState` subset.
///
/// `avg` is bytes per second; `interval_ns` is the burst window (the bucket
/// holds at most `avg * interval_ns / 1e9` tokens).
#[derive(Debug, Clone)]
pub struct ThrottleState {
    /// Average rate in bytes/second (upstream `bucket.avg`).
    pub avg: f64,
    /// Burst window in nanoseconds (defines the bucket capacity).
    pub interval_ns: u64,
    /// Current bucket level in bytes (upstream `bucket.level`).
    budget: f64,
    /// Virtual timestamp of the last refill/attempt (ns).
    last: u64,
}

impl ThrottleState {
    /// New limiter at `avg` bytes/second with a burst window of
    /// `interval_ns`; starts with a full bucket like a freshly configured
    /// upstream throttle group.
    pub fn new(avg: f64, interval_ns: u64) -> Self {
        let mut s = ThrottleState { avg, interval_ns, budget: 0.0, last: 0 };
        s.reset(0);
        s
    }

    /// Change the rate/window (upstream `throttle_config`); the bucket is
    /// re-primed so new settings start from a clean state.
    pub fn configure(&mut self, avg: f64, interval_ns: u64, now_ns: u64) {
        self.avg = avg;
        self.interval_ns = interval_ns;
        self.reset(now_ns);
    }

    /// Prime the bucket at `now_ns`.
    pub fn reset(&mut self, now_ns: u64) {
        self.last = now_ns;
        self.budget = self.capacity();
    }

    /// Bucket capacity in bytes (`avg` over one burst window).
    fn capacity(&self) -> f64 {
        self.avg * self.interval_ns as f64 / 1e9
    }

    /// Refill the bucket from elapsed virtual time (capped at capacity) —
    /// upstream `throttle_do_compute_wait`/refill logic.
    fn refresh(&mut self, now_ns: u64) {
        if now_ns > self.last {
            let elapsed_s = (now_ns - self.last) as f64 / 1e9;
            self.budget = (self.budget + elapsed_s * self.avg).min(self.capacity());
            self.last = now_ns;
        }
    }

    /// Account `bytes` at virtual time `now_ns`.
    ///
    /// Returns `true` (within rate) when the bucket can pay for the bytes;
    /// they are consumed. Returns `false` (throttled) and consumes nothing
    /// when the bucket is short — callers retry later, like upstream's
    /// `throttle_schedule_timer` + retry path.
    pub fn account(&mut self, bytes: u64, now_ns: u64) -> bool {
        self.refresh(now_ns);
        if (self.budget - bytes as f64) >= 0.0 {
            self.budget -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Nanoseconds (from `now_ns`) until `bytes` would be admitted;
    /// 0 when already within rate. Mirrors upstream
    /// `throttle_compute_wait` for burst exhaustion.
    pub fn wait_time_ns(&mut self, bytes: u64, now_ns: u64) -> u64 {
        self.refresh(now_ns);
        let missing = bytes as f64 - self.budget;
        if missing <= 0.0 || self.avg <= 0.0 {
            return 0;
        }
        (missing / self.avg * 1e9).ceil() as u64
    }

    /// Current bucket level in bytes (diagnostics).
    pub fn level(&self) -> f64 {
        self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: f64 = 1024.0 * 1024.0;

    #[test]
    fn admits_within_rate() {
        // 10 MB/s with a 1 s window => 10 MB burst capacity.
        let mut t = ThrottleState::new(10.0 * MB, 1_000_000_000);
        // A 1 MB write is admitted ten times in a row (burst).
        for _ in 0..10 {
            assert!(t.account(1_048_576, 1_000));
        }
        // The bucket is now empty: the 11th is throttled.
        assert!(!t.account(1_048_576, 2_000));
    }

    #[test]
    fn refills_with_virtual_time() {
        let mut t = ThrottleState::new(1.0 * MB, 1_000_000_000);
        // Drain the whole bucket (1 MB/s * 1 s window).
        assert!(t.account(1_048_576, 0));
        assert!(!t.account(1_048_576, 1)); // empty
        // Half a second at 1 MB/s => ~0.5 MB available.
        let wait = t.wait_time_ns(1_048_576, 500_000_000);
        assert!(wait > 0);
        // After the full window the bucket is full again.
        assert_eq!(t.wait_time_ns(1_048_576, 1_000_000_000), 0);
        assert!(t.account(1_048_576, 1_000_000_000));
    }

    #[test]
    fn burst_window_caps_refill() {
        let mut t = ThrottleState::new(1.0 * MB, 1_000_000_000); // 1 MB bucket
        assert!(t.account(1_048_576, 0)); // full burst admitted
        // Half a window: only half the bucket refilled, still short.
        assert!(!t.account(1_048_576, 500_000_000));
        // A full window later the bucket is topped up again.
        assert!(t.account(1_048_576, 1_000_000_000));
        // Refill is capped at the window: no second burst right after.
        assert!(!t.account(1_048_576, 1_100_000_000));
        assert!(t.level() < 1_048_576.0);
    }

    #[test]
    fn reconfigure_resets() {
        let mut t = ThrottleState::new(1.0, 1_000_000_000);
        assert!(t.account(1, 0));
        t.configure(4.0, 1_000_000_000, 1_000);
        assert_eq!(t.avg, 4.0);
        assert_eq!(t.interval_ns, 1_000_000_000);
        // Freshly configured: full bucket again (capacity 4 bytes).
        assert!(t.account(4, 1_001));
        assert!(!t.account(4, 1_002));
    }
}
