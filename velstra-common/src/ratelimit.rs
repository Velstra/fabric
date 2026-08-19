//! Per-rule rate limiting: a token bucket, as pure arithmetic.
//!
//! The data plane owns only the map access; every decision — refill, cap, spend —
//! lives here so it runs unchanged in the kernel and in the test suite. That
//! matters more than usual for a limiter: an off-by-one in the refill is invisible
//! in a packet capture and shows up months later as a rule that throttles traffic
//! it was never meant to touch.

/// Nanoseconds in a second. The kernel clock is nanoseconds; a rate is per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// One rule's token bucket, as stored in the `RULE_LIMITS` array.
///
/// Tokens are scaled by [`NANOS_PER_SEC`] rather than counted whole, so a refill
/// shorter than one token's worth of time is not lost to truncation. Without the
/// scaling a 10/s limit refilled on every packet of a fast flow would gain
/// `elapsed * 10 / 1e9 == 0` tokens each time and throttle to a standstill.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RateBucket {
    /// Sustained rate, packets per second. `0` disables the bucket (always allow),
    /// which is what an unprogrammed slot reads as.
    pub rate: u32,
    /// Burst capacity in packets — how much idle time may be banked.
    pub burst: u32,
    /// Available tokens, scaled by [`NANOS_PER_SEC`].
    pub tokens: u64,
    /// Kernel monotonic timestamp of the last refill, nanoseconds.
    pub last_ns: u64,
}

impl RateBucket {
    /// A fresh bucket, starting full so a rule does not throttle the first burst
    /// after a config apply.
    #[inline]
    pub const fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate,
            burst,
            tokens: (burst as u64) * NANOS_PER_SEC,
            last_ns: 0,
        }
    }

    /// The bucket's ceiling in scaled tokens. At most `u32::MAX × 1e9`, which is
    /// what keeps every later product inside u64 without a checked multiply.
    #[inline]
    const fn capacity(&self) -> u64 {
        (self.burst as u64) * NANOS_PER_SEC
    }

    /// Account for `now` and decide whether one packet may pass, updating the
    /// bucket in place.
    ///
    /// A zero `rate` always allows — an unprogrammed slot must never silently
    /// block traffic. A clock that appears to move backwards (a CPU whose
    /// timestamp lags another's) refills nothing rather than draining the bucket.
    #[inline]
    pub fn take(&mut self, now_ns: u64) -> bool {
        self.take_n(now_ns, 1)
    }

    /// Account for `now` and decide whether `n` units may pass.
    ///
    /// The bucket is deliberately **unit-agnostic**: `rate` and `burst` are per
    /// second and in whatever the thing being limited is counted in, and the map
    /// the bucket lives in is what names that. A per-rule limiter spends one unit
    /// per packet and its numbers are packets; a per-port limiter spends the
    /// frame's length and its numbers are bytes. One arithmetic, tested once —
    /// and the alternative, a second bucket type differing only in a comment,
    /// is how two limiters end up disagreeing about what a burst means.
    #[inline]
    pub fn take_n(&mut self, now_ns: u64, n: u32) -> bool {
        if self.rate == 0 {
            return true;
        }
        let cap = self.capacity();
        if self.last_ns == 0 {
            // First packet: the bucket already starts full, so anchor the clock
            // rather than banking the whole system uptime as credit.
            self.last_ns = now_ns;
        } else if now_ns > self.last_ns {
            // Clamp the gap to the time a refill from empty would take, *before*
            // multiplying. Two reasons, and the second is the binding one: any
            // longer gap is capped away in the next step anyway, and a checked
            // multiply here needs a 128-bit product, which the BPF target has no
            // `__multi3` for — the kernel build fails outright. Clamped, the
            // product is at most `cap` and the sum at most `2 × cap`, both well
            // inside u64.
            let full_ns = cap / (self.rate as u64);
            let elapsed = now_ns - self.last_ns;
            let elapsed = if elapsed > full_ns { full_ns } else { elapsed };
            // elapsed ns × rate/s = scaled tokens, already in the same units.
            self.tokens += elapsed * (self.rate as u64);
            if self.tokens > cap {
                self.tokens = cap;
            }
            self.last_ns = now_ns;
        }
        // A timestamp behind the last one refills nothing *and does not rewind the
        // clock*: rewinding would make the next packet measure the same gap twice
        // and bank credit the bucket never earned. Timestamps come from whichever
        // CPU handled the packet, so this is a normal occurrence, not a fault.
        // `n` is at most a frame length and `NANOS_PER_SEC` is 1e9, so the
        // product is ~1e13 at worst — nowhere near u64, and no checked multiply
        // (which the BPF target cannot lower: see the `__multi3` note above).
        let want = (n as u64) * NANOS_PER_SEC;
        if self.tokens >= want {
            self.tokens -= want;
            true
        } else {
            // Not "spend what there is": a partial spend would let a stream of
            // over-budget frames drain the bucket for ever and never pass one,
            // which is a limiter that has turned into a blackhole.
            false
        }
    }
}

// SAFETY: `#[repr(C)]` with only integer fields and no padding — safe to copy
// to/from a BPF map.
#[cfg(feature = "user")]
unsafe impl aya::Pod for RateBucket {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The burst is what a bucket may bank, and it is spendable immediately: a
    /// limiter that made the first packets wait would look like packet loss right
    /// after every config apply.
    #[test]
    fn a_fresh_bucket_spends_its_full_burst_at_once() {
        let mut b = RateBucket::new(10, 5);
        for i in 0..5 {
            assert!(b.take(1_000), "packet {i} of the burst was throttled");
        }
        assert!(!b.take(1_000), "the sixth packet must exceed a burst of 5");
    }

    /// Refilling is proportional to elapsed time, not to packet arrivals — the
    /// property that makes the limit a *rate* rather than a ratio.
    #[test]
    fn tokens_refill_with_time_and_stop_at_the_burst() {
        let mut b = RateBucket::new(10, 5);
        let start = 1_000_000_000;
        for _ in 0..5 {
            assert!(b.take(start));
        }
        assert!(!b.take(start));
        // Half a second at 10/s is 5 tokens, exactly the burst.
        assert!(b.take(start + NANOS_PER_SEC / 2));
        // …and idling far longer banks no more than the burst.
        let mut c = RateBucket::new(10, 5);
        for _ in 0..5 {
            assert!(c.take(start));
        }
        let later = start + 60 * NANOS_PER_SEC;
        for i in 0..5 {
            assert!(c.take(later), "banked token {i} after a long idle");
        }
        assert!(
            !c.take(later),
            "a minute of idling must not exceed the burst"
        );
    }

    /// Sub-second refills are the normal case for any real rate, and truncating
    /// them to whole tokens would throttle a limited rule to a standstill under
    /// load — the packets arrive far more often than one token's worth of time.
    #[test]
    fn a_refill_shorter_than_one_token_is_not_lost() {
        let mut b = RateBucket::new(1_000, 1);
        let mut t = 1_000_000_000;
        assert!(b.take(t));
        // One millisecond at 1000/s is exactly one token.
        for i in 0..100 {
            t += 1_000_000;
            assert!(b.take(t), "packet {i} lost its sub-second refill");
        }
        // …but arriving twice as fast is throttled to half.
        let mut allowed = 0;
        for _ in 0..100 {
            t += 500_000;
            if b.take(t) {
                allowed += 1;
            }
        }
        assert!(
            (45..=55).contains(&allowed),
            "expected about half of 100 to pass, got {allowed}"
        );
    }

    /// An unprogrammed slot reads as all-zero. Blocking on it would turn a
    /// half-applied config into a black hole, so a zero rate allows.
    #[test]
    fn an_unprogrammed_bucket_never_blocks() {
        let mut b = RateBucket::new(0, 0);
        for _ in 0..1_000 {
            assert!(b.take(0));
        }
    }

    /// Timestamps come from whichever CPU handled the packet, so `now` can appear
    /// to move backwards. That must cost nothing — and, less obviously, must not
    /// rewind the bucket's clock either: writing this test caught exactly that,
    /// where the packet *after* the backwards one measured the gap a second time
    /// and refilled the bucket to full.
    #[test]
    fn a_backwards_clock_neither_drains_nor_credits_the_bucket() {
        let mut b = RateBucket::new(10, 5);
        let t = 10 * NANOS_PER_SEC;
        assert!(b.take(t));
        assert!(b.take(t - NANOS_PER_SEC));
        assert!(b.take(t));
        // Four of the five burst tokens are spent, so one remains.
        assert!(b.take(t));
        assert!(b.take(t));
        assert!(!b.take(t));
    }
}

#[cfg(test)]
mod byte_tests {
    use super::*;

    /// A megabit ceiling, as a per-port limiter programs it: bytes per second.
    fn port_bucket(mbit: u32, burst_bytes: u32) -> RateBucket {
        RateBucket::new(mbit * 125_000, burst_bytes)
    }

    #[test]
    fn a_frame_costs_its_own_length() {
        let mut b = port_bucket(1, 3_000);
        assert!(
            b.take_n(1_000, 1_500),
            "the first frame did not fit the burst"
        );
        assert!(
            b.take_n(1_000, 1_500),
            "the burst was not spendable in full"
        );
        assert!(
            !b.take_n(1_000, 1_500),
            "a third frame fitted a two-frame burst"
        );
    }

    #[test]
    fn an_oversized_frame_does_not_drain_the_bucket_for_ever() {
        // Spending what there is and still refusing would mean a stream of
        // over-budget frames never passes one — a limiter turned blackhole.
        let mut b = port_bucket(1, 1_000);
        assert!(
            !b.take_n(1_000, 9_000),
            "a jumbo frame fitted a 1000-byte burst"
        );
        assert!(b.take_n(1_000, 900), "the refusal spent the bucket anyway");
    }

    #[test]
    fn the_refill_is_in_the_same_unit_as_the_rate() {
        // 1 Mbit/s = 125_000 bytes/s, so a tenth of a second buys 12_500 bytes.
        let mut b = port_bucket(1, 1_500);
        assert!(b.take_n(1_000_000_000, 1_500));
        assert!(!b.take_n(1_000_000_000, 1_500));
        assert!(
            b.take_n(1_100_000_000, 1_500),
            "100ms at 1 Mbit did not refill one 1500-byte frame"
        );
    }

    #[test]
    fn a_packet_limiter_still_spends_one_per_packet() {
        // The unit is the caller's; `take` must keep meaning what it meant.
        let mut b = RateBucket::new(10, 2);
        assert!(b.take(1_000));
        assert!(b.take(1_000));
        assert!(!b.take(1_000));
    }

    #[test]
    fn a_zero_rate_allows_whatever_the_unit_is() {
        // An unprogrammed slot must never silently black-hole a port.
        let mut b = RateBucket::new(0, 0);
        assert!(b.take_n(1_000, 9_000));
    }
}
