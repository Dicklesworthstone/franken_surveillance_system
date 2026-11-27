#![forbid(unsafe_code)]
//! Recent ingress telemetry on the supervisor's host receive clock.
//!
//! Semantic plane: `"support"`.

const BUCKET_NS: i128 = 100_000_000;
const BUCKETS_PER_SECOND: usize = 10;
// The open bucket must coexist with all ten completed buckets in the reporting window.
const SLOTS: usize = BUCKETS_PER_SECOND + 1;

#[derive(Default)]
pub(crate) struct RecentFrameRate {
    buckets: [Option<(i128, u32)>; SLOTS],
}

impl RecentFrameRate {
    pub(crate) fn observe(&mut self, received_ns: i128) {
        let bucket = received_ns.div_euclid(BUCKET_NS);
        let slot = &mut self.buckets[bucket.rem_euclid(SLOTS as i128) as usize];
        match slot {
            Some((stored, count)) if *stored == bucket => *count = count.saturating_add(1),
            _ => *slot = Some((bucket, 1)),
        }
    }

    /// Count the frames in one exact second ending at the last 100 ms boundary.
    /// Reads are independent of polling cadence and never advance the measurement.
    pub(crate) fn milli_fps(&self, now_ns: i128) -> u32 {
        let end = now_ns.div_euclid(BUCKET_NS);
        let window = end - BUCKETS_PER_SECOND as i128..end;
        self.buckets
            .iter()
            .flatten()
            .filter(|(bucket, _)| window.contains(bucket))
            .fold(0_u32, |sum, (_, count)| sum.saturating_add(*count))
            .saturating_mul(1_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_and_clock_boundaries_age_without_polling() {
        let mut rate = RecentFrameRate::default();
        for ns in [-1, 0, 0, 99_999_999, 100_000_000] {
            rate.observe(ns);
        }
        assert_eq!(rate.milli_fps(0), 1_000);
        assert_eq!(rate.milli_fps(100_000_000), 4_000);
        assert_eq!(rate.milli_fps(200_000_000), 5_000);
        assert_eq!(rate.milli_fps(1_000_000_000), 4_000);
        assert_eq!(rate.milli_fps(1_100_000_000), 1_000);
        assert_eq!(rate.milli_fps(1_200_000_000), 0);
        assert_eq!(rate.milli_fps(i128::MAX), 0);
    }

    #[test]
    fn steady_rate_stays_constant_across_slot_reuse() {
        let mut rate = RecentFrameRate::default();
        for idx in 0..250 {
            let ns = i128::from(idx) * 40_000_000;
            rate.observe(ns);
            if ns >= 1_000_000_000 {
                assert_eq!(rate.milli_fps(ns), 25_000);
            }
        }
    }
}
