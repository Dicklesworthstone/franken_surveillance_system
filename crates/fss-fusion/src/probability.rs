//! Outward-rounded conversion of exact log-odds intervals to probability bounds.
//!
//! Decisions never use these numbers: every threshold comparison is on exact integer log-odds.
//! They exist so an event can carry a conservative probability interval. The tables hold
//! `P(d) = 10^(d/10) / (1 + 10^(d/10))` in parts per million at every integer deciban
//! `d in -60..=60`, rounded down ([`FLOOR_PPM`]) and up ([`CEIL_PPM`]) from 60-digit decimal
//! arithmetic (generated offline, literal and platform independent). A lower bound uses the
//! floor table at the deciban at or below the log-odds; an upper bound the ceiling table at
//! the deciban at or above it; beyond +-60 dB the bound saturates outward to 0 or 1 000 000.

/// Smallest tabulated deciban.
pub const MIN_DECIBANS: i64 = -60;
/// Largest tabulated deciban.
pub const MAX_DECIBANS: i64 = 60;
/// One million parts per million.
pub const PPM: u32 = 1_000_000;

/// `floor(1e6 * P(d))` for `d = -60..=60`.
pub const FLOOR_PPM: [u32; 121] = [
    0, 1, 1, 1, 2, 3, 3, 5, 6, 7, 9, 12, 15, 19, 25, 31, 39, 50, 63, 79, 99, 125, 158, 199, 251,
    316, 397, 500, 630, 793, 999, 1257, 1582, 1991, 2505, 3152, 3965, 4986, 6270, 7880, 9900,
    12432, 15601, 19562, 24503, 30653, 38286, 47726, 59350, 73587, 90909, 111815, 136806, 166337,
    200760, 240253, 284747, 333860, 386863, 442688, 500000, 557311, 613136, 666139, 715252, 759746,
    799239, 833662, 863193, 888184, 909090, 926412, 940649, 952273, 961713, 969346, 975496, 980437,
    984398, 987567, 990099, 992119, 993729, 995013, 996034, 996847, 997494, 998008, 998417, 998742,
    999000, 999206, 999369, 999499, 999602, 999683, 999748, 999800, 999841, 999874, 999900, 999920,
    999936, 999949, 999960, 999968, 999974, 999980, 999984, 999987, 999990, 999992, 999993, 999994,
    999996, 999996, 999997, 999998, 999998, 999998, 999999,
];

/// `ceil(1e6 * P(d))` for `d = -60..=60`.
pub const CEIL_PPM: [u32; 121] = [
    1, 2, 2, 2, 3, 4, 4, 6, 7, 8, 10, 13, 16, 20, 26, 32, 40, 51, 64, 80, 100, 126, 159, 200, 252,
    317, 398, 501, 631, 794, 1000, 1258, 1583, 1992, 2506, 3153, 3966, 4987, 6271, 7881, 9901,
    12433, 15602, 19563, 24504, 30654, 38287, 47727, 59351, 73588, 90910, 111816, 136807, 166338,
    200761, 240254, 284748, 333861, 386864, 442689, 500000, 557312, 613137, 666140, 715253, 759747,
    799240, 833663, 863194, 888185, 909091, 926413, 940650, 952274, 961714, 969347, 975497, 980438,
    984399, 987568, 990100, 992120, 993730, 995014, 996035, 996848, 997495, 998009, 998418, 998743,
    999001, 999207, 999370, 999500, 999603, 999684, 999749, 999801, 999842, 999875, 999901, 999921,
    999937, 999950, 999961, 999969, 999975, 999981, 999985, 999988, 999991, 999993, 999994, 999995,
    999997, 999997, 999998, 999999, 999999, 999999, 1000000,
];

/// Conservative probability interval in parts per million of the log-odds interval
/// `[lo, hi]` given in millibans.
#[must_use]
pub fn probability_ppm(lo: i64, hi: i64) -> (u32, u32) {
    let lower = if lo < MIN_DECIBANS * 100 {
        0
    } else {
        let deciban = lo.div_euclid(100).min(MAX_DECIBANS);
        FLOOR_PPM[(deciban - MIN_DECIBANS) as usize]
    };
    let upper = if hi > MAX_DECIBANS * 100 {
        PPM
    } else {
        // Quotient and remainder avoid negating i64::MIN at the public numeric boundary.
        let deciban =
            (hi.div_euclid(100) + i64::from(hi.rem_euclid(100) != 0)).max(MIN_DECIBANS);
        CEIL_PPM[(deciban - MIN_DECIBANS) as usize]
    };
    (lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_monotone_symmetric_and_outward() {
        for index in 1..FLOOR_PPM.len() {
            assert!(FLOOR_PPM[index] >= FLOOR_PPM[index - 1]);
            assert!(CEIL_PPM[index] >= CEIL_PPM[index - 1]);
        }
        for index in 0..FLOOR_PPM.len() {
            assert!(CEIL_PPM[index] - FLOOR_PPM[index] <= 1);
            // P(-d) = 1 - P(d).
            assert_eq!(FLOOR_PPM[index] + CEIL_PPM[120 - index], PPM);
        }
        assert_eq!(FLOOR_PPM[60], 500_000);
        assert_eq!(probability_ppm(0, 0), (500_000, 500_000));
        assert_eq!(probability_ppm(-7_000, 7_000), (0, PPM));
        // 10 dB = odds 10 = 0.909090...
        assert_eq!(probability_ppm(1_000, 1_000), (909_090, 909_091));
        // 10.5 dB lies between 10 and 11 dB: outward to both.
        let (low, high) = probability_ppm(1_050, 1_050);
        assert_eq!((low, high), (FLOOR_PPM[70], CEIL_PPM[71]));
        // Negative non-integral decibans round outward too.
        let (low, high) = probability_ppm(-1_050, -1_050);
        assert_eq!((low, high), (FLOOR_PPM[49], CEIL_PPM[50]));
    }

    #[test]
    fn full_i64_range_saturates_outward_without_negation_overflow() {
        assert_eq!(probability_ppm(i64::MIN, i64::MAX), (0, PPM));
        assert_eq!(probability_ppm(i64::MIN, i64::MIN), (0, 1));
        assert_eq!(probability_ppm(i64::MAX, i64::MAX), (PPM - 1, PPM));
    }
}
