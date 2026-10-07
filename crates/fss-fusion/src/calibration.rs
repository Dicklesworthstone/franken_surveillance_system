//! Score calibration: per-bin log-likelihood-ratio intervals from labelled outcomes.
//!
//! A detector's raw score has no numeric authority (plan §16.4, §17.4). Given labelled
//! outcomes — each emitted candidate's score and whether it matched a true event (an
//! event-level evaluation's true and false positives) — this module builds a
//! [`ScoreCalibration`]: for every declared score bin, an interval for
//!
//! `LLR(bin) = log10( P(score in bin | true event) / P(score in bin | false alarm) )`
//!
//! and a prior interval for the log-odds that an emitted candidate is a true event. With the
//! prior and the bin's LLR, fusion reproduces the bin's precision odds while carrying the
//! sampling uncertainty of sparse bins instead of a point estimate.
//!
//! Everything is exact integer arithmetic with outward rounding:
//!
//! * the two bin fractions get Wilson score intervals at `z = 2` (about 95% each, not
//!   simultaneous), computed with exact integer square roots in parts per 10^12, the lower
//!   bound rounded down and the upper rounded up;
//! * `log10` of a fixed-point fraction is bounded rigorously by the literal table
//!   `floor(10^(j/1000) * 10^18)`: the result interval always contains the true value;
//! * an empty lower fraction (a bin with no positives or no negatives) yields the
//!   [`MAX_ABS_LLR`] clamp on that side — honest unboundedness, not a guess.
//!
//! A calibration is valid only for the detector, sensor mode, scene and pipeline generations it
//! was measured under; the caller names that in the `generation` and must not reuse it
//! elsewhere.

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::log_table::POW10_MILLI;
use crate::model::{Calibration, FusionError, LlrInterval, MAX_ABS_LLR, valid_text};

/// Score calibration digest domain (`SCHEMA-DOMAIN-FUSION-SCORE-CALIBRATION-001`).
pub const SCORE_CALIBRATION_DOMAIN: &str = "fss.fusion.score_calibration.v1";
/// Largest score (1.0 in parts per million).
pub const MAX_SCORE_PPM: u32 = 1_000_000;
/// Maximum declared bins.
pub const MAX_BINS: usize = 64;
/// Maximum labelled outcomes.
pub const MAX_OUTCOMES: usize = 1_000_000;
/// Fixed-point scale of Wilson bounds.
const SCALE: u128 = 1_000_000_000_000;

/// Floor and ceiling of `sqrt(value)`.
fn isqrt(value: u128) -> (u128, u128) {
    if value < 2 {
        return (value, value);
    }
    let mut x = (value as f64).sqrt() as u128;
    while x.saturating_mul(x) > value {
        x -= 1;
    }
    while (x + 1).saturating_mul(x + 1) <= value {
        x += 1;
    }
    let ceil = if x * x == value { x } else { x + 1 };
    (x, ceil)
}

/// Wilson score interval (`z = 2`) of `successes` out of `trials`, in parts per 10^12,
/// rounded outward. `trials` must be at least 1.
fn wilson(successes: u64, trials: u64) -> (u128, u128) {
    let (s, n) = (u128::from(successes), u128::from(trials));
    let spread = s * (n - s) + n; // n * (p q + 1/n) scaled by n^2 / n
    // 2 * sqrt(spread / n) * SCALE = sqrt(4 * SCALE^2 * spread / n).
    let radicand = 4 * SCALE * SCALE * spread;
    let (_, root_hi) = isqrt(radicand.div_ceil(n));
    let denominator = n + 4;
    let center = (s + 2) * SCALE;
    let lower = center.saturating_sub(root_hi) / denominator;
    let upper = (center + root_hi).div_ceil(denominator).min(SCALE);
    (lower, upper)
}

/// Rigorous millibans bounds of `log10(x / 10^18)` for `1 <= x <= 10^18`.
fn log10_fraction(x: u128) -> (i64, i64) {
    let mut decade = 0_i64;
    let mut scaled = x;
    while scaled < 1_000_000_000_000_000_000 {
        scaled *= 10;
        decade -= 1;
    }
    // scaled in [10^18, 10^19): find the table position.
    let exact = |j: usize| j == 0 || j == 1000;
    let mut lower = 0_i64;
    let mut upper = 1000_i64;
    for (j, &entry) in POW10_MILLI.iter().enumerate() {
        let certain_ge = if exact(j) {
            scaled >= entry
        } else {
            scaled > entry
        };
        if certain_ge {
            lower = j as i64;
        }
        if scaled <= entry {
            upper = j as i64;
            break;
        }
    }
    (decade * 1000 + lower, decade * 1000 + upper)
}

/// Millibans bounds of `log10(a / b)` for fractions `a, b` in parts per 10^12; a zero numerator
/// or denominator side clamps outward.
fn log_ratio(a: (u128, u128), b: (u128, u128)) -> (i64, i64) {
    let to_fraction = |value: u128| value * 1_000_000;
    let lower = if a.0 == 0 || b.1 == 0 {
        -MAX_ABS_LLR
    } else {
        let (a_lo, _) = log10_fraction(to_fraction(a.0));
        let (_, b_hi) = log10_fraction(to_fraction(b.1));
        (a_lo - b_hi).max(-MAX_ABS_LLR)
    };
    let upper = if b.0 == 0 || a.1 == 0 {
        MAX_ABS_LLR
    } else {
        let (_, a_hi) = log10_fraction(to_fraction(a.1));
        let (b_lo, _) = log10_fraction(to_fraction(b.0));
        (a_hi - b_lo).min(MAX_ABS_LLR)
    };
    (lower.min(upper), upper.max(lower))
}

/// One calibrated score bin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScoreBin {
    /// Inclusive lower score (ppm).
    pub lo_ppm: u32,
    /// Inclusive upper score (ppm).
    pub hi_ppm: u32,
    /// Labelled true events in the bin.
    pub positives: u64,
    /// Labelled false alarms in the bin.
    pub negatives: u64,
    /// Log-likelihood-ratio interval (millibans).
    pub llr: LlrInterval,
}

/// A digest-bound score calibration of one detector generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScoreCalibration {
    /// Caller-declared generation (detector, sensor mode, scene, pipeline).
    pub generation: String,
    /// All labelled true events.
    pub positives: u64,
    /// All labelled false alarms.
    pub negatives: u64,
    /// Log-odds interval that an emitted candidate is a true event.
    pub prior: LlrInterval,
    /// Bins in ascending score order, covering `0..=1_000_000`.
    pub bins: Vec<ScoreBin>,
    /// Canonical digest.
    pub digest: ContentDigest,
}

impl ScoreCalibration {
    /// Builds a calibration from `outcomes` (`(score_ppm, is_true_event)`) over the bins starting
    /// at `edges` (ascending, first `0`).
    ///
    /// # Errors
    ///
    /// [`FusionError::InvalidInput`] for an invalid generation, edge list or score, too many
    /// outcomes, or a sample without both true events and false alarms.
    pub fn build(
        generation: &str,
        edges: &[u32],
        outcomes: &[(u32, bool)],
    ) -> Result<Self, FusionError> {
        if !valid_text(generation) {
            return Err(FusionError::InvalidInput(
                "calibration generation".to_owned(),
            ));
        }
        if edges.is_empty()
            || edges.len() > MAX_BINS
            || edges[0] != 0
            || edges.windows(2).any(|pair| pair[0] >= pair[1])
            || edges.iter().any(|&edge| edge > MAX_SCORE_PPM)
        {
            return Err(FusionError::InvalidInput(
                "bin edges must start at 0, ascend strictly and stay within 0..=1000000".to_owned(),
            ));
        }
        if outcomes.len() > MAX_OUTCOMES {
            return Err(FusionError::InvalidInput(
                "too many labelled outcomes".to_owned(),
            ));
        }
        let mut counts = vec![(0_u64, 0_u64); edges.len()];
        for &(score, positive) in outcomes {
            if score > MAX_SCORE_PPM {
                return Err(FusionError::InvalidInput(format!("score {score} ppm")));
            }
            let bin = edges.partition_point(|&edge| edge <= score) - 1;
            if positive {
                counts[bin].0 += 1;
            } else {
                counts[bin].1 += 1;
            }
        }
        Self::from_counts(generation, edges, &counts)
    }

    /// Rebuilds a calibration from per-bin `(true events, false alarms)` counts — what a stored
    /// calibration report carries; every interval is recomputed, so a tampered report changes
    /// the digest.
    ///
    /// # Errors
    ///
    /// As [`Self::build`], and for a count list that does not match the edges.
    pub fn from_counts(
        generation: &str,
        edges: &[u32],
        counts: &[(u64, u64)],
    ) -> Result<Self, FusionError> {
        if !valid_text(generation) {
            return Err(FusionError::InvalidInput(
                "calibration generation".to_owned(),
            ));
        }
        if edges.is_empty()
            || edges.len() > MAX_BINS
            || edges[0] != 0
            || edges.windows(2).any(|pair| pair[0] >= pair[1])
            || edges.iter().any(|&edge| edge > MAX_SCORE_PPM)
            || counts.len() != edges.len()
        {
            return Err(FusionError::InvalidInput(
                "bin edges must start at 0, ascend strictly, stay within 0..=1000000 and match the counts".to_owned(),
            ));
        }
        let total_outcomes = counts
            .iter()
            .try_fold(0_u64, |sum, &(tp, fp)| sum.checked_add(tp)?.checked_add(fp));
        if total_outcomes.is_none_or(|total| total > MAX_OUTCOMES as u64) {
            return Err(FusionError::InvalidInput(
                "too many labelled outcomes".to_owned(),
            ));
        }
        let positives: u64 = counts.iter().map(|c| c.0).sum();
        let negatives: u64 = counts.iter().map(|c| c.1).sum();
        if positives == 0 || negatives == 0 {
            return Err(FusionError::InvalidInput(
                "a calibration needs labelled true events and false alarms".to_owned(),
            ));
        }
        let mut bins = Vec::with_capacity(edges.len());
        for (index, &(tp, fp)) in counts.iter().enumerate() {
            let (lo, hi) = log_ratio(wilson(tp, positives), wilson(fp, negatives));
            bins.push(ScoreBin {
                lo_ppm: edges[index],
                hi_ppm: edges.get(index + 1).map_or(MAX_SCORE_PPM, |&next| next - 1),
                positives: tp,
                negatives: fp,
                llr: LlrInterval::new(lo, hi)?,
            });
        }
        let total = positives + negatives;
        let (p_lo, p_hi) = wilson(positives, total);
        let (prior_lo, _) = log_ratio((p_lo, p_lo), (SCALE - p_lo, SCALE - p_lo));
        let (_, prior_hi) = log_ratio((p_hi, p_hi), (SCALE - p_hi, SCALE - p_hi));
        let prior = LlrInterval::new(prior_lo.min(prior_hi), prior_hi.max(prior_lo))?;
        let mut calibration = Self {
            generation: generation.to_owned(),
            positives,
            negatives,
            prior,
            bins,
            digest: ContentDigest::sha256(b""),
        };
        calibration.digest = calibration.compute_digest();
        Ok(calibration)
    }

    fn compute_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SCORE_CALIBRATION_DOMAIN);
        encoder.text(&self.generation);
        encoder.u64(self.positives);
        encoder.u64(self.negatives);
        self.prior.encode(&mut encoder);
        encoder.u64(self.bins.len() as u64);
        for bin in &self.bins {
            encoder.u32(bin.lo_ppm);
            encoder.u32(bin.hi_ppm);
            encoder.u64(bin.positives);
            encoder.u64(bin.negatives);
            bin.llr.encode(&mut encoder);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// The bin holding `score_ppm`.
    #[must_use]
    pub fn bin(&self, score_ppm: u32) -> Option<&ScoreBin> {
        self.bins
            .iter()
            .find(|bin| bin.lo_ppm <= score_ppm && score_ppm <= bin.hi_ppm)
    }

    /// The fusion calibration of one score: its bin's interval under this generation and
    /// digest.
    #[must_use]
    pub fn calibrate(&self, score_ppm: u32) -> Calibration {
        match self.bin(score_ppm) {
            Some(bin) => Calibration::Calibrated {
                generation: format!("{}@{}", self.generation, self.digest.to_text()),
                llr: bin.llr,
            },
            None => Calibration::Uncalibrated {
                reason: format!("score {score_ppm} ppm is outside the calibrated range"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_square_roots_are_exact() {
        for value in [
            0_u128,
            1,
            2,
            3,
            4,
            15,
            16,
            17,
            99,
            100,
            101,
            1 << 100,
            (1 << 100) + 1,
        ] {
            let (floor, ceil) = isqrt(value);
            assert!(floor * floor <= value && value < (floor + 1) * (floor + 1));
            assert!(ceil * ceil >= value && (ceil == 0 || (ceil - 1) * (ceil - 1) < value));
        }
    }

    #[test]
    fn log_bounds_contain_the_true_value() {
        // log10(0.5) = -0.30103 -> [-302, -301] millibans.
        let (lo, hi) = log10_fraction(500_000_000_000_000_000);
        assert!(lo <= -301 && hi >= -302 && hi - lo <= 2, "{lo} {hi}");
        assert!(lo as f64 <= -301.03 && hi as f64 >= -301.03);
        // Exact powers of ten.
        assert_eq!(log10_fraction(1_000_000_000_000_000_000), (0, 0));
        assert_eq!(log10_fraction(100_000_000_000_000_000), (-1000, -1000));
        // A spread of values against f64 log10.
        for x in [
            1_u128,
            7,
            123_456,
            999_999_999,
            314_159_265_358_979_323,
            999_999_999_999_999_999,
        ] {
            let truth = (x as f64 / 1e18).log10() * 1000.0;
            let (lo, hi) = log10_fraction(x);
            assert!(
                lo as f64 <= truth + 1e-6 && truth - 1e-6 <= hi as f64,
                "{x}: {lo} {truth} {hi}"
            );
            assert!(hi - lo <= 1, "{x}");
        }
    }

    #[test]
    fn wilson_bounds_bracket_the_proportion() {
        for (s, n) in [
            (0, 1),
            (1, 1),
            (5, 10),
            (1, 1000),
            (999, 1000),
            (0, 50),
            (50, 50),
        ] {
            let (lo, hi) = wilson(s, n);
            let p = (s as u128 * SCALE) / n as u128;
            assert!(lo <= p && p <= hi, "{s}/{n}: {lo} {p} {hi}");
            assert!(hi <= SCALE);
        }
        // Known value: 5/10 at z=2 -> 0.5 -+ sqrt(3.5)/7 = [0.232739, 0.767261].
        let (lo, hi) = wilson(5, 10);
        assert!((232_738_000_000..232_740_000_000).contains(&lo), "{lo}");
        assert!((767_260_000_000..767_263_000_000).contains(&hi), "{hi}");
    }
}
