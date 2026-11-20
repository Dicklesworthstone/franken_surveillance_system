#![forbid(unsafe_code)]
//! Exact integer split conformal prediction for distribution-free finite-sample calibration.
//!
//! Under exchangeability of calibration nonconformity scores `s_1, ..., s_n` and a test score
//! `s_test` (Vovk et al.; Lei et al. 2018), let `q_hat` be the `k`-th smallest calibration score
//! where `k = ceil((n + 1) * (1 - alpha))`. Then:
//!
//! * `P(s_test <= q_hat) >= 1 - alpha` for every finite sample size `n`, with no distributional
//!   assumptions and no asymptotic approximation;
//! * when `k > n`, finite-sample coverage cannot be certified without extrapolating beyond the
//!   observed calibration support, so [`SplitConformalCalibrator::quantile_ppm`] is `None` and
//!   [`SplitConformalCalibrator::evaluate`] honestly abstains rather than fabricating a threshold;
//! * every test score also carries its exact rational conformal p-value
//!   `p = (1 + |{i : s_i >= s_test}|) / (n + 1)` together with outward-rounded parts-per-million
//!   bounds.
//!
//! All arithmetic is exact integer (`u32` / `u64` / `u128`); no floating-point number enters any
//! quantile, p-value, verdict, or canonical digest.

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::calibration::MAX_SCORE_PPM;
use crate::model::{FusionError, valid_text};

/// Split conformal calibration digest domain (`SCHEMA-DOMAIN-FUSION-SPLIT-CONFORMAL-001`).
pub const SPLIT_CONFORMAL_DOMAIN: &str = "fss.fusion.split_conformal.v1";

/// Maximum calibration sample count accepted by a single split conformal calibrator.
pub const MAX_CONFORMAL_SAMPLES: usize = 1_000_000;

/// Exact miscoverage denominator (1.0 in parts per million).
pub const PPM_SCALE: u32 = MAX_SCORE_PPM;

/// Exact rational conformal p-value `numerator / denominator` plus outward-rounded ppm bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformalPValue {
    /// Exact numerator `1 + count(s_i >= s_test)` in `1..=denominator`.
    pub numerator: u64,
    /// Exact denominator `n + 1`.
    pub denominator: u64,
    /// Floor of `numerator / denominator` in parts per million.
    pub lo_ppm: u32,
    /// Ceiling of `numerator / denominator` in parts per million.
    pub hi_ppm: u32,
}

impl ConformalPValue {
    /// Computes an exact rational p-value and outward-rounded ppm bounds from `exceedances`
    /// (`|{i : s_i >= s_test}|`) and calibration sample count `n`.
    #[must_use]
    pub fn from_counts(exceedances: u64, n: u64) -> Self {
        let numerator = exceedances.saturating_add(1);
        let denominator = n.saturating_add(1);
        let scaled = u128::from(numerator) * u128::from(PPM_SCALE);
        let den = u128::from(denominator);
        let lo_ppm = (scaled / den).min(u128::from(PPM_SCALE)) as u32;
        let hi_ppm = scaled.div_ceil(den).min(u128::from(PPM_SCALE)) as u32;
        Self {
            numerator,
            denominator,
            lo_ppm,
            hi_ppm,
        }
    }

    /// Returns `true` iff `numerator / denominator > alpha_ppm / 1_000_000` strictly (exact cross
    /// multiplication without float rounding).
    #[must_use]
    pub fn strictly_exceeds_alpha(&self, alpha_ppm: u32) -> bool {
        u128::from(self.numerator) * u128::from(PPM_SCALE)
            > u128::from(self.denominator) * u128::from(alpha_ppm)
    }
}

/// Decision of evaluating one candidate nonconformity score against a split conformal calibrator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformalVerdict {
    /// Candidate lies inside the `1 - alpha` conformal prediction set (`nonconformity <= q_hat`).
    Admitted {
        /// Finite-sample conformal threshold `q_hat` in ppm.
        threshold_ppm: u32,
        /// Exact rational conformal p-value of the test score.
        p_value: ConformalPValue,
    },
    /// Candidate falls outside the `1 - alpha` conformal prediction set (`nonconformity > q_hat`).
    Excluded {
        /// Finite-sample conformal threshold `q_hat` in ppm.
        threshold_ppm: u32,
        /// Exact rational conformal p-value of the test score.
        p_value: ConformalPValue,
    },
    /// Calibration sample size `n` is too small to certify finite-sample coverage at `alpha_ppm`
    /// (`ceil((n + 1) * (1 - alpha)) > n`); fails closed by never excluding the candidate.
    AbstainedInsufficientCalibration {
        /// Minimum calibration sample count required for `alpha_ppm`.
        required_samples: u64,
        /// Observed calibration sample count `n`.
        have_samples: u64,
        /// Exact rational conformal p-value of the test score.
        p_value: ConformalPValue,
    },
}

impl ConformalVerdict {
    /// Returns `true` when the candidate remains inside the conformal set (either admitted or
    /// fail-closed abstention due to insufficient calibration samples).
    #[must_use]
    pub const fn is_retained_in_set(self) -> bool {
        !matches!(self, Self::Excluded { .. })
    }
}

/// Converts a higher-is-better detector confidence score in `0..=1_000_000` ppm into a
/// lower-is-better nonconformity score `1_000_000 - score_ppm`.
///
/// # Errors
///
/// Returns [`FusionError::InvalidInput`] if `score_ppm > 1_000_000`.
pub fn confidence_to_nonconformity_ppm(score_ppm: u32) -> Result<u32, FusionError> {
    if score_ppm > MAX_SCORE_PPM {
        return Err(FusionError::InvalidInput(format!(
            "score {score_ppm} ppm exceeds {MAX_SCORE_PPM}"
        )));
    }
    Ok(MAX_SCORE_PPM - score_ppm)
}

/// Minimum finite-sample calibration count `n` such that `ceil((n + 1) * (1 - alpha)) <= n`.
///
/// Equivalent to `n >= ceil((1 - alpha) / alpha) = ceil(1 / alpha) - 1`.
#[must_use]
pub fn minimum_calibration_samples(alpha_ppm: u32) -> u64 {
    if alpha_ppm == 0 {
        return u64::MAX;
    }
    let alpha = u128::from(alpha_ppm);
    let one_minus_alpha = u128::from(PPM_SCALE).saturating_sub(alpha);
    one_minus_alpha.div_ceil(alpha) as u64
}

/// Digest-bound split conformal calibrator over exact integer nonconformity scores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplitConformalCalibrator {
    /// Caller-declared generation (detector, sensor mode, scene, pipeline).
    generation: String,
    /// Target miscoverage level `alpha` in parts per million (`1..=999_999`).
    alpha_ppm: u32,
    /// Calibration nonconformity scores sorted ascending (`0..=1_000_000`).
    sorted_scores_ppm: Vec<u32>,
    /// Exact 1-indexed order statistic `k = ceil((n + 1) * (1 - alpha))`.
    order_rank: u64,
    /// Finite-sample quantile `s_(k)` if `k <= n`, or `None` when calibration is insufficient.
    quantile_ppm: Option<u32>,
    /// Canonical domain-separated SHA-256 digest binding generation, alpha, scores, and quantile.
    digest: ContentDigest,
}

impl SplitConformalCalibrator {
    /// Builds a split conformal calibrator from calibration nonconformity scores (in ppm) and a
    /// target miscoverage level `alpha_ppm` in `1..=999_999` (e.g. `50_000` for 95% coverage).
    ///
    /// # Errors
    ///
    /// Returns [`FusionError::InvalidInput`] if `generation` is invalid, `alpha_ppm` is outside
    /// `1..=999_999`, `nonconformity_scores_ppm` is empty or exceeds [`MAX_CONFORMAL_SAMPLES`],
    /// or any score exceeds `1_000_000`.
    pub fn build(
        generation: &str,
        alpha_ppm: u32,
        nonconformity_scores_ppm: &[u32],
    ) -> Result<Self, FusionError> {
        if !valid_text(generation) {
            return Err(FusionError::InvalidInput(
                "conformal calibration generation".to_owned(),
            ));
        }
        if alpha_ppm == 0 || alpha_ppm >= PPM_SCALE {
            return Err(FusionError::InvalidInput(format!(
                "alpha_ppm {alpha_ppm} must lie in 1..={}",
                PPM_SCALE - 1
            )));
        }
        if nonconformity_scores_ppm.is_empty()
            || nonconformity_scores_ppm.len() > MAX_CONFORMAL_SAMPLES
        {
            return Err(FusionError::InvalidInput(
                "conformal calibration requires 1..=1000000 scores".to_owned(),
            ));
        }
        for &score in nonconformity_scores_ppm {
            if score > MAX_SCORE_PPM {
                return Err(FusionError::InvalidInput(format!(
                    "nonconformity score {score} ppm exceeds {MAX_SCORE_PPM}"
                )));
            }
        }

        let mut sorted = nonconformity_scores_ppm.to_vec();
        sorted.sort_unstable();

        let n = sorted.len() as u64;
        let one_minus_alpha = u128::from(PPM_SCALE - alpha_ppm);
        let order_rank =
            ((u128::from(n) + 1) * one_minus_alpha).div_ceil(u128::from(PPM_SCALE)) as u64;
        let quantile_ppm = if order_rank >= 1 && order_rank <= n {
            Some(sorted[(order_rank - 1) as usize])
        } else {
            None
        };

        let mut encoder = CanonicalEncoder::new();
        encoder.text(SPLIT_CONFORMAL_DOMAIN);
        encoder.text(generation);
        encoder.u32(alpha_ppm);
        encoder.u64(n);
        for &score in &sorted {
            encoder.u32(score);
        }
        encoder.u64(order_rank);
        match quantile_ppm {
            None => encoder.tag(0),
            Some(q) => {
                encoder.tag(1);
                encoder.u32(q);
            }
        }
        let digest = ContentDigest::sha256(&encoder.finish());

        Ok(Self {
            generation: generation.to_owned(),
            alpha_ppm,
            sorted_scores_ppm: sorted,
            order_rank,
            quantile_ppm,
            digest,
        })
    }

    /// Caller-declared calibration generation.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Target miscoverage rate `alpha` in parts per million.
    #[must_use]
    pub const fn alpha_ppm(&self) -> u32 {
        self.alpha_ppm
    }

    /// Target finite-sample coverage guarantee `1 - alpha` in parts per million.
    #[must_use]
    pub const fn target_coverage_ppm(&self) -> u32 {
        PPM_SCALE - self.alpha_ppm
    }

    /// Number of calibration nonconformity scores `n`.
    #[must_use]
    pub fn sample_count(&self) -> u64 {
        self.sorted_scores_ppm.len() as u64
    }

    /// Exact 1-indexed conformal order statistic `ceil((n + 1) * (1 - alpha))`.
    #[must_use]
    pub const fn order_rank(&self) -> u64 {
        self.order_rank
    }

    /// Certified finite-sample quantile `q_hat` in ppm, or `None` when `n` is too small for
    /// `alpha_ppm`.
    #[must_use]
    pub const fn quantile_ppm(&self) -> Option<u32> {
        self.quantile_ppm
    }

    /// Canonical digest binding the complete calibrator state.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Computes the exact rational conformal p-value for a test nonconformity score.
    ///
    /// # Errors
    ///
    /// Returns [`FusionError::InvalidInput`] if `nonconformity_ppm > 1_000_000`.
    pub fn p_value(&self, nonconformity_ppm: u32) -> Result<ConformalPValue, FusionError> {
        if nonconformity_ppm > MAX_SCORE_PPM {
            return Err(FusionError::InvalidInput(format!(
                "test nonconformity score {nonconformity_ppm} ppm exceeds {MAX_SCORE_PPM}"
            )));
        }
        // Count calibration scores >= nonconformity_ppm using binary search on sorted ascending vec.
        let first_ge = self
            .sorted_scores_ppm
            .partition_point(|&score| score < nonconformity_ppm);
        let exceedances = (self.sorted_scores_ppm.len() - first_ge) as u64;
        Ok(ConformalPValue::from_counts(
            exceedances,
            self.sample_count(),
        ))
    }

    /// Evaluates a candidate nonconformity score against the certified finite-sample threshold.
    ///
    /// # Errors
    ///
    /// Returns [`FusionError::InvalidInput`] if `nonconformity_ppm > 1_000_000`.
    pub fn evaluate(&self, nonconformity_ppm: u32) -> Result<ConformalVerdict, FusionError> {
        let p_value = self.p_value(nonconformity_ppm)?;
        match self.quantile_ppm {
            Some(threshold_ppm) if nonconformity_ppm <= threshold_ppm => {
                Ok(ConformalVerdict::Admitted {
                    threshold_ppm,
                    p_value,
                })
            }
            Some(threshold_ppm) => Ok(ConformalVerdict::Excluded {
                threshold_ppm,
                p_value,
            }),
            None => Ok(ConformalVerdict::AbstainedInsufficientCalibration {
                required_samples: minimum_calibration_samples(self.alpha_ppm),
                have_samples: self.sample_count(),
                p_value,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstains_honestly_when_sample_size_cannot_certify_alpha() -> Result<(), FusionError> {
        // alpha = 0.05 (50_000 ppm) requires n >= 19 because ceil((18 + 1) * 0.95) = ceil(18.05) = 19 > 18.
        let scores_18: Vec<u32> = (1..=18).map(|i| i * 10_000).collect();
        let cal_18 = SplitConformalCalibrator::build("det:v1:cam1", 50_000, &scores_18)?;
        assert_eq!(cal_18.order_rank(), 19);
        assert_eq!(cal_18.quantile_ppm(), None);
        assert_eq!(minimum_calibration_samples(50_000), 19);
        let verdict = cal_18.evaluate(999_999)?;
        assert!(matches!(
            verdict,
            ConformalVerdict::AbstainedInsufficientCalibration {
                required_samples: 19,
                have_samples: 18,
                ..
            }
        ));
        assert!(verdict.is_retained_in_set());

        // At n = 19, ceil((19 + 1) * 0.95) = ceil(19.0) = 19 <= 19 -> certified quantile s_(19).
        let scores_19: Vec<u32> = (1..=19).map(|i| i * 10_000).collect();
        let cal_19 = SplitConformalCalibrator::build("det:v1:cam1", 50_000, &scores_19)?;
        assert_eq!(cal_19.order_rank(), 19);
        assert_eq!(cal_19.quantile_ppm(), Some(190_000));
        assert!(matches!(
            cal_19.evaluate(190_000)?,
            ConformalVerdict::Admitted {
                threshold_ppm: 190_000,
                ..
            }
        ));
        assert!(matches!(
            cal_19.evaluate(190_001)?,
            ConformalVerdict::Excluded {
                threshold_ppm: 190_000,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn exact_rational_pvalue_and_outward_ppm_bounds() -> Result<(), FusionError> {
        // n = 9 scores: [100k, 200k, ..., 900k], denominator = 10.
        let scores: Vec<u32> = (1..=9).map(|i| i * 100_000).collect();
        let cal = SplitConformalCalibrator::build("det:v1:cam1", 100_000, &scores)?;
        // Score 0 has all 9 calibration scores >= 0 -> p = (1 + 9)/10 = 1.0.
        let p_low = cal.p_value(0)?;
        assert_eq!((p_low.numerator, p_low.denominator), (10, 10));
        assert_eq!((p_low.lo_ppm, p_low.hi_ppm), (1_000_000, 1_000_000));

        // Score 900_000 has 1 calibration score >= 900_000 -> p = (1 + 1)/10 = 0.2.
        let p_eq = cal.p_value(900_000)?;
        assert_eq!((p_eq.numerator, p_eq.denominator), (2, 10));
        assert_eq!((p_eq.lo_ppm, p_eq.hi_ppm), (200_000, 200_000));
        assert!(p_eq.strictly_exceeds_alpha(100_000));

        // Score 950_000 has 0 calibration scores >= 950_000 -> p = 1/10 = 0.1 (not > 0.1).
        let p_high = cal.p_value(950_000)?;
        assert_eq!((p_high.numerator, p_high.denominator), (1, 10));
        assert_eq!((p_high.lo_ppm, p_high.hi_ppm), (100_000, 100_000));
        assert!(!p_high.strictly_exceeds_alpha(100_000));

        // Outward rounding on non-terminating fraction: n = 2 -> denominator 3.
        let cal3 = SplitConformalCalibrator::build("det:v1:cam1", 500_000, &[100_000, 200_000])?;
        let p_third = cal3.p_value(300_000)?;
        assert_eq!((p_third.numerator, p_third.denominator), (1, 3));
        assert_eq!((p_third.lo_ppm, p_third.hi_ppm), (333_333, 333_334));
        Ok(())
    }

    #[test]
    fn finite_sample_exchangeable_coverage_theorem_holds_across_splits() -> Result<(), FusionError>
    {
        // Leave-one-out over 100 distinct scores is exactly exchangeable: for alpha = 0.10,
        // each of the 100 held-out scores must be covered with empirical rate >= 90%.
        let population: Vec<u32> = (0..100).map(|i| ((i * 7919) % 100) * 10_000).collect();
        let mut covered = 0_usize;
        for holdout_idx in 0..population.len() {
            let mut cal_scores = Vec::with_capacity(population.len() - 1);
            for (idx, &score) in population.iter().enumerate() {
                if idx != holdout_idx {
                    cal_scores.push(score);
                }
            }
            let cal = SplitConformalCalibrator::build("det:v1:exchangeable", 100_000, &cal_scores)?;
            if cal.evaluate(population[holdout_idx])?.is_retained_in_set() {
                covered += 1;
            }
        }
        assert!(
            covered >= 90,
            "expected >= 90% finite-sample coverage, got {covered}/100"
        );
        Ok(())
    }

    #[test]
    fn digest_is_order_invariant_and_sensitive_to_alpha_and_generation() -> Result<(), FusionError>
    {
        let a = SplitConformalCalibrator::build(
            "det:v1:cam1",
            200_000,
            &[300_000, 100_000, 500_000, 200_000],
        )?;
        let b = SplitConformalCalibrator::build(
            "det:v1:cam1",
            200_000,
            &[500_000, 200_000, 100_000, 300_000],
        )?;
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.quantile_ppm(), Some(500_000));

        let c = SplitConformalCalibrator::build(
            "det:v1:cam2",
            200_000,
            &[300_000, 100_000, 500_000, 200_000],
        )?;
        assert_ne!(a.digest(), c.digest());

        let d = SplitConformalCalibrator::build(
            "det:v1:cam1",
            250_000,
            &[300_000, 100_000, 500_000, 200_000],
        )?;
        assert_ne!(a.digest(), d.digest());
        Ok(())
    }

    #[test]
    fn rejects_invalid_inputs_and_converts_confidence() {
        assert!(SplitConformalCalibrator::build("", 50_000, &[100]).is_err());
        assert!(SplitConformalCalibrator::build("det:v1", 0, &[100]).is_err());
        assert!(SplitConformalCalibrator::build("det:v1", 1_000_000, &[100]).is_err());
        assert!(SplitConformalCalibrator::build("det:v1", 50_000, &[]).is_err());
        assert!(SplitConformalCalibrator::build("det:v1", 50_000, &[1_000_001]).is_err());
        assert_eq!(confidence_to_nonconformity_ppm(850_000), Ok(150_000));
        assert!(confidence_to_nonconformity_ppm(1_000_001).is_err());
    }
}
