#![forbid(unsafe_code)]
//! Exact nominal lineage survives the lossless screen, including an uncalibrated companion.

use super::tests::fixture;
use super::*;
use crate::ingest::calibration_coverage::MAX_CALIBRATION_COVERAGE_WORK;

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NO_POLICY: MaskBinding = MaskBinding::NoPolicy;

fn project(
    a: &CoverageRecord,
    assessment: &CalibrationCoverageAssessment,
    b: &CoverageRecord,
) -> Result<GuardedCoverageSet, CorroborationError> {
    GuardedCoverageSet::project(
        &[
            CoverageProjectionInput {
                record: a,
                assessment: Some(assessment),
                privacy: &NO_POLICY,
            },
            CoverageProjectionInput {
                record: b,
                assessment: None,
                privacy: &NO_POLICY,
            },
        ],
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )
}

#[test]
fn complete_nominal_lineage_is_kept_even_when_the_screen_removes_witnesses() -> TestResult {
    let (a, screen) = fixture(1, true)?;
    let (b, _) = fixture(2, false)?;
    let expected = [a.digest(), b.digest()];
    let set = project(&a, &screen, &b)?;
    assert_eq!(set.nominal_digests(), &expected);
    assert!(set.abstained_intervals() > 0);
    assert_ne!(set.records()[0].digest(), expected[0]);
    assert_eq!(set.records()[1].digest(), expected[1]);
    assert_eq!(set.clone().nominal_digests(), &expected);
    // Bookkeeping must not invent a new coverage approval or mutate the native inputs.
    assert_eq!(
        set.approval(),
        approval_digest(&set.records().iter().collect::<Vec<_>>())
    );
    assert_eq!([a.digest(), b.digest()], expected);
    Ok(())
}

#[test]
fn lineage_is_ordered_and_binds_the_unscreened_companion_not_just_the_calibrated_camera() -> TestResult {
    let (a, screen) = fixture(1, true)?;
    let (b, _) = fixture(2, false)?;
    let set = project(&a, &screen, &b)?;
    let reversed = GuardedCoverageSet::project(
        &[
            CoverageProjectionInput {
                record: &b,
                assessment: None,
                privacy: &NO_POLICY,
            },
            CoverageProjectionInput {
                record: &a,
                assessment: Some(&screen),
                privacy: &NO_POLICY,
            },
        ],
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    assert_eq!(reversed.nominal_digests(), &[b.digest(), a.digest()]);
    assert_ne!(set.nominal_digests(), reversed.nominal_digests());
    let (other_companion, _) = fixture(3, false)?;
    let other = project(&a, &screen, &other_companion)?;
    assert_ne!(set.nominal_digests(), other.nominal_digests());
    assert_eq!(set.nominal_digests()[0], other.nominal_digests()[0]);
    Ok(())
}

#[test]
fn final_guarded_hashes_cannot_be_mistaken_for_original_lineage() -> TestResult {
    let (a, screen) = fixture(1, true)?;
    let (b, _) = fixture(2, false)?;
    let set = project(&a, &screen, &b)?;
    let final_digests: Vec<_> = set.records().iter().map(CoverageRecord::digest).collect();
    assert_ne!(set.nominal_digests(), final_digests.as_slice());
    // No serialization changes: existing version-6 record replay remains byte exact.
    for record in set.records() {
        assert_eq!(
            CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
            *record
        );
    }
    Ok(())
}
