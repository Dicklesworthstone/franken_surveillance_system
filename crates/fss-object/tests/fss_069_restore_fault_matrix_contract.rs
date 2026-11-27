#![forbid(unsafe_code)]
//! Contract & fault suite for `FSS-069` (`fss-x4a.13.9`): deterministic remote archive restore
//! and fault-injection matrix.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, Generation, TimestampNs,
};
use fss_object::restore_fault_matrix::{
    RestoreFaultKind, RestoreFaultMatrixReceipt, RestoreMatrixError, RestoreScenarioOutcome,
    run_restore_fault_matrix, standard_restore_fault_scenarios,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn fss_069_full_remote_archive_restore_fault_matrix_deterministic_and_canonical() -> TestResult {
    let scenarios = standard_restore_fault_scenarios();
    assert_eq!(scenarios.len(), 10);

    let r1 = run_restore_fault_matrix(
        "matrix:archive-restore-v1",
        0x5EED_0690_0001,
        Generation(3),
        TimestampNs(1_700_000_123_000),
        &scenarios,
        || false,
    )?;
    let r2 = run_restore_fault_matrix(
        "matrix:archive-restore-v1",
        0x5EED_0690_0001,
        Generation(3),
        TimestampNs(1_700_000_123_000),
        &scenarios,
        || false,
    )?;

    // Exact cross-run bit-identical determinism and 10/10 passing matrix!
    assert_eq!(r1, r2);
    assert!(r1.all_passed());
    assert_eq!(r1.cases.len(), 10);
    assert_eq!(r1.cases_passed, 10);
    assert!(!r1.read_local_source);

    // Spot-check key distinct non-collapsed outcomes across the matrix.
    let find =
        |kind: RestoreFaultKind| r1.cases.iter().find(|c| c.kind == kind).map(|c| c.observed);
    assert_eq!(
        find(RestoreFaultKind::NominalCleanRestore),
        Some(RestoreScenarioOutcome::RestoredVerifiedComplete)
    );
    assert_eq!(
        find(RestoreFaultKind::CorruptChunkReplicaFailover),
        Some(RestoreScenarioOutcome::RecoveredViaReplicaFailover)
    );
    assert_eq!(
        find(RestoreFaultKind::MissingChunkUnrecoverable),
        Some(RestoreScenarioOutcome::PartialDegradedPreserved)
    );
    assert_eq!(
        find(RestoreFaultKind::BelowCustodyFloorStagedOrReplicated),
        Some(RestoreScenarioOutcome::PartialDegradedPreserved)
    );
    assert_eq!(
        find(RestoreFaultKind::IndeterminateRemoteObservation),
        Some(RestoreScenarioOutcome::IndeterminatePreserved)
    );
    assert_eq!(
        find(RestoreFaultKind::UnauthorizedIncidentRoot),
        Some(RestoreScenarioOutcome::UnauthorizedRefused)
    );
    assert_eq!(
        find(RestoreFaultKind::CancelledAtRestoreBoundary),
        Some(RestoreScenarioOutcome::CancelledCleanly)
    );

    // Canonical binary round-trip.
    let mut enc = CanonicalEncoder::new();
    r1.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded =
        RestoreFaultMatrixReceipt::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, r1);

    println!(
        "CAPLOG {{\"step\":\"fss_069_restore_fault_matrix\",\"scenarios\":{},\"ok\":{},\"read_local_source\":{},\"verdict\":\"ok\"}}",
        r1.cases.len(),
        r1.cases_passed,
        r1.read_local_source
    );
    Ok(())
}

#[test]
fn fss_069_refuses_invalid_config_duplicate_scenarios_cancellation_and_forged_receipt() -> TestResult
{
    assert_eq!(
        run_restore_fault_matrix(
            "",
            1,
            Generation(1),
            TimestampNs(10),
            &[RestoreFaultKind::NominalCleanRestore],
            || false,
        ),
        Err(RestoreMatrixError::InvalidConfiguration(
            "invalid_matrix_args"
        ))
    );
    assert_eq!(
        run_restore_fault_matrix(
            "matrix:zero-gen",
            1,
            Generation(0),
            TimestampNs(10),
            &[RestoreFaultKind::NominalCleanRestore],
            || false,
        ),
        Err(RestoreMatrixError::InvalidConfiguration(
            "invalid_matrix_args"
        ))
    );
    assert_eq!(
        run_restore_fault_matrix(
            "matrix:dup",
            1,
            Generation(1),
            TimestampNs(10),
            &[
                RestoreFaultKind::NominalCleanRestore,
                RestoreFaultKind::NominalCleanRestore
            ],
            || false,
        ),
        Err(RestoreMatrixError::InvalidConfiguration(
            "duplicate_scenario"
        ))
    );
    assert_eq!(
        run_restore_fault_matrix(
            "matrix:cancel",
            1,
            Generation(1),
            TimestampNs(10),
            &standard_restore_fault_scenarios(),
            || true,
        ),
        Err(RestoreMatrixError::Cancelled)
    );

    // Wire-level forgeries (recomputed SHA-256!) claiming read_local_source=true or forged pass count refused!
    let receipt = run_restore_fault_matrix(
        "matrix:tamper",
        7,
        Generation(1),
        TimestampNs(99),
        &[RestoreFaultKind::NominalCleanRestore],
        || false,
    )?;

    let mut forged_local = receipt.clone();
    forged_local.read_local_source = true;
    forged_local.receipt_digest = forged_local.computed_digest();
    let mut enc1 = CanonicalEncoder::new();
    forged_local.encode_canonical(&mut enc1);
    assert!(
        RestoreFaultMatrixReceipt::decode_canonical(&mut CanonicalDecoder::new(&enc1.finish()))
            .is_err()
    );

    let mut forged_passed = receipt;
    forged_passed.cases[0].observed = RestoreScenarioOutcome::PartialDegradedPreserved;
    forged_passed.cases[0].passed = true; // contradiction: expected != observed!
    forged_passed.receipt_digest = forged_passed.computed_digest();
    let mut enc2 = CanonicalEncoder::new();
    forged_passed.encode_canonical(&mut enc2);
    assert!(
        RestoreFaultMatrixReceipt::decode_canonical(&mut CanonicalDecoder::new(&enc2.finish()))
            .is_err()
    );
    Ok(())
}
