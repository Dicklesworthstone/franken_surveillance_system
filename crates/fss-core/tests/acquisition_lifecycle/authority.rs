#![forbid(unsafe_code)]
//! Live admissions obey the same authority and resource bounds as durable recovery.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: TimestampNs = TimestampNs(1_100_000_000);
const EXPIRED: TimestampNs = TimestampNs(2_000_000_001);

fn at_stage(stage: AcquisitionStateKind) -> Result<AcquisitionSession, Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    if stage == AcquisitionStateKind::Requested {
        return Ok(session);
    }
    session.authenticate(sample_auth(&req), NOW)?;
    if stage == AcquisitionStateKind::Authenticated {
        return Ok(session);
    }
    session.accept(sample_ack(&req), NOW)?;
    if stage == AcquisitionStateKind::AdapterAccepted {
        return Ok(session);
    }
    session.observe_first_frame(sample_first_frame(&req), NOW)?;
    if stage == AcquisitionStateKind::FirstFrameObserved {
        return Ok(session);
    }
    session.verify_continuity(sample_continuity(&req, true), NOW)?;
    Ok(session)
}

fn next_window(req: &AcquisitionRequest) -> ContinuityWitness {
    let mut witness = sample_continuity(req, true);
    witness.window_start_seq = 61;
    witness.window_end_seq = 120;
    witness.window_start_pts_ns = TimestampNs(2_033_000_000);
    witness.window_end_pts_ns = TimestampNs(3_000_000_000);
    witness
}

fn uncertainty(session: &AcquisitionSession, now: TimestampNs) -> IndeterminateWitness {
    let req = session.request();
    IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: now,
        reason: "transport outcome needs reconciliation".to_owned(),
        unresolved_obligations: vec!["verify-source-continuity".to_owned()],
    }
}

#[test]
fn expiry_refuses_each_positive_admission_without_changing_state_or_history() -> TestResult {
    for stage in [
        AcquisitionStateKind::Authenticated,
        AcquisitionStateKind::AdapterAccepted,
        AcquisitionStateKind::FirstFrameObserved,
        AcquisitionStateKind::ContinuityVerified,
    ] {
        let mut session = at_stage(stage)?;
        let before = session.clone();
        let req = session.request().clone();
        let result = match stage {
            AcquisitionStateKind::Authenticated => session.accept(sample_ack(&req), EXPIRED),
            AcquisitionStateKind::AdapterAccepted => {
                session.observe_first_frame(sample_first_frame(&req), EXPIRED)
            }
            AcquisitionStateKind::FirstFrameObserved => {
                session.verify_continuity(sample_continuity(&req, true), EXPIRED)
            }
            _ => session.verify_continuity(next_window(&req), EXPIRED),
        };
        assert!(
            matches!(result, Err(AcquisitionError::WitnessMismatch { .. })),
            "{stage}: {result:?}"
        );
        assert_eq!(session, before, "refusal mutated {stage}");
    }
    Ok(())
}

#[test]
fn receipt_expiry_endpoint_is_inclusive() -> TestResult {
    let mut session = at_stage(AcquisitionStateKind::Authenticated)?;
    let req = session.request().clone();
    let endpoint = sample_auth(&req).expires_at_ns;
    session.accept(sample_ack(&req), endpoint)?;
    session.observe_first_frame(sample_first_frame(&req), endpoint)?;
    session.verify_continuity(sample_continuity(&req, true), endpoint)?;
    assert!(session.is_streaming());
    assert!(session.checkpoint_bytes().is_ok());
    Ok(())
}

#[test]
fn weaker_credential_method_is_refused_at_authentication() -> TestResult {
    let mut req = sample_request()?;
    req.adapter_identity.credential_method = CredentialMethod::DigestAuth;
    let mut session = AcquisitionSession::new(req.clone())?;
    let before = session.clone();
    assert!(matches!(
        session.authenticate(sample_auth(&req), NOW),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));
    assert_eq!(session, before);
    let mut auth = sample_auth(&req);
    auth.method = CredentialMethod::DigestAuth;
    session.authenticate(auth, NOW)?;
    assert!(session.checkpoint_bytes().is_ok());
    Ok(())
}

#[test]
fn buffer_limit_is_enforced_before_adapter_acceptance() -> TestResult {
    let mut session = at_stage(AcquisitionStateKind::Authenticated)?;
    let before = session.clone();
    let req = session.request().clone();
    let mut ack = sample_ack(&req);
    ack.allocated_buffer_frames = req.adapter_identity.max_buffer_frames + 1;
    assert!(matches!(
        session.accept(ack.clone(), NOW),
        Err(AcquisitionError::BoundsViolation {
            field: "allocated_buffer_frames",
            ..
        })
    ));
    assert_eq!(session, before);
    ack.allocated_buffer_frames = req.adapter_identity.max_buffer_frames;
    session.accept(ack, NOW)?;
    assert!(session.checkpoint_bytes().is_ok());
    Ok(())
}

#[test]
fn expired_receipt_cannot_add_continuity_through_reconciliation() -> TestResult {
    let mut session = at_stage(AcquisitionStateKind::ContinuityVerified)?;
    let mut resolved = session.clone();
    resolved.verify_continuity(next_window(resolved.request()), NOW)?;
    session.mark_indeterminate(uncertainty(&session, EXPIRED), EXPIRED)?;
    let before = session.clone();
    assert!(matches!(
        session.reconcile(
            resolved.state().clone(),
            "new window after interruption",
            EXPIRED
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));
    assert_eq!(session, before);
    assert!(matches!(
        session.verify_continuity(next_window(session.request()), EXPIRED),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn expired_authority_still_allows_loss_failure_and_quiescence_records() -> TestResult {
    let initial = at_stage(AcquisitionStateKind::ContinuityVerified)?;
    let req = initial.request().clone();
    let mut degraded = initial.clone();
    degraded.degrade(
        DegradationEvidence {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            source_id: req.source_identity.source_id.clone(),
            degraded_at_ns: EXPIRED,
            lost_dimensions: vec!["authorization".to_owned()],
            invalidated_negative_claims: vec!["unauthorized_intrusion_absent".to_owned()],
            observed_packet_loss: 0,
            observed_jitter_ns: 0,
        },
        EXPIRED,
    )?;
    assert!(degraded.check_absence_claim_allowed().is_err());
    assert!(
        degraded
            .verify_continuity(next_window(&req), EXPIRED)
            .is_err()
    );

    let mut failed = initial.clone();
    failed.fail(
        FailureWitness {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            source_id: req.source_identity.source_id.clone(),
            failed_at_ns: EXPIRED,
            error_code: "authorization_expired".to_owned(),
            error_message: "capture authority expired".to_owned(),
            retryable: true,
        },
        EXPIRED,
    )?;
    let mut cancelled = initial;
    cancelled.cancel(
        QuiescenceReceipt {
            adapter_id: req.adapter_identity.adapter_id,
            device_id: req.device_identity.device_id,
            source_id: req.source_identity.source_id,
            cancelled_at_ns: EXPIRED,
            active_tasks: 0,
            open_descriptors: 0,
            buffers_drained: true,
        },
        EXPIRED,
    )?;
    for session in [degraded, failed, cancelled] {
        assert!(!session.is_streaming());
        assert!(session.checkpoint_bytes().is_ok());
    }
    Ok(())
}

#[test]
fn positive_progress_cannot_backdate_lifecycle_history() -> TestResult {
    for stage in [
        AcquisitionStateKind::Authenticated,
        AcquisitionStateKind::AdapterAccepted,
        AcquisitionStateKind::FirstFrameObserved,
        AcquisitionStateKind::ContinuityVerified,
    ] {
        let mut session = at_stage(stage)?;
        let before = session.clone();
        let req = session.request().clone();
        let earlier = TimestampNs(NOW.0 - 1);
        let result = match stage {
            AcquisitionStateKind::Authenticated => session.accept(sample_ack(&req), earlier),
            AcquisitionStateKind::AdapterAccepted => {
                session.observe_first_frame(sample_first_frame(&req), earlier)
            }
            AcquisitionStateKind::FirstFrameObserved => {
                session.verify_continuity(sample_continuity(&req, true), earlier)
            }
            _ => session.verify_continuity(next_window(&req), earlier),
        };
        assert!(
            matches!(result, Err(AcquisitionError::InvalidTimestamp { .. })),
            "{stage}: {result:?}"
        );
        assert_eq!(session, before);
    }
    Ok(())
}

#[test]
fn authentication_and_uncertainty_cannot_precede_retained_history() -> TestResult {
    let mut session = at_stage(AcquisitionStateKind::Requested)?;
    let mut auth = sample_auth(session.request());
    auth.authorized_at_ns = TimestampNs(0);
    let before = session.clone();
    assert!(matches!(
        session.authenticate(auth, TimestampNs(999_999_999)),
        Err(AcquisitionError::InvalidTimestamp { .. })
    ));
    assert_eq!(session, before);

    let mut session = at_stage(AcquisitionStateKind::ContinuityVerified)?;
    let before = session.clone();
    for earlier in [TimestampNs(-1), TimestampNs(NOW.0 - 1)] {
        assert!(matches!(
            session.mark_indeterminate(uncertainty(&session, NOW), earlier),
            Err(AcquisitionError::InvalidTimestamp { .. })
        ));
        assert_eq!(session, before);
    }
    Ok(())
}

#[test]
fn negative_request_time_is_rejected() -> TestResult {
    let mut req = sample_request()?;
    req.requested_at_ns = TimestampNs(-1);
    assert!(matches!(
        AcquisitionSession::new(req),
        Err(AcquisitionError::InvalidTimestamp { .. })
    ));
    Ok(())
}
