#![forbid(unsafe_code)]
//! Integration and contract tests for the cross-adapter acquisition lifecycle (FSS-007 / ACQ-LIFECYCLE-001).

use std::collections::BTreeSet;

use fss_core::{
    ACQUISITION_TRANSITION_TABLE, AcquisitionError, AcquisitionRequest, AcquisitionSession,
    AcquisitionState, AcquisitionStateKind, AcquisitionTransitionRecord, AdapterAck,
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, AuthReceipt,
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, Completeness,
    ContentDigest, ContinuityWitness, ContractError, CoverageContinuity, CoverageStopReason,
    CoverageWitness, CredentialMethod, DecodeState, DegradationEvidence, DeviceCapabilities,
    DeviceClass, DeviceGeneration, DeviceId, DeviceIdentity, ExplicitOmission, FailureWitness,
    FirmwareGeneration, FirstFrameWitness, IndeterminateWitness, IsolationMode, LedgerAnchor,
    MediaKind, OmissionReason, QuiescenceReceipt, RetryClass, SourceCustody, SourceId,
    SourceIdentity, SourceKind, StreamGeneration, TimestampNs, get_transition_rule,
    is_allowed_transition,
};

fn sample_request() -> Result<AcquisitionRequest, Box<dyn std::error::Error>> {
    let source_id = SourceId::parse("src:camera-main-video")?;
    let device_id = DeviceId::parse("device:insta360-link-main")?;
    let adapter_id = AdapterId::parse("adapter:uvc-insta360-link")?;
    let stream_generation = StreamGeneration::parse("gen:stream:1080p60-nv12")?;

    let source_identity = SourceIdentity {
        source_id,
        device_id: device_id.clone(),
        adapter_id: adapter_id.clone(),
        source_kind: SourceKind::PhysicalSensor,
        media_kind: MediaKind::Video,
        channel: "main".to_string(),
        nominal_clock_basis: fss_core::ClockBasis::HostMonotonic,
        stream_generation,
        failure_domain: "power:poe-switch-1".to_string(),
        is_live: true,
    };
    source_identity.verify()?;

    let device_identity = DeviceIdentity {
        device_id,
        generation: DeviceGeneration::parse("gen:dev:2026-09-12:rev1")?,
        manufacturer: "Insta360".to_string(),
        model: "Link".to_string(),
        hardware_revision: "HW-2.1".to_string(),
        firmware_version: FirmwareGeneration::parse("gen:firmware:v1-2-64")?,
        application_version: None,
        model_generation: None,
        device_class: DeviceClass::Camera,
        capabilities: DeviceCapabilities::PTZ.union(DeviceCapabilities::AUDIO_CAPTURE),
        failure_domain: "power:poe-switch-1".to_string(),
    };
    device_identity.verify()?;

    let adapter_identity = AdapterIdentity {
        adapter_id,
        generation: AdapterGeneration::parse("gen:adapter:uvc-rust-v1")?,
        adapter_kind: AdapterKind::Uvc,
        protocol_profile: "uvc:1.5:isochronous".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING
            .union(AdapterCapabilities::PTZ_CONTROL)
            .union(AdapterCapabilities::TIME_SYNC),
        max_bandwidth_bytes_per_sec: 150_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };
    adapter_identity.verify()?;

    let req = AcquisitionRequest {
        source_identity,
        device_identity,
        adapter_identity,
        requested_capabilities: AdapterCapabilities::STREAMING,
        requested_at_ns: TimestampNs(1_000_000_000),
    };
    req.verify()?;
    Ok(req)
}

fn sample_auth(req: &AcquisitionRequest) -> AuthReceipt {
    AuthReceipt {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        method: CredentialMethod::None,
        principal_digest: ContentDigest::sha256(b"principal:owner-operator"),
        authorized_capabilities: req.requested_capabilities,
        authorized_at_ns: TimestampNs(1_000_000_000),
        expires_at_ns: TimestampNs(2_000_000_000),
    }
}

fn sample_ack(req: &AcquisitionRequest) -> AdapterAck {
    AdapterAck {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        request_digest: req.request_digest(),
        ack_timestamp_ns: TimestampNs(1_005_000_000),
        session_handle: "session:uvc-inst-001".to_string(),
        allocated_buffer_frames: 16,
    }
}

fn sample_first_frame(req: &AcquisitionRequest) -> FirstFrameWitness {
    FirstFrameWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        sequence_number: 1,
        pts_ns: TimestampNs(1_033_000_000),
        frame_bytes: 65536,
        decode_state: DecodeState::Verified,
        source_custody: SourceCustody::Retained {
            source_digest: ContentDigest::sha256(b"frame-1-bytes"),
            source_bytes: 65536,
            storage_handle: "spool:uvc/frame-001.raw".to_string(),
        },
        explicit_omission: ExplicitOmission::None,
    }
}

fn sample_coverage_witness(certifies: bool) -> CoverageWitness {
    let mut domain = BTreeSet::new();
    domain.insert("src:camera-main-video".to_string());
    CoverageWitness {
        anchor: LedgerAnchor::genesis("site:local"),
        authorized_domain: domain.clone(),
        observed_domain: if certifies { domain } else { BTreeSet::new() },
        excluded_domain: BTreeSet::new(),
        continuity: if certifies {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if certifies {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        negative_predicate: if certifies {
            "unauthorized_intrusion_absent".to_string()
        } else {
            String::new()
        },
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn sample_continuity(req: &AcquisitionRequest, certifies: bool) -> ContinuityWitness {
    ContinuityWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        window_start_seq: 1,
        window_end_seq: 60,
        window_start_pts_ns: TimestampNs(1_033_000_000),
        window_end_pts_ns: TimestampNs(2_000_000_000),
        frames_observed: 60,
        discontinuities: 0,
        packet_loss: 0,
        observed_jitter_ns: 250_000,
        max_jitter_threshold_ns: 2_000_000,
        coverage_witness: sample_coverage_witness(certifies),
    }
}

#[test]
fn test_happy_path_lifecycle_and_streaming_invariants() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;

    // Invariant: Requested state is NOT streaming
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    assert!(!session.is_streaming());
    assert!(!session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());

    // 1. Authenticate
    let auth = sample_auth(&req);
    session.authenticate(auth, TimestampNs(1_001_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Authenticated);
    assert!(!session.is_streaming());
    assert!(!session.has_continuity());

    // 2. Adapter Accepted (INV-005: stream acceptance is never called streaming)
    let ack = sample_ack(&req);
    session.accept(ack, TimestampNs(1_005_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::AdapterAccepted);
    assert!(
        !session.is_streaming(),
        "INV-005: AdapterAccepted must NOT be classified as streaming"
    );
    assert!(!session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());

    // 3. First Frame Observed (Decoded frame is NOT continuity)
    let first_frame = sample_first_frame(&req);
    session.observe_first_frame(first_frame, TimestampNs(1_033_000_000))?;
    assert_eq!(
        session.state_kind(),
        AcquisitionStateKind::FirstFrameObserved
    );
    assert!(
        !session.is_streaming(),
        "FirstFrameObserved is NOT streaming"
    );
    assert!(!session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());

    // 4. Continuity Verified (Now and ONLY now is it streaming)
    let continuity = sample_continuity(&req, true);
    session.verify_continuity(continuity, TimestampNs(2_000_000_000))?;
    assert_eq!(
        session.state_kind(),
        AcquisitionStateKind::ContinuityVerified
    );
    assert!(
        session.is_streaming(),
        "ContinuityVerified MUST be streaming"
    );
    assert!(session.has_continuity());

    // Coverage witness certifies absence
    let cov = session.check_absence_claim_allowed()?;
    assert!(cov.certifies_absence());

    // Audit trail verification
    assert!(session.history().len() >= 5);
    assert_eq!(session.history()[0].from, AcquisitionStateKind::Requested);
    assert_eq!(
        session.history()[4].to,
        AcquisitionStateKind::ContinuityVerified
    );

    Ok(())
}

#[test]
fn test_planted_negative_skipping_states() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;

    // Skipping Authenticated: Requested -> AdapterAccepted
    let mut session1 = AcquisitionSession::new(req.clone())?;
    let ack = sample_ack(&req);
    let err1 = session1.accept(ack, TimestampNs(1_005_000_000));
    assert!(matches!(
        err1,
        Err(AcquisitionError::IllegalTransition {
            from: AcquisitionStateKind::Requested,
            to: AcquisitionStateKind::AdapterAccepted
        })
    ));

    // Skipping to FirstFrameObserved from Requested
    let mut session2 = AcquisitionSession::new(req.clone())?;
    let first_frame = sample_first_frame(&req);
    let err2 = session2.observe_first_frame(first_frame, TimestampNs(1_033_000_000));
    assert!(matches!(
        err2,
        Err(AcquisitionError::IllegalTransition {
            from: AcquisitionStateKind::Requested,
            to: AcquisitionStateKind::FirstFrameObserved
        })
    ));

    // Skipping FirstFrameObserved: AdapterAccepted -> ContinuityVerified
    let mut session3 = AcquisitionSession::new(req.clone())?;
    session3.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session3.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;
    let continuity = sample_continuity(&req, true);
    let err3 = session3.verify_continuity(continuity, TimestampNs(2_000_000_000));
    assert!(matches!(
        err3,
        Err(AcquisitionError::IllegalTransition {
            from: AcquisitionStateKind::AdapterAccepted,
            to: AcquisitionStateKind::ContinuityVerified
        })
    ));

    Ok(())
}

#[test]
fn test_planted_negative_continuity_across_gap() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;

    // 1. Packet loss > 0
    let mut witness_packet_loss = sample_continuity(&req, true);
    witness_packet_loss.packet_loss = 1;
    let err_loss = witness_packet_loss.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_loss,
        Err(AcquisitionError::ContinuityGapDetected { .. })
    ));

    // 2. Discontinuity count > 0
    let mut witness_discontinuity = sample_continuity(&req, true);
    witness_discontinuity.discontinuities = 1;
    let err_disc = witness_discontinuity.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_disc,
        Err(AcquisitionError::ContinuityGapDetected { .. })
    ));

    // 3. Observed jitter exceeds threshold
    let mut witness_jitter = sample_continuity(&req, true);
    witness_jitter.observed_jitter_ns = 5_000_000;
    witness_jitter.max_jitter_threshold_ns = 2_000_000;
    let err_jitter = witness_jitter.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_jitter,
        Err(AcquisitionError::ContinuityGapDetected { .. })
    ));

    // 4. Sequence gap: frames_observed != sequence range
    let mut witness_seq_gap = sample_continuity(&req, true);
    witness_seq_gap.window_start_seq = 1;
    witness_seq_gap.window_end_seq = 60;
    witness_seq_gap.frames_observed = 59; // 1 frame dropped in sequence
    let err_gap = witness_seq_gap.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_gap,
        Err(AcquisitionError::ContinuityGapDetected { .. })
    ));

    // 5. Inverted sequence window
    let mut witness_inverted = sample_continuity(&req, true);
    witness_inverted.window_start_seq = 100;
    witness_inverted.window_end_seq = 50;
    let err_inv = witness_inverted.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_inv,
        Err(AcquisitionError::ContinuityGapDetected { .. })
    ));

    // 6. Coverage continuity not continuous
    let mut witness_gapped_coverage = sample_continuity(&req, false);
    witness_gapped_coverage.coverage_witness.continuity = CoverageContinuity::Gapped;
    let err_cov = witness_gapped_coverage.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(matches!(
        err_cov,
        Err(AcquisitionError::InvalidCoverageWitness { .. })
    ));

    Ok(())
}

#[test]
fn test_planted_negative_accept_then_silence() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_000_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    assert_eq!(session.state_kind(), AcquisitionStateKind::AdapterAccepted);

    let deadline = TimestampNs(1_050_000_000); // 45ms timeout deadline

    // Check before deadline: passes cleanly
    session.check_accept_silence(deadline, TimestampNs(1_030_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::AdapterAccepted);

    // Check after deadline elapsed: fails closed to Failed state
    let res = session.check_accept_silence(deadline, TimestampNs(1_060_000_000));
    assert!(matches!(
        res,
        Err(AcquisitionError::AcceptSilenceTimeout { .. })
    ));
    assert_eq!(session.state_kind(), AcquisitionStateKind::Failed);
    assert!(session.state().is_terminal());
    assert!(!session.is_streaming());

    // Cannot advance to first frame from Failed
    let first_frame = sample_first_frame(&req);
    let err_ff = session.observe_first_frame(first_frame, TimestampNs(1_070_000_000));
    assert!(matches!(
        err_ff,
        Err(AcquisitionError::IllegalTransition { .. })
    ));

    Ok(())
}

#[test]
fn test_reconnect_strictly_monotonic_generation() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;

    // Attempting to reconnect with identical generation fails closed
    let same_gen_req = req.clone();
    let err_same = session.reconnect(same_gen_req, TimestampNs(1_010_000_000));
    assert!(matches!(
        err_same,
        Err(AcquisitionError::GenerationConflict { .. })
    ));

    // Reconnect with strictly newer generation succeeds
    let mut newer_req = req.clone();
    let new_gen = StreamGeneration::parse("gen:stream:1080p60-nv12-rev2")?;
    newer_req.source_identity = req.source_identity.transition_stream_generation(new_gen)?;
    newer_req.requested_at_ns = TimestampNs(1_020_000_000);

    session.reconnect(newer_req, TimestampNs(1_020_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    assert_eq!(
        session.request().source_identity.stream_generation.as_str(),
        "gen:stream:1080p60-nv12-rev2"
    );

    Ok(())
}

#[test]
fn test_degradation_and_recovery_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;
    session.observe_first_frame(sample_first_frame(&req), TimestampNs(1_033_000_000))?;
    session.verify_continuity(sample_continuity(&req, true), TimestampNs(2_000_000_000))?;

    assert!(session.is_streaming());

    // Enter degradation
    let degradation = DegradationEvidence {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        degraded_at_ns: TimestampNs(2_050_000_000),
        lost_dimensions: vec!["packet_loss".to_string(), "timing_jitter".to_string()],
        invalidated_negative_claims: vec!["unauthorized_intrusion_absent".to_string()],
        observed_packet_loss: 4,
        observed_jitter_ns: 4_500_000,
    };
    session.degrade(degradation, TimestampNs(2_050_000_000))?;

    assert_eq!(session.state_kind(), AcquisitionStateKind::Degraded);
    assert!(!session.is_streaming());
    assert!(!session.has_continuity());

    // In Degraded, absence claims are strictly forbidden
    let err_absence = session.check_absence_claim_allowed();
    assert!(matches!(
        err_absence,
        Err(AcquisitionError::AbsenceClaimForbidden {
            state: AcquisitionStateKind::Degraded,
            ..
        })
    ));

    // Recovery back to ContinuityVerified with clean window
    let mut recovery_continuity = sample_continuity(&req, true);
    recovery_continuity.window_start_seq = 61;
    recovery_continuity.window_end_seq = 120;
    recovery_continuity.window_start_pts_ns = TimestampNs(2_066_000_000);
    recovery_continuity.window_end_pts_ns = TimestampNs(3_000_000_000);
    recovery_continuity.frames_observed = 60;

    session.verify_continuity(recovery_continuity, TimestampNs(3_000_000_000))?;
    assert_eq!(
        session.state_kind(),
        AcquisitionStateKind::ContinuityVerified
    );
    assert!(session.is_streaming());
    assert!(session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_ok());

    Ok(())
}

#[test]
fn test_clean_cancellation_requires_quiescence() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    // Cancellation with active tasks fails
    let dirty_receipt1 = QuiescenceReceipt {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        cancelled_at_ns: TimestampNs(1_010_000_000),
        active_tasks: 1, // dirty!
        open_descriptors: 0,
        buffers_drained: true,
    };
    let err1 = session.cancel(dirty_receipt1, TimestampNs(1_010_000_000));
    assert!(matches!(
        err1,
        Err(AcquisitionError::QuiescenceViolation { .. })
    ));

    // Cancellation with un-drained buffers fails
    let dirty_receipt2 = QuiescenceReceipt {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        cancelled_at_ns: TimestampNs(1_010_000_000),
        active_tasks: 0,
        open_descriptors: 0,
        buffers_drained: false, // dirty!
    };
    let err2 = session.cancel(dirty_receipt2, TimestampNs(1_010_000_000));
    assert!(matches!(
        err2,
        Err(AcquisitionError::QuiescenceViolation { .. })
    ));

    // Clean cancellation succeeds
    let clean_receipt = QuiescenceReceipt {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        cancelled_at_ns: TimestampNs(1_010_000_000),
        active_tasks: 0,
        open_descriptors: 0,
        buffers_drained: true,
    };
    session.cancel(clean_receipt, TimestampNs(1_010_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Cancelled);
    assert!(session.state().is_terminal());
    assert!(!session.is_streaming());

    Ok(())
}

#[test]
fn test_indeterminate_state_and_reconciliation() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let indeterminate_witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(1_020_000_000),
        reason: "driver unresponsive during resolution probe".to_string(),
        unresolved_obligations: vec!["obl:drain-buffers".to_string()],
    };
    session.mark_indeterminate(indeterminate_witness, TimestampNs(1_020_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Indeterminate);
    assert!(!session.is_streaming());

    // Forward transitions without reconciliation are rejected
    let ack = sample_ack(&req);
    let err_trans = session.accept(ack, TimestampNs(1_025_000_000));
    assert!(matches!(
        err_trans,
        Err(AcquisitionError::IllegalTransition { .. })
    ));

    // Reconciling back into Indeterminate is forbidden
    let err_self_reconcile = session.reconcile(
        session.state().clone(),
        "invalid attempt to self-reconcile",
        TimestampNs(1_030_000_000),
    );
    assert!(matches!(
        err_self_reconcile,
        Err(AcquisitionError::IndeterminateStateUnresolved { .. })
    ));

    // Clean reconciliation to terminal Failed
    let failure = FailureWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        failed_at_ns: TimestampNs(1_030_000_000),
        error_code: "driver_hang_unrecoverable".to_string(),
        error_message: "driver hang confirmed; reset required".to_string(),
        retryable: true,
    };
    let resolved_state = AcquisitionState::Failed {
        request: Box::new(req.clone()),
        failure,
        prior_state: AcquisitionStateKind::Indeterminate,
    };

    session.reconcile(
        resolved_state,
        "reconciled to terminal failure after probe",
        TimestampNs(1_030_000_000),
    )?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Failed);
    assert!(session.state().is_terminal());

    Ok(())
}

#[test]
fn test_witness_forgery_and_mismatch_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;

    // 1. AdapterAck with forged request digest
    let mut bad_ack = sample_ack(&req);
    bad_ack.request_digest = ContentDigest::sha256(b"forged_request_payload");
    let err_ack = session.accept(bad_ack, TimestampNs(1_005_000_000));
    assert!(matches!(
        err_ack,
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 2. AdapterAck with mismatched adapter ID
    let mut bad_adapter_ack = sample_ack(&req);
    bad_adapter_ack.adapter_id = AdapterId::parse("adapter:different-adapter")?;
    let err_adp = session.accept(bad_adapter_ack, TimestampNs(1_005_000_000));
    assert!(matches!(
        err_adp,
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // Accept legitimately
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    // 3. FirstFrameWitness with unverified decode state
    let mut bad_ff = sample_first_frame(&req);
    bad_ff.decode_state = DecodeState::ConcealedErrors;
    let err_ff_dec = session.observe_first_frame(bad_ff, TimestampNs(1_033_000_000));
    assert!(matches!(
        err_ff_dec,
        Err(AcquisitionError::DecodabilityError { .. })
    ));

    // 4. FirstFrameWitness with no custody AND no omission
    let mut empty_evidence_ff = sample_first_frame(&req);
    empty_evidence_ff.source_custody = SourceCustody::NotRetained;
    empty_evidence_ff.explicit_omission = ExplicitOmission::None;
    let err_ff_missing = session.observe_first_frame(empty_evidence_ff, TimestampNs(1_033_000_000));
    assert!(matches!(
        err_ff_missing,
        Err(AcquisitionError::MissingWitness { .. })
    ));

    // 5. FirstFrameWitness with contradictory omission (reason = None)
    let mut contra_ff = sample_first_frame(&req);
    contra_ff.source_custody = SourceCustody::NotRetained;
    contra_ff.explicit_omission = ExplicitOmission::Omitted {
        reason: OmissionReason::None,
        policy_rule: "rule:none".to_string(),
        omitted_bytes: 100,
        omitted_frames: 1,
    };
    let err_contra = session.observe_first_frame(contra_ff, TimestampNs(1_033_000_000));
    assert!(matches!(
        err_contra,
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    Ok(())
}

#[test]
fn test_canonical_id_prefix_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    // Non-canonical source prefix "source:" rejected by verify
    let mut req = sample_request()?;
    req.source_identity.source_id = SourceId::parse("custom:legacy-prefix")?;
    let err = req.verify();
    assert!(matches!(
        err,
        Err(AcquisitionError::NonCanonicalEncoding { .. })
    ));

    // 1. FirstFrameWitness with alias prefix "source:" instead of "src:"
    let mut enc = CanonicalEncoder::new();
    enc.text(FirstFrameWitness::SCHEMA);
    enc.text("adapter:uvc-insta360-link");
    enc.text("device:insta360-link-main");
    enc.text("source:camera-main-video");
    enc.u64(0);
    TimestampNs(1_200_000_000).encode_canonical(&mut enc);
    TimestampNs(1_201_000_000).encode_canonical(&mut enc);
    enc.digest(ContentDigest::sha256(b"frame-0-bytes"));
    enc.bool(true);
    enc.u8(DecodeState::Verified as u8);
    enc.bool(true);
    enc.text("h264");
    enc.u32(1920);
    enc.u32(1080);
    enc.text("nv12");
    enc.digest(ContentDigest::sha256(b"meta"));
    let bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes);
    let res = FirstFrameWitness::decode_canonical(&mut dec);
    assert!(matches!(res, Err(ContractError::NonCanonicalOrdering)));

    // 2. AdapterAck with alias prefix "adp:" instead of "adapter:"
    let mut enc = CanonicalEncoder::new();
    enc.text(AdapterAck::SCHEMA);
    enc.text("adp:uvc-insta360-link");
    enc.digest(req.request_digest());
    TimestampNs(1_100_000_000).encode_canonical(&mut enc);
    enc.text("sess-001");
    enc.u32(16);
    let bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes);
    let res = AdapterAck::decode_canonical(&mut dec);
    assert!(matches!(res, Err(ContractError::NonCanonicalOrdering)));

    // 3. FailureWitness with alias prefix "source:"
    let mut enc = CanonicalEncoder::new();
    enc.text(FailureWitness::SCHEMA);
    enc.text("adapter:uvc-insta360-link");
    enc.text("device:insta360-link-main");
    enc.text("source:camera-main-video");
    TimestampNs(2_100_000_000).encode_canonical(&mut enc);
    enc.text("timeout");
    enc.text("timed out");
    enc.bool(false);
    let bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes);
    let res = FailureWitness::decode_canonical(&mut dec);
    assert!(matches!(res, Err(ContractError::NonCanonicalOrdering)));

    // 4. QuiescenceReceipt with alias prefix "adp:"
    let mut enc = CanonicalEncoder::new();
    enc.text(QuiescenceReceipt::SCHEMA);
    enc.text("adp:uvc-insta360-link");
    req.device_identity.device_id.encode_canonical(&mut enc);
    req.source_identity.source_id.encode_canonical(&mut enc);
    TimestampNs(2_200_000_000).encode_canonical(&mut enc);
    enc.u32(0);
    enc.u32(0);
    enc.bool(true);
    let bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes);
    let res = QuiescenceReceipt::decode_canonical(&mut dec);
    assert!(matches!(res, Err(ContractError::NonCanonicalOrdering)));

    // 5. IndeterminateWitness with alias prefix "source:"
    let mut enc = CanonicalEncoder::new();
    enc.text(IndeterminateWitness::SCHEMA);
    enc.text("adapter:uvc-insta360-link");
    enc.text("device:insta360-link-main");
    enc.text("source:camera-main-video");
    TimestampNs(2_300_000_000).encode_canonical(&mut enc);
    enc.text("unknown");
    enc.u32(0);
    let bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes);
    let res = IndeterminateWitness::decode_canonical(&mut dec);
    assert!(matches!(res, Err(ContractError::NonCanonicalOrdering)));

    Ok(())
}

#[test]
fn test_transition_table_completeness_and_lookup() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!ACQUISITION_TRANSITION_TABLE.is_empty());

    // Valid forward transitions
    assert!(is_allowed_transition(
        AcquisitionStateKind::Requested,
        AcquisitionStateKind::Authenticated
    ));
    assert!(is_allowed_transition(
        AcquisitionStateKind::Authenticated,
        AcquisitionStateKind::AdapterAccepted
    ));
    assert!(is_allowed_transition(
        AcquisitionStateKind::AdapterAccepted,
        AcquisitionStateKind::FirstFrameObserved
    ));
    assert!(is_allowed_transition(
        AcquisitionStateKind::FirstFrameObserved,
        AcquisitionStateKind::ContinuityVerified
    ));

    // Recovery transition
    assert!(is_allowed_transition(
        AcquisitionStateKind::Degraded,
        AcquisitionStateKind::ContinuityVerified
    ));

    // Illegal transitions
    assert!(!is_allowed_transition(
        AcquisitionStateKind::Requested,
        AcquisitionStateKind::ContinuityVerified
    ));
    assert!(!is_allowed_transition(
        AcquisitionStateKind::Failed,
        AcquisitionStateKind::ContinuityVerified
    ));
    assert!(!is_allowed_transition(
        AcquisitionStateKind::Cancelled,
        AcquisitionStateKind::FirstFrameObserved
    ));

    let rule = get_transition_rule(
        AcquisitionStateKind::FirstFrameObserved,
        AcquisitionStateKind::ContinuityVerified,
    );
    assert!(rule.is_some());
    let r = match rule {
        Some(r) => r,
        None => {
            return Err(Box::new(AcquisitionError::WitnessMismatch {
                detail: "missing rule".to_string(),
            }));
        }
    };
    assert_eq!(r.retry_class, RetryClass::Immediate);
    assert!(!r.terminal);

    Ok(())
}

#[test]
fn test_canonical_encoding_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    // 1. State kinds
    for code in 1..=9 {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(code);
        let bytes = encoder.finish_checked()?;
        let mut decoder = CanonicalDecoder::new(&bytes);
        let kind = AcquisitionStateKind::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;

        let mut enc2 = CanonicalEncoder::new();
        kind.encode_canonical(&mut enc2);
        let bytes2 = enc2.finish_checked()?;
        assert_eq!(bytes, bytes2);
    }

    // 2. Retry classes
    for code in 1..=5 {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(code);
        let bytes = encoder.finish_checked()?;
        let mut decoder = CanonicalDecoder::new(&bytes);
        let rc = RetryClass::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;

        let mut enc2 = CanonicalEncoder::new();
        rc.encode_canonical(&mut enc2);
        let bytes2 = enc2.finish_checked()?;
        assert_eq!(bytes, bytes2);
    }

    // 3. AcquisitionRequest
    let req = sample_request()?;
    let mut enc_req = CanonicalEncoder::new();
    req.encode_canonical(&mut enc_req);
    let bytes_req = enc_req.finish_checked()?;
    let mut dec_req = CanonicalDecoder::new(&bytes_req);
    let req_decoded = AcquisitionRequest::decode_canonical(&mut dec_req)?;
    dec_req.ensure_finished()?;
    assert_eq!(req, req_decoded);

    // 4. AuthReceipt
    let auth = sample_auth(&req);
    let mut enc_auth = CanonicalEncoder::new();
    auth.encode_canonical(&mut enc_auth);
    let bytes_auth = enc_auth.finish_checked()?;
    let mut dec_auth = CanonicalDecoder::new(&bytes_auth);
    let auth_decoded = AuthReceipt::decode_canonical(&mut dec_auth)?;
    dec_auth.ensure_finished()?;
    assert_eq!(auth, auth_decoded);

    // 5. AdapterAck
    let ack = sample_ack(&req);
    let mut enc_ack = CanonicalEncoder::new();
    ack.encode_canonical(&mut enc_ack);
    let bytes_ack = enc_ack.finish_checked()?;
    let mut dec_ack = CanonicalDecoder::new(&bytes_ack);
    let ack_decoded = AdapterAck::decode_canonical(&mut dec_ack)?;
    dec_ack.ensure_finished()?;
    assert_eq!(ack, ack_decoded);

    // 6. FirstFrameWitness
    let ff = sample_first_frame(&req);
    let mut enc_ff = CanonicalEncoder::new();
    ff.encode_canonical(&mut enc_ff);
    let bytes_ff = enc_ff.finish_checked()?;
    let mut dec_ff = CanonicalDecoder::new(&bytes_ff);
    let ff_decoded = FirstFrameWitness::decode_canonical(&mut dec_ff)?;
    dec_ff.ensure_finished()?;
    assert_eq!(ff, ff_decoded);

    // 7. ContinuityWitness
    let cont = sample_continuity(&req, true);
    let mut enc_cont = CanonicalEncoder::new();
    cont.encode_canonical(&mut enc_cont);
    let bytes_cont = enc_cont.finish_checked()?;
    let mut dec_cont = CanonicalDecoder::new(&bytes_cont);
    let cont_decoded = ContinuityWitness::decode_canonical(&mut dec_cont)?;
    dec_cont.ensure_finished()?;
    assert_eq!(cont, cont_decoded);

    // 8. DegradationEvidence
    let deg = DegradationEvidence {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        degraded_at_ns: TimestampNs(2_000_000_000),
        lost_dimensions: vec!["packet_loss".to_string()],
        invalidated_negative_claims: vec!["absence_claim_1".to_string()],
        observed_packet_loss: 5,
        observed_jitter_ns: 3_000_000,
    };
    let mut enc_deg = CanonicalEncoder::new();
    deg.encode_canonical(&mut enc_deg);
    let bytes_deg = enc_deg.finish_checked()?;
    let mut dec_deg = CanonicalDecoder::new(&bytes_deg);
    let deg_decoded = DegradationEvidence::decode_canonical(&mut dec_deg)?;
    dec_deg.ensure_finished()?;
    assert_eq!(deg, deg_decoded);

    // 9. FailureWitness
    let fail = FailureWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        failed_at_ns: TimestampNs(2_100_000_000),
        error_code: "timeout".to_string(),
        error_message: "timed out".to_string(),
        retryable: false,
    };
    let mut enc_fail = CanonicalEncoder::new();
    fail.encode_canonical(&mut enc_fail);
    let bytes_fail = enc_fail.finish_checked()?;
    let mut dec_fail = CanonicalDecoder::new(&bytes_fail);
    let fail_decoded = FailureWitness::decode_canonical(&mut dec_fail)?;
    dec_fail.ensure_finished()?;
    assert_eq!(fail, fail_decoded);

    // 10. QuiescenceReceipt
    let quiesc = QuiescenceReceipt {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        cancelled_at_ns: TimestampNs(2_200_000_000),
        active_tasks: 0,
        open_descriptors: 0,
        buffers_drained: true,
    };
    let mut enc_q = CanonicalEncoder::new();
    quiesc.encode_canonical(&mut enc_q);
    let bytes_q = enc_q.finish_checked()?;
    let mut dec_q = CanonicalDecoder::new(&bytes_q);
    let q_decoded = QuiescenceReceipt::decode_canonical(&mut dec_q)?;
    dec_q.ensure_finished()?;
    assert_eq!(quiesc, q_decoded);

    // 11. IndeterminateWitness
    let indet = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(2_300_000_000),
        reason: "unknown state".to_string(),
        unresolved_obligations: vec!["obl-1".to_string()],
    };
    let mut enc_indet = CanonicalEncoder::new();
    indet.encode_canonical(&mut enc_indet);
    let bytes_indet = enc_indet.finish_checked()?;
    let mut dec_indet = CanonicalDecoder::new(&bytes_indet);
    let indet_decoded = IndeterminateWitness::decode_canonical(&mut dec_indet)?;
    dec_indet.ensure_finished()?;
    assert_eq!(indet, indet_decoded);

    // 12. AcquisitionTransitionRecord
    let record = AcquisitionTransitionRecord {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        from: AcquisitionStateKind::Requested,
        to: AcquisitionStateKind::Authenticated,
        timestamp_ns: TimestampNs(1_000_000_000),
        witness_digest: ContentDigest::sha256(&[0x42; 32]),
        note: "authenticated successfully".to_string(),
    };
    let mut enc_rec = CanonicalEncoder::new();
    record.encode_canonical(&mut enc_rec);
    let bytes_rec = enc_rec.finish_checked()?;
    let mut dec_rec = CanonicalDecoder::new(&bytes_rec);
    let record_decoded = AcquisitionTransitionRecord::decode_canonical(&mut dec_rec)?;
    dec_rec.ensure_finished()?;
    assert_eq!(record, record_decoded);

    Ok(())
}

#[test]
fn test_check_accept_silence_negative_deadline_wrapping() -> Result<(), Box<dyn std::error::Error>>
{
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let res = session.check_accept_silence(TimestampNs(-1), TimestampNs(1_000_000_000));
    match res {
        Err(AcquisitionError::AcceptSilenceTimeout { deadline_ns, .. }) => {
            assert_ne!(
                deadline_ns,
                u64::MAX,
                "Negative deadline_ns (-1) silently wrapped to u64::MAX via unchecked `as u64`"
            );
        }
        other => return Err(format!("Expected timeout error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_check_accept_silence_elapsed_overflow_truncation() -> Result<(), Box<dyn std::error::Error>>
{
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let deadline = TimestampNs(0);
    let now = TimestampNs((1i128 << 65) + 42);

    let res = session.check_accept_silence(deadline, now);
    match res {
        Err(AcquisitionError::AcceptSilenceTimeout { elapsed_ns, .. }) => {
            assert!(
                elapsed_ns >= u64::MAX,
                "Elapsed ns truncated high bits to {elapsed_ns} instead of saturating or erroring"
            );
        }
        other => return Err(format!("Expected timeout error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_illegal_transition_mark_indeterminate_from_requested()
-> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);

    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(1_001_000_000),
        reason: "driver unresponsive".to_string(),
        unresolved_obligations: vec!["reset hardware".to_string()],
    };

    assert!(!is_allowed_transition(
        AcquisitionStateKind::Requested,
        AcquisitionStateKind::Indeterminate
    ));

    let res = session.mark_indeterminate(witness, TimestampNs(1_001_000_000));
    assert!(
        matches!(res, Err(AcquisitionError::IllegalTransition { .. })),
        "mark_indeterminate must reject unpermitted transition from Requested, but succeeded"
    );
    Ok(())
}

#[test]
fn test_reconcile_accepts_illegal_destination_transition() -> Result<(), Box<dyn std::error::Error>>
{
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(1_010_000_000),
        reason: "temporary bus hang".to_string(),
        unresolved_obligations: vec!["retry connect".to_string()],
    };
    session.mark_indeterminate(witness, TimestampNs(1_010_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Indeterminate);

    assert!(!is_allowed_transition(
        AcquisitionStateKind::Indeterminate,
        AcquisitionStateKind::Requested
    ));

    let illegal_resolved_state = AcquisitionState::Requested(Box::new(req.clone()));
    let res = session.reconcile(
        illegal_resolved_state,
        "illegal reconciliation back to Requested",
        TimestampNs(1_015_000_000),
    );

    assert!(
        matches!(res, Err(AcquisitionError::IllegalTransition { .. })),
        "reconcile must reject illegal target transition Indeterminate -> Requested"
    );
    Ok(())
}

#[test]
fn test_degrade_rejects_allowed_transition_from_indeterminate()
-> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let indet = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(1_010_000_000),
        reason: "jitter spike".to_string(),
        unresolved_obligations: vec!["check network".to_string()],
    };
    session.mark_indeterminate(indet, TimestampNs(1_010_000_000))?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Indeterminate);

    assert!(is_allowed_transition(
        AcquisitionStateKind::Indeterminate,
        AcquisitionStateKind::Degraded
    ));

    let deg_evidence = DegradationEvidence {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        degraded_at_ns: TimestampNs(1_015_000_000),
        lost_dimensions: vec!["resolution".to_string()],
        invalidated_negative_claims: vec!["motion_absence".to_string()],
        observed_packet_loss: 5,
        observed_jitter_ns: 20_000_000,
    };

    let res = session.degrade(deg_evidence, TimestampNs(1_015_000_000));
    assert!(
        res.is_ok(),
        "degrade() must allow registered transition from Indeterminate to Degraded per ACQUISITION_TRANSITION_TABLE, but returned {res:?}"
    );
    Ok(())
}

#[test]
fn test_continuity_accepts_non_contiguous_sequence_jump() -> Result<(), Box<dyn std::error::Error>>
{
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let ff = FirstFrameWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        sequence_number: 1,
        pts_ns: TimestampNs(1_010_000_000),
        frame_bytes: 1024,
        decode_state: DecodeState::Verified,
        source_custody: SourceCustody::Retained {
            source_digest: ContentDigest::sha256(b"frame-1"),
            source_bytes: 1024,
            storage_handle: "mem://frame-1".to_string(),
        },
        explicit_omission: ExplicitOmission::None,
    };
    session.observe_first_frame(ff, TimestampNs(1_010_000_000))?;

    let cov = sample_coverage_witness(true);
    let jumped_continuity = ContinuityWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        window_start_seq: 100, // Discontiguous jump from seq 1!
        window_end_seq: 109,
        window_start_pts_ns: TimestampNs(1_010_000_000),
        window_end_pts_ns: TimestampNs(1_050_000_000),
        frames_observed: 10,
        discontinuities: 0,
        packet_loss: 0,
        observed_jitter_ns: 100_000,
        max_jitter_threshold_ns: 1_000_000,
        coverage_witness: cov,
    };

    let res = session.verify_continuity(jumped_continuity, TimestampNs(1_050_000_000));
    assert!(
        matches!(res, Err(AcquisitionError::ContinuityGapDetected { .. })),
        "verify_continuity must reject window_start_seq (100) that does not connect to first_frame sequence (1)"
    );
    Ok(())
}

#[test]
fn test_single_frame_cannot_certify_continuity() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let cov = sample_coverage_witness(true);
    let single_frame_witness = ContinuityWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        window_start_seq: 1,
        window_end_seq: 1,
        window_start_pts_ns: TimestampNs(1_010_000_000),
        window_end_pts_ns: TimestampNs(1_010_000_000),
        frames_observed: 1,
        discontinuities: 0,
        packet_loss: 0,
        observed_jitter_ns: 0,
        max_jitter_threshold_ns: 1_000_000,
        coverage_witness: cov,
    };

    let res = single_frame_witness.verify(
        &req.source_identity.source_id,
        &req.device_identity.device_id,
        &req.adapter_identity.adapter_id,
    );
    assert!(
        res.is_err(),
        "ContinuityWitness must require a multi-frame continuous window (>= 2 frames), but accepted a single frame"
    );
    Ok(())
}

#[test]
fn test_record_transition_utf8_boundary_panic() -> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(1_010_000_000),
        reason: "temp hang".to_string(),
        unresolved_obligations: vec!["retry".to_string()],
    };
    session.mark_indeterminate(witness, TimestampNs(1_010_000_000))?;

    let failure = FailureWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        failed_at_ns: TimestampNs(1_015_000_000),
        error_code: "driver_failure".to_string(),
        error_message: "unrecoverable".to_string(),
        retryable: false,
    };
    let resolved_state = AcquisitionState::Failed {
        request: Box::new(req.clone()),
        failure,
        prior_state: AcquisitionStateKind::Indeterminate,
    };

    // 255 ASCII bytes + 2-byte UTF-8 character ('é' = [0xC3, 0xA9]). Index 256 is not a char boundary!
    let mut note = "a".repeat(255);
    note.push('é');

    let res = session.reconcile(resolved_state, &note, TimestampNs(1_015_000_000));
    assert!(
        res.is_ok(),
        "reconcile failed or panicked on multi-byte char boundary note: {res:?}"
    );
    Ok(())
}

#[test]
fn test_acquisition_request_bypasses_identity_verify() -> Result<(), Box<dyn std::error::Error>> {
    let mut req = sample_request()?;
    req.device_identity.manufacturer = "x".repeat(1000); // Exceeds MAX_STR_LEN in 6.5 DeviceIdentity

    assert!(req.device_identity.verify().is_err());

    let res = req.verify();
    assert!(
        res.is_err(),
        "AcquisitionRequest::verify() must delegate to device_identity.verify() and reject invalid device identity"
    );
    Ok(())
}

#[test]
fn test_check_accept_silence_propagates_transition_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(sample_auth(&req), TimestampNs(1_001_000_000))?;
    session.accept(sample_ack(&req), TimestampNs(1_005_000_000))?;

    let res = session.check_accept_silence(TimestampNs(1_010_000_000), TimestampNs(1_020_000_000));
    assert!(res.is_err());

    assert_eq!(
        session.state_kind(),
        AcquisitionStateKind::Failed,
        "Session must transition to Failed after timeout, but remained in {:?}",
        session.state_kind()
    );
    Ok(())
}

#[test]
fn test_identity_mismatch_rejection_for_adapter_and_device()
-> Result<(), Box<dyn std::error::Error>> {
    let req = sample_request()?;
    let other_adapter = AdapterId::parse("adapter:other-camera-adapter")?;
    let other_device = DeviceId::parse("device:other-camera-hardware")?;

    // 1. AuthReceipt mismatch
    let mut bad_auth = sample_auth(&req);
    bad_auth.adapter_id = other_adapter.clone();
    assert!(matches!(
        bad_auth.verify(
            &req.adapter_identity.adapter_id,
            &req.device_identity.device_id,
            req.requested_capabilities,
            TimestampNs(1_000_000_000)
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 2. FirstFrameWitness mismatch
    let mut bad_ff = sample_first_frame(&req);
    bad_ff.device_id = other_device.clone();
    assert!(matches!(
        bad_ff.verify(
            &req.source_identity.source_id,
            &req.device_identity.device_id,
            &req.adapter_identity.adapter_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 3. ContinuityWitness mismatch
    let mut bad_cont = sample_continuity(&req, true);
    bad_cont.adapter_id = other_adapter.clone();
    assert!(matches!(
        bad_cont.verify(
            &req.source_identity.source_id,
            &req.device_identity.device_id,
            &req.adapter_identity.adapter_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 4. DegradationEvidence mismatch
    let bad_deg = DegradationEvidence {
        adapter_id: other_adapter.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        degraded_at_ns: TimestampNs(2_000_000_000),
        lost_dimensions: vec!["packet_loss".to_string()],
        invalidated_negative_claims: vec![],
        observed_packet_loss: 2,
        observed_jitter_ns: 100_000,
    };
    assert!(matches!(
        bad_deg.verify(
            &req.source_identity.source_id,
            &req.device_identity.device_id,
            &req.adapter_identity.adapter_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 5. FailureWitness mismatch
    let bad_fail = FailureWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: other_device.clone(),
        source_id: req.source_identity.source_id.clone(),
        failed_at_ns: TimestampNs(2_000_000_000),
        error_code: "test_err".to_string(),
        error_message: "failed".to_string(),
        retryable: false,
    };
    assert!(matches!(
        bad_fail.verify(
            &req.source_identity.source_id,
            &req.device_identity.device_id,
            &req.adapter_identity.adapter_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 6. QuiescenceReceipt mismatch
    let bad_quiesc = QuiescenceReceipt {
        adapter_id: other_adapter,
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        cancelled_at_ns: TimestampNs(2_000_000_000),
        active_tasks: 0,
        open_descriptors: 0,
        buffers_drained: true,
    };
    assert!(matches!(
        bad_quiesc.verify(
            &req.adapter_identity.adapter_id,
            &req.device_identity.device_id,
            &req.source_identity.source_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    // 7. IndeterminateWitness mismatch
    let bad_indet = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: other_device,
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: TimestampNs(2_000_000_000),
        reason: "probe hang".to_string(),
        unresolved_obligations: vec![],
    };
    assert!(matches!(
        bad_indet.verify(
            &req.source_identity.source_id,
            &req.device_identity.device_id,
            &req.adapter_identity.adapter_id
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    Ok(())
}
