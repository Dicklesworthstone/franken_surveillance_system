//! Checkpoint recovery must not promote old labels into current transport evidence.

use super::*;
use crate::{
    AdapterGeneration, AdapterKind, ClockBasis, DeviceCapabilities, DeviceClass, DeviceGeneration,
    FirmwareGeneration, IsolationMode, MediaKind, SourceKind,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: TimestampNs = TimestampNs(2_000_000_000);
const RESTART: TimestampNs = TimestampNs(4_000_000_000);

fn request() -> TestResult<AcquisitionRequest> {
    let device_id = DeviceId::parse("device:checkpoint-camera")?;
    let adapter_id = AdapterId::parse("adapter:checkpoint-fixture")?;
    Ok(AcquisitionRequest {
        source_identity: SourceIdentity {
            source_id: SourceId::parse("src:checkpoint-video")?,
            device_id: device_id.clone(),
            adapter_id: adapter_id.clone(),
            source_kind: SourceKind::PhysicalSensor,
            media_kind: MediaKind::Video,
            channel: "main".to_owned(),
            nominal_clock_basis: ClockBasis::HostMonotonic,
            stream_generation: StreamGeneration::parse("gen:stream:1")?,
            failure_domain: "power:fixture".to_owned(),
            is_live: true,
        },
        device_identity: DeviceIdentity {
            device_id,
            generation: DeviceGeneration::parse("gen:dev:1")?,
            manufacturer: "Fixture".to_owned(),
            model: "Checkpoint camera".to_owned(),
            hardware_revision: "1".to_owned(),
            firmware_version: FirmwareGeneration::parse("gen:firmware:1")?,
            application_version: None,
            model_generation: None,
            device_class: DeviceClass::Camera,
            capabilities: DeviceCapabilities::PTZ,
            failure_domain: "power:fixture".to_owned(),
        },
        adapter_identity: AdapterIdentity {
            adapter_id,
            generation: AdapterGeneration::parse("gen:adapter:1")?,
            adapter_kind: AdapterKind::Uvc,
            protocol_profile: "uvc:1.5:isochronous".to_owned(),
            isolation_mode: IsolationMode::NativePureRust,
            credential_method: CredentialMethod::None,
            capabilities: AdapterCapabilities::STREAMING.union(AdapterCapabilities::PTZ_CONTROL),
            max_bandwidth_bytes_per_sec: 150_000_000,
            max_buffer_frames: 32,
            request_timeout_ns: 5_000_000_000,
        },
        requested_capabilities: AdapterCapabilities::STREAMING,
        requested_at_ns: TimestampNs(1_000_000_000),
    })
}

fn pts(sequence: u64) -> TimestampNs {
    TimestampNs(1_000_000_000 + i128::from(sequence) * 1_000_000)
}

fn authenticated() -> TestResult<AcquisitionSession> {
    let req = request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(
        AuthReceipt {
            adapter_id: req.adapter_identity.adapter_id,
            device_id: req.device_identity.device_id,
            method: CredentialMethod::None,
            principal_digest: ContentDigest::sha256(b"fixture:authorized-reader"),
            authorized_capabilities: req.requested_capabilities,
            authorized_at_ns: req.requested_at_ns,
            expires_at_ns: TimestampNs(3_000_000_000),
        },
        NOW,
    )?;
    Ok(session)
}

fn accepted() -> TestResult<AcquisitionSession> {
    let mut session = authenticated()?;
    session.accept(
        AdapterAck {
            adapter_id: session.request().adapter_identity.adapter_id.clone(),
            request_digest: session.request().request_digest(),
            ack_timestamp_ns: NOW,
            session_handle: "session:checkpoint-fixture".to_owned(),
            allocated_buffer_frames: 16,
        },
        NOW,
    )?;
    Ok(session)
}

fn first_frame() -> TestResult<AcquisitionSession> {
    let mut session = accepted()?;
    let req = session.request().clone();
    session.observe_first_frame(
        FirstFrameWitness {
            adapter_id: req.adapter_identity.adapter_id,
            device_id: req.device_identity.device_id,
            source_id: req.source_identity.source_id,
            sequence_number: 10,
            pts_ns: pts(10),
            frame_bytes: 64,
            decode_state: DecodeState::Verified,
            source_custody: SourceCustody::Retained {
                source_digest: ContentDigest::sha256(b"fixture:first-decoded-picture"),
                source_bytes: 64,
                storage_handle: "spool:fixture/first-picture".to_owned(),
            },
            explicit_omission: ExplicitOmission::None,
        },
        NOW,
    )?;
    Ok(session)
}

fn continuity(req: &AcquisitionRequest, start: u64, end: u64) -> ContinuityWitness {
    let domain = BTreeSet::from([req.source_identity.source_id.as_str().to_owned()]);
    ContinuityWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        window_start_seq: start,
        window_end_seq: end,
        window_start_pts_ns: pts(start),
        window_end_pts_ns: pts(end),
        frames_observed: end - start + 1,
        discontinuities: 0,
        packet_loss: 0,
        observed_jitter_ns: 100,
        max_jitter_threshold_ns: 1_000,
        coverage_witness: CoverageWitness {
            anchor: LedgerAnchor::genesis("site:checkpoint-fixture"),
            authorized_domain: domain.clone(),
            observed_domain: domain,
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Continuous,
            completeness: Completeness::Complete,
            negative_predicate: "fixture_observation_absent".to_owned(),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: 1,
            observed_generation: 1,
        },
    }
}

fn clean() -> TestResult<AcquisitionSession> {
    let mut session = first_frame()?;
    session.verify_continuity(continuity(session.request(), 10, 19), NOW)?;
    Ok(session)
}

fn gap(session: &AcquisitionSession, start: u64, end: u64) -> TestResult<WindowedDegradationEvidence> {
    let req = session.request();
    Ok(WindowedDegradationEvidence {
        request_digest: req.request_digest(),
        predecessor_digest: session.continuity_predecessor_digest()?,
        window_start_seq: start,
        window_end_seq: end,
        degradation: DegradationEvidence {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            source_id: req.source_identity.source_id.clone(),
            degraded_at_ns: NOW,
            lost_dimensions: vec!["packet_continuity".to_owned()],
            invalidated_negative_claims: vec!["fixture_observation_absent".to_owned()],
            observed_packet_loss: 1,
            observed_jitter_ns: 100,
        },
    })
}

fn gapped() -> TestResult<AcquisitionSession> {
    let mut session = clean()?;
    session.degrade_window(gap(&session, 20, 29)?, NOW)?;
    session.degrade_window(gap(&session, 30, 39)?, NOW)?;
    Ok(session)
}

fn restore(session: &AcquisitionSession) -> TestResult<AcquisitionSession> {
    let bytes = session.checkpoint_bytes()?;
    Ok(AcquisitionSession::restore_checkpoint(
        &bytes,
        ContentDigest::sha256(&bytes),
        session.request().request_digest(),
        RESTART,
    )?)
}

#[test]
fn requested_round_trip_is_exact_and_encoding_is_deterministic() -> TestResult {
    let session = AcquisitionSession::new(request()?)?;
    assert_eq!(session.checkpoint_bytes()?, session.checkpoint_bytes()?);
    assert_eq!(restore(&session)?, session);
    Ok(())
}

#[test]
fn every_active_state_restores_as_uncertain_with_exact_prior_witnesses() -> TestResult {
    for session in [accepted()?, first_frame()?, clean()?, gapped()?] {
        let restored = restore(&session)?;
        assert!(!restored.is_streaming());
        assert!(!restored.has_continuity());
        assert!(restored.check_absence_claim_allowed().is_err());
        assert_eq!(restored.request(), session.request());
        assert_eq!(restored.history.len(), session.history.len() + 1);
        assert_eq!(&restored.history[..session.history.len()], session.history());
        let AcquisitionState::Indeterminate { prior_state, witness, .. } = restored.state() else {
            return Err("started checkpoint was not restored as indeterminate".into());
        };
        assert_eq!(prior_state.as_ref(), session.state());
        assert_eq!(witness.indeterminate_at_ns, RESTART);
        assert_eq!(witness.unresolved_obligations.len(), 3);
    }
    Ok(())
}

#[test]
fn authentication_only_checkpoint_requires_fresh_authorization() -> TestResult {
    let session = authenticated()?;
    let restored = restore(&session)?;
    let AcquisitionState::Failed { failure, prior_state, .. } = restored.state() else {
        return Err("old authorization was restored without reauthentication".into());
    };
    assert_eq!(*prior_state, AcquisitionStateKind::Authenticated);
    assert_eq!(failure.error_code, "restart_requires_reauthentication");
    assert!(failure.retryable);
    assert!(!restored.is_streaming());
    assert_eq!(&restored.history[..session.history.len()], session.history());
    assert_eq!(restore(&restored)?, restored);
    Ok(())
}

#[test]
fn repeated_restart_keeps_one_uncertainty_state_and_one_restart_receipt() -> TestResult {
    let once = restore(&clean()?)?;
    let twice = restore(&once)?;
    assert_eq!(twice, once);
    assert_eq!(twice.checkpoint_bytes()?, once.checkpoint_bytes()?);
    Ok(())
}

#[test]
fn recorded_gaps_and_exact_predecessor_survive_restart_and_reconciliation() -> TestResult {
    let original = gapped()?;
    let mut restored = restore(&original)?;
    let mut resolved = original.clone();
    resolved.verify_continuity(continuity(resolved.request(), 40, 49), NOW)?;
    restored.reconcile(resolved.state().clone(), "verified next clean window", RESTART)?;
    assert_eq!(restored.state(), resolved.state());
    assert!(restored.check_absence_claim_allowed().is_err());
    let generation = &restored.request().source_identity.stream_generation;
    assert!(restored
        .check_absence_claim_allowed_in_window(generation, 40, 49, pts(40), pts(49))
        .is_ok());
    assert!(restored
        .check_absence_claim_allowed_in_window(generation, 20, 29, pts(20), pts(29))
        .is_err());
    let again = restore(&restored)?;
    assert!(again.has_windowed_gap);
    Ok(())
}

#[test]
fn restart_of_clean_stream_also_forbids_generation_wide_absence() -> TestResult {
    let original = clean()?;
    let mut restored = restore(&original)?;
    restored.reconcile(original.state().clone(), "restore historical window only", RESTART)?;
    assert!(restored.check_absence_claim_allowed().is_err());
    assert!(restored
        .check_absence_claim_allowed_in_window(
            &original.request().source_identity.stream_generation, 10, 19, pts(10), pts(19),
        )
        .is_ok());
    Ok(())
}

#[test]
fn terminal_failure_and_cancellation_are_not_reactivated() -> TestResult {
    let mut failed = clean()?;
    let req = failed.request().clone();
    failed.fail(
        FailureWitness {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            source_id: req.source_identity.source_id.clone(),
            failed_at_ns: NOW,
            error_code: "input_disconnected".to_owned(),
            error_message: "fixture input disconnected".to_owned(),
            retryable: true,
        },
        NOW,
    )?;
    let mut cancelled = clean()?;
    cancelled.cancel(
        QuiescenceReceipt {
            adapter_id: req.adapter_identity.adapter_id,
            device_id: req.device_identity.device_id,
            source_id: req.source_identity.source_id,
            cancelled_at_ns: NOW,
            active_tasks: 0,
            open_descriptors: 0,
            buffers_drained: true,
        },
        NOW,
    )?;
    for session in [failed, cancelled] {
        let restored = restore(&session)?;
        assert_eq!(restored, session);
        assert!(restored.state().is_terminal());
        assert!(!restored.is_streaming());
    }
    Ok(())
}

#[test]
fn corruption_and_rollback_are_rejected_by_independent_custody_digest() -> TestResult {
    let mut session = clean()?;
    let older = session.checkpoint_bytes()?;
    session.verify_continuity(continuity(session.request(), 20, 29), NOW)?;
    let latest = session.checkpoint_bytes()?;
    let latest_digest = ContentDigest::sha256(&latest);
    let request_digest = session.request().request_digest();
    assert!(AcquisitionSession::restore_checkpoint(
        &older, latest_digest, request_digest, RESTART,
    ).is_err());
    let mut damaged = latest;
    let index = damaged.len() / 2;
    damaged[index] ^= 1;
    assert!(AcquisitionSession::restore_checkpoint(
        &damaged, latest_digest, request_digest, RESTART,
    ).is_err());
    Ok(())
}

#[test]
fn request_configuration_and_generation_substitution_are_rejected() -> TestResult {
    let session = clean()?;
    let bytes = session.checkpoint_bytes()?;
    let digest = ContentDigest::sha256(&bytes);
    let mut other = session.request().clone();
    other.source_identity.stream_generation = StreamGeneration::parse("gen:stream:2")?;
    assert!(AcquisitionSession::restore_checkpoint(
        &bytes, digest, other.request_digest(), RESTART,
    ).is_err());
    other = session.request().clone();
    other.source_identity.channel = "substream".to_owned();
    assert!(AcquisitionSession::restore_checkpoint(
        &bytes, digest, other.request_digest(), RESTART,
    ).is_err());
    Ok(())
}

#[test]
fn authenticated_bytes_still_reject_truncation_trailing_data_and_unknown_schema() -> TestResult {
    let session = clean()?;
    let bytes = session.checkpoint_bytes()?;
    let request_digest = session.request().request_digest();
    for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        let truncated = &bytes[..length];
        assert!(AcquisitionSession::restore_checkpoint(
            truncated, ContentDigest::sha256(truncated), request_digest, RESTART,
        ).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(AcquisitionSession::restore_checkpoint(
        &trailing, ContentDigest::sha256(&trailing), request_digest, RESTART,
    ).is_err());
    let mut unknown = bytes;
    // Canonical text begins after its 8-byte big-endian length prefix.
    unknown[8] = b'X';
    assert!(AcquisitionSession::restore_checkpoint(
        &unknown, ContentDigest::sha256(&unknown), request_digest, RESTART,
    ).is_err());
    Ok(())
}

#[test]
fn size_history_and_nesting_are_bounded_before_untrusted_allocation() -> TestResult {
    let req = request()?;
    let oversized = vec![0; AcquisitionSession::MAX_CHECKPOINT_BYTES + 1];
    assert!(matches!(
        AcquisitionSession::restore_checkpoint(
            &oversized, ContentDigest::sha256(b"irrelevant"), req.request_digest(), RESTART,
        ),
        Err(AcquisitionError::BoundsViolation { .. })
    ));
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CHECKPOINT_SCHEMA);
    req.encode_canonical(&mut encoder);
    encoder.bool(false);
    AcquisitionStateKind::Requested.encode_canonical(&mut encoder);
    encoder.u32((MAX_HISTORY_LEN + 1) as u32);
    assert!(decode_session(&encoder.finish_checked()?).is_err());

    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: NOW,
        reason: "bounded nesting fixture".to_owned(),
        unresolved_obligations: vec![],
    };
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CHECKPOINT_SCHEMA);
    req.encode_canonical(&mut encoder);
    encoder.bool(false);
    for _ in 0..=MAX_STATE_DEPTH {
        AcquisitionStateKind::Indeterminate.encode_canonical(&mut encoder);
        witness.encode_canonical(&mut encoder);
    }
    AcquisitionStateKind::Requested.encode_canonical(&mut encoder);
    assert!(decode_session(&encoder.finish_checked()?).is_err());
    Ok(())
}

#[test]
fn encoder_rejects_cleared_gap_flag_substituted_witnesses_and_broken_audit() -> TestResult {
    let original = gapped()?;
    let mut cleared = original.clone();
    cleared.has_windowed_gap = false;
    assert!(cleared.checkpoint_bytes().is_err());
    let mut substituted = original.clone();
    if let AcquisitionState::Degraded { degradation, .. } = &mut substituted.state {
        degradation.source_id = SourceId::parse("src:another-camera")?;
    }
    assert!(substituted.checkpoint_bytes().is_err());
    let mut broken = original;
    if let Some(last) = broken.history.last_mut() {
        last.witness_digest = ContentDigest::sha256(b"another-witness");
    }
    assert!(broken.checkpoint_bytes().is_err());
    Ok(())
}

#[test]
fn rolling_audit_tail_does_not_drop_sticky_gap_memory() -> TestResult {
    let mut session = gapped()?;
    for step in 0..MAX_HISTORY_LEN + 2 {
        let seq = 40 + step as u64;
        session.verify_continuity(continuity(session.request(), seq, seq), NOW)?;
    }
    assert_eq!(session.history.len(), MAX_HISTORY_LEN);
    let restored = restore(&session)?;
    assert_eq!(restored.history.len(), MAX_HISTORY_LEN);
    assert!(restored.has_windowed_gap);
    assert!(restored.check_absence_claim_allowed().is_err());
    Ok(())
}
