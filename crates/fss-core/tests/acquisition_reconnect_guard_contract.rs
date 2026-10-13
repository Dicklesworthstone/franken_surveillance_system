#![forbid(unsafe_code)]
//! Reconnect preserves unresolved outcomes, identity, time and cold-recovery obligations.

use fss_core::{
    AcquisitionError, AcquisitionRequest, AcquisitionSession, AcquisitionState,
    AcquisitionStateKind, AdapterAck, AdapterCapabilities, AdapterGeneration, AdapterId,
    AdapterIdentity, AdapterKind, AuthReceipt, ClockBasis, ContentDigest, CredentialMethod,
    DeviceCapabilities, DeviceClass, DeviceGeneration, DeviceId, DeviceIdentity, FailureWitness,
    FirmwareGeneration, IndeterminateWitness, IsolationMode, MediaKind, SourceId, SourceIdentity,
    SourceKind, StreamGeneration, TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: TimestampNs = TimestampNs(2_000_000_000);

fn request() -> TestResult<AcquisitionRequest> {
    let device_id = DeviceId::parse("device:reconnect-camera")?;
    let adapter_id = AdapterId::parse("adapter:reconnect-fixture")?;
    Ok(AcquisitionRequest {
        source_identity: SourceIdentity {
            source_id: SourceId::parse("src:reconnect-video")?,
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
            model: "Reconnect camera".to_owned(),
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

fn accepted_session() -> TestResult<AcquisitionSession> {
    let req = request()?;
    let mut session = AcquisitionSession::new(req.clone())?;
    session.authenticate(
        AuthReceipt {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            method: CredentialMethod::None,
            principal_digest: ContentDigest::sha256(b"fixture:authorized-reader"),
            authorized_capabilities: req.requested_capabilities,
            authorized_at_ns: req.requested_at_ns,
            expires_at_ns: TimestampNs(30_000_000_000),
        },
        NOW,
    )?;
    session.accept(
        AdapterAck {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            request_digest: req.request_digest(),
            ack_timestamp_ns: NOW,
            session_handle: "session:reconnect-fixture".to_owned(),
            allocated_buffer_frames: 16,
        },
        NOW,
    )?;
    Ok(session)
}

fn failure(session: &AcquisitionSession) -> FailureWitness {
    let req = session.request();
    FailureWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        failed_at_ns: NOW,
        error_code: "fixture_transport_lost".to_owned(),
        error_message: "fixture transport closed".to_owned(),
        retryable: true,
    }
}

fn failed_session() -> TestResult<AcquisitionSession> {
    let mut session = accepted_session()?;
    session.fail(failure(&session), NOW)?;
    Ok(session)
}

fn indeterminate_session() -> TestResult<AcquisitionSession> {
    let mut session = accepted_session()?;
    let req = session.request();
    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: NOW,
        reason: "fixture cancellation acknowledgement lost".to_owned(),
        unresolved_obligations: vec!["reconcile-owned-session".to_owned()],
    };
    session.mark_indeterminate(witness, NOW)?;
    Ok(session)
}

fn next_request(session: &AcquisitionSession) -> TestResult<AcquisitionRequest> {
    let mut req = session.request().clone();
    req.source_identity.stream_generation = StreamGeneration::parse("gen:stream:2")?;
    req.requested_at_ns = NOW;
    Ok(req)
}

#[test]
fn reconnect_preserves_indeterminate_obligations_and_all_retained_state() -> TestResult {
    let mut session = indeterminate_session()?;
    let before = session.clone();
    let req = next_request(&session)?;
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::IndeterminateStateUnresolved { .. })
    ));
    assert_eq!(session, before);
    assert!(session.check_absence_claim_allowed().is_err());
    Ok(())
}

#[test]
fn invalid_generation_does_not_hide_the_need_to_reconcile() -> TestResult {
    let mut session = indeterminate_session()?;
    let before = session.clone();
    let req = session.request().clone();
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::IndeterminateStateUnresolved { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn explicit_reconciliation_allows_a_fresh_unauthenticated_generation() -> TestResult {
    let mut session = indeterminate_session()?;
    let resolved = AcquisitionState::Failed {
        request: Box::new(session.request().clone()),
        failure: failure(&session),
        prior_state: AcquisitionStateKind::Indeterminate,
    };
    session.reconcile(resolved, "fixture explicitly reconciled", NOW)?;
    let history = session.history().to_vec();
    let req = next_request(&session)?;
    let digest = req.request_digest();
    session.reconnect(req, NOW)?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    assert!(!session.is_streaming());
    assert!(!session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());
    assert_eq!(&session.history()[..history.len()], history.as_slice());
    assert_eq!(session.request().request_digest(), digest);
    Ok(())
}

#[test]
fn reconnect_rejects_another_source_without_mutation() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let mut req = next_request(&session)?;
    req.source_identity.source_id = SourceId::parse("src:other-video")?;
    req.verify()?;
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn reconnect_rejects_another_device_with_a_self_consistent_request() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let mut req = next_request(&session)?;
    let other = DeviceId::parse("device:other-camera")?;
    req.source_identity.device_id = other.clone();
    req.device_identity.device_id = other;
    req.verify()?;
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn newer_device_and_adapter_generations_preserve_stable_identity() -> TestResult {
    let mut session = failed_session()?;
    let mut req = next_request(&session)?;
    req.device_identity.generation = DeviceGeneration::parse("gen:dev:2")?;
    req.adapter_identity.generation = AdapterGeneration::parse("gen:adapter:2")?;
    session.reconnect(req, NOW)?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    Ok(())
}

#[test]
fn explicit_adapter_replacement_still_requires_fresh_authentication() -> TestResult {
    let mut session = failed_session()?;
    let mut req = next_request(&session)?;
    let adapter = AdapterId::parse("adapter:replacement-fixture")?;
    req.source_identity.adapter_id = adapter.clone();
    req.adapter_identity.adapter_id = adapter;
    session.reconnect(req, NOW)?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    assert!(session.check_absence_claim_allowed().is_err());
    Ok(())
}

#[test]
fn reconnect_refuses_reversed_admission_time_without_mutation() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let mut req = next_request(&session)?;
    req.requested_at_ns = TimestampNs(1_500_000_000);
    assert!(matches!(
        session.reconnect(req, TimestampNs(1_900_000_000)),
        Err(AcquisitionError::InvalidTimestamp { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn reconnect_refuses_a_future_request_without_mutation() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let mut req = next_request(&session)?;
    req.requested_at_ns = TimestampNs(NOW.0 + 1);
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::InvalidTimestamp { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn reconnect_refuses_a_request_older_than_the_prior_generation() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let mut req = next_request(&session)?;
    req.requested_at_ns = TimestampNs(999_999_999);
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::InvalidTimestamp { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn reconnect_refuses_negative_times_and_keeps_its_checkpoint() -> TestResult {
    for (requested, admitted) in [(TimestampNs(-1), NOW), (NOW, TimestampNs(-1))] {
        let mut session = failed_session()?;
        let before = session.checkpoint_bytes()?;
        let mut req = next_request(&session)?;
        req.requested_at_ns = requested;
        assert!(matches!(
            session.reconnect(req, admitted),
            Err(AcquisitionError::InvalidTimestamp { .. })
        ));
        assert_eq!(session.checkpoint_bytes()?, before);
    }
    Ok(())
}

#[test]
fn reconnect_still_refuses_generation_reuse_without_mutation() -> TestResult {
    let mut session = failed_session()?;
    let before = session.clone();
    let req = session.request().clone();
    assert!(matches!(
        session.reconnect(req, NOW),
        Err(AcquisitionError::GenerationConflict { .. })
    ));
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn cold_restore_cannot_reconnect_away_its_restart_obligations() -> TestResult {
    for original in [accepted_session()?, indeterminate_session()?] {
        let bytes = original.checkpoint_bytes()?;
        let mut restored = AcquisitionSession::restore_checkpoint(
            &bytes,
            ContentDigest::sha256(&bytes),
            original.request().request_digest(),
            NOW,
        )?;
        assert_eq!(restored.state_kind(), AcquisitionStateKind::Indeterminate);
        let before = restored.checkpoint_bytes()?;
        let req = next_request(&restored)?;
        assert!(matches!(
            restored.reconnect(req, NOW),
            Err(AcquisitionError::IndeterminateStateUnresolved { .. })
        ));
        assert_eq!(restored.checkpoint_bytes()?, before);
    }
    Ok(())
}

#[test]
fn malformed_fresh_request_does_not_replace_the_terminal_predecessor() -> TestResult {
    let mut session = failed_session()?;
    let before = session.checkpoint_bytes()?;
    let mut req = next_request(&session)?;
    req.source_identity.adapter_id = AdapterId::parse("adapter:unbound")?;
    assert!(session.reconnect(req, NOW).is_err());
    assert_eq!(session.checkpoint_bytes()?, before);
    Ok(())
}
