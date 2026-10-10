#![forbid(unsafe_code)]
//! Recovery proves a new clean window without erasing gaps, custody or request identity.

use std::collections::BTreeSet;

use fss_core::acquisition::WindowedDegradationEvidence;
use fss_core::{
    AcquisitionError, AcquisitionRequest, AcquisitionSession, AcquisitionState,
    AcquisitionStateKind, AdapterAck, AdapterCapabilities, AdapterGeneration, AdapterId,
    AdapterIdentity, AdapterKind, AuthReceipt, CanonicalDecode, CanonicalEncode, ClockBasis,
    Completeness, ContentDigest, ContinuityWitness, CoverageContinuity, CoverageStopReason,
    CoverageWitness, CredentialMethod, DecodeState, DeviceCapabilities, DeviceClass,
    DeviceGeneration, DeviceId, DeviceIdentity, ExplicitOmission, FirmwareGeneration,
    FirstFrameWitness, IndeterminateWitness, IsolationMode, LedgerAnchor, MediaKind, SourceCustody,
    SourceId, SourceIdentity, SourceKind, StreamGeneration, TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NOW: TimestampNs = TimestampNs(2_000_000_000);

fn request() -> TestResult<AcquisitionRequest> {
    let device_id = DeviceId::parse("device:recovery-camera")?;
    let adapter_id = AdapterId::parse("adapter:recovery-fixture")?;
    Ok(AcquisitionRequest {
        source_identity: SourceIdentity {
            source_id: SourceId::parse("src:recovery-video")?,
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
            model: "Recovery camera".to_owned(),
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

fn observe_first_frame(session: &mut AcquisitionSession, sequence: u64) -> TestResult {
    let req = session.request().clone();
    session.authenticate(
        AuthReceipt {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            device_id: req.device_identity.device_id.clone(),
            method: CredentialMethod::None,
            principal_digest: ContentDigest::sha256(b"fixture:authorized-reader"),
            authorized_capabilities: req.requested_capabilities,
            authorized_at_ns: req.requested_at_ns,
            expires_at_ns: TimestampNs(3_000_000_000),
        },
        NOW,
    )?;
    session.accept(
        AdapterAck {
            adapter_id: req.adapter_identity.adapter_id.clone(),
            request_digest: req.request_digest(),
            ack_timestamp_ns: NOW,
            session_handle: "session:recovery-fixture".to_owned(),
            allocated_buffer_frames: 16,
        },
        NOW,
    )?;
    session.observe_first_frame(
        FirstFrameWitness {
            adapter_id: req.adapter_identity.adapter_id,
            device_id: req.device_identity.device_id,
            source_id: req.source_identity.source_id,
            sequence_number: sequence,
            pts_ns: pts(sequence),
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
    Ok(())
}

fn session_for(req: AcquisitionRequest, first_sequence: u64) -> TestResult<AcquisitionSession> {
    let mut session = AcquisitionSession::new(req)?;
    observe_first_frame(&mut session, first_sequence)?;
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
        // Malformed full-width and reversed ranges intentionally reach the verifier below.
        frames_observed: end.saturating_sub(start).saturating_add(1),
        discontinuities: 0,
        packet_loss: 0,
        observed_jitter_ns: 100,
        max_jitter_threshold_ns: 1_000,
        coverage_witness: CoverageWitness {
            anchor: LedgerAnchor::genesis("site:recovery-fixture"),
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

fn gap(
    session: &AcquisitionSession,
    start: u64,
    end: u64,
) -> TestResult<WindowedDegradationEvidence> {
    let req = session.request();
    Ok(WindowedDegradationEvidence {
        request_digest: req.request_digest(),
        predecessor_digest: session.continuity_predecessor_digest()?,
        window_start_seq: start,
        window_end_seq: end,
        degradation: fss_core::DegradationEvidence {
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

fn mark_indeterminate(session: &mut AcquisitionSession) -> TestResult {
    let req = session.request();
    let witness = IndeterminateWitness {
        adapter_id: req.adapter_identity.adapter_id.clone(),
        device_id: req.device_identity.device_id.clone(),
        source_id: req.source_identity.source_id.clone(),
        indeterminate_at_ns: NOW,
        reason: "interrupted acquisition reconciliation".to_owned(),
        unresolved_obligations: vec!["verify-next-window".to_owned()],
    };
    session.mark_indeterminate(witness, NOW)?;
    Ok(())
}

fn clean_session() -> TestResult<AcquisitionSession> {
    let mut session = session_for(request()?, 10)?;
    session.verify_continuity(continuity(session.request(), 10, 19), NOW)?;
    Ok(session)
}

fn gapped_session() -> TestResult<AcquisitionSession> {
    let mut session = clean_session()?;
    session.degrade_window(gap(&session, 20, 29)?, NOW)?;
    Ok(session)
}

fn recovered_session() -> TestResult<AcquisitionSession> {
    let mut session = gapped_session()?;
    session.verify_continuity(continuity(session.request(), 30, 39), NOW)?;
    Ok(session)
}

#[test]
fn consecutive_gaps_recover_without_rewriting_evidence_or_certifying_the_gap() -> TestResult {
    let mut session = clean_session()?;
    let initial_clean = session.state().clone();
    assert!(session.check_absence_claim_allowed()?.certifies_absence());

    let first_gap = gap(&session, 20, 29)?;
    session.degrade_window(first_gap.clone(), NOW)?;
    let second_gap = gap(&session, 30, 39)?;
    assert_eq!(second_gap.predecessor_digest, first_gap.evidence_digest());
    session.degrade_window(second_gap.clone(), NOW)?;
    assert!(!session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());

    let AcquisitionState::Degraded {
        first_frame: Some(retained_frame),
        last_continuity: Some(retained_clean),
        degradation,
        last_windowed_degradation: Some(retained_gap),
        ..
    } = session.state()
    else {
        return Err("degraded state lost its retained predecessors".into());
    };
    let AcquisitionState::ContinuityVerified {
        first_frame,
        continuity: original_clean,
        ..
    } = &initial_clean
    else {
        return Err("fixture lacks initial continuity".into());
    };
    assert_eq!(retained_frame, first_frame);
    assert_eq!(retained_clean, original_clean);
    assert_eq!(retained_gap.as_ref(), &second_gap);
    assert_eq!(degradation.as_ref(), &second_gap.degradation);

    let recovered = continuity(session.request(), 40, 49);
    session.verify_continuity(recovered.clone(), NOW)?;
    assert!(session.is_streaming());
    assert!(session.has_continuity());
    assert!(matches!(
        session.check_absence_claim_allowed(),
        Err(AcquisitionError::AbsenceClaimForbidden { .. })
    ));
    let generation = &session.request().source_identity.stream_generation;
    assert_eq!(
        session.check_absence_claim_allowed_in_window(generation, 40, 49, pts(40), pts(49))?,
        &recovered
    );
    assert!(
        session
            .check_absence_claim_allowed_in_window(generation, 20, 49, pts(20), pts(49))
            .is_err()
    );
    for evidence in [&first_gap, &second_gap] {
        assert!(session.history().iter().any(|record| {
            record.to == AcquisitionStateKind::Degraded
                && record.witness_digest == evidence.evidence_digest()
        }));
    }
    session.verify_continuity(continuity(session.request(), 50, 59), NOW)?;
    assert!(session.check_absence_claim_allowed().is_err());
    Ok(())
}

#[test]
fn first_frame_can_anchor_a_degraded_window_before_any_clean_window() -> TestResult {
    for start in [10, 11] {
        let mut session = session_for(request()?, 10)?;
        let predecessor = session.continuity_predecessor_digest()?;
        let evidence = gap(&session, start, 19)?;
        assert_eq!(evidence.predecessor_digest, predecessor);
        session.degrade_window(evidence, NOW)?;
        assert!(matches!(
            session.state(),
            AcquisitionState::Degraded {
                first_frame: Some(_),
                last_continuity: None,
                last_windowed_degradation: Some(_),
                ..
            }
        ));
        session.verify_continuity(continuity(session.request(), 20, 29), NOW)?;
        assert!(session.has_continuity());
        assert!(session.check_absence_claim_allowed().is_err());
    }
    Ok(())
}

#[test]
fn wrong_predecessors_requests_and_invalid_embedded_evidence_leave_session_unchanged() -> TestResult
{
    let session = clean_session()?;
    let valid = gap(&session, 20, 29)?;
    for mutation in 0..7 {
        let mut invalid = valid.clone();
        match mutation {
            0 => invalid.request_digest = ContentDigest::sha256(b"another-request"),
            1 => invalid.predecessor_digest = valid.degradation.evidence_digest(),
            2 => invalid.degradation.source_id = SourceId::parse("src:another-video")?,
            3 => invalid.degradation.device_id = DeviceId::parse("device:another-camera")?,
            4 => invalid.degradation.adapter_id = AdapterId::parse("adapter:another-adapter")?,
            5 => invalid.degradation.lost_dimensions.clear(),
            _ => invalid.degradation.observed_packet_loss = 11,
        }
        let mut candidate = session.clone();
        assert!(
            candidate.degrade_window(invalid, NOW).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(candidate, session, "mutation {mutation} changed session");
    }

    // These requests keep identical IDs and predecessor witnesses, but change request authority.
    for mutation in 0..4 {
        let mut changed_request = session.request().clone();
        match mutation {
            0 => {
                changed_request.source_identity.stream_generation =
                    StreamGeneration::parse("gen:stream:2")?;
            }
            1 => changed_request.source_identity.channel = "secondary".to_owned(),
            2 => changed_request.requested_at_ns = TimestampNs(1_000_000_001),
            _ => {
                changed_request.requested_capabilities = changed_request
                    .requested_capabilities
                    .union(AdapterCapabilities::PTZ_CONTROL);
            }
        }
        let mut candidate = session_for(changed_request, 10)?;
        candidate.verify_continuity(continuity(candidate.request(), 10, 19), NOW)?;
        assert_eq!(
            candidate.continuity_predecessor_digest()?,
            valid.predecessor_digest
        );
        let before = candidate.clone();
        assert!(matches!(
            candidate.degrade_window(valid.clone(), NOW),
            Err(AcquisitionError::WitnessMismatch { .. })
        ));
        assert_eq!(candidate, before);
    }
    Ok(())
}

#[test]
fn degraded_and_recovered_windows_reject_overlap_skips_reversal_and_overflow() -> TestResult {
    let session = clean_session()?;
    for (start, end) in [(19, 29), (21, 29), (20, 19), (0, u64::MAX)] {
        let mut candidate = session.clone();
        let evidence = gap(&candidate, start, end)?;
        assert!(
            candidate.degrade_window(evidence, NOW).is_err(),
            "{start}..={end}"
        );
        assert_eq!(candidate, session);
    }

    let session = gapped_session()?;
    for (start, end) in [(29, 39), (31, 39), (30, 29)] {
        let mut candidate = session.clone();
        let witness = continuity(candidate.request(), start, end);
        assert!(
            candidate.verify_continuity(witness, NOW).is_err(),
            "{start}..={end}"
        );
        assert_eq!(candidate, session);
    }

    // Inclusive [0, MAX] has MAX+1 positions; a saturated count is not a valid proof.
    let mut session = session_for(request()?, 0)?;
    let before = session.clone();
    let full_width = continuity(session.request(), 0, u64::MAX);
    assert_eq!(full_width.frames_observed, u64::MAX);
    assert!(session.verify_continuity(full_width, NOW).is_err());
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn exhausted_sequence_space_never_wraps_or_reuses_the_last_position() -> TestResult {
    let mut clean = session_for(request()?, u64::MAX - 1)?;
    clean.verify_continuity(continuity(clean.request(), u64::MAX - 1, u64::MAX), NOW)?;
    let mut degraded = session_for(request()?, u64::MAX)?;
    degraded.degrade_window(gap(&degraded, u64::MAX, u64::MAX)?, NOW)?;

    for session in [clean, degraded] {
        for (start, end) in [(0, 1), (u64::MAX, u64::MAX)] {
            let mut candidate = session.clone();
            let evidence = gap(&candidate, start, end)?;
            assert!(matches!(
                candidate.degrade_window(evidence, NOW),
                Err(AcquisitionError::ContinuityGapDetected { .. })
            ));
            assert_eq!(candidate, session);
            let witness = continuity(candidate.request(), start, end);
            assert!(candidate.verify_continuity(witness, NOW).is_err());
            assert_eq!(candidate, session);
        }
    }
    Ok(())
}

#[test]
fn generic_degradation_cannot_supply_or_restore_a_gap_cursor() -> TestResult {
    let mut session = gapped_session()?;
    let next_gap = gap(&session, 30, 39)?;
    let mut otherwise_recovered = session.clone();
    otherwise_recovered.verify_continuity(continuity(session.request(), 30, 39), NOW)?;
    session.degrade(next_gap.degradation.clone(), NOW)?;
    assert!(session.continuity_predecessor_digest().is_err());
    assert!(matches!(
        session.state(),
        AcquisitionState::Degraded {
            last_windowed_degradation: None,
            ..
        }
    ));

    let before = session.clone();
    assert!(matches!(
        session.verify_continuity(continuity(session.request(), 30, 39), NOW),
        Err(AcquisitionError::MissingWitness { .. })
    ));
    assert_eq!(session, before);
    assert!(session.degrade_window(next_gap, NOW).is_err());
    assert_eq!(session, before);

    mark_indeterminate(&mut session)?;
    let before = session.clone();
    assert!(
        session
            .verify_continuity(continuity(session.request(), 30, 39), NOW)
            .is_err()
    );
    assert_eq!(session, before);
    assert!(
        session
            .reconcile(
                otherwise_recovered.state().clone(),
                "cannot infer missing span",
                NOW
            )
            .is_err()
    );
    assert_eq!(session, before);
    Ok(())
}

#[test]
fn direct_recovery_from_indeterminate_preserves_the_recorded_gap() -> TestResult {
    let mut session = gapped_session()?;
    let successor_gap = gap(&session, 30, 39)?;
    mark_indeterminate(&mut session)?;
    let before = session.clone();
    assert!(session.continuity_predecessor_digest().is_err());
    assert!(session.degrade_window(successor_gap, NOW).is_err());
    assert_eq!(session, before);
    for start in [20, 29, 31] {
        let witness = continuity(session.request(), start, 39);
        assert!(session.verify_continuity(witness, NOW).is_err());
        assert_eq!(session, before);
    }
    session.verify_continuity(continuity(session.request(), 30, 39), NOW)?;
    assert!(session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());
    assert!(
        session
            .check_absence_claim_allowed_in_window(
                &session.request().source_identity.stream_generation,
                30,
                39,
                pts(30),
                pts(39)
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn reconciliation_admits_exact_proven_successors_and_keeps_the_gap_sticky() -> TestResult {
    let mut session = clean_session()?;
    for (start, end) in [(20, 29), (30, 39)] {
        let mut resolved = session.clone();
        let evidence = gap(&resolved, start, end)?;
        resolved.degrade_window(evidence.clone(), NOW)?;
        mark_indeterminate(&mut session)?;
        session.reconcile(
            resolved.state().clone(),
            "retained adjacent degraded window",
            NOW,
        )?;
        assert_eq!(session.state(), resolved.state());
        assert_eq!(
            session.history().last().map(|record| record.witness_digest),
            Some(evidence.evidence_digest())
        );
    }
    let mut recovered = session.clone();
    recovered.verify_continuity(continuity(recovered.request(), 40, 49), NOW)?;
    mark_indeterminate(&mut session)?;
    session.reconcile(
        recovered.state().clone(),
        "verified adjacent recovery window",
        NOW,
    )?;
    assert!(session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());

    let exact_prior = session.state().clone();
    mark_indeterminate(&mut session)?;
    session.reconcile(exact_prior.clone(), "restore exact retained state", NOW)?;
    assert_eq!(session.state(), &exact_prior);
    assert!(session.check_absence_claim_allowed().is_err());
    Ok(())
}

#[test]
fn reconciliation_rejects_changed_requests_and_substituted_custody_without_mutation() -> TestResult
{
    let mut session = gapped_session()?;
    let mut resolved = session.clone();
    resolved.verify_continuity(continuity(resolved.request(), 30, 39), NOW)?;
    mark_indeterminate(&mut session)?;
    let before = session.clone();
    for mutation in 0..7 {
        let mut forged = resolved.state().clone();
        let AcquisitionState::ContinuityVerified {
            request,
            auth,
            ack,
            first_frame,
            ..
        } = &mut forged
        else {
            return Err("fixture lacks resolved continuity".into());
        };
        match mutation {
            0 => {
                request.source_identity.stream_generation = StreamGeneration::parse("gen:stream:2")?
            }
            1 => request.requested_at_ns = TimestampNs(1_000_000_001),
            2 => request.source_identity.channel = "substituted".to_owned(),
            3 => auth.principal_digest = ContentDigest::sha256(b"substituted-principal"),
            4 => ack.session_handle = "session:substituted".to_owned(),
            5 => {
                first_frame.source_custody = SourceCustody::Retained {
                    source_digest: ContentDigest::sha256(b"substituted-picture"),
                    source_bytes: 64,
                    storage_handle: "spool:fixture/substituted".to_owned(),
                }
            }
            _ => first_frame.sequence_number = 11,
        }
        assert!(
            session
                .reconcile(forged, "untrusted resolved state", NOW)
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(session, before, "mutation {mutation} changed session");
    }
    Ok(())
}

#[test]
fn reconciliation_rejects_substituted_degradation_and_missing_first_frame_custody() -> TestResult {
    let mut session = clean_session()?;
    let mut resolved = session.clone();
    resolved.degrade_window(gap(&resolved, 20, 29)?, NOW)?;
    mark_indeterminate(&mut session)?;
    let before = session.clone();
    for mutation in 0..3 {
        let mut forged = resolved.state().clone();
        let AcquisitionState::Degraded {
            first_frame,
            last_continuity,
            degradation,
            ..
        } = &mut forged
        else {
            return Err("fixture lacks resolved degradation".into());
        };
        match mutation {
            0 => *first_frame = None,
            1 => *last_continuity = None,
            _ => degradation.invalidated_negative_claims.clear(),
        }
        assert!(
            session
                .reconcile(forged, "substituted degraded evidence", NOW)
                .is_err()
        );
        assert_eq!(session, before);
    }

    // A caller-supplied resolved state cannot inject a first picture into a session that
    // reached only AdapterAccepted before the interruption.
    let mut without_frame = AcquisitionSession::new(request()?)?;
    let AcquisitionState::ContinuityVerified { auth, ack, .. } = clean_session()?.state().clone()
    else {
        return Err("fixture lacks authenticated continuity".into());
    };
    without_frame.authenticate(auth, NOW)?;
    without_frame.accept(ack, NOW)?;
    mark_indeterminate(&mut without_frame)?;
    let before = without_frame.clone();
    assert!(
        without_frame
            .reconcile(
                clean_session()?.state().clone(),
                "invented first picture",
                NOW
            )
            .is_err()
    );
    assert_eq!(without_frame, before);
    Ok(())
}

#[test]
fn stale_gap_and_clean_states_cannot_be_replayed_across_a_later_gap() -> TestResult {
    let mut session = clean_session()?;
    let stale_clean = session.state().clone();
    let first_gap = gap(&session, 20, 29)?;
    session.degrade_window(first_gap.clone(), NOW)?;
    let stale_gap = session.state().clone();
    let before = session.clone();
    assert!(session.degrade_window(first_gap, NOW).is_err());
    assert_eq!(session, before);
    session.degrade_window(gap(&session, 30, 39)?, NOW)?;
    let exact_prior = session.state().clone();
    mark_indeterminate(&mut session)?;
    let before = session.clone();
    for stale in [stale_clean, stale_gap] {
        assert!(session.reconcile(stale, "stale proof replay", NOW).is_err());
        assert_eq!(session, before);
    }
    session.reconcile(exact_prior, "restore exact most recent gap", NOW)?;
    session.verify_continuity(continuity(session.request(), 40, 49), NOW)?;
    assert!(session.check_absence_claim_allowed().is_err());
    Ok(())
}

#[test]
fn scoped_absence_requires_generation_sequence_and_pts_containment_together() -> TestResult {
    let session = recovered_session()?;
    let generation = &session.request().source_identity.stream_generation;
    let expected = continuity(session.request(), 30, 39);
    for (start, end) in [(30, 39), (32, 37), (35, 35)] {
        assert_eq!(
            session.check_absence_claim_allowed_in_window(
                generation,
                start,
                end,
                pts(start),
                pts(end)
            )?,
            &expected
        );
    }
    for (start, end, start_pts, end_pts) in [
        (29, 39, 30, 39),
        (30, 40, 30, 39),
        (35, 34, 30, 39),
        (20, 29, 30, 39),
        (30, 39, 29, 39),
        (30, 39, 30, 40),
        (30, 39, 35, 34),
        (30, 39, 20, 29),
    ] {
        assert!(
            session
                .check_absence_claim_allowed_in_window(
                    generation,
                    start,
                    end,
                    pts(start_pts),
                    pts(end_pts)
                )
                .is_err(),
            "sequence {start}..={end}; PTS {start_pts}..={end_pts}"
        );
    }
    assert!(matches!(
        session.check_absence_claim_allowed_in_window(
            &StreamGeneration::parse("gen:stream:2")?,
            30,
            39,
            pts(30),
            pts(39)
        ),
        Err(AcquisitionError::WitnessMismatch { .. })
    ));

    let mut indeterminate = session.clone();
    mark_indeterminate(&mut indeterminate)?;
    assert!(
        indeterminate
            .check_absence_claim_allowed_in_window(generation, 30, 39, pts(30), pts(39))
            .is_err()
    );
    let degraded = gapped_session()?;
    assert!(
        degraded
            .check_absence_claim_allowed_in_window(generation, 20, 29, pts(20), pts(29))
            .is_err()
    );
    Ok(())
}

#[test]
fn transport_recovery_does_not_upgrade_uncertified_coverage_to_absence() -> TestResult {
    let mut session = gapped_session()?;
    let mut witness = continuity(session.request(), 30, 39);
    witness.coverage_witness.stop_reason = CoverageStopReason::Unsupported;
    session.verify_continuity(witness, NOW)?;
    assert!(session.has_continuity());
    assert!(session.check_absence_claim_allowed().is_err());
    assert!(matches!(
        session.check_absence_claim_allowed_in_window(
            &session.request().source_identity.stream_generation,
            30,
            39,
            pts(30),
            pts(39)
        ),
        Err(AcquisitionError::InvalidCoverageWitness { .. })
    ));
    Ok(())
}

#[test]
fn only_a_valid_new_generation_reconnect_resets_the_legacy_absence_barrier() -> TestResult {
    let mut session = recovered_session()?;
    session.verify_continuity(continuity(session.request(), 40, 49), NOW)?;
    assert!(session.check_absence_claim_allowed().is_err());
    let exact_clean = session.state().clone();
    mark_indeterminate(&mut session)?;
    session.reconcile(exact_clean, "restore later clean window", NOW)?;
    assert!(session.check_absence_claim_allowed().is_err());

    let unscoped = gap(&session, 50, 59)?.degradation;
    session.degrade(unscoped, NOW)?;
    let exact_degraded = session.state().clone();
    mark_indeterminate(&mut session)?;
    session.reconcile(exact_degraded, "restore unscoped degradation", NOW)?;
    let before = session.clone();
    for mutation in 0..3 {
        let mut invalid_request = session.request().clone();
        if mutation == 1 {
            invalid_request.source_identity.stream_generation =
                StreamGeneration::parse("gen:stream:0")?;
        } else if mutation == 2 {
            invalid_request.source_identity.stream_generation =
                StreamGeneration::parse("gen:stream:2")?;
            invalid_request.source_identity.device_id = DeviceId::parse("device:mismatched")?;
        }
        assert!(session.reconnect(invalid_request, NOW).is_err());
        assert_eq!(session, before);
    }
    assert!(
        session
            .verify_continuity(continuity(session.request(), 50, 59), NOW)
            .is_err()
    );
    assert_eq!(session, before);

    let old_generation = session.request().source_identity.stream_generation.clone();
    let mut next_request = session.request().clone();
    next_request.source_identity.stream_generation = StreamGeneration::parse("gen:stream:2")?;
    session.reconnect(next_request, NOW)?;
    assert_eq!(session.state_kind(), AcquisitionStateKind::Requested);
    assert!(session.check_absence_claim_allowed().is_err());
    observe_first_frame(&mut session, 10)?;
    session.verify_continuity(continuity(session.request(), 10, 19), NOW)?;
    assert!(session.check_absence_claim_allowed()?.certifies_absence());
    assert!(
        session
            .check_absence_claim_allowed_in_window(&old_generation, 10, 19, pts(10), pts(19))
            .is_err()
    );
    assert!(
        session
            .check_absence_claim_allowed_in_window(
                &session.request().source_identity.stream_generation,
                10,
                19,
                pts(10),
                pts(19)
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn windowed_evidence_round_trips_with_unchanged_v1_payload_and_strict_bounds() -> TestResult {
    let session = clean_session()?;
    let evidence = gap(&session, 20, 29)?;
    let bytes = evidence.canonical_bytes();
    assert!(bytes.ends_with(&evidence.degradation.canonical_bytes()));
    let decoded = WindowedDegradationEvidence::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, evidence);
    assert_eq!(decoded.evidence_digest(), evidence.evidence_digest());
    decoded.verify(session.request())?;

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(WindowedDegradationEvidence::from_canonical_bytes(&trailing).is_err());
    for mutation in 0..4 {
        let mut invalid = evidence.clone();
        match mutation {
            0 => invalid.window_end_seq = 19,
            1 => {
                invalid.window_start_seq = 0;
                invalid.window_end_seq = u64::MAX;
            }
            2 => invalid.degradation.observed_packet_loss = 11,
            _ => invalid.degradation.lost_dimensions.clear(),
        }
        assert!(
            WindowedDegradationEvidence::from_canonical_bytes(&invalid.canonical_bytes()).is_err()
        );
        assert!(invalid.verify(session.request()).is_err());
    }
    for mutation in 0..5 {
        let mut changed = evidence.clone();
        match mutation {
            0 => changed.request_digest = ContentDigest::sha256(b"changed-request"),
            1 => changed.predecessor_digest = ContentDigest::sha256(b"changed-predecessor"),
            2 => changed.window_start_seq += 1,
            3 => changed.window_end_seq += 1,
            _ => changed.degradation.observed_jitter_ns += 1,
        }
        assert_ne!(changed.evidence_digest(), evidence.evidence_digest());
    }
    Ok(())
}
