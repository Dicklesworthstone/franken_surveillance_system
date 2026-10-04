#![forbid(unsafe_code)]
//! Contract tests for the file acquisition lifecycle (fss-2h5zq.25 / fss-2h5zq.26).
//!
//! A file import drives one core `AcquisitionSession`. Each outcome has an exact transition
//! history; a completed import retains it in its completing ledger batch, reopenable and
//! replayed through the core; a file session never certifies absence; an idempotent re-import
//! appends no history.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    AcquisitionError, AcquisitionState, AcquisitionStateKind, AcquisitionTransitionRecord,
    AdapterAck, AuthReceipt, BudgetVector, CanonicalDecode, CanonicalDecoder, ContentDigest,
    ContextAuthority, CredentialMethod, DegradationEvidence, FailureWitness, OperationId,
    QuiescenceReceipt, RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::file_adapter::{STAGE_PUBLISH_ROOT, STAGE_STAGE};
use fss_reference::ingest::file_session::{
    LOST_CONTINUITY_NOT_OBSERVABLE, LOST_FIRST_FRAME_DECODE_NOT_ATTEMPTED, LOST_SEGMENT_GAP,
    LOST_SOURCE_BYTES_OMITTED, LOST_TRUNCATED_FRAME_OMITTED,
};
use fss_reference::ingest::{
    AcquisitionRetention, CaptureHint, FileAcquisitionHistory, FileIngestAdapter, FileIngestError,
    FileIngestOutcome, FileIngestReceipt, FileIngestRequest, FileSessionEnding,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, AppendPhase, DeploymentLimits, ReferenceDeployment,
    ReplayCx, ReplayIoAuthority,
};

type TestResult = Result<(), Box<dyn Error>>;
/// A retained transition record and its witness bytes.
type RetainedTransition = (AcquisitionTransitionRecord, Vec<u8>);

const PRINCIPAL_MARKER: &str = "operator:file-session-marker";
const RECEIVE: TimestampNs = TimestampNs(2_000_000_000);

use AcquisitionStateKind::{
    AdapterAccepted, Authenticated, Cancelled, Degraded, Failed, Indeterminate, Requested,
};

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find repo root".into())
}

fn fixture(rel: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = repo_root()?.join("tests/fixtures/media").join(rel);
    assert!(path.is_file(), "fixture {rel} must exist");
    Ok(path)
}

fn scratch(label: &str) -> PathBuf {
    std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("file-session-{label}-{}", std::process::id()))
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:file-session-{label}"),
        operation_id: OperationId::parse(format!("operation:file-session-{label}"))?,
        principal: PRINCIPAL_MARKER.to_string(),
        capabilities: vec![ADP_FILE_ROW_ID.to_string(), ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"file-session-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let cx_root = scratch(&format!("cx-{label}"));
    fs::create_dir_all(&cx_root)?;
    let io = ReplayIoAuthority::from_context_authority(&root_auth, cx_root)?;
    Ok(ReplayCx::new(io))
}

fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = scratch(&format!("deploy-{label}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn site(label: &str) -> String {
    format!("site:file-session:{label}")
}

fn request(path: PathBuf, label: &str) -> Result<FileIngestRequest, Box<dyn Error>> {
    Ok(FileIngestRequest::new(
        path,
        SensorId::parse(format!("sensor:{label}"))?,
        StreamId::parse(format!("stream:{label}"))?,
    )
    .with_receive_time(RECEIVE))
}

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn recorded(receipt: &FileIngestReceipt) -> Result<&FileAcquisitionHistory, Box<dyn Error>> {
    receipt
        .acquisition
        .history()
        .ok_or_else(|| "a new import must record its acquisition".into())
}

fn caplog(outcome: &str, history: &FileAcquisitionHistory) {
    let digests: Vec<String> = history
        .records()
        .iter()
        .map(|r| format!("\"{}\"", r.witness_digest))
        .collect();
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.25\",\"step\":\"{outcome}\",\"observed\":\"{}\",\"terminal\":\"{}\",\"ending\":\"{}\",\"retained\":{},\"witness_digests\":[{}]}}",
        history.kinds_text(),
        history.terminal().as_str(),
        history.ending().as_str(),
        history.retained(),
        digests.join(",")
    );
}

/// Decodes `fss.canonical.v1 | domain | value` bytes, checking the content digest.
fn decode_retained<T: CanonicalDecode>(
    bytes: &[u8],
    domain: &str,
    digest: ContentDigest,
) -> Result<T, Box<dyn Error>> {
    assert_eq!(ContentDigest::sha256(bytes), digest);
    let mut decoder = CanonicalDecoder::new(bytes);
    assert_eq!(decoder.text()?, "fss.canonical.v1");
    assert_eq!(decoder.text()?, domain);
    let value = T::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    Ok(value)
}

/// `(record, witness bytes)` of every retained acquisition delta of one import, in order.
fn retained_transitions(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
) -> Result<Vec<RetainedTransition>, Box<dyn Error>> {
    let id = hex(import_identity);
    let batch_id = format!("batch:file-import:{id}:manifest");
    let batch = deployment
        .ledger()
        .batches()
        .iter()
        .find(|b| b.batch_id.as_str() == batch_id)
        .ok_or("completing batch must exist")?;
    let mut out = Vec::new();
    for delta in batch
        .deltas
        .iter()
        .filter(|d| d.family == "acquisition_transition")
    {
        assert!(
            delta
                .object_id
                .as_str()
                .starts_with(&format!("object:acquisition-transition:{id}:"))
        );
        assert!(batch.children.contains(&delta.payload_digest));
        let witness = delta
            .witness_digest
            .ok_or("transition must carry a witness")?;
        assert!(batch.children.contains(&witness));
        let record: AcquisitionTransitionRecord = decode_retained(
            &deployment.publisher().spool().read(delta.payload_digest)?,
            "fss.acquisition.transition_record.v1",
            delta.payload_digest,
        )?;
        assert_eq!(record.witness_digest, witness);
        out.push((record, deployment.publisher().spool().read(witness)?));
    }
    Ok(out)
}

fn acquisition_delta_count(deployment: &ReferenceDeployment) -> usize {
    deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|b| &b.deltas)
        .filter(|d| d.family == "acquisition_transition")
        .count()
}

fn retained_degradation(
    deployment: &ReferenceDeployment,
    receipt: &FileIngestReceipt,
) -> Result<DegradationEvidence, Box<dyn Error>> {
    let transitions = retained_transitions(deployment, receipt.import_identity)?;
    let (record, bytes) = transitions.get(3).ok_or("degradation transition")?;
    assert_eq!(record.to, Degraded);
    decode_retained(
        bytes,
        "fss.acquisition.degradation.v1",
        record.witness_digest,
    )
}

/// The core absence gate refuses with the exact variant and the session's state.
fn assert_absence_forbidden(history: &FileAcquisitionHistory, state: AcquisitionStateKind) {
    let claim = history.absence_claim();
    assert!(
        matches!(
            claim,
            Err(AcquisitionError::AbsenceClaimForbidden { state: s, .. }) if s == state
        ),
        "absence must be forbidden in {state:?}, got {claim:?}"
    );
}

#[test]
fn complete_h264_import_retains_end_of_file_history() -> TestResult {
    let dir = fresh_dir("complete")?;
    let cx = test_cx("complete")?;
    let mut deployment = ReferenceDeployment::open(&dir, &site("complete"), &cx)?;
    let receipt = FileIngestAdapter::ingest(
        request(fixture("h264/clean.264")?, "complete")?,
        &cx,
        &mut deployment,
    )?;
    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    let history = recorded(&receipt)?;
    caplog("complete", history);

    assert_eq!(
        history.kinds(),
        vec![
            Requested,
            Authenticated,
            AdapterAccepted,
            Degraded,
            Cancelled
        ]
    );
    assert_eq!(history.terminal(), Cancelled);
    assert_eq!(history.ending(), &FileSessionEnding::EndOfFileSource);
    assert_eq!(history.ending().as_str(), "end_of_file_source");
    assert!(history.retained());
    assert!(!receipt.absence_certifiable);
    assert_absence_forbidden(history, Cancelled);
    // A file session never reaches FirstFrameObserved or ContinuityVerified.
    assert!(!history.session().has_continuity());
    assert!(!history.session().is_streaming());

    // Same ledger batch as the import completion: one delta per transition.
    let transitions = retained_transitions(&deployment, receipt.import_identity)?;
    let retained: Vec<AcquisitionTransitionRecord> =
        transitions.iter().map(|(r, _)| r.clone()).collect();
    assert_eq!(retained.as_slice(), history.records());
    assert_eq!(acquisition_delta_count(&deployment), 5);
    let manifest_batch = deployment
        .ledger()
        .batches()
        .last()
        .ok_or("ledger must hold the completing batch")?;
    assert_eq!(
        manifest_batch.batch_id.as_str(),
        format!(
            "batch:file-import:{}:manifest",
            hex(receipt.import_identity)
        )
    );

    // Every retained witness decodes and verifies against the session identities.
    let request = history.session().request().clone();
    let (src, dev, adp) = (
        &request.source_identity.source_id,
        &request.device_identity.device_id,
        &request.adapter_identity.adapter_id,
    );
    assert_eq!(
        src.as_str(),
        format!("src:fi-{}", hex(receipt.import_identity))
    );
    assert_eq!(adp.as_str(), "adapter:file-001");
    assert!(!request.source_identity.is_live);
    let auth: AuthReceipt = decode_retained(
        &transitions[1].1,
        AuthReceipt::SCHEMA,
        transitions[1].0.witness_digest,
    )?;
    assert_eq!(auth.method, CredentialMethod::None);
    assert_eq!(auth.principal_digest, receipt.import_identity);
    auth.verify(adp, dev, request.requested_capabilities, RECEIVE)?;
    let ack: AdapterAck = decode_retained(
        &transitions[2].1,
        AdapterAck::SCHEMA,
        transitions[2].0.witness_digest,
    )?;
    ack.verify(&request.request_digest(), adp)?;
    let degradation = retained_degradation(&deployment, &receipt)?;
    degradation.verify(src, dev, adp)?;
    assert_eq!(
        degradation.lost_dimensions,
        vec![
            LOST_CONTINUITY_NOT_OBSERVABLE.to_owned(),
            LOST_FIRST_FRAME_DECODE_NOT_ATTEMPTED.to_owned()
        ]
    );
    assert_eq!(
        degradation.invalidated_negative_claims,
        vec!["absence".to_owned()]
    );
    let quiescence: QuiescenceReceipt = decode_retained(
        &transitions[4].1,
        QuiescenceReceipt::SCHEMA,
        transitions[4].0.witness_digest,
    )?;
    quiescence.verify(adp, dev, src)?;
    assert_eq!(
        (
            quiescence.active_tasks,
            quiescence.open_descriptors,
            quiescence.buffers_drained
        ),
        (0, 0, true)
    );

    // Secret-free: the operator principal never reaches a retained acquisition object.
    for (_, witness) in &transitions {
        assert!(
            !witness
                .windows(PRINCIPAL_MARKER.len())
                .any(|w| w == PRINCIPAL_MARKER.as_bytes())
        );
    }
    Ok(())
}

#[test]
fn truncated_and_gapped_mjpeg_degrade_with_named_dimensions() -> TestResult {
    let dir = fresh_dir("truncated")?;
    let cx = test_cx("truncated")?;
    let mut deployment = ReferenceDeployment::open(&dir, &site("truncated"), &cx)?;

    let truncated = FileIngestAdapter::ingest(
        request(fixture("mjpeg/mjpeg_truncated_last.mjpeg")?, "truncated")?,
        &cx,
        &mut deployment,
    )?;
    let history = recorded(&truncated)?;
    caplog("truncated", history);
    assert_eq!(
        history.kinds(),
        vec![
            Requested,
            Authenticated,
            AdapterAccepted,
            Degraded,
            Cancelled
        ]
    );
    assert_eq!(history.ending(), &FileSessionEnding::EndOfFileSource);
    let lost = retained_degradation(&deployment, &truncated)?.lost_dimensions;
    assert!(
        lost.contains(&LOST_TRUNCATED_FRAME_OMITTED.to_owned()),
        "{lost:?}"
    );
    assert_absence_forbidden(history, Cancelled);

    let garbage = FileIngestAdapter::ingest(
        request(
            fixture("mjpeg/mjpeg_garbage_between_frames.mjpeg")?,
            "garbage",
        )?,
        &cx,
        &mut deployment,
    )?;
    let history = recorded(&garbage)?;
    caplog("malformed_gaps", history);
    assert_eq!(history.terminal(), Cancelled);
    let lost = retained_degradation(&deployment, &garbage)?.lost_dimensions;
    assert!(
        lost.contains(&LOST_SOURCE_BYTES_OMITTED.to_owned()),
        "{lost:?}"
    );
    assert!(lost.contains(&LOST_SEGMENT_GAP.to_owned()), "{lost:?}");
    assert!(!garbage.absence_certifiable);
    Ok(())
}

#[test]
fn cancellation_mid_import_ends_operator_cancel_and_retains_nothing() -> TestResult {
    for (label, stage) in [
        ("cancel-stage", STAGE_STAGE),
        ("cancel-publish", STAGE_PUBLISH_ROOT),
    ] {
        let dir = fresh_dir(label)?;
        let cx = test_cx(label)?;
        let mut deployment = ReferenceDeployment::open(&dir, &site(label), &cx)?;
        cx.set_cancel_at_checkpoint(stage);
        let failure = match FileIngestAdapter::ingest_with_session(
            request(fixture("h264/clean.264")?, label)?,
            &cx,
            &mut deployment,
        ) {
            Ok(_) => return Err("cancelled import must not complete".into()),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error,
            FileIngestError::CancellationRequested { stage: s } if s == stage
        ));
        let history = failure
            .acquisition
            .as_ref()
            .ok_or("an accepted import has a session")?;
        caplog(label, history);
        assert_eq!(
            history.kinds(),
            vec![
                Requested,
                Authenticated,
                AdapterAccepted,
                Degraded,
                Cancelled
            ]
        );
        assert_eq!(
            history.ending(),
            &FileSessionEnding::OperatorCancel {
                stage: stage.to_owned()
            }
        );
        assert!(!history.retained());
        assert_absence_forbidden(history, Cancelled);
        assert_eq!(acquisition_delta_count(&deployment), 0);
    }
    Ok(())
}

#[test]
fn refused_input_fails_through_the_core_with_a_failure_witness() -> TestResult {
    let dir = fresh_dir("refused")?;
    let cx = test_cx("refused")?;
    let mut deployment = ReferenceDeployment::open(&dir, &site("refused"), &cx)?;
    let batches_before = deployment.ledger().batches().len();

    // A capture-time assumption after arrival is refused before the adapter accepts.
    let hint = CaptureHint::new(TimestampNs(RECEIVE.0 + 1), 0, 30.0)?;
    let failure = match FileIngestAdapter::ingest_with_session(
        request(fixture("h264/clean.264")?, "refused")?.with_capture_hint(hint),
        &cx,
        &mut deployment,
    ) {
        Ok(_) => return Err("future capture hint must be refused".into()),
        Err(failure) => failure,
    };
    assert!(matches!(
        failure.error,
        FileIngestError::CaptureHintAfterReceive { .. }
    ));
    let history = failure.acquisition.as_ref().ok_or("session expected")?;
    caplog("refused", history);
    assert_eq!(history.kinds(), vec![Requested, Authenticated, Failed]);
    assert_eq!(
        history.ending(),
        &FileSessionEnding::Failed {
            error_code: "capture_hint_after_receive".to_owned()
        }
    );
    let AcquisitionState::Failed {
        failure: witness,
        prior_state,
        ..
    } = history.session().state()
    else {
        return Err("terminal state must be Failed".into());
    };
    assert_eq!(*prior_state, Authenticated);
    assert_eq!(witness.error_code, "capture_hint_after_receive");
    let acq = history.session().request();
    witness.verify(
        &acq.source_identity.source_id,
        &acq.device_identity.device_id,
        &acq.adapter_identity.adapter_id,
    )?;
    let record = history.records().last().ok_or("records")?;
    assert_eq!(record.witness_digest, witness.witness_digest());
    assert_absence_forbidden(history, Failed);

    // Refused at admission (empty file): no acquisition was ever requested.
    let empty = scratch("empty-input.264");
    fs::write(&empty, b"")?;
    let failure = match FileIngestAdapter::ingest_with_session(
        request(empty, "empty")?,
        &cx,
        &mut deployment,
    ) {
        Ok(_) => return Err("empty file must be refused".into()),
        Err(failure) => failure,
    };
    assert!(matches!(failure.error, FileIngestError::EmptyFile { .. }));
    assert!(failure.acquisition.is_none());

    // Refusals never write ledger history.
    assert_eq!(deployment.ledger().batches().len(), batches_before);
    assert_eq!(acquisition_delta_count(&deployment), 0);
    Ok(())
}

#[test]
fn capacity_failure_after_degradation_is_failed_and_leaves_no_history() -> TestResult {
    let path = fixture("h264/clean.264")?;
    let len = fs::metadata(&path)?.len();
    let dir = fresh_dir("capacity")?;
    let cx = test_cx("capacity")?;
    let mut limits = DeploymentLimits::standard();
    // Admits the file at stat time but not the file plus its metadata objects.
    limits.spool_total_max_bytes = len + 16;
    limits.scan_max_objects = limits.spool_max_objects;
    let mut deployment =
        ReferenceDeployment::open_with_limits(&dir, &site("capacity"), limits, &cx)?;
    let failure = match FileIngestAdapter::ingest_with_session(
        request(path, "capacity")?,
        &cx,
        &mut deployment,
    ) {
        Ok(_) => return Err("capacity must be exceeded".into()),
        Err(failure) => failure,
    };
    assert!(matches!(
        failure.error,
        FileIngestError::SpoolCapacityExceeded { .. }
    ));
    let history = failure.acquisition.as_ref().ok_or("session expected")?;
    caplog("capacity", history);
    assert_eq!(
        history.kinds(),
        vec![Requested, Authenticated, AdapterAccepted, Degraded, Failed]
    );
    let AcquisitionState::Failed { failure: w, .. } = history.session().state() else {
        return Err("terminal state must be Failed".into());
    };
    let w: &FailureWitness = w;
    assert_eq!(w.error_code, "spool_capacity_exceeded");
    assert!(w.retryable);
    assert_eq!(deployment.ledger().batches().len(), 0);
    Ok(())
}

#[test]
fn completion_failure_after_capsules_is_indeterminate() -> TestResult {
    let label = "indeterminate";
    let dir = fresh_dir(label)?;
    let path = fixture("h264/clean.264")?;

    // Attempt 1: cancelled after the capsule batch, before the root is published.
    {
        let cx = test_cx("indeterminate-1")?;
        let mut deployment = ReferenceDeployment::open(&dir, &site(label), &cx)?;
        cx.set_cancel_at_checkpoint(STAGE_PUBLISH_ROOT);
        let failure = FileIngestAdapter::ingest_with_session(
            request(path.clone(), label)?,
            &cx,
            &mut deployment,
        )
        .err()
        .ok_or("cancelled attempt must fail")?;
        let history = failure.acquisition.as_ref().ok_or("session expected")?;
        assert_eq!(history.terminal(), Cancelled);
        assert_eq!(acquisition_delta_count(&deployment), 0);
    }

    // Attempt 2: the completing append fails after the capsule batch is committed.
    {
        let cx = test_cx("indeterminate-2")?;
        let mut deployment = ReferenceDeployment::reopen(&dir, &site(label), &cx)?;
        deployment.fail_ledger_append_after_phase(AppendPhase::BodyWrite);
        let failure = FileIngestAdapter::ingest_with_session(
            request(path.clone(), label)?,
            &cx,
            &mut deployment,
        )
        .err()
        .ok_or("failed completion must fail")?;
        assert!(matches!(failure.error, FileIngestError::Reference(_)));
        let history = failure.acquisition.as_ref().ok_or("session expected")?;
        caplog("indeterminate", history);
        assert_eq!(
            history.kinds(),
            vec![
                Requested,
                Authenticated,
                AdapterAccepted,
                Degraded,
                Indeterminate
            ]
        );
        assert!(matches!(
            history.ending(),
            FileSessionEnding::Indeterminate { .. }
        ));
        let AcquisitionState::Indeterminate { witness, .. } = history.session().state() else {
            return Err("terminal state must be Indeterminate".into());
        };
        assert_eq!(witness.unresolved_obligations.len(), 1);
        assert!(witness.unresolved_obligations[0].starts_with("resume_file_import:"));
        assert_absence_forbidden(history, Indeterminate);
    }

    Ok(())
}

#[test]
fn import_resumed_after_cancellation_retains_history_once() -> TestResult {
    let label = "resume";
    let dir = fresh_dir(label)?;
    let path = fixture("h264/clean.264")?;
    {
        let cx = test_cx("resume-1")?;
        let mut deployment = ReferenceDeployment::open(&dir, &site(label), &cx)?;
        cx.set_cancel_at_checkpoint(STAGE_PUBLISH_ROOT);
        let failure = FileIngestAdapter::ingest_with_session(
            request(path.clone(), label)?,
            &cx,
            &mut deployment,
        )
        .err()
        .ok_or("cancelled attempt must fail")?;
        let history = failure.acquisition.as_ref().ok_or("session expected")?;
        assert_eq!(history.terminal(), Cancelled);
        assert_eq!(acquisition_delta_count(&deployment), 0);
    }
    let cx = test_cx("resume-2")?;
    let mut deployment = ReferenceDeployment::reopen(&dir, &site(label), &cx)?;
    let receipt = FileIngestAdapter::ingest(request(path, label)?, &cx, &mut deployment)?;
    let history = recorded(&receipt)?;
    caplog("resumed_after_cancel", history);
    assert_eq!(
        history.kinds(),
        vec![
            Requested,
            Authenticated,
            AdapterAccepted,
            Degraded,
            Cancelled
        ]
    );
    assert_eq!(history.ending(), &FileSessionEnding::EndOfFileSource);
    assert_eq!(acquisition_delta_count(&deployment), 5);
    assert_eq!(
        AcquisitionRetention::open(&deployment, receipt.import_identity)?,
        receipt.acquisition
    );
    Ok(())
}

#[test]
fn retained_history_survives_reopen_and_reimport_is_idempotent() -> TestResult {
    let label = "reopen";
    let dir = fresh_dir(label)?;
    let path = fixture("mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let first = {
        let cx = test_cx("reopen-1")?;
        let mut deployment = ReferenceDeployment::open(&dir, &site(label), &cx)?;
        FileIngestAdapter::ingest(request(path.clone(), label)?, &cx, &mut deployment)?
    };
    let history = recorded(&first)?.clone();

    let cx = test_cx("reopen-2")?;
    let mut deployment = ReferenceDeployment::reopen(&dir, &site(label), &cx)?;
    let reopened = AcquisitionRetention::open(&deployment, first.import_identity)?;
    let reopened_history = reopened.history().ok_or("history must be recorded")?;
    caplog("reopened", reopened_history);
    assert_eq!(reopened_history, &history);
    assert_eq!(reopened_history.records(), history.records());
    assert_absence_forbidden(reopened_history, Cancelled);

    let batches = deployment.ledger().batches().len();
    let second = FileIngestAdapter::ingest(request(path, label)?, &cx, &mut deployment)?;
    assert_eq!(second.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(second.acquisition, first.acquisition);
    assert!(!second.absence_certifiable);
    assert_eq!(deployment.ledger().batches().len(), batches);
    assert_eq!(acquisition_delta_count(&deployment), 5);
    Ok(())
}

#[test]
fn reopen_refuses_unknown_imports_and_replays_exactly() -> TestResult {
    let label = "replay";
    let dir = fresh_dir(label)?;
    let cx = test_cx(label)?;
    let mut deployment = ReferenceDeployment::open(&dir, &site(label), &cx)?;
    let receipt = FileIngestAdapter::ingest(
        request(fixture("h264/clean.264")?, label)?,
        &cx,
        &mut deployment,
    )?;
    // Another import's identity has no completing batch: refused, never NotRecorded.
    assert!(AcquisitionRetention::open(&deployment, ContentDigest::sha256(b"other")).is_err());
    // The recorded history replays to exactly the retained records.
    let reopened = AcquisitionRetention::open(&deployment, receipt.import_identity)?;
    assert_eq!(reopened, receipt.acquisition);
    Ok(())
}
