#![forbid(unsafe_code)]
//! Deterministic contract tests for [`FileIngestAdapter`] (`ADP-FILE-001`).
//!
//! Asserts exact-equality behavior on:
//! 1. Clean H.264 elementary stream import with 5 capsules whose custody bytes round-trip.
//! 2. Clean MJPEG stream import with 3 capsules.
//! 3. Rejection of non-regular files (directories).
//! 4. Rejection of symlinks (`SymlinkNotAllowed`) leaving the deployment unchanged.
//! 5. Rejection of oversize files (`FileTooLarge`) leaving the deployment unchanged.
//! 6. Format conflict detection between file signature and caller hint.
//! 7. Time truth: refusal of a capture hint that starts after receive time.
//! 8. Chunk boundary spanning and round-trip payload reassembly via [`fetch_segment_bytes`].
//! 9. Idempotent re-import returning the real existing batches and capsules.
//! 10. Absence over the imported interval is not certifiable from ledger-derived state.
//! 11. Time truth: unknown window without a hint, operator assumption with a positive hint.
//! 12. Empty file refusal (`EmptyFile`).
//! 13. Tracking of `gap_before` across garbage spans in MJPEG.
//! 14. Capacity refusals happen before staging and leave spool and ledger unchanged.
//! 15. Mutation killers for custody digest, clock basis, time labels, coverage, and symlinks.

use std::error::Error;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CaptureInterval, ClockBasis, ContentDigest,
    ContextAuthority, CoverageWitness, EventId, EventReadResult, EventRevisionStore,
    NotObservableReason, OperationId, RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_publication::ROOT_REACHABILITY_FAMILY;
use fss_reference::ingest::{
    CAPTURE_TIME_OPERATOR_ASSUMPTION, CAPTURE_TIME_UNKNOWN, CaptureHint, DetectedFileFormat,
    FILE_IMPORT_IDENTITY_DOMAIN, FILE_IMPORT_MANIFEST_SCHEMA, FILE_INGEST_LIMITS_DOMAIN,
    FileFormatHint, FileIngestAdapter, FileIngestError, FileIngestLimits, FileIngestOutcome,
    FileIngestRequest, MAX_BATCH_DELTAS, decode_capsule_custody_bytes, fetch_segment_bytes,
    sniff_format,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, DeploymentLimits, ReferenceDeployment, ReplayCx,
    ReplayIoAuthority, VirtualClock,
};

/// Virtual receive time used by most tests (5,000 s after the epoch).
const RECEIVE_NS: i128 = 5_000_000_000_000;

/// Delta families a file import may write; anything else (notably a coverage or continuity
/// witness) is a truth violation.
const IMPORT_FAMILIES: [&str; 4] = [
    "file_import",
    "sensor_capsule",
    "file_import_manifest",
    ROOT_REACHABILITY_FAMILY,
];

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find repo root".into())
}

fn fixture(relative: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = repo_root()?.join(relative);
    if !path.is_file() {
        return Err(format!("fixture {relative} must exist").into());
    }
    Ok(path)
}

fn scratch_dir(prefix: &str, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{prefix}-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:file-ingest-{label}"),
        operation_id: OperationId::parse(format!("operation:file-ingest-{label}"))?,
        principal: format!("operator:file-ingest-{label}"),
        capabilities: vec![
            ADP_FILE_ROW_ID.to_string(),
            ADP_REPLAY_ROW_ID.to_string(),
            "adp:file:001".to_string(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch_root = scratch_dir("test-file-ingest-cx", label)?;
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn clock_at(ns: i128) -> VirtualClock {
    VirtualClock::new(0x2305, TimestampNs(ns))
}

fn open_deployment(label: &str, cx: &ReplayCx) -> Result<ReferenceDeployment, Box<dyn Error>> {
    let dir = scratch_dir("test-deploy", label)?;
    Ok(ReferenceDeployment::open(
        &dir,
        &format!("site:deploy:{label}"),
        cx,
    )?)
}

fn open_deployment_with_limits(
    label: &str,
    limits: DeploymentLimits,
    cx: &ReplayCx,
) -> Result<ReferenceDeployment, Box<dyn Error>> {
    let dir = scratch_dir("test-deploy", label)?;
    Ok(ReferenceDeployment::open_with_limits(
        &dir,
        &format!("site:deploy:{label}"),
        limits,
        cx,
    )?)
}

fn h264_request(
    path: PathBuf,
    sensor: &str,
    stream: &str,
) -> Result<FileIngestRequest, Box<dyn Error>> {
    Ok(FileIngestRequest::new(
        path,
        SensorId::parse(sensor)?,
        StreamId::parse(stream)?,
    ))
}

/// Observable deployment state that a refused import must leave untouched.
fn state_fingerprint(
    deployment: &ReferenceDeployment,
) -> Result<(usize, u64, usize), Box<dyn Error>> {
    Ok((
        deployment.publisher().spool().object_count(),
        deployment.publisher().spool().occupied_bytes()?,
        deployment.ledger().batches().len(),
    ))
}

#[test]
fn test_01_h264_clean_file_import() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("h264-clean")?;
    let mut deployment = open_deployment("h264-clean", &cx)?;
    let request = h264_request(h264_path.clone(), "sensor:cam-001", "stream:h264-main")?
        .with_format_hint(FileFormatHint::AnnexB);

    let receipt = FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment)?;

    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_eq!(receipt.format, DetectedFileFormat::AnnexB);
    assert_eq!(receipt.capsule_count, 5);
    assert_eq!(receipt.manifest.segment_spans.len(), 5);
    assert_eq!(receipt.manifest.ordered_chunks.len(), 1);
    assert_eq!(receipt.chunk_count, 1);
    let raw = fs::read(&h264_path)?;
    assert_eq!(receipt.input_bytes, raw.len() as u64);
    assert_eq!(receipt.input_sha256, ContentDigest::sha256(&raw));
    assert!(!receipt.absence_certifiable);

    let visible_root = deployment
        .publisher()
        .root(&receipt.root_slot)
        .ok_or("root slot fi-<id> must be published")?;
    assert_eq!(visible_root.root, receipt.import_root);
    assert_eq!(visible_root.slot, receipt.root_slot);

    // The import object reached generation 2 (complete) in the ledger's materialized state.
    let batches = deployment.ledger().batches();
    let final_batch = batches.last().ok_or("ledger must have batches")?;
    assert_eq!(final_batch.batch_id, receipt.batch_ids[1]);
    let import_delta = final_batch
        .deltas
        .iter()
        .find(|d| d.family == "file_import")
        .ok_or("final batch must contain file_import delta")?;
    assert_eq!(import_delta.new_generation, 2);
    let import_object = deployment
        .ledger()
        .current()
        .objects
        .get(&import_delta.object_id)
        .ok_or("import object must be materialized")?;
    assert_eq!(import_object.generation, 2);
    assert_eq!(import_object.payload_digest, receipt.manifest_digest);

    // Every capsule is held in custody under its metadata digest and round-trips exactly.
    for (i, seg) in receipt.manifest.segment_spans.iter().enumerate() {
        let capsule = &receipt.capsules[i];
        let stored = deployment
            .publisher()
            .spool()
            .read(capsule.metadata_digest())?;
        assert_eq!(ContentDigest::sha256(&stored), capsule.metadata_digest());
        let decoded = decode_capsule_custody_bytes(&stored)?;
        assert_eq!(&decoded, capsule);
        assert_eq!(decoded.capsule_id, seg.capsule_id);
        assert_eq!(decoded.source_digest, seg.segment_sha256);
        assert_eq!(decoded.frame_count, 1);
        assert_eq!(decoded.source_bytes, seg.len);
    }

    // The stored import manifest is the manifest the receipt reports.
    let stored_manifest = deployment
        .publisher()
        .spool()
        .read(receipt.manifest_digest)?;
    assert_eq!(stored_manifest, receipt.manifest.canonical_bytes());
    Ok(())
}

#[test]
fn test_02_mjpeg_clean_file_import() -> Result<(), Box<dyn Error>> {
    let mjpeg_path = fixture("tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let cx = test_cx("mjpeg-clean")?;
    let mut deployment = open_deployment("mjpeg-clean", &cx)?;
    let request = h264_request(mjpeg_path.clone(), "sensor:cam-mjpeg", "stream:mjpeg-live")?;

    let receipt = FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment)?;

    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_eq!(receipt.format, DetectedFileFormat::JpegStream);
    assert_eq!(receipt.capsule_count, 3);
    assert_eq!(receipt.manifest.segment_spans.len(), 3);
    assert_eq!(receipt.input_bytes, fs::read(&mjpeg_path)?.len() as u64);
    Ok(())
}

#[test]
fn test_03_non_regular_file_refusal() -> Result<(), Box<dyn Error>> {
    let dir_path = repo_root()?.join("tests/fixtures/media");
    let cx = test_cx("dir-refusal")?;
    let mut deployment = open_deployment("dir-refusal", &cx)?;
    let request = h264_request(dir_path.clone(), "sensor:cam-001", "stream:h264")?;

    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::NotRegularFile { path }) => assert_eq!(path, dir_path),
        other => return Err(format!("expected NotRegularFile, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_04_symlink_refusal() -> Result<(), Box<dyn Error>> {
    let target = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("symlink-refusal")?;
    let link_path = cx.root_dir().join("clean_symlink.264");
    let _ = fs::remove_file(&link_path);
    symlink(&target, &link_path)?;
    let mut deployment = open_deployment("symlink-refusal", &cx)?;
    let before = state_fingerprint(&deployment)?;

    let request = h264_request(link_path.clone(), "sensor:cam-001", "stream:h264")?;
    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::SymlinkNotAllowed { path }) => assert_eq!(path, link_path),
        other => return Err(format!("expected SymlinkNotAllowed, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_05_oversize_file_refusal() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let file_len = fs::read(&h264_path)?.len() as u64;
    let cx = test_cx("oversize-refusal")?;
    let mut deployment = open_deployment("oversize-refusal", &cx)?;
    let before = state_fingerprint(&deployment)?;

    let mut request = h264_request(h264_path.clone(), "sensor:cam-001", "stream:h264")?;
    request.limits.max_file_bytes = file_len - 1;

    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::FileTooLarge { path, len, max }) => {
            assert_eq!(path, h264_path);
            assert_eq!(len, file_len);
            assert_eq!(max, file_len - 1);
        }
        other => return Err(format!("expected FileTooLarge, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_06_format_conflict_refusal() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("format-conflict")?;
    let mut deployment = open_deployment("format-conflict", &cx)?;
    let request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?
        .with_format_hint(FileFormatHint::JpegStream);

    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::FormatConflict { hint, detected }) => {
            assert_eq!(hint, FileFormatHint::JpegStream);
            assert_eq!(detected, DetectedFileFormat::AnnexB);
        }
        other => return Err(format!("expected FormatConflict, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_07_capture_hint_after_receive_refusal() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("hint-future")?;
    let mut deployment = open_deployment("hint-future", &cx)?;
    let receive_time = TimestampNs(1_000_000_000);
    let future_start = TimestampNs(receive_time.0 + 1_000_000_000);
    let request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?
        .with_capture_hint(CaptureHint::new(future_start, 500_000, 30.0)?);

    match FileIngestAdapter::ingest(request, &clock_at(receive_time.0), &cx, &mut deployment) {
        Err(FileIngestError::CaptureHintAfterReceive {
            hint_start,
            receive_time: rec,
        }) => {
            assert_eq!(hint_start, future_start);
            assert_eq!(rec, receive_time);
        }
        other => return Err(format!("expected CaptureHintAfterReceive, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_08_chunking_and_fetch_segment_bytes() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let raw_bytes = fs::read(&h264_path)?;
    let cx = test_cx("chunking-fetch")?;
    let mut deployment = open_deployment("chunking-fetch", &cx)?;
    let mut request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?;
    request.limits.chunk_bytes = 512;

    let receipt = FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment)?;
    assert!(
        receipt.manifest.ordered_chunks.len() > 1,
        "must have split into multiple chunks"
    );
    for (i, span) in receipt.manifest.segment_spans.iter().enumerate() {
        let fetched = fetch_segment_bytes(&receipt.manifest, &deployment, i)?;
        let start = usize::try_from(span.offset)?;
        let end = usize::try_from(span.offset + span.len)?;
        assert_eq!(fetched.as_slice(), &raw_bytes[start..end]);
        assert_eq!(ContentDigest::sha256(&fetched), span.segment_sha256);
    }
    Ok(())
}

#[test]
fn test_09_idempotent_reimport() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("idempotent")?;
    let mut deployment = open_deployment("idempotent", &cx)?;

    let first = FileIngestAdapter::ingest(
        h264_request(h264_path.clone(), "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(first.outcome, FileIngestOutcome::New);
    let batches_after_first = deployment.ledger().batches().len();

    // The clock has moved on; the identity has not.
    let second = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS + 60_000_000_000),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(second.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(second.import_identity, first.import_identity);
    assert_eq!(second.manifest_digest, first.manifest_digest);
    assert_eq!(second.import_root, first.import_root);
    assert_eq!(second.batch_ids, first.batch_ids);
    for batch_id in &second.batch_ids {
        assert!(
            deployment
                .ledger()
                .batches()
                .iter()
                .any(|b| &b.batch_id == batch_id),
            "reported batch {} must exist in the ledger",
            batch_id.as_str()
        );
    }
    // The existing capsules (with their original receive time) are reported, not re-minted.
    assert_eq!(second.capsules, first.capsules);
    assert_eq!(second.receive_time, TimestampNs(RECEIVE_NS));
    assert_eq!(
        deployment.ledger().batches().len(),
        batches_after_first,
        "idempotent re-import must not append batches"
    );
    Ok(())
}

#[test]
fn test_10_absence_query_not_certifiable() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("absence-test")?;
    let mut deployment = open_deployment("absence-test", &cx)?;
    let receipt = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;
    assert!(
        !receipt.absence_certifiable,
        "file import never certifies absence"
    );

    // No witness delta of any kind exists in the ledger after the import.
    for batch in deployment.ledger().batches() {
        for delta in &batch.deltas {
            assert!(
                IMPORT_FAMILIES.contains(&delta.family.as_str()),
                "unexpected delta family {} in {}",
                delta.family,
                batch.batch_id.as_str()
            );
            assert!(
                !delta.family.contains("coverage") && !delta.family.contains("continuity"),
                "file import emitted a {} delta",
                delta.family
            );
        }
    }

    // Derive the coverage state from the ledger: every materialized coverage witness whose
    // validity overlaps the imported interval is decoded from custody and registered.
    let imported = receipt
        .capsules
        .iter()
        .fold(None::<(TimestampNs, TimestampNs)>, |acc, c| match acc {
            None => Some((c.capture.earliest, c.capture.latest)),
            Some((e, l)) => Some((e.min(c.capture.earliest), l.max(c.capture.latest))),
        })
        .ok_or("import must produce capsules")?;
    let mut store = EventRevisionStore::new(deployment.current_anchor().clone());
    let mut witnesses = 0_usize;
    for revision in deployment.ledger().current().objects.values() {
        let overlaps =
            revision.validity.earliest <= imported.1 && revision.validity.latest >= imported.0;
        if overlaps
            && (revision.family.contains("coverage") || revision.family.contains("continuity"))
        {
            let bytes = deployment
                .publisher()
                .spool()
                .read(revision.payload_digest)?;
            let witness = CoverageWitness::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
            let basis = store.current_anchor().clone();
            store.register_coverage_witness(basis, witness, receipt.receive_time)?;
            witnesses += 1;
        }
    }
    assert_eq!(witnesses, 0, "no coverage or continuity witness may exist");

    let domain = "domain.file_import.stream:h264";
    let reasons = store.coverage_non_observability_reasons(domain);
    assert_eq!(reasons, vec![NotObservableReason::NoCoverageWitness]);
    match store.read_event_in_domain(&EventId::parse("event:absent-001")?, domain, None)? {
        EventReadResult::NotObservable {
            domain: read_domain,
            reason,
            ..
        } => {
            assert_eq!(read_domain, domain);
            assert_eq!(reason, NotObservableReason::NoCoverageWitness);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_11_time_truth_unspecified_vs_specified() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("time-truth")?;
    let mut deployment = open_deployment("time-truth", &cx)?;
    let receive_time = TimestampNs(20_000_000_000);

    // 1. Without a capture hint: the full unknown window, Estimated, labeled "unknown".
    let unspecified = FileIngestAdapter::ingest(
        h264_request(h264_path.clone(), "sensor:cam-time-1", "stream:h264-unspec")?,
        &clock_at(receive_time.0),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(unspecified.capture_time_label, CAPTURE_TIME_UNKNOWN);
    for capsule in &unspecified.capsules {
        assert_eq!(capsule.capture.earliest, TimestampNs(0));
        assert_eq!(capsule.capture.latest, receive_time);
        assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
    }

    // 2. With a positive capture hint: start + i/fps +/- u, still Estimated.
    let hint_start = TimestampNs(10_000_000_000);
    let specified = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-time-2", "stream:h264-spec")?
            .with_capture_hint(CaptureHint::new(hint_start, 250_000, 25.0)?),
        &clock_at(receive_time.0),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(
        specified.capture_time_label,
        CAPTURE_TIME_OPERATOR_ASSUMPTION
    );
    assert_eq!(
        specified.manifest.capture_time_label,
        CAPTURE_TIME_OPERATOR_ASSUMPTION
    );
    let frame_period_ns: i128 = 40_000_000;
    for (i, capsule) in specified.capsules.iter().enumerate() {
        let nominal = hint_start.0 + (i as i128) * frame_period_ns;
        assert_eq!(capsule.capture.earliest, TimestampNs(nominal - 250_000));
        assert_eq!(capsule.capture.latest, TimestampNs(nominal + 250_000));
        assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
        assert_eq!(capsule.receive_time, receive_time);
    }
    Ok(())
}

#[test]
fn test_11b_negative_capture_hint_start_refused() -> Result<(), Box<dyn Error>> {
    match CaptureHint::new(TimestampNs(-1), 0, 30.0) {
        Err(FileIngestError::NegativeCaptureHintStart { start_ns }) => {
            assert_eq!(start_ns, TimestampNs(-1));
        }
        other => return Err(format!("expected NegativeCaptureHintStart, got {other:?}").into()),
    }

    // A hint built field by field is refused by the adapter too, never clamped to zero.
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("negative-hint")?;
    let mut deployment = open_deployment("negative-hint", &cx)?;
    let before = state_fingerprint(&deployment)?;
    let hint = CaptureHint {
        start_ns: TimestampNs(-5_000_000_000),
        uncertainty_ns: 1_000,
        assumed_fps: 30.0,
    };
    let request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?.with_capture_hint(hint);
    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::NegativeCaptureHintStart { start_ns }) => {
            assert_eq!(start_ns, TimestampNs(-5_000_000_000));
        }
        other => return Err(format!("expected NegativeCaptureHintStart, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_12_empty_file_refusal() -> Result<(), Box<dyn Error>> {
    let cx = test_cx("empty-file")?;
    let empty_file_path = cx.root_dir().join("empty.bin");
    fs::write(&empty_file_path, b"")?;
    let mut deployment = open_deployment("empty-file", &cx)?;
    let request = h264_request(empty_file_path.clone(), "sensor:cam-001", "stream:h264")?;

    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::EmptyFile { path }) => assert_eq!(path, empty_file_path),
        other => return Err(format!("expected EmptyFile, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_13_mjpeg_garbage_tracks_gap_before() -> Result<(), Box<dyn Error>> {
    let mjpeg_path = fixture("tests/fixtures/media/mjpeg/mjpeg_garbage_between_frames.mjpeg")?;
    let cx = test_cx("mjpeg-garbage")?;
    let mut deployment = open_deployment("mjpeg-garbage", &cx)?;
    let receipt = FileIngestAdapter::ingest(
        h264_request(mjpeg_path, "sensor:cam-mjpeg-gap", "stream:mjpeg-gap")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;
    // The generated fixture is f0 + garbage + f1 + garbage + f2 (fixture_manifest.json:
    // frame_count 3), so every frame after a garbage span carries gap_before.
    let gaps: Vec<bool> = receipt
        .manifest
        .segment_spans
        .iter()
        .map(|s| s.gap_before)
        .collect();
    assert_eq!(gaps, vec![false, true, true]);
    assert_eq!(
        receipt
            .capsules
            .iter()
            .map(|c| c.gap_before)
            .collect::<Vec<_>>(),
        gaps
    );
    // Each garbage span lies in an omission span between the frames around it.
    for pair in receipt.manifest.segment_spans.windows(2) {
        let gap_start = pair[0].offset + pair[0].len;
        let gap_end = pair[1].offset;
        assert!(gap_end > gap_start, "fixture has bytes between frames");
        assert!(
            receipt
                .manifest
                .omission_spans
                .iter()
                .any(|o| o.offset < gap_end && o.offset + o.len > gap_start),
            "garbage between {gap_start} and {gap_end} must be recorded as an omission"
        );
    }
    Ok(())
}

#[test]
fn test_14_capacity_rejection_leaves_state_clean() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("capacity-clean")?;
    let mut limits = DeploymentLimits::standard();
    limits.spool_total_max_bytes = 100;
    let mut deployment = open_deployment_with_limits("capacity-clean", limits, &cx)?;
    let before = state_fingerprint(&deployment)?;

    match FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-cap", "stream:h264-cap")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    ) {
        Err(FileIngestError::SpoolCapacityExceeded { .. }) => {}
        other => return Err(format!("expected SpoolCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_15_capsule_batch_limit_counts_file_import_delta() -> Result<(), Box<dyn Error>> {
    // clean.264 yields 5 capsules; the capsule batch carries 5 + 1 deltas.
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("batch-cap")?;
    let mut limits = DeploymentLimits::standard();
    limits.batch_entries_max = 5;
    let mut deployment = open_deployment_with_limits("batch-cap", limits, &cx)?;
    let before = state_fingerprint(&deployment)?;

    match FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    ) {
        Err(FileIngestError::ImportCapacityExceeded {
            limit,
            required,
            maximum,
        }) => {
            assert_eq!(limit, "capsule_batch_deltas");
            assert_eq!(required, 6);
            assert_eq!(maximum, 5);
        }
        other => return Err(format!("expected ImportCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_15b_manifest_child_cap_checked_before_staging() -> Result<(), Box<dyn Error>> {
    // 1 chunk + 5 capsules + custody manifest + import manifest = 8 slot children.
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("children-cap")?;
    let mut limits = DeploymentLimits::standard();
    limits.manifest_children_max = 7;
    let mut deployment = open_deployment_with_limits("children-cap", limits, &cx)?;
    let before = state_fingerprint(&deployment)?;

    match FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    ) {
        Err(FileIngestError::ImportCapacityExceeded {
            limit,
            required,
            maximum,
        }) => {
            assert_eq!(limit, "import_manifest_children");
            assert_eq!(required, 8);
            assert_eq!(maximum, 7);
        }
        other => return Err(format!("expected ImportCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_16_max_segments_default_and_refusal() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        FileIngestLimits::standard().max_segments,
        MAX_BATCH_DELTAS - 1
    );

    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("max-segments")?;
    let mut deployment = open_deployment("max-segments", &cx)?;
    let before = state_fingerprint(&deployment)?;
    let mut request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?;
    request.limits.max_segments = 4;
    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::ImportCapacityExceeded {
            limit,
            required,
            maximum,
        }) => {
            assert_eq!(limit, "max_segments");
            assert_eq!(required, 5);
            assert_eq!(maximum, 4);
        }
        other => return Err(format!("expected ImportCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_17_chunk_size_refused_typed() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("chunk-size")?;
    let mut deployment = open_deployment("chunk-size", &cx)?;
    let before = state_fingerprint(&deployment)?;
    let object_max = DeploymentLimits::standard().spool_object_max_bytes;

    for chunk_bytes in [0, object_max + 1] {
        let mut request = h264_request(h264_path.clone(), "sensor:cam-001", "stream:h264")?;
        request.limits.chunk_bytes = chunk_bytes;
        match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
            Err(FileIngestError::InvalidChunkSize {
                chunk_bytes: got,
                maximum,
            }) => {
                assert_eq!(got, chunk_bytes);
                assert_eq!(maximum, object_max);
            }
            other => return Err(format!("expected InvalidChunkSize, got {other:?}").into()),
        }
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_18_fetch_segment_bytes_refuses_bad_spans_typed() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("fetch-bounds")?;
    let mut deployment = open_deployment("fetch-bounds", &cx)?;
    let receipt = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;

    let mut zero_chunk = receipt.manifest.clone();
    zero_chunk.chunk_bytes = 0;
    match fetch_segment_bytes(&zero_chunk, &deployment, 0) {
        Err(FileIngestError::InvalidChunkSize { chunk_bytes, .. }) => assert_eq!(chunk_bytes, 0),
        other => return Err(format!("expected InvalidChunkSize, got {other:?}").into()),
    }

    let mut zero_len = receipt.manifest.clone();
    zero_len.segment_spans[0].len = 0;
    match fetch_segment_bytes(&zero_len, &deployment, 0) {
        Err(FileIngestError::CorruptSegment { .. }) => {}
        other => return Err(format!("expected CorruptSegment, got {other:?}").into()),
    }

    let mut overflow = receipt.manifest.clone();
    overflow.segment_spans[0].offset = u64::MAX;
    match fetch_segment_bytes(&overflow, &deployment, 0) {
        Err(FileIngestError::CorruptSegment { .. }) => {}
        other => return Err(format!("expected CorruptSegment, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_19_custody_digest_covers_every_byte_read() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let raw = fs::read(&h264_path)?;
    let cx = test_cx("custody-digest")?;
    let mut deployment = open_deployment("custody-digest", &cx)?;
    let mut request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?;
    request.limits.chunk_bytes = 512;
    let receipt = FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment)?;

    // The digest is over the whole buffer, never a prefix of it.
    assert_eq!(receipt.input_bytes, raw.len() as u64);
    assert_eq!(receipt.input_sha256, ContentDigest::sha256(&raw));
    assert_ne!(
        receipt.input_sha256,
        ContentDigest::sha256(&raw[..raw.len() - 1])
    );
    assert_eq!(receipt.manifest.input_sha256, receipt.input_sha256);
    assert_eq!(receipt.manifest.input_bytes, receipt.input_bytes);

    // The ordered custody chunks reassemble exactly the bytes the digest covers.
    let mut reassembled = Vec::new();
    for digest in &receipt.manifest.ordered_chunks {
        reassembled.extend_from_slice(&deployment.publisher().spool().read(*digest)?);
    }
    assert_eq!(reassembled, raw);
    assert_eq!(ContentDigest::sha256(&reassembled), receipt.input_sha256);
    Ok(())
}

#[test]
fn test_20_no_hint_time_truth_is_unknown_and_estimated() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("no-hint-truth")?;
    let mut deployment = open_deployment("no-hint-truth", &cx)?;
    let clock = clock_at(RECEIVE_NS);
    let receipt = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock,
        &cx,
        &mut deployment,
    )?;

    assert_eq!(receipt.capture_time_label, "unknown");
    assert_eq!(receipt.manifest.capture_time_label, "unknown");
    assert_eq!(receipt.receive_time, clock.now());
    let unknown_window = CaptureInterval::new(TimestampNs(0), clock.now())?;
    for capsule in &receipt.capsules {
        assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
        assert_eq!(capsule.capture, unknown_window);
        assert!(capsule.capture.earliest < capsule.capture.latest);
        assert_eq!(capsule.receive_time, clock.now());
        let stored = deployment
            .publisher()
            .spool()
            .read(capsule.metadata_digest())?;
        assert_eq!(
            decode_capsule_custody_bytes(&stored)?.clock_basis,
            ClockBasis::Estimated
        );
    }
    for delta in deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|b| b.deltas.iter())
        .filter(|d| d.family == "sensor_capsule")
    {
        assert_eq!(delta.validity, unknown_window);
    }
    Ok(())
}

#[test]
fn test_21_import_plan_conflict_is_typed() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("plan-conflict")?;
    let mut deployment = open_deployment("plan-conflict", &cx)?;
    let first = FileIngestAdapter::ingest(
        h264_request(h264_path.clone(), "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;
    let before = state_fingerprint(&deployment)?;

    // Same identity (same bytes, limits, sensor, stream), different time assumption.
    let request = h264_request(h264_path, "sensor:cam-001", "stream:h264")?
        .with_capture_hint(CaptureHint::new(TimestampNs(1_000_000_000), 1_000, 30.0)?);
    match FileIngestAdapter::ingest(request, &clock_at(RECEIVE_NS), &cx, &mut deployment) {
        Err(FileIngestError::ImportPlanConflict { batch_id, .. }) => {
            assert_eq!(batch_id, first.batch_ids[0]);
        }
        other => return Err(format!("expected ImportPlanConflict, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

#[test]
fn test_22_receive_time_comes_from_the_virtual_clock() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("receive-clock")?;
    let mut deployment = open_deployment("receive-clock", &cx)?;
    for (sensor, ns) in [
        ("sensor:cam-a", 7_000_000_000_i128),
        ("sensor:cam-b", 9_123_456_789),
    ] {
        let receipt = FileIngestAdapter::ingest(
            h264_request(h264_path.clone(), sensor, "stream:h264")?,
            &clock_at(ns),
            &cx,
            &mut deployment,
        )?;
        assert_eq!(receipt.receive_time, TimestampNs(ns));
        for capsule in &receipt.capsules {
            assert_eq!(capsule.receive_time, TimestampNs(ns));
            assert_eq!(capsule.capture.latest, TimestampNs(ns));
        }
    }

    let before = state_fingerprint(&deployment)?;
    match FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-c", "stream:h264")?,
        &clock_at(-1),
        &cx,
        &mut deployment,
    ) {
        Err(FileIngestError::ReceiveTimeBeforeEpoch { receive_time }) => {
            assert_eq!(receive_time, TimestampNs(-1));
        }
        other => return Err(format!("expected ReceiveTimeBeforeEpoch, got {other:?}").into()),
    }
    assert_eq!(state_fingerprint(&deployment)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// Executed Mutation Killers
// ---------------------------------------------------------------------------

#[test]
fn test_m01_kill_sniffer_annexb_detection() -> Result<(), Box<dyn Error>> {
    let (detected, _) = sniff_format(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00])?;
    assert_eq!(detected, DetectedFileFormat::AnnexB);
    Ok(())
}

#[test]
fn test_m02_kill_sniffer_jpeg_detection() -> Result<(), Box<dyn Error>> {
    let (detected, _) = sniff_format(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])?;
    assert_eq!(detected, DetectedFileFormat::JpegStream);
    Ok(())
}

#[test]
fn test_m03_kill_sniffer_rtpplay_detection() -> Result<(), Box<dyn Error>> {
    let (detected, _) = sniff_format(b"#!rtpplay1.0 127.0.0.1/5004\n")?;
    assert_eq!(detected, DetectedFileFormat::RtpPlay);
    Ok(())
}

#[test]
fn test_m04_kill_digest_domain_pins() -> Result<(), Box<dyn Error>> {
    assert_eq!(FILE_IMPORT_MANIFEST_SCHEMA, "fss.file_import.manifest.v1");
    assert_eq!(FILE_INGEST_LIMITS_DOMAIN, "fss.file_ingest.limits.v1");
    assert_eq!(FILE_IMPORT_IDENTITY_DOMAIN, "fss.file_import.identity.v1");
    let registry = fs::read_to_string(repo_root()?.join("registries/DIGEST_DOMAINS.md"))?;
    for domain in [
        FILE_IMPORT_MANIFEST_SCHEMA,
        FILE_INGEST_LIMITS_DOMAIN,
        FILE_IMPORT_IDENTITY_DOMAIN,
    ] {
        assert!(
            registry.contains(&format!("`{domain}`")),
            "{domain} must be registered in DIGEST_DOMAINS.md"
        );
    }
    Ok(())
}

#[test]
fn test_m05_kill_fetch_segment_bounds_check() -> Result<(), Box<dyn Error>> {
    let h264_path = fixture("tests/fixtures/media/h264/clean.264")?;
    let cx = test_cx("m05-bounds")?;
    let mut deployment = open_deployment("m05-bounds", &cx)?;
    let receipt = FileIngestAdapter::ingest(
        h264_request(h264_path, "sensor:cam-001", "stream:h264")?,
        &clock_at(RECEIVE_NS),
        &cx,
        &mut deployment,
    )?;
    match fetch_segment_bytes(&receipt.manifest, &deployment, 9999) {
        Err(FileIngestError::SegmentIndexOutOfBounds { index, count }) => {
            assert_eq!(index, 9999);
            assert_eq!(count, receipt.manifest.segment_spans.len());
        }
        other => return Err(format!("expected SegmentIndexOutOfBounds, got {other:?}").into()),
    }
    Ok(())
}
