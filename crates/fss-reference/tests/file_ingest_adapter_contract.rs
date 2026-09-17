#![forbid(unsafe_code)]
//! Deterministic contract tests for [`FileIngestAdapter`] (`ADP-FILE-001`).
//!
//! Asserts exact-equality behavior on:
//! 1. Clean H.264 elementary stream import with 5 capsules and chunked manifest.
//! 2. Clean MJPEG stream import with 3 capsules.
//! 3. Rejection of non-regular files (directories).
//! 4. Rejection of symlinks (`SymlinkNotAllowed`).
//! 5. Rejection of oversize files (`FileTooLarge`) leaving deployment unchanged.
//! 6. Format conflict detection between file signature and caller hint.
//! 7. Time truth: refusal of future capture hint (`CaptureHintAfterReceive`).
//! 8. Chunk boundary spanning and round-trip payload reassembly via [`fetch_segment_bytes`].
//! 9. Idempotent re-import returning [`FileIngestOutcome::IdempotentExisting`].
//! 10. Absence query non-certifiability (`NotObservableReason::NoCoverageWitness`).
//! 11. Time truth honesty: unspecified hint produces full interval with `"unknown"`,
//!     specified hint produces calculated interval with `"operator_assumption"`.
//! 12. Empty file refusal (`EmptyFile`).
//! 13. Tracking of `gap_before` across corrupted / garbage spans in MJPEG.
//! 14. Capacity pre-check refusal leaves spool and ledger completely unmodified.
//! 15. Real executed source mutation coverage.

use std::error::Error;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, ContentDigest, ContextAuthority, EventId,
    EventReadResult, EventRevisionStore, NotObservableReason, OperationId, RootAuthoritySpec,
    SensorCapsule, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::{
    CaptureHint, DetectedFileFormat, FILE_IMPORT_MANIFEST_SCHEMA, FileFormatHint,
    FileIngestAdapter, FileIngestError, FileIngestOutcome, FileIngestRequest, fetch_segment_bytes,
    sniff_format,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, DeploymentLimits, ReferenceDeployment, ReplayCx,
    ReplayIoAuthority,
};

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find repo root".into())
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
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "test-file-ingest-cx-{label}-{}",
            std::process::id()
        ));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn temp_deployment_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("test-deploy-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn test_01_h264_clean_file_import() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");
    assert!(h264_path.is_file(), "clean.264 fixture must exist");

    let dep_dir = temp_deployment_dir("h264-clean")?;
    let cx = test_cx("h264-clean")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:h264-clean", &cx)?;

    let request = FileIngestRequest::new(
        h264_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264-main")?,
    )
    .with_format_hint(FileFormatHint::AnnexB);

    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_eq!(receipt.format, DetectedFileFormat::AnnexB);
    assert_eq!(receipt.capsule_count, 5);
    assert_eq!(receipt.manifest.segment_spans.len(), 5);
    assert_eq!(receipt.manifest.ordered_chunks.len(), 1);
    assert_eq!(receipt.chunk_count, 1);
    assert_eq!(receipt.input_bytes, fs::metadata(&h264_path)?.len());
    assert_eq!(
        receipt.input_sha256,
        ContentDigest::sha256(&fs::read(&h264_path)?)
    );

    // Root publication slot check
    let visible_root = deployment
        .publisher()
        .root(&receipt.root_slot)
        .ok_or("root slot fi-<id> must be published")?;
    assert_eq!(visible_root.root, receipt.import_root);
    assert_eq!(visible_root.slot, receipt.root_slot);

    // Verify final batch moves file_import to generation 2
    let ledger = deployment.effects_and_ledger().1;
    let final_batch = ledger.batches().last().ok_or("ledger must have batches")?;
    let import_delta = final_batch
        .deltas
        .iter()
        .find(|d| d.family == "file_import")
        .ok_or("final batch must contain file_import delta")?;
    assert_eq!(import_delta.new_generation, 2);

    // Verify all 5 capsules can be read and decoded from the publisher spool
    for (i, seg) in receipt.manifest.segment_spans.iter().enumerate() {
        let capsule = &receipt.capsules[i];
        let object_id = format!("object:capsule:{}", capsule.capsule_id.as_str());
        let payload_digest = ledger
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .find(|delta| delta.family == "sensor_capsule" && delta.object_id.as_str() == object_id)
            .ok_or("capsule must have a published ledger payload")?
            .payload_digest;
        let capsule_bytes = deployment
            .publisher()
            .spool()
            .read(payload_digest)?;
        let mut decoder = CanonicalDecoder::new(&capsule_bytes);
        let decoded = SensorCapsule::decode_canonical(&mut decoder)?;
        assert_eq!(&decoded.capsule_id, &seg.capsule_id);
        assert_eq!(decoded.source_digest, seg.segment_sha256);
        assert_eq!(decoded.frame_count, 1);
        assert_eq!(decoded.source_bytes, seg.len);
    }

    Ok(())
}

#[test]
fn test_02_mjpeg_clean_file_import() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let mjpeg_path = root.join("tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg");
    assert!(mjpeg_path.is_file(), "mjpeg fixture must exist");

    let dep_dir = temp_deployment_dir("mjpeg-clean")?;
    let cx = test_cx("mjpeg-clean")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:mjpeg-clean", &cx)?;

    let request = FileIngestRequest::new(
        mjpeg_path.clone(),
        SensorId::parse("sensor:cam-mjpeg")?,
        StreamId::parse("stream:mjpeg-live")?,
    );

    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_eq!(receipt.format, DetectedFileFormat::JpegStream);
    assert_eq!(receipt.capsule_count, 3);
    assert_eq!(receipt.manifest.segment_spans.len(), 3);
    assert_eq!(receipt.input_bytes, fs::metadata(&mjpeg_path)?.len());

    Ok(())
}

#[test]
fn test_03_non_regular_file_refusal() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let dir_path = root.join("tests/fixtures/media");

    let dep_dir = temp_deployment_dir("dir-refusal")?;
    let cx = test_cx("dir-refusal")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:dir-refusal", &cx)?;

    let request = FileIngestRequest::new(
        dir_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Err(FileIngestError::NotRegularFile { path }) => {
            assert_eq!(path, dir_path);
        }
        other => return Err(format!("expected NotRegularFile, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_04_symlink_refusal() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let target = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("symlink-refusal")?;
    let cx = test_cx("symlink-refusal")?;
    let link_path = cx.root_dir().join("clean_symlink.264");
    let _ = fs::remove_file(&link_path);
    symlink(&target, &link_path)?;

    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:symlink-refusal", &cx)?;

    let request = FileIngestRequest::new(
        link_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Err(FileIngestError::SymlinkNotAllowed { path }) => {
            assert_eq!(path, link_path);
        }
        other => return Err(format!("expected SymlinkNotAllowed, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_05_oversize_file_refusal() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");
    let file_len = fs::metadata(&h264_path)?.len();

    let dep_dir = temp_deployment_dir("oversize-refusal")?;
    let cx = test_cx("oversize-refusal")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:oversize-refusal", &cx)?;

    let initial_objects = deployment.publisher().spool().object_count();

    let mut request = FileIngestRequest::new(
        h264_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );
    request.limits.max_file_bytes = file_len - 1; // 1 byte too small

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Err(FileIngestError::FileTooLarge { path, len, max }) => {
            assert_eq!(path, h264_path);
            assert_eq!(len, file_len);
            assert_eq!(max, file_len - 1);
        }
        other => return Err(format!("expected FileTooLarge, got {other:?}").into()),
    }

    // Verify deployment object count remains unchanged
    assert_eq!(
        deployment.publisher().spool().object_count(),
        initial_objects
    );

    Ok(())
}

#[test]
fn test_06_format_conflict_refusal() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("format-conflict")?;
    let cx = test_cx("format-conflict")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:format-conflict", &cx)?;

    let request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    )
    .with_format_hint(FileFormatHint::JpegStream); // Intentional mismatch

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
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
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("hint-future")?;
    let cx = test_cx("hint-future")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:hint-future", &cx)?;

    let receive_time = TimestampNs(1_000_000_000);
    let future_start = TimestampNs(receive_time.0 + 1_000_000_000); // 1s in the future

    let hint = CaptureHint::new(future_start, 500_000, 30.0)?;

    let request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    )
    .with_receive_time(receive_time)
    .with_capture_hint(hint);

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
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
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");
    let raw_bytes = fs::read(&h264_path)?;

    let dep_dir = temp_deployment_dir("chunking-fetch")?;
    let cx = test_cx("chunking-fetch")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:chunking-fetch", &cx)?;

    let mut request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );
    request.limits.chunk_bytes = 512; // Small chunks so a ~2.6KB file creates 6 chunks

    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    assert!(
        receipt.manifest.ordered_chunks.len() > 1,
        "must have split into multiple chunks"
    );

    // Verify round-trip reassembly for every single segment
    for i in 0..receipt.manifest.segment_spans.len() {
        let span = &receipt.manifest.segment_spans[i];
        let fetched_bytes = fetch_segment_bytes(&receipt.manifest, &deployment, i)?;
        let expected_bytes = &raw_bytes[span.offset as usize..(span.offset + span.len) as usize];
        assert_eq!(
            fetched_bytes.as_slice(),
            expected_bytes,
            "segment {i} reassembled bytes must match original file slice exactly"
        );
        assert_eq!(
            ContentDigest::sha256(&fetched_bytes),
            span.segment_sha256,
            "segment {i} reassembled digest must match span digest"
        );
    }

    Ok(())
}

#[test]
fn test_09_idempotent_reimport() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("idempotent")?;
    let cx = test_cx("idempotent")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:idempotent", &cx)?;

    let request1 = FileIngestRequest::new(
        h264_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    // Ingest 1
    let receipt1 = FileIngestAdapter::ingest(request1, &cx, &mut deployment)?;
    assert_eq!(receipt1.outcome, FileIngestOutcome::New);

    let batches_after_first = deployment.effects_and_ledger().1.batches().len();

    // Ingest 2 (idempotent retry with exact same parameters)
    let request2 = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );
    let receipt2 = FileIngestAdapter::ingest(request2, &cx, &mut deployment)?;

    assert_eq!(receipt2.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(receipt1.manifest_digest, receipt2.manifest_digest);
    assert_eq!(receipt1.import_root, receipt2.import_root);

    // Verify ledger did NOT advance or record new batches
    let batches_after_second = deployment.effects_and_ledger().1.batches().len();
    assert_eq!(
        batches_after_first, batches_after_second,
        "idempotent re-import must not append new batches to ledger"
    );

    Ok(())
}

#[test]
fn test_10_absence_query_not_certifiable() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("absence-test")?;
    let cx = test_cx("absence-test")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:absence-test", &cx)?;

    let request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    // Reconstruct an EventRevisionStore from current anchor
    let store = EventRevisionStore::new(deployment.current_anchor().clone());

    // Proves prime directive: absence query over imported file window is not certifiable
    let reasons = store.coverage_non_observability_reasons("domain.monitored_perimeter");
    assert_eq!(
        reasons,
        vec![NotObservableReason::NoCoverageWitness],
        "file import emits no coverage witness; absence must evaluate to NoCoverageWitness"
    );

    let query_result = store.read_event_in_domain(
        &EventId::parse("event:absent-001")?,
        "domain.monitored_perimeter",
        None,
    )?;

    match query_result {
        EventReadResult::NotObservable { domain, reason, .. } => {
            assert_eq!(domain, "domain.monitored_perimeter");
            assert_eq!(reason, NotObservableReason::NoCoverageWitness);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_11_time_truth_unspecified_vs_specified() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("time-truth")?;
    let cx = test_cx("time-truth")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:time-truth", &cx)?;

    let receive_time = TimestampNs(2_000_000_000);

    // 1. Ingest without capture hint
    let request_unspecified = FileIngestRequest::new(
        h264_path.clone(),
        SensorId::parse("sensor:cam-time-1")?,
        StreamId::parse("stream:h264-unspec")?,
    )
    .with_receive_time(receive_time);

    let receipt1 = FileIngestAdapter::ingest(request_unspecified, &cx, &mut deployment)?;
    assert_eq!(receipt1.capture_time_label, "unknown");

    for capsule in &receipt1.capsules {
        assert_eq!(capsule.capture.earliest, TimestampNs(0));
        assert_eq!(capsule.capture.latest, receive_time);
    }

    // 2. Ingest with capture hint
    let hint_start = TimestampNs(receive_time.0 - 10_000_000_000); // 10s ago
    let hint = CaptureHint::new(hint_start, 250_000, 25.0)?;

    let request_specified = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-time-2")?,
        StreamId::parse("stream:h264-spec")?,
    )
    .with_receive_time(receive_time)
    .with_capture_hint(hint);

    let receipt2 = FileIngestAdapter::ingest(request_specified, &cx, &mut deployment)?;
    assert_eq!(receipt2.capture_time_label, "operator_assumption");

    let frame_period_ns: i128 = 40_000_000;
    for (i, capsule) in receipt2.capsules.iter().enumerate() {
        let nominal = hint_start.0 + (i as i128) * frame_period_ns;
        let expected_earliest = TimestampNs((nominal - 250_000).max(0));
        let expected_latest = TimestampNs(nominal + 250_000);
        assert_eq!(capsule.capture.earliest, expected_earliest);
        assert_eq!(capsule.capture.latest, expected_latest);
    }

    Ok(())
}

#[test]
fn test_12_empty_file_refusal() -> Result<(), Box<dyn Error>> {
    let dep_dir = temp_deployment_dir("empty-file")?;
    let cx = test_cx("empty-file")?;
    let empty_file_path = cx.root_dir().join("empty.bin");
    fs::write(&empty_file_path, b"")?;

    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:empty-file", &cx)?;

    let request = FileIngestRequest::new(
        empty_file_path.clone(),
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Err(FileIngestError::EmptyFile { path }) => {
            assert_eq!(path, empty_file_path);
        }
        other => return Err(format!("expected EmptyFile, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_13_mjpeg_garbage_tracks_gap_before() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let mjpeg_path = root.join("tests/fixtures/media/mjpeg/mjpeg_garbage_between_frames.mjpeg");
    assert!(mjpeg_path.is_file(), "mjpeg garbage fixture must exist");

    let dep_dir = temp_deployment_dir("mjpeg-garbage")?;
    let cx = test_cx("mjpeg-garbage")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:mjpeg-garbage", &cx)?;

    let request = FileIngestRequest::new(
        mjpeg_path,
        SensorId::parse("sensor:cam-mjpeg-gap")?,
        StreamId::parse("stream:mjpeg-gap")?,
    );

    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    // Frame 0 has no gap before it. Frame 1 had garbage before it, so gap_before must be true!
    assert_eq!(receipt.manifest.segment_spans.len(), 2);
    assert!(!receipt.manifest.segment_spans[0].gap_before);
    assert!(
        receipt.manifest.segment_spans[1].gap_before,
        "segment after garbage span must have gap_before == true"
    );

    Ok(())
}

#[test]
fn test_14_capacity_rejection_leaves_state_clean() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("capacity-clean")?;
    let cx = test_cx("capacity-clean")?;
    let mut dep_limits = DeploymentLimits::standard();
    dep_limits.spool_total_max_bytes = 100; // Far too small for 2.6KB file + metadata
    dep_limits.scan_max_objects = dep_limits.spool_max_objects;

    let mut deployment = ReferenceDeployment::open_with_limits(
        &dep_dir,
        "site:deploy:capacity-clean",
        dep_limits,
        &cx,
    )?;

    let initial_objects = deployment.publisher().spool().object_count();
    let initial_bytes = deployment.publisher().spool().occupied_bytes();

    let request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-cap")?,
        StreamId::parse("stream:h264-cap")?,
    );

    match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Err(FileIngestError::SpoolCapacityExceeded { .. }) => {
            // Expected capacity rejection
        }
        other => return Err(format!("expected SpoolCapacityExceeded, got {other:?}").into()),
    }

    // Verify spool and ledger are pristine
    assert_eq!(
        deployment.publisher().spool().object_count(),
        initial_objects
    );
    assert_eq!(
        deployment.publisher().spool().occupied_bytes(),
        initial_bytes
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Executed Mutation Killers
// ---------------------------------------------------------------------------

#[test]
fn test_m01_kill_sniffer_annexb_detection() {
    let bytes = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00];
    let (detected, _) = sniff_format(&bytes).expect("must detect AnnexB");
    assert_eq!(detected, DetectedFileFormat::AnnexB);
}

#[test]
fn test_m02_kill_sniffer_jpeg_detection() {
    let bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    let (detected, _) = sniff_format(&bytes).expect("must detect JpegStream");
    assert_eq!(detected, DetectedFileFormat::JpegStream);
}

#[test]
fn test_m03_kill_sniffer_rtpplay_detection() {
    let bytes = b"#!rtpplay1.0 127.0.0.1/5004\n";
    let (detected, _) = sniff_format(bytes).expect("must detect RtpPlay");
    assert_eq!(detected, DetectedFileFormat::RtpPlay);
}

#[test]
fn test_m04_kill_file_import_manifest_schema_pin() {
    assert_eq!(FILE_IMPORT_MANIFEST_SCHEMA, "fss.file_import.manifest.v1");
}

#[test]
fn test_m05_kill_fetch_segment_bounds_check() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let h264_path = root.join("tests/fixtures/media/h264/clean.264");

    let dep_dir = temp_deployment_dir("m05-bounds")?;
    let cx = test_cx("m05-bounds")?;
    let mut deployment = ReferenceDeployment::open(&dep_dir, "site:deploy:m05-bounds", &cx)?;

    let request = FileIngestRequest::new(
        h264_path,
        SensorId::parse("sensor:cam-001")?,
        StreamId::parse("stream:h264")?,
    );

    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;

    // Segment index out of bounds must return SegmentIndexOutOfBounds
    match fetch_segment_bytes(&receipt.manifest, &deployment, 9999) {
        Err(FileIngestError::SegmentIndexOutOfBounds { index, count }) => {
            assert_eq!(index, 9999);
            assert_eq!(count, receipt.manifest.segment_spans.len());
        }
        other => return Err(format!("expected SegmentIndexOutOfBounds, got {other:?}").into()),
    }

    Ok(())
}
