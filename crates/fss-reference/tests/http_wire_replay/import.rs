#![forbid(unsafe_code)]
//! Real native archive -> retained recording, with source closure, privacy and retry cuts.

use super::{Directory, JPEG, Test, acquire, archive_limits, framing, response, scope, work};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::Path;
use std::time::Instant;

use fss_codec_mjpeg::{ComponentInterpretation, DecodeLimits};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DigestAlgorithm, EventKind, EventState,
    OperationId, SensorId, StreamId, TimestampNs,
};
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_camera::{
    HttpCamera, HttpCameraLimits, HttpCameraRoute, HttpCameraSecurity, HttpCameraStep,
};
use fss_reference::ingest::http_import::{
    ADAPTER, HttpImportAuthority, HttpImportEnding, HttpImportReceipt, HttpImportRequest,
    import_http,
};
use fss_reference::ingest::long_watch::{LongWatchLimits, LongWatchReport};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-import-test".into(),
        operation_id: OperationId::parse("operation:http-import-test")?,
        principal: "principal:http-import-test".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
            "CAP-DELETE-PREPARE-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"site:http-import"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
struct Owner(Cell<bool>);
impl HttpImportAuthority for Owner {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        self.0.get()
            && request.source == scope()
            && destination.site_lineage() == "site:http-import"
    }
}
struct Fixture {
    source_dir: Directory,
    target_dir: Directory,
    source: Option<LocalRootPublisher>,
    target: ReferenceDeployment,
    cx: ReplayCx,
    request: HttpImportRequest,
}
impl Fixture {
    fn new(chunked: bool, close: bool) -> Test<Self> {
        let source_dir = Directory::new()?;
        let target_dir = Directory::new()?;
        let mut source = source_dir.open()?;
        let (pin, frames) = acquire(&mut source, response(chunked, close), 257)?;
        assert_eq!(frames.len(), 2);
        let cx = context(&target_dir.0)?;
        let target = ReferenceDeployment::open(&target_dir.0, "site:http-import", &cx)?;
        let request = HttpImportRequest {
            source: scope(),
            pin,
            sensor: SensorId::parse("sensor:http-import")?,
            stream: StreamId::parse("stream:http-import")?,
            receive_time: TimestampNs(2_000_000_000),
            capture_hint: None,
            max_frames: 8,
            max_bytes: 1024 * 1024,
        };
        Ok(Self {
            source_dir,
            target_dir,
            source: Some(source),
            target,
            cx,
            request,
        })
    }
    fn run(&mut self) -> Test<HttpImportReceipt> {
        Ok(import_http(
            self.source.as_ref().ok_or("source closed")?,
            &mut self.target,
            &self.request,
            &Owner(Cell::new(true)),
            &self.cx,
            &mut work(),
            &mut framing(),
        )?)
    }
    fn retained(&self, receipt: &HttpImportReceipt) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(
            &self.target,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?)
    }
}

#[test]
fn exact_http_import_keeps_duplicate_frames_and_survives_original_archive_removal() -> Test {
    for chunked in [false, true] {
        let mut f = Fixture::new(chunked, false)?;
        f.request.max_frames = 2;
        let imported = f.run()?;
        assert_eq!(imported.frames, 2);
        assert_eq!(imported.ending, HttpImportEnding::ExplicitFramingComplete);
        assert_eq!(imported.capture_time_label, "unknown");
        let retained = f.retained(&imported)?;
        let manifest = retained.manifest();
        assert_eq!(manifest.adapter_id, ADAPTER);
        assert_eq!(manifest.input_bytes, (JPEG.len() * 2) as u64);
        assert_eq!(
            manifest.segment_spans[0].segment_sha256,
            manifest.segment_spans[1].segment_sha256
        );
        assert_ne!(manifest.capsule_ids[0], manifest.capsule_ids[1]);
        assert!(
            manifest
                .validate_retained(RetainedReadLimits::default())
                .is_err()
        );
        assert!(fss_reference::ingest::fetch_segment_bytes(manifest, &f.target, 0).is_err());
        let batches = f.target.ledger().batches().len();
        let reused = f.run()?;
        assert!(reused.reused);
        assert_eq!(reused.import_root, imported.import_root);
        assert_eq!(f.target.ledger().batches().len(), batches);
        f.source.take();
        std::fs::remove_dir_all(&f.source_dir.0)?;
        let retained = f.retained(&imported)?;
        assert_eq!(
            retained.verify_source(&f.target, RetainedReadLimits::default(), &f.cx)?,
            ContentDigest::sha256(&[JPEG, JPEG].concat())
        );
        for index in 0..2 {
            assert_eq!(
                retained.read_segment(&f.target, index, RetainedReadLimits::default(), &f.cx)?,
                JPEG
            );
        }
    }
    Ok(())
}

#[test]
fn http_import_uses_current_sensor_masks_and_explicit_unknown_time() -> Test {
    let mut f = Fixture::new(true, false)?;
    let policy = PrivacyMaskPolicy::new(f.request.sensor.clone(), [17, 13], &[[0, 0, 17, 13]])?;
    let approval = preview_mask(&f.target, &policy)?.approval;
    declare_mask(&mut f.target, &policy, approval, &f.cx)?;
    let imported = f.run()?;
    let request = RecordedDecodeRequest {
        import_identity: imported.import_identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    let decoded =
        RecordedFrame::decode_and_publish(&mut f.target, &request, &mut framing(), &f.cx)?;
    assert_eq!(decoded.pixels(), vec![MASK_FILL_LUMA; 17 * 13]);
    assert_eq!(decoded.receipt().mask_policy(), Some(policy.digest()));
    assert_eq!(
        decoded.receipt().capsule().capture,
        CaptureInterval::new(TimestampNs(0), f.request.receive_time)?
    );
    assert!(decoded.receipt().capsule().capture.latest.0 > i128::from(super::NOW));
    Ok(())
}

#[test]
fn http_import_prefix_is_honest_and_timing_changes_are_distinct_imports() -> Test {
    let mut f = Fixture::new(false, true)?;
    let unknown = f.run()?;
    assert_eq!(unknown.ending, HttpImportEnding::PinnedPrefix);
    f.request.capture_hint = Some(CaptureHint::new(TimestampNs(100_000_000), 1_000_000, 20.0)?);
    let timed = f.run()?;
    assert_eq!(timed.ending, HttpImportEnding::PinnedPrefix);
    assert_eq!(timed.capture_time_label, "operator_assumption");
    assert_ne!(unknown.import_identity, timed.import_identity);
    assert_ne!(unknown.proof, timed.proof);
    assert_eq!(
        f.retained(&timed)?.manifest().input_sha256,
        f.retained(&unknown)?.manifest().input_sha256
    );
    Ok(())
}

#[test]
fn original_damage_refuses_read_full_custody_and_exact_retry() -> Test {
    let mut f = Fixture::new(true, false)?;
    let archive = HttpWireArchive::load(
        f.source.as_ref().ok_or("source")?,
        scope(),
        f.request.pin,
        archive_limits(),
        &NeverCancel,
        &mut work(),
    )?;
    let wire = archive.reads().next().ok_or("missing raw read")?.1;
    let digest = ContentDigest::new(DigestAlgorithm::Sha256, wire.sha256);
    let imported = f.run()?;
    let retained = f.retained(&imported)?;
    let path = f.target.publisher().spool().object_path(digest);
    std::fs::write(&path, b"damaged retained original")?;
    let before = f.target.ledger().batches().len();
    assert!(
        retained
            .verify_source(&f.target, RetainedReadLimits::default(), &f.cx)
            .is_err()
    );
    assert!(
        retained
            .read_segment(&f.target, 0, RetainedReadLimits::default(), &f.cx)
            .is_err()
    );
    assert!(f.run().is_err());
    assert_eq!(f.target.ledger().batches().len(), before);
    assert_eq!(std::fs::read(path)?, b"damaged retained original");
    Ok(())
}

#[test]
fn denied_or_incomplete_selection_publishes_nothing_and_cancelled_import_resumes() -> Test {
    let mut f = Fixture::new(false, false)?;
    let original = f.request.clone();
    let baseline = f.target.ledger().batches().len();
    let denied = import_http(
        f.source.as_ref().ok_or("source")?,
        &mut f.target,
        &f.request,
        &Owner(Cell::new(false)),
        &f.cx,
        &mut work(),
        &mut framing(),
    );
    assert!(denied.is_err());
    assert_eq!(f.target.ledger().batches().len(), baseline);
    f.request.max_frames = 1;
    assert!(f.run().is_err());
    assert_eq!(f.target.ledger().batches().len(), baseline);
    f.request = original.clone();
    f.request.pin.head = ContentDigest::sha256(b"incorrect independent head");
    assert!(f.run().is_err());
    assert_eq!(f.target.ledger().batches().len(), baseline);
    f.request = original;
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(f.run().is_err());
    assert!(f.target.ledger().batches().len() > baseline);
    assert!(
        !f.target
            .ledger()
            .batches()
            .iter()
            .any(|b| b.batch_id.as_str().ends_with(":manifest"))
    );
    f.cx = context(&f.target_dir.0)?;
    let completed = f.run()?;
    assert_eq!(f.retained(&completed)?.manifest().segment_spans.len(), 2);
    Ok(())
}

#[test]
fn generic_import_deletion_plan_includes_original_wire_and_origin_proof() -> Test {
    let mut f = Fixture::new(true, false)?;
    let archive = HttpWireArchive::load(
        f.source.as_ref().ok_or("source")?,
        scope(),
        f.request.pin,
        archive_limits(),
        &NeverCancel,
        &mut work(),
    )?;
    let originals: Vec<_> = archive
        .reads()
        .flat_map(|(pin, wire)| {
            [
                pin.head,
                ContentDigest::new(DigestAlgorithm::Sha256, wire.sha256),
            ]
        })
        .collect();
    let imported = f.run()?;
    let plan = fss_reference::deletion::plan_deletion(&f.target, imported.import_identity, &f.cx)?;
    for digest in originals.into_iter().chain(std::iter::once(imported.proof)) {
        assert!(plan.deletable.iter().any(|object| object.digest == digest));
    }
    Ok(())
}

fn moving_scene() -> Test<Vec<Vec<u8>>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let background = vec![40_u8; 96 * 48];
    let quiet = encode_jpeg(96, 48, &background, &config)?;
    let mut frames = vec![quiet; 150];
    for index in 0..50 {
        let mut pixels = background.clone();
        let x = 80 - (index * 2).min(64);
        for y in 16..32 {
            pixels[y * 96 + x..y * 96 + x + 16].fill(220);
        }
        frames.push(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(frames)
}

/// Same genuine native read boundary as the small replay fixtures, with bounded nonblocking
/// server writes so the generated recording cannot deadlock behind a socket send buffer.
fn acquire_scene(
    publisher: &mut LocalRootPublisher,
    frames: &[Vec<u8>],
) -> Test<fss_reference::ingest::http_archive::HttpWirePin> {
    let mut body = Vec::new();
    for jpeg in frames {
        body.extend_from_slice(
            format!(
                "--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len()
            )
            .as_bytes(),
        );
        body.extend_from_slice(jpeg);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(&body);
    if wire.len() > 1024 * 1024 {
        return Err("generated wire bound".into());
    }
    let listener = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0_u16)))?;
    listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(
        scope().stream,
        listener.local_addr()?,
        "camera.invalid",
        "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext,
    )?;
    let authority = super::Authority {
        route: route.clone(),
        started: Instant::now(),
    };
    let mut camera = HttpCamera::connect(
        route,
        HttpCameraLimits {
            read_bytes: 4096,
            connect_timeout_ns: 1_000_000_000,
            ..HttpCameraLimits::default()
        },
        super::NOW,
        super::DEADLINE,
        &authority,
    )?;
    let (mut socket, _) = listener.accept()?;
    socket.set_nonblocking(true)?;
    let mut request = Vec::new();
    let mut sent = 0;
    let mut closed = false;
    let mut archive = HttpWireArchive::new(scope(), archive_limits())?;
    let mut source_work = work();
    let mut parse_work = framing();
    let mut transferred = 0;
    for _ in 0..100_000 {
        if !request.ends_with(b"\r\n\r\n") {
            let mut bytes = [0_u8; 512];
            match socket.read(&mut bytes) {
                Ok(0) => return Err("client stopped before GET".into()),
                Ok(n) => request.extend_from_slice(&bytes[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
            if request.len() > 4096 {
                return Err("request bound".into());
            }
        } else if sent < wire.len() {
            assert!(request.starts_with(b"GET /video HTTP/1.1\r\n"));
            match socket.write(&wire[sent..wire.len().min(sent + 4096)]) {
                Ok(0) => return Err("zero-byte server write".into()),
                Ok(n) => sent += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        } else if !closed {
            socket.shutdown(Shutdown::Write)?;
            closed = true;
        }
        match camera.step(super::NOW, &authority, &mut parse_work)? {
            HttpCameraStep::WireReady(receipt) => {
                let prepared = archive.prepare(
                    camera.pending_wire().ok_or("missing original read")?,
                    &mut source_work,
                )?;
                archive.publish(&prepared, publisher, &NeverCancel, &mut source_work)?;
                camera.acknowledge_wire(receipt, super::NOW, &authority)?;
            }
            HttpCameraStep::FrameReady => {
                let receipt = camera
                    .pending_frame()
                    .ok_or("missing native frame")?
                    .part()
                    .receipt();
                let frame = camera.take_frame(
                    receipt.ordinal,
                    receipt.encoded_sha256,
                    super::NOW,
                    &authority,
                )?;
                assert_eq!(
                    frame.part().bytes(),
                    frames.get(transferred).ok_or("extra native frame")?
                );
                archive.verify_frame(publisher, &frame, &NeverCancel, &mut source_work)?;
                transferred += 1;
            }
            HttpCameraStep::Complete => {
                assert_eq!(transferred, frames.len());
                assert_eq!(archive.pin().bytes, wire.len() as u64);
                return Ok(archive.pin());
            }
            HttpCameraStep::Pending | HttpCameraStep::Advanced => std::thread::yield_now(),
        }
    }
    Err("generated acquisition step bound".into())
}

#[test]
fn imported_http_recording_finds_late_stream_entry_and_rechecks_originals_before_publication()
-> Test {
    let source_dir = Directory::new()?;
    let target_dir = Directory::new()?;
    let mut source = source_dir.open()?;
    let frames = moving_scene()?;
    assert_eq!(frames.len(), 200);
    let pin = acquire_scene(&mut source, &frames)?;
    let cx = context(&target_dir.0)?;
    let mut target = ReferenceDeployment::open(&target_dir.0, "site:http-import", &cx)?;
    let request = HttpImportRequest {
        source: scope(),
        pin,
        sensor: SensorId::parse("sensor:http-import")?,
        stream: StreamId::parse("stream:late-http-entry")?,
        receive_time: TimestampNs(1_000_000_000_000),
        capture_hint: Some(CaptureHint::new(TimestampNs(1_000_000_000), 0, 10.0)?),
        max_frames: 200,
        max_bytes: 1024 * 1024,
    };
    let imported = import_http(
        &source,
        &mut target,
        &request,
        &Owner(Cell::new(true)),
        &cx,
        &mut work(),
        &mut framing(),
    )?;
    assert_eq!(imported.frames, 200);
    let retained = RetainedFileImport::open(
        &target,
        imported.import_identity,
        RetainedReadLimits::default(),
        &cx,
    )?;
    let plan = WatchPlan {
        import_identity: imported.import_identity,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0,
        segment_count: 200,
        zones: vec![WatchZone {
            zone_id: "driveway".into(),
            x: 0,
            y: 0,
            width: 64,
            height: 48,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    let before = target.current_anchor().clone();
    let effects = target.effects().last_root();
    let mut report = LongWatchReport::analyze(
        &target,
        &plan,
        WatchOptions::default(),
        &LongWatchLimits::default(),
        &cx,
    )?;
    assert_eq!(target.current_anchor(), &before);
    assert_eq!(report.frames_decoded(), 200);
    assert_eq!(report.candidates().len(), 1);
    let candidate = &report.candidates()[0];
    assert!(candidate.entry().position() >= 150 && candidate.entry().position() < 200);
    assert_eq!(candidate.entry().tracker_epoch(), 0);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert_eq!(candidate.event().probability.lower, 0.0);
    assert_eq!(candidate.event().probability.upper, 1.0);
    assert!(
        candidate
            .event()
            .probability
            .calibration_generation
            .is_none()
    );
    assert!(candidate.event().decision_path.abstained);
    assert!(candidate.event().evidence.iter().all(|e| !e.supports));
    assert!(candidate.event().model_receipts.is_empty());
    let approvals = BTreeSet::from([candidate.proposal_digest()]);
    assert_eq!(report.publish(&mut target, &approvals, &cx)?, 1);
    let committed = target.current_anchor().clone();
    assert_eq!(report.publish(&mut target, &approvals, &cx)?, 0);
    assert_eq!(target.current_anchor(), &committed);
    assert_eq!(target.effects().last_root(), effects);

    let archive = HttpWireArchive::load(
        &source,
        scope(),
        pin,
        archive_limits(),
        &NeverCancel,
        &mut work(),
    )?;
    let wire = archive.reads().next().ok_or("missing raw read")?.1;
    let digest = ContentDigest::new(DigestAlgorithm::Sha256, wire.sha256);
    let path = target.publisher().spool().object_path(digest);
    let mut bytes = std::fs::read(&path)?;
    *bytes.last_mut().ok_or("empty raw custody")? ^= 0x80;
    std::fs::write(path, bytes)?;
    for chunk in &retained.manifest().ordered_chunks {
        assert_eq!(
            ContentDigest::sha256(&target.publisher().spool().read(*chunk)?),
            *chunk
        );
    }
    assert!(
        LongWatchReport::analyze(
            &target,
            &plan,
            WatchOptions::default(),
            &LongWatchLimits::default(),
            &cx
        )
        .is_err()
    );
    assert!(report.publish(&mut target, &approvals, &cx).is_err());
    assert_eq!(target.current_anchor(), &committed);
    assert_eq!(target.effects().last_root(), effects);
    Ok(())
}
