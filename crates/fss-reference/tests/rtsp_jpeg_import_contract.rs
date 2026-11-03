#![forbid(unsafe_code)]
//! Genuine packet publication -> retained import -> existing native pixel/privacy owners.

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CanonicalDecode, CaptureInterval, ClockBasis, OperationId, SensorCapsule,
};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, SensorId, StreamId,
    TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::{ObjectManifest, SpoolLimits};
use fss_packet::{ReorderLimits, StreamKey, jpeg::JpegLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::rtsp_jpeg_import::{
    ADAPTER, JpegImportAuthority, JpegImportError, JpegImportReceipt, JpegImportRequest,
    MAX_FRAMES, MAX_SOURCE_DATAGRAMS, import_rtsp_jpeg,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramRecord};
use fss_reference::rtsp::datagram_archive::{DatagramArchiveLimits, DatagramScope};
use fss_reference::rtsp::datagram_reconstruction::jpeg::JpegReplaySpec;
use fss_reference::rtsp::framed::RtspWireIntake;
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] =
    include_bytes!("../../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg");
const ORACLE: &[u8] =
    include_bytes!("../../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.ffmpeg.luma");
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-jpeg-import-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn work() -> WorkBudget<'static> {
    WorkBudget::new(1_000_000_000_000)
}
fn limits() -> DatagramArchiveLimits {
    DatagramArchiveLimits {
        max_datagrams: 512,
        max_payload_bytes: 1024 * 1024,
        max_scan_roots: 2048,
        max_spool_object_bytes: 65536,
    }
}
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        1024,
        8,
        1024,
        4096,
        SpoolLimits::new(4096, 32 * 1024 * 1024, 65536, 4096),
    )
}
fn scope() -> Test<DatagramScope> {
    Ok(DatagramScope {
        binding: TcpBinding::new(
            StreamKey {
                ingress: 71,
                generation: 2,
                ssrc: 7,
            },
            "127.0.0.1:554".parse()?,
            "camera.fixture",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: ContentDigest::sha256(b"original parser monotonic clock"),
        retention_evidence: ContentDigest::sha256(b"owner retained RTP and RTCP originals"),
    })
}
fn spec() -> JpegReplaySpec {
    JpegReplaySpec {
        payload_type: 26,
        reorder: ReorderLimits {
            max_packets: 32,
            max_bytes: 65536,
            max_delay_ns: 20,
            ..ReorderLimits::default()
        },
        jpeg: JpegLimits {
            max_frame_bytes: 65536,
            max_fragment_packets: 64,
            max_pending_age_ns: 100,
            max_cached_quantizers: 4,
            max_dimension: 64,
        },
        reduced_rtcp: true,
        configuration_evidence: ContentDigest::sha256(b"exact accepted JPEG SDP and policy"),
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-jpeg-import".into(),
        operation_id: OperationId::parse("operation:rtsp-jpeg-import")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"site:rtsp-jpeg-import"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
struct Owner(Cell<bool>);
impl JpegImportAuthority for Owner {
    fn permit(&self, r: &JpegImportRequest, d: &ReferenceDeployment) -> bool {
        self.0.get()
            && r.mapping_evidence == ContentDigest::sha256(b"explicit physical camera mapping")
            && d.site_lineage() == "site:rtsp-jpeg-import"
    }
}
fn scan() -> Test<&'static [u8]> {
    let mut at = 2;
    while at + 4 <= JPEG.len() {
        let end = at + 2 + usize::from(u16::from_be_bytes([JPEG[at + 2], JPEG[at + 3]]));
        JPEG.get(at..end).ok_or("fixture segment")?;
        if JPEG[at + 1] == 0xda {
            return Ok(&JPEG[end..]);
        }
        at = end;
    }
    Err("fixture scan".into())
}
fn packet(
    sequence: u16,
    timestamp: u32,
    range: std::ops::Range<usize>,
    marker: bool,
) -> Test<Vec<u8>> {
    let mut bytes = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes());
    bytes.extend_from_slice(&[
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        0,
        50,
        4,
        3,
    ]);
    bytes.extend_from_slice(scan()?.get(range).ok_or("scan range")?);
    Ok(bytes)
}
fn whole(sequence: u16) -> Test<Vec<u8>> {
    packet(sequence, u32::from(sequence) * 9000, 0..scan()?.len(), true)
}
fn quantized(sequence: u16, explicit: bool) -> Test<Vec<u8>> {
    let mut source = whole(sequence)?;
    source[17] = 128;
    let mut bytes = source[..20].to_vec();
    bytes.extend_from_slice(&[0, 0, 0, if explicit { 128 } else { 0 }]);
    if explicit {
        let mut tables = [0; 128];
        let mut seen = 0;
        let mut at = 2;
        while at + 4 <= JPEG.len() {
            let end = at + 2 + usize::from(u16::from_be_bytes([JPEG[at + 2], JPEG[at + 3]]));
            let body = JPEG.get(at + 4..end).ok_or("fixture quantizers")?;
            if JPEG[at + 1] == 0xdb {
                let (entries, remainder) = body.as_chunks::<65>();
                assert!(remainder.is_empty());
                for table in entries {
                    let id = usize::from(table[0]);
                    assert!(id < 2);
                    tables[id * 64..(id + 1) * 64].copy_from_slice(&table[1..]);
                    seen |= 1 << id;
                }
            }
            if JPEG[at + 1] == 0xda {
                break;
            }
            at = end;
        }
        assert_eq!(seen, 3);
        bytes.extend_from_slice(&tables);
    }
    bytes.extend_from_slice(&source[20..]);
    Ok(bytes)
}
fn observations() -> Test<Vec<(u8, u64, Vec<u8>)>> {
    Ok(vec![
        (0, 10, quantized(10, true)?),
        (0, 11, quantized(11, true)?),
        (0, 12, quantized(11, true)?),
        (1, 13, b"invalid retained RTCP".to_vec()),
        (0, 14, quantized(12, false)?),
    ])
}
fn add(
    archive: &mut DatagramArchive,
    publisher: &mut LocalRootPublisher,
    channel: u8,
    time: u64,
    payload: &[u8],
) -> Test {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    wire.extend_from_slice(payload);
    let mut intake = RtspWireIntake::new();
    intake.ingest(&wire, time)?;
    let frame = intake.poll(time)?.ok_or("complete original frame")?;
    let plan = archive.prepare_frame(&frame, &mut work())?;
    archive.publish(&plan, publisher, &NeverCancel, &mut work())?;
    Ok(())
}
struct Fixture {
    _directory: Directory,
    source_path: PathBuf,
    source: Option<LocalRootPublisher>,
    target: ReferenceDeployment,
    request: JpegImportRequest,
    cx: ReplayCx,
    records: Vec<DatagramRecord>,
}
impl Fixture {
    fn new(originals: &[(u8, u64, Vec<u8>)]) -> Test<Self> {
        Self::with_limits(originals, fss_reference::DeploymentLimits::standard())
    }
    fn with_limits(
        originals: &[(u8, u64, Vec<u8>)],
        target_limits: fss_reference::DeploymentLimits,
    ) -> Test<Self> {
        let directory = Directory::new()?;
        let source_path = directory.0.join("source");
        let target_path = directory.0.join("target");
        let cx = context(&target_path)?;
        let mut source = LocalRootPublisher::open(&source_path, storage())?;
        let mut archive = DatagramArchive::new(scope()?, limits())?;
        for (channel, time, bytes) in originals {
            add(&mut archive, &mut source, *channel, *time, bytes)?;
        }
        let request = JpegImportRequest {
            source: scope()?,
            pin: archive.pin(),
            replay: spec(),
            sensor: SensorId::parse("sensor:rtsp-jpeg")?,
            stream: StreamId::parse("stream:rtsp-jpeg")?,
            mapping_evidence: ContentDigest::sha256(b"explicit physical camera mapping"),
            receive_time: TimestampNs(2_000_000_000),
            archive_limits: limits(),
            max_frames: 512,
            max_original_bytes: 4 * 1024 * 1024,
            max_media_bytes: 4 * 1024 * 1024,
            max_read_bytes: 128 * 1024 * 1024,
            max_steps: 4096,
        };
        let target = ReferenceDeployment::open_with_limits(
            &target_path,
            "site:rtsp-jpeg-import",
            target_limits,
            &cx,
        )?;
        Ok(Self {
            _directory: directory,
            source_path,
            source: Some(source),
            target,
            request,
            cx,
            records: archive.records().to_vec(),
        })
    }
    fn run(&mut self) -> Test<JpegImportReceipt> {
        Ok(import_rtsp_jpeg(
            self.source.as_ref().ok_or("source")?,
            &mut self.target,
            &self.request,
            &Owner(Cell::new(true)),
            &self.cx,
            &mut work(),
        )?)
    }
    fn retained(&self, receipt: &JpegImportReceipt) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(
            &self.target,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?)
    }
    fn decoded(&mut self, identity: ContentDigest, index: usize) -> Test<RecordedFrame> {
        Ok(RecordedFrame::decode_and_publish(
            &mut self.target,
            &RecordedDecodeRequest {
                import_identity: identity,
                segment_index: index,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decode_limits: DecodeLimits::default(),
            },
            &mut DecodeBudget::new(1_000_000_000),
            &self.cx,
        )?)
    }
}

fn assert_pixels(actual: &[u8]) {
    assert_eq!(actual.len(), ORACLE.len());
    for (index, (&actual, &expected)) in actual.iter().zip(ORACLE).enumerate() {
        assert!(
            actual.abs_diff(expected) <= 1,
            "luma oracle at {index}: {actual} vs {expected}"
        );
    }
}

// Independent read-only inspection of the registered origin-proof wire format. This
// does not authenticate custody or replace a producer/consumer; the actual retained
// owner below performs all source and native replay validation.
struct ProofInspection {
    originals: Vec<(ContentDigest, u64)>,
    lineages: Vec<Vec<u8>>,
    gap_offsets: Vec<usize>,
}
fn inspect_proof(bytes: &[u8]) -> Test<ProofInspection> {
    assert!(bytes.len() <= 16 * 1024 * 1024);
    let mut d = CanonicalDecoder::new(bytes);
    assert_eq!(d.text()?, "fss.rtsp_jpeg_import.v1");
    let request = d.bytes()?;
    assert!(request.len() <= 4096);
    let _interpretation = d.digest()?;
    let count = usize::try_from(d.u64()?)?;
    assert!(count <= MAX_SOURCE_DATAGRAMS * 3);
    let mut originals = Vec::new();
    for _ in 0..count {
        originals.push((d.digest()?, d.u64()?));
    }
    let count = usize::try_from(d.u64()?)?;
    assert!((1..=MAX_FRAMES).contains(&count));
    let mut lineages = Vec::new();
    let mut gap_offsets = Vec::new();
    for _ in 0..count {
        let _encoded = d.digest()?;
        let _length = d.u64()?;
        gap_offsets.push(bytes.len() - d.remaining());
        let _gap = d.bool()?;
        let digest = d.digest()?;
        let lineage = d.bytes()?;
        assert_eq!(ContentDigest::sha256(lineage), digest);
        let mut native = CanonicalDecoder::new(lineage);
        assert_eq!(native.text()?, "fss.rtsp_datagram_jpeg_frame_provenance.v1");
        lineages.push(lineage.to_vec());
    }
    let _diagnostics = d.bytes()?;
    d.ensure_finished()?;
    Ok(ProofInspection {
        originals,
        lineages,
        gap_offsets,
    })
}

#[test]
fn genuine_import_retains_quantizer_ancestry_and_decodes_after_original_archive_removal() -> Test {
    let mut f = Fixture::new(&observations()?)?;
    let receipt = f.run()?;
    assert_eq!(receipt.frames, 2);
    assert_eq!(receipt.capture_time_label, "unknown");
    assert_eq!(receipt.ending, "pinned_prefix");
    assert_eq!(receipt.accounting.rtp_datagrams, 4);
    assert_eq!(receipt.accounting.rtcp_datagrams, 1);
    assert_eq!(receipt.accounting.invalid_rtcp_datagrams, 1);
    assert!(receipt.original_bytes > receipt.source.payload_bytes);
    assert!(receipt.read_bytes_reserved > receipt.original_bytes);
    let retained = f.retained(&receipt)?;
    assert_eq!(retained.manifest().adapter_id, ADAPTER);
    assert!(
        retained
            .manifest()
            .validate_retained(RetainedReadLimits::default())
            .is_err()
    );
    let proof = inspect_proof(&f.target.publisher().spool().read(receipt.proof)?)?;
    assert!(
        proof
            .originals
            .iter()
            .any(|(d, _)| *d == f.records[1].payload_digest)
    );
    for record in &f.records {
        let source = f.source.as_ref().ok_or("source owner")?;
        let root = source.spool().read(record.pin.head)?;
        assert_eq!(f.target.publisher().spool().read(record.pin.head)?, root);
        let original_manifest = ObjectManifest::from_canonical_bytes(&root)?;
        for digest in original_manifest.children() {
            assert_eq!(
                f.target.publisher().spool().read(*digest)?,
                source.spool().read(*digest)?
            );
        }
    }
    // Cached quantizers in frame two bind an earlier contributing original, beyond its own RTP interval.
    let ancestor = f.records[1].pin.head.bytes();
    assert!(proof.lineages[1].windows(32).any(|w| w == ancestor));
    f.source.take();
    fs::remove_dir_all(&f.source_path)?;
    let digest = retained.verify_source(&f.target, RetainedReadLimits::default(), &f.cx)?;
    assert_eq!(digest, retained.manifest().input_sha256);
    for index in 0..2 {
        let decoded = f.decoded(receipt.import_identity, index)?;
        assert_pixels(decoded.pixels());
        let capsule = decoded.receipt().capsule();
        assert_eq!(capsule.sensor_id, f.request.sensor);
        assert_eq!(capsule.stream_id, f.request.stream);
        assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
        assert_eq!(
            capsule.capture,
            CaptureInterval::new(TimestampNs(0), f.request.receive_time)?
        );
    }
    Ok(())
}

#[test]
fn exact_retry_is_ledger_idempotent_and_explicit_physical_mapping_changes_identity() -> Test {
    let mut f = Fixture::new(&observations()?)?;
    let first = f.run()?;
    let batches = f.target.ledger().batches().len();
    let repeated = f.run()?;
    assert!(repeated.reused);
    assert_eq!(first.import_root, repeated.import_root);
    assert_eq!(f.target.ledger().batches().len(), batches);
    f.request.sensor = SensorId::parse("sensor:other-explicit-camera")?;
    let other = f.run()?;
    assert_ne!(other.import_identity, first.import_identity);
    assert_eq!(
        f.retained(&other)?.manifest().input_sha256,
        f.retained(&first)?.manifest().input_sha256
    );
    assert_eq!(
        f.decoded(other.import_identity, 0)?
            .receipt()
            .capsule()
            .sensor_id,
        f.request.sensor
    );
    Ok(())
}

#[test]
fn native_delivery_gaps_and_partial_tail_are_retained_without_inventing_eof() -> Test {
    let half = scan()?.len() / 2;
    let mut f = Fixture::new(&[
        (0, 10, whole(1)?),
        (0, 11, whole(2)?),
        (0, 12, whole(4)?),
        (1, 100, b"retained RTCP timer witness".to_vec()),
        (0, 101, packet(5, 45_000, 0..half, false)?),
    ])?;
    let receipt = f.run()?;
    assert_eq!(receipt.frames, 2);
    assert_eq!(receipt.accounting.gap_events, 1);
    assert!(receipt.terminal.gap_pending);
    assert!(receipt.terminal.fragment.is_some());
    assert_eq!(receipt.terminal.replay_ns, 101);
    assert_eq!(receipt.ending, "pinned_prefix");
    let retained = f.retained(&receipt)?;
    assert!(retained.manifest().segment_spans[1].gap_before);
    assert!(
        f.decoded(receipt.import_identity, 1)?
            .receipt()
            .capsule()
            .gap_before
    );
    retained.verify_source(&f.target, RetainedReadLimits::default(), &f.cx)?;
    Ok(())
}

#[test]
fn no_complete_frame_and_malformed_rtp_refuse_before_any_destination_authority() -> Test {
    for originals in [
        vec![(0, 10, whole(1)?)],
        vec![(0, 10, whole(1)?), (0, 11, b"not RTP".to_vec())],
    ] {
        let mut f = Fixture::new(&originals)?;
        let before = f.target.ledger().batches().len();
        assert!(f.run().is_err());
        assert_eq!(f.target.ledger().batches().len(), before);
        assert_eq!(f.target.publisher().visible_roots().count(), 0);
    }
    Ok(())
}

#[test]
fn each_whole_call_allowance_and_work_cancellation_refuses_before_publication() -> Test {
    let mut f = Fixture::new(&observations()?)?;
    let valid = f.request.clone();
    for which in 0..5 {
        f.request = valid.clone();
        match which {
            0 => f.request.max_frames = 1,
            1 => f.request.max_original_bytes = 1,
            2 => f.request.max_media_bytes = 1,
            3 => f.request.max_read_bytes = 1,
            _ => f.request.max_steps = 1,
        }
        assert!(f.run().is_err());
        assert!(f.target.ledger().batches().is_empty());
        assert_eq!(f.target.publisher().visible_roots().count(), 0);
    }
    f.request = valid;
    let cancelled = AtomicBool::new(true);
    for mut budget in [
        WorkBudget::new(0),
        WorkBudget::cancellable(1_000_000_000, &cancelled),
    ] {
        assert!(
            import_rtsp_jpeg(
                f.source.as_ref().ok_or("source")?,
                &mut f.target,
                &f.request,
                &Owner(Cell::new(true)),
                &f.cx,
                &mut budget
            )
            .is_err()
        );
    }
    assert!(f.target.ledger().batches().is_empty());
    Ok(())
}

#[test]
fn revoked_owner_and_mutated_exact_pins_cannot_publish_any_media() -> Test {
    let mut f = Fixture::new(&observations()?)?;
    assert!(matches!(
        import_rtsp_jpeg(
            f.source.as_ref().ok_or("source")?,
            &mut f.target,
            &f.request,
            &Owner(Cell::new(false)),
            &f.cx,
            &mut work()
        ),
        Err(JpegImportError::Denied)
    ));
    let valid = f.request.clone();
    for which in 0..5 {
        f.request = valid.clone();
        match which {
            0 => f.request.pin.head = ContentDigest::sha256(b"other"),
            1 => f.request.pin.payload_bytes -= 1,
            2 => f.request.source.receive_clock = ContentDigest::sha256(b"other clock"),
            3 => f.request.mapping_evidence = ContentDigest::sha256(b"unapproved mapping"),
            _ => f.request.replay.payload_type = 96,
        }
        assert!(f.run().is_err());
        assert!(f.target.ledger().batches().is_empty());
    }
    Ok(())
}

#[test]
fn current_privacy_masks_apply_to_native_imported_pixels_and_keep_original_packet_identity() -> Test
{
    let mut f = Fixture::new(&observations()?)?;
    let receipt = f.run()?;
    let prior = f.decoded(receipt.import_identity, 0)?;
    assert_pixels(prior.pixels());
    let policy = PrivacyMaskPolicy::new(f.request.sensor.clone(), [32, 24], &[[0, 0, 32, 24]])?;
    let approval = preview_mask(&f.target, &policy)?.approval;
    declare_mask(&mut f.target, &policy, approval, &f.cx)?;
    let masked = f.decoded(receipt.import_identity, 0)?;
    assert_eq!(masked.pixels(), vec![MASK_FILL_LUMA; 32 * 24]);
    assert_eq!(masked.receipt().mask_policy(), Some(policy.digest()));
    assert_eq!(
        masked.receipt().capsule().source_digest,
        prior.receipt().capsule().source_digest
    );
    f.retained(&receipt)?
        .verify_source(&f.target, RetainedReadLimits::default(), &f.cx)?;
    Ok(())
}

#[test]
fn missing_or_corrupt_original_roots_metadata_and_cached_quantizers_refuse_read_decode_and_retry()
-> Test {
    for kind in 0..3 {
        let mut f = Fixture::new(&observations()?)?;
        let receipt = f.run()?;
        let retained = f.retained(&receipt)?;
        let ancestor = f.records[1];
        let digest = match kind {
            0 => ancestor.pin.head,
            1 => ObjectManifest::from_canonical_bytes(
                &f.target.publisher().spool().read(ancestor.pin.head)?,
            )?
            .metadata_digest()
            .ok_or("metadata")?,
            _ => ancestor.payload_digest,
        };
        let path = f.target.publisher().spool().object_path(digest);
        if kind == 0 {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"corrupted original object")?;
        }
        let before = f.target.ledger().batches().len();
        assert!(
            retained
                .read_segment(&f.target, 1, RetainedReadLimits::default(), &f.cx)
                .is_err()
        );
        assert!(
            retained
                .verify_source(&f.target, RetainedReadLimits::default(), &f.cx)
                .is_err()
        );
        assert!(f.decoded(receipt.import_identity, 1).is_err());
        assert!(f.run().is_err());
        assert_eq!(f.target.ledger().batches().len(), before);
        if kind != 0 {
            assert_eq!(fs::read(path)?, b"corrupted original object");
        }
    }
    Ok(())
}

#[test]
fn unknown_capture_and_gap_capsules_are_bound_to_the_exact_completion_root() -> Test {
    let mut f = Fixture::new(&observations()?)?;
    let receipt = f.run()?;
    let retained = f.retained(&receipt)?;
    let capsule = f
        .decoded(receipt.import_identity, 0)?
        .receipt()
        .capsule()
        .clone();
    let digest = ContentDigest::sha256(&capsule.canonical_bytes());
    let stored = f.target.publisher().spool().read(digest)?;
    assert_eq!(SensorCapsule::from_canonical_bytes(&stored)?, capsule);
    let original = f.target.publisher().spool().read(receipt.proof)?;
    let proof = inspect_proof(&original)?;
    let identity = |bytes: &[u8]| {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_jpeg_import_identity.v1");
        e.digest(ContentDigest::sha256(bytes));
        ContentDigest::sha256(&e.finish())
    };
    assert_eq!(identity(&original), receipt.import_identity);
    let mut changed = original;
    changed[proof.gap_offsets[0]] ^= 1;
    assert_ne!(identity(&changed), receipt.import_identity);
    assert_eq!(retained.manifest().limits_digest, f.request.digest()?);
    Ok(())
}

#[test]
fn intrinsic_replay_ceiling_refuses_even_with_larger_call_budget_before_any_publication() -> Test {
    let mut originals = Vec::new();
    for i in 1..=200u16 {
        originals.push((0, u64::from(i), whole(i)?));
    }
    let mut f = Fixture::new(&originals)?;
    f.request.replay.reorder.max_bytes = 16 * 1024 * 1024;
    f.request.replay.jpeg.max_frame_bytes = 16 * 1024 * 1024;
    f.request.replay.jpeg.max_fragment_packets = 4096;
    let result = import_rtsp_jpeg(
        f.source.as_ref().ok_or("source")?,
        &mut f.target,
        &f.request,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
    );
    assert!(matches!(
        result,
        Err(JpegImportError::Limit("intrinsic cold replay work"))
    ));
    assert!(f.target.ledger().batches().is_empty());
    assert_eq!(f.target.publisher().visible_roots().count(), 0);
    Ok(())
}

#[test]
fn interrupted_multipart_completion_resumes_exactly_but_never_repairs_committed_originals() -> Test
{
    struct StopAfterAggregate;
    impl JpegImportAuthority for StopAfterAggregate {
        fn permit(&self, _: &JpegImportRequest, destination: &ReferenceDeployment) -> bool {
            // Revoke precisely after the final ordinary aggregate is durable, before
            // the adapter can append its completing authority batch. Parts have suffixes.
            !destination
                .publisher()
                .visible_roots()
                .any(|root| root.slot.as_str().starts_with("fi-") && root.slot.as_str().len() == 67)
        }
    }
    for damaged in [false, true] {
        let limits = fss_reference::DeploymentLimits {
            manifest_children_max: 4,
            batch_entries_max: 4,
            ..fss_reference::DeploymentLimits::standard()
        };
        let mut f = Fixture::with_limits(&observations()?, limits)?;
        assert!(
            import_rtsp_jpeg(
                f.source.as_ref().ok_or("source")?,
                &mut f.target,
                &f.request,
                &StopAfterAggregate,
                &f.cx,
                &mut work(),
            )
            .is_err()
        );
        assert!(f.target.publisher().visible_roots().count() > 2);
        assert!(f.target.publisher().visible_roots().any(|root| {
            root.slot.as_str().len() == 67
                && root.state == fss_publication::LocalPublicationState::Durable
        }));
        assert!(
            !f.target
                .ledger()
                .batches()
                .iter()
                .any(|batch| batch.batch_id.as_str().ends_with(":manifest"))
        );
        let before = f.target.ledger().batches().len();
        if damaged {
            let path = f
                .target
                .publisher()
                .spool()
                .object_path(f.records[1].payload_digest);
            fs::write(&path, b"damaged committed original")?;
            assert!(f.run().is_err());
            assert_eq!(f.target.ledger().batches().len(), before);
            assert_eq!(fs::read(path)?, b"damaged committed original");
        } else {
            let completed = f.run()?;
            assert!(!completed.reused);
            let retained = f.retained(&completed)?;
            assert!(retained.manifest().part_roots.len() > 1);
            retained.verify_source(&f.target, RetainedReadLimits::default(), &f.cx)?;
            assert!(f.run()?.reused);
        }
    }
    Ok(())
}
