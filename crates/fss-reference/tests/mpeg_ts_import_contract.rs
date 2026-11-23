#![forbid(unsafe_code)]
//! Native transport import reaches retained decode with original custody, retry and refusal.

use std::fs;
use std::path::{Path, PathBuf};

use fss_container::demux::VideoCodec;
use fss_container::mpeg_ts::{MpegTsVideo, TsFraming, TsLimits, TsSelection};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_reference::ingest::mpeg_ts_import::{
    ADAPTER, MpegTsImportReceipt, MpegTsImportRequest, import_mpeg_ts_file,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
    VerifiedChunkCache,
};
use fss_reference::{DeploymentLimits, ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-mpegts-import-{label}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("directory allocation bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:mpegts-import".into(),
        operation_id: OperationId::parse("operation:mpegts-import")?,
        principal: "principal:mpegts-import".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(), "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(), "CAP-DELETE-PREPARE-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"site:mpegts-import"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn work() -> WorkBudget<'static> { WorkBudget::new(512 * 1024 * 1024) }

// Fixture construction only: independently spelled finite PAT/PMT, adaptation and PES framing.
fn section(table: u8, extension: u16, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![table, 0xb0, 0, (extension >> 8) as u8, extension as u8, 0xc1, 0, 0];
    bytes.extend_from_slice(content);
    let length = bytes.len() + 1;
    bytes[1] |= (length >> 8) as u8;
    bytes[2] = length as u8;
    let mut crc = u32::MAX;
    for byte in &bytes {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 { crc = (crc << 1) ^ if crc & 0x8000_0000 != 0 { 0x04c1_1db7 } else { 0 }; }
    }
    bytes.extend_from_slice(&crc.to_be_bytes());
    bytes
}
fn packet(pid: u16, first: bool, counter: u8, payload: &[u8]) -> Vec<u8> {
    assert!(!payload.is_empty() && payload.len() <= 184);
    let mut bytes = vec![0xff; 188];
    bytes[..4].copy_from_slice(&[
        0x47, (pid >> 8) as u8 | if first { 0x40 } else { 0 }, pid as u8,
        (if payload.len() == 184 { 0x10 } else { 0x30 }) | (counter & 15),
    ]);
    if payload.len() < 184 {
        bytes[4] = (183 - payload.len()) as u8;
        if bytes[4] > 0 { bytes[5] = 0; }
    }
    bytes[188 - payload.len()..].copy_from_slice(payload);
    bytes
}
fn transport(media: &[u8], codec: VideoCodec) -> Vec<u8> {
    let mut pat = vec![0];
    pat.extend(section(0, 1, &[0, 1, 0xf0, 0]));
    let mut pmt = vec![0];
    pmt.extend(section(2, 1, &[
        0xe1, 0, 0xf0, 0, if codec == VideoCodec::Avc { 0x1b } else { 0x24 },
        0xe1, 0, 0xf0, 0, 0x0f, 0xe1, 1, 0xf0, 0,
    ]));
    let mut bytes = packet(0, true, 0, &pat);
    bytes.extend(packet(0x1000, true, 0, &pmt));
    // Unselected audio is original custody, never appended to the video.
    bytes.extend(packet(0x101, true, 0, &[1, 2, 3, 4, 5]));
    // One zero-length video PES contains two complete picture sequences; PTS is 2^33 - 1.
    let mut pes = vec![0, 0, 1, 0xe0, 0, 0, 0x80, 0x80, 5, 0x2f, 0xff, 0xff, 0xff, 0xff];
    pes.extend_from_slice(media);
    let first = packet(0x100, true, 14, &pes[..2]);
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(&first); // An exact duplicate remains in original custody.
    for (index, body) in pes[2..].chunks(184).enumerate() {
        bytes.extend(packet(0x100, false, 15u8.wrapping_add(index as u8), body));
    }
    bytes
}
fn elementary(codec: VideoCodec) -> Vec<u8> {
    let one: &[u8] = match codec {
        VideoCodec::Avc => include_bytes!("../../fss-codec-h264/tests/fixtures/baseline_i64.h264"),
        VideoCodec::Hevc => include_bytes!("../../fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265"),
    };
    [one, one].concat()
}
struct Fixture {
    directory: Directory,
    target: Option<ReferenceDeployment>,
    cx: ReplayCx,
    request: MpegTsImportRequest,
    original: Vec<u8>,
    media: Vec<u8>,
    limits: DeploymentLimits,
}
impl Fixture {
    fn new(label: &str, codec: VideoCodec, partitioned: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut limits = DeploymentLimits::standard();
        if partitioned { limits.manifest_children_max = 8; limits.batch_entries_max = 8; }
        let target = ReferenceDeployment::open_with_limits(&root, "site:mpegts-import", limits, &cx)?;
        let media = elementary(codec);
        let original = transport(&media, codec);
        let source = directory.0.join("recording.ts");
        fs::write(&source, &original)?;
        let mut file = FileIngestRequest::new(source, SensorId::parse("sensor-ts")?, StreamId::parse("stream-ts")?);
        file.receive_time = Some(TimestampNs(10_000_000_000));
        if partitioned { file.limits.chunk_bytes = 512; file.limits.max_batch_deltas = 2; }
        let request = MpegTsImportRequest::new(file);
        Ok(Self { directory, target: Some(target), cx, request, original, media, limits })
    }
    fn target(&self) -> Test<&ReferenceDeployment> {
        self.target.as_ref().ok_or_else(|| "target closed".into())
    }
    fn use_m2ts(&mut self) -> Test {
        self.original = self
            .original
            .chunks_exact(188)
            .enumerate()
            .flat_map(|(index, packet)| {
                // Distinct, wrapping and disordered arrival prefixes also cover the duplicate
                // TS packet above. Prefix values never become receive/capture time.
                let prefix = u32::MAX.wrapping_sub((index as u32).wrapping_mul(0x4747_4747));
                prefix
                    .to_be_bytes()
                    .into_iter()
                    .chain(packet.iter().copied())
            })
            .collect();
        self.request.framing = TsFraming::M2ts192;
        fs::write(&self.request.file.path, &self.original)?;
        Ok(())
    }
    fn run(&mut self) -> Test<MpegTsImportReceipt> {
        Ok(import_mpeg_ts_file(
            self.target.as_mut().ok_or("target closed")?, &self.request, &self.cx, &mut work(),
        )?)
    }
    fn retained(&self, receipt: &MpegTsImportReceipt) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(self.target()?, receipt.import_identity, RetainedReadLimits::default(), &self.cx)?)
    }
    fn reopen(&mut self) -> Test {
        self.target.take();
        let root = self.directory.0.join("deployment");
        self.cx = context(&root)?;
        self.target = Some(ReferenceDeployment::open_with_limits(&root, "site:mpegts-import", self.limits, &self.cx)?);
        Ok(())
    }
}
fn decode(f: &Fixture, receipt: &MpegTsImportReceipt) -> Test<Vec<(Vec<u8>, CaptureInterval)>> {
    let mut frames = Vec::new();
    match receipt.codec {
        VideoCodec::Avc => {
            let mut range = RecordedH264Range::open(f.target()?, RecordedH264Request {
                import_identity: receipt.import_identity, first_segment: 0, segment_count: receipt.segments,
                interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
                decoder_limits: AvcLimits::default(),
            }, &f.cx)?;
            while let Some(frame) = range.next_frame(f.target()?, &f.cx)? {
                frames.push((frame.pixels().to_vec(), frame.receipt().capsule().capture));
            }
        }
        VideoCodec::Hevc => {
            let mut range = RecordedH265Range::open(f.target()?, RecordedH265Request {
                import_identity: receipt.import_identity, first_segment: 0, segment_count: receipt.segments,
                interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
                decoder_limits: HevcLimits::default(),
            }, &f.cx)?;
            while let Some(frame) = range.next_frame(f.target()?, &f.cx)? {
                frames.push((frame.pixels().to_vec(), frame.receipt().capsule().capture));
            }
        }
    }
    Ok(frames)
}

#[test]
fn multiple_access_units_in_one_pes_decode_after_restart_and_loose_source_removal() -> Test {
    for codec in [VideoCodec::Avc, VideoCodec::Hevc] {
        let pictures_per_copy = match codec {
            VideoCodec::Avc => 2, // The fixture contains an I picture and a P picture.
            VideoCodec::Hevc => 3,
        };
        let mut f = Fixture::new(&format!("cold-{codec:?}"), codec, false)?;
        let video = MpegTsVideo::parse(&f.original, TsSelection::default(), TsLimits::default())?;
        assert_eq!(video.elementary_stream(), f.media);
        assert_eq!(video.pes().len(), 1);
        assert_eq!(video.pes()[0].pts, Some((1u64 << 33) - 1));
        assert_eq!(video.duplicate_packets(), 1);
        let receipt = f.run()?;
        assert_eq!(receipt.segments, 2 * pictures_per_copy);
        assert_eq!(receipt.original_digest, ContentDigest::sha256(&f.original));
        assert_eq!(receipt.elementary_bytes, f.media.len() as u64);
        assert_eq!(receipt.capture_time_label, "unknown");
        let head = f.target()?.current_anchor().clone();
        f.reopen()?;
        let retry = f.run()?;
        assert!(retry.reused);
        assert_eq!(retry.import_identity, receipt.import_identity);
        assert_eq!(retry.import_root, receipt.import_root);
        assert_eq!(f.target()?.current_anchor(), &head);
        fs::remove_file(&f.request.file.path)?;
        let retained = f.retained(&receipt)?;
        let manifest = retained.manifest();
        assert_eq!(manifest.adapter_id, ADAPTER);
        assert!(manifest.validate_retained(RetainedReadLimits::default()).is_err());
        assert!(FileIngestAdapter::fetch_segment_bytes(manifest, f.target()?, 0).is_err());
        let mut cache = VerifiedChunkCache::default();
        for span in &manifest.segment_spans {
            let bytes = retained.read_segment_cached(f.target()?, span.segment_index, RetainedReadLimits::default(), &f.cx, &mut cache)?;
            assert_eq!(bytes, f.media[span.offset as usize..(span.offset + span.len) as usize]);
        }
        assert_eq!(retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?, ContentDigest::sha256(&f.media));
        let frames = decode(&f, &receipt)?;
        assert_eq!(frames.len(), 2 * pictures_per_copy);
        assert_eq!(frames[..pictures_per_copy], frames[pictures_per_copy..]);
        assert!(!frames[0].0.is_empty());
        let unknown = CaptureInterval::new(TimestampNs(0), TimestampNs(10_000_000_000))?;
        assert!(frames.iter().all(|(_, capture)| *capture == unknown));
    }
    Ok(())
}

#[test]
fn original_damage_missing_proof_and_direct_helpers_cannot_bypass_transport_custody() -> Test {
    for codec in [VideoCodec::Avc, VideoCodec::Hevc] {
        let mut f = Fixture::new(&format!("damage-{codec:?}"), codec, false)?;
        let receipt = f.run()?;
        let retained = f.retained(&receipt)?;
        let original = f.target()?.publisher().spool().object_path(receipt.original_digest);
        fs::write(&original, b"damaged original transport")?;
        let batches = f.target()?.ledger().batches().len();
        assert!(retained.read_segment(f.target()?, 0, RetainedReadLimits::default(), &f.cx).is_err());
        assert!(retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx).is_err());
        assert!(decode(&f, &receipt).is_err());
        assert!(f.run().is_err());
        assert_eq!(f.target()?.ledger().batches().len(), batches);
        assert_eq!(fs::read(&original)?, b"damaged original transport");
        fs::write(&original, &f.original)?;
        fs::remove_file(f.target()?.publisher().spool().object_path(receipt.proof))?;
        assert!(f.retained(&receipt).is_err());
        assert!(f.run().is_err());
    }
    Ok(())
}

#[test]
fn partitioned_transport_origin_is_retained_deleted_and_resumed_as_one_closure() -> Test {
    let mut f = Fixture::new("partitioned", VideoCodec::Hevc, true)?;
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(f.run().is_err());
    f.reopen()?;
    let receipt = f.run()?;
    let retained = f.retained(&receipt)?;
    assert!(!retained.manifest().part_roots.is_empty());
    retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?;
    let plan = fss_reference::deletion::plan_deletion(f.target()?, receipt.import_identity, &f.cx)?;
    for chunk in f.original.chunks(f.request.file.limits.chunk_bytes as usize) {
        assert!(plan.deletable.iter().any(|entry| entry.digest == ContentDigest::sha256(chunk)));
    }
    assert!(plan.deletable.iter().any(|entry| entry.digest == receipt.proof));
    assert!(f.run()?.reused);
    Ok(())
}

#[test]
fn independent_transport_split_scope_and_work_bounds_refuse_before_publication() -> Test {
    let mut f = Fixture::new("bounds", VideoCodec::Avc, false)?;
    let original = f.request.clone();
    let batches = f.target()?.ledger().batches().len();
    let roots = f.target()?.publisher().visible_roots().count();
    for case in 0..10 {
        f.request = original.clone();
        match case {
            0 => f.request.transport_limits.max_packets = f.original.len() / 188 - 1,
            1 => f.request.transport_limits.max_elementary_bytes = f.media.len() - 1,
            2 => f.request.transport_limits.max_payload_spans = 1,
            3 => f.request.transport_limits.max_pes_bytes = f.media.len(),
            4 => f.request.selection.program = Some(2),
            5 => f.request.selection.video_pid = Some(0x102),
            6 => f.request.file.limits.max_segments = 1,
            7 => f.request.file.receive_time = None,
            8 => f.request.file.limits.max_file_bytes = f.original.len() as u64 - 1,
            _ => f.request.file.capture_hint = Some(CaptureHint::new(TimestampNs(10_000_000_000), 1, 25.0)?),
        }
        assert!(f.run().is_err(), "case {case}");
        assert_eq!(f.target()?.ledger().batches().len(), batches);
        assert_eq!(f.target()?.publisher().visible_roots().count(), roots);
    }
    f.request = original;
    assert!(import_mpeg_ts_file(f.target.as_mut().ok_or("target")?, &f.request, &f.cx, &mut WorkBudget::new(1)).is_err());
    f.cx.set_cancel_at_checkpoint("mpegts_import:source_custody");
    assert!(f.run().is_err());
    assert_eq!(f.target()?.ledger().batches().len(), batches);
    Ok(())
}

#[test]
fn capture_hint_and_every_split_limit_are_part_of_identity() -> Test {
    let mut f = Fixture::new("hint", VideoCodec::Avc, false)?;
    let initial = f.run()?;
    f.request.file.capture_hint = Some(CaptureHint::new(TimestampNs(1_000_000_000), 100, 25.0)?);
    let assumed = f.run()?;
    assert_eq!(assumed.capture_time_label, "operator_assumption");
    assert_ne!(initial.import_identity, assumed.import_identity);
    let frames = decode(&f, &assumed)?;
    assert_eq!(frames[0].1, CaptureInterval::new(TimestampNs(999_999_900), TimestampNs(1_000_000_100))?);
    assert_eq!(frames[1].1, CaptureInterval::new(TimestampNs(1_039_999_900), TimestampNs(1_040_000_100))?);
    let first = f.request.digest()?;
    f.request.file.limits.annexb_limits.max_leading_garbage_bytes += 1;
    assert_ne!(first, f.request.digest()?);
    Ok(())
}

#[test]
fn m2ts_avc_and_hevc_reopen_and_decode_identically_with_all_original_prefixes_retained() -> Test {
    for codec in [VideoCodec::Avc, VideoCodec::Hevc] {
        let mut f = Fixture::new(&format!("m2ts-cold-{codec:?}"), codec, false)?;
        let standard = f.run()?;
        let expected = decode(&f, &standard)?;
        assert!(!expected.is_empty());
        let standard_request = f.request.digest()?;
        f.use_m2ts()?;
        assert_ne!(f.request.digest()?, standard_request);
        let parsed = MpegTsVideo::parse_framed(
            &f.original,
            TsFraming::M2ts192,
            TsSelection::default(),
            TsLimits::default(),
        )?;
        assert_eq!(parsed.elementary_stream(), f.media);
        assert_eq!(parsed.duplicate_packets(), 1);
        let receipt = f.run()?;
        assert_eq!(receipt.framing, TsFraming::M2ts192);
        assert_ne!(receipt.import_identity, standard.import_identity);
        assert_ne!(receipt.proof, standard.proof);
        assert_eq!(receipt.segments, standard.segments);
        assert_eq!(receipt.original_digest, ContentDigest::sha256(&f.original));
        assert_eq!(receipt.original_bytes, f.original.len() as u64);
        assert_eq!(receipt.elementary_bytes, standard.elementary_bytes);
        assert_eq!(receipt.capture_time_label, "unknown");
        f.reopen()?;
        let head = f.target()?.current_anchor().clone();
        let retried = f.run()?;
        assert!(retried.reused);
        assert_eq!(retried.import_root, receipt.import_root);
        assert_eq!(f.target()?.current_anchor(), &head);
        fs::remove_file(&f.request.file.path)?;
        let retained = f.retained(&receipt)?;
        assert_eq!(
            retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?,
            ContentDigest::sha256(&f.media)
        );
        assert_eq!(decode(&f, &receipt)?, expected);
    }
    Ok(())
}

#[test]
fn m2ts_prefix_and_unselected_payload_corruption_refuse_retained_reads_and_decode() -> Test {
    let mut f = Fixture::new("m2ts-custody", VideoCodec::Avc, false)?;
    f.use_m2ts()?;
    let receipt = f.run()?;
    let retained = f.retained(&receipt)?;
    let original_path = f
        .target()?
        .publisher()
        .spool()
        .object_path(receipt.original_digest);
    let batches = f.target()?.ledger().batches().len();
    for byte in [0, 3 * 192 - 1] {
        let mut damaged = f.original.clone();
        damaged[byte] ^= 1;
        let parsed = MpegTsVideo::parse_framed(
            &damaged,
            TsFraming::M2ts192,
            TsSelection::default(),
            TsLimits::default(),
        )?;
        assert_eq!(parsed.elementary_stream(), f.media);
        fs::write(&original_path, &damaged)?;
        assert!(
            retained
                .verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)
                .is_err()
        );
        assert!(
            retained
                .read_segment(f.target()?, 0, RetainedReadLimits::default(), &f.cx)
                .is_err()
        );
        assert!(decode(&f, &receipt).is_err());
        assert!(f.run().is_err());
        assert_eq!(f.target()?.ledger().batches().len(), batches);
        assert_eq!(fs::read(&original_path)?, damaged);
        fs::write(&original_path, &f.original)?;
    }
    assert!(!decode(&f, &receipt)?.is_empty());
    Ok(())
}

#[test]
fn explicit_m2ts_framing_and_packet_bounds_refuse_before_any_publication() -> Test {
    let mut f = Fixture::new("m2ts-refusal", VideoCodec::Hevc, false)?;
    f.use_m2ts()?;
    let original_request = f.request.clone();
    let batches = f.target()?.ledger().batches().len();
    let roots = f.target()?.publisher().visible_roots().count();
    for case in 0..4 {
        f.request = original_request.clone();
        match case {
            0 => f.request.framing = TsFraming::Ts188,
            1 => f.request.transport_limits.max_packets = f.original.len() / 192 - 1,
            2 => f.request.transport_limits.max_input_bytes = f.original.len() - 1,
            _ => fs::write(&f.request.file.path, &f.original[..f.original.len() - 1])?,
        }
        assert!(f.run().is_err(), "case {case}");
        assert_eq!(f.target()?.ledger().batches().len(), batches);
        assert_eq!(f.target()?.publisher().visible_roots().count(), roots);
    }
    f.request = original_request;
    fs::write(&f.request.file.path, &f.original)?;
    assert_eq!(f.run()?.framing, TsFraming::M2ts192);
    Ok(())
}
