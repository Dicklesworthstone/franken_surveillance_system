#![forbid(unsafe_code)]
//! Decode receipts and source-to-tensor lineage on the checked-in media fixtures
//! (fss-2h5zq.41 / fss-2h5zq.42).
//!
//! Every capsule of a real MJPEG/JPEG import is custody-verified, then decoded and receipted
//! (`fss.recorded_luma_receipt.v2`) or refused and receipted (`fss.recorded_decode_refusal.v1`);
//! both are published root-last and referenced by a cognition `decode_receipt` delta. Covers:
//! receipt canonical round trips (every truncation and a suffix fail closed), golden source
//! digests and an independent codec differential for tensor digests, stored-chunk tamper (typed
//! refusal, no codec work, nothing receipted), byte/capsule custody mismatch, reopen from the
//! ledger after restart, fresh-root rebuild equality, outcomes independent of prior decodes, and
//! an incomplete import that is never decoded. Each check prints one CAPLOG record.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::decode_luma;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, Plane,
    RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::file_adapter::STAGE_COMMIT_MANIFEST;
use fss_reference::ingest::recorded_decode::refusal::{
    CapsuleDecode, RecordedDecodeRefusal, RefusalKind, RetainedRefusal, decode_capsule,
};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeError,
    RecordedDecodeReceipt, RecordedDecodeRequest, RecordedFrame, retained_source_capsule,
    verify_custody,
};
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestError, FileIngestReceipt, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:decode-receipt";
/// Golden per-frame source digests of `mjpeg_clean_3frames.mjpeg`
/// (tests/fixtures/media/mjpeg/fixture_manifest.json, `frames[].frame_sha256`).
const CLEAN_FRAMES: [(u64, u64, &str); 3] = [
    (
        0,
        907,
        "3b92d4ad9cbcb3621b43105760025eb5d771a0944967ebd431712687245d36bd",
    ),
    (
        907,
        942,
        "e1ebbdd9ef55c057215ba0ba1b233419cd30f420084758cef8e2a38a4776de25",
    ),
    (
        1849,
        661,
        "cc8e0d2b7d3be5bf40e952e41ab5fb1d2cf903f05b3cc626df1c01b188fa3905",
    ),
];

mod caplog_support;
use caplog_support::Record;

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media")
        .join(relative)
}

struct Root(PathBuf);
impl Root {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-decode-receipt-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
    fn deployment(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:decode-receipt".to_owned(),
        operation_id: OperationId::parse("operation:decode-receipt")?,
        principal: "principal:decode-receipt".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(1 << 16)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Imported {
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    receipt: FileIngestReceipt,
}

fn file_request(relative: &str) -> TestResult<FileIngestRequest> {
    Ok(FileIngestRequest::new(
        fixture(relative),
        SensorId::parse("sensor:decode-receipt")?,
        StreamId::parse("stream:decode-receipt")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000)))
}

fn import(root: &Root, relative: &str) -> TestResult<Imported> {
    let cx = context(&root.deployment())?;
    let mut deployment = ReferenceDeployment::open(&root.deployment(), SITE, &cx)?;
    let receipt = FileIngestAdapter::ingest(file_request(relative)?, &cx, &mut deployment)?;
    Ok(Imported {
        cx,
        deployment,
        receipt,
    })
}

fn request(
    imported: &Imported,
    segment: usize,
    interpretation: ComponentInterpretation,
) -> RecordedDecodeRequest {
    RecordedDecodeRequest {
        import_identity: imported.receipt.import_identity,
        segment_index: segment,
        interpretation,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    }
}

fn decode_receipt_batches(deployment: &ReferenceDeployment) -> usize {
    deployment
        .ledger()
        .batches()
        .iter()
        .filter(|b| b.deltas.iter().any(|d| d.family == "decode_receipt"))
        .count()
}

fn decoded(outcome: CapsuleDecode) -> TestResult<RecordedFrame> {
    match outcome {
        CapsuleDecode::Decoded(frame) => Ok(*frame),
        CapsuleDecode::Refused(r) => Err(format!("expected decoded, got {:?}", r.refusal()).into()),
    }
}

fn refused(outcome: CapsuleDecode) -> TestResult<RetainedRefusal> {
    match outcome {
        CapsuleDecode::Refused(r) => Ok(*r),
        CapsuleDecode::Decoded(_) => {
            Err("expected a receipted refusal, got a decoded frame".into())
        }
    }
}

/// Every capsule of the clean MJPEG fixture: custody matches the golden span digests, the tensor
/// digest equals an independent decode of the exact fixture bytes, and the receipt is published
/// root-last and referenced by exactly one cognition `decode_receipt` delta.
#[test]
fn clean_mjpeg_capsules_decode_with_golden_lineage_and_ledgered_receipts() -> TestResult {
    let root = Root::new("clean")?;
    let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let file = fs::read(fixture("mjpeg/mjpeg_clean_3frames.mjpeg"))?;
    assert_eq!(imported.receipt.manifest.segment_spans.len(), 3);
    for (segment, (offset, len, golden)) in CLEAN_FRAMES.iter().enumerate() {
        let request = request(&imported, segment, ComponentInterpretation::YCbCr);
        let mut budget = DecodeBudget::new(100_000_000);
        let frame = decoded(decode_capsule(
            &mut imported.deployment,
            &request,
            &mut budget,
            &imported.cx,
        )?)?;
        let receipt = frame.receipt();
        let source = receipt.capsule().source_digest;
        let start = usize::try_from(*offset)?;
        let bytes = &file[start..start + usize::try_from(*len)?];
        let mut reference_budget = DecodeBudget::new(100_000_000);
        let reference = decode_luma(
            bytes,
            ContentDigest::sha256(bytes).bytes(),
            ComponentInterpretation::YCbCr,
            DecodeLimits::default(),
            &mut reference_budget,
        )?;
        let tensor = ContentDigest::new(DigestAlgorithm::Sha256, receipt.codec().luma_sha256);
        let pass = hex(source) == *golden
            && receipt.capsule().source_bytes == *len
            && receipt.codec().encoded_sha256 == source.bytes()
            && tensor == ContentDigest::sha256(reference.pixels())
            && receipt.dimensions() == reference.dimensions()
            && receipt.dimensions() == [64, 48]
            && frame.pixels() == reference.pixels()
            && receipt.work_units() == reference_budget.used();
        Record::new(&format!("clean_frame_{segment}"))
            .check("source_digest", *golden, hex(source))
            .check("source_bytes", *len, receipt.capsule().source_bytes)
            .check(
                "encoded_sha256",
                hex(source),
                hex(ContentDigest::new(
                    DigestAlgorithm::Sha256,
                    receipt.codec().encoded_sha256,
                )),
            )
            .check(
                "tensor_digest",
                hex(ContentDigest::sha256(reference.pixels())),
                hex(tensor),
            )
            .check("dimensions", reference.dimensions(), receipt.dimensions())
            .check("dimensions_64x48", [64_u32, 48], receipt.dimensions())
            .check(
                "pixels_equal_reference",
                true,
                frame.pixels() == reference.pixels(),
            )
            .check("work_units", reference_budget.used(), receipt.work_units())
            .emit_checked(0, pass);
        assert!(pass, "segment {segment}: lineage mismatch");

        let digest = receipt.digest()?;
        let batch = imported
            .deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.deltas.iter().any(|d| d.payload_digest == digest))
            .ok_or("receipt delta missing")?;
        assert_eq!(batch.deltas.len(), 1);
        let delta = &batch.deltas[0];
        assert_eq!(delta.family, "decode_receipt");
        assert_eq!(delta.plane, Plane::Cognition);
        assert_eq!(delta.witness_digest, Some(frame.publication_root()));
        assert!(batch.children.contains(&frame.publication_root()));
        assert!(batch.children.contains(&source), "source custody reachable");
        assert!(batch.children.contains(&tensor), "tensor bytes reachable");
        let stored = imported.deployment.publisher().spool().read(digest)?;
        assert_eq!(RecordedDecodeReceipt::decode(&stored, digest)?, *receipt);
    }
    Ok(())
}

/// The truncated last frame never becomes a capsule (the importer drops it and records
/// `truncated_frame_omitted` in its degradation), so it is never decoded or receipted; its 633
/// bytes at offset 1849 are covered by no segment. The two complete frames decode to the same
/// lineage as in the clean fixture.
#[test]
fn truncated_last_frame_is_never_a_capsule_and_complete_frames_still_decode() -> TestResult {
    let root = Root::new("truncated")?;
    let mut imported = import(&root, "mjpeg/mjpeg_truncated_last.mjpeg")?;
    let manifest = imported.receipt.manifest.clone();
    let covered_end = manifest
        .segment_spans
        .iter()
        .map(|s| s.offset + s.len)
        .max()
        .unwrap_or(0);
    let pass = manifest.segment_spans.len() == 2
        && covered_end == 1849
        && manifest.input_bytes == 2482
        && manifest
            .omission_spans
            .iter()
            .all(|o| o.offset + o.len <= 1849);
    Record::new("truncated_last_shape")
        .check("segments", 2_usize, manifest.segment_spans.len())
        .check("covered_end", 1849_u64, covered_end)
        .check("input_bytes", 2482_u64, manifest.input_bytes)
        .check(
            "omissions_before_1849",
            true,
            manifest
                .omission_spans
                .iter()
                .all(|o| o.offset + o.len <= 1849),
        )
        .emit_checked(0, pass);
    assert!(pass);
    for (segment, (_, _, golden)) in CLEAN_FRAMES.iter().take(2).enumerate() {
        let request = request(&imported, segment, ComponentInterpretation::YCbCr);
        let mut budget = DecodeBudget::new(100_000_000);
        let frame = decoded(decode_capsule(
            &mut imported.deployment,
            &request,
            &mut budget,
            &imported.cx,
        )?)?;
        assert_eq!(hex(frame.receipt().capsule().source_digest), *golden);
    }
    assert_eq!(decode_receipt_batches(&imported.deployment), 2);
    Ok(())
}

/// Source-determined refusals are never silent: an unsupported interpretation and a bounds
/// refusal are each published and receipted, round-trip canonically, reopen and replay, are
/// idempotent without codec work, and bind their limits.
#[test]
fn codec_refusals_are_receipted_reopened_replayed_and_idempotent() -> TestResult {
    let root = Root::new("refusal")?;
    let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let gray = request(&imported, 0, ComponentInterpretation::Grayscale);
    let mut budget = DecodeBudget::new(100_000_000);
    let unsupported = refused(decode_capsule(
        &mut imported.deployment,
        &gray,
        &mut budget,
        &imported.cx,
    )?)?;
    let refusal = unsupported.refusal();
    let pass = refusal.kind() == RefusalKind::Unsupported
        && refusal.error_id() == "ERR-DECODE-001"
        && hex(refusal.capsule().source_digest) == CLEAN_FRAMES[0].2
        && refusal.decoder() == fss_codec_mjpeg::decoder_identity();
    Record::new("refusal_unsupported")
        .check(
            "kind",
            RefusalKind::Unsupported.as_str(),
            refusal.kind().as_str(),
        )
        .check("error_id", "ERR-DECODE-001", refusal.error_id())
        .check(
            "source_digest",
            CLEAN_FRAMES[0].2,
            hex(refusal.capsule().source_digest),
        )
        .check(
            "decoder_is_codec_identity",
            true,
            refusal.decoder() == fss_codec_mjpeg::decoder_identity(),
        )
        .emit_checked(0, pass);
    assert!(pass);

    // Canonical round trip; every truncation, a suffix and a foreign digest fail closed.
    let bytes = refusal.encoded()?;
    let digest = refusal.digest()?;
    assert_eq!(RecordedDecodeRefusal::decode(&bytes, digest)?, *refusal);
    for cut in 0..bytes.len() {
        let short = &bytes[..cut];
        assert!(RecordedDecodeRefusal::decode(short, ContentDigest::sha256(short)).is_err());
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(RecordedDecodeRefusal::decode(&suffix, ContentDigest::sha256(&suffix)).is_err());
    assert!(RecordedDecodeRefusal::decode(&bytes, ContentDigest::sha256(b"other")).is_err());
    let stored = imported.deployment.publisher().spool().read(digest)?;
    assert_eq!(stored, bytes, "the refusal record is retained");

    // The ledger references it exactly once, as a cognition decode_receipt delta.
    let batch = imported
        .deployment
        .ledger()
        .batches()
        .iter()
        .find(|b| b.deltas.iter().any(|d| d.payload_digest == digest))
        .ok_or("refusal delta missing")?;
    assert_eq!(batch.deltas.len(), 1);
    assert_eq!(batch.deltas[0].family, "decode_receipt");
    assert_eq!(batch.deltas[0].plane, Plane::Cognition);
    assert_eq!(
        batch.deltas[0].witness_digest,
        Some(unsupported.publication_root())
    );
    assert!(batch.children.contains(&refusal.capsule().source_digest));

    // Reopen equals; replay re-runs the codec to the same refusal; repeat is idempotent.
    let reopened = RetainedRefusal::open(&imported.deployment, &gray, &imported.cx)?;
    assert_eq!(reopened, unsupported);
    let mut replay_budget = DecodeBudget::new(100_000_000);
    reopened.verify_by_replay(
        &imported.deployment,
        &gray,
        &mut replay_budget,
        &imported.cx,
    )?;
    let batches = imported.deployment.ledger().batches().len();
    let mut repeat_budget = DecodeBudget::new(100_000_000);
    let again = refused(decode_capsule(
        &mut imported.deployment,
        &gray,
        &mut repeat_budget,
        &imported.cx,
    )?)?;
    assert_eq!(again, unsupported);
    assert_eq!(
        repeat_budget.used(),
        0,
        "a committed refusal spends no codec work"
    );
    assert_eq!(imported.deployment.ledger().batches().len(), batches);

    // The same capsule decodes under the correct interpretation: a separate lineage.
    let ycbcr = request(&imported, 0, ComponentInterpretation::YCbCr);
    let mut decode_budget = DecodeBudget::new(100_000_000);
    decoded(decode_capsule(
        &mut imported.deployment,
        &ycbcr,
        &mut decode_budget,
        &imported.cx,
    )?)?;

    // A bounds refusal binds its limits; other limits are another identity.
    let mut tight = request(&imported, 1, ComponentInterpretation::YCbCr);
    tight.decode_limits.maximum_dimension = 32;
    let mut tight_budget = DecodeBudget::new(100_000_000);
    let bounds = refused(decode_capsule(
        &mut imported.deployment,
        &tight,
        &mut tight_budget,
        &imported.cx,
    )?)?;
    assert_eq!(bounds.refusal().kind(), RefusalKind::Bounds);
    assert_eq!(bounds.refusal().error_id(), "ERR-DECODE-BOUNDS-001");
    assert_eq!(bounds.refusal().limits()?.maximum_dimension, 32);
    let mut tighter = tight.clone();
    tighter.decode_limits.maximum_dimension = 16;
    let mut tighter_budget = DecodeBudget::new(100_000_000);
    let other = refused(decode_capsule(
        &mut imported.deployment,
        &tighter,
        &mut tighter_budget,
        &imported.cx,
    )?)?;
    assert_ne!(other.refusal().identity(), bounds.refusal().identity());
    // Every value below was asserted above; the record reports exactly those comparisons.
    Record::new("refusal_bounds_binds_limits")
        .check(
            "kind",
            RefusalKind::Bounds.as_str(),
            bounds.refusal().kind().as_str(),
        )
        .check(
            "error_id",
            "ERR-DECODE-BOUNDS-001",
            bounds.refusal().error_id(),
        )
        .check(
            "maximum_dimension",
            32_u32,
            bounds.refusal().limits()?.maximum_dimension,
        )
        .check(
            "other_limits_other_identity",
            true,
            other.refusal().identity() != bounds.refusal().identity(),
        )
        .emit_checked(0, true);
    Ok(())
}

/// Budget exhaustion describes the caller, not the source: typed error, nothing receipted.
#[test]
fn budget_exhaustion_is_typed_and_never_receipted() -> TestResult {
    let root = Root::new("budget")?;
    let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let request = request(&imported, 0, ComponentInterpretation::YCbCr);
    let before = imported.deployment.ledger().batches().len();
    let mut budget = DecodeBudget::new(1);
    let result = decode_capsule(
        &mut imported.deployment,
        &request,
        &mut budget,
        &imported.cx,
    );
    let pass = matches!(
        result,
        Err(RecordedDecodeError::Codec(
            fss_codec_mjpeg::DecodeError::BudgetExhausted
        ))
    ) && imported.deployment.ledger().batches().len() == before;
    Record::new("budget_not_receipted")
        .check(
            "codec_budget_exhausted",
            true,
            matches!(
                result,
                Err(RecordedDecodeError::Codec(
                    fss_codec_mjpeg::DecodeError::BudgetExhausted
                ))
            ),
        )
        .check(
            "ledger_batches",
            before,
            imported.deployment.ledger().batches().len(),
        )
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

fn flip_last_byte(path: &Path) -> TestResult {
    let mut stored = fs::read(path)?;
    let last = stored.last_mut().ok_or("stored object is empty")?;
    *last ^= 0x5a;
    let mut permissions = fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    fs::write(path, stored)?;
    Ok(())
}

/// A byte flipped in the stored chunk: the custody read refuses with the typed source/custody
/// identity before any codec work, and no decode receipt or refusal is retained.
#[test]
fn stored_chunk_tamper_refuses_before_decode_and_retains_nothing() -> TestResult {
    let root = Root::new("tamper")?;
    let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let chunk = *imported
        .receipt
        .manifest
        .ordered_chunks
        .first()
        .ok_or("no chunk")?;
    flip_last_byte(&imported.deployment.publisher().spool().object_path(chunk))?;
    let before = imported.deployment.ledger().batches().len();
    for segment in 0..3 {
        let request = request(&imported, segment, ComponentInterpretation::YCbCr);
        let mut budget = DecodeBudget::new(100_000_000);
        let result = decode_capsule(
            &mut imported.deployment,
            &request,
            &mut budget,
            &imported.cx,
        );
        let observed = match &result {
            Err(error) => error.stable_id(),
            Ok(_) => "decoded",
        };
        let pass = matches!(result, Err(RecordedDecodeError::Source(_)))
            && observed == "ERR-DECODE-SOURCE-UNAVAILABLE-001"
            && budget.used() == 0;
        Record::new(&format!("tamper_segment_{segment}"))
            .check(
                "source_error",
                true,
                matches!(result, Err(RecordedDecodeError::Source(_))),
            )
            .check("error_id", "ERR-DECODE-SOURCE-UNAVAILABLE-001", observed)
            .check("work_units", 0_u64, budget.used())
            .emit_checked(0, pass);
        assert!(pass, "segment {segment}: {result:?}");
    }
    assert_eq!(imported.deployment.ledger().batches().len(), before);
    assert_eq!(decode_receipt_batches(&imported.deployment), 0);
    Ok(())
}

/// The custody gate refuses bytes that disagree with the capsule's source digest or byte count
/// with the typed `CustodyMismatch`, and admits the exact span.
#[test]
fn custody_gate_refuses_bytes_that_disagree_with_the_capsule() -> TestResult {
    let root = Root::new("mismatch")?;
    let imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let retained = RetainedFileImport::open(
        &imported.deployment,
        imported.receipt.import_identity,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    let capsule = retained_source_capsule(&imported.deployment, &retained, 1)?;
    let bytes = retained.read_segment(
        &imported.deployment,
        1,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    verify_custody(&capsule, &bytes)?;
    let mut flipped = bytes.clone();
    flipped[bytes.len() / 2] ^= 0x01;
    let other_span = retained.read_segment(
        &imported.deployment,
        0,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    let cases: [(&str, &[u8]); 3] = [
        ("flipped_byte", &flipped),
        ("short_span", &bytes[..bytes.len() - 1]),
        ("other_capsule_span", &other_span),
    ];
    for (name, candidate) in cases {
        let result = verify_custody(&capsule, candidate);
        let pass = matches!(result, Err(RecordedDecodeError::CustodyMismatch))
            && result
                .as_ref()
                .err()
                .is_some_and(|e| e.stable_id() == "ERR-DECODE-CUSTODY-MISMATCH-001");
        Record::new(&format!("custody_mismatch_{name}"))
            .check(
                "custody_mismatch",
                true,
                matches!(result, Err(RecordedDecodeError::CustodyMismatch)),
            )
            .check(
                "error_id",
                Some("ERR-DECODE-CUSTODY-MISMATCH-001"),
                result.as_ref().err().map(RecordedDecodeError::stable_id),
            )
            .emit_checked(0, pass);
        assert!(pass, "{name}: {result:?}");
    }
    Ok(())
}

/// Derived state is rebuildable: after a restart the receipts reopen from the ledger and spool
/// unchanged, and importing the same file into a fresh root reproduces identical receipt and
/// tensor digests for decoded and refused capsules alike.
#[test]
fn receipts_reopen_after_restart_and_rebuild_identically_in_a_fresh_root() -> TestResult {
    fn run(root: &Root) -> TestResult<(Vec<RecordedFrame>, RetainedRefusal, Imported)> {
        let mut imported = import(root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
        let mut frames = Vec::new();
        for segment in 0..3 {
            let request = request(&imported, segment, ComponentInterpretation::YCbCr);
            let mut budget = DecodeBudget::new(100_000_000);
            frames.push(decoded(decode_capsule(
                &mut imported.deployment,
                &request,
                &mut budget,
                &imported.cx,
            )?)?);
        }
        let gray = request(&imported, 2, ComponentInterpretation::Grayscale);
        let mut budget = DecodeBudget::new(100_000_000);
        let refusal = refused(decode_capsule(
            &mut imported.deployment,
            &gray,
            &mut budget,
            &imported.cx,
        )?)?;
        Ok((frames, refusal, imported))
    }
    let first_root = Root::new("rebuild-a")?;
    let (frames, refusal, imported) = run(&first_root)?;
    let identity = imported.receipt.import_identity;
    drop(imported);

    // Restart: a new deployment instance over the same root reopens every receipt unchanged.
    let cx = context(&first_root.deployment())?;
    let deployment = ReferenceDeployment::open(&first_root.deployment(), SITE, &cx)?;
    for (segment, frame) in frames.iter().enumerate() {
        let request = RecordedDecodeRequest {
            import_identity: identity,
            segment_index: segment,
            interpretation: ComponentInterpretation::YCbCr,
            read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default(),
        };
        assert_eq!(RecordedFrame::open(&deployment, &request, &cx)?, *frame);
    }
    let gray = RecordedDecodeRequest {
        import_identity: identity,
        segment_index: 2,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    assert_eq!(RetainedRefusal::open(&deployment, &gray, &cx)?, refusal);
    drop(deployment);

    // Fresh root: identical receipt digests, tensor digests and refusal digest.
    let second_root = Root::new("rebuild-b")?;
    let (rebuilt, rebuilt_refusal, _) = run(&second_root)?;
    for (segment, (a, b)) in frames.iter().zip(&rebuilt).enumerate() {
        let (left, right) = (a.receipt().digest()?, b.receipt().digest()?);
        let pass = left == right && a.receipt().codec() == b.receipt().codec();
        Record::new(&format!("rebuild_frame_{segment}"))
            .check("receipt_digest", hex(left), hex(right))
            .check(
                "codec_equal",
                true,
                a.receipt().codec() == b.receipt().codec(),
            )
            .emit_checked(0, pass);
        assert!(pass, "segment {segment} rebuilt differently");
    }
    let (left, right) = (
        refusal.refusal().digest()?,
        rebuilt_refusal.refusal().digest()?,
    );
    Record::new("rebuild_refusal")
        .check("refusal_digest", hex(left), hex(right))
        .emit_checked(0, left == right);
    assert_eq!(left, right);
    Ok(())
}

/// A single baseline JPEG file is one capsule with the same custody-bound lineage.
#[test]
fn single_jpeg_file_is_one_receipted_capsule() -> TestResult {
    let root = Root::new("jpeg")?;
    let mut imported = import(&root, "jpeg/rgb_64x48_colorbars_420.jpg")?;
    let file = fs::read(fixture("jpeg/rgb_64x48_colorbars_420.jpg"))?;
    assert_eq!(imported.receipt.manifest.segment_spans.len(), 1);
    let request = request(&imported, 0, ComponentInterpretation::YCbCr);
    let mut budget = DecodeBudget::new(100_000_000);
    let frame = decoded(decode_capsule(
        &mut imported.deployment,
        &request,
        &mut budget,
        &imported.cx,
    )?)?;
    let pass = frame.receipt().capsule().source_digest == ContentDigest::sha256(&file)
        && frame.receipt().dimensions() == [64, 48];
    Record::new("single_jpeg")
        .check(
            "source_digest",
            hex(ContentDigest::sha256(&file)),
            hex(frame.receipt().capsule().source_digest),
        )
        .check("dimensions", [64_u32, 48], frame.receipt().dimensions())
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

/// fss-2h5zq.42 D4 (review probe P_REF): a request's outcome does not depend on what was decoded
/// before. Each request runs alone in a fresh root, then again in a root that first decoded the
/// same capsule under the widest limits: a narrower bound (dimension 32, or 3 markers, which the
/// codec counts but the success receipt does not) is the same receipted bounds refusal with the
/// same digest and work, and an admitting narrower bound (dimension 64) is the same decoded
/// receipt with the same work. The widest request still reopens without codec work.
#[test]
fn decode_outcomes_do_not_depend_on_prior_decodes() -> TestResult {
    fn outcome(
        imported: &mut Imported,
        limits: DecodeLimits,
    ) -> TestResult<(String, ContentDigest, u64)> {
        let mut req = request(imported, 1, ComponentInterpretation::YCbCr);
        req.decode_limits = limits;
        let mut budget = DecodeBudget::new(100_000_000);
        let decision = decode_capsule(&mut imported.deployment, &req, &mut budget, &imported.cx)?;
        Ok(match decision {
            CapsuleDecode::Decoded(frame) => (
                "decoded".to_owned(),
                frame.receipt().digest()?,
                budget.used(),
            ),
            CapsuleDecode::Refused(retained) => (
                format!("refused:{}", retained.refusal().kind().as_str()),
                retained.refusal().digest()?,
                budget.used(),
            ),
        })
    }
    let cases = [
        (
            "dimension-32",
            DecodeLimits {
                maximum_dimension: 32,
                ..DecodeLimits::default()
            },
            "refused:bounds",
        ),
        (
            "markers-3",
            DecodeLimits {
                maximum_markers: 3,
                ..DecodeLimits::default()
            },
            "refused:bounds",
        ),
        (
            "dimension-64",
            DecodeLimits {
                maximum_dimension: 64,
                ..DecodeLimits::default()
            },
            "decoded",
        ),
    ];
    let mut fresh = Vec::new();
    for (name, limits, expected) in cases {
        let root = Root::new(&format!("history-fresh-{name}"))?;
        let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
        let observed = outcome(&mut imported, limits)?;
        assert_eq!(observed.0, expected, "fresh {name}");
        fresh.push(observed);
    }
    let root = Root::new("history-wide-first")?;
    let mut imported = import(&root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let wide = outcome(&mut imported, DecodeLimits::default())?;
    assert_eq!(wide.0, "decoded");
    for ((name, limits, _), expected) in cases.iter().zip(&fresh) {
        let observed = outcome(&mut imported, *limits)?;
        let pass = observed == *expected;
        Record::new(&format!("history_independent_{name}"))
            .check("outcome", expected.0.as_str(), observed.0.as_str())
            .check("digest", hex(expected.1), hex(observed.1))
            .check("work_units", expected.2, observed.2)
            .emit_checked(0, pass);
        assert!(
            pass,
            "{name}: after a wide decode {observed:?}, fresh {expected:?}"
        );
    }
    // The admitting narrower request is the wide decode's own receipt.
    assert_eq!(fresh[2].1, wide.1);
    let again = outcome(&mut imported, DecodeLimits::default())?;
    assert_eq!(again, (wide.0.clone(), wide.1, 0));
    Ok(())
}

/// fss-2h5zq.42 round 3: an incomplete import (cut at its manifest commit, after its capsule
/// batches were committed) is never decoded. After a restart every segment is the typed
/// source-unavailable refusal with no codec work and nothing retained.
#[test]
fn incomplete_import_is_never_decoded() -> TestResult {
    // The import identity is deterministic; learn it from a complete import in another root.
    let complete_root = Root::new("incomplete-reference")?;
    let complete = import(&complete_root, "mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let identity = complete.receipt.import_identity;
    let segments = complete.receipt.manifest.segment_spans.len();
    drop(complete);

    let root = Root::new("incomplete")?;
    {
        let cx = context(&root.deployment())?;
        let mut deployment = ReferenceDeployment::open(&root.deployment(), SITE, &cx)?;
        cx.set_cancel_at_checkpoint(STAGE_COMMIT_MANIFEST);
        let cut = FileIngestAdapter::ingest(
            file_request("mjpeg/mjpeg_clean_3frames.mjpeg")?,
            &cx,
            &mut deployment,
        );
        match cut {
            Err(FileIngestError::CancellationRequested { stage }) => {
                assert_eq!(stage, STAGE_COMMIT_MANIFEST);
            }
            other => {
                return Err(format!("expected a cut at the manifest commit, got {other:?}").into());
            }
        }
    }
    let cx = context(&root.deployment())?;
    let mut deployment = ReferenceDeployment::open(&root.deployment(), SITE, &cx)?;
    let capsule_batches = format!("batch:file-import:{}:c", hex(identity));
    assert!(
        deployment
            .ledger()
            .batches()
            .iter()
            .any(|b| b.batch_id.as_str().starts_with(&capsule_batches)),
        "the cut import committed its capsule batches"
    );
    let before = deployment.ledger().batches().len();
    for segment in 0..segments {
        let request = RecordedDecodeRequest {
            import_identity: identity,
            segment_index: segment,
            interpretation: ComponentInterpretation::YCbCr,
            read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default(),
        };
        let mut budget = DecodeBudget::new(100_000_000);
        let result = decode_capsule(&mut deployment, &request, &mut budget, &cx);
        let pass = matches!(&result, Err(error)
                if error.stable_id() == "ERR-DECODE-SOURCE-UNAVAILABLE-001")
            && budget.used() == 0
            && deployment.ledger().batches().len() == before;
        Record::new(&format!("incomplete_import_segment_{segment}"))
            .check(
                "error_id",
                Some("ERR-DECODE-SOURCE-UNAVAILABLE-001"),
                result.as_ref().err().map(RecordedDecodeError::stable_id),
            )
            .check("work_units", 0_u64, budget.used())
            .check(
                "ledger_batches",
                before,
                deployment.ledger().batches().len(),
            )
            .emit_checked(0, pass);
        assert!(pass, "segment {segment}: {result:?}");
    }
    assert_eq!(decode_receipt_batches(&deployment), 0);
    Ok(())
}
