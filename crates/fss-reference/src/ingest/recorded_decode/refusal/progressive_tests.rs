#![forbid(unsafe_code)]
//! An old source refusal and a new progressive success coexist and survive cold replay.

use super::*;
use crate::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use std::fs;
use std::path::PathBuf;

type Test = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(
    "../../../../../fss-codec-mjpeg/tests/fixtures/progressive_jpeg/420_37x29_rst2.progressive.jpg"
);
const SITE: &str = "site:progressive-replay";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, std::io::Error> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-progressive-replay-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("test directory capacity"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn progressive_success_does_not_rewrite_or_reuse_a_retained_v1_refusal() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("source.mjpeg");
    fs::write(&input, JPEG)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:progressive-replay".to_owned(),
        operation_id: OperationId::parse("operation:progressive-replay")?,
        principal: "principal:progressive-replay".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            input.clone(),
            SensorId::parse("sensor:progressive")?,
            StreamId::parse("stream:progressive")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    let request = RecordedDecodeRequest {
        import_identity: imported.import_identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: crate::ingest::RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };

    // Materialize the exact v1 refusal using its unchanged codec, canonical layout, key, and
    // publication sequence. This represents a deployment written before progressive admission.
    let (retained, capsule, capsule_digest, encoded) = source(&deployment, &request, &cx)?;
    let mut old_work = DecodeBudget::new(100_000_000);
    assert_eq!(
        fss_codec_mjpeg::decode_luma_v1(
            &encoded,
            capsule.source_digest.bytes(),
            request.interpretation,
            request.decode_limits,
            &mut old_work
        )
        .err(),
        Some(DecodeError::Unsupported)
    );
    let refusal = RecordedDecodeRefusal {
        import_identity: retained.import_identity(),
        import_root: retained.import_root(),
        manifest_digest: retained.manifest_digest(),
        source_anchor: retained.authority_anchor().clone(),
        segment_index: 0,
        source_offset: retained.manifest().segment_spans[0].offset,
        capsule_digest,
        capsule,
        decoder: decoder_identity(),
        interpretation: request.interpretation,
        limits: limit_axes(request.decode_limits),
        kind: RefusalKind::Unsupported,
        work_units: old_work.used(),
        mask_policy: None,
    };
    let old_bytes = refusal.encoded()?;
    let manifest = refusal.manifest()?;
    let slot = refusal_slot(refusal.identity())?;
    for bytes in [encoded.as_slice(), old_bytes.as_slice()] {
        let digest = deployment.publisher_mut().stage_object(bytes)?;
        deployment.publisher_mut().verify_object(digest)?;
    }
    deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    deployment.publish_and_commit(&slot, &manifest, refusal.capsule.capture, &cx)?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    deployment.append_batch(
        refusal_batch(refusal.identity())?,
        vec![refusal.delta(manifest.root())?],
        children,
        &cx,
    )?;
    let old = RetainedRefusal::open_with_decoder(&deployment, &request, decoder_identity(), &cx)?;
    assert!(matches!(
        RetainedRefusal::open(&deployment, &request, &cx),
        Err(RecordedDecodeError::Unavailable)
    ));

    let CapsuleDecode::Decoded(current) = decode_capsule(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?
    else {
        return Err("new generation reused an old unsupported refusal".into());
    };
    assert_eq!(
        current.receipt().codec().decoder,
        progressive_decoder_identity()
    );
    assert_eq!(current.receipt().dimensions(), [37, 29]);
    assert_ne!(current.receipt().identity(), old.refusal().identity());
    assert_eq!(old.refusal().encoded()?, old_bytes);
    let anchor = deployment.current_anchor().clone();
    fs::remove_file(input)?;
    drop(deployment);

    let mut reopened = ReferenceDeployment::open(&root, SITE, &cx)?;
    let historical =
        RetainedRefusal::open_with_decoder(&reopened, &request, decoder_identity(), &cx)?;
    assert_eq!(historical, old);
    let mut replay = DecodeBudget::new(old_work.used());
    historical.verify_by_replay(&reopened, &request, &mut replay, &cx)?;
    assert_eq!(replay.used(), old_work.used());
    let restored = RecordedFrame::open(&reopened, &request, &cx)?;
    assert_eq!(restored, *current);
    restored.verify_by_replay(
        &reopened,
        &request,
        &mut DecodeBudget::new(current.receipt().work_units()),
        &cx,
    )?;
    let mut no_work = DecodeBudget::new(0);
    let CapsuleDecode::Decoded(repeated) =
        decode_capsule(&mut reopened, &request, &mut no_work, &cx)?
    else {
        return Err("repeat unexpectedly refused".into());
    };
    assert_eq!(*repeated, restored);
    assert_eq!(no_work.used(), 0);
    assert_eq!(*reopened.current_anchor(), anchor);

    let mut narrow = request;
    narrow.decode_limits.maximum_dimension = 36;
    let CapsuleDecode::Refused(bounds) = decode_capsule(
        &mut reopened,
        &narrow,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?
    else {
        return Err("progressive bound violation was not retained".into());
    };
    assert_eq!(bounds.refusal().decoder(), progressive_decoder_identity());
    assert_eq!(bounds.refusal().kind(), RefusalKind::Bounds);
    bounds.verify_by_replay(
        &reopened,
        &narrow,
        &mut DecodeBudget::new(bounds.refusal().work_units()),
        &cx,
    )?;
    Ok(())
}
