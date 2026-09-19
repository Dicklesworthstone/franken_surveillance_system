#![forbid(unsafe_code)]

use super::*;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use crate::ingest::{FileIngestAdapter, FileIngestRequest};

const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!("fss-recorded-decode-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn context(root: &std::path::Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-decode".to_owned(),
        operation_id: OperationId::parse("operation:recorded-decode")?,
        principal: "principal:recorded-decode".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()], deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(4096).build()?,
        privacy_scope: "privacy:test".to_owned(), retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-decode"), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}

fn fixture(name: &str) -> TestResult<(OwnedDirectory, ReplayCx, ReferenceDeployment, RecordedDecodeRequest)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("source.mjpeg");
    fs::write(&path, [JPEG, JPEG].concat())?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-decode", &cx)?;
    let request = FileIngestRequest::new(path, SensorId::parse("sensor:recorded-decode")?, StreamId::parse("stream:recorded-decode")?)
        .with_receive_time(TimestampNs(1_000_000_000));
    let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    let request = RecordedDecodeRequest {
        import_identity: imported.import_identity, segment_index: 1,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(), decode_limits: DecodeLimits::default(),
    };
    Ok((directory, cx, deployment, request))
}

#[test]
fn decode_restart_and_replay_need_no_original_file() -> TestResult {
    let (directory, cx, mut deployment, request) = fixture("restart")?;
    let decoded = RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    assert_eq!(decoded.receipt().codec().encoded_sha256, ContentDigest::sha256(JPEG).bytes());
    assert_eq!(decoded.receipt().capsule().clock_basis, fss_core::ClockBasis::Estimated);
    assert_eq!(decoded.receipt().capsule().capture.earliest, TimestampNs(0));
    assert_eq!(decoded.receipt().capsule().capture.latest, TimestampNs(1_000_000_000));
    assert!(decoded.pgm_bytes().starts_with(b"P5\n"));
    assert!(decoded.receipt().work_units() > 0);
    assert_eq!(decoded.receipt().codec().luma_sha256, ContentDigest::sha256(decoded.pixels()).bytes());
    let source_anchor = decoded.receipt().source_anchor().clone();
    assert!(decoded.authority_anchor().commit_sequence > source_anchor.commit_sequence);
    let final_anchor = deployment.current_anchor().clone();
    fs::remove_file(directory.0.join("source.mjpeg"))?;
    drop(deployment);
    let mut reopened = ReferenceDeployment::open(&directory.0.join("deployment"), "site:recorded-decode", &cx)?;
    let restored = RecordedFrame::open(&reopened, &request, &cx)?;
    assert_eq!(restored, decoded);
    restored.verify_by_replay(&reopened, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    assert_eq!(*reopened.current_anchor(), final_anchor);
    let retried = RecordedFrame::decode_and_publish(&mut reopened, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    assert_eq!(retried, decoded);
    assert_eq!(*reopened.current_anchor(), final_anchor);
    Ok(())
}

#[test]
fn identical_pixels_do_not_merge_distinct_source_capsules() -> TestResult {
    let (_directory, cx, mut deployment, mut request) = fixture("lineage")?;
    let mut budget = DecodeBudget::new(100_000_000);
    request.segment_index = 0;
    let first = RecordedFrame::decode_and_publish(&mut deployment, &request, &mut budget, &cx)?;
    request.segment_index = 1;
    let second = RecordedFrame::decode_and_publish(&mut deployment, &request, &mut budget, &cx)?;
    assert_eq!(first.pixels(), second.pixels());
    assert_ne!(first.receipt().identity(), second.receipt().identity());
    assert_ne!(first.receipt().capsule().capsule_id, second.receipt().capsule().capsule_id);
    assert_ne!(first.publication_root(), second.publication_root());
    assert_eq!(budget.used(), first.receipt().work_units() + second.receipt().work_units());
    assert!(deployment.ledger().batches().iter().flat_map(|b| &b.deltas)
        .filter(|d| d.family == "decode_receipt").all(|d| d.plane == Plane::Cognition));
    Ok(())
}

#[test]
fn budget_limits_and_wrong_interpretation_publish_nothing() -> TestResult {
    let (_directory, cx, mut deployment, request) = fixture("refuse")?;
    let before = deployment.current_anchor().clone();
    assert!(matches!(RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(0), &cx),
        Err(RecordedDecodeError::Codec(DecodeError::BudgetExhausted))));
    let mut bounded = request.clone(); bounded.decode_limits.maximum_pixels = 1;
    assert!(RecordedFrame::decode_and_publish(&mut deployment, &bounded, &mut DecodeBudget::new(100_000_000), &cx).is_err());
    let mut wrong = request.clone(); wrong.interpretation = ComponentInterpretation::YCbCr;
    assert!(RecordedFrame::decode_and_publish(&mut deployment, &wrong, &mut DecodeBudget::new(100_000_000), &cx).is_err());
    let mut invalid = request.clone(); invalid.decode_limits.maximum_bytes = 17 * 1024 * 1024;
    assert!(matches!(RecordedFrame::decode_and_publish(&mut deployment, &invalid, &mut DecodeBudget::new(100_000_000), &cx), Err(RecordedDecodeError::Limit)));
    assert_eq!(*deployment.current_anchor(), before);
    assert!(matches!(RecordedFrame::open(&deployment, &request, &cx), Err(RecordedDecodeError::Unavailable)));
    Ok(())
}

#[test]
fn owner_cancelled_codec_exposes_no_pixels_or_authority() -> TestResult {
    let (_directory, cx, mut deployment, request) = fixture("codec-cancel")?;
    let before = deployment.current_anchor().clone();
    let cancel = AtomicBool::new(true);
    let mut budget = DecodeBudget::cancellable(100_000_000, &cancel);
    assert!(matches!(RecordedFrame::decode_and_publish(&mut deployment, &request, &mut budget, &cx),
        Err(RecordedDecodeError::Codec(DecodeError::Cancelled))));
    assert_eq!(*deployment.current_anchor(), before);
    assert_eq!(budget.used(), 0);
    Ok(())
}

#[test]
fn cancellation_after_decode_prevents_any_derivative_publication() -> TestResult {
    let (_directory, cx, mut deployment, request) = fixture("before-publish")?;
    let before = deployment.current_anchor().clone();
    cx.set_cancel_at_checkpoint(STAGE_RECORDED_DECODE);
    assert!(matches!(RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx), Err(RecordedDecodeError::Cancelled)));
    assert_eq!(*deployment.current_anchor(), before);
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn interrupted_root_to_receipt_transition_resumes_without_duplicate_decode_claims() -> TestResult {
    let (directory, cx, mut deployment, request) = fixture("resume")?;
    cx.set_cancel_at_checkpoint(STAGE_RECORDED_DECODE_COMMIT);
    assert!(matches!(RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx), Err(RecordedDecodeError::Cancelled)));
    assert!(!deployment.ledger().batches().iter().flat_map(|b| &b.deltas).any(|d| d.family == "decode_receipt"));
    drop(deployment);
    let cx = context(&directory.0.join("deployment"))?;
    let mut deployment = ReferenceDeployment::open(&directory.0.join("deployment"), "site:recorded-decode", &cx)?;
    assert!(matches!(RecordedFrame::open(&deployment, &request, &cx), Err(RecordedDecodeError::Unavailable)));
    let decoded = RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    assert_eq!(RecordedFrame::open(&deployment, &request, &cx)?, decoded);
    assert_eq!(deployment.ledger().batches().iter().flat_map(|b| &b.deltas).filter(|d| d.family == "decode_receipt").count(), 1);
    Ok(())
}

#[test]
fn receipt_binary_roundtrip_and_all_truncations_fail_closed() -> TestResult {
    let (_directory, cx, mut deployment, request) = fixture("format")?;
    let frame = RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    let receipt = frame.receipt();
    let bytes = receipt.encoded()?;
    assert_eq!(RecordedDecodeReceipt::decode(&bytes, receipt.digest()?)?, *receipt);
    for end in 0..bytes.len() {
        let shortened = &bytes[..end];
        assert!(RecordedDecodeReceipt::decode(shortened, ContentDigest::sha256(shortened)).is_err());
    }
    let mut suffix = bytes.clone(); suffix.push(0);
    assert!(RecordedDecodeReceipt::decode(&suffix, ContentDigest::sha256(&suffix)).is_err());
    let mut unknown_version = bytes.clone(); unknown_version[19] = 2;
    assert!(RecordedDecodeReceipt::decode(&unknown_version, ContentDigest::sha256(&unknown_version)).is_err());
    assert!(RecordedDecodeReceipt::decode(&bytes, ContentDigest::sha256(b"another receipt")).is_err());
    let mut forged = receipt.clone(); forged.width = 4097;
    assert!(forged.encoded().is_err());
    let mut forged = receipt.clone(); forged.codec.encoded_sha256 = [1; 32];
    assert!(forged.encoded().is_err());
    Ok(())
}

#[test]
fn reads_do_not_substitute_another_recipe_or_broaden_pixel_bounds() -> TestResult {
    let (_directory, cx, mut deployment, request) = fixture("read-bounds")?;
    RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
    let before = deployment.current_anchor().clone();
    let mut wrong = request.clone(); wrong.segment_index = 0;
    assert!(matches!(RecordedFrame::open(&deployment, &wrong, &cx), Err(RecordedDecodeError::Unavailable)));
    wrong = request.clone(); wrong.interpretation = ComponentInterpretation::YCbCr;
    assert!(matches!(RecordedFrame::open(&deployment, &wrong, &cx), Err(RecordedDecodeError::Unavailable)));
    wrong = request.clone(); wrong.decode_limits.maximum_pixels = 1;
    assert!(matches!(RecordedFrame::open(&deployment, &wrong, &cx), Err(RecordedDecodeError::Limit)));
    assert_eq!(*deployment.current_anchor(), before);
    Ok(())
}
