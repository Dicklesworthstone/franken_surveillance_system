#![forbid(unsafe_code)]
//! Real retained source/codec/privacy owners feeding sealed native descriptors.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{
    BudgetVector, CanonicalEncode, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Request, STAGE_RECORDED_H264_SEGMENT,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
    retained_source_capsule,
};
use fss_reference::ingest::twin_localization::features::{
    RecordedFeatureReadBudget, RecordedFeatureRequest, RecordedFeatures, extract_recorded_features,
};
use fss_reference::ingest::twin_localization::{RecordedLocalizationSource, retained_exposure};
use fss_reference::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retained-feature-tests";
const PRINCIPAL: &str = "principal:retained-feature-tests";
const JPEG: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_q100.jpg");
const AVC: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/high_cropped.264");
const HEVC: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(tag: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retained-features-{tag}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-feature-tests".into(),
        operation_id: OperationId::parse("operation:retained-feature-tests")?,
        principal: principal.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
struct Fixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
    count: usize,
}
impl Fixture {
    fn new(tag: &str, bytes: &[u8], format: Option<FileFormatHint>) -> Test<Self> {
        let directory = Directory::new(tag)?;
        let root = directory.0.join("deployment");
        let cx = context(&root, PRINCIPAL)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let (identity, count) = import(&directory.0, &mut deployment, &cx, "one", bytes, format)?;
        Ok(Self {
            directory,
            root,
            cx,
            deployment,
            identity,
            count,
        })
    }
    fn extract(
        &mut self,
        source: RecordedLocalizationSource,
        budget: &RecordedFeatureReadBudget,
    ) -> Test<RecordedFeatures> {
        Ok(extract_recorded_features(
            &mut self.deployment,
            &request(source),
            budget,
            &mut DecodeBudget::new(100_000_000),
            &mut RecordedVideoDecodeBudget::with_separate_limits(256 * 1024 * 1024, 536_870_912)?,
            &mut WorkBudget::new(2_000_000_000),
            &self.cx,
        )?)
    }
    fn retained(&self) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(
            &self.deployment,
            self.identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?)
    }
}
fn import(
    directory: &Path,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
    label: &str,
    bytes: &[u8],
    format: Option<FileFormatHint>,
) -> Test<(ContentDigest, usize)> {
    let path = directory.join(format!("{label}.original"));
    fs::write(&path, bytes)?;
    let mut request = FileIngestRequest::new(
        &path,
        SensorId::parse(format!("sensor:retained-feature-{label}"))?,
        StreamId::parse(format!("stream:retained-feature-{label}"))?,
    )
    .with_receive_time(TimestampNs(10_000_000_000))
    .with_capture_hint(CaptureHint::new(
        TimestampNs(1_000_000_000),
        2_000_000,
        25.0,
    )?);
    request.format_hint = format;
    let receipt = FileIngestAdapter::ingest(request, cx, deployment)?;
    fs::remove_file(&path)?;
    assert!(!path.exists());
    Ok((
        receipt.import_identity,
        receipt.manifest.segment_spans.len(),
    ))
}
fn jpeg(identity: ContentDigest) -> RecordedLocalizationSource {
    RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
        import_identity: identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    })
}
fn video(f: &Fixture, hevc: bool, segment: usize) -> RecordedLocalizationSource {
    if hevc {
        RecordedLocalizationSource::H265 {
            request: RecordedH265Request {
                import_identity: f.identity,
                first_segment: 0,
                segment_count: f.count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decoder_limits: HevcLimits::default(),
            },
            segment,
        }
    } else {
        RecordedLocalizationSource::H264 {
            request: RecordedH264Request {
                import_identity: f.identity,
                first_segment: 0,
                segment_count: f.count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decoder_limits: AvcLimits::default(),
            },
            segment,
        }
    }
}
fn request(source: RecordedLocalizationSource) -> RecordedFeatureRequest {
    RecordedFeatureRequest {
        source,
        image_domain: ContentDigest::sha256(b"declared fixture image grid"),
        extraction: ExtractionOptions {
            maximum_features: 128,
            ..ExtractionOptions::default()
        },
    }
}
fn source_budget() -> RecordedFeatureReadBudget {
    RecordedFeatureReadBudget::new(4 * 1024 * 1024 * 1024)
}
fn revalidate(result: &RecordedFeatures, f: &Fixture) -> Test {
    result.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(2_000_000_000))?;
    Ok(())
}
fn mask(f: &mut Fixture, width: u32) -> Test {
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:retained-feature-one")?,
        [96, 96],
        &[[0, 0, width, 96]],
    )?;
    let preview = preview_mask(&f.deployment, &policy)?;
    declare_mask(&mut f.deployment, &policy, preview.approval, &f.cx)?;
    Ok(())
}

#[test]
fn actual_jpeg_features_bind_native_pixels_and_survive_later_publications_and_cold_open() -> Test {
    let mut f = Fixture::new("jpeg", JPEG, None)?;
    let budget = source_budget();
    let result = f.extract(jpeg(f.identity), &budget)?;
    assert!(!result.frame().features().is_empty());
    assert_eq!(result.selection().selected, result.frame().features().len());
    let original = retained_source_capsule(&f.deployment, &f.retained()?, 0)?;
    assert_eq!(result.capsule(), &original);
    assert_eq!(result.source().exposure, retained_exposure(&original)?);
    assert_eq!(result.source().encoded_source, original.source_digest);
    assert_eq!(
        result.source().decode_receipt,
        ContentDigest::sha256(result.native_receipt())
    );
    assert_eq!(
        result.frame().identity().pixels,
        result.source().luma.bytes()
    );
    let RecordedLocalizationSource::Jpeg(decode_request) = jpeg(f.identity) else {
        unreachable!()
    };
    let decoded = RecordedFrame::open(&f.deployment, &decode_request, &f.cx)?;
    let allowed = vec![1; decoded.pixels().len()];
    let mut work = WorkBudget::new(100_000_000);
    let image = GrayImage::new(
        result.frame().identity(),
        decoded.pixels(),
        &allowed,
        &mut work,
    )?;
    let oracle = extract_gray(&image, request(jpeg(f.identity)).extraction, &mut work)?;
    assert_eq!(result.frame().features(), oracle.frame.features());
    assert_eq!(result.selection(), oracle.selection);
    let before = f.deployment.current_anchor().clone();
    let (other, _) = import(&f.directory.0, &mut f.deployment, &f.cx, "two", JPEG, None)?;
    let _second = f.extract(jpeg(other), &budget)?;
    assert_ne!(f.deployment.current_anchor(), &before);
    revalidate(&result, &f)?;
    let wrong_principal = context(&f.root, "principal:another-authority")?;
    assert!(
        result
            .revalidate(
                &f.deployment,
                &wrong_principal,
                &mut WorkBudget::new(100_000_000)
            )
            .is_err()
    );
    drop(f.deployment);
    f.deployment = ReferenceDeployment::open(&f.root, SITE, &f.cx)?;
    revalidate(&result, &f)?;
    let retry = f.extract(jpeg(f.identity), &budget)?;
    assert_eq!(retry.digest(), result.digest());
    assert_eq!(retry.frame().features(), result.frame().features());
    Ok(())
}

#[test]
fn current_privacy_excludes_complete_descriptor_support_and_withdraws_older_features() -> Test {
    let mut f = Fixture::new("privacy", JPEG, None)?;
    let budget = source_budget();
    let before = f.extract(jpeg(f.identity), &budget)?;
    assert!(before.frame().features().iter().any(|p| p.pixel[0] < 48.5));
    mask(&mut f, 32)?;
    assert!(revalidate(&before, &f).is_err());
    let partial = f.extract(jpeg(f.identity), &budget)?;
    assert_eq!(partial.source().exposure, before.source().exposure);
    assert_ne!(partial.source().mask_binding, before.source().mask_binding);
    assert!(
        partial
            .frame()
            .features()
            .iter()
            .all(|p| p.pixel[0] >= 48.5)
    );
    mask(&mut f, 96)?;
    assert!(revalidate(&partial, &f).is_err());
    let full = f.extract(jpeg(f.identity), &budget)?;
    assert_eq!(full.selection().tested_centers, 0);
    assert_eq!(full.selection().selected, 0);
    assert!(full.frame().features().is_empty());
    assert_eq!(
        full.selection().mask_digest,
        ContentDigest::sha256(&vec![0; 96 * 96]).bytes()
    );
    Ok(())
}

#[test]
fn late_original_capsule_decode_and_pixel_corruption_is_never_repaired() -> Test {
    for kind in ["source", "capsule", "receipt", "pixels"] {
        let mut f = Fixture::new(kind, JPEG, None)?;
        let result = f.extract(jpeg(f.identity), &source_budget())?;
        let digest = match kind {
            "source" => f.retained()?.manifest().ordered_chunks[0],
            "capsule" => result.source().capsule,
            "receipt" => result.source().decode_receipt,
            _ => result.source().luma,
        };
        let path = f.deployment.publisher().spool().object_path(digest);
        let mut damaged = fs::read(&path)?;
        *damaged.last_mut().ok_or("empty retained envelope")? ^= 1;
        fs::write(&path, &damaged)?;
        let anchor = f.deployment.current_anchor().clone();
        assert!(revalidate(&result, &f).is_err(), "{kind}");
        assert_eq!(fs::read(&path)?, damaged);
        assert_eq!(f.deployment.current_anchor(), &anchor);
        fs::remove_file(&path)?;
        assert!(revalidate(&result, &f).is_err(), "missing {kind}");
        assert!(f.extract(jpeg(f.identity), &source_budget()).is_err());
        assert!(!path.exists(), "missing {kind} must not be recreated");
        assert_eq!(f.deployment.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn native_avc_and_hevc_select_original_coding_capsules_without_publication() -> Test {
    for hevc in [false, true] {
        let mut f = Fixture::new(
            if hevc { "hevc" } else { "avc" },
            if hevc { HEVC } else { AVC },
            Some(if hevc {
                FileFormatHint::Hevc
            } else {
                FileFormatHint::AnnexB
            }),
        )?;
        assert!((2..=64).contains(&f.count));
        let source = video(&f, hevc, 1);
        let before = f.deployment.current_anchor().clone();
        let result = f.extract(source, &source_budget())?;
        assert_eq!(result.source().codec, if hevc { "h265" } else { "h264" });
        assert_eq!(result.source().range_start, 0);
        assert_eq!(result.source().range_count, f.count as u64);
        assert_eq!(result.source().segment, 1);
        assert_eq!(result.source().decode_root, None);
        let capsule = retained_source_capsule(&f.deployment, &f.retained()?, 1)?;
        assert_eq!(result.capsule(), &capsule);
        assert_eq!(
            result.frame().identity().exposure,
            retained_exposure(&capsule)?.bytes()
        );
        assert_eq!(
            result.source().decode_receipt,
            ContentDigest::sha256(result.native_receipt())
        );
        revalidate(&result, &f)?;
        assert_eq!(f.deployment.current_anchor(), &before);
        // The selected picture already exists; every other range capsule must still be checked.
        let unselected = if f.count > 2 { f.count - 1 } else { 0 };
        let last = retained_source_capsule(&f.deployment, &f.retained()?, unselected)?;
        let last_digest = ContentDigest::sha256(&last.try_canonical_bytes()?);
        let path = f.deployment.publisher().spool().object_path(last_digest);
        fs::remove_file(&path)?;
        assert!(revalidate(&result, &f).is_err());
        assert!(!path.exists());
        assert_eq!(f.deployment.current_anchor(), &before);
    }
    Ok(())
}

#[test]
fn a_late_video_cancellation_or_invalid_range_never_returns_early_selected_features() -> Test {
    let mut f = Fixture::new("late-cancel", AVC, Some(FileFormatHint::AnnexB))?;
    let before = f.deployment.current_anchor().clone();
    let source = video(&f, false, 0);
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_RECORDED_H264_SEGMENT, f.count);
    assert!(f.extract(source, &source_budget()).is_err());
    assert_eq!(f.deployment.current_anchor(), &before);
    let mut f = Fixture::new("invalid-range", AVC, Some(FileFormatHint::AnnexB))?;
    let before = f.deployment.current_anchor().clone();
    let source = video(&f, false, f.count);
    let budget = source_budget();
    assert!(f.extract(source, &budget).is_err());
    assert_eq!(budget.used(), 0);
    assert_eq!(f.deployment.current_anchor(), &before);
    Ok(())
}

#[test]
fn source_allowance_is_shared_with_final_revalidation_and_cannot_be_renewed_by_cloning() -> Test {
    let mut f = Fixture::new("source-budget", JPEG, None)?;
    let budget = RecordedFeatureReadBudget::new(2 * JPEG.len() as u64);
    let result = f.extract(jpeg(f.identity), &budget)?;
    assert_eq!(budget.used(), 2 * JPEG.len() as u64);
    let before = f.deployment.current_anchor().clone();
    assert!(revalidate(&result, &f).is_err());
    assert!(f.extract(jpeg(f.identity), &budget.clone()).is_err());
    assert_eq!(budget.used(), 2 * JPEG.len() as u64);
    assert_eq!(f.deployment.current_anchor(), &before);
    Ok(())
}

#[test]
fn deadline_probe_refuses_before_source_work_and_after_downstream_computation() -> Test {
    let mut f = Fixture::new("deadline", JPEG, None)?;
    let cancelled = Arc::new(AtomicBool::new(true));
    let signal = cancelled.clone();
    let budget = RecordedFeatureReadBudget::with_cancellation_probe(
        1 << 30,
        Arc::new(move || signal.load(Ordering::Relaxed)),
    );
    let before = f.deployment.current_anchor().clone();
    assert!(f.extract(jpeg(f.identity), &budget).is_err());
    assert_eq!(budget.used(), 0);
    assert_eq!(f.deployment.current_anchor(), &before);
    cancelled.store(false, Ordering::Relaxed);
    let result = f.extract(jpeg(f.identity), &budget)?;
    let used = budget.used();
    cancelled.store(true, Ordering::Relaxed);
    assert!(revalidate(&result, &f).is_err());
    assert_eq!(budget.used(), used);
    Ok(())
}
