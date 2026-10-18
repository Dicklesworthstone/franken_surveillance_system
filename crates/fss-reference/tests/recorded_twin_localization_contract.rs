#![forbid(unsafe_code)]
//! Retained source/privacy -> native pixels -> actual twin poses, including native raw differential.

#[path = "../../fss-twin/tests/common/mod.rs"]
mod twin_fixture;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs};
use fss_geometry::{GeometryError, PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, DecodeLimits,
    RecordedDecodeError, RecordedDecodeRequest, RecordedFrame, retained_source_capsule};
use fss_reference::ingest::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use fss_reference::ingest::recorded_decode::h265::{DecoderLimits as H265Limits, RecordedH265Range, RecordedH265Request};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::twin_localization::*;
use fss_twin::{PropertyTwin};
use fss_twin::localization::*;
use fss_twin::localization::native::*;
use fss_twin::rectification::*;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_q100.jpg");
const QFIX: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_qfix.jpg");
const RAW: &[u8] = include_bytes!("../../fss-twin/tests/fixtures/brown_luma_96x96.gray");
const AVC: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/high_cropped.264");
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const UNSUPPORTED_AVC: &[u8] = include_bytes!("../../fss-codec-h264/tests/fixtures/decode/unsupported_high422.h264");
const HEVC: &[u8] = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");
const SITE: &str = "site:retained-localization";

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Test<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir().join(format!("fss-retained-localize-{tag}-{}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("scratch directory capacity".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-localize".into(),
        operation_id: OperationId::parse("operation:retained-localize")?,
        principal: "principal:retained-localize".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).storage_operations(65536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Imported {
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
    count: usize,
    directory: Scratch,
}
fn import(tag: &str, bytes: &[u8], format: Option<FileFormatHint>) -> Test<Imported> {
    let directory = Scratch::new(tag)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("original.media");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut request = FileIngestRequest::new(path.clone(), SensorId::parse("sensor:retained-localize")?,
        StreamId::parse("stream:retained-localize")?).with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = format;
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    fs::remove_file(path)?;
    Ok(Imported { cx, deployment, identity: receipt.import_identity,
        count: receipt.manifest.segment_spans.len(), directory })
}
fn jpeg(identity: ContentDigest) -> RecordedLocalizationSource {
    RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
        import_identity: identity, segment_index: 0, interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(), decode_limits: DecodeLimits::default(),
    })
}
fn options() -> ImageLocalizationOptions {
    ImageLocalizationOptions {
        extraction: ExtractionOptions { maximum_features: 200, ..ExtractionOptions::default() },
        matching: MatchOptions::default(),
        solving: PoseSolverOptions { ransac_trials: 0, ..PoseSolverOptions::default() },
    }
}
fn setup(exposure: [u8; 32]) -> Test<(PropertyTwin, LocalizationAtlas, RectificationSpec)> {
    let mut budget = WorkBudget::new(2_000_000_000);
    let twin = twin_fixture::twin(&[0.0], None)?;
    let mut state = 1973_u32;
    let pixels: Vec<u8> = (0..96 * 96).map(|_| {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        20 + ((state >> 16) % 180) as u8
    }).collect();
    let allowed = vec![1; pixels.len()];
    let gray = GrayImage::new(ImageIdentity { exposure, pixels: ContentDigest::sha256(&pixels).bytes(),
        image_domain: [9; 32], dimensions: [96, 96] }, &pixels, &allowed, &mut budget)?;
    let frame = extract_gray(&gray, options().extraction, &mut budget)?.frame;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for (i, point) in frame.features().iter().enumerate() {
        let depth = 6.0 + (i % 7) as f64 * 0.5;
        landmarks.push(AtlasLandmark { id: i as u64 + 1, physical_group: i as u64 + 1,
            feature: 0, world: [(point.pixel[0] - 48.0) * depth / 80.0,
                (point.pixel[1] - 48.0) * depth / 80.0, depth], evidence: [8; 32], error: None });
        bindings.push(AtlasBinding { landmark: i as u64 + 1, reference: 1, image_feature: point.id });
    }
    let atlas = LocalizationAtlas::new(&twin, landmarks, vec![AtlasReference { id: 1, frame }],
        bindings, &mut budget)?;
    let camera = PinholeIntrinsics::new(96, 96, 80.0, 80.0, 48.0, 48.0)?;
    Ok((twin, atlas, RectificationSpec { source: camera, target: camera,
        distortion: LensDistortion::BrownConrady { radial: [-0.1, 0.001, 0.0001],
            tangential: [0.001, -0.001] }, maximum_radius: 1.0, source_domain: [3; 32],
        calibration: [4; 32], range: LumaRange::Full }))
}
fn localize(imported: &mut Imported, source: &RecordedLocalizationSource,
    twin: &PropertyTwin, atlas: &LocalizationAtlas, image: RecordedImageMode) -> Test<RecordedLocalization>
{
    Ok(localize_recorded_frame(&mut imported.deployment, source, RecordedLocalizationPlan {
        twin, atlas, image, options: options(),
    }, &mut DecodeBudget::new(1_000_000_000), &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000), &imported.cx)?)
}
fn accurate_candidates(result: &ImageLocalization, maximum_center_error: f64) -> Test {
    let LocalizationOutcome::Candidates(search) = &result.localization.outcome else {
        return Err(format!("expected an admitted pose, got {:?}", result.localization.outcome).into());
    };
    assert_eq!(search.candidates().len(), 1);
    let c = &search.candidates()[0];
    assert!(c.rms_px() <= 0.5, "RMS {}", c.rms_px());
    for n in c.pose().center() { assert!(n.abs() < maximum_center_error, "center {:?}", c.pose().center()); }
    for (row, expected) in c.pose().rotation().into_iter().zip([[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]]) {
        for (a, b) in row.into_iter().zip(expected) { assert!((a-b).abs() < 0.02); }
    }
    Ok(())
}

#[test]
fn retained_q100_jpeg_localizes_against_the_raw_oracle_and_replays_after_cold_open() -> Test {
    let mut imported = import("jpeg-cold", JPEG, None)?;
    let (twin, atlas, spec) = setup([1; 32])?;
    let source = jpeg(imported.identity);
    let result = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
    accurate_candidates(result.result(), 0.05)?;
    assert!(result.result().localization.matches.correspondences.len() >= 16);
    assert_eq!(result.source().encoded_source, ContentDigest::sha256(JPEG));
    let RecordedLocalizationSource::Jpeg(request) = &source else { return Err("JPEG source".into()) };
    let frame = RecordedFrame::open(&imported.deployment, request, &imported.cx)?;
    assert_eq!(result.source().luma.bytes(), frame.receipt().codec().luma_sha256);
    assert_eq!(result.source().decode_receipt, frame.receipt().digest()?);
    assert_eq!(result.source().decode_root, Some(frame.publication_root()));
    assert_eq!(result.source().exposure, retained_exposure(frame.receipt().capsule())?);
    let errors: Vec<f64> = frame.pixels().iter().zip(RAW).map(|(a,b)| f64::from(a.abs_diff(*b))).collect();
    assert!(errors.iter().all(|v| *v <= 2.0));
    let mse = errors.iter().map(|v| v*v).sum::<f64>() / errors.len() as f64;
    assert!(10.0 * (255.0_f64.powi(2) / mse).log10() >= 55.0);
    let mut budget = WorkBudget::new(2_000_000_000);
    let allowed = vec![1; RAW.len()];
    let raw = RawGrayFrame::new(RawFrameIdentity { exposure: result.source().exposure.bytes(),
        storage: ContentDigest::sha256(RAW).bytes(), allowed_mask: ContentDigest::sha256(&allowed).bytes(),
        image_domain: spec.source_domain, calibration: spec.calibration, dimensions: [96, 96],
        row_stride: 96, range: LumaRange::Full }, RAW, &allowed, &mut budget)?;
    let plan = RectificationPlan::compile(spec, &mut budget)?;
    let oracle = localize_raw_frame(&atlas, &twin, &plan, &raw, options(), &mut budget)?;
    accurate_candidates(&oracle.result, 0.0001)?;
    assert_eq!(result.rectification().ok_or("rectification")?.map_digest, oracle.rectification.map_digest);
    assert_eq!(result.rectification().ok_or("rectification")?.source.exposure, oracle.rectification.source.exposure);
    assert_eq!(result.source().mask_policy, None);
    let bytes = result.encoded().to_vec();
    let anchor = imported.deployment.current_anchor().clone();
    let root = imported.directory.0.join("deployment");
    drop(imported.deployment);
    imported.deployment = ReferenceDeployment::reopen(&root, SITE, &imported.cx)?;
    let again = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
    assert_eq!(again.encoded(), bytes);
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert!(result.encoded().len() <= MAX_RECEIPT_BYTES);
    Ok(())
}

#[test]
fn current_privacy_excludes_entire_descriptor_support_and_starts_a_distinct_derivation() -> Test {
    let mut imported = import("privacy", JPEG, None)?;
    let (twin, atlas, spec) = setup([1; 32])?;
    let source = jpeg(imported.identity);
    let before = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse("sensor:retained-localize")?, [96,96], &[[0,0,96,96]])?;
    let approval = preview_mask(&imported.deployment, &policy)?.approval;
    declare_mask(&mut imported.deployment, &policy, approval, &imported.cx)?;
    let masked = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
    assert!(matches!(masked.result().localization.outcome, LocalizationOutcome::InsufficientMatches));
    assert_eq!(masked.result().selection.tested_centers, 0);
    assert_eq!(masked.result().selection.selected, 0);
    assert!(masked.result().localization.matches.decisions.is_empty());
    let rectification = masked.rectification().ok_or("rectification")?;
    assert_eq!(rectification.allowed_pixels, 0);
    assert_eq!(rectification.privacy_rejected, rectification.coverage.mapped);
    assert_eq!(masked.source().mask_policy, Some(policy.digest()));
    assert_eq!(masked.source().exposure, before.source().exposure);
    assert_ne!(masked.source().mask_binding, before.source().mask_binding);
    assert_ne!(masked.source().luma, before.source().luma);
    assert_ne!(masked.digest(), before.digest());
    // A one-pixel-wide exclusion through every candidate patch also admits no features.
    let policy = PrivacyMaskPolicy::new(SensorId::parse("sensor:retained-localize")?,
        [96,96], &[[16,0,1,96],[48,0,1,96],[80,0,1,96]])?;
    let approval = preview_mask(&imported.deployment, &policy)?.approval;
    declare_mask(&mut imported.deployment, &policy, approval, &imported.cx)?;
    let partial = localize(&mut imported, &source, &twin, &atlas,
        RecordedImageMode::Pinhole(LocalizationCamera { intrinsics: spec.source, image_domain: spec.source_domain }))?;
    assert_eq!(partial.result().selection.tested_centers, 0);
    assert!(matches!(partial.result().localization.outcome, LocalizationOutcome::InsufficientMatches));
    Ok(())
}

#[test]
fn source_or_decoded_custody_tamper_is_refused_even_after_a_successful_pose() -> Test {
    for source_tamper in [true, false] {
        let mut imported = import(if source_tamper { "source-tamper" } else { "luma-tamper" }, JPEG, None)?;
        let (twin, atlas, spec) = setup([1; 32])?;
        let source = jpeg(imported.identity);
        let result = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
        let retained = RetainedFileImport::open(&imported.deployment, imported.identity,
            RetainedReadLimits::default(), &imported.cx)?;
        let digest = if source_tamper { retained.manifest().ordered_chunks[0] } else { result.source().luma };
        fs::write(imported.deployment.publisher().spool().object_path(digest), b"corrupt retained object")?;
        let anchor = imported.deployment.current_anchor().clone();
        assert!(localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec)).is_err());
        assert_eq!(imported.deployment.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn reference_exposure_reuse_wrong_grid_and_invalid_lens_are_refused() -> Test {
    let mut imported = import("basis", JPEG, None)?;
    let source = jpeg(imported.identity);
    let retained = RetainedFileImport::open(&imported.deployment, imported.identity,
        RetainedReadLimits::default(), &imported.cx)?;
    let capsule = retained_source_capsule(&imported.deployment, &retained, 0)?;
    let (twin, atlas, spec) = setup(retained_exposure(&capsule)?.bytes())?;
    assert!(localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))
        .err().and_then(|e| e.downcast::<RecordedLocalizationError>().ok())
        .is_some_and(|e| matches!(*e, RecordedLocalizationError::Localization(LocalizationError::ReferenceExposure))));
    let (twin, atlas, mut spec) = setup([1;32])?;
    let bad_camera = PinholeIntrinsics::new(95,96,80.0,80.0,48.0,48.0)?;
    assert!(localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Pinhole(LocalizationCamera {
        intrinsics: bad_camera, image_domain: [9;32] })).is_err());
    spec.maximum_radius = f64::NAN;
    let anchor = imported.deployment.current_anchor().clone();
    assert!(localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec)).is_err());
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn work_exhaustion_and_both_cancellation_boundaries_return_no_proposal() -> Test {
    let mut imported = import("budgets", JPEG, None)?;
    let source = jpeg(imported.identity);
    let (twin, atlas, spec) = setup([1;32])?;
    let plan = RecordedLocalizationPlan { twin: &twin, atlas: &atlas, image: RecordedImageMode::Raw(spec), options: options() };
    let before = imported.deployment.current_anchor().clone();
    let cancelled = AtomicBool::new(true);
    for mut budget in [WorkBudget::new(1), WorkBudget::cancellable(2_000_000_000, &cancelled)] {
        assert!(matches!(localize_recorded_frame(&mut imported.deployment, &source, plan,
            &mut DecodeBudget::new(1_000_000_000), &mut RecordedVideoDecodeBudget::new(1_000_000_000),
            &mut budget, &imported.cx), Err(RecordedLocalizationError::Geometry(
                GeometryError::BudgetExhausted | GeometryError::Cancelled))));
        assert_eq!(imported.deployment.current_anchor(), &before);
    }
    imported.cx.set_cancel_at_checkpoint(STAGE_LOCALIZATION_COMPLETE);
    assert!(matches!(localize_recorded_frame(&mut imported.deployment, &source, plan,
        &mut DecodeBudget::new(1_000_000_000), &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000), &imported.cx), Err(RecordedLocalizationError::Cancelled)));
    let cancelled = context(&imported.directory.0.join("deployment"))?;
    cancelled.request_cancellation();
    assert!(matches!(localize_recorded_frame(&mut imported.deployment, &source, plan,
        &mut DecodeBudget::new(1_000_000_000), &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000), &cancelled), Err(RecordedLocalizationError::Cancelled)));
    Ok(())
}

#[test]
fn avc_and_hevc_select_original_coding_segments_despite_display_reordering() -> Test {
    for hevc in [false, true] {
        let mut imported = import(if hevc { "hevc" } else { "avc" }, if hevc { HEVC } else { AVC },
            Some(if hevc { FileFormatHint::Hevc } else { FileFormatHint::AnnexB }))?;
        let (twin, atlas, _) = setup([1;32])?;
        let selected = 1;
        let source;
        let mut order = Vec::new();
        let mut expected = None;
        if hevc {
            let request = RecordedH265Request { import_identity: imported.identity, first_segment: 0,
                segment_count: imported.count, interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(), decoder_limits: H265Limits::default() };
            let mut range = RecordedH265Range::open(&imported.deployment, request.clone(), &imported.cx)?;
            while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
                order.push(frame.segment_index());
                if frame.segment_index() == selected as u64 { expected = Some((frame.receipt().digest(),
                    frame.receipt().luma_sha256(), frame.dimensions())); }
            }
            source = RecordedLocalizationSource::H265 { request, segment: selected };
        } else {
            let request = RecordedH264Request { import_identity: imported.identity, first_segment: 0,
                segment_count: imported.count, interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(), decoder_limits: DecoderLimits::default() };
            let mut range = RecordedH264Range::open(&imported.deployment, request.clone(), &imported.cx)?;
            while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
                order.push(frame.segment_index());
                if frame.segment_index() == selected as u64 { expected = Some((frame.receipt().digest(),
                    frame.receipt().luma_sha256(), frame.dimensions())); }
            }
            source = RecordedLocalizationSource::H264 { request, segment: selected };
        }
        let mut sorted = order.clone(); sorted.sort_unstable();
        assert_ne!(order, sorted, "fixture must actually reorder display output");
        let (receipt, luma, [w,h]) = expected.ok_or("selected original picture")?;
        let image = RecordedImageMode::Pinhole(LocalizationCamera {
            intrinsics: PinholeIntrinsics::new(w,h,80.0,80.0,w as f64/2.0,h as f64/2.0)?, image_domain: [9;32] });
        let anchor = imported.deployment.current_anchor().clone();
        let result = localize(&mut imported, &source, &twin, &atlas, image)?;
        assert_eq!(result.source().segment, selected as u64);
        assert_eq!(result.source().decode_receipt, receipt);
        assert_eq!(result.source().luma, luma);
        assert_eq!(result.source().range_count, imported.count as u64);
        assert!(result.source().decode_root.is_none());
        assert_eq!(imported.deployment.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn later_unsupported_video_access_unit_refuses_the_entire_selected_picture_proposal() -> Test {
    let bytes = [BASELINE, UNSUPPORTED_AVC].concat();
    let mut imported = import("late-avc-refusal", &bytes, Some(FileFormatHint::AnnexB))?;
    let (twin, atlas, spec) = setup([1;32])?;
    let source = RecordedLocalizationSource::H264 { segment: 0, request: RecordedH264Request {
        import_identity: imported.identity, first_segment: 0, segment_count: imported.count,
        interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
        decoder_limits: DecoderLimits::default(),
    }};
    let anchor = imported.deployment.current_anchor().clone();
    let result = localize_recorded_frame(&mut imported.deployment, &source, RecordedLocalizationPlan {
        twin: &twin, atlas: &atlas, image: RecordedImageMode::Pinhole(LocalizationCamera {
            intrinsics: spec.source, image_domain: [9;32] }), options: options(),
    }, &mut DecodeBudget::new(1_000_000_000), &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000), &imported.cx);
    assert!(matches!(result, Err(RecordedLocalizationError::Decode(RecordedDecodeError::H264(_)))));
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn realistic_quantization_keeps_an_explicit_native_outcome() -> Test {
    let mut imported = import("qfix", QFIX, None)?;
    let (twin, atlas, spec) = setup([1;32])?;
    let source = jpeg(imported.identity);
    let result = localize(&mut imported, &source, &twin, &atlas, RecordedImageMode::Raw(spec))?;
    if matches!(result.result().localization.outcome, LocalizationOutcome::Candidates(_)) {
        accurate_candidates(result.result(), 0.10)?;
    }
    assert_eq!(result.source().encoded_source, ContentDigest::sha256(QFIX));
    assert!(result.encoded().len() <= MAX_RECEIPT_BYTES);
    Ok(())
}
