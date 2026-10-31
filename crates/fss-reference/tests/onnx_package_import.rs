#![forbid(unsafe_code)]
//! Original ONNX -> verified FMPK -> native RGB model and retained-frame detection.
//! The tiny explicit-weight graph tests wiring and custody, never detector quality.

use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, Generation, ModelGeneration, OperationId, SensorId, StreamId,
    TimestampNs,
};
use fss_model_ir::{OnnxChannelOrder, OnnxImageTransform};
use fss_object::{ModelId, ModelPackageArchive, ModelPackageLimits};
use fss_reference::ingest::onnx_package::{
    ONNX_SOURCE_ARTIFACT, OnnxPackageError, OnnxPackageLimits, OnnxPackageRecipe,
    OnnxPackageRequest, import_onnx_package,
};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, project_rgb_detections};
use fss_reference::ingest::rgb_inference::{RgbInference, RgbRunLimits, RgbSourceBinding};
use fss_reference::ingest::rgb_package::{PackageHeadSpec, RgbDetectorPackage};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::preprocess::ResizeFilter;
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = include_bytes!("fixtures/onnx_package/tiny_detector.onnx");
const NORMALIZATION_SOURCE: &[u8] =
    include_bytes!("fixtures/onnx_package/normalization_detector.onnx");
const LICENSE: &[u8] = include_bytes!("fixtures/onnx_package/LICENSE");
const NOTICE: &[u8] = include_bytes!("fixtures/onnx_package/NOTICE");
const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Test<Self> {
        for i in 0..100_u32 {
            let p = std::env::temp_dir().join(format!(
                "fss-onnx-package-{name}-{}-{i}",
                std::process::id()
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onnx-package-test".into(),
        operation_id: OperationId::parse("operation:onnx-package-test")?,
        principal: "principal:onnx-package-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 << 20)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"onnx-package-test"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&auth, root.to_path_buf())?)
}
fn recipe() -> Test<OnnxPackageRecipe> {
    Ok(OnnxPackageRecipe {
        model_id: ModelId::parse("MOD-ONNXFIXTURE-001")?,
        model_generation: ModelGeneration::parse("model:onnx-detector-fixture:g1")?,
        tensor_generation: Generation(1),
        image_input: "image".into(),
        target: [1, 1],
        filter: ResizeFilter::Nearest,
        letterbox_pad: 0,
        masked_rgb: [0; 3],
        scale_to_unit: false,
        image_transform: None,
        head: PackageHeadSpec {
            output_port: "head".into(),
            layout: HeadLayout::Rows,
            boxes: HeadBoxes::PixelCorners,
            class_score: HeadScore::Probability,
            objectness: None,
            classes: HeadClasses::Best,
            minimum_score_ppm: 500_000,
            nms_iou_ppm: 450_000,
            maximum_rows: 1,
            maximum_candidates: 4,
            maximum_detections: 4,
        },
        labels: vec!["fixture-object".into(), "fixture-other".into()],
        upstream: "fixture:fss/native-onnx-detector".into(),
        revision: "v1".into(),
        producer: "FSS test-only numerical fixture".into(),
        license_id: "MIT".into(),
        use_approved: true,
        restrictions: Vec::new(),
    })
}
fn request(recipe: &OnnxPackageRecipe) -> OnnxPackageRequest<'_> {
    OnnxPackageRequest {
        source: SOURCE,
        source_digest: ContentDigest::sha256(SOURCE),
        license: LICENSE,
        license_digest: ContentDigest::sha256(LICENSE),
        notice: NOTICE,
        notice_digest: ContentDigest::sha256(NOTICE),
        recipe,
    }
}

#[test]
fn exact_source_closed_archive_reopens_with_identical_model_and_contract() -> Test {
    let d = Directory::new("roundtrip")?;
    let cx = context(&d.0)?;
    let scalar = ScalarExecCx::new();
    let r = recipe()?;
    let first = import_onnx_package(&request(&r), OnnxPackageLimits::default(), &cx, &scalar)?;
    let second = import_onnx_package(&request(&r), OnnxPackageLimits::default(), &cx, &scalar)?;
    assert_eq!(first.archive(), second.archive());
    let decoded = ModelPackageArchive::decode(first.archive(), &ModelPackageLimits::default())?;
    let original = decoded
        .artifacts
        .values()
        .find(|a| a.name == ONNX_SOURCE_ARTIFACT)
        .ok_or("source artifact")?;
    assert_eq!(original.payload, SOURCE);
    assert_eq!(original.digest, ContentDigest::sha256(SOURCE));
    assert!(
        decoded
            .manifest
            .license()
            .artifact_digests()
            .contains(&original.digest)
    );
    let loaded = RgbDetectorPackage::load(
        first.archive(),
        first.package().archive_digest(),
        1 << 32,
        &cx,
        &scalar,
    )?;
    assert_eq!(loaded.model().digest(), first.package().model().digest());
    assert_eq!(
        loaded.contract().digest(),
        first.package().contract().digest()
    );
    assert_eq!(loaded.spec().source.opset, 13);
    assert_eq!(
        loaded.spec().source.source_sha256,
        ContentDigest::sha256(SOURCE)
    );
    assert_eq!(
        loaded.model().graph().outputs()[0].shape().dims(),
        [1, 1, 6]
    );
    let exact = OnnxPackageLimits {
        package_bytes: first.archive().len(),
        ..OnnxPackageLimits::default()
    };
    assert_eq!(
        import_onnx_package(&request(&r), exact, &cx, &scalar)?.archive(),
        first.archive()
    );
    assert!(matches!(
        import_onnx_package(
            &request(&r),
            OnnxPackageLimits {
                package_bytes: first.archive().len() - 1,
                ..exact
            },
            &cx,
            &scalar
        ),
        Err(OnnxPackageError::Limit)
    ));
    Ok(())
}

#[test]
fn pins_head_shapes_license_and_cancellation_fail_before_export() -> Test {
    let d = Directory::new("refusals")?;
    let cx = context(&d.0)?;
    let scalar = ScalarExecCx::new();
    let r = recipe()?;
    for which in 0..3 {
        let mut q = request(&r);
        match which {
            0 => q.source_digest = ContentDigest::sha256(b"other source"),
            1 => q.license_digest = ContentDigest::sha256(b"other license"),
            _ => q.notice_digest = ContentDigest::sha256(b"other notice"),
        }
        assert!(import_onnx_package(&q, OnnxPackageLimits::default(), &cx, &scalar).is_err());
    }
    for which in 0..6 {
        let mut bad = recipe()?;
        match which {
            0 => bad.target = [2, 2],
            1 => bad.head.output_port = "missing".into(),
            2 => bad.labels.pop().map(|_| ()).unwrap_or(()),
            3 => bad.head.objectness = Some(HeadScore::Probability),
            4 => bad.head.layout = HeadLayout::Channels,
            _ => bad.image_input = "weights".into(),
        }
        assert!(matches!(
            import_onnx_package(&request(&bad), OnnxPackageLimits::default(), &cx, &scalar),
            Err(OnnxPackageError::Recipe(_))
        ));
    }
    let mut unapproved = recipe()?;
    unapproved.use_approved = false;
    assert!(
        import_onnx_package(
            &request(&unapproved),
            OnnxPackageLimits::default(),
            &cx,
            &scalar
        )
        .is_err()
    );
    for which in 0..4 {
        let mut oversized = recipe()?;
        match which {
            0 => oversized.license_id = "a".repeat(129),
            1 => oversized.upstream = "a".repeat(257),
            2 => oversized.revision = "a".repeat(129),
            _ => oversized.restrictions = vec!["restriction".into(); 65],
        }
        assert!(matches!(
            import_onnx_package(
                &request(&oversized),
                OnnxPackageLimits::default(),
                &cx,
                &scalar
            ),
            Err(OnnxPackageError::Recipe(_))
        ));
    }
    let mut forbidden = recipe()?;
    forbidden.license_id = "CC-BY-NC-4.0".into();
    assert!(
        import_onnx_package(
            &request(&forbidden),
            OnnxPackageLimits::default(),
            &cx,
            &scalar
        )
        .is_err()
    );
    assert!(
        import_onnx_package(
            &request(&r),
            OnnxPackageLimits {
                verification_work: 0,
                ..OnnxPackageLimits::default()
            },
            &cx,
            &scalar
        )
        .is_err()
    );
    scalar.request_cancellation();
    assert!(matches!(
        import_onnx_package(&request(&r), OnnxPackageLimits::default(), &cx, &scalar),
        Err(OnnxPackageError::Cancelled)
    ));
    assert!(scalar.is_drain_completed());
    Ok(())
}

#[test]
fn imported_package_runs_existing_retained_jpeg_detection_without_activation() -> Test {
    let d = Directory::new("detection")?;
    let root = d.0.join("deployment");
    let cx = context(&root)?;
    let scalar = ScalarExecCx::new();
    let r = recipe()?;
    let package = import_onnx_package(&request(&r), OnnxPackageLimits::default(), &cx, &scalar)?;
    let path = d.0.join("source.mjpeg");
    fs::write(&path, JPEG)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:onnx-package", &cx)?;
    let source = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:onnx-package")?,
        StreamId::parse("stream:onnx-package")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    let identity = FileIngestAdapter::ingest(source, &cx, &mut deployment)?.import_identity;
    let before = deployment.current_anchor().clone();
    let report = run_package_detection(
        &deployment,
        package.package(),
        &PackageDetectRequest {
            import_identity: identity,
            first_segment: 0,
            segment_count: 1,
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &cx,
        &scalar,
    )?;
    assert_eq!(*deployment.current_anchor(), before);
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.frames[0].detections.detections().len(), 1);
    assert_eq!(report.frames[0].detections.detections()[0].class_index(), 0);
    assert!(
        report
            .json
            .contains(&package.package().archive_digest().to_string())
    );
    assert!(report.json.contains("\"quality_claim\":\"none\""));
    Ok(())
}

fn normalization_recipe() -> Test<OnnxPackageRecipe> {
    let mut recipe = recipe()?;
    recipe.model_id = ModelId::parse("MOD-ONNXNORMFIXTURE-001")?;
    recipe.model_generation = ModelGeneration::parse("model:onnx-normalization-fixture:g1")?;
    recipe.target = [2, 2];
    recipe.scale_to_unit = true;
    recipe.image_transform = Some(OnnxImageTransform {
        channel_order: OnnxChannelOrder::Bgr,
        mean: [0.1, 0.2, 0.3],
        standard_deviation: [0.25, 0.5, 0.75],
    });
    recipe.masked_rgb = [51, 102, 153];
    Ok(recipe)
}
fn normalization_request(recipe: &OnnxPackageRecipe) -> OnnxPackageRequest<'_> {
    let mut request = request(recipe);
    request.source = NORMALIZATION_SOURCE;
    request.source_digest = ContentDigest::sha256(NORMALIZATION_SOURCE);
    request
}
fn run_pixels(package: &RgbDetectorPackage, pixels: &[u8], mask: &[u8]) -> Test<RgbInference> {
    let encoded = ContentDigest::sha256(pixels).bytes();
    let source = RgbSourceBinding {
        encoded_sha256: encoded,
        exposure: [1; 32],
        camera: 1,
        clock: 1,
        capture: [1, 2],
        image_domain: [2; 32],
        calibration: [3; 32],
        permission_mask: ContentDigest::sha256(mask).bytes(),
    };
    // This entrypoint expressly admits caller-attested RGB, and records rather than
    // authenticates the synthetic decoder identity. No JPEG decode is claimed here.
    let receipt = RgbDecodeReceipt {
        encoded_sha256: encoded,
        rgb_sha256: encoded,
        decoder: ContentDigest::sha256(b"fixture:explicit-rgb-pixels").bytes(),
        interpretation: ComponentInterpretation::YCbCr,
        dimensions: [2, 2],
        mcus: 0,
        entropy_blocks: 0,
        restarts: 0,
        metadata_segments: 0,
        metadata_bytes: 0,
    };
    Ok(package.model().run_rgb_pixels(
        pixels,
        receipt,
        source,
        mask,
        RgbRunLimits {
            decode: Default::default(),
            preprocess: ExecBudget::new(1_000_000, 1 << 20),
            execution: ExecBudget::new(1_000_000, 1 << 20),
            maximum_output_bytes: 4096,
        },
        &ScalarExecCx::new(),
    )?)
}

#[test]
fn normalized_package_reopens_source_and_executes_bgr_pixel_and_detector_oracles() -> Test {
    let directory = Directory::new("normalization")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = normalization_recipe()?;
    let imported = import_onnx_package(
        &normalization_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let archive = ModelPackageArchive::decode(imported.archive(), &ModelPackageLimits::default())?;
    let source = archive
        .artifacts
        .values()
        .find(|a| a.name == ONNX_SOURCE_ARTIFACT)
        .ok_or("source")?;
    assert_eq!(source.payload, NORMALIZATION_SOURCE);
    assert_eq!(source.digest, ContentDigest::sha256(NORMALIZATION_SOURCE));
    assert!(
        archive
            .manifest
            .license()
            .artifact_digests()
            .contains(&source.digest)
    );
    let loaded = RgbDetectorPackage::load(
        imported.archive(),
        ContentDigest::sha256(imported.archive()),
        1 << 32,
        &cx,
        &scalar,
    )?;
    assert_eq!(loaded.model().digest(), imported.package().model().digest());
    let pixels = [10, 50, 90, 20, 100, 180, 30, 150, 210, 40, 200, 240];
    let result = run_pixels(&loaded, &pixels, &[1; 4])?;
    let mut expected = Vec::new();
    let mut means = [0.0_f32; 3];
    for (channel, rgb_channel) in [2, 1, 0].into_iter().enumerate() {
        for pixel in 0..4 {
            let value = f32::from(pixels[pixel * 3 + rgb_channel]) * (1.0_f32 / 255.0_f32);
            let normalized =
                (value - [0.1_f32, 0.2, 0.3][channel]) / [0.25_f32, 0.5, 0.75][channel];
            expected.push(normalized);
            means[channel] += normalized;
        }
        means[channel] /= 4.0_f32;
    }
    assert_eq!(result.outputs()["model_pixels"].values(), expected);
    // Authored dense fixture uses all three normalized channels, in this exact F32 order.
    let first = ((0.0_f32 + means[0] * 0.125) + means[1] * 0.0) + means[2] * 0.0625 + 0.6;
    let second = ((0.0_f32 + means[0] * 0.0) + means[1] * 0.125) + means[2] * -0.0625 + 0.4;
    assert_eq!(
        result.outputs()["head"].values(),
        [0.0, 0.0, 2.0, 2.0, first, second]
    );
    let detection = project_rgb_detections(
        &result,
        loaded.contract(),
        &[1; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(detection.detections().len(), 1);
    assert_eq!(detection.detections()[0].class_index(), 0);
    assert_eq!(detection.detections()[0].score().to_bits(), first.to_bits());
    assert_eq!(detection.detections()[0].bounds(), [0, 0, 512, 512]);
    let again = import_onnx_package(
        &normalization_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    assert_eq!(again.archive(), imported.archive());
    Ok(())
}

#[test]
fn normalization_occurs_after_rgb_privacy_replacement_and_invalid_recipes_refuse() -> Test {
    let directory = Directory::new("normalization-mask")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = normalization_recipe()?;
    let imported = import_onnx_package(
        &normalization_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let pixels = [10, 50, 90, 20, 100, 180, 30, 150, 210, 40, 200, 240];
    let mut changed = pixels;
    changed[3..6].copy_from_slice(&[255, 7, 23]);
    let mask = [1, 0, 1, 1];
    let a = run_pixels(imported.package(), &pixels, &mask)?;
    let b = run_pixels(imported.package(), &changed, &mask)?;
    assert_eq!(a.output_digest(), b.output_digest());
    assert_eq!(a.masked_digest(), b.masked_digest());
    assert_ne!(a.identity(), b.identity());
    let model_pixels = a.outputs()["model_pixels"].values();
    for (channel, byte) in [153_u8, 102, 51].into_iter().enumerate() {
        let expected = (f32::from(byte) * (1.0_f32 / 255.0_f32) - [0.1_f32, 0.2, 0.3][channel])
            / [0.25_f32, 0.5, 0.75][channel];
        assert_eq!(model_pixels[channel * 4 + 1].to_bits(), expected.to_bits());
    }
    for bad in [0.0, -1.0, f32::NAN, f32::INFINITY, f32::from_bits(1)] {
        let mut invalid = recipe.clone();
        invalid
            .image_transform
            .as_mut()
            .ok_or("transform")?
            .standard_deviation[0] = bad;
        assert!(matches!(
            import_onnx_package(
                &normalization_request(&invalid),
                OnnxPackageLimits::default(),
                &cx,
                &scalar
            ),
            Err(OnnxPackageError::Recipe(_))
        ));
    }
    Ok(())
}
