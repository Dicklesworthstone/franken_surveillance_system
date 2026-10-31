#![forbid(unsafe_code)]
//! Original ONNX -> verified FMPK -> native RGB model and retained-frame detection.
//! The tiny explicit-weight graph tests wiring and custody, never detector quality.

use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, Generation, ModelGeneration, OperationId, SensorId, StreamId,
    TimestampNs,
};
use fss_object::{ModelId, ModelPackageArchive, ModelPackageLimits};
use fss_reference::ingest::onnx_package::{
    ONNX_SOURCE_ARTIFACT, OnnxPackageError, OnnxPackageLimits, OnnxPackageRecipe,
    OnnxPackageRequest, import_onnx_package,
};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use fss_reference::ingest::rgb_package::{PackageHeadSpec, RgbDetectorPackage};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::preprocess::ResizeFilter;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = include_bytes!("fixtures/onnx_package/tiny_detector.onnx");
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
