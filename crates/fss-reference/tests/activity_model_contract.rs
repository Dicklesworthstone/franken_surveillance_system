#![forbid(unsafe_code)]
//! The first-party activity model package (fss-2h5zq.49 / fss-2h5zq.50).
//!
//! Covers builder determinism against the committed package, verification and the refusal paths
//! (archive tamper, re-pinned tamper of weights, graph and spec, license denial, wrong
//! generation, cancellation), hand-computed preprocessing and score goldens, and the guard that
//! refuses comparing scores across generations or model identities.

use std::error::Error;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, RgbDecodeReceipt, decode_rgb};
use fss_core::{
    CalibrationGeneration, ContentDigest, DigestAlgorithm, ModelGeneration, SchemaId, SensorId,
};
use fss_model_ir::{compute_model_ir_digest, encode_canonical_model_ir};
use fss_object::{
    ModelId, ModelLicensePolicy, ModelLicensePolicyError, ModelLicenseRecord, ModelManifestV1,
    ModelPackage, ModelPackageArchive, ModelPackageArtifact, ModelPackageLimits, ModelUseProfile,
};
use fss_reference::ExecBudget;
use fss_reference::ScalarExecCx;
use fss_reference::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy, ExecutorActivityError,
    ExecutorModelOutcome,
};
use fss_reference::executor_activity_package::{
    ACTIVITY_CALIBRATION_GENERATION, ACTIVITY_ELEMENTS, ACTIVITY_INPUT_SCHEMA,
    ACTIVITY_LICENSE_IDENTITY, ACTIVITY_LICENSE_TEXT, ACTIVITY_MODEL_GENERATION, ACTIVITY_MODEL_ID,
    ACTIVITY_OUTPUT_SCHEMA, ACTIVITY_PACKAGE_V1, ACTIVITY_PACKAGE_V1_SHA256,
    ACTIVITY_SOURCE_IDENTITY, ACTIVITY_SPEC_ARTIFACT, ActivityPackageError, ActivityPackageSpec,
    VerifiedActivityPackage, activity_graph, activity_license_policy, build_activity_package,
};
use fss_reference::ingest::rgb_package::{GRAPH_ARTIFACT, LICENSE_ARTIFACT, WEIGHTS_ARTIFACT};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

fn pinned() -> TestResult<ContentDigest> {
    Ok(ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Re-encodes the committed package with one artifact replaced and an optional other
/// generation, re-deriving the manifest exactly as the builder does. The result is a fully
/// self-consistent archive, so the caller can re-pin it: only the loader's semantic checks can
/// refuse it.
fn repack(replace: Option<(&str, Vec<u8>)>, generation: &str) -> TestResult<Vec<u8>> {
    let package = ModelPackageArchive::decode(ACTIVITY_PACKAGE_V1, &ModelPackageLimits::default())?;
    let mut artifacts = Vec::new();
    for name in [
        WEIGHTS_ARTIFACT,
        GRAPH_ARTIFACT,
        ACTIVITY_SPEC_ARTIFACT,
        LICENSE_ARTIFACT,
    ] {
        let payload = match &replace {
            Some((target, payload)) if *target == name => payload.clone(),
            _ => package
                .artifacts
                .values()
                .find(|a| a.name == name)
                .ok_or("artifact")?
                .payload
                .clone(),
        };
        artifacts.push(ModelPackageArtifact::new(name, payload)?);
    }
    let digest_of = |name: &str| -> TestResult<ContentDigest> {
        Ok(artifacts
            .iter()
            .find(|a| a.name == name)
            .ok_or("artifact")?
            .digest)
    };
    let license = ModelLicenseRecord::new(
        ACTIVITY_LICENSE_IDENTITY,
        Some(ContentDigest::sha256(ACTIVITY_LICENSE_TEXT.as_bytes())),
        true,
        Vec::new(),
        ACTIVITY_SOURCE_IDENTITY,
        vec![
            digest_of(GRAPH_ARTIFACT)?,
            digest_of(ACTIVITY_SPEC_ARTIFACT)?,
        ],
        None,
    )?;
    let manifest = ModelManifestV1::new(
        ModelId::parse(ACTIVITY_MODEL_ID)?,
        ModelGeneration::parse(generation)?,
        digest_of(WEIGHTS_ARTIFACT)?,
        SchemaId::parse(ACTIVITY_INPUT_SCHEMA)?,
        SchemaId::parse(ACTIVITY_OUTPUT_SCHEMA)?,
        CalibrationGeneration::parse(ACTIVITY_CALIBRATION_GENERATION)?,
        license,
    )?;
    Ok(ModelPackageArchive::encode(&ModelPackage::new(
        manifest, artifacts,
    )?)?)
}

/// Loads `bytes` re-pinned to their own digest under the first-party policy.
fn load_repinned(bytes: &[u8]) -> Result<VerifiedActivityPackage, ActivityPackageError> {
    VerifiedActivityPackage::load(
        bytes,
        ContentDigest::sha256(bytes),
        &activity_license_policy()?,
        &ScalarExecCx::new(),
    )
}

/// Deterministic Safetensors with one `mean_weights` tensor of the given values.
fn weights_safetensors(values: &[f32]) -> Vec<u8> {
    let mut data = Vec::new();
    for v in values {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let header = format!(
        "{{\"__metadata__\":{{\"format\":\"fss-first-party\",\"model\":\"{ACTIVITY_MODEL_GENERATION}\"}},\"mean_weights\":{{\"dtype\":\"F32\",\"shape\":[{},1],\"data_offsets\":[0,{}]}}}}",
        values.len(),
        data.len()
    );
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend(data);
    bytes
}

#[test]
fn builder_reproduces_the_committed_package_bit_for_bit() -> TestResult {
    let rebuilt = build_activity_package()?;
    let rebuilt_digest = ContentDigest::sha256(&rebuilt);
    if rebuilt != ACTIVITY_PACKAGE_V1 {
        // Traceable regeneration: the exact bytes and digest the builder produced.
        println!("ACTIVITY_PACKAGE_REBUILT_SHA256 {rebuilt_digest}");
        println!("ACTIVITY_PACKAGE_REBUILT_HEX {}", hex(&rebuilt));
    }
    assert_eq!(
        rebuilt, ACTIVITY_PACKAGE_V1,
        "builder drifted from the committed package"
    );
    assert_eq!(rebuilt_digest, pinned()?);
    assert_eq!(
        build_activity_package()?,
        rebuilt,
        "builder is deterministic"
    );
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"package_root\",\"package_sha256\":\"{rebuilt_digest}\",\"bytes\":{}}}",
        rebuilt.len()
    );
    Ok(())
}

#[test]
fn committed_package_verifies_and_binds_graph_spec_license_and_weights() -> TestResult {
    let package = VerifiedActivityPackage::load_committed(&ScalarExecCx::new())?;
    assert_eq!(package.archive_digest(), pinned()?);
    assert_eq!(package.manifest().model_id().as_str(), ACTIVITY_MODEL_ID);
    assert_eq!(
        package.manifest().generation().as_str(),
        ACTIVITY_MODEL_GENERATION
    );
    assert_eq!(
        package.manifest().license().spdx_or_identity(),
        ACTIVITY_LICENSE_IDENTITY
    );
    assert_eq!(
        package.manifest().license().text_digest(),
        Some(ContentDigest::sha256(ACTIVITY_LICENSE_TEXT.as_bytes()))
    );
    assert_eq!(
        package.manifest_digest(),
        package.manifest().manifest_digest()?
    );
    assert_eq!(
        package.graph_digest(),
        compute_model_ir_digest(&activity_graph()?)?
    );
    assert_eq!(package.spec(), &ActivityPackageSpec::v1());
    // Documented derivation: 1024 copies of 2^-10, exact in F32.
    assert_eq!(package.mean_weights().len(), ACTIVITY_ELEMENTS);
    assert!(
        package
            .mean_weights()
            .iter()
            .all(|w| w.to_bits() == 0x3a80_0000)
    );
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"verify\",\"verdict\":\"ok\",\"manifest\":\"{}\",\"graph\":\"{}\"}}",
        package.manifest_digest(),
        package.graph_digest()
    );
    Ok(())
}

#[test]
fn archive_tamper_is_refused_before_parsing() -> TestResult {
    // A one-byte change in the middle of the archive under the original pin.
    let mut tampered = ACTIVITY_PACKAGE_V1.to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    let policy = activity_license_policy()?;
    let error = VerifiedActivityPackage::load(&tampered, pinned()?, &policy, &ScalarExecCx::new())
        .err()
        .ok_or("tampered archive loaded")?;
    assert!(matches!(error, ActivityPackageError::DigestMismatch));
    assert_eq!(error.stable_id(), "ERR-MODEL-PACKAGE-DIGEST-001");
    // Even re-pinned to the tampered bytes, the archive's own checksum refuses it.
    assert!(matches!(
        load_repinned(&tampered),
        Err(ActivityPackageError::Archive(_))
    ));
    // A non-SHA-256 pin is never accepted.
    let blake = ContentDigest::new(DigestAlgorithm::Blake3, pinned()?.bytes());
    assert!(matches!(
        VerifiedActivityPackage::load(ACTIVITY_PACKAGE_V1, blake, &policy, &ScalarExecCx::new()),
        Err(ActivityPackageError::DigestMismatch)
    ));
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"tamper\",\"verdict\":\"refused\",\"stable_id\":\"{}\"}}",
        error.stable_id()
    );
    Ok(())
}

#[test]
fn self_consistent_repacks_with_other_weights_graph_or_spec_are_refused() -> TestResult {
    // The repack helper reproduces the committed package exactly when nothing is replaced.
    assert_eq!(
        repack(None, ACTIVITY_MODEL_GENERATION)?,
        ACTIVITY_PACKAGE_V1
    );

    let mut values = vec![1.0_f32 / ACTIVITY_ELEMENTS as f32; ACTIVITY_ELEMENTS];
    values[7] = 0.5;
    let other_weights = repack(
        Some((WEIGHTS_ARTIFACT, weights_safetensors(&values))),
        ACTIVITY_MODEL_GENERATION,
    )?;
    assert!(matches!(
        load_repinned(&other_weights),
        Err(ActivityPackageError::WeightsMismatch)
    ));
    let short = repack(
        Some((WEIGHTS_ARTIFACT, weights_safetensors(&[0.5; 16]))),
        ACTIVITY_MODEL_GENERATION,
    )?;
    assert!(matches!(
        load_repinned(&short),
        Err(ActivityPackageError::WeightsMismatch)
    ));
    let garbage = repack(
        Some((WEIGHTS_ARTIFACT, b"not safetensors".to_vec())),
        ACTIVITY_MODEL_GENERATION,
    )?;
    assert!(matches!(
        load_repinned(&garbage),
        Err(ActivityPackageError::Weights(_))
    ));

    // Another valid graph (frame and reference swapped) is not this model.
    let graph = activity_graph()?;
    let swapped = {
        use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, OpCode};
        let mut builder = ModelIrGraph::builder(ACTIVITY_MODEL_GENERATION, graph.generation());
        for port in graph.inputs() {
            builder = builder.add_input(port.clone());
        }
        for port in graph.outputs() {
            builder = builder.add_output(port.clone());
        }
        for node in graph.nodes() {
            let node = if node.id() == "node:delta" {
                GraphNode::new(
                    "node:delta",
                    OpCode::Sub,
                    "swapped",
                    vec!["reference".into(), "frame".into()],
                    vec!["delta".into()],
                    AttributeMap::new(),
                )?
            } else {
                node.clone()
            };
            builder = builder.add_node(node);
        }
        builder.build_and_validate()?
    };
    assert_ne!(
        compute_model_ir_digest(&swapped)?,
        compute_model_ir_digest(&graph)?
    );
    let other_graph = repack(
        Some((GRAPH_ARTIFACT, encode_canonical_model_ir(&swapped)?)),
        ACTIVITY_MODEL_GENERATION,
    )?;
    assert!(matches!(
        load_repinned(&other_graph),
        Err(ActivityPackageError::GraphMismatch)
    ));

    let mut spec = ActivityPackageSpec::v1().encode()?;
    let last = spec.len() - 1;
    spec[last] ^= 0x20;
    let other_spec = repack(
        Some((ACTIVITY_SPEC_ARTIFACT, spec)),
        ACTIVITY_MODEL_GENERATION,
    )?;
    assert!(matches!(
        load_repinned(&other_spec),
        Err(ActivityPackageError::InvalidSpec)
    ));
    Ok(())
}

#[test]
fn license_policy_without_the_first_party_identity_refuses_the_package() -> TestResult {
    let default = ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
    let error = VerifiedActivityPackage::load(
        ACTIVITY_PACKAGE_V1,
        pinned()?,
        &default,
        &ScalarExecCx::new(),
    )
    .err()
    .ok_or("unlisted license admitted")?;
    match &error {
        ActivityPackageError::License(ModelLicensePolicyError::UnknownLicense {
            spdx_or_identity,
        }) => assert_eq!(spdx_or_identity, ACTIVITY_LICENSE_IDENTITY),
        other => return Err(format!("expected UnknownLicense, got {other:?}").into()),
    }
    assert_eq!(error.stable_id(), "ERR-MODEL-PACKAGE-LICENSE-001");
    // Revoking the identity from the first-party policy refuses it again.
    let mut revoked = activity_license_policy()?;
    revoked.disallow_license(ACTIVITY_LICENSE_IDENTITY);
    assert!(matches!(
        VerifiedActivityPackage::load(
            ACTIVITY_PACKAGE_V1,
            pinned()?,
            &revoked,
            &ScalarExecCx::new()
        ),
        Err(ActivityPackageError::License(_))
    ));
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"license\",\"verdict\":\"refused\",\"stable_id\":\"{}\"}}",
        error.stable_id()
    );
    Ok(())
}

#[test]
fn other_generations_are_refused_and_at_sign_generations_cannot_exist() -> TestResult {
    let v2 = repack(None, "model:fss-activity:v2")?;
    match load_repinned(&v2) {
        Err(ActivityPackageError::WrongModel { generation, .. }) => {
            assert_eq!(generation, "model:fss-activity:v2");
        }
        other => return Err(format!("expected WrongModel, got {other:?}").into()),
    }
    assert!(ModelGeneration::parse("model:fss-activity@1").is_err());
    Ok(())
}

#[test]
fn cancellation_before_load_returns_no_package() -> TestResult {
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        VerifiedActivityPackage::load_committed(&cx),
        Err(ActivityPackageError::Cancelled)
    ));
    Ok(())
}

/// A synthetic decoded frame: RGB pixels and a receipt naming them and their fake source.
struct Frame {
    pixels: Vec<u8>,
    source: Vec<u8>,
    receipt: RgbDecodeReceipt,
}

impl Frame {
    fn new(width: u32, height: u32, white: &[(u32, u32)], tag: &str) -> Self {
        let mut pixels = vec![0_u8; (width * height * 3) as usize];
        for &(x, y) in white {
            let at = ((y * width + x) * 3) as usize;
            pixels[at..at + 3].copy_from_slice(&[255, 255, 255]);
        }
        let source = format!("synthetic-source:{tag}:{width}x{height}").into_bytes();
        let receipt = RgbDecodeReceipt {
            encoded_sha256: ContentDigest::sha256(&source).bytes(),
            rgb_sha256: ContentDigest::sha256(&pixels).bytes(),
            decoder: [7; 32],
            interpretation: ComponentInterpretation::YCbCr,
            dimensions: [width, height],
            mcus: 1,
            entropy_blocks: 1,
            restarts: 0,
            metadata_segments: 0,
            metadata_bytes: 0,
        };
        Self {
            pixels,
            source,
            receipt,
        }
    }

    fn binding(&self) -> ActivityFrameBinding<'_> {
        ActivityFrameBinding {
            pixels: &self.pixels,
            receipt: self.receipt,
            source_digest: ContentDigest::sha256(&self.source),
            capsule_digest: ContentDigest::sha256(&[&self.source[..], b"capsule"].concat()),
        }
    }
}

fn rows(width: u32, rows: u32) -> Vec<(u32, u32)> {
    (0..rows)
        .flat_map(|y| (0..width).map(move |x| (x, y)))
        .collect()
}

fn score(model: &ActivityExecutorModel, frame: &Frame, reference: &Frame) -> TestResult<f32> {
    let (result, _) = model.invoke(
        &SensorId::parse("sensor:golden")?,
        frame.binding(),
        reference.binding(),
        &ActivityThresholdPolicy::reference()?,
        ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        "job:golden",
        &ScalarExecCx::new(),
    )?;
    Ok(result.outcome.score().ok_or("no score")?)
}

#[test]
fn hand_computed_score_goldens_through_the_verified_package() -> TestResult {
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    // Pure white luma is exactly 1.0 in the program's F32 order, black is 0.0, every weight is
    // 2^-10, so each score is (changed model pixels) / 1024 with no rounding.
    let goldens: [(&str, Frame, Frame, f32); 6] = [
        (
            "32x32 identical",
            Frame::new(32, 32, &[], "a"),
            Frame::new(32, 32, &[], "b"),
            0.0,
        ),
        (
            "32x32 all white",
            Frame::new(32, 32, &rows(32, 32), "a"),
            Frame::new(32, 32, &[], "b"),
            1.0,
        ),
        (
            "32x32 top half",
            Frame::new(32, 32, &rows(32, 16), "a"),
            Frame::new(32, 32, &[], "b"),
            0.5,
        ),
        // Downscale: target row y samples source row floor(y*48/32) < 24 exactly for y < 16.
        (
            "64x48 top half",
            Frame::new(64, 48, &rows(64, 24), "a"),
            Frame::new(64, 48, &[], "b"),
            0.5,
        ),
        // Upscale: source pixel (0,0) of 16x16 covers target rows and columns {0,1}: 4 pixels.
        (
            "16x16 one pixel",
            Frame::new(16, 16, &[(0, 0)], "a"),
            Frame::new(16, 16, &[], "b"),
            4.0 / 1024.0,
        ),
        // 33x17: floor(y*17/32) == 0 for y in {0,1}; floor(x*33/32) == 0 for x == 0: 2 pixels.
        (
            "33x17 one pixel",
            Frame::new(33, 17, &[(0, 0)], "a"),
            Frame::new(33, 17, &[], "b"),
            2.0 / 1024.0,
        ),
    ];
    for (name, frame, reference, expected) in &goldens {
        let observed = score(&model, frame, reference)?;
        println!(
            "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"score_golden\",\"case\":\"{name}\",\"score\":{observed},\"golden\":{expected}}}"
        );
        assert_eq!(observed.to_bits(), expected.to_bits(), "{name}");
    }
    // The score is symmetric in which frame changed.
    let white = Frame::new(32, 32, &rows(32, 16), "w");
    let black = Frame::new(32, 32, &[], "k");
    assert_eq!(score(&model, &black, &white)?, 0.5);
    Ok(())
}

#[test]
fn preprocessing_goldens_and_f64_reference() -> TestResult {
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let cx = ScalarExecCx::new();
    // 33x17 with one white pixel at (0,0): exactly target indices 0 (y0,x0) and 32 (y1,x0).
    let frame = Frame::new(33, 17, &[(0, 0)], "pre");
    let tensor = model.preprocess(&frame.pixels, 33, 17, &cx)?;
    assert_eq!(tensor.shape().dims(), &[1, 1, 32, 32]);
    let values = tensor.to_vec::<f32>()?;
    for (index, value) in values.iter().enumerate() {
        let expected = if index == 0 || index == 32 { 1.0 } else { 0.0 };
        assert_eq!(value.to_bits(), f32::to_bits(expected), "index {index}");
    }
    // Uniform mid-grey: within one F32 ulp of the f64 luma reference.
    let grey = vec![128_u8; 20 * 10 * 3];
    let values = model.preprocess(&grey, 20, 10, &cx)?.to_vec::<f32>()?;
    let reference = 128.0_f64 * (0.299 + 0.587 + 0.114) / 255.0;
    for value in values {
        assert!((f64::from(value) - reference).abs() <= f64::from(f32::EPSILON));
    }
    // The resize identity is part of the model identity and the spec.
    assert_eq!(
        model.package().spec().resize_digest(),
        ActivityPackageSpec::v1().resize_digest()
    );
    // Out-of-bounds frames are refused, never silently cropped.
    assert!(matches!(
        model.preprocess(&[], 0, 0, &cx),
        Err(ExecutorActivityError::InvalidInput(_))
    ));
    Ok(())
}

fn bind<'a>(bytes: &[u8], decoded: &'a DecodedRgb) -> ActivityFrameBinding<'a> {
    ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(bytes),
        capsule_digest: ContentDigest::sha256(bytes),
    }
}

#[test]
fn fixture_frame_score_matches_an_independent_f64_computation() -> TestResult {
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let decode = |bytes: &[u8]| {
        decode_rgb(
            bytes,
            ContentDigest::sha256(bytes).bytes(),
            ComponentInterpretation::Grayscale,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(10_000_000),
        )
    };
    let frame = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let (result, _) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        bind(GRADIENT, &frame),
        bind(BACKGROUND, &reference),
        &ActivityThresholdPolicy::reference()?,
        ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        "job:fixture",
        &ScalarExecCx::new(),
    )?;
    let observed = result.outcome.score().ok_or("no score")?;
    // Independent path: f64 nearest resize of the decoded pixels and the mean squared luma
    // difference, without the executor or the F32 program.
    let [width, height] = frame.dimensions();
    let (w, h) = (width as usize, height as usize);
    let luma = |pixels: &[u8], x: usize, y: usize| {
        let sy = y * h / 32;
        let sx = x * w / 32;
        let at = (sy * w + sx) * 3;
        (0.299 * f64::from(pixels[at])
            + 0.587 * f64::from(pixels[at + 1])
            + 0.114 * f64::from(pixels[at + 2]))
            / 255.0
    };
    let mut sum = 0.0_f64;
    for y in 0..32 {
        for x in 0..32 {
            let d = luma(frame.pixels(), x, y) - luma(reference.pixels(), x, y);
            sum += d * d;
        }
    }
    let expected = sum / 1024.0;
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.50\",\"step\":\"fixture_score\",\"frame\":\"gray.jpg\",\"score\":{observed},\"f64\":{expected}}}"
    );
    assert!((f64::from(observed) - expected).abs() < 1e-6);
    assert!(matches!(
        result.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    Ok(())
}
