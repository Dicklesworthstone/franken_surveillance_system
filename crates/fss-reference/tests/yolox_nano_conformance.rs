#![forbid(unsafe_code)]
//! YOLOX-Nano package conformance (fss-q4ngj): the FSS scalar reference executor running the
//! verified package reproduces the upstream ONNX graph as evaluated by the laboratory oracle
//! (onnxruntime, outside this repository) on identical model-input tensors, and the package's
//! post-processing yields the same detections. Expected values come only from the oracle file
//! `tests/fixtures/yolox_nano/conformance.txt` (exact F32 bits). This is conformance to upstream,
//! not a detection-quality claim on any deployment data. Timing is not asserted.

use std::collections::BTreeMap;
use std::error::Error;

use fss_codec_mjpeg::color::{RgbDecodeLimits, RgbDecodeReceipt, rgb_decoder_identity};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, Generation, OperationId};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::ingest::rgb_detections::{
    RgbDetectionBudget, RgbDetectionContract, project_rgb_detections,
};
use fss_reference::ingest::rgb_inference::{RgbInference, RgbRunLimits, RgbSourceBinding};
use fss_reference::ingest::rgb_package::{RgbDetectorPackage, RgbPackageError};
use fss_reference::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeOptions};
use fss_reference::{
    ChannelTransform, ExecBudget, PreprocessProgram, ReplayCx, ScalarExecCx, ScalarExecutor,
};
use fss_tensor::{DType, Shape, Tensor};

#[path = "yolox_support/cases.rs"]
mod cases;
#[path = "yolox_support/person.rs"]
mod person;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Pinned whole-archive identity of models/yolox-nano/yolox_nano.fmpk.
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const LICENSE: &[u8] = include_bytes!("../../../models/yolox-nano/LICENSE");
const FIXTURE: &str = include_str!("fixtures/yolox_nano/conformance.txt");
const SOURCE_ONNX: &str = "sha256:c789161ed43c8269fcd4e67c67eeeb4e80c622da2eb296a20bc6007bd18a0b7d";
/// |fss - oracle| <= TOLERANCE * max(1, |oracle|). See models/yolox-nano/README.md.
const TOLERANCE: f64 = 1e-3;
/// Detection boxes must agree within half a source pixel (in 1/256-pixel units).
const BOX_TOLERANCE: u32 = 128;

fn context() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:yolox-conformance".into(),
        operation_id: OperationId::parse("operation:yolox-conformance")?,
        principal: "principal:yolox-conformance".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:yolox-conformance"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir(),
    )?)
}

fn load() -> TestResult<RgbDetectorPackage> {
    Ok(RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        &context()?,
        &ScalarExecCx::new(),
    )?)
}

/// (row, class, score, source bounds in 1/256 px) of one oracle detection.
type OracleDetection = (usize, usize, f32, [u32; 4]);

/// Parsed oracle fixture for one case.
#[derive(Default)]
struct Expected {
    input_sha256: String,
    geometry: Vec<usize>,
    samples: Vec<(usize, f32, f32)>,
    top_rows: Vec<(usize, Vec<f32>)>,
    detections: BTreeMap<u32, Vec<OracleDetection>>,
    candidates: BTreeMap<u32, usize>,
}

fn f32_bits(hex: &str) -> TestResult<f32> {
    Ok(f32::from_bits(u32::from_str_radix(hex, 16)?))
}

fn fixture() -> TestResult<(BTreeMap<String, Expected>, String)> {
    let mut cases: BTreeMap<String, Expected> = BTreeMap::new();
    let (mut current, mut oracle, mut ended) = (String::new(), String::new(), false);
    for line in FIXTURE.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(&kind) = f.first() else { continue };
        match kind {
            "#" | "thresholds" => {}
            "oracle" => oracle = line.to_owned(),
            "source_sha256" => assert_eq!(format!("sha256:{}", f[1]), SOURCE_ONNX),
            "case" => {
                current = f[1].to_owned();
                cases.insert(current.clone(), Expected::default());
            }
            "end" => ended = true,
            _ => {
                let c = cases.get_mut(current.as_str()).ok_or("line before case")?;
                match kind {
                    "input_sha256" => c.input_sha256 = f[1].to_owned(),
                    "geometry" => {
                        c.geometry = f[1..].iter().map(|v| v.parse()).collect::<Result<_, _>>()?
                    }
                    "sample" => c
                        .samples
                        .push((f[1].parse()?, f32_bits(f[2])?, f32_bits(f[3])?)),
                    "toprow" => c.top_rows.push((
                        f[1].parse()?,
                        f[2..]
                            .iter()
                            .map(|h| f32_bits(h))
                            .collect::<TestResult<_>>()?,
                    )),
                    "candidates" => {
                        c.candidates.insert(f[1].parse()?, f[2].parse()?);
                    }
                    "det" => c.detections.entry(f[1].parse()?).or_default().push((
                        f[2].parse()?,
                        f[3].parse()?,
                        f32_bits(f[4])?,
                        [f[5].parse()?, f[6].parse()?, f[7].parse()?, f[8].parse()?],
                    )),
                    other => return Err(format!("unknown fixture line {other}").into()),
                }
            }
        }
    }
    if !ended || cases.len() != cases::CASES.len() {
        return Err("truncated fixture".into());
    }
    Ok((cases, oracle))
}

fn allowed_all(image: &cases::SourceImage) -> Vec<u8> {
    vec![1; image.pixels.len() / 3]
}

fn binding(encoded: [u8; 32], allowed: &[u8]) -> RgbSourceBinding {
    RgbSourceBinding {
        encoded_sha256: encoded,
        exposure: [2; 32],
        camera: 7,
        clock: 1,
        capture: [10, 20],
        image_domain: [3; 32],
        calibration: [4; 32],
        permission_mask: ContentDigest::sha256(allowed).bytes(),
    }
}

fn limits() -> RgbRunLimits {
    RgbRunLimits {
        decode: RgbDecodeLimits::default(),
        preprocess: ExecBudget::new(1 << 40, 256 * 1024 * 1024),
        execution: ExecBudget::new(1 << 40, 256 * 1024 * 1024),
        maximum_output_bytes: 16 * 1024 * 1024,
    }
}

/// Run one case through the complete package path (JPEG through the native decoder).
fn infer(
    package: &RgbDetectorPackage,
    image: &cases::SourceImage,
    cx: &ScalarExecCx,
) -> TestResult<RgbInference> {
    let allowed = allowed_all(image);
    Ok(match image.jpeg {
        Some(jpeg) => package.model().run_jpeg(
            jpeg,
            ComponentInterpretation::YCbCr,
            binding(ContentDigest::sha256(jpeg).bytes(), &allowed),
            &allowed,
            limits(),
            &mut DecodeBudget::new(1 << 30),
            cx,
        )?,
        None => {
            let receipt = RgbDecodeReceipt {
                encoded_sha256: [1; 32],
                rgb_sha256: ContentDigest::sha256(&image.pixels).bytes(),
                decoder: rgb_decoder_identity(),
                interpretation: ComponentInterpretation::YCbCr,
                dimensions: image.dimensions,
                mcus: 0,
                entropy_blocks: 0,
                restarts: 0,
                metadata_segments: 0,
                metadata_bytes: 0,
            };
            package.model().run_rgb_pixels(
                &image.pixels,
                receipt,
                binding([1; 32], &allowed),
                &allowed,
                limits(),
                cx,
            )?
        }
    })
}

/// Returns (within tolerance, absolute error, error normalized by max(1, |oracle|)).
fn within(actual: f32, expected: f32) -> (bool, f64, f64) {
    let (a, e) = (f64::from(actual), f64::from(expected));
    let err = (a - e).abs();
    let normalized = err / e.abs().max(1.0);
    (normalized <= TOLERANCE, err, normalized)
}

#[test]
fn package_is_loaded_only_through_the_verified_path() -> TestResult {
    let package = load()?;
    let manifest = package.manifest();
    assert_eq!(manifest.model_id().as_str(), "MOD-YOLOXNANO-001");
    assert_eq!(manifest.license().spdx_or_identity(), "Apache-2.0");
    assert_eq!(
        manifest.license().text_digest(),
        Some(ContentDigest::sha256(LICENSE))
    );
    assert!(
        manifest
            .license()
            .source_identity()
            .ends_with("/0.1.1rc0/yolox_nano.onnx")
    );
    let spec = package.spec();
    assert_eq!(
        spec.source.source_sha256,
        ContentDigest::parse(SOURCE_ONNX)?
    );
    assert_eq!(
        (
            spec.target,
            spec.letterbox_pad,
            spec.scale_to_unit,
            spec.labels.len()
        ),
        ([416, 416], 114, false, 80)
    );
    assert_eq!(
        (spec.labels[0].as_str(), spec.labels[79].as_str()),
        ("person", "toothbrush")
    );
    assert_eq!(
        (spec.head.minimum_score_ppm, spec.head.nms_iou_ppm),
        (300_000, 450_000)
    );

    let cx = context()?;
    let scalar = ScalarExecCx::new();
    let expected = ContentDigest::parse(PACKAGE_SHA256)?;
    // Any single-byte change is refused before parsing, wherever it lands.
    for offset in [0, PACKAGE.len() / 3, PACKAGE.len() / 2, PACKAGE.len() - 1] {
        let mut tampered = PACKAGE.to_vec();
        tampered[offset] ^= 0x01;
        let refused = RgbDetectorPackage::load(&tampered, expected, 1 << 40, &cx, &scalar);
        assert!(
            matches!(refused, Err(RgbPackageError::DigestMismatch)),
            "offset {offset}"
        );
        // Re-pinning the tampered bytes does not help: the archive's own checksums refuse it.
        let repinned = RgbDetectorPackage::load(
            &tampered,
            ContentDigest::sha256(&tampered),
            1 << 40,
            &cx,
            &scalar,
        );
        assert!(repinned.is_err(), "offset {offset}");
    }
    let wrong = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::sha256(b"another package"),
        1 << 40,
        &cx,
        &scalar,
    );
    assert!(
        matches!(wrong, Err(ref e @ RgbPackageError::DigestMismatch) if e.stable_id() == "ERR-MODEL-PACKAGE-DIGEST-001")
    );
    assert!(matches!(
        RgbDetectorPackage::load(PACKAGE, expected, 1, &cx, &scalar),
        Err(RgbPackageError::Import(_))
    ));
    Ok(())
}

#[test]
fn scalar_reference_reproduces_the_onnxruntime_oracle() -> TestResult {
    let (expected, oracle) = fixture()?;
    let package = load()?;
    let cx = ScalarExecCx::new();
    let program = PreprocessProgram::new(416, 416, ChannelTransform::Rgb, false);
    let (mut worst_raw, mut worst_decoded, mut worst_normalized) = (0.0_f64, 0.0_f64, 0.0_f64);
    for name in cases::CASES {
        let e = expected.get(name).ok_or("case missing from fixture")?;
        let image = cases::source(name)?;
        let [w, h] = image.dimensions;
        // The model input is bit-identical to the tensor the oracle evaluated.
        let resized = program.execute_resized_bytes(
            ImageBytes {
                bytes: &image.pixels,
                height: h as usize,
                width: w as usize,
                channels: 3,
                generation: Generation(1),
            },
            ResizeOptions {
                filter: ResizeFilter::Bilinear,
                aspect: ResizeAspect::Letterbox(114),
                budget: ExecBudget::new(1 << 40, 1 << 30),
            },
            &cx,
        )?;
        let le: Vec<u8> = resized
            .tensor
            .to_vec::<f32>()?
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(
            ContentDigest::sha256(&le).to_string(),
            format!("sha256:{}", e.input_sha256),
            "{name} input"
        );
        let g = resized.geometry;
        assert_eq!(
            e.geometry,
            vec![
                g.source_width,
                g.source_height,
                g.image_width,
                g.image_height,
                g.left,
                g.top
            ]
        );

        let inference = infer(&package, &image, &cx)?;
        assert_eq!(
            inference.input_digest(),
            resized.output_digest,
            "{name}: package preprocessing differs"
        );
        let raw = inference.outputs().get("raw_head").ok_or("raw_head")?;
        let decoded = inference
            .outputs()
            .get("decoded_head")
            .ok_or("decoded_head")?;
        assert_eq!(
            (raw.shape(), decoded.shape()),
            (&[1, 3549, 85][..], &[1, 3549, 85][..])
        );
        for &(index, r, d) in &e.samples {
            let (ok, err, n) = within(raw.values()[index], r);
            worst_raw = worst_raw.max(err);
            worst_normalized = worst_normalized.max(n);
            assert!(
                ok,
                "{name} raw[{index}] fss={} oracle={r}",
                raw.values()[index]
            );
            let (ok, err, n) = within(decoded.values()[index], d);
            worst_decoded = worst_decoded.max(err);
            worst_normalized = worst_normalized.max(n);
            assert!(
                ok,
                "{name} decoded[{index}] fss={} oracle={d}",
                decoded.values()[index]
            );
        }
        for (row, values) in &e.top_rows {
            for (field, &v) in values.iter().enumerate() {
                let actual = raw.values()[row * 85 + field];
                let (ok, err, n) = within(actual, v);
                worst_raw = worst_raw.max(err);
                worst_normalized = worst_normalized.max(n);
                assert!(ok, "{name} row {row} field {field} fss={actual} oracle={v}");
            }
        }
        let allowed = allowed_all(&image);
        for (&ppm, dets) in &e.detections {
            let contract = package.contract_with_threshold(ppm)?;
            let report = project_rgb_detections(
                &inference,
                &contract,
                &allowed,
                &mut RgbDetectionBudget::new(1 << 40, 1 << 30),
                &cx,
            )?;
            assert_eq!(
                report.candidates().len(),
                e.candidates[&ppm],
                "{name} @{ppm} candidate count"
            );
            assert_eq!(
                report.detections().len(),
                dets.len(),
                "{name} @{ppm} detection count"
            );
            let mut unmatched: Vec<_> = report.detections().to_vec();
            for &(row, class, score, bounds) in dets {
                let position = unmatched.iter().position(|d| d.class_index() == class && d.row() == row
                    && d.bounds().iter().zip(bounds).all(|(a, b)| a.abs_diff(b) <= BOX_TOLERANCE)
                    && (f64::from(d.score()) - f64::from(score)).abs() <= TOLERANCE)
                    .ok_or_else(|| format!("{name} @{ppm}: oracle detection row {row} class {class} {bounds:?} unmatched"))?;
                unmatched.remove(position);
            }
        }
        eprintln!(
            "{name}: {} rows, detections at package threshold {:?}",
            raw.shape()[1],
            report_classes(&package, &inference, &allowed, &cx)?
        );
    }
    eprintln!(
        "oracle: {oracle}\nmax |raw error| {worst_raw:.3e}; max |decoded error| {worst_decoded:.3e} px; \
        max error / max(1, |oracle|) {worst_normalized:.3e} (tolerance {TOLERANCE:e})"
    );
    Ok(())
}

fn report_classes(
    package: &RgbDetectorPackage,
    inference: &RgbInference,
    allowed: &[u8],
    cx: &ScalarExecCx,
) -> TestResult<Vec<(String, f32)>> {
    let contract: &RgbDetectionContract = package.contract();
    let report = project_rgb_detections(
        inference,
        contract,
        allowed,
        &mut RgbDetectionBudget::new(1 << 40, 1 << 30),
        cx,
    )?;
    Ok(report
        .detections()
        .iter()
        .map(|d| (package.spec().labels[d.class_index()].clone(), d.score()))
        .collect())
}

/// Hand-computed checks of the exact IR compositions the importer emits.
fn run_graph(
    nodes: Vec<GraphNode>,
    input: (&str, Vec<usize>, Vec<f32>),
    extra: Vec<(&str, Vec<usize>, Vec<f32>)>,
    output: (&str, Vec<usize>),
) -> TestResult<Vec<f32>> {
    let g = Generation(1);
    let mut ports = vec![TensorPort::new(
        input.0,
        DType::F32,
        Shape::new(input.1.clone())?,
        g,
    )?];
    let mut tensors = vec![(
        input.0.to_owned(),
        Tensor::from_values(Shape::new(input.1)?, &input.2, g)?,
    )];
    for (name, dims, values) in extra {
        ports.push(TensorPort::new(
            name,
            DType::F32,
            Shape::new(dims.clone())?,
            g,
        )?);
        tensors.push((
            name.to_owned(),
            Tensor::from_values(Shape::new(dims)?, &values, g)?,
        ));
    }
    let graph = ModelIrGraph::new_validated(
        "composition",
        ModelIrVersion::V1,
        g,
        ports,
        vec![TensorPort::new(
            output.0,
            DType::F32,
            Shape::new(output.1)?,
            g,
        )?],
        nodes,
    )?;
    let out = ScalarExecutor::run(
        &graph,
        &tensors,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    Ok(out.get_output(output.0).ok_or("output")?.to_vec::<f32>()?)
}

fn node(
    id: &str,
    op: OpCode,
    inputs: &[&str],
    output: &str,
    attrs: &[(&str, AttrValue)],
) -> TestResult<GraphNode> {
    let map: AttributeMap = attrs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    Ok(GraphNode::new(
        id,
        op,
        id,
        inputs.iter().map(|s| (*s).to_owned()).collect(),
        vec![output.to_owned()],
        map,
    )?)
}

#[test]
fn nearest_resize_lowering_is_exact_by_hand() -> TestResult {
    // [1,1,2,3] = [[1,2,3],[4,5,6]], scale 2 nearest/asymmetric/floor: out[y][x] = in[y/2][x/2].
    let list = |v: &[i64]| AttrValue::IntList(v.to_vec());
    let out = run_graph(
        vec![
            node(
                "a",
                OpCode::Reshape,
                &["x"],
                "u",
                &[("shape", list(&[1, 1, 2, 1, 3, 1]))],
            )?,
            node(
                "b",
                OpCode::Concat,
                &["u", "u"],
                "w",
                &[("axis", AttrValue::Int(5))],
            )?,
            node(
                "c",
                OpCode::Concat,
                &["w", "w"],
                "hw",
                &[("axis", AttrValue::Int(3))],
            )?,
            node(
                "d",
                OpCode::Reshape,
                &["hw"],
                "y",
                &[("shape", list(&[1, 1, 4, 6]))],
            )?,
        ],
        ("x", vec![1, 1, 2, 3], vec![1., 2., 3., 4., 5., 6.]),
        vec![],
        ("y", vec![1, 1, 4, 6]),
    )?;
    assert_eq!(
        out,
        vec![
            1., 1., 2., 2., 3., 3., 1., 1., 2., 2., 3., 3., 4., 4., 5., 5., 6., 6., 4., 4., 5., 5.,
            6., 6.
        ]
    );
    Ok(())
}

#[test]
fn exponential_as_sigmoid_ratio_is_accurate_by_hand() -> TestResult {
    // exp(t) = sigmoid(t) / sigmoid(-t). Reference values of e^t rounded to F32 by hand.
    let t = vec![-3.0_f32, 0.0, 1.0, 2.5, 4.0];
    let expected = [
        0.049_787_068_367_863_94_f64,
        1.0,
        std::f64::consts::E,
        12.182_493_960_703_473,
        54.598_150_033_144_24,
    ];
    let out = run_graph(
        vec![
            node("neg", OpCode::Mul, &["t", "minus_one"], "n", &[])?,
            node("sp", OpCode::Sigmoid, &["t"], "p", &[])?,
            node("sn", OpCode::Sigmoid, &["n"], "q", &[])?,
            node("div", OpCode::Div, &["p", "q"], "e", &[])?,
        ],
        ("t", vec![5], t),
        vec![("minus_one", vec![1], vec![-1.0])],
        ("e", vec![5]),
    )?;
    for (a, e) in out.iter().zip(expected) {
        assert!((f64::from(*a) - e).abs() <= 1e-6 * e, "{a} vs {e}");
    }
    Ok(())
}

#[test]
fn rgb_to_bgr_prefix_is_pure_data_movement() -> TestResult {
    let list = |v: &[i64]| AttrValue::IntList(v.to_vec());
    let slice = |id: &str, c: i64, out: &str| {
        node(
            id,
            OpCode::Slice,
            &["x"],
            out,
            &[
                ("axes", list(&[1])),
                ("starts", list(&[c])),
                ("ends", list(&[c + 1])),
                ("steps", list(&[1])),
            ],
        )
    };
    let out = run_graph(
        vec![
            slice("b", 2, "bb")?,
            slice("g", 1, "gg")?,
            slice("r", 0, "rr")?,
            node(
                "cat",
                OpCode::Concat,
                &["bb", "gg", "rr"],
                "y",
                &[("axis", AttrValue::Int(1))],
            )?,
        ],
        ("x", vec![1, 3, 1, 2], vec![10., 11., 20., 21., 30., 31.]),
        vec![],
        ("y", vec![1, 3, 1, 2]),
    )?;
    assert_eq!(out, vec![30., 31., 20., 21., 10., 11.]);
    Ok(())
}
