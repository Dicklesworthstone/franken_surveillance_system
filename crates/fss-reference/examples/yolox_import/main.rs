#![forbid(unsafe_code)]
//! OFFLINE LABORATORY IMPORTER for YOLOX-Nano (fss-q4ngj). Never part of a runtime path.
//!
//! Reads the exact upstream `yolox_nano.onnx` (Megvii-BaseDetection/YOLOX release 0.1.1rc0,
//! Apache-2.0) from a local file the operator downloaded once, refuses any other bytes, parses it
//! with a bounded first-party protobuf reader, lowers it exactly onto FSS Model IR v1, and writes
//! one immutable `FMPK` model package (manifest, Safetensors weights, IR graph, package spec,
//! LICENSE, NOTICE). No network access, no foreign runtime, no timestamps: the output is a pure
//! function of the ONNX bytes and this importer's source, so reruns are byte-identical.
//!
//! Usage (see models/yolox-nano/README.md):
//!   cargo run --release -p fss-reference --example yolox_import -- IN.onnx OUT.fmpk

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::process::ExitCode;

use fss_core::{CalibrationGeneration, CanonicalEncoder, ContentDigest, ModelGeneration, SchemaId};
use fss_model_ir::{decode_canonical_model_ir, encode_canonical_model_ir};
use fss_object::{
    ModelId, ModelLicenseRecord, ModelManifestV1, ModelPackage, ModelPackageArchive,
    ModelPackageArtifact,
};
use fss_reference::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use fss_reference::ingest::rgb_package::{
    GRAPH_ARTIFACT, LICENSE_ARTIFACT, NOTICE_ARTIFACT, PackageHeadSpec, PackageSource,
    RgbPackageSpec, SPEC_ARTIFACT, WEIGHTS_ARTIFACT, YOLOX_NANO_MODEL_ID,
};
use fss_reference::preprocess::ResizeFilter;

mod lower;
mod onnx;

/// The only admitted source bytes.
const EXPECTED_ONNX_SHA256: &str =
    "sha256:c789161ed43c8269fcd4e67c67eeeb4e80c622da2eb296a20bc6007bd18a0b7d";
const UPSTREAM: &str =
    "https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_nano.onnx";
const REVISION: &str = "0.1.1rc0";
const INPUT: usize = 416;
const LICENSE: &[u8] = include_bytes!("../../../../models/yolox-nano/LICENSE");
const NOTICE: &[u8] = include_bytes!("../../../../models/yolox-nano/NOTICE");

/// COCO-80 labels in YOLOX `COCO_CLASSES` order (class index = position).
const COCO: [&str; 80] = [
    "person",
    "bicycle",
    "car",
    "motorcycle",
    "airplane",
    "bus",
    "train",
    "truck",
    "boat",
    "traffic light",
    "fire hydrant",
    "stop sign",
    "parking meter",
    "bench",
    "bird",
    "cat",
    "dog",
    "horse",
    "sheep",
    "cow",
    "elephant",
    "bear",
    "zebra",
    "giraffe",
    "backpack",
    "umbrella",
    "handbag",
    "tie",
    "suitcase",
    "frisbee",
    "skis",
    "snowboard",
    "sports ball",
    "kite",
    "baseball bat",
    "baseball glove",
    "skateboard",
    "surfboard",
    "tennis racket",
    "bottle",
    "wine glass",
    "cup",
    "fork",
    "knife",
    "spoon",
    "bowl",
    "banana",
    "apple",
    "sandwich",
    "orange",
    "broccoli",
    "carrot",
    "hot dog",
    "pizza",
    "donut",
    "cake",
    "chair",
    "couch",
    "potted plant",
    "bed",
    "dining table",
    "toilet",
    "tv",
    "laptop",
    "mouse",
    "remote",
    "keyboard",
    "cell phone",
    "microwave",
    "oven",
    "toaster",
    "sink",
    "refrigerator",
    "book",
    "clock",
    "vase",
    "scissors",
    "teddy bear",
    "hair drier",
    "toothbrush",
];

/// Source identity of this importer; recorded in the package spec.
fn importer_identity() -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.yolox_importer.v1");
    for source in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("onnx.rs"),
        include_bytes!("lower.rs"),
    ] {
        e.digest(ContentDigest::sha256(source));
    }
    ContentDigest::sha256(&e.finish())
}

/// Deterministic Safetensors: keys sorted, contiguous data in key order, no padding.
fn safetensors(
    params: &BTreeMap<String, (Vec<usize>, Vec<f32>)>,
    metadata: &[(&str, String)],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut header = String::from("{\"__metadata__\":{");
    for (i, (k, v)) in metadata.iter().enumerate() {
        if i != 0 {
            header.push(',');
        }
        header.push_str(&format!("\"{k}\":\"{v}\""));
    }
    header.push('}');
    let mut data = Vec::new();
    for (name, (dims, values)) in params {
        if name.contains(['"', '\\']) || name.chars().any(char::is_control) {
            return Err(format!("disallowed tensor name {name}").into());
        }
        let start = data.len();
        for v in values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        let shape = dims
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        header.push_str(&format!(
            ",\"{name}\":{{\"dtype\":\"F32\",\"shape\":[{shape}],\"data_offsets\":[{start},{}]}}",
            data.len()
        ));
    }
    header.push('}');
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend(data);
    Ok(bytes)
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [input, output] = args.as_slice() else {
        return Err("usage: yolox_import IN.onnx OUT.fmpk".into());
    };
    let file = fs::File::open(input)?;
    let mut onnx_bytes = Vec::new();
    file.take(onnx::MAX_MODEL_BYTES as u64 + 1)
        .read_to_end(&mut onnx_bytes)?;
    let source_sha256 = ContentDigest::sha256(&onnx_bytes);
    if source_sha256 != ContentDigest::parse(EXPECTED_ONNX_SHA256)? {
        return Err(format!(
            "refusing unpinned source {source_sha256}; expected {EXPECTED_ONNX_SHA256}"
        )
        .into());
    }
    let model = onnx::parse_model(&onnx_bytes)?;
    let lowered = lower::lower(&model, [INPUT, INPUT])?;
    let graph = encode_canonical_model_ir(&lowered.graph)?;
    let graph_digest = ContentDigest::sha256(&graph);
    decode_canonical_model_ir(&graph, graph_digest)
        .map_err(|e| format!("graph does not round-trip: {e:?}"))?;
    let importer = importer_identity();
    let weights = safetensors(
        &lowered.parameters,
        &[
            ("format", "fss-yolox-nano-import".to_owned()),
            ("source_sha256", source_sha256.to_string()),
            ("importer", importer.to_string()),
        ],
    )?;
    let spec = RgbPackageSpec {
        image_input: lower::IMAGE_INPUT.to_owned(),
        target: [INPUT, INPUT],
        filter: ResizeFilter::Bilinear,
        letterbox_pad: 114,
        masked_rgb: [114, 114, 114],
        scale_to_unit: false,
        head: PackageHeadSpec {
            output_port: lower::DECODED_OUTPUT.to_owned(),
            layout: HeadLayout::Rows,
            boxes: HeadBoxes::PixelCenterSize,
            class_score: HeadScore::Probability,
            objectness: Some(HeadScore::Probability),
            classes: HeadClasses::MultiLabel,
            minimum_score_ppm: 300_000,
            nms_iou_ppm: 450_000,
            maximum_rows: 3549,
            maximum_candidates: 4096,
            maximum_detections: 256,
        },
        labels: COCO.iter().map(|s| (*s).to_owned()).collect(),
        source: PackageSource {
            upstream: UPSTREAM.to_owned(),
            revision: REVISION.to_owned(),
            source_sha256,
            producer: format!("{} {}", model.producer, model.producer_version),
            opset: model.opsets.first().map_or(0, |(_, v)| *v as u64),
        },
        importer,
    }
    .encode()?;
    let artifacts = vec![
        ModelPackageArtifact::new(WEIGHTS_ARTIFACT, weights)?,
        ModelPackageArtifact::new(GRAPH_ARTIFACT, graph)?,
        ModelPackageArtifact::new(SPEC_ARTIFACT, spec)?,
        ModelPackageArtifact::new(LICENSE_ARTIFACT, LICENSE.to_vec())?,
        ModelPackageArtifact::new(NOTICE_ARTIFACT, NOTICE.to_vec())?,
    ];
    let digest_of = |name: &str| {
        artifacts
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.digest)
            .ok_or("artifact")
    };
    let license = ModelLicenseRecord::new(
        "Apache-2.0",
        Some(ContentDigest::sha256(LICENSE)),
        true,
        Vec::new(),
        UPSTREAM,
        vec![
            digest_of(GRAPH_ARTIFACT)?,
            digest_of(SPEC_ARTIFACT)?,
            digest_of(NOTICE_ARTIFACT)?,
        ],
        Some(REVISION.to_owned()),
    )?;
    let manifest = ModelManifestV1::new(
        ModelId::parse(YOLOX_NANO_MODEL_ID)?,
        ModelGeneration::parse("model:yolox-nano:coco80:416:onnx-0.1.1rc0:fss-ir-v1:f32:g1")?,
        digest_of(WEIGHTS_ARTIFACT)?,
        SchemaId::parse("fss.rgb_nchw_f32.1x3x416x416.raw255")?,
        SchemaId::parse("fss.yolox_decoded_head.1x3549x85")?,
        CalibrationGeneration::parse("cal:uncalibrated:none")?,
        license,
    )?;
    let archive = ModelPackageArchive::encode(&ModelPackage::new(manifest, artifacts)?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut out = options.open(output)?;
    out.write_all(&archive)?;
    out.sync_all()?;
    println!(
        "source_sha256={source_sha256}\nproducer={} {}\nopsets={:?}",
        model.producer, model.producer_version, model.opsets
    );
    println!(
        "onnx_ops={:?}\nir_ops={:?}",
        lowered.onnx_ops, lowered.ir_ops
    );
    println!(
        "ir_nodes={}\nsilu_fused={}\nresize_lowered={}",
        lowered.graph.node_count(),
        lowered.silu_fused,
        lowered.resize_lowered
    );
    println!(
        "parameters={}\nparameter_values={}",
        lowered.parameters.len(),
        lowered
            .parameters
            .values()
            .map(|(_, v)| v.len())
            .sum::<usize>()
    );
    println!(
        "graph_digest={graph_digest}\nimporter_identity={importer}\npackage_bytes={}\npackage_sha256={}",
        archive.len(),
        ContentDigest::sha256(&archive)
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yolox_import: {e}");
            ExitCode::FAILURE
        }
    }
}
