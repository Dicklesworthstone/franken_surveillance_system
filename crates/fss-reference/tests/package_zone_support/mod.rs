#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Tiny first-party FMPK/JPEG fixture. Numeric coefficients are not a trained quality claim.
use fss_core::{CalibrationGeneration, ContentDigest, Generation, ModelGeneration, SchemaId};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    encode_canonical_model_ir,
};
use fss_object::{
    ModelId, ModelLicenseRecord, ModelManifestV1, ModelPackage, ModelPackageArchive,
    ModelPackageArtifact,
};
use fss_reference::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use fss_reference::ingest::rgb_package::{
    GRAPH_ARTIFACT, LICENSE_ARTIFACT, NOTICE_ARTIFACT, PackageHeadSpec, PackageSource,
    RgbPackageSpec, SPEC_ARTIFACT, WEIGHTS_ARTIFACT,
};
use fss_reference::preprocess::ResizeFilter;
use fss_tensor::{DType, Shape};
use std::collections::BTreeMap;
#[path = "../../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod jpeg_support;
pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub fn jpeg(value: u8) -> Vec<u8> {
    jpeg_support::jpeg(32, 16, [1, 1], false, false, false, &[[value, 128, 128]])
}
pub fn footage() -> Vec<u8> {
    [
        64, 64, 96, 128, 160, 192, 224, 240, 240, 240, 0, 240, 240, 240,
    ]
    .into_iter()
    .flat_map(jpeg)
    .collect()
}
pub fn package() -> Test<Vec<u8>> {
    let g = Generation(7);
    let mut attrs = AttributeMap::new();
    attrs.insert("shape".into(), AttrValue::IntList(vec![1, 1, 6]));
    let graph = ModelIrGraph::new_validated(
        "model:package-zone-numeric",
        ModelIrVersion::V1,
        g,
        vec![
            TensorPort::new("image", DType::F32, Shape::new(vec![1, 3, 8, 8])?, g)?,
            TensorPort::new("weight", DType::F32, Shape::new(vec![6, 3, 8, 8])?, g)?,
            TensorPort::new("bias", DType::F32, Shape::new(vec![6])?, g)?,
        ],
        vec![TensorPort::new(
            "head",
            DType::F32,
            Shape::new(vec![1, 1, 6])?,
            g,
        )?],
        vec![
            GraphNode::new(
                "node:conv",
                OpCode::Conv2d,
                "numeric fixture pixels move one box",
                vec!["image".into(), "weight".into(), "bias".into()],
                vec!["raw".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "node:shape",
                OpCode::Reshape,
                "explicit fixture rows",
                vec!["raw".into()],
                vec!["head".into()],
                attrs,
            )?,
        ],
    )?;
    let mut weight = vec![0.0_f32; 6 * 3 * 64];
    for field in [0, 2] {
        weight[field * 3 * 64 + 3 * 8 + 1] = 4.0;
    }
    weight[4 * 3 * 64 + 3 * 8 + 1] = 1.0;
    let parameters = BTreeMap::from([
        (
            "bias",
            (vec![6_usize], vec![1.0_f32, 3.0, 2.0, 4.0, 0.0, 0.9]),
        ),
        ("weight", (vec![6, 3, 8, 8], weight)),
    ]);
    let mut data = Vec::new();
    let mut fields = Vec::new();
    for (name, (shape, values)) in parameters {
        let start = data.len();
        for value in values {
            data.extend_from_slice(&value.to_le_bytes());
        }
        fields.push(format!(
            "\"{name}\":{{\"dtype\":\"F32\",\"shape\":[{}],\"data_offsets\":[{start},{}]}}",
            shape
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
            data.len()
        ));
    }
    let header = format!("{{{}}}", fields.join(","));
    let mut weights = (header.len() as u64).to_le_bytes().to_vec();
    weights.extend_from_slice(header.as_bytes());
    weights.extend(data);
    let spec = RgbPackageSpec {
        image_input: "image".into(),
        target: [8, 8],
        filter: ResizeFilter::Bilinear,
        letterbox_pad: 114,
        masked_rgb: [0; 3],
        scale_to_unit: true,
        head: PackageHeadSpec {
            output_port: "head".into(),
            layout: HeadLayout::Rows,
            boxes: HeadBoxes::PixelCorners,
            class_score: HeadScore::Probability,
            objectness: None,
            classes: HeadClasses::MultiLabel,
            minimum_score_ppm: 200_000,
            nms_iou_ppm: 1_000_000,
            maximum_rows: 1,
            maximum_candidates: 2,
            maximum_detections: 2,
        },
        labels: vec!["numeric-a".into(), "numeric-b".into()],
        source: PackageSource {
            upstream: "test:package-zone-native-numeric".into(),
            revision: "fixture-v1".into(),
            source_sha256: ContentDigest::sha256(b"fixture, not trained"),
            producer: "first-party numeric test".into(),
            opset: 1,
        },
        importer: ContentDigest::sha256(b"package-zone-test-builder-v1"),
    }
    .encode()?;
    let license =
        b"Apache License, Version 2.0. Synthetic test coefficients, no model-quality claim.";
    let artifacts = vec![
        ModelPackageArtifact::new(WEIGHTS_ARTIFACT, weights)?,
        ModelPackageArtifact::new(GRAPH_ARTIFACT, encode_canonical_model_ir(&graph)?)?,
        ModelPackageArtifact::new(SPEC_ARTIFACT, spec)?,
        ModelPackageArtifact::new(LICENSE_ARTIFACT, license.to_vec())?,
        ModelPackageArtifact::new(
            NOTICE_ARTIFACT,
            b"Synthetic native numeric fixture; not a trained detector.".to_vec(),
        )?,
    ];
    let digest = |name: &str| -> Test<ContentDigest> {
        Ok(artifacts
            .iter()
            .find(|a| a.name == name)
            .ok_or("artifact")?
            .digest)
    };
    let rights = ModelLicenseRecord::new(
        "Apache-2.0",
        Some(digest(LICENSE_ARTIFACT)?),
        true,
        Vec::new(),
        "test:package-zone-native-numeric",
        vec![
            digest(GRAPH_ARTIFACT)?,
            digest(SPEC_ARTIFACT)?,
            digest(NOTICE_ARTIFACT)?,
        ],
        Some("fixture-v1".into()),
    )?;
    let manifest = ModelManifestV1::new(
        ModelId::parse("MOD-PACKAGE-ZONE-TEST-001")?,
        ModelGeneration::parse("model:package-zone-numeric:g1")?,
        digest(WEIGHTS_ARTIFACT)?,
        SchemaId::parse("fss.package_zone_fixture.rgb.v1")?,
        SchemaId::parse("fss.package_zone_fixture.head.v1")?,
        CalibrationGeneration::parse("cal:uncalibrated:none")?,
        rights,
    )?;
    Ok(ModelPackageArchive::encode(&ModelPackage::new(
        manifest, artifacts,
    )?)?)
}
