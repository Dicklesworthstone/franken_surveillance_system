#![forbid(unsafe_code)]
//! Full-class Softmax -> archive -> native RGB inference -> privacy-screened detections.

use super::*;
use fss_model_ir::{
    OnnxDflPyramidDecode, OnnxDflPyramidLayout, OnnxDflPyramidLevel, OnnxSplitHeadAssembly,
};
use fss_reference::ingest::rgb_detections::HeadRowDisposition;

#[path = "../../../../tests/fixtures/model/onnx_softmax_split.rs"]
mod fixture;

fn softmax_recipe() -> Test<OnnxPackageRecipe> {
    let mut recipe = recipe()?;
    recipe.model_id = ModelId::parse("MOD-ONNXSOFTMAXFIXTURE-001")?;
    recipe.model_generation = ModelGeneration::parse("model:onnx-softmax-fixture:g1")?;
    recipe.target = fixture::TARGET;
    recipe.image_input = fixture::INPUT.into();
    recipe.scale_to_unit = true;
    recipe.image_transform = Some(OnnxImageTransform {
        channel_order: OnnxChannelOrder::Rgb,
        mean: [0.0; 3],
        standard_deviation: [1.0; 3],
    });
    recipe.head_softmax_assembly = Some(OnnxSplitHeadAssembly {
        boxes_output: fixture::BOXES.into(),
        boxes_layout: OnnxHeadLayout::Rows,
        scores_output: fixture::SCORES.into(),
        scores_layout: OnnxHeadLayout::Channels,
        class_indices: fixture::CLASS_INDICES.to_vec(),
    });
    recipe.head.output_port = fixture::OUTPUT.into();
    recipe.head.maximum_rows = fixture::ROWS;
    recipe.head.maximum_candidates = 4;
    recipe.head.maximum_detections = fixture::ROWS;
    recipe.labels = vec!["fixture-class-two".into(), "fixture-class-zero".into()];
    recipe.upstream = "fixture:fss/native-onnx-softmax-split".into();
    recipe.producer = "FSS RGB-dependent full-class Softmax numerical fixture".into();
    Ok(recipe)
}

fn softmax_request<'a>(recipe: &'a OnnxPackageRecipe, source: &'a [u8]) -> OnnxPackageRequest<'a> {
    let mut request = request(recipe);
    request.source = source;
    request.source_digest = ContentDigest::sha256(source);
    request
}

fn assert_oracle(actual: &[f32], expected: &[f32]) {
    assert_eq!(
        actual.len(),
        fixture::ROWS * (4 + fixture::CLASS_INDICES.len())
    );
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        assert!(actual.is_finite());
        if index % 6 < 4 {
            assert_eq!(actual.to_bits(), expected.to_bits(), "box field {index}");
        } else {
            assert!(
                (actual - expected).abs() <= 2e-6,
                "probability field {index}: {actual} vs {expected}"
            );
        }
    }
}

#[test]
fn class_softmax_package_reloads_original_logits_and_excludes_the_background_dominated_row() -> Test
{
    let directory = Directory::new("softmax-roundtrip")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = softmax_recipe()?;
    let source = fixture::model();
    let request = softmax_request(&recipe, &source);
    let imported = import_onnx_package(&request, OnnxPackageLimits::default(), &cx, &scalar)?;
    let repeated = import_onnx_package(&request, OnnxPackageLimits::default(), &cx, &scalar)?;
    assert_eq!(imported.archive(), repeated.archive());
    let archive = ModelPackageArchive::decode(imported.archive(), &ModelPackageLimits::default())?;
    let original = archive
        .artifacts
        .values()
        .find(|artifact| artifact.name == ONNX_SOURCE_ARTIFACT)
        .ok_or("original ONNX")?;
    assert_eq!(original.payload, source);
    assert_eq!(original.digest, request.source_digest);
    assert!(
        archive
            .manifest
            .license()
            .artifact_digests()
            .contains(&original.digest)
    );
    let loaded = RgbDetectorPackage::load(
        imported.archive(),
        imported.package().archive_digest(),
        1 << 32,
        &cx,
        &scalar,
    )?;
    assert_eq!(loaded.model().digest(), imported.package().model().digest());
    assert_eq!(
        loaded.contract().digest(),
        imported.package().contract().digest()
    );
    assert_eq!(
        loaded.model().graph().version(),
        fss_model_ir::ModelIrVersion::V2
    );
    assert_eq!(
        loaded
            .model()
            .graph()
            .outputs()
            .iter()
            .map(|port| port.name())
            .collect::<Vec<_>>(),
        [
            fixture::SCORES,
            "embedding",
            fixture::BOXES,
            fixture::OUTPUT
        ]
    );

    let inference = run_pixels(&loaded, &fixture::sample_rgb(), &[1; 4])?;
    let decoded = inference
        .outputs()
        .get(fixture::OUTPUT)
        .ok_or("decoded head")?;
    assert_eq!(decoded.shape(), [1, fixture::ROWS, 6]);
    assert_oracle(decoded.values(), &fixture::oracle(&fixture::sample_input()));
    assert_eq!(
        inference.outputs()[fixture::BOXES].shape(),
        fixture::BOX_SHAPE
    );
    assert_eq!(
        inference.outputs()[fixture::BOXES].values(),
        fixture::BOX_VALUES
    );
    assert_eq!(
        inference.outputs()[fixture::SCORES].shape(),
        fixture::SCORE_SHAPE
    );
    assert_eq!(
        inference.outputs()[fixture::SCORES].values().len(),
        fixture::ROWS * fixture::SCORE_FIELDS
    );

    // Independently execute the original unadapted source to establish that every
    // source output, including raw logits and auxiliary features, survives packaging.
    let original = fss_model_ir::import_onnx(
        &source,
        request.source_digest,
        recipe.tensor_generation,
        Default::default(),
        &|| false,
    )?;
    let mut inputs = original.parameters().clone();
    inputs.insert(
        fixture::INPUT.into(),
        fss_tensor::Tensor::from_values(
            fss_tensor::Shape::new(vec![1, 3, 2, 2])?,
            &fixture::sample_input(),
            recipe.tensor_generation,
        )?,
    );
    let original_output = fss_reference::ScalarExecutor::run(
        original.graph(),
        &inputs.into_iter().collect::<Vec<_>>(),
        ExecBudget::unlimited(),
        &scalar,
    )?;
    for name in [fixture::BOXES, fixture::SCORES, "embedding"] {
        let expected = original_output
            .get_output(name)
            .ok_or("source output")?
            .to_vec::<f32>()?;
        assert_eq!(
            inference.outputs()[name]
                .values()
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            "retained original output {name}",
        );
    }
    let detection = project_rgb_detections(
        &inference,
        loaded.contract(),
        &[1; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(detection.rows().len(), 2);
    assert_eq!(
        detection.rows()[0].disposition,
        HeadRowDisposition::BelowThreshold
    );
    assert_eq!(
        detection.rows()[1].disposition,
        HeadRowDisposition::Candidates(1)
    );
    assert_eq!(detection.detections().len(), 1);
    let found = detection.detections()[0];
    assert_eq!(found.row(), 1);
    assert_eq!(found.class_index(), 0);
    assert_eq!(found.bounds(), [256, 256, 512, 512]);
    assert!(found.score() > 0.99);
    assert!(decoded.values()[4] < 0.005 && decoded.values()[5] < 0.005);
    Ok(())
}

#[test]
fn class_softmax_packaging_masks_before_normalization_and_screens_private_foreground_boxes() -> Test
{
    let directory = Directory::new("softmax-privacy")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = softmax_recipe()?;
    let source = fixture::model();
    let imported = import_onnx_package(
        &softmax_request(&recipe, &source),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let package = imported.package();
    let mask = [1, 1, 1, 0];
    let first = fixture::sample_rgb();
    let mut changed = first.clone();
    changed[9..12].copy_from_slice(&[251, 137, 79]);
    let a = run_pixels(package, &first, &mask)?;
    let b = run_pixels(package, &changed, &mask)?;
    assert_eq!(a.output_digest(), b.output_digest());
    assert_ne!(a.identity(), b.identity());
    let public = run_pixels(package, &changed, &[1; 4])?;
    assert_ne!(a.output_digest(), public.output_digest());
    let screened = project_rgb_detections(
        &b,
        package.contract(),
        &mask,
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert!(screened.detections().is_empty());
    assert_eq!(
        screened.rows()[0].disposition,
        HeadRowDisposition::BelowThreshold
    );
    assert_eq!(
        screened.rows()[1].disposition,
        HeadRowDisposition::PrivateFootprint
    );

    let denied = run_pixels(package, &changed, &[0; 4])?;
    assert_oracle(
        denied.outputs()[fixture::OUTPUT].values(),
        &fixture::oracle(&[0.0; 12]),
    );
    let screened = project_rgb_detections(
        &denied,
        package.contract(),
        &[0; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert!(screened.detections().is_empty());
    assert_eq!(
        screened.rows()[1].disposition,
        HeadRowDisposition::PrivateFootprint
    );
    Ok(())
}

#[test]
fn class_softmax_package_refuses_conflicting_modes_scores_roles_layouts_and_label_maps() -> Test {
    let directory = Directory::new("softmax-refusals")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let source = fixture::model();
    for which in 0..15 {
        let mut recipe = softmax_recipe()?;
        match which {
            0 => recipe.head.class_score = HeadScore::Logit,
            1 => recipe.head.objectness = Some(HeadScore::Probability),
            2 => recipe.head.layout = HeadLayout::Channels,
            3 => recipe.head.output_port = fixture::BOXES.into(),
            4 => recipe.head.output_port = fixture::SCORES.into(),
            5 => {
                recipe.labels.pop();
            }
            6 => {
                recipe
                    .head_softmax_assembly
                    .as_mut()
                    .ok_or("assembly")?
                    .class_indices = vec![0, 0]
            }
            7 => {
                recipe
                    .head_softmax_assembly
                    .as_mut()
                    .ok_or("assembly")?
                    .class_indices = vec![3, 0]
            }
            8 => {
                recipe
                    .head_softmax_assembly
                    .as_mut()
                    .ok_or("assembly")?
                    .boxes_output = "features".into()
            }
            9 => {
                recipe
                    .head_softmax_assembly
                    .as_mut()
                    .ok_or("assembly")?
                    .scores_layout = OnnxHeadLayout::Rows
            }
            10 => recipe.head.maximum_rows = 1,
            11 => recipe.target = [1, 2],
            12 => recipe.head_assembly = recipe.head_softmax_assembly.clone(),
            13 => recipe.head_decode = dfl_recipe()?.head_decode,
            _ => {
                recipe.head_pyramid = Some(OnnxDflPyramidDecode {
                    bins: 2,
                    levels: vec![OnnxDflPyramidLevel {
                        output: fixture::SCORES.into(),
                        stride: 1,
                        layout: OnnxDflPyramidLayout::Nchw,
                    }],
                })
            }
        }
        assert!(
            import_onnx_package(
                &softmax_request(&recipe, &source),
                OnnxPackageLimits::default(),
                &cx,
                &scalar,
            )
            .is_err(),
            "accepted conflicting class-softmax recipe {which}"
        );
    }
    Ok(())
}

#[test]
fn existing_v4_split_assembly_keeps_independent_logit_semantics_without_implicit_softmax() -> Test {
    let directory = Directory::new("softmax-v4-compatibility")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let source = fixture::model();
    let mut recipe = softmax_recipe()?;
    recipe.head_assembly = recipe.head_softmax_assembly.take();
    recipe.head.class_score = HeadScore::Logit;
    let imported = import_onnx_package(
        &softmax_request(&recipe, &source),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    assert!(
        !imported
            .package()
            .model()
            .graph()
            .nodes()
            .iter()
            .any(|node| node.op() == fss_model_ir::OpCode::Softmax)
    );
    let inference = run_pixels(imported.package(), &fixture::sample_rgb(), &[1; 4])?;
    let scores = inference.outputs()[fixture::SCORES].values();
    let assembled = inference.outputs()[fixture::OUTPUT].values();
    for row in 0..fixture::ROWS {
        for (offset, class) in fixture::CLASS_INDICES.into_iter().enumerate() {
            assert_eq!(
                assembled[row * 6 + 4 + offset].to_bits(),
                scores[class * fixture::ROWS + row].to_bits()
            );
        }
    }
    let detection = project_rgb_detections(
        &inference,
        imported.package().contract(),
        &[1; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    // V4 still interprets these as independent logits. Only explicit v6 performs
    // class competition with the omitted background before foreground selection.
    assert_eq!(detection.detections().len(), 2);
    assert!(detection.detections().iter().any(|item| item.row() == 0));
    Ok(())
}
