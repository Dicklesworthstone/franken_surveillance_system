#![forbid(unsafe_code)]
//! Complete multi-scale source -> archive -> native RGB detector path.

use super::*;
use fss_reference::ingest::onnx_package::{
    OnnxDflPyramidDecode, OnnxDflPyramidLayout, OnnxDflPyramidLevel,
};

#[path = "../../../../tests/fixtures/model/onnx_dfl_pyramid.rs"]
mod fixture;

fn pyramid_recipe() -> Test<OnnxPackageRecipe> {
    let mut recipe = recipe()?;
    recipe.model_id = ModelId::parse("MOD-ONNXPYRAMIDFIXTURE-001")?;
    recipe.model_generation = ModelGeneration::parse("model:onnx-pyramid-fixture:g1")?;
    recipe.target = fixture::TARGET;
    recipe.image_input = fixture::INPUT.into();
    recipe.scale_to_unit = true;
    recipe.image_transform = Some(OnnxImageTransform {
        channel_order: OnnxChannelOrder::Rgb,
        mean: [0.0; 3],
        standard_deviation: [1.0; 3],
    });
    recipe.head_pyramid = Some(OnnxDflPyramidDecode {
        bins: fixture::BINS,
        levels: (0..3)
            .map(|index| OnnxDflPyramidLevel {
                output: fixture::LEVEL_OUTPUTS[index].into(),
                stride: fixture::LEVEL_STRIDES[index],
                layout: if fixture::LEVEL_NCHW[index] {
                    OnnxDflPyramidLayout::Nchw
                } else {
                    OnnxDflPyramidLayout::Nhwc
                },
            })
            .collect(),
    });
    recipe.head.output_port = fixture::OUTPUT.into();
    recipe.head.maximum_rows = fixture::ROWS;
    recipe.head.maximum_candidates = 42;
    recipe.head.maximum_detections = fixture::ROWS;
    recipe.upstream = "fixture:fss/native-onnx-dfl-pyramid".into();
    recipe.producer = "FSS RGB-dependent three-scale DFL numerical fixture".into();
    Ok(recipe)
}

fn pyramid_request<'a>(recipe: &'a OnnxPackageRecipe, source: &'a [u8]) -> OnnxPackageRequest<'a> {
    let mut request = request(recipe);
    request.source = source;
    request.source_digest = ContentDigest::sha256(source);
    request
}

fn assert_oracle(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), fixture::ROWS * (4 + fixture::SCORE_FIELDS));
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        let tolerance = if index % 6 < 4 { 2e-4 } else { 2e-6 };
        assert!(
            actual.is_finite() && (actual - expected).abs() <= tolerance,
            "row {} field {}: {actual} != {expected}",
            index / 6,
            index % 6
        );
    }
}

#[test]
fn pyramid_package_preserves_source_and_runs_all_scales_after_archive_reload() -> Test {
    let directory = Directory::new("pyramid-roundtrip")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = pyramid_recipe()?;
    let source = fixture::model();
    let request = pyramid_request(&recipe, &source);
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
        loaded
            .model()
            .graph()
            .outputs()
            .iter()
            .map(|port| port.name())
            .collect::<Vec<_>>(),
        ["fine", "global", "coarse", "embedding", "detections"]
    );

    let inference = run_pixels(&loaded, &fixture::sample_rgb(), &[1; 64])?;
    let decoded = inference
        .outputs()
        .get(fixture::OUTPUT)
        .ok_or("decoded head")?;
    assert_eq!(decoded.shape(), [1, fixture::ROWS, 6]);
    assert_oracle(decoded.values(), &fixture::oracle(&fixture::sample_input()));
    for index in 0..3 {
        let level = inference
            .outputs()
            .get(fixture::LEVEL_OUTPUTS[index])
            .ok_or("original level")?;
        assert_eq!(level.shape(), fixture::level_shape(index));
    }
    assert_eq!(
        inference.outputs()["embedding"].values(),
        inference.outputs()["global"].values()
    );

    // Exact score bits survive packing, independent of the coordinate oracle.
    let mut first_row = 0;
    for index in 0..3 {
        let rows = (fixture::TARGET[0] / fixture::LEVEL_STRIDES[index])
            * (fixture::TARGET[1] / fixture::LEVEL_STRIDES[index]);
        let level = inference.outputs()[fixture::LEVEL_OUTPUTS[index]].values();
        for row in 0..rows {
            for score in 0..fixture::SCORE_FIELDS {
                let field = 4 * fixture::BINS + score;
                let source_index = if fixture::LEVEL_NCHW[index] {
                    field * rows + row
                } else {
                    row * fixture::FIELDS + field
                };
                assert_eq!(
                    level[source_index].to_bits(),
                    decoded.values()[(first_row + row) * 6 + 4 + score].to_bits()
                );
            }
        }
        first_row += rows;
    }
    let detection = project_rgb_detections(
        &inference,
        loaded.contract(),
        &[1; 64],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(detection.rows().len(), fixture::ROWS);
    assert!(!detection.detections().is_empty());
    assert!(
        detection
            .detections()
            .iter()
            .all(|item| item.class_index() == 0)
    );
    Ok(())
}

#[test]
fn pyramid_packaging_keeps_privacy_replacement_before_every_feature_level() -> Test {
    let directory = Directory::new("pyramid-privacy")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = pyramid_recipe()?;
    let source = fixture::model();
    let imported = import_onnx_package(
        &pyramid_request(&recipe, &source),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let loaded = imported.package();
    let mut mask = [1; 64];
    mask[0] = 0;
    let first = fixture::sample_rgb();
    let mut changed = first.clone();
    changed[..3].copy_from_slice(&[251, 137, 79]);
    let a = run_pixels(loaded, &first, &mask)?;
    let b = run_pixels(loaded, &changed, &mask)?;
    assert_eq!(a.output_digest(), b.output_digest());
    assert_ne!(a.identity(), b.identity());
    let visible = run_pixels(loaded, &changed, &[1; 64])?;
    assert_ne!(a.output_digest(), visible.output_digest());

    let denied = run_pixels(loaded, &changed, &[0; 64])?;
    assert_oracle(
        denied.outputs()[fixture::OUTPUT].values(),
        &fixture::oracle(&[0.0; 192]),
    );
    let screened = project_rgb_detections(
        &denied,
        loaded.contract(),
        &[0; 64],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert!(screened.detections().is_empty());
    assert!(screened.rows().iter().all(|row| {
        row.disposition
            == fss_reference::ingest::rgb_detections::HeadRowDisposition::PrivateFootprint
    }));
    Ok(())
}

#[test]
fn pyramid_package_refuses_conflicting_modes_and_source_shape_or_vocabulary_drift() -> Test {
    let directory = Directory::new("pyramid-refusals")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let source = fixture::model();
    for which in 0..14 {
        let mut recipe = pyramid_recipe()?;
        match which {
            0 => recipe.head_decode = dfl_recipe()?.head_decode,
            1 => {
                recipe.head_assembly = Some(fss_model_ir::OnnxSplitHeadAssembly {
                    boxes_output: "coarse".into(),
                    boxes_layout: OnnxHeadLayout::Rows,
                    scores_output: "fine".into(),
                    scores_layout: OnnxHeadLayout::Rows,
                    class_indices: vec![0, 1],
                });
            }
            2 => recipe.head.layout = HeadLayout::Channels,
            3 => recipe.head.boxes = HeadBoxes::NormalizedCorners,
            4 => recipe.head.output_port = "coarse".into(),
            5 => recipe.head_pyramid.as_mut().ok_or("pyramid")?.levels[0].stride = 2,
            6 => recipe.head_pyramid.as_mut().ok_or("pyramid")?.levels[0].output = "missing".into(),
            7 => {
                recipe.head_pyramid.as_mut().ok_or("pyramid")?.levels[0].layout =
                    OnnxDflPyramidLayout::Nhwc;
            }
            8 => recipe.head_pyramid.as_mut().ok_or("pyramid")?.bins = 2,
            9 => {
                recipe.labels.pop();
            }
            10 => {
                let levels = &mut recipe.head_pyramid.as_mut().ok_or("pyramid")?.levels;
                let first = levels[0].output.clone();
                levels[0].output = levels[1].output.clone();
                levels[1].output = first;
            }
            11 => recipe.target = [16, 8],
            12 => recipe.head.maximum_rows = 20,
            _ => recipe.head.objectness = Some(HeadScore::Probability),
        }
        assert!(
            import_onnx_package(
                &pyramid_request(&recipe, &source),
                OnnxPackageLimits::default(),
                &cx,
                &scalar,
            )
            .is_err(),
            "accepted conflicting recipe {which}"
        );
    }
    Ok(())
}
