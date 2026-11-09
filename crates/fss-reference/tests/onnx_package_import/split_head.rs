#![forbid(unsafe_code)]

use super::*;
use fss_reference::ingest::onnx_package::OnnxSplitHeadAssembly;

const SPLIT_SOURCE: &[u8] = include_bytes!("../fixtures/onnx_package/split_head_detector.onnx");

fn split_recipe() -> Test<OnnxPackageRecipe> {
    let mut recipe = recipe()?;
    recipe.model_id = ModelId::parse("MOD-ONNXSPLITFIXTURE-001")?;
    recipe.model_generation = ModelGeneration::parse("model:onnx-split-fixture:g1")?;
    recipe.target = [2, 2];
    recipe.scale_to_unit = true;
    recipe.masked_rgb = [51, 102, 153];
    recipe.image_transform = Some(OnnxImageTransform {
        channel_order: OnnxChannelOrder::Bgr,
        mean: [0.0; 3],
        standard_deviation: [1.0; 3],
    });
    recipe.head_assembly = Some(OnnxSplitHeadAssembly {
        boxes_output: "boxes".into(),
        boxes_layout: OnnxHeadLayout::Rows,
        scores_output: "scores".into(),
        scores_layout: OnnxHeadLayout::Channels,
        class_indices: vec![2, 0],
    });
    recipe.head.output_port = "assembled_head".into();
    recipe.head.boxes = HeadBoxes::NormalizedCenterSize;
    recipe.head.maximum_rows = 2;
    recipe.head.maximum_candidates = 8;
    recipe.head.maximum_detections = 2;
    recipe.labels = vec!["fixture-class-two".into(), "fixture-class-zero".into()];
    recipe.upstream = "fixture:fss/native-onnx-split".into();
    recipe.producer = "FSS pixel-dependent split-head numerical fixture".into();
    Ok(recipe)
}

fn split_request(recipe: &OnnxPackageRecipe) -> OnnxPackageRequest<'_> {
    let mut request = request(recipe);
    request.source = SPLIT_SOURCE;
    request.source_digest = ContentDigest::sha256(SPLIT_SOURCE);
    request
}

#[test]
fn split_package_reopens_source_and_preserves_outputs_while_projecting_named_classes() -> Test {
    let directory = Directory::new("split-roundtrip")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = split_recipe()?;
    assert_eq!(SPLIT_SOURCE.len(), 1060);
    assert_eq!(
        ContentDigest::sha256(SPLIT_SOURCE).to_text(),
        "sha256:9f38352f183e7f2f4748e254a29d121e3f3531c9137dce2750095b009e7d1f29"
    );
    let imported = import_onnx_package(
        &split_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let repeated = import_onnx_package(
        &split_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    assert_eq!(imported.archive(), repeated.archive());
    let archive = ModelPackageArchive::decode(imported.archive(), &ModelPackageLimits::default())?;
    let source = archive
        .artifacts
        .values()
        .find(|artifact| artifact.name == ONNX_SOURCE_ARTIFACT)
        .ok_or("original ONNX")?;
    assert_eq!(source.payload, SPLIT_SOURCE);
    assert_eq!(source.digest, ContentDigest::sha256(SPLIT_SOURCE));
    assert!(
        archive
            .manifest
            .license()
            .artifact_digests()
            .contains(&source.digest)
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
    assert_eq!(loaded.spec().labels, recipe.labels);
    assert_eq!(loaded.model().graph().outputs().len(), 4);

    let inference = run_pixels(&loaded, &[0; 12], &[1; 4])?;
    assert_eq!(inference.outputs()["boxes"].shape(), [1, 2, 4]);
    assert_eq!(inference.outputs()["scores"].shape(), [1, 3, 2]);
    assert_eq!(inference.outputs()["embedding"].values(), [0.0; 3]);
    assert_eq!(inference.outputs()["assembled_head"].shape(), [1, 2, 6]);
    assert_eq!(
        inference.outputs()["assembled_head"].values(),
        [
            0.25, 0.5, 0.5, 1.0, 0.875, 0.125, 0.75, 0.5, 0.5, 1.0, 0.125, 0.875
        ]
    );
    // Source column one deliberately has the highest scores. It is excluded because
    // the recipe lists columns [2, 0], never because of an inferred background rule.
    assert_eq!(
        inference.outputs()["scores"].values(),
        [0.125, 0.875, 0.99, 0.99, 0.875, 0.125]
    );
    let detections = project_rgb_detections(
        &inference,
        loaded.contract(),
        &[1; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(detections.detections().len(), 2);
    for (class, bounds) in [(0, [0, 0, 256, 512]), (1, [256, 0, 512, 512])] {
        let detection = detections
            .detections()
            .iter()
            .find(|detection| detection.class_index() == class)
            .ok_or("explicit class")?;
        assert_eq!(detection.bounds(), bounds);
        assert_eq!(detection.score().to_bits(), 0.875_f32.to_bits());
    }
    Ok(())
}

#[test]
fn split_package_matches_independent_bgr_matrix_oracle_and_preserves_selected_score_bits() -> Test {
    let directory = Directory::new("split-oracle")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = split_recipe()?;
    let imported = import_onnx_package(
        &split_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let pixels = [10, 50, 90, 20, 100, 180, 30, 150, 210, 40, 200, 240];
    let inference = run_pixels(imported.package(), &pixels, &[1; 4])?;
    let mut means = [0.0_f32; 3];
    for (channel, rgb_channel) in [2, 1, 0].into_iter().enumerate() {
        for pixel in 0..4 {
            means[channel] += f32::from(pixels[pixel * 3 + rgb_channel]) * (1.0_f32 / 255.0_f32);
        }
        means[channel] /= 4.0;
    }
    assert_eq!(inference.outputs()["embedding"].values(), means);
    // Independently authored matrix rows. MatMul accumulates channels in order,
    // followed by Add; the package assembler only rearranges the resulting bits.
    let box_weights = [
        [0.0625_f32, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        [0.0, 0.0, 0.0, 0.0, -0.0625, 0.0, 0.0, 0.0],
        [0.0, 0.0, 0.03125, 0.0, 0.0, 0.0, 0.0, 0.0],
    ];
    let score_weights = [
        [0.0625_f32, 0.0, 0.0, 0.0, 0.0, -0.0625],
        [0.0, -0.0625, 0.0, 0.0, 0.0625, 0.0],
        [0.0, 0.0, 0.03125, -0.03125, 0.0, 0.0],
    ];
    let box_bias = [0.25_f32, 0.5, 0.5, 1.0, 0.75, 0.5, 0.5, 1.0];
    let score_bias = [0.125_f32, 0.875, 0.99, 0.99, 0.875, 0.125];
    let mut boxes = [0.0_f32; 8];
    let mut scores = [0.0_f32; 6];
    for field in 0..8 {
        for channel in 0..3 {
            boxes[field] += means[channel] * box_weights[channel][field];
        }
        boxes[field] += box_bias[field];
    }
    for field in 0..6 {
        for channel in 0..3 {
            scores[field] += means[channel] * score_weights[channel][field];
        }
        scores[field] += score_bias[field];
    }
    assert_eq!(inference.outputs()["boxes"].values(), boxes);
    assert_eq!(inference.outputs()["scores"].values(), scores);
    let assembled = inference.outputs()["assembled_head"].values();
    for row in 0..2 {
        assert_eq!(
            &assembled[row * 6..row * 6 + 4],
            &boxes[row * 4..row * 4 + 4]
        );
        for (label, column) in [2, 0].into_iter().enumerate() {
            assert_eq!(
                assembled[row * 6 + 4 + label].to_bits(),
                scores[column * 2 + row].to_bits()
            );
        }
    }
    Ok(())
}

#[test]
fn split_class_mapping_changes_identity_and_logit_rule_is_applied_only_at_projection() -> Test {
    let directory = Directory::new("split-semantics")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = split_recipe()?;
    let first = import_onnx_package(
        &split_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let mut reordered = recipe.clone();
    reordered
        .head_assembly
        .as_mut()
        .ok_or("assembly")?
        .class_indices = vec![0, 2];
    let second = import_onnx_package(
        &split_request(&reordered),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    assert_ne!(first.archive(), second.archive());
    assert_ne!(
        first.package().model().digest(),
        second.package().model().digest()
    );
    let a = run_pixels(first.package(), &[0; 12], &[1; 4])?;
    let b = run_pixels(second.package(), &[0; 12], &[1; 4])?;
    assert_eq!(a.outputs()["boxes"].values(), b.outputs()["boxes"].values());
    assert_eq!(
        a.outputs()["scores"].values(),
        b.outputs()["scores"].values()
    );
    for row in 0..2 {
        assert_eq!(
            &a.outputs()["assembled_head"].values()[row * 6 + 4..row * 6 + 6],
            &b.outputs()["assembled_head"].values()[row * 6 + 4..row * 6 + 6]
                .iter()
                .copied()
                .rev()
                .collect::<Vec<_>>()
        );
    }
    let mut logits = recipe.clone();
    logits.head.class_score = HeadScore::Logit;
    let logit_package = import_onnx_package(
        &split_request(&logits),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    assert_ne!(
        first.package().contract().digest(),
        logit_package.package().contract().digest()
    );
    let inference = run_pixels(logit_package.package(), &[0; 12], &[1; 4])?;
    assert_eq!(
        inference.outputs()["assembled_head"].values(),
        a.outputs()["assembled_head"].values()
    );
    let detections = project_rgb_detections(
        &inference,
        logit_package.package().contract(),
        &[1; 4],
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(detections.detections().len(), 2);
    let expected = 1.0_f32 / (1.0 + (-0.875_f32).exp());
    for detection in detections.detections() {
        assert!((detection.score() - expected).abs() < 1.0e-6);
    }
    Ok(())
}

#[test]
fn split_privacy_substitution_precedes_both_heads_and_footprint_screening() -> Test {
    let directory = Directory::new("split-privacy")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    let recipe = split_recipe()?;
    let imported = import_onnx_package(
        &split_request(&recipe),
        OnnxPackageLimits::default(),
        &cx,
        &scalar,
    )?;
    let mut changed = [0; 12];
    changed[..3].copy_from_slice(&[251, 137, 79]);
    let mask = [0, 1, 1, 1];
    let a = run_pixels(imported.package(), &[0; 12], &mask)?;
    let b = run_pixels(imported.package(), &changed, &mask)?;
    assert_eq!(a.output_digest(), b.output_digest());
    assert_eq!(a.masked_digest(), b.masked_digest());
    assert_ne!(a.identity(), b.identity());
    let replacement =
        [153_u8, 102, 51].map(|value| (f32::from(value) * (1.0_f32 / 255.0_f32)) / 4.0);
    assert_eq!(a.outputs()["embedding"].values(), replacement);
    let screened = project_rgb_detections(
        &b,
        imported.package().contract(),
        &mask,
        &mut RgbDetectionBudget::new(1_000_000, 1 << 20),
        &scalar,
    )?;
    assert_eq!(
        screened.rows()[0].disposition,
        fss_reference::ingest::rgb_detections::HeadRowDisposition::PrivateFootprint
    );
    Ok(())
}

#[test]
fn split_packaging_refuses_conflicting_roles_shapes_mapping_bounds_and_cancellation() -> Test {
    let directory = Directory::new("split-refusals")?;
    let cx = context(&directory.0)?;
    let scalar = ScalarExecCx::new();
    for which in 0..15 {
        let mut recipe = split_recipe()?;
        let assembly = recipe.head_assembly.as_mut().ok_or("assembly")?;
        match which {
            0 => recipe.head.layout = HeadLayout::Channels,
            1 => recipe.head.objectness = Some(HeadScore::Probability),
            2 => recipe.head.output_port = "boxes".into(),
            3 => recipe.head.output_port = "scores".into(),
            4 => assembly.class_indices = vec![2, 2],
            5 => assembly.class_indices = vec![3, 0],
            6 => assembly.class_indices.clear(),
            7 => assembly.boxes_output = "scores".into(),
            8 => assembly.boxes_output = "missing".into(),
            9 => assembly.boxes_layout = OnnxHeadLayout::Channels,
            10 => assembly.scores_layout = OnnxHeadLayout::Rows,
            11 => assembly.scores_output = "embedding".into(),
            12 => {
                recipe.labels.pop();
            }
            13 => recipe.head.maximum_rows = 1,
            _ => {
                recipe.head_decode = Some(OnnxDflHeadDecode {
                    raw_output: "scores".into(),
                    raw_layout: OnnxHeadLayout::Channels,
                    bins: 2,
                    strides: vec![1],
                });
            }
        }
        assert!(
            import_onnx_package(
                &split_request(&recipe),
                OnnxPackageLimits::default(),
                &cx,
                &scalar
            )
            .is_err(),
            "invalid profile {which}"
        );
    }
    let recipe = split_recipe()?;
    let mut wrong_pin = split_request(&recipe);
    wrong_pin.source_digest = ContentDigest::sha256(b"wrong split source");
    assert!(import_onnx_package(&wrong_pin, OnnxPackageLimits::default(), &cx, &scalar).is_err());
    let mut limits = OnnxPackageLimits::default();
    limits.import.work_units = 0;
    assert!(import_onnx_package(&split_request(&recipe), limits, &cx, &scalar).is_err());
    let mut limits = OnnxPackageLimits::default();
    limits.export.work_units = 0;
    assert!(import_onnx_package(&split_request(&recipe), limits, &cx, &scalar).is_err());
    scalar.request_cancellation();
    assert!(matches!(
        import_onnx_package(
            &split_request(&recipe),
            OnnxPackageLimits::default(),
            &cx,
            &scalar
        ),
        Err(OnnxPackageError::Cancelled)
    ));
    Ok(())
}
