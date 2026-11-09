#![forbid(unsafe_code)]

use super::*;

#[test]
fn recipe_v4_preserves_named_roles_layouts_and_class_order() -> RunResult<()> {
    let parsed = recipe(RECIPE_V4)?;
    let assembly = parsed.head_assembly.as_ref().ok_or("assembly missing")?;
    assert!(parsed.head_decode.is_none());
    assert_eq!(parsed.target, [2, 2]);
    assert_eq!(assembly.boxes_output, "boxes");
    assert_eq!(assembly.boxes_layout, OnnxHeadLayout::Rows);
    assert_eq!(assembly.scores_output, "scores");
    assert_eq!(assembly.scores_layout, OnnxHeadLayout::Channels);
    assert_eq!(assembly.class_indices, [2, 0]);
    assert_eq!(parsed.labels, ["fixture-class-two", "fixture-class-zero"]);
    assert_eq!(parsed.head.output_port, "assembled_head");
    assert_eq!(parsed.head.layout, HeadLayout::Rows);
    assert_eq!(parsed.head.boxes, HeadBoxes::NormalizedCenterSize);
    assert_eq!(parsed.head.class_score, HeadScore::Probability);
    assert!(parsed.head.objectness.is_none());
    assert_eq!(
        parsed.image_transform.ok_or("transform")?.channel_order,
        OnnxChannelOrder::Bgr
    );

    let original = json_input::parse(std::str::from_utf8(RECIPE_V4)?)?;
    for (name, boxes) in [
        ("pixel-corners", HeadBoxes::PixelCorners),
        ("pixel-center-size", HeadBoxes::PixelCenterSize),
        ("normalized-corners", HeadBoxes::NormalizedCorners),
        ("normalized-center-size", HeadBoxes::NormalizedCenterSize),
    ] {
        let mut changed = original.clone();
        replace_recipe(&mut changed, &["head", "boxes"], Value::Text(name.into()))?;
        replace_recipe(
            &mut changed,
            &["head", "class_score"],
            Value::Text("logit".into()),
        )?;
        replace_recipe(
            &mut changed,
            &["head_assembly", "class_indices"],
            Value::Array(vec![Value::Number("0".into()), Value::Number("2".into())]),
        )?;
        replace_recipe(
            &mut changed,
            &["head_assembly", "boxes_layout"],
            Value::Text("channels".into()),
        )?;
        replace_recipe(
            &mut changed,
            &["head_assembly", "scores_layout"],
            Value::Text("rows".into()),
        )?;
        let changed = recipe(recipe_json(&changed).as_bytes())?;
        assert_eq!(changed.head.boxes, boxes);
        assert_eq!(changed.head.class_score, HeadScore::Logit);
        let assembly = changed.head_assembly.ok_or("assembly")?;
        assert_eq!(assembly.class_indices, [0, 2]);
        assert_eq!(assembly.boxes_layout, OnnxHeadLayout::Channels);
        assert_eq!(assembly.scores_layout, OnnxHeadLayout::Rows);
    }
    Ok(())
}

#[test]
fn recipe_v4_refuses_implicit_mapping_types_and_conflicting_heads() -> RunResult<()> {
    let original = json_input::parse(std::str::from_utf8(RECIPE_V4)?)?;
    let number = |value: &str| Value::Number(value.into());
    let text = |value: &str| Value::Text(value.into());
    let numbers =
        |values: &[&str]| Value::Array(values.iter().map(|value| number(value)).collect());
    for (path, value) in [
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v1")),
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v2")),
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v3")),
        (vec!["head_decode"], Value::Null),
        (vec!["head_assembly", "kind"], text("automatic")),
        (vec!["head_assembly", "boxes_layout"], text("automatic")),
        (vec!["head_assembly", "scores_layout"], text("automatic")),
        (vec!["head_assembly", "background_index"], number("1")),
        (vec!["head_assembly", "boxes_output"], text("")),
        (vec!["head_assembly", "boxes_output"], text("   ")),
        (
            vec!["head_assembly", "boxes_output"],
            text("bad\u{0000}name"),
        ),
        (vec!["head_assembly", "boxes_output"], text("scores")),
        (
            vec!["head_assembly", "scores_output"],
            text("assembled_head"),
        ),
        (
            vec!["head_assembly", "scores_output"],
            text(&"x".repeat(513)),
        ),
        (vec!["head", "layout"], text("channels")),
        (vec!["head", "objectness"], text("probability")),
        (vec!["head", "objectness"], text("logit")),
        (vec!["head", "class_score"], text("automatic")),
        (vec!["head", "boxes"], text("automatic")),
        (vec!["head_assembly", "class_indices"], numbers(&[])),
        (vec!["head_assembly", "class_indices"], numbers(&["0"])),
        (vec!["head_assembly", "class_indices"], numbers(&["0", "0"])),
        (
            vec!["head_assembly", "class_indices"],
            numbers(&["-1", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            numbers(&["257", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            numbers(&["2.0", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            numbers(&["2e0", "0"]),
        ),
        (vec!["head_assembly", "class_indices"], numbers(&["0"; 257])),
        (
            vec!["head_assembly", "class_indices"],
            Value::Array(vec![text("2"), number("0")]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            Value::Array(vec![Value::Bool(true), number("0")]),
        ),
    ] {
        let mut changed = original.clone();
        replace_recipe(&mut changed, &path, value)?;
        assert!(
            recipe(recipe_json(&changed).as_bytes()).is_err(),
            "{path:?}"
        );
    }
    for key in [
        "kind",
        "boxes_output",
        "boxes_layout",
        "scores_output",
        "scores_layout",
        "class_indices",
    ] {
        let mut changed = original.clone();
        let Value::Object(root) = &mut changed else {
            return Err("root object".into());
        };
        let Some(Value::Object(assembly)) = root.get_mut("head_assembly") else {
            return Err("assembly object".into());
        };
        assembly.remove(key);
        assert!(recipe(recipe_json(&changed).as_bytes()).is_err(), "{key}");
    }
    let text = std::str::from_utf8(RECIPE_V4)?;
    let duplicate = text.replace(
        "\"class_indices\":",
        "\"class_indices\": [2, 0], \"class_indices\":",
    );
    assert!(recipe(duplicate.as_bytes()).is_err());
    Ok(())
}
