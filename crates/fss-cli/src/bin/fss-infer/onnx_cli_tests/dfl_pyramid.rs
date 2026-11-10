#![forbid(unsafe_code)]

use super::*;
use fss_reference::ingest::onnx_package::OnnxDflPyramidLayout;

#[path = "../../../../../../tests/fixtures/model/onnx_dfl_pyramid.rs"]
#[allow(
    dead_code,
    reason = "the shared numerical oracle runs in model and package contracts"
)]
mod fixture;

const RECIPE_V5: &[u8] =
    include_bytes!("../../../../../fss-reference/tests/fixtures/onnx_package/recipe_v5.json");

fn level(output: &str, stride: Value, layout: &str) -> Value {
    Value::Object(BTreeMap::from([
        ("output".into(), Value::Text(output.into())),
        ("stride".into(), stride),
        ("layout".into(), Value::Text(layout.into())),
    ]))
}

#[test]
fn recipe_v5_binds_named_levels_in_caller_order_without_reinterpreting_older_recipes()
-> RunResult<()> {
    let parsed = recipe(RECIPE_V5)?;
    assert!(parsed.head_decode.is_none());
    assert!(parsed.head_assembly.is_none());
    let pyramid = parsed.head_pyramid.as_ref().ok_or("pyramid missing")?;
    assert_eq!(parsed.target, [8, 8]);
    assert_eq!(pyramid.bins, 4);
    assert_eq!(
        pyramid
            .levels
            .iter()
            .map(|level| (level.output.as_str(), level.stride, level.layout))
            .collect::<Vec<_>>(),
        [
            ("coarse", 4, OnnxDflPyramidLayout::Nchw),
            ("fine", 2, OnnxDflPyramidLayout::Nhwc),
            ("global", 8, OnnxDflPyramidLayout::Nchw),
        ]
    );
    assert_eq!(parsed.head.output_port, "detections");
    assert_eq!(parsed.head.layout, HeadLayout::Rows);
    assert_eq!(parsed.head.boxes, HeadBoxes::PixelCorners);
    assert_eq!(parsed.head.maximum_rows, 21);
    for older in [RECIPE, RECIPE_V2, RECIPE_V3, RECIPE_V4] {
        assert!(recipe(older)?.head_pyramid.is_none());
    }

    let mut changed = json_input::parse(std::str::from_utf8(RECIPE_V5)?)?;
    replace_recipe(
        &mut changed,
        &["head_decode", "levels"],
        Value::Array(vec![
            level("global", Value::Number("8".into()), "nchw"),
            level("coarse", Value::Number("4".into()), "nchw"),
            level("fine", Value::Number("2".into()), "nhwc"),
        ]),
    )?;
    let parsed = recipe(recipe_json(&changed).as_bytes())?;
    let reordered = parsed.head_pyramid.ok_or("pyramid missing")?;
    assert_eq!(
        reordered
            .levels
            .iter()
            .map(|level| level.stride)
            .collect::<Vec<_>>(),
        [8, 4, 2]
    );
    Ok(())
}

#[test]
fn recipe_v5_refuses_ambiguous_levels_layouts_grids_and_conflicting_profiles() -> RunResult<()> {
    let original = json_input::parse(std::str::from_utf8(RECIPE_V5)?)?;
    let number = |value: &str| Value::Number(value.into());
    let text = |value: &str| Value::Text(value.into());
    let one = |output: &str, stride: Value, layout: &str| {
        Value::Array(vec![level(output, stride, layout)])
    };
    for (path, value) in [
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v3")),
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v4")),
        (vec!["head_decode", "kind"], text("anchor-free-dfl")),
        (vec!["head_decode", "raw_output"], text("coarse")),
        (vec!["head_assembly"], Value::Null),
        (vec!["head_decode", "bins"], number("1")),
        (vec!["head_decode", "bins"], number("33")),
        (vec!["head_decode", "bins"], number("4.0")),
        (vec!["head_decode", "bins"], text("4")),
        (vec!["head_decode", "levels"], Value::Array(vec![])),
        (vec!["head_decode", "levels"], one("", number("4"), "nchw")),
        (vec!["head_decode", "levels"], one(" ", number("4"), "nchw")),
        (
            vec!["head_decode", "levels"],
            one("bad\u{0000}name", number("4"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one(&"x".repeat(513), number("4"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", number("4"), "automatic"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", number("0"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", number("3"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", number("4097"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", number("4.0"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            one("coarse", text("4"), "nchw"),
        ),
        (
            vec!["head_decode", "levels"],
            Value::Array(vec![
                level("coarse", number("4"), "nchw"),
                level("coarse", number("2"), "nchw"),
            ]),
        ),
        (
            vec!["head_decode", "levels"],
            Value::Array(vec![
                level("coarse", number("4"), "nchw"),
                level("fine", number("4"), "nhwc"),
            ]),
        ),
        (
            vec!["head_decode", "levels"],
            Value::Array(vec![level("coarse", number("4"), "nchw"); 9]),
        ),
        (vec!["head", "output_port"], text("coarse")),
        (vec!["head", "layout"], text("channels")),
        (vec!["head", "boxes"], text("normalized-corners")),
        (vec!["head", "maximum_rows"], number("20")),
        (vec!["preprocess", "height"], number("0")),
        (vec!["preprocess", "height"], number("4097")),
    ] {
        let mut changed = original.clone();
        replace_recipe(&mut changed, &path, value)?;
        assert!(
            recipe(recipe_json(&changed).as_bytes()).is_err(),
            "accepted {path:?}"
        );
    }
    for key in ["output", "stride", "layout"] {
        let mut incomplete = BTreeMap::from([
            ("output".into(), text("coarse")),
            ("stride".into(), number("4")),
            ("layout".into(), text("nchw")),
        ]);
        incomplete.remove(key);
        let mut changed = original.clone();
        replace_recipe(
            &mut changed,
            &["head_decode", "levels"],
            Value::Array(vec![Value::Object(incomplete)]),
        )?;
        assert!(recipe(recipe_json(&changed).as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn command_provisions_three_scale_package_and_refuses_bad_level_shape_before_output()
-> RunResult<()> {
    let mut directory = None;
    for index in 0..100 {
        let path = std::env::temp_dir().join(format!(
            "fss-onnx-pyramid-cli-{}-{index}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                directory = Some(path);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let cleanup = Cleanup(directory.ok_or("temporary-directory capacity")?);
    let license_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fss-reference/tests/fixtures/onnx_package");
    let inputs = [
        ("source", fixture::model()),
        ("recipe", RECIPE_V5.to_vec()),
        ("license", fs::read(license_root.join("LICENSE"))?),
        ("notice", fs::read(license_root.join("NOTICE"))?),
    ];
    let mut args = Vec::new();
    for (flag, bytes) in &inputs {
        let path = cleanup.0.join(flag);
        fs::write(&path, bytes)?;
        args.extend([
            OsString::from(format!("--{flag}")),
            path.into_os_string(),
            OsString::from(format!("--{flag}-digest")),
            ContentDigest::sha256(bytes).to_string().into(),
        ]);
    }
    let output = cleanup.0.join("pyramid.fmpk");
    args.extend(["--output".into(), output.as_os_str().to_owned()]);
    let mut report = Vec::new();
    run(parse(&args)?.ok_or("options")?, &mut report)?;
    let archive = fs::read(&output)?;
    assert!(std::str::from_utf8(&report)?.contains(&ContentDigest::sha256(&archive).to_string()));
    assert!(std::str::from_utf8(&report)?.contains("\"activated\":false"));
    assert!(run(parse(&args)?.ok_or("options")?, &mut Vec::new()).is_err());
    assert_eq!(fs::read(&output)?, archive);

    // The recipe is well-formed, but the retained source's coarse level is NCHW.
    // Wrong layout must fail graph admission before the fresh output is opened.
    let wrong =
        std::str::from_utf8(RECIPE_V5)?.replacen("\"layout\": \"nchw\"", "\"layout\": \"nhwc\"", 1);
    fs::write(cleanup.0.join("recipe"), wrong.as_bytes())?;
    args[7] = ContentDigest::sha256(wrong.as_bytes()).to_string().into();
    let refused = cleanup.0.join("refused.fmpk");
    let last = args.len() - 1;
    args[last] = refused.as_os_str().to_owned();
    assert!(run(parse(&args)?.ok_or("options")?, &mut Vec::new()).is_err());
    assert!(!refused.exists());
    Ok(())
}
