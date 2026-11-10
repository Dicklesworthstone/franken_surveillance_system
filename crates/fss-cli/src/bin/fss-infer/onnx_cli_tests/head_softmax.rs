#![forbid(unsafe_code)]

use super::*;

#[path = "../../../../../../tests/fixtures/model/onnx_softmax_split.rs"]
mod fixture;

const RECIPE_V5: &[u8] =
    include_bytes!("../../../../../fss-reference/tests/fixtures/onnx_package/recipe_v5.json");
const RECIPE_V6: &[u8] =
    include_bytes!("../../../../../fss-reference/tests/fixtures/onnx_package/recipe_v6.json");

#[test]
fn recipe_v6_explicitly_normalizes_complete_class_axes_and_preserves_v4_raw_score_semantics()
-> RunResult<()> {
    let parsed = recipe(RECIPE_V6)?;
    assert!(parsed.head_decode.is_none());
    assert!(parsed.head_pyramid.is_none());
    assert!(parsed.head_assembly.is_none());
    let assembly = parsed
        .head_softmax_assembly
        .as_ref()
        .ok_or("softmax assembly missing")?;
    assert_eq!(assembly.boxes_output, fixture::BOXES);
    assert_eq!(assembly.boxes_layout, OnnxHeadLayout::Rows);
    assert_eq!(assembly.scores_output, fixture::SCORES);
    assert_eq!(assembly.scores_layout, OnnxHeadLayout::Channels);
    assert_eq!(assembly.class_indices, fixture::CLASS_INDICES);
    assert_eq!(parsed.target, fixture::TARGET);
    assert_eq!(parsed.head.output_port, fixture::OUTPUT);
    assert_eq!(parsed.head.layout, HeadLayout::Rows);
    assert_eq!(parsed.head.class_score, HeadScore::Probability);
    assert!(parsed.head.objectness.is_none());
    assert_eq!(parsed.labels, ["fixture-class-two", "fixture-class-zero"]);
    for older in [RECIPE, RECIPE_V2, RECIPE_V3, RECIPE_V4, RECIPE_V5] {
        assert!(recipe(older)?.head_softmax_assembly.is_none());
    }
    let v4 = std::str::from_utf8(RECIPE_V4)?.replace(
        "\"class_score\": \"probability\"",
        "\"class_score\": \"logit\"",
    );
    let old = recipe(v4.as_bytes())?;
    assert!(old.head_assembly.is_some());
    assert!(old.head_softmax_assembly.is_none());
    assert_eq!(old.head.class_score, HeadScore::Logit);
    Ok(())
}

#[test]
fn recipe_v6_refuses_double_activation_ambiguous_roles_maps_and_conflicting_modes() -> RunResult<()>
{
    let original = json_input::parse(std::str::from_utf8(RECIPE_V6)?)?;
    let text = |value: &str| Value::Text(value.into());
    let number = |value: &str| Value::Number(value.into());
    let indices =
        |values: &[&str]| Value::Array(values.iter().map(|value| number(value)).collect());
    for (path, value) in [
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v4")),
        (vec!["format"], text("fss.onnx_rgb_package_recipe.v5")),
        (vec!["head_assembly", "kind"], text("split-boxes-scores")),
        (vec!["head_assembly", "kind"], text("automatic")),
        (vec!["head_decode"], Value::Null),
        (vec!["head", "class_score"], text("logit")),
        (vec!["head", "class_score"], text("softmax")),
        (vec!["head", "objectness"], text("probability")),
        (vec!["head", "layout"], text("channels")),
        (vec!["head", "output_port"], text("boxes")),
        (vec!["head", "output_port"], text("logits")),
        (vec!["head_assembly", "boxes_output"], text("logits")),
        (vec!["head_assembly", "scores_output"], text("")),
        (vec!["head_assembly", "scores_output"], text(" ")),
        (vec!["head_assembly", "scores_output"], text("bad\tname")),
        (
            vec!["head_assembly", "scores_output"],
            text(&"x".repeat(513)),
        ),
        (vec!["head_assembly", "scores_layout"], text("automatic")),
        (vec!["head_assembly", "class_indices"], indices(&[])),
        (vec!["head_assembly", "class_indices"], indices(&["2", "2"])),
        (
            vec!["head_assembly", "class_indices"],
            indices(&["257", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            indices(&["2.0", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            indices(&["-1", "0"]),
        ),
        (
            vec!["head_assembly", "class_indices"],
            Value::Array(vec![text("2"), number("0")]),
        ),
        (vec!["head_assembly", "class_indices"], indices(&["2"])),
        (
            vec!["head_assembly", "class_indices"],
            Value::Array(vec![number("0"); 257]),
        ),
        (vec!["head_assembly", "guess_background"], Value::Bool(true)),
    ] {
        let mut changed = original.clone();
        replace_recipe(&mut changed, &path, value)?;
        assert!(
            recipe(recipe_json(&changed).as_bytes()).is_err(),
            "accepted {path:?}"
        );
    }
    for missing in [
        "boxes_output",
        "scores_output",
        "boxes_layout",
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
        assembly.remove(missing);
        assert!(
            recipe(recipe_json(&changed).as_bytes()).is_err(),
            "accepted missing {missing}"
        );
    }
    Ok(())
}

#[test]
fn command_provisions_explicit_softmax_package_and_rejects_conflicting_score_contract_before_output()
-> RunResult<()> {
    let mut directory = None;
    for index in 0..100 {
        let path = std::env::temp_dir().join(format!(
            "fss-onnx-softmax-cli-{}-{index}",
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
        ("recipe", RECIPE_V6.to_vec()),
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
    let output = cleanup.0.join("softmax.fmpk");
    args.extend(["--output".into(), output.as_os_str().to_owned()]);
    let mut report = Vec::new();
    run(parse(&args)?.ok_or("options")?, &mut report)?;
    let archive = fs::read(&output)?;
    assert!(std::str::from_utf8(&report)?.contains(&ContentDigest::sha256(&archive).to_string()));
    assert!(std::str::from_utf8(&report)?.contains("\"activated\":false"));
    assert!(run(parse(&args)?.ok_or("options")?, &mut Vec::new()).is_err());
    assert_eq!(fs::read(&output)?, archive);

    // The head must consume normalized probabilities directly; accepting logit
    // would apply a second activation and violate the declared class semantics.
    for (index, wrong) in [
        std::str::from_utf8(RECIPE_V6)?.replace(
            "\"class_score\": \"probability\"",
            "\"class_score\": \"logit\"",
        ),
        std::str::from_utf8(RECIPE_V6)?.replace(
            "\"scores_layout\": \"channels\"",
            "\"scores_layout\": \"rows\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        fs::write(cleanup.0.join("recipe"), wrong.as_bytes())?;
        args[7] = ContentDigest::sha256(wrong.as_bytes()).to_string().into();
        let refused = cleanup.0.join(format!("refused-{index}.fmpk"));
        let last = args.len() - 1;
        args[last] = refused.as_os_str().to_owned();
        assert!(run(parse(&args)?.ok_or("options")?, &mut Vec::new()).is_err());
        assert!(!refused.exists());
    }
    Ok(())
}
