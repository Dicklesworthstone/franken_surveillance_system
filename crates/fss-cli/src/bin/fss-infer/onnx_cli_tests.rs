#![forbid(unsafe_code)]

use super::*;

const RECIPE: &[u8] =
    include_bytes!("../../../../fss-reference/tests/fixtures/onnx_package/recipe.json");

#[test]
fn recipe_requires_complete_explicit_choices() -> RunResult<()> {
    let r = recipe(RECIPE)?;
    assert_eq!(r.image_input, "image");
    assert_eq!(r.target, [1, 1]);
    assert_eq!(r.labels, ["fixture-object", "fixture-other"]);
    assert!(r.use_approved);
    assert!(r.head.objectness.is_none());
    let original = std::str::from_utf8(RECIPE)?;
    for text in [
        original.replace("\"resize\": \"nearest\"", "\"resize\": \"automatic\""),
        original.replace("\"use_approved\": true", "\"use_approved\": \"true\""),
        original.replace("\"tensor_generation\": 1", "\"tensor_generation\": 1.5"),
        original.replace("\"width\": 1", "\"width\": 1, \"width\": 2"),
        original.replace("\"width\": 1", "\"width\": 1, \"guess\": true"),
        original.replace("\"objectness\": \"none\",", ""),
        format!("{original} false"),
    ] {
        assert!(recipe(text.as_bytes()).is_err());
    }
    Ok(())
}

fn args() -> Vec<OsString> {
    let sha = ContentDigest::sha256(b"fixture").to_string();
    [
        "--source",
        "model.onnx",
        "--source-digest",
        &sha,
        "--recipe",
        "recipe.json",
        "--recipe-digest",
        &sha,
        "--license",
        "LICENSE",
        "--license-digest",
        &sha,
        "--notice",
        "NOTICE",
        "--notice-digest",
        &sha,
        "--output",
        "model.fmpk",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn command_requires_every_independent_pin_and_refuses_ambiguous_options() -> RunResult<()> {
    assert!(parse(&args())?.is_some());
    for i in (0..args().len()).step_by(2) {
        let mut a = args();
        a.drain(i..i + 2);
        assert!(parse(&a).is_err());
    }
    for pair in [
        ["--unknown", "yes"],
        ["--output", "different.fmpk"],
        ["--max-package-bytes", "33554433"],
    ] {
        let mut a = args();
        a.extend(pair.iter().map(OsString::from));
        assert!(parse(&a).is_err());
    }
    assert!(parse(&["--help".into()])?.is_none());
    assert!(parse(&["--help".into(), "extra".into()]).is_err());
    assert!(dispatch(&["package-detect".into()], &mut Vec::new()).is_none());
    Ok(())
}

#[test]
fn command_creates_verified_package_then_refuses_overwrite() -> RunResult<()> {
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fss-reference/tests/fixtures/onnx_package");
    let mut directory = None;
    for i in 0..100 {
        let path = std::env::temp_dir().join(format!("fss-onnx-cli-{}-{i}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                directory = Some(path);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let directory = directory.ok_or("temporary-directory capacity")?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let cleanup = Cleanup(directory);
    let output = cleanup.0.join("model.fmpk");
    let mut a = Vec::new();
    for (flag, filename) in [
        ("source", "tiny_detector.onnx"),
        ("recipe", "recipe.json"),
        ("license", "LICENSE"),
        ("notice", "NOTICE"),
    ] {
        let path = fixtures.join(filename);
        a.extend([
            OsString::from(format!("--{flag}")),
            path.as_os_str().to_owned(),
            OsString::from(format!("--{flag}-digest")),
            ContentDigest::sha256(&fs::read(path)?).to_string().into(),
        ]);
    }
    a.extend(["--output".into(), output.as_os_str().to_owned()]);
    let mut report = Vec::new();
    run(parse(&a)?.ok_or("options")?, &mut report)?;
    let package = fs::read(&output)?;
    assert!(std::str::from_utf8(&report)?.contains(&ContentDigest::sha256(&package).to_string()));
    assert!(std::str::from_utf8(&report)?.contains("\"activated\":false"));
    assert!(run(parse(&a)?.ok_or("options")?, &mut Vec::new()).is_err());
    assert_eq!(fs::read(&output)?, package);
    // A wrong independent pin cannot create another file.
    let fresh = cleanup.0.join("refused.fmpk");
    *a.last_mut().ok_or("output")? = fresh.as_os_str().to_owned();
    a[3] = ContentDigest::sha256(b"wrong source").to_string().into();
    assert!(run(parse(&a)?.ok_or("options")?, &mut Vec::new()).is_err());
    assert!(!fresh.exists());
    Ok(())
}
