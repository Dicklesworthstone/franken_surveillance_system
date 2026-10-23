#![forbid(unsafe_code)]
//! Real retained-file import -> native activity publication -> independent cold verification.
//! First-party generated pixels exercise wiring, never detector-quality claims.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{self, Value};
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:recorded-activity-cli";
const SENSOR: &str = "sensor:recorded-activity-cli";
const STREAM: &str = "stream:recorded-activity-cli";

struct Fixture {
    root: PathBuf,
    import: String,
    directory: PathBuf,
}

impl Fixture {
    fn new(name: &str, quiet: bool) -> TestResult<Self> {
        let directory = (0..100_u32)
            .find_map(|attempt| {
                let path = std::env::temp_dir().join(format!(
                    "fss-recorded-activity-cli-{name}-{}-{attempt}",
                    std::process::id(),
                ));
                match fs::create_dir(&path) {
                    Ok(()) => Some(Ok(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .ok_or("fixture directory capacity")??;
        let root = directory.join("deployment");
        let source = directory.join("real-retained-input.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let background = encode_jpeg(32, 32, &[16_u8; 1024], &config)?;
        let changed = encode_jpeg(32, 32, &[220_u8; 1024], &config)?;
        let mut recording = background.clone();
        recording.extend_from_slice(if quiet { &background } else { &changed });
        fs::write(&source, recording)?;
        let imported = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(&root)
            .args(["--site", SITE, "--input"])
            .arg(&source)
            .args([
                "--sensor",
                SENSOR,
                "--stream",
                STREAM,
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                "10000000000",
                "--capture-start-ns",
                "1000000000",
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                "10",
            ])
            .output()?;
        success(&imported);
        let import = std::str::from_utf8(&imported.stdout)?
            .lines()
            .find_map(|line| line.strip_prefix("import_identity="))
            .ok_or("missing import identity")?
            .to_owned();
        // Everything after import must use retained custody; loose media is unavailable.
        fs::remove_file(source)?;
        Ok(Self {
            root,
            import,
            directory,
        })
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = vec![
            "activity".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
        ];
        args.extend(
            [
                "--site",
                SITE,
                "--import-id",
                &self.import,
                "--reference-segment",
                "0",
                "--segment",
                "1",
                "--sensor",
                SENSOR,
                "--stream",
                STREAM,
                "--job",
                "job:real-import-activity",
                "--interpretation",
                "gray",
                "--package-digest",
                ACTIVITY_PACKAGE_V1_SHA256,
                "--policy-generation",
                "7",
                "--threshold-bits",
                "3c23d70a",
                "--execution-macs",
                "10000000",
                "--execution-bytes",
                "16777216",
            ]
            .into_iter()
            .map(OsString::from),
        );
        args
    }

    fn run(&self) -> TestResult<Output> {
        execute(&self.args())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn execute(args: &[OsString]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-infer"))
        .args(args)
        .output()?)
}

fn report(output: &Output) -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing report field {key}").into())
}

fn text<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("{key} is not text").into())
}

fn recipe(value: &Value) -> TestResult<Vec<OsString>> {
    field(value, "verification_arguments")?
        .array()
        .ok_or("missing verification recipe")?
        .iter()
        .map(|argument| {
            argument
                .text()
                .map(OsString::from)
                .ok_or_else(|| "nontext verification argument".into())
        })
        .collect()
}

fn cold_verify(value: &Value) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-evidence"))
        .args(recipe(value)?)
        .output()?)
}

fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut paths = vec![root.to_owned()];
    let mut contents = BTreeMap::new();
    while let Some(path) = paths.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                paths.push(entry?.path());
            }
        } else if metadata.is_file() {
            contents.insert(path.strip_prefix(root)?.to_owned(), fs::read(&path)?);
        } else {
            return Err("special file in fixture".into());
        }
    }
    Ok(contents)
}

fn replace(args: &mut [OsString], flag: &str, value: &str) -> TestResult {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or("flag not found")?;
    args[index + 1] = value.into();
    Ok(())
}

#[test]
fn real_import_activity_survives_restart_and_emits_an_exact_cold_verification_recipe() -> TestResult
{
    let fixture = Fixture::new("active", false)?;
    let output = fixture.run()?;
    success(&output);
    assert!(output.stderr.is_empty());
    let produced = report(&output)?;
    assert_eq!(
        text(&produced, "format")?,
        "fss.recorded_activity_report.v1"
    );
    assert_eq!(text(&produced, "outcome")?, "activity");
    assert_eq!(
        text(&produced, "package_sha256")?,
        ACTIVITY_PACKAGE_V1_SHA256
    );
    assert_eq!(field(&produced, "policy_generation")?.integer(), Some(7));
    assert_eq!(field(&produced, "reference_only")?.boolean(), Some(true));
    assert_eq!(field(&produced, "score_calibrated")?.boolean(), Some(false));
    assert_eq!(
        field(&produced, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(&produced, "effects_authorized")?.boolean(),
        Some(false)
    );
    let retained = inventory(&fixture.root)?;

    // A fresh producer invocation reopens the same roots, preserving the complete tree.
    let repeated = fixture.run()?;
    success(&repeated);
    assert_eq!(repeated.stdout, output.stdout);
    assert_eq!(inventory(&fixture.root)?, retained);
    let verified = cold_verify(&produced)?;
    success(&verified);
    let verified = report(&verified)?;
    assert_eq!(field(&verified, "verified")?.boolean(), Some(true));
    assert_eq!(text(&verified, "outcome")?, "activity");
    assert_eq!(
        text(&verified, "scoreBits")?,
        text(&produced, "score_bits")?
    );
    assert_eq!(text(&verified, "knowledgeState")?, "estimated");
    assert_eq!(text(&verified, "provenance")?, "derived");
    assert_eq!(inventory(&fixture.root)?, retained);

    let mut wrong_policy = recipe(&produced)?;
    replace(&mut wrong_policy, "--threshold-bits", "3f800000")?;
    let refused = Command::new(env!("CARGO_BIN_EXE_fss-evidence"))
        .args(wrong_policy)
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(inventory(&fixture.root)?, retained);
    Ok(())
}

#[test]
fn equal_payload_frames_retain_no_activity_without_an_absence_claim() -> TestResult {
    let fixture = Fixture::new("quiet", true)?;
    let output = fixture.run()?;
    success(&output);
    let produced = report(&output)?;
    assert_eq!(text(&produced, "outcome")?, "no_activity");
    assert_eq!(text(&produced, "score_bits")?, "00000000");
    assert_ne!(
        text(&produced, "reference_capsule")?,
        text(&produced, "frame_capsule")?
    );
    assert_eq!(
        field(&produced, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    let verified = cold_verify(&produced)?;
    success(&verified);
    assert_eq!(text(&report(&verified)?, "outcome")?, "no_activity");
    Ok(())
}

#[test]
fn executor_exhaustion_retains_an_abstention_without_a_success_recipe() -> TestResult {
    let fixture = Fixture::new("abstain", false)?;
    let mut args = fixture.args();
    replace(&mut args, "--execution-macs", "1")?;
    let output = execute(&args)?;
    success(&output);
    let produced = report(&output)?;
    assert_eq!(text(&produced, "outcome")?, "abstained");
    assert_eq!(field(&produced, "score_bits")?, &Value::Null);
    assert_eq!(field(&produced, "verification_arguments")?, &Value::Null);
    assert!(field(&produced, "abstention")?.object().is_some());
    assert_eq!(
        field(&produced, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    let retained = inventory(&fixture.root)?;
    let repeated = execute(&args)?;
    success(&repeated);
    assert_eq!(repeated.stdout, output.stdout);
    assert_eq!(inventory(&fixture.root)?, retained);
    Ok(())
}

#[test]
fn independent_binding_and_native_budget_fail_before_publication() -> TestResult {
    let fixture = Fixture::new("refusals", false)?;
    let retained = inventory(&fixture.root)?;
    for (key, value) in [
        ("--sensor", "sensor:another-camera"),
        ("--stream", "stream:another-stream"),
        ("--segment", "999"),
    ] {
        let mut args = fixture.args();
        replace(&mut args, key, value)?;
        let output = execute(&args)?;
        assert!(!output.status.success(), "{key} unexpectedly accepted");
        assert!(output.stdout.is_empty());
        assert_eq!(inventory(&fixture.root)?, retained);
    }
    for (key, value) in [
        ("--max-decode-work", "0"),
        ("--max-source-read-bytes", "1"),
        ("--max-staged-bytes", "1"),
    ] {
        let mut args = fixture.args();
        args.extend([key.into(), value.into()]);
        let output = execute(&args)?;
        assert!(!output.status.success(), "{key} unexpectedly accepted");
        assert!(output.stdout.is_empty());
        assert_eq!(inventory(&fixture.root)?, retained);
    }
    Ok(())
}

#[test]
fn current_privacy_mask_blocks_original_pixel_activity_and_preserves_evidence() -> TestResult {
    let fixture = Fixture::new("privacy", false)?;
    let mut args: Vec<OsString> = vec![
        "privacy-mask".into(),
        "declare".into(),
        "--root".into(),
        fixture.root.as_os_str().to_owned(),
    ];
    args.extend(
        [
            "--site",
            SITE,
            "--sensor",
            SENSOR,
            "--resolution",
            "32x32",
            "--rect",
            "0,0,1,1",
        ]
        .map(OsString::from),
    );
    let preview = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(&args)
        .output()?;
    success(&preview);
    let preview = report(&preview)?;
    args.extend([
        "--approve".into(),
        text(&preview, "approval_digest")?.into(),
    ]);
    let declared = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(&args)
        .output()?;
    success(&declared);
    let retained = inventory(&fixture.root)?;
    let output = fixture.run()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"));
    assert_eq!(inventory(&fixture.root)?, retained);
    Ok(())
}

#[test]
fn deleting_the_import_prevents_activity_reuse_and_cold_source_verification() -> TestResult {
    let fixture = Fixture::new("deletion", false)?;
    let produced = fixture.run()?;
    success(&produced);
    let produced = report(&produced)?;
    let plan = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(&fixture.root)
        .args(["--site", SITE, "--import-id", &fixture.import])
        .output()?;
    success(&plan);
    let plan = report(&plan)?;
    let deleted = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--plan",
            text(&plan, "plan_digest")?,
            "--approve",
            text(&plan, "approval_digest")?,
        ])
        .output()?;
    success(&deleted);
    let retained = inventory(&fixture.root)?;
    let rerun = fixture.run()?;
    assert!(!rerun.status.success());
    assert!(rerun.stdout.is_empty());
    assert_eq!(inventory(&fixture.root)?, retained);
    let verified = cold_verify(&produced)?;
    assert!(!verified.status.success());
    assert!(verified.stdout.is_empty());
    assert_eq!(inventory(&fixture.root)?, retained);
    Ok(())
}

#[test]
fn missing_explicit_policy_and_wrong_package_pin_do_not_initialize_a_deployment() -> TestResult {
    let fixture = Fixture::new("parse-refusal", false)?;
    let missing = fixture.directory.join("must-not-be-created");
    let mut base = fixture.args();
    let index = base
        .iter()
        .position(|arg| arg == "--root")
        .ok_or("root flag")?;
    base[index + 1] = missing.as_os_str().to_owned();
    for omitted in [
        "--policy-generation",
        "--threshold-bits",
        "--package-digest",
        "--execution-macs",
    ] {
        let mut args = base.clone();
        let index = args
            .iter()
            .position(|arg| arg == omitted)
            .ok_or("required flag")?;
        args.drain(index..index + 2);
        let output = execute(&args)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(output.stdout.is_empty());
        assert!(!missing.exists());
    }
    replace(
        &mut base,
        "--package-digest",
        &format!("sha256:{}", "1".repeat(64)),
    )?;
    let output = execute(&base)?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(!missing.exists());
    Ok(())
}
