#![forbid(unsafe_code)]
//! Integration contract tests for `NS-13` Operational Memory & Trauma-Guard Inversion
//! (`fss-gj2wd` / `fss-ksdck`).
//!
//! Verifies that:
//! 1. Below the threshold (`< 2` negative feedback / episode records on a target), `fss orient`
//!    emits no `trauma_guard_warning`.
//! 2. Once `>= 2` negative operational memory records (`hard_negative_candidate` or `harmful`)
//!    accumulate on a target, `fss orient` deterministically derives and surfaces a cited
//!    `AntiPatternWarning` (`trauma_guard_warning[trauma-guard:...]`) carrying the exact
//!    `feedback:...` IDs, evidence digests, cause class, `negative_count`, `decay_weight_ppm`,
//!    `half_life_ns`, and `active_policy_mutation=false`.
//! 3. `NEG-004` zero-policy-mutation invariant: `authority_tree` (ledger, effects, objects,
//!    `LAYOUT`) and `contractBasis` (`policyGeneration`, `modelGeneration`,
//!    `calibrationGeneration`) are 100% byte-identical before and after trauma-guard derivation.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:trauma-guard-cli";

fn emit_log(step: &str, case: &str, outcome: &str) {
    println!(
        "{{\"bead\":\"fss-ksdck\",\"step\":\"{step}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"verdict\":\"valid\"}}"
    );
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-trauma-guard-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scene() -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(width, height, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key} in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

fn publish_event(directory: &OwnedDirectory) -> TestResult<String> {
    let root = directory.root();
    let input = directory.0.join("east.mjpeg");
    fs::write(&input, scene()?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", "sensor:east", "--stream", "stream:sensor:east"])
        .args(["--media-format", "mjpeg", "--receive-time-ns", "1000000000"])
        .output()?;
    success(&output);
    let import_id = String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?;
    let watch = |extra: &[&str]| -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .arg("watch")
            .arg("--root")
            .arg(&root)
            .args(["--site", SITE, "--import-id", &import_id])
            .args(["--interpretation", "gray", "--zone", "door:64,0,32,32"])
            .args(extra)
            .output()?)
    };
    let prepared = watch(&[])?;
    success(&prepared);
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = watch(&["--approve", &proposal])?;
    success(&published);
    report_field(&published, "event_id")
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((output.status.code(), String::from_utf8(output.stdout)?))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing field {key}"))?;
    }
    Ok(current)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("{path:?} is not a string").into())
}

fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    field(value, path)?
        .array()
        .ok_or("not an array")?
        .iter()
        .map(|item| {
            item.text()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "not a string".into())
        })
        .collect()
}

fn authority_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut out = BTreeMap::new();
    let mut pending: Vec<PathBuf> = ["ledger", "effects", "objects", "LAYOUT"]
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.exists())
        .collect();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else {
            out.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(&path)?),
            );
        }
    }
    Ok(out)
}

fn orient(root: &Path) -> TestResult<Value> {
    let args: Vec<OsString> = vec![
        "orient".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
    ];
    let (code, stdout) = run_fss(&args)?;
    assert_eq!(code, Some(0), "orient failed: {stdout}");
    Ok(parse(stdout.trim_end())?)
}

#[test]
fn repeated_hard_negative_feedback_derives_trauma_guard_warning_without_policy_mutation()
-> TestResult {
    let directory = OwnedDirectory::new("spiderweb-foliage")?;
    let event_id = publish_event(&directory)?;
    let root = directory.root();
    let authority_before = authority_tree(&root)?;

    // Open an agent session on the deployment.
    let open_args: Vec<OsString> = vec![
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--mission".into(),
        "Audit recurring spiderweb and foliage false alarms at the east door".into(),
        "--objective".into(),
        "Verify advisory trauma-guard derivation without active policy mutation".into(),
    ];
    let (code, open_stdout) = run_fss(&open_args)?;
    assert_eq!(code, Some(0), "{open_stdout}");
    let open_doc = parse(open_stdout.trim_end())?;
    let session_id = text(&open_doc, &["sessionId"])?.to_owned();
    let initial_basis = field(&open_doc, &["contractBasis"])?.clone();

    // 1. Before any feedback, orient has 0 trauma_guard_warning lines.
    let orient_0 = orient(&root)?;
    let warnings_0 = texts(&orient_0, &["warnings"])?;
    assert!(
        !warnings_0
            .iter()
            .any(|w| w.starts_with("trauma_guard_warning["))
    );
    emit_log("orient_baseline", "zero_negative_records", "ok");

    // 2. First hard_negative_candidate feedback (count = 1 < 2): still 0 trauma_guard_warning lines.
    let ev_target = format!("event:{event_id}");
    let ev_digest_1 = ContentDigest::sha256(b"spiderweb frame 1").to_text();
    let fb1_args: Vec<OsString> = vec![
        "feedback".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--session".into(),
        session_id.clone().into(),
        "--target".into(),
        ev_target.clone().into(),
        "--kind".into(),
        "hard_negative_candidate".into(),
        "--statement".into(),
        "Spiderweb strand blown across IR LEDs triggered false candidate #1.".into(),
        "--supporting".into(),
        ev_digest_1.clone().into(),
        "--disposition".into(),
        "create_learning_proposal".into(),
    ];
    let (code, fb1_stdout) = run_fss(&fb1_args)?;
    assert_eq!(code, Some(0), "{fb1_stdout}");
    let fb1_doc = parse(fb1_stdout.trim_end())?;
    let fb1_id = text(&fb1_doc, &["payload", "feedbackId"])?.to_owned();
    assert_eq!(
        field(&fb1_doc, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );

    let orient_1 = orient(&root)?;
    let warnings_1 = texts(&orient_1, &["warnings"])?;
    assert!(
        !warnings_1
            .iter()
            .any(|w| w.starts_with("trauma_guard_warning["))
    );
    emit_log("orient_below_threshold", "single_negative_record", "ok");

    // 3. Second hard_negative_candidate feedback (count = 2 >= 2): derives cited AntiPatternWarning!
    let ev_digest_2 = ContentDigest::sha256(b"foliage shadow frame 2").to_text();
    let fb2_args: Vec<OsString> = vec![
        "feedback".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--session".into(),
        session_id.clone().into(),
        "--target".into(),
        ev_target.clone().into(),
        "--kind".into(),
        "hard_negative_candidate".into(),
        "--statement".into(),
        "Wind-blown foliage shadow on east door triggered false candidate #2.".into(),
        "--supporting".into(),
        ev_digest_2.clone().into(),
        "--disposition".into(),
        "create_learning_proposal".into(),
    ];
    let (code, fb2_stdout) = run_fss(&fb2_args)?;
    assert_eq!(code, Some(0), "{fb2_stdout}");
    let fb2_doc = parse(fb2_stdout.trim_end())?;
    let fb2_id = text(&fb2_doc, &["payload", "feedbackId"])?.to_owned();
    assert_ne!(fb1_id, fb2_id);

    let orient_2 = orient(&root)?;
    let warnings_2 = texts(&orient_2, &["warnings"])?;
    let trauma_line = warnings_2
        .iter()
        .find(|w| w.starts_with("trauma_guard_warning[trauma-guard:"))
        .ok_or_else(|| format!("missing trauma_guard_warning in {warnings_2:?}"))?;
    assert!(trauma_line.contains("cause=hypothesis"), "{trauma_line}");
    assert!(trauma_line.contains("negative_count=2"), "{trauma_line}");
    assert!(
        trauma_line.contains("decay_weight_ppm=2000000"),
        "{trauma_line}"
    );
    assert!(
        trauma_line.contains("half_life_ns=86400000000000"),
        "{trauma_line}"
    );
    assert!(
        trauma_line.contains("active_policy_mutation=false"),
        "{trauma_line}"
    );
    assert!(trauma_line.contains(&fb1_id), "{trauma_line}");
    assert!(trauma_line.contains(&fb2_id), "{trauma_line}");
    assert!(trauma_line.contains(&ev_digest_1), "{trauma_line}");
    assert!(trauma_line.contains(&ev_digest_2), "{trauma_line}");
    emit_log(
        "orient_trauma_guard_derived",
        "two_hard_negative_records",
        "ok",
    );

    // 4. Verify NEG-004: authority tree and contractBasis are 100% immutable.
    assert_eq!(authority_tree(&root)?, authority_before);
    assert_eq!(field(&orient_2, &["contractBasis"])?, &initial_basis);
    emit_log("neg_004_zero_policy_mutation", "authority_immutable", "ok");

    Ok(())
}
