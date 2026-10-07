#![forbid(unsafe_code)]
//! `fss-lab run file-activity` through the real binary (fss-2h5zq.52): the observations come from
//! the verified activity package on the scalar executor, every observation names its receipts,
//! one camera is never corroborated, and the file never certifies absence.

use std::path::PathBuf;
use std::process::Command;

use fss_core::ContentDigest;
use fss_reference::ScalarExecCx;
use fss_reference::executor_activity_package::{
    ACTIVITY_PACKAGE_V1_SHA256, VerifiedActivityPackage,
};

#[path = "../../fss-reference/tests/caplog_support/mod.rs"]
mod caplog_support;
use caplog_support::Record;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir().join(format!(
                "fss-lab-file-activity-{label}-{}-{n}",
                std::process::id()
            ));
            match std::fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(label: &str) -> TestResult<String> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("root");
    let output = Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(["run", "file-activity", "--root"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "fss-lab failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

/// Every `{...}` object of the `observations` array, in order.
fn observations(json: &str) -> TestResult<Vec<&str>> {
    let start = json.find("\"observations\":[").ok_or("no observations")? + 16;
    let body = &json[start..];
    let end = body.find("]}").ok_or("unterminated observations")?;
    Ok(body[..end]
        .split("},{")
        .map(|s| s.trim_start_matches('{').trim_end_matches('}'))
        .collect())
}

#[test]
fn file_activity_cli_runs_the_verified_package_and_never_corroborates() -> TestResult {
    let json = run("a")?;
    let package = VerifiedActivityPackage::load_committed(&ScalarExecCx::new())?;
    assert_eq!(
        package.archive_digest(),
        ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?
    );
    assert!(json.contains(&format!(
        "\"package_sha256\":\"{ACTIVITY_PACKAGE_V1_SHA256}\""
    )));
    assert!(json.contains(&format!(
        "\"model_package_root\":\"{}\"",
        package.manifest_digest()
    )));
    assert!(json.contains("\"model_generation\":\"model:fss-activity:v1\""));
    assert!(json.contains("\"score_calibrated\":false"));
    // One camera: single source, never corroborated, never certified absent.
    assert!(json.contains("\"corroboration\":\"single_source\""));
    assert!(!json.contains("\"envelope\":\"corroborated_threat\""));
    assert!(json.contains("\"absence_certified\":false"));
    let observed = observations(&json)?;
    assert_eq!(observed.len(), 2);
    let keys = [
        "\"invocation_receipt_digest\":\"sha256:",
        "\"invocation_receipt_object\":\"sha256:",
        "\"decode_receipt\":\"sha256:",
        "\"input_capture_root\":\"sha256:",
        "\"continuity\":{\"not_observable\":\"file_source\"}",
        "\"reference_only\":true",
        "\"supports_absence\":false",
    ];
    // Frame 1 repeats the background (score exactly 0); frame 2 is the gradient (activity).
    let outcomes = [
        "\"outcome\":\"no_activity\",\"score\":0",
        "\"outcome\":\"activity\"",
    ];
    for (index, observation) in observed.iter().enumerate() {
        let missing: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|key| !observation.contains(key))
            .collect();
        let outcome = observation.contains(outcomes[index]);
        Record::new(&format!("cli_observation_{index}"))
            .check_eq("missing_receipt_keys", Vec::<&str>::new(), missing.clone())
            .check_eq("outcome", true, outcome)
            .emit_checked(0, missing.is_empty() && outcome);
        println!("observation {index}: {{{observation}}}");
        assert!(missing.is_empty(), "{missing:?} missing in {observation}");
        assert!(outcome, "observation {index}: {observation}");
    }
    let single_source = json.contains("\"corroboration\":\"single_source\"")
        && !json.contains("\"envelope\":\"corroborated_threat\"")
        && json.contains("\"absence_certified\":false");
    // The run is deterministic across roots.
    let second = run("b")?;
    Record::new("cli_single_source_deterministic")
        .check_eq("single_source_never_corroborated", true, single_source)
        .check(
            "report_sha256",
            ContentDigest::sha256(json.as_bytes()).to_string(),
            ContentDigest::sha256(second.as_bytes()).to_string(),
        )
        .emit_checked(0, single_source && second == json);
    assert_eq!(second, json);
    Ok(())
}
