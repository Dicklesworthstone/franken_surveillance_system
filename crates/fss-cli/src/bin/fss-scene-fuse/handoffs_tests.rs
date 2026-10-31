#![forbid(unsafe_code)]
//! Real-file ownership and output contracts for the handoff subcommand.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

type Test = std::result::Result<(), Box<dyn std::error::Error>>;
const FIXTURE: &[u8] =
    include_bytes!("../../../../../tests/fixtures/continuity/three_camera_handoffs.json");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    query: PathBuf,
}
impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "fss-scene-handoff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let query = root.join("query.json");
        fs::write(&query, FIXTURE)?;
        Ok(Self { root, query })
    }
    fn options(&self) -> Options {
        Options {
            observations: self.query.clone(),
            report_out: None,
            expected: Some(ContentDigest::sha256(FIXTURE)),
            work: 2_000_000,
            timeout: Duration::from_secs(30),
            report_bytes: MAX_REPORT_BYTES,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn ok<T>(value: Result<T>) -> std::result::Result<T, Box<dyn std::error::Error>> {
    value.map_err(|e| format!("{}: {}", e.code, e.detail).into())
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn handoff_options_are_bounded_and_do_not_accept_ambiguous_input() -> Test {
    assert!(ok(options(&args(&["--help"])))?.is_none());
    for values in [
        vec![],
        vec!["--observations"],
        vec!["--observations", "a", "--observations", "b"],
        vec!["--observations", "a", "--unknown", "b"],
        vec!["--observations", "--report-out"],
        vec!["--observations", "a", "--work-units", "0"],
        vec!["--observations", "a", "--timeout-ms", "0"],
        vec!["--observations", "a", "--max-report-bytes", "1023"],
        vec!["--observations", "a", "--expected-input", "bad"],
    ] {
        assert!(options(&args(&values)).is_err(), "accepted {values:?}");
    }
    assert!(ok(options(&args(&["--observations", "query.json"])))?.is_some());
    Ok(())
}

#[test]
fn exact_input_pin_produces_same_private_file_and_stdout_and_never_overwrites() -> Test {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    let report = fixture.root.join("report.json");
    options.report_out = Some(report.clone());
    let mut stdout = Vec::new();
    assert!(ok(execute(&options, &mut stdout))?);
    assert_eq!(fs::read(&report)?, stdout);
    assert_eq!(fs::read(&fixture.query)?, FIXTURE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&report)?.permissions().mode() & 0o777, 0o600);
    }
    let mut retry = Vec::new();
    assert!(execute(&options, &mut retry).is_err());
    assert!(retry.is_empty());
    assert_eq!(fs::read(&report)?, stdout);
    Ok(())
}

#[test]
fn stale_input_cancelled_context_and_output_bound_create_no_report() -> Test {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    let report = fixture.root.join("report.json");
    options.report_out = Some(report.clone());
    options.expected = Some(ContentDigest::sha256(b"another input"));
    let mut stdout = Vec::new();
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert!(!report.exists());
    options.expected = Some(ContentDigest::sha256(FIXTURE));
    options.report_bytes = 1024;
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert!(!report.exists());
    options.report_bytes = MAX_REPORT_BYTES;
    let cx = ok(authority())?;
    cx.drain();
    assert!(analyze(&options, &cx).is_err());
    cx.drain_and_finalize();
    assert!(!report.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symbolic_input_is_refused_without_following_the_link() -> Test {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    let link = fixture.root.join("query-link.json");
    std::os::unix::fs::symlink(&fixture.query, &link)?;
    options.observations = link;
    let mut stdout = Vec::new();
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    Ok(())
}
