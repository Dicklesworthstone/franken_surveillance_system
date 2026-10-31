#![forbid(unsafe_code)]
//! Actual command/context/file boundaries; these require the complete reference runtime.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

type Test = std::result::Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const FIXTURE: &[u8] =
    include_bytes!("../../../../../tests/fixtures/continuity/retained_package_selection.json");

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "fss-retained-handoffs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::write(root.join("selection.json"), FIXTURE)?;
        Ok(Self { root })
    }
    fn options(&self) -> Options {
        Options {
            root: self.root.join("deployment"),
            site: "property:fixture".into(),
            principal: "principal:fixture".into(),
            selection: self.root.join("selection.json"),
            report_out: Some(self.root.join("report.json")),
            expected_input: Some(ContentDigest::sha256(FIXTURE)),
            expected_anchor: None,
            work: 2_000_000,
            timeout: Duration::from_secs(30),
            report_bytes: query::MAX_REPORT_BYTES,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
fn ok<T>(value: Result<T>) -> std::result::Result<T, Box<dyn std::error::Error>> {
    value.map_err(|e| format!("{}: {}", e.code, e.detail).into())
}

#[test]
fn options_require_existing_deployment_selection_and_bounded_allowances() -> Test {
    assert!(ok(options(&args(&["--help"])))?.is_none());
    let baseline = [
        "--root",
        "d",
        "--site",
        "property:fixture",
        "--selection",
        "q.json",
    ];
    assert!(ok(options(&args(&baseline)))?.is_some());
    for extra in [
        vec!["--work-units", "0"],
        vec!["--timeout-ms", "0"],
        vec!["--max-report-bytes", "4194305"],
        vec!["--expected-anchor", "bad"],
        vec!["--site", "property:other"],
        vec!["--unknown", "x"],
    ] {
        let mut values = baseline.to_vec();
        values.extend(extra);
        assert!(options(&args(&values)).is_err());
    }
    assert!(options(&args(&["--root", "d", "--site", "property:fixture"])).is_err());
    Ok(())
}

#[test]
fn absent_deployment_is_not_created_and_no_report_or_stdout_escapes() -> Test {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let mut stdout = Vec::new();
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert!(!options.root.exists());
    assert!(!fixture.root.join("report.json").exists());
    Ok(())
}

#[test]
fn valid_empty_deployment_refuses_unavailable_selected_custody_without_publication() -> Test {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let auth = ok(authority(&options))?;
    let cx = ReplayCx::from_context_authority(&auth, options.root.clone())?;
    let before = {
        let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        deployment.current_anchor().clone()
    };
    cx.drain_and_finalize();
    let mut stdout = Vec::new();
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert!(!fixture.root.join("report.json").exists());
    let cx = ReplayCx::from_context_authority(&auth, options.root.clone())?;
    let deployment = ReferenceDeployment::reopen(&options.root, &options.site, &cx)?;
    assert_eq!(deployment.current_anchor(), &before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn wrong_site_stale_document_and_existing_output_do_not_change_authority() -> Test {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    let auth = ok(authority(&options))?;
    let cx = ReplayCx::from_context_authority(&auth, options.root.clone())?;
    let before = {
        let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        deployment.current_anchor().clone()
    };
    cx.drain_and_finalize();
    options.site = "property:wrong".into();
    assert!(execute(&options, &mut Vec::new()).is_err());
    options.site = "property:fixture".into();
    options.expected_input = Some(ContentDigest::sha256(b"other"));
    assert!(execute(&options, &mut Vec::new()).is_err());
    assert!(!fixture.root.join("report.json").exists());
    fs::write(fixture.root.join("report.json"), b"keep")?;
    assert!(execute(&options, &mut Vec::new()).is_err());
    assert_eq!(fs::read(fixture.root.join("report.json"))?, b"keep");
    let cx = ReplayCx::from_context_authority(&auth, options.root.clone())?;
    let deployment = ReferenceDeployment::reopen(&options.root, &options.site, &cx)?;
    assert_eq!(deployment.current_anchor(), &before);
    cx.drain_and_finalize();
    Ok(())
}

#[cfg(unix)]
#[test]
fn symbolic_deployment_is_not_followed() -> Test {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    let target = fixture.root.join("target");
    fs::create_dir(&target)?;
    let link = fixture.root.join("link");
    std::os::unix::fs::symlink(&target, &link)?;
    options.root = link;
    assert!(execute(&options, &mut Vec::new()).is_err());
    assert!(fs::read_dir(target)?.next().is_none());
    Ok(())
}
