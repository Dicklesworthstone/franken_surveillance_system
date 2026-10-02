#![forbid(unsafe_code)]
//! CLI contract of `fss-lab crash-matrix` (fss-2h5zq.15): argument refusals and their exit
//! codes, the empty-root guard, the `fss.lab.crash_matrix.v1` document, and the exit code
//! following the verdict.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE,
    ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_OPTION, LabAction, parse_lab_args,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Every fault point of the expected-class table: 4 publish cut points, 1 ledger cut point,
/// 8 journal append phases, 2 effect faults and 14 registered cancellation stages.
const EXPECTED_ROWS: usize = 4 + 1 + 8 + 2 + 14;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir().join(format!(
                "fss-lab-crash-cli-{label}-{}-{n}",
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

fn lab(args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(args)
        .output()?)
}

fn lab_at(args: &[&str], root: &Path) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()?)
}

fn parse(argv: &[&str]) -> Result<LabAction, fss_cli::CliError> {
    parse_lab_args(argv.iter().map(OsString::from).collect::<Vec<_>>())
}

#[test]
fn crash_matrix_arguments_decode() -> TestResult {
    assert_eq!(
        parse(&["crash-matrix", "--root", "/tmp/cm"])?,
        LabAction::CrashMatrix {
            root: PathBuf::from("/tmp/cm"),
            scenario: "intrusion".to_owned(),
            json: false,
        }
    );
    assert_eq!(
        parse(&[
            "crash-matrix",
            "--json",
            "--scenario=intrusion",
            "--root=/tmp/cm"
        ])?,
        LabAction::CrashMatrix {
            root: PathBuf::from("/tmp/cm"),
            scenario: "intrusion".to_owned(),
            json: true,
        }
    );
    Ok(())
}

#[test]
fn crash_matrix_refusals_have_stable_identities() {
    let cases: &[(&[&str], &str)] = &[
        (&["crash-matrix"], ERR_CLI_MISSING_VALUE),
        (&["crash-matrix", "--json"], ERR_CLI_MISSING_VALUE),
        (&["crash-matrix", "--root"], ERR_CLI_MISSING_VALUE),
        (&["crash-matrix", "--root", "--json"], ERR_CLI_MISSING_VALUE),
        (
            &["crash-matrix", "--root", "/tmp/a", "--root", "/tmp/b"],
            ERR_CLI_DUPLICATE_OPTION,
        ),
        (
            &["crash-matrix", "--root", "/tmp/a", "--json", "--json"],
            ERR_CLI_DUPLICATE_OPTION,
        ),
        (
            &["crash-matrix", "--root", "/tmp/a", "--scenario", "quiet"],
            ERR_CLI_MALFORMED_VALUE,
        ),
        (
            &["crash-matrix", "--root", "/tmp/a", "--scenario=nope"],
            ERR_CLI_MALFORMED_VALUE,
        ),
        (&["crash-matrix", "--root", ""], ERR_CLI_MALFORMED_VALUE),
        (
            &["crash-matrix", "--root", "/tmp/a", "--kill"],
            ERR_CLI_UNKNOWN_OPTION,
        ),
        (
            &["crash-matrix", "--root", "/tmp/a", "extra"],
            ERR_CLI_TRAILING_ARGUMENT,
        ),
    ];
    for (argv, expected) in cases {
        let result = parse(argv);
        assert!(result.is_err(), "{argv:?} must be refused, got {result:?}");
        if let Err(error) = result {
            assert_eq!(error.error_id(), *expected, "{argv:?}");
            assert_eq!(error.exit_identity().code, 2, "{argv:?}");
        }
    }
}

#[test]
fn the_binary_refuses_without_a_root_and_writes_nothing() -> TestResult {
    let output = lab(&["crash-matrix", "--json"])?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains(ERR_CLI_MISSING_VALUE), "{stderr}");
    assert!(stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    let output = lab(&[
        "crash-matrix",
        "--root",
        "/nonexistent/x",
        "--scenario",
        "quiet",
    ])?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!Path::new("/nonexistent/x").exists());
    Ok(())
}

#[test]
fn the_binary_refuses_a_non_empty_root() -> TestResult {
    let dir = Directory::new("busy")?;
    std::fs::write(dir.0.join("keep"), b"operator data")?;
    let output = lab_at(&["crash-matrix", "--json"], &dir.0)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("ERR-LAB-ROOT-NOT-EMPTY-001"), "{stderr}");
    // Nothing was added next to the operator's file.
    assert_eq!(std::fs::read_dir(&dir.0)?.count(), 1);
    Ok(())
}

/// Text after `"key":` up to the next `,` or `}` (numbers, booleans, null).
fn scalar<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":");
    let start = json.find(&marker)? + marker.len();
    let rest = &json[start..];
    let end = rest.find([',', '}'])?;
    Some(&rest[..end])
}

#[test]
fn the_json_document_has_one_row_per_fault_point_and_the_exit_code_follows_the_verdict()
-> TestResult {
    let dir = Directory::new("json")?;
    let root = dir.0.join("matrix");
    let output = lab_at(&["crash-matrix", "--json"], &root)?;
    let stdout = String::from_utf8(output.stdout)?;
    let document = stdout.trim_end();
    assert!(document.starts_with("{\"schema\":\"fss.lab.crash_matrix.v1\""));
    assert!(document.ends_with('}'));
    assert!(document.contains("\"scenario\":\"intrusion\""));
    assert!(document.contains("\"no_claim\":\"in-process fault injection only"));
    assert_eq!(
        scalar(document, "row_count"),
        Some(EXPECTED_ROWS.to_string().as_str())
    );

    let rows: Vec<&str> = document.split("{\"fault\":").skip(1).collect::<Vec<_>>();
    assert_eq!(rows.len(), EXPECTED_ROWS);
    for row in &rows {
        for key in [
            "expected_class",
            "observed_class",
            "pass",
            "expected_interrupted",
            "interrupted",
            "reason",
            "orphaned",
            "broken_roots",
            "tail_state",
            "obligations",
            "recovery_actions",
            "rerun",
            "duplicate_effects",
            "contract",
        ] {
            assert!(
                row.contains(&format!("\"{key}\":")),
                "missing {key} in {row}"
            );
        }
        assert!(row.contains("\"obligations\":{\"terminal\":"), "{row}");
        assert!(row.contains(",\"indeterminate\":"), "{row}");
        // No row ever duplicates an effect.
        assert_eq!(scalar(row, "duplicate_effects"), Some("0"), "{row}");
    }
    let mismatches: usize = scalar(document, "mismatches")
        .ok_or("mismatches")?
        .parse()?;
    let failing_rows = rows
        .iter()
        .filter(|row| scalar(row, "pass") == Some("false"))
        .count();
    assert_eq!(mismatches, failing_rows);
    let passed = document.ends_with("\"verdict\":\"pass\"}");
    assert_eq!(passed, mismatches == 0);
    assert_eq!(output.status.code(), Some(if passed { 0 } else { 1 }));
    if !passed {
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("crash matrix verdict fail"), "{stderr}");
    }

    // Every run row left its crashed sub-root and its recovered copy on disk as a corpus;
    // not-applicable rows created nothing.
    for row in &rows {
        let slug = row.split('"').nth(1).ok_or("slug")?;
        let ran = !row.contains("\"observed_class\":\"not_applicable\"");
        assert_eq!(root.join(slug).is_dir(), ran, "{slug}");
        assert_eq!(root.join("rerun").join(slug).is_dir(), ran, "{slug}");
    }
    Ok(())
}
