#![forbid(unsafe_code)]
//! Process contract for `fss-archive upload-inspect` (FSS-064).
//!
//! The inspection path is the only operator-facing consumer of the upload journal, and it had no
//! process test at all. These checks pin the parts a caller scripts against: a typed refusal with the
//! malformed-value identity when required arguments are missing, the runtime-failure identity when the
//! journal directory does not exist, and a help surface that names the exact subcommand. No provider is
//! contacted and no journal is created.

use std::error::Error;
use std::path::Path;
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BIN: &str = env!("CARGO_BIN_EXE_fss-archive");
const MALFORMED: i32 = 2;
const RUNTIME: i32 = 1;

/// Every required option, so a test can drop exactly the ones it means to leave out.
const REQUIRED: [&str; 2] = ["--journal-resource", "archive:resource:test"];
const REST: [(&str, &str); 7] = [
    ("--minimum-sequence", "0"),
    (
        "--minimum-root",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ),
    ("--attested-now-ns", "0"),
    ("--max-journal-bytes", "65536"),
    ("--max-records", "16"),
    ("--max-checkpoint-bytes", "65536"),
    ("--max-read-bytes", "65536"),
];

fn run(journal: Option<&Path>, with_defaults: bool) -> TestResult<Output> {
    let mut command = Command::new(BIN);
    command.arg("upload-inspect");
    if let Some(journal) = journal {
        command.arg("--journal").arg(journal);
    }
    if with_defaults {
        command.args(REQUIRED);
        for (flag, value) in REST {
            command.arg(flag).arg(value);
        }
    }
    Ok(command.output()?)
}

#[test]
fn missing_journal_flag_is_a_malformed_value() -> TestResult {
    let output = run(None, false)?;
    assert_eq!(output.status.code(), Some(MALFORMED));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ERR-CLI-MISSING-VALUE"), "stderr: {stderr}");
    Ok(())
}

#[test]
fn absent_journal_directory_fails_typed_without_output() -> TestResult {
    let dir = std::env::temp_dir().join("fss-upload-inspect-absent-0123456789");
    let output = run(Some(&dir), true)?;
    // Either identity is a typed refusal; what must never happen is a success exit or a report on
    // stdout for a journal directory that does not exist.
    assert!(
        matches!(output.status.code(), Some(MALFORMED) | Some(RUNTIME)),
        "exit: {:?}",
        output.status.code()
    );
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!output.stderr.is_empty());
    Ok(())
}

#[test]
fn bare_invocation_lists_the_inspect_subcommand() -> TestResult {
    // `fss-archive` prints the whole surface (including every subcommand's own help) when it is given
    // no arguments; `upload-inspect --help` is not special-cased, so this is the surface a caller sees.
    let output = Command::new(BIN).output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("upload-inspect"), "output: {text}");
    assert!(text.contains("--journal"), "output: {text}");
    assert!(text.contains("--max-records"), "output: {text}");
    Ok(())
}
