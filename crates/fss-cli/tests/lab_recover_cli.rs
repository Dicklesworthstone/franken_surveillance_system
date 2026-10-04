#![forbid(unsafe_code)]
//! CLI contract of `fss-lab recover` (fss-2h5zq.15 refinement rounds 2 and 3): argument
//! refusals, the typed refusals and their registered identities (root locked, nothing to do,
//! plan mismatch, corrupt history), the read-only plan, the plan/apply digest round trip, and the
//! orphaned staging discard (fss-vmau3), each through a separate `fss-lab` process.
//!
//! The effect reconciliation of a crash-matrix corpus in a separate process is exercised by
//! `lab_crash_matrix_cli.rs`, which already builds that corpus.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE,
    ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_OPTION, ERR_LAB_RECOVER_CORRUPT_HISTORY,
    ERR_LAB_RECOVER_NOTHING_TO_DO, ERR_LAB_RECOVER_PLAN_MISMATCH, ERR_LAB_RECOVER_ROOT_LOCKED,
    ExitIdentity, LabAction, RecoverJournal, RecoverRequest, parse_lab_args,
};
use fss_core::ContentDigest;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir().join(format!(
                "fss-lab-recover-cli-{label}-{}-{n}",
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

fn parse(argv: &[&str]) -> Result<LabAction, fss_cli::CliError> {
    parse_lab_args(argv.iter().map(OsString::from).collect::<Vec<_>>())
}

fn recover(root: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .arg("recover")
        .arg("--root")
        .arg(root)
        .args(args)
        .arg("--json")
        .output()?)
}

/// A clean deployment root made by the real `fss-lab run intrusion` process.
fn clean_root(dir: &Directory) -> TestResult<PathBuf> {
    let root = dir.0.join("deployment");
    let output = Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(["run", "intrusion", "--root"])
        .arg(&root)
        .output()?;
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    Ok(root)
}

/// Asserts a typed refusal: exit 6, the identity on stderr in the `fss.cli_diagnostic.v1` line
/// and in the report on stdout.
fn assert_refused(output: &Output, error_id: &str, code: &str) -> TestResult {
    let stdout = String::from_utf8(output.stdout.clone())?;
    let stderr = String::from_utf8(output.stderr.clone())?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::LAB_RECOVER_REFUSED.code)),
        "{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("\"error_id\":\"{error_id}\"")),
        "{stderr}"
    );
    assert!(
        stderr.contains("\"exit_id\":\"EXIT-LAB-RECOVER-REFUSED-006\""),
        "{stderr}"
    );
    assert!(stderr.contains(code), "{stderr}");
    assert!(
        stdout.starts_with("{\"schema\":\"fss.lab.recover_report.v1\""),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("\"outcome\":\"{code}\"")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("\"error_id\":\"{error_id}\"")),
        "{stdout}"
    );
    Ok(())
}

/// The `"plan_digest":"..."` value of a report.
fn plan_digest(report: &str) -> TestResult<String> {
    let marker = "\"plan_digest\":\"";
    let start = report.find(marker).ok_or("no plan digest")? + marker.len();
    let end = report[start..].find('"').ok_or("unterminated digest")? + start;
    Ok(report[start..end].to_owned())
}

fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[test]
fn recover_arguments_decode_in_any_order() -> TestResult {
    let digest = ContentDigest::sha256(b"plan");
    let digest_text = digest.to_string();
    assert_eq!(
        parse(&[
            "recover",
            "--reconcile-effects",
            "--truncate-incomplete-tail=ledger",
            "--root",
            "/tmp/r",
            "--apply-effects-repair",
            &digest_text,
            "--discard-orphaned-temps",
            "--json",
        ])?,
        LabAction::Recover {
            root: PathBuf::from("/tmp/r"),
            request: RecoverRequest {
                truncate_incomplete_tail: Some(RecoverJournal::Ledger),
                apply_effects_repair: Some(digest),
                discard_orphaned_temps: true,
                reconcile_effects: true,
                ..RecoverRequest::default()
            },
            json: true,
        }
    );
    assert_eq!(
        parse(&["recover", "--root=/tmp/r", "--plan-effects-repair"])?,
        LabAction::Recover {
            root: PathBuf::from("/tmp/r"),
            request: RecoverRequest {
                plan_repair: Some(RecoverJournal::Effects),
                ..RecoverRequest::default()
            },
            json: false,
        }
    );
    // The flags are reported in the fixed execution order, not the order given.
    let request = RecoverRequest {
        truncate_incomplete_tail: Some(RecoverJournal::Effects),
        apply_ledger_repair: Some(digest),
        reconcile_effects: true,
        discard_orphaned_temps: true,
        ..RecoverRequest::default()
    };
    assert_eq!(
        request.flags(),
        vec![
            format!("--apply-ledger-repair {digest_text}"),
            "--truncate-incomplete-tail effects".to_owned(),
            "--discard-orphaned-temps".to_owned(),
            "--reconcile-effects".to_owned(),
        ]
    );
    Ok(())
}

#[test]
fn recover_argument_refusals_have_stable_identities() {
    let cases: &[(&[&str], &str)] = &[
        (&["recover", "--reconcile-effects"], ERR_CLI_MISSING_VALUE),
        // No action named: nothing is implied.
        (&["recover", "--root", "/tmp/r"], ERR_CLI_MISSING_VALUE),
        (
            &["recover", "--root", "/tmp/r", "--json"],
            ERR_CLI_MISSING_VALUE,
        ),
        (
            &["recover", "--root", "/tmp/r", "--truncate-incomplete-tail"],
            ERR_CLI_MISSING_VALUE,
        ),
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--truncate-incomplete-tail",
                "objects",
            ],
            ERR_CLI_MALFORMED_VALUE,
        ),
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--apply-ledger-repair",
                "abc",
            ],
            ERR_CLI_MALFORMED_VALUE,
        ),
        (
            &["recover", "--root", "/tmp/r", "--reconcile-effects=yes"],
            ERR_CLI_MALFORMED_VALUE,
        ),
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--reconcile-effects",
                "--reconcile-effects",
            ],
            ERR_CLI_DUPLICATE_OPTION,
        ),
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--plan-ledger-repair",
                "--plan-effects-repair",
            ],
            ERR_CLI_DUPLICATE_OPTION,
        ),
        // A plan is read-only and never runs with a mutating action.
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--plan-ledger-repair",
                "--reconcile-effects",
            ],
            ERR_CLI_DUPLICATE_OPTION,
        ),
        (
            &["recover", "--root", "/tmp/r", "--retry-dispatch"],
            ERR_CLI_UNKNOWN_OPTION,
        ),
        (
            &[
                "recover",
                "--root",
                "/tmp/r",
                "--reconcile-effects",
                "extra",
            ],
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
fn recover_refusals_and_the_plan_apply_round_trip_through_the_binary() -> TestResult {
    let dir = Directory::new("process")?;
    let root = clean_root(&dir)?;
    let journal = root.join("ledger").join("journal.fssj");

    // A clean root: every requested action has nothing to do.
    let output = recover(
        &root,
        &[
            "--truncate-incomplete-tail",
            "ledger",
            "--discard-orphaned-temps",
            "--reconcile-effects",
        ],
    )?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_NOTHING_TO_DO,
        "recover_nothing_to_do",
    )?;

    // No orphaned staging file: nothing to do (fss-vmau3).
    let output = recover(&root, &["--discard-orphaned-staging"])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_NOTHING_TO_DO,
        "recover_nothing_to_do",
    )?;

    // An interrupted ingest's staging file is discarded under the lock; a foreign entry in the
    // staging directory is never touched; the rerun has nothing to do.
    let staging = root.join("objects").join("spool").join("staging");
    let orphan = format!(
        "{}.0.tmp",
        ContentDigest::sha256(b"interrupted ingest")
            .to_text()
            .trim_start_matches("sha256:")
    );
    std::fs::write(staging.join(&orphan), b"partial")?;
    std::fs::write(staging.join("operator-notes"), b"keep")?;
    let output = recover(&root, &["--discard-orphaned-staging"])?;
    let report = String::from_utf8(output.stdout.clone())?;
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        report.contains(&format!(
            "{{\"action\":\"discard_orphaned_staging\",\"target\":\"objects\",\"status\":\"applied\",\"receipt\":{{\"discarded\":1,\"released_bytes\":7,\"orphans\":[\"staging/{orphan}\"]}}}}"
        )),
        "{report}"
    );
    assert!(report.contains("\"orphaned_staging\":0"), "{report}");
    assert!(report.contains("\"outcome\":\"applied\""), "{report}");
    assert!(!staging.join(&orphan).exists());
    assert_eq!(std::fs::read(staging.join("operator-notes"))?, b"keep");
    let output = recover(&root, &["--discard-orphaned-staging"])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_NOTHING_TO_DO,
        "recover_nothing_to_do",
    )?;
    assert_eq!(std::fs::read(staging.join("operator-notes"))?, b"keep");

    // Foreign trailing bytes: plan (read-only), refuse a different digest, apply the exact one.
    let clean_len = std::fs::metadata(&journal)?.len();
    append_bytes(&journal, b"foreign trailing bytes")?;
    let dirty = std::fs::read(&journal)?;
    let output = recover(&root, &["--plan-ledger-repair"])?;
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let planned = String::from_utf8(output.stdout)?;
    assert!(planned.contains("\"outcome\":\"planned\""), "{planned}");
    let digest = plan_digest(&planned)?;
    assert_eq!(std::fs::read(&journal)?, dirty, "the plan wrote");

    // A held deployment lock refuses every mutating action and leaves the bytes alone; the
    // read-only plan still answers, with the same digest.
    {
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("objects").join("LOCK"))?;
        lock.try_lock()?;
        let output = recover(&root, &["--apply-ledger-repair", &digest])?;
        assert_refused(&output, ERR_LAB_RECOVER_ROOT_LOCKED, "recover_root_locked")?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("\"retryable\":true"), "{stderr}");
        let output = recover(&root, &["--reconcile-effects"])?;
        assert_refused(&output, ERR_LAB_RECOVER_ROOT_LOCKED, "recover_root_locked")?;
        let output = recover(&root, &["--plan-ledger-repair"])?;
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(plan_digest(&String::from_utf8(output.stdout)?)?, digest);
        assert_eq!(std::fs::read(&journal)?, dirty);
    }

    let wrong = ContentDigest::sha256(b"not the plan").to_string();
    let output = recover(&root, &["--apply-ledger-repair", &wrong])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_PLAN_MISMATCH,
        "recover_plan_mismatch",
    )?;
    assert_eq!(std::fs::read(&journal)?, dirty);

    let output = recover(&root, &["--apply-ledger-repair", &digest])?;
    let applied = String::from_utf8(output.stdout)?;
    assert_eq!(output.status.code(), Some(0), "{applied}");
    assert!(applied.contains("\"outcome\":\"applied\""), "{applied}");
    assert!(
        applied.contains(&format!("\"plan_digest\":\"{digest}\"")),
        "{applied}"
    );
    assert!(applied.contains("\"quarantine_path\":"), "{applied}");
    assert_eq!(std::fs::metadata(&journal)?.len(), clean_len);
    // Resuming the completed apply: nothing to do.
    let output = recover(&root, &["--apply-ledger-repair", &digest])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_NOTHING_TO_DO,
        "recover_nothing_to_do",
    )?;

    // Foreign bytes that hold a structurally valid record are corrupt history: refused by the
    // plan and by apply.
    let history = std::fs::read(&journal)?;
    let mut foreign = b"garbage".to_vec();
    foreign.extend_from_slice(&history);
    append_bytes(&journal, &foreign)?;
    let output = recover(&root, &["--plan-ledger-repair"])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_CORRUPT_HISTORY,
        "recover_corrupt_history",
    )?;
    let output = recover(&root, &["--apply-ledger-repair", &digest])?;
    assert_refused(
        &output,
        ERR_LAB_RECOVER_CORRUPT_HISTORY,
        "recover_corrupt_history",
    )?;
    Ok(())
}

#[test]
fn recover_never_initializes_a_root() -> TestResult {
    let dir = Directory::new("uninit")?;
    let output = recover(&dir.0, &["--reconcile-effects"])?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(std::fs::read_dir(&dir.0)?.count(), 0);
    Ok(())
}
