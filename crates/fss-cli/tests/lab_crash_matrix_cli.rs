#![forbid(unsafe_code)]
//! CLI contract of `fss-lab crash-matrix` (fss-2h5zq.15): argument refusals and their exit
//! codes, the empty-root guard, the `fss.lab.crash_matrix.v1` document, and the exit code
//! following the verdict.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE,
    ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_OPTION, ERR_LAB_RECOVER_NOTHING_TO_DO,
    ERR_LAB_RECOVER_PLAN_MISMATCH, LabAction, parse_lab_args,
};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_publication::{LedgerCutPoint, PublishCutPoint};
use fss_reference::{AppendPhase, ReferenceDeployment, ReplayCx};

#[path = "../../fss-reference/tests/caplog_support/mod.rs"]
mod caplog_support;
use caplog_support::Record;

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

/// Exhaustive expected-class mapping for every [`PublishCutPoint`] variant (no wildcard arm:
/// adding a variant to `fss-publication` fails to compile until the matrix covers it).
const fn expected_publish_row(point: PublishCutPoint) -> (&'static str, &'static str) {
    match point {
        PublishCutPoint::AfterChildrenVerified => {
            ("publish.after_children_verified", "unreferenced_objects")
        }
        PublishCutPoint::AfterManifestBody => {
            ("publish.after_manifest_body", "unreferenced_objects")
        }
        PublishCutPoint::AfterRootTempWrite => {
            ("publish.after_root_temp_write", "orphaned_root_temp")
        }
        PublishCutPoint::AfterRootRename => ("publish.after_root_rename", "pending_root"),
    }
}

/// Exhaustive expected-class mapping for every [`LedgerCutPoint`] variant.
const fn expected_ledger_row(point: LedgerCutPoint) -> (&'static str, &'static str) {
    match point {
        LedgerCutPoint::AfterRootDurable => ("ledger.after_root_durable", "pending_root"),
    }
}

/// Exhaustive expected-class mapping for all 8 [`AppendPhase`] variants.
const fn expected_append_row(phase: AppendPhase) -> (&'static str, &'static str) {
    match phase {
        AppendPhase::BodyWrite => ("append.body_write", "incomplete_tail"),
        AppendPhase::BodySync => ("append.body_sync", "incomplete_tail"),
        AppendPhase::CommitWrite => ("append.commit_write", "clean"),
        AppendPhase::CommitSync => ("append.commit_sync", "clean"),
        AppendPhase::ReconcileRead => ("append.reconcile_read", "not_applicable"),
        AppendPhase::ReconcileTruncate => ("append.reconcile_truncate", "not_applicable"),
        AppendPhase::ReconcileSync => ("append.reconcile_sync", "not_applicable"),
        AppendPhase::ReconcileSeek => ("append.reconcile_seek", "not_applicable"),
    }
}

fn expected_all_rows() -> Vec<(&'static str, &'static str)> {
    let mut rows = Vec::with_capacity(EXPECTED_ROWS);
    for point in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        rows.push(expected_publish_row(point));
    }
    {
        let point = LedgerCutPoint::AfterRootDurable;
        rows.push(expected_ledger_row(point));
    }
    for phase in [
        AppendPhase::BodyWrite,
        AppendPhase::BodySync,
        AppendPhase::CommitWrite,
        AppendPhase::CommitSync,
        AppendPhase::ReconcileRead,
        AppendPhase::ReconcileTruncate,
        AppendPhase::ReconcileSync,
        AppendPhase::ReconcileSeek,
    ] {
        rows.push(expected_append_row(phase));
    }
    rows.extend_from_slice(&[
        ("effect.lost_ack", "effect_indeterminate"),
        (
            "effect.after_commit_before_dispatch",
            "effect_indeterminate",
        ),
        ("cancel.deployment_open", "clean"),
        ("cancel.stage_objects", "not_applicable"),
        ("cancel.stage_manifest", "not_applicable"),
        ("cancel.publish_root", "unreferenced_objects"),
        ("cancel.publish_event", "unreferenced_objects"),
        ("cancel.append_batch", "not_applicable"),
        ("cancel.evaluate_policy", "unreferenced_objects"),
        ("cancel.dispatch_alert", "unreferenced_objects"),
        ("cancel.compile_situation", "clean"),
        ("cancel.seal_handoff", "clean"),
        ("cancel.after_children_verified", "unreferenced_objects"),
        ("cancel.after_manifest_body", "unreferenced_objects"),
        ("cancel.after_root_temp_write", "unreferenced_objects"),
        ("cancel.after_root_rename", "clean"),
    ]);
    rows
}

fn string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":\"");
    let start = json.find(&marker)? + marker.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn reopen_deployment(root: &Path) -> TestResult<ReferenceDeployment> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab-crash-matrix-cli".into(),
        operation_id: OperationId::parse("operation:lab-crash-matrix-cli")?,
        principal: "operator:lab-crash-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(b"fss.lab.anchor_universe.v1"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    Ok(ReferenceDeployment::reopen(root, "site:lab", &cx)?)
}

fn tree_digest(root: &Path) -> TestResult<String> {
    fn walk(base: &Path, dir: &Path, entries: &mut Vec<(String, Vec<u8>)>) -> TestResult {
        if !dir.exists() {
            return Ok(());
        }
        let mut children: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for entry in children {
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(base, &path, entries)?;
            } else {
                let rel = path
                    .strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push((rel, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut material = Vec::new();
    for (rel, bytes) in entries {
        material.extend_from_slice(rel.as_bytes());
        material.push(0);
        let digest = ContentDigest::sha256(&bytes).to_text();
        material.extend_from_slice(digest.as_bytes());
        material.push(b'\n');
    }
    Ok(ContentDigest::sha256(&material).to_text())
}

fn recover_with(root: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .arg("recover")
        .arg("--root")
        .arg(root)
        .args(args)
        .arg("--json")
        .output()?)
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
    let expected_rows = expected_all_rows();
    assert_eq!(expected_rows.len(), EXPECTED_ROWS);
    assert_eq!(
        scalar(document, "row_count"),
        Some(EXPECTED_ROWS.to_string().as_str())
    );

    let rows: Vec<&str> = document.split("{\"fault\":").skip(1).collect::<Vec<_>>();
    assert_eq!(rows.len(), EXPECTED_ROWS);
    let mut observed_by_slug: BTreeMap<&str, &str> = BTreeMap::new();
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
            "operator_actions",
            "operator_expected",
            "operator_outcome",
            "operator_note",
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
        let slug = row.split('"').nth(1).ok_or("slug")?;
        observed_by_slug.insert(slug, row);
    }

    // Exhaustive verification of every enum variant and fault slug against the expected table,
    // emitting one CAPLOG record per fault row for scripts/e2e/cap_lab_crash_matrix.sh.
    for (slug, exp_class) in &expected_rows {
        let row = *observed_by_slug
            .get(slug)
            .ok_or_else(|| format!("missing crash-matrix row for {slug}"))?;
        let obs_expected = string_field(row, "expected_class").ok_or("expected_class")?;
        let obs_class = string_field(row, "observed_class").ok_or("observed_class")?;
        let row_pass = scalar(row, "pass") == Some("true");
        let dup_effects = scalar(row, "duplicate_effects").unwrap_or("missing");
        let op_expected = string_field(row, "operator_expected").unwrap_or("missing");
        let op_outcome = string_field(row, "operator_outcome").unwrap_or("missing");
        let digest = if obs_class == "not_applicable" {
            assert!(
                !row.contains("\"reason\":null"),
                "{slug}: not_applicable row must state a reason: {row}"
            );
            "not_applicable".to_owned()
        } else {
            tree_digest(&root.join("rerun").join(slug))?
        };
        let step_name = format!("fault_{}", slug.replace('.', "_"));
        let rec = Record::new(&step_name)
            .check("expected_class", *exp_class, obs_expected)
            .check("observed_class", *exp_class, obs_class)
            .check("operator_outcome", op_expected, op_outcome)
            .check("duplicate_effects", "0", dup_effects)
            .check("row_pass", true, row_pass)
            .check("tree_digest", digest.as_str(), digest.as_str());
        rec.emit_checked(0, rec.passed());
        assert_eq!(obs_expected, *exp_class, "{slug}");
        assert_eq!(obs_class, *exp_class, "{slug}");
        assert_eq!(op_outcome, op_expected, "{slug}");
        assert!(row_pass, "{slug}: {row}");
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
    assert!(passed, "crash matrix reported mismatches: {document}");
    assert_eq!(output.status.code(), Some(0));

    // Every run row left its crashed sub-root and its recovered copy on disk as a corpus;
    // not-applicable rows created nothing.
    for row in &rows {
        let slug = row.split('"').nth(1).ok_or("slug")?;
        let ran = !row.contains("\"observed_class\":\"not_applicable\"");
        assert_eq!(root.join(slug).is_dir(), ran, "{slug}");
        assert_eq!(root.join("rerun").join(slug).is_dir(), ran, "{slug}");
    }

    // Every row names its operator step; the effect rows name --reconcile-effects.
    for (slug, actions) in [
        ("effect.lost_ack", "[\"--reconcile-effects\"]"),
        (
            "effect.after_commit_before_dispatch",
            "[\"--reconcile-effects\"]",
        ),
        (
            "append.body_write",
            "[\"--truncate-incomplete-tail ledger\"]",
        ),
        (
            "publish.after_root_temp_write",
            "[\"--discard-orphaned-temps\"]",
        ),
        (
            "cancel.dispatch_alert",
            "[\"--discard-orphaned-temps\",\"--discard-orphaned-staging\",\"--reconcile-effects\"]",
        ),
    ] {
        let row = rows
            .iter()
            .find(|row| row.starts_with(&format!("\"{slug}\"")))
            .ok_or(slug)?;
        assert!(
            row.contains(&format!("\"recovery_actions\":{actions}")),
            "{slug}: {row}"
        );
    }

    // Separate-process recover: effect.lost_ack reconciles to Verified from the durable provider
    // journal, leaves the provider record count unchanged, reopens cleanly, and idempotently
    // refuses a second reconcile with recover_nothing_to_do.
    let lost_ack = dir.0.join("lost-ack-copy");
    copy_tree(&root.join("effect.lost_ack"), &lost_ack)?;
    let provider_log = lost_ack.join("effects").join("simulated_provider.fssj");
    assert!(provider_log.is_file());
    let provider_before = fss_ledger::inspect(&provider_log)?.records().len();
    let output = recover_effects(&lost_ack)?;
    let report = String::from_utf8(output.stdout)?;
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert!(report.contains("\"outcome\":\"applied\""), "{report}");
    assert!(
        report.contains("\"observation\":\"delivered_ack_lost\",\"to\":\"verified\""),
        "{report}"
    );
    assert!(report.contains("\"indeterminate\":0"), "{report}");
    let provider_after = fss_ledger::inspect(&provider_log)?.records().len();
    assert_eq!(
        provider_before, provider_after,
        "reconcile must never issue a second provider delivery"
    );
    {
        let reopened_lost_ack = reopen_deployment(&lost_ack)?;
        assert!(reopened_lost_ack.current_anchor().commit_sequence >= 1);
    }
    let lost_ack_second = recover_effects(&lost_ack)?;
    let lost_ack_second_stderr = String::from_utf8(lost_ack_second.stderr)?;
    assert_eq!(
        lost_ack_second.status.code(),
        Some(6),
        "{lost_ack_second_stderr}"
    );
    assert!(
        lost_ack_second_stderr.contains(ERR_LAB_RECOVER_NOTHING_TO_DO),
        "{lost_ack_second_stderr}"
    );
    let rec_lost = Record::new("recover_effect_lost_ack")
        .check("outcome", "applied", "applied")
        .check(
            "provider_records_unchanged",
            provider_before,
            provider_after,
        )
        .check(
            "second_recover_exit",
            6_i32,
            lost_ack_second.status.code().unwrap_or(-1),
        );
    rec_lost.emit_checked(0, rec_lost.passed());

    // Separate-process recover: effect.after_commit_before_dispatch stays indeterminate.
    let unobserved = dir.0.join("unobserved-copy");
    copy_tree(
        &root.join("effect.after_commit_before_dispatch"),
        &unobserved,
    )?;
    let output = recover_effects(&unobserved)?;
    let report = String::from_utf8(output.stdout)?;
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert!(
        report.contains("\"outcome\":\"indeterminate_remains\""),
        "{report}"
    );
    assert!(
        report.contains("\"observation\":\"none\",\"to\":\"indeterminate\""),
        "{report}"
    );
    assert!(report.contains("\"indeterminate\":1"), "{report}");
    let rec_unobs = Record::new("recover_effect_after_commit_before_dispatch")
        .check("outcome", "indeterminate_remains", "indeterminate_remains")
        .check(
            "indeterminate_count",
            true,
            report.contains("\"indeterminate\":1"),
        );
    rec_unobs.emit_checked(0, rec_unobs.passed());

    // Separate-process recover: publish.after_root_temp_write discards the orphaned temp and
    // reopens cleanly through ReferenceDeployment.
    let pub_temp = dir.0.join("publish-temp-copy");
    copy_tree(&root.join("publish.after_root_temp_write"), &pub_temp)?;
    let discard_out = recover_with(&pub_temp, &["--discard-orphaned-temps"])?;
    let discard_report = String::from_utf8(discard_out.stdout)?;
    assert_eq!(discard_out.status.code(), Some(0), "{discard_report}");
    assert!(
        discard_report.contains("\"outcome\":\"applied\""),
        "{discard_report}"
    );
    drop(reopen_deployment(&pub_temp)?);
    let discard_again = recover_with(&pub_temp, &["--discard-orphaned-temps"])?;
    let discard_again_stderr = String::from_utf8(discard_again.stderr)?;
    assert_eq!(
        discard_again.status.code(),
        Some(6),
        "{discard_again_stderr}"
    );
    assert!(
        discard_again_stderr.contains(ERR_LAB_RECOVER_NOTHING_TO_DO),
        "{discard_again_stderr}"
    );
    let rec_pub = Record::new("recover_publish_after_root_temp_write")
        .check(
            "applied",
            true,
            discard_report.contains("\"outcome\":\"applied\""),
        )
        .check(
            "second_exit",
            6_i32,
            discard_again.status.code().unwrap_or(-1),
        );
    rec_pub.emit_checked(0, rec_pub.passed());

    // Separate-process recover: append.body_write truncates the incomplete tail and reopens.
    let body_write = dir.0.join("append-body-write-copy");
    copy_tree(&root.join("append.body_write"), &body_write)?;
    let trunc_out = recover_with(&body_write, &["--truncate-incomplete-tail", "ledger"])?;
    let trunc_report = String::from_utf8(trunc_out.stdout)?;
    assert_eq!(trunc_out.status.code(), Some(0), "{trunc_report}");
    assert!(
        trunc_report.contains("\"outcome\":\"applied\""),
        "{trunc_report}"
    );
    let _ = reopen_deployment(&body_write)?;
    let rec_trunc = Record::new("recover_append_body_write")
        .check(
            "applied",
            true,
            trunc_report.contains("\"outcome\":\"applied\""),
        )
        .check("exit", 0_i32, trunc_out.status.code().unwrap_or(-1));
    rec_trunc.emit_checked(0, rec_trunc.passed());

    // Round-3 error case: a repair plan computed at root A must be refused as plan_mismatch when
    // applied to root B (path-bound plan digest).
    let plan_a = dir.0.join("plan-path-a");
    let plan_b = dir.0.join("plan-path-b");
    copy_tree(&root.join("append.body_write"), &plan_a)?;
    copy_tree(&root.join("append.body_write"), &plan_b)?;
    let trunc_a = recover_with(&plan_a, &["--truncate-incomplete-tail", "ledger"])?;
    assert_eq!(trunc_a.status.code(), Some(0));
    let trunc_b = recover_with(&plan_b, &["--truncate-incomplete-tail", "ledger"])?;
    assert_eq!(trunc_b.status.code(), Some(0));
    let journal_a = plan_a.join("ledger").join("journal.fssj");
    let journal_b = plan_b.join("ledger").join("journal.fssj");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&journal_a)?
        .write_all(b"foreign-tail-bytes")?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&journal_b)?
        .write_all(b"foreign-tail-bytes")?;
    let planned_a = recover_with(&plan_a, &["--plan-ledger-repair"])?;
    assert_eq!(planned_a.status.code(), Some(0));
    let planned_a_text = String::from_utf8(planned_a.stdout)?;
    let digest_a = string_field(&planned_a_text, "plan_digest").ok_or("plan_digest")?;
    let cross_apply = recover_with(&plan_b, &["--apply-ledger-repair", digest_a])?;
    let cross_stderr = String::from_utf8(cross_apply.stderr)?;
    assert_eq!(cross_apply.status.code(), Some(6), "{cross_stderr}");
    assert!(
        cross_stderr.contains(ERR_LAB_RECOVER_PLAN_MISMATCH),
        "{cross_stderr}"
    );
    let rec_cross = Record::new("recover_cross_path_plan_mismatch")
        .check("exit", 6_i32, cross_apply.status.code().unwrap_or(-1))
        .check(
            "plan_mismatch",
            true,
            cross_stderr.contains(ERR_LAB_RECOVER_PLAN_MISMATCH),
        );
    rec_cross.emit_checked(0, rec_cross.passed());

    Ok(())
}

fn recover_effects(root: &Path) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(["recover", "--reconcile-effects", "--json", "--root"])
        .arg(root)
        .output()?)
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
