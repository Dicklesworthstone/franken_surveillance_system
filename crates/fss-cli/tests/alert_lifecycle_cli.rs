#![forbid(unsafe_code)]
//! Real process tests over disk-durable prepared alerts. No relay or device is contacted.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EffectIntent,
    EffectState, EventHypothesis, EventId, EventKind, EventState, IdempotencyKey, ObligationId,
    OperationId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::alert_control::CAP_ALERT_CANCEL;
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:alert-lifecycle-cli";
const OPERATION: &str = "operation:alert:cli";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-alert-lifecycle-{label}-{}-{n}",
                std::process::id(),
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-lifecycle-test".into(),
        operation_id: OperationId::parse("operation:alert-lifecycle-test")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_CANCEL.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

// Forked CLI children briefly inherit another parallel test's file lock until exec.
// Retry only the known lock refusal, never a lifecycle or storage failure.
fn open(root: &Path, cx: &ReplayCx) -> TestResult<ReferenceDeployment> {
    for _ in 0..100 {
        match ReferenceDeployment::open(root, SITE, cx) {
            Err(e) if e.is_deployment_locked() => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            value => return Ok(value?),
        }
    }
    Err("test deployment lock remained held".into())
}

fn fixture(root: &Path, committed: bool) -> TestResult {
    let cx = context(root)?;
    let mut deployment = open(root, &cx)?;
    let id = OperationId::parse(OPERATION)?;
    deployment.effects_and_ledger().0.prepare(
        EffectIntent::new(
            id.clone(),
            IdempotencyKey::parse("idempotency:alert:cli")?,
            "alert.dispatch",
            ContentDigest::sha256(b"request"),
            ContentDigest::sha256(b"preconditions"),
        )?,
        ObligationId::parse("obligation:alert:cli")?,
        fss_reference::REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    if committed {
        deployment.effects_and_ledger().0.transition(
            &id,
            EffectState::Committed,
            TimestampNs(101),
            None,
            None,
        )?;
    }
    cx.drain_and_finalize();
    Ok(())
}

fn publish_hypothesis(root: &Path) -> TestResult<PathBuf> {
    let cx = context(root)?;
    let mut deployment = open(root, &cx)?;
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.into(),
        event_id: EventId::parse("event:alert-status-source")?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: None,
        zone_ids: vec!["door".into()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"synthetic source fixture"),
            fingerprint: ContentDigest::sha256(b"unclassified source hypothesis"),
            abstained: true,
            abstention_reason: Some("synthetic reference hypothesis only".into()),
        },
    };
    let receipt = deployment.publish_event(
        &ReferencePolicyDecision {
            event,
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(receipt.event_root);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(path)
}

fn invoke(root: &Path, mode: &str, args: &[&str]) -> TestResult<Output> {
    for _ in 0..100 {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-alert"))
            .arg(mode)
            .arg("--root")
            .arg(root)
            .args(["--site", SITE])
            .args(args)
            .output()?;
        if !String::from_utf8_lossy(&output.stderr).contains("reference deployment is locked") {
            return Ok(output);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err("CLI deployment lock remained held".into())
}

fn success(output: Output) -> TestResult<String> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

// Fields extracted here are canonical ASCII digests, not arbitrary JSON string data.
fn digest_field(text: &str, name: &str) -> TestResult<String> {
    let prefix = format!("\"{name}\":\"");
    let value = text
        .split_once(&prefix)
        .ok_or("digest field absent")?
        .1
        .split_once('"')
        .ok_or("unterminated digest field")?
        .0;
    ContentDigest::parse(value)?;
    Ok(value.to_owned())
}

fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(path)?),
            );
        }
    }
    Ok(result)
}

#[test]
fn status_is_read_only_even_for_a_crash_interrupted_commit() -> TestResult {
    let dir = Directory::new("status")?;
    fixture(&dir.0, true)?;
    let before = files(&dir.0)?;
    let status = success(invoke(&dir.0, "status", &[])?)?;
    assert!(status.contains("\"state\":\"committed\""));
    assert!(!status.contains("\"state\":\"cancelled\""));
    assert!(status.contains("\"writes\":\"none\""));
    assert!(status.contains("\"cancellation_candidate\":false"));
    assert!(status.contains("\"dispatch_authorized\":false"));
    assert!(status.contains("not_inferred_from_local_state"));
    assert!(status.contains("\"source_custody\":\"not_inspected\""));
    assert!(status.contains("\"terminal_proof_custody\":\"not_inspected\""));
    assert_eq!(
        before,
        files(&dir.0)?,
        "status must not perform restart reclassification"
    );
    assert_eq!(status, success(invoke(&dir.0, "status", &[])?)?);
    Ok(())
}

#[test]
fn preview_cancel_and_cold_exact_retry_retire_only_the_named_operation() -> TestResult {
    let dir = Directory::new("cancel")?;
    fixture(&dir.0, false)?;
    let before = files(&dir.0)?;
    let args = ["--operation-id", OPERATION];
    let preview = success(invoke(&dir.0, "cancel", &args)?)?;
    let approval = digest_field(&preview, "approval_digest")?;
    assert!(preview.contains("\"new_cancellation_committed\":false"));
    assert_eq!(before, files(&dir.0)?);
    let wrong_digest = ContentDigest::sha256(b"wrong").to_text();
    let wrong = invoke(
        &dir.0,
        "cancel",
        &["--operation-id", OPERATION, "--approve", &wrong_digest],
    )?;
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("ERR-ALERT-APPROVAL-STALE-001"));
    assert_eq!(before, files(&dir.0)?);
    let committed = success(invoke(
        &dir.0,
        "cancel",
        &["--operation-id", OPERATION, "--approve", &approval],
    )?)?;
    assert!(committed.contains("\"outcome\":\"cancelled\""));
    assert!(committed.contains("\"new_cancellation_committed\":true"));
    assert!(committed.contains("\"network_access\":false"));
    let after = files(&dir.0)?;
    let retry = success(invoke(
        &dir.0,
        "cancel",
        &["--operation-id", OPERATION, "--approve", &approval],
    )?)?;
    assert!(retry.contains("\"outcome\":\"already_cancelled\""));
    assert_eq!(after, files(&dir.0)?);
    let status = success(invoke(&dir.0, "status", &args)?)?;
    assert!(status.contains("\"state\":\"cancelled\""));
    assert!(status.contains("terminal_local_cancellation_do_not_dispatch"));
    assert_eq!(
        digest_field(&committed, "receipt_digest")?,
        digest_field(&status, "receipt_digest")?
    );
    assert_eq!(after, files(&dir.0)?);
    let evidence = digest_field(&committed, "evidence_digest")?;
    fs::remove_file(
        dir.0
            .join("objects/spool/objects")
            .join(evidence.trim_start_matches("sha256:")),
    )?;
    let without_evidence = files(&dir.0)?;
    let recorded = success(invoke(&dir.0, "status", &args)?)?;
    assert!(recorded.contains("\"state\":\"cancelled\""));
    assert!(recorded.contains("\"terminal_proof_custody\":\"not_inspected\""));
    assert_eq!(without_evidence, files(&dir.0)?);
    Ok(())
}

#[test]
fn lost_or_corrupt_event_objects_do_not_hide_recoverable_alert_operations() -> TestResult {
    for missing in [false, true] {
        let dir = Directory::new("source-loss")?;
        fixture(&dir.0, false)?;
        let event_manifest = publish_hypothesis(&dir.0)?;
        read_deployment(&dir.0, &OrientLimits::default())?;
        let healthy_status = success(invoke(&dir.0, "status", &[])?)?;
        if missing {
            fs::remove_file(event_manifest)?;
        } else {
            fs::write(event_manifest, b"corrupt event manifest")?;
        }
        assert!(
            read_deployment(&dir.0, &OrientLimits::default()).is_err(),
            "the original whole-deployment reader must encounter the damaged event"
        );
        let before = files(&dir.0)?;
        let status = success(invoke(&dir.0, "status", &[])?)?;
        assert_eq!(
            status, healthy_status,
            "journal inventory does not certify source custody"
        );
        assert!(status.contains(OPERATION));
        assert!(status.contains("\"state\":\"prepared\""));
        assert!(status.contains("\"source_custody\":\"not_inspected\""));
        assert!(status.contains("\"terminal_proof_custody\":\"not_inspected\""));
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn degraded_source_custody_does_not_relax_either_committed_journal_check() -> TestResult {
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let dir = Directory::new("journal-corruption")?;
        fixture(&dir.0, false)?;
        fs::remove_file(publish_hypothesis(&dir.0)?)?;
        let path = dir.0.join(relative);
        let mut bytes = fs::read(&path)?;
        // The 88-byte FSS journal header precedes a committed, checksummed payload.
        *bytes
            .get_mut(88)
            .ok_or("fixture has no committed payload")? ^= 1;
        fs::write(&path, bytes)?;
        let before = files(&dir.0)?;
        let refused = invoke(&dir.0, "status", &[])?;
        assert!(!refused.status.success(), "corrupt {relative} was accepted");
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("failed verification"));
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn an_absent_authority_or_effect_journal_is_unknown_and_is_never_recreated() -> TestResult {
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let dir = Directory::new("absent-journal")?;
        fixture(&dir.0, false)?;
        fs::remove_file(dir.0.join(relative))?;
        let before = files(&dir.0)?;
        let status = success(invoke(&dir.0, "status", &[])?)?;
        assert!(status.contains("unknown_beyond_committed_prefix"));
        assert!(!status.contains("\"cancellation_candidate\":true"));
        if relative == "ledger/journal.fssj" {
            assert!(status.contains("\"ledger_journal_present\":false"));
            assert!(status.contains(OPERATION));
        } else {
            assert!(status.contains("\"effect_journal_present\":false"));
            assert!(status.contains("\"operation_count\":0"));
        }
        let lookup = success(invoke(
            &dir.0,
            "status",
            &["--operation-id", "operation:possibly-in-missing-history"],
        )?)?;
        assert!(
            lookup.contains("\"requested_operation_id\":\"operation:possibly-in-missing-history\"")
        );
        assert!(lookup.contains("\"operation_lookup\":\"unknown_beyond_committed_prefix\""));
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn committed_alert_cannot_be_forced_cancelled_and_remains_unresolved() -> TestResult {
    let dir = Directory::new("committed")?;
    fixture(&dir.0, true)?;
    let failed = invoke(&dir.0, "cancel", &["--operation-id", OPERATION])?;
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    // Locked open performs the existing conservative restart classification, not a resend.
    let status = success(invoke(&dir.0, "status", &[])?)?;
    assert!(status.contains("\"state\":\"indeterminate\""));
    assert!(status.contains("restart_reconciliation_pending_observation"));
    assert!(!status.contains("\"state\":\"cancelled\""));
    assert!(
        status
            .contains("obtain_independent_provider_evidence_do_not_resend_or_force_terminal_state")
    );
    Ok(())
}

#[test]
fn incomplete_tail_is_visible_and_never_makes_a_cancellation_candidate() -> TestResult {
    let dir = Directory::new("tail")?;
    fixture(&dir.0, false)?;
    fs::OpenOptions::new()
        .append(true)
        .open(dir.0.join("effects/journal.fssj"))?
        .write_all(b"FSSJRN01")?;
    let before = files(&dir.0)?;
    let status = success(invoke(&dir.0, "status", &[])?)?;
    assert!(status.contains("\"effect_tail_uncommitted\":true"));
    assert!(status.contains("unknown_beyond_committed_prefix"));
    assert!(status.contains("\"cancellation_candidate\":false"));
    let lookup = success(invoke(
        &dir.0,
        "status",
        &["--operation-id", "operation:possibly-in-uncommitted-tail"],
    )?)?;
    assert!(lookup.contains("\"operation_lookup\":\"unknown_beyond_committed_prefix\""));
    assert!(lookup.contains("operation:possibly-in-uncommitted-tail"));
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn invalid_commands_fail_before_creating_a_deployment_or_printing_json() -> TestResult {
    let dir = Directory::new("parse")?;
    let missing = dir.0.join("does-not-exist");
    for (mode, extra) in [
        ("cancel", vec![]),
        ("status", vec!["--approve", "sha256:bad"]),
        (
            "cancel",
            vec!["--operation-id", OPERATION, "--operation-id", OPERATION],
        ),
        (
            "cancel",
            vec!["--operation-id", OPERATION, "--approve", "sha256:bad"],
        ),
        (
            "cancel",
            vec!["--operation-id", OPERATION, "--force", "yes"],
        ),
    ] {
        let output = invoke(&missing, mode, &extra)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!missing.exists());
    }
    let valid_but_missing = invoke(&missing, "cancel", &["--operation-id", OPERATION])?;
    assert!(!valid_but_missing.status.success());
    assert!(!missing.exists());
    let help = Command::new(env!("CARGO_BIN_EXE_fss-alert"))
        .args(["cancel", "--help"])
        .output()?;
    assert!(success(help)?.contains("never-committed alert"));
    Ok(())
}

#[test]
fn unknown_operation_and_different_actor_do_not_inherit_a_terminal_result() -> TestResult {
    let dir = Directory::new("actor")?;
    fixture(&dir.0, false)?;
    let missing = invoke(&dir.0, "status", &["--operation-id", "operation:missing"])?;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    let preview = success(invoke(&dir.0, "cancel", &["--operation-id", OPERATION])?)?;
    let approval = digest_field(&preview, "approval_digest")?;
    success(invoke(
        &dir.0,
        "cancel",
        &["--operation-id", OPERATION, "--approve", &approval],
    )?)?;
    let before = files(&dir.0)?;
    let wrong = invoke(
        &dir.0,
        "cancel",
        &[
            "--operation-id",
            OPERATION,
            "--principal",
            "principal:other",
            "--approve",
            &approval,
        ],
    )?;
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}
