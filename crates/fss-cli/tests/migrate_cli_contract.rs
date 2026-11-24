#![forbid(unsafe_code)]
//! CLI contract tests for `fss migrate --from <v1-root> --to <new-v2-root> [--json]`.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MISSING_VALUE, ERR_CLI_TRAILING_ARGUMENT,
    ERR_CLI_UNKNOWN_OPTION, FssCommand, MigrateArgs, parse_fss_args,
};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DecisionPath, EventHypothesis, EventId,
    EventKind, EventState, OperationId, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::migration::{
    DeploymentFormatVersion, ERR_MIGRATION_DESTINATION_EXISTS_001, MIGRATION_RECEIPT_FILENAME,
    detect_deployment_format,
};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:migrate-cli-contract";

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-migrate-cli-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err("could not allocate temp workspace".into())
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn build_v1_deployment(root: &Path) -> TestResult<ContentDigest> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:migrate-cli".to_owned(),
        operation_id: OperationId::parse("operation:migrate-cli")?,
        principal: "principal:cli-operator".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8_192)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    let mut dep = ReferenceDeployment::open(root, SITE, &cx)?;

    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:migrate-cli:1")?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        uncertainty_reason: Some("cli migration fixture".to_owned()),
        zone_ids: vec!["zone:yard".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.3, 0.7)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"cli-policy"),
            fingerprint: ContentDigest::sha256(b"cli-fp"),
            abstained: true,
            abstention_reason: Some("cli fixture".to_owned()),
        },
    };
    event.verify()?;
    dep.publish_event(
        &ReferencePolicyDecision {
            event,
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;

    let mask_policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:cli-cam")?,
        [320, 240],
        &[[0, 0, 32, 32]],
    )?;
    let mask_preview = preview_mask(&dep, &mask_policy)?;
    let _ = declare_mask(&mut dep, &mask_policy, mask_preview.approval, &cx)?;

    let orphan_digest = dep.stage_payload(b"cli-test-orphan-bytes")?;
    drop(dep);
    cx.drain_and_finalize();
    Ok(orphan_digest)
}

#[test]
fn migrate_argument_grammar_validates_strictly() {
    let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from));

    assert_eq!(
        parse(&["migrate", "--from", "/v1", "--to", "/v2", "--json"]).ok(),
        Some(FssCommand::Migrate(MigrateArgs {
            from: PathBuf::from("/v1"),
            to: PathBuf::from("/v2"),
            json: true,
            progress_jsonl: false,
        }))
    );
    assert_eq!(
        parse(&["migrate", "--from=/v1", "--to=/v2", "--progress-jsonl"]).ok(),
        Some(FssCommand::Migrate(MigrateArgs {
            from: PathBuf::from("/v1"),
            to: PathBuf::from("/v2"),
            json: false,
            progress_jsonl: true,
        }))
    );

    assert_eq!(
        parse(&["migrate", "--to", "/v2"])
            .err()
            .map(|e| e.error_id()),
        Some(ERR_CLI_MISSING_VALUE)
    );
    assert_eq!(
        parse(&["migrate", "--from", "/v1"])
            .err()
            .map(|e| e.error_id()),
        Some(ERR_CLI_MISSING_VALUE)
    );
    assert_eq!(
        parse(&["migrate", "--from", "/v1", "--from", "/v1b", "--to", "/v2"])
            .err()
            .map(|e| e.error_id()),
        Some(ERR_CLI_DUPLICATE_OPTION)
    );
    assert_eq!(
        parse(&["migrate", "--from", "/v1", "--to", "/v2", "--bogus"])
            .err()
            .map(|e| e.error_id()),
        Some(ERR_CLI_UNKNOWN_OPTION)
    );
    assert_eq!(
        parse(&["migrate", "--from", "/v1", "--to", "/v2", "extra"])
            .err()
            .map(|e| e.error_id()),
        Some(ERR_CLI_TRAILING_ARGUMENT)
    );
}

#[test]
fn fss_migrate_cli_end_to_end_json_progress_and_refusal() -> TestResult {
    let ws = TempWorkspace::new("e2e")?;
    let v1_root = ws.0.join("v1");
    let v2_root = ws.0.join("v2");
    let orphan_digest = build_v1_deployment(&v1_root)?;

    let fss_bin = env!("CARGO_BIN_EXE_fss");

    // 1. Run `fss migrate --from <v1> --to <v2> --json --progress-jsonl`.
    let output = Command::new(fss_bin)
        .args([
            "migrate",
            "--from",
            v1_root.to_string_lossy().as_ref(),
            "--to",
            v2_root.to_string_lossy().as_ref(),
            "--json",
            "--progress-jsonl",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "fss migrate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let stdout_trimmed = stdout.trim();
    assert!(stdout_trimmed.contains("\"schema\":\"fss.migration_receipt.v1\""));
    assert!(stdout_trimmed.contains("\"semantic_equivalence_verified\":true"));
    assert!(stdout_trimmed.contains("\"effects_verified\":true"));
    assert!(stdout_trimmed.contains("\"events_migrated\":1"));
    assert!(stdout_trimmed.contains("\"masks_migrated\":1"));
    assert!(stdout_trimmed.contains("\"source_unreferenced_orphan_count\":1"));
    assert!(stdout_trimmed.contains(&orphan_digest.to_text()));
    assert!(stdout_trimmed.contains("\"receipt_digest\":\"sha256:"));

    // Progress JSONL emitted on stderr.
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("\"schema\":\"fss.migration_progress.v1\""),
        "expected progress JSONL on stderr, got: {stderr}"
    );

    // Persisted receipt matches stdout byte-for-byte and destination is recognized as V2.
    let persisted = fs::read_to_string(v2_root.join(MIGRATION_RECEIPT_FILENAME))?;
    assert_eq!(persisted, stdout_trimmed);
    assert!(matches!(
        detect_deployment_format(&v2_root)?,
        DeploymentFormatVersion::V2 { .. }
    ));

    // 2. Re-running against existing destination refuses cleanly with diagnostic JSON.
    let second = Command::new(fss_bin)
        .args([
            "migrate",
            "--from",
            v1_root.to_string_lossy().as_ref(),
            "--to",
            v2_root.to_string_lossy().as_ref(),
            "--json",
        ])
        .output()?;
    assert!(!second.status.success());
    let second_stdout = String::from_utf8(second.stdout)?;
    assert!(second_stdout.contains(ERR_MIGRATION_DESTINATION_EXISTS_001));
    assert!(second_stdout.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    // 3. Human-readable mode (without --json) succeeds to a fresh destination.
    let v2_human = ws.0.join("v2-human");
    let human_out = Command::new(fss_bin)
        .args([
            "migrate",
            "--from",
            v1_root.to_string_lossy().as_ref(),
            "--to",
            v2_human.to_string_lossy().as_ref(),
        ])
        .output()?;
    assert!(
        human_out.status.success(),
        "human migrate failed: stderr={}",
        String::from_utf8_lossy(&human_out.stderr)
    );
    let human_stdout = String::from_utf8(human_out.stdout)?;
    assert!(human_stdout.contains("semantic_equivalence_verified: true"));
    assert!(human_stdout.contains("receipt_digest: sha256:"));

    Ok(())
}
