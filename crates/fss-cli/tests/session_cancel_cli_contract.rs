#![forbid(unsafe_code)]
//! Session cancellation through real CLI and MCP processes, durable cold recovery and fenced
//! claim reclamation. Only synthetic local deployment fixtures are used; no external effect runs.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use fss_cli::json_input::{Value, parse};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectIntent, IdempotencyKey, ObligationId,
    OperationId, RootAuthoritySpec, SessionId, TimestampNs,
};
use fss_object::{HostSpoolIo, SpoolLock};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::cancellation::{
    CAP_SESSION_CANCEL, SessionCancellationError, cancel_session,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:session-cancel-cli";
const OWNER: &str = "principal:session-cancel-owner";
const MISSION: &str = "Review the retained door observation";
const OBJECTIVE: &str = "Keep pending observations and work explicitly owned";

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut value = value;
    for key in path {
        value = value
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing {key}"))?;
    }
    Ok(value)
}
fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| "expected text".into())
}
fn pointer<'a>(value: &'a Value, prefix: &str) -> TestResult<&'a str> {
    let mut values = field(value, &["proofPointers"])?
        .array()
        .ok_or("proof pointers")?
        .iter()
        .filter_map(Value::text)
        .filter_map(|value| value.strip_prefix(prefix));
    let first = values.next().ok_or("missing pointer")?;
    assert!(values.next().is_none());
    Ok(first)
}

fn authority(
    principal: &str,
    capabilities: Vec<String>,
    site: &str,
) -> TestResult<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:session-cancel-fixture".into(),
        operation_id: OperationId::parse("operation:session-cancel-fixture")?,
        principal: principal.into(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })?)
}

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
}
impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        for serial in 0..100 {
            let directory = std::env::temp_dir().join(format!(
                "fss-session-cancel-{tag}-{}-{serial}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let root = directory.join("deployment");
                    let authority = authority(OWNER, vec![ADP_REPLAY_ROW_ID.into()], SITE)?;
                    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
                        &authority,
                        directory.join("cx"),
                    )?);
                    drop(ReferenceDeployment::open(&root, SITE, &cx)?);
                    return Ok(Self {
                        directory,
                        root,
                        cx,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory bound".into())
    }
    fn cli_as(
        &self,
        owner: &str,
        command: &[&str],
        options: &[&str],
    ) -> TestResult<(i32, String, Value)> {
        let mut args: Vec<OsString> = command.iter().map(OsString::from).collect();
        args.extend([
            OsString::from("--json"),
            OsString::from("--root"),
            self.root.as_os_str().to_owned(),
            OsString::from("--principal"),
            OsString::from(owner),
        ]);
        args.extend(options.iter().map(OsString::from));
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(args)
            .output()?;
        let body = String::from_utf8(output.stdout)?;
        let value = parse(body.trim())?;
        Ok((output.status.code().ok_or("CLI signal")?, body, value))
    }
    fn ok(&self, command: &[&str], options: &[&str]) -> TestResult<Value> {
        let (code, body, value) = self.cli_as(OWNER, command, options)?;
        assert_eq!(code, 0, "{body}");
        self.conforms("agent_response_envelope.v1.json", &body)?;
        if text(&value, &["payloadSchema"])? == "fss.agent_cognitive_envelope.v1" {
            let start = body.find(",\"payload\":").ok_or("payload")? + ",\"payload\":".len();
            let end = body.find(",\"payloadDigest\":").ok_or("payload digest")?;
            self.conforms("agent_cognitive_envelope.v1.json", &body[start..end])?;
        }
        Ok(value)
    }
    fn conforms(&self, schema: &str, body: &str) -> TestResult {
        let instance = self.directory.join("instance.json");
        fs::write(&instance, body)?;
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = Command::new("python3")
            .arg("-B")
            .arg(repo.join("scripts/json_instance_validate.py"))
            .arg(repo.join("schemas").join(schema))
            .arg(&instance)
            .output()?;
        assert!(
            output.status.success(),
            "{schema}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    fn open(&self, budget: &str) -> TestResult<String> {
        let answer = self.ok(
            &["session", "open"],
            &[
                "--mission-text",
                MISSION,
                "--objective",
                OBJECTIVE,
                "--budget-tokens",
                budget,
            ],
        )?;
        Ok(text(&answer, &["sessionId"])?.into())
    }
    fn cancel(&self, session: &str, approval: Option<&str>) -> TestResult<Value> {
        let mut options = vec!["--session", session];
        if let Some(approval) = approval {
            options.extend(["--approve", approval]);
        }
        self.ok(&["cancel"], &options)
    }
    fn journal(&self) -> TestResult<Vec<u8>> {
        Ok(fs::read(self.root.join("agent/sessions/journal.fssj"))?)
    }
    fn prepare_obligation(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: OperationId::parse("operation:session-cancel:synthetic")?,
                idempotency_key: IdempotencyKey::parse("idempotency:session-cancel:synthetic")?,
                effect_class: "fixture.observe".into(),
                request_digest: ContentDigest::sha256(b"synthetic request"),
                precondition_digest: ContentDigest::sha256(b"synthetic precondition"),
            },
            ObligationId::parse("obligation:session-cancel:synthetic")?,
            "synthetic observation verified",
            TimestampNs(100),
        )?;
        Ok(())
    }
    fn claim(&self, session: &str, transition: &str, options: &[&str]) -> TestResult<Value> {
        let mut all = vec!["--session", session, "--transition", transition];
        all.extend_from_slice(options);
        self.ok(&["investigate"], &all)
    }
    fn mcp(&self, principal: &str, arguments: &str) -> TestResult<Value> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.root)
            .arg("--principal")
            .arg(principal)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin")?;
        writeln!(
            input,
            "{}",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"session-cancellation-test","version":"1"}}}"#
        )?;
        writeln!(
            input,
            "{}",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )?;
        writeln!(
            input,
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"cancel\",\"arguments\":{arguments}}}}}"
        )?;
        drop(input);
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{stdout}");
        let initialized = parse(lines[0])?;
        assert_eq!(
            text(&initialized, &["result", "protocolVersion"])?,
            "2025-06-18",
            "{stdout}"
        );
        let wire = parse(lines[1])?;
        assert!(
            wire.object()
                .is_some_and(|fields| !fields.contains_key("error")),
            "MCP transport rejected the admitted cancellation: {stdout}"
        );
        assert_eq!(field(&wire, &["id"])?.integer(), Some(2), "{stdout}");
        let content = field(&wire, &["result", "content"])?
            .array()
            .ok_or("MCP content")?;
        let body = text(&content[0], &["text"])?;
        self.conforms("agent_response_envelope.v1.json", body)?;
        Ok(parse(body)?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

type FileState = BTreeMap<PathBuf, (ContentDigest, SystemTime)>;
fn tree(root: &Path, agent: bool) -> TestResult<FileState> {
    fn walk(root: &Path, directory: &Path, agent: bool, state: &mut FileState) -> TestResult {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if !agent && relative.starts_with("agent") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                walk(root, &path, agent, state)?;
            } else if metadata.is_file() {
                state.insert(
                    relative,
                    (
                        ContentDigest::sha256(&fs::read(path)?),
                        metadata.modified()?,
                    ),
                );
            } else {
                return Err("unexpected fixture file kind".into());
            }
        }
        Ok(())
    }
    let mut state = BTreeMap::new();
    walk(root, root, agent, &mut state)?;
    Ok(state)
}

#[test]
fn preview_is_read_only_and_fresh_grant_owner_approval_and_lock_are_mandatory() -> TestResult {
    let fixture = Fixture::new("authority")?;
    let session = fixture.open("3000")?;
    let session_id = SessionId::parse(&session)?;
    let before = tree(&fixture.root, true)?;
    let preview = fixture.cancel(&session, None)?;
    assert_eq!(text(&preview, &["operationId"])?, "AOP-010");
    assert_eq!(
        text(&preview, &["payloadSchema"])?,
        "fss.agent_cognitive_envelope.v1"
    );
    let approval = pointer(&preview, "session-cancellation-approval:")?;
    assert_eq!(
        tree(&fixture.root, true)?,
        before,
        "preview must not rewrite clocks or pins"
    );
    for grants in [Vec::new(), vec!["CAP-AGENT-SESSION-WRITE-001".into()]] {
        let denied = authority(OWNER, grants, SITE)?;
        assert!(matches!(
            cancel_session(&fixture.root, &session_id, &denied, None),
            Err(SessionCancellationError::Unauthorized)
        ));
    }
    let foreign = authority(OWNER, vec![CAP_SESSION_CANCEL.into()], "site:foreign")?;
    assert!(matches!(
        cancel_session(&fixture.root, &session_id, &foreign, None),
        Err(SessionCancellationError::Unauthorized)
    ));
    let (code, _, wrong_owner) = fixture.cli_as(
        "principal:other",
        &["cancel"],
        &["--session", &session, "--approve", approval],
    )?;
    assert_eq!(code, 5);
    assert_eq!(
        text(&wrong_owner, &["errorId"])?,
        "ERR-AGENT-SESSION-NOT-FOUND-001"
    );
    let wrong = ContentDigest::sha256(b"not the approved request").to_text();
    let (code, _, wrong_approval) = fixture.cli_as(
        OWNER,
        &["cancel"],
        &["--session", &session, "--approve", &wrong],
    )?;
    assert_eq!(code, 5);
    assert_eq!(
        text(&wrong_approval, &["errorId"])?,
        "ERR-PRECONDITION-STALE-001"
    );
    assert_eq!(tree(&fixture.root, true)?, before);
    let lock = SpoolLock::try_acquire(
        fs::File::open(fixture.root.join("agent/sessions/LOCK"))?,
        Arc::new(HostSpoolIo),
    )
    .map_err(|_| "fixture lock")?;
    let (code, _, locked) = fixture.cli_as(
        OWNER,
        &["cancel"],
        &["--session", &session, "--approve", approval],
    )?;
    assert_eq!(code, 5);
    assert_eq!(
        text(&locked, &["errorId"])?,
        "ERR-AGENT-SESSION-STORE-LOCKED-001"
    );
    drop(lock);
    assert_eq!(tree(&fixture.root, true)?, before);
    let lock = SpoolLock::try_acquire(
        fs::File::open(fixture.root.join("objects/LOCK"))?,
        Arc::new(HostSpoolIo),
    )
    .map_err(|_| "fixture deployment lock")?;
    let (code, _, locked) = fixture.cli_as(
        OWNER,
        &["cancel"],
        &["--session", &session, "--approve", approval],
    )?;
    assert_eq!(code, 5);
    assert_eq!(
        text(&locked, &["errorId"])?,
        "ERR-AGENT-SESSION-STORE-LOCKED-001"
    );
    drop(lock);
    assert_eq!(tree(&fixture.root, true)?, before);
    // Any later journal/workspace command makes a live preview stale, even at the same head.
    fixture.open("4000")?;
    let changed = tree(&fixture.root, true)?;
    let (code, _, stale) = fixture.cli_as(
        OWNER,
        &["cancel"],
        &["--session", &session, "--approve", approval],
    )?;
    assert_eq!(code, 5);
    assert_eq!(text(&stale, &["errorId"])?, "ERR-PRECONDITION-STALE-001");
    assert_eq!(tree(&fixture.root, true)?, changed);
    let fresh = fixture.cancel(&session, None)?;
    let fresh_approval = pointer(&fresh, "session-cancellation-approval:")?;
    // Independent effect owners change the preview's prefix without touching session history.
    let journal = fixture.journal()?;
    fixture.prepare_obligation()?;
    assert_eq!(fixture.journal()?, journal);
    let after_effect = tree(&fixture.root, true)?;
    let (code, _, stale) = fixture.cli_as(
        OWNER,
        &["cancel"],
        &["--session", &session, "--approve", fresh_approval],
    )?;
    assert_eq!(code, 5);
    assert_eq!(text(&stale, &["errorId"])?, "ERR-PRECONDITION-STALE-001");
    assert_eq!(tree(&fixture.root, true)?, after_effect);
    Ok(())
}

#[test]
fn cold_cancellation_recovers_original_receipt_repairs_only_pin_and_revokes_handoffs() -> TestResult
{
    let fixture = Fixture::new("recovery")?;
    let session = fixture.open("3000")?;
    let handoff = fixture.ok(&["handoff"], &["--session", &session])?;
    let handoff_id = text(&handoff, &["payload", "handoffId"])?;
    let preview = fixture.cancel(&session, None)?;
    let approval = pointer(&preview, "session-cancellation-approval:")?;
    let pin_path = fixture.root.join("agent/sessions/ROOT");
    let old_pin = fs::read(&pin_path)?;
    let authority_before = tree(&fixture.root, false)?;
    let committed = fixture.cancel(&session, Some(approval))?;
    let receipt = pointer(&committed, "session-cancellation-receipt:")?.to_owned();
    assert_eq!(tree(&fixture.root, false)?, authority_before);
    let journal = fixture.journal()?;
    let inspected = inspect_session_bytes(
        &journal,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert!(
        inspected
            .sessions
            .iter()
            .find(|entry| entry.session.session_id.as_str() == session)
            .ok_or("session")?
            .closed
    );
    // Simulate a crash after the cancellation append, before replacing ROOT.
    fs::write(&pin_path, &old_pin)?;
    let retry = fixture.cancel(&session, Some(approval))?;
    assert_eq!(pointer(&retry, "session-cancellation-receipt:")?, receipt);
    assert_eq!(fixture.journal()?, journal);
    assert_ne!(fs::read(&pin_path)?, old_pin);
    let settled = tree(&fixture.root, true)?;
    fixture.cancel(&session, Some(approval))?;
    assert_eq!(
        tree(&fixture.root, true)?,
        settled,
        "an exact retry must not rewrite the pin"
    );
    for (command, options) in [
        (vec!["handoff"], vec!["--session", session.as_str()]),
        (vec!["session", "resume"], vec!["--handoff", handoff_id]),
        (vec!["orient"], vec!["--session", session.as_str()]),
        (
            vec!["session", "open"],
            vec![
                "--mission-text",
                MISSION,
                "--objective",
                OBJECTIVE,
                "--budget-tokens",
                "3000",
            ],
        ),
    ] {
        let (code, _, refused) = fixture.cli_as(OWNER, &command, &options)?;
        assert_eq!(code, 5, "{refused:?}");
    }
    let replacement = fixture.open("4000")?;
    assert_ne!(replacement, session);
    let later = tree(&fixture.root, true)?;
    let retry = fixture.cancel(&session, Some(approval))?;
    assert_eq!(pointer(&retry, "session-cancellation-receipt:")?, receipt);
    assert_eq!(
        tree(&fixture.root, true)?,
        later,
        "later unrelated records cannot replace original approval"
    );
    let denied = authority(OWNER, Vec::new(), SITE)?;
    assert!(matches!(
        cancel_session(
            &fixture.root,
            &SessionId::parse(&session)?,
            &denied,
            Some(ContentDigest::parse(approval)?)
        ),
        Err(SessionCancellationError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn mcp_and_cli_share_exact_approval_and_preserve_unresolved_external_obligations() -> TestResult {
    let fixture = Fixture::new("mcp-obligation")?;
    fixture.prepare_obligation()?;
    let session = fixture.open("3000")?;
    let before = tree(&fixture.root, true)?;
    let cli = fixture.cancel(&session, None)?;
    let mcp = fixture.mcp(OWNER, &format!(r#"{{"session":"{session}"}}"#))?;
    assert_eq!(mcp, cli, "MCP must render the same native preview");
    assert_eq!(tree(&fixture.root, true)?, before);
    let approval = pointer(&cli, "session-cancellation-approval:")?;
    let obligations = field(&cli, &["payload", "continuity", "unresolvedObligations"])?
        .array()
        .ok_or("obligations")?;
    assert!(
        obligations
            .iter()
            .any(|value| value.text() == Some("obligation:session-cancel:synthetic"))
    );
    let authority_before = tree(&fixture.root, false)?;
    let committed = fixture.mcp(
        OWNER,
        &format!(r#"{{"session":"{session}","approve":"{approval}"}}"#),
    )?;
    assert_eq!(text(&committed, &["outcome"])?, "ok");
    assert_eq!(
        field(
            &committed,
            &["payload", "continuity", "unresolvedObligations"]
        )?,
        field(&cli, &["payload", "continuity", "unresolvedObligations"])?
    );
    let receipt = pointer(&committed, "session-cancellation-receipt:")?;
    let retry = fixture.cancel(&session, Some(approval))?;
    assert_eq!(pointer(&retry, "session-cancellation-receipt:")?, receipt);
    assert_eq!(tree(&fixture.root, false)?, authority_before);
    let rejected = fixture.mcp(
        "principal:other",
        &format!(r#"{{"session":"{session}","approve":"{approval}"}}"#),
    )?;
    assert_eq!(
        text(&rejected, &["errorId"])?,
        "ERR-AGENT-SESSION-NOT-FOUND-001"
    );
    Ok(())
}

#[test]
fn live_claim_is_reclaimed_with_new_fence_after_revocation_and_progress_is_preserved() -> TestResult
{
    let fixture = Fixture::new("reclaim")?;
    let first = fixture.open("3000")?;
    let second = fixture.open("4000")?;
    let case = fixture.directory.join("case.json");
    fs::write(
        &case,
        r#"{"caseId":"case:cancel-reclaim","question":"Did a person enter?","decisionInformed":"Whether to prepare an owner alert","hypotheses":[{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]},{"hypothesisId":"h:passerby","description":"A person passed","predictions":["the track leaves the frame"]}],"knowns":[],"unknowns":[{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}],"discriminators":[{"discriminatorId":"d:hallway","description":"Hallway frames","separates":["h:entry","h:passerby"],"expectedOutcomes":["person","empty"]}],"probes":["probe:hallway-frames"],"stopRules":["independent observation"],"decisionWindowNs":3600000000000}"#,
    )?;
    fixture.claim(
        &first,
        "open",
        &["--case-file", case.to_str().ok_or("case path")?],
    )?;
    let claimed = fixture.claim(
        &first,
        "claim",
        &[
            "--case",
            "case:cancel-reclaim",
            "--work",
            "probe:probe:hallway-frames",
            "--lease-ms",
            "60000",
        ],
    )?;
    let propositions = field(&claimed, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("claim propositions")?;
    let claim = text(&propositions[0], &["id"])?;
    let revision = text(&claimed, &["decisionFingerprint"])?;
    let active = fixture.claim(
        &first,
        "claim-activate",
        &["--claim", claim, "--expected", revision],
    )?;
    let artifact = ContentDigest::sha256(b"retained partial probe result").to_text();
    let progress = fixture.claim(
        &first,
        "claim-progress",
        &[
            "--claim",
            claim,
            "--expected",
            text(&active, &["decisionFingerprint"])?,
            "--artifact",
            &artifact,
        ],
    )?;
    let revision = text(&progress, &["decisionFingerprint"])?;
    let before = inspect_session_bytes(
        &fixture.journal()?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let original = before
        .claims
        .iter()
        .find(|entry| entry.claim().claim_id == claim)
        .ok_or("claim")?;
    assert!(
        original.lease_covers(TimestampNs(0)),
        "lease has not expired"
    );
    let preview = fixture.cancel(&first, None)?;
    fixture.cancel(
        &first,
        Some(pointer(&preview, "session-cancellation-approval:")?),
    )?;
    let unchanged = inspect_session_bytes(
        &fixture.journal()?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(
        unchanged.claims, before.claims,
        "revocation does not erase or rewrite work"
    );
    let (code, _, rejected) = fixture.cli_as(
        OWNER,
        &["investigate"],
        &[
            "--session",
            &first,
            "--transition",
            "claim-renew",
            "--claim",
            claim,
            "--expected",
            revision,
            "--lease-ms",
            "60000",
        ],
    )?;
    assert_eq!(code, 5, "{rejected:?}");
    let reclaimed = fixture.claim(
        &second,
        "claim-reclaim",
        &[
            "--claim",
            claim,
            "--expected",
            revision,
            "--lease-ms",
            "60000",
        ],
    )?;
    assert_ne!(text(&reclaimed, &["decisionFingerprint"])?, revision);
    let after = inspect_session_bytes(
        &fixture.journal()?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let replacement = after
        .claims
        .iter()
        .find(|entry| entry.claim().claim_id == claim)
        .ok_or("claim")?;
    assert_eq!(replacement.claim().owner_session_id, second);
    assert_eq!(
        replacement.claim().lease_incarnation,
        original.claim().lease_incarnation + 1
    );
    assert_eq!(
        replacement.claim().progress_json,
        original.claim().progress_json
    );
    assert!(replacement.claim().progress_json.contains(&artifact));
    Ok(())
}

#[test]
fn mixed_session_operation_scope_is_rejected_before_any_deployment_access() {
    assert!(
        fss_cli::parse_fss_args(
            [
                "cancel",
                "--json",
                "--root",
                "/missing",
                "--session",
                "session:one",
                "--operation",
                "operation:one"
            ]
            .map(OsString::from)
        )
        .is_err()
    );
}

#[test]
fn an_expiry_tombstone_is_never_adopted_as_an_approved_cancellation() -> TestResult {
    let fixture = Fixture::new("expiry")?;
    let session = fixture.open("3000")?;
    let preview = fixture.cancel(&session, None)?;
    let approval = pointer(&preview, "session-cancellation-approval:")?;
    let directory = fixture.root.join("agent/sessions");
    let pin = ContentDigest::parse(fs::read_to_string(directory.join("ROOT"))?.trim())?;
    let inspected = inspect_session_bytes(
        &fixture.journal()?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let retained = inspected
        .sessions
        .iter()
        .find(|entry| entry.session.session_id.as_str() == session)
        .ok_or("session")?;
    {
        let _lock = SpoolLock::try_acquire(
            fs::File::open(directory.join("LOCK"))?,
            Arc::new(HostSpoolIo),
        )
        .map_err(|_| "expiry fixture lock")?;
        let mut store = DurableSessionStore::open_existing_with_coordination(
            directory.join("journal.fssj"),
            pin,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        assert!(
            store
                .session(
                    &retained.session.principal_id,
                    &retained.session.session_id,
                    TimestampNs(retained.session.expires_at_ns)
                )
                .is_err()
        );
        fs::write(
            directory.join("ROOT"),
            format!("{}\n", store.committed_root()),
        )?;
    }
    let before = tree(&fixture.root, true)?;
    for options in [
        vec!["--session", session.as_str()],
        vec!["--session", session.as_str(), "--approve", approval],
    ] {
        let (code, _, response) = fixture.cli_as(OWNER, &["cancel"], &options)?;
        assert_eq!(code, 5);
        assert_eq!(
            text(&response, &["errorId"])?,
            "ERR-AGENT-SESSION-NOT-FOUND-001"
        );
        assert_eq!(field(&response, &["payload"])?, &Value::Null);
    }
    assert_eq!(tree(&fixture.root, true)?, before);
    Ok(())
}
