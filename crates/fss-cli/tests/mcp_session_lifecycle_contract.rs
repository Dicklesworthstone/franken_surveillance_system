#![forbid(unsafe_code)]
//! Native session lifecycle through fresh MCP processes, including durable follow delivery.
//! Every opening, handoff and resume goes through MCP. Only the explicitly synthetic authority
//! fixtures use native deployment APIs; no device, provider, remote service or affordance runs.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::json_input::{self, Value};
use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    ContractError, EffectIntent, EvidenceDelta, IdempotencyKey, ObjectId, ObligationId,
    OperationId, Plane, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::{HandoffRecord, MissionRecord};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-session-lifecycle";
const PRINCIPAL: &str = "principal:mcp-session-lifecycle";
const STRANGER: &str = "principal:mcp-session-stranger";
const MISSION: &str = "Observe retained changes across an operator handoff";
const OBJECTIVE: &str = "Keep uncertain evidence and explicit acknowledgements intact";
const SUBSCRIPTION: &str = "mission-watch";
const ACK_PREFIX: &str = "continuation:follow-ack:";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-session-lifecycle-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn quote(value: &str) -> String {
    format!("\"{}\"", fss_cli::escape_json_str(value))
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing object field {name}").into())
}

fn text<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("{name} is not text").into())
}

fn array<'a>(value: &'a Value, name: &str) -> TestResult<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("{name} is not an array").into())
}

fn integer(value: &Value, name: &str) -> TestResult<i128> {
    field(value, name)?
        .integer()
        .ok_or_else(|| format!("{name} is not an exact integer").into())
}

fn pointer<'a>(value: &'a Value, prefix: &str) -> TestResult<&'a str> {
    let mut found = array(value, "proofPointers")?
        .iter()
        .filter_map(Value::text)
        .filter_map(|value| value.strip_prefix(prefix));
    let value = found.next().ok_or("missing proof pointer")?;
    assert!(found.next().is_none(), "ambiguous proof pointer {prefix}");
    Ok(value)
}

fn raw_payload(body: &str) -> TestResult<&str> {
    let start = body.find(",\"payload\":").ok_or("missing payload")? + ",\"payload\":".len();
    let end = body
        .find(",\"payloadDigest\":")
        .ok_or("missing payload digest")?;
    Ok(&body[start..end])
}

fn conforms(scratch: &Path, schema: &str, instance: &str) -> TestResult {
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(instance.as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, instance)?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg("-B")
        .arg(root.join("scripts/json_instance_validate.py"))
        .arg(root.join("schemas").join(schema))
        .arg(&file)
        .output()?;
    fs::remove_file(&file)?;
    assert!(
        output.status.success(),
        "{schema}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

struct Reply {
    body: String,
    value: Value,
}

impl Reply {
    fn parse(body: String, scratch: &Path, operation: &str) -> TestResult<Self> {
        let (schema, capability) = match operation {
            "AOP-001" => ("situation_capsule.v1", "CAP-AGENT-SESSION-OPEN-001"),
            "AOP-002" => ("situation_capsule.v1", "CAP-AGENT-SESSION-READ-001"),
            "AOP-004" => ("agent_meaningful_delta.v1", "CAP-AGENT-SITUATION-READ-001"),
            "AOP-012" => ("agent_handoff_capsule.v1", "CAP-AGENT-HANDOFF-WRITE-001"),
            _ => return Err("unexpected lifecycle operation".into()),
        };
        assert_eq!(body.lines().count(), 1, "one complete semantic JSON document");
        assert!(body.trim_end().ends_with('}'));
        let value = json_input::parse(&body)?;
        assert_eq!(text(&value, "schema")?, "fss.agent_response_envelope.v1");
        assert_eq!(text(&value, "operationId")?, operation);
        assert_eq!(text(&value, "payloadSchema")?, format!("fss.{schema}"));
        assert_eq!(field(&value, "outputAnchor")?, &Value::Null);
        assert_eq!(
            array(&value, "effectiveCapabilities")?,
            [Value::Text(capability.to_owned())]
        );
        assert_eq!(
            text(&value, "payloadDigest")?,
            ContentDigest::sha256(raw_payload(&body)?.as_bytes()).to_text(),
            "MCP preserves the digest of the exact canonical payload bytes"
        );
        conforms(scratch, "agent_response_envelope.v1.json", &body)?;
        if raw_payload(&body)? != "null" {
            conforms(scratch, &format!("{schema}.json"), raw_payload(&body)?)?;
        }
        Ok(Self { body, value })
    }

    fn payload(&self) -> TestResult<&Value> {
        field(&self.value, "payload")
    }

    fn success(&self, session: &str, mission: &str) -> TestResult {
        assert_eq!(text(&self.value, "outcome")?, "ok");
        assert_eq!(field(&self.value, "errorId")?, &Value::Null);
        assert_eq!(text(&self.value, "principalId")?, PRINCIPAL);
        assert_eq!(text(&self.value, "sessionId")?, session);
        assert_eq!(text(&self.value, "missionId")?, mission);
        let session_field = if text(&self.value, "operationId")? == "AOP-012" {
            "sourceSessionId"
        } else {
            "sessionId"
        };
        assert_eq!(text(self.payload()?, session_field)?, session);
        Ok(())
    }

    fn refused(&self, error: &str) -> TestResult {
        assert_eq!(text(&self.value, "outcome")?, "refused");
        assert_eq!(text(&self.value, "errorId")?, error);
        assert_eq!(self.payload()?, &Value::Null);
        assert_eq!(field(&self.value, "sessionId")?, &Value::Null);
        assert_eq!(field(&self.value, "missionId")?, &Value::Null);
        Ok(())
    }

    fn opening_anchor(&self) -> TestResult<String> {
        let token = format!("anchor:{}", pointer(&self.value, "anchor:")?);
        assert!(AnchorToken::parse(&token).is_some());
        Ok(token)
    }

    fn receipt(&self) -> TestResult<ContentDigest> {
        let raw = text(&self.value, "continuation")?
            .strip_prefix(ACK_PREFIX)
            .ok_or("not an explicit follow acknowledgement")?;
        assert_eq!(pointer(&self.value, "follow-delivery:")?, raw);
        assert_eq!(
            field(self.payload()?, "continuation")?,
            field(&self.value, "continuation")?
        );
        Ok(ContentDigest::parse(raw)?)
    }

    fn sequence(&self, anchor: &str) -> TestResult<i128> {
        integer(field(self.payload()?, anchor)?, "capsuleSequence")
    }
}

struct Directory(PathBuf);

impl Directory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-mcp-session-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("no unused MCP lifecycle fixture directory".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    commits: u64,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let directory = Directory::new(tag)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:mcp-session:{tag}"),
            operation_id: OperationId::parse(format!("operation:mcp-session:{tag}"))?,
            principal: "operator:mcp-session-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit MCP session lifecycle fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            directory.0.join("cx"),
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            directory,
            root,
            cx,
            commits: 0,
        })
    }

    fn append(&mut self) -> TestResult {
        self.commits += 1;
        let index = self.commits;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(format!("synthetic metadata {index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:mcp-session:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:mcp-session:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:mcp-session:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(10_000))?,
                plane: Plane::Cognition,
                payload_digest: payload,
                witness_digest: None,
                operation_id: None,
            }],
            vec![payload],
            &self.cx,
        )?;
        Ok(())
    }

    fn prepare(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: OperationId::parse("operation:mcp-session:synthetic")?,
                idempotency_key: IdempotencyKey::parse("idempotency:mcp-session:synthetic")?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"synthetic observation request"),
                precondition_digest: ContentDigest::sha256(b"synthetic precondition"),
            },
            ObligationId::parse("obligation:mcp-session:synthetic")?,
            "synthetic observation verified",
            TimestampNs(100),
        )?;
        Ok(())
    }

    fn exchange(&self, principal: &str, tool: &str, arguments: &str) -> TestResult<Value> {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
            quote(tool)
        );
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
        writeln!(input, "{INIT}\n{READY}\n{request}")?;
        drop(input);
        let output = child.wait_with_output()?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "initialize and one tool response only");
        let initialized = json_input::parse(lines[0])?;
        assert_eq!(text(&initialized, "jsonrpc")?, "2.0");
        assert_eq!(integer(&initialized, "id")?, 1);
        assert_eq!(
            text(field(&initialized, "result")?, "protocolVersion")?,
            "2025-06-18"
        );
        let wire = json_input::parse(lines[1])?;
        assert_eq!(text(&wire, "jsonrpc")?, "2.0");
        assert_eq!(integer(&wire, "id")?, 2);
        Ok(wire)
    }

    fn call(
        &self,
        principal: &str,
        tool: &str,
        arguments: &str,
        operation: &str,
        failed: bool,
    ) -> TestResult<Reply> {
        let wire = self.exchange(principal, tool, arguments)?;
        let result = field(&wire, "result")?;
        assert_eq!(field(result, "isError")?, &Value::Bool(failed));
        let content = array(result, "content")?;
        assert_eq!(content.len(), 1);
        assert_eq!(text(&content[0], "type")?, "text");
        Reply::parse(
            text(&content[0], "text")?.to_owned(),
            &self.directory.0,
            operation,
        )
    }

    fn open(&self, mission: &str, budget: Option<u64>) -> TestResult<Reply> {
        let budget = budget.map_or_else(String::new, |tokens| {
            format!(",\"budget_tokens\":{tokens}")
        });
        self.call(
            PRINCIPAL,
            "session_open",
            &format!(
                "{{\"mission\":{},\"objective\":{}{budget}}}",
                quote(mission),
                quote(OBJECTIVE)
            ),
            "AOP-001",
            false,
        )
    }

    fn journal(&self) -> TestResult<Vec<u8>> {
        Ok(fs::read(self.root.join("agent/sessions/journal.fssj"))?)
    }

    fn inspect(&self) -> TestResult<SessionRecoveryState> {
        Ok(inspect_session_bytes(
            &self.journal()?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?)
    }

    fn published<T: PartialEq + Debug>(
        &self,
        reply: &Reply,
        decode: impl Fn(&[u8]) -> Result<T, ContractError>,
    ) -> TestResult<T> {
        let mut found = None;
        for pointer in array(&reply.value, "proofPointers")?.iter().filter_map(Value::text) {
            let Ok(digest) = ContentDigest::parse(pointer) else {
                continue;
            };
            let Ok(bytes) = fss_publication::read_verified(
                self.root.join("agent/publications"),
                digest,
                1 << 20,
            ) else {
                continue;
            };
            if let Ok(record) = decode(&bytes) {
                if let Some(prior) = &found {
                    assert_eq!(prior, &record, "proofs cannot name contradictory records");
                } else {
                    found = Some(record);
                }
            }
        }
        found.ok_or_else(|| "the response has no verified native record".into())
    }
}

fn follow_args(since: &str, session: &str, acknowledge: Option<ContentDigest>) -> String {
    let acknowledge = acknowledge.map_or_else(String::new, |receipt| {
        format!(",\"acknowledge\":{}", quote(&receipt.to_text()))
    });
    format!(
        "{{\"since\":{},\"session\":{},\"subscription\":{},\"view\":\"brief\",\"max_entries\":64{acknowledge}}}",
        quote(since),
        quote(session),
        quote(SUBSCRIPTION)
    )
}

fn authority_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut pending = ["ledger", "effects", "objects", "LAYOUT"]
        .map(|prefix| root.join(prefix))
        .to_vec();
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else {
            result.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(path)?),
            );
        }
    }
    Ok(result)
}

#[test]
fn mcp_open_follow_ack_handoff_and_cold_resume_preserve_durable_identity() -> TestResult {
    let mut fixture = Fixture::new("lifecycle")?;
    let opened = fixture.open(MISSION, Some(100_000))?;
    let session = text(&opened.value, "sessionId")?.to_owned();
    let mission = text(&opened.value, "missionId")?.to_owned();
    opened.success(&session, &mission)?;
    assert_eq!(integer(&opened.value, "workspaceRevision")?, 0);
    assert_eq!(text(&opened.value, "effectiveViewId")?, "AVIEW-002");
    assert_eq!(field(opened.payload()?, "meaningfulDelta")?, &Value::Null);
    let since = opened.opening_anchor()?;
    let original_session = fixture.inspect()?.sessions[0].session.clone();
    let journal = fixture.journal()?;
    let duplicate = fixture.open(MISSION, Some(100_000))?;
    assert_eq!(duplicate.body, opened.body, "same full head is an exact retry");
    assert_eq!(fixture.journal()?, journal);

    for _ in 0..3 {
        fixture.append()?;
    }
    let authority = authority_tree(&fixture.root)?;
    let arguments = follow_args(&since, &session, None);
    let first = fixture.call(PRINCIPAL, "session_follow", &arguments, "AOP-004", false)?;
    first.success(&session, &mission)?;
    assert_eq!(first.sequence("basisAnchor")?, 0);
    assert_eq!(first.sequence("resultAnchor")?, 1);
    let receipt = first.receipt()?;
    let frozen = pointer(&first.value, "follow-horizon:")?.to_owned();
    assert_eq!(
        AnchorToken::parse(&frozen)
            .ok_or("frozen horizon")?
            .position()
            .commit_sequence,
        3
    );
    let pending_journal = fixture.journal()?;
    let repeat = fixture.call(PRINCIPAL, "session_follow", &arguments, "AOP-004", false)?;
    assert_eq!(repeat.receipt()?, receipt);
    assert_eq!(repeat.payload()?, first.payload()?);
    assert_eq!(fixture.journal()?, pending_journal, "disconnect never ACKs");

    let arguments = follow_args(&since, &session, Some(receipt));
    let second = fixture.call(PRINCIPAL, "session_follow", &arguments, "AOP-004", false)?;
    second.success(&session, &mission)?;
    assert_eq!(second.sequence("basisAnchor")?, 1);
    assert_eq!(second.sequence("resultAnchor")?, 2);
    assert_eq!(pointer(&second.value, "follow-horizon:")?, frozen);
    assert_eq!(
        pointer(&second.value, "follow-acknowledged:")?,
        receipt.to_text()
    );
    let acknowledged_journal = fixture.journal()?;
    let lost_ack = fixture.call(PRINCIPAL, "session_follow", &arguments, "AOP-004", false)?;
    assert_eq!(lost_ack.receipt()?, second.receipt()?);
    assert_eq!(lost_ack.payload()?, second.payload()?);
    assert_eq!(fixture.journal()?, acknowledged_journal);
    let retained_follow = fixture.inspect()?.follows;

    let note = "Next operator: preserve the unacknowledged successor";
    let handed = fixture.call(
        PRINCIPAL,
        "handoff",
        &format!("{{\"session\":{},\"note\":{}}}", quote(&session), quote(note)),
        "AOP-012",
        false,
    )?;
    handed.success(&session, &mission)?;
    assert_eq!(text(&handed.value, "effectiveViewId")?, "AVIEW-006");
    assert_eq!(text(handed.payload()?, "objective")?, OBJECTIVE);
    assert_eq!(handed.sequence("anchor")?, 0, "handoff keeps its session basis");
    let handoff_id = text(handed.payload()?, "handoffId")?.to_owned();
    let record = fixture.published(&handed, HandoffRecord::from_bytes)?;
    assert_eq!(record.note.as_deref(), Some(note));
    assert_eq!(record.capsule.source_session_id.as_str(), session);
    assert_eq!(fixture.inspect()?.follows, retained_follow);

    // A completely new MCP process resumes the published native handoff, not conversational
    // state. The head moved, so native session/workspace rebase and invalidations must survive.
    let resume_args = format!("{{\"handoff\":{}}}", quote(&handoff_id));
    let resumed = fixture.call(PRINCIPAL, "session_resume", &resume_args, "AOP-002", false)?;
    resumed.success(&session, &mission)?;
    assert_eq!(resumed.sequence("previousAnchor")?, 0);
    assert_eq!(resumed.sequence("anchor")?, 3);
    assert_eq!(integer(&resumed.value, "workspaceRevision")?, 1);
    assert!(
        array(field(&resumed.value, "executionBoundary")?, "invalidated")?
            .iter()
            .filter_map(Value::text)
            .any(|line| line.starts_with("assumption assumption:anchor-current invalidated"))
    );
    assert_ne!(field(resumed.payload()?, "meaningfulDelta")?, &Value::Null);
    let recovered = fixture.inspect()?;
    assert_eq!(recovered.sessions.len(), 1);
    assert_eq!(recovered.sessions[0].session.session_id, original_session.session_id);
    assert_eq!(recovered.sessions[0].session.token_budget, original_session.token_budget);
    assert_eq!(recovered.sessions[0].session.expires_at_ns, original_session.expires_at_ns);
    assert_eq!(recovered.sessions[0].session.current_anchor.commit_sequence, 3);
    assert_eq!(recovered.follows, retained_follow);
    let resumed_journal = fixture.journal()?;
    let repeated = fixture.call(PRINCIPAL, "session_resume", &resume_args, "AOP-002", false)?;
    assert_eq!(repeated.body, resumed.body, "resume never rebases twice");
    assert_eq!(fixture.journal()?, resumed_journal);

    // Handoff/rebase is not an implicit transfer of an old subscription's semantic history.
    let refused = fixture.call(
        PRINCIPAL,
        "session_follow",
        &follow_args(&since, &session, None),
        "AOP-004",
        true,
    )?;
    assert_eq!(text(&refused.value, "outcome")?, "partial");
    assert_eq!(text(&refused.value, "errorId")?, "ERR-AGENT-RESNAPSHOT-001");
    assert_eq!(field(&refused.value, "resnapshotRequired")?, &Value::Bool(true));
    assert_eq!(refused.payload()?, &Value::Null);
    assert_eq!(fixture.inspect()?.follows, retained_follow);
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}

#[test]
fn mcp_cannot_handoff_follow_or_resume_another_principals_session() -> TestResult {
    let fixture = Fixture::new("principal")?;
    let opened = fixture.open(MISSION, Some(100_000))?;
    let session = text(&opened.value, "sessionId")?.to_owned();
    let since = opened.opening_anchor()?;
    let handed = fixture.call(
        PRINCIPAL,
        "handoff",
        &format!("{{\"session\":{}}}", quote(&session)),
        "AOP-012",
        false,
    )?;
    let handoff_id = text(handed.payload()?, "handoffId")?;
    let before = fixture.journal()?;
    let authority = authority_tree(&fixture.root)?;
    for (tool, arguments, operation, expected) in [
        (
            "session_follow",
            follow_args(&since, &session, None),
            "AOP-004",
            "ERR-AGENT-SESSION-NOT-FOUND-001",
        ),
        (
            "handoff",
            format!("{{\"session\":{}}}", quote(&session)),
            "AOP-012",
            "ERR-AGENT-SESSION-NOT-FOUND-001",
        ),
        (
            "session_resume",
            format!("{{\"handoff\":{}}}", quote(handoff_id)),
            "AOP-002",
            "ERR-AGENT-HANDOFF-INVALID-001",
        ),
    ] {
        let reply = fixture.call(STRANGER, tool, &arguments, operation, true)?;
        reply.refused(expected)?;
        assert_eq!(text(&reply.value, "principalId")?, STRANGER);
        assert_eq!(fixture.journal()?, before);
        assert_eq!(authority_tree(&fixture.root)?, authority);
    }
    Ok(())
}

#[test]
fn mcp_mission_is_literal_even_when_it_names_an_existing_outside_file() -> TestResult {
    let fixture = Fixture::new("literal")?;
    let outside = fixture.directory.0.join("outside operator mission.txt");
    assert!(!outside.starts_with(&fixture.root));
    // Legacy --mission would reject this oversized, non-UTF8 file. The MCP string itself is
    // short valid UTF-8 and must remain the literal statement, without loading the named file.
    let bytes = vec![0xff; 8193];
    fs::write(&outside, &bytes)?;
    let literal = outside.to_str().ok_or("fixture mission path UTF-8")?;
    let authority = authority_tree(&fixture.root)?;
    let opened = fixture.open(literal, None)?;
    let session = text(&opened.value, "sessionId")?.to_owned();
    let mission = text(&opened.value, "missionId")?.to_owned();
    opened.success(&session, &mission)?;
    let record = fixture.published(&opened, MissionRecord::from_bytes)?;
    assert_eq!(record.mission, literal);
    assert_eq!(record.objective, OBJECTIVE);
    assert_eq!(record.session_id.as_str(), session);
    assert_eq!(record.principal.as_str(), PRINCIPAL);
    assert_eq!(record.view, AgentView::Brief);
    assert_eq!(record.token_budget, u64::from(AgentView::Brief.maximum_tokens()));
    assert_eq!(record.opening_anchor_token, opened.opening_anchor()?);
    assert_eq!(fs::read(&outside)?, bytes);
    let journal = fixture.journal()?;
    let repeated = fixture.open(literal, None)?;
    assert_eq!(repeated.body, opened.body);
    assert_eq!(fixture.journal()?, journal);

    // A remote caller cannot replace either launch-pinned scope with a tool argument.
    for extra in [
        format!("\"root\":{}", quote(literal)),
        format!("\"principal\":{}", quote(STRANGER)),
    ] {
        let wire = fixture.exchange(
            PRINCIPAL,
            "session_open",
            &format!(
                "{{\"mission\":{},\"objective\":{},{extra}}}",
                quote(literal),
                quote(OBJECTIVE)
            ),
        )?;
        assert_eq!(integer(field(&wire, "error")?, "code")?, -32602);
        assert_eq!(fixture.journal()?, journal);
    }
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}

#[test]
fn mcp_open_identity_binds_effect_history_and_exact_retries() -> TestResult {
    let fixture = Fixture::new("effect-head")?;
    let first = fixture.open(MISSION, Some(100_000))?;
    let initial = AnchorToken::parse(&first.opening_anchor()?).ok_or("initial anchor")?;
    let initial_journal = fixture.journal()?;
    assert_eq!(fixture.open(MISSION, Some(100_000))?.body, first.body);
    assert_eq!(fixture.journal()?, initial_journal);

    fixture.prepare()?;
    let authority = authority_tree(&fixture.root)?;
    let next = fixture.open(MISSION, Some(100_000))?;
    let current = AnchorToken::parse(&next.opening_anchor()?).ok_or("current anchor")?;
    assert_eq!(initial.position().commit_sequence, current.position().commit_sequence);
    assert_ne!(initial.position().effect_records, current.position().effect_records);
    assert_ne!(initial, current);
    assert_ne!(text(&first.value, "sessionId")?, text(&next.value, "sessionId")?);
    assert_eq!(text(&first.value, "missionId")?, text(&next.value, "missionId")?);
    assert_eq!(fixture.inspect()?.sessions.len(), 2);
    let current_journal = fixture.journal()?;
    assert_eq!(fixture.open(MISSION, Some(100_000))?.body, next.body);
    assert_eq!(fixture.journal()?, current_journal);
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}
