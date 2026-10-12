#![forbid(unsafe_code)]
//! Fresh-process AOP-013 MCP feedback over native retained evidence and mission cases.
//! Every proposal crosses the real MCP binary. Native CLI parity and verified publication
//! closure distinguish advisory provenance from evidence, policy or effect authority.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_core::{
    AgentFeedbackProposal, BatchId, BudgetVector, CanonicalEncode, CaptureInterval, ContentDigest,
    ContextAuthority, EvidenceDelta, FeedbackPrivacyClass, FeedbackProposalKind, ObjectId,
    OperationId, Plane, RequestedDisposition, RootAuthoritySpec, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::feedback::{FeedbackTarget, render_json, target_json};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-feedback";
const PRINCIPAL: &str = "principal:mcp-feedback";
const STRANGER: &str = "principal:mcp-feedback-stranger";
const CASE: &str = "case:east-door";
const MISSION: &str = "Keep the east door under watch.";
const OBJECTIVE: &str = "Preserve evidence-linked corrections without activating policy.";
const EVIDENCE: [&[u8]; 3] = [
    b"synthetic door observation",
    b"synthetic hallway counterexample",
    b"synthetic street observation",
];
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-feedback-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn quote(value: &str) -> String {
    format!("\"{}\"", fss_cli::escape_json_str(value))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing field {key}"))?;
    }
    Ok(current)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("{path:?} is not text").into())
}

fn array<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or_else(|| format!("{path:?} is not an array").into())
}

fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    array(value, path)?
        .iter()
        .map(|item| {
            item.text()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "not a string".into())
        })
        .collect()
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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

fn tree(root: &Path, prefixes: &[&str]) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut pending = prefixes
        .iter()
        .map(|prefix| root.join(prefix))
        .collect::<Vec<_>>();
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

struct Directory(PathBuf);

impl Directory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-mcp-feedback-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("no unused feedback fixture directory".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Reply {
    body: String,
    value: Value,
}

#[derive(Clone)]
struct ProposalInput {
    target: FeedbackTarget,
    kind: FeedbackProposalKind,
    statement: String,
    supporting: Vec<ContentDigest>,
    contradicting: Vec<ContentDigest>,
    disposition: RequestedDisposition,
}

impl ProposalInput {
    fn new() -> Self {
        let digests = EVIDENCE.map(ContentDigest::sha256);
        Self {
            target: FeedbackTarget::Case(CASE.to_owned()),
            kind: FeedbackProposalKind::PolicyCandidate,
            statement: "@/outside/proposal.json --principal=principal:other\nPreserve the \"counterexample\" before changing a policy.".to_owned(),
            supporting: vec![digests[1], digests[0]],
            contradicting: vec![digests[2], digests[1]],
            disposition: RequestedDisposition::CreateLearningProposal,
        }
    }

    fn target(&self) -> String {
        format!("{}:{}", self.target.kind(), self.target.id())
    }

    fn arguments(&self, session: &str) -> String {
        let list = |values: &[ContentDigest]| {
            values
                .iter()
                .map(|value| quote(&value.to_text()))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            r#"{{"session":{},"target":{},"kind":{},"statement":{},"supporting":[{}],"contradicting":[{}],"disposition":{}}}"#,
            quote(session),
            quote(&self.target()),
            quote(self.kind.as_str()),
            quote(&self.statement),
            list(&self.supporting),
            list(&self.contradicting),
            quote(self.disposition.as_str())
        )
    }

    fn canonical_handles(values: &[ContentDigest]) -> Vec<String> {
        let mut result = values
            .iter()
            .map(|value| value.to_text())
            .collect::<Vec<_>>();
        result.sort();
        result.dedup();
        result
    }
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let directory = Directory::new(tag)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:mcp-feedback:{tag}"),
            operation_id: OperationId::parse(format!("operation:mcp-feedback:{tag}"))?,
            principal: "operator:mcp-feedback-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit MCP feedback fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            directory.0.join("cx"),
        )?);
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut deltas = Vec::new();
        let mut payloads = Vec::new();
        for (index, bytes) in EVIDENCE.into_iter().enumerate() {
            let payload = deployment.stage_payload(bytes)?;
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:mcp-feedback:observation:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:mcp-feedback:observation:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
                plane: Plane::Cognition,
                payload_digest: payload,
                witness_digest: None,
                operation_id: None,
            });
            payloads.push(payload);
        }
        deployment.append_batch(
            BatchId::parse("batch:mcp-feedback:observations")?,
            deltas,
            payloads,
            &cx,
        )?;
        drop(deployment);
        Ok(Self {
            directory,
            root,
            cx,
        })
    }

    fn authority(&self) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
        tree(&self.root, &["ledger", "effects", "objects", "LAYOUT"])
    }

    fn frames(&self, principal: &str, requests: &[String]) -> TestResult<Vec<Value>> {
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
        writeln!(input, "{INIT}\n{READY}")?;
        for request in requests {
            assert!(request.len() < 64 * 1024);
            writeln!(input, "{request}")?;
        }
        drop(input);
        let output = child.wait_with_output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let replies = String::from_utf8(output.stdout)?
            .lines()
            .map(|line| parse(line).map_err(Into::into))
            .collect::<TestResult<Vec<Value>>>()?;
        let initialized = replies.first().ok_or("missing initialization")?;
        assert_eq!(
            text(initialized, &["result", "protocolVersion"])?,
            "2025-06-18"
        );
        Ok(replies)
    }

    fn exchange(&self, principal: &str, tool: &str, arguments: &str) -> TestResult<Value> {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
            quote(tool)
        );
        let mut replies = self.frames(principal, &[request])?;
        assert_eq!(
            replies.len(),
            2,
            "initialize and one complete tool response"
        );
        let reply = replies.pop().ok_or("missing tool reply")?;
        assert_eq!(text(&reply, &["jsonrpc"])?, "2.0");
        assert_eq!(field(&reply, &["id"])?.integer(), Some(2));
        Ok(reply)
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
        assert_eq!(field(&wire, &["result", "isError"])?, &Value::Bool(failed));
        let content = array(&wire, &["result", "content"])?;
        assert_eq!(content.len(), 1);
        assert_eq!(text(&content[0], &["type"])?, "text");
        let body = text(&content[0], &["text"])?.to_owned();
        assert_eq!(body.lines().count(), 1);
        let value = parse(&body)?;
        assert_eq!(text(&value, &["schema"])?, "fss.agent_response_envelope.v1");
        assert_eq!(text(&value, &["operationId"])?, operation);
        assert_eq!(field(&value, &["outputAnchor"])?, &Value::Null);
        assert_eq!(
            text(&value, &["payloadDigest"])?,
            ContentDigest::sha256(raw_payload(&body)?.as_bytes()).to_text()
        );
        conforms(&self.directory.0, "agent_response_envelope.v1.json", &body)?;
        if raw_payload(&body)? != "null" {
            let schema = text(&value, &["payloadSchema"])?.trim_start_matches("fss.");
            conforms(
                &self.directory.0,
                &format!("{schema}.json"),
                raw_payload(&body)?,
            )?;
        }
        Ok(Reply { body, value })
    }

    fn open_for(&self, principal: &str, budget: u64) -> TestResult<String> {
        let reply = self.call(
            principal,
            "session_open",
            &format!(
                "{{\"mission\":{},\"objective\":{},\"budget_tokens\":{budget}}}",
                quote(MISSION),
                quote(OBJECTIVE)
            ),
            "AOP-001",
            false,
        )?;
        Ok(text(&reply.value, &["sessionId"])?.to_owned())
    }

    fn open_case(&self, session: &str) -> TestResult {
        self.call(
            PRINCIPAL,
            "investigate",
            &format!(
                r#"{{"session":{},"transition":"open","draft":{}}}"#,
                quote(session),
                case_document()
            ),
            "AOP-006",
            false,
        )?;
        Ok(())
    }

    fn feedback(&self, session: &str, input: &ProposalInput) -> TestResult<Reply> {
        let reply = self.call(
            PRINCIPAL,
            "feedback",
            &input.arguments(session),
            "AOP-013",
            false,
        )?;
        assert_eq!(text(&reply.value, &["outcome"])?, "ok", "{}", reply.body);
        assert_eq!(text(&reply.value, &["principalId"])?, PRINCIPAL);
        assert_eq!(text(&reply.value, &["sessionId"])?, session);
        assert_eq!(
            texts(&reply.value, &["effectiveCapabilities"])?,
            vec!["CAP-AGENT-FEEDBACK-001"]
        );
        assert_eq!(
            text(&reply.value, &["payloadSchema"])?,
            AgentFeedbackProposal::SCHEMA
        );
        assert_eq!(
            field(&reply.value, &["payload", "activePolicyMutation"])?,
            &Value::Bool(false)
        );
        assert!(
            texts(&reply.value, &["degradation"])?
                .iter()
                .any(|line| line.starts_with("Advisory only:")
                    && line.contains("recorded, not performed"))
        );
        Ok(reply)
    }

    fn compare_cli(&self, session: &str, input: &ProposalInput, reply: &Reply) -> TestResult {
        let mut argv: Vec<OsString> = vec![
            "feedback".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            format!("--principal={PRINCIPAL}").into(),
            format!("--session={session}").into(),
            format!("--target={}", input.target()).into(),
            format!("--kind={}", input.kind.as_str()).into(),
            format!("--statement={}", input.statement).into(),
            format!("--disposition={}", input.disposition.as_str()).into(),
        ];
        for (key, values) in [
            ("supporting", &input.supporting),
            ("contradicting", &input.contradicting),
        ] {
            if !values.is_empty() {
                argv.push(
                    format!(
                        "--{key}={}",
                        values
                            .iter()
                            .map(|value| value.to_text())
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                    .into(),
                );
            }
        }
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(argv)
            .output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let body = String::from_utf8(output.stdout)?;
        // Both surfaces return the complete same native envelope at the same head, including
        // protected context, evidence, capabilities, cost accounting and retry semantics.
        assert_eq!(body.trim_end(), reply.body);
        Ok(())
    }

    fn verify_publication(
        &self,
        session: &str,
        input: &ProposalInput,
        reply: &Reply,
    ) -> TestResult<(ContentDigest, ContentDigest, ContentDigest)> {
        let bytes = fs::read(self.root.join("agent/sessions/journal.fssj"))?;
        let recovery = inspect_session_bytes(
            &bytes,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        let session = recovery
            .sessions
            .into_iter()
            .map(|retained| retained.session)
            .find(|retained| retained.session_id.as_str() == session)
            .ok_or("missing native session")?;
        let proposal = AgentFeedbackProposal::new(
            text(&reply.value, &["payload", "feedbackId"])?,
            session.principal_id,
            session.session_id,
            session.current_anchor,
            target_json(&input.target),
            input.kind,
            input.statement.clone(),
            ProposalInput::canonical_handles(&input.supporting),
            ProposalInput::canonical_handles(&input.contradicting),
            input.disposition,
            FeedbackPrivacyClass::Private,
            field(&reply.value, &["payload", "createdAtNs"])?
                .integer()
                .ok_or("missing native feedback time")?,
        )?;
        assert_eq!(
            raw_payload(&reply.body)?,
            fss_cli::feedback_cmd::feedback_json(&proposal)
        );
        assert_eq!(
            text(&reply.value, &["decisionFingerprint"])?,
            proposal.proposal_digest().to_text()
        );
        let pointers = texts(&reply.value, &["proofPointers"])?;
        assert_eq!(pointers.len(), 3);
        assert_eq!(pointers[1], proposal.proposal_digest().to_text());
        let root = ContentDigest::parse(&pointers[0])?;
        let directory = self.root.join("agent/publications");
        let manifest = ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &directory,
            root,
            1 << 20,
        )?)?;
        assert_eq!(manifest.root(), root);
        let metadata = manifest
            .metadata_digest()
            .ok_or("missing feedback metadata")?;
        assert_eq!(
            fss_publication::read_verified(&directory, metadata, 1 << 20)?,
            proposal.try_canonical_bytes()?
        );
        let children = manifest
            .children()
            .iter()
            .copied()
            .filter(|child| *child != metadata)
            .collect::<Vec<_>>();
        assert_eq!(children.len(), 1, "the complete native rendering is linked");
        let rendering = children[0];
        // This retained native projection is deliberately smaller than the full CLI payload;
        // compare it with its native renderer rather than inventing missing schema fields.
        assert_eq!(
            fss_publication::read_verified(&directory, rendering, 1 << 20)?,
            render_json(&proposal).as_bytes()
        );
        for (bytes, digest) in EVIDENCE
            .into_iter()
            .zip(EVIDENCE.map(ContentDigest::sha256))
        {
            assert_eq!(
                fss_publication::read_verified(self.root.join("objects"), digest, 1 << 20)?,
                bytes
            );
        }
        Ok((root, metadata, rendering))
    }

    fn publication_file(&self, digest: ContentDigest) -> TestResult<PathBuf> {
        let identity = digest.to_text();
        let hex = identity
            .strip_prefix("sha256:")
            .ok_or("fixture requires SHA-256")?;
        let path = self.root.join("agent/publications/spool/objects").join(hex);
        assert!(fs::symlink_metadata(&path)?.is_file());
        // Stored files contain the spool envelope. The digest names the verified payload.
        let bytes =
            fss_publication::read_verified(self.root.join("agent/publications"), digest, 1 << 20)?;
        assert_eq!(ContentDigest::sha256(&bytes), digest);
        Ok(path)
    }

    fn advance_evidence_clock(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(b"synthetic clock-bearing observation")?;
        deployment.append_batch(
            BatchId::parse("batch:mcp-feedback:clock")?,
            vec![EvidenceDelta {
                delta_id: "delta:mcp-feedback:clock".to_owned(),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse("object:mcp-feedback:clock")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000))?,
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
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the east door?","decisionInformed":"Whether another observation is needed","hypotheses":[{{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]}},{{"hypothesisId":"h:passerby","description":"A person passed the door","predictions":["the track leaves eastward"]}}],"knowns":[],"unknowns":[{{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}}],"discriminators":[{{"discriminatorId":"d:hallway","description":"Hallway frames","separates":["h:entry","h:passerby"],"expectedOutcomes":["person in hallway","empty hallway"]}}],"probes":["probe:hallway-frames"],"stopRules":["independent observation distinguishes the hypotheses"],"decisionWindowNs":3600000000000}}"#
    )
}

#[test]
fn mcp_feedback_retains_native_provenance_and_exact_retry_after_restart() -> TestResult {
    let fixture = Fixture::new("retry")?;
    let session = fixture.open_for(PRINCIPAL, 30_000)?;
    fixture.open_case(&session)?;
    let input = ProposalInput::new();
    let authority = fixture.authority()?;
    let first = fixture.feedback(&session, &input)?;
    let custody = fixture.verify_publication(&session, &input, &first)?;
    assert_eq!(
        text(&first.value, &["payload", "statement"])?,
        input.statement
    );
    assert_eq!(
        texts(&first.value, &["payload", "supportingEvidence"])?,
        ProposalInput::canonical_handles(&input.supporting)
    );
    assert_eq!(
        texts(&first.value, &["payload", "contradictingEvidence"])?,
        ProposalInput::canonical_handles(&input.contradicting)
    );
    let shared = ContentDigest::sha256(EVIDENCE[1]).to_text();
    assert!(texts(&first.value, &["payload", "supportingEvidence"])?.contains(&shared));
    assert!(texts(&first.value, &["payload", "contradictingEvidence"])?.contains(&shared));
    let published = tree(&fixture.root, &["agent/publications"])?;

    // The first process has exited; a caller that lost its reply submits the exact intent.
    let restarted = fixture.feedback(&session, &input)?;
    assert_eq!(restarted.body, first.body);
    assert_eq!(
        fixture.verify_publication(&session, &input, &restarted)?,
        custody
    );
    fixture.compare_cli(&session, &input, &restarted)?;

    // Native semantics canonicalize each evidence set, including duplicates, without merging
    // a supporting citation into the contradictory side or dropping any distinct handle.
    let mut reordered = input.clone();
    reordered.supporting.reverse();
    reordered.supporting.push(reordered.supporting[0]);
    reordered.contradicting.reverse();
    let canonical_retry = fixture.feedback(&session, &reordered)?;
    assert_eq!(canonical_retry.body, first.body);
    assert_eq!(tree(&fixture.root, &["agent/publications"])?, published);
    assert_eq!(fixture.authority()?, authority);

    // Moving evidence does not rebase the old session or rewrite the original proposal.
    fixture.advance_evidence_clock()?;
    let advanced_authority = fixture.authority()?;
    let after_head_move = fixture.feedback(&session, &input)?;
    assert_eq!(
        raw_payload(&after_head_move.body)?,
        raw_payload(&first.body)?
    );
    assert_eq!(
        fixture.verify_publication(&session, &input, &after_head_move)?,
        custody
    );
    assert_eq!(
        field(&after_head_move.value, &["decisionFingerprint"])?,
        field(&first.value, &["decisionFingerprint"])?
    );
    assert_eq!(
        field(&after_head_move.value, &["inputAnchor"])?,
        field(&first.value, &["inputAnchor"])?
    );
    assert!(
        texts(&after_head_move.value, &["degradation"])?
            .iter()
            .any(|line| { line.contains("head has moved") && line.contains("session's anchor") })
    );
    fixture.compare_cli(&session, &input, &after_head_move)?;
    assert_eq!(tree(&fixture.root, &["agent/publications"])?, published);
    assert_eq!(fixture.authority()?, advanced_authority);
    Ok(())
}

#[test]
fn changed_feedback_intent_and_author_session_never_alias_prior_proposals() -> TestResult {
    let fixture = Fixture::new("identity")?;
    let first_session = fixture.open_for(PRINCIPAL, 30_000)?;
    let second_session = fixture.open_for(PRINCIPAL, 40_000)?;
    assert_ne!(first_session, second_session);
    fixture.open_case(&first_session)?;
    let input = ProposalInput::new();
    let first = fixture.feedback(&first_session, &input)?;
    let first_root = fixture
        .verify_publication(&first_session, &input, &first)?
        .0;
    let authority = fixture.authority()?;
    let mut variants = Vec::new();
    let mut changed = input.clone();
    changed.statement = "A different literal correction.".to_owned();
    variants.push(changed);
    let mut changed = input.clone();
    changed.kind = FeedbackProposalKind::Correction;
    variants.push(changed);
    let mut changed = input.clone();
    changed.disposition = RequestedDisposition::OperatorReview;
    variants.push(changed);
    let mut changed = input.clone();
    std::mem::swap(&mut changed.supporting, &mut changed.contradicting);
    variants.push(changed);
    let mut roots = vec![first_root];
    for variant in variants {
        let response = fixture.feedback(&first_session, &variant)?;
        let root = fixture
            .verify_publication(&first_session, &variant, &response)?
            .0;
        assert!(!roots.contains(&root));
        roots.push(root);
        assert_ne!(
            text(&response.value, &["payload", "feedbackId"])?,
            text(&first.value, &["payload", "feedbackId"])?
        );
        fixture.compare_cli(&first_session, &variant, &response)?;
    }
    let other_author = fixture.feedback(&second_session, &input)?;
    let other_root = fixture
        .verify_publication(&second_session, &input, &other_author)?
        .0;
    assert!(!roots.contains(&other_root));
    assert_eq!(
        text(&other_author.value, &["payload", "sessionId"])?,
        second_session
    );
    assert_eq!(
        fixture
            .verify_publication(&first_session, &input, &first)?
            .0,
        first_root
    );
    assert_eq!(fixture.authority()?, authority);
    Ok(())
}

#[test]
fn feedback_cold_retries_require_every_original_custody_object() -> TestResult {
    for (part, remove) in [
        ("manifest", true),
        ("manifest", false),
        ("metadata", true),
        ("metadata", false),
        ("rendering", true),
        ("rendering", false),
    ] {
        let fixture = Fixture::new(&format!("custody-{part}-{remove}"))?;
        let session = fixture.open_for(PRINCIPAL, 30_000)?;
        fixture.open_case(&session)?;
        let input = ProposalInput::new();
        let first = fixture.feedback(&session, &input)?;
        let (root, metadata, rendering) = fixture.verify_publication(&session, &input, &first)?;
        let digest = match part {
            "manifest" => root,
            "metadata" => metadata,
            "rendering" => rendering,
            _ => return Err("invalid custody fixture part".into()),
        };
        let path = fixture.publication_file(digest)?;
        if remove {
            fs::remove_file(&path)?;
        } else {
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty stored object")? ^= 1;
            fs::write(&path, bytes)?;
        }
        let corrupted = tree(&fixture.root, &["agent/publications"])?;
        let authority = fixture.authority()?;
        let refused = fixture.call(
            PRINCIPAL,
            "feedback",
            &input.arguments(&session),
            "AOP-013",
            true,
        )?;
        assert_eq!(
            text(&refused.value, &["outcome"])?,
            "refused",
            "{part} {remove}"
        );
        assert_eq!(
            text(&refused.value, &["errorId"])?,
            "ERR-AGENT-HANDOFF-INVALID-001",
            "{}",
            refused.body
        );
        assert_eq!(field(&refused.value, &["payload"])?, &Value::Null);
        assert_eq!(tree(&fixture.root, &["agent/publications"])?, corrupted);
        assert_eq!(fixture.authority()?, authority);
    }
    Ok(())
}

#[test]
fn feedback_notifications_malformed_targets_and_foreign_scope_do_not_publish() -> TestResult {
    let fixture = Fixture::new("refusals")?;
    let session = fixture.open_for(PRINCIPAL, 30_000)?;
    fixture.open_case(&session)?;
    let input = ProposalInput::new();
    let arguments = input.arguments(&session);
    let before = tree(&fixture.root, &[""])?;
    let notification = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"feedback","arguments":{arguments}}}}}"#
    );
    let replies = fixture.frames(PRINCIPAL, &[notification])?;
    assert_eq!(
        replies.len(),
        1,
        "a notification produces only the initialization reply"
    );
    assert_eq!(tree(&fixture.root, &[""])?, before);

    for suffix in [
        r#""root":"/outside/deployment""#,
        r#""principal":"principal:other""#,
        r#""statement_file":"/outside/proposal.json""#,
        r#""activePolicyMutation":true"#,
        r#""approve":"sha256:bad""#,
        r#""transition":"activate""#,
    ] {
        let invalid = format!("{},{suffix}}}", arguments.trim_end_matches('}'));
        let reply = fixture.exchange(PRINCIPAL, "feedback", &invalid)?;
        assert_eq!(field(&reply, &["error", "code"])?.integer(), Some(-32602));
        assert_eq!(tree(&fixture.root, &[""])?, before);
    }
    let valid_support = format!(
        "\"supporting\":[{}]",
        input
            .supporting
            .iter()
            .map(|digest| quote(&digest.to_text()))
            .collect::<Vec<_>>()
            .join(",")
    );
    for value in [
        "null".to_owned(),
        "true".to_owned(),
        r#""sha256:literal""#.to_owned(),
        r#"["sha256:bad"]"#.to_owned(),
        format!("[{},false]", quote(&input.supporting[0].to_text())),
        format!(
            "[{}]",
            quote(&format!("{},{}", input.supporting[0], input.supporting[1]))
        ),
        format!(
            "[{}]",
            (0..255)
                .map(|_| quote(&input.supporting[0].to_text()))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ] {
        let invalid = arguments.replace(&valid_support, &format!("\"supporting\":{value}"));
        assert_ne!(invalid, arguments);
        let reply = fixture.exchange(PRINCIPAL, "feedback", &invalid)?;
        assert_eq!(
            field(&reply, &["error", "code"])?.integer(),
            Some(-32602),
            "{value}"
        );
        assert_eq!(tree(&fixture.root, &[""])?, before);
    }
    for (needle, replacement) in [
        (quote("policy_candidate"), quote("activate_policy")),
        (quote("create_learning_proposal"), quote("activate")),
        (
            quote("case:case:east-door"),
            quote("file:/outside/proposal.json"),
        ),
    ] {
        let invalid = arguments.replace(&needle, &replacement);
        let reply = fixture.exchange(PRINCIPAL, "feedback", &invalid)?;
        assert_eq!(field(&reply, &["error", "code"])?.integer(), Some(-32602));
        assert_eq!(tree(&fixture.root, &[""])?, before);
    }

    // The native owner, not MCP, decides which actual targets this session can see.
    for target in [
        FeedbackTarget::Event("event:missing".into()),
        FeedbackTarget::Case("case:missing".into()),
        FeedbackTarget::Operation("operation:missing".into()),
        FeedbackTarget::Plan("plan:missing".into()),
    ] {
        let mut unknown = input.clone();
        unknown.target = target;
        let reply = fixture.call(
            PRINCIPAL,
            "feedback",
            &unknown.arguments(&session),
            "AOP-013",
            true,
        )?;
        assert_eq!(text(&reply.value, &["outcome"])?, "refused");
        assert_eq!(field(&reply.value, &["payload"])?, &Value::Null);
        assert_eq!(tree(&fixture.root, &[""])?, before);
    }
    let foreign = fixture.call(STRANGER, "feedback", &arguments, "AOP-013", true)?;
    assert_eq!(text(&foreign.value, &["outcome"])?, "refused");
    assert_eq!(text(&foreign.value, &["principalId"])?, STRANGER);
    assert_eq!(field(&foreign.value, &["payload"])?, &Value::Null);
    assert_eq!(tree(&fixture.root, &[""])?, before);

    let foreign_session = fixture.open_for(STRANGER, 30_000)?;
    let foreign_before = tree(&fixture.root, &[""])?;
    let foreign_case = fixture.call(
        STRANGER,
        "feedback",
        &input.arguments(&foreign_session),
        "AOP-013",
        true,
    )?;
    assert_eq!(text(&foreign_case.value, &["outcome"])?, "refused");
    assert_eq!(field(&foreign_case.value, &["payload"])?, &Value::Null);
    assert_eq!(tree(&fixture.root, &[""])?, foreign_before);
    Ok(())
}

#[test]
fn mcp_feedback_accepts_the_full_native_statement_and_evidence_bounds() -> TestResult {
    let fixture = Fixture::new("native-bounds")?;
    let session = fixture.open_for(PRINCIPAL, 30_000)?;
    fixture.open_case(&session)?;
    let mut input = ProposalInput::new();
    input.statement = "é".repeat(8192);
    input.supporting = vec![ContentDigest::sha256(EVIDENCE[0]); 128];
    input.contradicting = vec![ContentDigest::sha256(EVIDENCE[1]); 128];
    assert_eq!(input.statement.len(), 16_384);
    assert_eq!(input.supporting.len() + input.contradicting.len(), 256);
    let authority = fixture.authority()?;
    let published = fixture.feedback(&session, &input)?;
    fixture.verify_publication(&session, &input, &published)?;
    assert_eq!(
        text(&published.value, &["payload", "statement"])?,
        input.statement
    );
    assert_eq!(
        texts(&published.value, &["payload", "supportingEvidence"])?,
        vec![ContentDigest::sha256(EVIDENCE[0]).to_text()]
    );
    assert_eq!(
        texts(&published.value, &["payload", "contradictingEvidence"])?,
        vec![ContentDigest::sha256(EVIDENCE[1]).to_text()]
    );
    let closure = tree(&fixture.root, &["agent/publications"])?;
    let retry = fixture.feedback(&session, &input)?;
    assert_eq!(retry.body, published.body);
    assert_eq!(tree(&fixture.root, &["agent/publications"])?, closure);
    assert_eq!(fixture.authority()?, authority);
    // The actual CLI has a separate 4096-byte OS argument-token ceiling. Small requests above
    // pin cross-surface equality; this request proves the typed native feedback bound itself.
    Ok(())
}
