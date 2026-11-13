#![forbid(unsafe_code)]
//! Native H0/H1 event metadata through the canonical library and fresh CLI/MCP processes.
//! Synthetic committed hypotheses test custody and disclosure wiring, not sensor accuracy.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::json_input::{Value, parse};
use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContextAuthority, DecisionPath, EffectIntent, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, IdempotencyKey, ObligationId,
    OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec, SessionId, TimestampNs,
};
use fss_reference::agent_event_hydration::{
    EVENT_HYDRATION_CAPABILITY, EVENT_HYDRATION_H0_TOKENS, EVENT_HYDRATION_H1_TOKENS,
    EVENT_HYDRATION_QUERY_CAPABILITY, EventHydrationCatalog, build_event_hydration_catalog,
};
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::orient::{OrientSessionRequest, orient_session};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
type Tree = BTreeMap<PathBuf, (bool, Vec<u8>, SystemTime)>;

const SITE: &str = "site:event-hydration-cli";
const PRINCIPAL: &str = "principal:event-hydration-owner";
const STRANGER: &str = "principal:event-hydration-stranger";
const EVENT: &str = "event:hydration-retained-hypothesis";
const SESSION_BUDGET: u64 = 100_000;
const SUPPORTING_ASSERTION: &[u8] = b"synthetic retained assertion supporting the hypothesis";
const CONTRADICTING_ASSERTION: &[u8] = b"synthetic retained assertion contradicting the hypothesis";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"event-hydration-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn quote(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing field {name}").into())
}

fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("{name} is not text").into())
}

fn integer(value: &Value, name: &str) -> Test<u64> {
    let number = field(value, name)?.integer().ok_or("exact integer")?;
    Ok(u64::try_from(number)?)
}

fn array<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("{name} is not an array").into())
}

/// Round-trip the complete native cursor object; never substitute its display token.
fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => quote(value),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(json).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{}:{}", quote(key), json(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        output.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    output
}

fn tree(root: &Path) -> Test<Tree> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new(), metadata.modified()?));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?, metadata.modified()?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

fn authority_tree(root: &Path) -> Test<Tree> {
    Ok(tree(root)?
        .into_iter()
        .filter(|(path, _)| {
            ["ledger", "effects", "objects", "LAYOUT"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .collect())
}

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
}

impl Fixture {
    fn new(tag: &str) -> Test<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-event-hydration-cli-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    directory = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("fixture directory capacity")?;
        let root = directory.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:event-hydration-fixture".to_owned(),
            operation_id: OperationId::parse("operation:event-hydration-fixture")?,
            principal: "operator:event-hydration-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"native event hydration transport fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            directory.join("cx"),
        )?);
        let fixture = Self {
            directory,
            root,
            cx,
        };
        {
            let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
            deployment.stage_payload(SUPPORTING_ASSERTION)?;
            deployment.stage_payload(CONTRADICTING_ASSERTION)?;
        }
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse(EVENT)?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: None,
            zone_ids: vec!["door".to_owned()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![
                EventEvidence {
                    digest: ContentDigest::sha256(SUPPORTING_ASSERTION),
                    class: EvidenceClass::Assertion,
                    failure_domain: "synthetic:hydration-support".to_owned(),
                    supports: true,
                    relation: EvidenceEdgeRelation::Supports,
                    capsule_digest: None,
                    identity_digest: None,
                },
                EventEvidence {
                    digest: ContentDigest::sha256(CONTRADICTING_ASSERTION),
                    class: EvidenceClass::Assertion,
                    failure_domain: "synthetic:hydration-counterevidence".to_owned(),
                    supports: false,
                    relation: EvidenceEdgeRelation::Contradicts,
                    capsule_digest: None,
                    identity_digest: None,
                },
            ],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"synthetic event hydration policy"),
                fingerprint: ContentDigest::sha256(b"synthetic event hydration hypothesis"),
                abstained: true,
                abstention_reason: Some(
                    "Synthetic hypothesis; physical presence remains unknown.".to_owned(),
                ),
            },
        };
        fixture.publish(event)?;
        fixture.prepare("initial", 100)?;
        Ok(fixture)
    }

    fn publish(&self, event: EventHypothesis) -> Test {
        event.verify()?;
        ReferenceDeployment::open(&self.root, SITE, &self.cx)?.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            &self.cx,
        )?;
        Ok(())
    }

    fn prepare(&self, tag: &str, time: i128) -> Test {
        ReferenceDeployment::open(&self.root, SITE, &self.cx)?
            .effects_mut()
            .prepare(
                EffectIntent {
                    operation_id: OperationId::parse(format!("operation:hydration:{tag}"))?,
                    idempotency_key: IdempotencyKey::parse(format!("idempotency:hydration:{tag}"))?,
                    effect_class: "fixture.observe".to_owned(),
                    request_digest: ContentDigest::sha256(tag.as_bytes()),
                    precondition_digest: ContentDigest::sha256(b"synthetic pending obligation"),
                },
                ObligationId::parse(format!("obligation:hydration:{tag}"))?,
                "synthetic observation verified",
                TimestampNs(time),
            )?;
        Ok(())
    }

    fn revise(&self) -> Test {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        let mut event = snapshot
            .event(&EventId::parse(EVENT)?)
            .ok_or("event")?
            .event
            .clone();
        let predecessor = event.revision_digest();
        event.supersedes = Some(predecessor);
        event.revision += 1;
        event.state = EventState::Indeterminate;
        event.uncertainty_reason =
            Some("The synthetic retained claim remains unadjudicated.".to_owned());
        event.evidence.push(EventEvidence {
            digest: predecessor,
            class: EvidenceClass::Derived,
            failure_domain: "synthetic:event-hydration".to_owned(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        });
        event.decision_path.fingerprint = ContentDigest::sha256(b"revised hydration fixture");
        self.publish(event)
    }

    fn selection(&self) -> Test<(String, String)> {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        let revision = snapshot
            .event(&EventId::parse(EVENT)?)
            .ok_or("event")?
            .revision_digest;
        Ok((snapshot_anchor_token(&snapshot), revision.to_text()))
    }

    fn open(&self, tag: &str, budget: u64) -> Test<String> {
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["session", "open", "--json", "--root"])
            .arg(&self.root)
            .args([
                "--principal",
                PRINCIPAL,
                "--mission",
                &format!("Hydration mission {tag}"),
                "--objective",
                "Inspect exact retained event metadata without source media.",
                "--budget-tokens",
                &budget.to_string(),
            ])
            .output()?;
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let reply = parse(&String::from_utf8(output.stdout)?)?;
        Ok(text(&reply, "sessionId")?.to_owned())
    }

    fn inspect(&self) -> Test<SessionRecoveryState> {
        Ok(inspect_session_bytes(
            &fs::read(self.root.join("agent/sessions/journal.fssj"))?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?)
    }

    fn spent(&self, session: &str) -> Test<u64> {
        let state = self.inspect()?;
        Ok(state
            .sessions
            .iter()
            .find(|state| state.session.session_id.as_str() == session)
            .ok_or("retained session")?
            .spent_tokens)
    }

    fn generation(&self, session: &str) -> Test<u64> {
        let state = self.inspect()?;
        Ok(state
            .sessions
            .iter()
            .find(|state| state.session.session_id.as_str() == session)
            .ok_or("retained session")?
            .session
            .symbol_table_generation)
    }

    fn expected(&self, session: &str) -> Test<EventHydrationCatalog> {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        let oriented = orient_session(
            &self.root,
            &OrientSessionRequest {
                session_id: SessionId::parse(session)?,
                principal: PrincipalId::parse(PRINCIPAL)?,
                view: AgentView::Brief,
                budget_tokens: None,
            },
        )?;
        let revision = snapshot
            .event(&EventId::parse(EVENT)?)
            .ok_or("event")?
            .revision_digest;
        Ok(build_event_hydration_catalog(
            &snapshot,
            &oriented.orientation,
            &EventId::parse(EVENT)?,
            revision,
            TimestampNs(oriented.session.expires_at_ns),
        )?)
    }

    fn args(&self, session: &str, level: &str, extras: &[(&str, String)]) -> Test<Vec<OsString>> {
        let (anchor, revision) = self.selection()?;
        let mut values: BTreeMap<&str, String> = [
            ("--target", "evidence-hydration".to_owned()),
            ("--principal", PRINCIPAL.to_owned()),
            ("--session", session.to_owned()),
            ("--generation", self.generation(session)?.to_string()),
            ("--event-id", EVENT.to_owned()),
            ("--revision-digest", revision),
            ("--anchor", anchor),
            ("--level", level.to_owned()),
        ]
        .into();
        values.extend(extras.iter().map(|(key, value)| (*key, value.clone())));
        let mut args = vec![
            "query".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
        ];
        args.extend(
            values
                .into_iter()
                .map(|(key, value)| format!("{key}={value}").into()),
        );
        Ok(args)
    }

    fn cli(&self, session: &str, level: &str, extras: &[(&str, String)]) -> Test<(String, i32)> {
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(self.args(session, level, extras)?)
            .output()?;
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok((
            String::from_utf8(output.stdout)?.trim_end().to_owned(),
            output.status.code().ok_or("exit signal")?,
        ))
    }

    fn mcp(
        &self,
        session: &str,
        level: &str,
        principal: &str,
        extras: &[(&str, Value)],
    ) -> Test<Value> {
        let (anchor, revision) = self.selection()?;
        let mut values: BTreeMap<String, Value> = [
            ("target", Value::Text("evidence-hydration".to_owned())),
            ("session", Value::Text(session.to_owned())),
            (
                "generation",
                Value::Text(self.generation(session)?.to_string()),
            ),
            ("event_id", Value::Text(EVENT.to_owned())),
            ("revision_digest", Value::Text(revision)),
            ("anchor", Value::Text(anchor)),
            ("level", Value::Text(level.to_owned())),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        values.extend(
            extras
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone())),
        );
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query","arguments":{}}}}}"#,
            json(&Value::Object(values))
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.root)
            .args(["--principal", principal])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin")?;
        writeln!(input, "{INIT}\n{READY}\n{request}")?;
        drop(input);
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{stdout}");
        Ok(parse(lines[1])?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn mcp_body(wire: &Value, failed: bool) -> Test<String> {
    let result = field(wire, "result")?;
    assert_eq!(field(result, "isError")?.boolean(), Some(failed));
    let content = array(result, "content")?;
    assert_eq!(content.len(), 1);
    assert_eq!(text(&content[0], "type")?, "text");
    Ok(text(&content[0], "text")?.to_owned())
}

fn conforms(fixture: &Fixture, schema: &str, instance: &Value) -> Test {
    let body = json(instance);
    let file = fixture.directory.join(format!(
        "schema-{}.json",
        ContentDigest::sha256(body.as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, body)?;
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/json_instance_validate.py"))
        .arg(repository.join("schemas").join(schema))
        .arg(&file)
        .output()?;
    fs::remove_file(file)?;
    assert!(
        output.status.success(),
        "{schema}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn accepted(
    fixture: &Fixture,
    session: &str,
    body: &str,
    expected: &EventHydrationCatalog,
    level: &str,
    previous_spent: u64,
) -> Test<Value> {
    let envelope = parse(body)?;
    assert_eq!(text(&envelope, "schema")?, "fss.agent_response_envelope.v1");
    let outer_basis = parse(&fss_cli::agent_json::contract_basis(
        &fss_core::hydration_contract_basis(),
    ))?;
    let native_basis = parse(&fss_cli::agent_json::contract_basis(
        &fss_core::reference_contract_basis(),
    ))?;
    assert_ne!(outer_basis, native_basis);
    assert_eq!(field(&envelope, "contractBasis")?, &outer_basis);
    assert_eq!(text(&envelope, "safeRetry")?, "no");
    assert_eq!(
        text(&envelope, "payloadSchema")?,
        "fss.agent_evidence_hydration.v1"
    );
    assert_eq!(text(&envelope, "sessionId")?, session);
    assert_eq!(text(&envelope, "principalId")?, PRINCIPAL);
    assert_eq!(text(&envelope, "operationId")?, "AOP-005");
    assert_eq!(field(&envelope, "errorId")?, &Value::Null);
    assert_eq!(field(&envelope, "outputAnchor")?, &Value::Null);
    assert!(matches!(text(&envelope, "outcome")?, "ok" | "partial"));
    let payload = field(&envelope, "payload")?;
    assert_eq!(text(payload, "schema")?, "fss.agent_evidence_hydration.v1");
    assert_eq!(text(payload, "eventHandle")?, expected.event_handle);
    assert_eq!(text(payload, "anchorToken")?, fixture.selection()?.0);
    let descriptor = field(payload, "descriptor")?;
    assert_eq!(
        text(descriptor, "descriptorDigest")?,
        expected.descriptor.descriptor_digest.to_text()
    );
    assert_eq!(
        text(descriptor, "subjectDigest")?,
        expected.descriptor.subject_digest.to_text()
    );
    assert_eq!(
        array(descriptor, "levels")?,
        [Value::Text("H0".to_owned()), Value::Text("H1".to_owned())]
    );
    let request = field(payload, "request")?;
    let receipt = field(payload, "receipt")?;
    let artifact = field(payload, "artifact")?;
    for value in [descriptor, request] {
        assert_eq!(field(value, "contractBasis")?, &native_basis);
    }
    for value in [request, receipt] {
        let cursor = field(value, "continuation")?;
        if cursor != &Value::Null {
            assert_eq!(field(cursor, "contractBasis")?, &native_basis);
        }
    }
    assert_eq!(
        text(&envelope, "recoveryClass")?,
        if field(receipt, "continuation")? == &Value::Null {
            "never_unchanged"
        } else {
            "resume_from_continuation"
        }
    );
    assert_eq!(text(request, "sessionId")?, session);
    assert_eq!(field(request, "allowLowerLevel")?.boolean(), Some(false));
    assert_eq!(
        text(request, "expectedDescriptorDigest")?,
        text(descriptor, "descriptorDigest")?
    );
    assert_eq!(
        text(receipt, "requestDigest")?,
        text(request, "requestDigest")?
    );
    assert_eq!(
        text(receipt, "descriptorDigest")?,
        text(descriptor, "descriptorDigest")?
    );
    assert_eq!(
        text(receipt, "subjectDigest")?,
        text(descriptor, "subjectDigest")?
    );
    assert_eq!(text(receipt, "requestedLevel")?, level);
    assert_eq!(text(receipt, "deliveredLevel")?, level);
    assert_eq!(text(artifact, "level")?, level);
    assert_eq!(
        text(receipt, "artifactDigest")?,
        text(artifact, "artifactDigest")?
    );
    for value in [descriptor, request, receipt] {
        assert_eq!(
            integer(field(value, "anchor")?, "privacyEpoch")?,
            expected.descriptor.anchor.privacy_epoch
        );
    }
    let capabilities = array(request, "availableCapabilities")?;
    assert!(capabilities.contains(&Value::Text(EVENT_HYDRATION_CAPABILITY.to_owned())));
    assert!(capabilities.contains(&Value::Text(EVENT_HYDRATION_QUERY_CAPABILITY.to_owned())));
    assert!(!capabilities.contains(&Value::Text("CAP-READ-MEDIA-001".to_owned())));
    if level == "H0" {
        let mut encoder = CanonicalEncoder::new();
        expected.identity.encode_canonical(&mut encoder);
        let native = encoder.finish_checked()?;
        assert_eq!(text(artifact, "payloadBase64")?, base64(&native));
        assert_eq!(
            text(artifact, "payloadDigest")?,
            ContentDigest::sha256(&native).to_text()
        );
    } else {
        let native = expected.synopsis.to_hydration_artifact()?;
        assert_eq!(text(artifact, "payloadBase64")?, base64(&native.payload));
        assert_eq!(
            text(artifact, "payloadDigest")?,
            native.payload_digest.to_text()
        );
        assert_eq!(
            text(artifact, "artifactDigest")?,
            native.artifact_digest.to_text()
        );
    }
    let cognition = field(payload, "cognition")?;
    assert_eq!(field(cognition, "contractBasis")?, &native_basis);
    assert_eq!(
        text(cognition, "schema")?,
        "fss.agent_cognitive_envelope.v1"
    );
    if level == "H1" {
        let epistemic = field(cognition, "epistemic")?;
        let propositions = array(epistemic, "propositions")?;
        let invalidators = array(epistemic, "invalidators")?;
        assert!(
            expected
                .explanation
                .cells
                .iter()
                .any(|cell| !cell.contradictions().is_empty()),
            "fixture must exercise retained counterevidence"
        );
        for cell in &expected.explanation.cells {
            let proposition = propositions
                .iter()
                .find(|value| text(value, "id").ok() == Some(cell.claim_id()))
                .ok_or_else(|| format!("missing native event cell {}", cell.claim_id()))?;
            assert_eq!(text(proposition, "state")?, cell.knowledge_state().as_str());
            let supporting = array(proposition, "evidence")?;
            assert_eq!(
                supporting,
                cell.evidence_digests()
                    .iter()
                    .map(|root| Value::Text(root.to_text()))
                    .collect::<Vec<_>>(),
                "native supporting evidence changed for {}",
                cell.claim_id()
            );
            for root in cell.contradictions() {
                let root = root.to_text();
                assert!(
                    invalidators.iter().any(|value| value
                        .text()
                        .is_some_and(|invalidator| invalidator.contains(cell.claim_id())
                            && invalidator.contains(&root))),
                    "counterevidence {root} for {} omitted from invalidators",
                    cell.claim_id()
                );
                assert!(
                    !supporting.contains(&Value::Text(root.clone())),
                    "counterevidence {root} was presented as supporting evidence"
                );
            }
        }
        for world in &expected.explanation.worlds {
            assert!(
                body.contains(&world.world_id),
                "native world omitted: {}",
                world.world_id
            );
        }
    }
    assert!(
        body.contains("obligation:hydration:initial"),
        "protected pending effect omitted"
    );
    let charged = integer(field(payload, "admission")?, "chargedTokens")?;
    assert_eq!(
        integer(field(payload, "admission")?, "sessionGeneration")?,
        fixture.generation(session)?
    );
    assert_eq!(charged, integer(field(receipt, "cost")?, "tokens")?);
    assert_eq!(
        charged,
        if level == "H0" {
            EVENT_HYDRATION_H0_TOKENS
        } else {
            EVENT_HYDRATION_H1_TOKENS
        }
    );
    assert_eq!(fixture.spent(session)?, previous_spent + charged);
    assert_eq!(
        integer(field(payload, "admission")?, "remainingTokens")?,
        SESSION_BUDGET - previous_spent - charged
    );
    assert!(!body.contains(fixture.root.to_str().ok_or("root text")?));
    conforms(fixture, "agent_response_envelope.v1.json", &envelope)?;
    conforms(fixture, "agent_evidence_hydration.v1.json", payload)?;
    Ok(envelope)
}

fn next(reply: &Value) -> Test<(String, String)> {
    let payload = field(reply, "payload")?;
    let receipt = field(payload, "receipt")?;
    let cursor = field(receipt, "continuation")?;
    assert!(
        cursor.object().is_some(),
        "complete native continuation object"
    );
    assert_eq!(text(reply, "continuation")?, text(cursor, "cursorId")?);
    Ok((
        text(field(payload, "descriptor")?, "descriptorDigest")?.to_owned(),
        json(cursor),
    ))
}

fn refused(fixture: &Fixture, body: &str) -> Test {
    let reply = parse(body)?;
    assert_eq!(text(&reply, "outcome")?, "refused");
    assert_eq!(
        field(&reply, "contractBasis")?,
        &parse(&fss_cli::agent_json::contract_basis(
            &fss_core::hydration_contract_basis(),
        ))?
    );
    assert_eq!(text(&reply, "safeRetry")?, "no");
    assert!(array(&reply, "effectiveCapabilities")?.is_empty());
    assert!(
        array(
            field(&reply, "effectivePrivacyProjection")?,
            "allowedDomains"
        )?
        .is_empty()
    );
    assert_eq!(field(&reply, "payload")?, &Value::Null);
    assert!(!body.contains("payloadBase64"));
    conforms(fixture, "agent_response_envelope.v1.json", &reply)?;
    Ok(())
}

#[test]
fn library_cli_and_cold_mcp_deliver_exact_h0_h1_and_preserve_durable_accounting() -> Test {
    let fixture = Fixture::new("roundtrip")?;
    let first = fixture.open("library then CLI", SESSION_BUDGET)?;
    let second = fixture.open("fresh MCP processes", SESSION_BUDGET)?;
    assert_eq!(
        fixture.generation(&first)?,
        0,
        "the actual public session starts at generation zero"
    );
    let before = authority_tree(&fixture.root)?;
    let expected = fixture.expected(&first)?;
    let (body, exit) = execute_fss_with_exit(parse_fss_args(fixture.args(&first, "H0", &[])?)?);
    assert_eq!(exit, ExitIdentity::SUCCESS, "{body}");
    let h0 = accepted(&fixture, &first, &body, &expected, "H0", 0)?;
    let (descriptor, cursor) = next(&h0)?;
    let (body, exit) = fixture.cli(
        &first,
        "H1",
        &[
            ("--descriptor-digest", descriptor.clone()),
            ("--continuation", cursor.clone()),
        ],
    )?;
    assert_eq!(exit, 0, "{body}");
    accepted(
        &fixture,
        &first,
        &body,
        &expected,
        "H1",
        EVENT_HYDRATION_H0_TOKENS,
    )?;
    assert_eq!(authority_tree(&fixture.root)?, before);

    let expected = fixture.expected(&second)?;
    let wire = fixture.mcp(&second, "H0", PRINCIPAL, &[])?;
    let body = mcp_body(&wire, false)?;
    let h0 = accepted(&fixture, &second, &body, &expected, "H0", 0)?;
    let (descriptor, cursor) = next(&h0)?;
    let options = [
        ("descriptor_digest", Value::Text(descriptor)),
        ("continuation", Value::Text(cursor)),
    ];
    let wire = fixture.mcp(&second, "H1", PRINCIPAL, &options)?;
    let body = mcp_body(&wire, false)?;
    accepted(
        &fixture,
        &second,
        &body,
        &expected,
        "H1",
        EVENT_HYDRATION_H0_TOKENS,
    )?;
    let spent = fixture.spent(&second)?;
    let replay = fixture.mcp(&second, "H1", PRINCIPAL, &options)?;
    refused(&fixture, &mcp_body(&replay, true)?)?;
    assert_eq!(
        fixture.spent(&second)?,
        spent,
        "consumed cursor cannot debit again"
    );
    assert_eq!(authority_tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn foreign_principal_session_descriptor_and_cursor_never_disclose_or_mutate_authority() -> Test {
    let fixture = Fixture::new("scope")?;
    let session = fixture.open("scope owner", SESSION_BUDGET)?;
    let other = fixture.open("another session", SESSION_BUDGET)?;
    let expected = fixture.expected(&session)?;
    let (body, exit) = fixture.cli(&session, "H0", &[])?;
    assert_eq!(exit, 0, "{body}");
    let h0 = accepted(&fixture, &session, &body, &expected, "H0", 0)?;
    let (descriptor, cursor) = next(&h0)?;
    let before = authority_tree(&fixture.root)?;
    let original_spent = fixture.spent(&session)?;
    for (selected_session, principal, selected_descriptor, selected_cursor) in [
        (
            session.as_str(),
            STRANGER,
            descriptor.clone(),
            cursor.clone(),
        ),
        (
            other.as_str(),
            PRINCIPAL,
            descriptor.clone(),
            cursor.clone(),
        ),
        (
            session.as_str(),
            PRINCIPAL,
            ContentDigest::sha256(b"foreign descriptor").to_text(),
            cursor.clone(),
        ),
    ] {
        let wire = fixture.mcp(
            selected_session,
            "H1",
            principal,
            &[
                ("descriptor_digest", Value::Text(selected_descriptor)),
                ("continuation", Value::Text(selected_cursor)),
            ],
        )?;
        refused(&fixture, &mcp_body(&wire, true)?)?;
        assert_eq!(authority_tree(&fixture.root)?, before);
    }
    let wrong_generation = fixture
        .generation(&session)?
        .checked_add(1)
        .ok_or("fixture generation overflow")?;
    let wire = fixture.mcp(
        &session,
        "H1",
        PRINCIPAL,
        &[
            ("descriptor_digest", Value::Text(descriptor.clone())),
            ("continuation", Value::Text(cursor.clone())),
            ("generation", Value::Text(wrong_generation.to_string())),
        ],
    )?;
    refused(&fixture, &mcp_body(&wire, true)?)?;
    assert_eq!(authority_tree(&fixture.root)?, before);
    assert_eq!(fixture.spent(&session)?, original_spent);
    let mut tampered = parse(&cursor)?;
    let Value::Object(fields) = &mut tampered else {
        return Err("native cursor is not an object".into());
    };
    fields.insert("position".to_owned(), Value::Number("99".to_owned()));
    let wire = fixture.mcp(
        &session,
        "H1",
        PRINCIPAL,
        &[
            ("descriptor_digest", Value::Text(descriptor.clone())),
            ("continuation", Value::Text(json(&tampered))),
        ],
    )?;
    if let Some(error) = wire.object().and_then(|object| object.get("error")) {
        assert_eq!(field(error, "code")?.integer(), Some(-32602));
    } else {
        refused(&fixture, &mcp_body(&wire, true)?)?;
    }
    assert_eq!(authority_tree(&fixture.root)?, before);
    assert_eq!(fixture.spent(&session)?, original_spent);
    assert_eq!(fixture.spent(&other)?, 0);
    let (body, exit) = fixture.cli(
        &session,
        "H1",
        &[
            ("--descriptor-digest", descriptor),
            ("--continuation", cursor),
        ],
    )?;
    assert_eq!(
        exit, 0,
        "failed foreign attempts must not consume the owner's cursor: {body}"
    );
    accepted(&fixture, &session, &body, &expected, "H1", original_spent)?;
    assert_eq!(authority_tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn both_event_revision_and_effect_history_changes_require_a_fresh_exact_anchor() -> Test {
    for changed_event in [false, true] {
        let fixture = Fixture::new(if changed_event {
            "changed-event"
        } else {
            "changed-effect"
        })?;
        let session = fixture.open("stale selection", SESSION_BUDGET)?;
        let expected = fixture.expected(&session)?;
        let (anchor, revision) = fixture.selection()?;
        let (body, exit) = fixture.cli(&session, "H0", &[])?;
        assert_eq!(exit, 0, "{body}");
        let h0 = accepted(&fixture, &session, &body, &expected, "H0", 0)?;
        let (descriptor, cursor) = next(&h0)?;
        if changed_event {
            fixture.revise()?;
        } else {
            fixture.prepare("later", 101)?;
        }
        assert_ne!(fixture.selection()?.0, anchor);
        let before = authority_tree(&fixture.root)?;
        let (body, exit) = fixture.cli(
            &session,
            "H1",
            &[
                ("--anchor", anchor),
                ("--revision-digest", revision),
                ("--descriptor-digest", descriptor),
                ("--continuation", cursor),
            ],
        )?;
        assert_ne!(exit, 0);
        refused(&fixture, &body)?;
        assert_eq!(fixture.spent(&session)?, EVENT_HYDRATION_H0_TOKENS);
        assert_eq!(authority_tree(&fixture.root)?, before);
    }
    Ok(())
}

#[test]
fn insufficient_request_and_cumulative_session_budgets_never_degrade_h1_to_h0() -> Test {
    let fixture = Fixture::new("budget")?;
    let session = fixture.open("limited disclosure", EVENT_HYDRATION_H1_TOKENS)?;
    let before = authority_tree(&fixture.root)?;
    let (body, exit) = fixture.cli(&session, "H0", &[])?;
    assert_eq!(exit, 0, "{body}");
    let (descriptor, cursor) = next(&parse(&body)?)?;
    for budget in [1, EVENT_HYDRATION_H1_TOKENS] {
        let wire = fixture.mcp(
            &session,
            "H1",
            PRINCIPAL,
            &[
                ("descriptor_digest", Value::Text(descriptor.clone())),
                ("continuation", Value::Text(cursor.clone())),
                ("budget_tokens", Value::Number(budget.to_string())),
            ],
        )?;
        refused(&fixture, &mcp_body(&wire, true)?)?;
        assert_eq!(fixture.spent(&session)?, EVENT_HYDRATION_H0_TOKENS);
        assert_eq!(authority_tree(&fixture.root)?, before);
    }
    Ok(())
}

#[test]
fn closed_cli_mcp_grammar_rejects_source_grants_lossy_numbers_and_scope_overrides() -> Test {
    let fixture = Fixture::new("grammar")?;
    let session = fixture.open("grammar", SESSION_BUDGET)?;
    let before = tree(&fixture.root)?;
    for extras in [
        vec![("--level", "H2".to_owned())],
        vec![("--level", "H3".to_owned())],
        vec![("--generation", "01".to_owned())],
        vec![("--budget-tokens", "16001".to_owned())],
        vec![("--verify-original", "yes".to_owned())],
        vec![("--read-media", "yes".to_owned())],
        vec![("--continuation", "not-a-native-cursor".to_owned())],
    ] {
        let args = fixture.args(&session, "H0", &extras)?;
        assert!(parse_fss_args(args.clone()).is_err());
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(args)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(tree(&fixture.root)?, before);
    }
    for (key, value) in [
        (
            "root",
            Value::Text(fixture.root.to_string_lossy().into_owned()),
        ),
        ("principal", Value::Text(PRINCIPAL.to_owned())),
        ("allow_source_read", Value::Bool(true)),
        ("level", Value::Text("H3".to_owned())),
        ("generation", Value::Number("1".to_owned())),
        ("generation", Value::Text("01".to_owned())),
        ("budget_tokens", Value::Text("5000".to_owned())),
        ("budget_tokens", Value::Number("1e3".to_owned())),
        ("budget_tokens", Value::Number("16001".to_owned())),
        ("continuation", Value::Text("x".repeat(16_385))),
    ] {
        let wire = fixture.mcp(&session, "H0", PRINCIPAL, &[(key, value)])?;
        assert_eq!(
            field(field(&wire, "error")?, "code")?.integer(),
            Some(-32602)
        );
        assert_eq!(tree(&fixture.root)?, before);
    }
    Ok(())
}
