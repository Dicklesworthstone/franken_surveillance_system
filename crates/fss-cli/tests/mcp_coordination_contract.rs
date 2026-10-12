#![forbid(unsafe_code)]
//! Real-process MCP collaboration over one native mission. Every agent operation crosses a
//! fresh MCP process; synthetic deployment setup and explicit evidence-clock advancement are
//! the only native fixture writes. No device, provider, probe or effect is executed.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_core::{
    BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EvidenceDelta,
    ObjectId, OperationId, Plane, RootAuthoritySpec, TimestampNs, WorkClaimState,
};
use fss_object::ObjectManifest;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::{WorkClaimLimits, WorkClaimRevision};
use fss_reference::deployment_session::findings::FindingRecord;
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-coordination";
const PRINCIPAL: &str = "principal:mcp-coordination";
const STRANGER: &str = "principal:mcp-stranger";
const CASE: &str = "case:east-door";
const MISSION: &str = "Keep the east door under watch.";
const OBJECTIVE: &str = "Preserve competing explanations and coordinate the needed observations.";
const STALE: &str = "ERR-PRECONDITION-STALE-001";
const PRECONDITION: &str = "ERR-OP-PRECONDITION-FAILED-001";
const CONFLICT: &str = "ERR-AGENT-WORK-CLAIM-CONFLICT-001";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-coordination-contract","version":"1"}}}"#;
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
                "fss-mcp-coordination-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("no unused coordination fixture directory".into())
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

impl Reply {
    fn fingerprint(&self) -> TestResult<String> {
        Ok(text(&self.value, &["decisionFingerprint"])?.to_owned())
    }

    fn propositions(&self) -> TestResult<&[Value]> {
        array(&self.value, &["payload", "epistemic", "propositions"])
    }

    fn id(&self) -> TestResult<String> {
        let propositions = self.propositions()?;
        assert_eq!(propositions.len(), 1);
        Ok(text(&propositions[0], &["id"])?.to_owned())
    }

    fn standings(&self) -> TestResult<BTreeMap<String, String>> {
        self.propositions()?
            .iter()
            .map(|item| {
                Ok((
                    text(item, &["id"])?.to_owned(),
                    text(item, &["state"])?.to_owned(),
                ))
            })
            .collect()
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
            trace_id: format!("trace:mcp-coordination:{tag}"),
            operation_id: OperationId::parse(format!("operation:mcp-coordination:{tag}"))?,
            principal: "operator:mcp-coordination-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit MCP coordination fixture"),
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
        })
    }

    fn authority(&self) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
        tree(&self.root, &["ledger", "effects", "objects", "LAYOUT"])
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
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let stdout = String::from_utf8(output.stdout)?;
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "initialize and one complete tool response");
        let initialization = parse(lines[0])?;
        assert_eq!(
            text(&initialization, &["result", "protocolVersion"])?,
            "2025-06-18"
        );
        let reply = parse(lines[1])?;
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

    fn open(&self, budget: u64) -> TestResult<String> {
        let reply = self.call(
            PRINCIPAL,
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

    fn investigate(
        &self,
        session: &str,
        transition: &str,
        fields: &str,
        error: Option<&str>,
    ) -> TestResult<Reply> {
        let suffix = if fields.is_empty() {
            String::new()
        } else {
            format!(",{fields}")
        };
        let reply = self.call(
            PRINCIPAL,
            "investigate",
            &format!(
                "{{\"session\":{},\"transition\":{}{suffix}}}",
                quote(session),
                quote(transition)
            ),
            "AOP-006",
            error.is_some(),
        )?;
        assert_eq!(
            texts(&reply.value, &["effectiveCapabilities"])?,
            vec!["CAP-AGENT-CASE-WRITE-001"]
        );
        if let Some(error) = error {
            assert_eq!(text(&reply.value, &["outcome"])?, "refused");
            assert_eq!(text(&reply.value, &["errorId"])?, error, "{}", reply.body);
            assert_eq!(field(&reply.value, &["payload"])?, &Value::Null);
        } else {
            assert_eq!(text(&reply.value, &["outcome"])?, "ok", "{}", reply.body);
            assert_eq!(text(&reply.value, &["sessionId"])?, session);
            assert_eq!(text(&reply.value, &["principalId"])?, PRINCIPAL);
        }
        Ok(reply)
    }

    fn change(
        &self,
        session: &str,
        transition: &str,
        prior: &Reply,
        fields: &str,
        error: Option<&str>,
    ) -> TestResult<Reply> {
        let suffix = if fields.is_empty() {
            String::new()
        } else {
            format!(",{fields}")
        };
        self.investigate(
            session,
            transition,
            &format!(
                "\"claim\":{},\"expected\":{}{suffix}",
                quote(&prior.id()?),
                quote(&prior.fingerprint()?)
            ),
            error,
        )
    }

    fn claim(&self, id: &str) -> TestResult<WorkClaimRevision> {
        let bytes = fs::read(self.root.join("agent/sessions/journal.fssj"))?;
        let recovered = inspect_session_bytes(
            &bytes,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        recovered
            .claims
            .into_iter()
            .find(|head| head.claim().claim_id == id)
            .ok_or_else(|| "missing native claim".into())
    }

    fn handoff_items(&self, session: &str, key: &str) -> TestResult<Vec<String>> {
        let reply = self.call(
            PRINCIPAL,
            "handoff",
            &format!("{{\"session\":{}}}", quote(session)),
            "AOP-012",
            false,
        )?;
        texts(&reply.value, &["payload", key])
    }

    fn compare_cli(
        &self,
        session: &str,
        transition: &str,
        extra: &[&str],
        reply: &Reply,
    ) -> TestResult {
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["investigate", "--json", "--root"])
            .arg(&self.root)
            .args([
                "--principal",
                PRINCIPAL,
                "--session",
                session,
                "--transition",
                transition,
            ])
            .args(extra)
            .output()?;
        assert!(output.status.success(), "{output:?}");
        let body = String::from_utf8(output.stdout)?;
        let value = parse(body.trim_end())?;
        assert_eq!(raw_payload(body.trim_end())?, raw_payload(&reply.body)?);
        for key in [
            "decisionFingerprint",
            "effectiveCapabilities",
            "inputAnchor",
            "contractBasis",
        ] {
            assert_eq!(
                field(&value, &[key])?,
                field(&reply.value, &[key])?,
                "{key}"
            );
        }
        Ok(())
    }

    fn advance_evidence_clock(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(b"synthetic clock-bearing observation")?;
        deployment.append_batch(
            BatchId::parse("batch:mcp-coordination:clock")?,
            vec![EvidenceDelta {
                delta_id: "delta:mcp-coordination:clock".to_owned(),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse("object:mcp-coordination:clock")?,
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

    fn finding_record(&self, reply: &Reply) -> TestResult<(FindingRecord, Vec<u8>)> {
        let pointers = texts(&reply.value, &["proofPointers"])?;
        assert!(pointers.len() >= 2);
        let root = ContentDigest::parse(&pointers[0])?;
        let rendering = ContentDigest::parse(&pointers[1])?;
        let directory = self.root.join("agent/publications");
        let manifest = ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &directory,
            root,
            1 << 20,
        )?)?;
        assert_eq!(manifest.root(), root);
        let record = FindingRecord::from_bytes(&fss_publication::read_verified(
            &directory,
            manifest
                .metadata_digest()
                .ok_or("finding metadata missing")?,
            1 << 20,
        )?)?;
        let bytes = fss_publication::read_verified(&directory, rendering, 1 << 20)?;
        conforms(
            &self.directory.0,
            "agent_finding.v1.json",
            std::str::from_utf8(&bytes)?,
        )?;
        assert_eq!(record.finding_id, reply.id()?);
        assert_eq!(record.principal.as_str(), PRINCIPAL);
        Ok((record, bytes))
    }
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the east door?","decisionInformed":"Whether another observation is needed","hypotheses":[{{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]}},{{"hypothesisId":"h:passerby","description":"A person passed the door","predictions":["the track leaves eastward"]}}],"knowns":[],"unknowns":[{{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}}],"discriminators":[{{"discriminatorId":"d:hallway","description":"Hallway frames","separates":["h:entry","h:passerby"],"expectedOutcomes":["person in hallway","empty hallway"]}}],"probes":["probe:hallway-frames"],"stopRules":["independent observation distinguishes the hypotheses"],"decisionWindowNs":3600000000000}}"#
    )
}

#[test]
fn mcp_claims_enforce_conflict_dependencies_lost_ack_and_transfer_fences() -> TestResult {
    let fixture = Fixture::new("claims")?;
    let first = fixture.open(30_000)?;
    let second = fixture.open(40_000)?;
    assert_ne!(first, second);
    fixture.investigate(
        &first,
        "open",
        &format!("\"draft\":{}", case_document()),
        None,
    )?;
    let authority = fixture.authority()?;

    let opening = format!(r#""case":"{CASE}","work":"probe:probe:hallway-frames","lease_ms":1000"#);
    let claimed = fixture.investigate(&first, "claim", &opening, None)?;
    let probe = claimed.id()?;
    let original = fixture.claim(&probe)?;
    assert_eq!(original.claim().state, WorkClaimState::Claimed);
    assert_eq!(original.digest().to_text(), claimed.fingerprint()?);
    fixture.investigate(&second, "claim", &opening, Some(CONFLICT))?;
    assert_eq!(fixture.claim(&probe)?, original);
    fixture.investigate(
        &second,
        "claim",
        &format!(r#""case":"{CASE}","work":"probe:probe:missing""#),
        Some(PRECONDITION),
    )?;
    let waiting = fixture.investigate(
        &second,
        "claim",
        &format!(
            r#""case":"{CASE}","work":"discriminator:d:hallway","lease_ms":1000,"depends":[{}]"#,
            quote(&probe)
        ),
        None,
    )?;
    let dependent = waiting.id()?;
    fixture.change(&second, "claim-activate", &waiting, "", Some(PRECONDITION))?;
    fixture.change(&second, "claim-activate", &claimed, "", Some(STALE))?;
    let mut leases = vec![probe.clone(), dependent.clone()];
    leases.sort();
    assert_eq!(fixture.handoff_items(&first, "leases")?, leases);

    let active = fixture.change(&first, "claim-activate", &claimed, "", None)?;
    let artifact = ContentDigest::sha256(b"hallway progress artifact").to_text();
    let artifact_field = format!("\"artifact\":{}", quote(&artifact));
    let progressed = fixture.change(&first, "claim-progress", &active, &artifact_field, None)?;
    let recorded_progress = fixture.claim(&probe)?;
    // Losing the first acknowledgement never authorizes reapplying an old revision.
    fixture.change(
        &first,
        "claim-progress",
        &active,
        &artifact_field,
        Some(STALE),
    )?;
    assert_eq!(fixture.claim(&probe)?, recorded_progress);
    let retry = fixture.investigate(&first, "claim", &opening, None)?;
    assert_eq!(retry.fingerprint()?, progressed.fingerprint()?);
    assert_eq!(
        fixture.claim(&probe)?.claim().expires_at_ns,
        original.claim().expires_at_ns
    );
    let inspected = fixture.investigate(
        &first,
        "claim-inspect",
        &format!("\"claim\":{}", quote(&probe)),
        None,
    )?;
    fixture.compare_cli(&first, "claim-inspect", &["--claim", &probe], &inspected)?;
    let blocked = fixture.change(&first, "claim-block", &progressed, &artifact_field, None)?;
    assert_eq!(
        fixture.claim(&probe)?.claim().state,
        WorkClaimState::Blocked
    );
    let resumed = fixture.change(&first, "claim-activate", &blocked, "", None)?;
    fixture.change(
        &first,
        "claim-complete",
        &resumed,
        &format!("\"result\":{}", quote(&artifact)),
        None,
    )?;
    assert_eq!(
        fixture.claim(&probe)?.claim().state,
        WorkClaimState::Completed
    );
    assert_eq!(
        fixture.claim(&probe)?.claim().result_root.as_deref(),
        Some(artifact.as_str())
    );

    let running = fixture.change(&second, "claim-activate", &waiting, "", None)?;
    let renewed = fixture.change(&second, "claim-renew", &running, "\"lease_ms\":2000", None)?;
    let renewed_native = fixture.claim(&dependent)?;
    assert_eq!(renewed_native.claim().expires_at_ns, 2_000_000_000);
    let transferred = fixture.change(
        &second,
        "claim-transfer",
        &renewed,
        &format!("\"recipient\":{}", quote(&first)),
        None,
    )?;
    let transferred_native = fixture.claim(&dependent)?;
    assert_eq!(transferred_native.claim().owner_session_id, first);
    assert_eq!(transferred_native.claim().state, WorkClaimState::Claimed);
    assert_eq!(
        transferred_native.claim().lease_incarnation,
        renewed_native.claim().lease_incarnation + 1
    );
    assert_eq!(
        transferred_native.claim().expires_at_ns,
        renewed_native.claim().expires_at_ns
    );
    fixture.change(&second, "claim-release", &transferred, "", Some(STALE))?;
    let resumed = fixture.change(&first, "claim-activate", &transferred, "", None)?;
    fixture.change(&first, "claim-release", &resumed, "", None)?;
    assert!(fixture.handoff_items(&first, "leases")?.is_empty());
    let listed = fixture.investigate(&first, "claim-list", "", None)?;
    assert_eq!(listed.standings()?.into_keys().collect::<Vec<_>>(), leases);
    assert_eq!(fixture.authority()?, authority);
    Ok(())
}

#[test]
fn mcp_claim_expiry_is_explicit_and_reclaim_preserves_work_under_a_fresh_fence() -> TestResult {
    let fixture = Fixture::new("expiry")?;
    let first = fixture.open(30_000)?;
    let second = fixture.open(40_000)?;
    fixture.investigate(
        &first,
        "open",
        &format!("\"draft\":{}", case_document()),
        None,
    )?;
    let claimed = fixture.investigate(
        &first,
        "claim",
        &format!(r#""case":"{CASE}","work":"case","lease_ms":1"#),
        None,
    )?;
    let id = claimed.id()?;
    let original = fixture.claim(&id)?;
    fixture.change(&second, "claim-expire", &claimed, "", Some(PRECONDITION))?;
    fixture.advance_evidence_clock()?;
    let authority = fixture.authority()?;
    let inspected = fixture.investigate(
        &first,
        "claim-inspect",
        &format!("\"claim\":{}", quote(&id)),
        None,
    )?;
    assert_eq!(inspected.fingerprint()?, claimed.fingerprint()?);
    assert_eq!(
        fixture.claim(&id)?,
        original,
        "reading a lapsed lease never expires or renews it"
    );
    assert!(!fixture.claim(&id)?.lease_covers(TimestampNs(2_000_000)));
    fixture.change(&first, "claim-activate", &claimed, "", Some(PRECONDITION))?;
    let expired = fixture.change(&second, "claim-expire", &claimed, "", None)?;
    assert_eq!(fixture.claim(&id)?.claim().state, WorkClaimState::Expired);
    let reclaimed = fixture.change(
        &second,
        "claim-reclaim",
        &expired,
        "\"lease_ms\":1000",
        None,
    )?;
    let recovered = fixture.claim(&id)?;
    assert_eq!(recovered.work_root(), original.work_root());
    assert_eq!(recovered.claim().owner_session_id, second);
    assert_eq!(
        recovered.claim().lease_incarnation,
        original.claim().lease_incarnation + 1
    );
    assert_eq!(recovered.claim().expires_at_ns, 1_002_000_000);
    fixture.change(&first, "claim-release", &expired, "", Some(STALE))?;
    fixture.change(&second, "claim-release", &reclaimed, "", None)?;
    assert_eq!(fixture.claim(&id)?.claim().state, WorkClaimState::Released);
    assert_eq!(fixture.authority()?, authority);
    Ok(())
}

#[test]
fn mcp_findings_preserve_disagreement_and_immutable_supersession_and_withdrawal() -> TestResult {
    let fixture = Fixture::new("findings")?;
    let first = fixture.open(30_000)?;
    let second = fixture.open(40_000)?;
    let case = fixture.investigate(
        &first,
        "open",
        &format!("\"draft\":{}", case_document()),
        None,
    )?;
    let authority = fixture.authority()?;
    let hallway = ContentDigest::sha256(b"synthetic hallway evidence handle").to_text();
    let street = ContentDigest::sha256(b"synthetic street evidence handle").to_text();
    let entry_fields = format!(
        r#""case":"{CASE}","hypothesis":"h:entry","claim":"A person entered.","state":"estimated","supporting":[{}],"follow_up":["probe:hallway-frames"]"#,
        quote(&hallway)
    );
    let entry = fixture.investigate(&first, "finding", &entry_fields, None)?;
    let entry_id = entry.id()?;
    let (entry_record, entry_rendering) = fixture.finding_record(&entry)?;
    assert_eq!(entry_record.case_revision.to_text(), case.fingerprint()?);
    assert_eq!(entry_record.session_id.as_str(), first);
    assert_eq!(entry.standings()?[&entry_id], "estimated");
    let published = tree(&fixture.root, &["agent/publications"])?;
    // An exact ordinary publish retry recovers the prior publication after a lost response.
    let retry = fixture.investigate(&first, "finding", &entry_fields, None)?;
    assert_eq!(retry.id()?, entry_id);
    assert_eq!(retry.fingerprint()?, entry.fingerprint()?);
    assert_eq!(tree(&fixture.root, &["agent/publications"])?, published);

    let passerby = fixture.investigate(
        &second,
        "finding",
        &format!(
            r#""case":"{CASE}","hypothesis":"h:passerby","claim":"The person left eastward.","state":"estimated","supporting":[{}],"contradicting":[{}],"disagrees_with":[{}]"#,
            quote(&street), quote(&hallway), quote(&entry_id)
        ),
        None,
    )?;
    let passerby_id = passerby.id()?;
    let (passerby_record, _) = fixture.finding_record(&passerby)?;
    assert_eq!(passerby_record.disagrees_with, vec![entry_id.clone()]);
    assert_eq!(passerby_record.contradicting, vec![hallway.clone()]);
    assert_eq!(passerby.standings()?[&passerby_id], "conflicted");
    let board = fixture.investigate(&first, "finding-list", "", None)?;
    assert_eq!(
        board.standings()?,
        BTreeMap::from([
            (entry_id.clone(), "conflicted".to_owned()),
            (passerby_id.clone(), "conflicted".to_owned()),
        ])
    );
    fixture.compare_cli(&first, "finding-list", &[], &board)?;
    assert!(
        texts(&board.value, &["degradation"])?
            .iter()
            .any(|line| line.starts_with("Unresolved conflict:"))
    );
    let moves = array(&board.value, &["affordances"])?
        .iter()
        .map(|item| Ok(text(item, &["affordanceId"])?.to_owned()))
        .collect::<TestResult<Vec<_>>>()?;
    for id in [&entry_id, &passerby_id] {
        assert!(moves.contains(&format!("affordance:finding:{id}")));
    }
    let mut active = vec![entry_id.clone(), passerby_id.clone()];
    active.sort();
    assert_eq!(fixture.handoff_items(&first, "findings")?, active);
    assert_eq!(
        fixture.finding_record(&entry)?,
        (entry_record.clone(), entry_rendering.clone())
    );
    fixture.investigate(
        &second,
        "finding",
        &format!(
            r#""case":"{CASE}","claim":"Unrelated disagreement.","state":"unknown","supporting":[{}],"disagrees_with":["finding:missing"]"#,
            quote(&street)
        ),
        Some(PRECONDITION),
    )?;

    let correction_fields = format!(
        r#""case":"{CASE}","hypothesis":"h:passerby","claim":"Street evidence supports passing the door.","state":"estimated","supporting":[{}],"supersedes":{}"#,
        quote(&street),
        quote(&entry_id)
    );
    let corrected = fixture.investigate(&first, "finding", &correction_fields, None)?;
    let corrected_id = corrected.id()?;
    let (corrected_record, _) = fixture.finding_record(&corrected)?;
    assert_eq!(
        corrected_record.supersedes.as_deref(),
        Some(entry_id.as_str())
    );
    let supersession_closure = tree(&fixture.root, &["agent/publications"])?;
    let retry = fixture.investigate(&first, "finding", &correction_fields, None)?;
    assert_eq!(retry.id()?, corrected_id);
    assert_eq!(retry.fingerprint()?, corrected.fingerprint()?);
    assert_eq!(fixture.finding_record(&retry)?.0, corrected_record);
    assert_eq!(
        tree(&fixture.root, &["agent/publications"])?,
        supersession_closure
    );
    // Same principal does not make another author session's request the identical publication.
    fixture.investigate(&second, "finding", &correction_fields, Some(STALE))?;
    let board = fixture.investigate(
        &first,
        "finding-list",
        &format!("\"case\":{}", quote(CASE)),
        None,
    )?;
    assert_eq!(board.standings()?[&entry_id], "stale");
    assert_eq!(board.standings()?[&passerby_id], "estimated");
    assert_eq!(board.standings()?[&corrected_id], "estimated");
    assert!(
        !texts(&board.value, &["degradation"])?
            .iter()
            .any(|line| line.starts_with("Unresolved conflict:"))
    );
    let closure_before = tree(&fixture.root, &["agent/publications"])?;
    fixture.investigate(
        &first,
        "finding",
        &correction_fields.replace(
            "Street evidence supports passing the door.",
            "A competing second correction.",
        ),
        Some(STALE),
    )?;
    assert_eq!(
        tree(&fixture.root, &["agent/publications"])?,
        closure_before
    );

    let withdrawal_fields = format!(
        r#""finding":{},"claim":"The corrected finding replaces this one.","supporting":[{}]"#,
        quote(&passerby_id),
        quote(&street)
    );
    let withdrawn = fixture.investigate(&second, "finding-withdraw", &withdrawal_fields, None)?;
    let (withdrawal_record, withdrawal_rendering) = fixture.finding_record(&withdrawn)?;
    assert!(withdrawal_record.withdrawn);
    assert_eq!(
        withdrawal_record.supersedes.as_deref(),
        Some(passerby_id.as_str())
    );
    let withdrawal_closure = tree(&fixture.root, &["agent/publications"])?;
    let retry = fixture.investigate(&second, "finding-withdraw", &withdrawal_fields, None)?;
    assert_eq!(retry.id()?, withdrawn.id()?);
    assert_eq!(retry.fingerprint()?, withdrawn.fingerprint()?);
    assert_eq!(fixture.finding_record(&retry)?.0, withdrawal_record);
    assert_eq!(
        tree(&fixture.root, &["agent/publications"])?,
        withdrawal_closure
    );
    fixture.investigate(
        &second,
        "finding-withdraw",
        &withdrawal_fields.replace(
            "The corrected finding replaces this one.",
            "A different withdrawal reason.",
        ),
        Some(STALE),
    )?;
    fixture.investigate(&first, "finding-withdraw", &withdrawal_fields, Some(STALE))?;
    let rendered = parse(std::str::from_utf8(&withdrawal_rendering)?)?;
    assert_eq!(field(&rendered, &["withdrawn"])?, &Value::Bool(true));
    assert_eq!(
        fixture.handoff_items(&second, "findings")?,
        vec![corrected_id]
    );
    let board = fixture.investigate(&second, "finding-list", "", None)?;
    assert_eq!(board.standings()?[&passerby_id], "stale");
    assert_eq!(board.standings()?[&withdrawn.id()?], "stale");
    assert_eq!(
        fixture.finding_record(&entry)?,
        (entry_record, entry_rendering)
    );
    let final_closure = tree(&fixture.root, &["agent/publications"])?;
    // A later case revision is another basis, never an exact retry of the prior publication.
    fixture.investigate(
        &first,
        "activate",
        &format!(
            "\"case\":{},\"expected\":{}",
            quote(CASE),
            quote(&case.fingerprint()?)
        ),
        None,
    )?;
    fixture.investigate(&first, "finding", &correction_fields, Some(STALE))?;
    fixture.investigate(&second, "finding-withdraw", &withdrawal_fields, Some(STALE))?;
    assert_eq!(tree(&fixture.root, &["agent/publications"])?, final_closure);
    assert_eq!(fixture.authority()?, authority);
    Ok(())
}

#[test]
fn mcp_coordination_refuses_malformed_or_foreign_requests_before_mutation() -> TestResult {
    let fixture = Fixture::new("refusal")?;
    let session = fixture.open(30_000)?;
    fixture.investigate(
        &session,
        "open",
        &format!("\"draft\":{}", case_document()),
        None,
    )?;
    let before = tree(&fixture.root, &[""])?;
    let digest = ContentDigest::sha256(b"synthetic finding support").to_text();
    let acquire = format!(
        r#""session":{},"transition":"claim","case":"{CASE}","work":"case""#,
        quote(&session)
    );
    let finding = format!(
        r#""session":{},"transition":"finding","case":"{CASE}","claim":"Literal observation.","state":"estimated","supporting":[{}]"#,
        quote(&session),
        quote(&digest)
    );
    let mut invalid = Vec::new();
    for suffix in [
        r#""lease_ms":"1000""#,
        r#""lease_ms":1e3"#,
        r#""lease_ms":1000.0"#,
        r#""lease_ms":0"#,
        r#""lease_ms":300001"#,
        r#""lease_ms":true"#,
        r#""depends":"claim:a,claim:b""#,
        r#""depends":["claim:a,claim:b"]"#,
        r#""depends":["claim:a",false]"#,
        r#""depends":["claim:a","claim:a"]"#,
        r#""principal":"principal:other""#,
        r#""root":"/other""#,
        r#""case_file":"/private/operator-notes""#,
        r#""result":"sha256:bad""#,
    ] {
        invalid.push(format!("{{{acquire},{suffix}}}"));
    }
    for suffix in [
        r#""disagrees_with":["finding:a,finding:b"]"#.to_owned(),
        r#""follow_up":["probe:a",null]"#.to_owned(),
        r#""supersedes":[]"#.to_owned(),
        r#""expected":"sha256:bad""#.to_owned(),
        format!(r#""contradicting":["{digest}","{digest}"]"#),
    ] {
        invalid.push(format!("{{{finding},{suffix}}}"));
    }
    invalid.extend([
        format!(r#"{{"session":{},"transition":"claim-activate","claim":"claim:missing"}}"#, quote(&session)),
        format!(r#"{{"session":{},"transition":"claim-inspect","claim":"../private"}}"#, quote(&session)),
        format!(r#"{{"session":{},"transition":"claim-execute"}}"#, quote(&session)),
        format!(r#"{{"session":{},"transition":"finding-withdraw","finding":"finding:a","claim":"Withdraw","supporting":[]}}"#, quote(&session)),
    ]);
    for arguments in invalid {
        let reply = fixture.exchange(PRINCIPAL, "investigate", &arguments)?;
        assert_eq!(
            field(&reply, &["error", "code"])?.integer(),
            Some(-32602),
            "{arguments}"
        );
        assert_eq!(tree(&fixture.root, &[""])?, before, "{arguments}");
    }
    for transition in ["claim-list", "finding-list"] {
        let reply = fixture.call(
            STRANGER,
            "investigate",
            &format!(
                r#"{{"session":{},"transition":"{transition}"}}"#,
                quote(&session)
            ),
            "AOP-006",
            true,
        )?;
        assert_eq!(text(&reply.value, &["outcome"])?, "refused");
        assert_eq!(field(&reply.value, &["payload"])?, &Value::Null);
        assert_eq!(text(&reply.value, &["principalId"])?, STRANGER);
        assert_eq!(tree(&fixture.root, &[""])?, before);
    }
    Ok(())
}
