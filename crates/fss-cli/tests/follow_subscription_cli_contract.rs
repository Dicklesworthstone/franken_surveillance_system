#![forbid(unsafe_code)]
//! Durable AOP-004 contracts through fresh CLI and MCP processes over real deployment files.
//! The fixtures append explicitly synthetic metadata and effect records; no device or provider
//! is contacted. Every semantic response is checked against the registered public schemas.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::json_input::{self, Value};
use fss_core::{
    BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent,
    EvidenceDelta, IdempotencyKey, ObjectId, ObligationId, OperationId, Plane, RootAuthoritySpec,
    TimestampNs,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:follow-subscription-cli";
const PRINCIPAL: &str = "principal:follow-subscription-cli";
const CASE: &str = "case:follow-subscription:door";
const RECEIPT_PREFIX: &str = "continuation:follow-ack:";
const ITEM_FIELDS: [&str; 6] = [
    "changedCells",
    "removedClaimIds",
    "invalidatedAssumptions",
    "coverageChanges",
    "obligationChanges",
    "effectUncertaintyChanges",
];

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing object field {key}").into())
}

fn text<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("{key} is not text").into())
}

fn array<'a>(value: &'a Value, key: &str) -> TestResult<&'a [Value]> {
    field(value, key)?
        .array()
        .ok_or_else(|| format!("{key} is not an array").into())
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

fn commit(value: &Value, key: &str) -> TestResult<i128> {
    field(field(value, "payload")?, key)?
        .object()
        .and_then(|anchor| anchor.get("capsuleSequence"))
        .and_then(Value::integer)
        .ok_or_else(|| format!("{key} has no exact commit sequence").into())
}

fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("missing payload")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("missing payload digest")?;
    Ok(&stdout[start..end])
}

fn repository_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("../..")
}

fn conforms(scratch: &Path, schema: &str, instance: &str) -> TestResult {
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(instance.as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, instance)?;
    let root = repository_root();
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
    fn parse(body: String, scratch: &Path, operation: &str, schema: &str) -> TestResult<Self> {
        assert_eq!(body.lines().count(), 1, "one complete JSON document");
        assert!(body.trim_end().ends_with('}'));
        let value = json_input::parse(&body)?;
        assert_eq!(text(&value, "schema")?, "fss.agent_response_envelope.v1");
        assert_eq!(text(&value, "operationId")?, operation);
        assert_eq!(field(&value, "outputAnchor")?, &Value::Null);
        assert_eq!(
            text(&value, "payloadDigest")?,
            ContentDigest::sha256(raw_payload(&body)?.as_bytes()).to_text(),
            "the public digest commits the exact rendered payload bytes"
        );
        conforms(scratch, "agent_response_envelope.v1.json", &body)?;
        if raw_payload(&body)? != "null" {
            conforms(scratch, schema, raw_payload(&body)?)?;
        }
        Ok(Self { body, value })
    }

    fn receipt(&self) -> TestResult<ContentDigest> {
        let continuation = text(&self.value, "continuation")?;
        let raw = continuation
            .strip_prefix(RECEIPT_PREFIX)
            .ok_or("continuation is not an explicit follow ACK receipt")?;
        assert_eq!(
            field(field(&self.value, "payload")?, "continuation")?,
            field(&self.value, "continuation")?
        );
        assert_eq!(pointer(&self.value, "follow-delivery:")?, raw);
        Ok(ContentDigest::parse(raw)?)
    }

    fn assert_bound(&self, fixture: &Fixture) -> TestResult {
        assert_eq!(text(&self.value, "sessionId")?, fixture.session);
        assert_eq!(text(&self.value, "missionId")?, fixture.mission);
        assert_eq!(text(&self.value, "outcome")?, "ok");
        assert_eq!(field(&self.value, "errorId")?, &Value::Null);
        assert_eq!(
            text(field(&self.value, "payload")?, "sessionId")?,
            fixture.session,
            "the sealed native delta and response envelope have the same durable identity"
        );
        assert_eq!(text(&self.value, "effectiveViewId")?, "AVIEW-002");
        assert_eq!(
            text(&self.value, "payloadSchema")?,
            "fss.agent_meaningful_delta.v1"
        );
        self.receipt()?;
        Ok(())
    }
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-follow-subscription-cli-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("no unused fixture directory".into())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: OwnedDirectory,
    root: PathBuf,
    cx: ReplayCx,
    commits: u64,
    session: String,
    mission: String,
    since: String,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let directory = OwnedDirectory::new(tag)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:follow-subscription-cli:{tag}"),
            operation_id: OperationId::parse(format!("operation:follow-subscription-cli:{tag}"))?,
            principal: "operator:follow-subscription-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit subscription CLI fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            directory.0.join("cx"),
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        let mut args = vec![OsString::from("session"), OsString::from("open")];
        args.extend(common_args(&root));
        args.extend(
            [
                "--mission",
                "Observe every retained deployment transition",
                "--objective",
                "Preserve uncertainty and explicit delivery acknowledgement",
                "--view",
                "brief",
                "--budget-tokens",
                "100000",
            ]
            .map(OsString::from),
        );
        let body = run_fss(&args, 0)?;
        let opened = Reply::parse(body, &directory.0, "AOP-001", "situation_capsule.v1.json")?;
        let session = text(&opened.value, "sessionId")?.to_owned();
        let mission = text(&opened.value, "missionId")?.to_owned();
        let since = format!("anchor:{}", pointer(&opened.value, "anchor:")?);
        assert!(AnchorToken::parse(&since).is_some());
        Ok(Self {
            directory,
            root,
            cx,
            commits: 0,
            session,
            mission,
            since,
        })
    }

    fn append(&mut self) -> TestResult {
        self.commits += 1;
        let index = self.commits;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(format!("synthetic metadata {index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:follow-subscription:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:follow-subscription:{index}"),
                family: "decode_receipt".to_owned(),
                object_id: ObjectId::parse(format!("object:follow-subscription:{index}"))?,
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
                operation_id: OperationId::parse("operation:follow-subscription:synthetic")?,
                idempotency_key: IdempotencyKey::parse(
                    "idempotency:follow-subscription:synthetic",
                )?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"synthetic observation request"),
                precondition_digest: ContentDigest::sha256(b"synthetic precondition"),
            },
            ObligationId::parse("obligation:follow-subscription:synthetic")?,
            "synthetic observation verified",
            TimestampNs(100),
        )?;
        Ok(())
    }

    fn open_case(&self) -> TestResult<Reply> {
        let path = self.directory.0.join("follow-case.json");
        fs::write(
            &path,
            format!(
                r#"{{"caseId":"{CASE}","question":"Did a person enter?",
"decisionInformed":"Whether an owner alert needs preparation",
"hypotheses":[{{"hypothesisId":"h:entry","description":"Entered","predictions":["Hallway track"]}},
{{"hypothesisId":"h:passerby","description":"Passed","predictions":["Exterior only"]}}],
"stopRules":["An independent observation distinguishes the alternatives"],
"decisionWindowNs":3600000000000}}"#
            ),
        )?;
        let mut args = vec![OsString::from("investigate")];
        args.extend(common_args(&self.root));
        args.extend(
            [
                "--session",
                &self.session,
                "--transition",
                "open",
                "--case-file",
            ]
            .map(OsString::from),
        );
        args.push(path.into_os_string());
        Reply::parse(
            run_fss(&args, 0)?,
            &self.directory.0,
            "AOP-006",
            "investigation_state.v1.json",
        )
    }

    fn cancel_case(&self, revision: &str) -> TestResult<Reply> {
        let reason =
            ContentDigest::sha256(b"explicitly withdraw the fixture investigation").to_text();
        let mut args = vec![OsString::from("investigate")];
        args.extend(common_args(&self.root));
        args.extend(
            [
                "--session",
                &self.session,
                "--transition",
                "set-state",
                "--case",
                CASE,
                "--expected",
                revision,
                "--state",
                "cancelled",
                "--reason",
                &reason,
            ]
            .map(OsString::from),
        );
        Reply::parse(
            run_fss(&args, 0)?,
            &self.directory.0,
            "AOP-006",
            "investigation_state.v1.json",
        )
    }

    fn orient(&self) -> TestResult<Reply> {
        let mut args = vec![OsString::from("orient")];
        args.extend(common_args(&self.root));
        args.extend(["--session", &self.session, "--view", "brief"].map(OsString::from));
        Reply::parse(
            run_fss(&args, 0)?,
            &self.directory.0,
            "AOP-003",
            "situation_capsule.v1.json",
        )
    }

    fn args(&self, label: &str, size: u32, ack: Option<ContentDigest>) -> Vec<OsString> {
        let mut args = vec![OsString::from("follow")];
        args.extend(common_args(&self.root));
        for (key, value) in [
            ("--since", self.since.clone()),
            ("--session", self.session.clone()),
            ("--subscription", label.to_owned()),
            ("--view", "brief".to_owned()),
            ("--max-entries", size.to_string()),
        ] {
            args.push(key.into());
            args.push(value.into());
        }
        if let Some(receipt) = ack {
            args.push("--acknowledge".into());
            args.push(receipt.to_text().into());
        }
        args
    }

    fn follow(&self, label: &str, size: u32, ack: Option<ContentDigest>) -> TestResult<Reply> {
        let reply = self.command(&self.args(label, size, ack), 0)?;
        reply.assert_bound(self)?;
        Ok(reply)
    }

    fn command(&self, args: &[OsString], code: i32) -> TestResult<Reply> {
        Reply::parse(
            run_fss(args, code)?,
            &self.directory.0,
            "AOP-004",
            "agent_meaningful_delta.v1.json",
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

    fn mcp(
        &self,
        label: &str,
        size: u32,
        ack: Option<ContentDigest>,
        error: bool,
    ) -> TestResult<Reply> {
        let quote = |text: &str| format!("\"{}\"", fss_cli::escape_json_str(text));
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"follow-subscription-contract","version":"1"}}}"#;
        let ready = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let acknowledge = ack.map_or_else(String::new, |receipt| {
            format!(",\"acknowledge\":{}", quote(&receipt.to_text()))
        });
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"session":{},"subscription":{},"view":"brief","max_entries":{size}{acknowledge}}}}}}}"#,
            quote(&self.since),
            quote(&self.session),
            quote(label),
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .args([
                "--root",
                self.root.to_str().ok_or("fixture root UTF-8")?,
                "--principal",
                PRINCIPAL,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin")?;
        writeln!(input, "{init}\n{ready}\n{request}")?;
        drop(input);
        let output = child.wait_with_output()?;
        assert_output(&output, 0);
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(
            lines.len(),
            2,
            "one initialize response and one tool response"
        );
        let wire = json_input::parse(lines[1])?;
        let result = field(&wire, "result")?;
        assert_eq!(field(result, "isError")?, &Value::Bool(error));
        let content = array(result, "content")?;
        assert_eq!(content.len(), 1);
        Reply::parse(
            text(&content[0], "text")?.to_owned(),
            &self.directory.0,
            "AOP-004",
            "agent_meaningful_delta.v1.json",
        )
    }
}

fn common_args(root: &Path) -> Vec<OsString> {
    vec![
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--principal".into(),
        PRINCIPAL.into(),
    ]
}

fn assert_output(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_fss(args: &[OsString], expected: i32) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    assert_output(&output, expected);
    assert!(output.stderr.is_empty());
    Ok(String::from_utf8(output.stdout)?)
}

fn authority_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut pending = ["ledger", "effects", "objects", "LAYOUT"]
        .map(|prefix| root.join(prefix))
        .to_vec();
    let mut tree = BTreeMap::new();
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else {
            tree.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(path)?),
            );
        }
    }
    Ok(tree)
}

#[test]
fn pending_delivery_survives_cli_restart_and_mcp_resume_with_exact_ack_identity() -> TestResult {
    let mut fixture = Fixture::new("restart")?;
    for _ in 0..3 {
        fixture.append()?;
    }
    let original_authority = authority_tree(&fixture.root)?;
    let first = fixture.follow("watch", 64, None)?;
    assert_eq!(commit(&first.value, "basisAnchor")?, 0);
    assert_eq!(commit(&first.value, "resultAnchor")?, 1);
    let frozen = pointer(&first.value, "follow-horizon:")?.to_owned();
    assert_eq!(
        AnchorToken::parse(&frozen)
            .ok_or("horizon")?
            .position()
            .commit_sequence,
        3
    );
    let receipt = first.receipt()?;
    let first_journal = fixture.journal()?;
    let repeated = fixture.follow("watch", 64, None)?;
    let mcp_repeated = fixture.mcp("watch", 64, None, false)?;
    mcp_repeated.assert_bound(&fixture)?;
    for retry in [&repeated, &mcp_repeated] {
        assert_eq!(retry.receipt()?, receipt);
        assert_eq!(
            field(&retry.value, "payload")?,
            field(&first.value, "payload")?
        );
        assert_eq!(
            pointer(&retry.value, "follow-journal:")?,
            pointer(&first.value, "follow-journal:")?
        );
    }
    assert_eq!(
        fixture.journal()?,
        first_journal,
        "redelivery records no implicit ACK"
    );
    assert_eq!(authority_tree(&fixture.root)?, original_authority);

    // A new committed head does not replace the original replay window. The explicit MCP ACK
    // advances exactly one transition and a lost-response retry must not consume its successor.
    fixture.append()?;
    let authority = authority_tree(&fixture.root)?;
    let second = fixture.mcp("watch", 64, Some(receipt), false)?;
    second.assert_bound(&fixture)?;
    assert_eq!(commit(&second.value, "basisAnchor")?, 1);
    assert_eq!(commit(&second.value, "resultAnchor")?, 2);
    assert_eq!(pointer(&second.value, "follow-horizon:")?, frozen);
    assert_eq!(
        pointer(&second.value, "follow-acknowledged:")?,
        receipt.to_text()
    );
    let after_ack = fixture.journal()?;
    let lost_ack_retry = fixture.follow("watch", 64, Some(receipt))?;
    assert_eq!(lost_ack_retry.receipt()?, second.receipt()?);
    assert_eq!(
        field(&lost_ack_retry.value, "payload")?,
        field(&second.value, "payload")?
    );
    assert_eq!(fixture.journal()?, after_ack);
    let third = fixture.follow("watch", 64, Some(second.receipt()?))?;
    assert_eq!(commit(&third.value, "basisAnchor")?, 2);
    assert_eq!(commit(&third.value, "resultAnchor")?, 3);
    assert_eq!(pointer(&third.value, "follow-horizon:")?, frozen);
    assert_eq!(
        authority_tree(&fixture.root)?,
        authority,
        "delivery only changes agent state"
    );
    Ok(())
}

#[test]
fn every_native_item_is_delivered_before_acknowledgement_advances_the_anchor() -> TestResult {
    let mut fixture = Fixture::new("pages")?;
    fixture.append()?;
    fixture.append()?;
    let all = fixture.follow("complete-comparison", 64, None)?;
    let payload = field(&all.value, "payload")?;
    let mut expected = BTreeMap::new();
    let mut seen = BTreeMap::new();
    for key in ITEM_FIELDS {
        expected.insert(key, array(payload, key)?.to_vec());
        seen.insert(key, Vec::new());
    }
    let count = expected.values().map(Vec::len).sum::<usize>();
    assert!(
        count > 1 && count <= 64,
        "fixture must exercise real pagination: {count}"
    );
    let mut current = fixture.follow("paged", 1, None)?;
    let mut receipts = Vec::new();
    for index in 0..count {
        let page = field(&current.value, "payload")?;
        assert_eq!(commit(&current.value, "basisAnchor")?, 0);
        assert_eq!(commit(&current.value, "resultAnchor")?, 1);
        assert_eq!(
            field(page, "classes")?,
            field(payload, "classes")?,
            "protected class header survives every page"
        );
        let mut delivered = 0;
        for key in ITEM_FIELDS {
            let items = array(page, key)?;
            delivered += items.len();
            seen.get_mut(key)
                .ok_or("item bucket")?
                .extend_from_slice(items);
        }
        assert_eq!(delivered, 1);
        let receipt = current.receipt()?;
        assert!(
            !receipts.contains(&receipt),
            "each page has a different exact ACK receipt"
        );
        receipts.push(receipt);
        let inspection = fixture.inspect()?;
        let subscription = inspection
            .follows
            .iter()
            .find(|entry| entry.registration().subscription_id == "paged")
            .ok_or("paged subscription")?;
        assert_eq!(subscription.acknowledged_anchor(), fixture.since);
        assert_eq!(
            subscription.pending().ok_or("pending page")?.receipt(),
            receipt
        );
        if index + 1 < count {
            current = fixture.follow("paged", 1, Some(receipt))?;
        }
    }
    assert_eq!(
        seen, expected,
        "every native item appears exactly once in the acknowledged page order"
    );
    let next = fixture.follow("paged", 1, Some(current.receipt()?))?;
    assert_eq!(commit(&next.value, "basisAnchor")?, 1);
    assert_eq!(commit(&next.value, "resultAnchor")?, 2);
    Ok(())
}

#[test]
fn wrong_ack_scope_and_principal_cannot_consume_an_existing_pending_page() -> TestResult {
    let mut fixture = Fixture::new("refused")?;
    fixture.append()?;
    let first = fixture.follow("watch", 64, None)?;
    let before = fixture.journal()?;
    let wrong = ContentDigest::sha256(b"not a delivered receipt");
    for args in [
        fixture.args("watch", 64, Some(wrong)),
        fixture.args("watch", 1, None),
    ] {
        let refused = fixture.command(&args, 5)?;
        assert_eq!(
            text(&refused.value, "errorId")?,
            fss_cli::session_cmd::ERR_PRECONDITION_STALE
        );
        assert_eq!(field(&refused.value, "payload")?, &Value::Null);
        assert_eq!(field(&refused.value, "continuation")?, &Value::Null);
        assert!(
            array(&refused.value, "proofPointers")?
                .iter()
                .filter_map(Value::text)
                .all(|p| !p.starts_with("follow-acknowledged:"))
        );
        assert_eq!(
            fixture.journal()?,
            before,
            "a conflicting request cannot advance delivery"
        );
    }
    let mut other = fixture.args("watch", 64, Some(first.receipt()?));
    let index = other
        .iter()
        .position(|arg| arg == "--principal")
        .ok_or("principal option")?;
    other[index + 1] = "principal:someone-else".into();
    let denied = fixture.command(&other, 5)?;
    assert_eq!(
        text(&denied.value, "errorId")?,
        fss_cli::session_cmd::ERR_AGENT_SESSION_NOT_FOUND
    );
    assert_eq!(field(&denied.value, "sessionId")?, &Value::Null);
    assert_eq!(field(&denied.value, "payload")?, &Value::Null);
    assert_eq!(fixture.journal()?, before);
    let retry = fixture.follow("watch", 64, None)?;
    assert_eq!(retry.receipt()?, first.receipt()?);
    assert_eq!(raw_payload(&retry.body)?, raw_payload(&first.body)?);
    Ok(())
}

#[test]
fn mixed_journal_order_returns_schema_valid_resnapshot_without_delivery_or_ack() -> TestResult {
    let mut fixture = Fixture::new("mixed")?;
    fixture.append()?;
    fixture.prepare()?;
    let authority = authority_tree(&fixture.root)?;
    let refused = fixture.command(&fixture.args("watch", 64, None), 5)?;
    let mcp_refused = fixture.mcp("watch", 64, None, true)?;
    for reply in [&refused, &mcp_refused] {
        assert_eq!(text(&reply.value, "errorId")?, "ERR-AGENT-RESNAPSHOT-001");
        assert_eq!(text(&reply.value, "outcome")?, "partial");
        assert_eq!(
            field(&reply.value, "resnapshotRequired")?,
            &Value::Bool(true)
        );
        assert_eq!(field(&reply.value, "payload")?, &Value::Null);
        assert_eq!(field(&reply.value, "continuation")?, &Value::Null);
    }
    let recovered = fixture.inspect()?;
    assert_eq!(recovered.follows.len(), 1);
    assert_eq!(recovered.follows[0].acknowledged_anchor(), fixture.since);
    assert!(recovered.follows[0].pending().is_none());
    assert_eq!(recovered.follows[0].last_acknowledged(), None);
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}

fn case_purpose(reply: &Reply) -> TestResult<&str> {
    let id = format!("affordance:investigate:{CASE}");
    let affordance = array(&reply.value, "affordances")?
        .iter()
        .find(|value| text(value, "affordanceId").is_ok_and(|value| value == id.as_str()))
        .ok_or("the bound case must remain an explicit next affordance")?;
    text(affordance, "purpose")
}

fn assert_resnapshot_without_ack(reply: &Reply) -> TestResult {
    assert_eq!(text(&reply.value, "errorId")?, "ERR-AGENT-RESNAPSHOT-001");
    assert_eq!(text(&reply.value, "outcome")?, "partial");
    assert_eq!(
        field(&reply.value, "resnapshotRequired")?,
        &Value::Bool(true)
    );
    assert_eq!(field(&reply.value, "payload")?, &Value::Null);
    assert_eq!(field(&reply.value, "continuation")?, &Value::Null);
    assert!(
        array(&reply.value, "proofPointers")?
            .iter()
            .filter_map(Value::text)
            .all(|value| !value.starts_with("follow-acknowledged:")),
        "a semantic refusal must not claim the pending page was acknowledged"
    );
    Ok(())
}

#[test]
fn populated_case_follow_redelivers_across_transports_and_classifies_evidence_advance() -> TestResult
{
    let mut fixture = Fixture::new("populated-replay")?;
    let opened = fixture.open_case()?;
    assert_eq!(
        text(field(&opened.value, "payload")?, "investigationId")?,
        CASE
    );
    let orientation = fixture.orient()?;
    assert_eq!(text(&orientation.value, "missionId")?, fixture.mission);
    assert!(
        array(
            field(&orientation.value, "payload")?,
            "activeInvestigations"
        )?
        .iter()
        .filter_map(Value::text)
        .any(|value| value == CASE)
    );
    let authority = authority_tree(&fixture.root)?;
    let first = fixture.follow("populated", 64, None)?;
    assert_eq!(commit(&first.value, "basisAnchor")?, 0);
    assert_eq!(commit(&first.value, "resultAnchor")?, 0);
    assert_eq!(
        text(field(&first.value, "payload")?, "resultFrameId")?,
        text(
            field(field(&orientation.value, "payload")?, "situationFrame")?,
            "frameId"
        )?,
        "follow retains the real mission/case situation instead of projecting empty facets"
    );
    assert!(case_purpose(&first)?.contains("still discriminates"));
    let pending = first.receipt()?;
    let journal = fixture.journal()?;
    let cli_retry = fixture.follow("populated", 64, None)?;
    let mcp_retry = fixture.mcp("populated", 64, None, false)?;
    mcp_retry.assert_bound(&fixture)?;
    for retry in [&cli_retry, &mcp_retry] {
        assert_eq!(retry.receipt()?, pending);
        assert_eq!(raw_payload(&retry.body)?, raw_payload(&first.body)?);
        assert_eq!(case_purpose(retry)?, case_purpose(&first)?);
    }
    assert_eq!(fixture.journal()?, journal);
    assert_eq!(authority_tree(&fixture.root)?, authority);

    // Evidence advances independently of the retained case revision. The successor must
    // explain that the case needs rebasing without rewriting its original basis.
    fixture.append()?;
    let authority = authority_tree(&fixture.root)?;
    let advanced = fixture.mcp("populated", 64, Some(pending), false)?;
    advanced.assert_bound(&fixture)?;
    assert_eq!(commit(&advanced.value, "basisAnchor")?, 0);
    assert_eq!(commit(&advanced.value, "resultAnchor")?, 1);
    assert_eq!(
        text(field(&advanced.value, "payload")?, "basisFrameId")?,
        text(field(&first.value, "payload")?, "resultFrameId")?,
        "a later case rebase warning cannot be copied into the earlier evidence snapshot"
    );
    assert!(case_purpose(&advanced)?.contains("rebase it before any change"));
    assert!(
        array(field(&advanced.value, "payload")?, "classes")?
            .iter()
            .filter_map(Value::text)
            .any(|class| class == "material_state")
    );
    let journal = fixture.journal()?;
    let lost_ack_reply = fixture.follow("populated", 64, Some(pending))?;
    assert_eq!(lost_ack_reply.receipt()?, advanced.receipt()?);
    assert_eq!(
        raw_payload(&lost_ack_reply.body)?,
        raw_payload(&advanced.body)?
    );
    assert_eq!(fixture.journal()?, journal);
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}

#[test]
fn populated_case_follow_requires_current_head_for_a_new_subscription() -> TestResult {
    let mut fixture = Fixture::new("populated-start")?;
    fixture.open_case()?;
    fixture.append()?;
    let refused = fixture.command(&fixture.args("historical", 64, None), 5)?;
    // Live admission can persist the newer evidence clock even on refusal. Once admitted,
    // another transport must neither add a subscription nor acknowledge any delivery.
    let before = fixture.journal()?;
    let mcp_refused = fixture.mcp("historical", 64, None, true)?;
    assert_resnapshot_without_ack(&refused)?;
    assert_resnapshot_without_ack(&mcp_refused)?;
    assert_eq!(fixture.journal()?, before);
    assert!(fixture.inspect()?.follows.is_empty());

    // Resnapshot is an explicit read; the fresh subscription starts at that exact head.
    let orientation = fixture.orient()?;
    fixture.since = format!("anchor:{}", pointer(&orientation.value, "anchor:")?);
    let fresh = fixture.mcp("current", 64, None, false)?;
    fresh.assert_bound(&fixture)?;
    assert_eq!(commit(&fresh.value, "basisAnchor")?, 1);
    assert_eq!(commit(&fresh.value, "resultAnchor")?, 1);
    assert!(case_purpose(&fresh)?.contains("rebase it before any change"));
    let repeated = fixture.follow("current", 64, None)?;
    assert_eq!(repeated.receipt()?, fresh.receipt()?);
    assert_eq!(raw_payload(&repeated.body)?, raw_payload(&fresh.body)?);
    Ok(())
}

#[test]
fn populated_case_mutation_requires_resnapshot_without_consuming_pending_ack() -> TestResult {
    let mut fixture = Fixture::new("populated-mutation")?;
    let opened = fixture.open_case()?;
    let pending = fixture.follow("before-mutation", 64, None)?.receipt()?;
    let cancelled =
        fixture.cancel_case(text(field(&opened.value, "payload")?, "revisionDigest")?)?;
    assert_eq!(
        text(field(&cancelled.value, "payload")?, "state")?,
        "cancelled"
    );
    let authority = authority_tree(&fixture.root)?;
    let before = fixture.journal()?;
    let refused = fixture.command(&fixture.args("before-mutation", 64, Some(pending)), 5)?;
    let mcp_refused = fixture.mcp("before-mutation", 64, Some(pending), true)?;
    assert_resnapshot_without_ack(&refused)?;
    assert_resnapshot_without_ack(&mcp_refused)?;
    assert_eq!(fixture.journal()?, before);
    let inspection = fixture.inspect()?;
    let old = inspection
        .follows
        .iter()
        .find(|entry| entry.registration().subscription_id == "before-mutation")
        .ok_or("original subscription survives refusal")?;
    assert_eq!(
        old.pending().ok_or("pending delivery survives")?.receipt(),
        pending
    );
    assert_eq!(old.acknowledged_anchor(), fixture.since);
    assert_eq!(old.last_acknowledged(), None);

    // Even a terminal case revision is retained semantic history. A fresh current-head
    // subscription is permitted after an explicit resnapshot, never by consuming the old ACK.
    let orientation = fixture.orient()?;
    assert!(
        array(
            field(&orientation.value, "payload")?,
            "activeInvestigations"
        )?
        .is_empty()
    );
    fixture.since = format!("anchor:{}", pointer(&orientation.value, "anchor:")?);
    let fresh = fixture.mcp("after-resnapshot", 64, None, false)?;
    fresh.assert_bound(&fixture)?;
    assert_eq!(commit(&fresh.value, "basisAnchor")?, 0);
    assert_eq!(commit(&fresh.value, "resultAnchor")?, 0);
    assert!(
        case_purpose(&fresh).is_err(),
        "cancelled case is not listed as active"
    );
    let recovered = fixture.inspect()?;
    let old = recovered
        .follows
        .iter()
        .find(|entry| entry.registration().subscription_id == "before-mutation")
        .ok_or("original subscription remains retained")?;
    assert_eq!(
        old.pending().ok_or("old pending page remains")?.receipt(),
        pending
    );
    assert_eq!(old.last_acknowledged(), None);
    assert_eq!(authority_tree(&fixture.root)?, authority);
    Ok(())
}

#[test]
fn invalid_subscription_pairs_and_cursor_overrides_refuse_before_opening_the_root() -> TestResult {
    let directory = OwnedDirectory::new("parse")?;
    let missing = directory.0.join("must-stay-missing");
    let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
    for extra in [
        vec!["--session", "session:owner"],
        vec!["--subscription", "watch"],
        vec![
            "--session",
            "session:owner",
            "--subscription",
            "watch",
            "--wait-ms",
            "1",
        ],
        vec![
            "--session",
            "session:owner",
            "--subscription",
            "watch",
            "--continuation",
            "continuation:unowned",
        ],
        vec![
            "--session",
            "session:owner",
            "--subscription",
            "watch",
            "--acknowledge",
            "sha256:invalid",
        ],
    ] {
        let mut args = vec![OsString::from("follow")];
        args.extend(common_args(&missing));
        args.push("--since".into());
        args.push(anchor.clone().into());
        args.extend(extra.iter().map(OsString::from));
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(&args)
            .output()?;
        assert_output(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(
            !missing.exists(),
            "argument refusal never creates or opens agent state"
        );
    }
    Ok(())
}
