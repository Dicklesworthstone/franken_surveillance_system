#![forbid(unsafe_code)]
//! Exact retained adjacent event metadata through the native owner, library, CLI and cold MCP.
//! Published synthetic declarations exercise custody and uncertainty, not sensor accuracy.

#[path = "../src/custody_review/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use fixture::{Fixture, TestResult, inventory};
use fss_cli::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::json_input::{Value, parse, parse_reconstruction_atlas_report};
use fss_core::{
    AgentView, CanonicalEncode, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent,
    EventEvidence, EventHypothesis, EvidenceClass, EvidenceEdgeRelation, IdempotencyKey,
    ObligationId, OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_event_changes::{
    DeploymentEventChanges, EventChangesLimits, EventChangesRequest,
    explain_event_changes_in_deployment,
};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
    ReplayIoAuthority,
};

const PRINCIPAL: &str = "principal:event-changes-cli";
const PREFIX: &str = "claim:event-changes:";
const TOKENS: u64 = 16_000;
const LARGE_TIME: i128 = 9_007_199_254_740_993;
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"event-changes-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn quote(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}
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
fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn path<'a>(mut value: &'a Value, keys: &[&str]) -> TestResult<&'a Value> {
    for key in keys {
        value = field(value, key)?;
    }
    Ok(value)
}
fn text<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("{key} is not text").into())
}

fn publish(f: &Fixture, event: &EventHypothesis) -> TestResult {
    event.verify()?;
    let cx = fixture::context(&f.directory)?;
    ReferenceDeployment::open(&f.root, fixture::SITE, &cx)?.publish_event(
        &ReferencePolicyDecision {
            event: event.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    cx.drain_and_finalize();
    Ok(())
}

fn pair(label: &str) -> TestResult<(Fixture, EventHypothesis, EventHypothesis)> {
    let f = Fixture::with_extra(label, 2)?;
    let from = f.event.clone();
    let mut to = from.clone();
    to.revision += 1;
    to.supersedes = Some(from.revision_digest());
    to.interval = CaptureInterval::new(TimestampNs(LARGE_TIME), TimestampNs(LARGE_TIME + 17))?;
    to.uncertainty_reason =
        Some("The revised retained declaration remains indeterminate.".to_owned());
    to.zone_ids.push("revised-zone".to_owned());
    to.zone_ids.sort();
    to.track_ids = vec!["track:local-revised-observation".to_owned()];
    to.probability = ProbabilityInterval::new(0.125, 0.875)?;
    to.evidence = vec![
        EventEvidence {
            // Same object identity, different complete semantic edge. Digest-only set
            // subtraction must not conceal this change or treat it as unchanged support.
            digest: f.source,
            class: EvidenceClass::Assertion,
            failure_domain: "sensor:revised-declaration".to_owned(),
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            capsule_digest: None,
            identity_digest: None,
        },
        EventEvidence {
            digest: f.extras[0],
            class: EvidenceClass::Assertion,
            failure_domain: "sensor:additional-declaration".to_owned(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        },
    ];
    to.model_receipts.clear();
    to.decision_path.policy_generation = ContentDigest::sha256(b"revised synthetic policy");
    to.decision_path.fingerprint = ContentDigest::sha256(b"revised synthetic decision");
    to.decision_path.abstention_reason =
        Some("The new declaration is not physical adjudication.".to_owned());
    publish(&f, &to)?;
    let cx = fixture::context(&f.directory)?;
    ReferenceDeployment::open(&f.root, fixture::SITE, &cx)?
        .effects_mut()
        .prepare(
            EffectIntent {
                operation_id: OperationId::parse("operation:event-changes:pending")?,
                idempotency_key: IdempotencyKey::parse("idempotency:event-changes:pending")?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"pending independent observation"),
                precondition_digest: ContentDigest::sha256(b"unresolved observation required"),
            },
            ObligationId::parse("obligation:event-changes:pending")?,
            "independent observation retained",
            TimestampNs(LARGE_TIME + 18),
        )?;
    cx.drain_and_finalize();
    Ok((f, from, to))
}

fn request(from: &EventHypothesis, to: &EventHypothesis) -> TestResult<EventChangesRequest> {
    Ok(EventChangesRequest {
        event_id: to.event_id.clone(),
        from_revision_digest: from.revision_digest(),
        to_revision_digest: to.revision_digest(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        expected_anchor: None,
        view: AgentView::Forensic,
        budget_tokens: Some(TOKENS),
    })
}

fn native(
    f: &Fixture,
    from: &EventHypothesis,
    to: &EventHypothesis,
) -> TestResult<DeploymentEventChanges> {
    let request = request(from, to)?;
    let limits = EventChangesLimits::default();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-changes-cli-contract".to_owned(),
        operation_id: OperationId::parse("operation:event-changes-cli-contract")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            "CAP-AGENT-EXPLAIN-001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:current-deletion-restrictions".to_owned(),
        anchor_universe: to.revision_digest(),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, &f.root,
    )?);
    let answer = explain_event_changes_in_deployment(&f.root, &request, limits, &cx, &|| false)?;
    cx.drain_and_finalize();
    Ok(answer)
}

fn args(
    f: &Fixture,
    from: ContentDigest,
    to: ContentDigest,
    extras: &[(&str, String)],
) -> Vec<OsString> {
    let mut values = BTreeMap::<String, String>::from([
        ("--root".to_owned(), f.root.to_string_lossy().into_owned()),
        ("--principal".to_owned(), PRINCIPAL.to_owned()),
        ("--event-id".to_owned(), fixture::EVENT.to_owned()),
        ("--question".to_owned(), "what_changed".to_owned()),
        ("--from-revision-digest".to_owned(), from.to_text()),
        ("--to-revision-digest".to_owned(), to.to_text()),
        ("--view".to_owned(), "forensic".to_owned()),
        ("--budget-tokens".to_owned(), TOKENS.to_string()),
    ]);
    values.extend(
        extras
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone())),
    );
    let mut args = vec![OsString::from("explain"), OsString::from("--json")];
    for (key, value) in values {
        args.extend([key.into(), value.into()]);
    }
    args
}

fn cli(
    f: &Fixture,
    from: ContentDigest,
    to: ContentDigest,
    extras: &[(&str, String)],
) -> TestResult<(String, i32)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args(f, from, to, extras))
        .output()?;
    let code = output.status.code().ok_or("CLI terminated by signal")?;
    if code == 0 {
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let body = String::from_utf8(output.stdout)?.trim_end().to_owned();
    assert!(body.len() <= MAX_QUERY_OUTPUT_BYTES);
    Ok((body, code))
}

fn mcp(
    f: &Fixture,
    from: ContentDigest,
    to: ContentDigest,
    extras: &[(&str, Value)],
) -> TestResult<Value> {
    let mut values = BTreeMap::<String, Value>::from([
        (
            "event_id".to_owned(),
            Value::Text(fixture::EVENT.to_owned()),
        ),
        (
            "question".to_owned(),
            Value::Text("what_changed".to_owned()),
        ),
        (
            "from_revision_digest".to_owned(),
            Value::Text(from.to_text()),
        ),
        ("to_revision_digest".to_owned(), Value::Text(to.to_text())),
        ("view".to_owned(), Value::Text("forensic".to_owned())),
        (
            "budget_tokens".to_owned(),
            Value::Number(TOKENS.to_string()),
        ),
    ]);
    values.extend(
        extras
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone())),
    );
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"explain","arguments":{}}}}}"#,
        json(&Value::Object(values))
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(&f.root)
        .args(["--principal", PRINCIPAL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("MCP input")?;
    writeln!(input, "{INIT}\n{READY}\n{call}")?;
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
    assert!(lines[1].len() <= 6 * MAX_QUERY_OUTPUT_BYTES + 1024);
    Ok(parse_reconstruction_atlas_report(lines[1])?)
}

fn mcp_body(wire: &Value, failed: bool) -> TestResult<&str> {
    let result = field(wire, "result")
        .map_err(|_| format!("expected tool result, received {}", json(wire)))?;
    assert_eq!(field(result, "isError")?.boolean(), Some(failed));
    let content = field(result, "content")?.array().ok_or("content")?;
    assert_eq!(content.len(), 1);
    assert_eq!(text(&content[0], "type")?, "text");
    let body = text(&content[0], "text")?;
    assert!(body.len() <= MAX_QUERY_OUTPUT_BYTES);
    Ok(body)
}

// Reconstruct the complete independently identified native report, rather than asserting
// that selected words happen to be present somewhere in the agent's cognitive context.
fn insert(root: &mut Value, path: &[&str], value: Value) -> TestResult {
    if path.is_empty() {
        assert_eq!(*root, Value::Null, "duplicate projected value");
        *root = value;
        return Ok(());
    }
    let segment = path[0];
    if let Ok(index) = segment.parse::<usize>() {
        assert_eq!(index.to_string(), segment);
        if root == &Value::Null {
            *root = Value::Array(Vec::new());
        }
        let Value::Array(items) = root else {
            return Err("projected array/object collision".into());
        };
        if items.len() <= index {
            items.resize(index + 1, Value::Null);
        }
        insert(&mut items[index], &path[1..], value)
    } else {
        if root == &Value::Null {
            *root = Value::Object(BTreeMap::new());
        }
        let Value::Object(fields) = root else {
            return Err("projected object/array collision".into());
        };
        insert(
            fields.entry(segment.to_owned()).or_insert(Value::Null),
            &path[1..],
            value,
        )
    }
}

fn report(envelope: &Value) -> TestResult<Value> {
    let mut result = Value::Null;
    let rows = path(envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?;
    for row in rows {
        let Some(key) = text(row, "id")?.strip_prefix(PREFIX) else {
            continue;
        };
        assert_eq!(
            text(row, "state")?,
            "known",
            "metadata facts must not masquerade as physical observations"
        );
        let encoded = text(row, "statement")?
            .split_once(": ")
            .ok_or("complete comparison JSON separator")?
            .1;
        insert(
            &mut result,
            &key.split(':').collect::<Vec<_>>(),
            parse(encoded)?,
        )?;
    }
    assert!(
        result.object().is_some(),
        "missing complete comparison projection"
    );
    Ok(result)
}

fn conforms(f: &Fixture, schema: &str, value: &Value) -> TestResult {
    let body = json(value);
    let file = f.directory.join(format!(
        "schema-{}.json",
        ContentDigest::sha256(body.as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, body)?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg("-B")
        .arg(repo.join("scripts/json_instance_validate.py"))
        .arg(repo.join("schemas").join(schema))
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

fn accepted(f: &Fixture, body: &str, expected: &DeploymentEventChanges) -> TestResult<Value> {
    let envelope = parse_reconstruction_atlas_report(body)?;
    assert_eq!(text(&envelope, "operationId")?, "AOP-011");
    assert_eq!(text(&envelope, "schema")?, "fss.agent_response_envelope.v1");
    assert_eq!(
        text(&envelope, "payloadSchema")?,
        "fss.agent_cognitive_envelope.v1"
    );
    assert_eq!(text(&envelope, "effectiveViewId")?, "AVIEW-004");
    assert_eq!(field(&envelope, "errorId")?, &Value::Null);
    let reconstructed = report(&envelope)?;
    assert_eq!(reconstructed, parse(expected.report.to_json())?);
    assert_eq!(text(&reconstructed, "question")?, "what_changed");
    assert_eq!(
        text(&reconstructed, "comparisonDigest")?,
        expected.comparison_digest.to_text()
    );
    assert_eq!(
        path(
            &reconstructed,
            &["to", "revision", "timeInterval", "earliestNs"]
        )?
        .integer(),
        Some(LARGE_TIME)
    );
    let changes = field(&reconstructed, "changes")?.array().ok_or("changes")?;
    for name in [
        "revision",
        "supersedes",
        "timeInterval",
        "uncertaintyReason",
        "zoneIds",
        "trackIds",
        "probability",
        "evidence",
        "modelReceipts",
        "decisionPath",
    ] {
        assert!(
            changes
                .iter()
                .any(|row| text(row, "field").ok() == Some(name)),
            "missing changed field {name}"
        );
    }
    let before_edges = path(&reconstructed, &["from", "revision", "evidence"])?
        .array()
        .ok_or("before edges")?;
    let after_edges = path(&reconstructed, &["to", "revision", "evidence"])?
        .array()
        .ok_or("after edges")?;
    let identity = f.source.to_text();
    let old = before_edges
        .iter()
        .find(|edge| text(edge, "digest").ok() == Some(identity.as_str()))
        .ok_or("old shared object")?;
    let new = after_edges
        .iter()
        .find(|edge| text(edge, "digest").ok() == Some(identity.as_str()))
        .ok_or("new shared object")?;
    assert_eq!(field(old, "supports")?.boolean(), Some(true));
    assert_eq!(field(new, "supports")?.boolean(), Some(false));
    assert_ne!(field(old, "relation")?, field(new, "relation")?);
    assert_ne!(field(old, "failureDomain")?, field(new, "failureDomain")?);
    assert_ne!(field(old, "class")?, field(new, "class")?);
    let propositions = path(&envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?;
    for cell in &expected.explanation.cells {
        let row = propositions
            .iter()
            .find(|row| text(row, "id").ok() == Some(cell.claim_id()))
            .ok_or("protected current event cell missing")?;
        assert_eq!(text(row, "state")?, cell.knowledge_state().as_str());
        assert_eq!(text(row, "statement")?, cell.disclosable_statement());
    }
    for world in &expected.explanation.worlds {
        assert!(body.contains(&world.world_id), "protected world omitted");
    }
    assert!(body.contains("obligation:event-changes:pending"));
    for source in [fixture::SOURCE, fixture::COUNTER] {
        assert!(!body.contains(std::str::from_utf8(source)?));
    }
    assert!(!body.contains(f.root.to_str().ok_or("root")?));
    let proofs = field(&envelope, "proofPointers")?
        .array()
        .ok_or("proof pointers")?;
    for digest in [
        expected.comparison_digest,
        expected.report.from_publication_root(),
        expected.report.to_publication_root(),
        expected.receipt.receipt_digest(),
    ] {
        assert!(
            proofs.contains(&Value::Text(digest.to_text())),
            "missing comparison proof {digest:?}"
        );
    }
    let requested = path(&envelope, &["budgets", "requested", "tokens"])?
        .integer()
        .ok_or("requested tokens")?;
    let consumed = path(&envelope, &["budgets", "consumed", "tokens"])?
        .integer()
        .ok_or("consumed tokens")?;
    assert_eq!(requested, i128::from(TOKENS));
    assert!(consumed > 0 && consumed <= requested);
    conforms(f, "event_revision_comparison.v1.json", &reconstructed)?;
    conforms(f, "agent_response_envelope.v1.json", &envelope)?;
    Ok(envelope)
}

#[test]
fn native_library_cli_and_cold_mcp_preserve_the_complete_transition_and_current_uncertainty()
-> TestResult {
    let (f, from, to) = pair("changes-roundtrip")?;
    let before = inventory(&f.root)?;
    let expected = native(&f, &from, &to)?;
    assert_eq!(
        expected.receipt.question(),
        fss_core::ExplainQuestion::WhatChanged
    );
    let (library, exit) = execute_fss_with_exit(parse_fss_args(args(
        &f,
        from.revision_digest(),
        to.revision_digest(),
        &[],
    ))?);
    assert_eq!(exit, ExitIdentity::SUCCESS, "{library}");
    accepted(&f, &library, &expected)?;
    let (body, exit) = cli(&f, from.revision_digest(), to.revision_digest(), &[])?;
    assert_eq!(exit, 0, "{body}");
    assert_eq!(body, library.trim_end());
    let wire = mcp(&f, from.revision_digest(), to.revision_digest(), &[])?;
    assert_eq!(mcp_body(&wire, false)?, body);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn explicit_why_preserves_the_existing_request_and_response_bytes() -> TestResult {
    let (f, _, _) = pair("changes-why-compatible")?;
    let before = inventory(&f.root)?;
    let run = |explicit: bool| -> TestResult<_> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss"));
        command
            .args(["explain", "--json", "--root"])
            .arg(&f.root)
            .args([
                "--event-id",
                fixture::EVENT,
                "--principal",
                PRINCIPAL,
                "--view",
                "forensic",
                "--budget-tokens",
                "16000",
            ]);
        if explicit {
            command.args(["--question", "why"]);
        }
        Ok(command.output()?)
    };
    let ordinary = run(false)?;
    assert!(
        ordinary.status.success(),
        "{}{}",
        String::from_utf8_lossy(&ordinary.stdout),
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let explicit = run(true)?;
    assert_eq!(explicit.status.code(), ordinary.status.code());
    assert_eq!(explicit.stdout, ordinary.stdout);
    assert!(!String::from_utf8(ordinary.stdout)?.contains(PREFIX));
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn wrong_or_nonadjacent_endpoints_never_follow_a_later_head() -> TestResult {
    let (f, first, second) = pair("changes-exact-endpoints")?;
    let mut third = second.clone();
    third.revision += 1;
    third.supersedes = Some(second.revision_digest());
    third.decision_path.fingerprint =
        ContentDigest::sha256(b"later head must be selected explicitly");
    publish(&f, &third)?;
    let before = inventory(&f.root)?;
    for (from, to) in [
        (first.revision_digest(), second.revision_digest()),
        (first.revision_digest(), third.revision_digest()),
        (
            ContentDigest::sha256(b"foreign predecessor"),
            third.revision_digest(),
        ),
        (third.revision_digest(), second.revision_digest()),
    ] {
        let (body, exit) = cli(&f, from, to, &[])?;
        assert_ne!(exit, 0, "invalid selected pair succeeded: {body}");
        if !body.is_empty() {
            let reply = parse(&body)?;
            assert_eq!(field(&reply, "payload")?, &Value::Null);
            assert_eq!(text(&reply, "outcome")?, "refused");
        }
        assert!(!body.contains(PREFIX));
        let wire = mcp(&f, from, to, &[])?;
        let result = mcp_body(&wire, true)?;
        assert!(!result.contains(PREFIX));
        assert_eq!(inventory(&f.root)?, before);
    }
    let expected = native(&f, &second, &third)?;
    let (body, exit) = cli(&f, second.revision_digest(), third.revision_digest(), &[])?;
    assert_eq!(exit, 0, "{body}");
    assert_eq!(report(&parse(&body)?)?, parse(expected.report.to_json())?);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn original_media_is_not_opened_but_both_retained_revision_payloads_remain_required() -> TestResult
{
    let (f, from, to) = pair("changes-custody")?;
    fs::remove_file(f.object_path(f.source))?;
    let after_source_removal = inventory(&f.root)?;
    let (body, exit) = cli(&f, from.revision_digest(), to.revision_digest(), &[])?;
    assert_eq!(exit, 0, "{body}");
    assert_eq!(inventory(&f.root)?, after_source_removal);
    for event in [&from, &to] {
        let payload = f.object_path(ContentDigest::sha256(&event.canonical_bytes()));
        let saved = fs::read(&payload)?;
        let mut corrupt = saved.clone();
        let last = corrupt
            .last_mut()
            .ok_or("empty canonical object envelope")?;
        *last ^= 1;
        fs::write(&payload, &corrupt)?;
        let before = inventory(&f.root)?;
        let (body, exit) = cli(&f, from.revision_digest(), to.revision_digest(), &[])?;
        assert_ne!(exit, 0, "corrupt selected revision succeeded");
        assert!(!body.contains(PREFIX));
        assert_eq!(inventory(&f.root)?, before);
        fs::write(payload, saved)?;
    }
    let (body, exit) = cli(&f, from.revision_digest(), to.revision_digest(), &[])?;
    assert_eq!(exit, 0, "restored selected metadata must be usable: {body}");
    assert_eq!(inventory(&f.root)?, after_source_removal);
    Ok(())
}

#[test]
fn small_context_refuses_whole_comparison_without_automatic_view_or_budget_escalation() -> TestResult
{
    let (f, from, to) = pair("changes-context")?;
    let before = inventory(&f.root)?;
    let (body, exit) = cli(
        &f,
        from.revision_digest(),
        to.revision_digest(),
        &[("--budget-tokens", "1".to_owned())],
    )?;
    assert_ne!(exit, 0);
    let reply = parse(&body)?;
    assert_eq!(text(&reply, "outcome")?, "refused");
    assert_eq!(field(&reply, "payload")?, &Value::Null);
    assert_eq!(text(&reply, "effectiveViewId")?, "AVIEW-004");
    assert_eq!(
        path(&reply, &["budgets", "requested", "tokens"])?.integer(),
        Some(1)
    );
    assert!(!body.contains(PREFIX));
    let wire = mcp(
        &f,
        from.revision_digest(),
        to.revision_digest(),
        &[("budget_tokens", Value::Number("1".to_owned()))],
    )?;
    let failed = parse(mcp_body(&wire, true)?)?;
    assert_eq!(field(&failed, "payload")?, &Value::Null);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn comparison_grammar_refuses_unsupported_modes_lossy_identities_and_authority_overrides()
-> TestResult {
    let (f, from, to) = pair("changes-grammar")?;
    let before = inventory(&f.root)?;
    for extras in [
        vec![("--question", "why_not".to_owned())],
        vec![("--question", "what_if".to_owned())],
        vec![("--question", "why".to_owned())],
        vec![("--from-revision-digest", "sha256:ABC".to_owned())],
        vec![("--to-revision-digest", format!("sha256:{}", "0".repeat(64)))],
        vec![("--custody", "no".to_owned())],
        vec![(
            "--score-calibration",
            "/never-read-this-calibration".to_owned(),
        )],
        vec![("--fusion-policy", "3,2,1".to_owned())],
        vec![("--budget-tokens", "16001".to_owned())],
        vec![("--session", "session:foreign".to_owned())],
    ] {
        let invalid = args(&f, from.revision_digest(), to.revision_digest(), &extras);
        assert!(
            parse_fss_args(invalid.clone()).is_err(),
            "invalid selector was admitted"
        );
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(invalid)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(inventory(&f.root)?, before);
    }
    for (key, value) in [
        ("question", Value::Text("what_if".to_owned())),
        ("question", Value::Text("why".to_owned())),
        ("from_revision_digest", Value::Number("1".to_owned())),
        (
            "to_revision_digest",
            Value::Text(format!("sha256:{}", "0".repeat(64))),
        ),
        ("root", Value::Text(f.root.to_string_lossy().into_owned())),
        ("principal", Value::Text(PRINCIPAL.to_owned())),
        ("custody", Value::Bool(false)),
        ("budget_tokens", Value::Number("1e3".to_owned())),
        ("budget_tokens", Value::Number("16001".to_owned())),
    ] {
        let wire = mcp(
            &f,
            from.revision_digest(),
            to.revision_digest(),
            &[(key, value)],
        )?;
        assert_eq!(
            path(&wire, &["error", "code"])?.integer(),
            Some(-32602),
            "invalid {key}: {}",
            json(&wire)
        );
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}
