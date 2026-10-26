#![forbid(unsafe_code)]
//! Fresh-process durable supervision over the real retained native package fixture.

use super::*;

use fss_core::{BatchId, CaptureInterval, EvidenceDelta, ObjectId, Plane};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::checkpoint::journal::supervision::SupervisionSubscription;
use fss_reference::agent_session::work_claims::WorkClaimLimits;

const PRINCIPAL: &str = "principal:local-operator";

fn open_session(f: &Fixture) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["session", "open", "--json", "--root"]).arg(&f.root)
        .args([
            "--principal", PRINCIPAL,
            "--mission", "Review retained native class evidence with durable delivery",
            "--objective", "Preserve source verification, uncertainty and exact acknowledgements",
            "--view", "brief", "--budget-tokens", "100000",
        ])
        .output()?;
    success(&output);
    Ok(text(&report(&output)?, "sessionId")?.to_owned())
}

fn poll(
    f: &Fixture,
    request: &Value,
    session: &str,
    subscription: &str,
    maximum_attempts: u32,
    action: Option<(&str, &str)>,
) -> TestResult<Output> {
    let flags: Vec<_> = action.into_iter().collect();
    poll_with_flags(f, request, session, subscription, maximum_attempts, &flags)
}

fn poll_with_flags(
    f: &Fixture,
    request: &Value,
    session: &str,
    subscription: &str,
    maximum_attempts: u32,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    let bytes = encode(request);
    let file = f.directory.0.join("session-discovery.json");
    fs::write(&file, &bytes)?;
    let digest = ContentDigest::sha256(bytes.as_bytes()).to_text();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.args(["supervise", "--root"]).arg(&f.root)
        .args(["--site", SITE, "--discover-plan"]).arg(file)
        .args([
            "--discover-digest", &digest,
            "--session", session, "--subscription", subscription,
            "--authority-root", &f.authority.to_text(),
            "--max-poll-attempts", &maximum_attempts.to_string(),
        ]);
    for &(flag, value) in flags { command.args([flag, value]); }
    Ok(command.output()?)
}

#[path = "session/schedule.rs"]
mod schedule;

#[path = "session/resume.rs"]
mod resume;

#[path = "session/inventory.rs"]
mod inventory;

fn state(f: &Fixture, subscription: &str) -> TestResult<SupervisionSubscription> {
    inspect_session_bytes(
        &fs::read(f.root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?.supervisions.into_iter()
        .find(|state| state.registration().subscription_id == subscription)
        .ok_or_else(|| "retained supervision subscription missing".into())
}

fn canonical_inventory(f: &Fixture) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    Ok(inventory(&f.root)?.into_iter()
        .filter(|(path, _)| !path.starts_with("agent")).collect())
}

fn raw_report(output: &Output) -> TestResult<&[u8]> {
    let text = std::str::from_utf8(&output.stdout)?;
    let start = text.find(",\"report\":").ok_or("embedded report")? + ",\"report\":".len();
    let end = text.rfind(",\"receipt_digest\":").ok_or("outer complete receipt")?;
    if end <= start { return Err("invalid report boundaries".into()); }
    Ok(&output.stdout[start..end])
}

fn refusal(output: &Output) {
    assert!(!output.status.success(), "unexpected successful session operation");
    assert!(output.stdout.is_empty(), "private or partial successful report escaped refusal");
}

fn append_unrelated_authority(f: &mut Fixture) -> TestResult {
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let payload = deployment.stage_payload(b"explicit unrelated supervision retry fixture")?;
    deployment.append_batch(
        BatchId::parse("batch:supervision-session:unrelated")?,
        vec![EvidenceDelta {
            delta_id: "delta:supervision-session:unrelated".into(),
            family: "decode_receipt".into(),
            object_id: ObjectId::parse("object:supervision-session:unrelated")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?,
            plane: Plane::Cognition,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        }],
        vec![payload],
        &cx,
    )?;
    f.authority = deployment.current_anchor().state_root;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cold_pending_delivery_revalidates_advancing_authority_and_acknowledges_exactly_once()
-> TestResult {
    let mut f = Fixture::new("session-continuity", 2)?;
    let request = f.discovery(&[0, 1])?;
    let original_root = f.authority;
    let before_session = canonical_inventory(&f)?;
    let session = open_session(&f)?;
    assert_eq!(canonical_inventory(&f)?, before_session);
    refusal(&poll(&f, &request, &session, "unknown", 16, Some(("--inspect", "yes")))?);
    assert!(state(&f, "unknown").is_err());

    let first = poll(&f, &request, &session, "continuous", 16, None)?;
    success(&first);
    let initial = report(&first)?;
    assert_eq!(text(&initial, "schema")?, "fss.retained_supervisor_session_report.v1");
    assert_eq!(text(&initial, "state")?, "pending");
    assert_eq!(field(&initial, "replayed")?.boolean(), Some(false));
    assert_eq!(field(&initial, "attempts_reserved")?.integer(), Some(1));
    assert_eq!(field(&initial, "source_validation")?, &Value::Null);
    let receipt = text(&initial, "delivery_receipt")?.to_owned();
    let original_payload = raw_report(&first)?.to_vec();
    assert_eq!(
        text(&initial, "payload_digest")?,
        ContentDigest::sha256(&original_payload).to_text(),
    );
    assert_eq!(state(&f, "continuous")?.attempts_reserved(), 1);

    let second = poll(&f, &request, &session, "continuous", 16, None)?;
    success(&second);
    let second_json = report(&second)?;
    assert_eq!(raw_report(&second)?, original_payload);
    assert_eq!(text(&second_json, "delivery_receipt")?, receipt);
    assert_eq!(field(&second_json, "replayed")?.boolean(), Some(true));
    assert_eq!(field(&second_json, "attempts_reserved")?.integer(), Some(2));
    assert!(field(&second_json, "source_validation")?.object().is_some());
    assert_eq!(state(&f, "continuous")?.attempts_reserved(), 2);

    let bad = ContentDigest::sha256(b"wrong acknowledgement").to_text();
    refusal(&poll(&f, &request, &session, "continuous", 16, Some(("--acknowledge", &bad)))?);
    let mut changed = request.clone();
    fields(discovery_plan(&mut changed)).insert("prior".into(), Value::Array(vec![numeric(1), numeric(1)]));
    refusal(&poll(&f, &changed, &session, "continuous", 16, None)?);
    assert_eq!(state(&f, "continuous")?.attempts_reserved(), 2);
    assert_eq!(canonical_inventory(&f)?, before_session);

    // Advancing unrelated canonical history must not rewrite the pending historical report.
    append_unrelated_authority(&mut f)?;
    let advanced_inventory = canonical_inventory(&f)?;
    assert_ne!(f.authority, original_root);
    let advanced = poll(&f, &request, &session, "continuous", 16, None)?;
    success(&advanced);
    let advanced_json = report(&advanced)?;
    assert_eq!(raw_report(&advanced)?, original_payload);
    assert_eq!(text(&advanced_json, "delivery_receipt")?, receipt);
    assert_eq!(text(&advanced_json, "report_authority_root")?, original_root.to_text());
    assert_eq!(text(&advanced_json, "current_authority_root")?, f.authority.to_text());
    assert_eq!(
        text(field(&advanced_json, "source_validation")?, "current_authority_root")?,
        f.authority.to_text(),
    );
    assert_eq!(field(&advanced_json, "attempts_reserved")?.integer(), Some(3));

    let ack = poll(&f, &request, &session, "continuous", 16, Some(("--acknowledge", &receipt)))?;
    success(&ack);
    let ack_json = report(&ack)?;
    assert_eq!(text(&ack_json, "state")?, "acknowledged");
    assert_eq!(field(&ack_json, "report")?, &Value::Null);
    assert_eq!(text(&ack_json, "acknowledged")?, receipt);
    assert_eq!(field(&ack_json, "attempts_reserved")?.integer(), Some(4));
    let repeated_ack = poll(&f, &request, &session, "continuous", 16, Some(("--acknowledge", &receipt)))?;
    success(&repeated_ack);
    assert_eq!(field(&report(&repeated_ack)?, "attempts_reserved")?.integer(), Some(4));
    let acknowledged_state = state(&f, "continuous")?;
    let inspected_ack = poll(&f, &request, &session, "continuous", 16, Some(("--inspect", "yes")))?;
    success(&inspected_ack);
    let inspected_ack = report(&inspected_ack)?;
    assert_eq!(text(&inspected_ack, "state")?, "inspected");
    assert_eq!(text(&inspected_ack, "last_acknowledged")?, receipt);
    assert_eq!(field(&inspected_ack, "report")?, &Value::Null);
    assert_eq!(state(&f, "continuous")?, acknowledged_state);

    let next = poll(&f, &request, &session, "continuous", 16, None)?;
    success(&next);
    let next_json = report(&next)?;
    let next_receipt = text(&next_json, "delivery_receipt")?.to_owned();
    assert_ne!(next_receipt, receipt);
    assert_eq!(text(&next_json, "report_authority_root")?, f.authority.to_text());
    assert_eq!(field(&next_json, "attempts_reserved")?.integer(), Some(5));
    // Full recomputation retains unique evidence semantics across polls and process restarts.
    let initial_supervision = field(field(&initial, "report")?, "supervision")?;
    let next_supervision = field(field(&next_json, "report")?, "supervision")?;
    for key in ["observations", "windows"] {
        assert_eq!(field(initial_supervision, key)?, field(next_supervision, key)?);
    }
    success(&poll(&f, &request, &session, "continuous", 16, Some(("--acknowledge", &receipt)))?);
    assert_eq!(
        state(&f, "continuous")?.pending().ok_or("successor pending")?.receipt().to_text(),
        next_receipt,
    );
    let discarded = poll(&f, &request, &session, "continuous", 16, Some(("--discard", &next_receipt)))?;
    success(&discarded);
    let discarded = report(&discarded)?;
    assert_eq!(text(&discarded, "state")?, "discarded");
    assert_eq!(field(&discarded, "acknowledged")?, &Value::Null);
    assert_eq!(field(&discarded, "attempts_reserved")?.integer(), Some(5));
    success(&poll(&f, &request, &session, "continuous", 16, Some(("--discard", &next_receipt)))?);

    // A separate explicitly bounded subscription cannot refill after a cold retry or discard.
    let limited = poll(&f, &request, &session, "one-attempt", 1, None)?;
    success(&limited);
    let limited_state = state(&f, "one-attempt")?;
    // Recover a receipt even if the first stdout was lost and no source attempt remains.
    let inspection = poll(&f, &request, &session, "one-attempt", 1, Some(("--inspect", "yes")))?;
    success(&inspection);
    let inspection = report(&inspection)?;
    assert_eq!(text(&inspection, "state")?, "inspected");
    assert_eq!(field(&inspection, "report")?, &Value::Null);
    assert_eq!(field(&inspection, "source_validation")?, &Value::Null);
    let limited_receipt = text(&inspection, "pending_receipt")?.to_owned();
    assert_eq!(text(&report(&limited)?, "delivery_receipt")?, limited_receipt);
    assert_eq!(state(&f, "one-attempt")?, limited_state);
    refusal(&poll(&f, &request, &session, "one-attempt", 1, None)?);
    refusal(&poll(&f, &request, &session, "one-attempt", 1, Some(("--acknowledge", &limited_receipt)))?);
    success(&poll(&f, &request, &session, "one-attempt", 1, Some(("--discard", &limited_receipt)))?);
    refusal(&poll(&f, &request, &session, "one-attempt", 1, None)?);
    refusal(&poll(&f, &request, &session, "one-attempt", 2, None)?);
    let exhausted = state(&f, "one-attempt")?;
    assert_eq!(exhausted.attempts_reserved(), 1);
    assert_eq!(exhausted.reserved_bytes(), exhausted.registration().max_read_bytes);
    assert_eq!(exhausted.reserved_read_attempts(), exhausted.registration().max_read_attempts);
    assert!(exhausted.pending().is_none());
    assert_eq!(exhausted.last_acknowledged(), None);
    let inspected_discard = poll(&f, &request, &session, "one-attempt", 1, Some(("--inspect", "yes")))?;
    success(&inspected_discard);
    let inspected_discard = report(&inspected_discard)?;
    assert_eq!(text(&inspected_discard, "last_discarded")?, limited_receipt);
    assert_eq!(field(&inspected_discard, "pending_receipt")?, &Value::Null);
    assert_eq!(field(&inspected_discard, "report")?, &Value::Null);
    assert_eq!(state(&f, "one-attempt")?, exhausted);
    assert_eq!(canonical_inventory(&f)?, advanced_inventory);
    Ok(())
}

#[test]
fn deleted_generation_excluded_source_blocks_pending_replay_and_ack_but_allows_explicit_discard()
-> TestResult {
    let mut f = Fixture::new("session-deletion", 2)?;
    let mut request = f.discovery(&[0, 1])?;
    let camera = &mut rows(
        fields(discovery_plan(&mut request)).get_mut("cameras").ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"other explicitly selected package").to_text()),
    );
    let session = open_session(&f)?;
    let first = poll(&f, &request, &session, "excluded-source", 8, None)?;
    success(&first);
    let first_json = report(&first)?;
    let receipt = text(&first_json, "delivery_receipt")?.to_owned();
    let original_state = state(&f, "excluded-source")?;
    let original_pending = original_state.pending().ok_or("original pending")?;
    assert!(original_pending.source_inventory().iter().any(|source| {
        source.event_id == f.cameras[0].event && source.source_verified
    }));

    let deletion = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"]).arg(&f.root)
        .args(["--site", SITE, "--import-id", &f.cameras[0].import.to_text()])
        .output()?;
    success(&deletion);
    let deletion = report(&deletion)?;
    let committed = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"]).arg(&f.root)
        .args([
            "--site", SITE, "--plan", text(&deletion, "plan_digest")?,
            "--approve", text(&deletion, "approval_digest")?,
        ])
        .output()?;
    success(&committed);
    f.refresh_authority()?;
    let after_deletion = canonical_inventory(&f)?;
    refusal(&poll(&f, &request, &session, "excluded-source", 8, None)?);
    refusal(&poll(&f, &request, &session, "excluded-source", 8, Some(("--acknowledge", &receipt)))?);
    let blocked = state(&f, "excluded-source")?;
    assert_eq!(blocked.attempts_reserved(), 3);
    assert_eq!(blocked.pending().ok_or("blocked report retained")?.receipt(), original_pending.receipt());
    assert_eq!(blocked.last_acknowledged(), None);
    let inspection = poll(&f, &request, &session, "excluded-source", 8, Some(("--inspect", "yes")))?;
    success(&inspection);
    let inspection = report(&inspection)?;
    assert_eq!(text(&inspection, "state")?, "inspected");
    assert_eq!(text(&inspection, "pending_receipt")?, receipt);
    assert_eq!(field(&inspection, "report")?, &Value::Null);
    assert_eq!(field(&inspection, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "excluded-source")?, blocked);

    let discarded = poll(&f, &request, &session, "excluded-source", 8, Some(("--discard", &receipt)))?;
    success(&discarded);
    let discarded = report(&discarded)?;
    assert_eq!(text(&discarded, "state")?, "discarded");
    assert_eq!(field(&discarded, "report")?, &Value::Null);
    assert_eq!(field(&discarded, "acknowledged")?, &Value::Null);
    assert_eq!(field(&discarded, "attempts_reserved")?.integer(), Some(3));
    let final_state = state(&f, "excluded-source")?;
    assert!(final_state.pending().is_none());
    assert_eq!(final_state.last_acknowledged(), None);
    assert_eq!(final_state.last_discarded().map(|r| r.to_text()), Some(receipt));
    assert_eq!(canonical_inventory(&f)?, after_deletion);
    Ok(())
}
