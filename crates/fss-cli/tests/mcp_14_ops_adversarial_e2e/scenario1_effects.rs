#![forbid(unsafe_code)]
//! Scenario 1 (Part B) — Operational Intents, Alert Plan/Commit/Wait/Reconcile,
//! Pure-Rust RFC 8446 TLS 1.3 HMAC Webhook Delivery, Indeterminate Reconciliation,
//! Feedback/Handoff/Resume/Cancel, and Full Canary Leak Surface Audit.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_core::json_input::Value;
use fss_core::{
    AffordanceClass, AgentView, ContentDigest, EffectState, EventId, IdempotencyKey, ObligationId,
    OperationId, PrincipalId, TimestampNs,
};
use fss_ledger::IncompleteTailPolicy;
use fss_reference::DurableEffectJournal;
use fss_reference::agent_orient::{
    AFFORDANCE_PLAN, OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::notify::escalation::{
    NotificationChannelTarget, dispatch_prepared_notification, prepare_notification_effect,
    reconcile_notification_verified,
};
use fss_reference::notify::webhook::HttpsWebhookTarget;
use fss_reference::notify::x509::TlsTrustPolicy;
use fss_reference::notify::{
    DisclosureProfile, NotifyDeadlineCx, NotifyEventMetadata, NotifyLimits, NotifyPayload,
    PinnedDnsResolver,
};
use fss_vault::LabEntropy;

use super::TestResult;
use super::fixtures::{
    CANARY_WEBHOOK_HMAC, PRINCIPAL, TempWorkspace, VaultCanaryRig, publish_corroborated_event,
    wall_now_ns,
};
use super::harness::{
    LoopbackAlertRelay, McpClient, TranscriptEntry, accept_and_verify_tls13_webhook, array,
    bool_field, build_test_pki, quote, text, texts,
};

pub struct EffectsContext<'a> {
    pub ws: &'a TempWorkspace,
    pub deploy_root: &'a Path,
    pub session_id: &'a str,
    pub corr_event_id: &'a str,
    pub east_arg: &'a str,
    pub west_arg: &'a str,
    pub sentinel_import_hex: &'a str,
}

fn rebase_session(ops_mcp: &mut McpClient, session_id: &str, note: &str) -> TestResult {
    let ho = ops_mcp.call(
        "handoff",
        &object(&[("session", string(session_id)), ("note", string(note))]),
    )?;
    assert!(!ho.is_error, "handoff: {}", ho.body_text);
    let handoff_id = text(&ho.envelope, &["payload", "handoffId"])?.to_owned();
    let resumed = ops_mcp.call(
        "session_resume",
        &object(&[("handoff", string(&handoff_id))]),
    )?;
    assert!(!resumed.is_error, "session_resume: {}", resumed.body_text);
    assert_eq!(text(&resumed.envelope, &["sessionId"])?, session_id);
    Ok(())
}

pub struct EffectsOutcome {
    pub rig: VaultCanaryRig,
    pub tls13_idempotency_key: String,
    pub tls_audit_jsonl: String,
    pub tls_journal_path: PathBuf,
}

fn extract_plan_approvals(envelope: &Value) -> TestResult<(String, String, String)> {
    let pointers = texts(envelope, &["proofPointers"])?;
    Ok((
        text(envelope, &["payload", "planId"])?.to_owned(),
        pointers.get(2).ok_or("missing plan approval")?.clone(),
        pointers.last().ok_or("missing dispatch approval")?.clone(),
    ))
}

fn extract_operation_id(envelope: &Value) -> TestResult<String> {
    let steps = array(envelope, &["payload", "steps"])?;
    let prepare = steps
        .iter()
        .find(|s| text(s, &["stepId"]).is_ok_and(|id| id == "step:prepare"))
        .ok_or("missing step:prepare")?;
    texts(prepare, &["writeWitnesses"])?
        .into_iter()
        .next()
        .ok_or_else(|| "missing operation witness".into())
}

pub fn run_effects_and_closing(
    ops_mcp: &mut McpClient,
    ctx: &EffectsContext<'_>,
) -> TestResult<EffectsOutcome> {
    let snap_now = read_deployment(ctx.deploy_root, &OrientLimits::default())?;
    let retained_corr = snap_now
        .event(&EventId::parse(ctx.corr_event_id)?)
        .ok_or("corroborated event missing from snapshot")?;

    // 10. Verify dynamic affordance:orient:plan!
    let orient_check = orient_deployment(
        &snap_now,
        &OrientRequest {
            view: AgentView::EpistemicMap,
            principal: PrincipalId::parse(PRINCIPAL)?,
            budget_tokens: None,
        },
        &OrientLimits::default(),
    )?;
    let plan_aff = orient_check
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing dynamic affordance:orient:plan")?;
    assert!(matches!(
        plan_aff.class,
        AffordanceClass::Conditional | AffordanceClass::Robust
    ));

    // 11 & 12. Alert cancel + accepted dispatch/wait/reconcile/feedback + Pure-Rust RFC 8446 TLS 1.3
    //          HMAC webhook + Indeterminate fault/wait/reconcile!
    let ok_relay =
        LoopbackAlertRelay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let drop_relay = LoopbackAlertRelay::spawn(None)?;
    let plaintext_app = ContentDigest::sha256(b"s1 loopback alert approval").to_text();

    // 11a. Prepare BOTH Alert #3 (port-9 cancel target) AND Alert #1 (accepted loopback relay)
    //      while corr_event_id is at the current ledger head (keeps total deployment events <= 3)!
    let c_plan = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(ctx.corr_event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/cancel-check")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
    )?;
    assert!(!c_plan.is_error, "plan(cancel): {}", c_plan.body_text);
    let (c_plan_id, c_plan_app, _) = extract_plan_approvals(&c_plan.envelope)?;
    let c_op_id = extract_operation_id(&c_plan.envelope)?;
    let c_prep = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(ctx.corr_event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/cancel-check")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&c_plan_app)),
        ]),
    )?;
    assert!(
        !c_prep.is_error,
        "plan(cancel approve): {}",
        c_prep.body_text
    );

    // 11b. Prepare + commit + wait + reconcile + close + feedback on Alert #1 (accepted relay)
    let alert_plan = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(ctx.corr_event_id)),
            ("relay", string(&ok_relay.address.to_string())),
            ("path", string("/fss/alert")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
    )?;
    assert!(
        !alert_plan.is_error,
        "plan(alert): {}",
        alert_plan.body_text
    );
    let (plan_id_1, plan_app_1, _) = extract_plan_approvals(&alert_plan.envelope)?;
    let op_id_1 = extract_operation_id(&alert_plan.envelope)?;
    let alert_prep = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(ctx.corr_event_id)),
            ("relay", string(&ok_relay.address.to_string())),
            ("path", string("/fss/alert")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&plan_app_1)),
        ]),
    )?;
    assert!(
        !alert_prep.is_error,
        "plan(alert approve): {}",
        alert_prep.body_text
    );
    let (_, _, dispatch_app_1) = extract_plan_approvals(&alert_prep.envelope)?;
    let alert_commit = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("dispatch")),
            ("plan", string(&plan_id_1)),
            ("approve", string(&dispatch_app_1)),
        ]),
    )?;
    assert!(
        !alert_commit.is_error,
        "commit(dispatch): {}",
        alert_commit.body_text
    );
    assert_eq!(
        text(&alert_commit.envelope, &["payload", "state"])?,
        "adapter_accepted"
    );
    assert_eq!(ok_relay.request_count(), 1);

    let wait_ok = ops_mcp.call(
        "wait",
        &object(&[
            ("operation_id", string(&op_id_1)),
            ("deadline_ms", "50".to_owned()),
        ]),
    )?;
    assert_eq!(
        text(&wait_ok.envelope, &["payload", "state"])?,
        "adapter_accepted"
    );

    let ev_ack = ContentDigest::sha256(b"s1-loopback-ack-proof").to_text();
    let rec1_prev = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id_1)),
            ("outcome", string("delivered")),
            ("evidence", string(&ev_ack)),
            (
                "statement",
                string("Loopback relay accepted alert delivery."),
            ),
        ]),
    )?;
    assert!(!rec1_prev.is_error);
    let rec1_app = texts(&rec1_prev.envelope, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("missing rec1 approval")?;
    let rec1 = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id_1)),
            ("outcome", string("delivered")),
            ("evidence", string(&ev_ack)),
            (
                "statement",
                string("Loopback relay accepted alert delivery."),
            ),
            ("approve", string(&rec1_app)),
        ]),
    )?;
    assert!(!rec1.is_error, "reconcile(op1): {}", rec1.body_text);
    assert_eq!(text(&rec1.envelope, &["payload", "state"])?, "verified");

    let close1 = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(ctx.session_id)),
            ("plan", string(&plan_id_1)),
        ]),
    )?;
    assert!(!close1.is_error, "plan(close 1): {}", close1.body_text);
    let close1_proof = texts(&close1.envelope, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("missing close1 episode proof pointer")?;

    // Record advisory feedback + captured learning proposal on verified closed plan_id_1!
    let fb = ops_mcp.call(
        "feedback",
        &format!(
            r#"{{"session":{},"target":{},"kind":"helpful","statement":"14-tool lifecycle completed with verified TLS 1.3 delivery and reconciliation.","supporting":[{}],"disposition":"create_learning_proposal"}}"#,
            quote(ctx.session_id),
            quote(&format!("plan:{plan_id_1}")),
            quote(&close1_proof)
        ),
    )?;
    assert!(!fb.is_error, "feedback: {}", fb.body_text);
    assert_eq!(
        text(&fb.envelope, &["payloadSchema"])?,
        "fss.experience_capsule.v1"
    );
    assert!(!text(&fb.envelope, &["payload", "experienceId"])?.is_empty());
    assert!(!fb.body_text.contains("\"activePolicyMutation\":true"));

    // Cleanly cancel prepared Alert #3 (port 9) via AOP-010 and close its plan!
    let c_prev = ops_mcp.call("cancel", &object(&[("operation_id", string(&c_op_id))]))?;
    assert!(!c_prev.is_error, "cancel(op preview): {}", c_prev.body_text);
    let c_app = texts(&c_prev.envelope, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("missing cancel approval")?;
    let c_done = ops_mcp.call(
        "cancel",
        &object(&[
            ("operation_id", string(&c_op_id)),
            ("approve", string(&c_app)),
        ]),
    )?;
    assert!(!c_done.is_error, "cancel(op): {}", c_done.body_text);
    assert_eq!(text(&c_done.envelope, &["payload", "state"])?, "cancelled");
    let c_close = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(ctx.session_id)),
            ("plan", string(&c_plan_id)),
        ]),
    )?;
    assert!(
        !c_close.is_error,
        "plan(close cancel): {}",
        c_close.body_text
    );

    // 11b. Pure-Rust RFC 8446 TLS 1.3 HMAC-SHA256 webhook delivery with fss-vault canary secret!
    let pki = build_test_pki(&["hooks.fss.test"], 1_700_000_000, 1_900_000_000, 0x33);
    let tls_listener = TcpListener::bind("127.0.0.1:0")?;
    let tls_addr = tls_listener.local_addr()?;
    let meta_app = ContentDigest::sha256(b"s1-tls-meta-approval");
    let tls_target = HttpsWebhookTarget::new(
        "webhook-tls13-primary",
        &format!("https://hooks.fss.test:{}/alerts/ingest", tls_addr.port()),
        fss_vault::SecretId::parse("secret:webhook:primary-hmac")?,
        TlsTrustPolicy::from_pem_bundle(&pki.ca_pem)?,
        DisclosureProfile::EventMetadataV1,
        Some(meta_app),
        None,
    )?;
    let rig = VaultCanaryRig::open(&ctx.ws.vault_dir, tls_target.secret_scope.clone())?;
    let secret_cx = rig.secret_cx(tls_target.secret_scope.clone())?;

    let tls_journal_path = ctx.ws.base.join("tls_notify_effects.journal");
    let mut tls_journal =
        DurableEffectJournal::open(&tls_journal_path, IncompleteTailPolicy::Reject)?;
    let tls_op_id = OperationId::parse("op:notify:tls13:s1:1")?;
    let tls_idem_str = "idempotency:notify:tls13:s1:1";
    let tls_payload = NotifyPayload {
        operation_id: tls_op_id.clone(),
        idempotency_key: IdempotencyKey::parse(tls_idem_str)?,
        event_root: retained_corr.event_root,
        event_revision_digest: retained_corr.revision_digest,
        channel: tls_target.target_id.clone(),
        event_metadata: Some(NotifyEventMetadata {
            event_id: retained_corr.event.event_id.clone(),
            revision: retained_corr.event.revision,
            kind: "perimeter_breach".to_owned(),
            lifecycle: "corroborated".to_owned(),
            zone_ids: vec!["door".to_owned()],
            summary: "Corroborated two-camera alert delivered over RFC 8446 TLS 1.3".to_owned(),
        }),
        visual_attachment: None,
    };
    prepare_notification_effect(
        &mut tls_journal,
        &tls_payload,
        tls_target.route_digest,
        ContentDigest::sha256(b"s1-tls-precond"),
        ObligationId::parse("obligation:notify:tls13:s1:1")?,
        TimestampNs(rig.now.0 - 1_000),
    )?;
    let dns = PinnedDnsResolver::new().with_entry("hooks.fss.test", tls_addr);
    let (tls_dispatched, tls_verified_srv) = std::thread::scope(|scope| -> TestResult<_> {
        let srv_handle = scope.spawn(|| {
            accept_and_verify_tls13_webhook(&tls_listener, &pki, CANARY_WEBHOOK_HMAC, tls_idem_str)
        });
        let deadline = NotifyDeadlineCx::new(rig.now, Duration::from_secs(5))?;
        let mut cli_entropy = LabEntropy::from_seed([0x55; 32]);
        let res = dispatch_prepared_notification(
            &mut tls_journal,
            NotificationChannelTarget::HttpsWebhook(&tls_target),
            &tls_payload,
            &rig.vault,
            &secret_cx,
            &dns,
            &deadline,
            NotifyLimits::default(),
            &mut cli_entropy,
        )?;
        let verified = srv_handle
            .join()
            .map_err(|_| "TLS 1.3 webhook server thread panicked")?
            .map_err(|e| format!("TLS 1.3 webhook server verification failed: {e}"))?;
        Ok((res, verified))
    })?;
    assert_eq!(
        tls_dispatched.operation_receipt.state,
        EffectState::AdapterAccepted
    );
    assert!(
        tls_verified_srv
            .request_line
            .starts_with("POST /alerts/ingest ")
    );
    assert!(tls_verified_srv.body_bytes > 0);
    assert!(tls_verified_srv.signature_header.starts_with("sha256="));
    assert_eq!(tls_verified_srv.idempotency_key, tls_idem_str);
    assert_eq!(tls_verified_srv.delivery_id, tls_op_id.as_str());
    let _ = reconcile_notification_verified(
        &mut tls_journal,
        &tls_op_id,
        ContentDigest::sha256(b"tls13-verified-ack"),
        TimestampNs(rig.now.0 + 1_000),
        TimestampNs(rig.now.0 + 2_000),
    )?;

    // 12. Indeterminate alert delivery + wait + reconcile (fresh corroborated event at current head)!
    let ind_event_id = publish_corroborated_event(
        ctx.deploy_root,
        ctx.east_arg,
        ctx.west_arg,
        "door_ind:32,0,40,48",
    )?;
    rebase_session(
        ops_mcp,
        ctx.session_id,
        "Rebase session onto fresh head for Indeterminate alert reconciliation check.",
    )?;
    let ind_plan = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(&ind_event_id)),
            ("relay", string(&drop_relay.address.to_string())),
            ("path", string("/fss/drop")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
    )?;
    assert!(
        !ind_plan.is_error,
        "plan(indeterminate): {}",
        ind_plan.body_text
    );
    let (ind_plan_id, ind_plan_app, _) = extract_plan_approvals(&ind_plan.envelope)?;
    let ind_op_id = extract_operation_id(&ind_plan.envelope)?;
    let ind_prep = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(ctx.session_id)),
            ("event_id", string(&ind_event_id)),
            ("relay", string(&drop_relay.address.to_string())),
            ("path", string("/fss/drop")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&ind_plan_app)),
        ]),
    )?;
    assert!(!ind_prep.is_error);
    let (_, _, ind_dispatch_app) = extract_plan_approvals(&ind_prep.envelope)?;
    let ind_commit = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("dispatch")),
            ("plan", string(&ind_plan_id)),
            ("approve", string(&ind_dispatch_app)),
        ]),
    )?;
    assert!(ind_commit.is_error);
    assert_eq!(text(&ind_commit.envelope, &["outcome"])?, "indeterminate");
    assert_eq!(
        text(&ind_commit.envelope, &["errorId"])?,
        "ERR-EFFECT-INDETERMINATE-001"
    );
    assert_eq!(drop_relay.connections(), 1);

    let ind_wait = ops_mcp.call(
        "wait",
        &object(&[
            ("operation_id", string(&ind_op_id)),
            ("deadline_ms", "20".to_owned()),
        ]),
    )?;
    assert_eq!(
        text(&ind_wait.envelope, &["payload", "state"])?,
        "indeterminate"
    );

    let ind_ev = ContentDigest::sha256(b"s1-indeterminate-reconcile-evidence").to_text();
    let ind_rec_prev = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&ind_op_id)),
            ("outcome", string("delivered")),
            ("evidence", string(&ind_ev)),
            (
                "statement",
                string("Owner verified delivery after dropped HTTP acknowledgement."),
            ),
        ]),
    )?;
    assert!(!ind_rec_prev.is_error);
    let ind_rec_app = texts(&ind_rec_prev.envelope, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("missing ind reconcile approval")?;
    let ind_rec = ops_mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&ind_op_id)),
            ("outcome", string("delivered")),
            ("evidence", string(&ind_ev)),
            (
                "statement",
                string("Owner verified delivery after dropped HTTP acknowledgement."),
            ),
            ("approve", string(&ind_rec_app)),
        ]),
    )?;
    assert!(
        !ind_rec.is_error,
        "reconcile(indeterminate): {}",
        ind_rec.body_text
    );
    assert_eq!(text(&ind_rec.envelope, &["payload", "state"])?, "verified");
    assert_eq!(
        drop_relay.connections(),
        1,
        "indeterminate must never resend"
    );
    let ind_close = ops_mcp.call(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(ctx.session_id)),
            ("plan", string(&ind_plan_id)),
        ]),
    )?;
    assert!(!ind_close.is_error);

    // 13. Cleanly revoke session -> operational intents (evidence-hold,
    //     retention-policy, live camera-supervision, privacy-mask)!
    let s_prev = ops_mcp.call("cancel", &object(&[("session", string(ctx.session_id))]))?;
    assert!(!s_prev.is_error);
    let s_app = texts(&s_prev.envelope, &["proofPointers"])?
        .into_iter()
        .find(|p| p.starts_with("sha256:"))
        .ok_or("missing session cancel approval")?;
    let s_done = ops_mcp.call(
        "cancel",
        &object(&[
            ("session", string(ctx.session_id)),
            ("approve", string(&s_app)),
        ]),
    )?;
    assert!(!s_done.is_error, "cancel(session): {}", s_done.body_text);

    // Operational intent 10a: evidence-hold
    let hold_plan = ops_mcp.call(
        "plan",
        &format!(
            r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-s1-001","import_id":{},"reason":"preserve corroborated evidence"}}"#,
            quote(ctx.sentinel_import_hex)
        ),
    )?;
    assert!(
        !hold_plan.is_error,
        "plan(evidence-hold): {}",
        hold_plan.body_text
    );
    let hold_app = text(&hold_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let hold_commit = ops_mcp.call(
        "commit",
        &format!(
            r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-s1-001","import_id":{},"reason":"preserve corroborated evidence","approval_digest":{}}}"#,
            quote(ctx.sentinel_import_hex),
            quote(&hold_app)
        ),
    )?;
    assert!(
        !hold_commit.is_error,
        "commit(evidence-hold): {}",
        hold_commit.body_text
    );
    assert!(bool_field(
        &hold_commit.envelope,
        &["payload", "authorityChanged"]
    )?);

    // Operational intent 10b: retention-policy
    let attested_ns = wall_now_ns()?;
    let ret_args_base = format!(
        r#""intent":"retention-policy","sensor":"sensor:porch-cam","enabled":true,"retain_for_ns":3600000000000,"max_retained_source_bytes":50000000,"attested_earliest_ns":{attested_ns},"attested_latest_ns":{attested_ns},"reason":"bounded ring cap""#
    );
    let ret_plan = ops_mcp.call("plan", &format!("{{{ret_args_base}}}"))?;
    assert!(
        !ret_plan.is_error,
        "plan(retention-policy): {}",
        ret_plan.body_text
    );
    let ret_app = text(&ret_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let ret_commit = ops_mcp.call(
        "commit",
        &format!(
            r#"{{{ret_args_base},"approval_digest":{}}}"#,
            quote(&ret_app)
        ),
    )?;
    assert!(
        !ret_commit.is_error,
        "commit(retention-policy): {}",
        ret_commit.body_text
    );
    assert!(bool_field(
        &ret_commit.envelope,
        &["payload", "authorityChanged"]
    )?);

    // Operational intent 10c: camera-supervision against LIVE fss-daemon over UDS fss-ipc!
    let sup_plan = ops_mcp.call(
        "plan",
        r#"{"intent":"camera-supervision","op":"trigger_scrub"}"#,
    )?;
    assert!(
        !sup_plan.is_error,
        "plan(camera-supervision): {}",
        sup_plan.body_text
    );
    let sup_app = text(&sup_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let sup_commit = ops_mcp.call(
        "commit",
        &format!(
            r#"{{"intent":"camera-supervision","op":"trigger_scrub","approval_digest":{}}}"#,
            quote(&sup_app)
        ),
    )?;
    assert!(
        !sup_commit.is_error,
        "commit(camera-supervision): {}",
        sup_commit.body_text
    );
    assert_eq!(
        text(&sup_commit.envelope, &["payload", "status"])?,
        "queued"
    );

    // Operational intent 10d: privacy-mask
    let pm_plan = ops_mcp.call(
        "plan",
        r#"{"intent":"privacy-mask","sensor":"sensor:porch-cam","resolution":[128,96],"rectangles":[[16,16,48,32]]}"#,
    )?;
    assert!(
        !pm_plan.is_error,
        "plan(privacy-mask): {}",
        pm_plan.body_text
    );
    let pm_app = text(&pm_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let pm_commit = ops_mcp.call(
        "commit",
        &format!(
            r#"{{"intent":"privacy-mask","sensor":"sensor:porch-cam","resolution":[128,96],"rectangles":[[16,16,48,32]],"approval_digest":{}}}"#,
            quote(&pm_app)
        ),
    )?;
    assert!(
        !pm_commit.is_error,
        "commit(privacy-mask): {}",
        pm_commit.body_text
    );
    assert!(bool_field(
        &pm_commit.envelope,
        &["payload", "authorityChanged"]
    )?);

    Ok(EffectsOutcome {
        rig,
        tls13_idempotency_key: tls_verified_srv.idempotency_key,
        tls_audit_jsonl: tls_dispatched.audit_record.to_jsonl(),
        tls_journal_path,
    })
}

pub fn scan_all_canary_surfaces(
    rig: &VaultCanaryRig,
    deploy_root: &Path,
    tls_journal_path: &Path,
    tls_audit_jsonl: &str,
    transcript: &[TranscriptEntry],
    telemetry_lines: &[String],
) -> TestResult<(usize, usize)> {
    let mut surfaces = 0_usize;
    let mut bytes_scanned = 0_usize;
    let mut scan = |label: &str, data: &[u8]| -> TestResult {
        surfaces += 1;
        bytes_scanned += data.len();
        rig.scanner.assert_clean(label, data)?;
        Ok(())
    };
    for (idx, entry) in transcript.iter().enumerate() {
        scan(&format!("s1_req_{idx}"), entry.request_json.as_bytes())?;
        scan(&format!("s1_resp_{idx}"), entry.response_json.as_bytes())?;
    }
    for (idx, line) in telemetry_lines.iter().enumerate() {
        scan(&format!("s1_daemon_telemetry_{idx}"), line.as_bytes())?;
    }
    scan("s1_tls_audit_jsonl", tls_audit_jsonl.as_bytes())?;
    for path in [
        deploy_root.join("effects/journal.fssj"),
        deploy_root.join("ledger/journal.fssj"),
        deploy_root.join("agent/sessions/journal.fssj"),
        tls_journal_path.to_path_buf(),
    ] {
        if path.is_file() {
            let bytes = fs::read(&path)?;
            scan(&path.display().to_string(), &bytes)?;
        }
    }
    Ok((surfaces, bytes_scanned))
}
