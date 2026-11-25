#![forbid(unsafe_code)]
//! Loopback TLS 1.3 E2E contract, adversarial fault, multi-channel relay, escalation,
//! and canary leak-audit tests for `fss_reference::notify` (`fss-x4a.31.4.3`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContextAuthority, EffectIntent,
    EffectJournal, EffectState, EventId, IdempotencyKey, ObligationId, OperationId,
    RootAuthoritySpec, TimestampNs,
};
use fss_ledger::IncompleteTailPolicy;
use fss_reference::DurableEffectJournal;
use fss_reference::notify::ed25519::Ed25519SigningKey;
use fss_reference::notify::escalation::{
    DeliveryAuditRecord, EscalationPolicy, EscalationReason, NotificationChannelTarget,
    compute_notification_request_digest, dispatch_prepared_notification, prepare_escalation,
    prepare_notification_effect, reconcile_notification_verified,
};
use fss_reference::notify::relays::{NtfyTarget, PushoverTarget};
use fss_reference::notify::smtp::{SmtpSecurityMode, SmtpTlsTarget};
use fss_reference::notify::tls13::Tls13Stream;
use fss_reference::notify::webhook::{HttpsWebhookTarget, verify_webhook_signature};
use fss_reference::notify::x509::{
    CertBuilderParams, ERR_NOTIFY_TLS_CERT_001, TlsTrustPolicy, build_ed25519_x509_der,
    encode_cert_pem,
};
use fss_reference::notify::{
    DisclosureProfile, ERR_NOTIFY_DISCLOSURE_001, ERR_NOTIFY_INDETERMINATE_001,
    ERR_NOTIFY_PLAINTEXT_REFUSED_001, ERR_NOTIFY_REDIRECT_REFUSED_001, ERR_NOTIFY_TIMEOUT_001,
    ERR_NOTIFY_TRANSPORT_001, H3VisualAttachment, NotifyDeadlineCx, NotifyEventMetadata,
    NotifyLimits, NotifyPayload, PinnedDnsResolver,
};
use fss_vault::{
    CAP_SECRET_READ_001, CAP_SECRET_WRITE_001, CanaryLeakScanner, KdfParams, LabEntropy,
    LocalEncryptedVault, SecretAccessCx, SecretBytes, SecretId, SecretScope, SecretStore,
};

struct TestPki {
    ca_der: Vec<u8>,
    ca_pem: String,
    leaf_der: Vec<u8>,
    leaf_sk: Ed25519SigningKey,
}

fn build_test_pki(san_dns: &[&str], not_before_s: i64, not_after_s: i64, seed: u8) -> TestPki {
    let ca_sk = Ed25519SigningKey::from_seed([seed; 32]);
    let leaf_sk = Ed25519SigningKey::from_seed([seed.wrapping_add(1); 32]);
    let ca_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 1,
            issuer_cn: "FSS Contract Root CA",
            subject_cn: "FSS Contract Root CA",
            san_dns: &[],
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: true,
        },
        &ca_sk.verifying_key(),
        &ca_sk,
    );
    let leaf_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 2,
            issuer_cn: "FSS Contract Root CA",
            subject_cn: san_dns.first().copied().unwrap_or("localhost"),
            san_dns,
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &ca_sk,
    );
    let ca_pem = encode_cert_pem(&ca_der);
    TestPki {
        ca_der,
        ca_pem,
        leaf_der,
        leaf_sk,
    }
}

fn make_temp_dir(tag: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fss-notify-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn make_secret_cx(
    scope: SecretScope,
    now: TimestampNs,
) -> Result<SecretAccessCx, Box<dyn std::error::Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:notify-e2e".to_owned(),
        operation_id: OperationId::parse("op:vault:notify-e2e")?,
        principal: "principal:operator:e2e".to_owned(),
        capabilities: vec![
            CAP_SECRET_READ_001.to_owned(),
            CAP_SECRET_WRITE_001.to_owned(),
        ],
        deadline: None,
        priority: 100,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:owner".to_owned(),
        retention_scope: "retention:standard".to_owned(),
        anchor_universe: ContentDigest::sha256(b"universe"),
        generation: 1,
    })?;
    Ok(SecretAccessCx::new(authority, scope, now)?)
}

fn open_test_vault(
    dir: &std::path::Path,
) -> Result<LocalEncryptedVault<LabEntropy>, Box<dyn std::error::Error>> {
    let pass = SecretBytes::from_slice(b"test-vault-master-passphrase")?;
    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir,
        KdfParams::for_testing(1)?,
        LabEntropy::from_seed([0x99; 32]),
    );
    vault.initialize(&pass)?;
    Ok(vault)
}

fn sample_metadata() -> Result<NotifyEventMetadata, Box<dyn std::error::Error>> {
    Ok(NotifyEventMetadata {
        event_id: EventId::parse("evt:driveway:2026:01")?,
        revision: 3,
        kind: "unknown_presence".to_owned(),
        lifecycle: "corroborated".to_owned(),
        zone_ids: vec!["driveway-north".to_owned(), "porch-entry".to_owned()],
        summary: "Corroborated motion across two independent cameras".to_owned(),
    })
}

fn sample_redacted_h3() -> Result<H3VisualAttachment, Box<dyn std::error::Error>> {
    // Minimal valid SOI..EOI baseline JPEG frame marker bytes representing pre-redacted H3 output.
    let jpeg = vec![
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x04, 0x00, 0x10, 0xff, 0xd9,
    ];
    Ok(H3VisualAttachment::build_redacted(
        ContentDigest::sha256(b"source-import-001"),
        ContentDigest::sha256(b"source-capsule-001"),
        "cam-driveway-01",
        ContentDigest::sha256(b"privacy-mask-binding-gen-4"),
        320,
        180,
        jpeg,
    )?)
}

type ParsedHttpRequest = (String, Vec<(String, String)>, Vec<u8>);

fn read_http_request_over_tls(
    tls: &mut Tls13Stream<std::net::TcpStream>,
) -> Result<ParsedHttpRequest, String> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("server read header failed: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF reading HTTP request headers".to_owned());
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let head = std::str::from_utf8(&raw[..header_end - 4]).map_err(|e| e.to_string())?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or("missing request line")?.to_owned();
    let mut headers = Vec::new();
    let mut content_len = 0_usize;
    for line in lines {
        let (k, v) = line.split_once(':').ok_or("malformed header")?;
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_owned();
        if key == "content-length" {
            content_len = val.parse::<usize>().map_err(|e| e.to_string())?;
        }
        headers.push((key, val));
    }
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("server read body failed: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF reading HTTP request body".to_owned());
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_len);
    Ok((req_line, headers, body))
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
fn loopback_tls13_https_webhook_hmac_e2e_idempotency_and_durable_journal()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("webhook-e2e")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(&["hooks.fss.test"], 1_700_000_000, 1_900_000_000, 0x10);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr: SocketAddr = listener.local_addr()?;

    let hmac_canary = b"CANARY-WEBHOOK-HMAC-KEY-918273645!";
    let hmac_secret_id = SecretId::parse("secret:webhook:primary-hmac")?;
    let meta_approval = ContentDigest::sha256(b"approval:meta:v1");
    let target = HttpsWebhookTarget::new(
        "webhook-primary",
        &format!("https://hooks.fss.test:{}/alerts/ingest", addr.port()),
        hmac_secret_id.clone(),
        TlsTrustPolicy::from_pem_bundle(&pki.ca_pem)?,
        DisclosureProfile::EventMetadataV1,
        Some(meta_approval),
        None,
    )?;

    let mut vault = open_test_vault(&dir.join("vault"))?;
    let secret_cx = make_secret_cx(target.secret_scope.clone(), now)?;
    vault.store(
        &secret_cx,
        &hmac_secret_id,
        SecretBytes::from_slice(hmac_canary)?,
    )?;

    let journal_path = dir.join("effects.journal");
    let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let op_id = OperationId::parse("op:notify:webhook:e2e:1")?;
    let payload = NotifyPayload {
        operation_id: op_id.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:webhook:e2e:1")?,
        event_root: ContentDigest::sha256(b"evt-root-e2e"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev-e2e"),
        channel: target.target_id.clone(),
        event_metadata: Some(sample_metadata()?),
        visual_attachment: None,
    };
    prepare_notification_effect(
        &mut journal,
        &payload,
        target.route_digest,
        ContentDigest::sha256(b"precond-e2e"),
        ObligationId::parse("obligation:notify:webhook:e2e:1")?,
        TimestampNs(now.0 - 10_000),
    )?;

    let dns = PinnedDnsResolver::new().with_entry("hooks.fss.test", addr);
    let server_hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&server_hits);
    let expected_secret = hmac_canary.to_vec();

    let dispatched = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let leaf_sk = pki.leaf_sk.clone();
        let server_handle = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
            let mut srv_entropy = LabEntropy::from_seed([0x21; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &leaf_sk, &mut srv_entropy)
                .map_err(|e| e.to_string())?;
            let (req_line, headers, body) = read_http_request_over_tls(&mut tls)?;
            hits_clone.fetch_add(1, Ordering::SeqCst);

            if !req_line.starts_with("POST /alerts/ingest HTTP/1.1") {
                return Err(format!("unexpected request line: {req_line}"));
            }
            let ts: i64 = find_header(&headers, "x-fss-timestamp")
                .ok_or("missing X-FSS-Timestamp")?
                .parse()
                .map_err(|_| "bad X-FSS-Timestamp")?;
            let delivery_id = find_header(&headers, "x-fss-delivery-id")
                .ok_or("missing X-FSS-Delivery-Id")?;
            let sig = find_header(&headers, "x-fss-signature-256")
                .ok_or("missing X-FSS-Signature-256")?;
            if !verify_webhook_signature(&expected_secret, ts, delivery_id, &body, sig) {
                return Err("server HMAC-SHA256 webhook signature verification failed".to_owned());
            }
            let body_str = std::str::from_utf8(&body).map_err(|e| e.to_string())?;
            if !body_str.contains("driveway-north") || !body_str.contains("event-metadata-v1") {
                return Err("webhook metadata payload missing expected fields".to_owned());
            }

            let resp = "HTTP/1.1 202 Accepted\r\nContent-Length: 11\r\nX-Request-Id: wh-msg-001\r\nConnection: close\r\n\r\n{\"ok\":true}";
            tls.write_application_data(resp.as_bytes())
                .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(())
        });

        let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(5))?;
        let mut cli_entropy = LabEntropy::from_seed([0x22; 32]);
        let res = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::HttpsWebhook(&target),
            &payload,
            &vault,
            &secret_cx,
            &dns,
            &deadline,
            NotifyLimits::default(),
            &mut cli_entropy,
        )?;
        server_handle
            .join()
            .map_err(|_| "webhook server panicked")??;
        Ok(res)
    })?;

    assert_eq!(server_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        dispatched.operation_receipt.state,
        EffectState::AdapterAccepted
    );
    assert_eq!(dispatched.delivery_receipt.observation.protocol_status, 202);
    assert_eq!(
        dispatched.delivery_receipt.observation.dns_receipt.hostname,
        "hooks.fss.test"
    );
    assert_eq!(
        dispatched.delivery_receipt.remote_message_id.as_deref(),
        Some("wh-msg-001")
    );

    // Retry with same operation_id is strictly refused idempotently without touching network!
    let deadline2 = NotifyDeadlineCx::new(TimestampNs(now.0 + 100), Duration::from_secs(2))?;
    let mut cli_entropy2 = LabEntropy::from_seed([0x23; 32]);
    let dup = dispatch_prepared_notification(
        &mut journal,
        NotificationChannelTarget::HttpsWebhook(&target),
        &payload,
        &vault,
        &secret_cx,
        &dns,
        &deadline2,
        NotifyLimits::default(),
        &mut cli_entropy2,
    );
    assert!(dup.is_err());
    assert_eq!(server_hits.load(Ordering::SeqCst), 1);

    // Reconcile to Verified and prove durability across reopen!
    let proof = ContentDigest::sha256(b"independent-webhook-ack-proof");
    let verified = reconcile_notification_verified(
        &mut journal,
        &op_id,
        proof,
        TimestampNs(now.0 + 1_000),
        TimestampNs(now.0 + 2_000),
    )?;
    assert_eq!(verified.state, EffectState::Verified);
    drop(journal);

    let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        reopened.operation(&op_id).map(|r| r.state),
        Some(EffectState::Verified)
    );

    // Canary leak scan across receipts, audit JSONL, Debug output, and durable journal bytes!
    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("webhook-hmac-canary", hmac_canary)?;
    scanner.assert_clean(
        "delivery_receipt_debug",
        format!("{:?}", dispatched.delivery_receipt).as_bytes(),
    )?;
    scanner.assert_clean("audit_jsonl", dispatched.audit_record.to_jsonl().as_bytes())?;
    scanner.assert_clean("target_debug", format!("{target:?}").as_bytes())?;
    let journal_bytes = std::fs::read(&journal_path)?;
    scanner.assert_clean("durable_effect_journal", &journal_bytes)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn adversarial_tls_cert_san_ca_expiry_redirect_disclosure_and_indeterminate_faults()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("adversarial-faults")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let mut vault = open_test_vault(&dir.join("vault"))?;
    let secret_id = SecretId::parse("secret:webhook:faults")?;

    // Helper closure for testing pre-send TLS certificate refusals with ZERO HTTP bytes sent!
    let mut run_tls_refusal_case = |case_name: &str,
                                    server_pki: &TestPki,
                                    client_trust: TlsTrustPolicy,
                                    expected_host: &str|
     -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let target = HttpsWebhookTarget::new(
            format!("wh-{case_name}"),
            &format!("https://{expected_host}:{}/hook", addr.port()),
            secret_id.clone(),
            client_trust,
            DisclosureProfile::ReferencesV1,
            None,
            None,
        )?;
        let sid_case = SecretId::parse(format!("secret:webhook:{case_name}"))?;
        let target = HttpsWebhookTarget::new(
            format!("wh-{case_name}"),
            &format!("https://{expected_host}:{}/hook", addr.port()),
            sid_case.clone(),
            target.tls_trust.clone(),
            DisclosureProfile::ReferencesV1,
            None,
            None,
        )?;
        let cx = make_secret_cx(target.secret_scope.clone(), now)?;
        vault.store(
            &cx,
            &sid_case,
            SecretBytes::from_slice(b"fault-hmac-key-0001")?,
        )?;

        let mut journal = EffectJournal::new();
        let op_id = OperationId::parse(format!("op:notify:fault:{case_name}"))?;
        let payload = NotifyPayload {
            operation_id: op_id.clone(),
            idempotency_key: IdempotencyKey::parse(format!(
                "idempotency:notify:fault:{case_name}"
            ))?,
            event_root: ContentDigest::sha256(b"root"),
            event_revision_digest: ContentDigest::sha256(b"rev"),
            channel: target.target_id.clone(),
            event_metadata: None,
            visual_attachment: None,
        };
        prepare_notification_effect(
            &mut journal,
            &payload,
            target.route_digest,
            ContentDigest::sha256(b"pre"),
            ObligationId::parse(format!("obligation:notify:fault:{case_name}"))?,
            TimestampNs(now.0 - 10),
        )?;

        let http_bytes_seen = Arc::new(AtomicUsize::new(0));
        let seen_clone = Arc::clone(&http_bytes_seen);
        let dns = PinnedDnsResolver::new().with_entry(expected_host, addr);

        let err = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
            let chain = vec![server_pki.leaf_der.clone()];
            let sk = server_pki.leaf_sk.clone();
            let h = scope.spawn(move || {
                if let Ok((sock, _)) = listener.accept() {
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = sock.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut ent = LabEntropy::from_seed([0x31; 32]);
                    if let Ok(mut tls) = Tls13Stream::accept_server(sock, &chain, &sk, &mut ent) {
                        let mut buf = [0_u8; 64];
                        if let Ok(n) = tls.read_application_data(&mut buf) {
                            seen_clone.fetch_add(n, Ordering::SeqCst);
                        }
                    }
                }
            });
            let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(5))?;
            let mut ent = LabEntropy::from_seed([0x32; 32]);
            let res = dispatch_prepared_notification(
                &mut journal,
                NotificationChannelTarget::HttpsWebhook(&target),
                &payload,
                &vault,
                &cx,
                &dns,
                &deadline,
                NotifyLimits::default(),
                &mut ent,
            );
            let _ = h.join();
            Ok(res)
        })?;

        let notify_err = err.err().ok_or("expected TLS cert refusal")?;
        assert_eq!(notify_err.code, ERR_NOTIFY_TLS_CERT_001, "case={case_name}");
        assert_eq!(
            http_bytes_seen.load(Ordering::SeqCst),
            0,
            "ZERO HTTP bytes may be sent on cert failure ({case_name})"
        );
        assert_eq!(
            journal.operation(&op_id).map(|r| r.state),
            Some(EffectState::Failed)
        );
        Ok(())
    };

    let valid_pki = build_test_pki(&["real.fss.test"], 1_700_000_000, 1_900_000_000, 0x40);
    let other_ca_pki = build_test_pki(&["real.fss.test"], 1_700_000_000, 1_900_000_000, 0x50);
    let expired_pki = build_test_pki(&["real.fss.test"], 1_600_000_000, 1_700_000_000, 0x60);

    // 1. Mismatched SAN / wrong hostname -> ERR-NOTIFY-TLS-CERT-001, 0 HTTP bytes
    run_tls_refusal_case(
        "wrong-san",
        &valid_pki,
        TlsTrustPolicy::from_ca_certs_der(vec![valid_pki.ca_der.clone()]),
        "wrong.fss.test",
    )?;
    // 2. Untrusted / forged CA -> ERR-NOTIFY-TLS-CERT-001, 0 HTTP bytes
    run_tls_refusal_case(
        "untrusted-ca",
        &other_ca_pki,
        TlsTrustPolicy::from_ca_certs_der(vec![valid_pki.ca_der.clone()]),
        "real.fss.test",
    )?;
    // 3. Expired certificate -> ERR-NOTIFY-TLS-CERT-001, 0 HTTP bytes
    run_tls_refusal_case(
        "expired-cert",
        &expired_pki,
        TlsTrustPolicy::from_ca_certs_der(vec![expired_pki.ca_der.clone()]),
        "real.fss.test",
    )?;

    // 4. Plaintext http:// rejected in production mode
    let pt_err = HttpsWebhookTarget::new(
        "wh-plaintext",
        "http://real.fss.test:8080/hook",
        secret_id,
        TlsTrustPolicy::from_ca_certs_der(vec![valid_pki.ca_der.clone()]),
        DisclosureProfile::ReferencesV1,
        None,
        None,
    );
    assert!(pt_err.is_err_and(|e| e.code == ERR_NOTIFY_PLAINTEXT_REFUSED_001));

    // 5. HTTP 302 redirect refused fail-closed + mid-response socket drop -> Indeterminate + no resend!
    for (fault_name, mode) in [
        ("redirect-302", 1_u8),
        ("mid-response-drop", 2_u8),
        ("post-write-timeout", 3_u8),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let sid = SecretId::parse(format!("secret:webhook:{fault_name}"))?;
        let target = HttpsWebhookTarget::new(
            format!("wh-{fault_name}"),
            &format!("https://real.fss.test:{}/hook", addr.port()),
            sid.clone(),
            TlsTrustPolicy::from_ca_certs_der(vec![valid_pki.ca_der.clone()]),
            DisclosureProfile::ReferencesV1,
            None,
            None,
        )?;
        let cx = make_secret_cx(target.secret_scope.clone(), now)?;
        vault.store(&cx, &sid, SecretBytes::from_slice(b"fault-hmac-key-0002")?)?;
        let mut journal = EffectJournal::new();
        let op_id = OperationId::parse(format!("op:notify:fault:{fault_name}"))?;
        let payload = NotifyPayload {
            operation_id: op_id.clone(),
            idempotency_key: IdempotencyKey::parse(format!(
                "idempotency:notify:fault:{fault_name}"
            ))?,
            event_root: ContentDigest::sha256(b"root"),
            event_revision_digest: ContentDigest::sha256(b"rev"),
            channel: target.target_id.clone(),
            event_metadata: Some(sample_metadata()?),
            visual_attachment: None,
        };
        prepare_notification_effect(
            &mut journal,
            &payload,
            target.route_digest,
            ContentDigest::sha256(b"pre"),
            ObligationId::parse(format!("obligation:notify:fault:{fault_name}"))?,
            TimestampNs(now.0 - 10),
        )?;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        let dns = PinnedDnsResolver::new().with_entry("real.fss.test", addr);

        let res = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
            let chain = vec![valid_pki.leaf_der.clone()];
            let sk = valid_pki.leaf_sk.clone();
            let h = scope.spawn(move || -> Result<(), String> {
                let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
                let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = sock.set_write_timeout(Some(Duration::from_secs(3)));
                let mut ent = LabEntropy::from_seed([0x71; 32]);
                let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut ent)
                    .map_err(|e| e.to_string())?;
                let (_req_line, _headers, body) = read_http_request_over_tls(&mut tls)?;
                hits_clone.fetch_add(1, Ordering::SeqCst);
                // Prove references-v1 emitted ZERO event metadata or zone strings on wire!
                let body_text = std::str::from_utf8(&body).map_err(|e| e.to_string())?;
                if body_text.contains("driveway-north") || body_text.contains("unknown_presence") {
                    return Err("references-v1 leaked event metadata!".to_owned());
                }
                match mode {
                    1 => {
                        let _ = tls.write_application_data(
                            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/x\r\nContent-Length: 0\r\n\r\n",
                        );
                    }
                    2 => {
                        // Send truncated response header then kill socket immediately!
                        let _ = tls.write_application_data(b"HTTP/1.1 200 ");
                        drop(tls);
                    }
                    _ => {
                        // Hold socket open past client deadline so client times out post-write!
                        std::thread::sleep(Duration::from_millis(900));
                    }
                }
                Ok(())
            });

            let timeout = if mode == 3 {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(3)
            };
            let deadline = NotifyDeadlineCx::new(now, timeout)?;
            let mut ent = LabEntropy::from_seed([0x72; 32]);
            let r = dispatch_prepared_notification(
                &mut journal,
                NotificationChannelTarget::HttpsWebhook(&target),
                &payload,
                &vault,
                &cx,
                &dns,
                &deadline,
                NotifyLimits::default(),
                &mut ent,
            );
            let _ = h.join();
            Ok(r)
        })?;

        let err = res.err().ok_or("expected post-send fault")?;
        if mode == 1 {
            assert_eq!(err.code, ERR_NOTIFY_REDIRECT_REFUSED_001);
        } else {
            assert_eq!(err.code, ERR_NOTIFY_INDETERMINATE_001);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            journal.operation(&op_id).map(|r| r.state),
            Some(EffectState::Indeterminate)
        );

        // Retrying the Indeterminate operation MUST refuse automatic resend with ZERO extra calls!
        let retry_deadline =
            NotifyDeadlineCx::new(TimestampNs(now.0 + 50), Duration::from_secs(2))?;
        let mut ent2 = LabEntropy::from_seed([0x73; 32]);
        let retry = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::HttpsWebhook(&target),
            &payload,
            &vault,
            &cx,
            &dns,
            &retry_deadline,
            NotifyLimits::default(),
            &mut ent2,
        );
        assert!(retry.is_err_and(|e| e.code == ERR_NOTIFY_INDETERMINATE_001));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    // 6. Disclosure refusal check: event-metadata-visual-v1 rejects missing visual approval or unredacted H3
    let sid_vis = SecretId::parse("secret:webhook:vis-check")?;
    let missing_vis_approval = HttpsWebhookTarget::new(
        "wh-vis-missing",
        "https://real.fss.test:8443/hook",
        sid_vis,
        TlsTrustPolicy::from_ca_certs_der(vec![valid_pki.ca_der]),
        DisclosureProfile::EventMetadataVisualV1,
        Some(ContentDigest::sha256(b"meta")),
        None,
    );
    assert!(missing_vis_approval.is_err_and(|e| e.code == ERR_NOTIFY_DISCLOSURE_001));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn loopback_tls13_ntfy_and_pushover_relays_e2e_with_canary_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("ntfy-pushover")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(
        &["ntfy.fss.test", "api.pushover.test"],
        1_700_000_000,
        1_900_000_000,
        0x80,
    );
    let mut vault = open_test_vault(&dir.join("vault"))?;
    let mut scanner = CanaryLeakScanner::new();

    // --- 1. ntfy TLS 1.3 E2E ---
    let ntfy_listener = TcpListener::bind("127.0.0.1:0")?;
    let ntfy_addr = ntfy_listener.local_addr()?;
    let ntfy_token = b"CANARY-NTFY-BEARER-SECRET-771122";
    scanner.register_bytes("ntfy-bearer", ntfy_token)?;
    let ntfy_sid = SecretId::parse("secret:relay:ntfy-token")?;
    let ntfy_target = NtfyTarget::new(
        "ntfy-oncall",
        &format!("https://ntfy.fss.test:{}", ntfy_addr.port()),
        "site-north-alerts",
        ntfy_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der.clone()]),
        DisclosureProfile::EventMetadataVisualV1,
        Some(ContentDigest::sha256(b"meta-approval")),
        Some(ContentDigest::sha256(b"visual-approval")),
        5,
        vec!["warning".to_owned(), "camera".to_owned()],
    )?;
    let ntfy_cx = make_secret_cx(ntfy_target.secret_scope.clone(), now)?;
    vault.store(&ntfy_cx, &ntfy_sid, SecretBytes::from_slice(ntfy_token)?)?;

    let mut journal = EffectJournal::new();
    let ntfy_op = OperationId::parse("op:notify:ntfy:1")?;
    let h3 = sample_redacted_h3()?;
    let ntfy_payload = NotifyPayload {
        operation_id: ntfy_op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:ntfy:1")?,
        event_root: ContentDigest::sha256(b"evt-root-ntfy"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev-ntfy"),
        channel: ntfy_target.target_id.clone(),
        event_metadata: Some(sample_metadata()?),
        visual_attachment: Some(h3.clone()),
    };
    prepare_notification_effect(
        &mut journal,
        &ntfy_payload,
        ntfy_target.route_digest,
        ContentDigest::sha256(b"pre-ntfy"),
        ObligationId::parse("obligation:notify:ntfy:1")?,
        TimestampNs(now.0 - 10),
    )?;
    let dns = PinnedDnsResolver::new().with_entry("ntfy.fss.test", ntfy_addr);

    let ntfy_res = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let sk = pki.leaf_sk.clone();
        let expected_jpeg = h3.jpeg_bytes.clone();
        let h = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = ntfy_listener.accept().map_err(|e| e.to_string())?;
            let mut ent = LabEntropy::from_seed([0x81; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut ent)
                .map_err(|e| e.to_string())?;
            let (req_line, headers, body) = read_http_request_over_tls(&mut tls)?;
            if !req_line.starts_with("POST /site-north-alerts HTTP/1.1") {
                return Err(format!("bad ntfy req_line: {req_line}"));
            }
            if find_header(&headers, "authorization") != Some("Bearer CANARY-NTFY-BEARER-SECRET-771122") {
                return Err("ntfy bearer auth mismatch".to_owned());
            }
            if find_header(&headers, "priority") != Some("5")
                || find_header(&headers, "tags") != Some("warning,camera")
                || find_header(&headers, "x-idempotency-key") != Some("idempotency:notify:ntfy:1")
            {
                return Err("ntfy metadata headers mismatch".to_owned());
            }
            if body != expected_jpeg {
                return Err("ntfy redacted H3 JPEG attachment bytes mismatch".to_owned());
            }
            tls.write_application_data(
                b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nX-Message-Id: ntfy-99\r\n\r\n{\"id\":\"ntfy99\"}",
            )
            .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(())
        });

        let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(5))?;
        let mut ent = LabEntropy::from_seed([0x82; 32]);
        let r = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::Ntfy(&ntfy_target),
            &ntfy_payload,
            &vault,
            &ntfy_cx,
            &dns,
            &deadline,
            NotifyLimits::default(),
            &mut ent,
        )?;
        h.join().map_err(|_| "ntfy server panicked")??;
        Ok(r)
    })?;
    assert_eq!(
        ntfy_res.operation_receipt.state,
        EffectState::AdapterAccepted
    );
    assert_eq!(
        ntfy_res.delivery_receipt.observation.visual_receipt_digest,
        Some(h3.receipt_digest)
    );

    // --- 2. Pushover TLS 1.3 E2E ---
    let po_listener = TcpListener::bind("127.0.0.1:0")?;
    let po_addr = po_listener.local_addr()?;
    let po_app = b"CANARY-PUSHOVER-APP-TOKEN-554433";
    let po_user = b"CANARY-PUSHOVER-USER-KEY-889900";
    scanner.register_bytes("pushover-app", po_app)?;
    scanner.register_bytes("pushover-user", po_user)?;
    let app_sid = SecretId::parse("secret:relay:pushover-app")?;
    let user_sid = SecretId::parse("secret:relay:pushover-user")?;
    let po_target = PushoverTarget::new(
        "pushover-oncall",
        &format!(
            "https://api.pushover.test:{}/1/messages.json",
            po_addr.port()
        ),
        app_sid.clone(),
        user_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der]),
        DisclosureProfile::EventMetadataV1,
        Some(ContentDigest::sha256(b"meta-approval-po")),
        None,
        1,
    )?;
    let po_cx = make_secret_cx(po_target.secret_scope.clone(), now)?;
    vault.store(&po_cx, &app_sid, SecretBytes::from_slice(po_app)?)?;
    vault.store(&po_cx, &user_sid, SecretBytes::from_slice(po_user)?)?;

    let po_op = OperationId::parse("op:notify:pushover:1")?;
    let po_payload = NotifyPayload {
        operation_id: po_op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:pushover:1")?,
        event_root: ContentDigest::sha256(b"evt-root-po"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev-po"),
        channel: po_target.target_id.clone(),
        event_metadata: Some(sample_metadata()?),
        visual_attachment: None,
    };
    prepare_notification_effect(
        &mut journal,
        &po_payload,
        po_target.route_digest,
        ContentDigest::sha256(b"pre-po"),
        ObligationId::parse("obligation:notify:pushover:1")?,
        TimestampNs(now.0 - 10),
    )?;
    let po_dns = PinnedDnsResolver::new().with_entry("api.pushover.test", po_addr);

    let po_res = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let sk = pki.leaf_sk.clone();
        let h = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = po_listener.accept().map_err(|e| e.to_string())?;
            let mut ent = LabEntropy::from_seed([0x83; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut ent)
                .map_err(|e| e.to_string())?;
            let (req_line, _headers, body) = read_http_request_over_tls(&mut tls)?;
            if !req_line.starts_with("POST /1/messages.json HTTP/1.1") {
                return Err(format!("bad pushover req_line: {req_line}"));
            }
            let text = std::str::from_utf8(&body).map_err(|e| e.to_string())?;
            if !text.contains("\"token\":\"CANARY-PUSHOVER-APP-TOKEN-554433\"")
                || !text.contains("\"user\":\"CANARY-PUSHOVER-USER-KEY-889900\"")
                || !text.contains("driveway-north")
            {
                return Err("pushover JSON body missing expected credentials or metadata".to_owned());
            }
            tls.write_application_data(
                b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\nX-Request-Id: po-req-77\r\n\r\n{\"status\":1,\"request\":\"7\"}",
            )
            .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(())
        });

        let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(5))?;
        let mut ent = LabEntropy::from_seed([0x84; 32]);
        let r = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::Pushover(&po_target),
            &po_payload,
            &vault,
            &po_cx,
            &po_dns,
            &deadline,
            NotifyLimits::default(),
            &mut ent,
        )?;
        h.join().map_err(|_| "pushover server panicked")??;
        Ok(r)
    })?;
    assert_eq!(po_res.operation_receipt.state, EffectState::AdapterAccepted);

    // Zero secret canary leakage across ALL receipts, targets, and JSONL logs!
    for (label, text) in [
        ("ntfy_target", format!("{ntfy_target:?}")),
        ("ntfy_receipt", format!("{:?}", ntfy_res.delivery_receipt)),
        ("ntfy_jsonl", ntfy_res.audit_record.to_jsonl()),
        ("po_target", format!("{po_target:?}")),
        ("po_receipt", format!("{:?}", po_res.delivery_receipt)),
        ("po_jsonl", po_res.audit_record.to_jsonl()),
    ] {
        scanner.assert_clean(label, text.as_bytes())?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn read_line_plain(sock: &mut std::net::TcpStream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut b = [0_u8; 1];
    while !line.ends_with(b"\r\n") {
        let n = sock.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF reading plain SMTP line".to_owned());
        }
        line.push(b[0]);
    }
    String::from_utf8(line).map_err(|e| e.to_string())
}

fn read_smtp_tls_until(
    tls: &mut Tls13Stream<std::net::TcpStream>,
    buf: &mut Vec<u8>,
    delim: &[u8],
) -> Result<Vec<u8>, String> {
    let mut tmp = [0_u8; 1024];
    loop {
        if let Some(pos) = buf.windows(delim.len()).position(|w| w == delim) {
            let end = pos + delim.len();
            let rest = buf.split_off(end);
            let out = core::mem::replace(buf, rest);
            return Ok(out);
        }
        let n = tls
            .read_application_data(&mut tmp)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF reading TLS SMTP stream".to_owned());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[test]
fn loopback_smtp_implicit_tls_and_starttls_with_redacted_h3_attachment_and_canary_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("smtp-tls-e2e")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(&["smtp.fss.test"], 1_700_000_000, 1_900_000_000, 0x90);
    let mut vault = open_test_vault(&dir.join("vault"))?;
    let mut scanner = CanaryLeakScanner::new();

    let smtp_user = b"CANARY-SMTP-USER-4401";
    let smtp_pass = b"CANARY-SMTP-PASS-99887766!";
    scanner.register_bytes("smtp-user", smtp_user)?;
    scanner.register_bytes("smtp-pass", smtp_pass)?;

    for (mode, label) in [
        (SmtpSecurityMode::ImplicitTls, "smtps"),
        (SmtpSecurityMode::StartTls, "starttls"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let user_sid = SecretId::parse(format!("secret:relay:smtp-user-{label}"))?;
        let pass_sid = SecretId::parse(format!("secret:relay:smtp-pass-{label}"))?;
        let target = SmtpTlsTarget::new(
            format!("email-{label}"),
            "smtp.fss.test",
            addr.port(),
            mode,
            "site.fss.local",
            "alerts@fss.test",
            vec!["owner@fss.test".to_owned()],
            user_sid.clone(),
            pass_sid.clone(),
            TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der.clone()]),
            DisclosureProfile::EventMetadataVisualV1,
            Some(ContentDigest::sha256(b"meta-approval-smtp")),
            Some(ContentDigest::sha256(b"vis-approval-smtp")),
        )?;
        let cx = make_secret_cx(target.secret_scope.clone(), now)?;
        vault.store(&cx, &user_sid, SecretBytes::from_slice(smtp_user)?)?;
        vault.store(&cx, &pass_sid, SecretBytes::from_slice(smtp_pass)?)?;

        let mut journal = EffectJournal::new();
        let h3 = sample_redacted_h3()?;
        let op_id = OperationId::parse(format!("op:notify:smtp:{label}:1"))?;
        let payload = NotifyPayload {
            operation_id: op_id.clone(),
            idempotency_key: IdempotencyKey::parse(format!("idempotency:notify:smtp:{label}:1"))?,
            event_root: ContentDigest::sha256(b"evt-root-smtp"),
            event_revision_digest: ContentDigest::sha256(b"evt-rev-smtp"),
            channel: target.target_id.clone(),
            event_metadata: Some(sample_metadata()?),
            visual_attachment: Some(h3.clone()),
        };
        prepare_notification_effect(
            &mut journal,
            &payload,
            target.route_digest,
            ContentDigest::sha256(b"pre-smtp"),
            ObligationId::parse(format!("obligation:notify:smtp:{label}:1"))?,
            TimestampNs(now.0 - 10),
        )?;
        let dns = PinnedDnsResolver::new().with_entry("smtp.fss.test", addr);

        let dispatched = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
            let chain = vec![pki.leaf_der.clone()];
            let sk = pki.leaf_sk.clone();
            let expected_receipt = h3.receipt_digest.to_text();
            let h = scope.spawn(move || -> Result<(), String> {
                let (mut sock, _) = listener.accept().map_err(|e| e.to_string())?;
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
                let mut ent = LabEntropy::from_seed([0x91; 32]);
                let mut tls = match mode {
                    SmtpSecurityMode::ImplicitTls => {
                        let mut t = Tls13Stream::accept_server(sock, &chain, &sk, &mut ent)
                            .map_err(|e| e.to_string())?;
                        t.write_application_data(b"220 smtp.fss.test ESMTP\r\n")
                            .map_err(|e| e.to_string())?;
                        t
                    }
                    SmtpSecurityMode::StartTls => {
                        sock.write_all(b"220 smtp.fss.test ESMTP\r\n")
                            .map_err(|e| e.to_string())?;
                        let ehlo = read_line_plain(&mut sock)?;
                        if !ehlo.starts_with("EHLO ") {
                            return Err(format!("expected EHLO, got {ehlo}"));
                        }
                        sock.write_all(b"250-smtp.fss.test\r\n250 STARTTLS\r\n")
                            .map_err(|e| e.to_string())?;
                        let st = read_line_plain(&mut sock)?;
                        if st != "STARTTLS\r\n" {
                            return Err(format!("expected STARTTLS, got {st}"));
                        }
                        sock.write_all(b"220 Ready to start TLS\r\n")
                            .map_err(|e| e.to_string())?;
                        Tls13Stream::accept_server(sock, &chain, &sk, &mut ent)
                            .map_err(|e| e.to_string())?
                    }
                };

                let mut buf = Vec::new();
                let ehlo2 = String::from_utf8(read_smtp_tls_until(&mut tls, &mut buf, b"\r\n")?)
                    .map_err(|e| e.to_string())?;
                if !ehlo2.starts_with("EHLO ") {
                    return Err(format!("expected post-TLS EHLO, got {ehlo2}"));
                }
                tls.write_application_data(b"250-smtp.fss.test\r\n250 AUTH PLAIN\r\n")
                    .map_err(|e| e.to_string())?;

                let auth = String::from_utf8(read_smtp_tls_until(&mut tls, &mut buf, b"\r\n")?)
                    .map_err(|e| e.to_string())?;
                if !auth.starts_with("AUTH PLAIN ") {
                    return Err(format!("expected AUTH PLAIN, got {auth}"));
                }
                tls.write_application_data(b"235 Authentication succeeded\r\n")
                    .map_err(|e| e.to_string())?;

                let mf = String::from_utf8(read_smtp_tls_until(&mut tls, &mut buf, b"\r\n")?)
                    .map_err(|e| e.to_string())?;
                if mf != "MAIL FROM:<alerts@fss.test>\r\n" {
                    return Err(format!("unexpected MAIL FROM: {mf}"));
                }
                tls.write_application_data(b"250 OK\r\n")
                    .map_err(|e| e.to_string())?;

                let rt = String::from_utf8(read_smtp_tls_until(&mut tls, &mut buf, b"\r\n")?)
                    .map_err(|e| e.to_string())?;
                if rt != "RCPT TO:<owner@fss.test>\r\n" {
                    return Err(format!("unexpected RCPT TO: {rt}"));
                }
                tls.write_application_data(b"250 OK\r\n")
                    .map_err(|e| e.to_string())?;

                let data_cmd = String::from_utf8(read_smtp_tls_until(&mut tls, &mut buf, b"\r\n")?)
                    .map_err(|e| e.to_string())?;
                if data_cmd != "DATA\r\n" {
                    return Err(format!("expected DATA, got {data_cmd}"));
                }
                tls.write_application_data(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .map_err(|e| e.to_string())?;

                let mime_bytes = read_smtp_tls_until(&mut tls, &mut buf, b"\r\n.\r\n")?;
                let mime_text = std::str::from_utf8(&mime_bytes).map_err(|e| e.to_string())?;
                if !mime_text.contains("multipart/mixed")
                    || !mime_text.contains("Content-Type: image/jpeg")
                    || !mime_text.contains(&expected_receipt)
                    || !mime_text.contains("driveway-north")
                {
                    return Err(
                        "SMTP MIME body missing multipart/mixed redacted H3 JPEG attachment"
                            .to_owned(),
                    );
                }
                tls.write_application_data(b"250 Queued as smtp-q-42\r\n")
                    .map_err(|e| e.to_string())?;
                let _ = read_smtp_tls_until(&mut tls, &mut buf, b"\r\n");
                let _ = tls.write_application_data(b"221 Bye\r\n");
                let _ = tls.close_notify();
                Ok(())
            });

            let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(5))?;
            let mut ent = LabEntropy::from_seed([0x92; 32]);
            let r = dispatch_prepared_notification(
                &mut journal,
                NotificationChannelTarget::SmtpTls(&target),
                &payload,
                &vault,
                &cx,
                &dns,
                &deadline,
                NotifyLimits::default(),
                &mut ent,
            )?;
            h.join().map_err(|_| "SMTP server panicked")??;
            Ok(r)
        })?;

        assert_eq!(
            dispatched.operation_receipt.state,
            EffectState::AdapterAccepted
        );
        assert_eq!(dispatched.delivery_receipt.observation.protocol_status, 250);
        scanner.assert_clean(
            &format!("smtp_target_{label}"),
            format!("{target:?}").as_bytes(),
        )?;
        scanner.assert_clean(
            &format!("smtp_receipt_{label}"),
            format!("{:?}", dispatched.delivery_receipt).as_bytes(),
        )?;
        scanner.assert_clean(
            &format!("smtp_jsonl_{label}"),
            dispatched.audit_record.to_jsonl().as_bytes(),
        )?;
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn escalation_policy_primary_failure_escalates_to_distinct_ntfy_child_over_tls13()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("escalation-e2e")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(&["ntfy.fss.test"], 1_700_000_000, 1_900_000_000, 0xa0);
    let mut vault = open_test_vault(&dir.join("vault"))?;

    // Primary webhook points to an unreachable port (pre-send failure -> EffectState::Failed).
    let unused_listener = TcpListener::bind("127.0.0.1:0")?;
    let closed_addr = unused_listener.local_addr()?;
    drop(unused_listener);

    let wh_sid = SecretId::parse("secret:webhook:esc-primary")?;
    let wh_target = HttpsWebhookTarget::new(
        "webhook-primary",
        &format!("https://hooks.down.test:{}/alert", closed_addr.port()),
        wh_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der.clone()]),
        DisclosureProfile::ReferencesV1,
        None,
        None,
    )?;
    let wh_cx = make_secret_cx(wh_target.secret_scope.clone(), now)?;
    vault.store(
        &wh_cx,
        &wh_sid,
        SecretBytes::from_slice(b"CANARY-ESC-WH-SECRET-111")?,
    )?;

    // Fallback ntfy server is live over TLS 1.3.
    let ntfy_listener = TcpListener::bind("127.0.0.1:0")?;
    let ntfy_addr = ntfy_listener.local_addr()?;
    let ntfy_sid = SecretId::parse("secret:relay:esc-ntfy")?;
    let ntfy_target = NtfyTarget::new(
        "ntfy-fallback",
        &format!("https://ntfy.fss.test:{}", ntfy_addr.port()),
        "escalations",
        ntfy_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der]),
        DisclosureProfile::ReferencesV1,
        None,
        None,
        5,
        vec!["rotating_light".to_owned()],
    )?;
    let ntfy_cx = make_secret_cx(ntfy_target.secret_scope.clone(), now)?;
    vault.store(
        &ntfy_cx,
        &ntfy_sid,
        SecretBytes::from_slice(b"CANARY-ESC-NTFY-SECRET-222")?,
    )?;

    let mut journal =
        DurableEffectJournal::open(dir.join("esc.journal"), IncompleteTailPolicy::Reject)?;
    let parent_op = OperationId::parse("op:notify:esc:parent:1")?;
    let parent_payload = NotifyPayload {
        operation_id: parent_op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:esc:parent:1")?,
        event_root: ContentDigest::sha256(b"evt-root-esc"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev-esc"),
        channel: wh_target.target_id.clone(),
        event_metadata: None,
        visual_attachment: None,
    };
    prepare_notification_effect(
        &mut journal,
        &parent_payload,
        wh_target.route_digest,
        ContentDigest::sha256(b"precond-esc"),
        ObligationId::parse("obligation:notify:esc:parent:1")?,
        TimestampNs(now.0 - 10),
    )?;

    let dns = PinnedDnsResolver::new()
        .with_entry("hooks.down.test", closed_addr)
        .with_entry("ntfy.fss.test", ntfy_addr);
    let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(3))?;
    let mut ent = LabEntropy::from_seed([0xa1; 32]);
    let primary_res = dispatch_prepared_notification(
        &mut journal,
        NotificationChannelTarget::HttpsWebhook(&wh_target),
        &parent_payload,
        &vault,
        &wh_cx,
        &dns,
        &deadline,
        NotifyLimits::default(),
        &mut ent,
    );
    assert!(primary_res.is_err());
    assert_eq!(
        journal.operation(&parent_op).map(|r| r.state),
        Some(EffectState::Failed)
    );

    // Escalate via explicit operator-approved EscalationPolicy -> brand new child operation!
    let policy = EscalationPolicy {
        policy_id: "esc-webhook-to-ntfy".to_owned(),
        primary_channel: "webhook-primary".to_owned(),
        fallback_channels: vec!["ntfy-fallback".to_owned()],
        ack_deadline_ns: 30_000_000_000,
        escalate_on_failed: true,
        escalate_on_unacknowledged: true,
        operator_approval_digest: ContentDigest::sha256(b"op-approval-esc-01"),
    };
    let escalated = prepare_escalation(
        &mut journal,
        &policy,
        &parent_op,
        &parent_payload,
        0,
        ntfy_target.route_digest,
        TimestampNs(now.0 + 1_000),
    )?;
    assert_ne!(escalated.lineage.child_operation_id, parent_op);
    assert_ne!(
        escalated.lineage.child_idempotency_key,
        parent_payload.idempotency_key
    );
    assert_eq!(escalated.lineage.parent_operation_id, parent_op);
    assert!(matches!(
        escalated.lineage.reason,
        EscalationReason::PrimaryFailed { .. }
    ));

    let child_dispatched = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let sk = pki.leaf_sk.clone();
        let expected_child_idem = escalated.lineage.child_idempotency_key.as_str().to_owned();
        let h = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = ntfy_listener.accept().map_err(|e| e.to_string())?;
            let mut srv_ent = LabEntropy::from_seed([0xa2; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut srv_ent)
                .map_err(|e| e.to_string())?;
            let (_req_line, headers, _body) = read_http_request_over_tls(&mut tls)?;
            if find_header(&headers, "x-idempotency-key") != Some(expected_child_idem.as_str()) {
                return Err("fallback ntfy did not use distinct child idempotency_key".to_owned());
            }
            tls.write_application_data(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(())
        });

        let esc_deadline =
            NotifyDeadlineCx::new(TimestampNs(now.0 + 2_000), Duration::from_secs(5))?;
        let mut cli_ent = LabEntropy::from_seed([0xa3; 32]);
        let r = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::Ntfy(&ntfy_target),
            &escalated.child_payload,
            &vault,
            &ntfy_cx,
            &dns,
            &esc_deadline,
            NotifyLimits::default(),
            &mut cli_ent,
        )?;
        h.join().map_err(|_| "escalation ntfy server panicked")??;
        Ok(r)
    })?;

    assert_eq!(
        child_dispatched.operation_receipt.state,
        EffectState::AdapterAccepted
    );
    // Parent remained Failed and was never mutated or resent!
    assert_eq!(
        journal.operation(&parent_op).map(|r| r.state),
        Some(EffectState::Failed)
    );

    // Audit record preserves explicit parent_operation_id & escalation_reason without leaking secrets.
    let audit = DeliveryAuditRecord::from_accepted(
        &child_dispatched.operation_receipt,
        &child_dispatched.delivery_receipt,
        Some(&escalated.lineage),
    );
    let jsonl = audit.to_jsonl();
    assert!(jsonl.contains(parent_op.as_str()));
    assert!(jsonl.contains("\"escalation_reason\":\"primary_failed\""));

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("esc-wh", b"CANARY-ESC-WH-SECRET-111")?;
    scanner.register_bytes("esc-ntfy", b"CANARY-ESC-NTFY-SECRET-222")?;
    scanner.assert_clean("esc_jsonl", jsonl.as_bytes())?;
    scanner.assert_clean("esc_journal", &std::fs::read(dir.join("esc.journal"))?)?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn escalation_policy_ack_deadline_expiry_on_indeterminate_never_resends_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("escalation-ack-deadline")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(
        &["hooks.fss.test", "ntfy.fss.test"],
        1_700_000_000,
        1_900_000_000,
        0xb0,
    );
    let mut vault = open_test_vault(&dir.join("vault"))?;

    let wh_listener = TcpListener::bind("127.0.0.1:0")?;
    let wh_addr = wh_listener.local_addr()?;
    let ntfy_listener = TcpListener::bind("127.0.0.1:0")?;
    let ntfy_addr = ntfy_listener.local_addr()?;

    let wh_sid = SecretId::parse("secret:webhook:ack-primary")?;
    let wh_target = HttpsWebhookTarget::new(
        "webhook-primary",
        &format!("https://hooks.fss.test:{}/alert", wh_addr.port()),
        wh_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der.clone()]),
        DisclosureProfile::ReferencesV1,
        None,
        None,
    )?;
    let wh_cx = make_secret_cx(wh_target.secret_scope.clone(), now)?;
    vault.store(
        &wh_cx,
        &wh_sid,
        SecretBytes::from_slice(b"CANARY-ACK-WH-333")?,
    )?;

    let ntfy_sid = SecretId::parse("secret:relay:ack-ntfy")?;
    let ntfy_target = NtfyTarget::new(
        "ntfy-fallback",
        &format!("https://ntfy.fss.test:{}", ntfy_addr.port()),
        "ack-escalations",
        ntfy_sid.clone(),
        TlsTrustPolicy::from_ca_certs_der(vec![pki.ca_der]),
        DisclosureProfile::ReferencesV1,
        None,
        None,
        5,
        vec!["alarm".to_owned()],
    )?;
    let ntfy_cx = make_secret_cx(ntfy_target.secret_scope.clone(), now)?;
    vault.store(
        &ntfy_cx,
        &ntfy_sid,
        SecretBytes::from_slice(b"CANARY-ACK-NTFY-444")?,
    )?;

    let mut journal = EffectJournal::new();
    let parent_op = OperationId::parse("op:notify:ack:parent:1")?;
    let parent_payload = NotifyPayload {
        operation_id: parent_op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:ack:parent:1")?,
        event_root: ContentDigest::sha256(b"evt-root-ack"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev-ack"),
        channel: wh_target.target_id.clone(),
        event_metadata: None,
        visual_attachment: None,
    };
    prepare_notification_effect(
        &mut journal,
        &parent_payload,
        wh_target.route_digest,
        ContentDigest::sha256(b"pre-ack"),
        ObligationId::parse("obligation:notify:ack:parent:1")?,
        TimestampNs(now.0 - 10),
    )?;
    let dns = PinnedDnsResolver::new()
        .with_entry("hooks.fss.test", wh_addr)
        .with_entry("ntfy.fss.test", ntfy_addr);

    // Primary webhook drops mid-response -> Indeterminate
    let wh_res = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let sk = pki.leaf_sk.clone();
        let h = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = wh_listener.accept().map_err(|e| e.to_string())?;
            let mut srv_ent = LabEntropy::from_seed([0xb1; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut srv_ent)
                .map_err(|e| e.to_string())?;
            let _ = read_http_request_over_tls(&mut tls)?;
            drop(tls);
            Ok(())
        });
        let dl = NotifyDeadlineCx::new(now, Duration::from_secs(3))?;
        let mut ent = LabEntropy::from_seed([0xb2; 32]);
        let r = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::HttpsWebhook(&wh_target),
            &parent_payload,
            &vault,
            &wh_cx,
            &dns,
            &dl,
            NotifyLimits::default(),
            &mut ent,
        );
        let _ = h.join();
        Ok(r)
    })?;
    assert!(wh_res.is_err_and(|e| e.code == ERR_NOTIFY_INDETERMINATE_001));
    assert_eq!(
        journal.operation(&parent_op).map(|r| r.state),
        Some(EffectState::Indeterminate)
    );

    // After ack_deadline_ns passes, escalate via distinct child operation; parent remains Indeterminate!
    let policy = EscalationPolicy {
        policy_id: "esc-ack-timeout".to_owned(),
        primary_channel: "webhook-primary".to_owned(),
        fallback_channels: vec!["ntfy-fallback".to_owned()],
        ack_deadline_ns: 5_000,
        escalate_on_failed: true,
        escalate_on_unacknowledged: true,
        operator_approval_digest: ContentDigest::sha256(b"op-approval-ack"),
    };
    let escalated = prepare_escalation(
        &mut journal,
        &policy,
        &parent_op,
        &parent_payload,
        0,
        ntfy_target.route_digest,
        TimestampNs(now.0 + 10_000),
    )?;
    assert!(matches!(
        escalated.lineage.reason,
        EscalationReason::AckDeadlineExpired { .. }
    ));
    assert_ne!(escalated.lineage.child_operation_id, parent_op);

    let child_res = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let chain = vec![pki.leaf_der.clone()];
        let sk = pki.leaf_sk.clone();
        let h = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = ntfy_listener.accept().map_err(|e| e.to_string())?;
            let mut srv_ent = LabEntropy::from_seed([0xb3; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &sk, &mut srv_ent)
                .map_err(|e| e.to_string())?;
            let _ = read_http_request_over_tls(&mut tls)?;
            tls.write_application_data(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(())
        });
        let dl = NotifyDeadlineCx::new(TimestampNs(now.0 + 11_000), Duration::from_secs(3))?;
        let mut ent = LabEntropy::from_seed([0xb4; 32]);
        let r = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::Ntfy(&ntfy_target),
            &escalated.child_payload,
            &vault,
            &ntfy_cx,
            &dns,
            &dl,
            NotifyLimits::default(),
            &mut ent,
        )?;
        h.join().map_err(|_| "ntfy server panicked")??;
        Ok(r)
    })?;
    assert_eq!(
        child_res.operation_receipt.state,
        EffectState::AdapterAccepted
    );
    // Parent stays Indeterminate and is NEVER mutated or resent!
    assert_eq!(
        journal.operation(&parent_op).map(|r| r.state),
        Some(EffectState::Indeterminate)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn reopened_prepared_notification_refuses_metadata_substitution_and_legacy_digests()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("prepared-payload")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let target = HttpsWebhookTarget::new(
        "metadata-bound",
        "https://hooks.fss.test/alerts",
        SecretId::parse("secret:webhook:metadata-bound")?,
        TlsTrustPolicy::from_pinned_leaf_spki(ContentDigest::sha256(b"test-spki")),
        DisclosureProfile::EventMetadataV1,
        Some(ContentDigest::sha256(b"metadata-approval")),
        None,
    )?;
    let payload = NotifyPayload {
        operation_id: OperationId::parse("op:notify:metadata-bound")?,
        idempotency_key: IdempotencyKey::parse("idem:notify:metadata-bound")?,
        event_root: ContentDigest::sha256(b"event-root"),
        event_revision_digest: ContentDigest::sha256(b"event-revision"),
        channel: target.target_id.clone(),
        event_metadata: Some(sample_metadata()?),
        visual_attachment: None,
    };
    let journal_path = dir.join("effects.journal");
    let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let precondition = ContentDigest::sha256(b"exact-preview-approval");
    prepare_notification_effect(
        &mut journal,
        &payload,
        target.route_digest,
        precondition,
        ObligationId::parse("obligation:notify:metadata-bound")?,
        now,
    )?;
    drop(journal);
    let before = std::fs::read(&journal_path)?;
    let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;

    // No credentials or resolver entries exist: every changed payload must be refused by
    // the prepared-intent boundary, while preserving the exact durable Prepared record.
    let vault = LocalEncryptedVault::open(dir.join("unused-vault"));
    let secret_cx = make_secret_cx(target.secret_scope.clone(), now)?;
    let dns = PinnedDnsResolver::new();
    let mut variants = Vec::new();
    for field in 0..7 {
        let mut changed = payload.clone();
        let metadata = changed.event_metadata.as_mut().ok_or("missing metadata")?;
        match field {
            0 => metadata.event_id = EventId::parse("evt:other")?,
            1 => metadata.revision += 1,
            2 => metadata.kind = "different_kind".to_owned(),
            3 => metadata.lifecycle = "resolved".to_owned(),
            4 => metadata.zone_ids[0] = "another-zone".to_owned(),
            5 => metadata.zone_ids.reverse(),
            _ => metadata.summary = "Unapproved replacement summary".to_owned(),
        }
        variants.push(changed);
    }
    let mut omitted = payload.clone();
    omitted.event_metadata = None;
    variants.push(omitted);
    for changed in variants {
        assert_ne!(
            compute_notification_request_digest(&payload, target.route_digest),
            compute_notification_request_digest(&changed, target.route_digest)
        );
        let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(2))?;
        let mut entropy = LabEntropy::from_seed([0xc1; 32]);
        let result = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::HttpsWebhook(&target),
            &changed,
            &vault,
            &secret_cx,
            &dns,
            &deadline,
            NotifyLimits::default(),
            &mut entropy,
        );
        assert!(result.is_err_and(|err| {
            err.code == ERR_NOTIFY_TRANSPORT_001
                && err.is_pre_send_failure()
                && err.detail.contains("does not match prepared")
        }));
        assert_eq!(
            journal.operation(&payload.operation_id).map(|op| op.state),
            Some(EffectState::Prepared)
        );
        assert_eq!(std::fs::read(&journal_path)?, before);
    }

    // A fresh approval cannot overwrite the authority bound into a previously prepared intent.
    assert!(
        prepare_notification_effect(
            &mut journal,
            &payload,
            target.route_digest,
            ContentDigest::sha256(b"replacement-approval"),
            ObligationId::parse("obligation:notify:metadata-bound")?,
            TimestampNs(now.0 + 1),
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&journal_path)?, before);
    drop(journal);

    // Preserve v1 journal bytes but never reinterpret the old metadata-omitting digest as v2.
    let legacy_path = dir.join("legacy-effects.journal");
    let mut legacy = DurableEffectJournal::open(&legacy_path, IncompleteTailPolicy::Reject)?;
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.notify.effect_request.v1");
    payload.operation_id.encode_canonical(&mut enc);
    payload.idempotency_key.encode_canonical(&mut enc);
    enc.digest(payload.event_root);
    enc.digest(payload.event_revision_digest);
    enc.text(&payload.channel);
    enc.digest(target.route_digest);
    enc.bool(false);
    let intent = EffectIntent::new(
        payload.operation_id.clone(),
        payload.idempotency_key.clone(),
        "notify.tls_dispatch",
        ContentDigest::sha256(&enc.finish()),
        precondition,
    )?;
    let _ = legacy.prepare(
        intent,
        ObligationId::parse("obligation:notify:legacy")?,
        "notification delivery independently reconciled",
        now,
    )?;
    drop(legacy);
    let legacy_before = std::fs::read(&legacy_path)?;
    let mut legacy = DurableEffectJournal::open(&legacy_path, IncompleteTailPolicy::Reject)?;
    let deadline = NotifyDeadlineCx::new(now, Duration::from_secs(2))?;
    let mut entropy = LabEntropy::from_seed([0xc2; 32]);
    let refused = dispatch_prepared_notification(
        &mut legacy,
        NotificationChannelTarget::HttpsWebhook(&target),
        &payload,
        &vault,
        &secret_cx,
        &dns,
        &deadline,
        NotifyLimits::default(),
        &mut entropy,
    );
    assert!(refused.is_err_and(|err| {
        err.code == ERR_NOTIFY_TRANSPORT_001 && err.detail.contains("does not match prepared")
    }));
    assert_eq!(std::fs::read(&legacy_path)?, legacy_before);
    drop(legacy);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn live_cancellation_before_commit_preserves_prepared_but_not_committed_uncertainty()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("cancel-before-commit")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let target = HttpsWebhookTarget::new(
        "cancel-before-commit",
        "https://hooks.fss.test/alerts",
        SecretId::parse("secret:webhook:cancel-before-commit")?,
        TlsTrustPolicy::from_pinned_leaf_spki(ContentDigest::sha256(b"test-spki")),
        DisclosureProfile::ReferencesV1,
        None,
        None,
    )?;
    let payload = NotifyPayload {
        operation_id: OperationId::parse("op:notify:cancel-before-commit")?,
        idempotency_key: IdempotencyKey::parse("idem:notify:cancel-before-commit")?,
        event_root: ContentDigest::sha256(b"event-root"),
        event_revision_digest: ContentDigest::sha256(b"event-revision"),
        channel: target.target_id.clone(),
        event_metadata: None,
        visual_attachment: None,
    };
    let journal_path = dir.join("effects.journal");
    let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    prepare_notification_effect(
        &mut journal,
        &payload,
        target.route_digest,
        ContentDigest::sha256(b"approved"),
        ObligationId::parse("obligation:notify:cancel-before-commit")?,
        now,
    )?;
    let prepared_bytes = std::fs::read(&journal_path)?;
    let vault = LocalEncryptedVault::open(dir.join("unused-vault"));
    let secret_cx = make_secret_cx(target.secret_scope.clone(), now)?;
    let dns = PinnedDnsResolver::new();
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let deadline =
        NotifyDeadlineCx::new(now, Duration::from_secs(2))?.with_cancellation_probe(&probe);
    assert!(deadline.remaining(false).is_ok());
    cancelled.store(true, Ordering::SeqCst);
    let mut entropy = LabEntropy::from_seed([0xc3; 32]);
    let refused = dispatch_prepared_notification(
        &mut journal,
        NotificationChannelTarget::HttpsWebhook(&target),
        &payload,
        &vault,
        &secret_cx,
        &dns,
        &deadline,
        NotifyLimits::default(),
        &mut entropy,
    );
    assert!(
        refused
            .is_err_and(|err| { err.code == ERR_NOTIFY_TIMEOUT_001 && err.is_pre_send_failure() })
    );
    assert_eq!(std::fs::read(&journal_path)?, prepared_bytes);
    drop(journal);
    let mut reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        reopened.operation(&payload.operation_id).map(|op| op.state),
        Some(EffectState::Prepared)
    );

    // Simulate a crash after durable commitment: cancellation cannot erase possible delivery.
    let _ = reopened.transition(
        &payload.operation_id,
        EffectState::Committed,
        TimestampNs(now.0 + 1),
        None,
        None,
    )?;
    drop(reopened);
    let committed_bytes = std::fs::read(&journal_path)?;
    let mut reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let refused = dispatch_prepared_notification(
        &mut reopened,
        NotificationChannelTarget::HttpsWebhook(&target),
        &payload,
        &vault,
        &secret_cx,
        &dns,
        &deadline,
        NotifyLimits::default(),
        &mut entropy,
    );
    assert!(refused.is_err_and(|err| {
        err.code == ERR_NOTIFY_INDETERMINATE_001 && !err.is_pre_send_failure()
    }));
    assert_eq!(std::fs::read(&journal_path)?, committed_bytes);
    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cancellation_after_tls_request_stays_indeterminate_across_journal_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = make_temp_dir("cancel-after-write")?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pki = build_test_pki(&["hooks.fss.test"], 1_700_000_000, 1_900_000_000, 0xc4);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let secret_id = SecretId::parse("secret:webhook:cancel-after-write")?;
    let target = HttpsWebhookTarget::new(
        "cancel-after-write",
        &format!("https://hooks.fss.test:{}/alerts", addr.port()),
        secret_id.clone(),
        TlsTrustPolicy::from_pem_bundle(&pki.ca_pem)?,
        DisclosureProfile::ReferencesV1,
        None,
        None,
    )?;
    let mut vault = open_test_vault(&dir.join("vault"))?;
    let secret_cx = make_secret_cx(target.secret_scope.clone(), now)?;
    vault.store(
        &secret_cx,
        &secret_id,
        SecretBytes::from_slice(b"CANARY-CANCEL-AFTER-WRITE-HMAC")?,
    )?;
    let payload = NotifyPayload {
        operation_id: OperationId::parse("op:notify:cancel-after-write")?,
        idempotency_key: IdempotencyKey::parse("idem:notify:cancel-after-write")?,
        event_root: ContentDigest::sha256(b"event-root"),
        event_revision_digest: ContentDigest::sha256(b"event-revision"),
        channel: target.target_id.clone(),
        event_metadata: None,
        visual_attachment: None,
    };
    let journal_path = dir.join("effects.journal");
    let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    prepare_notification_effect(
        &mut journal,
        &payload,
        target.route_digest,
        ContentDigest::sha256(b"approved"),
        ObligationId::parse("obligation:notify:cancel-after-write")?,
        now,
    )?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let hits = AtomicUsize::new(0);
    let dns = PinnedDnsResolver::new().with_entry("hooks.fss.test", addr);
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server_cancelled = &cancelled;
        let server_hits = &hits;
        let server_listener = &listener;
        let chain = vec![pki.leaf_der.clone()];
        let leaf_sk = pki.leaf_sk.clone();
        let server = scope.spawn(move || -> Result<(), String> {
            let (sock, _) = server_listener.accept().map_err(|e| e.to_string())?;
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
            let mut entropy = LabEntropy::from_seed([0xc5; 32]);
            let mut tls = Tls13Stream::accept_server(sock, &chain, &leaf_sk, &mut entropy)
                .map_err(|e| e.to_string())?;
            let _ = read_http_request_over_tls(&mut tls)?;
            server_hits.fetch_add(1, Ordering::SeqCst);
            server_cancelled.store(true, Ordering::SeqCst);
            // Wake a client already blocked in response I/O without supplying a complete ACK.
            // Keep the socket alive until the client has observed the cooperative cancellation.
            let _ = tls.write_application_data(b"HTTP/1.1 202 Accepted\r\n");
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            Ok(())
        });
        let deadline =
            NotifyDeadlineCx::new(now, Duration::from_secs(3))?.with_cancellation_probe(&probe);
        let mut entropy = LabEntropy::from_seed([0xc6; 32]);
        let result = dispatch_prepared_notification(
            &mut journal,
            NotificationChannelTarget::HttpsWebhook(&target),
            &payload,
            &vault,
            &secret_cx,
            &dns,
            &deadline,
            NotifyLimits::default(),
            &mut entropy,
        );
        let _ = done_tx.send(());
        server
            .join()
            .map_err(|_| "cancellation TLS server panicked")??;
        assert!(result.is_err_and(|err| {
            err.code == ERR_NOTIFY_INDETERMINATE_001
                && !err.is_pre_send_failure()
                && err.detail.contains("cancelled")
        }));
        Ok(())
    })?;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        journal.operation(&payload.operation_id).map(|op| op.state),
        Some(EffectState::Indeterminate)
    );
    drop(journal);

    // A fresh process/request owner cannot turn the ambiguous delivery into an automatic resend.
    let before_retry = std::fs::read(&journal_path)?;
    let mut reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let deadline = NotifyDeadlineCx::new(TimestampNs(now.0 + 10), Duration::from_secs(2))?;
    let mut entropy = LabEntropy::from_seed([0xc7; 32]);
    let refused = dispatch_prepared_notification(
        &mut reopened,
        NotificationChannelTarget::HttpsWebhook(&target),
        &payload,
        &vault,
        &secret_cx,
        &dns,
        &deadline,
        NotifyLimits::default(),
        &mut entropy,
    );
    assert!(refused.is_err_and(|err| err.code == ERR_NOTIFY_INDETERMINATE_001));
    assert_eq!(std::fs::read(&journal_path)?, before_retry);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
