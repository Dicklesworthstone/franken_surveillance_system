#![forbid(unsafe_code)]
//! Unit tests for pure-Rust RFC 7748 X25519, RFC 8032 Ed25519, X.509 v3 verification,
//! RFC 8446 TLS 1.3 handshake/AEAD, webhook HMAC signing, disclosure profiles, and escalation.

use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

use fss_core::{
    ContentDigest, EffectJournal, EffectState, EventId, IdempotencyKey, ObligationId, OperationId,
    TimestampNs,
};
use fss_vault::LabEntropy;

use super::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey, Sha512Hasher};
use super::escalation::{
    EscalationPolicy, EscalationReason, prepare_escalation, prepare_notification_effect,
};
use super::tls13::Tls13Stream;
use super::webhook::{
    HttpsWebhookTarget, ValidatedHttpsUrl, build_webhook_json_body, compute_webhook_signature,
    verify_webhook_signature,
};
use super::x509::{
    CertBuilderParams, ERR_NOTIFY_TLS_CERT_001, TlsTrustPolicy, build_ed25519_x509_der,
    encode_cert_pem, parse_x509_der, verify_certificate_chain,
};
use super::x25519::{X25519_BASEPOINT, X25519PublicKey, X25519SecretKey, x25519_raw};
use super::{
    DisclosureProfile, ERR_NOTIFY_DISCLOSURE_001, ERR_NOTIFY_ESCALATION_001,
    ERR_NOTIFY_PLAINTEXT_REFUSED_001, H3VisualAttachment, NotifyEventMetadata, NotifyPayload,
    encode_hex_lower,
};

fn decode_hex(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert_eq!(hex.len() % 2, 0);
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(pair)?;
        out.push(u8::from_str_radix(s, 16)?);
    }
    Ok(out)
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let v = decode_hex(hex)?;
    let mut out = [0_u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[test]
fn x25519_matches_rfc7748_standard_and_iterated_vectors() -> Result<(), Box<dyn std::error::Error>>
{
    // RFC 7748 §5.2 Vector 1
    let k1 = decode_hex_32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")?;
    let u1 = decode_hex_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")?;
    assert_eq!(
        encode_hex_lower(&x25519_raw(&k1, &u1)),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    );

    // RFC 7748 §5.2 Vector 2
    let k2 = decode_hex_32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")?;
    let u2 = decode_hex_32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")?;
    assert_eq!(
        encode_hex_lower(&x25519_raw(&k2, &u2)),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    );

    // RFC 7748 §5.2 Iterated 1 and 1,000 times
    let mut k = X25519_BASEPOINT;
    let mut u = X25519_BASEPOINT;
    for iter in 1..=1000 {
        let next = x25519_raw(&k, &u);
        u = k;
        k = next;
        if iter == 1 {
            assert_eq!(
                encode_hex_lower(&k),
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
            );
        }
    }
    assert_eq!(
        encode_hex_lower(&k),
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
    );

    // RFC 7748 §6.1 Alice / Bob DH exchange
    let alice_sk = X25519SecretKey::from_bytes(decode_hex_32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )?);
    let bob_sk = X25519SecretKey::from_bytes(decode_hex_32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    )?);
    let alice_pk = alice_sk.public_key();
    let bob_pk = bob_sk.public_key();
    assert_eq!(
        encode_hex_lower(alice_pk.as_bytes()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        encode_hex_lower(bob_pk.as_bytes()),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    let shared_a = alice_sk.diffie_hellman(&bob_pk)?;
    let shared_b = bob_sk.diffie_hellman(&alice_pk)?;
    assert_eq!(*shared_a, *shared_b);
    assert_eq!(
        encode_hex_lower(&*shared_a),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );

    // Reject low-order all-zero public point
    assert!(
        alice_sk
            .diffie_hellman(&X25519PublicKey([0_u8; 32]))
            .is_err()
    );
    assert_eq!(format!("{alice_sk:?}"), "X25519SecretKey([REDACTED])");
    Ok(())
}

#[test]
fn sha512_and_ed25519_match_rfc8032_test_vectors() -> Result<(), Box<dyn std::error::Error>> {
    // FIPS 180-4 SHA-512("abc")
    assert_eq!(
        encode_hex_lower(&Sha512Hasher::digest(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );

    // RFC 8032 §7.1 Test Vector 1 (empty message)
    let sk1 = Ed25519SigningKey::from_seed(decode_hex_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )?);
    let vk1 = sk1.verifying_key();
    assert_eq!(
        encode_hex_lower(vk1.as_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig1 = sk1.sign(b"");
    assert_eq!(
        encode_hex_lower(&sig1),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    vk1.verify(b"", &sig1)?;

    // RFC 8032 §7.1 Test Vector 2 ([0x72])
    let sk2 = Ed25519SigningKey::from_seed(decode_hex_32(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    )?);
    let vk2 = sk2.verifying_key();
    assert_eq!(
        encode_hex_lower(vk2.as_bytes()),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let sig2 = sk2.sign(&[0x72]);
    assert_eq!(
        encode_hex_lower(&sig2),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    vk2.verify(&[0x72], &sig2)?;

    // RFC 8032 §7.1 Test Vector 3 ([0xaf, 0x82])
    let sk3 = Ed25519SigningKey::from_seed(decode_hex_32(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    )?);
    let vk3 = sk3.verifying_key();
    assert_eq!(
        encode_hex_lower(vk3.as_bytes()),
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    );
    let sig3 = sk3.sign(&[0xaf, 0x82]);
    assert_eq!(
        encode_hex_lower(&sig3),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    );
    vk3.verify(&[0xaf, 0x82], &sig3)?;

    // Tampered message & non-canonical S >= L refused
    assert!(vk3.verify(&[0xaf, 0x83], &sig3).is_err());
    let mut bad_s = sig3;
    bad_s[63] = 0xff;
    assert!(vk3.verify(&[0xaf, 0x82], &bad_s).is_err());
    assert!(Ed25519VerifyingKey::from_bytes([0xff; 32]).is_err());
    assert!(format!("{sk1:?}").contains("[REDACTED]"));
    Ok(())
}

#[test]
fn x509_chain_pem_pin_hostname_and_expiry_verification() -> Result<(), Box<dyn std::error::Error>> {
    let ca_sk = Ed25519SigningKey::from_seed([0x11; 32]);
    let leaf_sk = Ed25519SigningKey::from_seed([0x22; 32]);
    let rogue_sk = Ed25519SigningKey::from_seed([0x33; 32]);

    let ca_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 1,
            issuer_cn: "FSS Test Root CA",
            subject_cn: "FSS Test Root CA",
            san_dns: &[],
            san_ips: &[],
            not_before_unix_s: 1_700_000_000,
            not_after_unix_s: 1_900_000_000,
            is_ca: true,
        },
        &ca_sk.verifying_key(),
        &ca_sk,
    );
    let leaf_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 2,
            issuer_cn: "FSS Test Root CA",
            subject_cn: "hooks.fss.test",
            san_dns: &["hooks.fss.test", "*.relay.fss.test"],
            san_ips: &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            not_before_unix_s: 1_700_000_000,
            not_after_unix_s: 1_800_000_000,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &ca_sk,
    );
    let parsed_leaf = parse_x509_der(&leaf_der)?;
    let pem = encode_cert_pem(&ca_der);
    let trust = TlsTrustPolicy::from_pem_bundle(&pem)?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);

    // Exact DNS, single-label wildcard DNS, and IP SAN all pass
    let verified = verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &trust,
        "hooks.fss.test",
        now,
    )?;
    assert_eq!(verified.leaf_spki_sha256, parsed_leaf.spki_sha256);
    verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &trust,
        "eu.relay.fss.test",
        now,
    )?;
    verify_certificate_chain(std::slice::from_ref(&leaf_der), &trust, "127.0.0.1", now)?;

    // Leaf SPKI pin trust policy passes without CA bundle
    let pin_trust = TlsTrustPolicy::from_pinned_leaf_spki(parsed_leaf.spki_sha256);
    verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &pin_trust,
        "hooks.fss.test",
        now,
    )?;

    // Multi-level wildcard or wrong host refused
    let err = verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &trust,
        "a.b.relay.fss.test",
        now,
    );
    assert!(err.is_err_and(|e| e.error_code() == ERR_NOTIFY_TLS_CERT_001));
    let err = verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &trust,
        "evil.fss.test",
        now,
    );
    assert!(err.is_err_and(|e| e.error_code() == ERR_NOTIFY_TLS_CERT_001));

    // Expired & not-yet-valid refused
    let expired = TimestampNs(1_850_000_000_i128 * 1_000_000_000);
    let err = verify_certificate_chain(
        std::slice::from_ref(&leaf_der),
        &trust,
        "hooks.fss.test",
        expired,
    );
    assert!(err.is_err_and(|e| e.error_code() == ERR_NOTIFY_TLS_CERT_001));

    // Forged / untrusted CA refused
    let forged_leaf = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 9,
            issuer_cn: "FSS Test Root CA",
            subject_cn: "hooks.fss.test",
            san_dns: &["hooks.fss.test"],
            san_ips: &[],
            not_before_unix_s: 1_700_000_000,
            not_after_unix_s: 1_800_000_000,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &rogue_sk,
    );
    let err = verify_certificate_chain(&[forged_leaf], &trust, "hooks.fss.test", now);
    assert!(err.is_err_and(|e| e.error_code() == ERR_NOTIFY_TLS_CERT_001));
    Ok(())
}

#[test]
fn tls13_loopback_handshake_and_application_data_roundtrip()
-> Result<(), Box<dyn std::error::Error>> {
    let ca_sk = Ed25519SigningKey::from_seed([0x41; 32]);
    let leaf_sk = Ed25519SigningKey::from_seed([0x42; 32]);
    let ca_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 10,
            issuer_cn: "Loopback CA",
            subject_cn: "Loopback CA",
            san_dns: &[],
            san_ips: &[],
            not_before_unix_s: 1_700_000_000,
            not_after_unix_s: 1_900_000_000,
            is_ca: true,
        },
        &ca_sk.verifying_key(),
        &ca_sk,
    );
    let leaf_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 11,
            issuer_cn: "Loopback CA",
            subject_cn: "tls.fss.local",
            san_dns: &["tls.fss.local"],
            san_ips: &[],
            not_before_unix_s: 1_700_000_000,
            not_after_unix_s: 1_900_000_000,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &ca_sk,
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);

    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let server_chain = vec![leaf_der.clone()];
        let server_key = leaf_sk.clone();
        let handle = scope.spawn(move || -> Result<Vec<u8>, String> {
            let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
            let mut srv_entropy = LabEntropy::from_seed([0x55; 32]);
            let mut tls =
                Tls13Stream::accept_server(sock, &server_chain, &server_key, &mut srv_entropy)
                    .map_err(|e| e.to_string())?;
            let mut buf = [0_u8; 256];
            let n = tls
                .read_application_data(&mut buf)
                .map_err(|e| e.to_string())?;
            tls.write_application_data(b"pong-tls13")
                .map_err(|e| e.to_string())?;
            let _ = tls.close_notify();
            Ok(buf[..n].to_vec())
        });

        let client_sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        client_sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        client_sock.set_write_timeout(Some(Duration::from_secs(5)))?;
        let trust = TlsTrustPolicy::from_ca_certs_der(vec![ca_der]);
        let mut cli_entropy = LabEntropy::from_seed([0x66; 32]);
        let mut tls = Tls13Stream::connect_client(
            client_sock,
            "tls.fss.local",
            &trust,
            now,
            &mut cli_entropy,
        )?;
        tls.write_application_data(b"ping-tls13")?;
        let mut reply = [0_u8; 64];
        let n = tls.read_application_data(&mut reply)?;
        assert_eq!(&reply[..n], b"pong-tls13");
        tls.close_notify()?;

        let received = handle.join().map_err(|_| "server panicked")??;
        assert_eq!(received, b"ping-tls13");
        Ok(())
    })?;
    Ok(())
}

#[test]
fn url_plaintext_refusal_hmac_signature_and_disclosure_gates()
-> Result<(), Box<dyn std::error::Error>> {
    let err = ValidatedHttpsUrl::parse_production("http://hooks.example.com/alert");
    assert!(err.is_err_and(|e| e.code == ERR_NOTIFY_PLAINTEXT_REFUSED_001));
    assert!(ValidatedHttpsUrl::parse_production("https://user:pass@hooks.example.com/a").is_err());

    let sig = compute_webhook_signature(
        b"hmac-key-unit",
        1_750_000_000,
        "op:alert:1",
        b"{\"ok\":true}",
    );
    assert!(sig.starts_with("sha256="));
    assert!(verify_webhook_signature(
        b"hmac-key-unit",
        1_750_000_000,
        "op:alert:1",
        b"{\"ok\":true}",
        &sig
    ));
    assert!(!verify_webhook_signature(
        b"wrong-key",
        1_750_000_000,
        "op:alert:1",
        b"{\"ok\":true}",
        &sig
    ));

    let mut payload = NotifyPayload {
        operation_id: OperationId::parse("op:notify:disc:1")?,
        idempotency_key: IdempotencyKey::parse("idempotency:notify:disc:1")?,
        event_root: ContentDigest::sha256(b"evt-root"),
        event_revision_digest: ContentDigest::sha256(b"evt-rev"),
        channel: "webhook-primary".to_owned(),
        event_metadata: Some(NotifyEventMetadata {
            event_id: EventId::parse("evt:front:1")?,
            revision: 2,
            kind: "unknown_presence".to_owned(),
            lifecycle: "corroborated".to_owned(),
            zone_ids: vec!["front-porch".to_owned()],
            summary: "Corroborated front porch presence".to_owned(),
        }),
        visual_attachment: None,
    };

    // references-v1 strips all event metadata
    let ref_body = build_webhook_json_body(&payload, DisclosureProfile::ReferencesV1)?;
    assert!(!ref_body.contains("front-porch"));
    assert!(!ref_body.contains("unknown_presence"));

    // event-metadata-v1 refuses visual attachment
    let fake_jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0xff, 0xd9];
    let h3 = H3VisualAttachment::build_redacted(
        ContentDigest::sha256(b"imp"),
        ContentDigest::sha256(b"cap"),
        "cam-front-1",
        ContentDigest::sha256(b"mask-policy-v1"),
        320,
        240,
        fake_jpeg,
    )?;
    payload.visual_attachment = Some(h3.clone());
    assert!(
        payload
            .validate_for_profile(DisclosureProfile::EventMetadataV1)
            .is_err_and(|e| e.code == ERR_NOTIFY_DISCLOSURE_001)
    );

    // event-metadata-visual-v1 accepts verified redacted H3 and rejects unredacted tamper
    payload.validate_for_profile(DisclosureProfile::EventMetadataVisualV1)?;
    let mut unredacted = h3;
    unredacted.applied_redaction_transform = "none:unmasked".to_owned();
    assert!(
        unredacted
            .verify()
            .is_err_and(|e| e.code == ERR_NOTIFY_DISCLOSURE_001)
    );

    // HttpsWebhookTarget refuses plaintext http:// in production
    let trust = TlsTrustPolicy::from_pinned_leaf_spki(ContentDigest::sha256(b"spki"));
    let sid = fss_vault::SecretId::parse("secret:webhook:primary")?;
    let target_err = HttpsWebhookTarget::new(
        "webhook-primary",
        "http://127.0.0.1:8080/hook",
        sid,
        trust,
        DisclosureProfile::ReferencesV1,
        None,
        None,
    );
    assert!(target_err.is_err_and(|e| e.code == ERR_NOTIFY_PLAINTEXT_REFUSED_001));
    Ok(())
}

#[test]
fn escalation_policy_enforces_deadlines_and_distinct_child_lineage()
-> Result<(), Box<dyn std::error::Error>> {
    let mut journal = EffectJournal::new();
    let parent_op = OperationId::parse("op:notify:primary:1")?;
    let parent_payload = NotifyPayload {
        operation_id: parent_op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:notify:primary:1")?,
        event_root: ContentDigest::sha256(b"root"),
        event_revision_digest: ContentDigest::sha256(b"rev"),
        channel: "webhook-primary".to_owned(),
        event_metadata: None,
        visual_attachment: None,
    };
    let route = ContentDigest::sha256(b"route-primary");
    prepare_notification_effect(
        &mut journal,
        &parent_payload,
        route,
        ContentDigest::sha256(b"precond"),
        ObligationId::parse("obligation:notify:primary:1")?,
        TimestampNs(1_000),
    )?;
    journal.transition(
        &parent_op,
        EffectState::Committed,
        TimestampNs(2_000),
        None,
        None,
    )?;
    journal.transition(
        &parent_op,
        EffectState::AdapterAccepted,
        TimestampNs(3_000),
        Some(ContentDigest::sha256(b"obs")),
        None,
    )?;

    let policy = EscalationPolicy {
        policy_id: "esc-policy-1".to_owned(),
        primary_channel: "webhook-primary".to_owned(),
        fallback_channels: vec!["ntfy-oncall".to_owned(), "email-oncall".to_owned()],
        ack_deadline_ns: 10_000,
        escalate_on_failed: true,
        escalate_on_unacknowledged: true,
        operator_approval_digest: ContentDigest::sha256(b"operator-esc-approval"),
    };

    // Before ack_deadline_ns (3_000 + 10_000 = 13_000): refused!
    let early = prepare_escalation(
        &mut journal,
        &policy,
        &parent_op,
        &parent_payload,
        0,
        ContentDigest::sha256(b"route-ntfy"),
        TimestampNs(12_999),
    );
    assert!(early.is_err_and(|e| e.code == ERR_NOTIFY_ESCALATION_001));

    // At ack_deadline_ns: distinct child operation prepared; parent untouched!
    let escalated = prepare_escalation(
        &mut journal,
        &policy,
        &parent_op,
        &parent_payload,
        0,
        ContentDigest::sha256(b"route-ntfy"),
        TimestampNs(13_000),
    )?;
    assert_ne!(escalated.lineage.child_operation_id, parent_op);
    assert_ne!(
        escalated.lineage.child_idempotency_key,
        parent_payload.idempotency_key
    );
    assert_eq!(escalated.lineage.parent_operation_id, parent_op);
    assert!(matches!(
        escalated.lineage.reason,
        EscalationReason::AckDeadlineExpired { .. }
    ));
    assert_eq!(
        journal.operation(&parent_op).map(|r| r.state),
        Some(EffectState::AdapterAccepted)
    );
    assert_eq!(
        journal
            .operation(&escalated.lineage.child_operation_id)
            .map(|r| r.state),
        Some(EffectState::Prepared)
    );
    Ok(())
}
