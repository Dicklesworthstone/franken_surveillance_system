#![forbid(unsafe_code)]
//! Bounded, order-independent Digest offer negotiation on exact RTSP responses.

use fss_packet::{H265Limits, ReorderLimits, StreamKey, avc::AvcReceiveLimits};
use fss_reference::rtsp::{
    authentication::{AuthenticationError, DigestCredentials, DigestPolicy},
    avc_client::{
        AvcClientPoll,
        authenticated::{DigestAvcClient, DigestAvcPoll},
    },
    client::{
        ClientCommand as C, ClientConfig, ClientError, RtspClientSession,
        authenticated::DigestClientError as E,
    },
    hevc_client::{HevcClientPoll, RtspHevcClient},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BASIC: &str = r#"Basic realm="camera""#;
const SHA: &str = r#"Digest realm="camera", nonce="sha-nonce", algorithm=SHA-256, qop="auth""#;
const SHA_SESSION: &str =
    r#"Digest realm="camera", nonce="session-nonce", algorithm=SHA-256-sess, qop="auth""#;
const MD5: &str = r#"Digest realm="camera", nonce="legacy-nonce", algorithm=MD5, qop="auth""#;
const LEGACY: DigestPolicy = DigestPolicy {
    allow_legacy_md5: true,
    allow_legacy_no_qop: true,
};
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/?profile=main".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 100,
        default_session_timeout_seconds: 60,
    }
}

fn credentials() -> Result<DigestCredentials<'static>, AuthenticationError> {
    DigestCredentials::new("owner", "private-password")
}

fn client(policy: DigestPolicy) -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut client = RtspClientSession::new(config())?;
    client.enable_digest("camera", policy)?;
    client.request_digest(C::Describe, &credentials()?, [1; 16], 0)?;
    Ok(client)
}

fn response(cseq: u32, fields: &[&str]) -> Vec<u8> {
    let mut wire = format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n");
    for value in fields {
        wire.push_str("WWW-Authenticate: ");
        wire.push_str(value);
        wire.push_str("\r\n");
    }
    wire.push_str("Content-Length: 0\r\n\r\n");
    wire.into_bytes()
}

fn authorize(fields: &[&str], policy: DigestPolicy) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut client = client(policy)?;
    let signed = client.retry_digest_response(&response(1, fields), &credentials()?, [2; 16], 5)?;
    assert_eq!(signed.cseq(), 2);
    assert_eq!(signed.command(), C::Describe);
    assert_eq!(client.next_wake_ns(), Some(100));
    assert!(signed.bytes().starts_with(
        b"DESCRIBE rtsp://camera.local/live/?profile=main RTSP/1.0\r\nCSeq: 2\r\n",
    ));
    for secret in [
        "private-password",
        "sha-nonce",
        "session-nonce",
        "camera.local",
        "owner",
    ] {
        assert!(!format!("{signed:?} {client:?}").contains(secret));
    }
    Ok(signed.bytes().to_vec())
}

#[test]
fn basic_and_digest_offers_work_in_either_header_order_without_basic_fallback() -> TestResult {
    let expected = authorize(&[SHA], DigestPolicy::default())?;
    for fields in [[BASIC, SHA], [SHA, BASIC]] {
        assert_eq!(authorize(&fields, DigestPolicy::default())?, expected);
    }
    let mut client = client(DigestPolicy::default())?;
    assert!(matches!(
        client.retry_digest_response(&response(1, &[BASIC]), &credentials()?, [2; 16], 5),
        Err(E::Authentication(AuthenticationError::Unsupported))
    ));
    assert_eq!(
        client
            .retry_digest_response(&response(1, &[BASIC, SHA]), &credentials()?, [2; 16], 6)?
            .cseq(),
        2,
    );
    Ok(())
}

#[test]
fn combined_offers_preserve_quoted_commas_escapes_and_qop_lists() -> TestResult {
    let digest = r#"Digest realm="camera", nonce="quoted,nonce", opaque="a\"b, c\\d", algorithm=SHA-256, qop="auth-int, auth""#;
    let expected = authorize(&[digest], DigestPolicy::default())?;
    for combined in [
        format!("{BASIC}, {digest}"),
        format!("{digest}, {BASIC}"),
        format!("Bearer token-value, {BASIC}, {digest}"),
    ] {
        assert_eq!(authorize(&[&combined], DigestPolicy::default())?, expected);
    }
    Ok(())
}

#[test]
fn strongest_allowed_algorithm_is_independent_of_server_order_and_legacy_permission() -> TestResult {
    for policy in [DigestPolicy::default(), LEGACY] {
        for fields in [
            [MD5, SHA, SHA_SESSION],
            [SHA_SESSION, MD5, SHA],
            [SHA, SHA_SESSION, MD5],
        ] {
            let wire = authorize(&fields, policy)?;
            let wire = std::str::from_utf8(&wire)?;
            assert!(wire.contains("algorithm=SHA-256-sess"));
            assert!(wire.contains("nonce=\"session-nonce\""));
            assert!(!wire.contains("legacy-nonce"));
        }
    }
    let wire = authorize(&[BASIC, MD5], LEGACY)?;
    assert!(std::str::from_utf8(&wire)?.contains("algorithm=MD5"));
    let mut client = client(DigestPolicy::default())?;
    assert!(matches!(
        client.retry_digest_response(&response(1, &[BASIC, MD5]), &credentials()?, [2; 16], 5),
        Err(E::Authentication(AuthenticationError::Unsupported))
    ));
    Ok(())
}

#[test]
fn qop_and_userhash_are_preserved_when_selecting_between_allowed_offers() -> TestResult {
    let old = r#"Digest realm="camera", nonce="old-nonce", algorithm=MD5"#;
    let hashed = format!("{MD5}, userhash=true");
    let wire = authorize(&[old, MD5, &hashed], LEGACY)?;
    let wire = std::str::from_utf8(&wire)?;
    assert!(wire.contains("qop=auth"));
    assert!(wire.contains("userhash=true"));
    assert!(!wire.contains("username=\"owner\""));
    // No candidate preserves both the SHA family and the offered username privacy.
    for fields in [[SHA, &hashed], [&hashed, SHA]] {
        let mut client = client(LEGACY)?;
        assert!(matches!(
            client.retry_digest_response(&response(1, &fields), &credentials()?, [2; 16], 5),
            Err(E::Authentication(AuthenticationError::Unsupported))
        ));
    }
    Ok(())
}

#[test]
fn ambiguous_best_offer_and_malformed_or_wrong_realm_digest_are_nonconsuming_refusals() -> TestResult {
    let different_nonce = SHA.replace("sha-nonce", "different-nonce");
    let malformed = SHA.replace("qop=\"auth\"", "qop=auth,auth-int");
    let duplicated_field = format!("{SHA}, NONCE=\"second\"");
    let wrong_realm = SHA.replace("realm=\"camera\"", "realm=\"other\"");
    for fields in [
        vec![SHA, SHA],
        vec![SHA, &different_nonce],
        vec![SHA, &malformed],
        vec![SHA, &duplicated_field],
        vec![SHA, &wrong_realm],
    ] {
        let mut client = client(LEGACY)?;
        assert!(
            client
                .retry_digest_response(&response(1, &fields), &credentials()?, [2; 16], 5)
                .is_err(),
        );
        assert_eq!(client.next_wake_ns(), Some(100));
        assert_eq!(
            client
                .retry_digest_response(&response(1, &[SHA]), &credentials()?, [2; 16], 6)?
                .cseq(),
            2,
        );
    }
    let expected = authorize(&[SHA_SESSION], LEGACY)?;
    assert_eq!(authorize(&[SHA, SHA, SHA_SESSION], LEGACY)?, expected);
    assert_eq!(authorize(&[SHA_SESSION, SHA, SHA], LEGACY)?, expected);
    Ok(())
}

#[test]
fn offer_count_total_bytes_and_broken_quoted_lists_are_bounded_before_selection() -> TestResult {
    let oversized = format!("Basic realm=\"{}\"", "x".repeat(2_049));
    let large = format!("Basic realm=\"{}\"", "x".repeat(1_200));
    let combined = std::iter::repeat_n(BASIC, 9).collect::<Vec<_>>().join(", ");
    let bad_quote = format!("{BASIC}, {SHA}, Basic realm=\"unterminated");
    let trailing = format!("{BASIC}, {SHA},");
    for fields in [
        vec![BASIC; 9],
        vec![large.as_str(); 7],
        vec![oversized.as_str()],
        vec![combined.as_str()],
        vec![bad_quote.as_str()],
        vec![trailing.as_str()],
    ] {
        let mut client = client(DigestPolicy::default())?;
        assert!(
            client
                .retry_digest_response(&response(1, &fields), &credentials()?, [2; 16], 5)
                .is_err(),
        );
        assert_eq!(
            client
                .retry_digest_response(&response(1, &[SHA]), &credentials()?, [2; 16], 6)?
                .cseq(),
            2,
        );
    }
    Ok(())
}

#[test]
fn mixed_offers_cannot_hide_wrong_cseq_proxy_auth_or_expired_request() -> TestResult {
    let creds = credentials()?;
    let mut client = client(DigestPolicy::default())?;
    assert!(matches!(
        client.retry_digest_response(&response(9, &[BASIC, SHA]), &creds, [2; 16], 5),
        Err(E::Session(ClientError::CseqMismatch))
    ));
    let proxy = String::from_utf8(response(1, &[SHA]))?.replace(
        "Content-Length: 0",
        "Proxy-Authenticate: Digest realm=\"proxy\"\r\nContent-Length: 0",
    );
    assert!(
        client
            .retry_digest_response(proxy.as_bytes(), &creds, [2; 16], 5)
            .is_err()
    );
    assert_eq!(client.next_wake_ns(), Some(100));
    assert!(matches!(
        client.retry_digest_response(&response(1, &[BASIC, SHA]), &creds, [2; 16], 100),
        Err(E::Session(ClientError::ResponseTimeout))
    ));
    Ok(())
}

#[test]
fn mixed_stale_offers_never_downgrade_a_previously_selected_sha_challenge() -> TestResult {
    let creds = credentials()?;
    let mut client = client(LEGACY)?;
    client.retry_digest_response(&response(1, &[MD5, SHA]), &creds, [2; 16], 5)?;
    let stale_md5 = format!("{MD5}, stale=true");
    assert!(matches!(
        client.retry_digest_response(&response(2, &[BASIC, &stale_md5]), &creds, [3; 16], 6),
        Err(E::Authentication(AuthenticationError::Replay))
    ));
    let stale_sha = SHA.replace("sha-nonce", "fresh-nonce") + ", stale=true";
    let signed = client.retry_digest_response(
        &response(2, &[&stale_md5, &stale_sha]),
        &creds,
        [3; 16],
        7,
    )?;
    assert_eq!(signed.cseq(), 3);
    assert_eq!(client.next_wake_ns(), Some(100));
    assert!(std::str::from_utf8(signed.bytes())?.contains("algorithm=SHA-256"));
    Ok(())
}

#[test]
fn fragmented_avc_wire_selects_digest_even_when_public_first_scheme_is_basic() -> TestResult {
    for combined in [false, true] {
        let mut client = DigestAvcClient::new(
            config(),
            KEY,
            AvcReceiveLimits::default(),
            "camera",
            DigestPolicy::default(),
        )?;
        let creds = credentials()?;
        client.request(C::Describe, &creds, [1; 16], 0)?;
        let joined = format!("{BASIC}, {SHA}");
        let fields: Vec<&str> = if combined { vec![&joined] } else { vec![BASIC, SHA] };
        let wire = response(1, &fields);
        let mut challenged = false;
        for chunk in wire.chunks(7) {
            client.ingest(chunk, 1)?;
            for _ in 0..16 {
                match client.poll(1)? {
                    DigestAvcPoll::AuthenticationRequired { cseq: 1, .. } => {
                        challenged = true;
                        break;
                    }
                    DigestAvcPoll::Client { event, .. }
                        if matches!(*event, AvcClientPoll::Pending { .. }) =>
                    {
                        break;
                    }
                    other => {
                        return Err(format!("unexpected AVC negotiation event: {other:?}").into());
                    }
                }
            }
        }
        assert!(challenged);
        let signed = client.respond(&creds, [2; 16], 2)?;
        assert_eq!(signed.cseq(), 2);
        assert_eq!(client.next_wake_ns(), Some(100));
        assert!(std::str::from_utf8(signed.bytes())?.contains("algorithm=SHA-256"));
    }
    Ok(())
}

#[test]
fn fragmented_hevc_wire_selects_digest_and_retains_the_exact_original_challenge() -> TestResult {
    for combined in [false, true] {
        let mut client = RtspHevcClient::with_digest(
            config(),
            KEY,
            ReorderLimits::default(),
            H265Limits::default(),
            "camera",
            DigestPolicy::default(),
        )?;
        let creds = credentials()?;
        client.request_digest(C::Describe, &creds, [1; 16], 0)?;
        let joined = format!("{BASIC}, {SHA}");
        let fields: Vec<&str> = if combined { vec![&joined] } else { vec![BASIC, SHA] };
        let wire = response(1, &fields);
        let mut challenged = false;
        for chunk in wire.chunks(7) {
            client.ingest(chunk, 1)?;
            for _ in 0..16 {
                match client.poll(1)? {
                    HevcClientPoll::AuthenticationRequired { cseq: 1, .. } => {
                        challenged = true;
                        break;
                    }
                    HevcClientPoll::Pending { .. } => break,
                    other => {
                        return Err(format!("unexpected HEVC negotiation event: {other:?}").into());
                    }
                }
            }
        }
        assert!(challenged);
        let answer = client.respond_digest(&creds, [2; 16], 2)?;
        assert_eq!(answer.source.expose_wire(), wire);
        assert_eq!(answer.request.cseq(), 2);
        assert_eq!(client.next_wake_ns(), Some(100));
        assert!(std::str::from_utf8(answer.request.bytes())?.contains("algorithm=SHA-256"));
    }
    Ok(())
}
