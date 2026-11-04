#![forbid(unsafe_code)]
//! Native camera fixtures offering several HTTP authentication choices.

use super::*;
use fss_reference::rtsp::authentication::AuthenticationError;

fn offer(realm: &str, algorithm: &str, nonce: &str) -> String {
    format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm={algorithm}, qop=\"auth\"")
}

fn response(fields: &[&str]) -> String {
    let mut wire = "HTTP/1.1 401 Unauthorized\r\n".to_owned();
    for value in fields {
        wire.push_str(&format!("WWW-Authenticate: {value}\r\n"));
    }
    wire.push_str("Content-Length: 0\r\n\r\n");
    wire
}

#[test]
fn repeated_and_combined_offers_onboard_with_only_strong_exact_target_digest() {
    let basic = r#"Basic realm="fixture-basic""#;
    let sha = offer(REALM, "SHA-256", "fixture-strong");
    let md5 = offer(REALM, "MD5", "fixture-legacy");
    let combined = format!("{basic}, {sha}, {md5}");
    let server = Server::start(|peer| {
        vec![
            response(&[basic, &md5, &sha]),
            capabilities(&format!("http://{peer}/onvif/media_service")),
            response(&[&sha, basic, &md5]),
            profiles(),
            response(&[&combined]),
            stream(STREAM),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.auth = Some(AuthenticationConfig::HttpDigest(DigestConfig {
        expected_realm: REALM.into(),
        policy: DigestPolicy {
            allow_legacy_md5: true,
            allow_legacy_no_qop: false,
        },
    }));
    let result = run(&cfg, Some(TOKEN), &cx).unwrap();
    assert_eq!(result.exchanges, 6);
    assert_eq!(result.selection.as_ref().unwrap().stream.uri, STREAM);
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 3);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    let selected = DigestChallenge::parse(&sha, REALM, DigestPolicy::default()).unwrap();
    let credentials = DigestCredentials::new("fixture-user", "fixture-password").unwrap();
    for (index, request) in requests.iter().enumerate() {
        let target = if index < 2 {
            "/onvif/device_service"
        } else {
            "/onvif/media_service"
        };
        assert!(request.starts_with(&format!("POST {target} HTTP/1.1\r\n")));
        assert_eq!(request.contains("Authorization:"), index % 2 == 1);
        if index % 2 == 1 {
            let expected = selected
                .authorize("POST", target, &credentials, [(index / 2 + 1) as u8; 16], 1)
                .unwrap();
            assert!(request.contains(&format!("Authorization: {}\r\n", expected.expose())));
        }
        for forbidden in ["Authorization: Basic", "fixture-password", "fixture-legacy"] {
            assert!(!request.contains(forbidden));
        }
    }
}

#[test]
fn ambiguous_or_foreign_digest_offer_refuses_before_credential_callback() {
    let sha = offer(REALM, "SHA-256", "fixture-strong");
    let another = offer(REALM, "SHA-256", "fixture-other");
    let foreign = offer("foreign-realm", "MD5", "fixture-foreign");
    let malformed = format!("{sha}, nonce=\"duplicate\"");
    for (other, expected) in [
        (another, AuthenticationError::Malformed),
        (foreign, AuthenticationError::Realm),
        (malformed, AuthenticationError::Malformed),
    ] {
        let server = Server::start(|_| vec![response(&[&sha, &other])]);
        let cx = Context::new(server.peer);
        assert!(matches!(
            run(&config(server.peer), None, &cx),
            Err(ClientError::Authentication(error)) if error == expected
        ));
        assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn multiple_authentication_offers_do_not_add_retries_or_infer_credentials() {
    let sha = offer(REALM, "SHA-256", "fixture-strong");
    let fields = [r#"Basic realm="fixture-basic""#, sha.as_str()];
    let server = Server::start(|_| vec![response(&fields), response(&fields)]);
    let cx = Context::new(server.peer);
    assert!(matches!(
        run(&config(server.peer), None, &cx),
        Err(ClientError::AuthenticationRefused)
    ));
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests().len(), 2);

    let server = Server::start(|_| vec![response(&fields)]);
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.auth = None;
    assert!(matches!(
        run(&cfg, None, &cx),
        Err(ClientError::AuthenticationRequired)
    ));
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.requests().len(), 1);
}
