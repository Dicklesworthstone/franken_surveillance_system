#![forbid(unsafe_code)]
//! RTSP Digest authentication: full-target binding, no silent downgrade, pinned realm, strict fields.
use fss_reference::rtsp::authentication::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const LEGACY: DigestPolicy = DigestPolicy {
    allow_legacy_md5: true,
    allow_legacy_no_qop: true,
};
const CHALLENGE: &str =
    "Digest realm=\"camera-realm\", nonce=\"camera-nonce\", algorithm=SHA-256, qop=\"auth\"";
#[test]
fn independently_computed_digest_variants_bind_full_rtsp_target() -> TestResult {
    let credentials = DigestCredentials::new("camera-user", "camera-secret")?;
    for (algorithm, qop, expected) in [
        (
            "SHA-256",
            true,
            "993b80740f2ada43f34d22379c22cb045cf2267027343bae3103569d953fc5f7",
        ),
        (
            "SHA-256-sess",
            true,
            "bb2b57b4cdc03e84bf4e85ad2240ae454214d0a4583a595bef0cb6cfd479ea84",
        ),
        ("MD5", true, "3b61e1900c268d52d27aca754a698fb8"),
        ("MD5-sess", true, "845452f5e5f6172dc40fdffab7440b50"),
        ("MD5", false, "6d18ff56f0a1d7b564f85954ea48dc6a"),
        ("MD5-sess", false, "e20678cb806c613ddb3f3b0b70b0be1f"),
    ] {
        let mut challenge =
            format!("Digest realm=\"camera-realm\", nonce=\"camera-nonce\", algorithm={algorithm}");
        if qop {
            challenge.push_str(", qop=\"auth\"");
        }
        let c = DigestChallenge::parse(&challenge, "camera-realm", LEGACY)?;
        let auth = c.authorize(
            "DESCRIBE",
            "rtsp://camera.example/live?track=0",
            &credentials,
            [0xa5; 16],
            31,
        )?;
        assert!(auth.expose().contains(&format!("response=\"{expected}\"")));
        assert!(
            auth.expose()
                .contains("uri=\"rtsp://camera.example/live?track=0\"")
        );
        assert_eq!(auth.expose().contains("nc=0000001f"), qop);
        assert!(!auth.expose().contains("camera-secret"));
        assert!(auth.expose().len() <= MAX_AUTHORIZATION_BYTES);
    }
    Ok(())
}
#[test]
fn no_implicit_basic_algorithm_or_qop_downgrade() {
    for value in [
        "Basic realm=\"camera-realm\"",
        "Digest realm=\"camera-realm\", nonce=\"n\", qop=\"auth\"",
        "Digest realm=\"camera-realm\", nonce=\"n\", algorithm=SHA-256",
        "Digest realm=\"camera-realm\", nonce=\"n\", algorithm=SHA-256, qop=\"auth-int\"",
    ] {
        assert!(DigestChallenge::parse(value, "camera-realm", DigestPolicy::default()).is_err());
    }
}
#[test]
fn realm_is_pinned_before_credentials_are_used() {
    assert!(matches!(
        DigestChallenge::parse(CHALLENGE, "different", LEGACY),
        Err(AuthenticationError::Realm)
    ));
}
#[test]
fn duplicate_malformed_and_header_injection_fields_are_refused() {
    for suffix in [
        ", realm=\"camera-realm\"",
        ", NONCE=\"other\"",
        ",",
        ", stale=maybe",
        ", realm=\"unfinished",
        "\r\nX: injected",
    ] {
        assert!(
            DigestChallenge::parse(&format!("{CHALLENGE}{suffix}"), "camera-realm", LEGACY)
                .is_err()
        );
    }
    assert!(
        DigestChallenge::parse(&"x".repeat(MAX_CHALLENGE_BYTES + 1), "camera-realm", LEGACY)
            .is_err()
    );
}
#[test]
fn quoted_commas_and_escapes_roundtrip_without_header_injection() -> TestResult {
    let c = DigestChallenge::parse(
        r#"Digest realm="camera-realm", nonce="abc,def", opaque="quote\"slash\\", algorithm=SHA-256, qop="auth-int, auth""#,
        "camera-realm",
        LEGACY,
    )?;
    let credentials = DigestCredentials::new("user\"name", "password")?;
    let auth = c.authorize(
        "PLAY",
        "rtsp://camera.example/live",
        &credentials,
        [2; 16],
        1,
    )?;
    assert!(auth.expose().contains(r#"nonce="abc,def""#));
    assert!(!auth.expose().contains(['\r', '\n']));
    Ok(())
}
#[test]
fn debug_never_discloses_nonce_username_password_or_authorization() -> TestResult {
    let c = DigestChallenge::parse(CHALLENGE, "camera-realm", LEGACY)?;
    let credentials = DigestCredentials::new("camera-user", "camera-secret")?;
    let auth = c.authorize(
        "PLAY",
        "rtsp://camera.example/live",
        &credentials,
        [2; 16],
        1,
    )?;
    let text = format!("{c:?} {credentials:?} {auth:?}");
    for secret in [
        "camera-realm",
        "camera-nonce",
        "camera-user",
        "camera-secret",
        "response=",
    ] {
        assert!(!text.contains(secret));
    }
    Ok(())
}
#[test]
fn unsafe_credentials_targets_and_zero_counter_are_refused() -> TestResult {
    for (user, password) in [
        ("", "x"),
        ("user:realm", "x"),
        ("u", "pass\rword"),
        ("u", "nonasciié"),
    ] {
        assert!(DigestCredentials::new(user, password).is_err());
    }
    let c = DigestChallenge::parse(CHALLENGE, "camera-realm", LEGACY)?;
    let credentials = DigestCredentials::new("u", "p")?;
    assert!(
        c.authorize(
            "PLAY",
            "rtsp://camera.example/live",
            &credentials,
            [2; 16],
            0
        )
        .is_err()
    );
    assert!(
        c.authorize(
            "PLAY",
            "rtsp://camera.example/live\r\n",
            &credentials,
            [2; 16],
            1
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn userhash_does_not_disclose_the_plain_username() -> TestResult {
    let c = DigestChallenge::parse(
        &format!("{CHALLENGE}, userhash=true"),
        "camera-realm",
        LEGACY,
    )?;
    let auth = c.authorize(
        "PLAY",
        "rtsp://camera.example/live",
        &DigestCredentials::new("camera-user", "p")?,
        [2; 16],
        1,
    )?;
    assert!(auth.expose().contains("userhash=true"));
    assert!(!auth.expose().contains("camera-user"));
    Ok(())
}
