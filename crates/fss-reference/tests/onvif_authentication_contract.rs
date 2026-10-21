#![forbid(unsafe_code)]
//! Fixed protocol vectors and no-I/O boundaries for UsernameToken PasswordDigest.

use std::cell::Cell;

use fss_core::ContentDigest;
use fss_reference::onvif::authentication::{UsernameToken, UtcDateTime};
use fss_reference::onvif::http::{
    HttpAuthority, HttpDenial, HttpError, HttpExchange, HttpLimits, HttpOperation, HttpRoute,
};
use fss_reference::onvif::wire::{self, WireError};
use fss_reference::rtsp::authentication::{DigestChallenge, DigestCredentials, DigestPolicy};

fn created() -> UtcDateTime {
    UtcDateTime::new(2024, 2, 29, 23, 59, 59).unwrap()
}

fn token() -> UsernameToken {
    UsernameToken::new(
        &DigestCredentials::new("fixture-user", "fixture-password").unwrap(),
        std::array::from_fn(|index| u8::try_from(index).unwrap()),
        created(),
    )
}

#[test]
fn password_digest_hashes_raw_nonce_and_exact_created_bytes() {
    // Independent SHA-1/Base64 vectors, including the permitted empty password.
    for (password, proof) in [
        ("fixture-password", "lbXdsFuX9Sk5IYoaZtTD5oIjen8="),
        ("", "dhvTi7/D7VXXyotVle9r0m1+oRw="),
    ] {
        let credentials = DigestCredentials::new("fixture-user", password).unwrap();
        let token = UsernameToken::new(
            &credentials,
            std::array::from_fn(|i| u8::try_from(i).unwrap()),
            created(),
        );
        let request = wire::get_capabilities_request()
            .with_username_token(&token)
            .unwrap();
        let body = std::str::from_utf8(request.body()).unwrap();
        assert!(request.has_username_token());
        assert!(body.contains("xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""));
        assert!(body.contains("xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""));
        assert!(body.contains("<wsse:Security s:mustUnderstand=\"1\""));
        assert!(body.contains(&format!("#PasswordDigest\">{proof}</wsse:Password>")));
        assert!(body.contains("#Base64Binary\">AAECAwQFBgcICQoLDA0ODw==</wsse:Nonce>"));
        assert!(body.contains("<wsu:Created>2024-02-29T23:59:59Z</wsu:Created>"));
        assert_eq!(body.matches("<s:Header>").count(), 1);
        assert_eq!(body.matches("<s:Body>").count(), 1);
        assert!(!body.contains("PasswordText"));
        if !password.is_empty() {
            assert!(!body.contains(password));
        }
        let debug = format!("{request:?} {token:?} {credentials:?}");
        for sensitive in [
            "fixture-user",
            "fixture-password",
            proof,
            "2024-02-29",
            "AAECAw",
        ] {
            assert!(!debug.contains(sensitive));
        }
    }
}

#[test]
fn typed_headers_preserve_escaped_operations_and_refuse_duplicate_or_bootstrap_signing() {
    let credentials = DigestCredentials::new("fixture<&\"'>", "fixture-password").unwrap();
    let token = UsernameToken::new(&credentials, [7; 16], created());
    for original in [
        wire::get_capabilities_request(),
        wire::get_profiles_request(),
        wire::get_stream_uri_request("profile</s:Body>").unwrap(),
        wire::get_snapshot_uri_request("profile</s:Body>").unwrap(),
        wire::get_services_request(),
        wire::get_media2_profiles_request(),
        wire::get_media2_stream_uri_request("profile</s:Body>").unwrap(),
    ] {
        let action = original.action();
        let original_body = std::str::from_utf8(original.body())
            .unwrap()
            .split_once("<s:Body>")
            .unwrap()
            .1
            .to_owned();
        let signed = original.with_username_token(&token).unwrap();
        assert_eq!(signed.action(), action);
        let body = std::str::from_utf8(signed.body()).unwrap();
        assert!(body.contains("<wsse:Username>fixture&lt;&amp;&quot;&apos;&gt;</wsse:Username>"));
        assert_eq!(body.split_once("<s:Body>").unwrap().1, original_body);
        assert_eq!(body.matches("<s:Body>").count(), 1);
        assert_eq!(
            signed.with_username_token(&token),
            Err(WireError::UnsupportedHeader)
        );
    }
    assert_eq!(
        wire::get_system_date_and_time_request().with_username_token(&token),
        Err(WireError::UnsupportedHeader)
    );
}

#[test]
fn bounded_credentials_remain_borrowed_and_xml_expansion_is_bounded() {
    let username = "&".repeat(256);
    let password = "p".repeat(1024);
    let credentials = DigestCredentials::new(&username, &password).unwrap();
    let token = UsernameToken::new(&credentials, [255; 16], created());
    let request = wire::get_profiles_request()
        .with_username_token(&token)
        .unwrap();
    assert!(request.body().len() < HttpLimits::default().request_bytes);
    assert!(
        std::str::from_utf8(request.body())
            .unwrap()
            .contains(&"&amp;".repeat(256))
    );
    for (username, password) in [
        ("x".repeat(257), "p".into()),
        ("user".into(), "p".repeat(1025)),
        ("nonascii-é".into(), "p".into()),
        ("user".into(), "line\nbreak".into()),
    ] {
        assert!(DigestCredentials::new(&username, &password).is_err());
    }
}

#[derive(Default)]
struct DenyIo(Cell<u32>);

impl HttpAuthority for DenyIo {
    fn checkpoint(
        &self,
        _: &HttpRoute,
        _: HttpOperation,
        _: u64,
        _: u64,
    ) -> Result<(), HttpDenial> {
        self.0.set(self.0.get() + 1);
        Err(HttpDenial::Unauthorized)
    }
}

fn route() -> HttpRoute {
    HttpRoute::new(
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.1:9",
        "/onvif/device_service",
        1,
        ContentDigest::sha256(b"fixture-plaintext-consent"),
    )
    .unwrap()
}

#[test]
fn mixed_http_digest_and_soap_token_are_rejected_before_any_io_authority() {
    let route = route();
    let request = wire::get_capabilities_request()
        .with_username_token(&token())
        .unwrap();
    let challenge = DigestChallenge::parse(
        "Digest realm=\"fixture-realm\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"",
        "fixture-realm",
        DigestPolicy::default(),
    )
    .unwrap();
    let credentials = DigestCredentials::new("fixture-user", "fixture-password").unwrap();
    let authorization = challenge
        .authorize("POST", route.target(), &credentials, [9; 16], 1)
        .unwrap();
    let cx = DenyIo::default();
    let result = HttpExchange::connect(
        route,
        &request,
        Some(&authorization),
        HttpLimits::default(),
        1,
        1_000_000,
        &cx,
    );
    assert_eq!(result.err(), Some(HttpError::Configuration));
    assert_eq!(cx.0.get(), 0);
}

#[test]
fn complete_signed_request_including_http_framing_consumes_wire_budget() {
    let unsigned = wire::get_capabilities_request();
    let signed = unsigned.clone().with_username_token(&token()).unwrap();
    let limits = HttpLimits {
        request_bytes: signed.body().len(),
        ..HttpLimits::default()
    };
    let cx = DenyIo::default();
    let result = HttpExchange::connect(route(), &unsigned, None, limits, 1, 1_000_000, &cx);
    assert_eq!(
        result.err(),
        Some(HttpError::Denied(HttpDenial::Unauthorized))
    );
    assert_eq!(cx.0.get(), 1);
    let cx = DenyIo::default();
    let result = HttpExchange::connect(route(), &signed, None, limits, 1, 1_000_000, &cx);
    assert_eq!(result.err(), Some(HttpError::Limit));
    assert_eq!(cx.0.get(), 0);
    let result = HttpExchange::connect(
        route(),
        &signed,
        None,
        HttpLimits {
            request_bytes: signed.body().len() - 1,
            ..limits
        },
        1,
        1_000_000,
        &cx,
    );
    assert_eq!(result.err(), Some(HttpError::Configuration));
    assert_eq!(cx.0.get(), 0);
}
