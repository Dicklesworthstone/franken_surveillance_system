#![forbid(unsafe_code)]
//! HTTP authority and framing regressions over the production preview parser.

use super::{parse_request, token_matches};

const HOST: &str = "127.0.0.1:43210";
// Deliberately public test input, never a credential from a running capture.
const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn request(path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut text = format!("GET {path} HTTP/1.1\r\n");
    for (key, value) in headers {
        text.push_str(&format!("{key}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text.into_bytes()
}

fn authorized(path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut headers = vec![
        ("Host", HOST),
        ("X-FSS-Read", "1"),
        ("X-FSS-Preview", TOKEN),
    ];
    headers.extend_from_slice(extra);
    request(path, &headers)
}

#[test]
fn ordinary_browser_fetch_headers_preserve_exact_authorization() {
    for path in [
        "/api/manifest",
        "/api/window/1",
        "/api/window/18446744073709551615",
    ] {
        let bytes = request(
            path,
            &[
                ("hOsT", "\t127.0.0.1:43210 \t"),
                ("x-fss-read", "\t1\t"),
                ("X-Fss-Preview", TOKEN),
                ("Origin", "http://127.0.0.1:43210"),
                ("Sec-Fetch-Site", "same-origin"),
                ("Sec-Fetch-Mode", "cors"),
                ("Sec-Fetch-Dest", "empty"),
                ("Accept", "*/*"),
                ("Accept-Encoding", "gzip, deflate, br, zstd"),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("User-Agent", "preview-parser-regression/1.0"),
                ("Connection", "keep-alive"),
                ("Cache-Control", "no-cache"),
                ("Pragma", "no-cache"),
            ],
        );
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Ok(path));
    }
}

#[test]
fn static_viewer_assets_do_not_require_the_fragment_capability() {
    for path in ["/", "/preview.js", "/preview.css"] {
        let bytes = request(path, &[("Host", HOST), ("Sec-Fetch-Site", "none")]);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Ok(path));
    }
}

#[test]
fn both_data_routes_require_host_read_intent_and_the_session_capability() {
    for path in ["/api/manifest", "/api/window/1"] {
        for headers in [
            vec![("X-FSS-Read", "1"), ("X-FSS-Preview", TOKEN)],
            vec![("Host", HOST), ("X-FSS-Preview", TOKEN)],
            vec![("Host", HOST), ("X-FSS-Read", "1")],
            vec![("Host", HOST)],
            vec![],
        ] {
            let bytes = request(path, &headers);
            assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403));
        }
        for read in ["", "0", "true", "yes", "1, 1", "01"] {
            let bytes = request(
                path,
                &[
                    ("Host", HOST),
                    ("X-FSS-Read", read),
                    ("X-FSS-Preview", TOKEN),
                ],
            );
            assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403));
        }
    }
}

#[test]
fn every_capability_byte_and_its_exact_length_are_required() {
    assert!(token_matches(TOKEN, TOKEN));
    for position in 0..TOKEN.len() {
        let changed: String = TOKEN
            .chars()
            .enumerate()
            .map(|(index, value)| {
                if index == position {
                    if value == '0' { '1' } else { '0' }
                } else {
                    value
                }
            })
            .collect();
        assert!(!token_matches(&changed, TOKEN));
        let bytes = request(
            "/api/manifest",
            &[
                ("Host", HOST),
                ("X-FSS-Read", "1"),
                ("X-FSS-Preview", &changed),
            ],
        );
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403));
    }
    for invalid in [
        String::new(),
        TOKEN[..31].to_string(),
        format!("{TOKEN}0"),
        TOKEN.to_ascii_uppercase(),
        "00000000000000000000000000000000".to_string(),
        format!("Bearer {TOKEN}"),
        format!("{TOKEN}, {TOKEN}"),
        "é".repeat(16),
    ] {
        assert!(!token_matches(&invalid, TOKEN));
        let bytes = request(
            "/api/window/1",
            &[
                ("Host", HOST),
                ("X-FSS-Read", "1"),
                ("X-FSS-Preview", &invalid),
            ],
        );
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403));
    }
    assert!(!token_matches("", ""));
    assert!(!token_matches(&TOKEN[..31], &TOKEN[..31]));
}

#[test]
fn duplicates_are_rejected_case_insensitively_even_when_values_agree() {
    for (key, value) in [
        ("host", HOST),
        ("HOST", "attacker.invalid:43210"),
        ("x-fss-read", "1"),
        ("X-FSS-READ", "0"),
        ("x-fss-preview", TOKEN),
        ("X-FSS-PREVIEW", "00000000000000000000000000000000"),
    ] {
        let bytes = authorized("/api/manifest", &[(key, value)]);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(400), "{key}");
    }
    for pair in [
        [
            ("Origin", "http://127.0.0.1:43210"),
            ("origin", "http://127.0.0.1:43210"),
        ],
        [
            ("Sec-Fetch-Site", "same-origin"),
            ("sec-fetch-site", "same-origin"),
        ],
        [("Accept", "*/*"), ("ACCEPT", "*/*")],
    ] {
        let bytes = authorized("/api/manifest", &pair);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(400));
    }
}

#[test]
fn unique_header_count_has_a_fixed_admission_ceiling() {
    let extra: Vec<(String, String)> = (0..62)
        .map(|index| (format!("X-Extension-{index}"), "value".to_string()))
        .collect();
    let borrowed: Vec<(&str, &str)> = extra
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    // Three authority fields plus 61 optional fields fill the admitted 64 slots.
    let maximum = authorized("/api/manifest", &borrowed[..61]);
    assert_eq!(parse_request(&maximum, HOST, TOKEN), Ok("/api/manifest"));
    let excessive = authorized("/api/manifest", &borrowed);
    assert_eq!(parse_request(&excessive, HOST, TOKEN), Err(400));
}

#[test]
fn rebinding_and_host_aliases_do_not_inherit_loopback_authority() {
    for host in [
        "localhost:43210",
        "127.0.0.1",
        "127.0.0.1:43211",
        "127.1:43210",
        "2130706433:43210",
        "127.0.0.1.:43210",
        "[::1]:43210",
        "127.0.0.1.attacker.invalid:43210",
        "127.0.0.1:43210@attacker.invalid",
        "127.0.0.1:43210, attacker.invalid:43210",
    ] {
        for path in ["/", "/preview.js", "/api/manifest", "/api/window/1"] {
            let bytes = request(
                path,
                &[
                    ("Host", host),
                    ("X-FSS-Read", "1"),
                    ("X-FSS-Preview", TOKEN),
                ],
            );
            assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403), "{host}");
        }
    }
}

#[test]
fn origin_is_optional_but_when_present_must_match_scheme_host_and_port() {
    let bytes = authorized("/api/manifest", &[]);
    assert_eq!(parse_request(&bytes, HOST, TOKEN), Ok("/api/manifest"));
    for origin in [
        "null",
        "",
        "https://127.0.0.1:43210",
        "http://127.0.0.1:43211",
        "http://localhost:43210",
        "http://127.0.0.1:43210/",
        "http://attacker.invalid",
        "http://127.0.0.1:43210@attacker.invalid",
        "http://127.0.0.1:43210 http://attacker.invalid",
    ] {
        for path in ["/", "/preview.css", "/api/manifest", "/api/window/1"] {
            let bytes = authorized(path, &[("Origin", origin)]);
            assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403), "{origin}");
        }
    }
}

#[test]
fn cross_site_and_same_site_fetches_cannot_read_the_preview() {
    for site in ["cross-site", "same-site", "", "same-origin, cross-site"] {
        let bytes = authorized("/api/window/1", &[("Sec-Fetch-Site", site)]);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(403));
    }
    for site in ["same-origin", "none"] {
        let bytes = authorized("/api/manifest", &[("Sec-Fetch-Site", site)]);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Ok("/api/manifest"));
    }
}

#[test]
fn content_length_and_transfer_codings_are_never_admitted() {
    for field in [
        ("Content-Length", "0"),
        ("content-length", "1"),
        ("CONTENT-LENGTH", "0, 0"),
        ("Transfer-Encoding", "chunked"),
        ("transfer-encoding", "identity"),
        ("TRANSFER-ENCODING", "gzip, chunked"),
    ] {
        let bytes = authorized("/api/manifest", &[field]);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(400));
    }
    for fields in [
        [("Content-Length", "0"), ("Transfer-Encoding", "chunked")],
        [("Transfer-Encoding", "chunked"), ("Content-Length", "0")],
    ] {
        let bytes = authorized("/api/manifest", &fields);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(400));
    }
}

#[test]
fn a_complete_request_cannot_smuggle_a_body_or_a_second_request() {
    let valid = authorized("/api/manifest", &[]);
    for suffix in [
        b"body".as_slice(),
        b"\0".as_slice(),
        b"\r\n".as_slice(),
        b"0\r\n\r\n".as_slice(),
        valid.as_slice(),
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n\r\n".as_slice(),
    ] {
        let mut bytes = valid.clone();
        bytes.extend_from_slice(suffix);
        assert_eq!(parse_request(&bytes, HOST, TOKEN), Err(400));
    }
    let embedded = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n\r\nX-Next: value\r\n\r\n";
    assert_eq!(parse_request(embedded, HOST, TOKEN), Err(400));
}

#[test]
fn request_lines_require_one_exact_http11_get_in_origin_form() {
    for line in [
        "POST /api/manifest HTTP/1.1",
        "HEAD /api/manifest HTTP/1.1",
        "OPTIONS * HTTP/1.1",
        "GET /api/manifest HTTP/1.0",
        "GET /api/manifest HTTP/2",
        "GET http://127.0.0.1:43210/api/manifest HTTP/1.1",
        "GET  /api/manifest HTTP/1.1",
        "GET /api/manifest  HTTP/1.1",
        "GET /api/manifest HTTP/1.1 extra",
        "GET\t/api/manifest HTTP/1.1",
        "GET /api/manifest?token=ignored HTTP/1.1",
        "GET /api/manifest#fragment HTTP/1.1",
        "GET /api/%6danifest HTTP/1.1",
    ] {
        let bytes =
            format!("{line}\r\nHost: {HOST}\r\nX-FSS-Read: 1\r\nX-FSS-Preview: {TOKEN}\r\n\r\n");
        assert_eq!(parse_request(bytes.as_bytes(), HOST, TOKEN), Err(400));
    }
}

#[test]
fn incomplete_lf_only_and_non_utf8_requests_are_refused() {
    for bytes in [
        b"".as_slice(),
        b"\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n".as_slice(),
        b"GET / HTTP/1.1\nHost: 127.0.0.1:43210\n\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1:43210\r\nX-Test: \xff\r\n\r\n".as_slice(),
    ] {
        assert_eq!(parse_request(bytes, HOST, TOKEN), Err(400));
    }
}

#[test]
fn header_names_and_obsolete_folded_lines_cannot_hide_authority_fields() {
    for line in [
        "Host : 127.0.0.1:43210",
        " Host: 127.0.0.1:43210",
        "\tHost: 127.0.0.1:43210",
        "X-FSS-Read\t: 1",
        ": empty-name",
        "missing-colon",
        "X-Test: first\r\n continuation",
        "X-Test: first\r\n\tcontinuation",
    ] {
        let bytes = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n{line}\r\n\r\n");
        assert_eq!(parse_request(bytes.as_bytes(), HOST, TOKEN), Err(400));
    }
}

#[test]
fn control_bytes_are_rejected_before_header_whitespace_normalization() {
    for control in (0u8..=31).filter(|byte| *byte != b'\t').chain([127]) {
        for value in [
            format!("{}value", char::from(control)),
            format!("value{}", char::from(control)),
        ] {
            let bytes = authorized("/api/manifest", &[("X-Test", &value)]);
            assert_eq!(
                parse_request(&bytes, HOST, TOKEN),
                Err(400),
                "control byte {control}"
            );
        }
    }
}

#[test]
fn unicode_whitespace_cannot_be_stripped_from_authority_values() {
    for whitespace in [
        '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2028}', '\u{2029}', '\u{3000}',
    ] {
        for (selected, value) in [
            ("Host", HOST),
            ("X-FSS-Read", "1"),
            ("X-FSS-Preview", TOKEN),
            ("Origin", "http://127.0.0.1:43210"),
        ] {
            for altered in [
                format!("{whitespace}{value}"),
                format!("{value}{whitespace}"),
            ] {
                let mut headers = vec![
                    ("Host", HOST),
                    ("X-FSS-Read", "1"),
                    ("X-FSS-Preview", TOKEN),
                    ("Origin", "http://127.0.0.1:43210"),
                ];
                for (key, value) in &mut headers {
                    if *key == selected {
                        *value = &altered;
                    }
                }
                let bytes = request("/api/manifest", &headers);
                assert!(
                    matches!(parse_request(&bytes, HOST, TOKEN), Err(400 | 403)),
                    "{selected} must preserve its exact authority value"
                );
            }
        }
    }
}

#[test]
fn raw_control_bytes_cannot_be_part_of_the_request_target() {
    for control in (0u8..=31).chain([127]) {
        let path = format!("/api/manifest{}", char::from(control));
        let bytes = authorized(&path, &[]);
        assert_eq!(
            parse_request(&bytes, HOST, TOKEN),
            Err(400),
            "control byte {control}"
        );
    }
}
