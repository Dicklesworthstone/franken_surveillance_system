#![forbid(unsafe_code)]
//! Unit tests for the unified `fss <domain> <verb>` grammar, flag normalizer, canonical ID codec,
//! preview envelope normalization, and automated CLI ergonomics linter.

use fss_core::json_input::{Value, parse as parse_json};

use crate::token::ArgToken;

use super::domains::{UNIFIED_DOMAINS, find_domain, find_verb};
use super::help::{
    detect_subcommand_help, render_domain_help, render_top_level_help, render_verb_help,
};
use super::linter::lint_unified_cli_surface;
use super::normalize::{
    CanonicalIdKind, decode_hold_id_from_storage, encode_hold_id_for_storage,
    normalize_preview_json, translate_companion_args, validate_canonical_id,
};
use super::{UnifiedParseOutcome, parse_unified_tokens};

fn toks(args: &[&str]) -> Vec<ArgToken> {
    args.iter()
        .enumerate()
        .map(|(index, raw)| ArgToken {
            raw: (*raw).to_owned(),
            index,
        })
        .collect()
}

#[test]
fn ergonomics_linter_passes_with_zero_findings() {
    let report = lint_unified_cli_surface();
    assert!(
        report.is_clean(),
        "expected 0 ergonomics findings, got: {:?}",
        report.findings
    );
    assert_eq!(report.checked_domains, 14);
    assert!(report.checked_verbs >= 52);
    let json = report.to_json();
    assert!(parse_json(&json).is_ok());
    assert!(json.contains("\"clean\":true"));
}

#[test]
fn all_fourteen_domains_and_key_verbs_are_registered() {
    let expected: &[(&str, &[&str])] = &[
        (
            "site",
            &[
                "validate",
                "probe",
                "probe-file",
                "plan",
                "run",
                "status",
                "stop",
            ],
        ),
        (
            "camera",
            &[
                "discover",
                "capture-rtsp",
                "capture-tutk",
                "capture-onvif",
                "probe-unifi",
                "list",
            ],
        ),
        (
            "media",
            &[
                "import",
                "import-rtsp",
                "import-http",
                "decode",
                "verify",
                "export",
            ],
        ),
        ("infer", &["activity", "package-detect", "profile"]),
        (
            "event",
            &[
                "watch",
                "read",
                "detect-osd",
                "corroborate",
                "alert",
                "delete",
            ],
        ),
        ("fuse", &["evaluate", "ablate", "profile", "scene"]),
        (
            "graph",
            &["coverage", "claims", "failures", "obligations", "atlas"],
        ),
        ("hold", &["list", "place", "release", "policy"]),
        ("privacy", &["list", "set-mask", "review"]),
        ("backup", &["plan", "create", "inspect", "restore"]),
        ("migrate", &["v1-to-v2"]),
        ("vault", &["init", "set", "list", "revoke", "doctor"]),
        ("notify", &["preview", "dispatch"]),
        (
            "archive",
            &["seal", "verify", "upload", "restore", "crypto-erase"],
        ),
    ];
    assert_eq!(UNIFIED_DOMAINS.len(), expected.len());
    for (domain, verbs) in expected {
        let spec = find_domain(domain).expect("domain must exist");
        assert!(render_domain_help(spec).contains("--help"));
        for verb in *verbs {
            let v = find_verb(domain, verb).expect("verb must exist");
            let help = render_verb_help(v);
            assert!(help.contains("--help"));
            assert!(help.contains("--json"));
        }
    }
}

#[test]
fn flag_translation_enforces_root_vs_archive_and_approve_normalization() {
    let rtsp = find_verb("camera", "capture-rtsp").expect("capture-rtsp");
    let ok = translate_companion_args(
        rtsp,
        &toks(&[
            "--archive=/tmp/archive-dir",
            "--approve",
            "sha256:11",
            "--json",
        ]),
    )
    .expect("archive flag translates");
    let rendered: Vec<String> = ok
        .args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        rendered,
        vec!["--root", "/tmp/archive-dir", "--approve", "sha256:11"]
    );

    let refused = translate_companion_args(rtsp, &toks(&["--root", "/tmp/wrong"]));
    assert!(
        refused.is_err(),
        "`--root` must be refused on archive-only capture-rtsp"
    );

    let backup_create = find_verb("backup", "create").expect("backup create");
    let mapped = translate_companion_args(
        backup_create,
        &toks(&[
            "--root",
            "/tmp/dep",
            "--bundle",
            "/tmp/bun",
            "--approve",
            "sha256:aa",
            "--allow-originals",
            "--json",
        ]),
    )
    .expect("backup create translates");
    let rendered: Vec<String> = mapped
        .args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert!(rendered.contains(&"--expect".to_owned()));
    assert!(!rendered.contains(&"--approve".to_owned()));
    assert!(rendered.contains(&"--json".to_owned()));

    let unifi = find_verb("camera", "probe-unifi").expect("probe-unifi");
    let mapped = translate_companion_args(
        unifi,
        &toks(&["--approve=sha256:bb", "--owner-authorized", "--json"]),
    )
    .expect("probe-unifi translates");
    let rendered: Vec<String> = mapped
        .args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        rendered,
        vec!["--approval", "sha256:bb", "--owner-authorized"]
    );
}

#[test]
fn preview_normalization_handles_all_legacy_shapes_without_dropping_keys() {
    let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let legacy_approval = format!(r#"{{"format":"legacy.v1","approval":"{digest}","extra":42}}"#);
    let out1 = normalize_preview_json(&legacy_approval, Some("fss event alert --root /d"));
    let Value::Object(obj1) = parse_json(&out1).expect("valid json 1") else {
        panic!("expected object");
    };
    assert_eq!(
        obj1.get("approval_digest").and_then(Value::text),
        Some(digest)
    );
    assert_eq!(obj1.get("approval").and_then(Value::text), Some(digest));
    assert_eq!(obj1.get("extra").and_then(Value::integer), Some(42));
    assert!(
        obj1.get("approve_command")
            .and_then(Value::text)
            .is_some_and(|c| c.contains(digest) && c.starts_with("fss event alert"))
    );

    let nested_hold = format!(
        r#"{{"format":"fss.evidence_hold_cli.v1","result":{{"status":"proposed","approval_digest":"{digest}"}}}}"#
    );
    let out2 = normalize_preview_json(&nested_hold, Some("fss hold place --root /d"));
    let Value::Object(obj2) = parse_json(&out2).expect("valid json 2") else {
        panic!("expected object");
    };
    assert_eq!(
        obj2.get("approval_digest").and_then(Value::text),
        Some(digest)
    );
    assert_eq!(
        obj2.get("result")
            .and_then(Value::object)
            .and_then(|r| r.get("approval_digest"))
            .and_then(Value::text),
        Some(digest)
    );
    assert!(obj2.get("approve_command").and_then(Value::text).is_some());

    let planned_backup = format!(
        r#"{{"format":"fss.deployment_backup_report.v1","status":"planned","manifest_digest":"{digest}"}}"#
    );
    let out3 = normalize_preview_json(&planned_backup, Some("fss backup create --root /d"));
    let Value::Object(obj3) = parse_json(&out3).expect("valid json 3") else {
        panic!("expected object");
    };
    assert_eq!(
        obj3.get("approval_digest").and_then(Value::text),
        Some(digest)
    );
    assert_eq!(
        obj3.get("manifest_digest").and_then(Value::text),
        Some(digest)
    );
}

#[test]
fn canonical_hold_id_codec_and_validation() {
    assert!(validate_canonical_id(CanonicalIdKind::Hold, "hold:front-door-001").is_ok());
    assert!(validate_canonical_id(CanonicalIdKind::Hold, "hold_legacy_001").is_ok());
    assert_eq!(
        encode_hold_id_for_storage("hold:front-door-001").expect("encode canonical"),
        "hold__front-door-001"
    );
    assert_eq!(
        decode_hold_id_from_storage("hold__front-door-001"),
        "hold:front-door-001"
    );
    assert_eq!(
        encode_hold_id_for_storage("hold_legacy_001").expect("encode legacy"),
        "hold_legacy_001"
    );
    assert_eq!(
        decode_hold_id_from_storage("hold_legacy_001"),
        "hold_legacy_001"
    );

    for bad in [
        "",
        "../evil",
        "hold:../evil",
        "hold:a/b",
        "hold:a\\b",
        "hold:with space",
        "hold:line\nbreak",
        "hold:",
        ":nobody",
        "hold:a:b",
        "HOLD:upper-prefix",
    ] {
        assert!(
            validate_canonical_id(CanonicalIdKind::Hold, bad).is_err(),
            "expected `{bad}` to be rejected"
        );
    }
}

#[test]
fn subcommand_help_detection_covers_fss1_and_unified_domains() {
    for argv in [
        vec!["session", "--help"],
        vec!["session", "open", "--help"],
        vec!["session", "resume", "-h"],
        vec!["session", "orient", "--help"],
        vec!["session", "follow", "--help"],
        vec!["session", "handoff", "--help"],
        vec!["query", "--help"],
        vec!["explain", "--help"],
        vec!["investigate", "--help"],
        vec!["plan", "--help"],
        vec!["commit", "--help"],
        vec!["wait", "--help"],
        vec!["cancel", "--help"],
        vec!["feedback", "--help"],
        vec!["doctor", "--help"],
        vec!["status", "--help"],
        vec!["capabilities", "--help"],
        vec!["site", "--help"],
        vec!["site", "run", "--help"],
        vec!["migrate", "--help"],
    ] {
        let help = detect_subcommand_help(&toks(&argv));
        assert!(help.is_some(), "expected help for {argv:?}");
    }

    // Literal `--help` passed as a `--mission-text` value must NOT be stolen as help.
    assert!(
        detect_subcommand_help(&toks(&[
            "session",
            "open",
            "--mission-text",
            "--help",
            "--objective",
            "test",
            "--root",
            "/d",
            "--json"
        ]))
        .is_none()
    );

    // Unified domain and verb help parsing.
    assert!(matches!(
        parse_unified_tokens(&toks(&["camera", "--help"])),
        Ok(UnifiedParseOutcome::Help(_))
    ));
    assert!(matches!(
        parse_unified_tokens(&toks(&["camera", "discover", "--help"])),
        Ok(UnifiedParseOutcome::Help(_))
    ));
    assert!(render_top_level_help("session", Some("open")).is_some());
}
