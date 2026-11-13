#![forbid(unsafe_code)]
//! Exact native request parity and fail-closed MCP scope/grant checks.

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "/operator/fixed-deployment";
const PRINCIPAL: &str = "principal:fixed-qsr";
const REPORT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const ANCHOR: &str = "anchor:aaaaaaaaaaaaaaaa:0:none:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROLES: &str = r#"[{"zone":"queue","role":"queue"},{"zone":"register","role":"register"},{"zone":"lobby","role":"area"}]"#;
const STAGES: &str = r#"["order","pay"]"#;

fn ready() -> Server {
    let mut server = Server::new(ROOT.into(), PRINCIPAL.to_owned());
    server.phase = Phase::Ready;
    server
}

fn request(arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
    )
}

fn arguments(extra: &str) -> String {
    format!(r#"{{"target":"qsr","report_digest":"{REPORT}"{extra}}}"#)
}

fn native(extra: &[String]) -> Test<FssCommand> {
    let mut args: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        format!("--root={ROOT}").into(),
        format!("--principal={PRINCIPAL}").into(),
        "--target=qsr".into(),
        format!("--report-digest={REPORT}").into(),
        "--verify-qsr-source=yes".into(),
    ];
    args.extend(extra.iter().map(OsString::from));
    Ok(parse_fss_args(args)?)
}

#[test]
fn qsr_adapter_uses_canonical_request_and_preserves_native_response_bytes() -> Test {
    let full = format!(
        r#", "zone_roles":{ROLES},"lane_stages":{STAGES},"anchor":"{ANCHOR}","max_query_read_bytes":"4294967296","max_query_read_objects":"4000000""#
    );
    let full_flags = vec![
        format!("--zone-roles={ROLES}"),
        format!("--lane-stages={STAGES}"),
        format!("--anchor={ANCHOR}"),
        "--max-query-read-bytes=4294967296".to_owned(),
        "--max-query-read-objects=4000000".to_owned(),
    ];
    for (extra, flags) in [("", Vec::new()), (full.as_str(), full_flags)] {
        let expected = native(&flags)?;
        assert!(matches!(expected, FssCommand::QsrQuery(_)));
        for exit in [ExitIdentity::SUCCESS, ExitIdentity::AGENT_REFUSED] {
            let bytes =
                "{\"payload\":\"line\\nquote\\\"\\\\\",\"physicalQueueLength\":\"unknown\"}\n";
            let mut calls = 0;
            let response = ready()
                .with_qsr_source_verification()
                .handle_with(&request(&arguments(extra)), |command| {
                    calls += 1;
                    assert_eq!(command, expected);
                    (bytes.to_owned(), exit)
                })
                .ok_or("missing response")?;
            assert_eq!(calls, 1);
            let response = fss_cli::json_input::parse(&response)?;
            let result = response
                .object()
                .and_then(|root| root.get("result"))
                .and_then(fss_cli::json_input::Value::object)
                .ok_or("tool result")?;
            assert_eq!(
                result
                    .get("isError")
                    .and_then(fss_cli::json_input::Value::boolean),
                Some(exit != ExitIdentity::SUCCESS)
            );
            let text = result
                .get("content")
                .and_then(fss_cli::json_input::Value::array)
                .and_then(|rows| rows.first())
                .and_then(fss_cli::json_input::Value::object)
                .and_then(|row| row.get("text"))
                .and_then(fss_cli::json_input::Value::text);
            assert_eq!(text, Some(bytes));
        }
    }
    Ok(())
}

#[test]
fn qsr_read_requires_its_own_launcher_grant() {
    let input = request(&arguments(""));
    for mut server in [
        ready(),
        ready().with_replay_source_verification(),
        ready()
            .with_archive("/operator/archive".into())
            .with_replay_source_verification(),
    ] {
        let mut calls = 0;
        let response = server.handle_with(&input, |_| {
            calls += 1;
            ("{}".to_owned(), ExitIdentity::SUCCESS)
        });
        assert_eq!(calls, 0);
        assert!(response.is_some_and(|text| text.contains("-32602") && text.contains("launcher")));
    }
}

#[test]
fn qsr_refuses_client_authority_source_disclosure_and_other_target_selectors() {
    for extra in [
        r#", "root":"/private-canary""#,
        r#", "principal":"principal:private-canary""#,
        r#", "archive_root":"/private-canary""#,
        r#", "verify_qsr_source":true"#,
        r#", "allow_qsr_source_verification":true"#,
        r#", "verify_replay_source":true"#,
        r#", "include_values":true"#,
        r#", "hydrate":"H3""#,
        r#", "approve":"yes""#,
        r#", "at":"latest""#,
        r#", "continuation":"cursor:private-canary""#,
        r#", "sensor":"sensor:private-canary""#,
        r#", "stream":"stream:private-canary""#,
        r#", "report":"/private-canary""#,
        r#", "sources":[]"#,
        r#", "analysis":"tracks""#,
        r#", "max_entries":1"#,
        r#", "retained_import":"private-canary""#,
        r#", "max_query_io_calls":"1""#,
        r#", "max_query_source_bytes":"1""#,
    ] {
        refused(&arguments(extra));
    }
}

#[test]
fn qsr_refuses_inexact_digests_ambiguous_bounds_and_malformed_inline_config() {
    let base = arguments("");
    for invalid in [
        base.replace(REPORT, "/private-canary"),
        base.replace(REPORT, &REPORT.to_uppercase()),
        base.replace(REPORT, &format!("sha256:{}", "0".repeat(64))),
        base.replace(
            &format!(r#""report_digest":"{REPORT}""#),
            "\"report_digest\":null",
        ),
    ] {
        refused(&invalid);
    }
    refused(r#"{"target":"qsr"}"#);
    for field in ["max_query_read_bytes", "max_query_read_objects"] {
        for invalid in [
            "0",
            "\"0\"",
            "1",
            "1.0",
            "\"01\"",
            "\"+1\"",
            "\"1e3\"",
            "\" 1\"",
            "true",
            "null",
            "\"18446744073709551616\"",
        ] {
            refused(&arguments(&format!(",\"{field}\":{invalid}")));
        }
    }
    for extra in [
        r#", "max_query_read_bytes":"4294967297""#,
        r#", "max_query_read_objects":"4000001""#,
        r#", "zone_roles":"/private-canary""#,
        r#", "zone_roles":null"#,
        r#", "zone_roles":["queue"]"#,
        r#", "zone_roles":[{"zone":"queue"}]"#,
        r#", "zone_roles":[{"zone":"queue","role":"queue","root":"/private-canary"}]"#,
        r#", "zone_roles":[{"zone":"queue","role":"lane_stage"}]"#,
        r#", "zone_roles":[{"zone":"queue","role":"future"}]"#,
        r#", "zone_roles":[{"zone":"queue","role":null}]"#,
        r#", "zone_roles":[{"zone":"queue","role":"queue"},{"zone":"queue","role":"area"}]"#,
        r#", "zone_roles":[{"zone":"bad zone","role":"area"}]"#,
        r#", "zone_roles":[{"zone":"","role":"area"}]"#,
        r#", "lane_stages":"/private-canary""#,
        r#", "lane_stages":["order"]"#,
        r#", "lane_stages":["order","order"]"#,
        r#", "lane_stages":["order",1]"#,
        r#", "lane_stages":["order","bad/stage"]"#,
        r#", "lane_stages":["queue","pay"],"zone_roles":[{"zone":"queue","role":"queue"}]"#,
        r#", "anchor":1"#,
        r#", "anchor":"""#,
        r#", "anchor":"private-canary""#,
    ] {
        refused(&arguments(extra));
    }
    let roles = (0..17)
        .map(|index| format!(r#"{{"zone":"zone{index}","role":"area"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let stages = (0..17)
        .map(|index| format!("\"stage{index}\""))
        .collect::<Vec<_>>()
        .join(",");
    refused(&arguments(&format!(",\"zone_roles\":[{roles}]")));
    refused(&arguments(&format!(",\"lane_stages\":[{stages}]")));
    refused(&arguments(&format!(
        ",\"lane_stages\":[\"{}\",\"pay\"]",
        "x".repeat(65)
    )));
}

fn refused(arguments: &str) {
    let mut calls = 0;
    let response = ready()
        .with_qsr_source_verification()
        .with_tracks_source_verification()
        .handle_with(&request(arguments), |_| {
            calls += 1;
            ("{}".to_owned(), ExitIdentity::SUCCESS)
        });
    assert_eq!(calls, 0, "admitted {arguments}");
    assert!(
        response.is_some_and(|text| text.contains("-32602") && !text.contains("private-canary"))
    );
}

#[test]
fn qsr_notifications_never_execute_source_verification() {
    let message = request(&arguments("")).replace("\"id\":42,", "");
    let mut calls = 0;
    assert!(
        ready()
            .with_qsr_source_verification()
            .handle_with(&message, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            })
            .is_none()
    );
    assert_eq!(calls, 0);
}

#[test]
fn qsr_fields_never_extend_other_query_targets() {
    for target in ["events", "footage", "recordings", "onvif"] {
        for field in [
            format!(r#""report_digest":"{REPORT}""#),
            r#""zone_roles":[]"#.to_owned(),
            r#""lane_stages":[]"#.to_owned(),
        ] {
            refused(&format!(r#"{{"target":"{target}",{field}}}"#));
        }
    }
    // Tracks share the retained detector report selector, but never QSR zone annotations.
    for target in [
        format!(r#""target":"tracks","report_digest":"{REPORT}","label":"person""#),
        r#""target":"reports""#.to_owned(),
    ] {
        for field in [r#""zone_roles":[]"#, r#""lane_stages":[]"#] {
            refused(&format!("{{{target},{field}}}"));
        }
    }
}

#[test]
fn tools_list_exposes_qsr_under_existing_query_with_closed_target_fields() -> Test {
    use fss_cli::json_input::Value as NativeValue;
    let listed = fss_cli::json_input::parse(&tools_list())?;
    let tools = listed
        .object()
        .and_then(|root| root.get("tools"))
        .and_then(NativeValue::array)
        .ok_or("tools")?;
    assert!(!tools.iter().any(|tool| {
        tool.object()
            .and_then(|fields| fields.get("name"))
            .and_then(NativeValue::text)
            .is_some_and(|name| name.contains("qsr"))
    }));
    let queries = tools
        .iter()
        .filter(|tool| {
            tool.object()
                .and_then(|fields| fields.get("name"))
                .and_then(NativeValue::text)
                == Some("query")
        })
        .collect::<Vec<_>>();
    assert_eq!(queries.len(), 1);
    let schema = queries[0]
        .object()
        .and_then(|fields| fields.get("inputSchema"))
        .and_then(NativeValue::object)
        .ok_or("query schema")?;
    assert_eq!(
        schema
            .get("additionalProperties")
            .and_then(NativeValue::boolean),
        Some(false)
    );
    let properties = schema
        .get("properties")
        .and_then(NativeValue::object)
        .ok_or("properties")?;
    for forbidden in [
        "root",
        "principal",
        "archive_root",
        "verify_qsr_source",
        "allow_qsr_source_verification",
        "verify_tracks_source",
        "allow_tracks_source_verification",
    ] {
        assert!(!properties.contains_key(forbidden));
    }
    let branches = schema
        .get("oneOf")
        .and_then(NativeValue::array)
        .ok_or("branches")?;
    let mut qsr_branches = 0;
    for branch in branches {
        let branch = branch.object().ok_or("branch object")?;
        let target = branch
            .get("properties")
            .and_then(NativeValue::object)
            .and_then(|fields| fields.get("target"))
            .and_then(NativeValue::object)
            .and_then(|fields| fields.get("const"))
            .and_then(NativeValue::text)
            .ok_or("target")?;
        if target == "qsr" {
            qsr_branches += 1;
            let required = branch
                .get("required")
                .and_then(NativeValue::array)
                .ok_or("required")?;
            assert_eq!(
                required
                    .iter()
                    .filter_map(NativeValue::text)
                    .collect::<Vec<_>>(),
                ["target", "report_digest"]
            );
            let allowed = branch
                .get("propertyNames")
                .and_then(NativeValue::object)
                .and_then(|fields| fields.get("enum"))
                .and_then(NativeValue::array)
                .ok_or("closed QSR fields")?;
            assert_eq!(
                allowed
                    .iter()
                    .filter_map(NativeValue::text)
                    .collect::<Vec<_>>(),
                [
                    "target",
                    "report_digest",
                    "zone_roles",
                    "lane_stages",
                    "anchor",
                    "max_query_read_bytes",
                    "max_query_read_objects"
                ]
            );
        } else {
            let excludes = |field: &str| {
                branch
                    .get("propertyNames")
                    .and_then(NativeValue::object)
                    .and_then(|fields| fields.get("enum"))
                    .and_then(NativeValue::array)
                    .is_some_and(|allowed| !allowed.iter().any(|value| value.text() == Some(field)))
                    || branch
                        .get("not")
                        .and_then(NativeValue::object)
                        .and_then(|fields| fields.get("anyOf"))
                        .and_then(NativeValue::array)
                        .is_some_and(|excluded| {
                            excluded.iter().any(|row| {
                                row.object()
                                    .and_then(|fields| fields.get("required"))
                                    .and_then(NativeValue::array)
                                    .is_some_and(|required| {
                                        required.len() == 1 && required[0].text() == Some(field)
                                    })
                            })
                        })
            };
            for field in ["zone_roles", "lane_stages"] {
                assert!(excludes(field), "{target} admits QSR-only {field}");
            }
            if target == "tracks" {
                assert!(!excludes("report_digest"));
            } else {
                assert!(excludes("report_digest"));
            }
        }
    }
    assert_eq!(qsr_branches, 1);
    Ok(())
}
