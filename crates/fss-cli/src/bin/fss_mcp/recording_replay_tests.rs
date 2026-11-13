#![forbid(unsafe_code)]
//! The launcher owns source-read admission; MCP preserves the canonical replay command.

use super::*;

trait ObjectMember {
    fn get(&self, key: &str) -> Option<&Self>;
}

impl ObjectMember for fss_cli::json_input::Value {
    fn get(&self, key: &str) -> Option<&Self> {
        self.object()?.get(key)
    }
}

fn excludes_field(node: &fss_cli::json_input::Value, field: &str) -> bool {
    use fss_cli::json_input::Value;
    node.get("propertyNames")
        .and_then(|value| value.get("enum"))
        .and_then(Value::array)
        .is_some_and(|allowed| !allowed.iter().any(|value| value.text() == Some(field)))
        || node
            .get("not")
            .and_then(|value| value.get("anyOf"))
            .and_then(Value::array)
            .is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("required")
                        .and_then(Value::array)
                        .is_some_and(|required| {
                            required.iter().any(|value| value.text() == Some(field))
                        })
                })
            })
}

fn replay_fields(codec: &str) -> Fields {
    let mut values = fields(codec);
    for field in ["catalog_slot", "catalog_root", "start_tick", "end_tick"] {
        values.remove(field);
    }
    values.extend([
        ("replay_root", quote(CATALOG)),
        ("replay_request", quote(CLOCK)),
        ("ntp_era", "0".to_owned()),
        ("utc_start_ns", quote("18446744073709551616")),
        ("utc_end_ns", quote("18446744073709551617")),
    ]);
    values
}

fn replay_server(grant: bool) -> Server {
    let server = ready(true);
    if grant {
        server.with_replay_source_verification()
    } else {
        server
    }
}

fn native_replay(codec: &str, bounded: bool) -> Test<FssCommand> {
    let mut args = [
        "query",
        "--json",
        "--target=recordings",
        "--root=/owner/deployment",
        "--archive-root=/owner/archive with spaces",
        "--principal=principal:local-operator",
        "--sensor=sensor:register",
        "--stream=stream:main",
        "--generation=18446744073709551615",
        "--time-scale=4294967295",
        "--ntp-era=0",
        "--utc-start-ns=18446744073709551616",
        "--utc-end-ns=18446744073709551617",
        "--verify-replay-source=yes",
    ]
    .map(OsString::from)
    .to_vec();
    for (option, value) in [
        ("codec", codec),
        ("source-anchor", SOURCE),
        ("receive-clock", RECEIVE),
        ("decode-clock", DECODE),
        ("replay-root", CATALOG),
        ("replay-request", CLOCK),
    ] {
        args.push(format!("--{option}={value}").into());
    }
    if bounded {
        args.extend(
            [
                "--max-query-windows=64",
                "--max-query-samples=16384",
                "--max-query-packets=262144",
                "--max-query-source-bytes=2147483648",
                "--max-query-results=128",
                "--max-query-read-bytes=4294967296",
                "--max-query-io-calls=4000000",
            ]
            .map(OsString::from),
        );
        args.push(format!("--anchor={ANCHOR}").into());
    }
    Ok(parse_fss_args(args)?)
}

#[test]
fn replay_dispatch_preserves_cli_pins_i128_values_owner_scope_and_response_bytes() -> Test {
    for codec in ["avc", "hevc"] {
        for bounded in [false, true] {
            let mut values = replay_fields(codec);
            if bounded {
                values.extend([
                    ("max_query_windows", "64".to_owned()),
                    ("max_query_samples", "16384".to_owned()),
                    ("max_query_packets", "262144".to_owned()),
                    ("max_query_source_bytes", quote("2147483648")),
                    ("max_query_results", "128".to_owned()),
                    ("max_query_read_bytes", quote("4294967296")),
                    ("max_query_io_calls", quote("4000000")),
                    ("anchor", quote(ANCHOR)),
                ]);
            }
            let expected = native_replay(codec, bounded)?;
            for (bytes, exit) in [
                (
                    "{\"recorderTime\":\"conditional\",\"unknown\":[\"unmapped sample\"],\"mediaBytes\":false}\n",
                    ExitIdentity::SUCCESS,
                ),
                (
                    "{\"outcome\":\"refused\",\"payload\":null,\"reason\":\"source closure changed\"}\n",
                    ExitIdentity::AGENT_REFUSED,
                ),
            ] {
                let mut calls = 0;
                let response = replay_server(true)
                    .handle_with(&request(&values), |command| {
                        calls += 1;
                        assert_eq!(command, expected);
                        (bytes.to_owned(), exit)
                    })
                    .ok_or("missing replay response")?;
                assert_eq!(calls, 1);
                assert_eq!(
                    response_text(&response)?,
                    (bytes.to_owned(), exit != ExitIdentity::SUCCESS)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn replay_requires_the_launcher_grant_and_clients_cannot_supply_one() {
    let valid = replay_fields("avc");
    refused(&mut replay_server(false), &valid);
    refused(&mut ready(false).with_replay_source_verification(), &valid);
    for (field, value) in [
        ("verify_replay_source", quote("yes")),
        ("allow_replay_source_verification", "true".to_owned()),
        ("root", quote("/client/deployment")),
        ("archive_root", quote("/client/archive")),
        ("principal", quote("principal:client")),
    ] {
        let mut values = valid.clone();
        values.insert(field, value);
        refused(&mut replay_server(false), &values);
        refused(&mut replay_server(true), &values);
    }
}

#[test]
fn replay_mcp_refuses_missing_pins_mixed_modes_and_lossy_numeric_encodings() {
    let valid = replay_fields("hevc");
    let mut server = replay_server(true);
    for missing in valid.keys() {
        let mut values = valid.clone();
        values.remove(missing);
        refused(&mut server, &values);
    }
    for (field, value) in [
        ("catalog_slot", quote("catalog")),
        ("catalog_root", quote(CATALOG)),
        ("catalogs", "[]".to_owned()),
        ("sessions", "[]".to_owned()),
        ("discover_catalogs", "true".to_owned()),
        ("clock_slot", quote("clock")),
        ("clock_root", quote(CLOCK)),
        ("start_tick", quote("0")),
        ("end_tick", quote("1")),
        ("start_utc_ns", quote("0")),
        ("end_utc_ns", quote("1")),
        ("max_windows", "1".to_owned()),
        ("max_hydration_bytes", quote("1")),
        ("from_ns", quote("0")),
        ("at", quote(ANCHOR)),
        ("continuation", quote("next")),
        ("analysis", quote("tracks")),
        ("sources", "[]".to_owned()),
        ("ntp_era", "4294967296".to_owned()),
        ("ntp_era", "-1".to_owned()),
        ("ntp_era", "0.0".to_owned()),
        ("ntp_era", "0e0".to_owned()),
        ("ntp_era", quote("0")),
        ("max_query_results", "0".to_owned()),
        ("max_query_results", "129".to_owned()),
        ("max_query_results", "1e2".to_owned()),
        ("max_query_results", quote("32")),
        ("max_query_read_bytes", "1024".to_owned()),
        ("max_query_io_calls", "10".to_owned()),
        ("max_query_source_bytes", "1024".to_owned()),
        ("utc_start_ns", "18446744073709551616".to_owned()),
        ("utc_start_ns", quote("18446744073709551616.0")),
        ("utc_end_ns", quote("18446744073709551616")),
        ("utc_end_ns", quote("253402300800000000001")),
    ] {
        let mut values = valid.clone();
        values.insert(field, value);
        refused(&mut server, &values);
    }
}

#[test]
fn replay_schema_exposes_exact_closed_mode_without_client_source_authority() -> Test {
    use fss_cli::json_input as input;
    let value = input::parse(&tools_list())?;
    let schema = value
        .get("tools")
        .and_then(input::Value::array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool.get("name").and_then(input::Value::text) == Some("query"))
        })
        .and_then(|tool| tool.get("inputSchema"))
        .ok_or("query schema")?;
    let properties = schema
        .get("properties")
        .and_then(input::Value::object)
        .ok_or("query properties")?;
    for field in [
        "utc_start_ns",
        "utc_end_ns",
        "max_query_source_bytes",
        "max_query_read_bytes",
        "max_query_io_calls",
    ] {
        assert_eq!(
            properties
                .get(field)
                .and_then(|value| value.get("type"))
                .and_then(input::Value::text),
            Some("string")
        );
    }
    for field in [
        "ntp_era",
        "max_query_windows",
        "max_query_samples",
        "max_query_packets",
    ] {
        assert_eq!(
            properties
                .get(field)
                .and_then(|value| value.get("type"))
                .and_then(input::Value::text),
            Some("integer")
        );
    }
    for field in [
        "verify_replay_source",
        "allow_replay_source_verification",
        "root",
        "archive_root",
        "principal",
    ] {
        assert!(
            !properties.contains_key(field),
            "schema grants client override {field}"
        );
    }
    let branches = schema
        .get("oneOf")
        .and_then(input::Value::array)
        .ok_or("query modes")?;
    for branch in branches {
        let target = branch
            .get("properties")
            .and_then(|value| value.get("target"))
            .and_then(|value| value.get("const"))
            .and_then(input::Value::text)
            .ok_or("mode target")?;
        if target == "recordings" {
            let result_bound = branch
                .get("properties")
                .and_then(|value| value.get("max_query_results"))
                .ok_or("recording result bound")?;
            assert_eq!(
                result_bound.get("type").and_then(input::Value::text),
                Some("integer")
            );
            assert_eq!(
                result_bound.get("maximum").and_then(input::Value::integer),
                Some(128)
            );
            let modes = branch
                .get("oneOf")
                .and_then(input::Value::array)
                .ok_or("recording modes")?;
            let mut replay_modes = 0;
            for mode in modes {
                let required = mode
                    .get("required")
                    .and_then(input::Value::array)
                    .ok_or("mode required")?;
                let is_replay = required
                    .iter()
                    .any(|value| value.text() == Some("replay_root"));
                let forbidden = mode
                    .get("not")
                    .and_then(|value| value.get("anyOf"))
                    .and_then(input::Value::array)
                    .ok_or("mode exclusions")?;
                if is_replay {
                    replay_modes += 1;
                    for field in [
                        "replay_root",
                        "replay_request",
                        "ntp_era",
                        "utc_start_ns",
                        "utc_end_ns",
                    ] {
                        assert!(
                            required.iter().any(|value| value.text() == Some(field)),
                            "missing exact {field}"
                        );
                    }
                    for field in [
                        "catalogs",
                        "sessions",
                        "clock_root",
                        "start_utc_ns",
                        "end_utc_ns",
                        "max_hydration_bytes",
                    ] {
                        assert!(
                            forbidden.iter().any(|value| value
                                .get("required")
                                .and_then(input::Value::array)
                                .is_some_and(|values| values
                                    .iter()
                                    .any(|value| value.text() == Some(field)))),
                            "allowed mixed {field}"
                        );
                    }
                } else {
                    assert!(forbidden.iter().any(|value| {
                        value
                            .get("required")
                            .and_then(input::Value::array)
                            .is_some_and(|values| {
                                values
                                    .iter()
                                    .any(|value| value.text() == Some("replay_root"))
                            })
                    }));
                }
            }
            assert_eq!(replay_modes, 2);
        } else {
            assert!(excludes_field(branch, "replay_root"));
        }
    }
    Ok(())
}

#[test]
fn retained_replay_mcp_needs_source_grant_but_not_an_archive_binding() -> Test {
    for codec in ["avc", "hevc"] {
        let mut values = replay_fields(codec);
        values.insert("retained_import", quote(CATALOG));
        values.insert("max_query_read_objects", quote("12345"));
        let mut calls = 0;
        let output = ready(false)
            .with_replay_source_verification()
            .handle_with(&request(&values), |command| {
                calls += 1;
                let FssCommand::RetainedRecordingReplayQuery(args) = command else {
                    panic!("retained selector chose external archive");
                };
                assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                assert_eq!(args.request.import_identity.to_text(), CATALOG);
                assert_eq!(args.request.replay.replay.codec.as_str(), codec);
                assert_eq!(args.limits.read.max_read_objects, 12345);
                assert!(args.verify_replay_source);
                ("{\"retained\":true}".to_owned(), ExitIdentity::SUCCESS)
            })
            .ok_or("missing imported replay response")?;
        assert_eq!(calls, 1);
        assert_eq!(
            response_text(&output)?,
            ("{\"retained\":true}".to_owned(), false)
        );
        refused(&mut ready(false), &values);
        for (field, value) in [
            ("max_query_io_calls", quote("100")),
            ("archive_root", quote("/client/archive")),
            ("root", quote("/client/root")),
            ("verify_replay_source", quote("yes")),
            ("max_query_read_objects", "100".to_owned()),
            ("retained_import", "null".to_owned()),
        ] {
            let mut invalid = values.clone();
            invalid.insert(field, value);
            refused(
                &mut ready(false).with_replay_source_verification(),
                &invalid,
            );
        }
    }
    Ok(())
}

#[test]
fn retained_replay_schema_separates_payload_attempts_from_archive_syscalls() -> Test {
    use fss_cli::json_input as input;
    let value = input::parse(&tools_list())?;
    let schema = value
        .get("tools")
        .and_then(input::Value::array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool.get("name").and_then(input::Value::text) == Some("query"))
        })
        .and_then(|tool| tool.get("inputSchema"))
        .ok_or("query schema")?;
    let branches = schema
        .get("oneOf")
        .and_then(input::Value::array)
        .ok_or("branches")?;
    for branch in branches {
        let target = branch
            .get("properties")
            .and_then(|v| v.get("target"))
            .and_then(|v| v.get("const"))
            .and_then(input::Value::text)
            .ok_or("target")?;
        let excludes = excludes_field;
        if target == "recordings" {
            let modes = branch
                .get("oneOf")
                .and_then(input::Value::array)
                .ok_or("modes")?;
            let mut retained_modes = 0;
            for mode in modes {
                let retained = mode
                    .get("required")
                    .and_then(input::Value::array)
                    .is_some_and(|rows| rows.iter().any(|v| v.text() == Some("retained_import")));
                if retained {
                    retained_modes += 1;
                    assert!(excludes(mode, "max_query_io_calls"));
                    assert!(!excludes(mode, "max_query_read_objects"));
                } else {
                    assert!(excludes(mode, "retained_import"));
                    assert!(excludes(mode, "max_query_read_objects"));
                }
            }
            assert_eq!(retained_modes, 1);
        } else if matches!(target, "qsr" | "tracks" | "reports") {
            // These targets share immutable payload-read accounting, not archive syscall quotas.
            assert!(excludes(branch, "retained_import"));
            assert!(excludes(branch, "max_query_io_calls"));
            assert!(!excludes(branch, "max_query_read_objects"));
        } else {
            assert!(excludes(branch, "retained_import"));
            assert!(excludes(branch, "max_query_read_objects"));
        }
    }
    Ok(())
}
