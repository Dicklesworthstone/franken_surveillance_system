#![forbid(unsafe_code)]
//! Native recording-query dispatch, owner bindings and lossless transport boundaries.

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Fields = BTreeMap<&'static str, String>;

const CATALOG: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SOURCE: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const RECEIVE: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const DECODE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const CLOCK: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const ANCHOR: &str = "anchor:aaaaaaaaaaaaaaaa:0:none:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn discovery_fields(codec: &str) -> Fields {
    let mut values = fields(codec);
    values.remove("catalog_slot");
    values.remove("catalog_root");
    values.insert("discover_catalogs", "true".to_owned());
    values
}

fn native_discovery(codec: &str) -> Test<FssCommand> {
    use fss_reference::agent_recording_context::discover::RecordingDiscoveryContextRequest;
    use fss_reference::agent_recordings::discover::RecordingDiscoveryRequest;
    let FssCommand::RecordingQuery(base) = native(codec, false)? else {
        return Err("expected singleton fixture".into());
    };
    let source = base.request.recording;
    Ok(FssCommand::RecordingDiscoveryQuery(
        fss_cli::recording_query_cmd::discover::RecordingDiscoveryQueryArgs {
            root: base.root,
            archive_root: base.archive_root,
            request: RecordingDiscoveryContextRequest {
                principal: base.request.principal,
                expected_anchor: base.request.expected_anchor,
                recording: RecordingDiscoveryRequest {
                    codec: source.codec,
                    scope: source.scope,
                    interval: source.interval,
                    max_windows: source.max_windows,
                    max_hydration_bytes: source.max_hydration_bytes,
                },
            },
        },
    ))
}

#[test]
fn discovery_dispatch_preserves_native_scope_responses_and_archive_owner() -> Test {
    for codec in ["avc", "hevc"] {
        let expected = native_discovery(codec)?;
        let values = discovery_fields(codec);
        let mut server = ready(true);
        for exit in [ExitIdentity::SUCCESS, ExitIdentity::AGENT_REFUSED] {
            let bytes = "{\"inventory\":\"complete\",\"physicalPresence\":\"unknown\"}\n";
            let mut calls = 0;
            let answer = server
                .handle_with(&request(&values), |command| {
                    calls += 1;
                    assert_eq!(command, expected);
                    (bytes.to_owned(), exit)
                })
                .ok_or("missing discovery response")?;
            assert_eq!(calls, 1);
            assert_eq!(
                response_text(&answer)?,
                (bytes.to_owned(), exit != ExitIdentity::SUCCESS)
            );
        }
        refused(&mut ready(false), &values);
    }
    Ok(())
}

#[test]
fn discovery_mcp_requires_explicit_true_complete_scope_and_one_query_mode() {
    let valid = discovery_fields("avc");
    let mut server = ready(true);
    for value in ["false", "null", "0", "1", "\"true\"", "[]", "{}"] {
        let mut values = valid.clone();
        values.insert("discover_catalogs", value.to_owned());
        refused(&mut server, &values);
    }
    for (field, value) in [
        (
            "catalogs",
            format!(r#"[{{"slot":"catalog","root":"{CATALOG}"}}]"#),
        ),
        ("catalog_slot", quote("catalog")),
        ("catalog_root", quote(CATALOG)),
        ("clock_slot", quote("clock")),
        ("clock_root", quote(CLOCK)),
        ("start_utc_ns", quote("0")),
        ("end_utc_ns", quote("1")),
        ("archive_root", quote("/other/archive")),
        ("root", quote("/other")),
        ("principal", quote("principal:other")),
        ("from_ns", quote("0")),
    ] {
        let mut values = valid.clone();
        values.insert(field, value);
        refused(&mut server, &values);
    }
    for missing in valid.keys() {
        let mut values = valid.clone();
        values.remove(missing);
        refused(&mut server, &values);
    }
}

fn set_fields(codec: &str) -> Fields {
    let mut values = fields(codec);
    values.remove("catalog_slot");
    values.remove("catalog_root");
    values.insert("catalogs", format!(
        r#"[{{"slot":"camera_catalog-1","root":"{CATALOG}"}},{{"slot":"camera_catalog-2","root":"{CLOCK}"}}]"#,
    ));
    values
}

fn native_set(codec: &str) -> Test<FssCommand> {
    use fss_reference::agent_recording_context::set::RecordingSetContextRequest;
    use fss_reference::agent_recordings::set::{RecordingCatalogPin, RecordingSetQueryRequest};
    let FssCommand::RecordingQuery(base) = native(codec, false)? else {
        return Err("expected singleton fixture".into());
    };
    let source = base.request.recording;
    Ok(FssCommand::RecordingSetQuery(
        fss_cli::recording_query_cmd::set::RecordingSetQueryArgs {
            root: base.root,
            archive_root: base.archive_root,
            request: RecordingSetContextRequest {
                principal: base.request.principal,
                expected_anchor: base.request.expected_anchor,
                recording: RecordingSetQueryRequest {
                    codec: source.codec,
                    scope: source.scope,
                    interval: source.interval,
                    max_windows: source.max_windows,
                    max_hydration_bytes: source.max_hydration_bytes,
                    catalogs: vec![
                        RecordingCatalogPin {
                            slot: source.catalog_slot,
                            root: source.catalog_root,
                        },
                        RecordingCatalogPin {
                            slot: fss_publication::SlotName::parse("camera_catalog-2")?,
                            root: fss_core::ContentDigest::parse(CLOCK)?,
                        },
                    ],
                },
            },
        },
    ))
}

#[test]
fn catalog_set_dispatch_preserves_native_identity_responses_and_owner_binding() -> Test {
    for codec in ["avc", "hevc"] {
        let expected = native_set(codec)?;
        let values = set_fields(codec);
        let mut server = ready(true);
        for exit in [ExitIdentity::SUCCESS, ExitIdentity::AGENT_REFUSED] {
            let bytes =
                "{\"catalogs\":2,\"payloadAvailability\":\"unknown\",\"sourceBytesRead\":false}\n";
            let mut calls = 0;
            let answer = server
                .handle_with(&request(&values), |command| {
                    calls += 1;
                    assert_eq!(command, expected);
                    (bytes.to_owned(), exit)
                })
                .ok_or("missing catalog-set response")?;
            assert_eq!(calls, 1);
            assert_eq!(
                response_text(&answer)?,
                (bytes.to_owned(), exit != ExitIdentity::SUCCESS)
            );
        }
        refused(&mut ready(false), &values);
    }
    Ok(())
}

#[test]
fn catalog_set_mcp_refuses_mixed_modes_nested_overrides_and_delimiter_injection() {
    let valid = set_fields("avc");
    let mut server = ready(true);
    for (field, value) in [
        ("catalog_slot", quote("single")),
        ("catalog_root", quote(CATALOG)),
        ("clock_slot", quote("clock")),
        ("clock_root", quote(CLOCK)),
        ("start_utc_ns", quote("0")),
        ("end_utc_ns", quote("1")),
        ("archive_root", quote("/other/archive")),
        ("root", quote("/other")),
        ("principal", quote("principal:other")),
        ("from_ns", quote("0")),
    ] {
        let mut values = valid.clone();
        values.insert(field, value);
        refused(&mut server, &values);
    }
    for pins in [
        "null".to_owned(),
        "[]".to_owned(),
        "{}".to_owned(),
        "[null]".to_owned(),
        format!(r#"[{{"slot":"first","root":"{CATALOG}","path":"/other"}}]"#),
        format!(r#"[{{"slot":"first,second=bad","root":"{CATALOG}"}}]"#),
        format!(r#"[{{"slot":"first","root":"{CATALOG},second={CLOCK}"}}]"#),
        format!(
            r#"[{{"slot":"first","root":"{CATALOG}"}},{{"slot":"second","root":"{CATALOG}"}}]"#
        ),
        format!(r#"[{{"slot":"first","root":"{CATALOG}"}},{{"slot":"first","root":"{CLOCK}"}}]"#),
        format!(
            "[{}]",
            (0..9)
                .map(|i| format!(r#"{{"slot":"catalog-{i}","root":"{CATALOG}"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ] {
        let mut values = valid.clone();
        values.insert("catalogs", pins);
        refused(&mut server, &values);
    }
    for missing in valid.keys() {
        let mut values = valid.clone();
        values.remove(missing);
        refused(&mut server, &values);
    }
}

fn ready(archive: bool) -> Server {
    let mut server = Server::new(
        "/owner/deployment".into(),
        "principal:local-operator".into(),
    );
    if archive {
        server = server.with_archive("/owner/archive with spaces".into());
    }
    let initialized = server.handle(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"recording-test","version":"1"}}}"#,
    );
    assert!(initialized.is_some_and(|value| value.contains(PROTOCOL_VERSION)));
    assert_eq!(
        server.handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        None
    );
    server
}

fn fields(codec: &str) -> Fields {
    [
        ("target", quote("recordings")),
        ("codec", quote(codec)),
        ("catalog_slot", quote("camera_catalog-1")),
        ("catalog_root", quote(CATALOG)),
        ("sensor", quote("sensor:register")),
        ("stream", quote("stream:main")),
        ("generation", quote("18446744073709551615")),
        ("source_anchor", quote(SOURCE)),
        ("receive_clock", quote(RECEIVE)),
        ("decode_clock", quote(DECODE)),
        ("time_scale", "4294967295".into()),
        ("start_tick", quote("9007199254740993")),
        ("end_tick", quote("18446744073709551615")),
    ]
    .into_iter()
    .collect()
}

fn request(fields: &Fields) -> String {
    let fields = fields
        .iter()
        .map(|(name, value)| format!("{}:{value}", quote(name)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"jsonrpc":"2.0","id":81,"method":"tools/call","params":{{"name":"query","arguments":{{{fields}}}}}}}"#
    )
}

fn native(codec: &str, explicit: bool) -> Test<FssCommand> {
    let mut argv = [
        "query",
        "--json",
        "--root",
        "/owner/deployment",
        "--archive-root",
        "/owner/archive with spaces",
        "--principal",
        "principal:local-operator",
        "--target",
        "recordings",
        "--codec",
        codec,
        "--catalog-slot",
        "camera_catalog-1",
        "--catalog-root",
        CATALOG,
        "--sensor",
        "sensor:register",
        "--stream",
        "stream:main",
        "--generation",
        "18446744073709551615",
        "--source-anchor",
        SOURCE,
        "--receive-clock",
        RECEIVE,
        "--decode-clock",
        DECODE,
        "--time-scale",
        "4294967295",
        "--start-tick",
        "9007199254740993",
        "--end-tick",
        "18446744073709551615",
    ]
    .map(OsString::from)
    .to_vec();
    if explicit {
        argv.extend(
            [
                "--max-windows",
                "32",
                "--max-hydration-bytes",
                "2147483648",
                "--anchor",
                ANCHOR,
            ]
            .map(OsString::from),
        );
    }
    Ok(parse_fss_args(argv)?)
}

fn native_utc(codec: &str, explicit: bool) -> Test<FssCommand> {
    use fss_reference::agent_recording_context::utc::RecordingUtcContextRequest;
    use fss_reference::agent_recordings::utc::RecordingUtcQueryRequest;
    use fss_reference::rtsp::recording_clock::{RecordingClockCodec, clock_slot};

    let FssCommand::RecordingQuery(base) = native(codec, explicit)? else {
        return Err("legacy fixture command".into());
    };
    let source = base.request.recording;
    let clock_codec = match codec {
        "avc" => RecordingClockCodec::Avc,
        "hevc" => RecordingClockCodec::Hevc,
        _ => return Err("fixture codec".into()),
    };
    let clock_slot = clock_slot(clock_codec, &source.scope)?;
    Ok(FssCommand::RecordingUtcQuery(
        fss_cli::recording_query_cmd::utc::RecordingUtcQueryArgs {
            root: base.root,
            archive_root: base.archive_root,
            request: RecordingUtcContextRequest {
                recording: RecordingUtcQueryRequest {
                    codec: source.codec,
                    scope: source.scope,
                    catalog_slot: source.catalog_slot,
                    catalog_root: source.catalog_root,
                    clock_slot,
                    clock_root: fss_core::ContentDigest::parse(CLOCK)?,
                    interval: 9_007_199_254_740_993..u64::MAX,
                    max_windows: source.max_windows,
                    max_hydration_bytes: source.max_hydration_bytes,
                },
                principal: base.request.principal,
                expected_anchor: base.request.expected_anchor,
            },
        },
    ))
}

fn utc_fields(codec: &str) -> Test<Fields> {
    let FssCommand::RecordingUtcQuery(command) = native_utc(codec, false)? else {
        return Err("UTC fixture command".into());
    };
    let mut values = fields(codec);
    values.remove("start_tick");
    values.remove("end_tick");
    values.extend([
        (
            "clock_slot",
            quote(command.request.recording.clock_slot.as_str()),
        ),
        ("clock_root", quote(CLOCK)),
        ("start_utc_ns", quote("9007199254740993")),
        ("end_utc_ns", quote("18446744073709551615")),
    ]);
    Ok(values)
}

fn response_text(response: &str) -> Test<(String, bool)> {
    use fss_cli::json_input::{self as input, Value as Input};

    let value = input::parse(response)?;
    let result = value
        .object()
        .and_then(|value| value.get("result"))
        .and_then(Input::object)
        .ok_or("tool result")?;
    let content = result
        .get("content")
        .and_then(Input::array)
        .ok_or("tool content")?;
    assert_eq!(content.len(), 1);
    let text = content[0]
        .object()
        .and_then(|value| value.get("text"))
        .and_then(Input::text)
        .ok_or("semantic text")?;
    let failed = result
        .get("isError")
        .and_then(Input::boolean)
        .ok_or("error flag")?;
    Ok((text.to_owned(), failed))
}

fn refused(server: &mut Server, fields: &Fields) {
    let mut calls = 0;
    let response = server.handle_with(&request(fields), |_| {
        calls += 1;
        (String::new(), ExitIdentity::SUCCESS)
    });
    assert_eq!(calls, 0, "refused fields dispatched: {fields:?}");
    assert!(
        response.is_some_and(|value| value.contains("\"code\":-32602")),
        "missing typed invalid-arguments refusal: {fields:?}"
    );
}

#[test]
fn both_recording_codecs_equal_native_commands_and_preserve_response_bytes() -> Test {
    for codec in ["avc", "hevc"] {
        for explicit in [false, true] {
            let mut server = ready(true);
            let mut fields = fields(codec);
            if explicit {
                fields.insert("max_windows", "32".into());
                fields.insert("max_hydration_bytes", quote("2147483648"));
                fields.insert("anchor", quote(ANCHOR));
            }
            let expected = native(codec, explicit)?;
            assert!(matches!(expected, FssCommand::RecordingQuery(_)));
            let bytes = "{\"schema\":\"fss.agent_response_envelope.v1\",\"payload\":{\"hydrationLevel\":\"H0\",\"mediaBytes\":false,\"quote\":\"\\\"\\\\\\t\",\"unknowns\":[\"clock ≠ UTC\"]}}\n";
            let mut calls = 0;
            let response = server
                .handle_with(&request(&fields), |command| {
                    calls += 1;
                    assert_eq!(command, expected);
                    (bytes.to_owned(), ExitIdentity::SUCCESS)
                })
                .ok_or("missing response")?;
            assert_eq!(calls, 1);
            assert_eq!(response_text(&response)?, (bytes.to_owned(), false));
        }
    }
    Ok(())
}

#[test]
fn utc_recording_dispatch_is_lossless_and_preserves_native_unknowns_and_refusals() -> Test {
    for codec in ["avc", "hevc"] {
        for explicit in [false, true] {
            let mut server = ready(true);
            let mut fields = utc_fields(codec)?;
            if explicit {
                fields.insert("max_windows", "32".into());
                fields.insert("max_hydration_bytes", quote("2147483648"));
                fields.insert("anchor", quote(ANCHOR));
            }
            let expected = native_utc(codec, explicit)?;
            for (bytes, exit) in [
                (
                    "{\"clock\":\"declared_node_observation\",\"unannotated\":\"clock_unavailable\",\"source_replayed\":false}\n",
                    ExitIdentity::SUCCESS,
                ),
                (
                    "{\"refusal\":\"retained_clock_unverifiable\",\"selection\":null}\n",
                    ExitIdentity::AGENT_REFUSED,
                ),
            ] {
                let mut calls = 0;
                let response = server
                    .handle_with(&request(&fields), |command| {
                        calls += 1;
                        assert_eq!(command, expected);
                        (bytes.to_owned(), exit)
                    })
                    .ok_or("missing UTC response")?;
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
fn utc_missing_pins_mixed_modes_host_overrides_and_lossy_numbers_never_dispatch() -> Test {
    for codec in ["avc", "hevc"] {
        let values = utc_fields(codec)?;
        let mut server = ready(false);
        refused(&mut server, &values);
        let mut server = ready(true);
        for missing in values.keys() {
            let mut reduced = values.clone();
            reduced.remove(missing);
            refused(&mut server, &reduced);
        }
        for (key, value) in [
            ("start_tick", quote("0")),
            ("end_tick", quote("1")),
            ("from_ns", quote("0")),
            ("through_ns", quote("1")),
            ("root", quote("/other")),
            ("archive_root", quote("/other/archive")),
            ("principal", quote("principal:other")),
            ("hydrate", quote("H3")),
            ("clock_slot", quote("arbitrary-alias")),
            ("clock_root", quote("latest")),
            ("generation", quote("1")),
            ("target", quote("footage")),
            ("target", quote("events")),
        ] {
            let mut bad = values.clone();
            bad.insert(key, value);
            refused(&mut server, &bad);
        }
        for key in ["start_utc_ns", "end_utc_ns"] {
            for value in ["9007199254740993", "1e18", "1.0", "null", "true"] {
                let mut bad = values.clone();
                bad.insert(key, value.to_owned());
                refused(&mut server, &bad);
            }
            for value in ["+1", "01", "-1", "1e18", "1.0", "18446744073709551616"] {
                let mut bad = values.clone();
                bad.insert(key, quote(value));
                refused(&mut server, &bad);
            }
        }
        let mut reversed = values.clone();
        reversed.insert("start_utc_ns", quote("18446744073709551615"));
        refused(&mut server, &reversed);
    }
    Ok(())
}

#[test]
fn archive_binding_is_unavailable_by_default_and_client_scope_overrides_refuse() {
    for codec in ["avc", "hevc"] {
        let mut server = ready(false);
        refused(&mut server, &fields(codec));
        let mut server = ready(true);
        for (name, value) in [
            ("root", quote("/other")),
            ("archive_root", quote("/other/archive")),
            ("archive-root", quote("/other/archive")),
            ("archiveRoot", quote("/other/archive")),
            ("principal", quote("principal:other")),
            ("hydrate", quote("H3")),
            ("discover", "true".into()),
            ("path", quote("/etc/passwd")),
        ] {
            let mut fields = fields(codec);
            fields.insert(name, value);
            refused(&mut server, &fields);
        }
    }
}

#[test]
fn recording_and_existing_query_predicates_cannot_cross_targets() {
    let mut server = ready(true);
    for codec in ["avc", "hevc"] {
        for (name, value) in [
            ("event_id", quote("event:one")),
            ("kind", quote("unclassified")),
            ("state", quote("hypothesized")),
            ("zone", quote("door")),
            ("from_ns", quote("0")),
            ("through_ns", quote("100")),
            ("max_entries", "1".into()),
            ("at", quote(ANCHOR)),
            ("continuation", quote("continuation:page-2")),
        ] {
            let mut fields = fields(codec);
            fields.insert(name, value);
            refused(&mut server, &fields);
        }
    }
    let recording = fields("avc");
    for target in [None, Some("events"), Some("footage")] {
        for name in [
            "codec",
            "catalog_slot",
            "catalog_root",
            "generation",
            "source_anchor",
            "receive_clock",
            "decode_clock",
            "time_scale",
            "start_tick",
            "end_tick",
            "max_windows",
            "max_hydration_bytes",
        ] {
            let mut fields = Fields::new();
            if let Some(target) = target {
                fields.insert("target", quote(target));
            }
            let value = match name {
                "max_windows" => "1".into(),
                "max_hydration_bytes" => quote("1"),
                _ => recording[name].clone(),
            };
            fields.insert(name, value);
            refused(&mut server, &fields);
        }
    }
}

#[test]
fn recording_pins_intervals_and_integer_budgets_are_strict() {
    let mut server = ready(true);
    let valid = fields("avc");
    for name in valid.keys() {
        let mut fields = valid.clone();
        fields.remove(name);
        refused(&mut server, &fields);
    }
    for name in [
        "generation",
        "start_tick",
        "end_tick",
        "max_hydration_bytes",
    ] {
        for value in [
            "01",
            "-0",
            "-1",
            "+1",
            "1.0",
            "1e3",
            " 1",
            "1 ",
            "18446744073709551616",
            "١",
        ] {
            let mut fields = valid.clone();
            fields.insert(name, quote(value));
            refused(&mut server, &fields);
        }
        for value in ["1", "1.0", "true", "null", "[]", "{}"] {
            let mut fields = valid.clone();
            fields.insert(name, value.into());
            refused(&mut server, &fields);
        }
    }
    for (name, value) in [
        ("codec", quote("h264")),
        ("codec", quote("HEVC")),
        ("catalog_slot", quote("../catalog")),
        ("catalog_slot", quote("/catalog")),
        ("catalog_slot", quote("Catalog")),
        ("sensor", quote("sensor:invalid\nprivate")),
        ("stream", quote("")),
        ("generation", quote("0")),
        ("end_tick", quote("9007199254740993")),
        ("end_tick", quote("0")),
        ("start_tick", quote("18446744073709551615")),
        ("max_hydration_bytes", quote("0")),
        ("max_hydration_bytes", quote("2147483649")),
        ("time_scale", "0".into()),
        ("time_scale", "-1".into()),
        ("time_scale", "4294967296".into()),
        ("time_scale", "1.0".into()),
        ("time_scale", "1e3".into()),
        ("time_scale", quote("90000")),
        ("max_windows", "0".into()),
        ("max_windows", "33".into()),
        ("max_windows", "-1".into()),
        ("max_windows", "1.0".into()),
        ("max_windows", "1e1".into()),
        ("max_windows", quote("1")),
        ("anchor", quote("latest")),
        ("anchor", quote(SOURCE)),
    ] {
        let mut fields = valid.clone();
        fields.insert(name, value);
        refused(&mut server, &fields);
    }
    for name in [
        "catalog_root",
        "source_anchor",
        "receive_clock",
        "decode_clock",
    ] {
        for value in [
            quote("sha256:abcd"),
            quote(&format!("sha256:{}", "A".repeat(64))),
            quote(&format!("blake3:{}", "a".repeat(64))),
            quote(ANCHOR),
            "null".into(),
        ] {
            let mut fields = valid.clone();
            fields.insert(name, value);
            refused(&mut server, &fields);
        }
    }
}

#[test]
fn zero_start_tick_and_minimal_positive_bounds_are_admitted_without_anchor() -> Test {
    let mut server = ready(true);
    let mut fields = fields("hevc");
    fields.insert("generation", quote("1"));
    fields.insert("time_scale", "1".into());
    fields.insert("start_tick", quote("0"));
    fields.insert("end_tick", quote("1"));
    fields.insert("max_windows", "1".into());
    fields.insert("max_hydration_bytes", quote("1"));
    let mut calls = 0;
    let response = server
        .handle_with(&request(&fields), |command| {
            calls += 1;
            let FssCommand::RecordingQuery(args) = command else {
                unreachable!("recordings must dispatch through the native command");
            };
            assert_eq!(
                args.archive_root,
                std::path::Path::new("/owner/archive with spaces")
            );
            assert_eq!(args.request.recording.scope.recording.generation, 1);
            assert_eq!(args.request.recording.scope.time_scale, 1);
            assert_eq!(args.request.recording.interval, 0..1);
            assert_eq!(args.request.recording.max_windows, 1);
            assert_eq!(args.request.recording.max_hydration_bytes, 1);
            assert!(args.request.expected_anchor.is_none());
            ("metadata only".into(), ExitIdentity::SUCCESS)
        })
        .ok_or("missing response")?;
    assert_eq!(calls, 1);
    assert_eq!(response_text(&response)?, ("metadata only".into(), false));
    Ok(())
}

#[test]
fn recording_notifications_never_execute_and_native_refusals_are_unchanged() -> Test {
    let expected = "{\"schema\":\"fss.agent_response_envelope.v1\",\"outcome\":\"refused\",\"warnings\":[\"catalog root mismatch\"],\"payload\":null}\n";
    for codec in ["avc", "hevc"] {
        for archive in [false, true] {
            let mut server = ready(archive);
            let notification = request(&fields(codec)).replace("\"id\":81,", "");
            let mut calls = 0;
            assert_eq!(
                server.handle_with(&notification, |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                }),
                None
            );
            assert_eq!(calls, 0);
        }
        let mut server = ready(true);
        let response = server
            .handle_with(&request(&fields(codec)), |_| {
                (expected.into(), ExitIdentity::AGENT_REFUSED)
            })
            .ok_or("missing refusal")?;
        assert_eq!(response_text(&response)?, (expected.into(), true));
    }
    Ok(())
}

#[test]
fn recording_discovery_exposes_pins_and_budgets_without_host_scope() -> Test {
    use fss_cli::json_input::{self as input, Value as Input};

    let value = input::parse(&tools_list())?;
    let tool = value
        .object()
        .and_then(|value| value.get("tools"))
        .and_then(Input::array)
        .ok_or("tool list")?
        .iter()
        .filter_map(Input::object)
        .find(|value| value.get("name").and_then(Input::text) == Some("query"))
        .ok_or("query discovery")?;
    let schema = tool
        .get("inputSchema")
        .and_then(Input::object)
        .ok_or("query schema")?;
    let properties = schema
        .get("properties")
        .and_then(Input::object)
        .ok_or("query properties")?;
    for name in [
        "root",
        "archive_root",
        "archive-root",
        "principal",
        "hydrate",
        "discover",
    ] {
        assert!(!properties.contains_key(name), "host override {name}");
    }
    for name in [
        "generation",
        "start_tick",
        "end_tick",
        "max_hydration_bytes",
    ] {
        let property = properties
            .get(name)
            .and_then(Input::object)
            .ok_or("integer-string pin")?;
        assert_eq!(property.get("type").and_then(Input::text), Some("string"));
        assert_eq!(property.get("maxLength").and_then(Input::integer), Some(20));
    }
    let codec = properties
        .get("codec")
        .and_then(Input::object)
        .ok_or("codec")?;
    assert_eq!(
        codec.get("enum").and_then(Input::array),
        Some([Input::Text("avc".into()), Input::Text("hevc".into())].as_slice())
    );
    let windows = properties
        .get("max_windows")
        .and_then(Input::object)
        .ok_or("window budget")?;
    assert_eq!(windows.get("maximum").and_then(Input::integer), Some(32));
    assert_eq!(windows.get("default").and_then(Input::integer), Some(32));
    let scale = properties
        .get("time_scale")
        .and_then(Input::object)
        .ok_or("clock scale")?;
    assert_eq!(
        scale.get("maximum").and_then(Input::integer),
        Some(i128::from(u32::MAX))
    );
    let branches = schema
        .get("oneOf")
        .and_then(Input::array)
        .ok_or("target branches")?;
    let recording = branches
        .iter()
        .filter_map(Input::object)
        .find(|branch| {
            branch
                .get("properties")
                .and_then(Input::object)
                .and_then(|properties| properties.get("target"))
                .and_then(Input::object)
                .and_then(|target| target.get("const"))
                .and_then(Input::text)
                == Some("recordings")
        })
        .ok_or("recordings branch")?;
    let required = recording
        .get("required")
        .and_then(Input::array)
        .ok_or("required pins")?;
    let modes = recording
        .get("oneOf")
        .and_then(Input::array)
        .ok_or("recording clock modes")?;
    let tick_required = modes
        .iter()
        .filter_map(Input::object)
        .filter_map(|mode| mode.get("required").and_then(Input::array))
        .find(|required| {
            required
                .iter()
                .any(|value| value.text() == Some("start_tick"))
        })
        .ok_or("decode-clock bounds")?;
    for name in fields("avc").keys() {
        assert!(
            required
                .iter()
                .chain(tick_required)
                .any(|value| value.text() == Some(*name)),
            "required {name}"
        );
    }
    let utc_required = modes
        .iter()
        .filter_map(Input::object)
        .filter_map(|mode| mode.get("required").and_then(Input::array))
        .find(|required| {
            required
                .iter()
                .any(|value| value.text() == Some("start_utc_ns"))
        })
        .ok_or("UTC bounds and companion pins")?;
    for name in ["clock_slot", "clock_root", "start_utc_ns", "end_utc_ns"] {
        assert!(
            utc_required.iter().any(|value| value.text() == Some(name)),
            "required {name}"
        );
        assert!(!tick_required.iter().any(|value| value.text() == Some(name)));
        let property = properties
            .get(name)
            .and_then(Input::object)
            .ok_or("UTC property")?;
        assert_eq!(property.get("type").and_then(Input::text), Some("string"));
    }
    assert_eq!(modes.len(), 2);
    assert!(!required.iter().any(|value| value.text() == Some("anchor")));
    Ok(())
}
