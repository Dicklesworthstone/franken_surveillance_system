#![forbid(unsafe_code)]
//! Transport-only parity and denials; native custody execution is tested by the shared reader.

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "/operator/fixed-deployment";
const PRINCIPAL: &str = "principal:fixed-onvif";
const ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const PIN: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const ANCHOR: &str = "anchor:aaaaaaaaaaaaaaaa:0:none:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn sources() -> String {
    format!(r#"[{{"kind":"xml","identity":"{ID}","root":"{PIN}"}}]"#)
}
fn policy() -> String {
    format!(
        r#"{{"schema":"fss.onvif_vendor_zone_policy.v1","coordinates":"raw_vendor_object_millionths","zones":[{{"id":"entry","scope":"{PIN}","module_digest":"{PIN}","frame_transform_digest":"{PIN}","object_transform_digest":"{PIN}","min":[-1000000000000000,-1],"max":[1000000000000000,1],"margin":0}}]}}"#
    )
}
fn ready() -> Server {
    Server {
        root: ROOT.into(),
        principal: PRINCIPAL.to_owned(),
        archive_root: None,
        phase: Phase::Ready,
    }
}
fn request(arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
    )
}
fn arguments(analysis: &str, extra: &str) -> String {
    format!(
        r#"{{"target":"onvif","analysis":"{analysis}","sources":{},"max_entries":32,"anchor":"{ANCHOR}"{extra}}}"#,
        sources()
    )
}
fn native(analysis: &str, zone_policy: Option<&str>) -> Test<FssCommand> {
    let mut args: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        format!("--root={ROOT}").into(),
        format!("--principal={PRINCIPAL}").into(),
        "--target=onvif".into(),
        format!("--analysis={analysis}").into(),
        format!("--sources={}", sources()).into(),
        "--max-entries=32".into(),
        format!("--anchor={ANCHOR}").into(),
    ];
    if let Some(policy) = zone_policy {
        args.push(format!("--zone-policy={policy}").into());
    }
    Ok(parse_fss_args(args)?)
}

#[test]
fn onvif_adapter_uses_native_request_and_preserves_response_bytes() -> Test {
    for analysis in ["tracks", "lifecycle", "zones"] {
        let zone_policy = (analysis == "zones").then(policy);
        let expected = native(analysis, zone_policy.as_deref())?;
        let extra = zone_policy
            .as_ref()
            .map_or_else(String::new, |policy| format!(",\"zone_policy\":{policy}"));
        let input = request(&arguments(analysis, &extra));
        for exit in [ExitIdentity::SUCCESS, ExitIdentity::AGENT_REFUSED] {
            let bytes = "{\"payload\":\"line\\nquote\\\"\\\\\",\"physicalIdentity\":\"unknown\"}\n";
            let mut calls = 0;
            let response = ready()
                .handle_with(&input, |command| {
                    calls += 1;
                    assert_eq!(command, expected);
                    (bytes.to_owned(), exit)
                })
                .ok_or("missing response")?;
            assert_eq!(calls, 1);
            let value = fss_cli::json_input::parse(&response)?;
            let result = value
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
            let content = result
                .get("content")
                .and_then(fss_cli::json_input::Value::array)
                .and_then(|rows| rows.first())
                .and_then(fss_cli::json_input::Value::object)
                .and_then(|row| row.get("text"))
                .and_then(fss_cli::json_input::Value::text);
            assert_eq!(content, Some(bytes));
        }
    }
    Ok(())
}

#[test]
fn onvif_adapter_preserves_source_order_and_exact_policy_integers() -> Test {
    let sources = format!(
        r#"[{{"root":"{PIN}","identity":"{ID}","kind":"xml"}},{{"root":"{ID}","identity":"{PIN}","kind":"rtp"}}]"#
    );
    let input = request(&format!(
        r#"{{"target":"onvif","analysis":"zones","sources":{sources},"zone_policy":{}}}"#,
        policy()
    ));
    let mut calls = 0;
    let mut observed = None;
    let response = ready().handle_with(&input, |command| {
        calls += 1;
        observed = Some(command);
        ("{}".to_owned(), ExitIdentity::SUCCESS)
    });
    assert_eq!(calls, 1);
    assert!(response.is_some());
    let Some(FssCommand::OnvifQuery(args)) = observed else {
        return Err("ONVIF request expected".into());
    };
    assert_eq!(args.root, std::path::PathBuf::from(ROOT));
    assert_eq!(args.request.principal.as_str(), PRINCIPAL);
    assert_eq!(args.request.sources[0].kind(), "xml");
    assert_eq!(args.request.sources[0].identity().to_text(), ID);
    assert_eq!(args.request.sources[1].kind(), "rtp");
    assert_eq!(args.request.sources[1].identity().to_text(), PIN);
    let fss_reference::agent_onvif::OnvifAnalysis::Zones(policy) = args.request.analysis else {
        return Err("zone request expected".into());
    };
    assert_eq!(policy.zones[0].min[0], -1_000_000_000_000_000);
    assert_eq!(policy.zones[0].max[0], 1_000_000_000_000_000);
    Ok(())
}

#[test]
fn onvif_adapter_refuses_scope_overrides_disclosure_paths_and_ambiguous_numbers() {
    for extra in [
        r#", "root":"/private-canary""#,
        r#", "principal":"principal:other""#,
        r#", "archive_root":"/private-canary""#,
        r#", "at":"latest""#,
        r#", "continuation":"cursor:other""#,
        r#", "include_values":true"#,
        r#", "hydrate":"H3""#,
        r#", "approve":"yes""#,
        r#", "event_id":"event:other""#,
        r#", "sensor":"sensor:other""#,
        r#", "zone_policy":"/private-canary""#,
    ] {
        let mut calls = 0;
        let response = ready().handle_with(&request(&arguments("tracks", extra)), |_| {
            calls += 1;
            ("{}".to_owned(), ExitIdentity::SUCCESS)
        });
        assert_eq!(calls, 0);
        assert!(
            response
                .is_some_and(|text| text.contains("-32602") && !text.contains("private-canary"))
        );
    }
    let base = arguments("tracks", "");
    let invalid = [
        base.replace("\"max_entries\":32", "\"max_entries\":0"),
        base.replace("\"max_entries\":32", "\"max_entries\":33"),
        base.replace("\"max_entries\":32", "\"max_entries\":1.0"),
        base.replace("\"max_entries\":32", "\"max_entries\":\"1\""),
        base.replace("\"analysis\":\"tracks\"", "\"analysis\":\"zones\""),
        base.replace("\"analysis\":\"tracks\"", "\"analysis\":\"future\""),
        base.replace(&sources(), "[]"),
        base.replace(&sources(), "\"/private-canary\""),
        base.replace(ID, &ID.to_uppercase()),
    ];
    for input in invalid {
        let mut calls = 0;
        let response = ready().handle_with(&request(&input), |_| {
            calls += 1;
            ("{}".to_owned(), ExitIdentity::SUCCESS)
        });
        assert_eq!(calls, 0);
        assert!(
            response
                .is_some_and(|text| text.contains("-32602") && !text.contains("private-canary"))
        );
    }
}

#[test]
fn onvif_notifications_never_execute_a_query() {
    let message = request(&arguments("tracks", "")).replace("\"id\":42,", "");
    let mut calls = 0;
    assert!(
        ready()
            .handle_with(&message, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            })
            .is_none()
    );
    assert_eq!(calls, 0);
}

#[test]
fn discovery_keeps_one_registered_query_with_a_closed_onvif_branch() -> Test {
    use fss_cli::json_input::{Value as NativeValue, parse};
    let value = parse(&tools_list())?;
    let tools = value
        .object()
        .and_then(|root| root.get("tools"))
        .and_then(NativeValue::array)
        .ok_or("tools")?;
    let queries: Vec<_> = tools
        .iter()
        .filter(|tool| {
            tool.object()
                .and_then(|fields| fields.get("name"))
                .and_then(NativeValue::text)
                == Some("query")
        })
        .collect();
    assert_eq!(queries.len(), 1);
    assert!(!tools.iter().any(|tool| {
        tool.object()
            .and_then(|fields| fields.get("name"))
            .and_then(NativeValue::text)
            .is_some_and(|name| name.contains("onvif"))
    }));
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
    let branches = schema
        .get("oneOf")
        .and_then(NativeValue::array)
        .ok_or("query branches")?;
    let branch = branches
        .iter()
        .find(|branch| {
            branch
                .object()
                .and_then(|fields| fields.get("properties"))
                .and_then(NativeValue::object)
                .and_then(|fields| fields.get("target"))
                .and_then(NativeValue::object)
                .and_then(|fields| fields.get("const"))
                .and_then(NativeValue::text)
                == Some("onvif")
        })
        .ok_or("ONVIF branch")?;
    let required = branch
        .object()
        .and_then(|fields| fields.get("required"))
        .and_then(NativeValue::array)
        .ok_or("ONVIF required")?;
    assert_eq!(
        required
            .iter()
            .filter_map(NativeValue::text)
            .collect::<Vec<_>>(),
        ["target", "analysis", "sources"]
    );
    Ok(())
}
