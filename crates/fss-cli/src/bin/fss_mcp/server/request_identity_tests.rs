#![forbid(unsafe_code)]
//! Live request identities stay reserved across refusal, execution, output and cancellation.

use std::error::Error;
use std::path::PathBuf;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const INIT: &str = r#"{"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"identity-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const ROOT: &str = "/owner/request-identity/deployment";
const PRINCIPAL: &str = "principal:request-identity";

fn tracked() -> Server {
    let mut server = Server::new(ROOT.into(), PRINCIPAL.to_owned());
    server.enable_request_tracking();
    server
}

fn ready() -> TestResult<Server> {
    let mut server = tracked();
    let (_, response) = reply(server.dispatch(INIT))?;
    assert!(response.contains("Request IDs cannot be reused"));
    assert!(response.contains("4096 requests"));
    assert!(matches!(server.dispatch(READY), Dispatch::Ignore));
    assert!(matches!(server.phase, Phase::Ready));
    Ok(server)
}

fn reply(dispatch: Dispatch) -> TestResult<(Option<RequestId>, String)> {
    match dispatch {
        Dispatch::Reply { id, text } => Ok((id, text)),
        _ => Err("expected an immediate protocol reply, not native execution".into()),
    }
}

fn assert_wire_error(text: &str, id: &str, code: i32) -> TestResult {
    let value = json::parse(text).map_err(|_| "invalid response JSON")?;
    let fields = value.object().ok_or("response object")?;
    let expected_id = json::parse(id).map_err(|_| "invalid fixture id")?;
    assert_eq!(fields.get("id"), Some(&expected_id));
    let error = fields
        .get("error")
        .and_then(Value::object)
        .ok_or("error object")?;
    assert_eq!(error.get("code"), Some(&Value::Number(code.to_string())));
    assert!(!fields.contains_key("result"));
    Ok(())
}

fn assert_error(dispatch: Dispatch, id: &str, code: i32) -> TestResult {
    let (correlation, text) = reply(dispatch)?;
    assert_eq!(correlation.is_some(), id != "null");
    assert_wire_error(&text, id, code)
}

fn ping(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

fn doctor(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"doctor"}}}}"#)
}

fn cancel(id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id}}}}}"#
    )
}

#[test]
fn live_ids_survive_immediate_results_bad_parameters_and_native_handoff() -> TestResult {
    let mut server = ready()?;
    let (_, first) = reply(server.dispatch(&ping("7")))?;
    assert!(first.contains("\"result\":{}"));
    assert_error(server.dispatch(&doctor("7")), "null", -32600)?;

    assert_error(
        server.dispatch(r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":[]}"#),
        "8",
        -32602,
    )?;
    assert_error(server.dispatch(&ping("8")), "null", -32600)?;

    let Dispatch::Tool { id, command } = server.dispatch(&doctor("9")) else {
        return Err("native request was executed or refused during admission".into());
    };
    assert_eq!(id.key, RequestKey::Integer(9));
    assert!(matches!(command, FssCommand::Doctor(_)));
    // The server must not reuse an ID after the transport releases its native command/result.
    assert_error(server.dispatch(&ping("9")), "null", -32600)?;
    server.enable_request_tracking();
    assert_error(server.dispatch(&ping("7")), "null", -32600)?;
    assert_eq!(server.request_ids.as_ref().map(|ids| ids.len()), Some(4));
    Ok(())
}

#[test]
fn phase_refusals_reserve_ids_before_initialization_can_change() -> TestResult {
    let mut server = tracked();
    assert_error(server.dispatch(&doctor("17")), "17", -32002)?;
    assert_error(
        server.dispatch(&INIT.replace("\"initialize\",\"method\"", "17,\"method\"")),
        "null",
        -32600,
    )?;
    assert!(matches!(server.phase, Phase::New));
    let _ = reply(server.dispatch(INIT))?;
    assert!(matches!(server.dispatch(READY), Dispatch::Ignore));
    assert_error(server.dispatch(&doctor("17")), "null", -32600)?;
    Ok(())
}

#[test]
fn numeric_zero_and_text_zero_have_exact_distinct_cancellation_authority() -> TestResult {
    let mut server = ready()?;
    let Dispatch::Tool { id, .. } = server.dispatch(&doctor("-0")) else {
        return Err("negative-zero request was not admitted".into());
    };
    assert_eq!(id.key, RequestKey::Integer(0));
    assert_eq!(id.wire, "-0");
    let response = id.tool_result("native outcome", ExitIdentity::SUCCESS);
    let parsed = json::parse(&response).map_err(|_| "native reply JSON")?;
    assert_eq!(
        parsed.object().ok_or("native reply object")?.get("id"),
        Some(&Value::Number("-0".to_owned()))
    );
    assert_error(server.dispatch(&doctor("0")), "null", -32600)?;

    let Dispatch::Tool { id, .. } = server.dispatch(&doctor(r#""0""#)) else {
        return Err("text-zero request collided with integer zero".into());
    };
    assert_eq!(id.key, RequestKey::Text("0".to_owned()));
    assert_eq!(id.wire, r#""0""#);
    // Escaping the same text does not manufacture another identity.
    assert_error(server.dispatch(&ping(r#""\u0030""#)), "null", -32600)?;

    let Dispatch::Cancel(numeric) = server.dispatch(&cancel("-0")) else {
        return Err("numeric cancellation was not decoded".into());
    };
    let Dispatch::Cancel(text) = server.dispatch(&cancel(r#""0""#)) else {
        return Err("text cancellation was not decoded".into());
    };
    assert_eq!(numeric.key, RequestKey::Integer(0));
    assert_eq!(text.key, RequestKey::Text("0".to_owned()));
    assert_ne!(numeric.key, text.key);
    Ok(())
}

#[test]
fn integer_ids_never_round_and_invalid_ids_never_acquire_a_reservation() -> TestResult {
    let mut server = ready()?;
    for raw in [
        "9007199254740993",
        "9223372036854775807",
        "-9223372036854775808",
    ] {
        let Dispatch::Tool { id, .. } = server.dispatch(&doctor(raw)) else {
            return Err("exact 64-bit identity refused".into());
        };
        assert_eq!(id.key, RequestKey::Integer(raw.parse::<i64>()?));
        assert_eq!(id.wire, raw);
    }
    let before = server.request_ids.as_ref().map(|ids| ids.len());
    for invalid in [
        "null".to_owned(),
        "true".to_owned(),
        "[]".to_owned(),
        "{}".to_owned(),
        "1.0".to_owned(),
        "1e0".to_owned(),
        "9223372036854775808".to_owned(),
        quote(&"x".repeat(129)),
        quote(&"é".repeat(65)),
    ] {
        assert_error(server.dispatch(&ping(&invalid)), "null", -32600)?;
    }
    assert_eq!(server.request_ids.as_ref().map(|ids| ids.len()), before);
    let valid = quote(&"é".repeat(64));
    let (_, result) = reply(server.dispatch(&ping(&valid)))?;
    assert!(result.contains("\"result\":{}"));
    Ok(())
}

#[test]
fn malformed_and_uninitialized_notifications_cannot_cancel_or_invoke_native_work() -> TestResult {
    let mut server = tracked();
    assert!(matches!(server.dispatch(&cancel("3")), Dispatch::Ignore));
    let _ = reply(server.dispatch(INIT))?;
    assert!(matches!(server.dispatch(&cancel("3")), Dispatch::Ignore));
    assert!(matches!(
        server.dispatch(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"unexpected":true}}"#
        ),
        Dispatch::Ignore
    ));
    assert!(matches!(server.phase, Phase::AwaitingInitialized));
    assert!(matches!(server.dispatch(READY), Dispatch::Ignore));
    let before = server.request_ids.as_ref().map(|ids| ids.len());
    for params in [
        "null".to_owned(),
        "[]".to_owned(),
        "{}".to_owned(),
        r#"{"requestId":null}"#.to_owned(),
        r#"{"requestId":true}"#.to_owned(),
        r#"{"requestId":1.5}"#.to_owned(),
        r#"{"requestId":1e0}"#.to_owned(),
        r#"{"requestId":9223372036854775808}"#.to_owned(),
        r#"{"requestId":3,"reason":false}"#.to_owned(),
        r#"{"requestId":3,"_meta":[]}"#.to_owned(),
        r#"{"requestId":3,"root":"/different-deployment"}"#.to_owned(),
        format!(r#"{{"requestId":{}}}"#, quote(&"x".repeat(129))),
        format!(r#"{{"requestId":3,"reason":{}}}"#, quote(&"x".repeat(1025))),
    ] {
        let frame =
            format!(r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{params}}}"#);
        assert!(
            matches!(server.dispatch(&frame), Dispatch::Ignore),
            "{frame}"
        );
    }
    assert!(matches!(
        server.dispatch(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"session_open","arguments":{"mission":"literal","objective":"ignored notification"}}}"#),
        Dispatch::Ignore
    ));
    assert_eq!(server.request_ids.as_ref().map(|ids| ids.len()), before);
    // A cancellation method carrying its own request ID is not a cancellation notification.
    assert_error(
        server.dispatch(r#"{"jsonrpc":"2.0","id":77,"method":"notifications/cancelled","params":{"requestId":3}}"#),
        "77",
        -32601,
    )?;
    assert!(matches!(server.dispatch(&cancel("3")), Dispatch::Cancel(_)));
    Ok(())
}

#[test]
fn session_request_ceiling_keeps_existing_ids_and_cancellation_without_admitting_more_work()
-> TestResult {
    let mut server = ready()?;
    // Initialization owns the first slot; every protocol request also owns an identity.
    for id in 0..MAX_SESSION_REQUESTS - 1 {
        let (_, result) = reply(server.dispatch(&ping(&id.to_string())))?;
        assert!(result.contains("\"result\":{}"));
    }
    assert_eq!(
        server.request_ids.as_ref().map(|ids| ids.len()),
        Some(MAX_SESSION_REQUESTS)
    );
    let Dispatch::Exhausted { id, text } = server.dispatch(&doctor("900000")) else {
        return Err("exhausted session admitted a native request".into());
    };
    assert_eq!(id.key, RequestKey::Integer(900000));
    assert_wire_error(&text, "900000", -32000)?;
    assert_eq!(
        server.request_ids.as_ref().map(|ids| ids.len()),
        Some(MAX_SESSION_REQUESTS)
    );
    assert_error(server.dispatch(&ping("0")), "null", -32600)?;
    assert!(matches!(server.dispatch(&cancel("0")), Dispatch::Cancel(_)));
    Ok(())
}

#[test]
fn native_preparation_retains_fixed_scope_literal_mission_and_closed_command_clamp() -> TestResult {
    let mut server = ready()?;
    let mission = "/unopened/private/mission.txt --root=/different-deployment";
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"session_open","arguments":{{"mission":{},"objective":"Keep this literal","budget_tokens":1024}}}}}}"#,
        quote(mission)
    );
    let Dispatch::Tool { id, command } = server.dispatch(&frame) else {
        return Err("admission failed to return an unexecuted session command".into());
    };
    assert_eq!(id.key, RequestKey::Integer(1));
    let FssCommand::Session(SessionCommand::Open(args)) = command else {
        return Err("session command changed during admission".into());
    };
    assert_eq!(args.root, PathBuf::from(ROOT));
    assert_eq!(args.principal.as_str(), PRINCIPAL);
    assert_eq!(args.mission, mission);
    assert_eq!(args.objective, "Keep this literal");
    assert_eq!(args.budget_tokens, 1024);
    for arguments in [
        r#"{"root":"/different-deployment"}"#,
        r#"{"principal":"principal:other"}"#,
        r#"{"archive_root":"/different-archive"}"#,
    ] {
        let next_id = 100 + server.request_ids.as_ref().map_or(0, |ids| ids.len());
        let frame = format!(
            r#"{{"jsonrpc":"2.0","id":{next_id},"method":"tools/call","params":{{"name":"doctor","arguments":{arguments}}}}}"#
        );
        assert_error(server.dispatch(&frame), &next_id.to_string(), -32602)?;
    }
    assert!(admit(FssCommand::Help).is_err());
    assert!(admit(FssCommand::Capabilities).is_err());
    assert!(matches!(
        admit(FssCommand::Doctor(fss_cli::DoctorArgs {
            root: Some(PathBuf::from(ROOT))
        })),
        Ok(FssCommand::Doctor(_))
    ));
    Ok(())
}

#[test]
fn reference_oracle_keeps_legacy_id_handling_until_tracking_is_enabled() -> TestResult {
    let mut server = Server::new(ROOT.into(), PRINCIPAL.to_owned());
    assert!(server.request_ids.is_none());
    let _ = reply(server.dispatch(INIT))?;
    assert!(matches!(server.dispatch(READY), Dispatch::Ignore));
    for _ in 0..2 {
        let (_, result) = reply(server.dispatch(&ping("42")))?;
        assert!(result.contains("\"result\":{}"));
    }
    assert!(server.request_ids.is_none());
    Ok(())
}
