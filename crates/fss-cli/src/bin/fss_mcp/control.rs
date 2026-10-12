#![forbid(unsafe_code)]
//! Pure MCP projection of the existing native alert control grammar.
//! No deployment read, file lookup, capability minting, execution or retry lives here.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use fss_cli::effect_cmd::EffectCommand;
use fss_cli::{FssCommand, parse_fss_args};
use fss_reference::alert_reconcile::MAX_RECONCILE_STATEMENT_BYTES;

use super::json::Value;

type Refusal = (i32, &'static str);

pub(super) const PLAN_TOOL: &str = r#"{"name":"plan","description":"AOP-007: publish a witnessed native alert ControlPlan in the fixed deployment. intent=alert without approve publishes cognition only; the exact returned plan approval durably prepares that same alert and still sends nothing. intent=close records the native immutable execution episode or withdraws a never-prepared plan; unresolved effects cannot be silently closed. Plans and recommendations grant no effect authority.","inputSchema":{"type":"object","oneOf":[{"type":"object","properties":{"intent":{"const":"alert"},"session":{"type":"string","minLength":1,"maxLength":128},"event_id":{"type":"string","minLength":1,"maxLength":128},"relay":{"type":"string","minLength":1,"maxLength":128,"description":"Exact literal IP:PORT; no DNS or URL."},"path":{"type":"string","minLength":1,"maxLength":4096,"description":"Literal absolute webhook path."},"plaintext_approval":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"deadline_ms":{"type":"integer","minimum":1,"maximum":60000},"case":{"type":"string","minLength":1,"maxLength":128},"approve":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["intent","session","event_id","relay","path","plaintext_approval","deadline_ms"],"additionalProperties":false},{"type":"object","properties":{"intent":{"const":"close"},"session":{"type":"string","minLength":1,"maxLength":128},"plan":{"type":"string","minLength":1,"maxLength":128}},"required":["intent","session","plan"],"additionalProperties":false}]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}"#;

pub(super) const COMMIT_TOOL: &str = r#"{"name":"commit","description":"AOP-008: dispatch or reconcile through the existing durable native alert owner. intent=dispatch requires a retained plan and its exact prepared dispatch approval; it revalidates before durably committing and makes at most one bounded relay attempt. An already-dispatched operation is never resent. Relay acceptance is not human delivery. intent=reconcile previews or records an exactly approved owner attestation with explicit operator_asserted provenance and no network I/O. After response loss inspect with wait and reconcile indeterminacy; never invent an approval or blindly resend.","inputSchema":{"type":"object","oneOf":[{"type":"object","properties":{"intent":{"const":"dispatch"},"plan":{"type":"string","minLength":1,"maxLength":128},"approve":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["intent","plan","approve"],"additionalProperties":false},{"type":"object","properties":{"intent":{"const":"reconcile"},"operation_id":{"type":"string","minLength":1,"maxLength":128},"outcome":{"type":"string","enum":["delivered","not_delivered"]},"evidence":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"statement":{"type":"string","minLength":1,"maxLength":1024,"description":"Literal owner attestation, at most 1024 UTF-8 bytes; never a file path to read."},"approve":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["intent","operation_id","outcome","evidence","statement"],"additionalProperties":false}]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}"#;

pub(super) const CANCEL_TOOL: &str = r#"{"name":"cancel","description":"AOP-010: preview cancellation of a still-prepared native alert, then record it only with its exact returned cancellation approval. A dispatched operation cannot be turned into a not-sent cancellation; inspect and reconcile it. Exact completed cancellation retries preserve the original receipt. No network I/O, background task or implicit retry.","inputSchema":{"type":"object","properties":{"operation_id":{"type":"string","minLength":1,"maxLength":128},"approve":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["operation_id"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}"#;

fn only(args: &BTreeMap<String, Value>, names: &[&str]) -> Result<(), Refusal> {
    if args.keys().all(|key| names.contains(&key.as_str())) {
        Ok(())
    } else {
        Err((
            -32602,
            "Unexpected control argument, mixed intent or scope override",
        ))
    }
}

fn text<'a>(
    args: &'a BTreeMap<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<&'a str, Refusal> {
    args.get(key)
        .and_then(Value::text)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or((-32602, "Expected a non-empty bounded control string"))
}

fn put(
    argv: &mut Vec<OsString>,
    args: &BTreeMap<String, Value>,
    key: &str,
    flag: &str,
    maximum: usize,
) -> Result<(), Refusal> {
    let value = text(args, key, maximum)?;
    // Inline values are literal values even if they resemble another flag or a filename.
    argv.push(format!("{flag}={value}").into());
    Ok(())
}

fn optional_approval(
    argv: &mut Vec<OsString>,
    args: &BTreeMap<String, Value>,
) -> Result<(), Refusal> {
    if args.contains_key("approve") {
        put(argv, args, "approve", "--approve", 71)?;
    }
    Ok(())
}

fn deadline(args: &BTreeMap<String, Value>) -> Result<u64, Refusal> {
    let Some(Value::Number(raw)) = args.get("deadline_ms") else {
        return Err((-32602, "Expected a positive integer deadline_ms"));
    };
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err((-32602, "Expected a positive integer deadline_ms"));
    }
    raw.parse::<u64>()
        .ok()
        .filter(|value| (1..=fss_cli::alert_effect::MAX_DEADLINE_MS).contains(value))
        .ok_or((-32602, "Dispatch deadline_ms must be in 1..60000"))
}

/// Convert one admitted control tool into the existing typed CLI command. The caller alone
/// invokes the native owner after its ordinary JSON-RPC initialization/notification checks.
pub(super) fn command(
    name: &str,
    root: &OsStr,
    principal: &str,
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let mut argv: Vec<OsString> = vec![
        name.into(),
        "--json".into(),
        "--root".into(),
        root.to_owned(),
        format!("--principal={principal}").into(),
    ];
    match name {
        "plan" => match text(args, "intent", 32)? {
            "alert" => {
                only(
                    args,
                    &[
                        "intent",
                        "session",
                        "event_id",
                        "relay",
                        "path",
                        "plaintext_approval",
                        "deadline_ms",
                        "case",
                        "approve",
                    ],
                )?;
                argv.push("--intent=alert".into());
                for (key, flag, maximum) in [
                    ("session", "--session", 128),
                    ("event_id", "--event-id", 128),
                    ("relay", "--relay", 128),
                    ("path", "--path", 4096),
                    ("plaintext_approval", "--plaintext-approval", 71),
                ] {
                    put(&mut argv, args, key, flag, maximum)?;
                }
                argv.push(format!("--deadline-ms={}", deadline(args)?).into());
                if args.contains_key("case") {
                    put(&mut argv, args, "case", "--case", 128)?;
                }
                optional_approval(&mut argv, args)?;
            }
            "close" => {
                only(args, &["intent", "session", "plan"])?;
                put(&mut argv, args, "session", "--session", 128)?;
                put(&mut argv, args, "plan", "--close", 128)?;
            }
            _ => return Err((-32602, "Unsupported plan intent")),
        },
        "commit" => match text(args, "intent", 32)? {
            "dispatch" => {
                only(args, &["intent", "plan", "approve"])?;
                put(&mut argv, args, "plan", "--plan", 128)?;
                put(&mut argv, args, "approve", "--approve", 71)?;
            }
            "reconcile" => {
                only(
                    args,
                    &[
                        "intent",
                        "operation_id",
                        "outcome",
                        "evidence",
                        "statement",
                        "approve",
                    ],
                )?;
                let outcome = text(args, "outcome", 32)?;
                if !matches!(outcome, "delivered" | "not_delivered") {
                    return Err((-32602, "Unsupported reconciliation outcome"));
                }
                argv.push(format!("--reconcile={outcome}").into());
                put(&mut argv, args, "operation_id", "--operation", 128)?;
                put(&mut argv, args, "evidence", "--evidence", 71)?;
                put(
                    &mut argv,
                    args,
                    "statement",
                    "--statement",
                    MAX_RECONCILE_STATEMENT_BYTES,
                )?;
                optional_approval(&mut argv, args)?;
            }
            _ => return Err((-32602, "Unsupported commit intent")),
        },
        "cancel" => {
            only(args, &["operation_id", "approve"])?;
            put(&mut argv, args, "operation_id", "--operation", 128)?;
            optional_approval(&mut argv, args)?;
        }
        _ => return Err((-32602, "Unsupported control tool")),
    }
    let command = parse_fss_args(argv)
        .map_err(|_| (-32602, "Control arguments failed native typed validation"))?;
    let admitted = match &command {
        FssCommand::Effect(effect) => matches!(
            (name, effect.as_ref()),
            ("plan", EffectCommand::Plan(_) | EffectCommand::Close(_))
                | (
                    "commit",
                    EffectCommand::Commit(_) | EffectCommand::Reconcile(_)
                )
                | ("cancel", EffectCommand::Cancel(_))
        ),
        _ => false,
    };
    if !admitted {
        return Err((-32603, "Native control command boundary refused conversion"));
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINCIPAL: &str = "principal:mcp-control-test";
    const ROOT: &str = "/owner/fixed/deployment";
    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const ALERT: &str = r#"{"intent":"alert","session":"session:one","event_id":"event:one","relay":"127.0.0.1:9","path":"/alert","plaintext_approval":"sha256:1111111111111111111111111111111111111111111111111111111111111111","deadline_ms":5000}"#;

    fn args(raw: &str) -> Result<BTreeMap<String, Value>, &'static str> {
        match super::super::json::parse(raw).map_err(|()| "invalid test JSON")? {
            Value::Object(args) => Ok(args),
            _ => Err("test arguments are not an object"),
        }
    }

    fn mapped(name: &str, raw: &str) -> Result<EffectCommand, &'static str> {
        match command(name, OsStr::new(ROOT), PRINCIPAL, &args(raw)?)
            .map_err(|(_, message)| message)?
        {
            FssCommand::Effect(effect) => Ok(*effect),
            _ => Err("not a native effect command"),
        }
    }

    #[test]
    fn control_mapping_keeps_fixed_scope_and_exact_native_approvals() -> Result<(), &'static str> {
        let EffectCommand::Plan(plan) = mapped("plan", ALERT)? else {
            return Err("not an alert plan");
        };
        assert_eq!(plan.root, std::path::Path::new(ROOT));
        assert_eq!(plan.principal.as_str(), PRINCIPAL);
        assert_eq!(plan.session.as_str(), "session:one");
        assert_eq!(plan.deadline_ms, 5000);
        assert!(plan.approve.is_none());

        let EffectCommand::Commit(commit) = mapped(
            "commit",
            &format!(r#"{{"intent":"dispatch","plan":"plan:abc","approve":"{DIGEST}"}}"#),
        )?
        else {
            return Err("not a dispatch");
        };
        assert_eq!(commit.root, std::path::Path::new(ROOT));
        assert_eq!(commit.principal.as_str(), PRINCIPAL);
        assert_eq!(commit.approve.to_text(), DIGEST);
        assert_eq!(commit.plan, "plan:abc");

        let EffectCommand::Cancel(cancel) = mapped(
            "cancel",
            &format!(r#"{{"operation_id":"operation:one","approve":"{DIGEST}"}}"#),
        )?
        else {
            return Err("not a cancellation");
        };
        assert_eq!(cancel.principal.as_str(), PRINCIPAL);
        assert_eq!(
            cancel.approve.map(|digest| digest.to_text()).as_deref(),
            Some(DIGEST)
        );
        Ok(())
    }

    #[test]
    fn reconciliation_is_literal_and_close_uses_its_existing_intent() -> Result<(), &'static str> {
        let literal = "@/outside/attestation.json --approve=not-an-option";
        let EffectCommand::Reconcile(reconcile) = mapped(
            "commit",
            &format!(
                r#"{{"intent":"reconcile","operation_id":"operation:one","outcome":"delivered","evidence":"{DIGEST}","statement":"{literal}"}}"#
            ),
        )?
        else {
            return Err("not a reconciliation");
        };
        assert_eq!(reconcile.attestation.statement, literal);
        assert_eq!(reconcile.principal.as_str(), PRINCIPAL);
        assert!(reconcile.approve.is_none());
        let EffectCommand::Close(close) = mapped(
            "plan",
            r#"{"intent":"close","session":"session:one","plan":"plan:abc"}"#,
        )?
        else {
            return Err("not a closure");
        };
        assert_eq!(close.session.as_str(), "session:one");
        assert_eq!(close.plan, "plan:abc");
        Ok(())
    }

    #[test]
    fn controls_refuse_scope_overrides_mixed_intents_and_unpriced_dispatches()
    -> Result<(), &'static str> {
        for forbidden in [
            "root",
            "principal",
            "command",
            "url",
            "input",
            "output",
            "view",
        ] {
            let mut candidate = args(ALERT)?;
            candidate.insert(forbidden.to_owned(), Value::Text("ignored".to_owned()));
            assert!(command("plan", OsStr::new(ROOT), PRINCIPAL, &candidate).is_err());
        }
        for (name, raw) in [
            ("commit", r#"{"intent":"dispatch","plan":"plan:abc"}"#),
            (
                "commit",
                r#"{"intent":"dispatch","plan":"plan:abc","approve":"wrong"}"#,
            ),
            (
                "commit",
                r#"{"intent":"dispatch","plan":"plan:abc","approve":"wrong","operation_id":"operation:one"}"#,
            ),
            (
                "commit",
                r#"{"intent":"reconcile","plan":"plan:abc","operation_id":"operation:one","outcome":"delivered","evidence":"wrong","statement":"literal"}"#,
            ),
            (
                "plan",
                r#"{"intent":"close","session":"session:one","plan":"plan:abc","approve":"wrong"}"#,
            ),
            ("plan", r#"{"intent":"shell","session":"session:one"}"#),
            (
                "cancel",
                r#"{"operation_id":"operation:one","relay":"127.0.0.1:9"}"#,
            ),
        ] {
            assert!(mapped(name, raw).is_err(), "{name} {raw}");
        }
        for deadline in ["0", "60001", "1.5", "1e3", "-1", "\"1\""] {
            let raw = ALERT.replace(
                "\"deadline_ms\":5000",
                &format!("\"deadline_ms\":{deadline}"),
            );
            assert!(mapped("plan", &raw).is_err(), "{deadline}");
        }
        let oversized = "é".repeat(MAX_RECONCILE_STATEMENT_BYTES / 2 + 1);
        let raw = format!(
            r#"{{"intent":"reconcile","operation_id":"operation:one","outcome":"delivered","evidence":"{DIGEST}","statement":"{oversized}"}}"#
        );
        assert!(mapped("commit", &raw).is_err());
        Ok(())
    }

    #[test]
    fn schemas_are_complete_json_and_disclose_effects_and_nonautomatic_retry()
    -> Result<(), &'static str> {
        for schema in [PLAN_TOOL, COMMIT_TOOL, CANCEL_TOOL] {
            let value = fss_cli::json_input::parse(schema).map_err(|_| "invalid tool schema")?;
            let tool = value.object().ok_or("tool is not an object")?;
            assert!(tool.contains_key("inputSchema"));
            assert!(tool.contains_key("annotations"));
        }
        assert!(COMMIT_TOOL.contains("\"openWorldHint\":true"));
        assert!(COMMIT_TOOL.contains("\"idempotentHint\":false"));
        assert!(CANCEL_TOOL.contains("still-prepared"));
        Ok(())
    }
}
