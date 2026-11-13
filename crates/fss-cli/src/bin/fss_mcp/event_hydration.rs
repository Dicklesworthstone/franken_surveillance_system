#![forbid(unsafe_code)]
//! Closed AOP-005 transport for the existing session-owned metadata disclosure transaction.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::json::Value;

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    let allowed = [
        "target",
        "session",
        "generation",
        "event_id",
        "revision_digest",
        "anchor",
        "level",
        "descriptor_digest",
        "budget_tokens",
        "continuation",
    ];
    if fields
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err((
            -32602,
            "Unexpected evidence-hydration argument or authority override",
        ));
    }
    if fields.get("target").and_then(Value::text) != Some("evidence-hydration") {
        return Err((-32602, "Expected exact evidence-hydration query target"));
    }
    argv.push("--target=evidence-hydration".into());
    for (field, flag, maximum) in [
        ("session", "session", 128),
        ("event_id", "event-id", 128),
        ("anchor", "anchor", 256),
    ] {
        let value = fields
            .get(field)
            .and_then(Value::text)
            .filter(|value| {
                !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
            })
            .ok_or((
                -32602,
                "Expected exact retained session, event and current anchor identities",
            ))?;
        argv.push(format!("--{flag}={value}").into());
    }
    let generation = fields
        .get("generation")
        .and_then(Value::text)
        .filter(|value| {
            value
                .parse::<u64>()
                .is_ok_and(|number| number.to_string() == *value)
        })
        .ok_or((
            -32602,
            "Session generation requires a canonical nonnegative u64 decimal string",
        ))?;
    argv.push(format!("--generation={generation}").into());
    let level = fields
        .get("level")
        .and_then(Value::text)
        .filter(|value| matches!(*value, "H0" | "H1"))
        .ok_or((
            -32602,
            "Retained event metadata hydration admits only H0 or H1",
        ))?;
    argv.push(format!("--level={level}").into());
    for (field, flag, required) in [
        ("revision_digest", "revision-digest", true),
        ("descriptor_digest", "descriptor-digest", level == "H1"),
    ] {
        match fields.get(field) {
            Some(value) => {
                let value = value
                    .text()
                    .filter(|value| {
                        value.len() == 71
                            && value.starts_with("sha256:")
                            && value[7..]
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                            && value[7..].bytes().any(|byte| byte != b'0')
                    })
                    .ok_or((
                        -32602,
                        "Expected a canonical nonzero SHA-256 revision or descriptor digest",
                    ))?;
                argv.push(format!("--{flag}={value}").into());
            }
            None if required => {
                return Err((
                    -32602,
                    "Exact revision and the H1 descriptor precondition are required",
                ));
            }
            None => {}
        }
    }
    if let Some(value) = fields.get("budget_tokens") {
        let Value::Number(value) = value else {
            return Err((
                -32602,
                "Hydration budget_tokens must be a JSON integer in 1..16000",
            ));
        };
        if !value
            .parse::<u64>()
            .is_ok_and(|number| (1..=16_000).contains(&number) && number.to_string() == *value)
        {
            return Err((
                -32602,
                "Hydration budget_tokens must be a JSON integer in 1..16000",
            ));
        }
        argv.push(format!("--budget-tokens={value}").into());
    }
    if let Some(value) = fields.get("continuation") {
        if level != "H1" || !fields.contains_key("descriptor_digest") {
            return Err((
                -32602,
                "A progressive continuation requires H1 and its exact descriptor",
            ));
        }
        let value = value
            .text()
            .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
            .ok_or((
                -32602,
                "Continuation requires the complete native cursor JSON as a bounded string",
            ))?;
        argv.push(format!("--continuation={value}").into());
    }
    Ok(argv)
}
