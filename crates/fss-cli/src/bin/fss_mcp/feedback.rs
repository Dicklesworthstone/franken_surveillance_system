#![forbid(unsafe_code)]
//! Pure MCP projection of native AOP-013 advisory feedback.
//! The native parser and publication owner retain target grounding, authority, provenance,
//! canonical evidence sets, exact retry and root-last custody. No file is read here.

use std::collections::BTreeMap;
use std::ffi::OsStr;

use fss_cli::FssCommand;
use fss_cli::feedback_cmd::parse_feedback_args;
use fss_cli::token::ArgToken;
use fss_core::ContentDigest;
use fss_reference::deployment_session::feedback::MAX_FEEDBACK_EVIDENCE;

use super::json::Value;

type Refusal = (i32, &'static str);

pub(super) const FEEDBACK_TOOL: &str = r#"{"name":"feedback","description":"AOP-013: record an evidence-linked advisory proposal about an existing native event, visible case, committed operation or published plan. Uses the launcher's fixed root and principal and the exact live session anchor. Every supporting and contradicting citation reaches the native owner, which sorts and deduplicates each side independently; citations on both sides remain on both sides. Exact identical native proposals recover their original root and fingerprint after response loss, while authority, target grounding and full publication custody are rechecked. A requested disposition is recorded only: no policy, model, threshold, retention, privacy, identity or effect authority is changed.","inputSchema":{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128},"target":{"type":"string","minLength":6,"maxLength":16384,"pattern":"^(event|case|operation|plan):.+$","description":"Exact native kind:<literal identity>, including any prefix belonging to the identity itself; case:case:east-door targets case:east-door. No filename lookup."},"kind":{"type":"string","enum":["correction","adjudication","helpful","harmful","missing_evidence","bad_affordance","bad_summary","adapter_quirk","runbook_candidate","hard_negative_candidate","policy_candidate","model_candidate"]},"statement":{"type":"string","minLength":1,"maxLength":16384,"description":"Literal proposal text, at most 16384 UTF-8 bytes; never a file to read or a command to execute."},"supporting":{"type":"array","maxItems":256,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"contradicting":{"type":"array","maxItems":256,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"disposition":{"type":"string","enum":["record_only","create_learning_proposal","open_case","requalify","deprecate","operator_review"],"default":"record_only"}},"required":["session","target","kind","statement"],"anyOf":[{"required":["supporting"],"properties":{"supporting":{"minItems":1}}},{"required":["contradicting"],"properties":{"contradicting":{"minItems":1}}}],"additionalProperties":false,"description":"Native bound: supporting plus contradicting must contain 1..256 total supplied handles, before native canonical set normalization."},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}"#;

fn text<'a>(
    args: &'a BTreeMap<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<&'a str, Refusal> {
    args.get(key)
        .and_then(Value::text)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or((-32602, "Expected a non-empty bounded feedback string"))
}

fn evidence(args: &BTreeMap<String, Value>, key: &str) -> Result<Vec<ContentDigest>, Refusal> {
    let Some(value) = args.get(key) else {
        return Ok(Vec::new());
    };
    let Value::Array(values) = value else {
        return Err((
            -32602,
            "Feedback evidence must be an array of digest strings",
        ));
    };
    if values.len() > MAX_FEEDBACK_EVIDENCE {
        return Err((
            -32602,
            "Feedback evidence exceeds the native 256-handle bound",
        ));
    }
    values
        .iter()
        .map(|value| {
            let raw = value.text().ok_or((
                -32602,
                "Every feedback evidence item must be a digest string",
            ))?;
            ContentDigest::parse(raw).map_err(|_| {
                (
                    -32602,
                    "Every feedback evidence item must be sha256:<64 hex>",
                )
            })
        })
        .collect()
}

/// Admit exactly the native feedback grammar. Inline option values remain literal even when
/// they resemble flags or paths. Array values are individually parsed before comma encoding;
/// no item can inject another option, disappear, or move to the opposite evidence side.
pub(super) fn command(
    root: &OsStr,
    principal: &str,
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    if !args.keys().all(|key| {
        [
            "session",
            "target",
            "kind",
            "statement",
            "supporting",
            "contradicting",
            "disposition",
        ]
        .contains(&key.as_str())
    }) {
        return Err((-32602, "Unexpected feedback argument or scope override"));
    }
    let supporting = evidence(args, "supporting")?;
    let contradicting = evidence(args, "contradicting")?;
    let total = supporting.len() + contradicting.len();
    if !(1..=MAX_FEEDBACK_EVIDENCE).contains(&total) {
        return Err((-32602, "Feedback requires 1..256 total evidence handles"));
    }
    let root = root
        .to_str()
        .ok_or((-32602, "Launcher root is not a native UTF-8 path"))?;
    let mut values = vec![
        "feedback".to_owned(),
        "--json".to_owned(),
        format!("--root={root}"),
        format!("--principal={principal}"),
    ];
    for (key, maximum) in [
        ("session", 128),
        ("target", 16_384),
        ("kind", 64),
        ("statement", 16_384),
    ] {
        values.push(format!("--{key}={}", text(args, key, maximum)?));
    }
    if args.contains_key("disposition") {
        values.push(format!("--disposition={}", text(args, "disposition", 64)?));
    }
    for (flag, evidence) in [("supporting", supporting), ("contradicting", contradicting)] {
        if !evidence.is_empty() {
            let value = evidence
                .iter()
                .map(|digest| digest.to_text())
                .collect::<Vec<_>>()
                .join(",");
            values.push(format!("--{flag}={value}"));
        }
    }
    // MCP already bounds the UTF-8 frame, each literal and the combined evidence count.
    // The generic OS argv tokenizer has a separate 4096-byte token ceiling, which cannot
    // represent the native feedback contract's 16 KiB statement or 256 evidence handles.
    // Use the public feedback-specific typed parser with these exact literal tokens; all
    // feedback grammar, principal/session parsing and native validation remain canonical.
    let tokens = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| ArgToken::new(index, value))
        .collect::<Vec<_>>();
    parse_feedback_args(&tokens)
        .map(|feedback| FssCommand::Feedback(Box::new(feedback)))
        .map_err(|_| (-32602, "Feedback arguments failed native typed validation"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use fss_cli::parse_fss_args;

    use super::*;

    const ROOT: &str = "/owner/fixed/deployment";
    const PRINCIPAL: &str = "principal:mcp-feedback";
    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn args(raw: &str) -> Result<BTreeMap<String, Value>, &'static str> {
        match super::super::json::parse(raw).map_err(|()| "invalid test JSON")? {
            Value::Object(args) => Ok(args),
            _ => Err("test arguments are not an object"),
        }
    }

    fn input(kind: &str, target: &str) -> String {
        format!(
            r#"{{"session":"session:one","target":"{target}","kind":"{kind}","statement":"Keep the counterexample.","supporting":["{DIGEST}"]}}"#
        )
    }

    fn mapped(raw: &str) -> Result<fss_cli::feedback_cmd::FeedbackArgs, &'static str> {
        match command(OsStr::new(ROOT), PRINCIPAL, &args(raw)?).map_err(|(_, message)| message)? {
            FssCommand::Feedback(feedback) => Ok(*feedback),
            _ => Err("not a native feedback command"),
        }
    }

    #[test]
    fn all_registered_kinds_dispositions_and_targets_use_native_parsing() -> Result<(), &'static str>
    {
        for kind in [
            "correction",
            "adjudication",
            "helpful",
            "harmful",
            "missing_evidence",
            "bad_affordance",
            "bad_summary",
            "adapter_quirk",
            "runbook_candidate",
            "hard_negative_candidate",
            "policy_candidate",
            "model_candidate",
        ] {
            for target in ["event", "case", "operation", "plan"] {
                let id = format!("{target}:literal-id");
                let native = mapped(&input(kind, &format!("{target}:{id}")))?;
                assert_eq!(native.root, std::path::Path::new(ROOT));
                assert_eq!(native.request.principal.as_str(), PRINCIPAL);
                assert_eq!(native.request.session_id.as_str(), "session:one");
                assert_eq!(native.request.target.kind(), target);
                assert_eq!(native.request.target.id(), id);
                assert_eq!(native.request.kind.as_str(), kind);
                assert_eq!(native.request.disposition.as_str(), "record_only");
            }
        }
        for disposition in [
            "record_only",
            "create_learning_proposal",
            "open_case",
            "requalify",
            "deprecate",
            "operator_review",
        ] {
            let mut fields = args(&input("correction", "event:event:one"))?;
            fields.insert("disposition".into(), Value::Text(disposition.into()));
            let FssCommand::Feedback(native) =
                command(OsStr::new(ROOT), PRINCIPAL, &fields).map_err(|(_, message)| message)?
            else {
                return Err("not feedback");
            };
            assert_eq!(native.request.disposition.as_str(), disposition);
        }
        Ok(())
    }

    #[test]
    fn arrays_and_literal_statement_match_the_public_cli_request_exactly()
    -> Result<(), &'static str> {
        let statement =
            "@/outside/proposal.json --principal=principal:other\nretain \"both\" sides";
        let raw = format!(
            r#"{{"session":"session:one","target":"case:case:east-door","kind":"policy_candidate","statement":"{}","supporting":["{OTHER}","{DIGEST}","{OTHER}"],"contradicting":["{DIGEST}","{OTHER}"],"disposition":"create_learning_proposal"}}"#,
            fss_cli::escape_json_str(statement)
        );
        let mapped = mapped(&raw)?;
        assert_eq!(mapped.request.statement, statement);
        assert_eq!(mapped.request.supporting.len(), 3);
        assert_eq!(mapped.request.supporting[0], mapped.request.supporting[2]);
        assert_eq!(mapped.request.contradicting.len(), 2);
        let argv: Vec<OsString> = vec![
            "feedback".into(),
            "--json".into(),
            "--root".into(),
            ROOT.into(),
            format!("--principal={PRINCIPAL}").into(),
            "--session=session:one".into(),
            "--target=case:case:east-door".into(),
            "--kind=policy_candidate".into(),
            format!("--statement={statement}").into(),
            format!("--supporting={OTHER},{DIGEST},{OTHER}").into(),
            format!("--contradicting={DIGEST},{OTHER}").into(),
            "--disposition=create_learning_proposal".into(),
        ];
        let FssCommand::Feedback(native) = parse_fss_args(argv).map_err(|_| "native parse")? else {
            return Err("not feedback");
        };
        assert_eq!(mapped, *native);
        Ok(())
    }

    #[test]
    fn no_invalid_evidence_item_or_oversized_combined_list_is_dropped() -> Result<(), &'static str>
    {
        for raw in [
            "null",
            "false",
            "1",
            r#""sha256:literal""#,
            r#"["bad"]"#,
            r#"[""]"#,
            r#"[{}]"#,
            r#"[[]]"#,
        ] {
            let mut fields = args(&input("helpful", "event:event:one"))?;
            fields.insert(
                "contradicting".into(),
                super::super::json::parse(raw).map_err(|()| "invalid test item")?,
            );
            assert!(
                command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err(),
                "{raw}"
            );
        }
        let mut fields = args(&input("helpful", "event:event:one"))?;
        fields.insert(
            "contradicting".into(),
            Value::Array(vec![Value::Text(DIGEST.into()), Value::Boolean(false)]),
        );
        assert!(command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err());
        fields.insert(
            "supporting".into(),
            Value::Array((0..128).map(|_| Value::Text(DIGEST.into())).collect()),
        );
        fields.insert(
            "contradicting".into(),
            Value::Array((0..128).map(|_| Value::Text(OTHER.into())).collect()),
        );
        let FssCommand::Feedback(native) =
            command(OsStr::new(ROOT), PRINCIPAL, &fields).map_err(|(_, message)| message)?
        else {
            return Err("not feedback");
        };
        assert_eq!(
            native.request.supporting.len() + native.request.contradicting.len(),
            256
        );
        fields.insert(
            "contradicting".into(),
            Value::Array((0..129).map(|_| Value::Text(OTHER.into())).collect()),
        );
        assert!(command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err());
        fields.insert("supporting".into(), Value::Array(Vec::new()));
        fields.insert("contradicting".into(), Value::Array(Vec::new()));
        assert!(command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err());
        Ok(())
    }

    #[test]
    fn feedback_refuses_scope_overrides_and_non_native_grammar() -> Result<(), &'static str> {
        for key in [
            "root",
            "principal",
            "command",
            "input",
            "statement_file",
            "approve",
            "activePolicyMutation",
            "target_kind",
            "transition",
        ] {
            let mut fields = args(&input("helpful", "event:event:one"))?;
            fields.insert(key.into(), Value::Text("ignored".into()));
            assert!(
                command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err(),
                "{key}"
            );
        }
        for (key, invalid) in [
            ("session", ""),
            ("session", "session,coerced"),
            ("target", "case:"),
            ("target", "file:/outside/proposal.json"),
            ("target", "case"),
            ("kind", "activate_policy"),
            ("statement", ""),
            ("disposition", "activate"),
        ] {
            let mut fields = args(&input("helpful", "event:event:one"))?;
            fields.insert(key.into(), Value::Text(invalid.into()));
            assert!(
                command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err(),
                "{key}"
            );
        }
        let mut fields = args(&input("helpful", "event:event:one"))?;
        fields.insert("statement".into(), Value::Text("é".repeat(8193)));
        assert!(command(OsStr::new(ROOT), PRINCIPAL, &fields).is_err());
        fields.insert("statement".into(), Value::Text("é".repeat(8192)));
        assert!(command(OsStr::new(ROOT), PRINCIPAL, &fields).is_ok());
        Ok(())
    }

    #[test]
    fn discovery_schema_is_bounded_and_advisory() -> Result<(), &'static str> {
        let descriptor =
            super::super::json::parse(FEEDBACK_TOOL).map_err(|()| "invalid feedback schema")?;
        let fields = descriptor.object().ok_or("descriptor is not an object")?;
        assert_eq!(fields.get("name").and_then(Value::text), Some("feedback"));
        assert!(fields.contains_key("inputSchema"));
        assert!(FEEDBACK_TOOL.contains("\"additionalProperties\":false"));
        assert!(FEEDBACK_TOOL.contains("\"idempotentHint\":true"));
        assert!(FEEDBACK_TOOL.contains("1..256 total"));
        assert!(FEEDBACK_TOOL.contains("recorded only"));
        Ok(())
    }
}
