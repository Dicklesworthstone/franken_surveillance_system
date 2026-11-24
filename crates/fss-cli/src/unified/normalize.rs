#![forbid(unsafe_code)]
//! Deterministic flag normalization, canonical ID validation, and preview JSON envelope
//! normalization for the unified `fss <domain> <verb>` CLI surface.
//!
//! Semantic plane: `"support"` (pure deterministic normalization and validation; zero Serde).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use fss_core::json_input::{Value, parse as parse_json};
use fss_core::{EventId, SensorId};
use fss_reference::agent_orient::{OrientLimits, read_deployment_cancellable};

use crate::error::CliError;
use crate::json_output::{array, escape_json_str, string};
use crate::token::ArgToken;

use super::domains::{FlagTranslationMode, UnifiedBackend, VerbSpec};

/// Identifier domain validated by [`validate_canonical_id`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalIdKind {
    /// Evidence preservation hold identifier (`hold:front-door-001` or legacy `hold_001`).
    Hold,
    /// Camera/sensor identifier (`sensor:front-door`).
    Sensor,
    /// Committed event identifier (`event:watch:001`).
    Event,
    /// Deployment site lineage identifier (`site:home-main`).
    Site,
}

/// Translated companion binary invocation ready for `std::process::Command`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedCompanionCall {
    /// Companion binary basename (for example `"fss-hold"`).
    pub binary: &'static str,
    /// Complete argv vector passed to the companion binary.
    pub args: Vec<OsString>,
    /// True if JSON output was requested by the caller or guaranteed by the companion.
    pub json_requested: bool,
    /// Unified command prefix suitable for synthesizing `approve_command` on previews.
    pub unified_rerun_prefix: String,
}

/// Validates a canonical `prefix:id` identifier (and legacy `[A-Za-z0-9_-]` for holds) while
/// unconditionally rejecting path traversal, slashes, whitespace, and control characters.
pub fn validate_canonical_id(kind: CanonicalIdKind, raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("identifier must not be empty".to_owned());
    }
    if raw
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
    {
        return Err("identifier must not contain control characters or whitespace".to_owned());
    }
    if raw.contains("..") || raw.contains('/') || raw.contains('\\') || raw.contains('\0') {
        return Err("identifier must not contain path traversal or path separators".to_owned());
    }
    match kind {
        CanonicalIdKind::Hold => validate_hold_id(raw),
        CanonicalIdKind::Sensor => {
            if !raw.contains(':') {
                return Err("sensor ID must use canonical `prefix:id` form".to_owned());
            }
            SensorId::parse(raw.to_owned())
                .map(|_| ())
                .map_err(|_| "invalid canonical sensor identifier".to_owned())
        }
        CanonicalIdKind::Event => {
            if !raw.contains(':') {
                return Err("event ID must use canonical `prefix:id` form".to_owned());
            }
            EventId::parse(raw.to_owned())
                .map(|_| ())
                .map_err(|_| "invalid canonical event identifier".to_owned())
        }
        CanonicalIdKind::Site => {
            if !raw.contains(':') || raw.len() > 256 {
                return Err("site ID must use canonical `prefix:id` form (<= 256 bytes)".to_owned());
            }
            fss_reference::reference_deployment::validate_site_lineage(raw)
                .map_err(|_| "invalid canonical site lineage identifier".to_owned())
        }
    }
}

fn validate_hold_id(raw: &str) -> Result<(), String> {
    if let Some((prefix, body)) = raw.split_once(':') {
        if body.contains(':') {
            return Err("canonical hold ID may contain at most one `:` separator".to_owned());
        }
        if !is_valid_canonical_prefix(prefix) {
            return Err(
                "canonical hold ID prefix must be 1..=16 lowercase [a-z][a-z0-9_-]*".to_owned(),
            );
        }
        if body.is_empty()
            || !body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("canonical hold ID body must be non-empty [A-Za-z0-9_-]".to_owned());
        }
        // Encoded storage representation replaces `:` with `__` (+1 byte) to satisfy the
        // 64-byte `[A-Za-z0-9_-]` invariant in `fss_reference::deletion::holds::HoldRequest`.
        if prefix.len() + 2 + body.len() > 64 {
            return Err("canonical hold ID exceeds maximum length (63 bytes)".to_owned());
        }
        Ok(())
    } else {
        if raw.len() > 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("hold ID must be 1..=64 of [A-Za-z0-9_-] or `prefix:id`".to_owned());
        }
        Ok(())
    }
}

fn is_valid_canonical_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 16
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// Encodes a validated canonical `prefix:id` or legacy `[A-Za-z0-9_-]` hold ID into the exact
/// storage spelling admitted by `fss_reference::deletion::holds::HoldRequest::validate`.
pub fn encode_hold_id_for_storage(raw: &str) -> Result<String, String> {
    validate_canonical_id(CanonicalIdKind::Hold, raw)?;
    if let Some((prefix, body)) = raw.split_once(':') {
        Ok(format!("{prefix}__{body}"))
    } else {
        Ok(raw.to_owned())
    }
}

/// Decodes a storage hold ID back into canonical `prefix:id` form when it was encoded from a
/// canonical prefix; legacy IDs without `__` are returned unchanged.
#[must_use]
pub fn decode_hold_id_from_storage(stored: &str) -> String {
    if let Some((prefix, body)) = stored.split_once("__")
        && is_valid_canonical_prefix(prefix)
        && !body.is_empty()
        && !body.contains("__")
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return format!("{prefix}:{body}");
    }
    stored.to_owned()
}

/// Bare boolean flags recognized across unified and companion commands.
const BARE_FLAGS: &[&str] = &[
    "--json",
    "--owner-authorized",
    "--allow-originals",
    "--unifi-only",
    "--combined-v2",
    "--limited-broadcast",
    "--include-mac-claims",
    "--neighbor-cache",
    "--sweep-all",
    "--tolerate-decode-refusals",
    "--stream-watch",
    "--stream-dwell",
    "--stream-corroborate",
    "--progress-jsonl",
];

/// Splits `--flag=value` tokens into normalized `(flag, value)` pairs while preserving positional
/// tokens and bare boolean flags verbatim.
fn split_inline_equals(tokens: &[ArgToken]) -> Result<Vec<(String, usize)>, CliError> {
    let mut flat = Vec::with_capacity(tokens.len());
    for token in tokens {
        let raw = token.as_str();
        if raw.starts_with("--")
            && let Some((flag, value)) = raw.split_once('=')
        {
            if value.is_empty() {
                return Err(CliError::MissingValue {
                    option: flag.to_owned(),
                    command: None,
                    expected: format!("non-empty value for `{flag}`"),
                });
            }
            flat.push((flag.to_owned(), token.index));
            flat.push((value.to_owned(), token.index));
        } else {
            flat.push((raw.to_owned(), token.index));
        }
    }
    Ok(flat)
}

/// Shells-safely quotes an argument token for display in `approve_command` hints.
#[must_use]
pub fn quote_cli_arg(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

/// Best-effort read-only lookup of `site_lineage` from an existing deployment root's verified
/// history so unified commands do not force redundant `--site` flags when `--root` already exists.
#[must_use]
pub fn infer_site_lineage_read_only(root: &Path) -> Option<String> {
    let is_dir = fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_dir());
    let has_layout =
        fs::symlink_metadata(root.join("LAYOUT")).is_ok_and(|m| m.file_type().is_file());
    if !is_dir || !has_layout {
        return None;
    }
    let never_cancelled = || false;
    read_deployment_cancellable(root, &OrientLimits::default(), &never_cancelled)
        .ok()
        .map(|snapshot| snapshot.site_lineage)
}

/// Translates unified `<domain> <verb>` flags into an exact companion binary invocation,
/// enforcing strict `--root` vs `--archive` separation and canonical ID validation.
pub fn translate_companion_args(
    verb: &VerbSpec,
    raw_tokens: &[ArgToken],
) -> Result<TranslatedCompanionCall, CliError> {
    let UnifiedBackend::Companion {
        binary,
        prefix_args,
        flag_mode,
        companion_accepts_json,
    } = verb.backend
    else {
        return Err(CliError::MalformedValue {
            option: "command".to_owned(),
            value: format!("{} {}", verb.domain, verb.verb),
            reason: format!("`fss {} {}` is handled in-process", verb.domain, verb.verb),
            command: Some(verb.domain.to_owned()),
            index: 0,
        });
    };

    let cmd_label = format!("{} {}", verb.domain, verb.verb);
    let flat = split_inline_equals(raw_tokens)?;

    let mut out: Vec<OsString> = prefix_args.iter().map(OsString::from).collect();
    let mut rerun_parts: Vec<String> = vec![
        "fss".to_owned(),
        verb.domain.to_owned(),
        verb.verb.to_owned(),
    ];

    let mut start_idx = 0_usize;
    if flag_mode == FlagTranslationMode::HoldPolicy {
        let sub = flat
            .first()
            .filter(|(s, _)| !s.starts_with('-'))
            .map(|(s, _)| s.as_str());
        match sub {
            Some("show") => {
                out.push(OsString::from("policy-show"));
                rerun_parts.push("show".to_owned());
                start_idx = 1;
            }
            Some("plan") => {
                out.push(OsString::from("policy-plan"));
                rerun_parts.push("plan".to_owned());
                start_idx = 1;
            }
            Some("commit") => {
                out.push(OsString::from("policy-commit"));
                rerun_parts.push("commit".to_owned());
                start_idx = 1;
            }
            Some(other) => {
                return Err(CliError::UnknownCommand {
                    command: other.to_owned(),
                    context: Some(cmd_label),
                    index: flat[0].1,
                });
            }
            None => {
                out.push(OsString::from("policy-show"));
                rerun_parts.push("show".to_owned());
            }
        }
    } else if flag_mode == FlagTranslationMode::PrivacyReview {
        let sub = flat
            .first()
            .filter(|(s, _)| !s.starts_with('-'))
            .map(|(s, _)| s.as_str());
        if sub.is_none() {
            out.push(OsString::from("show"));
            rerun_parts.push("show".to_owned());
        }
    } else if flag_mode == FlagTranslationMode::MediaExport {
        let sub = flat
            .first()
            .filter(|(s, _)| !s.starts_with('-'))
            .map(|(s, _)| s.as_str());
        if sub.is_none() {
            out.push(OsString::from("event"));
            rerun_parts.push("event".to_owned());
        }
    } else if flag_mode == FlagTranslationMode::EventDelete {
        let sub = flat
            .first()
            .filter(|(s, _)| !s.starts_with('-'))
            .map(|(s, _)| s.as_str());
        if sub.is_none() {
            out.push(OsString::from("plan"));
            rerun_parts.push("plan".to_owned());
        }
    }

    let mut json_requested = false;
    let mut seen_site = false;
    let mut seen_expect = false;
    let mut seen_approve = false;
    let mut root_value: Option<String> = None;

    let mut idx = start_idx;
    while idx < flat.len() {
        let (ref tok, tok_idx) = flat[idx];
        if tok == "--json" {
            if json_requested {
                return Err(CliError::DuplicateOption {
                    option: "--json".to_owned(),
                    command: Some(cmd_label),
                    index: tok_idx,
                });
            }
            json_requested = true;
            if companion_accepts_json {
                out.push(OsString::from("--json"));
            }
            rerun_parts.push("--json".to_owned());
            idx += 1;
            continue;
        }
        if BARE_FLAGS.contains(&tok.as_str()) {
            out.push(OsString::from(tok));
            rerun_parts.push(quote_cli_arg(tok));
            idx += 1;
            continue;
        }
        if tok == "--root" && flag_mode == FlagTranslationMode::ArchiveAsLegacyRoot {
            return Err(CliError::MalformedValue {
                option: "--root".to_owned(),
                value: "[redacted]".to_owned(),
                reason: "`--root` is reserved for deployment roots; use `--archive <archive-dir>` for RTSP capture archives".to_owned(),
                command: Some(cmd_label),
                index: tok_idx,
            });
        }
        if tok.starts_with("--") {
            let Some((val, val_idx)) = flat.get(idx + 1) else {
                return Err(CliError::MissingValue {
                    option: tok.clone(),
                    command: Some(cmd_label),
                    expected: format!("value for `{tok}`"),
                });
            };
            if val.is_empty() || val.starts_with("--") {
                return Err(CliError::MissingValue {
                    option: tok.clone(),
                    command: Some(cmd_label),
                    expected: format!("value for `{tok}`"),
                });
            }
            if tok == "--site" {
                validate_canonical_id(CanonicalIdKind::Site, val).map_err(|reason| {
                    CliError::MalformedValue {
                        option: "--site".to_owned(),
                        value: val.clone(),
                        reason,
                        command: Some(cmd_label.clone()),
                        index: *val_idx,
                    }
                })?;
                seen_site = true;
            }
            if tok == "--root" {
                root_value = Some(val.clone());
            }
            if tok == "--hold-id" && flag_mode == FlagTranslationMode::HoldSubcommand {
                validate_canonical_id(CanonicalIdKind::Hold, val).map_err(|reason| {
                    CliError::MalformedValue {
                        option: "--hold-id".to_owned(),
                        value: val.clone(),
                        reason,
                        command: Some(cmd_label.clone()),
                        index: *val_idx,
                    }
                })?;
            }
            if tok == "--expect" {
                seen_expect = true;
            }
            if tok == "--approve" {
                if seen_approve {
                    return Err(CliError::DuplicateOption {
                        option: "--approve".to_owned(),
                        command: Some(cmd_label),
                        index: tok_idx,
                    });
                }
                seen_approve = true;
            }

            let mapped_flag = match (flag_mode, tok.as_str()) {
                (FlagTranslationMode::ArchiveAsLegacyRoot, "--archive") => "--root",
                (FlagTranslationMode::ApproveAsExpect, "--approve") => {
                    if seen_expect {
                        return Err(CliError::DuplicateOption {
                            option: "--approve".to_owned(),
                            command: Some(cmd_label),
                            index: tok_idx,
                        });
                    }
                    seen_expect = true;
                    "--expect"
                }
                (FlagTranslationMode::ApproveAsApproval, "--approve") => "--approval",
                _ => tok.as_str(),
            };
            out.push(OsString::from(mapped_flag));
            out.push(OsString::from(val));
            if tok != "--approve" && tok != "--expect" && tok != "--approval" {
                rerun_parts.push(quote_cli_arg(tok));
                rerun_parts.push(quote_cli_arg(val));
            }
            idx += 2;
            continue;
        }
        out.push(OsString::from(tok));
        rerun_parts.push(quote_cli_arg(tok));
        idx += 1;
    }

    if flag_mode == FlagTranslationMode::Discover && !json_requested {
        out.push(OsString::from("--json"));
        json_requested = true;
    }

    // Auto-resolve `--site` from an existing deployment root when the caller omitted `--site`
    // and the companion binary requires `--site`.
    let companion_needs_site = matches!(
        flag_mode,
        FlagTranslationMode::HoldSubcommand
            | FlagTranslationMode::HoldPolicy
            | FlagTranslationMode::PrivacyMaskDeclare
            | FlagTranslationMode::PrivacyReview
            | FlagTranslationMode::EventDelete
            | FlagTranslationMode::GraphAtlas
            | FlagTranslationMode::FileSubcommand
            | FlagTranslationMode::MediaExport
    ) || matches!(
        binary,
        "fss-event" | "fss-infer" | "fss-import-rtsp" | "fss-import-http"
    );
    if companion_needs_site
        && !seen_site
        && let Some(ref root_dir) = root_value
        && let Some(site_lineage) = infer_site_lineage_read_only(Path::new(root_dir))
    {
        out.push(OsString::from("--site"));
        out.push(OsString::from(&site_lineage));
    }

    Ok(TranslatedCompanionCall {
        binary,
        args: out,
        json_requested: json_requested || !companion_accepts_json,
        unified_rerun_prefix: rerun_parts.join(" "),
    })
}

/// Lossless, deterministic JSON serializer for [`fss_core::json_input::Value`].
#[must_use]
pub fn render_json_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(raw) => raw.clone(),
        Value::Text(raw) => string(raw),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(render_json_value).collect();
            array(&rendered)
        }
        Value::Object(fields) => {
            let mut out = String::from("{");
            for (index, (key, val)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_str(key));
                out.push_str("\":");
                out.push_str(&render_json_value(val));
            }
            out.push('}');
            out
        }
    }
}

fn extract_approval_digest(fields: &BTreeMap<String, Value>) -> Option<String> {
    if let Some(d) = fields
        .get("approval_digest")
        .and_then(Value::text)
        .filter(|s| s.starts_with("sha256:"))
    {
        return Some(d.to_owned());
    }
    if let Some(val) = fields.get("approval") {
        if let Some(d) = val.text().filter(|s| s.starts_with("sha256:")) {
            return Some(d.to_owned());
        }
        if let Some(obj) = val.object()
            && let Some(d) = obj
                .get("approval_digest")
                .or_else(|| obj.get("digest"))
                .and_then(Value::text)
                .filter(|s| s.starts_with("sha256:"))
        {
            return Some(d.to_owned());
        }
    }
    if let Some(result_obj) = fields.get("result").and_then(Value::object)
        && let Some(d) = result_obj
            .get("approval_digest")
            .and_then(Value::text)
            .filter(|s| s.starts_with("sha256:"))
    {
        return Some(d.to_owned());
    }
    if let Some(payload_obj) = fields.get("payload").and_then(Value::object)
        && let Some(d) = payload_obj
            .get("approvalDigest")
            .or_else(|| payload_obj.get("approval_digest"))
            .and_then(Value::text)
            .filter(|s| s.starts_with("sha256:"))
    {
        return Some(d.to_owned());
    }
    if fields.get("status").and_then(Value::text) == Some("planned")
        && let Some(d) = fields
            .get("manifest_digest")
            .and_then(Value::text)
            .filter(|s| s.starts_with("sha256:"))
    {
        return Some(d.to_owned());
    }
    None
}

fn extract_existing_approve_command(fields: &BTreeMap<String, Value>) -> Option<String> {
    if let Some(cmd) = fields
        .get("approve_command")
        .and_then(Value::text)
        .filter(|s| !s.is_empty())
    {
        return Some(cmd.to_owned());
    }
    if let Some(result_obj) = fields.get("result").and_then(Value::object)
        && let Some(cmd) = result_obj
            .get("approve_command")
            .and_then(Value::text)
            .filter(|s| !s.is_empty())
    {
        return Some(cmd.to_owned());
    }
    if let Some(payload_obj) = fields.get("payload").and_then(Value::object)
        && let Some(cmd) = payload_obj
            .get("approve_command")
            .or_else(|| payload_obj.get("approveCommand"))
            .and_then(Value::text)
            .filter(|s| !s.is_empty())
    {
        return Some(cmd.to_owned());
    }
    None
}

/// Normalizes a preview JSON response from any unified or legacy companion command so that
/// top-level `"approval_digest"` and `"approve_command"` keys are ALWAYS present whenever an
/// approval digest exists in `.approval_digest`, `.approval`, `.result.approval_digest`,
/// `.payload.approvalDigest`, or a `planned` `.manifest_digest`, WITHOUT dropping any original keys.
#[must_use]
pub fn normalize_preview_json(raw_json: &str, rerun_base_command: Option<&str>) -> String {
    let trimmed = raw_json.trim();
    let Ok(Value::Object(mut fields)) = parse_json(trimmed) else {
        return raw_json.to_owned();
    };
    let Some(digest) = extract_approval_digest(&fields) else {
        return raw_json.to_owned();
    };

    fields
        .entry("approval_digest".to_owned())
        .or_insert_with(|| Value::Text(digest.clone()));

    let approve_cmd = match extract_existing_approve_command(&fields) {
        Some(existing) => existing,
        None => match rerun_base_command.filter(|s| !s.is_empty()) {
            Some(base) => format!("{base} --approve {digest}"),
            None => format!("--approve {digest}"),
        },
    };
    fields.insert("approve_command".to_owned(), Value::Text(approve_cmd));
    render_json_value(&Value::Object(fields))
}
