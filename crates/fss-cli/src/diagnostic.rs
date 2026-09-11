#![forbid(unsafe_code)]
//! Diagnostic rendering and structured error logging for CLI failures.

use std::io::{self, Write};

use crate::error::CliError;
use crate::redact::{redact_argument, redact_value_or_digest};

const CONTRACT_BASIS: &str = "fss/1";
const PROOF_HANDLE: &str = "fss://proof/cli/parse-failure";

/// Escapes a string slice for safe inclusion inside a JSON string literal according to RFC 8259.
#[must_use]
pub fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '\x7f' => out.push_str("\\u007f"),
            c if (c as u32) < 0x20 || (0x80..=0x9F).contains(&(c as u32)) => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Formats the human-readable diagnostic message and the machine-readable JSON log.
#[must_use]
pub fn render_diagnostic(
    error: &CliError,
    binary_name: &str,
    context_command: Option<&str>,
) -> (String, String) {
    let error_id = error.error_id();
    let exit_id = error.exit_identity();
    let repair = error.repair_guidance();
    let effective_command = error.command_name().or(context_command);
    let arg_index = error.argument_index();

    let human_text = format!(
        "{binary_name}: error[{error_id}]: {error}\n  exit identity: {} (code {})\n  repair: {repair}",
        exit_id.identifier, exit_id.code
    );

    let cmd_json = match effective_command {
        Some(cmd) => format!("\"{}\"", escape_json_str(&redact_argument(cmd))),
        None => "null".to_owned(),
    };

    let idx_json = match arg_index {
        Some(idx) => idx.to_string(),
        None => "null".to_owned(),
    };

    let redacted_input = match error {
        CliError::UnknownCommand { command, .. } => redact_value_or_digest(command),
        CliError::UnknownOption { option, .. } => redact_argument(option),
        CliError::MissingValue { option, .. } => redact_argument(option),
        CliError::DuplicateOption { option, .. } => redact_argument(option),
        CliError::MalformedValue { value, .. } => redact_value_or_digest(value),
        CliError::InvalidUnicode { redacted_repr, .. } => redacted_repr.clone(),
        CliError::UnexpectedPositional { argument, .. } => redact_value_or_digest(argument),
        CliError::TrailingArgument { argument, .. } => redact_value_or_digest(argument),
    };

    let safe_redacted_input = escape_json_str(&redacted_input);
    let correlation_id = format!("corr-{binary_name}-{error_id}-{}", arg_index.unwrap_or(0));

    let structured_json = format!(
        "{{\"schema\":\"fss.cli_diagnostic.v1\",\"phase\":\"argument_parsing\",\"binary\":\"{binary_name}\",\"command\":{cmd_json},\"argument_index\":{idx_json},\"redacted_input\":\"{safe_redacted_input}\",\"error_id\":\"{error_id}\",\"exit_id\":\"{}\",\"exit_code\":{},\"contract_basis\":\"{CONTRACT_BASIS}\",\"effect_started\":false,\"retryable\":false,\"recovery_class\":\"never_unchanged\",\"correlation_id\":\"{correlation_id}\",\"proof_handle\":\"{PROOF_HANDLE}\"}}",
        exit_id.identifier, exit_id.code
    );

    (human_text, structured_json)
}

/// Emits the diagnostic text and structured JSON log to standard error.
pub fn emit_diagnostic(error: &CliError, binary_name: &str, context_command: Option<&str>) {
    let (human_text, structured_json) = render_diagnostic(error, binary_name, context_command);
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{human_text}");
    let _ = writeln!(stderr, "{structured_json}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_rendering_contains_required_fields() {
        let err = CliError::TrailingArgument {
            argument: "extra".to_owned(),
            index: 2,
            command: Some("status".to_owned()),
        };
        let (human, json) = render_diagnostic(&err, "fss", None);
        assert!(human.contains("ERR-CLI-TRAILING-ARGUMENT-001"));
        assert!(human.contains("EXIT-CLI-TRAILING-ARGUMENT-002"));
        assert!(json.contains("\"schema\":\"fss.cli_diagnostic.v1\""));
        assert!(json.contains("\"phase\":\"argument_parsing\""));
        assert!(json.contains("\"error_id\":\"ERR-CLI-TRAILING-ARGUMENT-001\""));
        assert!(json.contains("\"exit_id\":\"EXIT-CLI-TRAILING-ARGUMENT-002\""));
        assert!(json.contains("\"exit_code\":2"));
        assert!(json.contains("\"effect_started\":false"));
        assert!(json.contains("\"contract_basis\":\"fss/1\""));
        assert!(json.contains("\"argument_index\":2"));
        assert!(json.contains("\"command\":\"status\""));
    }
}
