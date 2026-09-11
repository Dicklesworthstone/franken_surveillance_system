#![forbid(unsafe_code)]
//! Diagnostic rendering and structured error logging for CLI failures.

use std::io::{self, Write};

use crate::error::CliError;
use crate::redact::redact_argument;

const CONTRACT_BASIS: &str = "fss/1";
const PROOF_HANDLE: &str = "fss://proof/cli/parse-failure";

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
        Some(cmd) => format!("\"{}\"", redact_argument(cmd)),
        None => "null".to_owned(),
    };

    let idx_json = match arg_index {
        Some(idx) => idx.to_string(),
        None => "null".to_owned(),
    };

    let redacted_input = match error {
        CliError::UnknownCommand { command, .. } => redact_argument(command),
        CliError::UnknownOption { option, .. } => redact_argument(option),
        CliError::MissingValue { option, .. } => redact_argument(option),
        CliError::DuplicateOption { option, .. } => redact_argument(option),
        CliError::MalformedValue { value, .. } => redact_argument(value),
        CliError::InvalidUnicode { redacted_repr, .. } => redacted_repr.clone(),
        CliError::UnexpectedPositional { argument, .. } => redact_argument(argument),
        CliError::TrailingArgument { argument, .. } => redact_argument(argument),
    };

    let correlation_id = format!("corr-{binary_name}-{error_id}-{}", arg_index.unwrap_or(0));

    let structured_json = format!(
        "{{\"schema\":\"fss.cli_diagnostic.v1\",\"phase\":\"argument_parsing\",\"binary\":\"{binary_name}\",\"command\":{cmd_json},\"argument_index\":{idx_json},\"redacted_input\":\"{redacted_input}\",\"error_id\":\"{error_id}\",\"exit_id\":\"{}\",\"exit_code\":{},\"contract_basis\":\"{CONTRACT_BASIS}\",\"effect_started\":false,\"retryable\":false,\"recovery_class\":\"never_unchanged\",\"correlation_id\":\"{correlation_id}\",\"proof_handle\":\"{PROOF_HANDLE}\"}}",
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
