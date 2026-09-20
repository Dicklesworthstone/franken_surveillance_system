#![forbid(unsafe_code)]
//! Agent-friendly CLI library for Franken Surveillance System.
//!
//! Provides total OS-native argument parsing, deterministic rejection of trailing
//! or unknown inputs with stable error and exit identities, structured diagnostic logging,
//! and command execution for FSS binaries.

/// Explicit operator access to existing local AVC/HEVC archives; not an agent operation.
pub mod archive_cmd;
pub mod crosswalk;
pub mod diagnostic;
pub mod error;
pub mod fss_cmd;
pub mod hydration_cmd;
pub mod lab_cmd;
pub mod negative_evidence_cmd;
pub mod redact;
pub mod token;

pub use crosswalk::{
    CrosswalkValidationError, OperationCrosswalkEntry, REGISTERED_EXIT_IDENTITIES,
    REGISTERED_OPERATION_CROSSWALK, REGISTERED_RESOURCE_CROSSWALK, ResourceCrosswalkEntry,
    lookup_by_cli_command, lookup_by_library_entry_point, lookup_by_mcp_tool_name,
    lookup_by_operation_id, lookup_by_operation_name, lookup_resource_by_id,
    lookup_resource_by_name, lookup_resource_by_uri_template, validate_crosswalk_entries,
};

pub use diagnostic::{emit_diagnostic, escape_json_str, render_diagnostic};
pub use error::{
    CliError, ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_TRAILING_ARGUMENT,
    ERR_CLI_UNEXPECTED_POSITIONAL, ERR_CLI_UNKNOWN_COMMAND, ERR_CLI_UNKNOWN_OPTION,
    ERR_DOCTOR_ATTENTION_REQUIRED, ERR_DOCTOR_NOT_A_DEPLOYMENT, ExitIdentity,
};
pub use fss_cmd::{
    DoctorArgs, FssCommand, execute_fss, execute_fss_with_exit, help_text as fss_help_text,
    parse_fss_args, parse_fss_tokens,
};
pub use hydration_cmd::{
    HydrationAction, VALID_HYDRATION_SCENARIOS, help_text as hydration_help_text,
    parse_hydration_args, parse_hydration_tokens,
};
pub use lab_cmd::{
    LabAction, VALID_SCENARIOS as VALID_LAB_SCENARIOS, help_text as lab_help_text, parse_lab_args,
    parse_lab_tokens,
};
pub use negative_evidence_cmd::{
    NEGATIVE_EVIDENCE_REPORT_SCHEMA, NegativeEvidenceAction, execute_negative_evidence,
    help_text as negative_evidence_help_text, parse_negative_evidence_tokens,
};
pub use redact::{
    is_safe_to_echo, is_sensitive_standalone_flag, redact_argument, redact_sensitive_bytes,
    redact_value_or_digest, safe_os_repr, sanitize_and_truncate,
};
pub use token::{ArgToken, MAX_ARG_TOKEN_BYTES, is_option_shaped, tokenize_os_args};
