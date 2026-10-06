#![forbid(unsafe_code)]
//! Agent-friendly CLI library for Franken Surveillance System.
//!
//! Provides total OS-native argument parsing, deterministic rejection of trailing
//! or unknown inputs with stable error and exit identities, structured diagnostic logging,
//! and command execution for FSS binaries.

/// Deterministic JSON rendering of the fss-core agent contract types.
pub mod agent_json;
/// The one alert-effect core shared by `fss-event alert`, `fss plan`, and `fss commit`.
pub mod alert_effect;
/// Explicit operator access to existing local AVC/HEVC archives; not an agent operation.
pub mod archive_cmd;
/// Work claims (FSS-226): the work-claiming intent family of `fss investigate` (AOP-006).
pub mod claim_cmd;
pub mod crosswalk;
pub mod diagnostic;
/// `fss plan` / `commit` / `wait` / `cancel` (AOP-007..010): the canonical effect grammar.
pub mod effect_cmd;
/// `fss plan --close`: the immutable execution episode of a terminal plan (AOP-007 `close`).
pub mod episode_cmd;
pub mod error;
/// `fss feedback` (AOP-013): advisory, evidence-linked proposals; never a policy mutation.
pub mod feedback_cmd;
/// Shared findings (FSS-227): the case-board intent family of `fss investigate` (AOP-006).
pub mod finding_cmd;
/// Read-only `follow` (AOP-004 `session.follow`) since an earlier committed anchor.
pub mod follow_cmd;
pub mod fss_cmd;
pub mod hydration_cmd;
/// `fss investigate` (AOP-006): durable mission-scoped investigation cases; agent-plane writes.
pub mod investigate_cmd;
/// Bounded strict JSON reading for intent files.
pub mod json_input;
pub mod lab_cmd;
pub mod negative_evidence_cmd;
/// Read-only `orient` (AOP-003) and `explain` (AOP-011) over a deployment root.
pub mod orient_cmd;
/// Read-only AOP-005 projection of the verified event-record query engine.
pub mod query_cmd;
pub mod redact;
/// Durable agent sessions: `session open` (AOP-001), `session handoff` (AOP-012), and
/// `session resume` (AOP-002); agent-plane writes only.
pub mod session_cmd;
/// `fss status --json [--root <dir>]`: read-only retained inventory (SCHEMA-STATUS-001).
pub mod status_cmd;
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
    ERR_DOCTOR_ATTENTION_REQUIRED, ERR_DOCTOR_NOT_A_DEPLOYMENT, ERR_LAB_RECOVER_ACTION_UNSUPPORTED,
    ERR_LAB_RECOVER_CORRUPT_HISTORY, ERR_LAB_RECOVER_NOTHING_TO_DO, ERR_LAB_RECOVER_PLAN_MISMATCH,
    ERR_LAB_RECOVER_ROOT_LOCKED, ExitIdentity,
};
pub use follow_cmd::{
    ERR_AGENT_FOLLOW_ANCHOR_AHEAD, ERR_AGENT_FOLLOW_ANCHOR_FOREIGN,
    ERR_AGENT_FOLLOW_ANCHOR_UNKNOWN, ERR_AGENT_FOLLOW_CONTINUATION, FollowArgs, execute_follow,
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
    LabAction, LabInterpretation, RecoverJournal, RecoverRequest,
    VALID_SCENARIOS as VALID_LAB_SCENARIOS, help_text as lab_help_text, lab_recover_diagnostic,
    parse_lab_args, parse_lab_tokens,
};
pub use negative_evidence_cmd::{
    NEGATIVE_EVIDENCE_REPORT_SCHEMA, NegativeEvidenceAction, execute_negative_evidence,
    help_text as negative_evidence_help_text, parse_negative_evidence_tokens,
};
pub use orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, ERR_AGENT_EVENT_NOT_FOUND, ExplainArgs, OrientArgs,
    execute_explain, execute_orient,
};
pub use redact::{
    is_safe_to_echo, is_sensitive_standalone_flag, redact_argument, redact_sensitive_bytes,
    redact_value_or_digest, safe_os_repr, sanitize_and_truncate,
};
pub use session_cmd::{
    ERR_AGENT_HANDOFF_INVALID, ERR_AGENT_HANDOFF_NOT_FOUND, ERR_AGENT_SESSION_NOT_FOUND,
    ERR_AGENT_SESSION_STALE, ERR_AGENT_SESSION_STORE_INVALID, ERR_AGENT_SESSION_STORE_LOCKED,
    SessionCommand, SessionHandoffArgs, SessionOpenArgs, SessionResumeArgs, execute_session,
};
pub use status_cmd::{
    ERR_STATUS_CANCELLED, ERR_STATUS_CHANGED, ERR_STATUS_CORRUPT, ERR_STATUS_OVER_BUDGET,
    ERR_STATUS_UNREADABLE, MAX_STATUS_OUTPUT_BYTES, STATUS_SCHEMA, StatusArgs, execute_status,
    execute_status_with, parse_status_args,
};
pub use token::{ArgToken, MAX_ARG_TOKEN_BYTES, is_option_shaped, tokenize_os_args};
