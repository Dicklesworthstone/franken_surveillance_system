#![forbid(unsafe_code)]
//! Execution-phase diagnostics, redaction, render errors, request digests, and read-only
//! execution boundaries shared across CLI agent commands.

use fss_core::{CanonicalEncoder, ContentDigest, ExecutionBoundary};
use fss_reference::agent_orient::DeploymentReadError;

use crate::diagnostic::escape_json_str;
use crate::error::{ERR_CLI_RUNTIME_FAILURE, ERR_DOCTOR_NOT_A_DEPLOYMENT, ExitIdentity};
use crate::redact::redact_value_or_digest;

/// Why a typed answer could not be rendered (an internal failure, never a partial answer).
#[derive(Debug)]
pub(crate) struct RenderError(pub(crate) &'static str);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for RenderError {}

/// Execution-phase refusal rendered as `fss.cli_diagnostic.v1` (no anchor exists to answer at).
pub(crate) fn execution_diagnostic(
    command: &str,
    root: &std::path::Path,
    error_id: &str,
    exit: ExitIdentity,
) -> String {
    execution_diagnostic_with_detail(command, root, error_id, exit, None, None)
}

/// Execution-phase refusal rendered as `fss.cli_diagnostic.v1`, preserving redacted error detail
/// and a safe recovery hint so callers never see opaque `ERR-CLI-RUNTIME-FAILURE-001` swallows.
pub(crate) fn execution_diagnostic_with_detail(
    command: &str,
    root: &std::path::Path,
    error_id: &str,
    exit: ExitIdentity,
    detail: Option<&str>,
    recovery_hint: Option<&str>,
) -> String {
    let input = redact_value_or_digest(&root.to_string_lossy());
    let mut extras = String::new();
    if let Some(raw_detail) = detail.filter(|text| !text.trim().is_empty()) {
        let sanitized = sanitize_diagnostic_text(raw_detail);
        extras.push_str(",\"detail\":\"");
        extras.push_str(&escape_json_str(&sanitized));
        extras.push('"');
    }
    if let Some(raw_hint) = recovery_hint.filter(|text| !text.trim().is_empty()) {
        let sanitized = sanitize_diagnostic_text(raw_hint);
        extras.push_str(",\"recovery_hint\":\"");
        extras.push_str(&escape_json_str(&sanitized));
        extras.push('"');
    }
    format!(
        "{{\"schema\":\"fss.cli_diagnostic.v1\",\"phase\":\"execution\",\"binary\":\"fss\",\"command\":\"{command}\",\"argument_index\":null,\"redacted_input\":\"{}\",\"error_id\":\"{error_id}\",\"exit_id\":\"{}\",\"exit_code\":{},\"contract_basis\":\"fss/1\",\"effect_started\":false,\"retryable\":false,\"recovery_class\":\"operator_action_required\",\"correlation_id\":\"corr-fss-{error_id}\",\"proof_handle\":\"fss://proof/cli/{command}-refusal\"{extras}}}",
        escape_json_str(&input),
        exit.identifier,
        exit.code
    )
}

pub(super) fn sanitize_diagnostic_text(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let scrubbed_tokens: Vec<String> = cleaned
        .split_whitespace()
        .map(scrub_diagnostic_token)
        .collect();
    let joined = scrubbed_tokens.join(" ");
    const MAX_DETAIL_BYTES: usize = 512;
    if joined.len() <= MAX_DETAIL_BYTES {
        return joined;
    }
    let mut end = MAX_DETAIL_BYTES.saturating_sub(3);
    while !joined.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &joined[..end])
}

fn scrub_diagnostic_token(token: &str) -> String {
    // Redact URL userinfo (`scheme://user:pass@host/...` -> `scheme://<redacted>@host/...`).
    if let Some(scheme_end) = token.find("://") {
        let after_scheme = &token[scheme_end + 3..];
        let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        if let Some(at_pos) = authority.rfind('@') {
            let scheme = &token[..scheme_end + 3];
            let rest = &after_scheme[at_pos + 1..];
            return format!("{scheme}<redacted>@{rest}");
        }
    }
    // Redact secret key=value or key:value tokens while preserving the key name.
    let lower = token.to_ascii_lowercase();
    for sep in ['=', ':'] {
        if let Some(pos) = lower.find(sep) {
            let key = &lower[..pos];
            if matches!(
                key,
                "password"
                    | "passwd"
                    | "pwd"
                    | "token"
                    | "access_token"
                    | "refresh_token"
                    | "secret"
                    | "api_key"
                    | "apikey"
                    | "authorization"
                    | "cookie"
                    | "bearer"
            ) {
                return format!("{}{sep}<redacted>", &token[..pos]);
            }
        }
    }
    token.to_owned()
}

pub(crate) fn read_refusal(
    command: &str,
    root: &std::path::Path,
    error: &DeploymentReadError,
) -> (String, ExitIdentity) {
    let detail = error.to_string();
    match error {
        DeploymentReadError::NotADeployment { .. } => (
            execution_diagnostic_with_detail(
                command,
                root,
                ERR_DOCTOR_NOT_A_DEPLOYMENT,
                ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
                Some(&detail),
                Some(
                    "Verify --root points to an initialized FSS deployment containing LAYOUT and ledger/.",
                ),
            ),
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ),
        DeploymentReadError::Unreadable { .. }
        | DeploymentReadError::Corrupt { .. }
        | DeploymentReadError::NotCommitted { .. } => (
            execution_diagnostic_with_detail(
                command,
                root,
                ERR_CLI_RUNTIME_FAILURE,
                ExitIdentity::RUNTIME_FAILURE,
                Some(&detail),
                Some(
                    "Inspect the deployment read-only with `fss doctor --root <DIR>` before retrying.",
                ),
            ),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

pub(crate) fn internal_failure(command: &str, root: &std::path::Path) -> (String, ExitIdentity) {
    internal_failure_with_detail(
        command,
        root,
        "unexpected internal rendering or contract failure",
    )
}

pub(crate) fn internal_failure_with_detail(
    command: &str,
    root: &std::path::Path,
    detail: &str,
) -> (String, ExitIdentity) {
    (
        execution_diagnostic_with_detail(
            command,
            root,
            ERR_CLI_RUNTIME_FAILURE,
            ExitIdentity::RUNTIME_FAILURE,
            Some(detail),
            Some(
                "Inspect the `detail` field and run `fss doctor --root <DIR>` to verify deployment integrity.",
            ),
        ),
        ExitIdentity::RUNTIME_FAILURE,
    )
}

pub(crate) fn request_identity(
    domain: &str,
    parts: impl FnOnce(&mut CanonicalEncoder),
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    parts(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

pub(crate) fn read_only_boundary(completed: String) -> ExecutionBoundary {
    ExecutionBoundary {
        completed: vec![completed],
        not_started: vec!["Every listed affordance: this read executes none of them.".to_owned()],
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "The deployment root was only read: no file was created, written, locked, or \
             repaired."
                .to_owned(),
        ],
        invalidated: Vec::new(),
    }
}

pub(crate) fn rendered(
    result: Result<String, Box<dyn std::error::Error>>,
    exit: ExitIdentity,
    command: &str,
    root: &std::path::Path,
) -> (String, ExitIdentity) {
    match result {
        Ok(json) => (json, exit),
        Err(error) => internal_failure_with_detail(command, root, &error.to_string()),
    }
}
