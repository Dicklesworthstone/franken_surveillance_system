#![forbid(unsafe_code)]
//! AOP-005 event evidence hydration through the deployment's exclusive session owner.
//!
//! Source authority stays read-only. Session charges and progressive cursor consumption are
//! durable agent-plane writes, so repeated requests are not free or transport-idempotent.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{AgentView, ContentDigest, DigestAlgorithm, EventId, HydrationLevel, SessionId};
use fss_reference::agent_event_hydration::{EVENT_HYDRATION_H0_TOKENS, EVENT_HYDRATION_H1_TOKENS};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::deployment_session::evidence_hydration::{
    EvidenceHydrationCharge, EvidenceHydrationFailure, EvidenceHydrationRequest,
    MAX_EVIDENCE_HYDRATION_TOKENS, hydrate_event_evidence,
};

use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options, principal, required_root, take};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

mod render;
mod wire;

/// Exact caller-selected event revision and live durable session, without caller grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventHydrationQueryArgs {
    /// Existing deployment root; only its existing agent session store may be updated.
    pub root: PathBuf,
    /// Native admission input shared by the CLI and MCP adapter.
    pub request: EvidenceHydrationRequest,
}

fn malformed(option: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: "[redacted]".to_owned(),
        reason: reason.to_owned(),
        command: Some("query".to_owned()),
        index,
    }
}

fn required<'a>(
    values: &'a [(String, String, usize)],
    name: &str,
) -> Result<(&'a str, usize), CliError> {
    take(values, name)
        .map(|(_, value, index)| (value.as_str(), *index))
        .ok_or_else(|| CliError::MissingValue {
            option: name.to_owned(),
            command: Some("query".to_owned()),
            expected: format!("explicit {name} for exact retained event evidence"),
        })
}

fn digest(name: &str, text: &str, index: usize) -> Result<ContentDigest, CliError> {
    ContentDigest::parse(text)
        .ok()
        .filter(|value| {
            value.algorithm() == DigestAlgorithm::Sha256
                && value.to_text() == text
                && value.bytes().iter().any(|byte| *byte != 0)
        })
        .ok_or_else(|| malformed(name, "expected a canonical nonzero SHA-256 digest", index))
}

fn positive(name: &str, value: &str, maximum: u64, index: usize) -> Result<u64, CliError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| (1..=maximum).contains(number) && number.to_string() == value)
        .ok_or_else(|| {
            malformed(
                name,
                "expected a bounded positive canonical decimal integer",
                index,
            )
        })
}

/// Closed H0/H1 grammar: the descriptor is discovered at H0 and explicitly pinned at H1.
pub fn parse_event_hydration_query_args(
    tokens: &[ArgToken],
) -> Result<EventHydrationQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--session",
            "--generation",
            "--event-id",
            "--revision-digest",
            "--anchor",
            "--level",
            "--descriptor-digest",
            "--budget-tokens",
            "--continuation",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "evidence-hydration" {
        return Err(malformed("--target", "expected evidence-hydration", index));
    }
    let root = required_root("query", &values)?;
    if !root.is_absolute() {
        return Err(malformed(
            "--root",
            "an absolute deployment root is required",
            0,
        ));
    }
    let (value, index) = required(&values, "--session")?;
    let session_id = SessionId::parse(value).map_err(|_| {
        malformed(
            "--session",
            "expected an exact retained session identity",
            index,
        )
    })?;
    let (value, index) = required(&values, "--generation")?;
    let generation = positive("--generation", value, u64::MAX, index)?;
    let (value, index) = required(&values, "--event-id")?;
    let event_id = EventId::parse(value)
        .map_err(|_| malformed("--event-id", "expected an exact event identity", index))?;
    let (value, index) = required(&values, "--revision-digest")?;
    let expected_revision = digest("--revision-digest", value, index)?;
    let (value, index) = required(&values, "--anchor")?;
    let expected_anchor = AnchorToken::parse(value).ok_or_else(|| {
        malformed(
            "--anchor",
            "expected the exact current deployment authority/effect token",
            index,
        )
    })?;
    let (value, index) = required(&values, "--level")?;
    let level = match value {
        "H0" => HydrationLevel::H0,
        "H1" => HydrationLevel::H1,
        _ => {
            return Err(malformed(
                "--level",
                "this retained metadata profile admits H0 or H1",
                index,
            ));
        }
    };
    let expected_descriptor = take(&values, "--descriptor-digest")
        .map(|(_, value, index)| digest("--descriptor-digest", value, *index))
        .transpose()?;
    let budget_tokens = match take(&values, "--budget-tokens") {
        Some((_, value, index)) => positive(
            "--budget-tokens",
            value,
            MAX_EVIDENCE_HYDRATION_TOKENS,
            *index,
        )?,
        None if level == HydrationLevel::H0 => EVENT_HYDRATION_H0_TOKENS,
        None => EVENT_HYDRATION_H1_TOKENS,
    };
    let continuation = take(&values, "--continuation")
        .map(|(_, value, index)| wire::parse_cursor(value).map_err(|()| malformed(
            "--continuation", "expected the complete exact evidence-hydration cursor JSON returned in receipt.continuation", *index,
        ))).transpose()?;
    let request = EvidenceHydrationRequest {
        session_id,
        principal: principal("query", &values)?,
        generation,
        event_id,
        expected_revision,
        expected_anchor,
        expected_descriptor,
        level,
        budget_tokens,
        continuation,
    };
    request.validate().map_err(|_| {
        malformed(
            "query",
            "invalid exact H0/H1 hydration scope or missing descriptor precondition",
            0,
        )
    })?;
    Ok(EventHydrationQueryArgs { root, request })
}

fn view(level: HydrationLevel) -> AgentView {
    if level == HydrationLevel::H0 {
        AgentView::Case
    } else {
        AgentView::Forensic
    }
}

fn failure(
    args: &EventHydrationQueryArgs,
    failure: EvidenceHydrationFailure,
) -> (String, ExitIdentity) {
    if let Some(charge) = failure.committed {
        return render::charged_refusal(args, &charge, failure.error.code());
    }
    if let Some(observed) = failure.observed {
        return render::uncommitted_refusal(args, &observed, failure.error.code());
    }
    // No trusted anchor exists. Do not invent one or start an unbudgeted read just to format
    // an error; in particular the general session refusal reader can inspect original media.
    (
        crate::orient_cmd::execution_diagnostic(
            "query",
            &args.root,
            failure.error.code(),
            ExitIdentity::AGENT_REFUSED,
        ),
        ExitIdentity::AGENT_REFUSED,
    )
}

/// Execute the native session-owned transaction, then render its complete admitted result.
#[must_use]
pub fn execute_event_hydration_query(args: &EventHydrationQueryArgs) -> (String, ExitIdentity) {
    let started = Instant::now();
    let cancelled = || started.elapsed() >= Duration::from_secs(60);
    let answer = match hydrate_event_evidence(&args.root, &args.request, &cancelled) {
        Ok(answer) => answer,
        Err(error) => return failure(args, error),
    };
    match render::response(args, &answer) {
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES && !cancelled() => {
            (output, ExitIdentity::SUCCESS)
        }
        _ => render::charged_refusal(
            args,
            &EvidenceHydrationCharge {
                journal_root: answer.journal_root,
                anchor: answer.descriptor.anchor.clone(),
                observed_at: answer.response.receipt.issued_at,
                charged_tokens: answer.charged_tokens,
                remaining_tokens: answer.remaining_tokens,
            },
            crate::orient_cmd::ERR_AGENT_CONTEXT_INCOMPLETE,
        ),
    }
}
