#![forbid(unsafe_code)]
//! AOP-005 event evidence hydration through the deployment's exclusive session owner (H0/H1)
//! plus capability-gated H2 structured analytic and H3 privacy-masked visual hydration.
//!
//! Source authority stays read-only. H0/H1 session charges and progressive cursor consumption
//! are durable agent-plane writes; H2/H3 are strictly read-only capability-gated projections.

use std::collections::BTreeSet;
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
use crate::orient_cmd::{collect_options_with_repeatable, principal, required_root, take};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::query_cmd::hydration::{
    CapabilityGrantContext, CropBox, DEFAULT_H3_DIMENSION, DEFAULT_H3_JPEG_QUALITY,
    DEFAULT_MAX_H3_BYTES, ExtendedHydrationRequest, H3Limits, HydrationTarget, MAX_H3_FRAMES,
    h2::H2HydrationRequest, h3::H3HydrationRequest,
};
use crate::token::ArgToken;

mod render;
mod wire;

/// Exact caller-selected event revision and live durable session, or extended H2/H3 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventHydrationQueryArgs {
    /// Existing deployment root; read-only for H2/H3, session-store-only write for H0/H1.
    pub root: PathBuf,
    /// Native H0/H1 admission input shared by the CLI and MCP adapter.
    pub request: EvidenceHydrationRequest,
    /// Extended capability-gated H2 or H3 hydration request when `--level H2|H3` is selected.
    pub extended: Option<ExtendedHydrationRequest>,
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

fn nonnegative_usize(name: &str, value: &str, index: usize) -> Result<usize, CliError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|number| number.to_string() == value)
        .ok_or_else(|| {
            malformed(
                name,
                "expected a canonical nonnegative decimal integer",
                index,
            )
        })
}

fn parse_segment_indices(value: &str, index: usize) -> Result<Vec<usize>, CliError> {
    if value.is_empty() {
        return Err(malformed(
            "--segment-indices",
            "expected comma-separated canonical segment indices",
            index,
        ));
    }
    let mut out = Vec::new();
    for part in value.split(',') {
        let seg = nonnegative_usize("--segment-indices", part, index)?;
        out.push(seg);
    }
    Ok(out)
}

/// Normalizes bare `--allow-visual-hydration` into a valued option while preserving closed parsing.
fn normalize_visual_flag(tokens: &[ArgToken]) -> Result<(Vec<ArgToken>, bool), CliError> {
    let mut normalized = Vec::with_capacity(tokens.len());
    let mut allow_visual = false;
    for token in tokens {
        let text = token.as_str();
        if text == "--allow-visual-hydration" {
            if allow_visual {
                return Err(CliError::DuplicateOption {
                    option: "--allow-visual-hydration".to_owned(),
                    command: Some("query".to_owned()),
                    index: token.index,
                });
            }
            allow_visual = true;
            continue;
        }
        if let Some(rest) = text.strip_prefix("--allow-visual-hydration=") {
            if rest != "yes" {
                return Err(malformed(
                    "--allow-visual-hydration",
                    "expected bare --allow-visual-hydration or --allow-visual-hydration=yes",
                    token.index,
                ));
            }
            if allow_visual {
                return Err(CliError::DuplicateOption {
                    option: "--allow-visual-hydration".to_owned(),
                    command: Some("query".to_owned()),
                    index: token.index,
                });
            }
            allow_visual = true;
            continue;
        }
        normalized.push(token.clone());
    }
    Ok((normalized, allow_visual))
}

/// Closed H0/H1/H2/H3 grammar: H0 discovers the descriptor, H1/H2/H3 pin it (or H2/H3 pin import_id).
pub fn parse_event_hydration_query_args(
    tokens: &[ArgToken],
) -> Result<EventHydrationQueryArgs, CliError> {
    let (normalized, allow_visual_hydration) = normalize_visual_flag(tokens)?;
    let values = collect_options_with_repeatable(
        "query",
        &normalized,
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
            "--import-id",
            "--segment-indices",
            "--max-dimension",
            "--crop-box",
            "--max-h3-frames",
            "--max-h3-bytes",
            "--capability",
        ],
        &[("--capability", 8)],
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
    let (level_str, level_idx) = required(&values, "--level")?;
    if matches!(level_str, "H2" | "H3") {
        return parse_extended_args(root, level_str, allow_visual_hydration, &values);
    }
    if allow_visual_hydration {
        return Err(malformed(
            "--allow-visual-hydration",
            "visual hydration flag is only admitted for --level H3",
            0,
        ));
    }
    for extended_only in [
        "--import-id",
        "--segment-indices",
        "--max-dimension",
        "--crop-box",
        "--max-h3-frames",
        "--max-h3-bytes",
        "--capability",
    ] {
        if let Some((_, _, idx)) = take(&values, extended_only) {
            return Err(malformed(
                extended_only,
                "option is only admitted for --level H2 or H3",
                *idx,
            ));
        }
    }
    let level = match level_str {
        "H0" => HydrationLevel::H0,
        "H1" => HydrationLevel::H1,
        _ => {
            return Err(malformed(
                "--level",
                "expected H0, H1, H2, or H3",
                level_idx,
            ));
        }
    };
    let (value, index) = required(&values, "--session")?;
    let session_id = SessionId::parse(value).map_err(|_| {
        malformed(
            "--session",
            "expected an exact retained session identity",
            index,
        )
    })?;
    let (value, index) = required(&values, "--generation")?;
    let generation = value
        .parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == value)
        .ok_or_else(|| {
            malformed(
                "--generation",
                "expected the canonical nonnegative retained session generation",
                index,
            )
        })?;
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
        .map(|(_, value, index)| {
            wire::parse_cursor(value).map_err(|()| {
                malformed(
                    "--continuation",
                    "expected the complete exact evidence-hydration cursor JSON returned in receipt.continuation",
                    *index,
                )
            })
        })
        .transpose()?;
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
    Ok(EventHydrationQueryArgs {
        root,
        request,
        extended: None,
    })
}

fn parse_extended_args(
    root: PathBuf,
    level_str: &str,
    allow_visual_hydration: bool,
    values: &[(String, String, usize)],
) -> Result<EventHydrationQueryArgs, CliError> {
    if let Some((_, _, idx)) = take(values, "--continuation") {
        return Err(malformed(
            "--continuation",
            "H2/H3 hydration does not accept progressive H1 continuations",
            *idx,
        ));
    }
    let principal_id = principal("query", values)?;
    let session_id = take(values, "--session")
        .map(|(_, val, idx)| {
            SessionId::parse(val)
                .map_err(|_| malformed("--session", "expected valid session id", *idx))
        })
        .transpose()?;
    let session_generation = take(values, "--generation")
        .map(|(_, val, idx)| {
            val.parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == *val)
                .ok_or_else(|| malformed("--generation", "expected canonical u64", *idx))
        })
        .transpose()?;
    let expected_anchor = take(values, "--anchor")
        .map(|(_, val, idx)| {
            AnchorToken::parse(val)
                .ok_or_else(|| malformed("--anchor", "expected exact anchor token", *idx))
        })
        .transpose()?;
    let budget_tokens = take(values, "--budget-tokens")
        .map(|(_, val, idx)| positive("--budget-tokens", val, 1_000_000, *idx))
        .transpose()?;
    let mut granted_capabilities = BTreeSet::new();
    for (name, val, idx) in values {
        if name == "--capability" {
            if val.is_empty() || val.len() > 128 {
                return Err(malformed("--capability", "expected capability id", *idx));
            }
            granted_capabilities.insert(val.clone());
        }
    }

    let import_opt = take(values, "--import-id")
        .map(|(_, val, idx)| digest("--import-id", val, *idx))
        .transpose()?;
    let event_opt = take(values, "--event-id")
        .map(|(_, val, idx)| {
            EventId::parse(val)
                .map_err(|_| malformed("--event-id", "expected valid event id", *idx))
        })
        .transpose()?;
    let rev_opt = take(values, "--revision-digest")
        .map(|(_, val, idx)| digest("--revision-digest", val, *idx))
        .transpose()?;
    let desc_opt = take(values, "--descriptor-digest")
        .map(|(_, val, idx)| digest("--descriptor-digest", val, *idx))
        .transpose()?;

    let (target, expected_descriptor) = match (import_opt, event_opt, rev_opt, desc_opt) {
        (Some(import_id), None, None, None) => (HydrationTarget::Import { import_id }, None),
        (None, Some(event_id), Some(revision_digest), Some(descriptor_digest)) => (
            HydrationTarget::Event {
                event_id,
                revision_digest,
            },
            Some(descriptor_digest),
        ),
        _ => {
            return Err(malformed(
                "--level",
                "H2/H3 requires either --import-id OR (--event-id, --revision-digest, --descriptor-digest)",
                0,
            ));
        }
    };

    let capabilities = CapabilityGrantContext {
        granted_capabilities,
        allow_visual_hydration,
    };
    let extended = if level_str == "H2" {
        if allow_visual_hydration {
            return Err(malformed(
                "--allow-visual-hydration",
                "visual hydration grant is only admitted for --level H3",
                0,
            ));
        }
        for h3_only in [
            "--segment-indices",
            "--max-dimension",
            "--crop-box",
            "--max-h3-frames",
            "--max-h3-bytes",
        ] {
            if let Some((_, _, idx)) = take(values, h3_only) {
                return Err(malformed(
                    h3_only,
                    "visual H3 option is not admitted for --level H2",
                    *idx,
                ));
            }
        }
        ExtendedHydrationRequest::H2(H2HydrationRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            target,
            expected_anchor: expected_anchor.clone(),
            expected_descriptor,
            session_id: session_id.clone(),
            session_generation,
            capabilities,
            budget_tokens,
        })
    } else {
        let segment_indices = take(values, "--segment-indices")
            .map(|(_, val, idx)| parse_segment_indices(val, *idx))
            .transpose()?
            .unwrap_or_default();
        let max_dimension = take(values, "--max-dimension")
            .map(|(_, val, idx)| {
                val.parse::<u32>()
                    .ok()
                    .filter(|n| n.to_string() == *val)
                    .ok_or_else(|| malformed("--max-dimension", "expected canonical u32", *idx))
            })
            .transpose()?
            .unwrap_or(DEFAULT_H3_DIMENSION);
        let max_h3_frames = take(values, "--max-h3-frames")
            .map(|(_, val, idx)| nonnegative_usize("--max-h3-frames", val, *idx))
            .transpose()?
            .unwrap_or(MAX_H3_FRAMES);
        let max_h3_bytes = take(values, "--max-h3-bytes")
            .map(|(_, val, idx)| nonnegative_usize("--max-h3-bytes", val, *idx))
            .transpose()?
            .unwrap_or(DEFAULT_MAX_H3_BYTES);
        let crop_box = take(values, "--crop-box")
            .map(|(_, val, idx)| {
                CropBox::parse(val).map_err(|err| malformed("--crop-box", &err.to_string(), *idx))
            })
            .transpose()?;
        ExtendedHydrationRequest::H3(H3HydrationRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            target,
            segment_indices,
            limits: H3Limits {
                max_h3_frames,
                max_h3_bytes,
                max_dimension,
            },
            crop_box,
            jpeg_quality: DEFAULT_H3_JPEG_QUALITY,
            expected_anchor: expected_anchor.clone(),
            expected_descriptor,
            session_id: session_id.clone(),
            session_generation,
            capabilities,
            budget_tokens,
        })
    };

    // Placeholder H0/H1 struct (never executed when `extended` is `Some`).
    let dummy_session = match session_id {
        Some(id) => id,
        None => SessionId::parse("session:extended-placeholder")
            .map_err(|_| malformed("--session", "invalid placeholder session", 0))?,
    };
    let dummy_event = EventId::parse("event:extended-placeholder")
        .map_err(|_| malformed("--event-id", "invalid placeholder event", 0))?;
    let dummy_anchor = match expected_anchor {
        Some(anchor) => anchor,
        None => AnchorToken::parse(
            "anchor:0000000000000000:0:none:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .ok_or_else(|| malformed("--anchor", "invalid placeholder anchor", 0))?,
    };
    let request = EvidenceHydrationRequest {
        session_id: dummy_session,
        principal: principal_id,
        generation: session_generation.unwrap_or(0),
        event_id: dummy_event,
        expected_revision: ContentDigest::sha256(b"extended-placeholder"),
        expected_anchor: dummy_anchor,
        expected_descriptor,
        level: if level_str == "H2" {
            HydrationLevel::H2
        } else {
            HydrationLevel::H3
        },
        budget_tokens: budget_tokens.unwrap_or(EVENT_HYDRATION_H1_TOKENS),
        continuation: None,
    };

    Ok(EventHydrationQueryArgs {
        root,
        request,
        extended: Some(extended),
    })
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

/// Execute the native session-owned transaction (H0/H1) or capability-gated H2/H3 hydration.
#[must_use]
pub fn execute_event_hydration_query(args: &EventHydrationQueryArgs) -> (String, ExitIdentity) {
    execute_event_hydration_query_with_time(args, None)
}

pub(crate) fn execute_event_hydration_query_with_time(
    args: &EventHydrationQueryArgs,
    clock: crate::session_time::Clock<'_>,
) -> (String, ExitIdentity) {
    execute_event_hydration_query_with_control(args, clock, &crate::RequestControl::uncancelled())
}

pub(crate) fn execute_event_hydration_query_with_control(
    args: &EventHydrationQueryArgs,
    clock: crate::session_time::Clock<'_>,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if let Some(extended) = &args.extended {
        return crate::query_cmd::hydration::execute_extended(extended, control);
    }
    let started = Instant::now();
    let cancelled = || control.is_cancelled() || started.elapsed() >= Duration::from_secs(60);
    let answer = match hydrate_event_evidence(
        crate::session_time::context(&args.root, clock),
        &args.request,
        &cancelled,
    ) {
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
