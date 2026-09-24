#![forbid(unsafe_code)]
//! `fss follow` (AOP-004 `session.follow`): the meaningful decision-impact delta between the
//! situation at an earlier committed anchor and the situation at the head of a deployment root,
//! answered as the registered `AgentResponseEnvelope` carrying one exact page of an
//! `fss.agent_meaningful_delta.v1`.
//!
//! The command opens no file for writing. [`fss_reference::agent_follow`] resolves the `--since`
//! anchor token against the root's committed history, compiles the situation as of that anchor
//! from the committed prefix alone and the situation at the head, classifies them with the
//! reference meaningful-delta engine, and pages the delta through an exact continuation stream;
//! this module only decodes arguments and renders the typed values. A page carries the delta's
//! complete class set and the items of that page; the rest continue through the envelope's
//! `continuation`, never truncated or coalesced.

use std::path::PathBuf;

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, Completeness, ContentDigest, ContinuationError,
    KnowledgeState, LedgerAnchor, MeaningfulDeltaClass, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, TimestampNs,
};
use fss_reference::agent_follow::{
    AnchorRefusal, AnchorToken, DEFAULT_FOLLOW_MAX_ENTRIES, DeploymentFollow, FollowError,
    FollowItem, FollowRequest, MAX_FOLLOW_ENTRIES, follow_deployment,
};
use fss_reference::agent_orient::{
    CAPABILITY_SITUATION_READ, DeploymentHistory, OrientError, OrientLimits,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_response, collect_options,
    contexts, internal_failure, principal, read_only_boundary, read_refusal, rendered,
    request_identity, required_root, take,
};
use crate::token::ArgToken;

/// Registered error identity: the `--since` anchor names another deployment.
pub const ERR_AGENT_FOLLOW_ANCHOR_FOREIGN: &str = "ERR-AGENT-FOLLOW-ANCHOR-FOREIGN-001";
/// Registered error identity: the `--since` anchor lies past the committed head.
pub const ERR_AGENT_FOLLOW_ANCHOR_AHEAD: &str = "ERR-AGENT-FOLLOW-ANCHOR-AHEAD-001";
/// Registered error identity: the `--since` anchor is not in this deployment's committed history.
pub const ERR_AGENT_FOLLOW_ANCHOR_UNKNOWN: &str = "ERR-AGENT-FOLLOW-ANCHOR-UNKNOWN-001";
/// Registered error identity: the continuation is not a cursor of this exact follow stream.
pub const ERR_AGENT_FOLLOW_CONTINUATION: &str = "ERR-AGENT-FOLLOW-CONTINUATION-001";
/// Payload schema of every follow answer.
pub const FOLLOW_PAYLOAD_SCHEMA: &str = "fss.agent_meaningful_delta.v1";
/// Views a follow may be requested in.
pub const FOLLOW_VIEWS: [&str; 2] = ["pulse", "brief"];

/// Options for the `follow` command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowArgs {
    /// Existing deployment root, read-only.
    pub root: PathBuf,
    /// Anchor token an earlier orientation (or follow) emitted.
    pub since: AnchorToken,
    /// Registered view both situations are compiled in (default `pulse`, AOP-004's view).
    pub view: AgentView,
    /// Requesting principal label.
    pub principal: PrincipalId,
    /// Delta items delivered per page.
    pub max_entries: u32,
    /// Exact continuation token of the page to deliver.
    pub continuation: Option<String>,
}

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some("follow".to_owned()),
        index,
    }
}

/// Whether `value` is spelled as a continuation token (`continuation:` then `[a-z0-9:+._-]`).
fn continuation_spelling(value: &str) -> bool {
    value.len() <= 256
        && value.strip_prefix("continuation:").is_some_and(|rest| {
            !rest.is_empty()
                && rest.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b':' | b'+' | b'.' | b'_' | b'-')
                })
        })
}

/// Parses `follow --json --root <dir> --since <anchor> [--view pulse|brief] [--principal <id>]
/// [--max-entries <n>] [--continuation <token>]`.
pub fn parse_follow_args(tokens: &[ArgToken]) -> Result<FollowArgs, CliError> {
    let values = collect_options(
        "follow",
        tokens,
        &[
            "--root",
            "--since",
            "--view",
            "--principal",
            "--max-entries",
            "--continuation",
        ],
    )?;
    let root = required_root("follow", &values)?;
    let (_, raw, index) = take(&values, "--since").ok_or_else(|| CliError::MissingValue {
        option: "--since".to_owned(),
        command: Some("follow".to_owned()),
        expected: "the anchor token an orientation emitted for `--since`".to_owned(),
    })?;
    let since = AnchorToken::parse(raw).ok_or_else(|| {
        malformed(
            "--since",
            raw,
            "anchor token must be `anchor:<site>:<commit>:<e<records>|none>:<binding>` exactly as \
             `fss orient` emits it",
            *index,
        )
    })?;
    let view = match take(&values, "--view") {
        None => AgentView::Pulse,
        Some((_, value, index)) => {
            if !FOLLOW_VIEWS.contains(&value.as_str()) {
                return Err(malformed(
                    "--view",
                    value,
                    "view must be one of pulse, brief",
                    *index,
                ));
            }
            AgentView::from_name(value)
                .map_err(|_| malformed("--view", value, "view is not registered", *index))?
        }
    };
    let max_entries = match take(&values, "--max-entries") {
        None => DEFAULT_FOLLOW_MAX_ENTRIES,
        Some((_, value, index)) => match value.parse::<u32>() {
            Ok(entries) if (1..=MAX_FOLLOW_ENTRIES).contains(&entries) => entries,
            _ => {
                return Err(malformed(
                    "--max-entries",
                    value,
                    &format!("page size must be an integer in 1..={MAX_FOLLOW_ENTRIES}"),
                    *index,
                ));
            }
        },
    };
    let continuation = match take(&values, "--continuation") {
        None => None,
        Some((_, value, index)) => {
            if !continuation_spelling(value) {
                return Err(malformed(
                    "--continuation",
                    value,
                    "continuation must be the exact `continuation:...` token a follow page \
                     returned",
                    *index,
                ));
            }
            Some(value.clone())
        }
    };
    Ok(FollowArgs {
        root,
        since,
        view,
        principal: principal("follow", &values)?,
        max_entries,
        continuation,
    })
}

fn request_digest(args: &FollowArgs, head: &LedgerAnchor) -> ContentDigest {
    request_identity("fss.cli.follow.request.v1", |encoder| {
        encoder.text(args.since.as_str());
        encoder.text(args.view.id());
        args.principal.encode_canonical(encoder);
        encoder.u64(u64::from(args.max_entries));
        match &args.continuation {
            Some(token) => {
                encoder.bool(true);
                encoder.text(token);
            }
            None => encoder.bool(false),
        }
        head.encode_canonical(encoder);
    })
}

fn classes_text(follow: &DeploymentFollow, protected_only: bool) -> Vec<&'static str> {
    follow
        .delta
        .classes
        .iter()
        .filter(|class| !protected_only || class.is_non_coalescible())
        .map(|class| class.as_str())
        .collect()
}

/// The page payload: the delta's header and complete class set with the items of this page.
fn page_payload(follow: &DeploymentFollow) -> String {
    let delta = &follow.delta;
    let (cell_context, _) = contexts(&follow.result);
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut invalidated = Vec::new();
    let mut coverage = Vec::new();
    let mut obligations = Vec::new();
    let mut effects = Vec::new();
    for item in &follow.page_items {
        match item {
            FollowItem::ChangedCell(cell) => {
                changed.push(agent_json::knowledge_cell(cell, &cell_context));
            }
            FollowItem::RemovedClaim(text) => removed.push(text.as_str()),
            FollowItem::InvalidatedAssumption(text) => invalidated.push(text.as_str()),
            FollowItem::Coverage(text) => coverage.push(text.as_str()),
            FollowItem::Obligation(text) => obligations.push(text.as_str()),
            FollowItem::EffectUncertainty(text) => effects.push(text.as_str()),
        }
    }
    let continuation = follow
        .page
        .next_cursor
        .as_ref()
        .map_or(delta.continuation.as_str(), |cursor| cursor.token());
    let silence = delta.silence_certificate.as_ref().map_or_else(
        || "null".to_owned(),
        |certificate| {
            agent_json::object(&[
                (
                    "basisFrameDigest",
                    agent_json::string(&certificate.basis_frame_digest.to_text()),
                ),
                (
                    "resultFrameDigest",
                    agent_json::string(&certificate.result_frame_digest.to_text()),
                ),
                (
                    "selectionWitness",
                    agent_json::string(&certificate.selection_witness.to_text()),
                ),
                (
                    "authorizedDomain",
                    agent_json::strings(&certificate.authorized_domain),
                ),
                (
                    "authorizedGeneration",
                    agent_json::string(&certificate.authorized_generation),
                ),
                ("reason", agent_json::string(&certificate.reason)),
                (
                    "certificateDigest",
                    agent_json::string(&certificate.certificate_digest().to_text()),
                ),
            ])
        },
    );
    agent_json::object(&[
        ("schema", agent_json::string(FOLLOW_PAYLOAD_SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&delta.contract_basis),
        ),
        ("deltaId", agent_json::string(&delta.delta_id)),
        ("sessionId", agent_json::string(delta.session_id.as_str())),
        ("basisFrameId", agent_json::string(&delta.basis_frame_id)),
        ("resultFrameId", agent_json::string(&delta.result_frame_id)),
        (
            "basisAnchor",
            agent_json::evidence_anchor(&delta.basis_anchor),
        ),
        (
            "resultAnchor",
            agent_json::evidence_anchor(&delta.result_anchor),
        ),
        ("classes", agent_json::strings(classes_text(follow, false))),
        ("changedCells", agent_json::array(&changed)),
        ("removedClaimIds", agent_json::strings(removed)),
        ("invalidatedAssumptions", agent_json::strings(invalidated)),
        ("coverageChanges", agent_json::strings(coverage)),
        ("obligationChanges", agent_json::strings(obligations)),
        ("effectUncertaintyChanges", agent_json::strings(effects)),
        // Pagination is not coalescing or omission: every item of the delta is delivered, on this
        // page or through the continuation.
        ("coalescedCount", delta.coalesced_count.to_string()),
        ("omittedCount", delta.omitted_count.to_string()),
        (
            "omissionReasons",
            agent_json::strings(&delta.omission_reasons),
        ),
        ("priority", agent_json::string(delta.priority.as_str())),
        ("continuation", agent_json::string(continuation)),
        (
            "selectionWitness",
            agent_json::string(&delta.selection_witness.to_text()),
        ),
        ("silenceCertificate", silence),
    ])
}

fn follow_response(
    follow: &DeploymentFollow,
    request_digest: ContentDigest,
) -> Result<String, Box<dyn std::error::Error>> {
    let result = &follow.result;
    let capsule = result.capsule();
    let delta = &follow.delta;
    let total = follow.items.len() as u64;
    let start = follow.page_start();
    let delivered = follow.page_items.len() as u64;
    let end = start + delivered;

    let mut warnings = result.warnings.clone();
    let protected = classes_text(follow, true);
    if !protected.is_empty() {
        warnings.push(format!(
            "Protected classes [{}] are never coalesced: every page carries the delta's complete \
             class set, and protected items are delivered first.",
            protected.join(", ")
        ));
    }
    let mut degradation = result.degradation.clone();
    degradation.push(match &follow.page.next_cursor {
        Some(_) => format!(
            "This page carries delta items {start}..{end} of {total}; the remaining {} continue \
             through the envelope continuation (the same --since, --view, and --max-entries).",
            total - end
        ),
        None if start == 0 => format!("All {total} delta item(s) are on this page."),
        None => format!("This last page carries delta items {start}..{end} of {total}."),
    });
    if delta.silence_certificate.is_none()
        && delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss)
    {
        degradation.push(format!(
            "No silence certificate: silence is certified only over complete coverage, and the \
             head situation is {} with no retained CoverageWitness, so the persisting gap is \
             reported as protected coverage_loss.",
            completeness_text(capsule.completeness)
        ));
    }
    let mut proof_pointers = Vec::new();
    for pointer in [
        follow.basis.publication.publication_digest.to_text(),
        result.publication.publication_digest.to_text(),
        delta.selection_witness.to_text(),
        follow.stream.source_digest.to_text(),
        follow.cursor.cursor_digest.to_text(),
        follow.page.page_digest.to_text(),
        follow.basis.anchor_token.clone(),
        result.anchor_token.clone(),
    ] {
        if !proof_pointers.contains(&pointer) {
            proof_pointers.push(pointer);
        }
    }
    let (_, affordance_context) = contexts(result);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let consumed = follow
        .basis
        .consumed
        .checked_add(&result.consumed)
        .map_err(|_| RenderError("consumed budget overflows"))?;
    let continuation = follow
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    build_response(ResponseParts {
        operation: "session.follow",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: result.view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: FOLLOW_PAYLOAD_SCHEMA,
        payload_json: page_payload(follow),
        epistemic_state: result.epistemic_state,
        completeness: capsule.completeness,
        warnings,
        contradictions: result.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&result.requested, &consumed),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: delta.selection_witness,
        compression_receipt_id: None,
        recovery_class: if continuation.is_some() {
            "resume_from_continuation"
        } else {
            "safe_read_retry"
        },
        continuation,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary(format!(
            "Compared the {} situation as of commit {} with the head at commit {}; delivered {} \
             of {} delta item(s).",
            result.view.name(),
            delta.basis_anchor.commit_sequence,
            delta.result_anchor.commit_sequence,
            delivered,
            total
        )),
        created_at_ns: capsule.created_at.0,
    })
}

const fn completeness_text(value: Completeness) -> &'static str {
    match value {
        Completeness::Complete => "complete",
        Completeness::Bounded => "bounded",
        Completeness::Partial => "partial",
        Completeness::Unknown => "unknown",
        Completeness::NotObservable => "not_observable",
        Completeness::Unauthorized => "unauthorized",
        Completeness::Stale => "stale",
    }
}

/// One typed follow refusal: what was refused and how to recover.
struct Refusal {
    error_id: &'static str,
    reason: String,
    guidance: &'static str,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
}

fn refusal_response(
    args: &FollowArgs,
    head: &LedgerAnchor,
    created_at: TimestampNs,
    request_digest: ContentDigest,
    refusal: Refusal,
) -> Result<String, Box<dyn std::error::Error>> {
    build_response(ResponseParts {
        operation: "session.follow",
        request_digest,
        principal: args.principal.clone(),
        session_id: None,
        mission_id: None,
        anchor: head.clone(),
        view: args.view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Refused,
        error_id: Some(refusal.error_id),
        payload_schema: FOLLOW_PAYLOAD_SCHEMA,
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: vec![refusal.reason, refusal.guidance.to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers: vec![head.state_root.to_text()],
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: request_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: refusal.recovery_class,
        safe_retry: refusal.safe_retry,
        boundary: read_only_boundary(format!(
            "Read the deployment at commit {}; no delta was compared.",
            head.commit_sequence
        )),
        created_at_ns: created_at.0,
    })
}

fn anchor_refusal(refusal: AnchorRefusal, since: &AnchorToken) -> Refusal {
    let position = since.position();
    let (error_id, reason) = match refusal {
        AnchorRefusal::Foreign => (
            ERR_AGENT_FOLLOW_ANCHOR_FOREIGN,
            "The --since anchor names another deployment's site lineage.".to_owned(),
        ),
        AnchorRefusal::Ahead => (
            ERR_AGENT_FOLLOW_ANCHOR_AHEAD,
            format!(
                "The --since anchor (commit {}) lies past this deployment's committed head.",
                position.commit_sequence
            ),
        ),
        AnchorRefusal::Unknown => (
            ERR_AGENT_FOLLOW_ANCHOR_UNKNOWN,
            format!(
                "The --since anchor's binding does not match this deployment's committed history \
                 at commit {}.",
                position.commit_sequence
            ),
        ),
    };
    Refusal {
        error_id,
        reason,
        guidance: "Orient this root (`fss orient --json --root <dir>`) and follow from the anchor \
                   token it emits.",
        recovery_class: "rebase_required",
        safe_retry: ResponseSafeRetry::YesAfterRefresh,
    }
}

/// Executes `follow`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_follow(args: &FollowArgs) -> (String, ExitIdentity) {
    let limits = OrientLimits::default();
    let history = match DeploymentHistory::read(&args.root, &limits) {
        Ok(history) => history,
        Err(error) => return read_refusal("follow", &args.root, &error),
    };
    let request = FollowRequest {
        view: args.view,
        principal: args.principal.clone(),
        max_entries: args.max_entries,
        continuation: args.continuation.clone(),
    };
    let outcome = follow_deployment(&history, &args.since, &request);
    let refusal = match outcome {
        Ok(follow) => {
            let digest = request_digest(args, &follow.result.capsule().anchor);
            return rendered(
                follow_response(&follow, digest),
                ExitIdentity::SUCCESS,
                "follow",
                &args.root,
            );
        }
        Err(FollowError::Anchor(refusal)) => anchor_refusal(refusal, &args.since),
        Err(FollowError::Continuation(ContinuationError::WrongStream))
            if args.continuation.is_some() =>
        {
            Refusal {
                error_id: ERR_AGENT_FOLLOW_CONTINUATION,
                reason: "The continuation is not a cursor of this exact follow stream: it was \
                         altered, issued for another --since, --view, or --max-entries, or issued \
                         before the head advanced."
                    .to_owned(),
                guidance: "Follow again without --continuation to receive the first page of the \
                           current delta.",
                recovery_class: "rebase_required",
                safe_retry: ResponseSafeRetry::YesAfterRefresh,
            }
        }
        Err(FollowError::Orient(
            error @ (OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. }),
        )) => Refusal {
            error_id: ERR_AGENT_CONTEXT_INCOMPLETE,
            reason: error.to_string(),
            guidance: "Critical context is never truncated; follow with --view brief.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        Err(_) => return internal_failure("follow", &args.root),
    };
    let head = match history.snapshot_at(history.head()) {
        Ok(head) => head,
        Err(_) => return internal_failure("follow", &args.root),
    };
    let digest = request_digest(args, &head.anchor);
    rendered(
        refusal_response(
            args,
            &head.anchor,
            head.latest_evidence_time,
            digest,
            refusal,
        ),
        ExitIdentity::AGENT_REFUSED,
        "follow",
        &args.root,
    )
}
