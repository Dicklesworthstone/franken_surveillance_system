#![forbid(unsafe_code)]
//! Work claims (FSS-226): the work-claiming intent family of `fss investigate` (AOP-006),
//! answered as the registered `AgentResponseEnvelope` carrying `fss.agent_cognitive_envelope.v1`.
//!
//! [`fss_reference::deployment_session::claims`] owns the durable state: every command is
//! committed to the deployment's session journal through the journaled coordination engine. A
//! claim coordinates cognition only: it never confers effect authority, dispatches anything, or
//! settles an obligation.
//!
//! ```text
//! claim          --case ID --work case|hypothesis:ID|discriminator:ID|probe:ID
//!                [--lease-ms N] [--depends CLAIM[,CLAIM..]]
//! claim-inspect  --claim ID
//! claim-activate --claim ID --expected sha256:..
//! claim-progress --claim ID --expected .. --artifact sha256:..
//! claim-block    --claim ID --expected .. --artifact sha256:..
//! claim-complete --claim ID --expected .. --result sha256:..
//! claim-release  --claim ID --expected ..
//! claim-renew    --claim ID --expected .. [--lease-ms N]
//! claim-expire   --claim ID --expected ..
//! claim-transfer --claim ID --expected .. --recipient SESSION
//! claim-reclaim  --claim ID --expected .. [--lease-ms N]
//! claim-list
//! ```
//!
//! A claim answer's `decisionFingerprint` is the claim revision digest: the exact `--expected`
//! precondition of the holder's next change.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{
    AgentView, BudgetVector, CognitiveAnswerClass, ContentDigest, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
    SessionId, TimestampNs,
};
use fss_reference::agent_session::work_claims::WorkClaimRevision;
use fss_reference::deployment_session::claims::{
    CAPABILITY_WORK_CLAIM, ClaimAction, ClaimAnswer, ClaimChange, ClaimRecovery, ClaimRequest,
    ClaimWork, DEFAULT_LEASE_MS, MAX_CLAIM_DEPENDENCIES, work_claim,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    CognitiveParts, ResponseParts, build_response, cognitive_payload, collect_options, principal,
    rendered, required_root, take,
};
use crate::session_cmd::{Operation, agent_plane_boundary, idempotency_key, refuse};
use crate::token::ArgToken;

/// Capability registry row of AOP-006 (`investigate`).
const CAPABILITY_CASE_WRITE: &str = "CAP-AGENT-CASE-WRITE-001";
/// Response payload schema of every claim answer.
pub const COGNITIVE_PAYLOAD_SCHEMA: &str = "fss.agent_cognitive_envelope.v1";
const COMMAND: &str = "investigate";
const OPTIONS: &[&str] = &[
    "--root",
    "--session",
    "--principal",
    "--transition",
    "--case",
    "--work",
    "--lease-ms",
    "--depends",
    "--claim",
    "--expected",
    "--artifact",
    "--result",
    "--recipient",
];
const COMMON: &[&str] = &["--root", "--session", "--principal", "--transition"];
/// Longest admitted lease (the engine's ceiling).
const MAX_LEASE_MS: u64 = 300_000;

/// Options for one work-claim transition of `fss investigate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// The decoded request.
    pub request: ClaimRequest,
}

/// True when `tokens` select a work-claim transition (`--transition claim...`).
#[must_use]
pub fn selects_claim(tokens: &[ArgToken]) -> bool {
    let texts: Vec<&str> = tokens.iter().map(ArgToken::as_str).collect();
    texts.iter().enumerate().any(|(index, text)| {
        text.strip_prefix("--transition=")
            .or_else(|| {
                (*text == "--transition")
                    .then(|| texts.get(index + 1).copied())
                    .flatten()
            })
            .is_some_and(|value| value == "claim" || value.starts_with("claim-"))
    })
}

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some(COMMAND.to_owned()),
        index,
    }
}

fn required<'a>(
    values: &'a [(String, String, usize)],
    option: &str,
    expected: &str,
) -> Result<&'a (String, String, usize), CliError> {
    take(values, option).ok_or_else(|| CliError::MissingValue {
        option: option.to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: expected.to_owned(),
    })
}

/// Refuses every option outside `allowed` (and the common options).
fn only(
    transition: &str,
    values: &[(String, String, usize)],
    allowed: &[&str],
) -> Result<(), CliError> {
    for (option, value, index) in values {
        if !COMMON.contains(&option.as_str()) && !allowed.contains(&option.as_str()) {
            return Err(malformed(
                option,
                value,
                &format!("not an option of --transition {transition}"),
                *index,
            ));
        }
    }
    Ok(())
}

fn identity(values: &[(String, String, usize)], option: &str) -> Result<String, CliError> {
    let (_, raw, index) = required(values, option, "an identity of [A-Za-z0-9._:-]")?;
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(malformed(
            option,
            raw,
            "identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        ));
    }
    Ok(raw.clone())
}

fn digest(values: &[(String, String, usize)], option: &str) -> Result<ContentDigest, CliError> {
    let (_, raw, index) = required(values, option, "a sha256:<64 hex> digest")?;
    ContentDigest::parse(raw)
        .map_err(|_| malformed(option, raw, "expected a sha256:<64 hex> digest", *index))
}

fn lease_ms(values: &[(String, String, usize)]) -> Result<u64, CliError> {
    match take(values, "--lease-ms") {
        None => Ok(DEFAULT_LEASE_MS),
        Some((_, raw, index)) => raw
            .parse::<u64>()
            .ok()
            .filter(|lease| (1..=MAX_LEASE_MS).contains(lease))
            .ok_or_else(|| {
                malformed(
                    "--lease-ms",
                    raw,
                    "lease must be 1..=300000 milliseconds on the evidence clock",
                    *index,
                )
            }),
    }
}

fn work(values: &[(String, String, usize)]) -> Result<ClaimWork, CliError> {
    let (_, raw, index) = required(
        values,
        "--work",
        "case, hypothesis:<id>, discriminator:<id>, or probe:<id>",
    )?;
    let item = |id: &str| (!id.is_empty() && id.len() <= 256).then(|| id.to_owned());
    let parsed = match raw.split_once(':') {
        None if raw == "case" => Some(ClaimWork::Case),
        Some(("hypothesis", id)) => item(id).map(ClaimWork::Hypothesis),
        Some(("discriminator", id)) => item(id).map(ClaimWork::Discriminator),
        Some(("probe", id)) => item(id).map(ClaimWork::Probe),
        _ => None,
    };
    parsed.ok_or_else(|| {
        malformed(
            "--work",
            raw,
            "work must be case, hypothesis:<id>, discriminator:<id>, or probe:<id>",
            *index,
        )
    })
}

fn dependencies(values: &[(String, String, usize)]) -> Result<BTreeSet<String>, CliError> {
    let Some((_, raw, index)) = take(values, "--depends") else {
        return Ok(BTreeSet::new());
    };
    let items: BTreeSet<String> = raw.split(',').map(ToOwned::to_owned).collect();
    if items.len() > MAX_CLAIM_DEPENDENCIES
        || items.iter().any(|item| {
            item.is_empty()
                || item.len() > 128
                || !item.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        })
    {
        return Err(malformed(
            "--depends",
            raw,
            "expected 1..64 comma-separated claim identities",
            *index,
        ));
    }
    Ok(items)
}

/// Parses one `investigate --transition claim...` invocation.
pub fn parse_claim_args(tokens: &[ArgToken]) -> Result<ClaimArgs, CliError> {
    let values = collect_options(COMMAND, tokens, OPTIONS)?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(&values, "--session", "the session identity")?;
    let session_id = SessionId::parse(raw.clone()).map_err(|_| {
        malformed(
            "--session",
            raw,
            "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    let principal = principal(COMMAND, &values)?;
    let (_, transition, index) = required(&values, "--transition", "a claim transition")?;
    let transition = transition.as_str();
    let held = |values: &[(String, String, usize)]| -> Result<(String, ContentDigest), CliError> {
        Ok((identity(values, "--claim")?, digest(values, "--expected")?))
    };
    let change = |change: ClaimChange, values: &[(String, String, usize)]| {
        held(values).map(|(claim_id, expected)| ClaimAction::Change {
            claim_id,
            expected,
            change,
        })
    };
    let recover = |recovery: ClaimRecovery, values: &[(String, String, usize)]| {
        held(values).map(|(claim_id, expected)| ClaimAction::Recover {
            claim_id,
            expected,
            recovery,
        })
    };
    let action = match transition {
        "claim" => {
            only(
                transition,
                &values,
                &["--case", "--work", "--lease-ms", "--depends"],
            )?;
            ClaimAction::Acquire {
                case_id: identity(&values, "--case")?,
                work: work(&values)?,
                lease_ms: lease_ms(&values)?,
                dependencies: dependencies(&values)?,
            }
        }
        "claim-inspect" => {
            only(transition, &values, &["--claim"])?;
            ClaimAction::Inspect {
                claim_id: identity(&values, "--claim")?,
            }
        }
        "claim-list" => {
            only(transition, &values, &[])?;
            ClaimAction::List
        }
        "claim-activate" => {
            only(transition, &values, &["--claim", "--expected"])?;
            change(ClaimChange::Activate, &values)?
        }
        "claim-progress" => {
            only(
                transition,
                &values,
                &["--claim", "--expected", "--artifact"],
            )?;
            change(
                ClaimChange::Progress(digest(&values, "--artifact")?),
                &values,
            )?
        }
        "claim-block" => {
            only(
                transition,
                &values,
                &["--claim", "--expected", "--artifact"],
            )?;
            change(ClaimChange::Block(digest(&values, "--artifact")?), &values)?
        }
        "claim-complete" => {
            only(transition, &values, &["--claim", "--expected", "--result"])?;
            change(ClaimChange::Complete(digest(&values, "--result")?), &values)?
        }
        "claim-release" => {
            only(transition, &values, &["--claim", "--expected"])?;
            change(ClaimChange::Release, &values)?
        }
        "claim-renew" => {
            only(
                transition,
                &values,
                &["--claim", "--expected", "--lease-ms"],
            )?;
            change(
                ClaimChange::Renew {
                    lease_ms: lease_ms(&values)?,
                },
                &values,
            )?
        }
        "claim-expire" => {
            only(transition, &values, &["--claim", "--expected"])?;
            recover(ClaimRecovery::Expire, &values)?
        }
        "claim-transfer" => {
            only(
                transition,
                &values,
                &["--claim", "--expected", "--recipient"],
            )?;
            let (_, raw, index) = required(&values, "--recipient", "the recipient session")?;
            let recipient = SessionId::parse(raw.clone()).map_err(|_| {
                malformed(
                    "--recipient",
                    raw,
                    "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
                    *index,
                )
            })?;
            recover(ClaimRecovery::Transfer(recipient), &values)?
        }
        "claim-reclaim" => {
            only(
                transition,
                &values,
                &["--claim", "--expected", "--lease-ms"],
            )?;
            recover(
                ClaimRecovery::Reclaim {
                    lease_ms: lease_ms(&values)?,
                },
                &values,
            )?
        }
        other => {
            return Err(malformed(
                "--transition",
                other,
                "claim transitions are claim, claim-inspect, claim-list, claim-activate, \
                 claim-progress, claim-block, claim-complete, claim-release, claim-renew, \
                 claim-expire, claim-transfer, or claim-reclaim",
                *index,
            ));
        }
    };
    Ok(ClaimArgs {
        root,
        request: ClaimRequest {
            session_id,
            principal,
            action,
        },
    })
}

fn is_open(revision: &WorkClaimRevision) -> bool {
    matches!(
        revision.claim().state.as_str(),
        "claimed" | "active" | "blocked"
    )
}

/// One claim as an envelope proposition: its recorded state, holder, lease, and work.
pub(crate) fn claim_proposition(
    revision: &WorkClaimRevision,
    now: TimestampNs,
) -> EnvelopeProposition {
    let claim = revision.claim();
    let lease = if !is_open(revision) {
        "it holds no lease".to_owned()
    } else if revision.lease_covers(now) {
        format!(
            "its lease (incarnation {}) covers the evidence clock until {} ns",
            claim.lease_incarnation, claim.expires_at_ns
        )
    } else {
        format!(
            "its lease (incarnation {}) lapsed at {} ns: expire or reclaim it",
            claim.lease_incarnation, claim.expires_at_ns
        )
    };
    EnvelopeProposition {
        id: claim.claim_id.clone(),
        statement: format!(
            "Claim {} on case {} (work root {}) is {}, held by session {}; {}; dependencies \
             [{}]; progress {}; result {}. It coordinates cognition only and confers no effect \
             authority.",
            claim.claim_id,
            claim.case_id.as_deref().unwrap_or("none"),
            revision.work_root(),
            claim.state.as_str(),
            claim.owner_session_id,
            lease,
            claim.dependencies.join(", "),
            claim.progress_json,
            claim.result_root.as_deref().unwrap_or("none"),
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![revision.digest().to_text()],
    }
}

/// One claim revision as an H0 evidence handle (journal-owned; identity only).
pub(crate) fn claim_handle(revision: &WorkClaimRevision) -> agent_json::EvidenceHandle {
    agent_json::EvidenceHandle {
        handle_id: format!(
            "fss://claim/{}/revision/{}",
            revision.claim().claim_id,
            revision.digest()
        ),
        object_digest: revision.digest(),
        kind: "work_claim_revision".to_owned(),
        hydration: "H0",
        allowed_hydration: vec!["H0"],
        privacy_class: revision.privacy_class().to_owned(),
        availability: "available",
        estimated_cost: BudgetVector::ZERO,
        required_capability: Some(CAPABILITY_WORK_CLAIM.to_owned()),
    }
}

fn response(answer: &ClaimAnswer) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &answer.orientation;
    let capsule = orientation.capsule();
    let shown: Vec<&WorkClaimRevision> = match &answer.claim {
        Some(claim) => vec![claim],
        None => answer.claims.iter().collect(),
    };
    let mission_domain = format!(
        "fss://mission/{}/claims",
        answer.session.mission_id.as_str()
    );
    let next_actions = capsule
        .affordances
        .iter()
        .filter(|affordance| capsule.frame.next.contains(&affordance.affordance_id))
        .cloned()
        .collect();
    let decision_digest = match &answer.claim {
        Some(claim) => claim.digest(),
        None => capsule.decision_fingerprint()?,
    };
    let (payload, next_ids, next_objects) = cognitive_payload(
        orientation,
        answer.request_digest,
        COMMAND,
        AgentView::Case,
        CognitiveParts {
            answer_class: if answer.claim.is_some() {
                CognitiveAnswerClass::DirectFact
            } else {
                CognitiveAnswerClass::BoundedSummary
            },
            epistemic: EnvelopeEpistemic {
                propositions: shown
                    .iter()
                    .map(|revision| claim_proposition(revision, answer.now))
                    .collect(),
                assumptions: vec![
                    "Leases run on the deployment evidence clock: a lease lapses only as \
                     committed evidence advances that clock."
                        .to_owned(),
                ],
                invalidators: vec![
                    "The session is rebased to another anchor: its claims become stale-basis \
                     until reclaimed."
                        .to_owned(),
                ],
            },
            coverage: EnvelopeCoverage {
                authorized_domain: vec![mission_domain.clone()],
                observed_domain: vec![mission_domain],
                not_observable_domain: Vec::new(),
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles: shown
                .iter()
                .map(|revision| claim_handle(revision))
                .collect(),
            next_actions,
            decision_digest,
        },
    )?;
    let mut degradation = orientation.degradation.clone();
    if answer.head_moved {
        degradation.push(
            "The deployment head has moved past this session's anchor: claims are bound to the \
             session's anchor."
                .to_owned(),
        );
    }
    degradation.push(
        "Coordination only: a work claim never grants effect authority, dispatches anything, or \
         settles an obligation."
            .to_owned(),
    );
    let mut proof_pointers = Vec::new();
    if let Some(claim) = &answer.claim {
        proof_pointers.push(claim.digest().to_text());
        if let Some(predecessor) = claim.predecessor() {
            proof_pointers.push(predecessor.to_text());
        }
    }
    proof_pointers.push(answer.journal_root.to_text());
    proof_pointers.push(orientation.anchor_token.clone());
    let completed = match &answer.claim {
        Some(claim) => format!(
            "{} claim {} revision {} ({}) in session journal root {} at evidence time {} ns.",
            if answer.committed {
                "Committed"
            } else {
                "Read"
            },
            claim.claim().claim_id,
            claim.revision(),
            claim.claim().state.as_str(),
            answer.journal_root,
            answer.now.0
        ),
        None => format!(
            "Listed {} claim(s) of mission {} visible to session {}.",
            answer.claims.len(),
            answer.session.mission_id.as_str(),
            answer.session.session_id.as_str()
        ),
    };
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: answer.request_digest,
        principal: answer.session.principal_id.clone(),
        session_id: Some(answer.session.session_id.as_str().to_owned()),
        mission_id: Some(answer.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_CASE_WRITE,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: COGNITIVE_PAYLOAD_SCHEMA,
        payload_json: payload,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: next_ids,
        affordance_objects: next_objects,
        decision_fingerprint: decision_digest,
        compression_receipt_id: Some(
            orientation
                .publication
                .compression_receipt
                .receipt_id
                .clone(),
        ),
        continuation: orientation.publication.context_pack.continuation.clone(),
        recovery_class: "refresh_and_retry",
        safe_retry: ResponseSafeRetry::YesAfterRefresh,
        boundary: agent_plane_boundary(completed, Vec::new()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(answer.request_digest)),
    })
}

/// Executes one work-claim transition, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_claim(args: &ClaimArgs) -> (String, ExitIdentity) {
    match work_claim(&args.root, &args.request) {
        Ok(answer) => rendered(
            response(&answer),
            ExitIdentity::SUCCESS,
            COMMAND,
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: COMMAND,
                name: COMMAND,
                capability: CAPABILITY_CASE_WRITE,
                payload_schema: COGNITIVE_PAYLOAD_SCHEMA,
                view: AgentView::Case,
                root: args.root.clone(),
                principal: args.request.principal.clone(),
                request: [
                    args.request.session_id.as_str().as_bytes(),
                    b"\0claim\0",
                    format!("{:?}", args.request.action).as_bytes(),
                ]
                .concat(),
            },
            error,
        ),
    }
}
