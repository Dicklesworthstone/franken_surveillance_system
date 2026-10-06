#![forbid(unsafe_code)]
//! Immutable execution episodes of terminal agent plans (AGT-LAYER-009 `outcome_and_episode`,
//! FSS-230; the `close` intent family of AOP-007 `plan`).
//!
//! **Cognition plane.** An episode records what one plan predicted, what executed, what was
//! observed, what it consumed, and what stayed uncertain, once the plan's effect operation is
//! terminal in the head's effect journal. It is compiled deterministically from the published
//! plan, the journal's terminal receipt and obligation, the event at the head, and the session
//! principal's published feedback about the plan, its operation, or its event. Recording it never
//! changes evidence, authority, policy, thresholds, or effect state.
//!
//! **Immutability.** There is exactly one episode per plan: its identity is derived from the plan
//! identity alone. The first close publishes it root-last under `<root>/agent/publications/`
//! (the canonical `fss.agent_execution_episode.v1` encoding as the only child); every later close
//! returns the published episode unchanged, so original predictions are never rewritten after the
//! outcome. A terminal plan stays in the session's active plans until its episode exists.
//!
//! **Honesty.** Whether the alert was warranted (real activity rather than an artifact world of
//! the plan's WorldEnvelope) is never observed by an effect outcome: it stays an unobserved
//! prediction and an indeterminate predicate. Attribution confidences are a uniform prior over
//! the listed hypotheses (no attribution model is calibrated), and agent tokens, compute, and
//! operator attention are reported as unmetered rather than as zero.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{
    AgentFeedbackProposal, AgentSession, AttributionCauseClass, AttributionHypothesis,
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, EpisodeOutcome, EpisodeOutcomeState, EpisodePrediction, ExecutionEpisode,
    FeedbackProposalKind, LedgerAnchor, MissionId, PrincipalId, SessionId, TimestampNs,
};
use fss_publication::SlotName;

use crate::agent_follow::{AnchorToken, resolve_anchor};
use crate::agent_orient::{CAPABILITY_PLAN_PREPARE, DeploymentSnapshot};

use super::feedback::{FeedbackTarget, target_json};
use super::plan::{PlanRecord, read_control_plan};
use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, MAX_RECORD_BYTES,
    MAX_RECORD_ITEMS, ObligationFacts, OperationFacts, OrientLimits, SessionJournal, digest_of,
    evidence_now, hex, operation_facts, orient_bound, publish_record, read_published,
};

const EPISODE_RECORD_DOMAIN: &str = "fss.reference_agent_episode.v1";
const EPISODE_IDENTITY_DOMAIN: &str = "fss.reference_agent_episode_identity.v1";
const EPISODE_REQUEST_DOMAIN: &str = "fss.reference_agent_episode_request.v1";
/// Most feedback proposals one episode cites as attribution hypotheses; the rest are counted.
pub const MAX_EPISODE_FEEDBACK: usize = 64;
const MAX_TEXT_BYTES: usize = 4096;
const OPERATOR_NOT_DELIVERED: &str = "operator_reconciled_not_delivered:";

/// One published episode and the plan identities it closes.
#[derive(Clone, Debug, PartialEq)]
pub struct EpisodeRecord {
    /// The plan this episode closes.
    pub plan_id: String,
    /// The plan's mission.
    pub mission_id: MissionId,
    /// The plan's principal.
    pub principal: PrincipalId,
    /// The plan's effect operation.
    pub operation_id: String,
    /// Terminal effect state the episode was compiled from.
    pub terminal_state: TerminalOutcome,
    /// The schema-faithful episode.
    pub episode: ExecutionEpisode,
    /// Close time on the deployment evidence clock.
    pub recorded_at: TimestampNs,
}

/// The terminal effect state an episode closes over. Cognition reads effect state only through
/// the session boundary's [`super::OperationFacts`] projection, as registered spellings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    /// The effect was verified.
    Verified,
    /// The effect failed.
    Failed,
    /// The effect was cancelled before dispatch.
    Cancelled,
}

impl TerminalOutcome {
    /// Registered effect-state spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

const TERMINAL_STATES: [TerminalOutcome; 3] = [
    TerminalOutcome::Verified,
    TerminalOutcome::Failed,
    TerminalOutcome::Cancelled,
];

const OUTCOME_STATES: [EpisodeOutcomeState; 5] = [
    EpisodeOutcomeState::Succeeded,
    EpisodeOutcomeState::PartiallySucceeded,
    EpisodeOutcomeState::Failed,
    EpisodeOutcomeState::Cancelled,
    EpisodeOutcomeState::Indeterminate,
];

const CAUSE_CLASSES: [AttributionCauseClass; 13] = [
    AttributionCauseClass::Evidence,
    AttributionCauseClass::Hypothesis,
    AttributionCauseClass::ContextSelection,
    AttributionCauseClass::Model,
    AttributionCauseClass::Calibration,
    AttributionCauseClass::Adapter,
    AttributionCauseClass::Policy,
    AttributionCauseClass::Execution,
    AttributionCauseClass::External,
    AttributionCauseClass::Budget,
    AttributionCauseClass::Authority,
    AttributionCauseClass::Memory,
    AttributionCauseClass::Unobservability,
];

fn spelled<T: Copy>(values: &[T], spelling: impl Fn(T) -> &'static str, text: &str) -> Option<T> {
    values
        .iter()
        .copied()
        .find(|value| spelling(*value) == text)
}

fn count(decoder: &mut CanonicalDecoder<'_>) -> Result<usize, ContractError> {
    let count = decoder.u32()? as usize;
    if count > MAX_RECORD_ITEMS {
        return Err(ContractError::CountBoundExceeded);
    }
    Ok(count)
}

fn texts(decoder: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, ContractError> {
    let count = count(decoder)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decoder.text()?.to_owned());
    }
    Ok(out)
}

/// Decodes the canonical [`ExecutionEpisode`] encoding (its `CanonicalEncode` field order).
fn decode_episode(decoder: &mut CanonicalDecoder<'_>) -> Result<ExecutionEpisode, ContractError> {
    if decoder.text()? != ExecutionEpisode::SCHEMA {
        return Err(ContractError::DigestMismatch);
    }
    let episode_id = decoder.text()?.to_owned();
    let session_id = SessionId::decode_canonical(decoder)?;
    let objective_id = decoder.text()?.to_owned();
    let initial_anchor = LedgerAnchor::decode_canonical(decoder)?;
    let terminal_anchor = LedgerAnchor::decode_canonical(decoder)?;
    let plan_digest = decoder.text()?.to_owned();
    let predictions_len = count(decoder)?;
    let mut predictions = Vec::with_capacity(predictions_len);
    for _ in 0..predictions_len {
        let prediction_id = decoder.text()?.to_owned();
        let statement = decoder.text()?.to_owned();
        let expected_state = decoder.text()?.to_owned();
        let observed_state = if decoder.bool()? {
            Some(decoder.text()?.to_owned())
        } else {
            None
        };
        let error = if decoder.bool()? {
            Some(
                decoder
                    .text()?
                    .parse::<f64>()
                    .map_err(|_| ContractError::DigestMismatch)?,
            )
        } else {
            None
        };
        predictions.push(EpisodePrediction {
            prediction_id,
            statement,
            expected_state,
            observed_state,
            error,
        });
    }
    let step_receipts = texts(decoder)?;
    let effect_receipts = texts(decoder)?;
    let obligations = texts(decoder)?;
    let state = spelled(
        &OUTCOME_STATES,
        EpisodeOutcomeState::as_str,
        decoder.text()?,
    )
    .ok_or(ContractError::DigestMismatch)?;
    let outcome = EpisodeOutcome {
        state,
        success_predicates: texts(decoder)?,
        failed_predicates: texts(decoder)?,
        indeterminate_predicates: texts(decoder)?,
    };
    let resource_use_json = decoder.text()?.to_owned();
    let attributions_len = count(decoder)?;
    let mut attribution_hypotheses = Vec::with_capacity(attributions_len);
    for _ in 0..attributions_len {
        let cause_class = spelled(
            &CAUSE_CLASSES,
            AttributionCauseClass::as_str,
            decoder.text()?,
        )
        .ok_or(ContractError::DigestMismatch)?;
        attribution_hypotheses.push(AttributionHypothesis {
            cause_class,
            statement: decoder.text()?.to_owned(),
            supporting_evidence: texts(decoder)?,
            contradicting_evidence: texts(decoder)?,
            confidence_numerator: decoder.u32()?,
        });
    }
    let residual_uncertainty = texts(decoder)?;
    let decision_digest = decoder.text()?.to_owned();
    ExecutionEpisode::new(
        episode_id,
        session_id,
        objective_id,
        initial_anchor,
        terminal_anchor,
        plan_digest,
        predictions,
        step_receipts,
        effect_receipts,
        obligations,
        outcome,
        resource_use_json,
        attribution_hypotheses,
        residual_uncertainty,
        decision_digest,
    )
}

impl EpisodeRecord {
    /// The episode identity of `plan_id` (one episode per plan).
    #[must_use]
    pub fn identity(plan_id: &str) -> String {
        let digest = digest_of(EPISODE_IDENTITY_DOMAIN, |encoder| encoder.text(plan_id));
        format!(
            "episode:{}",
            hex(digest).chars().take(32).collect::<String>()
        )
    }

    /// Canonical record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(EPISODE_RECORD_DOMAIN);
        encoder.text(&self.plan_id);
        self.mission_id.encode_canonical(&mut encoder);
        self.principal.encode_canonical(&mut encoder);
        encoder.text(&self.operation_id);
        encoder.text(self.terminal_state.as_str());
        self.episode.encode_canonical(&mut encoder);
        encoder.i128(self.recorded_at.0);
        encoder.finish()
    }

    /// Decodes exactly canonical record bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != EPISODE_RECORD_DOMAIN {
            return Err(ContractError::DigestMismatch);
        }
        let plan_id = decoder.text()?.to_owned();
        let mission_id = MissionId::parse(decoder.text()?)?;
        let principal = PrincipalId::parse(decoder.text()?)?;
        let operation_id = decoder.text()?.to_owned();
        let terminal_state = spelled(&TERMINAL_STATES, TerminalOutcome::as_str, decoder.text()?)
            .ok_or(ContractError::DigestMismatch)?;
        let episode = decode_episode(&mut decoder)?;
        let record = Self {
            plan_id,
            mission_id,
            principal,
            operation_id,
            terminal_state,
            episode,
            recorded_at: TimestampNs(decoder.i128()?),
        };
        decoder.ensure_finished()?;
        if record.to_bytes() != bytes
            || record.episode.episode_id != Self::identity(&record.plan_id)
        {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }

    fn slot(episode_id: &str) -> Result<SlotName, DeploymentSessionError> {
        SlotName::parse(&format!(
            "episode-{}",
            hex(ContentDigest::sha256(episode_id.as_bytes()))
        ))
        .map_err(|_| DeploymentSessionError::Internal("episode slot name".to_owned()))
    }
}

/// One published episode as read back from its root.
#[derive(Clone, Debug, PartialEq)]
pub struct PublishedEpisode {
    /// The verified record.
    pub record: EpisodeRecord,
    /// Root of its publication.
    pub root: ContentDigest,
    /// Digest of its `fss.agent_execution_episode.v1` rendering, the root's only other child
    /// (hydrated from the agent publication store).
    pub rendering: ContentDigest,
}

fn read_episode_at(
    root: &Path,
    slot: &SlotName,
) -> Result<Option<PublishedEpisode>, DeploymentSessionError> {
    let published = read_published(root, slot).map_err(|error| match error {
        DeploymentSessionError::HandoffInvalid(reason) => {
            DeploymentSessionError::PlanInvalid(reason)
        }
        other => other,
    })?;
    let Some(published) = published else {
        return Ok(None);
    };
    let record = EpisodeRecord::from_bytes(&published.record).map_err(|error| {
        DeploymentSessionError::PlanInvalid(format!("the episode record does not verify: {error}"))
    })?;
    let rendering = match published.children.as_slice() {
        [rendering] => *rendering,
        _ => {
            return Err(DeploymentSessionError::PlanInvalid(
                "the episode root does not carry exactly one rendering".to_owned(),
            ));
        }
    };
    Ok(Some(PublishedEpisode {
        record,
        root: published.root,
        rendering,
    }))
}

/// Plans of `mission_id` by `principal` that already have a published episode.
pub(super) fn closed_plans(
    root: &Path,
    mission_id: &MissionId,
    principal: &PrincipalId,
) -> Result<BTreeSet<String>, DeploymentSessionError> {
    let mut closed = BTreeSet::new();
    for published in super::published_records(root, "episode-")? {
        let record = EpisodeRecord::from_bytes(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!(
                "an episode record does not verify: {error}"
            ))
        })?;
        if record.mission_id == *mission_id && record.principal == *principal {
            closed.insert(record.plan_id);
        }
    }
    Ok(closed)
}

/// Reads the published episode of `plan_id`, if the plan has been closed.
pub fn read_episode(
    root: &Path,
    plan_id: &str,
) -> Result<Option<PublishedEpisode>, DeploymentSessionError> {
    let slot = EpisodeRecord::slot(&EpisodeRecord::identity(plan_id))?;
    let found = read_episode_at(root, &slot)?;
    if found
        .as_ref()
        .is_some_and(|published| published.record.plan_id != plan_id)
    {
        return Err(DeploymentSessionError::PlanInvalid(
            "the published episode names another plan".to_owned(),
        ));
    }
    Ok(found)
}

/// Truncates `text` to at most [`MAX_TEXT_BYTES`] on a character boundary.
fn bounded(mut text: String) -> String {
    if text.len() > MAX_TEXT_BYTES {
        let mut end = MAX_TEXT_BYTES - 3;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

fn feedback_cause(kind: FeedbackProposalKind) -> AttributionCauseClass {
    match kind {
        FeedbackProposalKind::Correction
        | FeedbackProposalKind::Adjudication
        | FeedbackProposalKind::HardNegativeCandidate => AttributionCauseClass::Hypothesis,
        FeedbackProposalKind::AdapterQuirk => AttributionCauseClass::Adapter,
        FeedbackProposalKind::MissingEvidence => AttributionCauseClass::Unobservability,
        FeedbackProposalKind::BadAffordance | FeedbackProposalKind::BadSummary => {
            AttributionCauseClass::ContextSelection
        }
        FeedbackProposalKind::PolicyCandidate => AttributionCauseClass::Policy,
        FeedbackProposalKind::ModelCandidate => AttributionCauseClass::Model,
        FeedbackProposalKind::Helpful
        | FeedbackProposalKind::Harmful
        | FeedbackProposalKind::RunbookCandidate => AttributionCauseClass::Execution,
    }
}

/// Everything one episode is compiled from.
struct EpisodeInputs<'a> {
    plan: &'a PlanRecord,
    plan_record_digest: ContentDigest,
    initial_anchor: LedgerAnchor,
    head: &'a DeploymentSnapshot,
    terminal: TerminalOutcome,
    facts: &'a OperationFacts,
    obligation: &'a ObligationFacts,
    feedback: &'a [AgentFeedbackProposal],
    omitted_feedback: usize,
}

/// Compiles the episode deterministically from its inputs.
fn compile(inputs: &EpisodeInputs<'_>) -> Result<ExecutionEpisode, ContractError> {
    let plan = inputs.plan;
    let facts = inputs.facts;
    let state = inputs.terminal;
    let dispatched = facts.dispatched;
    let current_revision = inputs
        .head
        .events
        .iter()
        .find(|retained| retained.event.event_id.as_str() == plan.event_id)
        .map(|retained| retained.revision_digest);
    let revision_current = current_revision == Some(plan.event_revision);
    let operator_not_delivered = facts
        .error_code
        .as_deref()
        .is_some_and(|code| code.starts_with(OPERATOR_NOT_DELIVERED));
    let reconciled = state == TerminalOutcome::Verified || operator_not_delivered;
    let loss = |hit: bool| Some(if hit { 0.0 } else { 1.0 });

    let predictions = vec![
        EpisodePrediction {
            prediction_id: "prediction:delivery".to_owned(),
            statement: format!(
                "The alert about event {} (revision {}) reaches its owner over relay {}{}.",
                plan.event_id, plan.event_revision, plan.route.relay, plan.route.path
            ),
            expected_state: TerminalOutcome::Verified.as_str().to_owned(),
            observed_state: Some(state.as_str().to_owned()),
            // A plan withdrawn before dispatch never tested its delivery prediction.
            error: if state == TerminalOutcome::Cancelled {
                None
            } else {
                loss(state == TerminalOutcome::Verified)
            },
        },
        EpisodePrediction {
            prediction_id: "prediction:event-revision".to_owned(),
            statement: format!(
                "Event {} stays at revision {} through the outcome (a newer revision invalidates \
                 the plan).",
                plan.event_id, plan.event_revision
            ),
            expected_state: plan.event_revision.to_text(),
            observed_state: Some(
                current_revision.map_or_else(|| "absent".to_owned(), |digest| digest.to_text()),
            ),
            error: loss(revision_current),
        },
        EpisodePrediction {
            prediction_id: "prediction:warranted".to_owned(),
            statement: format!(
                "Event {} reflects real activity: the commit step serves the activity worlds of \
                 control plan {} and is a false alarm in its artifact worlds.",
                plan.event_id, plan.control_plan_digest
            ),
            expected_state: "activity".to_owned(),
            observed_state: None,
            error: None,
        },
    ];

    let step = |id: &str, status: &str| format!("step:{id}={status}");
    let step_receipts = vec![
        step("observe-event", "completed"),
        step("decide-policy", "completed"),
        step("prepare", "completed"),
        step(
            "commit",
            if dispatched {
                "completed"
            } else {
                "not_started"
            },
        ),
        step(
            "record",
            if dispatched {
                "completed"
            } else {
                "not_started"
            },
        ),
        step(
            "reconcile",
            if reconciled {
                "completed"
            } else if dispatched {
                "not_required"
            } else {
                "not_started"
            },
        ),
    ];

    let mut effect_receipts = vec![format!(
        "operation-receipt:{}",
        facts.receipt_digest.to_text()
    )];
    if let Some(result) = facts.result_digest {
        effect_receipts.push(format!("result:{}", result.to_text()));
    }
    if let Some(proof) = inputs.obligation.proof_digest {
        effect_receipts.push(format!("obligation-proof:{}", proof.to_text()));
    }
    let obligations = vec![format!(
        "{}={}",
        inputs.obligation.obligation_id, inputs.obligation.state
    )];

    let mut success = Vec::new();
    let mut failed = Vec::new();
    let outcome_state = match state {
        TerminalOutcome::Verified => {
            success.push("delivered".to_owned());
            if revision_current {
                EpisodeOutcomeState::Succeeded
            } else {
                EpisodeOutcomeState::PartiallySucceeded
            }
        }
        TerminalOutcome::Failed => {
            failed.push("delivered".to_owned());
            EpisodeOutcomeState::Failed
        }
        TerminalOutcome::Cancelled => {
            success.push("not_dispatched".to_owned());
            EpisodeOutcomeState::Cancelled
        }
    };
    if revision_current {
        success.push("event_revision_current".to_owned());
    } else {
        failed.push("event_revision_current".to_owned());
    }
    let outcome = EpisodeOutcome {
        state: outcome_state,
        success_predicates: success,
        failed_predicates: failed,
        indeterminate_predicates: vec!["warranted".to_owned()],
    };

    let effect_span = facts.effect_span_ns.max(0);
    // Only what the effect journal measures; unmetered dimensions are named in the residual
    // uncertainty instead of being reported as zero.
    let resource_use_json = format!(
        "{{\"dispatches\":{},\"effectSpanNs\":{effect_span}}}",
        u8::from(dispatched)
    );

    let result_handles: Vec<String> = facts
        .result_digest
        .into_iter()
        .map(ContentDigest::to_text)
        .collect();
    let mut hypotheses: Vec<(AttributionCauseClass, String, Vec<String>, Vec<String>)> = Vec::new();
    match state {
        TerminalOutcome::Verified => hypotheses.push((
            AttributionCauseClass::Execution,
            "The plan executed as compiled: one dispatch, relay acceptance, and an \
             owner-attested delivery."
                .to_owned(),
            result_handles.clone(),
            Vec::new(),
        )),
        TerminalOutcome::Failed if operator_not_delivered => {
            hypotheses.push((
                AttributionCauseClass::Adapter,
                "The relay accepted the alert but did not deliver it.".to_owned(),
                result_handles.clone(),
                Vec::new(),
            ));
            hypotheses.push((
                AttributionCauseClass::External,
                "The owner's receiving endpoint or device lost the alert after relay acceptance."
                    .to_owned(),
                result_handles.clone(),
                Vec::new(),
            ));
        }
        TerminalOutcome::Failed if dispatched => hypotheses.push((
            AttributionCauseClass::Adapter,
            format!(
                "The relay or route refused or broke the single dispatch ({}).",
                facts.error_code.as_deref().unwrap_or("no error code")
            ),
            result_handles.clone(),
            Vec::new(),
        )),
        TerminalOutcome::Failed => hypotheses.push((
            AttributionCauseClass::Execution,
            format!(
                "The operation failed before any dispatch ({}).",
                facts.error_code.as_deref().unwrap_or("no error code")
            ),
            result_handles.clone(),
            Vec::new(),
        )),
        _ => hypotheses.push((
            AttributionCauseClass::Policy,
            "The operator withdrew the prepared alert before dispatch.".to_owned(),
            result_handles.clone(),
            Vec::new(),
        )),
    }
    if !revision_current {
        hypotheses.push((
            AttributionCauseClass::Evidence,
            format!(
                "Evidence about event {} changed after the plan was compiled (revision {} -> {}).",
                plan.event_id,
                plan.event_revision,
                current_revision.map_or_else(|| "absent".to_owned(), |digest| digest.to_text())
            ),
            current_revision
                .into_iter()
                .map(ContentDigest::to_text)
                .collect(),
            vec![plan.event_revision.to_text()],
        ));
    }
    for proposal in inputs.feedback {
        hypotheses.push((
            feedback_cause(proposal.kind),
            bounded(format!(
                "Owner feedback {} ({}) about {}: {}",
                proposal.feedback_id,
                proposal.kind.as_str(),
                proposal.target_json,
                proposal.statement
            )),
            proposal.supporting_evidence.clone(),
            proposal.contradicting_evidence.clone(),
        ));
    }
    let prior = 1_000_000 / u32::try_from(hypotheses.len()).unwrap_or(u32::MAX).max(1);
    let attribution_hypotheses = hypotheses
        .into_iter()
        .map(
            |(cause_class, statement, supporting_evidence, contradicting_evidence)| {
                AttributionHypothesis {
                    cause_class,
                    statement,
                    supporting_evidence,
                    contradicting_evidence,
                    confidence_numerator: prior,
                }
            },
        )
        .collect();

    let mut residual_uncertainty = vec![format!(
        "Whether the alert about event {} was warranted (real activity rather than an artifact \
         world) is not established by its effect outcome.",
        plan.event_id
    )];
    if reconciled {
        residual_uncertainty.push(format!(
            "The delivery outcome is operator_asserted (owner attestation {}), not a provider \
             receipt.",
            facts
                .result_digest
                .map_or_else(|| "unrecorded".to_owned(), |digest| digest.to_text())
        ));
    }
    residual_uncertainty.push(
        "Attribution confidences are a uniform prior over the listed hypotheses; no attribution \
         model is calibrated in this build."
            .to_owned(),
    );
    residual_uncertainty.push(
        "Agent tokens, compute, and operator attention were not metered for this plan.".to_owned(),
    );
    if inputs.omitted_feedback > 0 {
        residual_uncertainty.push(format!(
            "{} further feedback proposals about this plan, its operation, or its event are not \
             cited (bound {MAX_EPISODE_FEEDBACK}).",
            inputs.omitted_feedback
        ));
    }

    ExecutionEpisode::new(
        EpisodeRecord::identity(&plan.plan_id),
        plan.session_id.clone(),
        plan.mission_id.as_str(),
        inputs.initial_anchor.clone(),
        inputs.head.anchor.clone(),
        inputs.plan_record_digest.to_text(),
        predictions,
        step_receipts,
        effect_receipts,
        obligations,
        outcome,
        resource_use_json,
        attribution_hypotheses,
        residual_uncertainty,
        plan.control_plan_digest.to_text(),
    )
}

/// One `plan --close` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseRequest {
    /// Session whose authority admits the close.
    pub session_id: SessionId,
    /// The session's principal (must be the plan's).
    pub principal: PrincipalId,
    /// Plan to close.
    pub plan_id: String,
}

/// A closed plan: its immutable episode and the session's situation afterwards.
#[derive(Clone, Debug)]
pub struct ClosedPlan {
    /// The published episode.
    pub episode: PublishedEpisode,
    /// The closed plan's published `fss.agent_control_plan.v1` rendering, exactly as published.
    pub control_plan: Vec<u8>,
    /// Root of the closed plan's publication.
    pub plan_root: ContentDigest,
    /// True when this request published the episode; false when it already existed.
    pub committed: bool,
    /// The live session.
    pub session: AgentSession,
    /// Session-bound situation as of the session's anchor (the closed plan is no longer active).
    pub orientation: DeploymentOrientation,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
    /// True when the deployment head lies past the session's anchor.
    pub head_moved: bool,
}

/// The session principal's published feedback about `targets`, sorted by identity.
fn feedback_about(
    root: &Path,
    principal: &PrincipalId,
    targets: &[String],
) -> Result<Vec<AgentFeedbackProposal>, DeploymentSessionError> {
    let mut found = Vec::new();
    for published in super::published_records(root, "feedback-")? {
        let proposal = super::feedback::decode_proposal(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!(
                "a feedback record does not verify: {error}"
            ))
        })?;
        if proposal.principal_id == *principal && targets.contains(&proposal.target_json) {
            found.push(proposal);
        }
    }
    found.sort_by(|left, right| left.feedback_id.cmp(&right.feedback_id));
    Ok(found)
}

/// Compiles and publishes the episode of a terminal plan, or returns the published one.
fn close_in(
    root: &Path,
    history: &DeploymentHistory,
    head: &DeploymentSnapshot,
    session: &AgentSession,
    plan: &PlanRecord,
    now: TimestampNs,
    render: &dyn Fn(&ExecutionEpisode) -> String,
) -> Result<(PublishedEpisode, bool), DeploymentSessionError> {
    let plan_id = plan.plan_id.as_str();
    if let Some(existing) = read_episode(root, plan_id)? {
        return Ok((existing, false));
    }
    let facts = operation_facts(head, &plan.operation_id, &plan.obligation_id)
        .ok_or(DeploymentSessionError::PlanOpen(None))?;
    let terminal = match facts.state {
        "verified" => TerminalOutcome::Verified,
        "failed" => TerminalOutcome::Failed,
        "cancelled" => TerminalOutcome::Cancelled,
        open => return Err(DeploymentSessionError::PlanOpen(Some(open))),
    };
    let obligation = facts.obligation.as_ref().ok_or_else(|| {
        DeploymentSessionError::PlanInvalid(
            "the plan's obligation is not in the effect journal".to_owned(),
        )
    })?;
    let initial_anchor = AnchorToken::parse(&plan.anchor_token)
        .and_then(|token| resolve_anchor(history, &token).ok())
        .and_then(|position| history.roots_at(position))
        .map(|(anchor, _, _)| anchor)
        .ok_or_else(|| {
            DeploymentSessionError::PlanInvalid(
                "the plan's anchor does not resolve in this deployment".to_owned(),
            )
        })?;
    let targets = [
        FeedbackTarget::Event(plan.event_id.clone()),
        FeedbackTarget::Operation(plan.operation_id.clone()),
        FeedbackTarget::Plan(plan.plan_id.clone()),
    ]
    .iter()
    .map(target_json)
    .collect::<Vec<_>>();
    let mut feedback = feedback_about(root, &session.principal_id, &targets)?;
    let omitted_feedback = feedback.len().saturating_sub(MAX_EPISODE_FEEDBACK);
    feedback.truncate(MAX_EPISODE_FEEDBACK);
    let episode = compile(&EpisodeInputs {
        plan,
        plan_record_digest: ContentDigest::sha256(&plan.to_bytes()),
        initial_anchor,
        head,
        terminal,
        facts: &facts,
        obligation,
        feedback: &feedback,
        omitted_feedback,
    })?;
    let record = EpisodeRecord {
        plan_id: plan.plan_id.clone(),
        mission_id: plan.mission_id.clone(),
        principal: plan.principal.clone(),
        operation_id: plan.operation_id.clone(),
        terminal_state: terminal,
        episode,
        recorded_at: now,
    };
    let slot = EpisodeRecord::slot(&record.episode.episode_id)?;
    let rendering = render(&record.episode).into_bytes();
    let rendering_digest = ContentDigest::sha256(&rendering);
    match publish_record(
        root,
        &slot,
        "agent-episode",
        &record.to_bytes(),
        &[rendering],
        None,
    ) {
        Ok(receipt) => Ok((
            PublishedEpisode {
                record,
                root: receipt.root,
                rendering: rendering_digest,
            },
            true,
        )),
        // A concurrent close of the same plan published first: its episode is the episode.
        Err(error) => match read_episode(root, plan_id)? {
            Some(existing) => Ok((existing, false)),
            None => Err(error),
        },
    }
}

/// Closes a terminal plan by recording its immutable execution episode (AOP-007, `close`).
///
/// The session must be live, hold the plan grant, and belong to the plan's mission and
/// principal. A plan whose operation is absent or not terminal is refused (`PlanOpen`); a plan
/// already closed returns its published episode unchanged. The session journal root is pinned
/// before the answer or refusal is returned.
///
/// `render` produces the public `fss.agent_execution_episode.v1` rendering published as the
/// episode root's only other child; it is called only when the episode is first published.
pub fn close_plan(
    root: &Path,
    request: &CloseRequest,
    render: &dyn Fn(&ExecutionEpisode) -> String,
) -> Result<ClosedPlan, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let mut journal = SessionJournal::open(root)?;
    let position = super::session_position(
        &mut journal,
        &history,
        &request.principal,
        &request.session_id,
        now,
    )?;
    let session = position.session;
    let closed = (|| {
        if !session.capabilities.contains(CAPABILITY_PLAN_PREPARE) {
            return Err(DeploymentSessionError::PlanDenied);
        }
        let (plan, plan_root, control_plan) = read_control_plan(root, &request.plan_id)?;
        if plan.mission_id != session.mission_id || plan.principal != session.principal_id {
            return Err(DeploymentSessionError::PlanUnknown);
        }
        let (episode, committed) = close_in(root, &history, &head, &session, &plan, now, render)?;
        Ok((episode, committed, plan_root, control_plan))
    })();
    let (episode, committed, plan_root, control_plan) = match closed {
        Ok(closed) => closed,
        Err(error) => {
            journal.commit_pin()?;
            return Err(error);
        }
    };
    let orientation = orient_bound(
        Some((root, &head)),
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::session_briefs(&journal.store, &session, &session.current_anchor, now),
    )?;
    journal.commit_pin()?;
    let request_digest = digest_of(EPISODE_REQUEST_DOMAIN, |encoder| {
        request.session_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        encoder.text(&request.plan_id);
        head.anchor.encode_canonical(encoder);
    });
    Ok(ClosedPlan {
        episode,
        control_plan,
        plan_root,
        committed,
        session,
        orientation,
        request_digest,
        head_moved: position.head_moved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn episode(error: Option<f64>) -> Result<ExecutionEpisode, ContractError> {
        let anchor = LedgerAnchor::genesis("site:episode");
        let mut terminal = anchor.clone();
        terminal.commit_sequence = 3;
        ExecutionEpisode::new(
            EpisodeRecord::identity("plan:00"),
            SessionId::parse("session:a")?,
            "mission:a",
            anchor,
            terminal,
            ContentDigest::sha256(b"plan").to_text(),
            vec![
                EpisodePrediction {
                    prediction_id: "prediction:delivery".to_owned(),
                    statement: "The alert reaches its owner.".to_owned(),
                    expected_state: "verified".to_owned(),
                    observed_state: Some("failed".to_owned()),
                    error,
                },
                EpisodePrediction {
                    prediction_id: "prediction:warranted".to_owned(),
                    statement: "The event reflects real activity.".to_owned(),
                    expected_state: "activity".to_owned(),
                    observed_state: None,
                    error: None,
                },
            ],
            vec!["step:commit=completed".to_owned()],
            vec![format!(
                "operation-receipt:{}",
                ContentDigest::sha256(b"receipt").to_text()
            )],
            vec!["obligation:alert:x=failed".to_owned()],
            EpisodeOutcome {
                state: EpisodeOutcomeState::Failed,
                success_predicates: vec!["event_revision_current".to_owned()],
                failed_predicates: vec!["delivered".to_owned()],
                indeterminate_predicates: vec!["warranted".to_owned()],
            },
            "{\"dispatches\":1,\"effectSpanNs\":5}",
            vec![
                AttributionHypothesis {
                    cause_class: AttributionCauseClass::Adapter,
                    statement: "The relay dropped it.".to_owned(),
                    supporting_evidence: vec![ContentDigest::sha256(b"attest").to_text()],
                    contradicting_evidence: Vec::new(),
                    confidence_numerator: 500_000,
                },
                AttributionHypothesis {
                    cause_class: AttributionCauseClass::Unobservability,
                    statement: "The endpoint is not observable.".to_owned(),
                    supporting_evidence: Vec::new(),
                    contradicting_evidence: vec![ContentDigest::sha256(b"x").to_text()],
                    confidence_numerator: 500_000,
                },
            ],
            vec!["Whether the alert was warranted is not established.".to_owned()],
            ContentDigest::sha256(b"dag").to_text(),
        )
    }

    fn record(error: Option<f64>) -> Result<EpisodeRecord, ContractError> {
        Ok(EpisodeRecord {
            plan_id: "plan:00".to_owned(),
            mission_id: MissionId::parse("mission:a")?,
            principal: PrincipalId::parse("principal:local-operator")?,
            operation_id: "operation:alert:x".to_owned(),
            terminal_state: TerminalOutcome::Failed,
            episode: episode(error)?,
            recorded_at: TimestampNs(11),
        })
    }

    #[test]
    fn episode_records_round_trip_exactly_and_refuse_any_other_bytes() -> Result<(), ContractError>
    {
        for error in [Some(1.0), Some(0.0), Some(0.25), None] {
            let record = record(error)?;
            let bytes = record.to_bytes();
            assert_eq!(EpisodeRecord::from_bytes(&bytes)?, record);
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(EpisodeRecord::from_bytes(&trailing).is_err());
            assert!(EpisodeRecord::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        }
        // An episode published under another plan's identity never verifies.
        let mut foreign = record(None)?;
        foreign.plan_id = "plan:01".to_owned();
        assert!(EpisodeRecord::from_bytes(&foreign.to_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn episode_identity_is_one_per_plan() {
        assert_eq!(
            EpisodeRecord::identity("plan:00"),
            EpisodeRecord::identity("plan:00")
        );
        assert_ne!(
            EpisodeRecord::identity("plan:00"),
            EpisodeRecord::identity("plan:01")
        );
    }

    #[test]
    fn long_statements_are_bounded_on_a_character_boundary() {
        let cut = bounded("é".repeat(MAX_TEXT_BYTES));
        assert!(cut.len() <= MAX_TEXT_BYTES);
        assert!(cut.ends_with("..."));
        assert_eq!(bounded("short".to_owned()), "short");
    }
}
