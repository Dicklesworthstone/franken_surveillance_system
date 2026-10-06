#![forbid(unsafe_code)]
//! Advisory, evidence-linked feedback proposals over a deployment root (AOP-013 `feedback`).
//!
//! **Advisory only.** A feedback proposal records that a principal, in a live session at an exact
//! anchor, proposes a correction, adjudication, outcome signal, or learning candidate about one
//! existing target, citing evidence. Recording it never changes evidence, authority, policy,
//! thresholds, models, retention, privacy, identity, or effect state
//! (`AgentFeedbackProposal::ACTIVE_POLICY_MUTATION` is the constant `false`); any change must go
//! through its own validation and activation path.
//!
//! **Grounding.** The target must exist where the proposal claims it does: a published event at
//! the session's anchor, a case visible to the session, an operation in the committed effect
//! journal, or a published plan. A proposal about nothing is refused.
//!
//! **Persistence.** The canonical proposal bytes are published root-last under
//! `<root>/agent/publications/` in a `feedback-<digest>` slot with the rendered public JSON as the
//! only child. The identity is derived from the exact content and anchor, so an identical
//! proposal is an exact retry.

use std::path::Path;

use fss_core::{
    AgentFeedbackProposal, AgentSession, CanonicalEncode, ContentDigest, FeedbackPrivacyClass,
    FeedbackProposalKind, PrincipalId, RequestedDisposition, SessionId,
};
use fss_publication::SlotName;

use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, OrientLimits, SessionJournal,
    digest_of, evidence_now, hex, orient_bound, publish_record, read_published,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::InvestigationError;

/// Registered advisory-write grant every feedback proposal requires.
pub const CAPABILITY_FEEDBACK: &str = "CAP-AGENT-FEEDBACK-001";
const FEEDBACK_IDENTITY_DOMAIN: &str = "fss.reference_agent_feedback_identity.v1";
/// Most evidence handles one proposal may cite.
pub const MAX_FEEDBACK_EVIDENCE: usize = 256;

/// What a proposal is about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeedbackTarget {
    /// A published event.
    Event(String),
    /// An investigation case visible to the session.
    Case(String),
    /// An operation in the committed effect journal.
    Operation(String),
    /// A published plan.
    Plan(String),
}

impl FeedbackTarget {
    /// Registered target-kind spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Event(_) => "event",
            Self::Case(_) => "case",
            Self::Operation(_) => "operation",
            Self::Plan(_) => "plan",
        }
    }

    /// The target identity.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Event(id) | Self::Case(id) | Self::Operation(id) | Self::Plan(id) => id,
        }
    }
}

/// One `feedback` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackRequest {
    /// Session whose authority admits the proposal.
    pub session_id: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// Target of the proposal.
    pub target: FeedbackTarget,
    /// Registered feedback kind.
    pub kind: FeedbackProposalKind,
    /// The proposal statement.
    pub statement: String,
    /// Evidence supporting the statement.
    pub supporting: Vec<ContentDigest>,
    /// Evidence contradicting it.
    pub contradicting: Vec<ContentDigest>,
    /// What the proposer asks to happen next (never performed by recording).
    pub disposition: RequestedDisposition,
}

/// A published proposal.
#[derive(Clone, Debug, PartialEq)]
pub struct PublishedFeedback {
    /// The schema-faithful proposal.
    pub proposal: AgentFeedbackProposal,
    /// Root of its publication.
    pub root: ContentDigest,
    /// The live session.
    pub session: AgentSession,
    /// Session-bound situation as of the session's anchor.
    pub orientation: DeploymentOrientation,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
    /// True when the deployment head lies past the session's anchor.
    pub head_moved: bool,
}

fn slot(feedback_id: &str) -> Result<SlotName, DeploymentSessionError> {
    SlotName::parse(&format!(
        "feedback-{}",
        hex(ContentDigest::sha256(feedback_id.as_bytes()))
    ))
    .map_err(|_| DeploymentSessionError::Internal("feedback slot name".to_owned()))
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The pinned canonical JSON of a target (`{"id":..,"kind":..}`, sorted keys).
#[must_use]
pub fn target_json(target: &FeedbackTarget) -> String {
    format!(
        "{{\"id\":{},\"kind\":{}}}",
        json_string(target.id()),
        json_string(target.kind())
    )
}

fn handles(digests: &[ContentDigest]) -> Vec<String> {
    let mut out: Vec<String> = digests.iter().map(|digest| digest.to_text()).collect();
    out.sort();
    out.dedup();
    out
}

/// Validates the target against the deployment and publishes the proposal (AOP-013).
pub fn publish_feedback(
    root: &Path,
    request: &FeedbackRequest,
) -> Result<PublishedFeedback, DeploymentSessionError> {
    let total = request.supporting.len() + request.contradicting.len();
    if total == 0 || total > MAX_FEEDBACK_EVIDENCE {
        return Err(DeploymentSessionError::FeedbackRefused(format!(
            "a proposal must cite 1..={MAX_FEEDBACK_EVIDENCE} evidence handles"
        )));
    }
    if request.statement.is_empty() || request.statement.len() > 16_384 {
        return Err(DeploymentSessionError::FeedbackRefused(
            "the statement must be 1..=16384 bytes".to_owned(),
        ));
    }
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
    if !session.capabilities.contains(CAPABILITY_FEEDBACK) {
        journal.commit_pin()?;
        return Err(DeploymentSessionError::FeedbackDenied);
    }
    let cases = super::investigation::visible_cases(&journal.store, &session);
    let grounded = match &request.target {
        FeedbackTarget::Event(id) => position
            .snapshot
            .events
            .iter()
            .any(|retained| retained.event.event_id.as_str() == id),
        FeedbackTarget::Case(id) => cases
            .iter()
            .any(|case| case.record().investigation_id == *id),
        FeedbackTarget::Operation(id) => head
            .operations
            .iter()
            .any(|operation| operation.intent.operation_id.as_str() == id),
        FeedbackTarget::Plan(id) => super::plan::read_plan(root, id).is_ok(),
    };
    if !grounded {
        journal.commit_pin()?;
        return Err(match request.target {
            FeedbackTarget::Case(_) => {
                DeploymentSessionError::CaseRefused(InvestigationError::Unavailable)
            }
            _ => DeploymentSessionError::FeedbackRefused(format!(
                "no {} `{}` exists where this session can see it",
                request.target.kind(),
                request.target.id()
            )),
        });
    }
    let orientation = orient_bound(
        Some((root, &head)),
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::investigation::case_briefs(&journal.store, &session, &session.current_anchor),
    )?;
    journal.commit_pin()?;
    drop(journal);
    let supporting = handles(&request.supporting);
    let contradicting = handles(&request.contradicting);
    let target = target_json(&request.target);
    let anchor = session.current_anchor.clone();
    let identity = digest_of(FEEDBACK_IDENTITY_DOMAIN, |encoder| {
        session.session_id.encode_canonical(encoder);
        anchor.encode_canonical(encoder);
        encoder.text(&target);
        encoder.text(request.kind.as_str());
        encoder.text(&request.statement);
        encoder.u32(supporting.len() as u32);
        for handle in &supporting {
            encoder.text(handle);
        }
        encoder.u32(contradicting.len() as u32);
        for handle in &contradicting {
            encoder.text(handle);
        }
        encoder.text(request.disposition.as_str());
    });
    let feedback_id = format!(
        "feedback:{}",
        hex(identity).chars().take(32).collect::<String>()
    );
    // Stamped with the anchor's situation time, so an identical proposal is an exact retry even
    // after evidence advances.
    let proposal = AgentFeedbackProposal::new(
        feedback_id.clone(),
        session.principal_id.clone(),
        session.session_id.clone(),
        anchor,
        target,
        request.kind,
        request.statement.clone(),
        supporting,
        contradicting,
        request.disposition,
        FeedbackPrivacyClass::Private,
        orientation.capsule().created_at.0.max(0),
    )?;
    let record = proposal.try_canonical_bytes()?;
    let slot = slot(&feedback_id)?;
    let published_root = match read_published(root, &slot)? {
        Some(existing) if existing.record == record => existing.root,
        Some(_) => {
            return Err(DeploymentSessionError::FeedbackRefused(
                "a different proposal is already published under this identity".to_owned(),
            ));
        }
        None => {
            publish_record(
                root,
                &slot,
                "agent-feedback",
                &record,
                &[render_json(&proposal).into_bytes()],
                None,
            )?
            .root
        }
    };
    let request_digest = digest_of("fss.reference_agent_feedback_request.v1", |encoder| {
        encoder.text(&feedback_id);
        head.anchor.encode_canonical(encoder);
    });
    Ok(PublishedFeedback {
        proposal,
        root: published_root,
        session,
        orientation,
        request_digest,
        head_moved: position.head_moved,
    })
}

/// The public `fss.agent_feedback_proposal.v1` rendering (published beside the record). The
/// contract basis and anchor are rendered by the caller's JSON helpers; this reference rendering
/// is the minimal self-describing projection retained with the record.
#[must_use]
pub fn render_json(proposal: &AgentFeedbackProposal) -> String {
    let list = |values: &[String]| {
        format!(
            "[{}]",
            values
                .iter()
                .map(|value| json_string(value))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    format!(
        "{{\"schema\":{},\"feedbackId\":{},\"principalId\":{},\"sessionId\":{},\"target\":{},\
         \"kind\":{},\"statement\":{},\"supportingEvidence\":{},\"contradictingEvidence\":{},\
         \"requestedDisposition\":{},\"privacyClass\":{},\"createdAtNs\":{},\
         \"activePolicyMutation\":false}}",
        json_string(AgentFeedbackProposal::SCHEMA),
        json_string(&proposal.feedback_id),
        json_string(proposal.principal_id.as_str()),
        json_string(proposal.session_id.as_str()),
        proposal.target_json,
        json_string(proposal.kind.as_str()),
        json_string(&proposal.statement),
        list(&proposal.supporting_evidence),
        list(&proposal.contradicting_evidence),
        json_string(proposal.requested_disposition.as_str()),
        json_string(proposal.privacy_class.as_str()),
        proposal.created_at_ns.max(0)
    )
}
