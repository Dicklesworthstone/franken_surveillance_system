#![forbid(unsafe_code)]
//! Authenticated captured-learning metadata in protected session context.
//!
//! Known cells attest retained records only. Candidate statements, causal efficacy and current
//! applicability never become facts or execution authority through discovery.

use super::*;
use crate::deployment_session::learning::MAX_CAPTURED_LEARNING;

/// Compact verified metadata for one immutable, unpromoted historical capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientLearningBrief {
    /// Immutable experience identity.
    pub experience_id: String,
    /// Immutable learning-proposal identity.
    pub proposal_id: String,
    /// Exact originating execution episode.
    pub source_episode_id: String,
    /// Registered advisory class; this is not an active policy kind.
    pub class: fss_core::LearningClass,
    /// Root containing the entire captured graph.
    pub publication_root: ContentDigest,
    /// SHA-256 of the canonical experience child bytes.
    pub experience_digest: ContentDigest,
    /// SHA-256 of the canonical proposal child bytes.
    pub proposal_digest: ContentDigest,
    /// Exact original episode publication.
    pub episode_root: ContentDigest,
    /// Exact immutable original feedback publication.
    pub feedback_root: ContentDigest,
    /// Exact originating plan publication.
    pub plan_root: ContentDigest,
    /// Immutable review deadline on the deployment evidence clock.
    pub review_after: TimestampNs,
    /// Immutable expiry deadline on the deployment evidence clock.
    pub expires_at: TimestampNs,
    /// Whether the evidence clock reached the review deadline; no review is inferred.
    pub review_due: bool,
    /// Whether the evidence clock reached expiry; retained history remains advisory.
    pub expired: bool,
    /// Every canonical residual uncertainty, including unmetered cost and unknown efficacy.
    pub missing_evidence: Vec<String>,
}

#[derive(Default)]
pub(super) struct Projection {
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub unknown: Vec<String>,
    pub at_risk: Vec<String>,
}

pub(super) fn project(session: Option<&OrientSessionBinding>) -> Result<Projection, ContractError> {
    let mut result = Projection::default();
    let Some(session) = session else {
        return Ok(result);
    };
    let Some(captures) = session.captured_learning.as_deref() else {
        result.unknown.push(
            "Captured learning is unavailable in this session projection; no absence of historical proposals is established."
                .to_owned(),
        );
        return Ok(result);
    };
    if captures.len() > MAX_CAPTURED_LEARNING {
        return Err(ContractError::BudgetExhausted);
    }
    if captures.is_empty() {
        return Ok(result);
    }
    let mut ordered: Vec<_> = captures.iter().collect();
    ordered.sort_by(|left, right| left.proposal_id.cmp(&right.proposal_id));
    if ordered
        .windows(2)
        .any(|pair| pair[0].proposal_id == pair[1].proposal_id)
    {
        return Err(ContractError::NonCanonicalOrdering);
    }
    let mut unknown = BTreeSet::new();
    for capture in ordered {
        result.proof_roots.extend([
            capture.publication_root,
            capture.experience_digest,
            capture.proposal_digest,
            capture.episode_root,
            capture.feedback_root,
            capture.plan_root,
        ]);
        unknown.extend(capture.missing_evidence.iter().cloned());
        // Identity, custody, uncalibrated status and immutable deadlines are mandatory context.
        // The complete statement remains in the verified captured graph; it is never promoted
        // to a current-world fact or duplicated into every Brief/Pulse rendering.
        result.at_risk.push(format!(
            "Captured learning {} ({}) from {}; experience={}; state=captured; evidence=single_episode; confidence=0/1000000; helpful=0; harmful=0; review_after_ns={}; review={}; expiry_ns={}; expiry={}; publication={}; experience_digest={}; proposal_digest={}. Advisory history only; no policy or effect authority.",
            capture.proposal_id,
            capture.class.as_str(),
            capture.source_episode_id,
            capture.experience_id,
            capture.review_after.0,
            if capture.review_due { "due" } else { "pending" },
            capture.expires_at.0,
            if capture.expired { "expired" } else { "unexpired" },
            capture.publication_root.to_text(),
            capture.experience_digest.to_text(),
            capture.proposal_digest.to_text(),
        ));
    }
    unknown.insert(
        "Current applicability and full custody-verification cost remain unknown; review/expiry grants no activation or revival."
            .to_owned(),
    );
    result.unknown = unknown.into_iter().collect();
    result.cells.push(cell(KnowledgeCellParams {
        claim_id: "claim:learning:inventory".to_owned(),
        statement: format!(
            "The complete admitted inventory contains {} immutable captured learning proposals for this session. Each is single-episode advisory history with zero calibrated confidence and zero verified helpful or harmful outcome counts; none grants active policy or effect authority.",
            captures.len(),
        ),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: result.proof_roots.iter().copied().collect(),
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?);
    Ok(result)
}
