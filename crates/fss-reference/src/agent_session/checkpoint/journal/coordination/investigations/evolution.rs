#![forbid(unsafe_code)]
//! Explicit, conservative changes to the question space and authority anchor of a live case.
//!
//! The runtime supplies an authenticated session and authorizes every citation/receipt beforehand.
//! A receipt here attributes a cognition decision; it does not prove source custody or grant effects.

use super::*;
use fss_core::{CaseDiscriminator, CaseHypothesis, KnowledgeState, LedgerAnchor};

/// Live-custody citation acquisition and its durable case-link receipts.
pub use super::journal::source_citation::{
    SourceAcquisition, SourceCitationError, SourceCitationReceipt, SourceCitationTarget,
};

/// Rebased revision identity. Never-rebased revisions retain their exact v1 bytes and digest.
pub const EVOLVED_REVISION_DOMAIN: &str = "fss-reference:investigation-revision:v2";

/// One exact use of a citation. A readmission cannot be reused for another hypothesis or side.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InvestigationCitation {
    /// Stable hypothesis within this case.
    pub hypothesis: String,
    /// Immutable source/derived evidence citation, not a custody claim.
    pub evidence: ContentDigest,
    /// Counterevidence when true, supporting evidence otherwise.
    pub contradicts: bool,
}

/// Applicability changes at the most recent explicit rebase; prior epochs remain in history.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigationValidity {
    /// Exact revision whose knowledge and dispositions were invalidated.
    pub source_revision: ContentDigest,
    /// Exact prior authority anchor, not an implicit latest reference.
    pub source_anchor: LedgerAnchor,
    /// Owner-supplied immutable rationale for the rebase; not an authentication proof.
    pub witness: ContentDigest,
    inherited_roots: BTreeSet<ContentDigest>,
    readmissions: BTreeMap<InvestigationCitation, ContentDigest>,
}

impl InvestigationValidity {
    /// All inherited evidence identities, including counterevidence. They remain in the case.
    #[must_use]
    pub const fn inherited_roots(&self) -> &BTreeSet<ContentDigest> {
        &self.inherited_roots
    }

    /// Explicit current-basis receipts, separately bound to hypothesis and evidence side.
    #[must_use]
    pub const fn readmissions(&self) -> &BTreeMap<InvestigationCitation, ContentDigest> {
        &self.readmissions
    }

    /// Whether this citation still requires explicit current-basis readmission before assessment.
    #[must_use]
    pub fn needs_readmission(
        &self,
        hypothesis: &str,
        evidence: ContentDigest,
        contradicts: bool,
    ) -> bool {
        self.inherited_roots.contains(&evidence)
            && !self.readmissions.contains_key(&InvestigationCitation {
                hypothesis: hypothesis.to_owned(),
                evidence,
                contradicts,
            })
    }
}

impl CanonicalEncode for InvestigationValidity {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.text("fss.reference_investigation_validity.v1");
        e.digest(self.source_revision);
        self.source_anchor.encode_canonical(e);
        e.digest(self.witness);
        e.u32(self.inherited_roots.len() as u32);
        for root in &self.inherited_roots {
            e.digest(*root);
        }
        e.u32(self.readmissions.len() as u32);
        for (citation, witness) in &self.readmissions {
            e.text(&citation.hypothesis);
            e.digest(citation.evidence);
            e.bool(citation.contradicts);
            e.digest(*witness);
        }
    }
}

/// Append-only case evolution. None of these changes executes a probe or verifies physical truth.
#[derive(Clone, Debug, PartialEq)]
pub enum InvestigationEvolution {
    /// Invalidate old applicability at a strictly newer, runtime-verified session anchor.
    /// Preserves the hard deadline, all alternatives, citations, unknowns and historical revisions.
    Rebase {
        /// Exact target anchor; must equal the current authenticated session anchor.
        anchor: LedgerAnchor,
        /// Immutable owner rationale for invalidation, already authorized for the case's domain.
        witness: ContentDigest,
    },
    /// Explicitly record the evidence owner's current-basis applicability assessment.
    /// Repeating `Cite` is deliberately insufficient to readmit an inherited root.
    ReadmitCitation {
        /// Attached inherited citation and its exact intended use.
        citation: InvestigationCitation,
        /// Owner-supplied applicability receipt; does not upgrade statement knowledge state.
        witness: ContentDigest,
    },
    /// Introduce a previously unnamed alternative and a concrete way to discriminate it.
    /// Existing dispositions, statements, evidence, deadlines and stop rules remain untouched.
    Expand {
        /// Starts Unknown, with predictions but no pre-attached evidence or contradictions.
        hypothesis: Box<CaseHypothesis>,
        /// New discriminator separating the new hypothesis from at least one existing alternative.
        discriminator: Box<CaseDiscriminator>,
        /// Authorized observation handle; this operation records it without executing it.
        probe: String,
    },
}

/// Full-head precondition and one bounded evolution intent.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigationEvolutionRequest {
    /// Stable investigation identity; never reset or reused.
    pub case_id: String,
    /// Exact revision, including authority, predecessor and invalidation receipts.
    pub expected: ContentDigest,
    /// Explicit evolution, not a replacement record.
    pub change: InvestigationEvolution,
}

impl ReferenceInvestigationStore {
    /// Evolves a live investigation under the same session/mission/privacy admission as `execute`.
    /// Refusals append no case revision, but session/store watermarks may advance.
    pub fn evolve(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        request: &InvestigationEvolutionRequest,
        now: TimestampNs,
    ) -> Result<InvestigationRevision, InvestigationError> {
        validate_request(request)?;
        let mut next = self.execute(
            sessions,
            principal,
            session_id,
            &InvestigationCommand::Inspect {
                case_id: request.case_id.clone(),
                revision: None,
            },
            now,
        )?;
        if next.digest() != request.expected {
            return Err(InvestigationError::StaleRevision);
        }
        if !open_state(next.record.state) || next.control.is_terminal() {
            return Err(InvestigationError::InvalidTransition);
        }
        if now.0 >= next.record.decision_deadline_ns {
            return Err(InvestigationError::DeadlineElapsed);
        }
        // execute just performed live admission. This single-owner call cannot interleave a
        // session mutation between admission and reading these exact authority coordinates.
        let entry = sessions
            .sessions
            .get(session_id)
            .ok_or(InvestigationError::Unavailable)?;
        match &request.change {
            InvestigationEvolution::Rebase { anchor, witness } => {
                let old = &next.record.basis_anchor;
                if &entry.session.current_anchor != anchor
                    || entry.basis != next.record.contract_basis
                    || old.site_lineage != anchor.site_lineage
                    || old.ledger_epoch != anchor.ledger_epoch
                    || anchor.commit_sequence <= old.commit_sequence
                    || anchor.adapter_registry_epoch < old.adapter_registry_epoch
                {
                    return Err(InvestigationError::StaleBasis);
                }
                let inherited_roots = next
                    .record
                    .hypotheses
                    .iter()
                    .flat_map(|h| h.evidence.iter().chain(&h.contradictions))
                    .copied()
                    .collect();
                next.validity = Some(InvestigationValidity {
                    source_revision: request.expected,
                    source_anchor: old.clone(),
                    witness: *witness,
                    inherited_roots,
                    readmissions: BTreeMap::new(),
                });
                next.record.basis_anchor = anchor.clone();
                for h in &mut next.record.hypotheses {
                    invalidate_positive(&mut h.epistemic_state);
                }
                for s in next
                    .record
                    .knowns
                    .iter_mut()
                    .chain(&mut next.record.unknowns)
                {
                    invalidate_positive(&mut s.epistemic_state);
                }
                // This is a new applicability epoch, not reversal of an old disposition in place.
                // The entire old control machine is retained by the predecessor revision.
                next.control = make_control(&next.record, None)?;
                next.record.state = InvestigationLifecycle::AwaitingEvidence;
                next.assessment = Some(*witness);
            }
            InvestigationEvolution::ReadmitCitation { citation, witness } => {
                Self::basis(&next.record, &entry.session, &entry.basis)?;
                let h = next
                    .record
                    .hypotheses
                    .iter()
                    .find(|h| h.hypothesis_id == citation.hypothesis)
                    .ok_or(InvestigationError::InvalidRecord)?;
                let roots = if citation.contradicts {
                    &h.contradictions
                } else {
                    &h.evidence
                };
                let validity = next
                    .validity
                    .as_mut()
                    .ok_or(InvestigationError::InvalidTransition)?;
                if !roots.contains(&citation.evidence)
                    || !validity.inherited_roots.contains(&citation.evidence)
                {
                    return Err(InvestigationError::EvidenceRequired);
                }
                if validity.readmissions.contains_key(citation) {
                    return Err(InvestigationError::Conflict);
                }
                validity.readmissions.insert(citation.clone(), *witness);
                next.assessment = Some(*witness);
            }
            InvestigationEvolution::Expand {
                hypothesis,
                discriminator,
                probe,
            } => {
                Self::basis(&next.record, &entry.session, &entry.basis)?;
                if next
                    .record
                    .hypotheses
                    .iter()
                    .any(|h| h.hypothesis_id == hypothesis.hypothesis_id)
                    || next
                        .record
                        .discriminators
                        .iter()
                        .any(|d| d.discriminator_id == discriminator.discriminator_id)
                {
                    return Err(InvestigationError::Conflict);
                }
                if next.record.hypotheses.len() >= 64
                    || next.record.discriminators.len() >= 128
                    || (!next.record.probes.contains(probe) && next.record.probes.len() >= 128)
                {
                    return Err(InvestigationError::CapacityExceeded);
                }
                next.record.hypotheses.push(hypothesis.as_ref().clone());
                next.record
                    .discriminators
                    .push(discriminator.as_ref().clone());
                if !next.record.probes.contains(probe) {
                    next.record.probes.push(probe.clone());
                }
                validation::record_fields(&next.record)?;
                next.control = make_control(&next.record, Some(&next.control))?;
            }
        }
        next.record.revision = next
            .record
            .revision
            .checked_add(1)
            .ok_or(InvestigationError::CounterExhausted)?;
        next.predecessor = Some(request.expected);
        next.author_session = session_id.clone();
        next.changed_at = now;
        let bytes = self.reserve(&next)?;
        let current = self
            .entries
            .get_mut(&request.case_id)
            .ok_or(InvestigationError::Unavailable)?;
        current.history.push(current.head.clone());
        current.head = next.clone();
        self.revisions += 1;
        self.retained_bytes += bytes;
        Ok(next)
    }
}

fn invalidate_positive(state: &mut KnowledgeState) {
    if matches!(state, KnowledgeState::Known | KnowledgeState::Estimated) {
        *state = KnowledgeState::Stale;
    }
}

fn make_control(
    record: &InvestigationState,
    prior: Option<&InvestigationCaseState>,
) -> Result<InvestigationCaseState, InvestigationError> {
    let ids = record
        .hypotheses
        .iter()
        .map(|h| h.hypothesis_id.clone())
        .collect();
    let mut control = InvestigationCaseState::create(
        record.investigation_id.clone(),
        record.mission_id.clone(),
        &ids,
    )
    .map_err(|_| InvestigationError::InvalidRecord)?;
    if let Some(prior) = prior {
        for (id, disposition) in prior.hypotheses() {
            if *disposition != HypothesisDisposition::Live {
                control
                    .advance_hypothesis(id, *disposition)
                    .map_err(|_| InvestigationError::InvalidTransition)?;
            }
        }
    }
    Ok(control)
}

pub(super) fn validate_request(
    request: &InvestigationEvolutionRequest,
) -> Result<(), InvestigationError> {
    let id = |s: &str| {
        CaseId::parse(s)
            .map(|_| ())
            .map_err(|_| InvestigationError::InvalidRecord)
    };
    let text = |s: &str, bound: usize| {
        if s.is_empty() || s.len() > bound {
            Err(InvestigationError::InvalidRecord)
        } else {
            Ok(())
        }
    };
    id(&request.case_id)?;
    match &request.change {
        InvestigationEvolution::Rebase { anchor, .. } => {
            let bytes = anchor
                .try_canonical_bytes()
                .map_err(|_| InvestigationError::InvalidRecord)?;
            if bytes.len() > 4_096 {
                return Err(InvestigationError::CapacityExceeded);
            }
        }
        InvestigationEvolution::ReadmitCitation { citation, .. } => id(&citation.hypothesis)?,
        InvestigationEvolution::Expand {
            hypothesis: h,
            discriminator: d,
            probe,
        } => {
            id(&h.hypothesis_id)?;
            id(&d.discriminator_id)?;
            id(probe)?;
            text(&h.description, 8_192)?;
            text(&d.description, 1_024)?;
            if h.epistemic_state != KnowledgeState::Unknown
                || !h.evidence.is_empty()
                || !h.contradictions.is_empty()
                || h.predictions.is_empty()
                || d.separates.len() < 2
                || d.expected_outcomes.len() != d.separates.len()
                || !d.separates.contains(&h.hypothesis_id)
            {
                return Err(InvestigationError::InvalidRecord);
            }
            if h.predictions.len() > 128 || d.separates.len() > 64 {
                return Err(InvestigationError::CapacityExceeded);
            }
            for p in &h.predictions {
                text(p, 1_024)?;
            }
            for s in &d.separates {
                id(s)?;
            }
            for outcome in &d.expected_outcomes {
                text(outcome, 1_024)?;
            }
            if d.separates.iter().collect::<BTreeSet<_>>().len() != d.separates.len()
                || d.expected_outcomes.iter().collect::<BTreeSet<_>>().len() < 2
            {
                return Err(InvestigationError::InvalidRecord);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
