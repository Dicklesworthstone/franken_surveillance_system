//! Decision-impact deltas, non-coalescible transitions, and silence certificates.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractBasis, ContractError, KnowledgeCell,
    KnowledgeState, LedgerAnchor, SessionId,
};

/// Semantic class of a mission-relative situation change.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MeaningfulDeltaClass {
    /// Material world or mission state changed.
    MaterialState,
    /// A hypothesis or its disposition changed.
    Hypothesis,
    /// Material admissible evidence became contradictory or a contradiction was resolved.
    Contradiction,
    /// Observability or certified coverage was lost.
    CoverageLoss,
    /// Observability or certified coverage recovered.
    CoverageRecovery,
    /// Sensor health changed without yet proving coverage loss.
    SensorHealth,
    /// A plan or one of its assumptions became invalid.
    PlanInvalidation,
    /// An active terminal-proof obligation changed.
    Obligation,
    /// New or changed external-effect uncertainty appeared.
    EffectUncertainty,
    /// Policy, privacy, schema, registry, or authority generation changed.
    PolicyOrAuthority,
    /// Resource pressure or an explicit degraded dimension changed.
    BudgetPressure,
    /// A terminal mission, event, plan, or effect transition occurred.
    TerminalTransition,
    /// The comparison proved there was no decision-relevant change.
    NoMeaningfulChange,
}

impl MeaningfulDeltaClass {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaterialState => "material_state",
            Self::Hypothesis => "hypothesis",
            Self::Contradiction => "contradiction",
            Self::CoverageLoss => "coverage_loss",
            Self::CoverageRecovery => "coverage_recovery",
            Self::SensorHealth => "sensor_health",
            Self::PlanInvalidation => "plan_invalidation",
            Self::Obligation => "obligation",
            Self::EffectUncertainty => "effect_uncertainty",
            Self::PolicyOrAuthority => "policy_or_authority",
            Self::BudgetPressure => "budget_pressure",
            Self::TerminalTransition => "terminal_transition",
            Self::NoMeaningfulChange => "no_meaningful_change",
        }
    }

    /// Returns true when this class must be delivered without omission or coalescing.
    #[must_use]
    pub const fn is_non_coalescible(self) -> bool {
        matches!(
            self,
            Self::Contradiction
                | Self::CoverageLoss
                | Self::PlanInvalidation
                | Self::Obligation
                | Self::EffectUncertainty
                | Self::PolicyOrAuthority
                | Self::TerminalTransition
        )
    }
}

impl CanonicalEncode for MeaningfulDeltaClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// Delivery priority after constitutional non-coalescing clamps.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeltaPriority {
    /// Authority, policy, privacy, or other constitutional state changed.
    Constitutional,
    /// Immediate decision-changing or retry-hazard transition.
    Critical,
    /// Material but not immediately hazardous change.
    High,
    /// Ordinary mission-relevant change.
    Normal,
    /// Certified silence or low-impact informational change.
    Low,
}

impl DeltaPriority {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Constitutional => "constitutional",
            Self::Critical => "critical",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
        }
    }

    /// Returns true when the delta must interrupt ordinary coalescing.
    #[must_use]
    pub const fn is_urgent(self) -> bool {
        matches!(self, Self::Constitutional | Self::Critical)
    }
}

impl CanonicalEncode for DeltaPriority {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// Proof that a frame comparison found no decision-relevant change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilenceCertificate {
    /// Canonical basis-frame digest.
    pub basis_frame_digest: ContentDigest,
    /// Canonical result-frame digest.
    pub result_frame_digest: ContentDigest,
    /// Exact comparison/selection witness.
    pub selection_witness: ContentDigest,
    /// Bounded explanation of the silence claim.
    pub reason: String,
}

impl SilenceCertificate {
    /// Validates that the certificate contains an explicit comparison basis.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.reason.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns the canonical certificate digest.
    #[must_use]
    pub fn certificate_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_silence_certificate.v1")
    }
}

impl CanonicalEncode for SilenceCertificate {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.basis_frame_digest);
        encoder.digest(self.result_frame_digest);
        encoder.digest(self.selection_witness);
        encoder.text(&self.reason);
    }
}

/// Mission-relative, decision-impact change between two exact situation frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeaningfulDelta {
    /// Stable content-derived delta identity.
    pub delta_id: String,
    /// Exact semantic contract basis.
    pub contract_basis: ContractBasis,
    /// Session receiving the delta.
    pub session_id: SessionId,
    /// Basis frame identity.
    pub basis_frame_id: String,
    /// Result frame identity.
    pub result_frame_id: String,
    /// Exact basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Exact result authority anchor.
    pub result_anchor: LedgerAnchor,
    /// One or more semantic change classes.
    pub classes: BTreeSet<MeaningfulDeltaClass>,
    /// Result knowledge cells whose decision semantics changed.
    pub changed_cells: Vec<KnowledgeCell>,
    /// Assumptions or plans invalidated by the change.
    pub invalidated_assumptions: Vec<String>,
    /// Explicit coverage loss/recovery statements.
    pub coverage_changes: Vec<String>,
    /// Explicit obligation transition statements.
    pub obligation_changes: Vec<String>,
    /// Explicit external-effect uncertainty statements.
    pub effect_uncertainty_changes: Vec<String>,
    /// Number of lower-priority deltas combined into this one.
    pub coalesced_count: u64,
    /// Number of optional details omitted behind the continuation.
    pub omitted_count: u64,
    /// Reasons for every class of optional omission.
    pub omission_reasons: Vec<String>,
    /// Delivery priority after hard clamps.
    pub priority: DeltaPriority,
    /// Deterministic continuation or acknowledgement identity.
    pub continuation: String,
    /// Selection and comparison witness digest.
    pub selection_witness: ContentDigest,
    /// Present only for a certified no-change delta.
    pub silence_certificate: Option<SilenceCertificate>,
}

impl MeaningfulDelta {
    /// Validates non-coalescing clamps, evidence obligations, and anchor continuity.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.delta_id.is_empty()
            || self.basis_frame_id.is_empty()
            || self.result_frame_id.is_empty()
            || self.continuation.is_empty()
            || self.contract_basis.semantic_protocol != "fss/1"
            || self.classes.is_empty()
            || self.basis_anchor.site_lineage != self.result_anchor.site_lineage
            || self.basis_anchor.ledger_epoch != self.result_anchor.ledger_epoch
            || self.result_anchor.commit_sequence < self.basis_anchor.commit_sequence
        {
            return Err(ContractError::InvalidAnchorSuccessor);
        }
        validate_changed_cells(&self.changed_cells)?;
        validate_text_vector(&self.invalidated_assumptions)?;
        validate_text_vector(&self.coverage_changes)?;
        validate_text_vector(&self.obligation_changes)?;
        validate_text_vector(&self.effect_uncertainty_changes)?;
        validate_text_vector(&self.omission_reasons)?;

        let no_change = self
            .classes
            .contains(&MeaningfulDeltaClass::NoMeaningfulChange);
        if no_change {
            if self.classes.len() != 1
                || !self.changed_cells.is_empty()
                || !self.invalidated_assumptions.is_empty()
                || !self.coverage_changes.is_empty()
                || !self.obligation_changes.is_empty()
                || !self.effect_uncertainty_changes.is_empty()
                || self.coalesced_count != 0
                || self.omitted_count != 0
                || !self.omission_reasons.is_empty()
                || self.priority != DeltaPriority::Low
            {
                return Err(ContractError::EvidenceRequired);
            }
            let certificate = self
                .silence_certificate
                .as_ref()
                .ok_or(ContractError::EvidenceRequired)?;
            certificate.validate()?;
            if certificate.selection_witness != self.selection_witness {
                return Err(ContractError::DigestMismatch);
            }
        } else if self.silence_certificate.is_some() {
            return Err(ContractError::EvidenceRequired);
        }

        if self.classes.contains(&MeaningfulDeltaClass::Contradiction)
            && self.changed_cells.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.classes.iter().any(|class| {
            matches!(
                class,
                MeaningfulDeltaClass::CoverageLoss | MeaningfulDeltaClass::CoverageRecovery
            )
        }) && self.coverage_changes.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.classes.contains(&MeaningfulDeltaClass::PlanInvalidation)
            && self.invalidated_assumptions.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.classes.contains(&MeaningfulDeltaClass::Obligation)
            && self.obligation_changes.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty)
            && self.effect_uncertainty_changes.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }

        if self.is_non_coalescible()
            && (self.coalesced_count != 0
                || self.omitted_count != 0
                || !self.omission_reasons.is_empty()
                || !self.priority.is_urgent())
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.omitted_count > 0 && self.omission_reasons.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if self.omitted_count == 0 && !self.omission_reasons.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns true when any represented class is protected from coalescing or omission.
    #[must_use]
    pub fn is_non_coalescible(&self) -> bool {
        self.classes
            .iter()
            .any(|class| class.is_non_coalescible())
    }

    /// Returns whether two validated deltas may be combined without violating a hard clamp.
    pub fn can_coalesce_with(&self, next: &Self) -> Result<bool, ContractError> {
        self.validate()?;
        next.validate()?;
        Ok(!self.is_non_coalescible()
            && !next.is_non_coalescible()
            && !self
                .classes
                .contains(&MeaningfulDeltaClass::NoMeaningfulChange)
            && !next
                .classes
                .contains(&MeaningfulDeltaClass::NoMeaningfulChange)
            && self.contract_basis == next.contract_basis
            && self.session_id == next.session_id
            && self.result_anchor == next.basis_anchor)
    }

    /// Coalesces two eligible low-risk deltas while retaining the final cell state and counts.
    pub fn coalesce(
        &self,
        next: &Self,
        delta_id: impl Into<String>,
        continuation: impl Into<String>,
        selection_witness: ContentDigest,
    ) -> Result<Self, ContractError> {
        if !self.can_coalesce_with(next)? {
            return Err(ContractError::EvidenceRequired);
        }
        let mut classes = self.classes.clone();
        classes.extend(next.classes.iter().copied());
        let mut cells: BTreeMap<String, KnowledgeCell> = self
            .changed_cells
            .iter()
            .cloned()
            .map(|cell| (cell.claim_id.clone(), cell))
            .collect();
        for cell in &next.changed_cells {
            cells.insert(cell.claim_id.clone(), cell.clone());
        }
        let coalesced_count = self
            .coalesced_count
            .checked_add(next.coalesced_count)
            .and_then(|value| value.checked_add(1))
            .ok_or(ContractError::BudgetExhausted)?;
        let omitted_count = self
            .omitted_count
            .checked_add(next.omitted_count)
            .ok_or(ContractError::BudgetExhausted)?;
        let delta = Self {
            delta_id: delta_id.into(),
            contract_basis: self.contract_basis.clone(),
            session_id: self.session_id.clone(),
            basis_frame_id: self.basis_frame_id.clone(),
            result_frame_id: next.result_frame_id.clone(),
            basis_anchor: self.basis_anchor.clone(),
            result_anchor: next.result_anchor.clone(),
            classes,
            changed_cells: cells.into_values().collect(),
            invalidated_assumptions: merge_text(
                &self.invalidated_assumptions,
                &next.invalidated_assumptions,
            ),
            coverage_changes: merge_text(&self.coverage_changes, &next.coverage_changes),
            obligation_changes: merge_text(&self.obligation_changes, &next.obligation_changes),
            effect_uncertainty_changes: merge_text(
                &self.effect_uncertainty_changes,
                &next.effect_uncertainty_changes,
            ),
            coalesced_count,
            omitted_count,
            omission_reasons: merge_text(&self.omission_reasons, &next.omission_reasons),
            priority: self.priority.min(next.priority),
            continuation: continuation.into(),
            selection_witness,
            silence_certificate: None,
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Returns the canonical decision-impact delta digest.
    #[must_use]
    pub fn delta_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_meaningful_delta.v1")
    }
}

impl CanonicalEncode for MeaningfulDelta {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.delta_id);
        self.contract_basis.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.basis_frame_id);
        encoder.text(&self.result_frame_id);
        self.basis_anchor.encode_canonical(encoder);
        self.result_anchor.encode_canonical(encoder);
        encoder.u64(self.classes.len() as u64);
        for class in &self.classes {
            class.encode_canonical(encoder);
        }
        let mut cells = self.changed_cells.clone();
        cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        encoder.u64(cells.len() as u64);
        for cell in &cells {
            cell.encode_canonical(encoder);
        }
        encode_text_vector(&self.invalidated_assumptions, encoder);
        encode_text_vector(&self.coverage_changes, encoder);
        encode_text_vector(&self.obligation_changes, encoder);
        encode_text_vector(&self.effect_uncertainty_changes, encoder);
        encoder.u64(self.coalesced_count);
        encoder.u64(self.omitted_count);
        encode_text_vector(&self.omission_reasons, encoder);
        self.priority.encode_canonical(encoder);
        encoder.text(&self.continuation);
        encoder.digest(self.selection_witness);
        match &self.silence_certificate {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

fn validate_changed_cells(cells: &[KnowledgeCell]) -> Result<(), ContractError> {
    let mut claims = BTreeSet::new();
    for cell in cells {
        if cell.claim_id.is_empty()
            || cell.statement.is_empty()
            || !claims.insert(cell.claim_id.as_str())
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
    }
    Ok(())
}

fn validate_text_vector(values: &[String]) -> Result<(), ContractError> {
    if values.iter().any(String::is_empty) {
        return Err(ContractError::EvidenceRequired);
    }
    Ok(())
}

fn encode_text_vector(values: &[String], encoder: &mut CanonicalEncoder) {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    encoder.u64(values.len() as u64);
    for value in &values {
        encoder.text(value);
    }
}

fn merge_text(left: &[String], right: &[String]) -> Vec<String> {
    let mut values = left.to_vec();
    values.extend_from_slice(right);
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProvenanceClass, TimestampNs};

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss:test",
            None,
        )
    }

    fn anchor(sequence: u64) -> LedgerAnchor {
        let mut anchor = LedgerAnchor::genesis("site:delta");
        anchor.commit_sequence = sequence;
        anchor
    }

    fn cell(state: KnowledgeState) -> KnowledgeCell {
        KnowledgeCell {
            claim_id: "claim:test".to_owned(),
            statement: "test claim".to_owned(),
            knowledge_state: state,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"evidence")],
            contradictions: if state == KnowledgeState::Conflicted {
                vec![ContentDigest::sha256(b"contradiction")]
            } else {
                Vec::new()
            },
            valid_until: Some(TimestampNs(10)),
        }
    }

    fn delta(class: MeaningfulDeltaClass, sequence: u64) -> Result<MeaningfulDelta, ContractError> {
        let mut classes = BTreeSet::from([class]);
        let mut changed_cells = vec![cell(KnowledgeState::Known)];
        let mut coverage_changes = Vec::new();
        let mut invalidated_assumptions = Vec::new();
        let mut obligation_changes = Vec::new();
        let mut effect_uncertainty_changes = Vec::new();
        let priority = if class.is_non_coalescible() {
            DeltaPriority::Critical
        } else {
            DeltaPriority::Normal
        };
        match class {
            MeaningfulDeltaClass::Contradiction => {
                changed_cells = vec![cell(KnowledgeState::Conflicted)];
            }
            MeaningfulDeltaClass::CoverageLoss | MeaningfulDeltaClass::CoverageRecovery => {
                coverage_changes.push("coverage changed".to_owned());
            }
            MeaningfulDeltaClass::PlanInvalidation => {
                invalidated_assumptions.push("plan premise invalid".to_owned());
            }
            MeaningfulDeltaClass::Obligation => {
                obligation_changes.push("obligation changed".to_owned());
            }
            MeaningfulDeltaClass::EffectUncertainty => {
                effect_uncertainty_changes.push("effect became indeterminate".to_owned());
            }
            MeaningfulDeltaClass::NoMeaningfulChange => {
                classes = BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]);
                changed_cells.clear();
            }
            _ => {}
        }
        let selection_witness = ContentDigest::sha256(b"selection");
        Ok(MeaningfulDelta {
            delta_id: format!("delta:{sequence}"),
            contract_basis: basis(),
            session_id: SessionId::parse("session:test")?,
            basis_frame_id: format!("frame:{sequence}"),
            result_frame_id: format!("frame:{}", sequence + 1),
            basis_anchor: anchor(sequence),
            result_anchor: anchor(sequence + 1),
            classes,
            changed_cells,
            invalidated_assumptions,
            coverage_changes,
            obligation_changes,
            effect_uncertainty_changes,
            coalesced_count: 0,
            omitted_count: 0,
            omission_reasons: Vec::new(),
            priority: if class == MeaningfulDeltaClass::NoMeaningfulChange {
                DeltaPriority::Low
            } else {
                priority
            },
            continuation: format!("continuation:{sequence}"),
            selection_witness,
            silence_certificate: if class == MeaningfulDeltaClass::NoMeaningfulChange {
                Some(SilenceCertificate {
                    basis_frame_digest: ContentDigest::sha256(b"frame"),
                    result_frame_digest: ContentDigest::sha256(b"frame"),
                    selection_witness,
                    reason: "no decision-relevant change".to_owned(),
                })
            } else {
                None
            },
        })
    }

    #[test]
    fn contradiction_is_non_coalescible() -> Result<(), ContractError> {
        let delta = delta(MeaningfulDeltaClass::Contradiction, 1)?;
        delta.validate()?;
        assert!(delta.is_non_coalescible());
        Ok(())
    }

    #[test]
    fn contradiction_resolution_is_non_coalescible() -> Result<(), ContractError> {
        let delta = MeaningfulDelta {
            changed_cells: vec![cell(KnowledgeState::Known)],
            ..delta(MeaningfulDeltaClass::Contradiction, 1)?
        };
        delta.validate()?;
        assert!(delta.is_non_coalescible());
        Ok(())
    }

    #[test]
    fn noncritical_material_deltas_can_coalesce() -> Result<(), ContractError> {
        let first = delta(MeaningfulDeltaClass::MaterialState, 1)?;
        let second = delta(MeaningfulDeltaClass::Hypothesis, 2)?;
        let merged = first.coalesce(
            &second,
            "delta:merged",
            "continuation:merged",
            ContentDigest::sha256(b"merged"),
        )?;
        assert_eq!(merged.coalesced_count, 1);
        assert_eq!(merged.basis_anchor.commit_sequence, 1);
        assert_eq!(merged.result_anchor.commit_sequence, 3);
        merged.validate()
    }

    #[test]
    fn silence_is_a_proved_distinct_state() -> Result<(), ContractError> {
        let delta = delta(MeaningfulDeltaClass::NoMeaningfulChange, 1)?;
        delta.validate()?;
        assert!(delta.silence_certificate.is_some());
        Ok(())
    }

    #[test]
    fn silence_witness_must_match_delta_witness() -> Result<(), ContractError> {
        let mut delta = delta(MeaningfulDeltaClass::NoMeaningfulChange, 1)?;
        delta
            .silence_certificate
            .as_mut()
            .ok_or(ContractError::EvidenceRequired)?
            .selection_witness = ContentDigest::sha256(b"different");
        assert_eq!(delta.validate(), Err(ContractError::DigestMismatch));
        Ok(())
    }
}
