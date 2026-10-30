#![forbid(unsafe_code)]
//! Versioned cognitive reply carrying the exact selected context and its compression receipt.
//!
//! V1 remains a closed, unchanged contract. V2 carries the actual proof objects rather than an
//! unresolvable receipt identity; a receiver can verify the exact selected context in the reply.

use crate::{
    AgentCognitiveEnvelope, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError,
    SemanticCompressionReceipt, SemanticContextPack,
};

/// A concise cognitive summary plus a required, complete registered context/receipt pair.
///
/// Receivers must consume `context_pack`: its typed items carry the admitted detail, including
/// propositions absent from the summary. Each summary proposition must match an item exactly.
/// The receipt describes this complete pack, not the summary subset or the original raw sources.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentCognitiveEnvelopeV2 {
    cognition: AgentCognitiveEnvelope,
    context_pack: SemanticContextPack,
    compression_receipt: SemanticCompressionReceipt,
}

impl AgentCognitiveEnvelopeV2 {
    /// Additive version; strict v1 readers must refuse this different schema identity.
    pub const SCHEMA: &str = "fss.agent_cognitive_envelope.v2";

    /// Bind exact existing cognition to actual proof objects under the same view and authority.
    pub fn new(
        cognition: AgentCognitiveEnvelope,
        context_pack: SemanticContextPack,
        compression_receipt: SemanticCompressionReceipt,
    ) -> Result<Self, ContractError> {
        let value = Self {
            cognition,
            context_pack,
            compression_receipt,
        };
        value.validate()?;
        Ok(value)
    }

    /// Original cognitive fields; no mutable escape can replace the checked pair.
    #[must_use]
    pub const fn cognition(&self) -> &AgentCognitiveEnvelope {
        &self.cognition
    }
    /// Complete context carried to the receiver, not merely a digest or availability claim.
    #[must_use]
    pub const fn context_pack(&self) -> &SemanticContextPack {
        &self.context_pack
    }
    /// Exact registered receipt, independently verifiable against the carried pack.
    #[must_use]
    pub const fn compression_receipt(&self) -> &SemanticCompressionReceipt {
        &self.compression_receipt
    }

    /// Recheck proof/authority coupling and every cognitive proposition before serialization.
    pub fn validate(&self) -> Result<(), ContractError> {
        let envelope = &self.cognition;
        let pack = &self.context_pack;
        if !crate::contract_basis::is_probe_contract_basis(&envelope.contract_basis)
            || envelope.operation != crate::AgentOperation::Investigate
            || !matches!(
                envelope.view,
                crate::AgentView::Case | crate::AgentView::Forensic
            )
        {
            return Err(ContractError::EvidenceRequired);
        }
        envelope
            .validate()
            .map_err(|_| ContractError::EvidenceRequired)?;
        // These are the registered V2 wire constraints. Keep the historical V1 constructor and
        // canonical bytes unchanged, while refusing a self-consistent but unrenderable V2 pair.
        if !valid_semantic_verb(&envelope.semantic_verb) {
            return Err(ContractError::EvidenceRequired);
        }
        self.compression_receipt.validate_for(pack)?;
        if pack.contract_basis != envelope.contract_basis
            || pack.anchor != envelope.basis_anchor
            || pack.view_id != envelope.view.id()
        {
            return Err(ContractError::DigestMismatch);
        }
        if self.compression_receipt.target_tokens > u64::from(envelope.view.maximum_tokens()) {
            return Err(ContractError::BudgetExhausted);
        }
        let mut identities = std::collections::BTreeSet::new();
        for proposition in &envelope.epistemic.propositions {
            if !matches!(
                proposition.provenance.as_str(),
                "observed"
                    | "derived"
                    | "predicted"
                    | "remembered"
                    | "operator_asserted"
                    | "vendor_claimed"
                    | "policy"
            ) {
                return Err(ContractError::EvidenceRequired);
            }
            if !identities.insert(proposition.id.as_str()) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            let item = pack
                .items
                .iter()
                .find(|item| item.item_id == proposition.id)
                .ok_or(ContractError::EvidenceRequired)?;
            let mut expected_basis: std::collections::BTreeSet<_> =
                proposition.evidence.iter().cloned().collect();
            expected_basis.insert(format!("provenance:{}", proposition.provenance));
            if item.content != proposition.statement
                || item.epistemic_state != proposition.state
                || item.basis != expected_basis
            {
                return Err(ContractError::DigestMismatch);
            }
        }
        Ok(())
    }

    /// Domain-separated identity of the complete versioned reply, including both proof objects.
    #[must_use]
    pub fn envelope_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

fn valid_semantic_verb(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|&byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

impl CanonicalEncode for AgentCognitiveEnvelopeV2 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.cognition.encode_canonical(encoder);
        self.context_pack.encode_canonical(encoder);
        self.compression_receipt.encode_canonical(encoder);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentView, CognitiveAnswerClass, Completeness, CompressionCompleteness,
        CompressionLossClass, CompressionStopReason, CompressionTransform,
        CompressionTransformKind, ContextItem, CriticalPreservation, EnvelopeBudget,
        EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
        KnowledgeState, LedgerAnchor, MissionId, SemanticContextPackPublishParams, SessionId,
        TimestampNs,
    };
    use std::collections::BTreeSet;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> TestResult<(
        AgentCognitiveEnvelope,
        SemanticContextPack,
        SemanticCompressionReceipt,
    )> {
        let basis = crate::contract_basis::probe_contract_basis();
        let anchor = LedgerAnchor::genesis("site:probe-context");
        let cognition = AgentCognitiveEnvelope::new(
            basis.clone(),
            "request:probe",
            "response:probe",
            "trace:probe",
            "investigate",
            "probe",
            AgentView::Case.id(),
            CognitiveAnswerClass::BoundedSummary,
            anchor.clone(),
            EnvelopeEpistemic {
                propositions: vec![EnvelopeProposition {
                    id: "probe:pending".to_owned(),
                    statement:
                        "Historical result remains pending; no ACK or physical absence is inferred."
                            .to_owned(),
                    state: KnowledgeState::Known,
                    provenance: "derived".to_owned(),
                    evidence: vec!["receipt:pending".to_owned()],
                }],
                assumptions: Vec::new(),
                invalidators: Vec::new(),
            },
            EnvelopeCoverage {
                authorized_domain: vec!["probe:one".to_owned()],
                observed_domain: Vec::new(),
                not_observable_domain: vec!["physical absence".to_owned()],
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "one bounded operation".to_owned(),
            },
            EnvelopeBudget {
                requested_json: "{}".to_owned(),
                consumed_json: "{}".to_owned(),
                remaining_json: "{}".to_owned(),
                degraded_dimensions: Vec::new(),
                marginal_work_declined: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
            EnvelopeContinuity {
                cursor: None,
                reanchor_triggers: Vec::new(),
                session_capsule_digest: None,
                unresolved_obligations: Vec::new(),
            },
            ContentDigest::sha256(b"probe decision").to_text(),
        )?;
        let proposition = &cognition.epistemic.propositions[0];
        let pack = SemanticContextPack::publish(SemanticContextPackPublishParams {
            pack_id: "context-pack:probe".to_owned(),
            contract_basis: basis,
            mission_id: MissionId::parse("mission:probe")?,
            session_id: SessionId::parse("session:probe")?,
            view_id: AgentView::Case.id().to_owned(),
            anchor,
            situation_fingerprint: ContentDigest::sha256(b"current situation"),
            items: vec![ContextItem {
                item_id: proposition.id.clone(),
                kind: "admitted_cognition".to_owned(),
                content: proposition.statement.clone(),
                epistemic_state: proposition.state,
                basis: BTreeSet::from([
                    "receipt:pending".to_owned(),
                    "provenance:derived".to_owned(),
                ]),
                expansion_handles: BTreeSet::new(),
            }],
            compression_receipt_id: "compression:probe".to_owned(),
            continuation: None,
            created_at: TimestampNs(1),
        })?;
        let receipt = SemanticCompressionReceipt {
            receipt_id: pack.compression_receipt_id.clone(),
            source_anchor: pack.anchor.clone(),
            view_id: pack.view_id.clone(),
            target_tokens: 5000,
            selected_classes: BTreeSet::from(["admitted_cognition".to_owned()]),
            omitted_classes: BTreeSet::new(),
            transforms: vec![CompressionTransform {
                kind: CompressionTransformKind::Select,
                scope: "admitted cognition only".to_owned(),
                loss_class: CompressionLossClass::Lossless,
                details: Some(
                    "All supplied cognition is retained; no raw source compression is claimed."
                        .to_owned(),
                ),
            }],
            completeness: vec![CompressionCompleteness {
                domain: "admitted_cognition".to_owned(),
                state: Completeness::Complete,
                omitted_count: 0,
            }],
            critical_preservation: CriticalPreservation {
                known_critical_items: 1,
                omitted_critical_items: 0,
                omitted_invalidations: 0,
                omitted_contradictions: 0,
            },
            actual_tokens: pack.token_count,
            actual_bytes: pack.encoded_bytes(),
            expansion_handles: Vec::new(),
            selection_frontier_digest: None,
            stop_reason: CompressionStopReason::Complete,
            output_digest: pack.pack_digest,
        };
        Ok((cognition, pack, receipt))
    }

    #[test]
    fn carries_verifiable_pair_without_reinterpreting_v1_bytes() -> TestResult {
        let (base, pack, receipt) = fixture()?;
        let old = base.canonical_bytes();
        let value = AgentCognitiveEnvelopeV2::new(base.clone(), pack.clone(), receipt.clone())?;
        assert_eq!(value.cognition().canonical_bytes(), old);
        assert_eq!(value.context_pack(), &pack);
        assert_eq!(value.compression_receipt(), &receipt);
        assert_ne!(value.envelope_digest(), base.envelope_digest());
        value.validate()?;
        Ok(())
    }

    #[test]
    fn refuses_substituted_pack_receipt_and_hidden_or_relabeled_propositions() -> TestResult {
        let (base, pack, receipt) = fixture()?;
        let mut corrupted = pack.clone();
        corrupted.items[0].content.push_str(" fabricated");
        assert!(AgentCognitiveEnvelopeV2::new(base.clone(), corrupted, receipt.clone()).is_err());
        let mut corrupted = receipt.clone();
        corrupted.output_digest = ContentDigest::sha256(b"unrelated context");
        assert!(AgentCognitiveEnvelopeV2::new(base.clone(), pack.clone(), corrupted).is_err());
        for change in [0, 1, 2, 3, 4] {
            let mut changed = base.clone();
            match change {
                0 => changed.epistemic.propositions[0].state = KnowledgeState::Estimated,
                1 => changed.epistemic.propositions[0].provenance = "observed".to_owned(),
                2 => changed.epistemic.propositions[0].id = "probe:unrepresented".to_owned(),
                3 => changed.epistemic.propositions[0].evidence.clear(),
                _ => {
                    changed.epistemic.propositions[0].evidence =
                        vec!["receipt:substituted".to_owned()]
                }
            }
            assert!(AgentCognitiveEnvelopeV2::new(changed, pack.clone(), receipt.clone()).is_err());
        }
        let mut augmented = pack.clone();
        augmented.items[0]
            .basis
            .insert("receipt:unrelated".to_owned());
        augmented.token_count = crate::projection::reference_token_count(&augmented.items);
        augmented.pack_digest = augmented.computed_digest();
        let mut augmented_receipt = receipt.clone();
        augmented_receipt.actual_tokens = augmented.token_count;
        augmented_receipt.actual_bytes = augmented.encoded_bytes();
        augmented_receipt.output_digest = augmented.pack_digest;
        augmented_receipt.validate_for(&augmented)?;
        assert!(AgentCognitiveEnvelopeV2::new(base, augmented, augmented_receipt).is_err());
        Ok(())
    }

    #[test]
    fn refuses_legacy_basis_scope_drift_and_mutated_base_metadata() -> TestResult {
        let (base, pack, receipt) = fixture()?;
        for change in [0, 1, 2, 3, 4] {
            let mut changed = base.clone();
            match change {
                0 => changed.contract_basis = crate::reference_contract_basis(),
                1 => changed.basis_anchor = LedgerAnchor::genesis("site:another"),
                2 => changed.view = AgentView::Brief,
                3 => changed.request_id.clear(),
                _ => changed.coverage.stop_reason.clear(),
            }
            assert!(AgentCognitiveEnvelopeV2::new(changed, pack.clone(), receipt.clone()).is_err());
        }
        Ok(())
    }

    #[test]
    fn required_pack_preserves_details_outside_exact_summary_subset() -> TestResult {
        let (base, pack, receipt) = fixture()?;
        let mut summary = base;
        summary.epistemic.propositions.clear();
        let value = AgentCognitiveEnvelopeV2::new(summary, pack.clone(), receipt.clone())?;
        assert!(value.cognition().epistemic.propositions.is_empty());
        assert_eq!(value.context_pack().items, pack.items);
        assert_eq!(value.compression_receipt(), &receipt);
        assert_eq!(
            value.context_pack().items[0].epistemic_state,
            KnowledgeState::Known
        );
        Ok(())
    }

    #[test]
    fn forensic_is_explicit_and_does_not_widen_case_receipt_budget() -> TestResult {
        let (mut base, mut pack, mut receipt) = fixture()?;
        receipt.target_tokens = u64::from(AgentView::Forensic.maximum_tokens());
        assert!(
            AgentCognitiveEnvelopeV2::new(base.clone(), pack.clone(), receipt.clone()).is_err()
        );
        base.view = AgentView::Forensic;
        pack.view_id = AgentView::Forensic.id().to_owned();
        pack.pack_digest = pack.computed_digest();
        receipt.view_id = pack.view_id.clone();
        receipt.actual_bytes = pack.encoded_bytes();
        receipt.output_digest = pack.pack_digest;
        let value = AgentCognitiveEnvelopeV2::new(base, pack, receipt)?;
        assert_eq!(value.cognition().view, AgentView::Forensic);
        assert_eq!(value.compression_receipt().target_tokens, 16_000);
        assert_eq!(AgentView::Case.maximum_tokens(), 5_000);
        Ok(())
    }

    #[test]
    fn refuses_v2_wire_invalid_semantic_verb_and_provenance() -> TestResult {
        let (base, pack, receipt) = fixture()?;
        for verb in ["Probe", "probe action", "probe/inspect", "évidence"] {
            let mut changed = base.clone();
            changed.semantic_verb = verb.to_owned();
            assert!(AgentCognitiveEnvelopeV2::new(changed, pack.clone(), receipt.clone()).is_err());
        }
        let mut changed = base;
        changed.epistemic.propositions[0].provenance = "unregistered".to_owned();
        let mut changed_pack = pack;
        changed_pack.items[0].basis.remove("provenance:derived");
        changed_pack.items[0]
            .basis
            .insert("provenance:unregistered".to_owned());
        changed_pack.token_count = crate::projection::reference_token_count(&changed_pack.items);
        changed_pack.pack_digest = changed_pack.computed_digest();
        let mut changed_receipt = receipt;
        changed_receipt.actual_tokens = changed_pack.token_count;
        changed_receipt.actual_bytes = changed_pack.encoded_bytes();
        changed_receipt.output_digest = changed_pack.pack_digest;
        changed_receipt.validate_for(&changed_pack)?;
        assert!(AgentCognitiveEnvelopeV2::new(changed, changed_pack, changed_receipt).is_err());
        Ok(())
    }
}
