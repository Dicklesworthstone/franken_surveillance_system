//! Correct class-aware semantic-compression receipt validation.

use std::collections::BTreeSet;

use crate::{
    CanonicalEncode, CanonicalEncoder, Completeness, CompressionCompleteness,
    CompressionStopReason, CompressionTransform, ContentDigest, ContractError, ExpansionHandle,
    LedgerAnchor, SemanticContextPack,
};

/// Proof-bearing record of semantic context selection and omission.
///
/// `selected_classes` and `omitted_classes` intentionally may overlap. Overlap means a semantic
/// class was partially selected; the domain-level completeness rows and omitted counts carry the
/// exact distinction. Treating those sets as disjoint would force an entire class to be either
/// retained or discarded and would make bounded item-level selection impossible to describe.
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticCompressionReceipt {
    /// Stable receipt identity.
    pub receipt_id: String,
    /// Exact source authority anchor.
    pub source_anchor: LedgerAnchor,
    /// Registered view identity.
    pub view_id: String,
    /// Target output token budget under the reference estimator.
    pub target_tokens: u64,
    /// Semantic classes represented in the selected output.
    pub selected_classes: BTreeSet<String>,
    /// Semantic classes with at least one optional omitted item.
    pub omitted_classes: BTreeSet<String>,
    /// Explicit transforms applied.
    pub transforms: Vec<CompressionTransform>,
    /// Domain-by-domain completeness.
    pub completeness: Vec<CompressionCompleteness>,
    /// Proof that critical classes were preserved.
    pub critical_preservation: crate::CriticalPreservation,
    /// Actual reference token count.
    pub actual_tokens: u64,
    /// Actual canonical context-pack byte count.
    pub actual_bytes: u64,
    /// Priced expansion handles for omitted optional detail.
    pub expansion_handles: Vec<ExpansionHandle>,
    /// Digest of the selector frontier, when retained.
    pub selection_frontier_digest: Option<ContentDigest>,
    /// Why selection stopped.
    pub stop_reason: CompressionStopReason,
    /// Exact selected context-pack digest.
    pub output_digest: ContentDigest,
}

impl SemanticCompressionReceipt {
    /// Validates the receipt independently of its selected context pack.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.receipt_id.is_empty()
            || self.view_id.is_empty()
            || self.actual_tokens > self.target_tokens
            || !self.critical_preservation.is_lossless()
            || self.selected_classes.iter().any(String::is_empty)
            || self.omitted_classes.iter().any(String::is_empty)
        {
            return Err(ContractError::BudgetExhausted);
        }
        if self.stop_reason == CompressionStopReason::Complete && !self.omitted_classes.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if !self.omitted_classes.is_empty() && self.expansion_handles.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }

        let mut completeness_domains = BTreeSet::new();
        let mut bounded_domains = BTreeSet::new();
        for row in &self.completeness {
            if row.domain.is_empty()
                || !completeness_domains.insert(row.domain.as_str())
                || row.state == Completeness::Stale
                || (row.omitted_count == 0 && row.state != Completeness::Complete)
                || (row.omitted_count > 0
                    && !matches!(
                        row.state,
                        Completeness::Bounded
                            | Completeness::Partial
                            | Completeness::Unknown
                            | Completeness::NotObservable
                            | Completeness::Unauthorized
                    ))
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            if row.omitted_count > 0 {
                bounded_domains.insert(row.domain.as_str());
            }
        }
        if self
            .selected_classes
            .iter()
            .chain(self.omitted_classes.iter())
            .any(|class| !completeness_domains.contains(class.as_str()))
            || self
                .omitted_classes
                .iter()
                .any(|class| !bounded_domains.contains(class.as_str()))
            || bounded_domains
                .iter()
                .any(|domain| !self.omitted_classes.contains(*domain))
        {
            return Err(ContractError::EvidenceRequired);
        }

        let mut handles = BTreeSet::new();
        for handle in &self.expansion_handles {
            if handle.handle.is_empty()
                || handle.purpose.is_empty()
                || !handle.estimated_cost.is_valid()
                || !handles.insert(handle.handle.as_str())
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        for transform in &self.transforms {
            if transform.scope.is_empty() || transform.details.as_deref().is_some_and(str::is_empty)
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        Ok(())
    }

    /// Cross-checks the receipt against the exact selected context pack.
    pub fn validate_for(&self, pack: &SemanticContextPack) -> Result<(), ContractError> {
        self.validate()?;
        pack.verify()?;
        let selected_kinds: BTreeSet<_> = pack.items.iter().map(|item| item.kind.clone()).collect();
        if self.receipt_id != pack.compression_receipt_id
            || self.source_anchor != pack.anchor
            || self.view_id != pack.view_id
            || self.actual_tokens != pack.token_count
            || self.actual_bytes != pack.encoded_bytes()
            || self.output_digest != pack.pack_digest
            || selected_kinds != self.selected_classes
        {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns the canonical receipt digest.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.semantic_compression_receipt.v1")
    }
}

impl CanonicalEncode for SemanticCompressionReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.receipt_id);
        self.source_anchor.encode_canonical(encoder);
        encoder.text(&self.view_id);
        encoder.u64(self.target_tokens);
        encode_text_set(&self.selected_classes, encoder);
        encode_text_set(&self.omitted_classes, encoder);
        encoder.u64(self.transforms.len() as u64);
        for transform in &self.transforms {
            transform.encode_canonical(encoder);
        }
        let mut completeness = self.completeness.clone();
        completeness.sort_by(|left, right| left.domain.cmp(&right.domain));
        encoder.u64(completeness.len() as u64);
        for row in &completeness {
            row.encode_canonical(encoder);
        }
        self.critical_preservation.encode_canonical(encoder);
        encoder.u64(self.actual_tokens);
        encoder.u64(self.actual_bytes);
        let mut handles = self.expansion_handles.clone();
        handles.sort_by(|left, right| left.handle.cmp(&right.handle));
        encoder.u64(handles.len() as u64);
        for handle in &handles {
            handle.encode_canonical(encoder);
        }
        match self.selection_frontier_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        encoder.text(self.stop_reason.as_str());
        encoder.digest(self.output_digest);
    }
}

fn encode_text_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BudgetVector, CompressionLossClass, CompressionTransformKind, ContextItem,
        CriticalPreservation, KnowledgeState, MissionId, SessionId, TimestampNs,
    };

    fn pack() -> Result<SemanticContextPack, ContractError> {
        SemanticContextPack::publish(
            "context-pack:partial",
            crate::ContractBasis::from_registry_bytes(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss:test",
                None,
            ),
            MissionId::parse("mission:partial")?,
            SessionId::parse("session:partial")?,
            "AVIEW-001",
            LedgerAnchor::genesis("site:partial"),
            ContentDigest::sha256(b"frame"),
            vec![ContextItem {
                item_id: "context:knowledge:selected".to_owned(),
                kind: "knowledge".to_owned(),
                epistemic_state: KnowledgeState::Known,
                content: "selected knowledge item".to_owned(),
                basis: BTreeSet::from(["claim:selected".to_owned()]),
                expansion_handles: BTreeSet::new(),
            }],
            "compression:partial",
            Some("continuation:partial".to_owned()),
            TimestampNs(1),
        )
    }

    #[test]
    fn one_class_may_be_partially_selected() -> Result<(), ContractError> {
        let pack = pack()?;
        let receipt = SemanticCompressionReceipt {
            receipt_id: "compression:partial".to_owned(),
            source_anchor: pack.anchor.clone(),
            view_id: pack.view_id.clone(),
            target_tokens: pack.token_count + 100,
            selected_classes: BTreeSet::from(["knowledge".to_owned()]),
            omitted_classes: BTreeSet::from(["knowledge".to_owned()]),
            transforms: vec![CompressionTransform {
                kind: CompressionTransformKind::Select,
                scope: "knowledge".to_owned(),
                loss_class: CompressionLossClass::BoundedLoss,
                details: Some("one optional item omitted".to_owned()),
            }],
            completeness: vec![CompressionCompleteness {
                domain: "knowledge".to_owned(),
                state: Completeness::Bounded,
                omitted_count: 1,
            }],
            critical_preservation: CriticalPreservation {
                known_critical_items: 0,
                omitted_critical_items: 0,
                omitted_invalidations: 0,
                omitted_contradictions: 0,
            },
            actual_tokens: pack.token_count,
            actual_bytes: pack.encoded_bytes(),
            expansion_handles: vec![ExpansionHandle {
                handle: "context-expand:knowledge".to_owned(),
                purpose: "hydrate omitted knowledge".to_owned(),
                estimated_cost: BudgetVector {
                    tokens: 100,
                    bytes: 1_000,
                    ..BudgetVector::default()
                },
            }],
            selection_frontier_digest: Some(ContentDigest::sha256(b"frontier")),
            stop_reason: CompressionStopReason::TargetBudget,
            output_digest: pack.pack_digest,
        };
        receipt.validate_for(&pack)
    }
}
