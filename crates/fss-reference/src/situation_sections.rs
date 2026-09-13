//! Proof-bearing resource, control, context, and compression sections for reference situations.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AffordanceClass, BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness,
    CompressionCompleteness, CompressionLossClass, CompressionStopReason, CompressionTransform,
    CompressionTransformKind, ContentDigest, ContextItem, ContractError, ControlEnvelope,
    CriticalPreservation, ExpansionHandle, HandoffCapsule, HandoffId, HandoffPublishParams,
    KnowledgeCell, KnowledgeState, OperationReceipt, ResourcePressure, ResourceState,
    SemanticCompressionReceipt, SemanticContextPack, SemanticContextPackPublishParams, TimestampNs,
    reference_token_count,
};
use fss_ledger::DurableReferenceLedger;

use crate::{
    ReferenceError,
    situation::{ReferenceSituation, ReferenceSituationRequest},
    situation_guard,
};

const MAX_VIEW_ID_BYTES: usize = 256;

/// Deterministic resource and selection policy for one reference situation publication.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceProjectionSpec {
    /// Registered view identity.
    pub view_id: String,
    /// Total budget available to this publication and its continuations.
    pub available_resources: BudgetVector,
    /// Budget reserved for active obligations and already-committed work.
    pub reserved_resources: BudgetVector,
    /// Explicit resource pressure class.
    pub pressure: ResourcePressure,
    /// Dimensions using a declared degraded path.
    pub degraded_dimensions: BTreeSet<String>,
    /// Hard token limit under the dependency-free reference estimator.
    pub target_tokens: u64,
}

impl ReferenceProjectionSpec {
    /// Validates the projection policy and returns its semantic digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.view_id.is_empty()
            || self.view_id.len() > MAX_VIEW_ID_BYTES
            || self.target_tokens == 0
            || self.target_tokens
                > self
                    .available_resources
                    .tokens
                    .saturating_sub(self.reserved_resources.tokens)
        {
            return Err(ContractError::BudgetExhausted);
        }
        ResourceState::new(
            self.available_resources,
            self.reserved_resources,
            self.pressure,
            self.degraded_dimensions.iter().cloned(),
        )?;
        Ok(())
    }

    /// Returns the canonical projection-policy digest.
    #[must_use]
    pub fn spec_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.reference_projection_spec.v1")
    }
}

impl CanonicalEncode for ReferenceProjectionSpec {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.view_id);
        encode_budget(self.available_resources, encoder);
        encode_budget(self.reserved_resources, encoder);
        self.pressure.encode_canonical(encoder);
        encoder.u64(self.degraded_dimensions.len() as u64);
        for dimension in &self.degraded_dimensions {
            encoder.text(dimension);
        }
        encoder.u64(self.target_tokens);
    }
}

/// Complete reference publication carrying the schema-required outer situation sections.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceSituationPublication {
    /// Guarded mission-relative situation and its proof roots.
    pub situation: ReferenceSituation,
    /// Explicit available/reserved resource state.
    pub resource_state: ResourceState,
    /// Exact categorized affordance frontier.
    pub control_envelope: ControlEnvelope,
    /// Bounded decision-oriented context.
    pub context_pack: SemanticContextPack,
    /// Proof of selection, omission, and critical preservation.
    pub compression_receipt: SemanticCompressionReceipt,
    /// Digest of the complete publication.
    pub publication_digest: ContentDigest,
}

impl ReferenceSituationPublication {
    /// Returns the required critical context item identities for the situation, or error if candidates cannot be computed.
    pub fn required_context_item_ids(
        situation: &ReferenceSituation,
    ) -> Result<BTreeSet<String>, ReferenceError> {
        required_context_item_ids(situation)
    }

    /// Returns the redundancy records documented in this publication's compression receipt.
    pub fn redundancy_records(&self) -> Vec<RedundancyRecord> {
        let mut records = Vec::new();
        for transform in &self.compression_receipt.transforms {
            if transform.kind == CompressionTransformKind::Deduplicate
                && let Some((kind, dropped_id)) = transform.scope.split_once(':')
                && let Some(ref details) = transform.details
            {
                let retained_prefix = "retained representative: ";
                let reason_prefix = "; reason: ";
                if let Some(start) = details.strip_prefix(retained_prefix)
                    && let Some((retained_id, reason)) = start.split_once(reason_prefix)
                {
                    records.push(RedundancyRecord {
                        dropped_item_id: dropped_id.to_owned(),
                        retained_item_id: retained_id.to_owned(),
                        kind: kind.to_owned(),
                        reason: reason.to_owned(),
                    });
                }
            }
        }
        records
    }

    /// Recomputes all cross-section invariants and publication identity.
    pub fn verify(&self) -> Result<ContentDigest, ReferenceError> {
        let base = self.situation.verify()?;
        self.resource_state.validate()?;
        self.control_envelope.validate_against(
            &self.situation.capsule.frame.world_envelope,
            &self.situation.capsule.affordances,
        )?;
        self.context_pack.verify()?;
        self.compression_receipt.validate_for(&self.context_pack)?;
        if self.context_pack.contract_basis != self.situation.capsule.contract_basis
            || self.context_pack.mission_id != self.situation.capsule.mission_id
            || self.context_pack.session_id != self.situation.capsule.session_id
            || self.context_pack.anchor != self.situation.capsule.anchor
            || self.context_pack.situation_fingerprint
                != self.situation.capsule.frame.frame_digest()?
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let required = required_context_item_ids(&self.situation)?;
        let selected: BTreeSet<_> = self
            .context_pack
            .items
            .iter()
            .map(|item| item.item_id.clone())
            .collect();
        if !required.is_subset(&selected)
            || self
                .compression_receipt
                .critical_preservation
                .known_critical_items
                != required.len() as u64
            || !self.compression_receipt.critical_preservation.is_lossless()
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let computed = self.computed_digest()?;
        if computed != self.publication_digest {
            return Err(ContractError::DigestMismatch.into());
        }
        if !self.situation.proof_roots.contains(&base) {
            // The base situation fingerprint is itself a handoff child even when no object store
            // materializes the reference-only projection.
            return Err(ContractError::IncompletePublicationGraph.into());
        }
        Ok(computed)
    }

    /// Computes the complete publication digest with the digest field omitted.
    ///
    /// Fails with the capsule's typed refusal when the situation capsule does not validate, since
    /// an invalid capsule has no decision fingerprint.
    pub fn computed_digest(&self) -> Result<ContentDigest, ReferenceError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_situation_publication.v1");
        encoder.digest(self.situation.capsule.decision_fingerprint()?);
        // The publication commits to the compile path's seal, so a sealed publication and the same
        // capsule rebuilt unsealed never share a digest (fss-6sph6).
        match self.situation.seal_digest() {
            Some(seal) => {
                encoder.bool(true);
                encoder.digest(seal);
            }
            None => encoder.bool(false),
        }
        self.resource_state.encode_canonical(&mut encoder);
        self.control_envelope.encode_canonical(&mut encoder);
        self.context_pack.encode_canonical(&mut encoder);
        self.compression_receipt.encode_canonical(&mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish()))
    }
}

/// Compiles, guards, selects, and proves one complete reference situation publication.
pub fn compile_reference_situation_publication(
    request: ReferenceSituationRequest<'_>,
    authority: &DurableReferenceLedger,
    spec: &ReferenceProjectionSpec,
) -> Result<ReferenceSituationPublication, ReferenceError> {
    let situation = situation_guard::compile_reference_situation(request, authority)?;
    project_reference_situation(situation, spec)
}

/// Compiles a complete publication while binding the exact local operation receipt.
pub fn compile_reference_situation_publication_with_operation_receipt(
    request: ReferenceSituationRequest<'_>,
    operation_receipt: &OperationReceipt,
    authority: &DurableReferenceLedger,
    spec: &ReferenceProjectionSpec,
) -> Result<ReferenceSituationPublication, ReferenceError> {
    let situation = situation_guard::compile_reference_situation_with_operation_receipt(
        request,
        operation_receipt,
        authority,
    )?;
    project_reference_situation(situation, spec)
}

/// Adds deterministic resource/control/context/compression sections to a guarded situation.
pub fn project_reference_situation(
    mut situation: ReferenceSituation,
    spec: &ReferenceProjectionSpec,
) -> Result<ReferenceSituationPublication, ReferenceError> {
    spec.validate()?;
    let base_digest = situation.verify()?;
    situation.proof_roots.insert(base_digest);

    let resource_state = ResourceState::new(
        spec.available_resources,
        spec.reserved_resources,
        spec.pressure,
        spec.degraded_dimensions.iter().cloned(),
    )?;
    let control_envelope = ControlEnvelope::from_affordances(
        &situation.capsule.frame.world_envelope,
        &situation.capsule.affordances,
    )?;
    let selection = select_context(&situation, spec.target_tokens)?;
    let identity = projection_identity(base_digest, spec, selection.frontier_digest);
    let receipt_id = format!("compression:{identity}");
    let continuation = if selection.omitted.is_empty() {
        None
    } else {
        Some(format!("continuation:context:{identity}"))
    };
    let context_pack = SemanticContextPack::publish(SemanticContextPackPublishParams {
        pack_id: format!("context-pack:{identity}"),
        contract_basis: situation.capsule.contract_basis.clone(),
        mission_id: situation.capsule.mission_id.clone(),
        session_id: situation.capsule.session_id.clone(),
        view_id: spec.view_id.clone(),
        anchor: situation.capsule.anchor.clone(),
        situation_fingerprint: situation.capsule.frame.frame_digest()?,
        items: selection.selected.clone(),
        compression_receipt_id: receipt_id.clone(),
        continuation,
        created_at: situation.capsule.created_at,
    })?;
    if context_pack.encoded_bytes() > spec.available_resources.bytes {
        return Err(ContractError::BudgetExhausted.into());
    }

    let selected_classes: BTreeSet<_> = selection
        .selected
        .iter()
        .map(|item| item.kind.clone())
        .collect();
    let omitted_classes: BTreeSet<_> = selection
        .omitted
        .iter()
        .map(|item| item.kind.clone())
        .collect();
    let completeness = compression_completeness(&selection.selected, &selection.omitted);
    let mut transforms = vec![CompressionTransform {
        kind: CompressionTransformKind::Select,
        scope: "mission-relative situation context".to_owned(),
        loss_class: CompressionLossClass::DecisionPreserving,
        details: Some("all critical items are hard inclusions".to_owned()),
    }];
    for record in &selection.redundancy_records {
        transforms.push(CompressionTransform {
            kind: CompressionTransformKind::Deduplicate,
            scope: format!("{}:{}", record.kind, record.dropped_item_id),
            loss_class: CompressionLossClass::Lossless,
            details: Some(format!(
                "retained representative: {}; reason: {}",
                record.retained_item_id, record.reason
            )),
        });
    }
    if !selection.omitted.is_empty() {
        transforms.push(CompressionTransform {
            kind: CompressionTransformKind::Truncate,
            scope: "optional context beyond target token budget".to_owned(),
            loss_class: CompressionLossClass::BoundedLoss,
            details: Some(
                "omitted classes remain available through priced expansion handles".to_owned(),
            ),
        });
    }
    let expansion_handles = expansion_handles(&context_pack.pack_id, &omitted_classes)?;
    let compression_receipt = SemanticCompressionReceipt {
        receipt_id,
        source_anchor: situation.capsule.anchor.clone(),
        view_id: spec.view_id.clone(),
        target_tokens: spec.target_tokens,
        selected_classes,
        omitted_classes,
        transforms,
        completeness,
        critical_preservation: CriticalPreservation {
            known_critical_items: selection.critical_count as u64,
            omitted_critical_items: 0,
            omitted_invalidations: 0,
            omitted_contradictions: 0,
        },
        actual_tokens: context_pack.token_count,
        actual_bytes: context_pack.encoded_bytes(),
        expansion_handles,
        selection_frontier_digest: Some(selection.frontier_digest),
        stop_reason: if selection.omitted.is_empty() {
            CompressionStopReason::Complete
        } else {
            CompressionStopReason::TargetBudget
        },
        output_digest: context_pack.pack_digest,
    };
    compression_receipt.validate_for(&context_pack)?;

    situation.proof_roots.insert(resource_state.state_digest());
    situation
        .proof_roots
        .insert(control_envelope.control_digest());
    situation.proof_roots.insert(context_pack.pack_digest);
    situation
        .proof_roots
        .insert(compression_receipt.receipt_digest());

    let mut publication = ReferenceSituationPublication {
        situation,
        resource_state,
        control_envelope,
        context_pack,
        compression_receipt,
        publication_digest: ContentDigest::sha256(b"unpublished-situation-publication"),
    };
    publication.publication_digest = publication.computed_digest()?;
    publication.verify()?;
    Ok(publication)
}

/// Seals a handoff rooted in the complete resource/control/context/compression publication.
pub fn seal_reference_publication_handoff(
    publication: &ReferenceSituationPublication,
    handoff_id: HandoffId,
    created_at: TimestampNs,
    expires_at: TimestampNs,
) -> Result<HandoffCapsule, ReferenceError> {
    let publication_root = publication.verify()?;
    // A handoff carries the publication to another principal on its own, so it must be one a
    // compile path produced and sealed (fss-6sph6).
    if !publication.situation.is_sealed() {
        return Err(ReferenceError::InvalidSpec("situation_handoff_unsealed"));
    }
    let mut children = publication.situation.proof_roots.clone();
    children.insert(publication.situation.capsule.decision_fingerprint()?);
    children.insert(publication.resource_state.state_digest());
    children.insert(publication.control_envelope.control_digest());
    children.insert(publication.context_pack.pack_digest);
    children.insert(publication.compression_receipt.receipt_digest());
    let handoff = HandoffCapsule::publish(HandoffPublishParams {
        handoff_id,
        mission_id: publication.situation.capsule.mission_id.clone(),
        source_session_id: publication.situation.capsule.session_id.clone(),
        source_principal_id: publication.situation.capsule.principal_id.clone(),
        anchor: publication.situation.capsule.anchor.clone(),
        situation_capsule_root: publication_root,
        child_roots: children,
        contract_basis: publication.situation.capsule.contract_basis.clone(),
        created_at,
        expires_at,
    })?;
    handoff.verify()?;
    Ok(handoff)
}

#[derive(Clone, Debug)]
struct ContextCandidate {
    item: ContextItem,
    critical: bool,
    priority: u8,
}

/// Typed record explaining why a redundant context candidate was dropped in favor of a retained representative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedundancyRecord {
    /// Identifier of the candidate that was dropped.
    pub dropped_item_id: String,
    /// Identifier of the retained representative candidate.
    pub retained_item_id: String,
    /// Semantic class of the item (e.g., "contradiction", "at_risk").
    pub kind: String,
    /// Explanatory reason for redundancy removal.
    pub reason: String,
}

#[derive(Clone, Debug)]
struct ContextSelection {
    selected: Vec<ContextItem>,
    omitted: Vec<ContextItem>,
    critical_count: usize,
    frontier_digest: ContentDigest,
    redundancy_records: Vec<RedundancyRecord>,
}

fn select_context(
    situation: &ReferenceSituation,
    target_tokens: u64,
) -> Result<ContextSelection, ReferenceError> {
    let (mut candidates, redundancy_records) = context_candidates(situation)?;
    candidates.sort_by(|left, right| {
        (!left.critical, left.priority, left.item.item_id.as_str()).cmp(&(
            !right.critical,
            right.priority,
            right.item.item_id.as_str(),
        ))
    });
    let frontier_digest = context_frontier_digest(&candidates);
    let critical_count = candidates.iter().filter(|item| item.critical).count();
    let mut selected: Vec<ContextItem> = candidates
        .iter()
        .filter(|candidate| candidate.critical)
        .map(|candidate| candidate.item.clone())
        .collect();
    if reference_token_count(&selected) > target_tokens {
        return Err(ContractError::BudgetExhausted.into());
    }
    let mut omitted = Vec::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| !candidate.critical)
    {
        let mut trial = selected.clone();
        trial.push(candidate.item.clone());
        if reference_token_count(&trial) <= target_tokens {
            selected.push(candidate.item);
        } else {
            omitted.push(candidate.item);
        }
    }
    selected.sort_by(|left, right| left.item_id.cmp(&right.item_id));
    omitted.sort_by(|left, right| left.item_id.cmp(&right.item_id));

    // INV-092: Context selection may remove redundancy but must not remove protected
    // high-loss worlds, contradictions, or required warnings.
    for item in &omitted {
        if matches!(
            item.kind.as_str(),
            "protected_world"
                | "contradiction"
                | "at_risk"
                | "hard_clamp"
                | "obligation"
                | "epistemic_boundary"
        ) {
            return Err(ContractError::EvidenceRequired.into());
        }
    }

    Ok(ContextSelection {
        selected,
        omitted,
        critical_count,
        frontier_digest,
        redundancy_records,
    })
}

fn context_candidates(
    situation: &ReferenceSituation,
) -> Result<(Vec<ContextCandidate>, Vec<RedundancyRecord>), ReferenceError> {
    let capsule = &situation.capsule;
    let frame = &capsule.frame;
    let mut candidates: BTreeMap<String, ContextCandidate> = BTreeMap::new();
    let mut redundancy: Vec<RedundancyRecord> = Vec::new();
    let summary = frame
        .now
        .first()
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("frame.now must not be empty"))?;
    insert_candidate(
        &mut candidates,
        &mut redundancy,
        ContextCandidate {
            item: ContextItem {
                item_id: "context:frame:summary".to_owned(),
                kind: "frame".to_owned(),
                epistemic_state: KnowledgeState::Known,
                content: summary,
                basis: BTreeSet::from([
                    frame.frame_id.clone(),
                    frame.world_envelope.envelope_id.clone(),
                ]),
                expansion_handles: BTreeSet::new(),
            },
            critical: true,
            priority: 0,
        },
    )?;

    for statement in &frame.at_risk {
        insert_statement(
            &mut candidates,
            &mut redundancy,
            StatementCandidateSpec {
                id_class: "at-risk",
                kind: "at_risk",
                state: KnowledgeState::Indeterminate,
                statement,
                frame_id: &frame.frame_id,
                critical: true,
                priority: 0,
            },
        )?;
    }
    for statement in &frame.unknown {
        insert_statement(
            &mut candidates,
            &mut redundancy,
            StatementCandidateSpec {
                id_class: "unknown",
                kind: "unknown",
                state: KnowledgeState::Unknown,
                statement,
                frame_id: &frame.frame_id,
                critical: true,
                priority: 0,
            },
        )?;
    }
    for statement in &frame.changed {
        insert_statement(
            &mut candidates,
            &mut redundancy,
            StatementCandidateSpec {
                id_class: "changed",
                kind: "changed",
                state: KnowledgeState::Known,
                statement,
                frame_id: &frame.frame_id,
                critical: true,
                priority: 1,
            },
        )?;
    }
    for obligation in &capsule.obligations {
        insert_candidate(
            &mut candidates,
            &mut redundancy,
            ContextCandidate {
                item: ContextItem {
                    item_id: format!("context:obligation:{obligation}"),
                    kind: "obligation".to_owned(),
                    epistemic_state: KnowledgeState::Indeterminate,
                    content: format!(
                        "Terminal-proof obligation {obligation} remains active in this situation."
                    ),
                    basis: BTreeSet::from([obligation.to_string()]),
                    expansion_handles: BTreeSet::new(),
                },
                critical: true,
                priority: 0,
            },
        )?;
    }
    for next in &frame.next {
        let affordance = capsule
            .affordances
            .iter()
            .find(|candidate| candidate.affordance_id == *next)
            .ok_or(ContractError::NotFound)?;
        let mut basis = affordance.supported_worlds.clone();
        basis.insert(affordance.affordance_id.clone());
        basis.insert(affordance.target.clone());
        insert_candidate(
            &mut candidates,
            &mut redundancy,
            ContextCandidate {
                item: ContextItem {
                    item_id: format!("context:affordance:{}", affordance.affordance_id),
                    kind: "next_affordance".to_owned(),
                    epistemic_state: KnowledgeState::Known,
                    content: format!("{}: {}", affordance.operation, affordance.rationale),
                    basis,
                    expansion_handles: BTreeSet::new(),
                },
                critical: true,
                priority: 0,
            },
        )?;
    }
    for affordance in &capsule.affordances {
        if affordance.class == AffordanceClass::Unavailable
            || affordance.class == AffordanceClass::Blocked
        {
            let mut basis = affordance.supported_worlds.clone();
            basis.insert(affordance.affordance_id.clone());
            basis.insert(affordance.target.clone());
            basis.extend(affordance.required_capabilities.clone());
            insert_candidate(
                &mut candidates,
                &mut redundancy,
                ContextCandidate {
                    item: ContextItem {
                        item_id: format!("context:hard_clamp:{}", affordance.affordance_id),
                        kind: "hard_clamp".to_owned(),
                        epistemic_state: KnowledgeState::Known,
                        content: format!("{}: {}", affordance.operation, affordance.rationale),
                        basis,
                        expansion_handles: BTreeSet::new(),
                    },
                    critical: true,
                    priority: 0,
                },
            )?;
        }
    }
    for world in frame
        .world_envelope
        .alternatives
        .iter()
        .chain(frame.world_envelope.adversarial_residuals.iter())
        .filter(|world| world.protected || world.consequence_severity >= 4)
    {
        let mut basis = world.claim_ids.clone();
        basis.insert(world.world_id.clone());
        basis.extend(world.evidence.iter().map(ToString::to_string));
        insert_candidate(
            &mut candidates,
            &mut redundancy,
            ContextCandidate {
                item: ContextItem {
                    item_id: format!("context:world:{}", world.world_id),
                    kind: "protected_world".to_owned(),
                    epistemic_state: KnowledgeState::Estimated,
                    content: world.description.clone(),
                    basis,
                    expansion_handles: BTreeSet::new(),
                },
                critical: true,
                priority: 0,
            },
        )?;
    }
    let mut seen_contradictions: Vec<(&KnowledgeCell, String)> = Vec::new();
    for cell in &frame.knowledge_cells {
        if !cell.contradictions.is_empty() {
            let item_id = format!("context:contradiction:{}", cell.claim_id);
            if let Some((_, prev_item_id)) = seen_contradictions.iter().find(|(c, _)| {
                same_disclosed_statement(c, cell) && c.contradictions == cell.contradictions
            }) {
                if let Some(existing) = candidates.get_mut(prev_item_id) {
                    existing.item.basis.insert(cell.claim_id.clone());
                    existing
                        .item
                        .basis
                        .extend(cell.evidence.iter().map(ToString::to_string));
                }
                let dropped_item_id = if item_id == *prev_item_id {
                    let duplicate_count = redundancy
                        .iter()
                        .filter(|r| r.retained_item_id == *prev_item_id)
                        .count()
                        + 1;
                    format!("{item_id}:duplicate:{duplicate_count}")
                } else {
                    item_id
                };
                redundancy.push(RedundancyRecord {
                    dropped_item_id,
                    retained_item_id: prev_item_id.clone(),
                    kind: "contradiction".to_owned(),
                    reason: "duplicate contradiction with identical statement and contradicting evidence roots; retained earlier representative with merged evidence basis".to_owned(),
                });
            } else {
                seen_contradictions.push((cell, item_id.clone()));
                let mut basis = BTreeSet::from([cell.claim_id.clone()]);
                basis.extend(cell.evidence.iter().map(ToString::to_string));
                basis.extend(cell.contradictions.iter().map(ToString::to_string));
                insert_candidate(
                    &mut candidates,
                    &mut redundancy,
                    ContextCandidate {
                        item: ContextItem {
                            item_id,
                            kind: "contradiction".to_owned(),
                            epistemic_state: KnowledgeState::Conflicted,
                            content: cell.disclosable_statement().to_owned(),
                            basis,
                            expansion_handles: BTreeSet::new(),
                        },
                        critical: true,
                        priority: 0,
                    },
                )?;
            }
        }
    }
    let mut seen_epistemic: Vec<(&KnowledgeCell, String)> = Vec::new();
    for cell in &frame.knowledge_cells {
        if cell_state_lane(cell) == CellStateLane::EpistemicBoundary {
            let item_id = format!("context:epistemic:{}", cell.claim_id);
            if let Some((_, prev_item_id)) = seen_epistemic.iter().find(|(c, _)| {
                same_disclosed_statement(c, cell)
                    && c.knowledge_state == cell.knowledge_state
                    && c.evidence == cell.evidence
                    && c.contradictions == cell.contradictions
            }) {
                redundancy.push(RedundancyRecord {
                    dropped_item_id: item_id,
                    retained_item_id: prev_item_id.clone(),
                    kind: "epistemic_boundary".to_owned(),
                    reason: "duplicate epistemic boundary with identical statement and evidence roots; retained earlier representative".to_owned(),
                });
            } else {
                seen_epistemic.push((cell, item_id.clone()));
                let mut basis = BTreeSet::from([cell.claim_id.clone()]);
                basis.extend(cell.evidence.iter().map(ToString::to_string));
                basis.extend(cell.contradictions.iter().map(ToString::to_string));
                insert_candidate(
                    &mut candidates,
                    &mut redundancy,
                    ContextCandidate {
                        item: ContextItem {
                            item_id,
                            kind: "epistemic_boundary".to_owned(),
                            epistemic_state: cell.knowledge_state,
                            content: cell.disclosable_statement().to_owned(),
                            basis,
                            expansion_handles: BTreeSet::new(),
                        },
                        critical: true,
                        priority: 0,
                    },
                )?;
            }
        }
    }

    for statement in &frame.now {
        insert_statement(
            &mut candidates,
            &mut redundancy,
            StatementCandidateSpec {
                id_class: "now",
                kind: "now",
                state: KnowledgeState::Known,
                statement,
                frame_id: &frame.frame_id,
                critical: false,
                priority: 2,
            },
        )?;
    }
    for statement in &frame.why {
        insert_statement(
            &mut candidates,
            &mut redundancy,
            StatementCandidateSpec {
                id_class: "why",
                kind: "why",
                state: KnowledgeState::Estimated,
                statement,
                frame_id: &frame.frame_id,
                critical: false,
                priority: 3,
            },
        )?;
    }
    let mut seen_knowledge: Vec<(&KnowledgeCell, String)> = Vec::new();
    for cell in &frame.knowledge_cells {
        if cell_state_lane(cell) == CellStateLane::Knowledge {
            let item_id = format!("context:knowledge:{}", cell.claim_id);
            if let Some((_, prev_item_id)) = seen_knowledge.iter().find(|(c, _)| {
                same_disclosed_statement(c, cell)
                    && c.knowledge_state == cell.knowledge_state
                    && c.evidence == cell.evidence
            }) {
                let dropped_item_id = if item_id == *prev_item_id {
                    let duplicate_count = redundancy
                        .iter()
                        .filter(|r| r.retained_item_id == *prev_item_id)
                        .count()
                        + 1;
                    format!("{item_id}:duplicate:{duplicate_count}")
                } else {
                    item_id
                };
                redundancy.push(RedundancyRecord {
                    dropped_item_id,
                    retained_item_id: prev_item_id.clone(),
                    kind: "knowledge".to_owned(),
                    reason: "duplicate knowledge proposition with identical statement and evidence roots; retained earlier representative".to_owned(),
                });
            } else {
                seen_knowledge.push((cell, item_id.clone()));
                let mut basis = BTreeSet::from([cell.claim_id.clone()]);
                basis.extend(cell.evidence.iter().map(ToString::to_string));
                insert_candidate(
                    &mut candidates,
                    &mut redundancy,
                    ContextCandidate {
                        item: ContextItem {
                            item_id,
                            kind: "knowledge".to_owned(),
                            epistemic_state: cell.knowledge_state,
                            content: cell.disclosable_statement().to_owned(),
                            basis,
                            expansion_handles: BTreeSet::new(),
                        },
                        critical: false,
                        priority: 4,
                    },
                )?;
            }
        }
    }
    // KSTATE-009: a not_applicable proposition is carried as its own optional kind so it is never
    // aggregated with, or mistaken for, false or missing knowledge. Budget pressure can omit it,
    // but only through the receipted Truncate/omitted-class/expansion-handle path, and exact
    // duplicates leave a redundancy record; it never vanishes silently.
    let mut seen_not_applicable: Vec<(&KnowledgeCell, String)> = Vec::new();
    for cell in &frame.knowledge_cells {
        if cell_state_lane(cell) == CellStateLane::NotApplicable {
            let item_id = format!("context:not_applicable:{}", cell.claim_id);
            if let Some((_, prev_item_id)) = seen_not_applicable.iter().find(|(c, _)| {
                same_disclosed_statement(c, cell)
                    && c.evidence == cell.evidence
                    && c.contradictions == cell.contradictions
            }) {
                let dropped_item_id = if item_id == *prev_item_id {
                    let duplicate_count = redundancy
                        .iter()
                        .filter(|r| r.retained_item_id == *prev_item_id)
                        .count()
                        + 1;
                    format!("{item_id}:duplicate:{duplicate_count}")
                } else {
                    item_id
                };
                redundancy.push(RedundancyRecord {
                    dropped_item_id,
                    retained_item_id: prev_item_id.clone(),
                    kind: "not_applicable".to_owned(),
                    reason: "duplicate not_applicable proposition with identical statement and evidence roots; retained earlier representative".to_owned(),
                });
            } else {
                seen_not_applicable.push((cell, item_id.clone()));
                let mut basis = BTreeSet::from([cell.claim_id.clone()]);
                basis.extend(cell.evidence.iter().map(ToString::to_string));
                basis.extend(cell.contradictions.iter().map(ToString::to_string));
                insert_candidate(
                    &mut candidates,
                    &mut redundancy,
                    ContextCandidate {
                        item: ContextItem {
                            item_id,
                            kind: "not_applicable".to_owned(),
                            epistemic_state: KnowledgeState::NotApplicable,
                            content: cell.disclosable_statement().to_owned(),
                            basis,
                            expansion_handles: BTreeSet::new(),
                        },
                        critical: false,
                        priority: 4,
                    },
                )?;
            }
        }
    }
    for world in frame
        .world_envelope
        .alternatives
        .iter()
        .chain(frame.world_envelope.adversarial_residuals.iter())
        .filter(|world| !world.protected && world.consequence_severity < 4)
    {
        let mut basis = world.claim_ids.clone();
        basis.insert(world.world_id.clone());
        basis.extend(world.evidence.iter().map(ToString::to_string));
        insert_candidate(
            &mut candidates,
            &mut redundancy,
            ContextCandidate {
                item: ContextItem {
                    item_id: format!("context:world:{}", world.world_id),
                    kind: "possible_world".to_owned(),
                    epistemic_state: KnowledgeState::Estimated,
                    content: world.description.clone(),
                    basis,
                    expansion_handles: BTreeSet::new(),
                },
                critical: false,
                priority: 5,
            },
        )?;
    }
    for handle in &frame.evidence_handles {
        insert_candidate(
            &mut candidates,
            &mut redundancy,
            ContextCandidate {
                item: ContextItem {
                    item_id: format!(
                        "context:evidence:{}",
                        ContentDigest::sha256(handle.as_bytes())
                    ),
                    kind: "evidence_handle".to_owned(),
                    epistemic_state: KnowledgeState::Known,
                    content: format!("Hydratable evidence handle {handle}."),
                    basis: BTreeSet::from([handle.clone()]),
                    expansion_handles: BTreeSet::from([handle.clone()]),
                },
                critical: false,
                priority: 6,
            },
        )?;
    }

    Ok((candidates.into_values().collect(), redundancy))
}

/// Context lane that a knowledge cell's own knowledge state routes it to.
///
/// A cell carrying contradicting roots is additionally projected as a critical `contradiction`
/// item; the lane below decides where its knowledge state itself lands. The classifier is an
/// exhaustive match so a new `KnowledgeState` cannot silently vanish from the context pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CellStateLane {
    /// Critical epistemic boundary item.
    EpistemicBoundary,
    /// Optional known/estimated knowledge item.
    Knowledge,
    /// Optional `not_applicable` item (KSTATE-009), kept distinct from knowledge and boundaries.
    NotApplicable,
    /// Conflicted cell whose state is already carried by its critical contradiction item.
    ContradictionItem,
}

/// Returns whether two cells carry the same disclosed statement for deduplication.
///
/// A withheld statement is never compared: equality of redacted content is itself a disclosure,
/// so a cell that withholds its statement is never a duplicate of any other cell, whatever the
/// two withheld statements are.
fn same_disclosed_statement(left: &KnowledgeCell, right: &KnowledgeCell) -> bool {
    !left.withholds_statement() && !right.withholds_statement() && left.statement == right.statement
}

fn cell_state_lane(cell: &KnowledgeCell) -> CellStateLane {
    match cell.knowledge_state {
        // Admissible or model-supported propositions.
        KnowledgeState::Known | KnowledgeState::Estimated => CellStateLane::Knowledge,
        // Non-known states that bound what the agent may conclude: never optional.
        KnowledgeState::Unknown
        | KnowledgeState::Stale
        | KnowledgeState::NotObservable
        | KnowledgeState::Redacted
        | KnowledgeState::Indeterminate => CellStateLane::EpistemicBoundary,
        // A conflicted cell with contradicting roots is projected once, as a contradiction; one
        // without roots is still a conflict boundary.
        KnowledgeState::Conflicted => {
            if cell.contradictions.is_empty() {
                CellStateLane::EpistemicBoundary
            } else {
                CellStateLane::ContradictionItem
            }
        }
        // The proposition has no meaning for this scope: carried explicitly, not aggregated.
        KnowledgeState::NotApplicable => CellStateLane::NotApplicable,
    }
}

struct StatementCandidateSpec<'a> {
    id_class: &'a str,
    kind: &'a str,
    state: KnowledgeState,
    statement: &'a str,
    frame_id: &'a str,
    critical: bool,
    priority: u8,
}

fn insert_statement(
    candidates: &mut BTreeMap<String, ContextCandidate>,
    redundancy: &mut Vec<RedundancyRecord>,
    spec: StatementCandidateSpec<'_>,
) -> Result<(), ReferenceError> {
    let item_id = format!(
        "context:{}:{}",
        spec.id_class,
        ContentDigest::sha256(spec.statement.as_bytes())
    );
    insert_candidate(
        candidates,
        redundancy,
        ContextCandidate {
            item: ContextItem {
                item_id,
                kind: spec.kind.to_owned(),
                epistemic_state: spec.state,
                content: spec.statement.to_owned(),
                basis: BTreeSet::from([spec.frame_id.to_owned()]),
                expansion_handles: BTreeSet::new(),
            },
            critical: spec.critical,
            priority: spec.priority,
        },
    )
}

fn insert_candidate(
    candidates: &mut BTreeMap<String, ContextCandidate>,
    redundancy: &mut Vec<RedundancyRecord>,
    candidate: ContextCandidate,
) -> Result<(), ReferenceError> {
    candidate.item.validate()?;
    match candidates.get(&candidate.item.item_id) {
        Some(existing) if existing.item == candidate.item => {
            let duplicate_count = redundancy
                .iter()
                .filter(|r| r.retained_item_id == existing.item.item_id)
                .count()
                + 1;
            let dropped_item_id =
                format!("{}:duplicate:{}", candidate.item.item_id, duplicate_count);
            redundancy.push(RedundancyRecord {
                dropped_item_id,
                retained_item_id: existing.item.item_id.clone(),
                kind: candidate.item.kind.clone(),
                reason: format!("duplicate exact {} item", candidate.item.kind),
            });
            Ok(())
        }
        Some(_) => Err(ContractError::IdempotencyConflict.into()),
        None => {
            candidates.insert(candidate.item.item_id.clone(), candidate);
            Ok(())
        }
    }
}

/// Returns the required critical context item identities for the situation, or error if candidates cannot be computed.
///
/// The situation is verified first, so a capsule refused by [`ReferenceSituation::verify`] (for
/// example a frame carrying a basisless stale, indeterminate, or redacted cell) yields exactly
/// that typed refusal instead of a candidate set built from an invalid capsule.
pub fn required_context_item_ids(
    situation: &ReferenceSituation,
) -> Result<BTreeSet<String>, ReferenceError> {
    situation.verify()?;
    context_candidates(situation).map(|(candidates, _)| {
        candidates
            .into_iter()
            .filter(|candidate| candidate.critical)
            .map(|candidate| candidate.item.item_id)
            .collect()
    })
}

fn context_frontier_digest(candidates: &[ContextCandidate]) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_context_frontier.v1");
    let mut candidates = candidates.to_vec();
    candidates.sort_by(|left, right| left.item.item_id.cmp(&right.item.item_id));
    encoder.u64(candidates.len() as u64);
    for candidate in &candidates {
        encoder.bool(candidate.critical);
        encoder.u8(candidate.priority);
        candidate.item.encode_canonical(&mut encoder);
    }
    ContentDigest::sha256(&encoder.finish())
}

fn compression_completeness(
    selected: &[ContextItem],
    omitted: &[ContextItem],
) -> Vec<CompressionCompleteness> {
    let mut counts: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for item in selected {
        counts.entry(item.kind.clone()).or_default().0 += 1;
    }
    for item in omitted {
        counts.entry(item.kind.clone()).or_default().1 += 1;
    }
    counts
        .into_iter()
        .map(
            |(domain, (_selected, omitted_count))| CompressionCompleteness {
                domain,
                state: if omitted_count == 0 {
                    Completeness::Complete
                } else {
                    Completeness::Bounded
                },
                omitted_count,
            },
        )
        .collect()
}

fn expansion_handles(
    pack_id: &str,
    omitted_classes: &BTreeSet<String>,
) -> Result<Vec<ExpansionHandle>, ReferenceError> {
    let mut handles = Vec::with_capacity(omitted_classes.len());
    for class in omitted_classes {
        let estimated_cost = BudgetVector::builder()
            .latency_ms(100)
            .tokens(1_024)
            .bytes(16_384)
            .cpu_millis(10)
            .storage_operations(1)
            .privacy_exposure(0.1)
            .build()
            .map_err(|_| ReferenceError::InvalidSpec("expansion_handle_cost"))?;
        handles.push(ExpansionHandle {
            handle: format!(
                "context-expand:{}",
                ContentDigest::sha256(format!("{pack_id}:{class}").as_bytes())
            ),
            purpose: format!("Hydrate optional omitted {class} context."),
            estimated_cost,
        });
    }
    Ok(handles)
}

/// Projection identity over the decision fingerprint of an already-verified situation.
fn projection_identity(
    situation_fingerprint: ContentDigest,
    spec: &ReferenceProjectionSpec,
    frontier_digest: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_projection_identity.v1");
    encoder.digest(situation_fingerprint);
    encoder.digest(spec.spec_digest());
    encoder.digest(frontier_digest);
    ContentDigest::sha256(&encoder.finish())
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    value.encode_to_canonical(encoder);
}

#[cfg(test)]
#[path = "situation_sections_dedup_tests.rs"]
mod dedup_tests;
