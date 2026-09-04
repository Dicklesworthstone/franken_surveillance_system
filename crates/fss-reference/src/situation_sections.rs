//! Proof-bearing resource, control, context, and compression sections for reference situations.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, CompressionCompleteness,
    CompressionLossClass, CompressionStopReason, CompressionTransform, CompressionTransformKind,
    ContentDigest, ContextItem, ContractError, ControlEnvelope, CriticalPreservation,
    ExpansionHandle, HandoffCapsule, HandoffId, KnowledgeState, OperationReceipt, ResourcePressure,
    ResourceState, SemanticCompressionReceipt, SemanticContextPack, TimestampNs,
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
            || self.target_tokens > self.available_resources.tokens
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
                != self.situation.capsule.frame.frame_digest()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let required = required_context_item_ids(&self.situation);
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
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let computed = self.computed_digest();
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
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_situation_publication.v1");
        encoder.digest(self.situation.capsule.decision_fingerprint());
        self.resource_state.encode_canonical(&mut encoder);
        self.control_envelope.encode_canonical(&mut encoder);
        self.context_pack.encode_canonical(&mut encoder);
        self.compression_receipt.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
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
    let identity = projection_identity(&situation, spec, selection.frontier_digest);
    let receipt_id = format!("compression:{identity}");
    let continuation = if selection.omitted.is_empty() {
        None
    } else {
        Some(format!("continuation:context:{identity}"))
    };
    let context_pack = SemanticContextPack::publish(
        format!("context-pack:{identity}"),
        situation.capsule.contract_basis.clone(),
        situation.capsule.mission_id.clone(),
        situation.capsule.session_id.clone(),
        spec.view_id.clone(),
        situation.capsule.anchor.clone(),
        situation.capsule.frame.frame_digest(),
        selection.selected.clone(),
        receipt_id.clone(),
        continuation,
        situation.capsule.created_at,
    )?;
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
    let expansion_handles = expansion_handles(&context_pack.pack_id, &omitted_classes);
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
    publication.publication_digest = publication.computed_digest();
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
    let mut children = publication.situation.proof_roots.clone();
    children.insert(publication.situation.capsule.decision_fingerprint());
    children.insert(publication.resource_state.state_digest());
    children.insert(publication.control_envelope.control_digest());
    children.insert(publication.context_pack.pack_digest);
    children.insert(publication.compression_receipt.receipt_digest());
    let handoff = HandoffCapsule::publish(
        handoff_id,
        publication.situation.capsule.mission_id.clone(),
        publication.situation.capsule.session_id.clone(),
        publication.situation.capsule.principal_id.clone(),
        publication.situation.capsule.anchor.clone(),
        publication_root,
        children,
        publication.situation.capsule.contract_basis.clone(),
        created_at,
        expires_at,
    )?;
    handoff.verify()?;
    Ok(handoff)
}

#[derive(Clone, Debug)]
struct ContextCandidate {
    item: ContextItem,
    critical: bool,
    priority: u8,
}

#[derive(Clone, Debug)]
struct ContextSelection {
    selected: Vec<ContextItem>,
    omitted: Vec<ContextItem>,
    critical_count: usize,
    frontier_digest: ContentDigest,
}

fn select_context(
    situation: &ReferenceSituation,
    target_tokens: u64,
) -> Result<ContextSelection, ReferenceError> {
    let mut candidates = context_candidates(situation)?;
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
    Ok(ContextSelection {
        selected,
        omitted,
        critical_count,
        frontier_digest,
    })
}

fn context_candidates(
    situation: &ReferenceSituation,
) -> Result<Vec<ContextCandidate>, ReferenceError> {
    let capsule = &situation.capsule;
    let frame = &capsule.frame;
    let mut candidates: BTreeMap<String, ContextCandidate> = BTreeMap::new();
    let summary = frame.now.first().cloned().unwrap_or_else(|| {
        format!(
            "Situation at authority commit {}.",
            capsule.anchor.commit_sequence
        )
    });
    insert_candidate(
        &mut candidates,
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
            "at-risk",
            "at_risk",
            KnowledgeState::Indeterminate,
            statement,
            &frame.frame_id,
            true,
            0,
        )?;
    }
    for statement in &frame.unknown {
        insert_statement(
            &mut candidates,
            "unknown",
            "unknown",
            KnowledgeState::Unknown,
            statement,
            &frame.frame_id,
            true,
            0,
        )?;
    }
    for statement in &frame.changed {
        insert_statement(
            &mut candidates,
            "changed",
            "changed",
            KnowledgeState::Known,
            statement,
            &frame.frame_id,
            true,
            1,
        )?;
    }
    for obligation in &capsule.obligations {
        insert_candidate(
            &mut candidates,
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
    for world in frame
        .world_envelope
        .alternatives
        .iter()
        .chain(frame.world_envelope.adversarial_residuals.iter())
        .filter(|world| world.protected)
    {
        let mut basis = world.claim_ids.clone();
        basis.extend(world.evidence.iter().map(ToString::to_string));
        insert_candidate(
            &mut candidates,
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
    for cell in &frame.knowledge_cells {
        if !cell.contradictions.is_empty() {
            let mut basis = BTreeSet::from([cell.claim_id.clone()]);
            basis.extend(cell.contradictions.iter().map(ToString::to_string));
            insert_candidate(
                &mut candidates,
                ContextCandidate {
                    item: ContextItem {
                        item_id: format!("context:contradiction:{}", cell.claim_id),
                        kind: "contradiction".to_owned(),
                        epistemic_state: KnowledgeState::Conflicted,
                        content: cell.statement.clone(),
                        basis,
                        expansion_handles: BTreeSet::new(),
                    },
                    critical: true,
                    priority: 0,
                },
            )?;
        }
        if matches!(
            cell.knowledge_state,
            KnowledgeState::Conflicted
                | KnowledgeState::Stale
                | KnowledgeState::NotObservable
                | KnowledgeState::Redacted
                | KnowledgeState::Indeterminate
        ) {
            let mut basis = BTreeSet::from([cell.claim_id.clone()]);
            basis.extend(cell.evidence.iter().map(ToString::to_string));
            basis.extend(cell.contradictions.iter().map(ToString::to_string));
            insert_candidate(
                &mut candidates,
                ContextCandidate {
                    item: ContextItem {
                        item_id: format!("context:epistemic:{}", cell.claim_id),
                        kind: "epistemic_boundary".to_owned(),
                        epistemic_state: cell.knowledge_state,
                        content: cell.statement.clone(),
                        basis,
                        expansion_handles: BTreeSet::new(),
                    },
                    critical: true,
                    priority: 0,
                },
            )?;
        }
    }

    for statement in &frame.now {
        insert_statement(
            &mut candidates,
            "now",
            "now",
            KnowledgeState::Known,
            statement,
            &frame.frame_id,
            false,
            2,
        )?;
    }
    for statement in &frame.why {
        insert_statement(
            &mut candidates,
            "why",
            "why",
            KnowledgeState::Estimated,
            statement,
            &frame.frame_id,
            false,
            3,
        )?;
    }
    for cell in &frame.knowledge_cells {
        if matches!(
            cell.knowledge_state,
            KnowledgeState::Known | KnowledgeState::Estimated
        ) {
            let mut basis = BTreeSet::from([cell.claim_id.clone()]);
            basis.extend(cell.evidence.iter().map(ToString::to_string));
            insert_candidate(
                &mut candidates,
                ContextCandidate {
                    item: ContextItem {
                        item_id: format!("context:knowledge:{}", cell.claim_id),
                        kind: "knowledge".to_owned(),
                        epistemic_state: cell.knowledge_state,
                        content: cell.statement.clone(),
                        basis,
                        expansion_handles: BTreeSet::new(),
                    },
                    critical: false,
                    priority: 4,
                },
            )?;
        }
    }
    for world in frame
        .world_envelope
        .alternatives
        .iter()
        .chain(frame.world_envelope.adversarial_residuals.iter())
        .filter(|world| !world.protected)
    {
        let mut basis = world.claim_ids.clone();
        basis.extend(world.evidence.iter().map(ToString::to_string));
        insert_candidate(
            &mut candidates,
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

    Ok(candidates.into_values().collect())
}

fn insert_statement(
    candidates: &mut BTreeMap<String, ContextCandidate>,
    id_class: &str,
    kind: &str,
    state: KnowledgeState,
    statement: &str,
    frame_id: &str,
    critical: bool,
    priority: u8,
) -> Result<(), ReferenceError> {
    let item_id = format!(
        "context:{id_class}:{}",
        ContentDigest::sha256(statement.as_bytes())
    );
    insert_candidate(
        candidates,
        ContextCandidate {
            item: ContextItem {
                item_id,
                kind: kind.to_owned(),
                epistemic_state: state,
                content: statement.to_owned(),
                basis: BTreeSet::from([frame_id.to_owned()]),
                expansion_handles: BTreeSet::new(),
            },
            critical,
            priority,
        },
    )
}

fn insert_candidate(
    candidates: &mut BTreeMap<String, ContextCandidate>,
    candidate: ContextCandidate,
) -> Result<(), ReferenceError> {
    candidate.item.validate()?;
    match candidates.get(&candidate.item.item_id) {
        Some(existing) if existing.item == candidate.item => Ok(()),
        Some(_) => Err(ContractError::IdempotencyConflict.into()),
        None => {
            candidates.insert(candidate.item.item_id.clone(), candidate);
            Ok(())
        }
    }
}

fn required_context_item_ids(situation: &ReferenceSituation) -> BTreeSet<String> {
    context_candidates(situation)
        .map(|candidates| {
            candidates
                .into_iter()
                .filter(|candidate| candidate.critical)
                .map(|candidate| candidate.item.item_id)
                .collect()
        })
        .unwrap_or_default()
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

fn expansion_handles(pack_id: &str, omitted_classes: &BTreeSet<String>) -> Vec<ExpansionHandle> {
    omitted_classes
        .iter()
        .map(|class| ExpansionHandle {
            handle: format!(
                "context-expand:{}",
                ContentDigest::sha256(format!("{pack_id}:{class}").as_bytes())
            ),
            purpose: format!("Hydrate optional omitted {class} context."),
            estimated_cost: BudgetVector {
                latency_ms: 100,
                tokens: 1_024,
                bytes: 16_384,
                cpu_millis: 10,
                storage_operations: 1,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
        })
        .collect()
}

fn projection_identity(
    situation: &ReferenceSituation,
    spec: &ReferenceProjectionSpec,
    frontier_digest: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_projection_identity.v1");
    encoder.digest(situation.capsule.decision_fingerprint());
    encoder.digest(spec.spec_digest());
    encoder.digest(frontier_digest);
    ContentDigest::sha256(&encoder.finish())
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    encoder.u64(value.latency_ms);
    encoder.u64(value.tokens);
    encoder.u64(value.bytes);
    encoder.u32(value.model_calls);
    encoder.u64(value.cpu_millis);
    encoder.u64(value.accelerator_millis);
    encoder.u64(value.energy_millijoules);
    encoder.u64(value.network_bytes);
    encoder.u64(value.storage_operations);
    encoder.u64(canonical_f64_bits(value.privacy_exposure));
    encoder.u64(canonical_f64_bits(value.operator_attention_seconds));
}

fn canonical_f64_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}
