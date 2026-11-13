#![forbid(unsafe_code)]
//! Exact H0/H1 event metadata rebuilt from a verified, current deployment snapshot.
//!
//! This pure compiler does not authenticate callers or read storage. Its caller owns the
//! immutable metadata read, current privacy/deletion admission, final revalidation and durable
//! session disclosure. Existing event revision handles select an exact immutable subject; the
//! resulting native semantic handle never silently follows a newer event revision.
//!
//! H1 describes the retained record and its bounded native explanation. A fact about a recorded
//! claim is not that claim: original unknown, conflicted and indeterminate cells remain in the
//! returned explanation. Source evidence is neither opened nor declared currently available.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractError, EventId, Generation, H0Identity,
    H1ContentSpec, H1SemanticSynopsis, HandleAvailability, HydrationArtifact, HydrationError,
    HydrationLevel, KnowledgeState, LaboratoryAccess, OmissionReason, ProvenanceClass,
    SemanticHandle, SemanticHandleSpec, SynopsisClassification, SynopsisQuality, TimestampNs,
    WorldFact, WorldFactKind, reference_contract_basis,
};

use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, EventExplanation, OrientError, explain_event,
};
use crate::{ReferenceHydrationCatalog, ReferenceHydrationLimits};

/// Registered metadata hydration grant; no source-media or effect authority is implied.
pub const EVENT_HYDRATION_CAPABILITY: &str = "CAP-AGENT-EVIDENCE-HYDRATE-001";
/// Registered query grant required alongside metadata hydration.
pub const EVENT_HYDRATION_QUERY_CAPABILITY: &str = "CAP-AGENT-QUERY-001";
/// One shared immutable payload byte allowance, including final metadata revalidation.
pub const MAX_EVENT_HYDRATION_READ_BYTES: usize = 256 * 1024 * 1024;
/// One shared immutable payload read-attempt allowance, including final revalidation.
pub const MAX_EVENT_HYDRATION_READ_OBJECTS: usize = 65_536;
/// Conservative H0 response quote, matching the existing case-view token ceiling.
pub const EVENT_HYDRATION_H0_TOKENS: u64 = 5_000;
/// Conservative H1 response quote, matching the existing forensic-view token ceiling.
pub const EVENT_HYDRATION_H1_TOKENS: u64 = 16_000;
/// Maximum complete canonical H0 identity bytes.
pub const MAX_EVENT_HYDRATION_H0_BYTES: usize = 8 * 1024;
/// Maximum complete canonical H1 metadata synopsis bytes; no truncation is permitted.
pub const MAX_EVENT_HYDRATION_H1_BYTES: usize = 64 * 1024;

/// Pure metadata compilation failed. Display messages omit event IDs and retained text.
#[derive(Debug)]
pub enum EventHydrationBuildError {
    /// No current committed revision has the selected event identity.
    UnknownEvent,
    /// The selected immutable revision is no longer the current revision.
    RevisionChanged,
    /// Orientation, snapshot, contract universe or current metadata do not agree.
    BasisChanged,
    /// The event revision's own metadata is revoked by a committed deletion.
    MetadataDeleted,
    /// The authoritative descriptor lifetime does not extend past its publication time.
    Expired,
    /// The whole artifact exceeds its finite bound or the requested level is unsupported.
    Limit,
    /// Native canonical data or budget validation failed.
    Contract(ContractError),
    /// Native descriptor or hydration validation failed.
    Hydration(HydrationError),
    /// The existing native event explanation could not be compiled.
    Explanation(OrientError),
}

impl fmt::Display for EventHydrationBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownEvent => "event hydration subject is unavailable",
            Self::RevisionChanged => "event hydration revision changed",
            Self::BasisChanged => "event hydration authority basis changed",
            Self::MetadataDeleted => "event hydration metadata is deleted",
            Self::Expired => "event hydration descriptor lifetime expired",
            Self::Limit => "event hydration metadata bound exceeded",
            Self::Contract(_) => "event hydration contract refused",
            Self::Hydration(_) => "event hydration descriptor refused",
            Self::Explanation(_) => "event hydration explanation refused",
        })
    }
}
impl std::error::Error for EventHydrationBuildError {}
impl From<ContractError> for EventHydrationBuildError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<HydrationError> for EventHydrationBuildError {
    fn from(error: HydrationError) -> Self {
        Self::Hydration(error)
    }
}

/// Exact native artifacts and their complete protected interpretation.
///
/// The catalog is a freshly rebuilt descriptor authority, without consumed cursor state. The
/// sole durable disclosure owner must reconcile its existing cursor checkpoint before use.
#[derive(Clone, Debug)]
pub struct EventHydrationCatalog {
    /// Rebuilt H0/H1 native catalog, never containing original source payloads.
    pub catalog: ReferenceHydrationCatalog,
    /// Exact native semantic descriptor, including all prices and grants.
    pub descriptor: SemanticHandle,
    /// Typed H0 identity; its canonical encoding is the H0 artifact payload.
    pub identity: H0Identity,
    /// Typed H1 metadata synopsis; its canonical encoding is the H1 artifact payload.
    pub synopsis: H1SemanticSynopsis,
    /// Native cells, worlds, contradictions and warnings, without state promotion.
    pub explanation: EventExplanation,
    /// Existing query/explain revision handle that selected this immutable subject.
    pub event_handle: String,
}

/// Conservative descriptor quote. These are ceilings, not measured filesystem syscall counts.
pub fn event_hydration_cost(
    level: HydrationLevel,
) -> Result<BudgetVector, EventHydrationBuildError> {
    let tokens = match level {
        HydrationLevel::H0 => EVENT_HYDRATION_H0_TOKENS,
        HydrationLevel::H1 => EVENT_HYDRATION_H1_TOKENS,
        _ => return Err(EventHydrationBuildError::Limit),
    };
    BudgetVector::builder()
        .tokens(tokens)
        .bytes(MAX_EVENT_HYDRATION_READ_BYTES as u64)
        .storage_operations(MAX_EVENT_HYDRATION_READ_OBJECTS as u64)
        .build()
        .map_err(|error| EventHydrationBuildError::Contract(error.into()))
}

/// Rebuilds the current descriptor for one exact event revision from native metadata.
///
/// `retention_until` is supplied by the trusted session owner, not by a hydration request. The
/// builder accepts only a snapshot and orientation with identical full authority/effect anchors.
/// The caller must verify the snapshot's storage custody and revalidate it before disclosure.
pub fn build_event_hydration_catalog(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
    expected_revision: ContentDigest,
    retention_until: TimestampNs,
) -> Result<EventHydrationCatalog, EventHydrationBuildError> {
    let basis = reference_contract_basis();
    if snapshot.ledger_tail_uncommitted
        || snapshot.effect_tail_uncommitted
        || orientation.capsule().anchor != snapshot.anchor
        || orientation.capsule().contract_basis != basis
        || orientation.anchor_token != snapshot_anchor_token(snapshot)
    {
        return Err(EventHydrationBuildError::BasisChanged);
    }
    if retention_until <= snapshot.latest_evidence_time {
        return Err(EventHydrationBuildError::Expired);
    }
    let retained = snapshot
        .event(event_id)
        .ok_or(EventHydrationBuildError::UnknownEvent)?;
    if retained.revision_digest != expected_revision
        || retained.event.revision_digest() != expected_revision
        || retained.event.verify().is_err()
    {
        return Err(EventHydrationBuildError::RevisionChanged);
    }
    if snapshot.deletions.object(retained.event_root).is_some()
        || snapshot
            .deletions
            .object(retained.revision_digest)
            .is_some()
    {
        return Err(EventHydrationBuildError::MetadataDeleted);
    }
    let explanation = explain_event(snapshot, orientation, event_id)
        .map_err(EventHydrationBuildError::Explanation)?
        .ok_or(EventHydrationBuildError::UnknownEvent)?;
    if explanation.hydration.revision_digest != expected_revision {
        return Err(EventHydrationBuildError::RevisionChanged);
    }
    let event_handle = format!(
        "fss://event/{}/revision/{}",
        event_id.as_str(),
        retained.event.revision
    );
    if explanation.hydration.handle != event_handle {
        return Err(EventHydrationBuildError::BasisChanged);
    }
    let required: BTreeSet<String> = [
        EVENT_HYDRATION_CAPABILITY.to_owned(),
        EVENT_HYDRATION_QUERY_CAPABILITY.to_owned(),
    ]
    .into();
    let descriptor = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis,
        anchor: snapshot.anchor.clone(),
        subject_id: event_handle.clone(),
        subject_digest: expected_revision,
        semantic_type: "event_revision".to_owned(),
        source_id: snapshot.site_lineage.clone(),
        capture_interval: Some(retained.event.interval),
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until,
        levels: [HydrationLevel::H0, HydrationLevel::H1].into(),
        required_capabilities: BTreeMap::from([
            (HydrationLevel::H0, required.clone()),
            (HydrationLevel::H1, required),
        ]),
        estimated_costs: BTreeMap::from([
            (
                HydrationLevel::H0,
                event_hydration_cost(HydrationLevel::H0)?,
            ),
            (
                HydrationLevel::H1,
                event_hydration_cost(HydrationLevel::H1)?,
            ),
        ]),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: snapshot.latest_evidence_time,
    })?;
    let identity = descriptor.to_h0_identity()?;
    let h0 = HydrationArtifact::publish_h0_identity(&descriptor)?;
    if h0.payload.len() > MAX_EVENT_HYDRATION_H0_BYTES {
        return Err(EventHydrationBuildError::Limit);
    }
    let synopsis = descriptor.to_h1_synopsis(synopsis_content(snapshot, &explanation)?)?;
    let h1 = synopsis.to_hydration_artifact()?;
    if h1.payload.len() > MAX_EVENT_HYDRATION_H1_BYTES {
        return Err(EventHydrationBuildError::Limit);
    }
    let mut catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 1,
        max_payload_bytes: MAX_EVENT_HYDRATION_H0_BYTES + MAX_EVENT_HYDRATION_H1_BYTES,
        max_issued_cursors: 4_096,
    });
    catalog.register_descriptor(descriptor.clone())?;
    for artifact in [h0, h1] {
        catalog.register_artifact(
            &descriptor.handle_id,
            descriptor.descriptor_digest,
            artifact,
        )?;
    }
    Ok(EventHydrationCatalog {
        catalog,
        descriptor,
        identity,
        synopsis,
        explanation,
        event_handle,
    })
}

fn synopsis_content(
    snapshot: &DeploymentSnapshot,
    explanation: &EventExplanation,
) -> Result<H1ContentSpec, EventHydrationBuildError> {
    let retained = &explanation.event;
    let event = &retained.event;
    let mut facts = MetadataFacts {
        snapshot,
        revision: retained.revision_digest,
        facts: Vec::new(),
    };
    facts.add(
        "scope",
        "This synopsis describes retained event metadata and the native explanation at the stated anchor. It does not read original source evidence, establish current source availability, identify physical people or certify physical absence.",
        ProvenanceClass::Derived,
    )?;
    facts.add(
        "revision",
        &format!(
            "Event {} revision {} is recorded as kind {} in lifecycle state {} at retention commit {}. Revision digest {}; publication root {}.",
            event.event_id.as_str(), event.revision, event.kind.as_str(), event.state.as_str(),
            retained.committed_sequence, retained.revision_digest, retained.event_root
        ),
        ProvenanceClass::Observed,
    )?;
    facts.add(
        "interval",
        &format!(
            "Recorded event validity is [{}, {}] nanoseconds; this is the record's declared interval, not continuous camera coverage.",
            event.interval.earliest.0, event.interval.latest.0
        ),
        ProvenanceClass::Observed,
    )?;
    facts.add_with_evidence(
        "publication",
        &format!(
            "The verified metadata publication root is {}.",
            retained.event_root
        ),
        ProvenanceClass::Observed,
        retained.event_root,
    )?;
    facts.add(
        "recorded-probability",
        &format!(
            "The record stores probability interval [{}, {}] with calibration generation {}. This restates stored metadata and does not supply a new calibrated detection or physical-presence estimate.",
            event.probability.lower, event.probability.upper,
            event.probability.calibration_generation.map_or_else(|| "none".to_owned(), |value| value.to_text())
        ),
        ProvenanceClass::Observed,
    )?;
    if let Some(reason) = &event.uncertainty_reason {
        facts.add("uncertainty", reason, ProvenanceClass::Observed)?;
    }
    if let Some(supersedes) = event.supersedes {
        facts.add(
            "supersedes",
            &supersedes.to_text(),
            ProvenanceClass::Observed,
        )?;
    }
    for zone in &event.zone_ids {
        facts.add("zone", zone, ProvenanceClass::Observed)?;
    }
    for track in &event.track_ids {
        facts.add("track", track, ProvenanceClass::Observed)?;
    }
    for edge in &event.evidence {
        facts.add(
            "evidence-edge",
            &format!(
                "Recorded evidence {} has class {}, relation {}, supports={}, failure domain {}, capsule {}, identity {}. This is an exact recorded reference; its original payload was not read.",
                edge.digest, fss_core::event::evidence_class_as_str(edge.class), edge.relation.as_str(), edge.supports,
                edge.failure_domain,
                edge.capsule_digest.map_or_else(|| "none".to_owned(), |value| value.to_text()),
                edge.identity_digest.map_or_else(|| "none".to_owned(), |value| value.to_text())
            ),
            ProvenanceClass::Observed,
        )?;
    }
    for receipt in &event.model_receipts {
        facts.add(
            "model-receipt-reference",
            &receipt.to_text(),
            ProvenanceClass::Observed,
        )?;
    }
    facts.add(
        "policy",
        &format!(
            "Recorded policy generation {}; decision fingerprint {}; abstained={}.",
            event.decision_path.policy_generation,
            event.decision_path.fingerprint,
            event.decision_path.abstained
        ),
        ProvenanceClass::Observed,
    )?;
    if let Some(reason) = &event.decision_path.abstention_reason {
        facts.add("abstention-reason", reason, ProvenanceClass::Observed)?;
    }
    for cell in &explanation.cells {
        facts.add(
            "claim-state",
            &format!(
                "Native claim {} has recorded knowledge state {}, provenance {}, hypothesis {}, and exact cell digest {}. This reports the claim's state, not its physical truth.",
                cell.claim_id(), cell.knowledge_state().as_str(), cell.provenance().as_str(),
                cell.hypothesis().map_or("none", |value| value.as_str()), cell.cell_digest()
            ),
            ProvenanceClass::Derived,
        )?;
        facts.add(
            "claim-statement",
            &format!("{}: {}", cell.claim_id(), cell.disclosable_statement()),
            ProvenanceClass::Derived,
        )?;
        for digest in cell.evidence_digests() {
            facts.add(
                "claim-evidence",
                &format!("{} cites {}.", cell.claim_id(), digest),
                ProvenanceClass::Derived,
            )?;
        }
        for digest in cell.contradictions() {
            facts.add(
                "claim-contradiction",
                &format!(
                    "{} retains contradicting evidence {}.",
                    cell.claim_id(),
                    digest
                ),
                ProvenanceClass::Derived,
            )?;
        }
    }
    for world in &explanation.worlds {
        facts.add(
            "world",
            &format!(
                "Native world {} has consequence severity {}, protected={}, adversarial_residual={}. It remains an alternative, not an observed physical fact. {}",
                world.world_id, world.consequence_severity, world.protected,
                explanation.residual_ids.contains(&world.world_id), world.description
            ),
            ProvenanceClass::Derived,
        )?;
        for claim in &world.claim_ids {
            facts.add(
                "world-claim",
                &format!("{} references {}.", world.world_id, claim),
                ProvenanceClass::Derived,
            )?;
        }
        for digest in &world.evidence {
            facts.add(
                "world-evidence",
                &format!("{} references {}.", world.world_id, digest),
                ProvenanceClass::Derived,
            )?;
        }
    }
    for (category, values) in [
        ("assumption", &explanation.assumptions),
        ("warning", &explanation.warnings),
        ("would-change", &explanation.would_change),
    ] {
        for value in values {
            facts.add(category, value, ProvenanceClass::Derived)?;
        }
    }
    let provenance_classes = facts.facts.iter().map(|fact| fact.provenance).collect();
    // These states describe metadata facts only. The original physical claim's richer typed
    // basis is preserved without conversion in `EventHydrationCatalog::explanation`.
    let knowledge_states = facts
        .facts
        .iter()
        .map(|fact| {
            if fact.provenance == ProvenanceClass::Observed {
                KnowledgeState::Known
            } else {
                KnowledgeState::Estimated
            }
        })
        .collect();
    Ok(H1ContentSpec {
        facts: facts.facts,
        knowledge_states,
        provenance_classes,
        contradictions: Vec::new(),
        // Exact metadata timestamps have no rounding. This is not a physical timing or
        // detection-quality calibration; neither a belief interval nor calibration is asserted.
        quality: SynopsisQuality::new(Completeness::Complete, None, 0, None)?,
        omissions: [OmissionReason::CapabilityFiltered].into(),
        classification: Some(SynopsisClassification::SemanticSynopsis),
    })
}

struct MetadataFacts<'a> {
    snapshot: &'a DeploymentSnapshot,
    revision: ContentDigest,
    facts: Vec<WorldFact>,
}
impl MetadataFacts<'_> {
    fn add(
        &mut self,
        category: &str,
        value: &str,
        provenance: ProvenanceClass,
    ) -> Result<(), EventHydrationBuildError> {
        self.add_with_evidence(category, value, provenance, self.revision)
    }

    fn add_with_evidence(
        &mut self,
        category: &str,
        value: &str,
        provenance: ProvenanceClass,
        evidence: ContentDigest,
    ) -> Result<(), EventHydrationBuildError> {
        // WorldFact's native statement bound is 512 bytes. Split complete text at UTF-8
        // boundaries, name every part, and refuse the whole artifact if the fact limit is hit.
        const CHUNK_BYTES: usize = 360;
        let mut chunks = Vec::new();
        let mut remainder = value;
        while !remainder.is_empty() {
            let mut end = remainder.len().min(CHUNK_BYTES);
            while !remainder.is_char_boundary(end) {
                end -= 1;
            }
            chunks.push(&remainder[..end]);
            remainder = &remainder[end..];
        }
        if chunks.is_empty() {
            chunks.push("");
        }
        if self.facts.len().saturating_add(chunks.len()) > fss_core::hydration::MAX_H1_FACTS {
            return Err(EventHydrationBuildError::Limit);
        }
        for (part, chunk) in chunks.iter().enumerate() {
            let number = self.facts.len();
            self.facts.push(WorldFact::new(
                format!("fact:event-hydration:{}:{number:04}", self.revision),
                WorldFactKind::Archive,
                self.snapshot.anchor.clone(),
                format!(
                    "Retained event metadata ({category}, part {}/{}): {chunk}",
                    part + 1,
                    chunks.len()
                ),
                provenance,
                evidence,
                Generation(1),
            )?);
        }
        Ok(())
    }
}
