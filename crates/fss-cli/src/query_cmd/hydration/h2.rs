#![forbid(unsafe_code)]
//! H2 structured analytic hydration (`CAP-AGENT-HYDRATE-H2-001`).
//!
//! Produces a bounded, anchor-pinned structured JSON projection for an exact event revision or
//! retained import without decoding any raw pixels:
//! - Track trajectories and observation boxes decoded from retained watch provenance.
//! - Detection/model receipts (`model_id`, `model_generation`, uncalibrated provenance).
//! - Failure-domain clusters and milliban LLR support structure (`calibrated: false` whenever no
//!   calibration artifact is bound).
//! - Certified radius-2 evidence-graph neighborhood (`fss-graph-algorithms`) when hydrating an
//!   event revision.
//! - Canonical [`H2HydrationReceipt`] digested under `fss.hydration.h2_receipt.v1`.

use std::path::PathBuf;

use fss_core::hydration::DecisionArtifactKind;
use fss_core::{
    AgentView, ContentDigest, HydrationLevel, LedgerAnchor, PrincipalId, SessionId, TimestampNs,
};
use fss_reference::agent_event_hydration::build_event_h2_graph_neighborhood;
use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
use fss_reference::agent_orient::{OrientLimits, OrientRequest, RetainedEvent, orient_deployment};
use fss_reference::retained_source::ImmutableRetainedSource;

use super::budget::{HydrationBudgetReport, HydrationCostInputs, PricingProfile, compute_budget};
use super::h2_provenance::{
    build_failure_domains, build_import_h2, extract_event_provenance, seal_h2_receipt,
};
use super::render_json::render_h2_answer_json;
use super::{
    CAP_AGENT_HYDRATE_H2, CapabilityGrantContext, HydrationError, HydrationTarget,
    build_readonly_cx, is_valid_sha256, open_readonly_source, resolve_effective_capabilities,
};

const DEFAULT_RETENTION_HORIZON_NS: i128 = 3_600_000_000_000;

/// Request for H2 structured analytic hydration over an exact event revision or import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2HydrationRequest {
    /// Existing deployment root; opened strictly read-only.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Exact immutable event revision or retained import target.
    pub target: HydrationTarget,
    /// Optional exact current deployment anchor token precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Optional H0 descriptor digest pin.
    pub expected_descriptor: Option<ContentDigest>,
    /// Optional existing session identity whose stored capabilities are inspected read-only.
    pub session_id: Option<SessionId>,
    /// Optional expected session symbol-table generation.
    pub session_generation: Option<u64>,
    /// Explicit capability grants; `CAP-AGENT-HYDRATE-H2-001` is mandatory.
    pub capabilities: CapabilityGrantContext,
    /// Optional per-request token ceiling checked against payload-proportional pricing.
    pub budget_tokens: Option<u64>,
}

/// One decoded track observation bounding box from retained provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2ObservationBox {
    /// Source segment index inside the import.
    pub segment_index: u64,
    /// Retained source capsule digest.
    pub capsule_digest: ContentDigest,
    /// Masked luma digest bound to this observation.
    pub luma_digest: ContentDigest,
    /// Track bounding box `[x, y, width, height]` in decoded source coordinates.
    pub bbox: [i64; 4],
}

/// Ordered trajectory for one track extracted from retained event provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2TrackTrajectory {
    /// Tracker-assigned numeric identity.
    pub track_id: u64,
    /// Retained import identity containing the observed segments.
    pub import_identity: ContentDigest,
    /// Retained watch plan digest.
    pub plan_digest: ContentDigest,
    /// Time-ordered observations for this track.
    pub observations: Vec<H2ObservationBox>,
}

/// Model/detector receipt projection with explicit calibration status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2ModelReceiptProjection {
    /// Retained receipt or evidence digest.
    pub receipt_digest: ContentDigest,
    /// Model or package identifier (explicitly `"unretained_reference"` when not stored locally).
    pub model_id: String,
    /// Immutable model generation string.
    pub model_generation: String,
    /// Associated detection label when present in retained class evidence.
    pub label: Option<String>,
    /// Uncalibrated score in integer parts-per-million (`0..=1_000_000`) when available.
    pub uncalibrated_score_ppm: Option<u32>,
    /// Detection bounding box `[x, y, width, height]` when available.
    pub detection_box: Option<[u32; 4]>,
    /// Whether this score has a bound calibration artifact (`false` when uncalibrated).
    pub calibrated: bool,
    /// Explicit provenance note explaining calibration status.
    pub score_provenance: String,
}

/// Failure-domain support and contradiction summary for an event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2FailureDomainCluster {
    /// Declared failure-domain identifier.
    pub failure_domain: String,
    /// Count of `Supports` edges in this domain.
    pub supporting_edges: u32,
    /// Count of `Contradicts` edges in this domain.
    pub contradicting_edges: u32,
    /// Count of `DerivedFrom` edges in this domain.
    pub derived_edges: u32,
    /// Count of `RequiredBy` edges in this domain.
    pub required_by_edges: u32,
    /// Whether an explicit calibration artifact backs milliban LLR values here.
    pub calibrated: bool,
    /// Milliban LLR interval `[low, high]` if calibrated; `None` when uncalibrated.
    pub llr_millibans: Option<[i64; 2]>,
    /// Explicit LLR status explanation.
    pub llr_status: &'static str,
    /// Distinct retained source capsule digests cited in this failure domain.
    pub capsule_digests: Vec<ContentDigest>,
}

/// Certified radius-2 evidence-graph neighborhood summary from `fss-graph-algorithms`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2GraphNeighborhoodSummary {
    /// Center event identity.
    pub center_entity_id: String,
    /// Induced neighborhood hop radius.
    pub radius_hops: u32,
    /// Node count in the certified projection.
    pub node_count: u32,
    /// Arc count in the certified projection.
    pub edge_count: u32,
    /// Canonical weighted-graph digest.
    pub subgraph_digest: ContentDigest,
    /// Verified `H2DecisionArtifact` digest.
    pub artifact_digest: ContentDigest,
    /// Explicitly masked attributes never disclosed in H2.
    pub masked_attributes: Vec<String>,
}

/// Canonical H2 receipt digested under `fss.hydration.h2_receipt.v1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2HydrationReceipt {
    /// Canonical receipt digest under `fss.hydration.h2_receipt.v1`.
    pub receipt_digest: ContentDigest,
    /// Digest of the canonical H2 projection summary.
    pub projection_digest: ContentDigest,
    /// Optional certified subgraph digest.
    pub subgraph_digest: Option<ContentDigest>,
    /// Number of decoded track trajectories.
    pub track_count: usize,
    /// Total observation boxes across tracks.
    pub observation_count: usize,
    /// Number of model/detector receipts projected.
    pub model_receipt_count: usize,
    /// Number of distinct failure-domain clusters.
    pub failure_domain_count: usize,
    /// Whether any score/LLR projection is calibrated.
    pub calibrated: bool,
    /// Required capability satisfied for this delivery.
    pub capability: &'static str,
}

/// Complete anchor-pinned H2 analytic hydration answer.
#[derive(Clone, Debug, PartialEq)]
pub struct H2HydrationAnswer {
    /// Exact authority anchor verified through final revalidation.
    pub anchor: LedgerAnchor,
    /// Canonical anchor token string.
    pub anchor_token: String,
    /// Evidence clock observation timestamp.
    pub observed_at_ns: i128,
    /// Target description label (`event:<id>` or `import:<digest>`).
    pub target_label: String,
    /// Declared zone IDs from the event (empty for import-only targets).
    pub zone_ids: Vec<String>,
    /// Declared track IDs from the event metadata.
    pub declared_track_ids: Vec<String>,
    /// Decoded track trajectories and bounding boxes.
    pub trajectories: Vec<H2TrackTrajectory>,
    /// Model and detector receipts with explicit calibration status.
    pub model_receipts: Vec<H2ModelReceiptProjection>,
    /// Failure-domain clusters and milliban LLR status.
    pub failure_domains: Vec<H2FailureDomainCluster>,
    /// Count of independent supporting failure-domain clusters.
    pub independent_supporting_clusters: usize,
    /// Whether independent corroboration (`>= 2` domains) is satisfied.
    pub corroboration_satisfied: bool,
    /// Certified graph neighborhood when hydrating an event revision.
    pub graph_neighborhood: Option<H2GraphNeighborhoodSummary>,
    /// Active privacy-mask status when hydrating a retained import.
    pub import_privacy_binding: Option<String>,
    /// Canonical H2 receipt (`fss.hydration.h2_receipt.v1`).
    pub receipt: H2HydrationReceipt,
    /// Deterministic payload-proportional budget report.
    pub budget: HydrationBudgetReport,
    /// Proof root pointers bound to this projection.
    pub proof_pointers: Vec<String>,
    /// Explicit epistemic and boundary warnings.
    pub warnings: Vec<String>,
}

impl H2HydrationAnswer {
    /// Renders the complete H2 structured projection payload as deterministic JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        render_h2_answer_json(self)
    }
}

/// Executes fail-closed H2 structured analytic hydration.
pub fn hydrate_h2(
    request: &H2HydrationRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<H2HydrationAnswer, HydrationError> {
    if cancelled() {
        return Err(HydrationError::Cancelled);
    }
    let effective_caps = resolve_effective_capabilities(
        &request.root,
        &request.principal,
        request.session_id.as_ref(),
        request.session_generation,
        &request.capabilities.granted_capabilities,
    )?;
    request.capabilities.require_h2(&effective_caps)?;

    let cx = build_readonly_cx(&request.root, &request.principal, &effective_caps)?;
    let owner = open_readonly_source(&request.root, &cx, cancelled)?;
    let snapshot = owner.snapshot();
    let anchor_token = snapshot_anchor_token(snapshot);
    if let Some(expected) = &request.expected_anchor
        && expected.as_str() != anchor_token
    {
        return Err(HydrationError::AnchorMismatch(
            "deployment anchor changed; refresh anchor before H2 hydration".into(),
        ));
    }

    let mut answer = match &request.target {
        HydrationTarget::Event {
            event_id,
            revision_digest,
        } => {
            if !is_valid_sha256(*revision_digest) {
                return Err(HydrationError::InvalidRequest(
                    "revision_digest must be a canonical nonzero SHA-256 digest".into(),
                ));
            }
            let retained = snapshot.event(event_id).ok_or_else(|| {
                HydrationError::NotFound(format!("event {} not found at anchor", event_id.as_str()))
            })?;
            if retained.revision_digest != *revision_digest {
                return Err(HydrationError::AnchorMismatch(
                    "event revision_digest does not match current committed revision".into(),
                ));
            }
            if snapshot.deletions.object(retained.event_root).is_some()
                || snapshot
                    .deletions
                    .object(retained.revision_digest)
                    .is_some()
            {
                return Err(HydrationError::EvidenceDeleted(
                    "event revision metadata is covered by a committed deletion".into(),
                ));
            }
            build_event_h2(&owner, request, retained, &anchor_token)?
        }
        HydrationTarget::Import { import_id } => {
            if !is_valid_sha256(*import_id) {
                return Err(HydrationError::InvalidRequest(
                    "import_id must be a canonical nonzero SHA-256 digest".into(),
                ));
            }
            build_import_h2(&owner, &cx, *import_id, &anchor_token)?
        }
    };

    owner.revalidate().map_err(|error| {
        HydrationError::CustodyFailure(format!("final H2 custody revalidation failed: {error}"))
    })?;
    let usage = owner.usage();
    let preliminary_bytes = answer.to_json().len();
    let budget = compute_budget(
        PricingProfile::PayloadProportionalV2,
        &HydrationCostInputs {
            level: HydrationLevel::H2,
            serialized_bytes: preliminary_bytes,
            storage_reads: usage.read_objects,
            media_bytes_read: 0,
            decode_work_units: 0,
            encode_work_units: 0,
            frame_count: 0,
        },
    )?;
    if let Some(limit) = request.budget_tokens
        && budget.vector.tokens > limit
    {
        return Err(HydrationError::BoundsExceeded(format!(
            "H2 payload requires {} tokens, exceeding requested ceiling {limit}",
            budget.vector.tokens
        )));
    }
    answer.budget = budget;
    Ok(answer)
}

fn build_event_h2(
    owner: &ImmutableRetainedSource<'_>,
    request: &H2HydrationRequest,
    retained: &RetainedEvent,
    anchor_token: &str,
) -> Result<H2HydrationAnswer, HydrationError> {
    let snapshot = owner.snapshot();
    let orientation = orient_deployment(
        snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: request.principal.clone(),
            budget_tokens: None,
        },
        &OrientLimits::default(),
    )
    .map_err(|_| HydrationError::CustodyFailure("could not compile H2 orientation".into()))?;
    let retention_until = TimestampNs(
        snapshot
            .latest_evidence_time
            .0
            .saturating_add(DEFAULT_RETENTION_HORIZON_NS),
    );
    let h2_artifact = build_event_h2_graph_neighborhood(
        snapshot,
        &orientation,
        &retained.event.event_id,
        retained.revision_digest,
        CAP_AGENT_HYDRATE_H2,
        retention_until,
    )
    .map_err(|error| {
        HydrationError::CustodyFailure(format!("H2 graph neighborhood failed: {error}"))
    })?;
    let DecisionArtifactKind::GraphNeighborhood(neighborhood) = h2_artifact.artifact_kind() else {
        return Err(HydrationError::CustodyFailure(
            "unexpected H2 decision artifact kind".into(),
        ));
    };
    let graph_summary = H2GraphNeighborhoodSummary {
        center_entity_id: neighborhood.center_entity_id().to_owned(),
        radius_hops: u32::from(neighborhood.radius_hops()),
        node_count: neighborhood.node_count(),
        edge_count: neighborhood.edge_count(),
        subgraph_digest: neighborhood.subgraph_digest(),
        artifact_digest: h2_artifact.artifact_digest(),
        masked_attributes: neighborhood.masked_attributes().iter().cloned().collect(),
    };

    let (trajectories, mut model_receipts) = extract_event_provenance(owner, retained);
    for receipt_digest in &retained.event.model_receipts {
        if !model_receipts
            .iter()
            .any(|item| item.receipt_digest == *receipt_digest)
        {
            model_receipts.push(H2ModelReceiptProjection {
                receipt_digest: *receipt_digest,
                model_id: "unretained_reference".to_owned(),
                model_generation: "unretained_reference".to_owned(),
                label: None,
                uncalibrated_score_ppm: None,
                detection_box: None,
                calibrated: false,
                score_provenance:
                    "Event model_receipts reference without an attached calibration artifact."
                        .to_owned(),
            });
        }
    }

    let calibrated = retained.event.probability.calibration_generation.is_some();
    let (failure_domains, independent_supporting_clusters) =
        build_failure_domains(retained, calibrated);
    let corroboration_satisfied = independent_supporting_clusters >= 2;
    let observation_count: usize = trajectories.iter().map(|t| t.observations.len()).sum();
    let receipt = seal_h2_receipt(
        &snapshot.anchor,
        retained.event.event_id.as_str(),
        retained.revision_digest,
        Some(graph_summary.subgraph_digest),
        trajectories.len(),
        observation_count,
        model_receipts.len(),
        failure_domains.len(),
        calibrated,
    );
    let mut proof_pointers: Vec<String> = h2_artifact
        .proof_roots()
        .iter()
        .copied()
        .map(ContentDigest::to_text)
        .collect();
    proof_pointers.push(receipt.receipt_digest.to_text());
    proof_pointers.sort();
    proof_pointers.dedup();
    let placeholder_budget = zero_h2_budget()?;

    Ok(H2HydrationAnswer {
        anchor: snapshot.anchor.clone(),
        anchor_token: anchor_token.to_owned(),
        observed_at_ns: snapshot.latest_evidence_time.0,
        target_label: format!(
            "event:{}:{}",
            retained.event.event_id.as_str(),
            retained.revision_digest.to_text()
        ),
        zone_ids: retained.event.zone_ids.clone(),
        declared_track_ids: retained.event.track_ids.clone(),
        trajectories,
        model_receipts,
        failure_domains,
        independent_supporting_clusters,
        corroboration_satisfied,
        graph_neighborhood: Some(graph_summary),
        import_privacy_binding: None,
        receipt,
        budget: placeholder_budget,
        proof_pointers,
        warnings: vec![
            "H2 structured analytic projection: no raw media bytes decoded or disclosed.".to_owned(),
            "Uncalibrated detector scores and structural graph proximity do not establish physical truth or effect authority."
                .to_owned(),
        ],
    })
}

pub(super) fn zero_h2_budget() -> Result<HydrationBudgetReport, HydrationError> {
    compute_budget(
        PricingProfile::PayloadProportionalV2,
        &HydrationCostInputs {
            level: HydrationLevel::H2,
            serialized_bytes: 0,
            storage_reads: 0,
            media_bytes_read: 0,
            decode_work_units: 0,
            encode_work_units: 0,
            frame_count: 0,
        },
    )
}
