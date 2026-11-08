#![forbid(unsafe_code)]
//! Protected deployment context for complete metadata discovery in one archive namespace.
//!
//! Archive metadata is verified as one request. Deployment reads bracket that request;
//! this does not claim an atomic snapshot across the two independent owners.

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, CanonicalEncode, CanonicalEncoder, ContentDigest, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, MissionId, PrincipalId,
    QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt, SessionId, admit_query_read,
    reference_contract_basis,
};
use fss_object::SpoolIo;

use super::{RecordingContextError, RecordingContextLimits};
use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::agent_recordings::RecordingQueryLimits;
use crate::agent_recordings::discover::{
    RecordingDiscoveryLimits, RecordingDiscoveryQuery, RecordingDiscoveryRequest,
    discover_recordings,
};

/// Exact historical source namespace plus current deployment preconditions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryContextRequest {
    /// Explicit source/decode-clock scope and bounded archive discovery.
    pub recording: RecordingDiscoveryRequest,
    /// Audit label, never authentication or permission to hydrate media.
    pub principal: PrincipalId,
    /// Optional exact current deployment authority/effect-history token.
    pub expected_anchor: Option<AnchorToken>,
}

/// Nonrefillable deployment and archive allowances for the complete query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryContextLimits {
    /// Per-input deployment metadata ceilings.
    pub snapshot: OrientLimits,
    /// Total bytes across both deployment history reads.
    pub deployment_bytes: usize,
    /// Total metadata payload reads across both deployment history reads.
    pub deployment_reads: usize,
    /// Shared archive allowance across all catalogs and final revalidation.
    pub recording: RecordingDiscoveryLimits,
}
impl Default for RecordingDiscoveryContextLimits {
    fn default() -> Self {
        let context = RecordingContextLimits::default();
        Self {
            snapshot: context.snapshot,
            deployment_bytes: context.deployment_bytes,
            deployment_reads: context.deployment_reads,
            recording: RecordingDiscoveryLimits::default(),
        }
    }
}
impl RecordingDiscoveryContextLimits {
    fn context(&self) -> RecordingContextLimits {
        RecordingContextLimits {
            snapshot: self.snapshot,
            deployment_bytes: self.deployment_bytes,
            deployment_reads: self.deployment_reads,
            recording: RecordingQueryLimits {
                metadata: self.recording.metadata,
            },
        }
    }

    fn validate(&self) -> Result<(), RecordingContextError> {
        self.context().validate()?;
        self.recording
            .validate()
            .map_err(RecordingContextError::Discovery)
    }

    /// Declared combined allowance; each owner's counters retain their distinct meanings.
    pub fn allowance(&self) -> Result<fss_core::BudgetVector, RecordingContextError> {
        self.context().allowance()
    }
}

/// Complete namespace metadata result with protected current deployment context.
#[derive(Clone, Debug)]
pub struct DeploymentRecordingDiscoveryQuery {
    /// Metadata snapshot bracketed by unchanged deployment-prefix reads.
    pub snapshot: DeploymentSnapshot,
    /// Current authority/effect prefix, distinct from historical source authority.
    pub anchor_token: String,
    /// Verified namespace inventory, selected windows, indexed gaps and shared metadata work.
    pub native: RecordingDiscoveryQuery,
    /// Existing AOP-005 query-plan contract.
    pub plan: AgentQueryPlan,
    /// Read admission; grants neither effect nor source-media authority.
    pub admission: QueryReadReceipt,
    /// Identity of principal, deployment prefix, exact query and allowances.
    pub request_digest: ContentDigest,
    /// Identity of admitted plan and complete native selection.
    pub decision_digest: ContentDigest,
    /// Deterministic request label, not durable workspace state.
    pub session_id: SessionId,
    /// Deterministic query mission label.
    pub mission_id: MissionId,
    /// Actual bytes read across both deployment observations.
    pub deployment_bytes_read: u64,
    /// Actual metadata payload reads across both deployment observations.
    pub deployment_metadata_reads: u64,
}

impl DeploymentRecordingDiscoveryQuery {
    /// Catalog positions supporting selected rows; the complete inventory remains digest-bound.
    pub fn selected_catalog_indexes(&self) -> std::collections::BTreeSet<usize> {
        self.native
            .rows
            .iter()
            .flat_map(|row| row.locations.iter().map(|location| location.catalog_index))
            .collect()
    }

    /// Project exact namespace observations without promoting index gaps into physical absence.
    pub fn epistemic(&self, request: &RecordingDiscoveryRequest) -> EnvelopeEpistemic {
        let inventory_evidence = vec![self.native.inventory_digest.to_text()];
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:recordings-discovery:inventory".to_owned(),
                statement: format!(
                    "Verified the complete indexed archive namespace: namespace_digest={}, inventory_digest={}, catalogs={}, scanned_windows={}, selected_windows={}, scanned_root_entries={}, decode_interval=[{},{}), time_scale={}, quoted_hydration_bytes={}. Source sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}. All page and window membership was checked; unselected catalog identities remain bound by the complete inventory digest. No source media was read.",
                    self.native.namespace_digest, self.native.inventory_digest,
                    self.native.catalogs.len(), self.native.scanned_windows, self.native.rows.len(),
                    self.native.scanned_root_entries, request.interval.start, request.interval.end,
                    request.scope.time_scale, self.native.quoted_hydration_bytes,
                    request.scope.recording.sensor.as_str(), request.scope.recording.stream.as_str(),
                    request.scope.recording.generation, request.scope.recording.anchor,
                    request.scope.recording.receive_clock, request.scope.decode_clock,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: inventory_evidence.clone(),
            },
            EnvelopeProposition {
                id: "claim:recordings-discovery:physical-observability".to_owned(),
                statement: "Source payload availability, trusted UTC, physical activity, physical absence and live coverage remain unknown. Discovery covers only the explicitly scoped canonical archive namespace; it does not register that source, search other generations or infer clock equivalence. An empty namespace or indexed gap cannot establish physical absence. A hydration quote grants no media authority.".to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for index in self.selected_catalog_indexes() {
            let catalog = &self.native.catalogs[index];
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-discovery:catalog:{index}"),
                statement: format!(
                    "Catalog supporting selected recording metadata: catalog_index={index}, slot={}, root={}, metadata={}, indexed_windows={}. Other verified catalog identities are represented by the complete inventory digest.",
                    catalog.pin.slot.as_str(), catalog.pin.root, catalog.metadata_digest,
                    catalog.scanned_windows,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![catalog.pin.root.to_text(), catalog.metadata_digest.to_text()],
            });
        }
        for (index, row) in self.native.rows.iter().enumerate() {
            let interval = row.entry.decode_interval();
            let memberships = row
                .locations
                .iter()
                .map(|location| {
                    format!(
                        "{}:{}:{}",
                        location.catalog_index, location.ordinal, location.catalog_root
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let mut evidence = vec![row.entry.root().to_text()];
            evidence.extend(row.locations.iter().map(|location| {
                self.native.catalogs[location.catalog_index]
                    .metadata_digest
                    .to_text()
            }));
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-discovery:window:{index}"),
                statement: format!(
                    "Published recording metadata: slot={}, root={}, row_digest={}, catalog_index:ordinal:root=[{}], decode_interval=[{},{}), selected_overlap=[{},{}), hydration_bytes={}, samples={}, packets={}, nals={}, metadata_availability=verified, source_payload_availability=unknown.",
                    row.entry.slot().as_str(), row.entry.root(), row.row_digest(), memberships,
                    interval.start, interval.end, row.overlap.start, row.overlap.end,
                    row.entry.byte_len(), row.entry.samples(), row.entry.packets(), row.entry.nals(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence,
            });
        }
        for (index, gap) in self.native.indexed_gaps.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-discovery:indexed-gap:{index}"),
                statement: format!(
                    "No window in the completely indexed selected namespace indexes decode interval [{},{}). The gap's cause, source availability and physical observability remain unknown.",
                    gap.start, gap.end,
                ),
                state: KnowledgeState::NotObservable,
                provenance: "derived".to_owned(),
                evidence: inventory_evidence.clone(),
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label. No media or effect authority is granted.".to_owned(),
                "The historical namespace pins do not establish current source registration or a trusted wall clock.".to_owned(),
                "Matching archive and deployment observations do not create an atomic cross-owner snapshot.".to_owned(),
            ],
            invalidators: vec![
                "Any namespace membership, metadata, deletion, deployment prefix, scope or allowance change requires a new query.".to_owned(),
            ],
        }
    }

    /// Completeness concerns one finite namespace, never physical activity or other clocks.
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one explicitly selected native AVC/HEVC archive namespace".to_owned()],
            observed_domain: vec!["all canonical page/window publication metadata in the bounded namespace; complete index membership and selected native intervals".to_owned()],
            not_observable_domain: vec!["other namespaces and generations, source payload availability, trusted UTC, live coverage, physical activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "archive_namespace_exhausted".to_owned(),
        }
    }
}

/// Discover one complete indexed namespace without losing current protected deployment context.
pub fn discover_recordings_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingDiscoveryContextRequest,
    limits: &RecordingDiscoveryContextLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingDiscoveryQuery, RecordingContextError> {
    request
        .recording
        .request_digest(limits.recording)
        .map_err(RecordingContextError::Discovery)?;
    limits.validate()?;
    if !(1..=32).contains(&request.recording.max_windows) {
        return Err(RecordingContextError::InvalidRequest);
    }
    let checkpoint = || {
        if cancelled() {
            Err(RecordingContextError::Cancelled)
        } else {
            Ok(())
        }
    };
    checkpoint()?;
    let budget = MetadataReadBudget::new(limits.deployment_bytes, limits.deployment_reads);
    let history = DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
        .map_err(RecordingContextError::Deployment)?;
    let snapshot = history
        .snapshot_at(history.head())
        .map_err(RecordingContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingContextError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|anchor| anchor.as_str() != anchor_token)
    {
        return Err(RecordingContextError::AnchorChanged);
    }
    checkpoint()?;
    let native = discover_recordings(
        io,
        archive_root,
        &request.recording,
        limits.recording,
        cancelled,
    )
    .map_err(RecordingContextError::Discovery)?;
    checkpoint()?;
    let final_history =
        DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
            .map_err(RecordingContextError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(RecordingContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingContextError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || native
            .reference_digests
            .iter()
            .any(|digest| snapshot.deletions.object(*digest).is_some())
    {
        return Err(RecordingContextError::AnchorChanged);
    }
    checkpoint()?;
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.discovery.context_request.v1");
    basis.encode_canonical(&mut encoder);
    encoder.text(&anchor_token);
    request.principal.encode_canonical(&mut encoder);
    encoder.digest(native.request_digest);
    for value in [
        limits.deployment_bytes,
        limits.deployment_reads,
        limits.snapshot.max_layout_bytes,
        limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes,
        limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        encoder.u64(value as u64);
    }
    let request_digest = ContentDigest::sha256(&encoder.finish());
    let suffix = request_digest.to_text();
    let suffix = suffix.strip_prefix("sha256:").unwrap_or(&suffix);
    let session_id = SessionId::parse(format!("session:recordings-discovery:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings-discovery:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.recording.max_windows as u32,
        allowance,
    )
    .map_err(|_| RecordingContextError::Contract)?;
    let description = "Complete indexed native archive metadata in one exact source namespace; no source-media availability or physical absence claim";
    let interpretation_id = "interpretation:native-recording-namespace-metadata";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| RecordingContextError::Contract)?;
    let plan = AgentQueryPlan::compile(
        format!("query-plan:{suffix}"),
        mission_id.clone(),
        session_id.clone(),
        &basis,
        "AOP-005",
        request_digest,
        vec!["taint:structured-operator-input".to_owned()],
        snapshot.anchor.clone(),
        description,
        vec![
            native.namespace_digest.to_text(),
            native.inventory_digest.to_text(),
        ],
        vec!["recording_window".to_owned()],
        vec![crate::agent_query::CAPABILITY_QUERY.to_owned()],
        vec!["metadata_only".to_owned()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        interpretation_id,
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )
    .map_err(|_| RecordingContextError::Contract)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.discovery.context_decision.v1");
    encoder.digest(request_digest);
    encoder.digest(native.decision_digest);
    encoder.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&encoder.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingDiscoveryQuery {
        snapshot,
        anchor_token,
        native,
        plan,
        admission,
        request_digest,
        decision_digest,
        session_id,
        mission_id,
        deployment_bytes_read,
        deployment_metadata_reads,
    })
}
