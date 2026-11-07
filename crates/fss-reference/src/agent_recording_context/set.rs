#![forbid(unsafe_code)]
//! One protected deployment read over a bounded set of exact native recording catalogs.
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
use crate::agent_recordings::set::{
    RecordingSetQuery, RecordingSetQueryLimits, RecordingSetQueryRequest, query_recording_set,
};

/// Exact historical source/catalog pins plus current deployment preconditions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetContextRequest {
    /// Bounded explicit catalogs and one shared native decode-clock scope.
    pub recording: RecordingSetQueryRequest,
    /// Audit label, never authentication or permission to hydrate media.
    pub principal: PrincipalId,
    /// Optional exact current deployment authority/effect-history token.
    pub expected_anchor: Option<AnchorToken>,
}

/// Nonrefillable deployment and archive allowances for the complete query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingSetContextLimits {
    /// Per-input deployment metadata ceilings.
    pub snapshot: OrientLimits,
    /// Total bytes across both deployment history reads.
    pub deployment_bytes: usize,
    /// Total metadata payload reads across both deployment history reads.
    pub deployment_reads: usize,
    /// Shared archive allowance across all catalogs and final revalidation.
    pub recording: RecordingSetQueryLimits,
}
impl Default for RecordingSetContextLimits {
    fn default() -> Self {
        let context = RecordingContextLimits::default();
        Self {
            snapshot: context.snapshot,
            deployment_bytes: context.deployment_bytes,
            deployment_reads: context.deployment_reads,
            recording: RecordingSetQueryLimits::default(),
        }
    }
}
impl RecordingSetContextLimits {
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
            .map_err(RecordingContextError::Recording)
    }

    /// Declared combined allowance; each owner's counters retain their distinct meanings.
    pub fn allowance(&self) -> Result<fss_core::BudgetVector, RecordingContextError> {
        self.context().allowance()
    }
}

/// Complete multi-catalog metadata result with protected current deployment context.
#[derive(Clone, Debug)]
pub struct DeploymentRecordingSetQuery {
    /// Metadata snapshot bracketed by unchanged deployment-prefix reads.
    pub snapshot: DeploymentSnapshot,
    /// Current authority/effect prefix, distinct from historical source authority.
    pub anchor_token: String,
    /// Canonical catalog set, unique windows, gap union and shared metadata work.
    pub native: RecordingSetQuery,
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

impl DeploymentRecordingSetQuery {
    /// Preserve unknown source availability, physical observability and UTC through projection.
    pub fn epistemic(&self, request: &RecordingSetQueryRequest) -> EnvelopeEpistemic {
        let evidence: Vec<_> = self
            .native
            .catalogs
            .iter()
            .flat_map(|catalog| {
                [
                    catalog.pin.root.to_text(),
                    catalog.metadata_digest.to_text(),
                ]
            })
            .collect();
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:recordings-set:catalog-selection".to_owned(),
                statement: format!(
                    "Verified {} explicitly pinned catalogs in one shared request: scanned_descriptors={}, unique_windows={}, selected_windows={}, decode_interval=[{},{}), time_scale={}, quoted_hydration_bytes={}. Source sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}. Duplicate windows share one hydration quote; every catalog membership is retained. No media was read.",
                    self.native.catalogs.len(), self.native.scanned_windows,
                    self.native.unique_windows, self.native.rows.len(),
                    request.interval.start, request.interval.end, request.scope.time_scale,
                    self.native.quoted_hydration_bytes, request.scope.recording.sensor.as_str(),
                    request.scope.recording.stream.as_str(), request.scope.recording.generation,
                    request.scope.recording.anchor, request.scope.recording.receive_clock,
                    request.scope.decode_clock,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: evidence.clone(),
            },
            EnvelopeProposition {
                id: "claim:recordings-set:physical-observability".to_owned(),
                statement: "Source payload availability, trusted UTC, live coverage, physical activity and physical absence remain unknown. The caller selected these catalogs explicitly; no search of other catalogs or sources occurred. Indexed gaps mean no selected catalog indexes that interval; their cause is unknown. A byte quote grants no hydration authority.".to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for (index, catalog) in self.native.catalogs.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-set:catalog:{index}"),
                statement: format!(
                    "Verified catalog membership: catalog_index={index}, slot={}, root={}, metadata={}, indexed_windows={}.",
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
                .map(|location| format!("{}:{}", location.catalog_index, location.ordinal))
                .collect::<Vec<_>>()
                .join(",");
            let mut evidence = vec![row.entry.root().to_text()];
            evidence.extend(row.locations.iter().map(|location| {
                self.native.catalogs[location.catalog_index]
                    .metadata_digest
                    .to_text()
            }));
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-set:window:{index}"),
                statement: format!(
                    "Published recording metadata: slot={}, root={}, row_digest={}, catalog_index:ordinal=[{}], decode_interval=[{},{}), selected_overlap=[{},{}), hydration_bytes={}, samples={}, packets={}, nals={}, metadata_availability=verified, source_payload_availability=unknown.",
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
                id: format!("claim:recordings-set:indexed-gap:{index}"),
                statement: format!(
                    "No window in the union of these pinned catalogs indexes decode interval [{},{}). Gap cause, source availability and physical observability remain unknown.",
                    gap.start, gap.end,
                ),
                state: KnowledgeState::NotObservable,
                provenance: "derived".to_owned(),
                evidence: evidence.clone(),
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label. No source-media or effect authority is granted.".to_owned(),
                "All catalogs share exact historical source and decode-clock pins. Those pins do not register a source in the current deployment.".to_owned(),
                "Archive and deployment are separately verified owners, not an atomic cross-owner snapshot. The deployment spool doctor was not run.".to_owned(),
            ],
            invalidators: vec![
                "Any deployment-prefix, deletion, publication, metadata, catalog-set, source-scope or allowance change requires a new query.".to_owned(),
            ],
        }
    }

    /// Exhausting selected indexes never establishes physical coverage or global discovery.
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["explicitly pinned native AVC/HEVC catalog set in one source/decode-clock scope".to_owned()],
            observed_domain: vec!["all selected catalog and member publication metadata; union of indexed decode-clock intervals".to_owned()],
            not_observable_domain: vec!["unselected catalogs, source bytes and availability, UTC, live coverage, physical activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "pinned_catalog_set_exhausted".to_owned(),
        }
    }
}

/// Read a complete explicit catalog set without losing current protected deployment context.
pub fn query_recording_set_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingSetContextRequest,
    limits: &RecordingSetContextLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingSetQuery, RecordingContextError> {
    request
        .recording
        .request_digest(limits.recording)
        .map_err(RecordingContextError::Recording)?;
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
    let native = query_recording_set(
        io,
        archive_root,
        &request.recording,
        limits.recording,
        cancelled,
    )
    .map_err(RecordingContextError::Recording)?;
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
    encoder.text("fss.agent_recordings.set.context_request.v1");
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
    let session_id = SessionId::parse(format!("session:recordings-set:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings-set:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.recording.max_windows as u32,
        allowance,
    )
    .map_err(|_| RecordingContextError::Contract)?;
    let description = "Exact published native recording metadata across an explicitly pinned catalog set; one decode clock; no source-media availability or physical absence claim";
    let interpretation_id = "interpretation:pinned-native-recording-set-metadata";
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
        native
            .catalogs
            .iter()
            .map(|catalog| catalog.pin.root.to_text())
            .collect(),
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
    encoder.text("fss.agent_recordings.set.context_decision.v1");
    encoder.digest(request_digest);
    encoder.digest(native.decision_digest);
    encoder.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&encoder.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingSetQuery {
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
