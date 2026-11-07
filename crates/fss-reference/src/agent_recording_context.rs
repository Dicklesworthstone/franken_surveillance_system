#![forbid(unsafe_code)]
//! AOP-005 recording metadata with independently verified deployment context.
//!
//! The deployment and archive are distinct owners. The deployment prefix is read before and
//! after the native archive query; neither read claims an atomic cross-owner snapshot. One
//! non-replenishing deployment allowance and one non-replenishing archive allowance bound the
//! entire operation. No writer, recovery handle, directory discovery or source-media read is
//! admitted by the archive query.

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    KnowledgeState, MissionId, PrincipalId, QueryCompletenessRequested, QueryInterpretation,
    QueryReadReceipt, SessionId, admit_query_read, reference_contract_basis,
};
use fss_object::SpoolIo;

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::agent_recordings::{
    RecordingQuery, RecordingQueryError, RecordingQueryLimits, RecordingQueryRequest,
    query_recordings,
};

/// Caller-pinned native archive query and deployment authority precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingContextRequest {
    /// Exact codec, source, catalog and half-open decode-clock interval.
    pub recording: RecordingQueryRequest,
    /// Audit label; this does not authenticate the caller or grant hydration authority.
    pub principal: PrincipalId,
    /// Optional exact deployment authority/effect-history token.
    pub expected_anchor: Option<AnchorToken>,
}

/// Separate, non-replenishing allowances for the two independently verified owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingContextLimits {
    /// Per-input deployment metadata limits.
    pub snapshot: OrientLimits,
    /// Total deployment metadata payload bytes across both history reads.
    pub deployment_bytes: usize,
    /// Total deployment file/object payload reads, including rereads.
    pub deployment_reads: usize,
    /// Native archive metadata and filesystem-call limits.
    pub recording: RecordingQueryLimits,
}

impl Default for RecordingContextLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            deployment_bytes: 256 * 1024 * 1024,
            deployment_reads: 65_536,
            recording: RecordingQueryLimits::default(),
        }
    }
}

impl RecordingContextLimits {
    fn validate(&self) -> Result<(), RecordingContextError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.deployment_bytes, ceiling.deployment_bytes),
            (self.deployment_reads, ceiling.deployment_reads),
            (
                self.snapshot.max_layout_bytes,
                ceiling.snapshot.max_layout_bytes,
            ),
            (
                self.snapshot.max_journal_bytes,
                ceiling.snapshot.max_journal_bytes,
            ),
            (
                self.snapshot.max_object_bytes,
                ceiling.snapshot.max_object_bytes,
            ),
            (self.snapshot.max_events, ceiling.snapshot.max_events),
            (
                self.snapshot.max_revisions_per_event,
                ceiling.snapshot.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(RecordingContextError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Combined declared allowance. Archive filesystem calls and deployment payload reads
    /// retain their distinct meanings in the result's individual counters.
    pub fn allowance(&self) -> Result<BudgetVector, RecordingContextError> {
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: (self.deployment_bytes as u64)
                .checked_add(self.recording.metadata.max_read_bytes)
                .ok_or(RecordingContextError::InvalidRequest)?,
            storage_operations: (self.deployment_reads as u64)
                .checked_add(self.recording.metadata.max_io_calls)
                .ok_or(RecordingContextError::InvalidRequest)?,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// A refusal is never an empty match set or a physical absence claim.
#[derive(Debug)]
pub enum RecordingContextError {
    /// Unsupported request or limits, rejected before archive I/O.
    InvalidRequest,
    /// Metadata-only deployment replay failed.
    Deployment(DeploymentReadError),
    /// Native archive custody, scope or budget verification failed.
    Recording(RecordingQueryError),
    /// The expected/current deployment prefix or deletion state changed.
    AnchorChanged,
    /// The shared deployment read allowance was exhausted.
    OverBudget,
    /// Cooperative cancellation requested before another bounded phase.
    Cancelled,
    /// A verified query could not be admitted by the existing AOP-005 contract.
    Contract,
}

impl std::fmt::Display for RecordingContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid recording query request or allowance",
            Self::Deployment(_) => "deployment metadata verification failed",
            Self::Recording(_) => "native recording metadata verification refused",
            Self::AnchorChanged => "deployment authority, layout or deletion state changed",
            Self::OverBudget => "deployment metadata read allowance exhausted",
            Self::Cancelled => "recording query cancelled",
            Self::Contract => "recording query contract admission failed",
        })
    }
}
impl std::error::Error for RecordingContextError {}

/// Complete bounded catalog selection together with current protected deployment context.
#[derive(Clone, Debug)]
pub struct DeploymentRecordingQuery {
    /// Metadata-only snapshot, bracketed by matching authority/effect-prefix reads.
    pub snapshot: DeploymentSnapshot,
    /// Exact current deployment prefix; distinct from the catalog's source anchor.
    pub anchor_token: String,
    /// Native, byte-free catalog selection and its metered read usage.
    pub native: RecordingQuery,
    /// Existing AOP-005 query-plan receipt.
    pub plan: AgentQueryPlan,
    /// Existing read admission; no source-media or effect authority.
    pub admission: QueryReadReceipt,
    /// Request identity binds principal, deployment prefix, source pins and allowances.
    pub request_digest: ContentDigest,
    /// Decision binds the request and native selection witness.
    pub decision_digest: ContentDigest,
    /// Deterministic query session label, not a durable workspace.
    pub session_id: SessionId,
    /// Deterministic metadata-query mission label.
    pub mission_id: MissionId,
    /// Both deployment history reads, separate from native archive counters.
    pub deployment_bytes_read: u64,
    /// Both deployment file/object payload reads.
    pub deployment_metadata_reads: u64,
}

impl DeploymentRecordingQuery {
    /// Metadata statements preserve unknown payload availability and physical observability.
    pub fn epistemic(&self, request: &RecordingQueryRequest) -> EnvelopeEpistemic {
        let mut propositions = vec![EnvelopeProposition {
            id: "claim:recordings:catalog-selection".to_owned(),
            statement: format!(
                "Verified one exact published catalog: root={}, metadata={}, indexed_windows={}, selected_windows={}, decode_interval=[{},{}), time_scale={}, quoted_hydration_bytes={}. Source sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}. The byte quote is declared metadata for complete selected recordings, not bytes read or authority to hydrate.",
                self.native.catalog_root, self.native.catalog_metadata_digest,
                self.native.scanned_windows, self.native.rows.len(),
                request.interval.start, request.interval.end, request.scope.time_scale,
                self.native.quoted_hydration_bytes, request.scope.recording.sensor.as_str(),
                request.scope.recording.stream.as_str(), request.scope.recording.generation,
                request.scope.recording.anchor, request.scope.recording.receive_clock,
                request.scope.decode_clock,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![self.native.catalog_root.to_text(), self.native.catalog_metadata_digest.to_text()],
        }, EnvelopeProposition {
            id: "claim:recordings:physical-observability".to_owned(),
            statement: "Source-media availability, live coverage, physical activity, physical absence and trusted UTC are unknown. Indexed gaps mean that this exact catalog has no matching recording window; they do not establish why recording is missing. No source-media bytes were read.".to_owned(),
            state: KnowledgeState::Unknown,
            provenance: "derived".to_owned(),
            evidence: Vec::new(),
        }];
        for row in &self.native.rows {
            let interval = row.entry.decode_interval();
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings:window:{}", row.ordinal),
                statement: format!(
                    "Published recording metadata: ordinal={}, slot={}, root={}, decode_interval=[{},{}), selected_overlap=[{},{}), hydration_bytes={}, samples={}, packets={}, nals={}, metadata_availability=verified, source_payload_availability=unknown.",
                    row.ordinal, row.entry.slot().as_str(), row.entry.root(), interval.start,
                    interval.end, row.overlap.start, row.overlap.end, row.entry.byte_len(),
                    row.entry.samples(), row.entry.packets(), row.entry.nals(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.native.catalog_metadata_digest.to_text(), row.entry.root().to_text()],
            });
        }
        for (index, gap) in self.native.indexed_gaps.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings:indexed-gap:{index}"),
                statement: format!("No window in this pinned catalog indexes decode interval [{},{}); cause, source availability and physical observability remain unknown.", gap.start, gap.end),
                state: KnowledgeState::NotObservable,
                provenance: "derived".to_owned(),
                evidence: vec![self.native.catalog_metadata_digest.to_text()],
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label, not authentication; this query grants no effect or media hydration authority.".to_owned(),
                "Archive pins are explicit caller input, not proof that a camera belongs to this deployment. The archive and deployment are separately verified owners, not an atomic cross-owner snapshot.".to_owned(),
                "The deployment spool doctor was not run; metadata-only context retains its conservative attention verdict.".to_owned(),
            ],
            invalidators: vec!["Any authority/effect-prefix, publication, metadata, tombstone, source scope or allowance change requires a new query.".to_owned()],
        }
    }

    /// Exhaustion of a finite metadata catalog never claims physical-world completeness.
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one explicitly pinned native AVC/HEVC recording catalog".to_owned()],
            observed_domain: vec!["verified published catalog and recording-root metadata over the requested decode-clock interval".to_owned()],
            not_observable_domain: vec!["other catalogs, source-media bytes and availability, UTC, live coverage, physical activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "pinned_catalog_exhausted".to_owned(),
        }
    }
}

/// Read one exact archive catalog without losing current protected deployment context.
pub fn query_recordings_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingContextRequest,
    limits: &RecordingContextLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingQuery, RecordingContextError> {
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
    budget.ensure_valid().map_err(|_| RecordingContextError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request.expected_anchor.as_ref().is_some_and(|a| a.as_str() != anchor_token) {
        return Err(RecordingContextError::AnchorChanged);
    }
    checkpoint()?;
    let native = query_recordings(io, archive_root, &request.recording, limits.recording, cancelled)
        .map_err(RecordingContextError::Recording)?;
    checkpoint()?;
    let final_history = DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
        .map_err(RecordingContextError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(RecordingContextError::Deployment)?;
    budget.ensure_valid().map_err(|_| RecordingContextError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || snapshot.deletions.object(native.catalog_root).is_some()
        || snapshot.deletions.object(native.catalog_metadata_digest).is_some()
        || native.rows.iter().any(|r| snapshot.deletions.object(r.entry.root()).is_some())
    {
        return Err(RecordingContextError::AnchorChanged);
    }
    checkpoint()?;
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.context_request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    request.principal.encode_canonical(&mut e);
    e.digest(native.request_digest);
    for value in [
        limits.deployment_bytes, limits.deployment_reads,
        limits.snapshot.max_layout_bytes, limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes, limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        e.u64(value as u64);
    }
    let request_digest = ContentDigest::sha256(&e.finish());
    let suffix = request_digest.to_text();
    let suffix = suffix.strip_prefix("sha256:").unwrap_or(&suffix);
    let session_id = SessionId::parse(format!("session:recordings:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings:{suffix}"))
        .map_err(|_| RecordingContextError::Contract)?;
    let admission = admit_query_read(
        &basis, &snapshot.anchor, "query", request.recording.max_windows as u32, allowance,
    ).map_err(|_| RecordingContextError::Contract)?;
    let description = "Exact published native recording metadata in a half-open source decode-clock interval; no UTC conversion, payload availability or physical absence claim";
    let interpretation_id = "interpretation:pinned-native-recording-metadata";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| RecordingContextError::Contract)?;
    let plan = AgentQueryPlan::compile(
        format!("query-plan:{suffix}"), mission_id.clone(), session_id.clone(), &basis,
        "AOP-005", request_digest, vec!["taint:structured-operator-input".to_owned()],
        snapshot.anchor.clone(), description,
        vec![native.catalog_root.to_text()], vec!["recording_window".to_owned()],
        vec![crate::agent_query::CAPABILITY_QUERY.to_owned()], vec!["metadata_only".to_owned()],
        QueryCompletenessRequested::Bounded, allowance, vec![interpretation], interpretation_id,
        allowance, AgentView::Case.id(), snapshot.latest_evidence_time.0,
    ).map_err(|_| RecordingContextError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.context_decision.v1");
    e.digest(request_digest);
    e.digest(native.decision_digest);
    e.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&e.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingQuery {
        snapshot, anchor_token, native, plan, admission, request_digest, decision_digest,
        session_id, mission_id, deployment_bytes_read, deployment_metadata_reads,
    })
}
