#![forbid(unsafe_code)]
//! Source-verified recorder UTC with current protected deployment context.
//!
//! An explicit, exact-source [`ReplaySourceReadPermit`] admits bounded original reads. The
//! retained replay receipt is evidence, never present authority. Deployment deletion state
//! gates the complete receipt closure before original I/O, and matching deployment prefixes
//! bracket the native query. These separately verified owners are not an atomic snapshot.

mod permit;
mod projection;
/// Recorder assertions reconstructed from an exact completed deployment import.
pub mod retained;

pub use permit::ReplaySourceReadPermit;

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, MissionId, PrincipalId, QueryCompletenessRequested,
    QueryInterpretation, QueryReadReceipt, RuntimeGrant, SessionId, admit_query_read,
    reference_contract_basis,
};
use fss_object::SpoolIo;

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::rtsp::recording_replay::ReplayReceipt;
use crate::rtsp::recording_replay::time::ReplayTimeQuery;
use crate::rtsp::recording_replay::time::pinned::{
    ReplayTimeReadError, ReplayTimeReadLimits, ReplayTimeReadReport,
    query_replay_time_read_only_admitted,
};

/// Exact native request and an independent current deployment precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingReplayContextRequest {
    /// Explicit codec, source pins, replay receipt/request, NTP era and UTC interval.
    pub replay: ReplayTimeQuery,
    /// Audit identity, matched to the independently supplied source authority.
    pub principal: PrincipalId,
    /// Optional current deployment authority/effect-prefix precondition.
    pub expected_anchor: Option<AnchorToken>,
}

/// Independent cumulative allowances for deployment, archive metadata and native originals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingReplayContextLimits {
    /// Per-input deployment metadata bounds.
    pub snapshot: OrientLimits,
    /// Aggregate deployment metadata bytes across both history reads.
    pub deployment_bytes: usize,
    /// Aggregate deployment payload reads, including rereads.
    pub deployment_reads: usize,
    /// Native metadata and original verification allowances; neither refills per window.
    pub replay: ReplayTimeReadLimits,
}

impl Default for RecordingReplayContextLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            deployment_bytes: 256 * 1024 * 1024,
            deployment_reads: 65_536,
            replay: ReplayTimeReadLimits::default(),
        }
    }
}

impl RecordingReplayContextLimits {
    fn validate(&self) -> Result<(), RecordingReplayContextError> {
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
                return Err(RecordingReplayContextError::InvalidRequest);
            }
        }
        self.replay
            .validate()
            .map_err(RecordingReplayContextError::Replay)
    }

    /// Combined declared cost, preserving separate metered counters in the result.
    pub fn allowance(&self) -> Result<BudgetVector, RecordingReplayContextError> {
        self.validate()?;
        let (bytes, calls) = permit::read_allowance(self.replay)?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: (self.deployment_bytes as u64)
                .checked_add(bytes)
                .ok_or(RecordingReplayContextError::InvalidRequest)?,
            storage_operations: (self.deployment_reads as u64)
                .checked_add(calls)
                .ok_or(RecordingReplayContextError::InvalidRequest)?,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Whole-query refusal; no partial native rows or original bytes are released.
#[derive(Debug)]
pub enum RecordingReplayContextError {
    /// Unsupported request, path or allowance, rejected before archive I/O.
    InvalidRequest,
    /// Missing, mismatched, cancelled, expired or insufficient source authority.
    Unauthorized,
    /// Protected deployment metadata could not be verified.
    Deployment(DeploymentReadError),
    /// Exact native custody, scope, budget or recorder-time verification refused.
    Replay(ReplayTimeReadError),
    /// Current imported custody, bounded immutable reads or final revalidation refused.
    RetainedSource(crate::ingest::FileIngestError),
    /// Native recorder projection from imported original custody refused.
    RetainedReplay(crate::ingest::rtsp_import::replay::RetainedReplayTimeError),
    /// Current deployment prefix, layout or deletion state refuses the observation.
    AnchorChanged,
    /// The shared deployment metadata allowance was exhausted.
    OverBudget,
    /// Cooperative cancellation requested before another bounded phase.
    Cancelled,
    /// A verified observation could not satisfy the existing AOP-005 contract.
    Contract,
}

impl std::fmt::Display for RecordingReplayContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid recorder-time query request or allowance",
            Self::Unauthorized => "recorder-time source verification is not authorized",
            Self::Deployment(_) => "deployment metadata verification failed",
            Self::Replay(_) => "native recorder-time verification refused",
            Self::RetainedSource(_) => "retained recorder custody verification refused",
            Self::RetainedReplay(_) => "retained recorder-time verification refused",
            Self::AnchorChanged => "deployment authority, layout or deletion state refused",
            Self::OverBudget => "deployment metadata read allowance exhausted",
            Self::Cancelled => "recorder-time query cancelled",
            Self::Contract => "recorder-time query contract admission failed",
        })
    }
}
impl std::error::Error for RecordingReplayContextError {}

/// Unchanged native source evidence together with independently protected deployment context.
#[derive(Debug)]
pub struct DeploymentRecordingReplayQuery {
    /// Deployment metadata bracketed by matching authority/effect-prefix observations.
    pub snapshot: DeploymentSnapshot,
    /// Current deployment prefix, distinct from the historical original-source anchor.
    pub anchor_token: String,
    /// Complete byte-free native report and actual metadata/original read accounting.
    pub native: ReplayTimeReadReport,
    /// AOP-005 plan explicitly declaring the independently granted source verification.
    pub plan: AgentQueryPlan,
    /// Canonical read admission; this does not grant source or effect authority.
    pub admission: QueryReadReceipt,
    /// Exact principal, current prefix, native query, source grant and limits.
    pub request_digest: ContentDigest,
    /// Exact request, native result/index and plan identity.
    pub decision_digest: ContentDigest,
    /// Semantic source grant identity, excluding process-local execution clock readings.
    pub source_permit_digest: ContentDigest,
    /// Deterministic read session label, not a durable workspace.
    pub session_id: SessionId,
    /// Deterministic recorder-time query mission label.
    pub mission_id: MissionId,
    /// Aggregate deployment bytes across both prefix observations.
    pub deployment_bytes_read: u64,
    /// Aggregate deployment payload reads across both observations.
    pub deployment_metadata_reads: u64,
}

/// Verify exact native recorder assertions under an independently supplied current source grant.
///
/// The last callback checkpoint admits a bounded synchronous final deployment observation.
/// No caller callback runs after its authority/deletion comparison. A frontend must separately
/// gate actual response delivery on its execution deadline. No writer, recovery, archive scan,
/// device connection or media disclosure occurs.
#[allow(clippy::too_many_arguments)]
pub fn query_recordings_replay_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingReplayContextRequest,
    limits: &RecordingReplayContextLimits,
    permit: Option<&ReplaySourceReadPermit<'_>>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingReplayQuery, RecordingReplayContextError> {
    let native_request = request
        .replay
        .digest()
        .map_err(|error| RecordingReplayContextError::Replay(ReplayTimeReadError::Query(error)))?;
    limits.validate()?;
    if !deployment_root.is_absolute()
        || !archive_root.is_absolute()
        || !(1..=128).contains(&request.replay.limits.max_results)
    {
        return Err(RecordingReplayContextError::InvalidRequest);
    }
    let permit = permit.ok_or(RecordingReplayContextError::Unauthorized)?;
    permit.check(request, limits.replay, native_request)?;
    let checkpoint = || {
        if cancelled() {
            Err(RecordingReplayContextError::Cancelled)
        } else {
            permit.check_current()
        }
    };
    checkpoint()?;
    let budget = MetadataReadBudget::new(limits.deployment_bytes, limits.deployment_reads);
    let history = DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
        .map_err(RecordingReplayContextError::Deployment)?;
    let snapshot = history
        .snapshot_at(history.head())
        .map_err(RecordingReplayContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingReplayContextError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|a| a.as_str() != anchor_token)
        || snapshot
            .deletions
            .object(request.replay.receipt_root)
            .is_some()
    {
        return Err(RecordingReplayContextError::AnchorChanged);
    }
    checkpoint()?;
    let source_cancelled = || cancelled() || permit.check_current().is_err();
    let native = query_replay_time_read_only_admitted(
        io,
        archive_root,
        &request.replay,
        limits.replay,
        &source_cancelled,
        |receipt| !receipt_deleted(&snapshot, receipt),
    )
    .map_err(|error| match error {
        ReplayTimeReadError::AdmissionDenied => RecordingReplayContextError::AnchorChanged,
        other => RecordingReplayContextError::Replay(other),
    })?;
    checkpoint()?;
    let final_history =
        DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
            .map_err(RecordingReplayContextError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(RecordingReplayContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingReplayContextError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || receipt_deleted(&final_snapshot, &native.report.receipt)
    {
        return Err(RecordingReplayContextError::AnchorChanged);
    }

    // Only pure bounded projection follows the final current-authority observation.
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let source_permit_digest = permit.digest();
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recording_replay_query.request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    request.principal.encode_canonical(&mut e);
    e.digest(native_request);
    e.digest(source_permit_digest);
    for value in [
        limits.deployment_bytes,
        limits.deployment_reads,
        limits.snapshot.max_layout_bytes,
        limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes,
        limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        e.u64(value as u64);
    }
    let request_digest = ContentDigest::sha256(&e.finish());
    let suffix = request_digest.to_text();
    let suffix = suffix.strip_prefix("sha256:").unwrap_or(&suffix);
    let session_id = SessionId::parse(format!("session:recordings-replay:{suffix}"))
        .map_err(|_| RecordingReplayContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings-replay:{suffix}"))
        .map_err(|_| RecordingReplayContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.replay.limits.max_results as u32,
        allowance,
    )
    .map_err(|_| RecordingReplayContextError::Contract)?;
    let description = "Exact native recorder UTC assertions from independently authorized, reverified original RTP; byte-free sample and source-only evidence with explicit unknowns";
    let interpretation_id = "interpretation:pinned-native-recorder-time";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| RecordingReplayContextError::Contract)?;
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
        vec![native.report.receipt.root().to_text()],
        vec![
            "recording_window".to_owned(),
            "recorder_time_assertion".to_owned(),
        ],
        vec![
            RuntimeGrant::AgentQuery.as_str().to_owned(),
            RuntimeGrant::ReadMedia.as_str().to_owned(),
        ],
        vec![
            "source_verification_only".to_owned(),
            "byte_free_result".to_owned(),
        ],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        interpretation_id,
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )
    .map_err(|_| RecordingReplayContextError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recording_replay_query.decision.v1");
    e.digest(request_digest);
    e.digest(native.report.digest);
    e.digest(native.report.index_digest);
    e.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&e.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingReplayQuery {
        snapshot,
        anchor_token,
        native,
        plan,
        admission,
        request_digest,
        decision_digest,
        source_permit_digest,
        session_id,
        mission_id,
        deployment_bytes_read,
        deployment_metadata_reads,
    })
}

fn receipt_deleted(snapshot: &DeploymentSnapshot, receipt: &ReplayReceipt) -> bool {
    std::iter::once(receipt.root())
        .chain(receipt.manifest().children().iter().copied())
        .any(|digest| snapshot.deletions.object(digest).is_some())
}
