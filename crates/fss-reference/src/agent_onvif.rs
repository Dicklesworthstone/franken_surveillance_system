#![forbid(unsafe_code)]
//! AOP-005 ONVIF cognition from exact retained sources and current read-only deployment context.
//!
//! Deployment history brackets two complete original-source reconstruction/projection passes.
//! Both history reads share one metadata balance, and all source reads share one real immutable
//! closure capability. No publisher/recovery handle, live device or effect path is opened.

mod projection;

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, MissionId, PrincipalId, QueryCompletenessRequested,
    QueryInterpretation, QueryReadReceipt, SessionId, admit_query_read, reference_contract_basis,
};
use fss_object::SpoolIo;

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
pub use crate::onvif::metadata::read_view::{
    OnvifAnalysis, OnvifAnalysisResult, OnvifReadError, OnvifReadLimits, OnvifReadResult,
};
use crate::onvif::metadata::read_view::{read_analysis, validate_pins};
use crate::onvif::metadata::tracks::{MAX_TRACK_SOURCES, TrackSourcePin};

/// Exact finite vendor-claim interpretation. Principal is an audit label, not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifQueryRequest {
    /// Ordered source identities and publication roots; each pin is a continuity boundary.
    pub sources: Vec<TrackSourcePin>,
    /// Tracks, lifecycle or an explicitly pinned raw-coordinate zone policy.
    pub analysis: OnvifAnalysis,
    /// Maximum complete semantic synopsis rows, 1..32; no truncation or inferred continuation.
    pub max_entries: usize,
    /// Operator-bound audit principal.
    pub principal: PrincipalId,
    /// Optional exact current deployment authority/effect-history precondition.
    pub expected_anchor: Option<AnchorToken>,
}
impl OnvifQueryRequest {
    /// Validate the complete request before history or source I/O.
    pub fn validate(&self) -> Result<(), OnvifQueryError> {
        if !(1..=32).contains(&self.max_entries) {
            return Err(OnvifQueryError::InvalidRequest);
        }
        validate_pins(&self.sources, MAX_TRACK_SOURCES).map_err(OnvifQueryError::Source)?;
        if let OnvifAnalysis::Zones(policy) = &self.analysis {
            policy
                .validate()
                .map_err(|e| OnvifQueryError::Source(e.into()))?;
        }
        Ok(())
    }
}

/// One fixed budget for both deployment observations and one for both complete source passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnvifQueryLimits {
    /// Per-file and semantic deployment-history limits.
    pub snapshot: OrientLimits,
    /// Cumulative deployment metadata bytes, including deletion proof objects and rereads.
    pub deployment_bytes: usize,
    /// Cumulative deployment payload-read attempts; not source filesystem calls.
    pub deployment_reads: usize,
    /// Exact source closure and computation allowances.
    pub source: OnvifReadLimits,
}
impl Default for OnvifQueryLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            deployment_bytes: 256 * 1024 * 1024,
            deployment_reads: 65_536,
            source: OnvifReadLimits::default(),
        }
    }
}
impl OnvifQueryLimits {
    fn validate(&self, analysis: &OnvifAnalysis) -> Result<(), OnvifQueryError> {
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
                return Err(OnvifQueryError::InvalidRequest);
            }
        }
        self.source
            .validate(analysis)
            .map_err(OnvifQueryError::Source)
    }
    /// Combined declared byte/storage budget. Individual counters retain their own meanings.
    pub fn allowance(&self) -> Result<BudgetVector, OnvifQueryError> {
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: (self.deployment_bytes as u64)
                .checked_add(self.source.custody.max_read_bytes)
                .ok_or(OnvifQueryError::InvalidRequest)?,
            storage_operations: (self.deployment_reads as u64)
                .checked_add(self.source.custody.max_io_calls)
                .ok_or(OnvifQueryError::InvalidRequest)?,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Whole-response refusal. Missing or unknown evidence never becomes a successful empty set.
#[derive(Debug)]
pub enum OnvifQueryError {
    /// Invalid source, analysis, row count or resource policy.
    InvalidRequest,
    /// Read-only deployment metadata verification failed.
    Deployment(DeploymentReadError),
    /// Original retained sources or their derived interpretation could not be verified.
    Source(OnvifReadError),
    /// Current authority, layout, effects or deletion state changed.
    AnchorChanged,
    /// Shared deployment metadata allowance was exhausted.
    OverBudget,
    /// Cooperative cancellation was observed before another bounded phase.
    Cancelled,
    /// Complete synopsis needs more rows than explicitly admitted; no partial result returned.
    ResultLimit,
    /// Canonical AOP-005 plan/read admission failed.
    Contract,
}
impl OnvifQueryError {
    /// Stable payload-free refusal, without root paths or vendor identifiers.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "onvif.query.invalid_request",
            Self::Deployment(_) => "onvif.query.deployment",
            Self::Source(e) => e.code(),
            Self::AnchorChanged => "onvif.query.anchor_changed",
            Self::OverBudget => "onvif.query.over_budget",
            Self::Cancelled => "onvif.query.cancelled",
            Self::ResultLimit => "onvif.query.result_limit",
            Self::Contract => "onvif.query.contract",
        }
    }
}
impl std::fmt::Display for OnvifQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for OnvifQueryError {}

/// Exact finite ONVIF interpretation inside the existing protected canonical agent context.
#[derive(Clone, Debug)]
pub struct DeploymentOnvifQuery {
    /// Current metadata-only deployment snapshot; spool doctor was not run.
    pub snapshot: DeploymentSnapshot,
    /// Matching pre/post authority/effect prefix, distinct from each source publication anchor.
    pub anchor_token: String,
    /// Complete source-verified cognitive result and accounting.
    pub native: OnvifReadResult,
    /// Existing canonical AOP-005 query plan.
    pub plan: AgentQueryPlan,
    /// Existing canonical read admission; grants no new filesystem or effect capability.
    pub admission: QueryReadReceipt,
    /// Exact principal, source/policy/limits and current deployment identity.
    pub request_digest: ContentDigest,
    /// Complete native interpretation plus canonical plan identity.
    pub decision_digest: ContentDigest,
    /// Deterministic ephemeral query session; nothing is persisted.
    pub session_id: SessionId,
    /// Deterministic bounded interpretation objective.
    pub mission_id: MissionId,
    /// Actual bytes across both read-only deployment observations.
    pub deployment_bytes_read: u64,
    /// Actual deployment payload reads across both observations.
    pub deployment_metadata_reads: u64,
}

/// Query exact sources from the deployment's own retained object root without opening a writer.
/// Repeated checks are not an atomic snapshot or a promise of future source availability.
/// Cancellation is checked at phase boundaries and every source filesystem call. The last
/// checkpoint admits a bounded finalization phase: the existing synchronous deployment reader
/// reconstructs the final prefix, then only pure comparison/assembly remains. No caller callback
/// runs in or after that finalization, so it cannot mutate already-verified authority. A caller
/// must gate delivery if its cancellation/deadline arrives after finalization admission; the
/// canonical CLI does so after rendering. This API does not claim interruptible history reads.
pub fn query_onvif_in_deployment(
    io: &dyn SpoolIo,
    root: &Path,
    request: &OnvifQueryRequest,
    limits: OnvifQueryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentOnvifQuery, OnvifQueryError> {
    request.validate()?;
    limits.validate(&request.analysis)?;
    if !root.is_absolute() {
        return Err(OnvifQueryError::InvalidRequest);
    }
    let checkpoint = || {
        if cancelled() {
            Err(OnvifQueryError::Cancelled)
        } else {
            Ok(())
        }
    };
    let budget = MetadataReadBudget::new(limits.deployment_bytes, limits.deployment_reads);
    checkpoint()?;
    let history = DeploymentHistory::read_metadata(root, &limits.snapshot, &budget)
        .map_err(OnvifQueryError::Deployment)?;
    let snapshot = history
        .snapshot_at(history.head())
        .map_err(OnvifQueryError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| OnvifQueryError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|a| a.as_str() != anchor_token)
    {
        return Err(OnvifQueryError::AnchorChanged);
    }
    checkpoint()?;
    let native = read_analysis(
        io,
        history.replay_objects_root(),
        history.site_lineage(),
        history.batches_through_head(),
        &snapshot.deletions,
        &request.sources,
        &request.analysis,
        limits.source,
        cancelled,
    )
    .map_err(OnvifQueryError::Source)?;
    let entries = projection::entry_count(&native);
    if entries > request.max_entries {
        return Err(OnvifQueryError::ResultLimit);
    }
    checkpoint()?;
    let final_history = DeploymentHistory::read_metadata(root, &limits.snapshot, &budget)
        .map_err(OnvifQueryError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(OnvifQueryError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| OnvifQueryError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || native
            .reference_digests
            .iter()
            .any(|d| final_snapshot.deletions.object(*d).is_some())
    {
        return Err(OnvifQueryError::AnchorChanged);
    }
    // No caller callback or new source read follows the last authority comparison.
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_onvif.context_request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    request.principal.encode_canonical(&mut e);
    e.digest(native.request_digest);
    e.u64(request.max_entries as u64);
    for n in [
        limits.deployment_bytes,
        limits.deployment_reads,
        limits.snapshot.max_layout_bytes,
        limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes,
        limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        e.u64(n as u64);
    }
    let request_digest = ContentDigest::sha256(&e.finish());
    let suffix = request_digest.to_text();
    let suffix = &suffix[7..];
    let session_id = SessionId::parse(format!("session:onvif:{suffix}"))
        .map_err(|_| OnvifQueryError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:onvif:{suffix}"))
        .map_err(|_| OnvifQueryError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.max_entries as u32,
        allowance,
    )
    .map_err(|_| OnvifQueryError::Contract)?;
    let description = "Complete bounded redacted synopsis of retained vendor ONVIF claims, original tracklets and selected interpretation; no physical identity, coverage, absence, calibration, trusted time or effect authority";
    let interpretation_id = "interpretation:pinned-onvif-vendor-claims";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| OnvifQueryError::Contract)?;
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
        request.sources.iter().map(|p| p.root().to_text()).collect(),
        vec!["onvif_vendor_claim".to_owned()],
        vec![crate::agent_query::CAPABILITY_QUERY.to_owned()],
        vec!["vendor_values_redacted".to_owned()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        interpretation_id,
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )
    .map_err(|_| OnvifQueryError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_onvif.context_decision.v1");
    e.digest(request_digest);
    e.digest(native.decision_digest);
    e.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&e.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentOnvifQuery {
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
