#![forbid(unsafe_code)]
//! Canonical QSR reads from immutable retained, screened detector evidence.
//!
//! A separate exact source-read permit admits internal custody verification. One immutable
//! owner covers history, native reconstruction and final revalidation without a writer,
//! recovery, inference, disclosure or effect capability.

mod projection;

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, ContextAuthority, DigestAlgorithm, EnvelopeEpistemic,
    MissionId, PrincipalId, QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt,
    RuntimeGrant, SessionId, TimestampNs, admit_query_read, reference_contract_basis,
};

use crate::ReplayCx;
use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{DeploymentSnapshot, OrientLimits};
use crate::ingest::FileIngestError;
use crate::ingest::qsr_observations::{QsrConfig, QsrError, QsrObservationReport};
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};

/// Exact retained screened report and operator-declared roles; no new geometry or model input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrQueryRequest {
    /// Digest of a retained screened package-zone report, not a loose file or JSON report.
    pub report_digest: ContentDigest,
    /// Bounded annotations over that report's existing zones.
    pub config: QsrConfig,
    /// Operator-supplied audit principal, separately bound by the source-read grant.
    pub principal: PrincipalId,
    /// Optional exact current authority/effect-history precondition.
    pub expected_anchor: Option<AnchorToken>,
}

impl QsrQueryRequest {
    /// Validate complete request shape without opening the deployment.
    pub fn validate(&self) -> Result<(), QsrQueryError> {
        if self.report_digest.algorithm() != DigestAlgorithm::Sha256
            || self.report_digest.bytes() == [0; 32]
        {
            return Err(QsrQueryError::InvalidRequest);
        }
        self.config
            .validate_shape()
            .map_err(|_| QsrQueryError::InvalidRequest)
    }
}

/// One nonrenewing byte/read-attempt allowance for the whole native read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QsrQueryLimits {
    /// Metadata, retained source payloads and final revalidation share this owner budget.
    pub read: ImmutableRetainedReadLimits,
}

impl Default for QsrQueryLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: 1024 * 1024 * 1024,
                max_read_objects: 1_000_000,
            },
        }
    }
}

impl QsrQueryLimits {
    /// Refuse invalid or widened native bounds before filesystem access.
    pub fn validate(&self) -> Result<(), QsrQueryError> {
        let ceiling = OrientLimits::default();
        if self.read.max_read_bytes == 0
            || self.read.max_read_bytes as u64 > 4_u64 * 1024 * 1024 * 1024
            || !(1..=4_000_000).contains(&self.read.max_read_objects)
        {
            return Err(QsrQueryError::InvalidRequest);
        }
        for (value, maximum) in [
            (
                self.read.snapshot.max_layout_bytes,
                ceiling.max_layout_bytes,
            ),
            (
                self.read.snapshot.max_journal_bytes,
                ceiling.max_journal_bytes,
            ),
            (
                self.read.snapshot.max_object_bytes,
                ceiling.max_object_bytes,
            ),
            (self.read.snapshot.max_events, ceiling.max_events),
            (
                self.read.snapshot.max_revisions_per_event,
                ceiling.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(QsrQueryError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Payload-byte and read-attempt accounting, not filesystem syscall or CPU accounting.
    pub fn allowance(&self) -> Result<BudgetVector, QsrQueryError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Complete refusal. No missing evidence or failed verification becomes an empty observation.
#[derive(Debug)]
pub enum QsrQueryError {
    /// Malformed pins, annotations or limits.
    InvalidRequest,
    /// Missing, stale or mismatched independent source-read authority.
    Unauthorized,
    /// Immutable current history, custody or source revalidation failed.
    Source(FileIngestError),
    /// The existing native screened observation owner refused.
    Observation(QsrError),
    /// Current authority/effect prefix did not match the caller's exact precondition.
    AnchorChanged,
    /// A cancellation or cooperative deadline was observed.
    Cancelled,
    /// Complete semantic rows exceeded the existing cognitive-envelope limits.
    ResultLimit,
    /// The registered read plan or envelope could not be constructed.
    Contract,
}

impl QsrQueryError {
    /// Stable payload-free diagnostic; original paths and source values are never echoed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "qsr.query.invalid_request",
            Self::Unauthorized => "qsr.query.unauthorized",
            Self::Source(_) => "qsr.query.source_unavailable",
            Self::Observation(_) => "qsr.query.observation_unavailable",
            Self::AnchorChanged => "qsr.query.anchor_changed",
            Self::Cancelled => "qsr.query.cancelled",
            Self::ResultLimit => "qsr.query.result_limit",
            Self::Contract => "qsr.query.contract",
        }
    }
}
impl std::fmt::Display for QsrQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for QsrQueryError {}

fn input_digest(
    request: &QsrQueryRequest,
    limits: QsrQueryLimits,
) -> Result<ContentDigest, QsrQueryError> {
    request.validate()?;
    limits.validate()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_qsr_query.input.v1");
    e.digest(request.report_digest);
    request.principal.encode_canonical(&mut e);
    e.text(
        request
            .expected_anchor
            .as_ref()
            .map_or("", AnchorToken::as_str),
    );
    // Role order has no meaning; the explicit lane-stage order does.
    let mut roles: Vec<_> = request.config.zone_roles.iter().collect();
    roles.sort_by(|left, right| left.zone.cmp(&right.zone));
    e.u64(roles.len() as u64);
    for role in roles {
        e.text(&role.zone);
        e.text(role.role.as_str());
    }
    e.u64(request.config.lane_stages.len() as u64);
    for stage in &request.config.lane_stages {
        e.text(stage);
    }
    for value in [
        limits.read.max_read_bytes,
        limits.read.max_read_objects,
        limits.read.snapshot.max_layout_bytes,
        limits.read.snapshot.max_journal_bytes,
        limits.read.snapshot.max_object_bytes,
        limits.read.snapshot.max_events,
        limits.read.snapshot.max_revisions_per_event,
    ] {
        e.u64(value as u64);
    }
    Ok(ContentDigest::sha256(&e.finish()))
}

/// Current source-verification permission for one exact report, root, principal and read budget.
/// It permits internal source reconstruction only; it never permits source-media disclosure.
pub struct QsrSourceReadPermit<'a> {
    authority: &'a ContextAuthority,
    now: &'a (dyn Fn() -> TimestampNs + Sync),
    cx: ReplayCx,
    input: ContentDigest,
    digest: ContentDigest,
}

impl<'a> QsrSourceReadPermit<'a> {
    /// Pure grant admission. The authority universe is the exact retained report, generation 1.
    pub fn authorize(
        authority: &'a ContextAuthority,
        root: &Path,
        request: &QsrQueryRequest,
        limits: QsrQueryLimits,
        now: &'a (dyn Fn() -> TimestampNs + Sync),
    ) -> Result<Self, QsrQueryError> {
        let input = input_digest(request, limits)?;
        authority
            .validate()
            .map_err(|_| QsrQueryError::Unauthorized)?;
        if !root.is_absolute()
            || !authority.budgets.is_valid()
            || !limits.allowance()?.fits_within(authority.budgets)
            || authority.principal != request.principal.as_str()
            || authority.anchor_universe != request.report_digest
            || authority.generation != 1
            || !authority.has_capability(RuntimeGrant::AgentQuery.as_str())
            || !authority.has_capability(RuntimeGrant::ReadMedia.as_str())
        {
            return Err(QsrQueryError::Unauthorized);
        }
        let cx = ReplayCx::from_context_authority_read_only(authority, root)
            .map_err(|_| QsrQueryError::Unauthorized)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_qsr_query.source_permit.v1");
        e.digest(input);
        e.text(RuntimeGrant::AgentQuery.as_str());
        e.text(RuntimeGrant::ReadMedia.as_str());
        e.text("ADP-REPLAY-001");
        e.text(&authority.privacy_scope);
        e.text(&authority.retention_scope);
        let permit = Self {
            authority,
            now,
            cx,
            input,
            digest: ContentDigest::sha256(&e.finish()),
        };
        permit.check_current()?;
        Ok(permit)
    }

    /// Portable semantic grant identity; private filesystem paths are excluded.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    fn check_current(&self) -> Result<(), QsrQueryError> {
        if self.authority.cancellation_reason.is_some()
            || self.cx.is_cancelled()
            || self
                .authority
                .deadline
                .is_some_and(|deadline| (self.now)() >= deadline)
        {
            return Err(QsrQueryError::Unauthorized);
        }
        Ok(())
    }
}

impl Drop for QsrSourceReadPermit<'_> {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
    }
}

/// Complete native observations and canonical read context after final immutable revalidation.
#[derive(Debug)]
pub struct DeploymentQsrQuery {
    /// Verified current metadata snapshot; no publisher or recovery handle was constructed.
    pub snapshot: DeploymentSnapshot,
    /// Exact current authority and effect prefix, separate from historical source anchors.
    pub anchor_token: String,
    /// Unchanged native sampled observation identities and full reconstruction result.
    pub report: QsrObservationReport,
    /// Complete row projection, admitted before final authority revalidation.
    pub epistemic: EnvelopeEpistemic,
    /// Shared payload-read accounting including final revalidation.
    pub read_usage: RetainedReadUsage,
    /// Registered AOP-005 read plan.
    pub plan: AgentQueryPlan,
    /// Registered query admission receipt; confers no effect authority.
    pub admission: QueryReadReceipt,
    /// Exact input, source permit and current authority identity.
    pub request_digest: ContentDigest,
    /// Request, original native report, whole-lane companion and canonical plan identity.
    pub decision_digest: ContentDigest,
    /// Separate internal source-verification grant identity.
    pub source_permit_digest: ContentDigest,
    /// Deterministic ephemeral read session; no session is persisted.
    pub session_id: SessionId,
    /// Deterministic bounded read mission.
    pub mission_id: MissionId,
}

/// Read one exact screened QSR report with no writable deployment, recovery, model or effect.
pub fn query_qsr_in_deployment(
    root: &Path,
    request: &QsrQueryRequest,
    limits: QsrQueryLimits,
    permit: Option<&QsrSourceReadPermit<'_>>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentQsrQuery, QsrQueryError> {
    let input = input_digest(request, limits)?;
    let permit = permit.ok_or(QsrQueryError::Unauthorized)?;
    if permit.input != input || permit.cx.root_dir() != root {
        return Err(QsrQueryError::Unauthorized);
    }
    permit.check_current()?;
    let stopped = || cancelled() || permit.check_current().is_err();
    if stopped() {
        return Err(QsrQueryError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &permit.cx, &stopped)
        .map_err(QsrQueryError::Source)?;
    let anchor_token = snapshot_anchor_token(owner.snapshot());
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|pin| pin.as_str() != anchor_token)
    {
        return Err(QsrQueryError::AnchorChanged);
    }
    let report = QsrObservationReport::open_retained(
        &owner,
        request.report_digest,
        request.config.clone(),
        &permit.cx,
    )
    .map_err(QsrQueryError::Observation)?;
    let epistemic = projection::epistemic(&report)?;
    if stopped() {
        return Err(QsrQueryError::Cancelled);
    }
    owner.revalidate().map_err(QsrQueryError::Source)?;
    // Only pure projection follows the last authority observation; no caller callback or I/O.
    let snapshot = owner.snapshot().clone();
    let read_usage = owner.usage();
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let source_permit_digest = permit.digest();
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_qsr_query.request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    e.digest(input);
    e.digest(source_permit_digest);
    let request_digest = ContentDigest::sha256(&e.finish());
    let text = request_digest.to_text();
    let suffix = &text[7..];
    let session_id =
        SessionId::parse(format!("session:qsr:{suffix}")).map_err(|_| QsrQueryError::Contract)?;
    let mission_id =
        MissionId::parse(format!("mission:qsr:{suffix}")).map_err(|_| QsrQueryError::Contract)?;
    let admission = admit_query_read(&basis, &snapshot.anchor, "query", 1, allowance)
        .map_err(|_| QsrQueryError::Contract)?;
    let description = "Complete sampled QSR observations from one retained screened detector report; no inference, source disclosure, physical identity, service duration or absence claim";
    let interpretation_id = "interpretation:retained-screened-qsr";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| QsrQueryError::Contract)?;
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
        vec![request.report_digest.to_text()],
        vec![
            "retained_screened_package_zones".to_owned(),
            "sampled_qsr_observations".to_owned(),
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
    .map_err(|_| QsrQueryError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_qsr_query.lane_decision.v1");
    e.digest(request_digest);
    e.digest(report.digest());
    e.digest(report.lane_traversals().digest());
    e.digest(plan.plan_digest());
    Ok(DeploymentQsrQuery {
        snapshot,
        anchor_token,
        report,
        epistemic,
        read_usage,
        plan,
        admission,
        request_digest,
        decision_digest: ContentDigest::sha256(&e.finish()),
        source_permit_digest,
        session_id,
        mission_id,
    })
}
