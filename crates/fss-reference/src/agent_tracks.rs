#![forbid(unsafe_code)]
//! Source-verified, paginated AOP-005 observations of retained detector tracks.
//!
//! This bridge runs the existing bounded native tracker over one exact retained detector
//! report. It neither executes a model nor publishes an event. Every page reopens current
//! privacy, deletion and source custody through one immutable owner. Continuations bind
//! the complete native analysis, full authority/effect prefix, principal, tracking recipe,
//! page size and read allowance; a changed head never silently rebases a continuation.

mod projection;

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority, ContinuationCursor,
    ContinuationEntry, ContinuationError, ContinuationPage, ContinuationScope, ContinuationStream,
    ContinuationStreamPublishParams, DigestAlgorithm, EnvelopeCoverage, EnvelopeEpistemic,
    MissionId, PrincipalId, QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt,
    RuntimeGrant, SessionId, TimestampNs, admit_query_read, reference_contract_basis,
};

use crate::ReplayCx;
use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{DeploymentSnapshot, OrientLimits};
use crate::agent_query::QUERY_CURSOR_LIFETIME_NS;
use crate::ingest::FileIngestError;
use crate::ingest::package_event::{
    PackageAnalysisReport, PackageEventError, PackageObservation, PackageTrackingConfig,
};
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};

/// Maximum matched observations on one canonical page.
pub const MAX_TRACK_QUERY_ENTRIES: u32 = 32;
/// Default canonical page size.
pub const DEFAULT_TRACK_QUERY_ENTRIES: u32 = 16;
/// The native report admits at most 64 frames with 256 detections per frame.
pub const MAX_TRACK_QUERY_OBSERVATIONS: usize =
    crate::ingest::package_detect::MAX_PACKAGE_DETECT_FRAMES * 256;

/// One retained detector report and an exact model-vocabulary label/tracking recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackQueryRequest {
    /// Retained package-detection report digest; never a loose report file.
    pub report_digest: ContentDigest,
    /// Exact, case-sensitive member of the report's model vocabulary.
    pub label: String,
    /// Explicit native Kalman/IoU association and confirmation policy.
    pub config: PackageTrackingConfig,
    /// Audit principal independently bound by the source-read permit.
    pub principal: PrincipalId,
    /// Matched observations per page, in 1..=MAX_TRACK_QUERY_ENTRIES.
    pub max_entries: u32,
    /// Optional exact current authority/effect-history precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Exact native continuation from the preceding page, never a caller-supplied offset.
    pub continuation: Option<String>,
}

impl TrackQueryRequest {
    /// Validate scalar bounds before opening the deployment or reconstructing a track.
    pub fn validate(&self) -> Result<(), TrackQueryError> {
        if self.report_digest.algorithm() != DigestAlgorithm::Sha256
            || self.report_digest.bytes() == [0; 32]
            || self.label.is_empty()
            || self.label.len() > 512
            || self.label.chars().any(char::is_control)
            || self.config.confirmation_hits == 0
            || self.config.maximum_missed_frames == 0
            || self.config.minimum_iou_ppm > 1_000_000
            || !(1..=MAX_TRACK_QUERY_ENTRIES).contains(&self.max_entries)
            || self.continuation.as_ref().is_some_and(|token| {
                token.len() > 256
                    || !token.starts_with("continuation:")
                    || !token.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b':' | b'+' | b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(TrackQueryError::InvalidRequest);
        }
        Ok(())
    }
}

/// One nonrenewing allowance shared by metadata, original sources and final revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackQueryLimits {
    /// Exact native metadata and aggregate payload-read limits.
    pub read: ImmutableRetainedReadLimits,
}

impl Default for TrackQueryLimits {
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

impl TrackQueryLimits {
    /// Refuse invalid or widened native limits before filesystem access.
    pub fn validate(&self) -> Result<(), TrackQueryError> {
        let ceiling = OrientLimits::default();
        if self.read.max_read_bytes == 0
            || self.read.max_read_bytes as u64 > 4_u64 * 1024 * 1024 * 1024
            || !(1..=4_000_000).contains(&self.read.max_read_objects)
        {
            return Err(TrackQueryError::InvalidRequest);
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
                return Err(TrackQueryError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Payload-byte/read-attempt allowance, not measured CPU time or filesystem syscalls.
    pub fn allowance(&self) -> Result<BudgetVector, TrackQueryError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Complete refusal: missing or invalid evidence never becomes an empty successful page.
#[derive(Debug)]
pub enum TrackQueryError {
    /// Invalid report, label, recipe, page or read bounds.
    InvalidRequest,
    /// Missing, expired or mismatched independent source-verification authority.
    Unauthorized,
    /// Immutable authority, custody or source revalidation failed.
    Source(FileIngestError),
    /// The native source-verifying analysis refused.
    Analysis(PackageEventError),
    /// The caller's explicit current-head precondition no longer holds.
    AnchorChanged,
    /// A cooperative cancellation/deadline was observed.
    Cancelled,
    /// A native cursor does not belong to this exact bounded query.
    Continuation(ContinuationError),
    /// A complete semantic row or native observation set exceeded its hard bound.
    ResultLimit,
    /// The native row relationship or registered query contract could not be verified.
    Contract,
}

impl TrackQueryError {
    /// Stable payload-free diagnostics; paths and source payloads are never echoed.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "tracks.query.invalid_request",
            Self::Unauthorized => "tracks.query.unauthorized",
            Self::Source(_) => "tracks.query.source_unavailable",
            Self::Analysis(_) => "tracks.query.analysis_unavailable",
            Self::AnchorChanged => "tracks.query.anchor_changed",
            Self::Cancelled => "tracks.query.cancelled",
            Self::Continuation(_) => "tracks.query.continuation",
            Self::ResultLimit => "tracks.query.result_limit",
            Self::Contract => "tracks.query.contract",
        }
    }
}
impl std::fmt::Display for TrackQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for TrackQueryError {}
impl From<ContinuationError> for TrackQueryError {
    fn from(error: ContinuationError) -> Self {
        Self::Continuation(error)
    }
}

// Page-independent inputs. Anchor preconditions are checked separately against the actual
// full current anchor; continuation tokens select a page without changing the stream.
fn selection_input_digest(
    request: &TrackQueryRequest,
    limits: TrackQueryLimits,
) -> Result<ContentDigest, TrackQueryError> {
    request.validate()?;
    limits.validate()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.selection_input.v1");
    e.digest(request.report_digest);
    e.text(&request.label);
    e.u32(request.config.confirmation_hits);
    e.u32(request.config.maximum_missed_frames);
    e.u32(request.config.minimum_iou_ppm);
    request.principal.encode_canonical(&mut e);
    e.u32(request.max_entries);
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

fn input_digest(
    request: &TrackQueryRequest,
    limits: TrackQueryLimits,
) -> Result<ContentDigest, TrackQueryError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.input.v1");
    e.digest(selection_input_digest(request, limits)?);
    e.text(
        request
            .expected_anchor
            .as_ref()
            .map_or("", AnchorToken::as_str),
    );
    e.text(request.continuation.as_deref().unwrap_or(""));
    Ok(ContentDigest::sha256(&e.finish()))
}

/// Internal source-verification grant for an exact query page, root, principal and allowance.
/// It grants neither source-media disclosure, inference, event publication nor effects.
pub struct TrackSourceReadPermit<'a> {
    authority: &'a ContextAuthority,
    now: &'a (dyn Fn() -> TimestampNs + Sync),
    cx: ReplayCx,
    input: ContentDigest,
    scope_digest: ContentDigest,
    digest: ContentDigest,
}

impl<'a> TrackSourceReadPermit<'a> {
    /// Pure admission with the retained report as authority universe, generation 1.
    pub fn authorize(
        authority: &'a ContextAuthority,
        root: &Path,
        request: &TrackQueryRequest,
        limits: TrackQueryLimits,
        now: &'a (dyn Fn() -> TimestampNs + Sync),
    ) -> Result<Self, TrackQueryError> {
        let input = input_digest(request, limits)?;
        authority
            .validate()
            .map_err(|_| TrackQueryError::Unauthorized)?;
        if !root.is_absolute()
            || !authority.budgets.is_valid()
            || !limits.allowance()?.fits_within(authority.budgets)
            || authority.principal != request.principal.as_str()
            || authority.anchor_universe != request.report_digest
            || authority.generation != 1
            || !authority.has_capability(RuntimeGrant::AgentQuery.as_str())
            || !authority.has_capability(RuntimeGrant::ReadMedia.as_str())
        {
            return Err(TrackQueryError::Unauthorized);
        }
        let cx = ReplayCx::from_context_authority_read_only(authority, root)
            .map_err(|_| TrackQueryError::Unauthorized)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_tracks_query.source_scope.v1");
        e.digest(selection_input_digest(request, limits)?);
        e.text(RuntimeGrant::AgentQuery.as_str());
        e.text(RuntimeGrant::ReadMedia.as_str());
        e.text("ADP-REPLAY-001");
        e.text(&authority.privacy_scope);
        e.text(&authority.retention_scope);
        let scope_digest = ContentDigest::sha256(&e.finish());
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_tracks_query.source_permit.v1");
        e.digest(scope_digest);
        e.digest(input);
        let permit = Self {
            authority,
            now,
            cx,
            input,
            scope_digest,
            digest: ContentDigest::sha256(&e.finish()),
        };
        permit.check_current()?;
        Ok(permit)
    }

    /// Portable semantic grant identity, excluding private filesystem paths.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    fn check_current(&self) -> Result<(), TrackQueryError> {
        if self.authority.cancellation_reason.is_some()
            || self.cx.is_cancelled()
            || self
                .authority
                .deadline
                .is_some_and(|deadline| (self.now)() >= deadline)
        {
            return Err(TrackQueryError::Unauthorized);
        }
        Ok(())
    }
}

impl Drop for TrackSourceReadPermit<'_> {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
    }
}

/// One complete actual matched observation, with its exact native source-frame relationship.
/// Track identity is analysis-local association, never physical identity. Native reports do
/// not retain predicted-only/missed-frame boxes; this bridge does not invent such samples.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackObservationRow {
    /// Content-bound row identity used by the native continuation entry.
    pub row_digest: ContentDigest,
    /// Native identity, bound to the retained record, label, recipe and local tracker id.
    pub track_identity: ContentDigest,
    /// Native analysis-local tracker id; never recycled across source discontinuities.
    pub track_id: u64,
    /// Display-order index within this track's actual matched observations.
    pub observation_index: u64,
    /// Display-order index of the corresponding source frame in the retained record.
    pub frame_index: u64,
    /// Zero-based continuity epoch; explicit source boundaries start fresh tracking state.
    pub continuity_epoch: u64,
    /// Whether this exact sample had reached the configured confirmation hit count.
    pub sample_confirmed: bool,
    /// Whether this track was ever confirmed; does not rewrite earlier tentative samples.
    pub track_ever_confirmed: bool,
    /// Exact native assigned detection and filtered box, without row substitution.
    pub observation: PackageObservation,
    /// Source sensor recorded for this exact frame.
    pub sensor_id: String,
    /// Conservative capture bounds; no inferred UTC conversion.
    pub capture: CaptureInterval,
    /// Coded source dimensions.
    pub dimensions: [u32; 2],
    /// Recorded source colour path.
    pub color: String,
    /// Exact retained inference identity for this frame.
    pub inference_identity: ContentDigest,
    /// Exact output tensor digest.
    pub output_digest: ContentDigest,
    /// Exact head projection report digest.
    pub detection_report_digest: ContentDigest,
    /// Source-grid clipping flag of the actual assigned row, absent only with no assignment.
    pub detection_clipped: Option<bool>,
}

/// One complete bounded page after source reconstruction and final immutable revalidation.
#[derive(Debug)]
pub struct DeploymentTrackQuery {
    /// Verified current metadata without writer ownership or recovery.
    pub snapshot: DeploymentSnapshot,
    /// Current full authority/effect-prefix identity, distinct from historical source anchors.
    pub anchor_token: String,
    /// Complete unchanged native reconstruction; its digest binds every selected observation.
    pub report: PackageAnalysisReport,
    /// Complete matched observations on this page, in native track then display order.
    pub observations: Vec<TrackObservationRow>,
    /// Bounded complete-row metadata projection, including source/recipe and coverage limits.
    pub epistemic: EnvelopeEpistemic,
    /// Aggregate payload accounting including final source and authority revalidation.
    pub read_usage: RetainedReadUsage,
    /// Registered AOP-005 plan, stable across this exact stream's pages.
    pub plan: AgentQueryPlan,
    /// Registered bounded read admission; grants no effects.
    pub admission: QueryReadReceipt,
    /// Exact input, admitted source permit and native cursor identity.
    pub request_digest: ContentDigest,
    /// Complete ordered native observation set and plan witness.
    pub selection_witness: ContentDigest,
    /// Request, page and native analysis decision identity.
    pub decision_digest: ContentDigest,
    /// Independent internal source-verification permit identity.
    pub source_permit_digest: ContentDigest,
    /// Deterministic ephemeral session; no durable session is created.
    pub session_id: SessionId,
    /// Deterministic bounded read mission.
    pub mission_id: MissionId,
    /// Actual matched observations in the complete native analysis, including tentative ones.
    pub total_observations: usize,
    /// Native cursor used for this page.
    pub cursor: ContinuationCursor,
    /// Native page and exact next continuation, when any observations remain.
    pub page: ContinuationPage,
}

impl DeploymentTrackQuery {
    /// Matched observations still available after this page, not missing physical detections.
    #[must_use]
    pub fn remaining_observations(&self) -> usize {
        self.total_observations - (self.cursor.position as usize + self.observations.len())
    }

    /// Native record completeness stays separate from physical-world observability.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_observations();
        EnvelopeCoverage {
            authorized_domain: vec!["one exact retained package detection, selected model-vocabulary label and explicit native tracking recipe under current source custody and privacy".into()],
            observed_domain: vec!["actual matched track observations, exact assigned detection rows, per-sample confirmation, source frames and continuity resets".into()],
            not_observable_domain: vec!["physical identity, detection accuracy, calibrated confidence, physical absence, continuous coverage, predicted-only or missed-frame boxes, unsampled intervals and other sources".into()],
            omitted_count: remaining as u64,
            omission_reasons: if remaining == 0 { Vec::new() } else {
                vec!["remaining matched observations are available through the exact continuation".into()]
            },
            stop_reason: if remaining == 0 { "native_track_observations_exhausted" } else { "page_limit" }.into(),
        }
    }
}

/// Query exact retained detector tracks without a writable deployment or new model execution.
pub fn query_tracks_in_deployment(
    root: &Path,
    request: &TrackQueryRequest,
    limits: TrackQueryLimits,
    permit: Option<&TrackSourceReadPermit<'_>>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentTrackQuery, TrackQueryError> {
    let input = input_digest(request, limits)?;
    let permit = permit.ok_or(TrackQueryError::Unauthorized)?;
    if permit.input != input || permit.cx.root_dir() != root {
        return Err(TrackQueryError::Unauthorized);
    }
    permit.check_current()?;
    let stopped = || cancelled() || permit.check_current().is_err();
    if stopped() {
        return Err(TrackQueryError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &permit.cx, &stopped)
        .map_err(TrackQueryError::Source)?;
    let anchor_token = snapshot_anchor_token(owner.snapshot());
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|pin| pin.as_str() != anchor_token)
    {
        return Err(TrackQueryError::AnchorChanged);
    }
    let report = PackageAnalysisReport::read(
        &owner,
        request.report_digest,
        &request.label,
        request.config,
        &permit.cx,
    )
    .map_err(TrackQueryError::Analysis)?;
    let rows = projection::observations(&report)?;
    let snapshot = owner.snapshot().clone();
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.scope.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    e.digest(permit.scope_digest);
    e.digest(report.digest());
    let scope = ContentDigest::sha256(&e.finish());
    let text = scope.to_text();
    let suffix = &text[7..];
    let session_id = SessionId::parse(format!("session:tracks:{suffix}"))
        .map_err(|_| TrackQueryError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:tracks:{suffix}"))
        .map_err(|_| TrackQueryError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.max_entries,
        allowance,
    )
    .map_err(|_| TrackQueryError::Contract)?;
    let description = "Actual matched observations of one retained detector label under an explicit native tracking recipe; tentative samples remain tentative, source discontinuities reset tracking, scores are uncalibrated and track identities are not physical identities";
    let interpretation_id = "interpretation:retained-detector-tracks";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| TrackQueryError::Contract)?;
    let plan = AgentQueryPlan::compile(
        format!("query-plan:{suffix}"),
        mission_id.clone(),
        session_id.clone(),
        &basis,
        "AOP-005",
        scope,
        vec!["taint:structured-operator-input".into()],
        snapshot.anchor.clone(),
        description,
        vec![request.report_digest.to_text()],
        vec![
            "retained_package_detection".into(),
            "matched_track_observations".into(),
        ],
        vec![
            RuntimeGrant::AgentQuery.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ],
        vec!["source_verification_only".into(), "byte_free_result".into()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        interpretation_id,
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )
    .map_err(|_| TrackQueryError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.selection.v1");
    e.digest(scope);
    e.digest(plan.plan_digest());
    e.digest(report.digest());
    e.u64(rows.len() as u64);
    for row in &rows {
        e.digest(row.row_digest);
    }
    let selection_witness = ContentDigest::sha256(&e.finish());
    let entries = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            ContinuationEntry::new(index as u64, "track_observation", row.row_digest, true)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(
        issued_at
            .0
            .checked_add(QUERY_CURSOR_LIFETIME_NS)
            .ok_or(TrackQueryError::InvalidRequest)?,
    );
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("tracks:{suffix}"),
        scope: ContinuationScope::Investigation,
        contract_basis: basis,
        session_id: session_id.clone(),
        view_id: AgentView::Case.id().into(),
        anchor: snapshot.anchor.clone(),
        entries,
        page_size: request.max_entries,
        selection_witness,
        issued_at,
        expires_at,
    })?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor()?,
        Some(token) => stream.cursor_for_token(token, issued_at)?,
    };
    let page = stream.read_page(&cursor, issued_at)?;
    page.verify()?;
    let mut observations = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence)
            .ok()
            .and_then(|index| rows.get(index))
            .filter(|row| row.row_digest == entry.payload_digest)
            .ok_or(ContinuationError::OutOfRange)?;
        observations.push(row.clone());
    }
    let epistemic = projection::epistemic(
        &report,
        &observations,
        rows.len(),
        cursor.position,
        selection_witness,
    )?;
    if stopped() {
        return Err(TrackQueryError::Cancelled);
    }
    owner.revalidate().map_err(TrackQueryError::Source)?;
    // No caller callbacks or I/O follow the final native authority observation.
    let read_usage = owner.usage();
    let source_permit_digest = permit.digest();
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.request.v1");
    e.digest(input);
    e.digest(scope);
    e.digest(source_permit_digest);
    e.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&e.finish());
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.decision.v1");
    e.digest(request_digest);
    e.digest(selection_witness);
    e.digest(admission.receipt_digest());
    e.digest(page.page_digest);
    Ok(DeploymentTrackQuery {
        snapshot,
        anchor_token,
        report,
        observations,
        epistemic,
        read_usage,
        plan,
        admission,
        request_digest,
        selection_witness,
        decision_digest: ContentDigest::sha256(&e.finish()),
        source_permit_digest,
        session_id,
        mission_id,
        total_observations: rows.len(),
        cursor,
        page,
    })
}
