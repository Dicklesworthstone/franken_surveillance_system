#![forbid(unsafe_code)]
//! Canonical recorder-time queries after original archive custody has been imported.
//!
//! The immutable retained owner verifies current completion, source ancestry, publication and
//! deletion under one non-refilling read balance. An explicit root/import/query-bound permit
//! authorizes internal original verification; no source bytes or mutation handle is returned.

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, ContextAuthority, DigestAlgorithm, MissionId,
    QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt, RuntimeGrant, SessionId,
    TimestampNs, admit_query_read, reference_contract_basis,
};
use fss_publication::{PublishCancellation, PublishCutPoint};

use super::{RecordingReplayContextError, RecordingReplayContextRequest};
use crate::ReplayCx;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::{DeploymentSnapshot, OrientLimits};
use crate::ingest::rtsp_import::replay::query_retained_replay_time;
use crate::ingest::{RetainedFileImport, RetainedReadLimits};
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use crate::rtsp::recording_replay::time::ReplayTimeReport;

/// One completed import plus independent original recorder scope and time interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecordingReplayRequest {
    /// Destination completion identity, never inferred from an original receipt root.
    pub import_identity: ContentDigest,
    /// Original pins, explicit NTP era, interval, principal and current-head precondition.
    pub replay: RecordingReplayContextRequest,
}

/// One cumulative balance for current history, retained metadata, originals and revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRecordingReplayLimits {
    /// Payload bytes/read attempts; filesystem probes and CPU are not counted as payload reads.
    pub read: ImmutableRetainedReadLimits,
    /// Exact existing per-import/source-chunk allocation ceilings.
    pub retained: RetainedReadLimits,
}

impl Default for RetainedRecordingReplayLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: 1024 * 1024 * 1024,
                max_read_objects: 1_000_000,
            },
            retained: RetainedReadLimits::default(),
        }
    }
}

impl RetainedRecordingReplayLimits {
    /// Pure admission before opening a path. Limits may narrow but never exceed hard ceilings.
    pub fn validate(&self) -> Result<(), RecordingReplayContextError> {
        let maximum = OrientLimits::default();
        if self.read.max_read_bytes == 0
            || self.read.max_read_bytes as u64 > 4_u64 * 1024 * 1024 * 1024
            || !(1..=4_000_000).contains(&self.read.max_read_objects)
            || self.retained.max_source_bytes == 0
            || self.retained.max_source_bytes > 2_u64 * 1024 * 1024 * 1024
            || self.retained.max_chunk_bytes == 0
            || self.retained.max_chunk_bytes > 64 * 1024 * 1024
            || self.retained.max_segment_bytes == 0
            || self.retained.max_segment_bytes > 64 * 1024 * 1024
        {
            return Err(RecordingReplayContextError::InvalidRequest);
        }
        for (value, ceiling) in [
            (
                self.read.snapshot.max_layout_bytes,
                maximum.max_layout_bytes,
            ),
            (
                self.read.snapshot.max_journal_bytes,
                maximum.max_journal_bytes,
            ),
            (
                self.read.snapshot.max_object_bytes,
                maximum.max_object_bytes,
            ),
            (self.read.snapshot.max_events, maximum.max_events),
            (
                self.read.snapshot.max_revisions_per_event,
                maximum.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > ceiling {
                return Err(RecordingReplayContextError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// This allowance is shared across the complete read, never refilled for a window or retry.
    pub fn allowance(&self) -> Result<BudgetVector, RecordingReplayContextError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        for value in [
            self.read.max_read_bytes,
            self.read.max_read_objects,
            self.read.snapshot.max_layout_bytes,
            self.read.snapshot.max_journal_bytes,
            self.read.snapshot.max_object_bytes,
            self.read.snapshot.max_events,
            self.read.snapshot.max_revisions_per_event,
        ] {
            e.u64(value as u64);
        }
        for value in [
            self.retained.max_source_bytes,
            self.retained.max_chunk_bytes,
            self.retained.max_segment_bytes,
        ] {
            e.u64(value);
        }
    }
}

fn input_digest(
    request: &RetainedRecordingReplayRequest,
    limits: RetainedRecordingReplayLimits,
) -> Result<ContentDigest, RecordingReplayContextError> {
    limits.validate()?;
    if request.import_identity.algorithm() != DigestAlgorithm::Sha256
        || request.import_identity.bytes() == [0; 32]
        || !(1..=128).contains(&request.replay.replay.limits.max_results)
    {
        return Err(RecordingReplayContextError::InvalidRequest);
    }
    let native = request.replay.replay.digest().map_err(|error| {
        RecordingReplayContextError::Replay(super::ReplayTimeReadError::Query(error))
    })?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_retained_replay_query.input.v1");
    e.digest(request.import_identity);
    e.digest(native);
    request.replay.principal.encode_canonical(&mut e);
    e.bool(request.replay.expected_anchor.is_some());
    if let Some(anchor) = &request.replay.expected_anchor {
        e.text(anchor.as_str());
    }
    limits.encode(&mut e);
    Ok(ContentDigest::sha256(&e.finish()))
}

/// Opaque current read grant for one exact root, import, recorder query and allowance.
///
/// A query capability or retained receipt alone cannot construct this grant. The owner must
/// separately supply current media-read and retained I/O authority. The borrowed deadline clock
/// is checked throughout the immutable reader; this grant never authorizes media disclosure.
pub struct RetainedReplaySourceReadPermit<'a> {
    authority: &'a ContextAuthority,
    now: &'a (dyn Fn() -> TimestampNs + Sync),
    cx: ReplayCx,
    input: ContentDigest,
    digest: ContentDigest,
}

impl<'a> RetainedReplaySourceReadPermit<'a> {
    /// Pure admission and context construction. Missing deployment paths are never created.
    pub fn authorize(
        authority: &'a ContextAuthority,
        root: &Path,
        request: &RetainedRecordingReplayRequest,
        limits: RetainedRecordingReplayLimits,
        now: &'a (dyn Fn() -> TimestampNs + Sync),
    ) -> Result<Self, RecordingReplayContextError> {
        let input = input_digest(request, limits)?;
        authority
            .validate()
            .map_err(|_| RecordingReplayContextError::Unauthorized)?;
        let allowance = limits.allowance()?;
        if !root.is_absolute()
            || !authority.budgets.is_valid()
            || !allowance.fits_within(authority.budgets)
            || authority.principal != request.replay.principal.as_str()
            || authority.anchor_universe != request.replay.replay.scope.recording.anchor
            || authority.generation != request.replay.replay.scope.recording.generation
            || !authority.has_capability(RuntimeGrant::AgentQuery.as_str())
            || !authority.has_capability(RuntimeGrant::ReadMedia.as_str())
        {
            return Err(RecordingReplayContextError::Unauthorized);
        }
        let cx = ReplayCx::from_context_authority_read_only(authority, root)
            .map_err(|_| RecordingReplayContextError::Unauthorized)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_retained_replay_query.source_permit.v1");
        e.digest(input);
        e.digest(authority.anchor_universe);
        e.u64(authority.generation);
        e.text(RuntimeGrant::AgentQuery.as_str());
        e.text(RuntimeGrant::ReadMedia.as_str());
        e.text("ADP-REPLAY-001");
        e.text(&authority.privacy_scope);
        e.text(&authority.retention_scope);
        // The root is an execution scope checked below, not a portable source identity. Absolute
        // host paths do not enter result identities or diagnostics.
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

    /// Portable semantic grant identity, excluding private paths and process clock readings.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    fn check_current(&self) -> Result<(), RecordingReplayContextError> {
        if self.authority.cancellation_reason.is_some()
            || self.cx.is_cancelled()
            || self
                .authority
                .deadline
                .is_some_and(|deadline| (self.now)() >= deadline)
        {
            Err(RecordingReplayContextError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

impl Drop for RetainedReplaySourceReadPermit<'_> {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
    }
}

/// Byte-free native recorder assertions linked to current imported custody and agent context.
#[derive(Debug)]
pub struct DeploymentRetainedReplayQuery {
    /// Current immutable metadata snapshot after complete source and authority revalidation.
    pub snapshot: DeploymentSnapshot,
    /// Exact current authority/effect-history observation.
    pub anchor_token: String,
    /// Independently selected current import completion identity.
    pub import_identity: ContentDigest,
    /// Verified destination publication root.
    pub import_root: ContentDigest,
    /// Verified destination manifest identity.
    pub manifest_digest: ContentDigest,
    /// Unchanged native packet-to-recorder-time projection and its proof identities.
    pub report: ReplayTimeReport,
    /// Total actual payload bytes and attempts, including history and final revalidation.
    pub read_usage: RetainedReadUsage,
    /// Existing canonical AOP-005 plan, declaring internal original verification.
    pub plan: AgentQueryPlan,
    /// Canonical read admission, without new filesystem or effect authority.
    pub admission: QueryReadReceipt,
    /// Exact current context, selected import, source grant and complete input identity.
    pub request_digest: ContentDigest,
    /// Request, native report/index and canonical plan identity.
    pub decision_digest: ContentDigest,
    /// Independently issued bounded source grant identity.
    pub source_permit_digest: ContentDigest,
    /// Ephemeral deterministic read session; no session file is written.
    pub session_id: SessionId,
    /// Ephemeral bounded recorder query mission.
    pub mission_id: MissionId,
}

struct Cancellation<'a>(&'a (dyn Fn() -> bool + Sync));
impl PublishCancellation for Cancellation<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        (self.0)()
    }
}

/// Verify one imported recorder receipt with no dependence on the original archive directory.
///
/// All source reads use a single immutable owner. Final revalidation checks every observed
/// publication/deletion marker and current authority without recovery, locks or writes. The
/// resulting observation is not an atomic filesystem snapshot or future availability lease.
pub fn query_retained_recordings_replay_in_deployment(
    root: &Path,
    request: &RetainedRecordingReplayRequest,
    limits: RetainedRecordingReplayLimits,
    permit: Option<&RetainedReplaySourceReadPermit<'_>>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRetainedReplayQuery, RecordingReplayContextError> {
    let input = input_digest(request, limits)?;
    let permit = permit.ok_or(RecordingReplayContextError::Unauthorized)?;
    if permit.input != input || permit.cx.root_dir() != root {
        return Err(RecordingReplayContextError::Unauthorized);
    }
    permit.check_current()?;
    let stopped = || cancelled() || permit.check_current().is_err();
    if stopped() {
        return Err(RecordingReplayContextError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &permit.cx, &stopped)
        .map_err(RecordingReplayContextError::RetainedSource)?;
    let anchor_token = snapshot_anchor_token(owner.snapshot());
    if request
        .replay
        .expected_anchor
        .as_ref()
        .is_some_and(|anchor| anchor.as_str() != anchor_token)
    {
        return Err(RecordingReplayContextError::AnchorChanged);
    }
    let imported =
        RetainedFileImport::open(&owner, request.import_identity, limits.retained, &permit.cx)
            .map_err(RecordingReplayContextError::RetainedSource)?;
    let report = query_retained_replay_time(
        &owner,
        request.import_identity,
        &request.replay.replay,
        limits.retained,
        &permit.cx,
        &Cancellation(&stopped),
    )
    .map_err(RecordingReplayContextError::RetainedReplay)?;
    if stopped() {
        return Err(RecordingReplayContextError::Cancelled);
    }
    owner
        .revalidate()
        .map_err(RecordingReplayContextError::RetainedSource)?;
    // No callback or additional source I/O follows the final current-authority comparison.
    let snapshot = owner.snapshot().clone();
    let read_usage = owner.usage();
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let source_permit_digest = permit.digest();
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_retained_replay_query.request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    e.digest(input);
    e.digest(imported.import_root());
    e.digest(imported.manifest_digest());
    e.digest(source_permit_digest);
    let request_digest = ContentDigest::sha256(&e.finish());
    let text = request_digest.to_text();
    let suffix = &text[7..];
    let session_id = SessionId::parse(format!("session:retained-replay:{suffix}"))
        .map_err(|_| RecordingReplayContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:retained-replay:{suffix}"))
        .map_err(|_| RecordingReplayContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.replay.replay.limits.max_results as u32,
        allowance,
    )
    .map_err(|_| RecordingReplayContextError::Contract)?;
    let description = "Complete recorder UTC assertions from a currently retained import, with exact source ancestry and internal original verification; no source disclosure, trusted UTC or absence claim";
    let interpretation_id = "interpretation:retained-native-recorder-time";
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
        vec![
            imported.import_root().to_text(),
            report.receipt.root().to_text(),
        ],
        vec![
            "retained_import".to_owned(),
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
    e.text("fss.agent_retained_replay_query.decision.v1");
    e.digest(request_digest);
    e.digest(report.digest);
    e.digest(report.index_digest);
    e.digest(plan.plan_digest());
    Ok(DeploymentRetainedReplayQuery {
        snapshot,
        anchor_token,
        import_identity: request.import_identity,
        import_root: imported.import_root(),
        manifest_digest: imported.manifest_digest(),
        report,
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
