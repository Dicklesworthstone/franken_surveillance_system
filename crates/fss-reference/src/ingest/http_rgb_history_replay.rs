#![forbid(unsafe_code)]
//! Whole-session cold replay from exact committed HTTP RGB history.
//!
//! Restore is not execution: this owner runs the native HTTP/MIME cursor, source-closed
//! graph/JPEG/head replay, and the existing tracker/zone engine in retained order. Each
//! actual stage must match its saved fingerprint. Nothing is published, repaired, contacted,
//! reclassified, or alerted. Pending roots are described but never executed as committed.
//! A verified prefix is not a complete stream, health certificate or evidence of absence.

use crate::ingest::http_archive::{
    HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWirePin,
};
use crate::ingest::http_replay::completion::{
    HttpCompletionError, HttpCompletionPin, VerifiedHttpCompletion,
};
use crate::ingest::http_replay::{
    HttpReplayAccess, HttpReplayError, HttpReplayLimits, HttpReplayStep, HttpWireReplay,
};
use crate::ingest::http_rgb_evidence::{HttpRgbEvidenceLimits, HttpRgbEvidencePin};
use crate::ingest::http_rgb_evidence_replay::{
    HttpRgbEvidenceReplayError, HttpRgbEvidenceReplaySource, restore_http_rgb_evidence,
};
use crate::ingest::http_rgb_history::{
    HistoryAuthority, HistoryError, HistoryLimits, HistoryOperation, HistoryRecovery,
    HttpRgbHistory, HttpRgbHistoryTip, MAX_HISTORY_FRAMES, read_latest_history,
};
use crate::ingest::model_import::ImportLimits;
use crate::ingest::privacy_mask::live::SensorMask;
use crate::ingest::rgb_archive::{RgbArchiveAuthority, RgbArchiveOperation};
use crate::ingest::rgb_evidence::RgbReplayLimits;
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::ingest::rgb_tracking::{RgbTrackingError, RgbZoneTracker};
use crate::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_codec_mjpeg::http::HttpLimits;
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor};
use fss_geometry::GeometryError;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

mod budget;
pub use budget::{ReplayAllowance, ReplayBudget, ReplayUsage};

/// Semantic result identity, excluding resource counters and read fragmentation.
pub const REPLAY_DOMAIN: &str = "fss.http_rgb_history_replay.v1";

/// Current, independent permission to execute the exact retained model for a session.
/// History metadata-read permission and possession of a model digest are not this grant.
pub trait ReplayAuthority {
    /// Recheck the principal, model, session, cancellation, deadline and compute scope.
    fn permits_replay(&self, session: ContentDigest, model: ContentDigest) -> bool;
}

/// Independent source, metadata, evidence and compute boundaries; no permissive default.
#[derive(Clone, Copy)]
pub struct ReplayAccess<'a> {
    /// Read the exact session recipe and canonical prefixes.
    pub history: &'a dyn HistoryAuthority,
    /// Disclose exact source-closed graph/weights/JPEG/permission objects.
    pub evidence: &'a dyn RgbArchiveAuthority,
    /// Read original HTTP headers and media from the separately owned wire archive.
    pub originals: &'a dyn PublishCancellation,
    /// Execute the retained model. Must be checked independently of read access.
    pub execution: &'a dyn ReplayAuthority,
}

/// Privacy authority is selected explicitly; the retained session chooses the sensor.
#[derive(Clone, Copy)]
pub enum ReplayPrivacy<'a> {
    /// Resolve the named sensor's current policy in the history/evidence deployment.
    HistoryDeployment,
    /// Resolve it in another explicitly owned deployment, as allowed by live SensorMask.
    /// The stored policy digest AND generation must still match; no old mask is replayed.
    External(&'a ReferenceDeployment),
}

/// Independently selected original source. An explicit later tip can verify a committed
/// history prefix without executing later frames. None uses only the pin in committed history;
/// it never discovers or follows an unrecorded newer original head.
#[derive(Clone, Copy)]
pub struct ReplaySource<'a> {
    /// Current, exclusively owned original-wire archive (not the evidence deployment).
    pub publisher: &'a LocalRootPublisher,
    /// Optional independently retained wire tip; a committed completion must match it exactly.
    pub tip: Option<HttpWirePin>,
}

/// Independent native bounds; stored configuration cannot enlarge them.
#[derive(Clone, Copy, Debug)]
pub struct ReplayLimits {
    /// Canonical history and source-closed archive bounds.
    pub history: HistoryLimits,
    /// Original-wire inventory bounds.
    pub originals: HttpArchiveLimits,
    /// Native framing/allocation bounds. Complete histories need one lookahead frame.
    pub parser: HttpReplayLimits,
    /// Native importer, decoder, preprocessing and graph limits per attempt.
    pub execution: RgbReplayLimits,
}
impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            history: HistoryLimits::default(),
            originals: HttpArchiveLimits {
                maximum_reads: 4096,
                maximum_bytes: 256 * 1024 * 1024,
                maximum_scan_roots: 65536,
                maximum_spool_object_bytes: 16 * 1024 * 1024,
            },
            parser: HttpReplayLimits {
                http: HttpLimits {
                    wire_bytes: 256 * 1024 * 1024,
                    entity_bytes: 256 * 1024 * 1024,
                    ..HttpLimits::default()
                },
                frames: MAX_HISTORY_FRAMES as u64 + 1,
                ..HttpReplayLimits::default()
            },
            execution: RgbReplayLimits {
                import: ImportLimits::default(),
                run: RgbRunLimits {
                    decode: Default::default(),
                    preprocess: ExecBudget::new(100_000_000, 64 * 1024 * 1024),
                    execution: ExecBudget::new(20_000_000_000, 256 * 1024 * 1024),
                    maximum_output_bytes: 16 * 1024 * 1024,
                },
            },
        }
    }
}

/// A refusal returns no reconstructed session or partial successful report.
#[derive(Debug)]
pub enum ReplayError {
    /// Complete input, cursor, inference-count or allocation bound exhausted.
    Limit,
    /// Metadata read, original disclosure, computation or cancellation was denied.
    Denied,
    /// Expected session/root/revision is not the latest committed history tip.
    StaleSelection,
    /// A frame, model, temporal configuration or full-source count differs.
    Mismatch,
    /// Native source ends or exhausts before all committed history frames are checked.
    IncompleteSource,
    /// Canonical history or its custody refused.
    History(HistoryError),
    /// Native original inventory refused.
    Archive(HttpArchiveError),
    /// Native HTTP/MIME replay refused.
    Source(HttpReplayError),
    /// Exact original completion witness refused.
    Completion(HttpCompletionError),
    /// Source-closed native recomputation failed at this one-based part ordinal.
    Frame {
        /// One-based source part ordinal.
        ordinal: u64,
        /// Native recomputation refusal.
        error: HttpRgbEvidenceReplayError,
    },
    /// Native anonymous temporal reconstruction refused at this part ordinal.
    Tracking {
        /// One-based source part ordinal.
        ordinal: u64,
        /// Native temporal reconstruction refusal.
        error: RgbTrackingError,
    },
    /// Shared deterministic work refused before a complete result.
    Work(GeometryError),
}
impl ReplayError {
    /// Stable non-disclosing error identifier; native causes remain available via Error::source.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-HTTP-RGB-REPLAY-LIMIT-001",
            Self::Denied => "ERR-HTTP-RGB-REPLAY-DENIED-001",
            Self::StaleSelection => "ERR-HTTP-RGB-REPLAY-STALE-001",
            Self::Mismatch => "ERR-HTTP-RGB-REPLAY-MISMATCH-001",
            Self::IncompleteSource => "ERR-HTTP-RGB-REPLAY-INCOMPLETE-001",
            _ => "ERR-HTTP-RGB-REPLAY-001",
        }
    }
}
impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.stable_id())
    }
}
impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::History(e) => Some(e),
            Self::Archive(e) => Some(e),
            Self::Source(e) => Some(e),
            Self::Completion(e) => Some(e),
            Self::Frame { error, .. } => Some(error),
            Self::Tracking { error, .. } => Some(error),
            Self::Work(e) => Some(e),
            _ => None,
        }
    }
}
impl From<HistoryError> for ReplayError {
    fn from(e: HistoryError) -> Self {
        Self::History(e)
    }
}

/// Exact completion distinction; none is a claim of scene absence or sensor availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayStatus {
    /// Only an empty committed configuration exists. No source or numerical result checked.
    ConfigurationOnly,
    /// All committed frames reconstructed, but no committed native completion was selected.
    PrefixVerified,
    /// Every frame and the actual native HTTP/MIME ending match the committed completion.
    CompleteVerified,
}
impl ReplayStatus {
    /// Stable machine spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationOnly => "configuration_only",
            Self::PrefixVerified => "prefix_verified",
            Self::CompleteVerified => "complete_verified",
        }
    }
}

/// Actual native work for one complete retained frame. No raw media or model tensor escapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayedFrame {
    /// Exact saved pin matched by native source, inference, head, tracking and zones.
    pub pin: HttpRgbEvidencePin,
    /// Complete post-NMS model hypotheses, across every class; not physical objects.
    pub detections: usize,
    /// Hypotheses of the one configured temporal class; never an identity count.
    pub selected_class_detections: usize,
    /// Actual executed native graph operations, not a reservation or performance SLO.
    pub executed_macs: u64,
    /// Actual native preprocessing work.
    pub preprocess_work: u64,
}

/// Immutable result plus the actual reconstructed temporal owner, never a deserialized snapshot.
/// It confers no authority to acquire another frame, change an episode, or publish an event.
pub struct ReplayedHistory {
    tip: HttpRgbHistoryTip,
    anchor: LedgerAnchor,
    pending: Option<HttpRgbHistoryTip>,
    privacy_site: String,
    privacy_anchor: LedgerAnchor,
    source: Option<HttpWirePin>,
    completion: Option<HttpCompletionPin>,
    status: ReplayStatus,
    frames: Vec<ReplayedFrame>,
    temporal: Option<RgbZoneTracker>,
    before: ReplayUsage,
    after: ReplayUsage,
}
impl ReplayedHistory {
    /// Exact committed history that was selected and checked.
    pub fn tip(&self) -> HttpRgbHistoryTip {
        self.tip
    }
    /// Canonical read basis; no new batch was appended by replay.
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Durable-but-unledgered next history, if present; NOT replayed or repaired.
    pub fn pending(&self) -> Option<HttpRgbHistoryTip> {
        self.pending
    }
    /// Explicitly selected current policy authority. Naming it does not authenticate a sensor.
    pub fn privacy_site(&self) -> &str {
        &self.privacy_site
    }
    /// Policy authority position used for this reconstruction.
    pub fn privacy_anchor(&self) -> &LedgerAnchor {
        &self.privacy_anchor
    }
    /// Exact independently retained original prefix selected for this reconstruction.
    pub fn source(&self) -> Option<HttpWirePin> {
        self.source
    }
    /// Checked actual source completion, absent for ordinary prefixes.
    pub fn completion(&self) -> Option<HttpCompletionPin> {
        self.completion
    }
    /// Source completion is separate from successful numerical verification.
    pub fn status(&self) -> ReplayStatus {
        self.status
    }
    /// Every checked frame, in original part order. No partial result is returned on failure.
    pub fn frames(&self) -> &[ReplayedFrame] {
        &self.frames
    }
    /// Actual reconstructed native state, including the last tracking/zone reports.
    pub fn temporal(&self) -> Option<&RgbZoneTracker> {
        self.temporal.as_ref()
    }
    /// Transfer native temporal state to an explicit owner. This is not capture/effect authority.
    pub fn into_temporal(self) -> Option<RgbZoneTracker> {
        self.temporal
    }
    /// Whole caller budget counters before and after this successful invocation.
    pub fn usage(&self) -> (ReplayUsage, ReplayUsage) {
        (self.before, self.after)
    }
    /// Fragmentation-independent semantic result. Resource costs remain separate.
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(REPLAY_DOMAIN);
        encode_tip(&mut e, self.tip);
        self.anchor.encode_canonical(&mut e);
        e.bool(self.pending.is_some());
        if let Some(pending) = self.pending {
            encode_tip(&mut e, pending);
        }
        e.text(&self.privacy_site);
        self.privacy_anchor.encode_canonical(&mut e);
        e.text(self.status.as_str());
        e.bool(self.source.is_some());
        if let Some(source) = self.source {
            e.digest(source.scope);
            e.digest(source.head);
            e.u64(source.reads);
            e.u64(source.bytes);
        }
        e.bool(self.completion.is_some());
        if let Some(completion) = self.completion {
            e.digest(completion.root);
        }
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            e.u64(frame.pin.ordinal);
            e.digest(frame.pin.archive.root);
            e.digest(sha(frame.pin.exposure));
            for stage in frame.pin.stages {
                e.digest(sha(stage));
            }
            e.u64(frame.detections as u64);
            e.u64(frame.selected_class_detections as u64);
        }
        ContentDigest::sha256(&e.finish())
    }
}
fn sha(v: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, v)
}
fn encode_tip(e: &mut CanonicalEncoder, tip: HttpRgbHistoryTip) {
    e.digest(tip.session);
    e.digest(tip.root);
    e.u64(tip.revision);
}

fn authorize(
    history: &HttpRgbHistory,
    access: ReplayAccess<'_>,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<(), ReplayError> {
    let spec = history.config().spec();
    if cx.checkpoint("http-rgb-history-replay:admit").is_err()
        || scalar.checkpoint("http-rgb-history-replay:admit").is_err()
        || !access
            .history
            .permits(HistoryOperation::Read, history.config().identity())
        || access
            .originals
            .cancel_requested(PublishCutPoint::AfterChildrenVerified)
        || !access
            .execution
            .permits_replay(history.config().identity(), spec.model)
    {
        return Err(ReplayError::Denied);
    }
    Ok(())
}
fn authorize_frames(history: &HttpRgbHistory, access: ReplayAccess<'_>) -> Result<(), ReplayError> {
    // Check the ENTIRE selected disclosure set before the first original read and again before
    // returning. A late revocation of an earlier frame cannot leak its stored summary.
    if history.frames().iter().any(|pin| {
        !access.evidence.permits(
            RgbArchiveOperation::ReadOriginals,
            pin.archive.retention,
            pin.archive.evidence,
        )
    }) {
        return Err(ReplayError::Denied);
    }
    Ok(())
}
fn frame_error(ordinal: u64, error: HttpRgbEvidenceReplayError) -> ReplayError {
    ReplayError::Frame { ordinal, error }
}

/// Inspect committed and pending history with the same cumulative metadata-read allowance.
/// This does not open original storage or grant/invoke model execution. The returned pins
/// are expectations, never a substitute for `replay_history`'s actual native reconstruction.
pub fn inspect_history(
    deployment: &mut ReferenceDeployment,
    session: ContentDigest,
    limits: HistoryLimits,
    authority: &dyn HistoryAuthority,
    budget: &mut ReplayBudget,
    cx: &ReplayCx,
) -> Result<HistoryRecovery, ReplayError> {
    Ok(read_latest_history(
        deployment,
        session,
        limits,
        authority,
        &mut budget.source,
        cx,
    )?)
}

/// Reconstruct one EXACT latest committed history, including its original temporal configuration.
///
/// No caller-supplied frame list, timestamp or tracker state can substitute for
/// canonical history. Pending prefixes remain pending. Source/JPEG/model buffers are sequential;
/// native temporaries are released before the next frame. All budgets persist on failure.
/// Per-attempt numerical ceilings are reserved before native execution because failed kernels
/// cannot return complete usage; successful rows separately report actual numerical work.
///
/// The named sensor is resolved from the session in the explicitly chosen current privacy
/// deployment. This remains an owner binding, not camera authentication. Native replay retains
/// all uncertainty and can refuse incompatible/superseded numerical or privacy generations.
#[allow(clippy::too_many_arguments)]
pub fn replay_history(
    deployment: &mut ReferenceDeployment,
    source: ReplaySource<'_>,
    expected: HttpRgbHistoryTip,
    privacy: ReplayPrivacy<'_>,
    limits: ReplayLimits,
    access: ReplayAccess<'_>,
    budget: &mut ReplayBudget,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<ReplayedHistory, ReplayError> {
    let before = budget.used();
    let recovered = read_latest_history(
        deployment,
        expected.session,
        limits.history,
        access.history,
        &mut budget.source,
        cx,
    )?;
    let history = recovered.committed.ok_or(ReplayError::StaleSelection)?;
    if history.tip()? != expected {
        return Err(ReplayError::StaleSelection);
    }
    authorize(&history, access, cx, scalar)?;
    authorize_frames(&history, access)?;
    let pending = recovered
        .pending
        .as_ref()
        .map(HttpRgbHistory::tip)
        .transpose()?;
    let retained_source = history
        .source_completion()
        .map(|c| c.wire)
        .or_else(|| history.frames().last().map(|p| p.wire));
    let selected_source = select_source(history.is_complete(), retained_source, source.tip)?;
    let policy = match privacy {
        ReplayPrivacy::HistoryDeployment => &*deployment,
        ReplayPrivacy::External(d) => d,
    };
    let mut result = ReplayedHistory {
        tip: expected,
        anchor: recovered.anchor,
        pending,
        privacy_site: policy.site_lineage().to_owned(),
        privacy_anchor: policy.current_anchor().clone(),
        source: selected_source,
        completion: history.source_completion(),
        status: if history.frames().is_empty() && !history.is_complete() {
            ReplayStatus::ConfigurationOnly
        } else {
            ReplayStatus::PrefixVerified
        },
        frames: Vec::new(),
        temporal: None,
        before,
        after: before,
    };
    if let Some(pin) = selected_source {
        execute(
            &history,
            deployment,
            source.publisher,
            pin,
            privacy,
            limits,
            access,
            budget,
            cx,
            scalar,
            &mut result,
        )?;
    }
    // Re-read canonical selection after computation. This neither reconciles a pending root
    // nor follows a changed head. It also detects external custody alteration of history bytes.
    let checked = read_latest_history(
        deployment,
        expected.session,
        limits.history,
        access.history,
        &mut budget.source,
        cx,
    )?;
    if checked.anchor != result.anchor
        || checked
            .committed
            .as_ref()
            .map(HttpRgbHistory::tip)
            .transpose()?
            != Some(expected)
        || checked
            .pending
            .as_ref()
            .map(HttpRgbHistory::tip)
            .transpose()?
            != pending
    {
        return Err(ReplayError::StaleSelection);
    }
    authorize(&history, access, cx, scalar)?;
    authorize_frames(&history, access)?;
    result.after = budget.used();
    Ok(result)
}

fn select_source(
    complete: bool,
    retained: Option<HttpWirePin>,
    supplied: Option<HttpWirePin>,
) -> Result<Option<HttpWirePin>, ReplayError> {
    let Some(retained) = retained else {
        return if supplied.is_none() {
            Ok(None)
        } else {
            Err(ReplayError::Mismatch)
        };
    };
    let chosen = supplied.unwrap_or(retained);
    if chosen.scope != retained.scope
        || chosen.reads < retained.reads
        || chosen.bytes < retained.bytes
        || (chosen.reads == retained.reads && chosen != retained)
        || (complete && chosen != retained)
    {
        return Err(ReplayError::Mismatch);
    }
    Ok(Some(chosen))
}

#[allow(clippy::too_many_arguments)]
fn execute(
    history: &HttpRgbHistory,
    deployment: &mut ReferenceDeployment,
    originals: &LocalRootPublisher,
    pin: HttpWirePin,
    privacy: ReplayPrivacy<'_>,
    limits: ReplayLimits,
    access: ReplayAccess<'_>,
    budget: &mut ReplayBudget,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    result: &mut ReplayedHistory,
) -> Result<(), ReplayError> {
    let config = history.config();
    let spec = config.spec();
    let archive = HttpWireArchive::load(
        originals,
        spec.source,
        pin,
        limits.originals,
        access.originals,
        &mut budget.source,
    )
    .map_err(ReplayError::Archive)?;
    let completion = history
        .source_completion()
        .map(|complete| {
            VerifiedHttpCompletion::load(
                originals,
                &archive,
                complete,
                access.originals,
                &mut budget.source,
            )
        })
        .transpose()
        .map_err(ReplayError::Completion)?;
    if completion
        .as_ref()
        .is_some_and(|c| c.frames() != history.frames().len() as u64)
    {
        return Err(ReplayError::Mismatch);
    }
    let needed = history.frames().len() as u64 + u64::from(history.is_complete());
    if limits.parser.frames < needed {
        return Err(ReplayError::Limit);
    }
    let mut cursor =
        HttpWireReplay::new(&archive, pin, limits.parser).map_err(ReplayError::Source)?;
    result
        .frames
        .try_reserve_exact(history.frames().len())
        .map_err(|_| ReplayError::Limit)?;
    let mut index = 0_usize;
    loop {
        authorize(history, access, cx, scalar)?;
        // A committed prefix authorizes just its frames, not analysis of lookahead parts in
        // the final read. Do not pretend its socket ended merely because those frames matched.
        if index == history.frames().len() && !history.is_complete() {
            break;
        }
        budget.step()?;
        let mut step = cursor
            .step(HttpReplayAccess {
                publisher: originals,
                cancellation: access.originals,
                work: &mut budget.source,
                framing: &mut budget.framing,
            })
            .map_err(ReplayError::Source)?;
        if step == HttpReplayStep::PrefixExhausted {
            let complete = completion.as_ref().ok_or(ReplayError::IncompleteSource)?;
            budget.step()?;
            step = cursor
                .finish_completed(
                    complete,
                    HttpReplayAccess {
                        publisher: originals,
                        cancellation: access.originals,
                        work: &mut budget.source,
                        framing: &mut budget.framing,
                    },
                )
                .map_err(ReplayError::Completion)?;
        }
        match step {
            HttpReplayStep::PrefixVerified
            | HttpReplayStep::WireLoaded { .. }
            | HttpReplayStep::Advanced => {}
            HttpReplayStep::PrefixExhausted => return Err(ReplayError::IncompleteSource),
            HttpReplayStep::Complete => {
                if index != history.frames().len() {
                    return Err(ReplayError::IncompleteSource);
                }
                let complete = completion.as_ref().ok_or(ReplayError::Mismatch)?;
                budget.step()?;
                if cursor
                    .finish_completed(
                        complete,
                        HttpReplayAccess {
                            publisher: originals,
                            cancellation: access.originals,
                            work: &mut budget.source,
                            framing: &mut budget.framing,
                        },
                    )
                    .map_err(ReplayError::Completion)?
                    != HttpReplayStep::Complete
                {
                    return Err(ReplayError::Mismatch);
                }
                result.status = ReplayStatus::CompleteVerified;
                break;
            }
            HttpReplayStep::FrameReady => {
                let expected = *history.frames().get(index).ok_or(ReplayError::Mismatch)?;
                let frame = cursor.pending_frame().ok_or(ReplayError::Mismatch)?;
                let restored = restore_http_rgb_evidence(
                    expected,
                    HttpRgbEvidenceReplaySource {
                        publisher: originals,
                        scope: spec.source,
                        tip: pin,
                        frame,
                        cancellation: access.originals,
                    },
                    deployment,
                    access.evidence,
                    HttpRgbEvidenceLimits {
                        source: limits.originals,
                        archive: limits.history.archive,
                    },
                    &mut budget.copy,
                    &mut budget.source,
                    cx,
                )
                .map_err(|e| frame_error(expected.ordinal, e))?;
                authorize(history, access, cx, scalar)?;
                budget.inference(limits)?;
                let privacy_deployment = match privacy {
                    ReplayPrivacy::HistoryDeployment => &*deployment,
                    ReplayPrivacy::External(d) => d,
                };
                let replayed = restored
                    .replay(
                        SensorMask::new(privacy_deployment, &spec.sensor),
                        limits.execution,
                        access.originals,
                        access.evidence,
                        &mut budget.copy,
                        &mut budget.import,
                        &mut budget.decode,
                        &mut budget.detections,
                        cx,
                        scalar,
                    )
                    .map_err(|e| frame_error(expected.ordinal, e))?;
                let replay = replayed.evidence();
                // Check against the committed configuration on EVERY frame, not only the first.
                if replay.head().digest() != spec.head
                    || replay.run().inference().model_digest() != spec.model
                {
                    return Err(ReplayError::Mismatch);
                }
                if result.temporal.is_none() {
                    result.temporal = Some(config.tracker(replay.head(), &mut budget.temporal)?);
                }
                let owner = result.temporal.as_mut().ok_or(ReplayError::Mismatch)?;
                owner
                    .observe(
                        replay.run().inference(),
                        replay.run().report(),
                        replay.admission(),
                        &mut budget.temporal,
                    )
                    .map_err(|error| ReplayError::Tracking {
                        ordinal: expected.ordinal,
                        error,
                    })?;
                replayed
                    .verify_temporal(owner)
                    .map_err(|e| frame_error(expected.ordinal, e))?;
                let rows = replay.run().report().detections();
                let row = ReplayedFrame {
                    pin: expected,
                    detections: rows.len(),
                    selected_class_detections: rows
                        .iter()
                        .filter(|d| d.class_index() == spec.class_index)
                        .count(),
                    executed_macs: replay.run().inference().executed_macs(),
                    preprocess_work: replay.run().inference().preprocess_work(),
                };
                // Transfer only after all four native stages matched. A late refusal discards
                // this local reconstruction; it cannot append history or leak a partial report.
                cursor
                    .take_frame(
                        expected.ordinal,
                        expected.encoded,
                        HttpReplayAccess {
                            publisher: originals,
                            cancellation: access.originals,
                            work: &mut budget.source,
                            framing: &mut budget.framing,
                        },
                    )
                    .map_err(ReplayError::Source)?;
                result.frames.push(row);
                index += 1;
            }
        }
    }
    if cursor.position().transferred_frames != history.frames().len() as u64
        || result
            .temporal
            .as_ref()
            .is_some_and(|t| t.tracker().exposure_count() != history.frames().len())
    {
        return Err(ReplayError::Mismatch);
    }
    // The final original verification is independent of numerical success and also runs for
    // partial histories. A subsequent external filesystem change is not ruled out by a receipt.
    HttpWireArchive::load(
        originals,
        spec.source,
        pin,
        limits.originals,
        access.originals,
        &mut budget.source,
    )
    .map_err(ReplayError::Archive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin() -> HttpWirePin {
        HttpWirePin {
            scope: ContentDigest::sha256(b"scope"),
            head: ContentDigest::sha256(b"head"),
            reads: 2,
            bytes: 100,
        }
    }
    #[test]
    fn original_tip_never_implicitly_follows_later_storage() -> Result<(), ReplayError> {
        let old = pin();
        assert_eq!(select_source(false, Some(old), None)?, Some(old));
        let later = HttpWirePin {
            head: ContentDigest::sha256(b"later"),
            reads: 3,
            bytes: 120,
            ..old
        };
        assert_eq!(select_source(false, Some(old), Some(later))?, Some(later));
        assert!(matches!(
            select_source(true, Some(old), Some(later)),
            Err(ReplayError::Mismatch)
        ));
        Ok(())
    }
    #[test]
    fn rival_regressing_and_mismatched_source_scopes_are_refused() {
        let old = pin();
        for rival in [
            HttpWirePin {
                scope: ContentDigest::sha256(b"other"),
                ..old
            },
            HttpWirePin {
                head: ContentDigest::sha256(b"other"),
                ..old
            },
            HttpWirePin { reads: 1, ..old },
            HttpWirePin { bytes: 99, ..old },
            HttpWirePin { bytes: 101, ..old },
        ] {
            assert!(select_source(false, Some(old), Some(rival)).is_err());
        }
    }
    #[test]
    fn empty_configuration_does_not_admit_unselected_originals() -> Result<(), ReplayError> {
        assert_eq!(select_source(false, None, None)?, None);
        assert!(select_source(false, None, Some(pin())).is_err());
        Ok(())
    }
}
