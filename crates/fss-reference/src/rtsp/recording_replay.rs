#![forbid(unsafe_code)]
//! Immutable receipts for a bounded, explicitly approved recorder replay request.
//!
//! Requested and acknowledged UTC ranges describe protocol intent and recorder
//! assertions. They do not calibrate frame capture times or prove that the whole
//! requested interval was retained or delivered. Original recording roots keep
//! their authority anchor, receive clock, source bytes and decode-time semantics.
//! This companion is published last, after native verification of every named
//! original, and cold loading repeats that verification through the same owner.

mod storage;
mod wire;

use std::collections::BTreeSet;
use std::ops::Range;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::client::replay::{ReplayAcceptance, ReplayError, ReplayWindow};
use super::recording::local::RecordingIoError;
use super::recording::hevc::{HEVC_RECORDING_KIND, PreparedHevcRecording};
use super::recording::{
    MAX_RECORDING_BYTES, MAX_RECORDING_MAPPINGS, MAX_RECORDING_PACKETS,
    MAX_RECORDING_SAMPLES, PreparedRecording, RECORDING_KIND, RecordingError, RecordingScope,
    RecordingSummary,
};
use super::recording_archive::ArchiveNamespace;
use super::recording_archive::hevc::HevcArchiveNamespace;
use super::recording_catalog::CatalogScope;

pub use storage::{load_hevc_replay_receipt, load_replay_receipt, publish_replay_receipt};

/// Maximum original windows in one immutable replay receipt.
pub const MAX_REPLAY_WINDOWS: usize = 64;
/// Combined canonical receipt metadata and manifest byte ceiling.
pub const MAX_REPLAY_RECEIPT_BYTES: usize = 64 * 1024;
/// Companion family; original four-child AVC recording roots remain unchanged.
pub const REPLAY_RECEIPT_KIND: &str = "avc_recording_replay_receipt_v1";
/// Canonical request identity, including original authority, route, range and base clock.
pub const REPLAY_REQUEST_DOMAIN: &str = "fss.rtsp_replay_request.v1";
/// Replay-specific decode-clock binding over the base clock and request identity.
pub const REPLAY_DECODE_CLOCK_DOMAIN: &str = "fss.rtsp_replay_decode_clock.v1";
/// Versioned canonical receipt metadata domain.
pub const REPLAY_RECEIPT_DOMAIN: &str = "fss.recording_replay_receipt.v1";
/// Separate immutable routing namespace for an exact scope and replay request.
pub const REPLAY_SLOT_DOMAIN: &str = "fss.recording_replay_slot.v1";
/// HEVC companion family; native original HEVC recording roots remain unchanged.
pub const HEVC_REPLAY_RECEIPT_KIND: &str = "hevc_recording_replay_receipt_v1";
/// HEVC request identity, distinct from an otherwise identical AVC request.
pub const HEVC_REPLAY_REQUEST_DOMAIN: &str = "fss.rtsp_hevc_replay_request.v1";
/// HEVC replay-specific decode-clock binding.
pub const HEVC_REPLAY_DECODE_CLOCK_DOMAIN: &str = "fss.rtsp_hevc_replay_decode_clock.v1";
/// Canonical HEVC receipt metadata; the caller pins this family before decoding.
pub const HEVC_REPLAY_RECEIPT_DOMAIN: &str = "fss.hevc_recording_replay_receipt.v1";
/// Immutable HEVC replay routing namespace.
pub const HEVC_REPLAY_SLOT_DOMAIN: &str = "fss.hevc_recording_replay_slot.v1";

/// Closed caller-selected replay codec. Stored bytes never select a verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCodec {
    /// Native H.264/AVC recording verification.
    Avc,
    /// Native H.265/HEVC recording verification, including source-only tails.
    Hevc,
}

impl ReplayCodec {
    /// Stable codec spelling in bounded operator reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Avc => "avc", Self::Hevc => "hevc" }
    }

    const fn request_domain(self) -> &'static str {
        match self { Self::Avc => REPLAY_REQUEST_DOMAIN, Self::Hevc => HEVC_REPLAY_REQUEST_DOMAIN }
    }

    const fn clock_domain(self) -> &'static str {
        match self { Self::Avc => REPLAY_DECODE_CLOCK_DOMAIN, Self::Hevc => HEVC_REPLAY_DECODE_CLOCK_DOMAIN }
    }

    const fn receipt_domain(self) -> &'static str {
        match self { Self::Avc => REPLAY_RECEIPT_DOMAIN, Self::Hevc => HEVC_REPLAY_RECEIPT_DOMAIN }
    }

    const fn receipt_kind(self) -> &'static str {
        match self { Self::Avc => REPLAY_RECEIPT_KIND, Self::Hevc => HEVC_REPLAY_RECEIPT_KIND }
    }

    const fn recording_kind(self) -> &'static str {
        match self { Self::Avc => RECORDING_KIND, Self::Hevc => HEVC_RECORDING_KIND }
    }

    fn window_slot(self, scope: &CatalogScope, ordinal: usize) -> Result<SlotName> {
        match self {
            Self::Avc => ArchiveNamespace::new(scope.clone()).and_then(|namespace| namespace.window_slot(ordinal)),
            Self::Hevc => HevcArchiveNamespace::new(scope.clone()).and_then(|namespace| namespace.window_slot(ordinal)),
        }.map_err(|_| ReplayReceiptError::Scope)
    }
}

/// Payload-free validation and storage refusal. Publication indeterminacy is retained.
#[derive(Debug)]
pub enum ReplayReceiptError {
    /// Authority, route, request, replay clock, generation or time scale differs.
    Scope,
    /// A fixed count, byte or allocation ceiling was exceeded.
    Limit,
    /// Unsupported, truncated or noncanonical metadata.
    Malformed,
    /// Content identity, checksum or original closure differs.
    Digest,
    /// Duplicate roots/slots or unordered/overlapping decode intervals.
    Order,
    /// An original decode interval is empty or reversed.
    Interval,
    /// A stored descriptor disagrees with native original-source verification.
    WindowMismatch,
    /// The requested or acknowledged replay range is invalid.
    Protocol(ReplayError),
    /// Native original recording preparation or replay refused the source.
    Content(RecordingError),
    /// The existing I/O owner refused custody, cancellation, tombstone or durability.
    Storage(RecordingIoError),
}

impl std::fmt::Display for ReplayReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "recording replay refusal: {self:?}")
    }
}
impl std::error::Error for ReplayReceiptError {}
impl From<ReplayError> for ReplayReceiptError {
    fn from(error: ReplayError) -> Self {
        Self::Protocol(error)
    }
}
impl From<RecordingError> for ReplayReceiptError {
    fn from(error: RecordingError) -> Self {
        Self::Content(error)
    }
}
impl From<RecordingIoError> for ReplayReceiptError {
    fn from(error: RecordingIoError) -> Self {
        Self::Storage(error)
    }
}

type Result<T> = std::result::Result<T, ReplayReceiptError>;

/// Exact caller-approved replay identity. No URI or credential is retained.
/// The route digest must name the caller's credential-free approved route plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayRequest {
    codec: ReplayCodec,
    scope: RecordingScope,
    route: ContentDigest,
    window: ReplayWindow,
    base_decode_clock: ContentDigest,
    digest: ContentDigest,
    decode_clock: ContentDigest,
}

impl ReplayRequest {
    /// Bind the original authority and receive clock without replacing either.
    /// The separate base decode clock makes the derived replay clock noncircular
    /// and independently reconstructible when the receipt is loaded cold.
    pub fn new(
        scope: RecordingScope,
        route: ContentDigest,
        window: ReplayWindow,
        base_decode_clock: ContentDigest,
    ) -> Result<Self> {
        Self::for_codec(ReplayCodec::Avc, scope, route, window, base_decode_clock)
    }

    /// Bind an explicitly selected HEVC replay without changing native source
    /// authority. AVC and HEVC requests cannot share a replay clock or namespace.
    pub fn new_hevc(
        scope: RecordingScope,
        route: ContentDigest,
        window: ReplayWindow,
        base_decode_clock: ContentDigest,
    ) -> Result<Self> {
        Self::for_codec(ReplayCodec::Hevc, scope, route, window, base_decode_clock)
    }

    fn for_codec(
        codec: ReplayCodec,
        scope: RecordingScope,
        route: ContentDigest,
        window: ReplayWindow,
        base_decode_clock: ContentDigest,
    ) -> Result<Self> {
        validate_recording_scope(&scope)?;
        if !valid_digest(route) || !valid_digest(base_decode_clock) {
            return Err(ReplayReceiptError::Scope);
        }
        ReplayWindow::new(window.start(), window.end())?;
        let mut out = CanonicalEncoder::new();
        out.text(codec.request_domain());
        wire::encode_recording_scope(&mut out, &scope);
        out.digest(route);
        out.text(&window.to_string());
        out.digest(base_decode_clock);
        let digest = digest(&out.finish_checked().map_err(|_| ReplayReceiptError::Limit)?)?;
        let mut out = CanonicalEncoder::new();
        out.text(codec.clock_domain());
        out.digest(base_decode_clock);
        out.digest(digest);
        let decode_clock = self::digest(
            &out.finish_checked().map_err(|_| ReplayReceiptError::Limit)?,
        )?;
        Ok(Self { codec, scope, route, window, base_decode_clock, digest, decode_clock })
    }

    /// Explicit caller-selected native recording family.
    #[must_use]
    pub const fn codec(&self) -> ReplayCodec { self.codec }
    /// Stable exact request identity, independent of approval and publication outcomes.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.digest }
    /// Original sensor/stream generation, authority anchor and receive-clock identity.
    #[must_use]
    pub const fn scope(&self) -> &RecordingScope { &self.scope }
    /// Caller-approved, credential-free route-plan identity.
    #[must_use]
    pub const fn route(&self) -> ContentDigest { self.route }
    /// Requested UTC protocol interval, not a measured frame-capture interval.
    #[must_use]
    pub const fn window(&self) -> ReplayWindow { self.window }
    /// Original owner-supplied decode-clock identity before binding this replay.
    #[must_use]
    pub const fn base_decode_clock(&self) -> ContentDigest { self.base_decode_clock }
    /// Replay-specific clock required in the recording's catalog namespace.
    #[must_use]
    pub const fn decode_clock(&self) -> ContentDigest { self.decode_clock }
}

/// Why the bounded capture owner stopped; separate from publication completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayTermination {
    /// The caller's requested finite stop condition was reached.
    RequestedStop,
    /// The input ended; this does not prove the requested UTC interval was complete.
    InputEnded,
    /// Native source or picture reconstruction failed.
    SourceFailure,
    /// The capture owner's deadline was reached.
    Deadline,
    /// A bounded work, byte, frame or window allowance was exhausted.
    Budget,
    /// Current authority or lease no longer permitted capture.
    Authority,
    /// The original archive publisher could not complete its work.
    Storage,
    /// The caller's output owner refused progress.
    Output,
    /// The bounded driver could not make further progress.
    ProgressStalled,
    /// The owner explicitly cancelled; cancellation is not a source error.
    Cancelled,
    /// The recorder protocol failed after accepting replay.
    ProtocolFailure,
}

impl ReplayTermination {
    /// Stable payload-free spelling for bounded reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestedStop => "requested_stop",
            Self::InputEnded => "input_ended",
            Self::SourceFailure => "source_failure",
            Self::Deadline => "deadline",
            Self::Budget => "budget",
            Self::Authority => "authority",
            Self::Storage => "storage",
            Self::Output => "output",
            Self::ProgressStalled => "progress_stalled",
            Self::Cancelled => "cancelled",
            Self::ProtocolFailure => "protocol_failure",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::RequestedStop => 0, Self::InputEnded => 1, Self::SourceFailure => 2,
            Self::Deadline => 3, Self::Budget => 4, Self::Authority => 5, Self::Storage => 6,
            Self::Output => 7, Self::ProgressStalled => 8, Self::Cancelled => 9,
            Self::ProtocolFailure => 10,
        }
    }
}

/// Exact original descriptor extracted from sealed, native-verified recording bytes.
/// This alone is not a durable-publication receipt; publication verifies the slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayWindowProof {
    codec: ReplayCodec,
    slot: SlotName,
    summary: RecordingSummary,
    bytes: usize,
    leaves: [ContentDigest; 4],
}

impl ReplayWindowProof {
    /// Extract exact original identity, accounting and closure without copying media.
    pub fn from_avc(slot: SlotName, recording: &PreparedRecording) -> Result<Self> {
        Self::from_recording(ReplayCodec::Avc, slot, recording)
    }

    /// Extract a native HEVC original, preserving its source-only trailing NALs
    /// through the exact source and index closure verified again on cold load.
    pub fn from_hevc(slot: SlotName, recording: &PreparedHevcRecording) -> Result<Self> {
        Self::from_recording(ReplayCodec::Hevc, slot, recording.publication_plan())
    }

    fn from_recording(codec: ReplayCodec, slot: SlotName, recording: &PreparedRecording) -> Result<Self> {
        if recording.manifest().kind() != codec.recording_kind() {
            return Err(ReplayReceiptError::Scope);
        }
        let value = Self {
            codec,
            slot,
            summary: recording.summary().clone(),
            bytes: recording.byte_len(),
            leaves: recording.children().map(|(_, digest, _)| digest),
        };
        validate_window(&value)?;
        Ok(value)
    }

    /// Native codec verifier required for this original descriptor.
    #[must_use]
    pub const fn codec(&self) -> ReplayCodec { self.codec }
    /// Exact current local slot required at publication and cold retrieval.
    #[must_use]
    pub const fn slot(&self) -> &SlotName { &self.slot }
    /// Immutable original recording root.
    #[must_use]
    pub const fn root(&self) -> ContentDigest { self.summary.root }
    /// Unchanged original authority and receive-clock scope.
    #[must_use]
    pub const fn scope(&self) -> &RecordingScope { &self.summary.scope }
    /// Half-open original decode interval, never interpreted as UTC.
    #[must_use]
    pub fn decode_interval(&self) -> Range<u64> { self.summary.decode_interval.clone() }
    /// Original decode tick rate.
    #[must_use]
    pub const fn time_scale(&self) -> u32 { self.summary.time_scale }
    /// Number of retained original datagrams.
    #[must_use]
    pub const fn packets(&self) -> usize { self.summary.packets }
    /// Number of source-linked picture groups, not a decoded-frame certificate.
    #[must_use]
    pub const fn samples(&self) -> usize { self.summary.samples }
    /// Number of original source-linked NALs.
    #[must_use]
    pub const fn nals(&self) -> usize { self.summary.nals }
    /// Complete original payload cost including its root.
    #[must_use]
    pub const fn byte_len(&self) -> usize { self.bytes }
    /// Source, initialization, media and recording-index digests in role order.
    #[must_use]
    pub const fn original_leaf_digests(&self) -> [ContentDigest; 4] { self.leaves }
}

/// Canonical replay intent, acknowledgement and observed durable recording set.
/// An empty set retains only the accepted request, with no original-media claim.
pub struct ReplayReceipt {
    request: ReplayRequest,
    scope: CatalogScope,
    approval: ContentDigest,
    acceptance: ReplayAcceptance,
    windows: Vec<ReplayWindowProof>,
    termination: ReplayTermination,
    publication_complete: bool,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
}

impl std::fmt::Debug for ReplayReceipt {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("ReplayReceipt")
            .field("root", &self.root())
            .field("request", &self.request.digest())
            .field("windows", &self.windows.len())
            .field("termination", &self.termination)
            .field("publication_complete", &self.publication_complete)
            .finish_non_exhaustive()
    }
}

impl ReplayReceipt {
    /// Prepare one immutable companion without I/O. Window descriptors must be in
    /// nonoverlapping decode order, in the contiguous zero-based window slots of
    /// this replay-bound archive namespace. Every original is reverified later.
    /// `publication_complete` records whether the caller settled its observed
    /// original-publication work; it never asserts complete requested UTC coverage.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        request: ReplayRequest,
        scope: CatalogScope,
        approval: ContentDigest,
        acceptance: ReplayAcceptance,
        windows: Vec<ReplayWindowProof>,
        termination: ReplayTermination,
        publication_complete: bool,
    ) -> Result<Self> {
        validate_scope(&scope)?;
        if scope.recording != request.scope || scope.decode_clock != request.decode_clock()
            || !valid_digest(approval) || acceptance.requested() != request.window()
        {
            return Err(ReplayReceiptError::Scope);
        }
        ReplayAcceptance::new(acceptance.cseq(), acceptance.requested(), acceptance.acknowledged())?;
        if windows.len() > MAX_REPLAY_WINDOWS { return Err(ReplayReceiptError::Limit); }
        let mut roots = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut previous_end = None;
        for (ordinal, window) in windows.iter().enumerate() {
            validate_window(window)?;
            if window.codec() != request.codec() || window.scope() != &scope.recording
                || window.time_scale() != scope.time_scale
                || window.slot() != &request.codec().window_slot(&scope, ordinal)?
            {
                return Err(ReplayReceiptError::Scope);
            }
            if previous_end.is_some_and(|end| end > window.summary.decode_interval.start)
                || !roots.insert(window.root()) || !slots.insert(window.slot.as_str())
            {
                return Err(ReplayReceiptError::Order);
            }
            previous_end = Some(window.summary.decode_interval.end);
        }
        let metadata = wire::encode(&request, &scope, approval, acceptance, &windows,
            termination, publication_complete)?;
        let mut children = BTreeSet::new();
        for window in &windows {
            children.insert(window.root());
            children.extend(window.leaves);
        }
        let manifest = ObjectManifest::new(request.codec().receipt_kind(), children, Some(digest(&metadata)?))
            .map_err(|_| ReplayReceiptError::Digest)?;
        if metadata.len().checked_add(manifest.canonical_bytes().len())
            .is_none_or(|bytes| bytes > MAX_REPLAY_RECEIPT_BYTES)
        { return Err(ReplayReceiptError::Limit); }
        Ok(Self { request, scope, approval, acceptance, windows, termination,
            publication_complete, metadata, manifest })
    }

    /// Exact root-last companion identity.
    #[must_use]
    pub fn root(&self) -> ContentDigest { self.manifest.root() }
    /// Original request and its independently reconstructible replay clock.
    #[must_use]
    pub const fn request(&self) -> &ReplayRequest { &self.request }
    /// Immutable codec-specific routing slot for this exact request and scope.
    pub fn slot(&self) -> Result<SlotName> {
        codec_replay_slot(self.request.codec(), &self.scope, self.request.digest())
    }
    /// Exact replay-bound catalog namespace and unchanged authority anchor.
    #[must_use]
    pub const fn scope(&self) -> &CatalogScope { &self.scope }
    /// Complete caller-approved capture-plan identity, separate from request identity.
    #[must_use]
    pub const fn approval(&self) -> ContentDigest { self.approval }
    /// Recorder's contained accepted range and exact nonzero PLAY correlation.
    #[must_use]
    pub const fn acceptance(&self) -> ReplayAcceptance { self.acceptance }
    /// Canonically ordered original descriptors; never a UTC coverage witness.
    #[must_use]
    pub fn windows(&self) -> &[ReplayWindowProof] { &self.windows }
    /// Why capture stopped, independently of original publication state.
    #[must_use]
    pub const fn termination(&self) -> ReplayTermination { self.termination }
    /// Whether the caller settled all of its observed original-publication work.
    #[must_use]
    pub const fn publication_complete(&self) -> bool { self.publication_complete }
    /// Explicit requested replay transport policy; not a frame-time assertion.
    #[must_use]
    pub const fn rate_control(&self) -> &'static str { "no" }
    /// Exact canonical metadata without source/media payloads or credential-bearing URIs.
    #[must_use]
    pub fn metadata_bytes(&self) -> &[u8] { &self.metadata }
    /// Root-last manifest with the flattened original source closure.
    #[must_use]
    pub const fn manifest(&self) -> &ObjectManifest { &self.manifest }
    /// New companion bytes only; already retained original media is not copied.
    #[must_use]
    pub fn byte_len(&self) -> usize { self.metadata.len() + self.manifest.canonical_bytes().len() }
}

/// One immutable slot per exact replay scope and request, with no mutable latest pointer.
pub fn replay_slot(scope: &CatalogScope, request_digest: ContentDigest) -> Result<SlotName> {
    codec_replay_slot(ReplayCodec::Avc, scope, request_digest)
}

/// HEVC companion slot, independently selected before any stored bytes are read.
pub fn hevc_replay_slot(scope: &CatalogScope, request_digest: ContentDigest) -> Result<SlotName> {
    codec_replay_slot(ReplayCodec::Hevc, scope, request_digest)
}

fn codec_replay_slot(codec: ReplayCodec, scope: &CatalogScope, request_digest: ContentDigest) -> Result<SlotName> {
    validate_scope(scope)?;
    if !valid_digest(request_digest) { return Err(ReplayReceiptError::Scope); }
    let mut out = CanonicalEncoder::new();
    out.text(match codec { ReplayCodec::Avc => REPLAY_SLOT_DOMAIN, ReplayCodec::Hevc => HEVC_REPLAY_SLOT_DOMAIN });
    wire::encode_scope(&mut out, scope);
    out.digest(request_digest);
    let identity = digest(&out.finish_checked().map_err(|_| ReplayReceiptError::Limit)?)?.to_text();
    let hex = identity.strip_prefix("sha256:").ok_or(ReplayReceiptError::Digest)?;
    SlotName::parse(&format!("fssrr1-{}-{hex}", codec.as_str())).map_err(|_| ReplayReceiptError::Malformed)
}

fn validate_recording_scope(scope: &RecordingScope) -> Result<()> {
    if scope.generation == 0 || !valid_digest(scope.anchor) || !valid_digest(scope.receive_clock) {
        return Err(ReplayReceiptError::Scope);
    }
    Ok(())
}

fn validate_scope(scope: &CatalogScope) -> Result<()> {
    validate_recording_scope(&scope.recording)?;
    if scope.time_scale == 0 || !valid_digest(scope.decode_clock) {
        return Err(ReplayReceiptError::Scope);
    }
    Ok(())
}

fn validate_window(window: &ReplayWindowProof) -> Result<()> {
    validate_recording_scope(window.scope())?;
    if !(1..=MAX_RECORDING_PACKETS).contains(&window.summary.packets)
        || !(1..=MAX_RECORDING_SAMPLES).contains(&window.summary.samples)
        || !(1..=MAX_RECORDING_MAPPINGS).contains(&window.summary.nals)
        || !(1..=MAX_RECORDING_BYTES).contains(&window.bytes)
        || window.summary.time_scale == 0
    { return Err(ReplayReceiptError::Limit); }
    if window.summary.decode_interval.start >= window.summary.decode_interval.end {
        return Err(ReplayReceiptError::Interval);
    }
    if !valid_digest(window.root()) || window.leaves.iter().any(|value| !valid_digest(*value)) {
        return Err(ReplayReceiptError::Digest);
    }
    let original = ObjectManifest::new(window.codec.recording_kind(), window.leaves[..3].iter().copied(),
        Some(window.leaves[3])).map_err(|_| ReplayReceiptError::Digest)?;
    if original.root() != window.root() { return Err(ReplayReceiptError::Digest); }
    Ok(())
}

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && !value.is_laboratory() && value.bytes() != [0; 32]
}

fn digest(bytes: &[u8]) -> Result<ContentDigest> {
    ContentDigest::try_sha256(bytes).map_err(|_| ReplayReceiptError::Limit)
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_| ReplayReceiptError::Limit)?;
    Ok(values)
}
