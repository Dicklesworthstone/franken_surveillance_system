#![forbid(unsafe_code)]
//! Retained, source-bound node observation clocks for native recording windows.
//!
//! These intervals describe native read/admission observations of retained packets,
//! including source-only boundary lookahead. They are neither camera exposure
//! times nor continuous scene coverage. The exact local NTP exchange is an
//! unauthenticated assertion, subject to the retained drift and lifetime policy.
//! A receive-clock identity binds one caller-owned monotonic session; a probe or
//! another capture's clock cannot be substituted for that session.

mod prepare;
mod storage;
mod wire;

use std::ops::Range;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

pub use crate::site::clock::UtcInterval;
use crate::site::clock::{ClockCorrelationError, HostClockSample};
use crate::site::clock_proof::{ClockProofError, LocalNtpExchange};

use super::recording::hevc::PreparedHevcRecording;
use super::recording::local::RecordingIoError;
use super::recording::{
    MAX_RECORDING_BYTES, MAX_RECORDING_PACKETS, PreparedRecording, RecordingError, RecordingScope,
    RecordingSummary,
};
use super::recording_catalog::{CatalogQueryLimits, CatalogScope};

pub use storage::{load_clock_index, publish_clock_index};

/// Maximum complete recording windows in one immutable clock index.
pub const MAX_CLOCK_WINDOWS: usize = 64;
/// Maximum distinct native admission brackets in one clock index.
pub const MAX_CLOCK_BRACKETS: usize = 65_536;
/// Combined canonical index and manifest bytes; original media is not copied.
pub const MAX_CLOCK_INDEX_BYTES: usize = 16 * 1024 * 1024;
/// Immutable companion manifest kind; original four-child recordings are unchanged.
pub const CLOCK_INDEX_KIND: &str = "recording_clock_index_v1";
/// Versioned canonical metadata domain, shared by the explicitly selected codecs.
pub const CLOCK_INDEX_DOMAIN: &str = "fss.recording_clock_index.v1";
/// Separate routing namespace for one clock index per exact recording/decode scope.
pub const CLOCK_SLOT_DOMAIN: &str = "fss.recording_clock_slot.v1";

/// Codec selected by the caller, never inferred from an untrusted stored tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingClockCodec {
    /// Source-replay-verified native AVC windows.
    Avc,
    /// Source-replay-verified native HEVC windows.
    Hevc,
}

impl RecordingClockCodec {
    /// Stable codec spelling for bounded metadata output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Avc => 0,
            Self::Hevc => 1,
        }
    }

    const fn recording_kind(self) -> &'static str {
        match self {
            Self::Avc => super::recording::RECORDING_KIND,
            Self::Hevc => super::recording::hevc::HEVC_RECORDING_KIND,
        }
    }
}

/// One native read/admission bracket on the recording's own monotonic clock.
/// The completed sample follows the read that admitted a packet; framing may use
/// earlier buffered bytes and occur later. Neither first-byte nor kernel arrival
/// time is claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveClockBracket {
    /// Exact native read coordinate carried into each original packet it admitted.
    pub admission_ns: u64,
    /// Bracketed host-clock sample after that native read completed.
    pub completed: HostClockSample,
}

/// Payload-free content, time and storage refusals. Storage indeterminacy remains typed.
#[derive(Debug)]
pub enum RecordingClockError {
    /// Codec, owner scope, nonzero identity or clock basis differs.
    Scope,
    /// A count, byte, allocation or output bound was exceeded.
    Limit,
    /// Unsupported, truncated or noncanonical metadata.
    Malformed,
    /// Content identity, checksum or flattened closure differs.
    Digest,
    /// Duplicate, overlapping or out-of-order input rows.
    Order,
    /// A retained source packet has no exact completed read/admission bracket.
    MissingBracket,
    /// An original recording differs from its retained clock descriptor.
    WindowMismatch,
    /// An empty/reversed query or unrepresentable observation interval.
    Interval,
    /// Native source parsing or replay refused a recording.
    Content(RecordingError),
    /// Exact local-daemon exchange was refused.
    Exchange(ClockProofError),
    /// A sampled discontinuity, stale calibration or checked projection was refused.
    Correlation(ClockCorrelationError),
    /// Existing owner refused I/O, cancellation, tombstone, or unsettled publication.
    Storage(RecordingIoError),
}

impl std::fmt::Display for RecordingClockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "recording clock refusal: {self:?}")
    }
}

impl std::error::Error for RecordingClockError {}
impl From<RecordingError> for RecordingClockError {
    fn from(error: RecordingError) -> Self {
        Self::Content(error)
    }
}
impl From<ClockProofError> for RecordingClockError {
    fn from(error: ClockProofError) -> Self {
        Self::Exchange(error)
    }
}
impl From<ClockCorrelationError> for RecordingClockError {
    fn from(error: ClockCorrelationError) -> Self {
        Self::Correlation(error)
    }
}
impl From<RecordingIoError> for RecordingClockError {
    fn from(error: RecordingIoError) -> Self {
        Self::Storage(error)
    }
}

type Result<T> = std::result::Result<T, RecordingClockError>;

/// Native-recording descriptor. Public constructors extract all coordinates from
/// sealed original source bytes; a caller cannot provide a shorter invented span.
#[derive(Clone, Eq, PartialEq)]
pub struct ClockWindow {
    codec: RecordingClockCodec,
    slot: SlotName,
    summary: RecordingSummary,
    bytes: usize,
    leaves: [ContentDigest; 4],
    admissions: Vec<u64>,
}

impl std::fmt::Debug for ClockWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClockWindow")
            .field("root", &self.root())
            .field("packet_admissions", &self.admissions.len())
            .finish_non_exhaustive()
    }
}

impl ClockWindow {
    /// Extract a bounded descriptor from an already native-verified AVC window.
    pub fn from_avc(slot: SlotName, recording: &PreparedRecording) -> Result<Self> {
        Self::from_recording(slot, recording, RecordingClockCodec::Avc)
    }

    /// Extract a bounded descriptor from an already native-verified HEVC window.
    pub fn from_hevc(slot: SlotName, recording: &PreparedHevcRecording) -> Result<Self> {
        Self::from_recording(
            slot,
            recording.publication_plan(),
            RecordingClockCodec::Hevc,
        )
    }

    fn from_recording(
        slot: SlotName,
        recording: &PreparedRecording,
        codec: RecordingClockCodec,
    ) -> Result<Self> {
        if recording.manifest().kind() != codec.recording_kind() {
            return Err(RecordingClockError::Scope);
        }
        let packets = recording.packets()?;
        if packets.is_empty() || packets.len() > MAX_RECORDING_PACKETS {
            return Err(RecordingClockError::Limit);
        }
        let mut admissions = bounded_vec(packets.len())?;
        admissions.extend(packets.iter().map(|packet| packet.received_ns));
        // Source custody is in extended sequence order, not arrival order.
        admissions.sort_unstable();
        admissions.dedup();
        Ok(Self {
            codec,
            slot,
            summary: recording.summary().clone(),
            bytes: recording.byte_len(),
            leaves: recording.children().map(|(_, digest, _)| digest),
            admissions,
        })
    }

    /// Exact native local recording slot; routing is not authority.
    #[must_use]
    pub fn slot(&self) -> &SlotName {
        &self.slot
    }
    /// Exact immutable recording manifest identity.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.summary.root
    }
    /// Sensor, logical stream generation, authority anchor and receive-clock identity.
    #[must_use]
    pub const fn scope(&self) -> &RecordingScope {
        &self.summary.scope
    }
    /// Original half-open decode interval; never reinterpreted as UTC.
    #[must_use]
    pub fn decode_interval(&self) -> Range<u64> {
        self.summary.decode_interval.clone()
    }
    /// Whole recording payload bytes, including its original manifest.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.bytes
    }
    /// Every unique original packet coordinate, sorted independently of sequence order.
    #[must_use]
    pub fn packet_admissions(&self) -> &[u64] {
        &self.admissions
    }
    /// Original source, initialization, media and index digests, in role order.
    #[must_use]
    pub const fn original_leaf_digests(&self) -> [ContentDigest; 4] {
        self.leaves
    }
}

/// One whole original recording with a conservative closed node observation interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockIndexEntry {
    window: ClockWindow,
    utc: UtcInterval,
}

impl ClockIndexEntry {
    /// Exact immutable recording slot.
    #[must_use]
    pub fn slot(&self) -> &SlotName {
        self.window.slot()
    }
    /// Exact immutable recording root.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.window.root()
    }
    /// Unchanged original half-open decode interval.
    #[must_use]
    pub fn decode_interval(&self) -> Range<u64> {
        self.window.decode_interval()
    }
    /// Whole original window cost; a query does not trim encoded source bytes.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.window.byte_len()
    }
    /// Every unique source packet coordinate, including retained boundary lookahead.
    #[must_use]
    pub fn packet_admissions(&self) -> &[u64] {
        self.window.packet_admissions()
    }
    /// Closed UTC envelope of native read/admission observations, not camera capture time.
    #[must_use]
    pub const fn utc_interval(&self) -> UtcInterval {
        self.utc
    }
    /// Exact four original child identities, retained without recopying media.
    #[must_use]
    pub const fn original_leaf_digests(&self) -> [ContentDigest; 4] {
        self.window.original_leaf_digests()
    }
}

/// Immutable, bounded clock metadata. Preparation is pure; publication verifies
/// all original windows, and cold loading repeats their native source verification.
pub struct RecordingClockIndex {
    scope: CatalogScope,
    codec: RecordingClockCodec,
    approval_digest: ContentDigest,
    exchange: LocalNtpExchange,
    terminal: HostClockSample,
    brackets: Vec<ReceiveClockBracket>,
    windows: Vec<ClockIndexEntry>,
    index: Vec<u8>,
    manifest: ObjectManifest,
}

impl std::fmt::Debug for RecordingClockIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingClockIndex")
            .field("root", &self.root())
            .field("codec", &self.codec)
            .field("windows", &self.windows.len())
            .field("brackets", &self.brackets.len())
            .finish_non_exhaustive()
    }
}

impl RecordingClockIndex {
    /// Bind actual original packet coordinates to one exact same-session clock.
    /// Inputs must be canonical: windows in nonoverlapping decode order, brackets
    /// strictly increasing by admission. Compatible unused brackets are checked
    /// then omitted from retained metadata; every referenced coordinate is required.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        scope: CatalogScope,
        codec: RecordingClockCodec,
        approval_digest: ContentDigest,
        exchange: LocalNtpExchange,
        terminal: HostClockSample,
        brackets: &[ReceiveClockBracket],
        windows: &[ClockWindow],
    ) -> Result<Self> {
        prepare::prepare(
            scope,
            codec,
            approval_digest,
            exchange,
            terminal,
            brackets,
            windows,
        )
    }

    /// Root-last immutable companion manifest, including the complete original closure.
    #[must_use]
    pub const fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Exact metadata bytes, without original media payloads.
    #[must_use]
    pub fn index_bytes(&self) -> &[u8] {
        &self.index
    }
    /// Exact companion manifest identity.
    #[must_use]
    pub fn root(&self) -> ContentDigest {
        self.manifest.root()
    }
    /// New metadata and manifest bytes, excluding existing original recordings.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.index.len() + self.manifest.canonical_bytes().len()
    }
    /// Exact recording and decode scope; not inferred from source timestamps.
    #[must_use]
    pub const fn scope(&self) -> &CatalogScope {
        &self.scope
    }
    /// Independently selected native codec.
    #[must_use]
    pub const fn codec(&self) -> RecordingClockCodec {
        self.codec
    }
    /// Exact capture approval which selected this observation policy.
    #[must_use]
    pub const fn approval_digest(&self) -> ContentDigest {
        self.approval_digest
    }
    /// Exact unauthenticated local-daemon exchange and all host-read brackets.
    #[must_use]
    pub const fn exchange(&self) -> &LocalNtpExchange {
        &self.exchange
    }
    /// Final sampled host-clock observation, not a continuous absence-of-steps proof.
    #[must_use]
    pub const fn terminal(&self) -> HostClockSample {
        self.terminal
    }
    /// Retained native brackets, restricted to coordinates referenced by original windows.
    #[must_use]
    pub fn brackets(&self) -> &[ReceiveClockBracket] {
        &self.brackets
    }
    /// Original windows in canonical decode order; observation intervals may overlap.
    #[must_use]
    pub fn windows(&self) -> &[ClockIndexEntry] {
        &self.windows
    }

    /// Select whole-window candidates overlapping a half-open UTC request. Closed
    /// observation intervals overlap precisely when latest >= start and earliest < end.
    /// An empty answer is not camera absence or a claim about unannotated originals.
    pub fn select(&self, query: Range<u64>, limits: CatalogQueryLimits) -> Result<ClockSelection> {
        if query.start >= query.end {
            return Err(RecordingClockError::Interval);
        }
        if !(1..=MAX_CLOCK_WINDOWS).contains(&limits.max_windows)
            || limits.max_output_bytes == 0
            || limits.max_output_bytes > (MAX_CLOCK_WINDOWS * MAX_RECORDING_BYTES) as u64
        {
            return Err(RecordingClockError::Limit);
        }
        let mut ordinals = bounded_vec(self.windows.len().min(limits.max_windows))?;
        let mut bytes = 0_u64;
        for (ordinal, window) in self.windows.iter().enumerate() {
            if window.utc.latest_ns < query.start || window.utc.earliest_ns >= query.end {
                continue;
            }
            if ordinals.len() == limits.max_windows {
                return Err(RecordingClockError::Limit);
            }
            bytes = bytes
                .checked_add(window.byte_len() as u64)
                .ok_or(RecordingClockError::Limit)?;
            if bytes > limits.max_output_bytes {
                return Err(RecordingClockError::Limit);
            }
            ordinals.push(ordinal);
        }
        Ok(ClockSelection {
            query,
            ordinals,
            bytes,
        })
    }
}

/// Complete bounded candidate selection; never a truncated response or coverage witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSelection {
    query: Range<u64>,
    ordinals: Vec<usize>,
    bytes: u64,
}

impl ClockSelection {
    /// Original nonempty half-open UTC request.
    #[must_use]
    pub fn query(&self) -> Range<u64> {
        self.query.clone()
    }
    /// Stable indices into this exact clock index, in original decode order.
    #[must_use]
    pub fn ordinals(&self) -> &[usize] {
        &self.ordinals
    }
    /// Exact sum of selected whole-window payload costs.
    #[must_use]
    pub const fn output_bytes(&self) -> u64 {
        self.bytes
    }
}

/// Stable, separate immutable companion slot for one exact codec and catalog scope.
/// This routing name is neither a mutable latest pointer nor an authorization grant.
pub fn clock_slot(codec: RecordingClockCodec, scope: &CatalogScope) -> Result<SlotName> {
    prepare::validate_scope(scope)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CLOCK_SLOT_DOMAIN);
    encoder.u8(codec.tag());
    wire::encode_scope(&mut encoder, scope);
    let encoded = encoder
        .finish_checked()
        .map_err(|_| RecordingClockError::Limit)?;
    let identity = digest(&encoded)?.to_text();
    let hex = identity
        .strip_prefix("sha256:")
        .ok_or(RecordingClockError::Digest)?;
    SlotName::parse(&format!("fssrc1-{}-{hex}", codec.as_str()))
        .map_err(|_| RecordingClockError::Malformed)
}

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}

fn digest(bytes: &[u8]) -> Result<ContentDigest> {
    ContentDigest::try_sha256(bytes).map_err(|_| RecordingClockError::Limit)
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| RecordingClockError::Limit)?;
    Ok(values)
}
