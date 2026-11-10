#![forbid(unsafe_code)]
//! Cold queries over exact recorder-reported ONVIF replay UTC assertions.
//!
//! Every row is derived from original RTP datagrams after native codec/source
//! verification. The caller independently pins receipt, request, codec, complete
//! archive scope and NTP era. Receive clocks, requested/acknowledged PLAY ranges,
//! media decode/presentation times and sender reports never supply missing UTC.
//!
//! Positive rows are recorder assertions with a conservative rounding enclosure,
//! not authenticated sensor exposure times. The eight-bit CSeq field cannot prove
//! the full PLAY identity. Missing/malformed/conflicting assertions and HEVC
//! source-only lookahead remain explicit. An empty answer proves no absence,
//! continuous coverage, successful EOF, or completeness of the requested interval.
//!
//! Receipt count limits are checked before original reads and again against
//! verified outputs. Native codec verification keeps its own fixed per-window
//! ceilings (4096 packets, 256 samples, 32 MiB). A forged smaller descriptor may
//! be rejected only after that bounded verification; lower query packet/sample
//! limits are admission/result limits, not CPU-step budgets for malformed media.
//! Original payload reads are separately capped before allocation.

#[path = "time/proof.rs"]
mod proof;
#[path = "time/scan.rs"]
mod scan;
#[path = "time/source.rs"]
mod source;

use super::{ReplayCodec, ReplayReceipt, ReplayReceiptError};
use crate::rtsp::recording_catalog::CatalogScope;
use fss_core::ContentDigest;
use fss_packet::onvif_replay::{RecordedUtcInterval, ReplayExtensionError, ReplayHeaderExtension};
use fss_publication::{LocalRootPublisher, PublishCancellation, SlotName};

/// Complete caller-pinned query identity, including explicit work allowances.
pub const REPLAY_TIME_QUERY_DOMAIN: &str = "fss.rtsp_replay_time_query.v1";
/// Ordered full-datagram identities for one native source association.
pub const REPLAY_TIME_PACKETS_DOMAIN: &str = "fss.rtsp_replay_time_packets.v1";
/// One native sample or separate source-only observation and all of its pins.
pub const REPLAY_TIME_SAMPLE_DOMAIN: &str = "fss.rtsp_replay_time_sample.v1";
/// Every observed association, including known values outside the query interval.
pub const REPLAY_TIME_INDEX_DOMAIN: &str = "fss.rtsp_replay_time_index.v1";
/// Complete result partition, query identity and fully scanned index.
pub const REPLAY_TIME_REPORT_DOMAIN: &str = "fss.rtsp_replay_time_report.v1";

/// Maximum report rows, counting matches, unknown samples and source-only groups together.
pub const MAX_REPLAY_TIME_RESULTS: usize = 32_768;
/// Exclusive upper UTC query bound: the start of year 10000, in Unix nanoseconds.
pub const REPLAY_TIME_END_EXCLUSIVE_NS: i128 = 253_402_300_800_000_000_000;

/// Explicit admission, original-payload and aggregate result ceilings. No result is truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayTimeLimits {
    /// Receipt original windows, from 1 through 64.
    pub max_windows: usize,
    /// Admitted and projected native samples, from 1 through 16384.
    /// Does not lower the codec verifier's intrinsic per-window work ceiling.
    pub max_samples: usize,
    /// Admitted and projected original packets, from 1 through 262144.
    /// Does not lower the codec verifier's intrinsic per-window work ceiling.
    pub max_packets: usize,
    /// Original verification allowance, from 1 byte through 2 GiB.
    /// Preflight reserves the native 32 MiB window ceiling for each original.
    pub max_source_bytes: u64,
    /// Total returned matches, unknown samples and source-only groups, from 1 through 32768.
    pub max_results: usize,
}

impl Default for ReplayTimeLimits {
    fn default() -> Self {
        Self {
            max_windows: 64,
            max_samples: 16_384,
            max_packets: 262_144,
            max_source_bytes: 256 * 1024 * 1024,
            max_results: 4096,
        }
    }
}

impl ReplayTimeLimits {
    /// Validate before opening an archive or performing any original I/O.
    pub fn validate(&self) -> Result<(), ReplayTimeError> {
        if !(1..=super::MAX_REPLAY_WINDOWS).contains(&self.max_windows)
            || !(1..=super::MAX_REPLAY_WINDOWS * super::MAX_RECORDING_SAMPLES)
                .contains(&self.max_samples)
            || !(1..=super::MAX_REPLAY_WINDOWS * super::MAX_RECORDING_PACKETS)
                .contains(&self.max_packets)
            || !(1..=2_147_483_648).contains(&self.max_source_bytes)
            || !(1..=MAX_REPLAY_TIME_RESULTS).contains(&self.max_results)
        {
            return Err(ReplayTimeError::Limit);
        }
        Ok(())
    }
}

/// Caller-supplied authority and a half-open UTC query. None is inferred from stored bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayTimeQuery {
    /// Independently chosen native verifier.
    pub codec: ReplayCodec,
    /// Independently pinned original recording, decode-clock and tick-scale scope.
    pub scope: CatalogScope,
    /// Exact immutable replay companion root.
    pub receipt_root: ContentDigest,
    /// Independently pinned complete replay request identity.
    pub request: ContentDigest,
    /// Explicit NTP era. No request, wall clock or packet arrival selects this.
    pub ntp_era: u32,
    /// Inclusive query start in Unix nanoseconds.
    pub start_ns: i128,
    /// Exclusive query end in Unix nanoseconds.
    pub end_ns: i128,
    /// Admission, pre-read original payload and aggregate output ceilings.
    pub limits: ReplayTimeLimits,
}

impl ReplayTimeQuery {
    /// Validate every pure pin and bound before storage access.
    pub fn validate(&self) -> Result<(), ReplayTimeError> {
        self.limits.validate()?;
        if self.start_ns < 0
            || self.start_ns >= self.end_ns
            || self.end_ns > REPLAY_TIME_END_EXCLUSIVE_NS
        {
            return Err(ReplayTimeError::Interval);
        }
        if super::validate_scope(&self.scope).is_err()
            || !super::valid_digest(self.receipt_root)
            || !super::valid_digest(self.request)
        {
            return Err(ReplayTimeError::Scope);
        }
        Ok(())
    }

    /// Deterministic caller intent, including limits, without reading any original.
    pub fn digest(&self) -> Result<ContentDigest, ReplayTimeError> {
        self.validate()?;
        proof::query_digest(self).map_err(ReplayTimeError::from)
    }
}

/// Why a native sample or source-only observation cannot provide recorder UTC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayTimeUnknown {
    /// ONVIF requires the first packet of each access unit to carry the assertion.
    MissingFirstExtension,
    /// Its first packet has another extension profile, with no replay timestamp.
    ForeignFirstExtension,
    /// A present replay assertion violates the supported wire contract.
    MalformedExtension(ReplayExtensionError),
    /// Repeated assertions in one association disagree; padding is ignored.
    ConflictingExtensions,
    /// Source packet timestamp differs from the native sample/group timestamp.
    RtpTimestampMismatch,
    /// One RTP packet contributes to more than one native association.
    SharedPacket,
    /// The observed low eight CSeq bits disagree with the pinned accepted PLAY.
    PlayCseqMismatch,
    /// Recorder supplied the all-zero timestamp sentinel.
    UnknownTimestamp,
    /// The caller's explicit era cannot place this assertion in supported UTC.
    UtcOutOfRange,
}

impl ReplayTimeUnknown {
    /// Stable, payload-free machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingFirstExtension => "missing_first_packet_extension",
            Self::ForeignFirstExtension => "foreign_first_packet_extension",
            Self::MalformedExtension(_) => "malformed_replay_extension",
            Self::ConflictingExtensions => "conflicting_replay_extensions",
            Self::RtpTimestampMismatch => "rtp_timestamp_mismatch",
            Self::SharedPacket => "packet_shared_between_access_units",
            Self::PlayCseqMismatch => "play_cseq_low_mismatch",
            Self::UnknownTimestamp => "recorder_timestamp_unknown",
            Self::UtcOutOfRange => "era_out_of_range",
        }
    }

    /// Stable parser error when applicable; structural absence/conflict has no fabricated error.
    #[must_use]
    pub fn error_code(self) -> Option<&'static str> {
        match self {
            Self::MalformedExtension(error) => Some(error.code()),
            Self::PlayCseqMismatch => Some(ReplayExtensionError::PlayCseqMismatch.code()),
            Self::UnknownTimestamp => Some(ReplayExtensionError::UnknownTimestamp.code()),
            Self::UtcOutOfRange => Some(ReplayExtensionError::UtcRange.code()),
            _ => None,
        }
    }
}

/// Exact original packet citation and an optional recorder UTC assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayTimeEvidence {
    /// First contributing extended sequence, in original source order.
    pub first_sequence: u64,
    /// Last contributing extended sequence; gaps are not filled or inferred.
    pub last_sequence: u64,
    /// Number of distinct contributing original RTP datagrams.
    pub packet_count: usize,
    /// Canonical ordered sequence plus full-datagram hashes.
    pub packet_set_digest: ContentDigest,
    /// Exact sample/group association, all independent pins and observed result.
    pub proof_digest: ContentDigest,
    /// Parsed first assertion, retained even when its UTC/CSeq is unknown.
    pub header: Option<ReplayHeaderExtension>,
    /// Outward nanosecond enclosure, present only when the whole association agrees.
    pub utc: Option<RecordedUtcInterval>,
    /// Explicit reason for missing UTC; never filled from another clock.
    pub unknown: Option<ReplayTimeUnknown>,
}

/// One native media sample and its source-derived recorder-time evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySampleTime {
    /// Ordinal in the pinned replay receipt.
    pub window: usize,
    /// Exact durable native original slot.
    pub slot: SlotName,
    /// Exact native original root, binding source, index and media.
    pub root: ContentDigest,
    /// Native sample ordinal in decode order.
    pub sample: usize,
    /// Original owner-supplied media decode ticks, independent of recorder UTC.
    pub decode_time: u64,
    /// Original presentation ticks, preserving signed composition offsets.
    pub presentation_time: u64,
    /// Original sample duration in the explicitly pinned media scale.
    pub duration: u32,
    /// Native picture's uninterpreted RTP timestamp.
    pub rtp_timestamp: u32,
    /// Recorder assertion and packet-level citations.
    pub evidence: ReplayTimeEvidence,
}

/// Trailing HEVC source observation, never a published media sample or completion proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySourceOnlyTime {
    /// Ordinal in the pinned replay receipt.
    pub window: usize,
    /// Exact durable native original slot.
    pub slot: SlotName,
    /// Exact native original root containing this source-only evidence.
    pub root: ContentDigest,
    /// Timestamp of a consecutive trailing source-NAL group.
    pub rtp_timestamp: u32,
    /// Recorder assertion retained separately from sample matches.
    pub evidence: ReplayTimeEvidence,
}

/// Complete bounded result over one point-in-time reverified original closure.
/// Native decode order is retained; B-frame presentation/UTC order may differ.
#[derive(Debug)]
pub struct ReplayTimeReport {
    /// Complete validated query and independent pins.
    pub query: ReplayTimeQuery,
    /// Reverified companion retaining accepted/requested ranges and discovery provenance.
    pub receipt: ReplayReceipt,
    /// Query, index, accounting and exact result partition identity.
    pub digest: ContentDigest,
    /// All associations, including known outside samples; independent of query range/limits.
    pub index_digest: ContentDigest,
    /// Entire receipt window count; never a partial scan.
    pub scanned_windows: usize,
    /// Entire verified native sample count.
    pub scanned_samples: usize,
    /// Entire original RTP packet count.
    pub scanned_packets: usize,
    /// Conservative preflight reservation: 32 MiB per original window.
    pub source_bytes_reserved: u64,
    /// Actual original root plus four-child closure bytes verified during this query.
    pub source_bytes: u64,
    /// Known native samples whose rounding enclosures do not overlap the query.
    pub outside_samples: usize,
    /// Positive recorder assertions conservatively overlapping the half-open query.
    pub matches: Vec<ReplaySampleTime>,
    /// Native samples lacking a usable recorder UTC assertion.
    pub unknown: Vec<ReplaySampleTime>,
    /// All separate trailing source groups, regardless of their UTC/query overlap.
    pub source_only: Vec<ReplaySourceOnlyTime>,
}

/// Whole-query refusal. No partial rows are released on budget, custody or cancellation failure.
#[derive(Debug)]
pub enum ReplayTimeError {
    /// Invalid independent scope or identity pin.
    Scope,
    /// Invalid half-open supported UTC query interval.
    Interval,
    /// Invalid/exhausted admission, source payload, allocation or aggregate output allowance.
    Limit,
    /// Exact pinned receipt/original custody or native verification failed.
    Receipt(ReplayReceiptError),
}

impl ReplayTimeError {
    /// Stable payload-free operator error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Scope => "ERR-REPLAY-TIME-SCOPE-001",
            Self::Interval => "ERR-REPLAY-TIME-INTERVAL-001",
            Self::Limit => "ERR-REPLAY-TIME-LIMIT-001",
            Self::Receipt(ReplayReceiptError::Storage(
                crate::rtsp::recording::local::RecordingIoError::Cancelled,
            )) => "ERR-REPLAY-TIME-CANCELLED-001",
            Self::Receipt(_) => "ERR-REPLAY-TIME-CUSTODY-001",
        }
    }
}
impl std::fmt::Display for ReplayTimeError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.code())
    }
}
impl std::error::Error for ReplayTimeError {}
impl From<ReplayReceiptError> for ReplayTimeError {
    fn from(error: ReplayReceiptError) -> Self {
        match error {
            ReplayReceiptError::Limit
            | ReplayReceiptError::Content(crate::rtsp::recording::RecordingError::Limit)
            | ReplayReceiptError::Storage(
                crate::rtsp::recording::local::RecordingIoError::Budget,
            ) => Self::Limit,
            error => Self::Receipt(error),
        }
    }
}

/// Reverify every named original once, project exact native packet associations,
/// then recheck receipt roots, originals, tombstones and cancellation before return.
/// No object is published or modified, no URI is fetched and no alternate root is discovered.
pub fn query_replay_time(
    publisher: &LocalRootPublisher,
    query: &ReplayTimeQuery,
    cancel: &dyn PublishCancellation,
) -> Result<ReplayTimeReport, ReplayTimeError> {
    query.validate()?;
    scan::query(publisher, query, cancel)
}
