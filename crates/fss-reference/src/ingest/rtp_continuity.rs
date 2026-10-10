#![forbid(unsafe_code)]
//! Recorded RTP continuity driven truthfully through [`fss_core::AcquisitionSession`]
//! (fss-2h5zq.29).
//!
//! Input is a fully re-read recorded-RTP import ([`VerifiedRtpImport`] plus its
//! [`RtpFileImportReceipt`]): the same report and source-linked NALs the rtpdump pipeline
//! published, so every claim below rests on retained custody and the real packet kernels
//! (`fss_packet::SequenceTracker`, `JitterEstimator`, `H264Depacketizer`) and the first-party
//! H.264 decoder. Every transition goes through the core session API; this module never
//! re-implements the transition table or a witness `verify()`.
//!
//! # Per stream generation
//!
//! `Requested → Authenticated → AdapterAccepted`, then:
//!
//! * **First frame.** The generation's reconstructed NALs feed a fresh `fss_codec_h264` decoder
//!   until it outputs its first picture. That is a real `Verified` decode, so the core
//!   [`FirstFrameWitness`] is honest; its sequence number is the extended RTP sequence of the first
//!   packet carrying that picture's slice data. A generation that never decodes a picture (for
//!   example the synthetic, non-decodable fixture family) degrades with
//!   `first_frame_not_verified` and never reaches `ContinuityVerified`.
//! * **Windows.** From the first frame's sequence onward, the extended sequence space is cut into
//!   windows of [`RtpContinuityPolicy::window_packets`] positions. A window whose every position
//!   arrived in time, with no discontinuity, no media-reconstruction fault and jitter within the
//!   threshold, becomes a [`ContinuityWitness`] (`discontinuities: 0`, `packet_loss: 0`) whose
//!   coverage names only this one source and is passed to `verify_continuity`. A fault with no
//!   sequence of its own (a refused or truncated record, a suspected discontinuity, a reversed
//!   offset on an unsequenced record) is charged by its recorder arrival: to every window whose
//!   interval contains that arrival (both windows at a shared boundary), to the pre-first-frame
//!   span when it arrives no later than the first frame's first packet, and to the last window
//!   when it arrives after it (no window of its own covers the generation's tail). Anything else
//!   becomes [`DegradationEvidence`] naming the lost dimensions and invalidating absence over the
//!   window's interval. A [`WindowedDegradationEvidence`] binds it to the exact acquisition
//!   request, predecessor witness, and degraded sequence span before `degrade_window` admits it.
//!   A later clean window can then recover continuity in the same generation only when it
//!   immediately follows the accounted span. The skipped span remains degraded evidence, never
//!   continuous coverage. Every window retains its exact wrapper for replay; a genuine core
//!   refusal is still [`RtpWindowOutcome::CleanNotVerified`], never overridden.
//! * **Restart.** An SSRC change or `RestartRequired` opens a new stream generation in the
//!   replay; here it is `reconnect` with a strictly newer [`StreamGeneration`]. The capsule of the
//!   first NAL after it carries `gap_before = true` (set by the importer).
//!
//! The session ends `Cancelled` with a drained [`QuiescenceReceipt`] at the end of the recording
//! (the core has no "end of source" kind), after degrading for a framing-refused suffix.
//!
//! # Packets are counted, not pictures
//!
//! The core witness field `frames_observed` must equal `window_end_seq - window_start_seq + 1`;
//! here it counts the RTP sequence positions observed in the window. It is not a decoded-picture
//! count: only the first picture of each generation is decoded. Recovery of packet and NAL
//! continuity after a gap does not establish decoding of later reference-dependent pictures.
//!
//! # Media reconstruction
//!
//! The depacketizer ignores non-increasing input, so a packet that arrives reordered (even within
//! the transport tolerance) is delivered but its media is not reconstructed. Such a window has
//! `packet_loss = 0` yet degrades with `media_reconstruction_gap`: transport continuity alone is
//! never presented as media continuity.
//!
//! # Absence
//!
//! The core coverage witness carries no interval, so a witness that certified absence on its own
//! would certify it over all time. A verified window's coverage witness is therefore
//! `Continuous`/`Complete` (the core requires both to verify continuity) but stops with
//! [`CoverageStopReason::Unsupported`]: absence over capture time is not supported from a
//! recorder's estimated clock. `certifies_absence()` is false for every witness this module
//! mints, so registering one in an event store never yields absence on its own.
//!
//! The interval binding lives here:
//! [`RtpContinuityReport::absence_over`] refuses any query that touches a degraded window, an
//! unverified window, the pre-first-frame span or a generation boundary, and evaluates every
//! overlapping window (never the first match only). A query inside one run of verified windows
//! is then handed to the shared stored-witness rule ([`build_source_coverage`], and
//! [`crate::ingest::source_coverage::verify_retained_coverage`] after retention): recorded-RTP
//! capsules carry an `estimated` clock (recorder offsets are not capture time), so that rule
//! refuses them. Recorded continuity therefore never certifies absence on its own.
//!
//! **No-Claim.** A verified window means the recorded packets of this one stream were contiguous,
//! timely by the recorder's offsets and reconstructable. It is not live-network RTSP continuity,
//! capture-time truth or site-wide coverage. A windowed degradation accounts for a sequence span;
//! it establishes no clock bridge across that span. Recovery leaves these absence limits intact.
//!
//! # Residuals (fss-iui8a)
//!
//! * **Spliced streams are adopted (RFC 3550).** A foreign SSRC whose first two packets are
//!   consecutive on the bound payload type passes the replay's validation and opens a new
//!   generation under the same device and source id, exactly as a legitimate SSRC change does.
//!   A complete foreign stream spliced into a recording therefore becomes its own
//!   `ContinuityVerified` generation, and two forged packets of a fresh SSRC force a restart away
//!   from the bound stream and back (two restarts, lost decode of the pictures between). Both
//!   fail closed: every generation boundary is outside any one run, so no absence query spans it,
//!   and recorded continuity certifies no absence on its own (see Absence). The recording carries
//!   no authentication that could tell the splice from a real SSRC change. Packets on another
//!   payload type (an interleaved audio stream) never open a generation.
//! * **Unsequenced faults are charged at millisecond resolution.** Recorder offsets are whole
//!   milliseconds, so an unsequenced fault (a stray or refused record) in the same millisecond as
//!   the first picture's first packet counts as arriving no later than it, even when it was
//!   recorded after it, and blocks the generation's first frame. This errs toward refusing
//!   coverage, never toward certifying it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_codec_h264::{Decoder, DecoderLimits};
use fss_core::identity::{
    AdapterCapabilities, CredentialMethod, DeviceCapabilities, DeviceClass, DeviceIdentity,
    MediaKind, SourceIdentity, SourceKind,
};
use fss_core::{
    AcquisitionError, AcquisitionRequest, AcquisitionSession, AcquisitionStateKind, AdapterAck,
    AuthReceipt, CaptureInterval, ClockBasis, Completeness, ContentDigest, ContinuityWitness,
    ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness, DecodeState,
    DegradationEvidence, DeviceGeneration, DeviceId, ExplicitOmission, FirmwareGeneration,
    FirstFrameWitness, LedgerAnchor, MAX_HISTORY_LEN, QuiescenceReceipt, SensorCapsule,
    SourceCustody, SourceId, StreamGeneration, TimestampNs, WindowedDegradationEvidence,
};
use fss_packet::{H264Status, JitterEstimator, SequenceClass, arrival_ticks};

use crate::ReplayCx;
use crate::ingest::file_adapter::default_adapter_identity;
use crate::ingest::rtpdump::RtpDumpKind;
use crate::ingest::rtpdump::import::{
    ImportEnd, RecordDisposition, RecordReport, RtpFileImportReceipt, VerifiedRtpImport,
};
use crate::ingest::rtpdump::replay::RestartCause;
use crate::ingest::source_coverage::{
    SourceCoverageInput, SourceCoverageRecord, build_source_coverage,
};

/// Lost dimension: sequence positions of the window never arrived (or arrived too late).
pub const LOST_PACKET_LOSS: &str = "packet_loss";
/// Lost dimension: a packet arrived later than the reorder tolerance.
pub const LOST_LATE_PACKET: &str = "late_packet_beyond_reorder_tolerance";
/// Lost dimension: the sequence kernel suspected a discontinuity.
pub const LOST_SEQUENCE_DISCONTINUITY: &str = "sequence_discontinuity";
/// Lost dimension: the depacketizer could not reconstruct delivered media.
pub const LOST_MEDIA_RECONSTRUCTION: &str = "media_reconstruction_gap";
/// Lost dimension: an RTP record could not be parsed, was truncated, or was refused.
pub const LOST_PACKET_REFUSED: &str = "packet_refused";
/// Lost dimension: observed interarrival jitter exceeded the threshold.
pub const LOST_TIMING_JITTER: &str = "timing_jitter";
/// Lost dimension: arrival timing could not be evaluated (reversed offsets, ambiguous clock).
pub const LOST_TIMING_UNUSABLE: &str = "timing_clock_unusable";
/// Lost dimension: the generation never produced a verified decoded picture.
pub const LOST_FIRST_FRAME_NOT_VERIFIED: &str = "first_frame_not_verified";
/// Lost dimension: the recording's suffix could not be framed.
pub const LOST_FRAMING_REFUSED: &str = "recording_framing_refused";
/// The negative claim every degradation invalidates.
pub const INVALIDATED_ABSENCE: &str = "absence";

/// Largest window, in sequence positions.
pub const MAX_WINDOW_PACKETS: u64 = 65_536;
/// Largest reorder tolerance (the sequence kernel retains 128 positions).
pub const MAX_REORDER_TOLERANCE: u64 = 127;
/// Most transitions one run may record: the core keeps at most [`MAX_HISTORY_LEN`] records and
/// would silently drop the oldest beyond it, so a run that needs more is refused up front.
const MAX_TRANSITIONS: usize = MAX_HISTORY_LEN;

/// Owner policy of a continuity run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpContinuityPolicy {
    /// Sequence positions per window (2..=[`MAX_WINDOW_PACKETS`]).
    pub window_packets: u64,
    /// How far behind the highest sequence a reordered packet may arrive and still count as
    /// delivered in time (0..=[`MAX_REORDER_TOLERANCE`]).
    pub reorder_tolerance_packets: u64,
    /// Negotiated RTP clock rate of the payload (90 kHz for H.264 video).
    pub clock_rate: u32,
    /// Largest admissible RFC 3550 interarrival jitter within a verified window.
    pub max_jitter_threshold_ns: u64,
    /// Bounds of the first-picture decode of each generation.
    pub decoder: DecoderLimits,
}

impl Default for RtpContinuityPolicy {
    fn default() -> Self {
        Self {
            window_packets: 64,
            reorder_tolerance_packets: 8,
            clock_rate: 90_000,
            max_jitter_threshold_ns: 20_000_000,
            decoder: DecoderLimits {
                max_pictures: 16,
                ..DecoderLimits::default()
            },
        }
    }
}

impl RtpContinuityPolicy {
    fn validate(&self) -> Result<(), RtpContinuityError> {
        if !(2..=MAX_WINDOW_PACKETS).contains(&self.window_packets)
            || self.reorder_tolerance_packets > MAX_REORDER_TOLERANCE
            || self.clock_rate == 0
            || self.clock_rate > 1_000_000_000
            || Decoder::new(self.decoder).is_err()
        {
            return Err(RtpContinuityError::Policy);
        }
        Ok(())
    }
}

/// Owner-declared identities of the recorded stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpContinuityScope {
    /// Evidence source the witnesses name (the only member of every coverage domain here).
    pub source_id: SourceId,
    /// Device the source belongs to.
    pub device_id: DeviceId,
    /// Failure domain of the source, used by the shared stored-witness rule.
    pub failure_domain: String,
    /// Owner-declared instant of recorder offset zero. Offsets are a laboratory timer, never
    /// capture time; intervals here are `recording_origin + offset`.
    pub recording_origin: TimestampNs,
    /// Authority anchor the coverage witnesses are read at.
    pub basis: LedgerAnchor,
    /// Negative predicate the coverage witnesses state.
    pub negative_predicate: String,
}

/// Refusal of a continuity run. A refused run claims nothing.
#[derive(Debug)]
pub enum RtpContinuityError {
    /// The policy or scope is invalid.
    Policy,
    /// The verified import and its receipt do not describe the same publication.
    Binding,
    /// The run would exceed a bound (windows, generations or the core history).
    Limit,
    /// Cooperative cancellation at the named stage.
    Cancelled {
        /// Stage where cancellation was observed.
        stage: &'static str,
    },
    /// The core refused a transition this module requires (request, auth, accept, reconnect,
    /// first frame or the concluding cancel).
    Acquisition(AcquisitionError),
    /// A contract value was refused.
    Contract(ContractError),
}

impl fmt::Display for RtpContinuityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy => f.write_str("recorded RTP continuity: invalid policy or scope"),
            Self::Binding => {
                f.write_str("recorded RTP continuity: verified import does not match its receipt")
            }
            Self::Limit => f.write_str("recorded RTP continuity: a run bound was exceeded"),
            Self::Cancelled { stage } => {
                write!(f, "recorded RTP continuity: cancelled at {stage}")
            }
            Self::Acquisition(error) => write!(f, "recorded RTP continuity: {error}"),
            Self::Contract(error) => write!(f, "recorded RTP continuity: {error}"),
        }
    }
}

impl std::error::Error for RtpContinuityError {}

impl From<AcquisitionError> for RtpContinuityError {
    fn from(error: AcquisitionError) -> Self {
        Self::Acquisition(error)
    }
}

impl From<ContractError> for RtpContinuityError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// The verified first picture of one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpFirstPicture {
    /// Extended sequence of the first packet carrying the picture's slice data.
    pub sequence: u64,
    /// Extended sequence of the packet whose NAL completed the picture.
    pub completed_at_sequence: u64,
    /// SHA-256 of the decoded picture's packed I420 planes.
    pub i420_sha256: [u8; 32],
    /// Decoded (cropped) width and height.
    pub dimensions: (u32, u32),
    /// The core witness passed to `observe_first_frame`.
    pub witness: FirstFrameWitness,
}

/// What became of one stream generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpGenerationOutcome {
    /// Owner epoch number (the replay's stream key generation).
    pub generation: u64,
    /// Core stream generation identity of the generation's acquisition request.
    pub stream_generation: StreamGeneration,
    /// SSRC bound to the generation.
    pub ssrc: u32,
    /// Why the generation was opened, `None` for the owner-bound first one.
    pub cause: Option<RestartCause>,
    /// Recorder-offset interval of every record of the generation.
    pub interval: CaptureInterval,
    /// The authentication receipt the core accepted for the generation. A recorded file has no
    /// credential (`CredentialMethod::None`); the receipt binds the import digest and is valid
    /// from the generation's first arrival through the end of the recording's last recorder
    /// millisecond, never expiring at the instant it is issued.
    pub auth: AuthReceipt,
    /// The verified first picture, when one decoded.
    pub first_picture: Option<RtpFirstPicture>,
    /// Lost dimensions that kept the generation from reaching a first frame (empty when it did).
    pub pre_first_frame_lost: Vec<String>,
}

/// How the core judged one window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtpWindowOutcome {
    /// `verify_continuity` accepted the witness.
    Verified {
        /// The core witness.
        witness: Box<ContinuityWitness>,
    },
    /// `degrade_window` accepted the evidence; the window is a gap for absence.
    Degraded {
        /// The core evidence.
        evidence: Box<DegradationEvidence>,
    },
    /// The window was clean, but the core refused to verify it (for example after a sequence
    /// gap). It certifies nothing.
    CleanNotVerified {
        /// The core refusal.
        refusal: String,
    },
    /// A clean final window of one position: the core requires at least two.
    TooShort,
}

impl RtpWindowOutcome {
    /// Stable label of the outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Degraded { .. } => "degraded",
            Self::CleanNotVerified { .. } => "clean_not_verified",
            Self::TooShort => "too_short",
        }
    }
}

/// One judged window of one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpContinuityWindow {
    /// Owner epoch number of the generation.
    pub generation: u64,
    /// First extended sequence position of the window.
    pub start_seq: u64,
    /// Last extended sequence position of the window.
    pub end_seq: u64,
    /// Recorder-offset interval: from the previous window's last arrival (or the first frame's
    /// first packet) to this window's last arrival, so windows tile the generation without slivers.
    pub interval: CaptureInterval,
    /// RTP media-time span of the window's packets (ns since the generation's first timestamp),
    /// `None` when no position of the window carries a media timestamp (nothing arrived).
    pub pts: Option<(TimestampNs, TimestampNs)>,
    /// Positions that arrived in time.
    pub packets_observed: u64,
    /// Positions that never arrived in time.
    pub missing_positions: u64,
    /// Suspected sequence discontinuities attributed to the window.
    pub discontinuities: u32,
    /// Largest RFC 3550 interarrival jitter over the window.
    pub observed_jitter_ns: u64,
    /// Lost dimensions (empty for a clean window), sorted.
    pub lost_dimensions: Vec<String>,
    /// Coverage witness of this window over this one source: continuous and complete when
    /// verified, gapped (or unknown) otherwise. It never certifies absence on its own (see the
    /// module documentation on absence).
    pub coverage: CoverageWitness,
    /// The core's judgment.
    pub outcome: RtpWindowOutcome,
    /// Exact request-, predecessor-, and sequence-bound degradation admitted by the core.
    /// Present only for a degraded sequence window. The embedded legacy degradation is the
    /// same evidence carried by `outcome`; neither recovery nor a later clean window removes it.
    pub windowed_degradation: Option<Box<WindowedDegradationEvidence>>,
    capsules: Vec<usize>,
}

/// Why an absence query is not certified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtpAbsenceRefusal {
    /// The query interval is not inside one run of verified windows of one generation
    /// (pre-first-frame span, generation boundary, or outside the recording).
    OutsideVerifiedCoverage,
    /// The query overlaps degraded windows: gaps. Every overlapping gap is listed.
    GapOverlaps {
        /// `(generation, start_seq, end_seq, interval)` of each overlapping degraded window.
        gaps: Vec<(u64, u64, u64, CaptureInterval)>,
    },
    /// The query overlaps windows the core did not verify (no gap evidence, no certification).
    NotVerified {
        /// `(generation, start_seq, end_seq, outcome)` of each such window.
        windows: Vec<(u64, u64, u64, &'static str)>,
    },
    /// The query overlaps a generation that never reached a first frame.
    GenerationUnverified {
        /// Owner epoch numbers of those generations.
        generations: Vec<u64>,
    },
    /// Continuity was verified over the query, but the shared stored-witness rule refused to
    /// build a coverage record from the window's capsules.
    StoredWitnessRule(ContractError),
}

/// Answer of [`RtpContinuityReport::absence_over`]. There is no "certified" answer here:
/// certification belongs to the shared stored-witness rule after retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtpAbsenceAnswer {
    /// Absence is not certified, for the stated reason.
    NotCertified(RtpAbsenceRefusal),
    /// The stored-witness rule built this record; it certifies only once retained
    /// (`retain_source_coverage`) and accepted by `verify_retained_coverage`.
    RequiresRetention(Box<SourceCoverageRecord>),
}

/// Result of a continuity run over one recorded RTP import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpContinuityReport {
    session: AcquisitionSession,
    generations: Vec<RtpGenerationOutcome>,
    windows: Vec<RtpContinuityWindow>,
    capsules: Vec<SensorCapsule>,
    scope: RtpContinuityScope,
}

impl RtpContinuityReport {
    /// The concluded core session (its history holds every transition).
    #[must_use]
    pub const fn session(&self) -> &AcquisitionSession {
        &self.session
    }

    /// State kinds entered, oldest first.
    #[must_use]
    pub fn kinds(&self) -> Vec<AcquisitionStateKind> {
        self.session.history().iter().map(|r| r.to).collect()
    }

    /// Every generation, oldest first.
    #[must_use]
    pub fn generations(&self) -> &[RtpGenerationOutcome] {
        &self.generations
    }

    /// Every judged window, in generation then sequence order.
    #[must_use]
    pub fn windows(&self) -> &[RtpContinuityWindow] {
        &self.windows
    }

    /// The import capsules a window's packets carry (recorded access units whose NAL source
    /// records all lie in the window).
    pub fn window_capsules<'a>(
        &'a self,
        window: &'a RtpContinuityWindow,
    ) -> impl Iterator<Item = &'a SensorCapsule> + 'a {
        window
            .capsules
            .iter()
            .filter_map(|index| self.capsules.get(*index))
    }

    /// Answers whether absence over `query` (recorder-offset clock) could be certified. Every
    /// overlapping window and generation is evaluated; any gap, unverified window, unverified
    /// generation or boundary refuses, whatever its position among the overlaps.
    #[must_use]
    pub fn absence_over(&self, query: CaptureInterval) -> RtpAbsenceAnswer {
        let overlaps =
            |i: &CaptureInterval| i.earliest <= query.latest && i.latest >= query.earliest;
        let unverified: Vec<u64> = self
            .generations
            .iter()
            .filter(|g| g.first_picture.is_none() && overlaps(&g.interval))
            .map(|g| g.generation)
            .collect();
        let hit: Vec<&RtpContinuityWindow> = self
            .windows
            .iter()
            .filter(|w| overlaps(&w.interval))
            .collect();
        let gaps: Vec<(u64, u64, u64, CaptureInterval)> = hit
            .iter()
            .filter(|w| matches!(w.outcome, RtpWindowOutcome::Degraded { .. }))
            .map(|w| (w.generation, w.start_seq, w.end_seq, w.interval))
            .collect();
        if !gaps.is_empty() {
            return RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { gaps });
        }
        if !unverified.is_empty() {
            return RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GenerationUnverified {
                generations: unverified,
            });
        }
        let not_verified: Vec<(u64, u64, u64, &'static str)> = hit
            .iter()
            .filter(|w| !matches!(w.outcome, RtpWindowOutcome::Verified { .. }))
            .map(|w| (w.generation, w.start_seq, w.end_seq, w.outcome.as_str()))
            .collect();
        if !not_verified.is_empty() {
            return RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::NotVerified {
                windows: not_verified,
            });
        }
        let (Some(first), Some(last)) = (hit.first(), hit.last()) else {
            return RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage);
        };
        let one_run = hit.windows(2).all(|pair| {
            pair[0].generation == pair[1].generation
                && pair[0].end_seq.checked_add(1) == Some(pair[1].start_seq)
        });
        if !one_run
            || query.earliest < first.interval.earliest
            || query.latest > last.interval.latest
        {
            return RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage);
        }
        let sources: Vec<(String, &SensorCapsule)> = hit
            .iter()
            .flat_map(|w| self.window_capsules(w))
            .map(|capsule| (self.scope.failure_domain.clone(), capsule))
            .collect();
        let input = SourceCoverageInput {
            basis: self.scope.basis.clone(),
            interval: query,
            negative_predicate: &self.scope.negative_predicate,
            authorized_domain: BTreeSet::from([self.scope.failure_domain.clone()]),
            sources,
        };
        match build_source_coverage(&input) {
            Ok(record) => RtpAbsenceAnswer::RequiresRetention(Box::new(record)),
            Err(error) => {
                RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::StoredWitnessRule(error))
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 1: per-generation facts from the verified import report.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Position {
    arrival_ns: u64,
    /// Unwrapped media time; `None` when the packet carried no usable RTP timestamp.
    pts_ticks: Option<i64>,
    jitter_ticks: u32,
    timely: bool,
}

/// Where a fault is charged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultAt {
    /// The extended sequence of the faulty packet itself.
    Sequence(u64),
    /// Recorder arrival (ns since offset zero) of a fault with no sequence of its own.
    Arrival(u64),
}

#[derive(Clone, Copy, Debug)]
struct Fault {
    at: FaultAt,
    dimension: &'static str,
}

#[derive(Debug)]
struct GenerationFacts {
    generation: u64,
    ssrc: u32,
    cause: Option<RestartCause>,
    first_arrival: u64,
    last_arrival: u64,
    positions: BTreeMap<u64, Position>,
    faults: Vec<Fault>,
    baseline: Option<u64>,
    highest: Option<u64>,
    jitter: JitterEstimator,
    last_timestamp: Option<(u32, i64)>,
    first_pts: Option<i64>,
}

impl GenerationFacts {
    fn new(record: &RecordReport, cause: Option<RestartCause>, arrival: u64) -> Self {
        Self {
            generation: record.generation,
            ssrc: record.ssrc,
            cause,
            first_arrival: arrival,
            last_arrival: arrival,
            positions: BTreeMap::new(),
            faults: Vec::new(),
            baseline: None,
            highest: None,
            jitter: JitterEstimator::default(),
            last_timestamp: None,
            first_pts: None,
        }
    }

    fn fault(&mut self, at: FaultAt, dimension: &'static str) {
        self.faults.push(Fault { at, dimension });
    }

    /// Unwrapped media time of `timestamp`, in clock ticks since the generation's first one.
    fn pts(&mut self, timestamp: u32) -> i64 {
        let extended = match self.last_timestamp {
            None => 0,
            Some((last, extended)) => {
                extended.saturating_add(i64::from(timestamp.wrapping_sub(last) as i32))
            }
        };
        self.last_timestamp = Some((timestamp, extended));
        let first = *self.first_pts.get_or_insert(extended);
        extended.saturating_sub(first)
    }
}

fn collect_facts(
    report: &crate::ingest::rtpdump::import::RtpImportReport,
    policy: &RtpContinuityPolicy,
) -> Result<Vec<GenerationFacts>, RtpContinuityError> {
    let mut generations: Vec<GenerationFacts> = Vec::new();
    let mut clock_ms: u64 = 0;
    for record in report.records() {
        clock_ms = clock_ms.max(u64::from(record.offset_ms));
        let arrival = clock_ms.saturating_mul(1_000_000);
        let opens = record.restart.is_some()
            || generations
                .last()
                .is_none_or(|g| g.generation != record.generation);
        if opens {
            if let (Some(previous), Some(_)) = (generations.last_mut(), record.discarded.as_ref()) {
                // The restart retired the old generation's pending fragment, whose last packet is
                // the old generation's highest position.
                let at = previous
                    .highest
                    .map_or(FaultAt::Arrival(previous.last_arrival), FaultAt::Sequence);
                previous.fault(at, LOST_MEDIA_RECONSTRUCTION);
            }
            if generations.len() > crate::ingest::rtpdump::replay::MAX_STREAM_RESTARTS as usize {
                return Err(RtpContinuityError::Limit);
            }
            generations.push(GenerationFacts::new(record, record.restart, arrival));
        }
        let Some(facts) = generations.last_mut() else {
            return Err(RtpContinuityError::Binding);
        };
        facts.last_arrival = facts.last_arrival.max(arrival);
        // A reversed recorder offset is charged to the record's own sequence when it has one,
        // else by arrival.
        let reversed_at = record
            .sequence
            .and_then(|o| o.extended_sequence)
            .map_or(FaultAt::Arrival(arrival), FaultAt::Sequence);
        if record.offset_reversed {
            facts.fault(reversed_at, LOST_TIMING_UNUSABLE);
        }
        // Faults below carry no sequence of their own: they are charged by arrival.
        let unsequenced = FaultAt::Arrival(arrival);
        match record.kind {
            RtpDumpKind::Rtcp => continue,
            RtpDumpKind::CapturedPrefix => {
                facts.fault(unsequenced, LOST_PACKET_REFUSED);
                continue;
            }
            RtpDumpKind::Rtp => {}
        }
        let observation = match (record.disposition, record.sequence) {
            (RecordDisposition::PacketRefused(_) | RecordDisposition::StreamRefused(_), _)
            | (_, None) => {
                facts.fault(unsequenced, LOST_PACKET_REFUSED);
                continue;
            }
            (_, Some(observation)) => observation,
        };
        let Some(sequence) = observation.extended_sequence else {
            match observation.class {
                // Normal epoch establishment and stale pre-baseline input: outside coverage.
                SequenceClass::Probation | SequenceClass::BeforeBaseline => {}
                _ => facts.fault(unsequenced, LOST_SEQUENCE_DISCONTINUITY),
            }
            continue;
        };
        let pts = record.timestamp.map(|t| facts.pts(t));
        let jitter = match record.timestamp {
            Some(timestamp) => match arrival_ticks(arrival, policy.clock_rate)
                .and_then(|ticks| facts.jitter.observe(ticks, timestamp))
            {
                Ok(value) => Some(value),
                Err(_) => {
                    facts.fault(FaultAt::Sequence(sequence), LOST_TIMING_UNUSABLE);
                    None
                }
            },
            None => {
                facts.fault(FaultAt::Sequence(sequence), LOST_TIMING_UNUSABLE);
                None
            }
        };
        let highest_before = facts.highest;
        match observation.class {
            SequenceClass::Baseline | SequenceClass::Advanced | SequenceClass::Reordered => {
                let timely = match (observation.class, highest_before) {
                    (SequenceClass::Reordered, Some(highest)) => {
                        highest.saturating_sub(sequence) <= policy.reorder_tolerance_packets
                    }
                    _ => true,
                };
                if !timely {
                    facts.fault(FaultAt::Sequence(sequence), LOST_LATE_PACKET);
                }
                if observation.class == SequenceClass::Baseline {
                    facts.baseline = Some(sequence);
                }
                if facts.positions.len() >= report.records().len() {
                    return Err(RtpContinuityError::Limit);
                }
                facts.positions.insert(
                    sequence,
                    Position {
                        arrival_ns: arrival,
                        pts_ticks: pts,
                        // A jitter that could not be evaluated is already a timing fault above.
                        jitter_ticks: jitter.unwrap_or(0),
                        timely,
                    },
                );
                facts.highest = Some(highest_before.map_or(sequence, |h| h.max(sequence)));
            }
            SequenceClass::Duplicate => {
                if let (Some(position), Some(value)) = (facts.positions.get_mut(&sequence), jitter)
                {
                    position.jitter_ticks = position.jitter_ticks.max(value);
                }
            }
            _ => {
                facts.fault(FaultAt::Sequence(sequence), LOST_SEQUENCE_DISCONTINUITY);
            }
        }
        let after_baseline = facts.baseline.is_some_and(|b| sequence > b);
        let media_fault = match record.disposition {
            RecordDisposition::CodecRefused(_) => true,
            RecordDisposition::H264(H264Status::IgnoredNonIncreasing) => true,
            RecordDisposition::H264(_) => record.gap_before && after_baseline,
            _ => false,
        } || record.expired.is_some()
            || (record.discarded.is_some() && record.restart.is_none());
        if media_fault {
            facts.fault(FaultAt::Sequence(sequence), LOST_MEDIA_RECONSTRUCTION);
        }
    }
    Ok(generations)
}

// ---------------------------------------------------------------------------------------------
// First picture per generation.
// ---------------------------------------------------------------------------------------------

struct DecodedFirst {
    sequence: u64,
    completed_at: u64,
    completed_arrival: u64,
    vcl_bytes: u64,
    i420_sha256: [u8; 32],
    dimensions: (u32, u32),
}

/// Feeds the generation's complete NALs, in reconstruction order, to a fresh decoder until it
/// outputs a picture. A decode error resets the decoder (no picture predicts across it).
/// Returns the picture and whether any decode was refused before it.
fn decode_first_picture(
    import: &VerifiedRtpImport,
    generation: u64,
    policy: &RtpContinuityPolicy,
    cx: &ReplayCx,
) -> Result<(Option<DecodedFirst>, bool), RtpContinuityError> {
    let records = import.report().records();
    let mut decoder = Decoder::new(policy.decoder).map_err(|_| RtpContinuityError::Policy)?;
    let mut first_vcl: Option<u64> = None;
    let mut vcl_bytes: u64 = 0;
    let mut refused = false;
    let mut last_fed: Option<(u64, usize)> = None;
    for (nal, replayed) in import.report().nals().iter().zip(import.nals()) {
        let (Some(first_span), Some(last_span)) = (nal.spans.first(), nal.spans.last()) else {
            return Err(RtpContinuityError::Binding);
        };
        let (Some(first_record), Some(last_record)) = (
            records.get(first_span.record),
            records.get(last_span.record),
        ) else {
            return Err(RtpContinuityError::Binding);
        };
        if first_record.generation != generation {
            continue;
        }
        cx.checkpoint("rtp_continuity:decode")
            .map_err(|_| RtpContinuityError::Cancelled {
                stage: "rtp_continuity:decode",
            })?;
        let bytes = replayed.nal.bytes();
        let is_vcl = bytes.first().is_some_and(|h| matches!(h & 31, 1 | 5));
        let first_sequence = first_record
            .sequence
            .and_then(|o| o.extended_sequence)
            .ok_or(RtpContinuityError::Binding)?;
        let last_sequence = last_record
            .sequence
            .and_then(|o| o.extended_sequence)
            .ok_or(RtpContinuityError::Binding)?;
        if is_vcl {
            first_vcl.get_or_insert(first_sequence);
            vcl_bytes = vcl_bytes.saturating_add(bytes.len() as u64);
        }
        last_fed = Some((last_sequence, last_span.record));
        match decoder.decode_nal(bytes) {
            Ok(Some(picture)) => {
                return first_of(
                    records,
                    &picture,
                    first_vcl,
                    vcl_bytes,
                    last_sequence,
                    last_span.record,
                )
                .map(|first| (Some(first), refused));
            }
            Ok(None) => {}
            Err(_) => {
                refused = true;
                decoder = Decoder::new(policy.decoder).map_err(|_| RtpContinuityError::Policy)?;
                first_vcl = None;
                vcl_bytes = 0;
            }
        }
    }
    // End of the generation: a picture still held for output is released by `finish`; one
    // missing slices is discarded by the decoder and refused here.
    if let Some((last_sequence, last_record)) = last_fed {
        match decoder.finish() {
            Ok(pictures) => {
                if let Some(picture) = pictures.first() {
                    return first_of(
                        records,
                        picture,
                        first_vcl,
                        vcl_bytes,
                        last_sequence,
                        last_record,
                    )
                    .map(|first| (Some(first), refused));
                }
            }
            Err(_) => refused = true,
        }
    }
    Ok((None, refused))
}

fn first_of(
    records: &[RecordReport],
    picture: &fss_codec_h264::Picture,
    first_vcl: Option<u64>,
    vcl_bytes: u64,
    completed_at: u64,
    completed_record: usize,
) -> Result<DecodedFirst, RtpContinuityError> {
    let sequence = first_vcl.ok_or(RtpContinuityError::Binding)?;
    // The recorder clock at the completing record: the running maximum of offsets, as replayed.
    let completed_arrival = records
        .iter()
        .take(completed_record.saturating_add(1))
        .map(|r| u64::from(r.offset_ms))
        .max()
        .unwrap_or(0)
        .saturating_mul(1_000_000);
    Ok(DecodedFirst {
        sequence,
        completed_at,
        completed_arrival,
        vcl_bytes,
        i420_sha256: picture.i420_sha256(),
        dimensions: (picture.width(), picture.height()),
    })
}

// ---------------------------------------------------------------------------------------------
// Phase 2: drive the core session.
// ---------------------------------------------------------------------------------------------

struct Driver<'a> {
    session: Option<AcquisitionSession>,
    scope: &'a RtpContinuityScope,
}

impl Driver<'_> {
    fn at(&self, arrival_ns: u64) -> Result<TimestampNs, RtpContinuityError> {
        self.scope
            .recording_origin
            .0
            .checked_add(i128::from(arrival_ns))
            .map(TimestampNs)
            .ok_or(RtpContinuityError::Limit)
    }

    fn request(
        &self,
        facts: &GenerationFacts,
        at: TimestampNs,
    ) -> Result<AcquisitionRequest, RtpContinuityError> {
        let adapter_identity = default_adapter_identity()?;
        Ok(AcquisitionRequest {
            source_identity: SourceIdentity {
                source_id: self.scope.source_id.clone(),
                device_id: self.scope.device_id.clone(),
                adapter_id: adapter_identity.adapter_id.clone(),
                source_kind: SourceKind::ImportedArchive,
                media_kind: MediaKind::Video,
                channel: format!("rtp:ssrc:{:08x}", facts.ssrc),
                nominal_clock_basis: ClockBasis::Estimated,
                stream_generation: stream_generation(facts.generation)?,
                failure_domain: self.scope.failure_domain.clone(),
                is_live: false,
            },
            device_identity: DeviceIdentity {
                device_id: self.scope.device_id.clone(),
                generation: DeviceGeneration::parse("gen:device:recorded-rtp-v1")?,
                manufacturer: "fss".to_owned(),
                model: "recorded-rtp-import".to_owned(),
                hardware_revision: "not_applicable".to_owned(),
                firmware_version: FirmwareGeneration::parse("gen:firmware:not-applicable")?,
                application_version: None,
                model_generation: None,
                device_class: DeviceClass::VirtualDevice,
                capabilities: DeviceCapabilities::NONE,
                failure_domain: self.scope.failure_domain.clone(),
            },
            adapter_identity,
            // A recorded replay requests no live or device capability.
            requested_capabilities: AdapterCapabilities::NONE,
            requested_at_ns: at,
        })
    }

    fn session(&mut self) -> Result<&mut AcquisitionSession, RtpContinuityError> {
        self.session.as_mut().ok_or(RtpContinuityError::Binding)
    }

    /// `Requested` (new, or `reconnect` with the newer generation) → `Authenticated` →
    /// `AdapterAccepted`.
    fn open(
        &mut self,
        facts: &GenerationFacts,
        import_digest: ContentDigest,
        expires_at: TimestampNs,
    ) -> Result<AuthReceipt, RtpContinuityError> {
        let at = self.at(facts.first_arrival)?;
        if expires_at <= at {
            return Err(RtpContinuityError::Limit);
        }
        let request = self.request(facts, at)?;
        match self.session.as_mut() {
            None => self.session = Some(AcquisitionSession::new(request.clone())?),
            Some(session) => session.reconnect(request.clone(), at)?,
        }
        let auth = AuthReceipt {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            method: CredentialMethod::None,
            // A recorded file has no credential principal; the receipt binds the import.
            principal_digest: import_digest,
            authorized_capabilities: request.requested_capabilities,
            authorized_at_ns: at,
            expires_at_ns: expires_at,
        };
        let ack = AdapterAck {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            request_digest: request.request_digest(),
            ack_timestamp_ns: at,
            session_handle: format!("rtp-g{}", facts.generation),
            allocated_buffer_frames: 0,
        };
        let session = self.session()?;
        session.authenticate(auth.clone(), at)?;
        session.accept(ack, at)?;
        Ok(auth)
    }

    fn evidence(
        &mut self,
        lost: &[String],
        loss: u64,
        jitter_ns: u64,
        interval: CaptureInterval,
        at: TimestampNs,
    ) -> Result<DegradationEvidence, RtpContinuityError> {
        let request = self.session()?.request().clone();
        Ok(DegradationEvidence {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            degraded_at_ns: at,
            lost_dimensions: lost.to_vec(),
            invalidated_negative_claims: vec![
                INVALIDATED_ABSENCE.to_owned(),
                format!(
                    "absence_interval_ns:{}..{}",
                    interval.earliest.0, interval.latest.0
                ),
            ],
            observed_packet_loss: u32::try_from(loss).unwrap_or(u32::MAX),
            observed_jitter_ns: jitter_ns,
        })
    }
}

fn stream_generation(generation: u64) -> Result<StreamGeneration, ContractError> {
    // Zero-padded so the identifier's ordering is the numeric generation ordering.
    StreamGeneration::parse(format!("gen:stream:recorded-rtp-g{generation:020}"))
}

fn coverage(
    scope: &RtpContinuityScope,
    observed: bool,
    continuity: CoverageContinuity,
    completeness: Completeness,
    stop_reason: CoverageStopReason,
) -> CoverageWitness {
    let domain = BTreeSet::from([scope.source_id.as_str().to_owned()]);
    CoverageWitness {
        anchor: scope.basis.clone(),
        authorized_domain: domain.clone(),
        observed_domain: if observed { domain } else { BTreeSet::new() },
        excluded_domain: BTreeSet::new(),
        continuity,
        completeness,
        negative_predicate: scope.negative_predicate.clone(),
        stop_reason,
        authorized_generation: scope.basis.policy_epoch,
        observed_generation: scope.basis.policy_epoch,
    }
}

fn ticks_to_ns(ticks: i64, clock_rate: u32) -> i128 {
    i128::from(ticks) * 1_000_000_000 / i128::from(clock_rate)
}

fn sorted_dimensions(dimensions: impl IntoIterator<Item = &'static str>) -> Vec<String> {
    dimensions
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), RtpContinuityError> {
    cx.checkpoint(stage)
        .map_err(|_| RtpContinuityError::Cancelled { stage })
}

/// Drives the core acquisition session over one verified recorded-RTP import.
///
/// # Errors
/// [`RtpContinuityError`]: invalid policy or scope, a receipt that does not match the import,
/// an exceeded bound, cancellation, or a core refusal of a transition this module requires.
pub fn drive_rtp_continuity(
    receipt: &RtpFileImportReceipt,
    import: &VerifiedRtpImport,
    scope: &RtpContinuityScope,
    policy: RtpContinuityPolicy,
    cx: &ReplayCx,
) -> Result<RtpContinuityReport, RtpContinuityError> {
    checkpoint(cx, "rtp_continuity:start")?;
    policy.validate()?;
    if scope.failure_domain.is_empty() || scope.negative_predicate.is_empty() {
        return Err(RtpContinuityError::Policy);
    }
    let report = import.report();
    if report != receipt.report() || report.nals().len() != import.nals().len() {
        return Err(RtpContinuityError::Binding);
    }
    let facts = collect_facts(report, &policy)?;
    let mut driver = Driver {
        session: None,
        scope,
    };
    let custody = SourceCustody::Retained {
        source_digest: report.input_digest(),
        source_bytes: report.input_bytes() as u64,
        storage_handle: receipt.slot().as_str().to_owned(),
    };
    let records = report.records();
    let mut generations = Vec::with_capacity(facts.len());
    let mut windows: Vec<RtpContinuityWindow> = Vec::new();
    let mut transitions: usize = 2;
    let mut last_at = TimestampNs(scope.recording_origin.0);
    // Recorder offsets have millisecond resolution: a record at offset `t` ms may have arrived
    // anywhere in `[t, t + 1 ms)`. The replay authorization therefore runs through the end of the
    // last recorded millisecond, so it never expires at the instant it is issued.
    let recording_end = facts
        .iter()
        .map(|g| g.last_arrival)
        .max()
        .unwrap_or(0)
        .checked_add(1_000_000)
        .ok_or(RtpContinuityError::Limit)?;
    let expires_at = driver.at(recording_end)?;
    for generation in &facts {
        checkpoint(cx, "rtp_continuity:generation")?;
        transitions = transitions.saturating_add(4);
        if transitions > MAX_TRANSITIONS {
            return Err(RtpContinuityError::Limit);
        }
        let auth = driver.open(generation, report.input_digest(), expires_at)?;
        let interval = CaptureInterval::new(
            driver.at(generation.first_arrival)?,
            driver.at(generation.last_arrival)?,
        )?;
        last_at = last_at.max(interval.latest);
        let (decoded, decode_refused) =
            decode_first_picture(import, generation.generation, &policy, cx)?;
        // Faults before the first frame's sequence (or with no sequence anchor) and lost
        // positions between the baseline and the first frame keep the generation from a first
        // frame: the core admits no first frame after a degradation.
        let mut pre_lost: Vec<&'static str> = Vec::new();
        let first = match decoded {
            None => {
                pre_lost.push(LOST_FIRST_FRAME_NOT_VERIFIED);
                if decode_refused {
                    pre_lost.push(LOST_MEDIA_RECONSTRUCTION);
                }
                None
            }
            Some(first) => {
                // The first picture's first packet is a position (it was delivered to the
                // depacketizer); its arrival bounds the pre-first-frame span.
                let first_position = generation.positions.get(&first.sequence);
                let first_arrival =
                    first_position.map_or(first.completed_arrival, |p| p.arrival_ns);
                for fault in &generation.faults {
                    let before = match fault.at {
                        FaultAt::Sequence(at) => at < first.sequence,
                        FaultAt::Arrival(at) => at <= first_arrival,
                    };
                    if before {
                        pre_lost.push(fault.dimension);
                    }
                }
                // The first frame's media time must be known: never a silent zero.
                if first_position.and_then(|p| p.pts_ticks).is_none() {
                    pre_lost.push(LOST_TIMING_UNUSABLE);
                }
                if let Some(baseline) = generation.baseline {
                    let missing = (baseline..first.sequence)
                        .any(|seq| generation.positions.get(&seq).is_none_or(|p| !p.timely));
                    if missing {
                        pre_lost.push(LOST_PACKET_LOSS);
                    }
                }
                if pre_lost.is_empty() {
                    Some(first)
                } else {
                    pre_lost.push(LOST_FIRST_FRAME_NOT_VERIFIED);
                    None
                }
            }
        };
        let Some(first) = first else {
            let lost = sorted_dimensions(pre_lost);
            let at = interval.latest;
            let evidence = driver.evidence(&lost, 0, 0, interval, at)?;
            driver.session()?.degrade(evidence, at)?;
            generations.push(RtpGenerationOutcome {
                generation: generation.generation,
                stream_generation: stream_generation(generation.generation)?,
                ssrc: generation.ssrc,
                cause: generation.cause,
                interval,
                auth,
                first_picture: None,
                pre_first_frame_lost: lost,
            });
            continue;
        };
        let request = driver.session()?.request().clone();
        let first_position = generation
            .positions
            .get(&first.sequence)
            .ok_or(RtpContinuityError::Binding)?;
        // Checked above: a first frame without a known media time never reaches here.
        let first_pts = first_position
            .pts_ticks
            .ok_or(RtpContinuityError::Binding)?;
        let witness = FirstFrameWitness {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            sequence_number: first.sequence,
            pts_ns: TimestampNs(ticks_to_ns(first_pts, policy.clock_rate)),
            frame_bytes: first.vcl_bytes,
            decode_state: DecodeState::Verified,
            source_custody: custody.clone(),
            explicit_omission: ExplicitOmission::None,
        };
        let first_at = driver.at(first.completed_arrival)?;
        driver
            .session()?
            .observe_first_frame(witness.clone(), first_at)?;
        let mut window_start_arrival = first_position.arrival_ns;
        let highest = generation.highest.unwrap_or(first.sequence);
        let mut start = first.sequence;
        while start <= highest {
            checkpoint(cx, "rtp_continuity:window")?;
            transitions = transitions.saturating_add(1);
            if transitions > MAX_TRANSITIONS {
                return Err(RtpContinuityError::Limit);
            }
            let end = start.saturating_add(policy.window_packets - 1).min(highest);
            let in_window: Vec<(&u64, &Position)> =
                generation.positions.range(start..=end).collect();
            let present = in_window.iter().filter(|(_, p)| p.timely).count() as u64;
            let span = end - start + 1;
            let missing = span - present;
            let jitter_ticks = in_window
                .iter()
                .map(|(_, p)| p.jitter_ticks)
                .max()
                .unwrap_or(0);
            let jitter_ns = u64::try_from(ticks_to_ns(i64::from(jitter_ticks), policy.clock_rate))
                .unwrap_or(u64::MAX);
            let window_end_arrival = generation
                .positions
                .range(..=end)
                .map(|(_, p)| p.arrival_ns)
                .max()
                .unwrap_or(window_start_arrival)
                .max(window_start_arrival);
            let window_interval = CaptureInterval::new(
                driver.at(window_start_arrival)?,
                driver.at(window_end_arrival)?,
            )?;
            let pts_known = in_window.iter().filter_map(|(_, p)| p.pts_ticks);
            let pts = match (pts_known.clone().min(), pts_known.max()) {
                (Some(min), Some(max)) => Some((
                    TimestampNs(ticks_to_ns(min, policy.clock_rate)),
                    TimestampNs(ticks_to_ns(max, policy.clock_rate)),
                )),
                _ => None,
            };
            let last_window = end == highest;
            let arrivals = window_start_arrival..=window_end_arrival;
            let faults: Vec<&'static str> = generation
                .faults
                .iter()
                .filter(|f| match f.at {
                    FaultAt::Sequence(at) => (start..=end).contains(&at),
                    FaultAt::Arrival(at) => {
                        arrivals.contains(&at) || (last_window && at > window_end_arrival)
                    }
                })
                .map(|f| f.dimension)
                .collect();
            let discontinuities = faults
                .iter()
                .filter(|d| **d == LOST_SEQUENCE_DISCONTINUITY)
                .count();
            let mut dims = faults.clone();
            if missing > 0 {
                dims.push(LOST_PACKET_LOSS);
            }
            if jitter_ns > policy.max_jitter_threshold_ns {
                dims.push(LOST_TIMING_JITTER);
            }
            let lost = sorted_dimensions(dims);
            let at = driver.at(window_end_arrival)?.max(first_at);
            let capsules = window_capsules(report, records, generation.generation, start, end)?;
            let mut windowed_degradation = None;
            let (outcome, cover) = if !lost.is_empty() {
                let evidence = driver.evidence(&lost, missing, jitter_ns, window_interval, at)?;
                let session = driver.session()?;
                let windowed = WindowedDegradationEvidence {
                    request_digest: request.request_digest(),
                    predecessor_digest: session.continuity_predecessor_digest()?,
                    window_start_seq: start,
                    window_end_seq: end,
                    degradation: evidence.clone(),
                };
                session.degrade_window(windowed.clone(), at)?;
                windowed_degradation = Some(Box::new(windowed));
                (
                    RtpWindowOutcome::Degraded {
                        evidence: Box::new(evidence),
                    },
                    // The source was observed (with gaps) whenever any position arrived: the
                    // witness names it as observed and gapped, so a registry keyed by observed
                    // domain sees the gap. Nothing arrived: not observable.
                    coverage(
                        scope,
                        present > 0,
                        CoverageContinuity::Gapped,
                        if present == 0 {
                            Completeness::NotObservable
                        } else {
                            Completeness::Partial
                        },
                        CoverageStopReason::SourceGap,
                    ),
                )
            } else if span < 2 {
                (
                    RtpWindowOutcome::TooShort,
                    coverage(
                        scope,
                        true,
                        CoverageContinuity::Unknown,
                        Completeness::Unknown,
                        CoverageStopReason::Unsupported,
                    ),
                )
            } else {
                // Continuous and complete over this window's packets (the core requires both to
                // verify continuity), but the witness carries no interval and the recorder clock
                // is estimated: it must not certify absence on its own, anywhere. `Unsupported`
                // says absence over capture time is not supported from this evidence; absence
                // goes through `absence_over` and the shared stored-witness rule instead.
                let cover = coverage(
                    scope,
                    true,
                    CoverageContinuity::Continuous,
                    Completeness::Complete,
                    CoverageStopReason::Unsupported,
                );
                let (window_start_pts_ns, window_end_pts_ns) =
                    pts.ok_or(RtpContinuityError::Binding)?;
                let witness = ContinuityWitness {
                    adapter_id: request.adapter_identity.adapter_id.clone(),
                    device_id: request.device_identity.device_id.clone(),
                    source_id: request.source_identity.source_id.clone(),
                    window_start_seq: start,
                    window_end_seq: end,
                    window_start_pts_ns,
                    window_end_pts_ns,
                    frames_observed: present,
                    discontinuities: 0,
                    packet_loss: 0,
                    observed_jitter_ns: jitter_ns,
                    max_jitter_threshold_ns: policy.max_jitter_threshold_ns,
                    coverage_witness: cover.clone(),
                };
                match driver.session()?.verify_continuity(witness.clone(), at) {
                    Ok(()) => (
                        RtpWindowOutcome::Verified {
                            witness: Box::new(witness),
                        },
                        cover,
                    ),
                    Err(refusal) => (
                        RtpWindowOutcome::CleanNotVerified {
                            refusal: refusal.to_string(),
                        },
                        coverage(
                            scope,
                            true,
                            CoverageContinuity::Unknown,
                            Completeness::Unknown,
                            CoverageStopReason::SourceGap,
                        ),
                    ),
                }
            };
            windows.push(RtpContinuityWindow {
                generation: generation.generation,
                start_seq: start,
                end_seq: end,
                interval: window_interval,
                pts,
                packets_observed: present,
                missing_positions: missing,
                discontinuities: u32::try_from(discontinuities).unwrap_or(u32::MAX),
                observed_jitter_ns: jitter_ns,
                lost_dimensions: lost,
                coverage: cover,
                outcome,
                windowed_degradation,
                capsules,
            });
            window_start_arrival = window_end_arrival;
            start = match end.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        generations.push(RtpGenerationOutcome {
            generation: generation.generation,
            stream_generation: stream_generation(generation.generation)?,
            ssrc: generation.ssrc,
            cause: generation.cause,
            interval,
            auth,
            first_picture: Some(RtpFirstPicture {
                sequence: first.sequence,
                completed_at_sequence: first.completed_at,
                i420_sha256: first.i420_sha256,
                dimensions: first.dimensions,
                witness,
            }),
            pre_first_frame_lost: Vec::new(),
        });
    }
    let mut session = driver.session.ok_or(RtpContinuityError::Binding)?;
    if let ImportEnd::FramingRefused(_) = report.end() {
        let request = session.request().clone();
        let evidence = DegradationEvidence {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            degraded_at_ns: last_at,
            lost_dimensions: vec![LOST_FRAMING_REFUSED.to_owned()],
            invalidated_negative_claims: vec![INVALIDATED_ABSENCE.to_owned()],
            observed_packet_loss: 0,
            observed_jitter_ns: 0,
        };
        session.degrade(evidence, last_at)?;
    }
    let request = session.request().clone();
    session.cancel(
        QuiescenceReceipt {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            cancelled_at_ns: last_at,
            // The recording was read into one bounded buffer; no task or descriptor remains.
            active_tasks: 0,
            open_descriptors: 0,
            buffers_drained: true,
        },
        last_at,
    )?;
    Ok(RtpContinuityReport {
        session,
        generations,
        windows,
        capsules: report
            .access_units()
            .iter()
            .map(|u| u.capsule.clone())
            .collect(),
        scope: scope.clone(),
    })
}

/// Indices of the import's access-unit capsules whose every NAL source record is an admitted
/// packet of `generation` within `[start, end]`.
fn window_capsules(
    report: &crate::ingest::rtpdump::import::RtpImportReport,
    records: &[RecordReport],
    generation: u64,
    start: u64,
    end: u64,
) -> Result<Vec<usize>, RtpContinuityError> {
    let mut out = Vec::new();
    for (index, unit) in report.access_units().iter().enumerate() {
        let nals = report
            .nals()
            .get(unit.nals.clone())
            .ok_or(RtpContinuityError::Binding)?;
        let mut inside = !nals.is_empty();
        for span in nals.iter().flat_map(|nal| nal.spans.iter()) {
            let record = records
                .get(span.record)
                .ok_or(RtpContinuityError::Binding)?;
            inside &= record.generation == generation
                && record
                    .sequence
                    .and_then(|o| o.extended_sequence)
                    .is_some_and(|seq| (start..=end).contains(&seq));
        }
        inside &= nals.iter().all(|nal| !nal.spans.is_empty());
        if inside {
            out.push(index);
        }
    }
    Ok(out)
}
