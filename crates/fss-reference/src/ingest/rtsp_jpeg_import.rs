#![forbid(unsafe_code)]
//! Source-closed finite RTP/JPEG imports using the native recorded-arrival replay.
//!
//! The original selected datagram closure and reconstruction maps remain custody.
//! Neither a prefix ending nor an RTP timestamp supplies EOF or capture-clock authority.
//! JPEG framing is retained here; existing pixel owners independently validate entropy
//! and apply the destination's current privacy policy.

mod provenance;
mod publication;
mod replay;
mod request;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

use fss_core::{ContentDigest, ContractError, SensorId, StreamId, TimestampNs};
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::file_adapter::FileIngestError;
use crate::rtsp::datagram_archive::{
    DatagramArchiveError, DatagramArchiveLimits, DatagramObjectReader, DatagramPin, DatagramScope,
    DetachedDatagramPrefix, prefix::DatagramPrefix,
};
use crate::rtsp::datagram_reconstruction::jpeg::JpegReplaySpec;
use crate::{ReferenceDeployment, ReplayCx};

pub(crate) use provenance::{
    OriginCache, verify_membership, verify_originals, verify_range_budgeted,
};

/// Explicit source-closed adapter; ordinary file and HTTP imports keep their old identities.
pub const ADAPTER: &str = "ADP-RTSP-JPEG-ARCHIVE-001";
pub(crate) const GENERATION: &str = "gen:rtsp-jpeg-archive:v1:";
pub(crate) const DOMAIN: &str = "fss.rtsp_jpeg_import.v1";
/// Live permission/cancellation checkpoint across source reads and destination publication.
pub const STAGE_RTSP_JPEG_IMPORT: &str = "rtsp_jpeg_import:source_custody";
/// Complete output images, independently bounded from packet observations.
pub const MAX_FRAMES: usize = 4096;
/// Complete original arrival inventory, including duplicates, probation and RTCP.
pub const MAX_SOURCE_DATAGRAMS: usize = 8192;
/// Whole current source payload ceiling; descendants count during live recovery.
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
/// All publisher entries examined during source recovery.
pub const MAX_SCAN_ROOTS: usize = 32768;
/// Unique original root, metadata and payload objects copied into the import.
pub const MAX_ORIGINAL_BYTES: u64 = 64 * 1024 * 1024;
/// Complete reconstructed media bytes, independent of original storage.
pub const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
/// Conservative original-read and explicit custody-comparison payload reservation.
/// Publisher recovery and publication metadata I/O have their own native spool bounds.
pub const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;
/// Native scheduler calls, including pending polls and timer advances.
pub const MAX_STEPS: u64 = 262144;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLAY_WORK: u64 = 16_000_000_000;
const CHUNK_BYTES: usize = 1024 * 1024;

/// Exact source interpretation and explicit physical-camera mapping.
#[derive(Clone, Debug)]
pub struct JpegImportRequest {
    /// Original route, stream generation, receive clock and retention basis.
    pub source: DatagramScope,
    /// Exact complete prefix, never a count-only selection or latest lookup.
    pub pin: DatagramPin,
    /// Negotiated RTP/JPEG semantics and their independent configuration evidence.
    pub replay: JpegReplaySpec,
    /// Explicit destination physical sensor; SSRC is not sensor authentication.
    pub sensor: SensorId,
    /// Explicit destination stream.
    pub stream: StreamId,
    /// Owner evidence connecting the exact original scope to this sensor/stream.
    pub mapping_evidence: ContentDigest,
    /// Ingest timestamp; every capture interval remains unknown, `[0, receive_time]`.
    pub receive_time: TimestampNs,
    /// Complete current-source recovery bounds, including later descendants.
    pub archive_limits: DatagramArchiveLimits,
    /// Complete image bound, never a top-k selection.
    pub max_frames: usize,
    /// Independent unique original closure byte bound.
    pub max_original_bytes: u64,
    /// Independent reconstructed media byte bound.
    pub max_media_bytes: u64,
    /// Original/custody verification payload reservation, including repeated reads.
    pub max_read_bytes: u64,
    /// Independent unrenewable replay-call bound.
    pub max_steps: u64,
}

/// Independent current source disclosure and destination retention authority.
pub trait JpegImportAuthority {
    /// Must recheck exact request, capabilities, revocation and deadline.
    fn permit(&self, request: &JpegImportRequest, destination: &ReferenceDeployment) -> bool;
}

/// Payload-free incomplete JPEG accounting; ranges are observed contributions, not coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegImportDiscard {
    /// Stable native reason spelling.
    pub reason: &'static str,
    /// First contributing extended sequence.
    pub first_sequence: u64,
    /// Last contributing extended sequence.
    pub last_sequence: u64,
    /// Retired reconstructed bytes, including generated headers.
    pub bytes: usize,
    /// Actual contributing datagrams.
    pub fragments: usize,
}

/// Prefix retirement is explicit; no finish() or future timeout was invented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegImportTerminal {
    /// Last historical virtual time reached, not camera or storage time.
    pub replay_ns: u64,
    /// Queued originals retired without ordered delivery.
    pub queue_packets: usize,
    /// Wire bytes of those queued originals.
    pub queue_bytes: usize,
    /// Lowest queued extended sequence, absent for an empty queue.
    pub queue_first_sequence: Option<u64>,
    /// Highest queued extended sequence, absent for an empty queue.
    pub queue_last_sequence: Option<u64>,
    /// Incomplete JPEG remaining at the exact prefix ending.
    pub fragment: Option<JpegImportDiscard>,
    /// A discontinuity/omission remained after the last complete output image.
    pub gap_pending: bool,
}

/// Summary only; exact event ranges and maps remain in the retained origin proof.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JpegImportAccounting {
    /// Original RTP observations, including probation and duplicates.
    pub rtp_datagrams: u64,
    /// Original RTCP observations.
    pub rtcp_datagrams: u64,
    /// RTCP compounds refused by native whole-compound validation.
    pub invalid_rtcp_datagrams: u64,
    /// Original RTP packets actually delivered in native ordered sequence.
    pub ordered_packets: u64,
    /// Payload reconstruction refusals; no partial image was published.
    pub codec_refusals: u64,
    /// Explicit ordered-delivery gap events, not certified network losses.
    pub gap_events: u64,
    /// Mid-prefix incomplete JPEG retirements; terminal fragment is separate.
    pub fragment_discards: u64,
}

/// Ordinary retained import plus source interpretation and finite-prefix accounting.
#[derive(Debug)]
pub struct JpegImportReceipt {
    /// Ordinary completed import identity accepted by retained image owners.
    pub import_identity: ContentDigest,
    /// Durable root witnessed by import completion authority.
    pub import_root: ContentDigest,
    /// Exact existing file-import metadata.
    pub manifest_digest: ContentDigest,
    /// Complete canonical origin proof inside the import closure.
    pub proof: ContentDigest,
    /// Native arrival-replay profile, distinct from pixel decoder identity.
    pub interpretation: ContentDigest,
    /// Exactly selected original packet prefix.
    pub source: DatagramPin,
    /// Complete reconstructed JPEGs, including repeated source observations.
    pub frames: usize,
    /// Unique original root, metadata and payload bytes retained.
    pub original_bytes: u64,
    /// Complete concatenated reconstructed JPEG bytes.
    pub media_bytes: u64,
    /// Conservative original-read and explicit custody-comparison payload reservation;
    /// excludes publisher opening and internal publication metadata I/O.
    pub read_bytes_reserved: u64,
    /// Native scheduler calls through the exact selected prefix retirement.
    pub replay_steps: u64,
    /// Always `unknown`; transport timestamps never become capture time.
    pub capture_time_label: &'static str,
    /// Always `pinned_prefix`; no source EOF or continuity is asserted.
    pub ending: &'static str,
    /// Payload-free original admission and reconstruction summary.
    pub accounting: JpegImportAccounting,
    /// Remaining queue/fragment ownership at finite prefix exhaustion.
    pub terminal: JpegImportTerminal,
    /// True only after an exact completed import was reverified without new writes.
    pub reused: bool,
}

/// Explicit request, authority, source, resource and publication refusals.
#[derive(Debug)]
pub enum JpegImportError {
    /// Invalid selection, mapping or a native terminal refusal.
    Invalid(&'static str),
    /// The complete selected prefix contained no publishable JPEG.
    NoCompleteFrames,
    /// Current source/destination authority, deadline or cancellation refused.
    Denied,
    /// One independent complete-operation allowance was exhausted.
    Limit(&'static str),
    /// Original custody or native reconstruction refused without revealing packet bytes.
    Source(String),
    /// Existing retained-storage/publication owner refused.
    Import(Box<FileIngestError>),
}
impl JpegImportError {
    /// Stable machine error identity; no private packet bytes are displayed.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::NoCompleteFrames => "ERR-RTSP-JPEG-IMPORT-REQUEST-001",
            Self::Denied => "ERR-RTSP-JPEG-IMPORT-AUTHORITY-001",
            Self::Limit(_) => "ERR-RTSP-JPEG-IMPORT-LIMIT-001",
            Self::Source(_) => "ERR-RTSP-JPEG-IMPORT-SOURCE-001",
            Self::Import(_) => "ERR-RTSP-JPEG-IMPORT-CUSTODY-001",
        }
    }
}
impl fmt::Display for JpegImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for JpegImportError {}
impl From<FileIngestError> for JpegImportError {
    fn from(value: FileIngestError) -> Self {
        Self::Import(Box::new(value))
    }
}
impl From<ContractError> for JpegImportError {
    fn from(value: ContractError) -> Self {
        FileIngestError::from(value).into()
    }
}
fn source_error(e: impl fmt::Debug) -> JpegImportError {
    JpegImportError::Source(format!("{e:?}"))
}
fn storage_error(e: impl Into<FileIngestError>) -> JpegImportError {
    e.into().into()
}
fn corrupt(reason: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("RTP/JPEG import origin: {reason}"),
    }
}
fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE_RTSP_JPEG_IMPORT)
        .map_err(|_| FileIngestError::CancellationRequested {
            stage: STAGE_RTSP_JPEG_IMPORT,
        })
}
fn guard(
    authority: &dyn JpegImportAuthority,
    request: &JpegImportRequest,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<(), JpegImportError> {
    checkpoint(cx)?;
    if !authority.permit(request, destination) {
        return Err(JpegImportError::Denied);
    }
    Ok(())
}
struct Access<'a> {
    authority: &'a dyn JpegImportAuthority,
    request: &'a JpegImportRequest,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        guard(self.authority, self.request, self.destination, self.cx).is_err()
    }
}
struct ReadMeter {
    maximum: u64,
    used: Cell<u64>,
}
impl ReadMeter {
    fn reserve(&self, bytes: u64) -> Result<(), JpegImportError> {
        let next = self
            .used
            .get()
            .checked_add(bytes)
            .filter(|n| *n <= self.maximum)
            .ok_or(JpegImportError::Limit("original read bytes"))?;
        self.used.set(next);
        Ok(())
    }
}

/// Recover, replay and copy one exact original prefix, then publish the ordinary import root last.
/// Every independent allowance is shared for the complete call and never refilled per frame.
pub fn import_rtsp_jpeg(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &JpegImportRequest,
    authority: &dyn JpegImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<JpegImportReceipt, JpegImportError> {
    if cx.root_dir() != destination.root()
        || publisher.root_dir().starts_with(destination.root())
        || destination.root().starts_with(publisher.root_dir())
    {
        return Err(JpegImportError::Invalid(
            "distinct source and destination owners required",
        ));
    }
    request.digest()?;
    guard(authority, request, destination, cx)?;
    let reads = ReadMeter {
        maximum: request.max_read_bytes,
        used: Cell::new(0),
    };
    reads.reserve(request.live_read_reservation())?;
    let mut originals = BTreeMap::new();
    let (prefix, result) = {
        let access = Access {
            authority,
            request,
            destination,
            cx,
        };
        let prefix = DatagramPrefix::recover(
            publisher,
            request.source.clone(),
            request.archive_limits,
            request.pin,
            &access,
            work,
        )
        .map_err(source_error)?;
        let mut reader = provenance::OriginalReader::new(
            publisher,
            &reads,
            Some(&mut originals),
            request.max_original_bytes,
        );
        let detached = DetachedDatagramPrefix::recover(
            request.source.clone(),
            request.archive_limits,
            request.pin,
            &mut reader,
            &access,
            work,
        )
        .map_err(source_error)?;
        let result = replay::reconstruct(&detached, request, &mut reader, &access, work)?;
        (prefix, result)
    };
    // Charge bounded proof cloning/encoding/hashing and media/capsule/chunk planning
    // BEFORE those allocations. Staging I/O is additionally charged per object.
    let planning_bytes = result.media.len() as u64
        + result
            .frames
            .iter()
            .map(|f| f.lineage.len() as u64)
            .sum::<u64>()
        + result.diagnostics.len() as u64
        + originals.len() as u64 * 128
        + result.frames.len() as u64 * 1024
        + 4096;
    work.charge(planning_bytes * 16).map_err(source_error)?;
    guard(authority, request, destination, cx)?;
    let proof = provenance::Proof::new(request.clone(), &originals, &result)?;
    publication::publish(
        publisher,
        &prefix,
        destination,
        request,
        authority,
        cx,
        work,
        &reads,
        proof,
        result,
        originals,
    )
}
