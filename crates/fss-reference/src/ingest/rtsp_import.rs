#![forbid(unsafe_code)]
//! Source-closed import of one exact native RTSP recording window.
//!
//! Original RTP, the recording index, initialization and fragment remain retained with the
//! reconstructed MP4. Existing native container timing supplies relative presentation offsets;
//! absolute capture time is an explicit owner assumption, never inferred from RTP or receive time.
//! This finite offline operation grants neither network access, live continuity nor event authority.

mod provenance;
mod publication;

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint, SlotName};

use super::file_adapter::{
    CaptureHint, DetectedFileFormat, FileImportManifest, FileIngestAdapter, FileIngestError,
    FileIngestLimits, FileIngestRequest, ScannedSegments,
};
use crate::rtsp::recording::{
    MAX_RECORDING_BYTES, MAX_RECORDING_SAMPLES, RecordingScope,
    hevc::local::load_hevc_recording, local::load_recording,
};
use crate::{ReferenceDeployment, ReplayCx};

pub(crate) use provenance::{
    OriginCache, verify_membership, verify_originals, verify_range_budgeted,
};

/// Native recording origin; ordinary file-import identities and bytes are unchanged.
pub const ADAPTER: &str = "ADP-RTSP-RECORDING-ARCHIVE-001";
pub(crate) const GENERATION: &str = "gen:rtsp-recording-archive:v1:";
pub(crate) const DOMAIN: &str = "fss.rtsp_recording_import.v1";
/// Explicit authority/cancellation boundary for source reads and destination publication.
pub const STAGE_RTSP_IMPORT: &str = "rtsp_import:source_custody";
/// One native, independently sealed recording window, never an arbitrary truncated frame list.
pub const MAX_FRAMES: usize = MAX_RECORDING_SAMPLES;
/// Entire original recording graph payload, including its immutable root.
pub const MAX_ORIGINAL_BYTES: u64 = MAX_RECORDING_BYTES as u64;
/// Independent reconstructed initialization-plus-fragment byte ceiling.
pub const MAX_MEDIA_BYTES: u64 = MAX_RECORDING_BYTES as u64;
pub(crate) const MAX_PROOF_BYTES: usize = 256 * 1024;
pub(crate) const CHUNK_BYTES: usize = 1024 * 1024;

/// Exact codec owner; no fallback or sniffed substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtspImportCodec {
    /// Native source-verified H.264/AVC recording.
    Avc,
    /// Native source-verified H.265/HEVC recording.
    Hevc,
}
impl RtspImportCodec {
    /// Stable operator spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
    pub(crate) const fn format(self) -> DetectedFileFormat {
        match self {
            Self::Avc => DetectedFileFormat::Mp4Avc,
            Self::Hevc => DetectedFileFormat::Mp4Hevc,
        }
    }
}

/// Explicit absolute capture origin, independent of RTP/receive clock identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspCaptureOrigin {
    /// Nominal capture timestamp of the window's earliest presentation sample.
    pub start_ns: TimestampNs,
    /// Symmetric uncertainty around each native presentation-time-derived capture timestamp.
    pub uncertainty_ns: u64,
}

/// Independently pinned source and explicit camera/time/retention bounds.
/// Source scope is reused for destination sensor and stream; this operation never remaps a camera.
#[derive(Clone, Debug)]
pub struct RtspImportRequest {
    /// The codec-specific native verifier.
    pub codec: RtspImportCodec,
    /// Exact durable recording window slot, not a catalog query or mutable latest pointer.
    pub slot: SlotName,
    /// Exact immutable window root independently selected by the owner.
    pub root: ContentDigest,
    /// Retained sensor/stream/generation, authority reference and monotonic receive-clock identity.
    pub source: RecordingScope,
    /// Explicit ingestion time in the destination timestamp universe.
    pub receive_time: TimestampNs,
    /// Optional absolute capture origin and uncertainty. Native MP4 presentation offsets apply;
    /// no assumed frame rate replaces the retained sample timeline.
    pub capture_origin: Option<RtspCaptureOrigin>,
    /// Maximum complete samples; an oversized window is refused as a whole.
    pub max_frames: usize,
    /// Maximum combined original root/source/index/init/media payload admitted for retention.
    pub max_original_bytes: u64,
    /// Independent maximum initialization-plus-fragment MP4 payload.
    pub max_media_bytes: u64,
}
impl RtspImportRequest {
    /// Validates pure input and returns the identity binding every owner interpretation and bound.
    pub fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    fn validate(&self) -> Result<(), RtspImportError> {
        if [self.root, self.source.anchor, self.source.receive_clock]
            .iter()
            .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
            || self.source.generation == 0
            || self.receive_time.0 < 0
            || !(1..=MAX_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_ORIGINAL_BYTES).contains(&self.max_original_bytes)
            || !(1..=MAX_MEDIA_BYTES).contains(&self.max_media_bytes)
        {
            return Err(RtspImportError::Invalid("source scope, time or bounds"));
        }
        if let Some(h) = self.capture_origin {
            if h.start_ns.0 < 0 || h.start_ns.0.checked_add(i128::from(h.uncertainty_ns)).is_none() {
                return Err(RtspImportError::Invalid("capture hint"));
            }
            FileIngestAdapter::compute_capture_interval(0, self.native_hint().as_ref(), self.receive_time)?;
        }
        Ok(())
    }
    pub(crate) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text("fss.rtsp_recording_import_request.v1");
        e.text(self.codec.as_str());
        e.text(self.slot.as_str());
        e.digest(self.root);
        e.text(self.source.sensor.as_str());
        e.text(self.source.stream.as_str());
        e.u64(self.source.generation);
        e.digest(self.source.anchor);
        e.digest(self.source.receive_clock);
        e.i128(self.receive_time.0);
        e.bool(self.capture_origin.is_some());
        if let Some(h) = self.capture_origin {
            e.i128(h.start_ns.0);
            e.u64(h.uncertainty_ns);
        }
        e.u64(self.max_frames as u64);
        e.u64(self.max_original_bytes);
        e.u64(self.max_media_bytes);
    }
    pub(crate) fn identity(&self) -> Result<ContentDigest, RtspImportError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_recording_import_identity.v1");
        e.digest(self.digest()?);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(crate) fn scan(
        &self,
        media: &[u8],
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        if let Some(origin) = self.capture_origin {
            use fss_container::demux::{AvcMp4, DemuxError};
            let mut limits = super::file_adapter::mp4_demux_limits(self.max_frames);
            limits.maximum_input_bytes = usize::try_from(self.max_media_bytes)
                .map_err(|_| corrupt("media byte ceiling"))?;
            let mut check = || cx.checkpoint(STAGE_RTSP_IMPORT).map_err(|_| DemuxError::Cancelled);
            let video = AvcMp4::parse_recovering_tail(media, None, limits, &mut check)
                .map_err(|refusal| FileIngestError::Mp4Refused { refusal })?;
            let earliest = video.samples().iter().map(|s| s.presentation_time()).min().unwrap_or(0);
            let denominator = i128::from(video.timescale());
            for sample in video.samples() {
                let offset = sample.presentation_time().checked_sub(earliest)
                    .and_then(|n| n.checked_mul(1_000_000_000))
                    .and_then(|n| n.checked_add(denominator / 2))
                    .map(|n| n / denominator)
                    .ok_or_else(|| corrupt("presentation-time arithmetic"))?;
                origin.start_ns.0.checked_add(offset)
                    .and_then(|n| n.checked_add(i128::from(origin.uncertainty_ns)))
                    .ok_or_else(|| corrupt("capture timestamp overflow"))?;
            }
        }
        let mut native = FileIngestRequest::new(
            std::path::PathBuf::new(),
            self.source.sensor.clone(),
            self.source.stream.clone(),
        );
        native.limits = FileIngestLimits {
            max_file_bytes: self.max_media_bytes,
            chunk_bytes: CHUNK_BYTES as u64,
            max_segments: self.max_frames,
            max_batch_deltas: 1,
            ..FileIngestLimits::standard()
        };
        native.capture_hint = self.native_hint();
        native.receive_time = Some(self.receive_time);
        FileIngestAdapter::container_segments(
            media,
            self.codec.format(),
            &native,
            &hex(self.identity().map_err(|_| corrupt("request identity"))?),
            self.receive_time,
            cx,
        )
    }
    fn native_hint(&self) -> Option<CaptureHint> {
        self.capture_origin.map(|origin| CaptureHint {
            start_ns: origin.start_ns,
            uncertainty_ns: origin.uncertainty_ns,
            // The MP4 scanner uses only sample presentation offsets, never this file-only field.
            assumed_fps: 1.0,
        })
    }
    pub(crate) const fn time_label(&self) -> &'static str {
        if self.capture_origin.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        }
    }
}

/// Independent permission to disclose the selected original packets and retain them in destination.
/// Callers must check current principal, policy, revocation and deadline. No default grant exists.
pub trait RtspImportAuthority {
    /// Authorize this exact source/destination binding at the current operation boundary.
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool;
}

/// A source/custody failure carries metadata only, never original packet/media bytes.
#[derive(Debug)]
pub enum RtspImportError {
    /// Invalid pure request or source window beyond its independent bounds.
    Invalid(&'static str),
    /// Current permission, cancellation or operation deadline refused.
    Denied,
    /// Native source, codec, scope or work verification failed.
    Source(String),
    /// Existing native import/publication boundary failed.
    Import(Box<FileIngestError>),
}
impl RtspImportError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-RTSP-IMPORT-REQUEST-001",
            Self::Denied => "ERR-RTSP-IMPORT-AUTHORITY-001",
            Self::Source(_) => "ERR-RTSP-IMPORT-SOURCE-001",
            Self::Import(_) => "ERR-RTSP-IMPORT-CUSTODY-001",
        }
    }
}
impl fmt::Display for RtspImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for RtspImportError {}
impl From<FileIngestError> for RtspImportError {
    fn from(value: FileIngestError) -> Self {
        Self::Import(Box::new(value))
    }
}
impl From<ContractError> for RtspImportError {
    fn from(value: ContractError) -> Self {
        FileIngestError::from(value).into()
    }
}
fn source_error(value: impl fmt::Debug) -> RtspImportError {
    RtspImportError::Source(format!("{value:?}"))
}
pub(crate) fn corrupt(reason: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("RTSP recording origin: {reason}"),
    }
}
pub(crate) fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE_RTSP_IMPORT)
        .map_err(|_| FileIngestError::CancellationRequested {
            stage: STAGE_RTSP_IMPORT,
        })
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn guard(
    authority: &dyn RtspImportAuthority,
    request: &RtspImportRequest,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<(), RtspImportError> {
    checkpoint(cx)?;
    if !authority.permit(request, destination) {
        return Err(RtspImportError::Denied);
    }
    Ok(())
}
struct Access<'a> {
    authority: &'a dyn RtspImportAuthority,
    request: &'a RtspImportRequest,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        guard(self.authority, self.request, self.destination, self.cx).is_err()
    }
}

/// Completed ordinary retained-import identity plus its exact native recording origin.
#[derive(Debug)]
pub struct RtspImportReceipt {
    /// Accepted by the existing retained decode, motion, inference, watch and corroboration APIs.
    pub import_identity: ContentDigest,
    /// Root of the complete source-closed import publication.
    pub import_root: ContentDigest,
    /// Exact normal FileImportManifest digest.
    pub manifest_digest: ContentDigest,
    /// Actual complete native MP4 samples, never a count of decoder-certified pictures.
    pub frames: usize,
    /// Explicit admitted codec, preserved independently of operator output spelling.
    pub codec: RtspImportCodec,
    /// Unknown or operator_assumption; no remote clock trust is implied.
    pub capture_time_label: &'static str,
    /// Canonical retained recipe and origin proof.
    pub proof: ContentDigest,
    /// True only when the exact completed import was reverified without new writes.
    pub reused: bool,
}

/// Verify one selected native recording and retain an ordinary source-closed MP4 import.
/// The byte-work allowance is whole-call and never renewed per read, sample or publication.
/// One native source verification reserves the fixed maximum window byte allowance up front;
/// request maxima independently restrict the actual source and reconstructed media admitted.
/// No unfinished source tail is synthesized into a sample.
pub fn import_rtsp<'cx>(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &RtspImportRequest,
    authority: &dyn RtspImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'cx>,
) -> Result<RtspImportReceipt, RtspImportError> {
    request.digest()?;
    if cx.root_dir() != destination.root()
        || publisher.root_dir().starts_with(destination.root())
        || destination.root().starts_with(publisher.root_dir())
    {
        return Err(RtspImportError::Invalid("distinct source and destination owners required"));
    }
    guard(authority, request, destination, cx)?;
    // Native window readers have a fixed bounded original/replay contract. Reserve it before
    // their first read; a narrower request is a retention admission bound, not a syscall meter.
    work.charge(MAX_ORIGINAL_BYTES).map_err(source_error)?;
    let window = {
        let access = Access { authority, request, destination, cx };
        match request.codec {
            RtspImportCodec::Avc => {
                let plan = load_recording(
                    publisher, &request.slot, request.root, &request.source, &access,
                ).map_err(source_error)?;
                provenance::Window::from_verified(&plan, request)?
            }
            RtspImportCodec::Hevc => {
                let plan = load_hevc_recording(
                    publisher, &request.slot, request.root, &request.source, &access,
                ).map_err(source_error)?;
                provenance::Window::from_verified(plan.publication_plan(), request)?
            }
        }
    };
    guard(authority, request, destination, cx)?;
    work.charge((window.media_len() as u64).saturating_mul(2)).map_err(source_error)?;
    let media = window.media()?;
    let scan = request.scan(&media, cx)?;
    if scan.capsules.is_empty()
        || scan.capsules.len() > request.max_frames
        || scan.capsules.len() != window.samples
        || scan.truncated_frames != 0
        || scan.omission_spans.iter().any(|span| !span.is_container_structure())
    {
        return Err(RtspImportError::Invalid("complete native sample set"));
    }
    let proof = provenance::Proof::new(request.clone(), &window, &media, &scan)?;
    let mut payloads = BTreeMap::new();
    for (digest, bytes) in window.payloads() {
        payloads.insert(digest, bytes.to_vec());
    }
    publication::publish(
        destination, request, authority, cx, work, proof, media, scan, payloads,
    )
}
