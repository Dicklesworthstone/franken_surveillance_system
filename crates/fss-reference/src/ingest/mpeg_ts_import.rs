#![forbid(unsafe_code)]
//! Finite MPEG-TS file custody with native AVC/HEVC elementary-stream reconstruction.
//!
//! Original transport packets, extraction policy and exact source-map commitment remain in the
//! retained publication closure. Existing Annex-B splitters establish access units; a PES never
//! stands for a decoded picture. PTS/DTS remain untrusted media clocks in the extraction receipt.
//! Capture time uses only the existing explicit file-import assumption, or stays unknown.

mod provenance;
mod publication;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;

use fss_container::demux::VideoCodec;
use fss_container::mpeg_ts::{
    MpegTsVideo, TsError, TsFraming, TsLimits, TsSelection, receipt::TsExtractionReceipt,
};
use fss_core::{CanonicalEncoder, ContentDigest, ContractError, TimestampNs};
use fss_geometry::WorkBudget;

use super::file_adapter::{
    DetectedFileFormat, FileIngestAdapter, FileIngestError, FileIngestRequest, ScannedSegments,
};
use crate::{ReferenceDeployment, ReplayCx};

pub(crate) use provenance::{
    OriginCache, verify_membership, verify_originals, verify_range_budgeted,
};

/// Explicit reconstructed-media adapter; ordinary file-import identities remain unchanged.
pub const ADAPTER: &str = "ADP-MPEGTS-FILE-001";
pub(crate) const GENERATION: &str = "gen:mpegts-file:v1:";
pub(crate) const DOMAIN: &str = "fss.mpegts_file_import.v1";
const REQUEST_DOMAIN: &str = "fss.mpegts_file_import_request.v1";
const FRAMED_REQUEST_DOMAIN: &str = "fss.mpegts_file_import_request.v2";
const IDENTITY_DOMAIN: &str = "fss.mpegts_file_import_identity.v1";
const SCAN_DOMAIN: &str = "fss.mpegts_file_import_scan.v1";
const DETECTOR: &str = "native_mpegts:reconstructed_annexb:original_transport_retained";
/// Separate hard ceilings for original transport and reconstructed elementary bytes.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SEGMENTS: usize = 65_536;
const MAX_OBJECTS: usize = 65_536;
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Cooperative checkpoint used for original-file reads, replay and publication.
pub const STAGE_MPEGTS_IMPORT: &str = "mpegts_import:source_custody";

/// Explicit finite-file operation; generic file sniffing never silently selects MPEG-TS.
#[derive(Clone, Debug)]
pub struct MpegTsImportRequest {
    /// Existing file authority, sensor, stream, receive time, split and chunk limits.
    /// A media-format hint or recorded-RTP binding is refused for this explicit operation.
    pub file: FileIngestRequest,
    /// Physical packet framing, supplied by the owner rather than inferred from source bytes.
    /// Standard TS is the default; M2TS prefixes and DVB trailers remain opaque original custody.
    pub framing: TsFraming,
    /// Program and video PID; omitted values require unambiguous native selection.
    pub selection: TsSelection,
    /// Independent transport parsing and elementary-output limits.
    pub transport_limits: TsLimits,
}

impl MpegTsImportRequest {
    /// Standard bounded transport policy with the caller's existing file binding.
    #[must_use]
    pub fn new(file: FileIngestRequest) -> Self {
        let transport_limits = TsLimits {
            max_input_bytes: file.limits.max_file_bytes.min(MAX_BYTES) as usize,
            max_elementary_bytes: MAX_BYTES as usize,
            ..TsLimits::default()
        };
        Self {
            file,
            framing: TsFraming::Ts188,
            selection: TsSelection::default(),
            transport_limits,
        }
    }

    fn validate(&self) -> Result<(), MpegTsImportError> {
        self.transport_limits
            .validate()
            .map_err(MpegTsImportError::Transport)?;
        let file = &self.file;
        let receive = file
            .receive_time
            .ok_or(FileIngestError::MissingReceiveTime {})?;
        if file.format_hint.is_some()
            || file.rtp_binding.is_some()
            || receive.0 < 0
            || file.limits.max_file_bytes == 0
            || !(1..=MAX_BYTES).contains(&file.limits.chunk_bytes)
            || !(1..=MAX_SEGMENTS).contains(&file.limits.max_segments)
            || file.limits.max_batch_deltas == 0
            || self.transport_limits.max_input_bytes as u64 > MAX_BYTES
            || self.transport_limits.max_elementary_bytes as u64 > MAX_BYTES
            || self.selection.program == Some(0)
            || self.selection.video_pid.is_some_and(|p| p >= 0x1fff)
        {
            return Err(MpegTsImportError::Invalid("scope, receive time or bounds"));
        }
        let split = file.limits.annexb_limits;
        if split.max_input_bytes == 0
            || split.max_nal_bytes == 0
            || !(1..=MAX_SEGMENTS).contains(&split.max_nals)
            || !(1..=MAX_SEGMENTS).contains(&split.max_aus)
        {
            return Err(MpegTsImportError::Invalid("elementary split bounds"));
        }
        if let Some(hint) = file.capture_hint {
            if hint.start_ns.0 < 0 || !hint.assumed_fps.is_finite() || hint.assumed_fps <= 0.0 {
                return Err(MpegTsImportError::Invalid("capture hint"));
            }
            FileIngestAdapter::compute_capture_interval(0, Some(&hint), receive)?;
        }
        Ok(())
    }

    /// Canonical request identity binds every supplied limit and clock assumption, not the path.
    pub fn digest(&self) -> Result<ContentDigest, MpegTsImportError> {
        self.validate()?;
        Ok(ContentDigest::sha256(&self.encode()))
    }

    fn encode(&self) -> Vec<u8> {
        let file = &self.file;
        let limits = &file.limits;
        let mut e = CanonicalEncoder::new();
        match self.framing.outer_framing_tag() {
            None => e.text(REQUEST_DOMAIN),
            Some(tag) => {
                e.text(FRAMED_REQUEST_DOMAIN);
                e.u8(tag);
            }
        }
        e.text(file.sensor_id.as_str());
        e.text(file.stream_id.as_str());
        e.i128(file.receive_time.map_or(-1, |t| t.0));
        e.bool(file.capture_hint.is_some());
        if let Some(hint) = file.capture_hint {
            e.i128(hint.start_ns.0);
            e.u64(hint.uncertainty_ns);
            e.u64(hint.assumed_fps.to_bits());
        }
        e.u64(limits.max_file_bytes);
        e.u64(limits.chunk_bytes);
        e.u64(limits.max_segments as u64);
        e.u64(limits.max_batch_deltas as u64);
        e.u64(limits.annexb_limits.max_input_bytes as u64);
        e.u64(limits.annexb_limits.max_nal_bytes as u64);
        e.u64(limits.annexb_limits.max_nals as u64);
        e.u64(limits.annexb_limits.max_aus as u64);
        e.u64(limits.annexb_limits.max_leading_garbage_bytes as u64);
        e.u64(limits.mjpeg_limits.max_input_bytes as u64);
        e.u64(limits.mjpeg_limits.max_frame_bytes as u64);
        e.u64(limits.mjpeg_limits.max_frames as u64);
        e.u64(limits.mjpeg_limits.max_marker_segments_per_frame as u64);
        e.u64(u64::from(limits.mjpeg_limits.max_dimension));
        e.bool(self.selection.program.is_some());
        if let Some(value) = self.selection.program {
            e.u64(u64::from(value));
        }
        e.bool(self.selection.video_pid.is_some());
        if let Some(value) = self.selection.video_pid {
            e.u64(u64::from(value));
        }
        let t = self.transport_limits;
        e.u64(t.max_input_bytes as u64);
        e.u64(t.max_packets as u64);
        e.u64(t.max_psi_sections as u64);
        e.u64(t.max_pes as u64);
        e.u64(t.max_pes_bytes as u64);
        e.u64(t.max_payload_spans as u64);
        e.u64(t.max_elementary_bytes as u64);
        e.finish()
    }

    fn identity(&self, source: ContentDigest) -> Result<ContentDigest, MpegTsImportError> {
        let mut e = CanonicalEncoder::new();
        e.text(IDENTITY_DOMAIN);
        e.digest(source);
        e.digest(self.digest()?);
        Ok(ContentDigest::sha256(&e.finish()))
    }

    fn time_label(&self) -> &'static str {
        if self.file.capture_hint.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        }
    }

    fn scan(
        &self,
        receipt: &TsExtractionReceipt,
        media: &[u8],
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        let identity = self
            .identity(receipt.source_digest())
            .map_err(|_| corrupt("identity"))?;
        let scan = FileIngestAdapter::scan_media(
            media,
            format(receipt.codec()),
            &self.file,
            &hex(identity),
            self.file
                .receive_time
                .ok_or(FileIngestError::MissingReceiveTime {})?,
            cx,
        )?;
        if scan.segment_spans.is_empty()
            || scan.segment_spans.len() > self.file.limits.max_segments
            || scan.omission_spans.len() > MAX_SEGMENTS
            || scan.truncated_frames != 0
        {
            return Err(corrupt("native access-unit count or omission bound"));
        }
        Ok(scan)
    }
}

/// Typed request, native transport and existing custody refusals, without source payload text.
#[derive(Debug)]
pub enum MpegTsImportError {
    /// Invalid explicit policy, source selection or independent ceiling.
    Invalid(&'static str),
    /// Native transport extraction or receipt verification refused.
    Transport(TsError),
    /// Existing file authority, source, cancellation, work or publication owner refused.
    Import(Box<FileIngestError>),
}
impl MpegTsImportError {
    /// Stable operator error identity.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-MPEGTS-IMPORT-REQUEST-001",
            Self::Transport(_) => "ERR-MPEGTS-IMPORT-SOURCE-001",
            Self::Import(_) => "ERR-MPEGTS-IMPORT-CUSTODY-001",
        }
    }
}
impl fmt::Display for MpegTsImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for MpegTsImportError {}
impl From<FileIngestError> for MpegTsImportError {
    fn from(error: FileIngestError) -> Self {
        Self::Import(Box::new(error))
    }
}
impl From<ContractError> for MpegTsImportError {
    fn from(error: ContractError) -> Self {
        FileIngestError::from(error).into()
    }
}
fn storage_error(error: impl Into<FileIngestError>) -> MpegTsImportError {
    MpegTsImportError::Import(Box::new(error.into()))
}
fn work_error(error: impl fmt::Debug) -> MpegTsImportError {
    corrupt(&format!("aggregate work refused: {error:?}")).into()
}
fn corrupt(reason: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("MPEG-TS import origin: {reason}"),
    }
}
fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE_MPEGTS_IMPORT)
        .map_err(|_| FileIngestError::CancellationRequested {
            stage: STAGE_MPEGTS_IMPORT,
        })
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn format(codec: VideoCodec) -> DetectedFileFormat {
    match codec {
        VideoCodec::Avc => DetectedFileFormat::AnnexB,
        VideoCodec::Hevc => DetectedFileFormat::Hevc,
    }
}
fn guard(destination: &ReferenceDeployment, cx: &ReplayCx) -> Result<(), MpegTsImportError> {
    if cx.root_dir() != destination.root() || !cx.io_authority().is_valid() {
        return Err(MpegTsImportError::Invalid(
            "destination context or I/O authority",
        ));
    }
    checkpoint(cx)?;
    Ok(())
}

/// Completed source-closed import. Access units are syntax units, never decoded-picture proof.
#[derive(Debug)]
pub struct MpegTsImportReceipt {
    /// Identity consumed by existing retained decode, watch and footage queries.
    pub import_identity: ContentDigest,
    /// Durable root of the retained file-import publication.
    pub import_root: ContentDigest,
    /// Canonical retained file-import metadata.
    pub manifest_digest: ContentDigest,
    /// Canonical origin proof held in this import's own publication closure.
    pub proof: ContentDigest,
    /// Digest of the original complete transport file, including unselected packets.
    pub original_digest: ContentDigest,
    /// Exact number of retained original transport bytes.
    pub original_bytes: u64,
    /// Exact number of reconstructed elementary bytes.
    pub elementary_bytes: u64,
    /// Physical framing committed by the original-source extraction receipt.
    pub framing: TsFraming,
    /// Video codec declared by the selected PMT and routed to the native splitter.
    pub codec: VideoCodec,
    /// Selected PAT program number.
    pub program: u16,
    /// Selected elementary video PID.
    pub video_pid: u16,
    /// Native Annex-B access units, independent of PES packet count.
    pub segments: usize,
    /// Unknown capture time or an explicit operator assumption; never TS PTS/DTS.
    pub capture_time_label: &'static str,
    /// Exact existing completion was revalidated without new writes.
    pub reused: bool,
}

/// Import one explicitly named finite MPEG-TS file through existing file I/O authority.
/// Whole-call work, packet, PES, source-map, split and byte budgets never refill per segment.
/// Work uses conservative reservations for requested I/O and native/preparation/publication
/// passes, not an instruction count. Short, failed and EOF reads do not refund their debit.
pub fn import_mpeg_ts_file(
    destination: &mut ReferenceDeployment,
    request: &MpegTsImportRequest,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<MpegTsImportReceipt, MpegTsImportError> {
    guard(destination, cx)?;
    request.validate()?;
    let bound = destination
        .limits()
        .spool_object_max_bytes
        .min(destination.publisher().spool().limits().max_object_bytes as u64);
    if request.file.limits.chunk_bytes > bound {
        return Err(MpegTsImportError::Invalid(
            "chunk exceeds spool object bound",
        ));
    }
    let maximum = request
        .file
        .limits
        .max_file_bytes
        .min(request.transport_limits.max_input_bytes as u64);
    let metadata = fs::symlink_metadata(&request.file.path).map_err(FileIngestError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(FileIngestError::SymlinkNotAllowed {
            path: request.file.path.clone(),
        }
        .into());
    }
    if !metadata.file_type().is_file() {
        return Err(FileIngestError::NotRegularFile {
            path: request.file.path.clone(),
        }
        .into());
    }
    if metadata.len() == 0 {
        return Err(FileIngestError::EmptyFile {
            path: request.file.path.clone(),
        }
        .into());
    }
    if metadata.len() > maximum {
        return Err(FileIngestError::FileTooLarge {
            path: request.file.path.clone(),
            len: metadata.len(),
            max: maximum,
        }
        .into());
    }
    let file = super::file_adapter::open_admitted_source(cx, &request.file.path, &metadata)?;
    let mut original = Vec::new();
    original
        .try_reserve_exact(metadata.len() as usize)
        .map_err(|_| MpegTsImportError::Invalid("original allocation"))?;
    let mut handle = (&file).take(maximum);
    let mut expected_len = metadata.len();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        guard(destination, cx)?;
        let remaining = maximum - original.len() as u64;
        if remaining == 0 {
            break;
        }
        // The admitted length guides finite reads. At its end, one charged byte probes EOF;
        // observed growth is restatted and stays under the same non-replenishing ceiling.
        let expected_remaining = expected_len.saturating_sub(original.len() as u64);
        let requested = expected_remaining
            .max(1)
            .min(remaining)
            .min(buffer.len() as u64) as usize;
        work.charge(requested as u64).map_err(work_error)?;
        let n = handle
            .read(&mut buffer[..requested])
            .map_err(FileIngestError::Io)?;
        if n == 0 {
            break;
        }
        original.extend_from_slice(&buffer[..n]);
        if n as u64 >= expected_remaining {
            expected_len = file.metadata().map_err(FileIngestError::Io)?.len();
            if expected_len > maximum {
                return Err(FileIngestError::FileTooLarge {
                    path: request.file.path.clone(),
                    len: expected_len,
                    max: maximum,
                }
                .into());
            }
        }
    }
    let current_len = file.metadata().map_err(FileIngestError::Io)?.len();
    if current_len > maximum {
        return Err(FileIngestError::FileTooLarge {
            path: request.file.path.clone(),
            len: current_len,
            max: maximum,
        }
        .into());
    }
    if original.is_empty() {
        return Err(FileIngestError::EmptyFile {
            path: request.file.path.clone(),
        }
        .into());
    }
    guard(destination, cx)?;
    work.charge(original.len() as u64).map_err(work_error)?;
    let video = MpegTsVideo::parse_framed_with_checkpoint(
        &original,
        request.framing,
        request.selection,
        request.transport_limits,
        &mut || checkpoint(cx).map_err(|_| TsError::Cancelled),
    )
    .map_err(MpegTsImportError::Transport)?;
    work.charge(original.len() as u64 + video.elementary_stream().len() as u64)
        .map_err(work_error)?;
    let receipt = TsExtractionReceipt::from_extraction_with_checkpoint(&video, &mut || {
        checkpoint(cx).map_err(|_| TsError::Cancelled)
    })
    .map_err(MpegTsImportError::Transport)?;
    work.charge(video.elementary_stream().len() as u64)
        .map_err(work_error)?;
    let scan = request.scan(&receipt, video.elementary_stream(), cx)?;
    if original
        .len()
        .div_ceil(request.file.limits.chunk_bytes as usize)
        > MAX_OBJECTS
    {
        return Err(MpegTsImportError::Invalid("original chunk count"));
    }
    // Reserve bounded source hashing/copying and native-map metadata work before preparation.
    let metadata_work = (scan.segment_spans.len() as u64 + scan.omission_spans.len() as u64)
        .checked_mul(1024)
        .ok_or(MpegTsImportError::Invalid("metadata work overflow"))?;
    work.charge(original.len() as u64 + metadata_work)
        .map_err(work_error)?;
    let mut payloads = BTreeMap::new();
    let mut original_chunks = Vec::new();
    for bytes in original.chunks(request.file.limits.chunk_bytes as usize) {
        if original_chunks.len() == MAX_OBJECTS {
            return Err(MpegTsImportError::Invalid("original chunk count"));
        }
        checkpoint(cx)?;
        let digest = ContentDigest::sha256(bytes);
        original_chunks.push((digest, bytes.len() as u64));
        payloads.insert(digest, bytes.to_vec());
    }
    let proof = provenance::Proof {
        request: request.clone(),
        receipt,
        original_chunks,
        scan_digest: provenance::scan_digest(
            &scan.segment_spans,
            &scan.omission_spans,
            &scan.capsules,
        ),
    };
    publication::publish(
        destination,
        cx,
        work,
        proof,
        video.into_elementary_stream(),
        scan,
        payloads,
    )
}
