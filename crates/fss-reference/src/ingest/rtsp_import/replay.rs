#![forbid(unsafe_code)]
//! Whole-receipt retained imports preserving an explicitly pinned recorder replay request.
//!
//! Every original window and the complete replay companion stay in the destination closure.
//! Requested and acknowledged UTC ranges remain recorder protocol assertions, never capture
//! timestamps or coverage. Source-only HEVC lookahead remains original evidence, not a frame.

mod inspection;
mod provenance;
mod time;

pub use inspection::retained_replay_receipt;
pub use time::{RetainedReplayTimeError, query_retained_replay_time};

pub(crate) use provenance::{
    OriginCache, verify_membership, verify_originals, verify_range_budgeted,
};

use super::provenance::Window;
use super::publication::{PublicationInput, publish_import};
use super::*;
use crate::rtsp::client::replay::ReplayWindow;
use crate::rtsp::recording_catalog::CatalogScope;
use crate::rtsp::recording_replay::{
    MAX_REPLAY_RECEIPT_BYTES, ReplayCodec, ReplayReceipt, ReplayReceiptError, ReplayTermination,
    ReplayWindowProof, decode_retained_receipt,
    storage::{ReceiptVisitor, VerifiedOriginal, load_codec_receipt_visit, revalidate_receipt},
};
use fss_container::demux::{AvcMp4, DemuxError};
use fss_core::CanonicalEncode;
use std::collections::BTreeSet;
use std::ops::Range;

/// Retained-origin profile, distinct from ordinary live recording and catalog imports.
pub const ADAPTER: &str = "ADP-RTSP-REPLAY-ARCHIVE-001";
pub(crate) const GENERATION: &str = "gen:rtsp-replay-archive:v1:";
const EVIDENCE: &str = "native_rtsp_replay:whole_receipt_multifragment_mp4:original_rtp_and_replay_provenance_retained";
const REQUEST_DOMAIN: &str = "fss.rtsp_replay_import_request.v1";
const IDENTITY_DOMAIN: &str = "fss.rtsp_replay_import_identity.v1";
const PROOF_DOMAIN: &str = "fss.rtsp_replay_import.v1";
/// Maximum complete original windows, never a selected prefix of a larger receipt.
pub const MAX_WINDOWS: usize = crate::rtsp::recording_replay::MAX_REPLAY_WINDOWS;
/// Whole-receipt complete sample allowance.
pub const MAX_FRAMES: usize = MAX_WINDOWS * super::MAX_FRAMES;
/// Complete replay companion and every original window, conservatively charged per window.
pub const MAX_ORIGINAL_BYTES: u64 = super::catalog::MAX_ORIGINAL_BYTES;
/// Complete derived movie allowance; never truncates a receipt to fit.
pub const MAX_MEDIA_BYTES: u64 = super::catalog::MAX_MEDIA_BYTES;
/// Bounded canonical retained origin proof.
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Complete cold verification allowance, including the reserved proof envelope.
pub const MAX_REPLAY_READ_BYTES: u64 = MAX_ORIGINAL_BYTES + MAX_PROOF_BYTES as u64;

/// Independent replay pins, explicit time assumptions and cumulative import limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspReplayImportRequest {
    /// Caller-selected native codec; stored data cannot choose a fallback.
    pub codec: RtspImportCodec,
    /// Exact immutable replay companion root, independent of its own stored bytes.
    pub receipt_root: ContentDigest,
    /// Exact independently pinned native replay request identity.
    pub request_identity: ContentDigest,
    /// Complete source, authority, receive-clock, replay decode-clock and timescale binding.
    pub scope: CatalogScope,
    /// Destination ingestion time; never interpreted as historical frame capture time.
    pub receive_time: TimestampNs,
    /// Optional separate owner assumption about the earliest presentation sample.
    /// No requested/acknowledged recorder UTC range supplies this value implicitly.
    pub capture_origin: Option<RtspCaptureOrigin>,
    /// Explicitly admit native decode gaps while retaining their exact sample boundaries.
    pub preserve_decode_gaps: bool,
    /// Cumulative whole-receipt window ceiling.
    pub max_windows: usize,
    /// Cumulative complete-sample ceiling.
    pub max_frames: usize,
    /// Complete companion plus original payload ceiling, at most 128 MiB.
    pub max_original_bytes: u64,
    /// Reconstructed initialization and all fragments, at most 64 MiB.
    pub max_media_bytes: u64,
}
impl RtspReplayImportRequest {
    /// Pure canonical identity of all pins, time assumptions, gap policy and resource bounds.
    pub fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.validate()?;
        let mut out = CanonicalEncoder::new();
        self.encode(&mut out);
        Ok(ContentDigest::sha256(&out.finish_checked()?))
    }
    fn validate(&self) -> Result<(), RtspImportError> {
        if [
            self.receipt_root,
            self.request_identity,
            self.scope.decode_clock,
            self.scope.recording.anchor,
            self.scope.recording.receive_clock,
        ]
        .iter()
        .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
            || self.scope.recording.generation == 0
            || self.scope.time_scale == 0
            || self.receive_time.0 < 0
            || !(1..=MAX_WINDOWS).contains(&self.max_windows)
            || !(1..=MAX_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_ORIGINAL_BYTES).contains(&self.max_original_bytes)
            || !(1..=MAX_MEDIA_BYTES).contains(&self.max_media_bytes)
        {
            return Err(RtspImportError::Invalid("replay scope, time or bounds"));
        }
        if let Some(origin) = self.capture_origin {
            if origin.start_ns.0 < 0
                || origin
                    .start_ns
                    .0
                    .checked_add(i128::from(origin.uncertainty_ns))
                    .is_none()
            {
                return Err(RtspImportError::Invalid("replay capture assumption"));
            }
            FileIngestAdapter::compute_capture_interval(
                0,
                Some(&CaptureHint {
                    start_ns: origin.start_ns,
                    uncertainty_ns: origin.uncertainty_ns,
                    assumed_fps: 1.0,
                }),
                self.receive_time,
            )?;
        }
        Ok(())
    }
    fn encode(&self, out: &mut CanonicalEncoder) {
        out.text(REQUEST_DOMAIN);
        out.text(self.codec.as_str());
        out.digest(self.receipt_root);
        out.digest(self.request_identity);
        let scope = &self.scope.recording;
        out.text(scope.sensor.as_str());
        out.text(scope.stream.as_str());
        out.u64(scope.generation);
        out.digest(scope.anchor);
        out.digest(scope.receive_clock);
        out.digest(self.scope.decode_clock);
        out.u32(self.scope.time_scale);
        out.i128(self.receive_time.0);
        out.bool(self.capture_origin.is_some());
        if let Some(origin) = self.capture_origin {
            out.i128(origin.start_ns.0);
            out.u64(origin.uncertainty_ns);
        }
        out.bool(self.preserve_decode_gaps);
        out.u64(self.max_windows as u64);
        out.u64(self.max_frames as u64);
        out.u64(self.max_original_bytes);
        out.u64(self.max_media_bytes);
    }
    fn identity(&self) -> Result<ContentDigest, RtspImportError> {
        let mut out = CanonicalEncoder::new();
        out.text(IDENTITY_DOMAIN);
        out.digest(self.digest()?);
        Ok(ContentDigest::sha256(&out.finish_checked()?))
    }
    fn replay_codec(&self) -> ReplayCodec {
        match self.codec {
            RtspImportCodec::Avc => ReplayCodec::Avc,
            RtspImportCodec::Hevc => ReplayCodec::Hevc,
        }
    }
    fn time_label(&self) -> &'static str {
        if self.capture_origin.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        }
    }
    fn scan(&self, media: &[u8], cx: &ReplayCx) -> Result<ScannedSegments, FileIngestError> {
        let mut scan = scan_media(
            media,
            self.codec,
            &self.scope.recording,
            self.receive_time,
            self.capture_origin,
            self.max_frames,
            self.max_media_bytes,
            self.identity()
                .map_err(|_| corrupt("replay import identity"))?,
            cx,
        )?;
        if self.preserve_decode_gaps {
            let mut limits = super::super::file_adapter::mp4_demux_limits(self.max_frames);
            limits.maximum_input_bytes = usize::try_from(self.max_media_bytes)
                .map_err(|_| corrupt("replay media ceiling"))?;
            let mut check = || {
                cx.checkpoint(STAGE_RTSP_IMPORT)
                    .map_err(|_| DemuxError::Cancelled)
            };
            let movie = AvcMp4::parse_with_checkpoint(media, None, limits, &mut check)
                .map_err(|refusal| FileIngestError::Mp4Refused { refusal })?;
            if movie.samples().len() != scan.segment_spans.len()
                || scan.capsules.len() != scan.segment_spans.len()
            {
                return Err(corrupt("replay sample count"));
            }
            let mut previous_end = None;
            for (ordinal, sample) in movie.samples().iter().enumerate() {
                checkpoint(cx)?;
                if previous_end.is_some_and(|end| end > sample.decode_time) {
                    return Err(corrupt("overlapping replay decode intervals"));
                }
                let gap = previous_end.is_some_and(|end| end < sample.decode_time);
                if gap && (!sample.sync_sample || !sample.contains_idr) {
                    return Err(corrupt(
                        "replay decode gap must restart at a random-access sample",
                    ));
                }
                scan.segment_spans[ordinal].gap_before = gap;
                scan.capsules[ordinal].gap_before = gap;
                previous_end = Some(
                    sample
                        .decode_time
                        .checked_add(u64::from(sample.duration))
                        .ok_or_else(|| corrupt("replay decode interval overflow"))?,
                );
            }
        }
        Ok(scan)
    }
}

/// Current permission to read this exact complete receipt and retain it at the destination.
pub trait RtspReplayImportAuthority {
    /// Enforce current principal, privacy/retention policy, revocation and deadline.
    fn permit(&self, request: &RtspReplayImportRequest, destination: &ReferenceDeployment) -> bool;
}

/// Completed retained import and its independently pinned historical acquisition provenance.
#[derive(Debug)]
pub struct RtspReplayImportReceipt {
    /// Existing retained-media identity, accepted by native model, review and export owners.
    pub import: RtspImportReceipt,
    /// All complete original windows in the replay receipt.
    pub windows: usize,
    /// Retained replay companion root, including every original source child.
    pub replay_root: ContentDigest,
    /// Original native replay request identity, not the new import approval.
    pub replay_request: ContentDigest,
    /// Original capture approval, including protected ONVIF discovery when present.
    pub replay_approval: ContentDigest,
    /// Exact requested historical range; protocol intent, never a capture-clock witness.
    pub requested_window: ReplayWindow,
    /// Recorder-acknowledged contained range; it does not certify complete retrieval.
    pub acknowledged_window: ReplayWindow,
    /// Canonical protected ONVIF discovery binding, when present; no URI or token text.
    pub onvif_source: Option<ContentDigest>,
    /// Native decode-time hull; it makes no physical capture or coverage claim.
    pub decode_interval: Range<u64>,
    /// Explicit native decode gaps, never collapsed by concatenating windows.
    pub decode_gaps: Vec<Range<u64>>,
    /// Original finite capture stop reason, preserved without upgrading it to retrieval success.
    pub termination: ReplayTermination,
    /// Whether the capture owner settled observed original publication, not interval coverage.
    pub publication_complete: bool,
}

fn gaps(receipt: &ReplayReceipt) -> Vec<Range<u64>> {
    receipt
        .windows()
        .windows(2)
        .filter_map(|pair| {
            let start = pair[0].decode_interval().end;
            let end = pair[1].decode_interval().start;
            (start < end).then_some(start..end)
        })
        .collect()
}
fn gap_indices(receipt: &ReplayReceipt) -> Result<BTreeSet<usize>, FileIngestError> {
    let mut indices = BTreeSet::new();
    let mut samples = 0usize;
    let mut previous = None;
    for window in receipt.windows() {
        let interval = window.decode_interval();
        if previous.is_some_and(|end| end > interval.start) {
            return Err(corrupt("replay windows overlap"));
        }
        if previous.is_some_and(|end| end < interval.start) {
            indices.insert(samples);
        }
        samples = samples
            .checked_add(window.samples())
            .ok_or_else(|| corrupt("replay samples overflow"))?;
        previous = Some(interval.end);
    }
    Ok(indices)
}
fn admit(
    request: &RtspReplayImportRequest,
    receipt: &ReplayReceipt,
) -> Result<(), FileIngestError> {
    request
        .validate()
        .map_err(|_| corrupt("replay import request"))?;
    if receipt.request().codec() != request.replay_codec()
        || receipt.scope() != &request.scope
        || receipt.root() != request.receipt_root
        || receipt.request().digest() != request.request_identity
        || receipt.windows().is_empty()
        || receipt.windows().len() > request.max_windows
    {
        return Err(corrupt("complete replay selection or pins"));
    }
    let frames = receipt
        .windows()
        .iter()
        .try_fold(0usize, |n, w| n.checked_add(w.samples()))
        .ok_or_else(|| corrupt("replay sample total overflow"))?;
    let original = receipt
        .windows()
        .iter()
        .try_fold(receipt.byte_len() as u64, |n, w| {
            n.checked_add(w.byte_len() as u64)
        })
        .ok_or_else(|| corrupt("replay original total overflow"))?;
    if frames == 0
        || frames > request.max_frames
        || original > request.max_original_bytes
        || (!request.preserve_decode_gaps && !gaps(receipt).is_empty())
    {
        return Err(corrupt("complete replay bounds or unapproved decode gap"));
    }
    // Upper-bound every later proof allocation from the metadata before reading any original.
    let maximum = MAX_REPLAY_RECEIPT_BYTES
        .checked_add(receipt.windows().len() * (8 + 4096 + 4 * 41))
        .and_then(|n| n.checked_add(frames * 81 + 4096 * (24 + 256) + 8192))
        .ok_or_else(|| corrupt("replay proof bound overflow"))?;
    if maximum > MAX_PROOF_BYTES {
        return Err(corrupt("replay proof envelope"));
    }
    Ok(())
}
fn verify_scan(
    request: &RtspReplayImportRequest,
    receipt: &ReplayReceipt,
    scan: &ScannedSegments,
) -> Result<(), FileIngestError> {
    admit(request, receipt)?;
    let indices = gap_indices(receipt)?;
    let frames: usize = receipt.windows().iter().map(|w| w.samples()).sum();
    if scan.truncated_frames != 0
        || scan.capsules.len() != frames
        || scan.segment_spans.len() != frames
        || scan
            .omission_spans
            .iter()
            .any(|o| !o.is_container_structure())
        || scan
            .segment_spans
            .iter()
            .zip(&scan.capsules)
            .enumerate()
            .any(|(i, (s, c))| {
                s.gap_before != indices.contains(&i) || c.gap_before != indices.contains(&i)
            })
    {
        return Err(corrupt("complete replay native sample map"));
    }
    Ok(())
}

struct Access<'a> {
    request: &'a RtspReplayImportRequest,
    destination: &'a ReferenceDeployment,
    authority: &'a dyn RtspReplayImportAuthority,
    cx: &'a ReplayCx,
}
impl Access<'_> {
    fn check(&self) -> Result<(), RtspImportError> {
        checkpoint(self.cx)?;
        if !self.authority.permit(self.request, self.destination) {
            return Err(RtspImportError::Denied);
        }
        Ok(())
    }
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.check().is_err()
    }
}

struct Collector<'a, 'work> {
    request: &'a RtspReplayImportRequest,
    work: &'a mut WorkBudget<'work>,
    media: Vec<u8>,
    windows: Vec<provenance::WindowReference>,
    payloads: BTreeMap<ContentDigest, Vec<u8>>,
    initialization: Option<ContentDigest>,
    failure: Option<RtspImportError>,
}
impl Collector<'_, '_> {
    fn admit(&mut self, receipt: &ReplayReceipt) -> Result<(), RtspImportError> {
        admit(self.request, receipt)?;
        // The native verifier caps the complete root/source/index/init/media to 32 MiB
        // before each read. Reserve that full envelope for every original before I/O.
        self.work
            .charge(
                (receipt.windows().len() as u64)
                    .checked_mul(super::MAX_ORIGINAL_BYTES)
                    .ok_or(RtspImportError::Invalid("replay native work overflow"))?,
            )
            .map_err(source_error)?;
        self.payloads
            .insert(receipt.root(), receipt.manifest().canonical_bytes());
        self.payloads.insert(
            ContentDigest::sha256(receipt.metadata_bytes()),
            receipt.metadata_bytes().to_vec(),
        );
        Ok(())
    }
    fn original(
        &mut self,
        ordinal: usize,
        descriptor: &ReplayWindowProof,
        original: VerifiedOriginal<'_>,
    ) -> Result<(), RtspImportError> {
        if ordinal != self.windows.len() || ordinal >= self.request.max_windows {
            return Err(RtspImportError::Invalid("replay original order"));
        }
        let single = RtspImportRequest {
            codec: self.request.codec,
            slot: descriptor.slot().clone(),
            root: descriptor.root(),
            source: self.request.scope.recording.clone(),
            receive_time: self.request.receive_time,
            capture_origin: None,
            max_frames: super::MAX_FRAMES,
            max_original_bytes: super::MAX_ORIGINAL_BYTES,
            max_media_bytes: super::MAX_MEDIA_BYTES,
        };
        let window = match original {
            VerifiedOriginal::Avc(plan) => Window::from_verified(plan, &single)?,
            VerifiedOriginal::Hevc(plan) => {
                Window::from_verified(plan.publication_plan(), &single)?
            }
        };
        let initialization = ContentDigest::sha256(&window.initialization);
        match self.initialization {
            Some(previous) if previous != initialization => {
                return Err(RtspImportError::Invalid(
                    "replay changes decoder initialization",
                ));
            }
            None => {
                super::catalog::append_media(
                    &mut self.media,
                    &window.initialization,
                    self.request.max_media_bytes,
                )?;
                self.initialization = Some(initialization);
            }
            _ => {}
        }
        super::catalog::append_fragment(
            &mut self.media,
            &window.fragment,
            ordinal,
            self.request.max_media_bytes,
        )?;
        self.windows.push(provenance::WindowReference::new(&window));
        for (digest, bytes) in window.payloads() {
            self.payloads.insert(digest, bytes.to_vec());
        }
        Ok(())
    }
    fn convert(&mut self, result: Result<(), RtspImportError>) -> Result<(), ReplayReceiptError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.failure = Some(error);
                Err(ReplayReceiptError::Limit)
            }
        }
    }
}
impl ReceiptVisitor for Collector<'_, '_> {
    fn admit_receipt(&mut self, receipt: &ReplayReceipt) -> Result<(), ReplayReceiptError> {
        let result = self.admit(receipt);
        self.convert(result)
    }
    fn original(
        &mut self,
        ordinal: usize,
        descriptor: &ReplayWindowProof,
        original: VerifiedOriginal<'_>,
    ) -> Result<(), ReplayReceiptError> {
        let result = self.original(ordinal, descriptor, original);
        self.convert(result)
    }
}

/// Import every original in one exact replay receipt through the native verifier and root-last owner.
/// No destination staging starts until the full companion/source closure and sample map pass.
/// Fresh source/cancellation/authority checks also apply to an exact idempotent retry.
pub fn import_rtsp_replay(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &RtspReplayImportRequest,
    authority: &dyn RtspReplayImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspReplayImportReceipt, RtspImportError> {
    request.validate()?;
    if cx.root_dir() != destination.root()
        || publisher.root_dir().starts_with(destination.root())
        || destination.root().starts_with(publisher.root_dir())
    {
        return Err(RtspImportError::Invalid(
            "distinct source and destination owners required",
        ));
    }
    let access = Access {
        request,
        destination,
        authority,
        cx,
    };
    access.check()?;
    work.charge((2 * MAX_REPLAY_RECEIPT_BYTES) as u64)
        .map_err(source_error)?;
    let mut collector = Collector {
        request,
        work,
        media: Vec::new(),
        windows: Vec::new(),
        payloads: BTreeMap::new(),
        initialization: None,
        failure: None,
    };
    let receipt = load_codec_receipt_visit(
        publisher,
        request.replay_codec(),
        request.receipt_root,
        &request.scope,
        request.request_identity,
        &access,
        &mut collector,
    );
    if let Some(error) = collector.failure.take() {
        return Err(error);
    }
    access.check()?;
    let receipt = receipt.map_err(source_error)?;
    let Collector {
        media,
        windows,
        payloads,
        ..
    } = collector;
    work.charge(
        (media.len() as u64).saturating_mul(if request.preserve_decode_gaps { 3 } else { 2 }),
    )
    .map_err(source_error)?;
    let scan = request.scan(&media, cx)?;
    verify_scan(request, &receipt, &scan)?;
    let frames = scan.capsules.len();
    let proof = provenance::Proof::new(request.clone(), &receipt, windows, &media, &scan)?;
    let first = receipt
        .windows()
        .first()
        .ok_or(RtspImportError::Invalid("empty replay"))?;
    let last = receipt
        .windows()
        .last()
        .ok_or(RtspImportError::Invalid("empty replay"))?;
    let interval = first.decode_interval().start..last.decode_interval().end;
    let input = PublicationInput {
        identity: request.identity()?,
        limits_digest: request.digest()?,
        codec: request.codec,
        adapter: ADAPTER,
        generation: GENERATION,
        detector_evidence: EVIDENCE,
        capture_time_label: request.time_label(),
        frames,
        proof: proof.encode()?,
    };
    let onvif_source = receipt
        .request()
        .onvif_source()
        .map(|source| source.digest())
        .transpose()
        .map_err(source_error)?;
    drop(access);
    let import = publish_import(
        destination,
        cx,
        work,
        input,
        media,
        scan,
        payloads,
        &|current| {
            checkpoint(cx)?;
            let access = Access {
                request,
                destination: current,
                authority,
                cx,
            };
            access.check()?;
            revalidate_receipt(publisher, &receipt, &access).map_err(source_error)
        },
    )?;
    Ok(RtspReplayImportReceipt {
        import,
        windows: receipt.windows().len(),
        replay_root: receipt.root(),
        replay_request: receipt.request().digest(),
        replay_approval: receipt.approval(),
        requested_window: receipt.request().window(),
        acknowledged_window: receipt.acceptance().acknowledged(),
        onvif_source,
        decode_interval: interval,
        decode_gaps: gaps(&receipt),
        termination: receipt.termination(),
        publication_complete: receipt.publication_complete(),
    })
}
