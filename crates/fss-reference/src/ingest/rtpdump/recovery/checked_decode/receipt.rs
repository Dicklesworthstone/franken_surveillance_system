#![forbid(unsafe_code)]
//! Portable, reproducible receipts for custody-checked, privacy-projected RTP pictures.
//! Saved bytes are verified by reproducing the decode and comparing the whole receipt;
//! decoding a serialized claim can never create a successful-decode witness.

use super::{CheckedRetainedRtpH264Decoder, CheckedRtpDecodeError, RtpCustodyDecodeLimits};
use crate::ingest::recorded_decode::h264::h264_decoder_identity;
use crate::ingest::rtpdump::avc::AvcDumpConfig;
use crate::ingest::rtpdump::decode::RtpDecodeRecovery;
use crate::ingest::rtpdump::recovery::decode::{
    RetainedRtpDecodeRequest, RetainedRtpDecodeStats, RetainedRtpDecodeStep, RetainedRtpH264Frame,
};
use crate::ingest::rtpdump::recovery::RecoveredRtpImport;
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_packet::avc::AvcBoundary;
use fss_packet::{H264Mode, RtcpMode};

/// Versioned receipt domain, encoded using the existing canonical encoder.
pub const RTP_FRAME_RECEIPT_DOMAIN: &str = "fss.retained_rtp_h264_frame_receipt.v1";
/// Decoder/receiver recipe domain; excludes process-local ingress and custody-read policy.
pub const RTP_FRAME_RECIPE_DOMAIN: &str = "fss.retained_rtp_h264_frame_recipe.v1";

/// Encoded receipt bounds, independent of source, pixel and custody-read allowances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpFrameReceiptLimits {
    /// Maximum one-receipt encoding, 1 byte..8 MiB.
    pub max_receipt_bytes: usize,
    /// Cumulative encoded bytes, 1 byte..256 MiB; IDR recovery never replenishes it.
    pub max_total_bytes: u64,
}
impl Default for RtpFrameReceiptLimits {
    fn default() -> Self {
        Self {
            max_receipt_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Receipt admission/delivery refusal. No variant contains raw or partially masked media.
#[derive(Debug)]
pub enum RtpFrameReceiptError {
    /// The existing custody/privacy/decoder owner refused delivery.
    Custody(CheckedRtpDecodeError),
    /// Receipt length or cumulative encoding cannot be admitted.
    Limit,
    /// Canonical encoding could not represent the verified frame.
    Encoding,
    /// Supplied saved bytes or expected identity differ from the reproduced receipt.
    Mismatch,
    /// Cancellation occurred before receipted frame delivery.
    Cancelled,
}
impl std::fmt::Display for RtpFrameReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RTP frame receipt refused: {self:?}")
    }
}
impl std::error::Error for RtpFrameReceiptError {}
impl From<CheckedRtpDecodeError> for RtpFrameReceiptError {
    fn from(error: CheckedRtpDecodeError) -> Self {
        Self::Custody(error)
    }
}
type Result<T> = std::result::Result<T, RtpFrameReceiptError>;

/// Canonical source-to-pixels derivation produced only after actual checked frame delivery.
/// It is not a signature, future-custody promise, capability, or absence certificate.
#[derive(Eq, PartialEq)]
pub struct RetainedRtpFrameReceipt {
    bytes: Vec<u8>,
    digest: ContentDigest,
    recipe: ContentDigest,
    planes: [ContentDigest; 4],
}
impl std::fmt::Debug for RetainedRtpFrameReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedRtpFrameReceipt")
            .field("digest", &self.digest)
            .field("recipe", &self.recipe)
            .field("encoded_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl RetainedRtpFrameReceipt {
    /// Exact versioned, network-order canonical bytes, suitable for independent retention.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the complete encoding.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact receiver/decoder interpretation and resource policy used for this attempt.
    pub fn recipe(&self) -> ContentDigest {
        self.recipe
    }
    /// Digests of served masked Y, Cb, Cr and concatenated I420, in that order.
    pub fn plane_digests(&self) -> [ContentDigest; 4] {
        self.planes
    }
    /// Compare an independently retained receipt to this freshly reproduced one.
    /// Both exact bytes and the caller's expected digest must agree; no claim is deserialized.
    pub fn verify_saved(&self, bytes: &[u8], expected: ContentDigest) -> Result<()> {
        if expected != self.digest || bytes != self.bytes.as_slice() {
            return Err(RtpFrameReceiptError::Mismatch);
        }
        Ok(())
    }
}

/// One native progress event, one jointly delivered masked frame/receipt, or final accounting.
#[derive(Debug)]
pub enum ReceiptedRtpDecodeStep {
    /// Original bounded progress and native consequences, with no packet bytes.
    Progress {
        /// Existing payload-free receiver event.
        event: crate::ingest::rtpdump::recovery::decode::RetainedRtpEvent,
        /// Existing native decode consequence.
        effect: crate::ingest::rtpdump::decode::RtpDecodeEffect,
    },
    /// The frame and its receipt become visible together, never before receipt admission.
    Frame {
        /// Existing privacy-projected frame; the raw codec picture is not exposed.
        frame: RetainedRtpH264Frame,
        /// Canonical derivation of exactly this frame, with no process-local identity.
        receipt: RetainedRtpFrameReceipt,
    },
    /// Only jointly delivered frame/receipt pairs are counted as frames.
    Ended(RetainedRtpDecodeStats),
}

/// Owned composition over checked decoding. Failed receipt work discards queued pixel output.
pub struct ReceiptedRetainedRtpH264Decoder<'a> {
    inner: Option<CheckedRetainedRtpH264Decoder<'a>>,
    recipe: ContentDigest,
    source_bytes: u64,
    limits: RtpFrameReceiptLimits,
    used: u64,
    reads: u64,
    steps: usize,
    stats: RetainedRtpDecodeStats,
}
impl RecoveredRtpImport {
    /// Open checked decoding plus portable receipts, without creating files or authority rows.
    pub fn decode_h264_receipted(
        &self,
        request: RetainedRtpDecodeRequest,
        custody: RtpCustodyDecodeLimits,
        receipts: RtpFrameReceiptLimits,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<ReceiptedRetainedRtpH264Decoder<'_>> {
        checkpoint(cx)?;
        if !(1..=8 * 1024 * 1024).contains(&receipts.max_receipt_bytes)
            || !(1..=256 * 1024 * 1024).contains(&receipts.max_total_bytes)
        {
            return Err(RtpFrameReceiptError::Limit);
        }
        let stored = self.recipe.config;
        let config = AvcDumpConfig {
            key: stored.key,
            payload_type: stored.payload_type,
            mode: stored.mode,
            dump: stored.dump,
            receiver: request.receiver,
            rtcp: stored.rtcp,
        };
        let recipe = recipe_digest(config, request)?;
        let inner = self.decode_h264_checked(request, custody, deployment, cx)?;
        let reads = inner.read_bytes();
        Ok(ReceiptedRetainedRtpH264Decoder {
            inner: Some(inner),
            recipe,
            source_bytes: self.report.input_bytes() as u64,
            limits: receipts,
            used: 0,
            reads,
            steps: 0,
            stats: RetainedRtpDecodeStats::default(),
        })
    }
}
impl ReceiptedRetainedRtpH264Decoder<'_> {
    /// Actual jointly delivered output and underlying refusal/skip history.
    pub fn stats(&self) -> RetainedRtpDecodeStats {
        self.stats
    }
    /// Lifetime receipt-byte reservations, retained even if admitted work subsequently fails.
    pub fn receipt_bytes(&self) -> u64 {
        self.used
    }
    /// Existing checked owner's cumulative source-custody cost.
    pub fn read_bytes(&self) -> u64 {
        self.reads
    }
    /// Existing checked owner's cumulative progress calls.
    pub fn steps(&self) -> usize {
        self.steps
    }
    /// One bounded native step or one complete pair. Terminal failure cannot be retried in place.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<ReceiptedRtpDecodeStep> {
        if self.inner.is_none() {
            return Ok(ReceiptedRtpDecodeStep::Ended(self.stats));
        }
        let previous_refusals = self.stats.refusals;
        let result = self.advance(deployment, cx);
        if result.is_err() {
            self.inner = None;
            if self.stats.refusals == previous_refusals {
                self.stats.refusals += 1;
            }
            self.stats.ended = true;
        }
        result
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<ReceiptedRtpDecodeStep> {
        checkpoint(cx)?;
        let delivered = self.stats.frames;
        let inner = self.inner.as_mut().ok_or(RtpFrameReceiptError::Encoding)?;
        let result = inner.step(deployment, cx);
        self.stats = inner.stats();
        self.stats.frames = delivered;
        self.reads = inner.read_bytes();
        self.steps = inner.steps();
        match result? {
            RetainedRtpDecodeStep::Frame(frame) => {
                let size = encoded_size(&frame)?;
                let used = self.used.checked_add(size as u64).ok_or(RtpFrameReceiptError::Limit)?;
                if size > self.limits.max_receipt_bytes || used > self.limits.max_total_bytes {
                    return Err(RtpFrameReceiptError::Limit);
                }
                // Reserve the exact encoding before hashing planes or allocating receipt bytes.
                self.used = used;
                let receipt = seal(&frame, self.recipe, self.source_bytes, size, cx)?;
                checkpoint(cx)?;
                self.stats.frames += 1;
                Ok(ReceiptedRtpDecodeStep::Frame { frame, receipt })
            }
            RetainedRtpDecodeStep::Progress { event, effect } => {
                Ok(ReceiptedRtpDecodeStep::Progress { event, effect })
            }
            RetainedRtpDecodeStep::Ended(_) => {
                self.inner = None;
                Ok(ReceiptedRtpDecodeStep::Ended(self.stats))
            }
        }
    }
}

fn recipe_digest(config: AvcDumpConfig, request: RetainedRtpDecodeRequest) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(RTP_FRAME_RECIPE_DOMAIN);
    e.digest(h264_decoder_identity());
    for parameter in request.parameters {
        e.digest(parameter);
    }
    // Ingress is a process-local authorization handle, not a durable source identity.
    e.u64(config.key.generation);
    e.u32(config.key.ssrc);
    e.u8(config.payload_type);
    e.u8(match config.mode { H264Mode::SingleNal => 0, H264Mode::NonInterleaved => 1 });
    e.u8(match config.rtcp { RtcpMode::Compound => 0, RtcpMode::ReducedSize => 1 });
    let r = config.receiver;
    let d = request.decode;
    for n in [
        config.dump.max_input_bytes, config.dump.max_records, config.dump.max_packet_bytes,
        r.reorder.packet.max_packet_bytes, r.reorder.packet.max_extension_bytes,
        r.reorder.packet.max_rtcp_packets, r.reorder.max_packets, r.reorder.max_bytes,
        r.reconstruction.max_nal_bytes, r.reconstruction.max_packet_nals,
        r.reconstruction.max_fragment_packets, r.syntax.max_nal_bytes,
        r.syntax.max_parameter_set_bytes, r.syntax.max_slice_identity_bits,
        r.assembly.max_nals, r.assembly.max_bytes, d.codec.max_nal_bytes,
        d.max_groups, d.max_source_spans, d.max_decode_calls, d.max_decode_bytes,
        d.max_output_bytes,
    ] {
        e.u64(n as u64);
    }
    for n in [
        r.reorder.max_delay_ns, r.reconstruction.max_pending_age_ns,
        r.syntax.max_luma_samples, r.assembly.max_age_ns, d.codec.max_pictures,
    ] {
        e.u64(n);
    }
    for n in [
        r.syntax.max_width, r.syntax.max_height, r.syntax.max_reference_frames,
        d.codec.max_width, d.codec.max_height, d.codec.max_macroblocks,
        d.codec.max_slices_per_picture, d.codec.max_reference_frames,
    ] {
        e.u32(n);
    }
    e.u8(match d.recovery { RtpDecodeRecovery::Stop => 0, RtpDecodeRecovery::NextIdr => 1 });
    let bytes = e.finish_checked().map_err(|_| RtpFrameReceiptError::Encoding)?;
    Ok(ContentDigest::sha256(&bytes))
}

fn encoded_size(frame: &RetainedRtpH264Frame) -> Result<usize> {
    // Fixed-width canonical fields, plus the three length-prefixed text values.
    let mut size = 8 + RTP_FRAME_RECEIPT_DOMAIN.len() + 4 + 3 * 33 + 8
        + 8 + frame.sensor().as_str().len() + 8 + frame.stream().as_str().len()
        + 8 + 4 + 2 * 33 + 8 + 8 + 4 + 1 + 2 * 16 + 2 * 4 + 33 + 1 + 1 + 4 * 33 + 8;
    if frame.mask().policy_digest().is_some() { size += 33; }
    if frame.mask().generation().is_some() { size += 8; }
    let mut spans = 0_usize;
    if frame.source().nals.len() > 4096 { return Err(RtpFrameReceiptError::Limit); }
    for nal in &frame.source().nals {
        size = size.checked_add(33 + 8).ok_or(RtpFrameReceiptError::Limit)?;
        spans = spans.checked_add(nal.spans.len()).ok_or(RtpFrameReceiptError::Limit)?;
        if spans > 65_536 { return Err(RtpFrameReceiptError::Limit); }
        for span in &nal.spans {
            size = size.checked_add(41 + if span.fragment_header.is_some() { 16 } else { 0 })
                .ok_or(RtpFrameReceiptError::Limit)?;
        }
    }
    Ok(size)
}

fn seal(
    frame: &RetainedRtpH264Frame,
    recipe: ContentDigest,
    source_bytes: u64,
    expected_size: usize,
    cx: &ReplayCx,
) -> Result<RetainedRtpFrameReceipt> {
    let mut i420 = Sha256Hasher::new();
    let mut planes = [ContentDigest::sha256(&[]); 4];
    for (index, plane) in [frame.pixels(), frame.cb(), frame.cr()].into_iter().enumerate() {
        checkpoint(cx)?;
        planes[index] = ContentDigest::sha256(plane);
        i420.update(plane);
    }
    planes[3] = ContentDigest::new(
        DigestAlgorithm::Sha256,
        i420.finalize().map_err(|_| RtpFrameReceiptError::Encoding)?,
    );
    let mut e = CanonicalEncoder::new();
    e.text(RTP_FRAME_RECEIPT_DOMAIN);
    e.u32(1);
    e.digest(recipe);
    e.digest(frame.root());
    e.digest(frame.source().recording);
    e.u64(source_bytes);
    e.text(frame.sensor().as_str());
    e.text(frame.stream().as_str());
    let source = frame.source();
    e.u64(source.key.generation);
    e.u32(source.key.ssrc);
    for parameter in source.parameters { e.digest(parameter); }
    e.u64(source.group as u64);
    e.u64(source.decoder_epoch as u64);
    e.u32(source.timestamp);
    e.u8(match source.boundary {
        AvcBoundary::NextPrimaryPicture => 0,
        AvcBoundary::NextAccessUnitPrefix => 1,
        AvcBoundary::RtpMarker => 2,
        AvcBoundary::EndOfSequence => 3,
        AvcBoundary::EndOfStream => 4,
        AvcBoundary::EndOfInputUnverified => 5,
    });
    e.i128(frame.capture().earliest.0);
    e.i128(frame.capture().latest.0);
    let [width, height] = frame.dimensions();
    e.u32(width);
    e.u32(height);
    e.digest(frame.mask().digest());
    e.bool(frame.mask().policy_digest().is_some());
    if let Some(policy) = frame.mask().policy_digest() { e.digest(policy); }
    e.bool(frame.mask().generation().is_some());
    if let Some(generation) = frame.mask().generation() { e.u64(generation); }
    for plane in planes { e.digest(plane); }
    e.u64(source.nals.len() as u64);
    for nal in &source.nals {
        checkpoint(cx)?;
        e.digest(nal.digest);
        e.u64(nal.spans.len() as u64);
        for span in &nal.spans {
            checkpoint(cx)?;
            e.u64(span.record as u64);
            for range in [&span.wire, &span.nal] {
                e.u64(range.start as u64);
                e.u64(range.end as u64);
            }
            e.bool(span.fragment_header.is_some());
            if let Some(range) = &span.fragment_header {
                e.u64(range.start as u64);
                e.u64(range.end as u64);
            }
        }
    }
    let bytes = e.finish_checked().map_err(|_| RtpFrameReceiptError::Encoding)?;
    if bytes.len() != expected_size { return Err(RtpFrameReceiptError::Encoding); }
    let digest = ContentDigest::sha256(&bytes);
    Ok(RetainedRtpFrameReceipt { bytes, digest, recipe, planes })
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("rtpdump:frame_receipt")
        .map_err(|_| RtpFrameReceiptError::Cancelled)
}
