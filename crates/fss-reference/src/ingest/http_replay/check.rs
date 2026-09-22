#![forbid(unsafe_code)]
//! Bounded operator check over retained originals, native framing and optional full JPEG decode.
//! No filesystem opening, network, publication, model invocation or implicit EOF occurs here.

use super::{HttpReplayAccess, HttpReplayError, HttpReplayLimits, HttpReplayPosition, HttpReplayStep, HttpWireReplay};
use super::completion::{HttpCompletionError, HttpCompletionPin, VerifiedHttpCompletion};
use crate::ingest::http_archive::{HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWirePin, HttpWireScope};
use crate::ingest::http_camera::rgb::http_rgb_exposure;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits};
use fss_codec_mjpeg::http::HttpTermination;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

/// Exact original recording scope, never a camera address or disclosure capability.
#[derive(Clone, Copy, Debug)]
pub struct HttpCheckSource {
    /// Original plaintext-response identity, not inferred from JPEG bytes.
    pub source: ContentDigest,
    /// Original nonzero source generation.
    pub generation: u64,
    /// Original RECEIVE clock identity, not a capture timestamp.
    pub receive_clock: ContentDigest,
    /// Exact original retention decision; not current read permission.
    pub retention_evidence: ContentDigest,
}
impl HttpCheckSource {
    /// Validate and construct the existing source-owner scope without I/O.
    pub fn scope(self) -> Result<HttpWireScope, HttpCheckError> {
        if self.generation == 0 || ![self.source, self.receive_clock, self.retention_evidence].into_iter().all(valid) {
            return Err(HttpCheckError::Configuration);
        }
        Ok(HttpWireScope { stream: StreamBasis { source: self.source.bytes(), generation: self.generation },
            receive_clock: self.receive_clock.bytes(), retention_evidence: self.retention_evidence.bytes() })
    }
}
/// Explicit source component interpretation. No image-content or header guessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCheckDecode {
    /// Check source/framing only, with NO decoded-pixel claim.
    None,
    /// Validate/reconstruct a full grayscale JPEG.
    Grayscale,
    /// Validate all Y/Cb/Cr entropy and reconstruct the full native luma plane.
    YCbCr,
}
/// An exact selection, not permission to read and not a request for latest history.
#[derive(Clone, Copy, Debug)]
pub struct HttpCheckRequest {
    /// Independently selected original clock/retention/source scope.
    pub source: HttpCheckSource,
    /// Exact independently retained final original-read root (or scope for empty).
    pub head: ContentDigest,
    /// Original reads in that exact prefix, not frame count.
    pub reads: u64,
    /// Exact original wire bytes, not decoded or dechunked bytes.
    pub bytes: u64,
    /// Optional independently retained terminal root; never auto-discovered.
    pub completion: Option<ContentDigest>,
    /// Native decoding requested for EVERY emitted frame or not at all.
    pub decode: HttpCheckDecode,
}
impl HttpCheckRequest {
    /// Exact existing archive pin, validated before any source access.
    pub fn pin(self) -> Result<HttpWirePin, HttpCheckError> {
        if !valid(self.head) || self.completion.is_some_and(|d| !valid(d)) {
            return Err(HttpCheckError::Configuration);
        }
        let scope = self.source.scope()?.digest().map_err(HttpCheckError::Archive)?;
        Ok(HttpWirePin { scope, head: self.head, reads: self.reads, bytes: self.bytes })
    }
}
/// Whole-request bounds; none refill at the next frame or resume boundary.
#[derive(Clone, Copy, Debug)]
pub struct HttpCheckLimits {
    /// Complete original read inventory, up to 4096.
    pub maximum_reads: usize,
    /// Complete source prefix, up to 256 MiB.
    pub maximum_source_bytes: u64,
    /// All publisher roots inspected, up to 65536.
    pub maximum_scan_roots: usize,
    /// Actual attached spool's maximum allocation per read, up to 16 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Complete report rows and frame ceiling, up to 4096; never top-k output.
    pub maximum_frames: usize,
    /// Native replay steps, up to one million.
    pub maximum_steps: u64,
    /// Read-buffer size, up to 65536 bytes.
    pub read_bytes: usize,
    /// One complete encoded frame, up to 16 MiB.
    pub maximum_frame_bytes: usize,
    /// Each native decoded dimension, up to 4096.
    pub maximum_dimension: u32,
    /// Native decoded luma samples per frame, up to 4194304.
    pub maximum_pixels: usize,
    /// Entire source read, verification and linking allowance.
    pub source_work: u64,
    /// Entire native HTTP/MIME parse allowance.
    pub framing_work: u64,
    /// Entire native JPEG decode allowance, not per frame.
    pub decode_work: u64,
}
impl Default for HttpCheckLimits {
    fn default() -> Self {
        Self { maximum_reads: 4096, maximum_source_bytes: 256 * 1024 * 1024, maximum_scan_roots: 65536,
            maximum_spool_object_bytes: 16 * 1024 * 1024, maximum_frames: 1024, maximum_steps: 1_000_000,
            read_bytes: 16384, maximum_frame_bytes: 16 * 1024 * 1024, maximum_dimension: 4096,
            maximum_pixels: 4_194_304, source_work: 1_000_000_000_000, framing_work: 1_000_000_000,
            decode_work: 1_000_000_000 }
    }
}
impl HttpCheckLimits {
    /// Validate all operator bounds without opening or reading any source.
    pub fn validate(self) -> Result<(), HttpCheckError> {
        if !(1..=4096).contains(&self.maximum_reads) || !(1..=256 * 1024 * 1024).contains(&self.maximum_source_bytes)
            || !(1..=65536).contains(&self.maximum_scan_roots) || !(1024..=16 * 1024 * 1024).contains(&self.maximum_spool_object_bytes)
            || !(1..=4096).contains(&self.maximum_frames) || !(1..=1_000_000).contains(&self.maximum_steps)
            || !(1..=65536).contains(&self.read_bytes) || !(4..=16 * 1024 * 1024).contains(&self.maximum_frame_bytes)
            || !(1..=4096).contains(&self.maximum_dimension) || !(1..=4_194_304).contains(&self.maximum_pixels)
            || [self.source_work, self.framing_work, self.decode_work].into_iter().any(|n| n > 1_000_000_000_000_000) {
            return Err(HttpCheckError::Configuration);
        }
        Ok(())
    }
}
/// Payload-free exact failure family; previously verified frame rows remain in the report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCheckError {
    /// Invalid independent identity or limits.
    Configuration,
    /// Whole-request step/output limit, never clean EOF.
    Limit,
    /// Live original-byte read/compute authority or deadline refused.
    Cancelled,
    /// Existing source verification refused.
    Archive(HttpArchiveError),
    /// Existing parser/replay refused.
    Replay(HttpReplayError),
    /// Requested completion witness or its current original closure refused.
    Completion(HttpCompletionError),
    /// Exact source frame failed full native decoding.
    Decode { /// Original one-based MIME ordinal.
        ordinal: u64, /// Native codec error, without pixels or metadata.
        error: DecodeError },
    /// Source/linking work exhausted or cancelled.
    Work(GeometryError),
}
impl std::fmt::Display for HttpCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "HTTP recording check refused: {self:?}") }
}
impl std::error::Error for HttpCheckError {}
/// HTTP framing outcome remains separate from a completed operator inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCheckStatus {
    /// All selected frames checked and native HTTP/MIME terminated successfully.
    Complete,
    /// Every pinned byte consumed, but no admissible source-EOF witness was supplied.
    PrefixExhausted,
    /// A typed error stopped the check. Retained frame rows are a verified PREFIX only.
    Refused,
}
/// A fully checked frame; no raw image/header values are included in this projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpCheckedFrame {
    /// Original MIME ordinal.
    pub ordinal: u64,
    /// Exact original compressed bytes.
    pub encoded: ContentDigest,
    /// Complete original HTTP/MIME source-map identity, stable across read sizes.
    pub exposure: ContentDigest,
    /// Exact original compressed length.
    pub bytes: usize,
    /// Complete source-run count, not a truncated map.
    pub source_runs: usize,
    /// Dimensions only after complete native decode; None means not requested.
    pub dimensions: Option<[u32; 2]>,
    /// Native reconstructed luma digest, only after complete decode.
    pub luma: Option<ContentDigest>,
}
/// Inspection result; no publication, source completeness or physical coverage is implied.
#[derive(Debug)]
pub struct HttpCheckReport {
    /// Exact original source prefix that was selected.
    pub pin: HttpWirePin,
    /// Exact requested terminal root, or None. It is not silently guessed.
    pub completion_root: Option<ContentDigest>,
    /// Current framing/check classification.
    pub status: HttpCheckStatus,
    /// Native terminal classification, only after successful finalization.
    pub termination: Option<HttpTermination>,
    /// Explicit requested decode mode.
    pub decode: HttpCheckDecode,
    /// Exact native decoder generation, absent for framing-only checks.
    pub decoder: Option<ContentDigest>,
    /// All successfully checked rows, or their explicit verified prefix on refusal.
    pub frames: Vec<HttpCheckedFrame>,
    /// Ordered commitment to the selected source, decode mode and checked frame rows.
    /// This is a frame-prefix digest, NOT a complete report or success certificate.
    pub frame_chain: ContentDigest,
    /// Exact cause when stopped; no partial result is silently upgraded.
    pub error: Option<HttpCheckError>,
    /// Includes the source of a frame whose subsequent decode/linking failed.
    pub position: HttpReplayPosition,
    /// Actually attempted native replay steps.
    pub steps: u64,
    /// Deterministic reference source units charged, not measured time/energy.
    pub source_work: u64,
    /// Native framing units charged, including unsuccessful work.
    pub framing_work: u64,
    /// Native decode units charged, including unsuccessful work.
    pub decode_work: u64,
}

impl HttpCheckReport {
    /// Stable projection of the native terminal classification, without parser text.
    pub fn termination_name(&self) -> Option<&'static str> {
        self.termination.map(|t| match t {
            HttpTermination::ExplicitFraming => "explicit_framing",
            HttpTermination::CloseDelimitedEof => "close_delimited_eof",
        })
    }
}

/// Verify one exact existing recording and return bounded original-linked results.
/// The caller supplies the authorized store and a LIVE original-media access probe.
/// Preparation errors occur before any frame is checked; later errors return a
/// Refused report containing all earlier verified frames, counts and exact cause.
pub fn check_http_recording(publisher: &LocalRootPublisher, request: HttpCheckRequest,
    limits: HttpCheckLimits, cancel: &dyn PublishCancellation) -> Result<HttpCheckReport, HttpCheckError> {
    limits.validate()?; let pin = request.pin()?; probe(cancel)?;
    let mut work = WorkBudget::new(limits.source_work);
    let mut framing = DecodeBudget::new(limits.framing_work);
    let mut decoding = DecodeBudget::new(limits.decode_work);
    let bounds = HttpArchiveLimits { maximum_reads: limits.maximum_reads, maximum_bytes: limits.maximum_source_bytes,
        maximum_scan_roots: limits.maximum_scan_roots, maximum_spool_object_bytes: limits.maximum_spool_object_bytes };
    let archive = HttpWireArchive::load(publisher, request.source.scope()?, pin, bounds, cancel, &mut work)
        .map_err(HttpCheckError::Archive)?;
    let witness = request.completion.map(|root| VerifiedHttpCompletion::load(publisher, &archive,
        HttpCompletionPin { root, wire: pin }, cancel, &mut work).map_err(HttpCheckError::Completion)).transpose()?;
    let replay_limits = HttpReplayLimits { read_bytes: limits.read_bytes, frames: limits.maximum_frames as u64,
        multipart: fss_codec_mjpeg::multipart::MultipartLimits { frame_bytes: limits.maximum_frame_bytes,
            ..Default::default() }, ..Default::default() };
    let mut replay = HttpWireReplay::new(&archive, pin, replay_limits).map_err(HttpCheckError::Replay)?;
    work.charge((limits.maximum_frames * std::mem::size_of::<HttpCheckedFrame>()) as u64).map_err(HttpCheckError::Work)?;
    let mut frames = Vec::new(); frames.try_reserve_exact(limits.maximum_frames).map_err(|_| HttpCheckError::Limit)?;
    let decoder = (request.decode != HttpCheckDecode::None).then(|| sha(fss_codec_mjpeg::decoder_identity()));
    let mut initial = CanonicalEncoder::new(); initial.text("fss.http_check_frames.v1");
    initial.digest(pin.scope); initial.digest(pin.head); initial.u64(pin.reads); initial.u64(pin.bytes);
    initial.u64(match request.decode { HttpCheckDecode::None => 0, HttpCheckDecode::Grayscale => 1, HttpCheckDecode::YCbCr => 2 });
    if let Some(d) = decoder { initial.digest(d); }
    let mut chain = ContentDigest::sha256(&initial.finish_checked().map_err(|_| HttpCheckError::Limit)?);
    let mut steps = 0;
    let result = (|| -> Result<HttpCheckStatus, HttpCheckError> {
        for _ in 0..limits.maximum_steps {
            probe(cancel)?; steps += 1;
            let mut step = replay.step(HttpReplayAccess { publisher, cancellation: cancel, work: &mut work, framing: &mut framing })
                .map_err(HttpCheckError::Replay)?;
            if step == HttpReplayStep::PrefixExhausted && let Some(proof) = &witness {
                step = replay.finish_completed(proof, HttpReplayAccess { publisher, cancellation: cancel,
                    work: &mut work, framing: &mut framing }).map_err(HttpCheckError::Completion)?;
            }
            match step {
                HttpReplayStep::FrameReady => {
                    let receipt = replay.pending_frame().ok_or(HttpCheckError::Limit)?.part().receipt();
                    let frame = replay.take_frame(receipt.ordinal, receipt.encoded_sha256,
                        HttpReplayAccess { publisher, cancellation: cancel, work: &mut work, framing: &mut framing })
                        .map_err(HttpCheckError::Replay)?;
                    let exposure = sha(http_rgb_exposure(&frame, &mut work).map_err(HttpCheckError::Work)?);
                    probe(cancel)?;
                    let decoded = match request.decode {
                        HttpCheckDecode::None => None,
                        mode => Some(frame.decode(match mode { HttpCheckDecode::Grayscale => ComponentInterpretation::Grayscale,
                                _ => ComponentInterpretation::YCbCr },
                            DecodeLimits { maximum_bytes: limits.maximum_frame_bytes, maximum_dimension: limits.maximum_dimension,
                                maximum_pixels: limits.maximum_pixels, ..Default::default() }, &mut decoding)
                            .map_err(|error| HttpCheckError::Decode { ordinal: receipt.ordinal, error })?),
                    };
                    let row = HttpCheckedFrame { ordinal: receipt.ordinal, encoded: sha(receipt.encoded_sha256), exposure,
                        bytes: frame.part().bytes().len(), source_runs: frame.source_spans().len(),
                        dimensions: decoded.as_ref().map(|image| image.dimensions()),
                        luma: decoded.as_ref().map(|image| sha(image.receipt().luma_sha256)) };
                    work.charge(1024).map_err(HttpCheckError::Work)?;
                    let mut e = CanonicalEncoder::new(); e.digest(chain); e.u64(row.ordinal);
                    e.digest(row.encoded); e.digest(row.exposure); e.u64(row.bytes as u64); e.u64(row.source_runs as u64);
                    if let (Some([w, h]), Some(luma)) = (row.dimensions, row.luma) { e.u64(1); e.u64(u64::from(w)); e.u64(u64::from(h)); e.digest(luma); }
                    else { e.u64(0); }
                    chain = ContentDigest::sha256(&e.finish_checked().map_err(|_| HttpCheckError::Limit)?);
                    frames.push(row); // Preserve completed verification before a late refusal.
                    probe(cancel)?;
                }
                HttpReplayStep::Complete => {
                    if let Some(proof) = &witness {
                        replay.finish_completed(proof, HttpReplayAccess { publisher, cancellation: cancel,
                            work: &mut work, framing: &mut framing }).map_err(HttpCheckError::Completion)?;
                    }
                    probe(cancel)?; return Ok(HttpCheckStatus::Complete);
                }
                HttpReplayStep::PrefixExhausted => return Ok(HttpCheckStatus::PrefixExhausted),
                _ => {},
            }
        }
        Err(HttpCheckError::Limit)
    })();
    let (status, error) = match result { Ok(status) => (status, None), Err(error) => (HttpCheckStatus::Refused, Some(error)) };
    Ok(HttpCheckReport { pin, completion_root: request.completion, status, decode: request.decode, decoder,
        termination: if status == HttpCheckStatus::Complete { replay.completion().map(|c| c.http.termination) } else { None },
        frames, frame_chain: chain, error, position: replay.position(), steps, source_work: work.used(),
        framing_work: framing.used(), decode_work: decoding.used() })
}
fn valid(d: ContentDigest) -> bool { d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32] }
fn sha(bytes: [u8; 32]) -> ContentDigest { ContentDigest::new(DigestAlgorithm::Sha256, bytes) }
fn probe(cancel: &dyn PublishCancellation) -> Result<(), HttpCheckError> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { Err(HttpCheckError::Cancelled) } else { Ok(()) }
}
