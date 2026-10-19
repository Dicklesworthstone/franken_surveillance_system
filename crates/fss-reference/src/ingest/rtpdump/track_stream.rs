#![forbid(unsafe_code)]
//! Canonical anonymous trajectory transcripts and independent native replay verification.
//!
//! Every record comes from the current-custody RTP -> decoder -> verified package -> tracker
//! owner. Saved bytes never configure that owner. These portable derivatives are NOT deployment
//! publications, physical identities, absence certificates, or a replacement for original custody.

use std::io::{self, Read, Write};

use super::decode::{RtpDecodeEffect, RtpDecodeError};
use super::recovery::RecoveredRtpImport;
use super::recovery::decode::RetainedRtpEvent;
use super::track::{
    RtpPackageTracker, RtpTrackReset, RtpTrackedFrame, RtpTrackingError, RtpTrackingRequest,
    RtpTrackingStats, RtpTrackingStep,
};
use crate::ingest::rgb_detections::{HeadRowDisposition, RgbDetection};
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::ingest::tracker::TrackStatus;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Sha256Hasher};

/// Versioned, network-order transcript encoding. Existing frame/track identities are unchanged.
pub const RTP_TRACK_STREAM_DOMAIN: &str = "fss.retained_rtp_tracking_stream.v1";
const IO_CHUNK: usize = 4096;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Source-refusal policy is explicit and bound into the transcript, never inferred from EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpTrackStreamCompletion {
    /// Require the native owner's complete source, inference and association result.
    CompleteSource,
    /// Permit a fully enumerated diagnostic transcript with source refusals or skipped groups.
    /// At least one frame must exist; failed inference/tracking, cancellation and budgets still
    /// refuse. The terminal result retains `stats.complete() == false` for incomplete sources.
    SourceDiagnostics,
}

/// Exact native interpretation plus independent transcript allocation, I/O and work ceilings.
#[derive(Clone, Debug)]
pub struct RtpTrackStreamRequest {
    /// Actual decoder, verified detector and anonymous tracking configuration.
    pub tracking: RtpTrackingRequest,
    /// Whether a diagnostic source-refusal history may receive a terminal record.
    pub completion: RtpTrackStreamCompletion,
    /// Total accepted encoding, including header, source progress and terminal (1..=256 MiB).
    pub max_stream_bytes: u64,
    /// Conservative per-frame encoding allocation quote, including the native receipt.
    /// Quoted before allocation; actual output is additionally checked (1..=16 MiB).
    pub max_frame_bytes: usize,
    /// All records, including source-only progress, header and terminal (3..=5,000,002).
    pub max_records: u64,
}
impl RtpTrackStreamRequest {
    /// Strict complete-source export with bounded source progress and 64 MiB total output.
    pub fn new(tracking: RtpTrackingRequest) -> Self {
        Self {
            tracking,
            completion: RtpTrackStreamCompletion::CompleteSource,
            max_stream_bytes: 64 * 1024 * 1024,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_records: 1_000_002,
        }
    }
    fn validate(&self) -> Result<()> {
        if !(1..=256 * 1024 * 1024).contains(&self.max_stream_bytes)
            || !(1..=MAX_FRAME_BYTES).contains(&self.max_frame_bytes)
            || !(3..=5_000_002).contains(&self.max_records)
        {
            return Err(RtpTrackStreamError::Limit);
        }
        Ok(())
    }
}

/// Produced only after complete transcript delivery or exact fresh replay plus final saved EOF.
#[derive(Clone, Debug)]
pub struct RtpTrackStreamSummary {
    /// SHA-256 of all accepted canonical bytes, including terminal accounting.
    pub digest: ContentDigest,
    /// Complete encoded byte count, distinct from source-custody and inference work.
    pub bytes: u64,
    /// Complete record count, including the header and terminal.
    pub records: u64,
    /// Existing tracking interpretation identity.
    pub recipe: ContentDigest,
    /// Existing native frame-receipt interpretation; no process-local ingress is introduced.
    pub native_recipe: ContentDigest,
    /// Actual observed assignments, never coasting predictions.
    pub observations: u64,
    /// Last native linked frame result, not the transcript hash.
    pub last_frame: ContentDigest,
    /// Exact unchanged native, detector and tracker terminal accounting.
    pub stats: RtpTrackingStats,
}

/// No failure certifies a partial transcript or returns a fabricated tracking completion.
#[derive(Debug)]
pub enum RtpTrackStreamError {
    /// The current source/privacy, native inference or association owner refused.
    Tracking(RtpTrackingError),
    /// Source/analysis completeness does not satisfy the explicit completion policy.
    Incomplete(RtpTrackingStats),
    /// A complete next record or its encoding work cannot fit the declared allowances.
    Limit,
    /// Saved bytes, independently supplied digest, or final EOF differ from fresh native work.
    Mismatch,
    /// Payload-free I/O failure. A partial destination must not be treated as a complete stream.
    Io(io::ErrorKind),
    /// Either explicit owner cancelled before another I/O, encoding or delivery boundary.
    Cancelled,
    /// Canonical encoding or native-result linkage was inconsistent.
    Encoding,
}
impl std::fmt::Display for RtpTrackStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tracking(_) => "native trajectory reproduction refused",
            Self::Incomplete(_) => {
                "trajectory transcript is not complete under the selected policy"
            }
            Self::Limit => "trajectory transcript allowance exhausted",
            Self::Mismatch => "saved trajectory transcript does not match native reproduction",
            Self::Io(_) => "trajectory transcript I/O refused",
            Self::Cancelled => "trajectory transcript owner cancelled",
            Self::Encoding => "trajectory transcript encoding refused",
        })
    }
}
impl std::error::Error for RtpTrackStreamError {}
impl From<RtpTrackingError> for RtpTrackStreamError {
    fn from(error: RtpTrackingError) -> Self {
        Self::Tracking(error)
    }
}
impl From<io::Error> for RtpTrackStreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
type Result<T> = std::result::Result<T, RtpTrackStreamError>;

/// Export actual source-witnessed anonymous trajectories. No deployment state is changed.
/// The caller owns file creation, path authority and durable synchronization. The native owner
/// checks current custody before each frame; this is not a future retrievability promise.
pub fn write_tracking_stream(
    retained: &RecoveredRtpImport,
    package: &RgbDetectorPackage,
    request: RtpTrackStreamRequest,
    writer: &mut impl Write,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<RtpTrackStreamSummary> {
    checkpoint(cx, scalar)?;
    request.validate()?;
    let mut owner = RtpPackageTracker::new(
        retained,
        package,
        request.tracking.clone(),
        deployment,
        cx,
        scalar,
    )?;
    let recipe = owner.recipe();
    let mut output = Output::new(writer, request.max_stream_bytes, request.max_records);
    output.record(&header(retained, package, &request, recipe)?, cx, scalar)?;
    let mut previous = None;
    let mut native_recipe = None;
    let mut frames = 0_usize;
    let mut observations = 0_u64;
    loop {
        checkpoint(cx, scalar)?;
        // Refuse before another native step when no record slot remains, not after inference.
        output.admit_record()?;
        match owner.step(deployment, cx, scalar)? {
            RtpTrackingStep::Progress { event, effect } => {
                output.record(&progress(event, &effect)?, cx, scalar)?;
            }
            RtpTrackingStep::Frame(frame) => {
                let native = frame.detected().receipt().recipe();
                if frame.recipe() != recipe
                    || frame.predecessor() != previous
                    || native_recipe.is_some_and(|expected| expected != native)
                    || frame.detected().source().output_index != frames
                {
                    return Err(RtpTrackStreamError::Encoding);
                }
                let bytes = encode_frame(&frame, request.max_frame_bytes, cx, scalar)?;
                output.record(&bytes, cx, scalar)?;
                frames += 1;
                observations = observations
                    .checked_add(frame.observations().len() as u64)
                    .ok_or(RtpTrackStreamError::Limit)?;
                previous = Some(frame.digest());
                native_recipe = Some(native);
            }
            RtpTrackingStep::Ended(stats) => {
                if !terminal_allowed(stats, request.completion) || stats.frames != frames {
                    return Err(RtpTrackStreamError::Incomplete(stats));
                }
                let last_frame = previous.ok_or(RtpTrackStreamError::Encoding)?;
                let native_recipe = native_recipe.ok_or(RtpTrackStreamError::Encoding)?;
                let mut e = CanonicalEncoder::new();
                e.u8(3);
                e.digest(recipe);
                e.digest(native_recipe);
                e.digest(last_frame);
                e.u64(observations);
                e.u64(output.records);
                e.u64(output.used);
                encode_stats(&mut e, stats);
                output.record(&encoded(e)?, cx, scalar)?;
                checkpoint(cx, scalar)?;
                output.writer.flush()?;
                checkpoint(cx, scalar)?;
                return Ok(RtpTrackStreamSummary {
                    digest: ContentDigest::new(
                        DigestAlgorithm::Sha256,
                        output
                            .hash
                            .finalize()
                            .map_err(|_| RtpTrackStreamError::Encoding)?,
                    ),
                    bytes: output.used,
                    records: output.records,
                    recipe,
                    native_recipe,
                    observations,
                    last_frame,
                    stats,
                });
            }
        }
    }
}

/// Re-run original RTP, native decode, verified neural inference and tracking, comparing every
/// byte to the saved transcript. Saved lengths, labels, scores, identities and completion flags
/// are NEVER parsed into authority or allocation sizes. Truncation, reordering, substitution,
/// trailing bytes and a wrong independent digest refuse. This function writes no files.
#[allow(clippy::too_many_arguments)]
pub fn verify_tracking_stream(
    retained: &RecoveredRtpImport,
    package: &RgbDetectorPackage,
    request: RtpTrackStreamRequest,
    saved: &mut impl Read,
    expected: ContentDigest,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<RtpTrackStreamSummary> {
    checkpoint(cx, scalar)?;
    if expected.algorithm() != DigestAlgorithm::Sha256 {
        return Err(RtpTrackStreamError::Mismatch);
    }
    let mut compare = Compare {
        reader: saved,
        cx,
        scalar,
        mismatch: false,
    };
    let result = write_tracking_stream(
        retained,
        package,
        request,
        &mut compare,
        deployment,
        cx,
        scalar,
    );
    checkpoint(cx, scalar)?;
    if compare.mismatch {
        return Err(RtpTrackStreamError::Mismatch);
    }
    let summary = result?;
    if summary.digest != expected || read_once(compare.reader, &mut [0_u8; 1], cx, scalar)? != 0 {
        return Err(RtpTrackStreamError::Mismatch);
    }
    checkpoint(cx, scalar)?;
    Ok(summary)
}

fn terminal_allowed(stats: RtpTrackingStats, completion: RtpTrackStreamCompletion) -> bool {
    stats.frames > 0
        && stats.ended
        && stats.failures == 0
        && stats.detection.ended
        && stats.detection.failures == 0
        && stats.detection.native.ended
        && stats.frames == stats.detection.frames
        && stats.frames == stats.detection.native.frames
        && (stats.complete() || completion == RtpTrackStreamCompletion::SourceDiagnostics)
}
fn header(
    retained: &RecoveredRtpImport,
    package: &RgbDetectorPackage,
    request: &RtpTrackStreamRequest,
    recipe: ContentDigest,
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.u8(0);
    e.text(RTP_TRACK_STREAM_DOMAIN);
    e.u32(1);
    e.digest(retained.root());
    e.digest(package.archive_digest());
    e.digest(package.manifest_digest());
    e.digest(recipe);
    e.u64(request.max_stream_bytes);
    e.u64(request.max_frame_bytes as u64);
    e.u64(request.max_records);
    e.u8(match request.completion {
        RtpTrackStreamCompletion::CompleteSource => 0,
        RtpTrackStreamCompletion::SourceDiagnostics => 1,
    });
    let detection = &request.tracking.detection;
    for parameter in detection.decode.parameters {
        e.digest(parameter);
    }
    // Native receiver/codec bounds are bound by every complete frame receipt. Bind the
    // independent outer admissions too; changing a successful ceiling is not a silent rebase.
    let c = detection.custody;
    let a = detection.analysis;
    for n in [
        c.max_source_bytes as u64,
        c.max_records as u64,
        c.max_object_bytes as u64,
        c.max_read_bytes,
        c.max_steps as u64,
        c.max_graph_objects as u64,
        detection.receipts.max_receipt_bytes as u64,
        detection.receipts.max_total_bytes,
        a.max_frames as u64,
        a.max_color_pixels,
        a.max_preprocess_work,
        a.max_execution_macs,
        a.max_tensor_bytes,
        a.detection_work,
        a.detection_scratch_bytes as u64,
    ] {
        e.u64(n);
    }
    e.u64(request.tracking.class_index as u64);
    e.text("observed-frame-step:not-seconds");
    e.text("full-head-dispositions-and-observations:inference-tensors-digest-only");
    e.text("source-errors-classified:no-debug-or-untrusted-error-text");
    e.bool(false); // Physical identity authority.
    e.bool(false); // Absence certificate.
    e.bool(false); // Effect authority.
    encoded(e)
}
fn progress(event: RetainedRtpEvent, effect: &RtpDecodeEffect) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.u8(1);
    match event {
        RetainedRtpEvent::Record {
            index,
            offset_reversed,
        } => {
            e.u8(0);
            e.u64(index as u64);
            e.bool(offset_reversed);
        }
        RetainedRtpEvent::RecordRefused { index } => {
            e.u8(1);
            e.u64(index as u64);
        }
        RetainedRtpEvent::Progress => e.u8(2),
        RetainedRtpEvent::InputEnded => e.u8(3),
        RetainedRtpEvent::FramingRefused => e.u8(4),
        RetainedRtpEvent::ReceiverRefused => e.u8(5),
        RetainedRtpEvent::ReceiverExhausted => e.u8(6),
    }
    match effect {
        RtpDecodeEffect::None => e.u8(0),
        RtpDecodeEffect::Admitted { group } => {
            e.u8(1);
            e.u64(*group as u64);
        }
        RtpDecodeEffect::WaitingForIdr { group } => {
            e.u8(2);
            e.u64(*group as u64);
        }
        RtpDecodeEffect::Fenced => e.u8(3),
        RtpDecodeEffect::Refused {
            error,
            retired_groups,
            awaiting_idr,
            resumed_group,
        } => {
            e.u8(4);
            e.u8(match error {
                RtpDecodeError::Limit => 0,
                RtpDecodeError::Allocation => 1,
                RtpDecodeError::Replay(_) => 2,
                RtpDecodeError::Codec(_) => 3,
                RtpDecodeError::PictureMapping => 4,
                RtpDecodeError::Discontinuity => 5,
                RtpDecodeError::Cancelled => 6,
            });
            e.u64(*retired_groups as u64);
            e.bool(*awaiting_idr);
            e.bool(resumed_group.is_some());
            if let Some(group) = resumed_group {
                e.u64(*group as u64);
            }
        }
        RtpDecodeEffect::Finished => e.u8(5),
    }
    encoded(e)
}
fn encode_frame(
    frame: &RtpTrackedFrame,
    maximum: usize,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<Vec<u8>> {
    let detected = frame.detected();
    let report = detected.detections();
    // Generous checked upper quote for the fixed fields and bounded variable arrays. No
    // input-provided allocation length is used, and no prefix is written on quote refusal.
    let source = detected.source();
    let mut quote = 4096_usize
        .checked_add(source.sensor.as_str().len())
        .and_then(|n| n.checked_add(source.stream.as_str().len()))
        .and_then(|n| n.checked_add(detected.receipt().bytes().len()))
        .ok_or(RtpTrackStreamError::Limit)?;
    for (count, size) in [
        (report.rows().len(), 32),
        (report.candidates().len(), 96),
        (report.detections().len(), 64),
        (frame.observations().len(), 128),
    ] {
        quote = quote
            .checked_add(count.checked_mul(size).ok_or(RtpTrackStreamError::Limit)?)
            .ok_or(RtpTrackStreamError::Limit)?;
    }
    if quote > maximum {
        return Err(RtpTrackStreamError::Limit);
    }
    checkpoint(cx, scalar)?;
    let mut e = CanonicalEncoder::new();
    e.u8(2);
    for d in [
        frame.recipe(),
        frame.digest(),
        detected.recipe(),
        detected.digest(),
        detected.inference().identity(),
        report.digest(),
        report.contract_digest(),
    ] {
        e.digest(d);
    }
    optional_digest(&mut e, frame.predecessor());
    e.u64(frame.epoch());
    e.u8(match frame.reset() {
        None => 0,
        Some(RtpTrackReset::Baseline) => 1,
        Some(RtpTrackReset::SourceGap) => 2,
        Some(RtpTrackReset::DisplayGap) => 3,
        Some(RtpTrackReset::ProjectionChanged) => 4,
    });
    e.u64(frame.active_tracks() as u64);
    e.u64(frame.deleted_tracks() as u64);
    let s = detected.source();
    e.digest(s.root);
    e.text(s.sensor.as_str());
    e.text(s.stream.as_str());
    e.u64(u64::try_from(s.capture.earliest.0).map_err(|_| RtpTrackStreamError::Encoding)?);
    e.u64(u64::try_from(s.capture.latest.0).map_err(|_| RtpTrackStreamError::Encoding)?);
    e.u32(s.dimensions[0]);
    e.u32(s.dimensions[1]);
    e.u64(s.output_index as u64);
    e.u64(s.group as u64);
    e.u64(s.decoder_epoch as u64);
    e.u32(s.rtp_timestamp);
    e.digest(s.privacy);
    optional_digest(&mut e, s.policy);
    e.digest(detected.receipt().digest());
    e.digest(detected.receipt().recipe());
    e.bytes(detected.receipt().bytes());
    e.u64(report.rows().len() as u64);
    for row in report.rows() {
        checkpoint(cx, scalar)?;
        e.u64(row.row as u64);
        match row.disposition {
            HeadRowDisposition::BelowThreshold => e.u8(0),
            HeadRowDisposition::OutsideImage => e.u8(1),
            HeadRowDisposition::PrivateFootprint => e.u8(2),
            HeadRowDisposition::Candidates(n) => {
                e.u8(3);
                e.u64(n as u64);
            }
        }
    }
    e.u64(report.candidates().len() as u64);
    for candidate in report.candidates() {
        checkpoint(cx, scalar)?;
        encode_detection(&mut e, &candidate.detection);
        e.bool(candidate.suppressed_by.is_some());
        if let Some(index) = candidate.suppressed_by {
            e.u64(index as u64);
        }
    }
    e.u64(report.detections().len() as u64);
    for detection in report.detections() {
        checkpoint(cx, scalar)?;
        encode_detection(&mut e, detection);
    }
    e.u64(frame.observations().len() as u64);
    for observation in frame.observations() {
        checkpoint(cx, scalar)?;
        if observation.detection_index >= report.detections().len() {
            return Err(RtpTrackStreamError::Encoding);
        }
        e.digest(observation.identity);
        e.u64(observation.local_id);
        e.u64(observation.detection_index as u64);
        e.u32(observation.hits);
        e.u8(match observation.status {
            TrackStatus::Tentative => 0,
            TrackStatus::Confirmed => 1,
            TrackStatus::Lost => return Err(RtpTrackStreamError::Encoding),
        });
    }
    let bytes = encoded(e)?;
    if bytes.len() > quote {
        return Err(RtpTrackStreamError::Encoding);
    }
    Ok(bytes)
}
fn encode_detection(e: &mut CanonicalEncoder, d: &RgbDetection) {
    e.u64(d.row() as u64);
    e.u64(d.class_index() as u64);
    e.u32(d.score().to_bits());
    for n in d.bounds() {
        e.u32(n);
    }
    e.bool(d.clipped());
}
fn encode_stats(e: &mut CanonicalEncoder, s: RtpTrackingStats) {
    let d = s.detection;
    let n = d.native;
    for count in [
        s.frames as u64,
        s.assignments_reserved,
        s.assignment_work_reserved,
        s.resets,
        s.failures as u64,
        d.attempts as u64,
        d.frames as u64,
        d.proposals as u64,
        d.failures as u64,
        d.color_pixels,
        d.preprocess_work,
        d.execution_macs,
        d.tensor_bytes,
        d.detection_work,
        d.custody_read_bytes,
        d.receipt_bytes,
        n.records as u64,
        n.frames as u64,
        n.refusals as u64,
        n.skipped_groups as u64,
    ] {
        e.u64(count);
    }
    for flag in [
        s.ended,
        d.ended,
        n.input_ended,
        n.native_finished,
        n.ended,
        s.complete(),
    ] {
        e.bool(flag);
    }
}
fn optional_digest(e: &mut CanonicalEncoder, d: Option<ContentDigest>) {
    e.bool(d.is_some());
    if let Some(d) = d {
        e.digest(d);
    }
}
fn encoded(e: CanonicalEncoder) -> Result<Vec<u8>> {
    e.finish_checked()
        .map_err(|_| RtpTrackStreamError::Encoding)
}
fn checkpoint(cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<()> {
    if cx.checkpoint("rtp_track_stream:checkpoint").is_err()
        || scalar.checkpoint("rtp_track_stream:checkpoint").is_err()
    {
        cx.drain_and_finalize();
        scalar.request_cancellation();
        scalar.drain_and_finalize();
        return Err(RtpTrackStreamError::Cancelled);
    }
    Ok(())
}

struct Output<'a, W> {
    writer: &'a mut W,
    hash: Sha256Hasher,
    used: u64,
    records: u64,
    maximum: u64,
    max_records: u64,
}
impl<'a, W: Write> Output<'a, W> {
    fn new(writer: &'a mut W, maximum: u64, max_records: u64) -> Self {
        Self {
            writer,
            hash: Sha256Hasher::new(),
            used: 0,
            records: 0,
            maximum,
            max_records,
        }
    }
    fn admit_record(&self) -> Result<()> {
        if self.records >= self.max_records || self.used >= self.maximum {
            return Err(RtpTrackStreamError::Limit);
        }
        Ok(())
    }
    fn record(&mut self, bytes: &[u8], cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<()> {
        self.admit_record()?;
        let mut prefix = CanonicalEncoder::new();
        prefix.u64(self.records);
        prefix.u64(bytes.len() as u64);
        let prefix = encoded(prefix)?;
        let size = (prefix.len() as u64)
            .checked_add(bytes.len() as u64)
            .ok_or(RtpTrackStreamError::Limit)?;
        if size > self.maximum.saturating_sub(self.used) {
            return Err(RtpTrackStreamError::Limit);
        }
        self.write(&prefix, cx, scalar)?;
        self.write(bytes, cx, scalar)?;
        self.records += 1;
        Ok(())
    }
    fn write(&mut self, mut bytes: &[u8], cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<()> {
        let mut interruptions = 0;
        while !bytes.is_empty() {
            checkpoint(cx, scalar)?;
            let chunk = &bytes[..bytes.len().min(IO_CHUNK)];
            match self.writer.write(chunk) {
                Ok(0) => return Err(RtpTrackStreamError::Io(io::ErrorKind::WriteZero)),
                Ok(n) if n <= chunk.len() => {
                    self.hash.update(&chunk[..n]);
                    self.used += n as u64;
                    bytes = &bytes[n..];
                    interruptions = 0;
                }
                Ok(_) => return Err(RtpTrackStreamError::Io(io::ErrorKind::InvalidData)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                    interruptions += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
struct Compare<'a, R> {
    reader: &'a mut R,
    cx: &'a ReplayCx,
    scalar: &'a ScalarExecCx,
    mismatch: bool,
}
impl<R: Read> Write for Compare<'_, R> {
    fn write(&mut self, expected: &[u8]) -> io::Result<usize> {
        if self.mismatch {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut buffer = [0_u8; IO_CHUNK];
        let length = expected.len().min(buffer.len());
        let n = read_once(self.reader, &mut buffer[..length], self.cx, self.scalar)?;
        if n == 0 || buffer[..n] != expected[..n] {
            self.mismatch = true;
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn read_once(
    reader: &mut impl Read,
    buffer: &mut [u8],
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> io::Result<usize> {
    for attempt in 0..8 {
        checkpoint(cx, scalar)
            .map_err(|_| io::Error::other("trajectory verification cancelled"))?;
        match reader.read(buffer) {
            Ok(n) if n <= buffer.len() => return Ok(n),
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && attempt < 7 => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::ErrorKind::Interrupted.into())
}
