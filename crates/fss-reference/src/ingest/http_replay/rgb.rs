#![forbid(unsafe_code)]
//! Exact archived HTTP frames -> existing RGB neural/trajectory/zone owners.
//!
//! Original payload custody is reverified before computation, unfinished-stage
//! resumption and result transfer. Independent capture/mask/availability context
//! is required; replay position never supplies a camera timestamp or health claim.
//! Accepted stages and their original frame stay held across refusal/cancellation.

use super::{HttpReplayAccess, HttpReplayError, HttpReplayPosition, HttpReplayRetirement,
    HttpReplayStep, HttpWireReplay, probe};
use crate::ScalarExecCx;
use crate::ingest::http_archive::HttpWirePin;
use crate::ingest::http_camera::rgb::{HttpRgbBudgets, HttpRgbContext, http_rgb_exposure};
use crate::ingest::rgb_detections::RgbDetectionBudget;
use crate::ingest::rgb_detections::pipeline::RgbDetectionInput;
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::ingest::rgb_tracking::pipeline::{RetiredRgbZoneWork, RgbJpegZoneError,
    RgbJpegZonePipeline, RgbJpegZoneProgress, RgbZoneCompletion, RgbZonePhase};
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_geometry::{GeometryError, WorkBudget};

/// An exact in-process transfer key, not a stored recipe, grant or durable receipt.
/// Its original prefix and all completed stage identities must match together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbReplayReceipt {
    pin: HttpWirePin, exposure: [u8; 32], ordinal: u64, encoded: [u8; 32],
    inference: [u8; 32], detections: [u8; 32], tracking: [u8; 32], zones: [u8; 32],
}
impl HttpRgbReplayReceipt {
    /// Exact archived prefix supplying the frame; not implicit latest-head discovery.
    pub fn pin(self) -> HttpWirePin { self.pin }
    /// The same mapped source identity used by native HTTP RGB acquisition.
    pub fn exposure(self) -> [u8; 32] { self.exposure }
    /// Original response-local part index, not capture time.
    pub fn ordinal(self) -> u64 { self.ordinal }
    /// Original compressed JPEG hash, not an inference digest.
    pub fn encoded_sha256(self) -> [u8; 32] { self.encoded }
    /// Actual existing neural execution identity.
    pub fn inference(self) -> [u8; 32] { self.inference }
    /// Actual complete existing detector-head projection identity.
    pub fn detections(self) -> [u8; 32] { self.detections }
    /// Actual accepted temporal association identity.
    pub fn tracking(self) -> [u8; 32] { self.tracking }
    /// Actual accepted zone update identity; no canonical event publication implied.
    pub fn zones(self) -> [u8; 32] { self.zones }
}
/// Replay framing, required independent context and actual computation are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbReplayStep {
    /// Exact archive/framing progress, including incomplete-prefix termination.
    Source(HttpReplayStep),
    /// A complete mapped original needs capture, permission and availability context.
    AwaitingContext,
    /// Resume only unfinished existing stages; do not supply a replacement JPEG.
    AnalysisPending(RgbZonePhase),
    /// The precise native processing error remains in processing_result().
    AnalysisRefused(RgbZonePhase),
    /// Original frame and complete neural/temporal output remain held together.
    ResultReady(HttpRgbReplayReceipt),
}
/// Refusals never replace a complete observation with an empty-scene result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbReplayError {
    /// Existing source archive/parser/access owner refused.
    Source(HttpReplayError),
    /// Requested source identity, part or independently admitted exposure differs.
    FrameMismatch,
    /// Existing accepted work must be resumed or transferred, not reinterpreted.
    AlreadyAccepted,
    /// There is no accepted source work or complete output for this operation.
    NotReady,
    /// The transfer key names another exact result; no ownership changed.
    ReceiptMismatch,
    /// Caller-owned linking work refused before stage mutation.
    Work(GeometryError),
    /// An inconsistent owner combination was found; neither owner is reset.
    State,
}
impl From<HttpReplayError> for HttpRgbReplayError {
    fn from(error: HttpReplayError) -> Self { Self::Source(error) }
}
impl From<GeometryError> for HttpRgbReplayError {
    fn from(error: GeometryError) -> Self { Self::Work(error) }
}
impl std::fmt::Display for HttpRgbReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "archived HTTP RGB replay refused: {self:?}")
    }
}
impl std::error::Error for HttpRgbReplayError {}

/// Rejected attachment returns both caller-owned values without dropping evidence.
#[must_use]
pub struct HttpRgbReplayAttachRefusal<'archive, 'model, 'temporal> {
    /// Exact unchanged source cursor.
    pub source: HttpWireReplay<'archive>,
    /// Exact unchanged neural/temporal owner.
    pub processor: RgbJpegZonePipeline<'model, 'temporal>,
}
impl std::fmt::Debug for HttpRgbReplayAttachRefusal<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRgbReplayAttachRefusal").field("source_position", &self.source.position())
            .field("phase", &self.processor.phase()).finish_non_exhaustive()
    }
}
/// Exclusive composition with one frame of backpressure through result transfer.
/// No model download, independent tracker, automatic replay restart or effect owner.
pub struct HttpRgbReplay<'archive, 'model, 'temporal> {
    source: HttpWireReplay<'archive>,
    processor: RgbJpegZonePipeline<'model, 'temporal>,
    exposure: Option<[u8; 32]>,
    complete: Option<HttpRgbReplayReceipt>,
    held: Option<RgbZoneCompletion>,
    processing: Option<Result<RgbJpegZoneProgress, RgbJpegZoneError>>,
    last_taken: Option<HttpRgbReplayReceipt>,
}
impl<'archive, 'model, 'temporal> HttpRgbReplay<'archive, 'model, 'temporal> {
    /// Attach a fresh source and ready processor. The caller owns the historical
    /// temporal episode selection; this operation never clears/rebases its state.
    #[allow(clippy::result_large_err)]
    pub fn attach(source: HttpWireReplay<'archive>, processor: RgbJpegZonePipeline<'model, 'temporal>)
        -> Result<Self, HttpRgbReplayAttachRefusal<'archive, 'model, 'temporal>> {
        if source.position() != HttpReplayPosition::default() || source.failure().is_some()
            || processor.phase() != RgbZonePhase::Ready {
            return Err(HttpRgbReplayAttachRefusal { source, processor });
        }
        Ok(Self { source, processor, exposure: None, complete: None, held: None,
            processing: None, last_taken: None })
    }
    /// Read-only exact source progress and original held frame.
    pub fn source(&self) -> &HttpWireReplay<'archive> { &self.source }
    /// Current-frame analysis only; unfinished tensors and reports remain inspectable.
    pub fn analysis(&self) -> Option<&RgbJpegZonePipeline<'model, 'temporal>> {
        self.exposure.map(|_| &self.processor)
    }
    /// Completed output, including after source verification refused final transfer.
    pub fn completed(&self) -> Option<&RgbZoneCompletion> {
        self.held.as_ref().or_else(|| self.processor.completed())
    }
    /// Current phase, including output held after the processor released its copy.
    pub fn phase(&self) -> RgbZonePhase {
        if self.held.is_some() { RgbZonePhase::Complete } else { self.processor.phase() }
    }
    /// Precise processing result retained BEFORE any post-work access checkpoint.
    pub fn processing_result(&self) -> Option<&Result<RgbJpegZoneProgress, RgbJpegZoneError>> {
        self.processing.as_ref()
    }
    /// Exact complete untransferred result key, not evidence of current retrievability.
    pub fn completion(&self) -> Option<HttpRgbReplayReceipt> { self.complete }
    /// Explicitly historical key of the last caller-transferred complete result.
    pub fn last_taken(&self) -> Option<HttpRgbReplayReceipt> { self.last_taken }

    /// One source step. Accepted analysis/result always retains the original frame,
    /// so the existing source owner enforces backpressure without a second cursor.
    pub fn step(&mut self, access: HttpReplayAccess<'_, '_>) -> Result<HttpRgbReplayStep, HttpRgbReplayError> {
        if self.exposure.is_some() && self.source.pending_frame().is_none() {
            return Err(HttpRgbReplayError::State);
        }
        Ok(match self.source.step(access)? {
            HttpReplayStep::FrameReady => self.current(),
            step => HttpRgbReplayStep::Source(step),
        })
    }
    /// Run the existing native RGB decoder/graph/detector/tracker on the archived
    /// pending frame, never caller-supplied pixels or detection boxes. Source proof
    /// and independent admission binding are checked BEFORE any inference is run.
    /// Failed pre-acceptance input can be corrected; accepted input cannot be changed.
    pub fn analyze(&mut self, context: HttpRgbContext<'_>, limits: RgbRunLimits,
        mut access: HttpReplayAccess<'_, '_>, budgets: HttpRgbBudgets<'_, '_>, cx: &ScalarExecCx)
        -> Result<HttpRgbReplayStep, HttpRgbReplayError> {
        probe(access.cancellation)?;
        if self.exposure.is_some() { return Err(HttpRgbReplayError::AlreadyAccepted); }
        let frame = self.source.pending_frame().ok_or(HttpRgbReplayError::FrameMismatch)?;
        let receipt = frame.part().receipt(); let source = context.admission.source();
        if frame.head() != context.expected_head || receipt.ordinal != context.ordinal
            || receipt.encoded_sha256 != source.encoded_sha256 {
            return Err(HttpRgbReplayError::FrameMismatch);
        }
        let exposure = http_rgb_exposure(frame, budgets.linking)?;
        if exposure != source.exposure { return Err(HttpRgbReplayError::FrameMismatch); }
        self.verify(&mut access)?;
        let result = self.processor.run_jpeg(RgbDetectionInput { bytes: frame.part().bytes(),
            interpretation: context.interpretation, source, allowed: context.allowed }, context.admission,
            limits, budgets.decoder, budgets.projection, budgets.temporal, cx);
        self.record(result, exposure, receipt.ordinal, receipt.encoded_sha256);
        probe(access.cancellation)?;
        access.work.charge(0)?;
        Ok(self.current())
    }
    /// Revalidate current original-byte custody, then resume ONLY unfinished native
    /// stages. No replacement image, capture context, model or permission mask enters.
    pub fn resume(&mut self, mut access: HttpReplayAccess<'_, '_>, projection: &mut RgbDetectionBudget,
        temporal: &mut WorkBudget<'_>, cx: &ScalarExecCx) -> Result<HttpRgbReplayStep, HttpRgbReplayError> {
        probe(access.cancellation)?;
        let exposure = self.exposure.ok_or(HttpRgbReplayError::NotReady)?;
        self.verify(&mut access)?;
        if self.complete.is_some() { return Ok(self.current()); }
        let receipt = self.source.pending_frame().ok_or(HttpRgbReplayError::State)?.part().receipt();
        let result = self.processor.resume(projection, temporal, cx);
        self.record(result, exposure, receipt.ordinal, receipt.encoded_sha256);
        probe(access.cancellation)?;
        access.work.charge(0)?;
        Ok(self.current())
    }
    fn verify(&self, access: &mut HttpReplayAccess<'_, '_>) -> Result<(), HttpRgbReplayError> {
        let frame = self.source.pending_frame().ok_or(HttpRgbReplayError::FrameMismatch)?;
        self.source.archive.verify_frame(access.publisher, frame, access.cancellation, access.work)
            .map_err(HttpReplayError::Archive)?;
        Ok(())
    }
    fn record(&mut self, result: Result<RgbJpegZoneProgress, RgbJpegZoneError>,
        exposure: [u8; 32], ordinal: u64, encoded: [u8; 32]) {
        if self.processor.phase() != RgbZonePhase::Ready { self.exposure = Some(exposure); }
        if let Some(done) = self.processor.completed() {
            self.complete = Some(HttpRgbReplayReceipt { pin: self.source.pin(), exposure, ordinal, encoded,
                inference: done.detection_run().inference().identity().bytes(),
                detections: done.detection_run().report().digest().bytes(),
                tracking: done.temporal().tracking_digest(), zones: done.temporal().zone_digest() });
        }
        self.processing = Some(result);
    }
    fn current(&self) -> HttpRgbReplayStep {
        if let Some(receipt) = self.complete { HttpRgbReplayStep::ResultReady(receipt) }
        else if self.processing.as_ref().is_some_and(Result::is_err) {
            HttpRgbReplayStep::AnalysisRefused(self.phase())
        } else if self.exposure.is_some() { HttpRgbReplayStep::AnalysisPending(self.phase()) }
        else { HttpRgbReplayStep::AwaitingContext }
    }
    /// Transfer the original mapped JPEG and complete native analysis together only
    /// after current source verification. Corruption, tombstones, cancellation and
    /// insufficient work leave BOTH owners recoverable. No inference is repeated.
    pub fn take_result(&mut self, expected: HttpRgbReplayReceipt, access: HttpReplayAccess<'_, '_>)
        -> Result<HttpRgbReplayOutput, HttpRgbReplayError> {
        probe(access.cancellation)?;
        if self.complete.ok_or(HttpRgbReplayError::NotReady)? != expected {
            return Err(HttpRgbReplayError::ReceiptMismatch);
        }
        if self.held.is_none() {
            self.held = Some(self.processor.take_complete().ok_or(HttpRgbReplayError::State)?);
        }
        let analysis = self.held.take().ok_or(HttpRgbReplayError::State)?;
        let frame = match self.source.take_frame(expected.ordinal, expected.encoded, access) {
            Ok(frame) => frame,
            Err(error) => { self.held = Some(analysis); return Err(error.into()); }
        };
        self.last_taken = Some(expected); self.complete = None;
        self.exposure = None; self.processing = None;
        Ok(HttpRgbReplayOutput { receipt: expected, frame, analysis })
    }
    /// Transfer every original, incomplete stage and already accepted result without
    /// I/O, source reacquisition, implicit restart, or a fabricated completion claim.
    pub fn retire(self) -> HttpRgbReplayRetirement {
        HttpRgbReplayRetirement { source: self.source.retire(), processor: self.processor.retire(),
            exposure: self.exposure, complete: self.complete, held: self.held,
            processing: self.processing, last_taken: self.last_taken }
    }
}
/// One fully transferred source and native computational result. No event authority.
pub struct HttpRgbReplayOutput {
    receipt: HttpRgbReplayReceipt, frame: HttpJpegFrame, analysis: RgbZoneCompletion,
}
impl HttpRgbReplayOutput {
    /// The exact key that authorized this ownership transfer, not a capability.
    pub fn receipt(&self) -> HttpRgbReplayReceipt { self.receipt }
    /// Unmodified original JPEG and complete HTTP/MIME source map.
    pub fn frame(&self) -> &HttpJpegFrame { &self.frame }
    /// Actual native neural, detector, trajectory and zone records.
    pub fn analysis(&self) -> &RgbZoneCompletion { &self.analysis }
    /// Move all evidence together without hidden clones or new publication.
    pub fn into_parts(self) -> (HttpRgbReplayReceipt, HttpJpegFrame, RgbZoneCompletion) {
        (self.receipt, self.frame, self.analysis)
    }
}
/// Explicit non-success handoff, including after final source-transfer refusal.
#[must_use]
pub struct HttpRgbReplayRetirement {
    /// Exact archived source cursor, original bytes and both parser remainders.
    pub source: HttpReplayRetirement,
    /// Every original native computation stage still held by the processor.
    pub processor: RetiredRgbZoneWork,
    /// Exact accepted exposure, absent before successful inference acceptance.
    pub exposure: Option<[u8; 32]>,
    /// Current complete untransferred result key, when any.
    pub complete: Option<HttpRgbReplayReceipt>,
    /// Analysis already released by the processor before source transfer refused.
    pub held: Option<RgbZoneCompletion>,
    /// Precise last processing result, including before late cancellation.
    pub processing: Option<Result<RgbJpegZoneProgress, RgbJpegZoneError>>,
    /// Explicitly historical last transferred result key.
    pub last_taken: Option<HttpRgbReplayReceipt>,
}
