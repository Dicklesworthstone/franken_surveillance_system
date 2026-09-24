#![forbid(unsafe_code)]
//! Native HTTP MJPEG -> existing RGB neural inference -> anonymous tracks -> zones.
//!
//! Original wire reads keep the camera's custody barrier. The complete mapped JPEG
//! stays owned until its complete neural/temporal result is taken, including after
//! cancellation or revocation. Capture time and availability are independent owner
//! declarations; neither is inferred from HTTP arrival or successful inference.

use super::{
    HttpCamera, HttpCameraAuthority, HttpCameraError, HttpCameraOperation, HttpCameraRetirement,
    HttpCameraStep, HttpCameraTotals, HttpWireRead, HttpWireReceipt,
};
use crate::ScalarExecCx;
use crate::ingest::rgb_detections::RgbDetectionBudget;
use crate::ingest::rgb_detections::pipeline::RgbDetectionInput;
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::ingest::rgb_tracking::RgbFrameAdmission;
use crate::ingest::rgb_tracking::pipeline::{
    RetiredRgbZoneWork, RgbJpegZoneError, RgbJpegZonePipeline, RgbJpegZoneProgress,
    RgbZoneCompletion, RgbZonePhase,
};
use fss_codec_mjpeg::http::{BodyFraming, HttpHeadIdentity};
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Independently selected context for exactly one pending HTTP part. No caller
/// supplies the encoded image: its bytes come only from the acquisition owner.
#[derive(Clone, Copy)]
pub struct HttpRgbContext<'a> {
    /// Expected full response identity, not merely a matching JPEG hash.
    pub expected_head: HttpHeadIdentity,
    /// Exact original MIME part ordinal, never a camera timestamp.
    pub ordinal: u64,
    /// Explicit interpretation of the coded components; no inferred RGB fallback.
    pub interpretation: ComponentInterpretation,
    /// Original coded-grid permission mask; native inference verifies its hash.
    pub allowed: &'a [u8],
    /// Exact source/capture/calibration/mask and independent availability evidence.
    /// Its exposure must equal [`http_rgb_exposure`] for the pending mapped frame.
    pub admission: RgbFrameAdmission,
}
/// Separate caller-owned budgets, none automatically refilled by a frame or retry.
pub struct HttpRgbBudgets<'a, 'cx> {
    /// Native entropy/color reconstruction; not used by resume().
    pub decoder: &'a mut DecodeBudget<'cx>,
    /// Existing complete detector-head projection and suppression.
    pub projection: &'a mut RgbDetectionBudget,
    /// Existing temporal association, zones and owned-output snapshot.
    pub temporal: &'a mut WorkBudget<'cx>,
    /// Exact network-source binding and completion hashing, before stage mutation.
    pub linking: &'a mut WorkBudget<'cx>,
}
/// Source/wrapper refusals never discard previously accepted computation. Inspect
/// processing_result() and phase() after an error; retire() transfers all evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbError {
    /// Existing live source owner refused or fenced its socket.
    Source(HttpCameraError),
    /// Expected head, ordinal, compressed identity or exposure did not match.
    FrameMismatch,
    /// An accepted part must be resumed/taken, not submitted under new context.
    AlreadyAccepted,
    /// No accepted input/result exists for this operation.
    NotReady,
    /// The exact completion acknowledgement names a different result.
    ReceiptMismatch,
    /// Bounded source linking was cancelled or exhausted before computation.
    Work(GeometryError),
    /// An internal owner/result combination is inconsistent; no owner is reset.
    StageInvariant,
}
impl From<HttpCameraError> for HttpRgbError {
    fn from(error: HttpCameraError) -> Self {
        Self::Source(error)
    }
}
impl From<GeometryError> for HttpRgbError {
    fn from(error: GeometryError) -> Self {
        Self::Work(error)
    }
}
impl std::fmt::Display for HttpRgbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP RGB processing refused: {self:?}")
    }
}
impl std::error::Error for HttpRgbError {}

/// Opaque exact completion key. It names a derived computation, not durable
/// custody, a physical identity, corroboration, an event publication or a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbReceipt {
    digest: [u8; 32],
    exposure: [u8; 32],
    ordinal: u64,
    encoded: [u8; 32],
    inference: [u8; 32],
    detections: [u8; 32],
    tracking: [u8; 32],
    zones: [u8; 32],
}
impl HttpRgbReceipt {
    /// Hash of the exact mapped source and four completed computation roots.
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
    /// Source-record identity returned by http_rgb_exposure, not biometric identity.
    pub fn exposure(self) -> [u8; 32] {
        self.exposure
    }
    /// Original response-local part ordinal.
    pub fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Exact original compressed bytes, independent of model output.
    pub fn encoded_sha256(self) -> [u8; 32] {
        self.encoded
    }
    /// Complete neural execution identity, with original source and model bindings.
    pub fn inference(self) -> [u8; 32] {
        self.inference
    }
    /// Complete head projection, including rejected and suppressed candidates.
    pub fn detections(self) -> [u8; 32] {
        self.detections
    }
    /// Existing accepted trajectory receipt, not a person-identity certificate.
    pub fn tracking(self) -> [u8; 32] {
        self.tracking
    }
    /// Existing zone receipt, including observation interruptions and retirements.
    pub fn zones(self) -> [u8; 32] {
        self.zones
    }
}
/// Observed stage at the network backpressure barrier. A processing refusal is
/// distinct from no detections and from source failure. Its typed cause is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbStep {
    /// Existing socket/framing progress, including exact raw-read acknowledgements.
    Source(HttpCameraStep),
    /// A complete mapped JPEG needs independently supplied context.
    AwaitingContext,
    /// Actual inference was accepted; resume only unfinished stages.
    AnalysisPending(RgbZonePhase),
    /// Native processing refused; processing_result() retains the precise error.
    /// Ready permits corrected input retry; every other phase permits only resume.
    AnalysisRefused(RgbZonePhase),
    /// All output is retained until take_result() transfers it together with source.
    ResultReady(HttpRgbReceipt),
}
/// Rejected attachment returns both owners unchanged, not an abandoned socket or
/// discarded inference. The analysis owner may borrow a live temporal episode.
#[must_use]
pub struct HttpRgbAttachRefusal<'model, 'temporal> {
    /// Original acquisition owner, including any pending wire or mapped part.
    pub camera: HttpCamera,
    /// Original neural/temporal owner, including any unfinished work.
    pub processor: RgbJpegZonePipeline<'model, 'temporal>,
}
impl std::fmt::Debug for HttpRgbAttachRefusal<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRgbAttachRefusal")
            .field("camera", &self.camera)
            .field("phase", &self.processor.phase())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HttpRgbAttachRefusal<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HTTP RGB attachment requires fresh acquisition and ready analysis")
    }
}
impl std::error::Error for HttpRgbAttachRefusal<'_, '_> {}

/// Exclusive composition of the existing acquisition and RGB temporal engines.
/// No mutable camera/processor escape, thread, network retry, model download,
/// automatic capture/health claim, or canonical publication is introduced.
pub struct HttpRgbCapture<'model, 'temporal> {
    camera: HttpCamera,
    processor: RgbJpegZonePipeline<'model, 'temporal>,
    exposure: Option<[u8; 32]>,
    complete: Option<HttpRgbReceipt>,
    // ReleaseFrame may be denied after taking the processor's complete output.
    // Keep that output here instead of dropping it or re-running accepted work.
    held: Option<RgbZoneCompletion>,
    processing: Option<Result<RgbJpegZoneProgress, RgbJpegZoneError>>,
    last_taken: Option<HttpRgbReceipt>,
}
impl<'model, 'temporal> HttpRgbCapture<'model, 'temporal> {
    /// Attach without performing I/O or consuming an image. Failure returns owners.
    /// Inline refusal avoids a fallible allocation merely to preserve those owners.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        camera: HttpCamera,
        processor: RgbJpegZonePipeline<'model, 'temporal>,
    ) -> Result<Self, HttpRgbAttachRefusal<'model, 'temporal>> {
        if camera.totals() != HttpCameraTotals::default()
            || camera.failure().is_some()
            || processor.phase() != RgbZonePhase::Ready
        {
            return Err(HttpRgbAttachRefusal { camera, processor });
        }
        Ok(Self {
            camera,
            processor,
            exposure: None,
            complete: None,
            held: None,
            processing: None,
            last_taken: None,
        })
    }
    /// Read-only source counts, failures and original custody/framing state.
    pub fn camera(&self) -> &HttpCamera {
        &self.camera
    }
    /// Exact original mapped JPEG remains held through every accepted stage.
    pub fn frame(&self) -> Option<&HttpJpegFrame> {
        self.camera.pending_frame()
    }
    /// Save/handle these unchanged raw bytes before acknowledging their receipt.
    pub fn pending_wire(&self) -> Option<&HttpWireRead> {
        self.camera.pending_wire()
    }
    /// Delegate exact raw-read custody responsibility to the original owner. A
    /// matching receipt alone is NOT proof that the caller durably stored anything.
    pub fn acknowledge_wire(
        &mut self,
        receipt: HttpWireReceipt,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<(), HttpRgbError> {
        Ok(self.camera.acknowledge_wire(receipt, now, auth)?)
    }
    /// Current accepted analysis only, never a predecessor while acquiring a frame.
    /// All access is read-only; unfinished tensors/reports remain inspectable.
    pub fn analysis(&self) -> Option<&RgbJpegZonePipeline<'model, 'temporal>> {
        self.exposure.map(|_| &self.processor)
    }
    /// Complete owned output, including after a final source-release refusal.
    pub fn completed(&self) -> Option<&RgbZoneCompletion> {
        self.held.as_ref().or_else(|| self.processor.completed())
    }
    /// Stage of the complete composition; held output remains Complete even when
    /// the processor has already transferred it to this wrapper for final release.
    pub fn phase(&self) -> RgbZonePhase {
        if self.held.is_some() {
            RgbZonePhase::Complete
        } else {
            self.processor.phase()
        }
    }
    /// Precise latest native result/error, retained before post-work authority checks.
    pub fn processing_result(&self) -> Option<&Result<RgbJpegZoneProgress, RgbJpegZoneError>> {
        self.processing.as_ref()
    }
    /// Current exact untransferred result; absent is not an empty scene.
    pub fn completion(&self) -> Option<HttpRgbReceipt> {
        self.complete
    }
    /// Explicitly historical key for the last result transferred to the caller.
    pub fn last_taken(&self) -> Option<HttpRgbReceipt> {
        self.last_taken
    }
    /// Run one existing bounded acquisition step unless accepted analysis or output
    /// is pending. Authority is checked even while no network work can advance.
    pub fn step(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        framing: &mut DecodeBudget<'_>,
    ) -> Result<HttpRgbStep, HttpRgbError> {
        if self.exposure.is_some() {
            self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
            return Ok(self.current());
        }
        Ok(match self.camera.step(now, auth, framing)? {
            HttpCameraStep::FrameReady => HttpRgbStep::AwaitingContext,
            step => HttpRgbStep::Source(step),
        })
    }
    /// Run actual RGB computation on the pending network frame, not caller bytes.
    /// A pre-acceptance processing error permits corrected context on this same
    /// frame. After acceptance, only resume/take/retire may advance ownership.
    /// Post-work authority refusal fences acquisition but retains accepted results.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze(
        &mut self,
        context: HttpRgbContext<'_>,
        limits: RgbRunLimits,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        budgets: HttpRgbBudgets<'_, '_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbError> {
        if self.exposure.is_some() {
            return Err(HttpRgbError::AlreadyAccepted);
        }
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        let frame = self
            .camera
            .pending_frame()
            .ok_or(HttpRgbError::FrameMismatch)?;
        let receipt = frame.part().receipt();
        let source = context.admission.source();
        if context.expected_head != frame.head()
            || frame.head().wire != self.camera.route().basis()
            || context.ordinal != receipt.ordinal
            || source.encoded_sha256 != receipt.encoded_sha256
        {
            return Err(HttpRgbError::FrameMismatch);
        }
        let exposure = http_rgb_exposure(frame, budgets.linking)?;
        if source.exposure != exposure {
            return Err(HttpRgbError::FrameMismatch);
        }
        // No wrapper allocation/hash failure can lose accepted temporal work.
        budgets.linking.charge(256)?;
        let result = self.processor.run_jpeg(
            RgbDetectionInput {
                bytes: frame.part().bytes(),
                interpretation: context.interpretation,
                source,
                allowed: context.allowed,
            },
            context.admission,
            limits,
            budgets.decoder,
            budgets.projection,
            budgets.temporal,
            cx,
        );
        self.record(result, exposure, receipt.ordinal, receipt.encoded_sha256);
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        Ok(self.current())
    }
    /// Retry only unfinished native stages; no decoder, JPEG, capture context,
    /// permission mask, or model replacement is accepted by this method.
    pub fn resume(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        projection: &mut RgbDetectionBudget,
        temporal: &mut WorkBudget<'_>,
        linking: &mut WorkBudget<'_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbError> {
        let exposure = self.exposure.ok_or(HttpRgbError::NotReady)?;
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        if self.complete.is_some() {
            return Ok(self.current());
        }
        linking.charge(256)?;
        let receipt = self
            .camera
            .pending_frame()
            .ok_or(HttpRgbError::FrameMismatch)?
            .part()
            .receipt();
        let result = self.processor.resume(projection, temporal, cx);
        self.record(result, exposure, receipt.ordinal, receipt.encoded_sha256);
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        Ok(self.current())
    }
    /// Transfer the complete neural/temporal output and original mapped JPEG
    /// together. Exact receipt matching precedes mutation. No allocation follows
    /// taking either owner. If ReleaseFrame is denied, both remain recoverable.
    pub fn take_result(
        &mut self,
        expected: HttpRgbReceipt,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<HttpRgbOutput, HttpRgbError> {
        let current = self.complete.ok_or(HttpRgbError::NotReady)?;
        if current != expected {
            return Err(HttpRgbError::ReceiptMismatch);
        }
        let frame = self
            .camera
            .pending_frame()
            .ok_or(HttpRgbError::StageInvariant)?;
        if frame.part().receipt().ordinal != expected.ordinal
            || frame.part().receipt().encoded_sha256 != expected.encoded
        {
            return Err(HttpRgbError::StageInvariant);
        }
        self.camera
            .admit(HttpCameraOperation::ReleaseResult, now, auth)?;
        if self.held.is_none() {
            self.held = Some(
                self.processor
                    .take_complete()
                    .ok_or(HttpRgbError::StageInvariant)?,
            );
        }
        // Validate the local transfer slot before the camera can release its frame.
        let analysis = self.held.take().ok_or(HttpRgbError::StageInvariant)?;
        let frame = match self
            .camera
            .take_frame(expected.ordinal, expected.encoded, now, auth)
        {
            Ok(frame) => frame,
            Err(error) => {
                self.held = Some(analysis);
                return Err(error.into());
            }
        };
        self.last_taken = self.complete.take();
        self.exposure = None;
        self.processing = None;
        Ok(HttpRgbOutput {
            receipt: expected,
            frame,
            analysis,
        })
    }
    fn record(
        &mut self,
        result: Result<RgbJpegZoneProgress, RgbJpegZoneError>,
        exposure: [u8; 32],
        ordinal: u64,
        encoded: [u8; 32],
    ) {
        // Some native outer errors occur AFTER inference or tracking accepted.
        // The actual phase, not Result::is_ok(), determines the ownership fence.
        if self.processor.phase() != RgbZonePhase::Ready {
            self.exposure = Some(exposure);
        }
        if let Some(done) = self.processor.completed() {
            self.complete = Some(completion(exposure, ordinal, encoded, done));
        }
        self.processing = Some(result);
    }
    fn current(&self) -> HttpRgbStep {
        if let Some(done) = self.complete {
            return HttpRgbStep::ResultReady(done);
        }
        if matches!(self.processing, Some(Err(_))) {
            return HttpRgbStep::AnalysisRefused(self.phase());
        }
        HttpRgbStep::AnalysisPending(self.phase())
    }
    /// Close without another request and transfer every unfinished original/result.
    /// A borrowed temporal owner is released; any pending zone obligation remains
    /// in that owner. Retirement never asserts completion or authorizes redispatch.
    pub fn retire(self) -> HttpRgbRetirement {
        HttpRgbRetirement {
            source: self.camera.retire(),
            processor: self.processor.retire(),
            exposure: self.exposure,
            complete: self.complete,
            held: self.held,
            processing: self.processing,
            last_taken: self.last_taken,
        }
    }
}
/// Owned final result survives subsequent frames; it is not an automatic disk write.
pub struct HttpRgbOutput {
    receipt: HttpRgbReceipt,
    frame: HttpJpegFrame,
    analysis: RgbZoneCompletion,
}
impl HttpRgbOutput {
    /// Exact source/computation completion key used for the transfer.
    pub fn receipt(&self) -> HttpRgbReceipt {
        self.receipt
    }
    /// Original compressed JPEG, MIME receipt, response identity and wire map.
    pub fn frame(&self) -> &HttpJpegFrame {
        &self.frame
    }
    /// Actual inference, permissions, detections, trajectories, zones and events.
    pub fn analysis(&self) -> &RgbZoneCompletion {
        &self.analysis
    }
    /// Transfer the entire result without a hidden clone, publication or omission.
    pub fn into_parts(self) -> (HttpRgbReceipt, HttpJpegFrame, RgbZoneCompletion) {
        (self.receipt, self.frame, self.analysis)
    }
}
/// Complete recovery ownership. No source bytes or pending computation are dropped.
pub struct HttpRgbRetirement {
    /// Existing camera's originals, framing remainder, counts and terminal reason.
    pub source: HttpCameraRetirement,
    /// Every stage still owned by the existing RGB processor.
    pub processor: RetiredRgbZoneWork,
    /// Exact accepted network exposure, absent before image acceptance.
    pub exposure: Option<[u8; 32]>,
    /// Current untransferred completion key, if computation finished.
    pub complete: Option<HttpRgbReceipt>,
    /// Output already moved from processor when final source release was refused.
    pub held: Option<RgbZoneCompletion>,
    /// Latest precise processing result, including before a late source refusal.
    pub processing: Option<Result<RgbJpegZoneProgress, RgbJpegZoneError>>,
    /// Explicitly historical last transferred key.
    pub last_taken: Option<HttpRgbReceipt>,
}
fn completion(
    exposure: [u8; 32],
    ordinal: u64,
    encoded: [u8; 32],
    done: &RgbZoneCompletion,
) -> HttpRgbReceipt {
    let inference = done.detection_run().inference().identity().bytes();
    let detections = done.detection_run().report().digest().bytes();
    let tracking = done.temporal().tracking_digest();
    let zones = done.temporal().zone_digest();
    let mut bytes = [0_u8; 232];
    let tag = b"fss/http-rgb-completion/1\0";
    bytes[..tag.len()].copy_from_slice(tag);
    bytes[32..64].copy_from_slice(&exposure);
    bytes[64..72].copy_from_slice(&ordinal.to_le_bytes());
    bytes[72..104].copy_from_slice(&encoded);
    for (i, root) in [inference, detections, tracking, zones].iter().enumerate() {
        bytes[104 + i * 32..136 + i * 32].copy_from_slice(root);
    }
    HttpRgbReceipt {
        digest: ContentDigest::sha256(&bytes).bytes(),
        exposure,
        ordinal,
        encoded,
        inference,
        detections,
        tracking,
        zones,
    }
}

/// Derive an exact exposure handle from the original HTTP/MIME identity and full
/// JPEG-to-wire map. This is a source-record identity, not proof of distinct sensor
/// exposures, authenticated camera identity or actual capture time. Replaying the
/// same mapped record gives the same handle; repeated JPEG bytes in other parts do not.
/// Raw-read custody receipts remain the acquisition owner's separate obligations.
pub fn http_rgb_exposure(
    frame: &HttpJpegFrame,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], GeometryError> {
    budget.charge(512 + frame.source_spans().len() as u64 * 128)?;
    let h = frame.head();
    let r = frame.part().receipt();
    let mut bytes = [0_u8; 512];
    let tag = b"fss/http-rgb-source/1\0";
    bytes[..tag.len()].copy_from_slice(tag);
    for (i, id) in [
        h.wire.source,
        h.entity.source,
        h.header_sha256,
        r.content_type_sha256,
        r.encoded_sha256,
        r.headers_sha256,
    ]
    .iter()
    .enumerate()
    {
        bytes[32 + i * 32..64 + i * 32].copy_from_slice(id);
    }
    let (mode, length) = match h.framing {
        BodyFraming::Length(n) => (0, n),
        BodyFraming::Chunked => (1, 0),
        BodyFraming::UntilEof => (2, 0),
    };
    let nums = [
        h.wire.generation,
        h.entity.generation,
        r.ordinal,
        r.opening_range[0],
        r.opening_range[1],
        r.headers_range[0],
        r.headers_range[1],
        r.jpeg_range[0],
        r.jpeg_range[1],
        r.closing_range[0],
        r.closing_range[1],
        u64::from(r.declared_length.is_some()),
        r.declared_length.unwrap_or(0) as u64,
        u64::from(r.closes_entity),
        mode,
        length,
        frame.source_spans().len() as u64,
    ];
    for (i, n) in nums.iter().enumerate() {
        bytes[224 + i * 8..232 + i * 8].copy_from_slice(&n.to_le_bytes());
    }
    let mut digest = ContentDigest::sha256(&bytes).bytes();
    for span in frame.source_spans() {
        let mut record = [0_u8; 80];
        record[..32].copy_from_slice(&digest);
        for (i, n) in [
            span.wire_range[0],
            span.wire_range[1],
            span.jpeg_range[0],
            span.jpeg_range[1],
            u64::from(span.chunk.is_some()),
            span.chunk.unwrap_or(0),
        ]
        .iter()
        .enumerate()
        {
            record[32 + i * 8..40 + i * 8].copy_from_slice(&n.to_le_bytes());
        }
        digest = ContentDigest::sha256(&record).bytes();
    }
    budget.charge(0)?;
    Ok(digest)
}

/// Durable original-wire publication before the native camera parse barrier is released.
pub mod custody;
