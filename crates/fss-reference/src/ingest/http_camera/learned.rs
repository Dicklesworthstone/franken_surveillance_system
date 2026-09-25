#![forbid(unsafe_code)]
//! Native HTTP acquisition -> the existing JPEG/HOG/tracking/zone owner.
//! Raw wire and complete mapped frames stay behind the acquisition barrier until
//! their caller handles them. Capture intervals are supplied independently, never
//! synthesized from network arrival, part ordinals or uninterpreted MIME headers.
//!
//! Every frame is decoded under the named sensor's *current* retained privacy mask
//! ([`crate::ingest::privacy_mask::live`]): masked luma is filled before screening, foreground,
//! the learned scan, tracking, zones or any decoded-plane digest; the owner permission grid and
//! every background reference must already exclude/mask the same pixels, or the frame is refused
//! as unmasked access. A policy retained mid-capture applies from the next analysed frame.

use super::{
    HttpCamera, HttpCameraAuthority, HttpCameraError, HttpCameraOperation, HttpCameraRetirement,
    HttpCameraStep, HttpWireRead, HttpWireReceipt,
};
use crate::ingest::privacy_mask::MaskBinding;
use crate::ingest::privacy_mask::live::{MaskRefusal, SensorMask};
use fss_codec_mjpeg::http::{BodyFraming, HttpHeadIdentity};
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame, HttpMjpegEnd};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::ForegroundPolicy;
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::mjpeg::{JpegBackground, JpegFrameBinding};
use fss_twin::rectification::RectificationPlan;
use fss_twin::screened_mjpeg::JpegScreeningQuery;
use fss_twin::screening::tracking::hog::jpeg::{
    JpegHogCompletion, JpegHogError, JpegHogPipeline, JpegHogProgress, JpegHogStage,
};
use fss_twin::screening::{ScreeningStamp, StallObservation};

/// Owner-supplied, independently source-bound interpretation of the pending part.
/// A digest proves linkage, not the correctness of capture-clock/calibration claims.
#[derive(Clone, Copy)]
pub struct HttpFrameContext<'a> {
    /// Independently expected response identity, not just matching compressed bytes.
    pub expected_head: HttpHeadIdentity,
    /// Original coded-grid 0/1 permission mask, verified by native image processing.
    pub mask: &'a [u8],
    /// Exact compressed hash, exposure, mask, image-domain and calibration bindings.
    pub binding: JpegFrameBinding,
    /// Actual independently established camera capture interval and clock generation.
    pub capture: FrameCapture,
    /// Explicit frozen-background comparison assumptions.
    pub foreground_policy: ForegroundPolicy,
    /// Narrowable native JPEG limits.
    pub decode_limits: DecodeLimits,
    /// Original part ordinal MUST equal sequence; generation MUST equal the wire
    /// generation. Receive time is separate from capture time and is not fabricated.
    pub stamp: ScreeningStamp,
    /// The sensor this stream belongs to; its current retained privacy mask is applied.
    pub privacy: SensorMask<'a>,
}
/// Separate owner-controlled allowances. Share an owner cancellation flag across
/// them. None of these budgets refills automatically when a new part arrives.
pub struct HttpHogBudgets<'a, 'cx> {
    /// Complete native JPEG entropy and pixel reconstruction.
    pub decode: &'a mut DecodeBudget<'cx>,
    /// Source-link hashing and native rectification.
    pub rectification: &'a mut WorkBudget<'cx>,
    /// Frozen-background comparison.
    pub foreground: &'a mut WorkBudget<'cx>,
    /// Independent source/image health checks.
    pub health: &'a mut WorkBudget<'cx>,
    /// Actual learned multiscale inference.
    pub inference: &'a mut WorkBudget<'cx>,
    /// Existing tracking and zone derivation.
    pub downstream: &'a mut WorkBudget<'cx>,
}
/// Refusals never discard a network frame or an accepted image/scan/trajectory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpHogError {
    /// Source/lease/current-authority boundary refused. The socket is fenced on
    /// terminal source failures; retire() still transfers every owned result.
    Source(HttpCameraError),
    /// No complete HTTP frame is pending, or caller head/hash/sequence does not match.
    FrameMismatch,
    /// This frame was already accepted; use resume(), not another interpretation.
    AlreadyAccepted,
    /// There is no accepted image to resume, or no completed result to acknowledge.
    NotReady,
    /// Exact completion acknowledgement does not name the current result.
    ReceiptMismatch,
    /// Bounded source-link work refused before image or resume advancement.
    Work(GeometryError),
    /// Existing image/analysis owner refused before accepting a new image, or its
    /// resume call refused. Accepted state remains available through analysis().
    Processing(JpegHogError),
    /// The sensor's privacy mask refused the frame before acceptance: the permission grid or a
    /// background reference admits masked pixels, the mask could not be resolved, or the
    /// decoded resolution differs from the policy's. A corrected retry is permitted.
    Privacy(MaskRefusal),
}
impl From<HttpCameraError> for HttpHogError {
    fn from(e: HttpCameraError) -> Self {
        Self::Source(e)
    }
}
impl std::fmt::Display for HttpHogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP learned processing refused: {self:?}")
    }
}
impl std::error::Error for HttpHogError {}
/// Compound result constructed only after this exact network frame completed the
/// existing processor. It is a derivation receipt, not a canonical event or grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHogCompletion {
    digest: [u8; 32],
    source: [u8; 32],
    ordinal: u64,
    encoded: [u8; 32],
    analysis: JpegHogCompletion,
    mask_policy: Option<ContentDigest>,
    mask_generation: Option<u64>,
}
impl HttpHogCompletion {
    /// Binds the original HTTP/MIME/wire maps and all four completed analysis roots, and the
    /// applied privacy mask policy when one applied (unchanged bytes without a policy).
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
    /// Privacy mask policy applied to this frame's decoded plane, or `None`: the explicit
    /// no-policy marker (the sensor had no retained policy when this frame was decoded).
    pub fn mask_policy(self) -> Option<ContentDigest> {
        self.mask_policy
    }
    /// Ledger generation of the applied policy, if any.
    pub fn mask_generation(self) -> Option<u64> {
        self.mask_generation
    }
    /// Complete HTTP/MIME/source-span identity, independent of model output.
    pub fn source_digest(self) -> [u8; 32] {
        self.source
    }
    /// Original MIME part ordinal, never a camera timestamp or track identifier.
    pub fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Exact unchanged compressed image identity.
    pub fn encoded_sha256(self) -> [u8; 32] {
        self.encoded
    }
    /// Existing image/scan/tracking/zone computation roots, with no implied custody.
    pub fn analysis(self) -> JpegHogCompletion {
        self.analysis
    }
}
/// Progress at the outer ownership barrier. Network processing does not implicitly
/// choose a model, infer capture time, accept result custody, or publish an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpHogStep {
    /// Underlying bounded socket/framing step, including raw-read acknowledgement.
    Source(HttpCameraStep),
    /// Complete frame requires an independently bound HttpFrameContext.
    AwaitingContext,
    /// An upstream stage accepted this part. Only resume() may advance it now.
    AnalysisPending(JpegHogStage),
    /// Every analysis stage completed; save/handle the result then acknowledge it.
    ResultReady(HttpHogCompletion),
}
/// Failed attachment returns both original owners instead of closing a camera and
/// dropping its pending source. Neither owner may already have consumed an image.
#[must_use]
pub struct HttpHogAttachRefusal {
    /// Original acquisition owner, unchanged and still eligible for retirement.
    pub camera: HttpCamera,
    /// Original analysis owner, unchanged.
    pub processor: JpegHogPipeline,
}
impl std::fmt::Debug for HttpHogAttachRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpHogAttachRefusal")
            .field("camera", &self.camera)
            .field("analysis_stage", &self.processor.stage())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HttpHogAttachRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HTTP and learned owners must both be fresh before attachment")
    }
}
impl std::error::Error for HttpHogAttachRefusal {}

/// Exclusive network/analysis composition. No mutable upstream escape is exposed:
/// pending inference, pending zones and an unacknowledged complete result ALL keep
/// the exact HTTP frame in the source owner, preventing another read or overwrite.
pub struct HttpHogCapture {
    camera: HttpCamera,
    processor: JpegHogPipeline,
    source: Option<[u8; 32]>,
    progress: Option<JpegHogProgress>,
    complete: Option<HttpHogCompletion>,
    last_acknowledged: Option<HttpHogCompletion>,
    processing_error: Option<JpegHogError>,
    mask: MaskBinding,
}
impl HttpHogCapture {
    /// Take two fresh owners without connecting, reading or inferring another frame.
    /// Generation mismatch is refused by the exact source/stamp/processor checks
    /// before a new image is accepted. A refusal returns both unchanged owners.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        camera: HttpCamera,
        processor: JpegHogPipeline,
    ) -> Result<Self, HttpHogAttachRefusal> {
        if camera.totals() != super::HttpCameraTotals::default()
            || camera.failure().is_some()
            || processor.stage() != JpegHogStage::AwaitingImage
        {
            return Err(HttpHogAttachRefusal { camera, processor });
        }
        Ok(Self {
            camera,
            processor,
            source: None,
            progress: None,
            complete: None,
            last_acknowledged: None,
            processing_error: None,
            mask: MaskBinding::NoPolicy,
        })
    }
    /// Privacy mask binding the current accepted frame was decoded under (the explicit
    /// no-policy marker before any frame was accepted, or when the sensor has no policy).
    pub fn privacy_mask(&self) -> &MaskBinding {
        &self.mask
    }
    /// Read-only source accounting and retained raw/frame evidence. No read/release bypass.
    pub fn camera(&self) -> &HttpCamera {
        &self.camera
    }
    /// Original complete frame while it awaits context, analysis or acknowledgement.
    pub fn frame(&self) -> Option<&HttpJpegFrame> {
        self.camera.pending_frame()
    }
    /// Original raw socket read, even after failure; caller must save it before ACK.
    pub fn pending_wire(&self) -> Option<&HttpWireRead> {
        self.camera.pending_wire()
    }
    /// Accept the existing exact raw-read custody obligation, without doing storage I/O.
    pub fn acknowledge_wire(
        &mut self,
        receipt: HttpWireReceipt,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<(), HttpHogError> {
        Ok(self.camera.acknowledge_wire(receipt, now, auth)?)
    }
    /// Current accepted analysis only; never exposes the previous frame as current
    /// while a new frame is acquiring or awaiting independent context.
    pub fn analysis(&self) -> Option<&JpegHogPipeline> {
        self.source.map(|_| &self.processor)
    }
    /// Current progress, retaining exact accepted-stage refusal information.
    pub fn analysis_progress(&self) -> Option<JpegHogProgress> {
        self.progress
    }
    /// Current source-linked complete result; no stale predecessor is returned.
    pub fn completion(&self) -> Option<HttpHogCompletion> {
        self.complete
    }
    /// Explicitly historical last acknowledged result, not a current observation.
    pub fn last_acknowledged(&self) -> Option<HttpHogCompletion> {
        self.last_acknowledged
    }
    /// Most recent outer image/resume error. This survives post-work authority refusal.
    pub fn processing_error(&self) -> Option<JpegHogError> {
        self.processing_error
    }
    /// Whole-response termination, separate from every individual analysis completion.
    pub fn source_completion(&self) -> Option<&HttpMjpegEnd> {
        self.camera.completion()
    }

    /// Advance bounded network/framing work only when no accepted analysis awaits
    /// completion/acknowledgement. Even under pressure, recheck current source authority.
    pub fn step(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        framing: &mut DecodeBudget<'_>,
    ) -> Result<HttpHogStep, HttpHogError> {
        if self.source.is_some() {
            self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
            return Ok(self.complete.map_or(
                HttpHogStep::AnalysisPending(self.processor.stage()),
                HttpHogStep::ResultReady,
            ));
        }
        Ok(match self.camera.step(now, auth, framing)? {
            HttpCameraStep::FrameReady => HttpHogStep::AwaitingContext,
            step => HttpHogStep::Source(step),
        })
    }
    /// Compose the actual pending compressed source with independent capture/mask/
    /// calibration context. A returned Processing error before acceptance permits
    /// a corrected retry against the same frame. Pending requires resume instead.
    /// Every successful upstream stage stays retained before post-work revalidation.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze(
        &mut self,
        context: HttpFrameContext<'_>,
        background: Option<&JpegBackground>,
        plan: &RectificationPlan,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        budgets: HttpHogBudgets<'_, '_>,
    ) -> Result<HttpHogStep, HttpHogError> {
        if self.source.is_some() {
            return Err(HttpHogError::AlreadyAccepted);
        }
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        let frame = self
            .camera
            .pending_frame()
            .ok_or(HttpHogError::FrameMismatch)?;
        let receipt = frame.part().receipt();
        if context.expected_head != frame.head()
            || frame.head().wire != self.camera.route().basis()
            || context.binding.encoded_sha256 != receipt.encoded_sha256
            || context.stamp.sequence != receipt.ordinal
            || context.stamp.stream_generation != frame.head().wire.generation
        {
            return Err(HttpHogError::FrameMismatch);
        }
        // The sensor's current mask, resolved for THIS frame. The permission grid and every
        // background reference must exclude the masked pixels; the decoded plane is filled.
        let refusal = |e| HttpHogError::Privacy(MaskRefusal::from(e));
        let mask = context.privacy.resolve().map_err(refusal)?;
        mask.refuse_admitted(context.mask, plan.spec().source.dimensions())
            .map_err(refusal)?;
        if background.is_some_and(|model| {
            model
                .reference_receipts()
                .iter()
                .any(|r| r.redaction != mask.redaction_identity())
        }) {
            return Err(HttpHogError::Privacy(MaskRefusal::UnmaskedAccess));
        }
        // Reserve all wrapper hashing before the only mutation-bearing pipeline call.
        let source = source_digest(frame, budgets.rectification).map_err(HttpHogError::Work)?;
        budgets
            .rectification
            .charge(256)
            .map_err(HttpHogError::Work)?;
        let result = self.processor.observe(
            background,
            plan,
            JpegScreeningQuery {
                bytes: frame.part().bytes(),
                mask: context.mask,
                binding: context.binding,
                capture: context.capture,
                foreground_policy: context.foreground_policy,
                decode_limits: context.decode_limits,
                stamp: context.stamp,
                redaction: mask.luma_redaction(),
            },
            budgets.decode,
            budgets.rectification,
            budgets.foreground,
            budgets.health,
            budgets.inference,
            budgets.downstream,
        );
        if result.is_ok() {
            self.mask = mask;
        }
        self.record(result, source, receipt.ordinal, receipt.encoded_sha256);
        // Even a late revocation leaves the exact current completed/pending result owned.
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        self.current(result)
    }
    /// Resume only unfinished inference/tracking/zone work. No read, decode, capture
    /// rebinding, source consumption, or completed-inference rerun happens here.
    pub fn resume(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
        linking: &mut WorkBudget<'_>,
    ) -> Result<HttpHogStep, HttpHogError> {
        let source = self.source.ok_or(HttpHogError::NotReady)?;
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        if let Some(complete) = self.complete {
            return Ok(HttpHogStep::ResultReady(complete));
        }
        linking.charge(256).map_err(HttpHogError::Work)?;
        let r = self
            .camera
            .pending_frame()
            .ok_or(HttpHogError::FrameMismatch)?
            .part()
            .receipt();
        let result = self.processor.resume(inference, downstream);
        self.record(result, source, r.ordinal, r.encoded_sha256);
        self.camera.admit(HttpCameraOperation::Analyze, now, auth)?;
        self.current(result)
    }
    /// After saving/handling all current evidence, accept result custody responsibility
    /// and transfer its original mapped frame. This does NOT acknowledge the health
    /// monitor's semantic result custody, publish a ledger event, or grant an effect.
    /// No fallible work follows the acquisition owner's exact-frame release.
    pub fn acknowledge_result(
        &mut self,
        expected: HttpHogCompletion,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<HttpJpegFrame, HttpHogError> {
        if self.complete.is_none() {
            return Err(HttpHogError::NotReady);
        }
        if self.complete != Some(expected) {
            return Err(HttpHogError::ReceiptMismatch);
        }
        self.camera
            .admit(HttpCameraOperation::ReleaseResult, now, auth)?;
        let frame = self
            .camera
            .take_frame(expected.ordinal, expected.encoded, now, auth)?;
        self.last_acknowledged = self.complete.take();
        self.source = None;
        self.progress = None;
        self.processing_error = None;
        Ok(frame)
    }
    /// Poll the existing source-input-silence watchdog without making another read.
    /// Its time is the owner's receive clock, never a constructed camera timestamp.
    pub fn poll_health(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<StallObservation, HttpHogError> {
        self.camera.admit(HttpCameraOperation::Poll, now, auth)?;
        self.processor.poll(now).map_err(HttpHogError::Processing)
    }
    fn record(
        &mut self,
        result: Result<JpegHogProgress, JpegHogError>,
        source: [u8; 32],
        ordinal: u64,
        encoded: [u8; 32],
    ) {
        match result {
            Ok(progress) => {
                self.source = Some(source);
                self.progress = Some(progress);
                self.processing_error = None;
                self.complete = match progress {
                    JpegHogProgress::Complete(analysis) => {
                        Some(completion(source, ordinal, encoded, analysis, &self.mask))
                    }
                    JpegHogProgress::Pending { .. } => None,
                };
            }
            Err(error) => self.processing_error = Some(error),
        }
    }
    fn current(
        &self,
        result: Result<JpegHogProgress, JpegHogError>,
    ) -> Result<HttpHogStep, HttpHogError> {
        result.map_err(HttpHogError::Processing)?;
        Ok(self.complete.map_or(
            HttpHogStep::AnalysisPending(self.processor.stage()),
            HttpHogStep::ResultReady,
        ))
    }
    /// Close the socket and transfer all original sources and the exact resumable
    /// analysis owner. Retirement creates no replacement exposure or storage claim.
    pub fn retire(self) -> HttpHogRetirement {
        HttpHogRetirement {
            source: self.camera.retire(),
            processor: self.processor,
            current_source_digest: self.source,
            progress: self.progress,
            complete: self.complete,
            last_acknowledged: self.last_acknowledged,
            processing_error: self.processing_error,
        }
    }
}
/// Source and derived obligations move together even after revoked authority.
#[must_use]
pub struct HttpHogRetirement {
    /// Original unfinished network source, frames, maps, parse state and terminal reason.
    pub source: HttpCameraRetirement,
    /// Existing native image and all accepted downstream stages, not a new copy/replay.
    pub processor: JpegHogPipeline,
    /// Current accepted source binding, absent before native image acceptance.
    pub current_source_digest: Option<[u8; 32]>,
    /// Exact completed/pending derivation status.
    pub progress: Option<JpegHogProgress>,
    /// Current complete unacknowledged result, if one exists.
    pub complete: Option<HttpHogCompletion>,
    /// Explicitly historical last acknowledged result.
    pub last_acknowledged: Option<HttpHogCompletion>,
    /// Last outer processing refusal, even if authority subsequently failed.
    pub processing_error: Option<JpegHogError>,
}
impl std::fmt::Debug for HttpHogRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpHogRetirement")
            .field("source", &self.source)
            .field("analysis_stage", &self.processor.stage())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}
fn completion(
    source: [u8; 32],
    ordinal: u64,
    encoded: [u8; 32],
    analysis: JpegHogCompletion,
    mask: &MaskBinding,
) -> HttpHogCompletion {
    let mut bytes = [0_u8; 232];
    let tag = b"fss/http-hog-completion/1\0";
    bytes[..tag.len()].copy_from_slice(tag);
    bytes[32..64].copy_from_slice(&source);
    bytes[64..72].copy_from_slice(&ordinal.to_le_bytes());
    bytes[72..104].copy_from_slice(&encoded);
    for (i, root) in [
        analysis.image,
        analysis.scan,
        analysis.tracking,
        analysis.zones,
    ]
    .iter()
    .enumerate()
    {
        bytes[104 + i * 32..136 + i * 32].copy_from_slice(root);
    }
    HttpHogCompletion {
        digest: mask.fold_identity("http_hog_completion", ContentDigest::sha256(&bytes).bytes()),
        source,
        ordinal,
        encoded,
        analysis,
        mask_policy: mask.policy_digest(),
        mask_generation: mask.generation(),
    }
}
fn source_digest(
    frame: &HttpJpegFrame,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], GeometryError> {
    budget.charge(512 + frame.source_spans().len() as u64 * 128)?;
    let h = frame.head();
    let r = frame.part().receipt();
    let mut bytes = [0_u8; 512];
    let tag = b"fss/http-hog-source/1\0";
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
