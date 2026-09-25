#![forbid(unsafe_code)]
//! Native camera -> durable original reads -> verified frames -> terminal root.
//!
//! This owner composes existing acquisition/publication/codec contracts. Every
//! original read stops at a prepare barrier BEFORE storage I/O. The caller retains
//! its exact expected pin, explicitly commits it, and only then may parsing advance.
//! There is no responsibility-only ACK escape, network retry, hidden worker, clock,
//! new journal, canonical event, or inference of capture time from receipt time.
//!
//! Original reads are unmasked source custody. A requested decode is masked by the named
//! sensor's *current* retained privacy mask ([`super::privacy_mask::live`]), resolved for each
//! frame, so a policy retained mid-recording applies from the next decoded frame and earlier
//! frames keep the binding they were decoded under. A decode without a named sensor is refused
//! (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`); no unmasked luma is ever returned.

use fss_codec_mjpeg::http::{HttpHeadIdentity, HttpLimits};
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_codec_mjpeg::multipart::MultipartLimits;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::MAX_MANIFEST_CHILDREN;
use fss_publication::{
    LocalPublicationReceipt, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};

use super::http_archive::{
    HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWirePin, HttpWirePublication,
    HttpWireScope,
};
use super::http_camera::rgb::http_rgb_exposure;
use super::http_camera::{
    HttpCamera, HttpCameraAuthority, HttpCameraError, HttpCameraLimits, HttpCameraRetirement,
    HttpCameraRoute, HttpCameraSecurity, HttpCameraStep, HttpWireReceipt,
};
use super::http_replay::check::{HttpCheckDecode, HttpCheckLimits, HttpCheckSource};
use super::http_replay::completion::{
    HttpCompletionError, HttpCompletionPin, PreparedHttpCompletion,
};
use super::privacy_mask::live::{MaskRefusal, MaskedLuma, SensorMask};

/// Whole-recording limits, including the existing checker's source/decode bounds.
#[derive(Clone, Copy, Debug)]
pub struct HttpRecordingLimits {
    /// Whole-source and native work bounds. No budget refills per frame or retry.
    pub media: HttpCheckLimits,
    /// Explicit component interpretation, or framing-only capture.
    pub decode: HttpCheckDecode,
    /// Read AND write syscall attempts for the complete connection.
    pub io_calls: u64,
    /// One connect attempt, bounded by this and the owner's absolute deadline.
    pub connect_timeout_ns: u64,
}
impl Default for HttpRecordingLimits {
    fn default() -> Self {
        let mut media = HttpCheckLimits::default();
        media.maximum_reads = media
            .maximum_reads
            .min(MAX_MANIFEST_CHILDREN.saturating_sub(1));
        Self {
            media,
            decode: HttpCheckDecode::None,
            io_calls: 1_000_000,
            connect_timeout_ns: 5_000_000_000,
        }
    }
}
/// Exact operator-selected source. No credentials, DNS, redirect or inferred authorization.
#[derive(Debug)]
pub struct HttpRecordingRequest {
    /// Existing validated route; Debug does not expose its address/path.
    pub route: HttpCameraRoute,
    /// Original source generation, receive clock and raw-header/media retention scope.
    pub scope: HttpWireScope,
    /// Independently selected complete-input, work and network bounds.
    pub limits: HttpRecordingLimits,
    /// Absolute deadline in the owning authority's monotonic clock.
    pub deadline_ns: u64,
}
impl HttpRecordingRequest {
    /// Build the exact approved plaintext route without I/O. This is NOT a grant.
    pub fn new(
        source: HttpCheckSource,
        peer: std::net::SocketAddr,
        authority: &str,
        target: &str,
        limits: HttpRecordingLimits,
        deadline_ns: u64,
    ) -> Result<Self, HttpRecordingError> {
        let scope = source
            .scope()
            .map_err(|_| HttpRecordingError::Configuration)?;
        let route = HttpCameraRoute::new(
            scope.stream,
            peer,
            authority,
            target,
            HttpCameraSecurity::OwnerApprovedPlaintext,
        )?;
        Ok(Self {
            route,
            scope,
            limits,
            deadline_ns,
        })
    }
}
/// Independent live network AND original-byte storage/disclosure authority.
#[derive(Clone, Copy)]
pub struct HttpRecordingAccess<'a> {
    /// Current admission time; the camera authority independently checks elapsed time.
    pub now_ns: u64,
    /// Owning Cx/route/grant/deadline/revocation adapter; no default is supplied.
    pub camera: &'a dyn HttpCameraAuthority,
    /// Live retention/read/publication probe for ORIGINAL headers and media.
    pub storage: &'a dyn PublishCancellation,
}
/// Refusals never imply an empty scene, clean EOF, or permission to reconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRecordingError {
    /// Invalid independent limits, clock or source binding, before connection.
    Configuration,
    /// Existing native source owner refused; it retains all accepted input.
    Source(HttpCameraError),
    /// Original root publication or current verification refused.
    Archive(HttpArchiveError),
    /// Native completion publication refused; exact prepared pin remains available.
    Completion(HttpCompletionError),
    /// Original-media retention/disclosure/deadline probe refused.
    Cancelled,
    /// Whole-request poll or frame bound, never a successful recording end.
    Limit,
    /// Stale/unprepared wire, frame or completion key; nothing was committed.
    PlanMismatch,
    /// Wrong state for this operation; no implicit state reset.
    NotReady,
    /// Full native decode failed; the original frame remains held and archived.
    Decode {
        /// Original part ordinal, not a capture timestamp.
        ordinal: u64,
        /// Payload-free native failure.
        error: DecodeError,
    },
    /// Whole-recording source/linking budget or cancellation refused.
    Work(GeometryError),
    /// The privacy mask refused a decode: no sensor was named, its mask could not be resolved,
    /// or the frame's resolution differs from the policy's. The original frame remains held.
    Privacy(MaskRefusal),
}
impl From<HttpCameraError> for HttpRecordingError {
    fn from(e: HttpCameraError) -> Self {
        Self::Source(e)
    }
}
impl From<HttpArchiveError> for HttpRecordingError {
    fn from(e: HttpArchiveError) -> Self {
        Self::Archive(e)
    }
}
impl From<HttpCompletionError> for HttpRecordingError {
    fn from(e: HttpCompletionError) -> Self {
        Self::Completion(e)
    }
}
impl From<GeometryError> for HttpRecordingError {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}
impl std::fmt::Display for HttpRecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP recording refused: {self:?}")
    }
}
impl std::error::Error for HttpRecordingError {}
/// No HTTP request was sent by a failed connect. The peer may have seen TCP connect.
#[derive(Debug)]
pub struct HttpRecordingStartFailure {
    /// Payload-free refusal; archive contents were not modified by connection setup.
    pub reason: HttpRecordingError,
    /// Whether the existing native connector attempted TCP.
    pub attempted: bool,
}
impl std::fmt::Display for HttpRecordingStartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HttpRecordingStartFailure {}
/// Exact original read and intended post-publication prefix, exposed BEFORE I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRecordingWirePlan {
    wire: HttpWireReceipt,
    pin: HttpWirePin,
}
impl HttpRecordingWirePlan {
    /// Independently retain this key before allowing its publication.
    pub fn expected_pin(self) -> HttpWirePin {
        self.pin
    }
    /// Exact immutable read, including source offsets and receive admission time.
    pub fn wire(self) -> HttpWireReceipt {
        self.wire
    }
}
/// Exact source-mapped part key; no field grants read, decode or event authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRecordingFrameKey {
    head: HttpHeadIdentity,
    ordinal: u64,
    encoded: [u8; 32],
}
impl HttpRecordingFrameKey {
    /// Original complete response identity.
    pub fn head(self) -> HttpHeadIdentity {
        self.head
    }
    /// Original one-based part ordinal.
    pub fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Hash of complete original JPEG bytes.
    pub fn encoded_sha256(self) -> [u8; 32] {
        self.encoded
    }
    fn of(frame: &HttpJpegFrame) -> Self {
        let r = frame.part().receipt();
        Self {
            head: frame.head(),
            ordinal: r.ordinal,
            encoded: r.encoded_sha256,
        }
    }
}
/// Source progress and durable publication progress are deliberately different states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRecordingStep {
    /// One existing bounded source/parser operation advanced.
    Advanced,
    /// Socket WouldBlock/Interrupted; wait under the external owner, never spin here.
    Pending,
    /// Save this exact expected pin, then call commit_wire. No parsing before commit.
    WirePrepared(HttpRecordingWirePlan),
    /// Original bytes are durable; take_frame verifies and optionally decodes this part.
    FrameReady(HttpRecordingFrameKey),
    /// Native HTTP/MIME ended. Save this pin before committing the completion root.
    CompletionPrepared(HttpCompletionPin),
    /// Native end AND locally durable completion graph, never sensor-coverage proof.
    Complete(HttpCompletionPin),
}
/// A disk publication succeeded even if later camera acknowledgement was denied.
#[derive(Debug)]
pub struct HttpRecordingWireCommit {
    /// Existing root-last publisher's actual durable outcome, including exact retry.
    pub publication: HttpWirePublication,
    /// Separate camera-authority result. Err must not hide the successful disk write.
    pub acknowledgement: Result<(), HttpCameraError>,
}
/// Accepted computation retained even when the final source transfer is denied.
#[derive(Debug)]
pub struct HttpRecordingFrameCheck {
    /// Existing exact HTTP source-map identity; not proof of a distinct physical exposure.
    pub exposure: [u8; 32],
    /// Full native luma result when requested, masked by the sensor's current privacy mask
    /// (its receipt names the applied policy or the explicit no-policy marker).
    pub decoded: Option<MaskedLuma>,
}
/// Whole original frame and its optional native decode, transferable to another owner.
#[derive(Debug)]
pub struct HttpRecordedFrame {
    /// Complete original mapped source, already checked against current disk bytes.
    pub frame: HttpJpegFrame,
    /// Exact source identity and any actual decoded result.
    pub check: HttpRecordingFrameCheck,
}
/// Consumed whole-operation deterministic allowances, including refused work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRecordingWork {
    /// Poll calls admitted, not elapsed time.
    pub steps: u64,
    /// Source/storage/verification/linking units charged.
    pub source: u64,
    /// Native HTTP/MIME units charged.
    pub framing: u64,
    /// Native full-JPEG units charged.
    pub decode: u64,
}
/// One exclusive recording, with no mutable source or responsibility-only ACK escape.
pub struct HttpRecording {
    camera: HttpCamera,
    archive: HttpWireArchive,
    limits: HttpRecordingLimits,
    steps: u64,
    work: WorkBudget<'static>,
    framing: DecodeBudget<'static>,
    decoder: DecodeBudget<'static>,
    wire_plan: Option<HttpRecordingWirePlan>,
    terminal: Option<PreparedHttpCompletion>,
    complete: Option<HttpCompletionPin>,
    frame_check: Option<HttpRecordingFrameCheck>,
    frame_error: Option<HttpRecordingError>,
    transferred: u64,
}
impl HttpRecording {
    /// Reverify an EMPTY source namespace before any connect attempt. Existing
    /// source roots are a recovery task, not permission to restart this generation.
    pub fn connect(
        request: HttpRecordingRequest,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<Self, HttpRecordingStartFailure> {
        let before = |reason| HttpRecordingStartFailure {
            reason,
            attempted: false,
        };
        let limits = request.limits;
        let m = limits.media;
        m.validate()
            .map_err(|_| before(HttpRecordingError::Configuration))?;
        if request.route.basis() != request.scope.stream
            || access.now_ns >= request.deadline_ns
            || !(1..=1_000_000).contains(&limits.io_calls)
            || !(1..=60_000_000_000).contains(&limits.connect_timeout_ns)
            || m.maximum_reads >= MAX_MANIFEST_CHILDREN
            || publisher.limits().max_children <= m.maximum_reads
            || publisher.limits().spool.max_object_bytes
                < m.read_bytes.max(1024 + (m.maximum_reads + 1) * 64)
        {
            return Err(before(HttpRecordingError::Configuration));
        }
        probe(access).map_err(before)?;
        let mut work = WorkBudget::new(m.source_work);
        let bounds = HttpArchiveLimits {
            maximum_reads: m.maximum_reads,
            maximum_bytes: m.maximum_source_bytes,
            maximum_scan_roots: m.maximum_scan_roots,
            maximum_spool_object_bytes: m.maximum_spool_object_bytes,
        };
        let empty = HttpWireArchive::new(request.scope, bounds).map_err(|e| before(e.into()))?;
        let archive = HttpWireArchive::load(
            publisher,
            request.scope,
            empty.pin(),
            bounds,
            access.storage,
            &mut work,
        )
        .map_err(|e| before(e.into()))?;
        let camera_limits = HttpCameraLimits {
            http: HttpLimits {
                wire_bytes: m.maximum_source_bytes,
                entity_bytes: m.maximum_source_bytes,
                ..HttpLimits::default()
            },
            multipart: MultipartLimits {
                frame_bytes: m.maximum_frame_bytes,
                ..MultipartLimits::default()
            },
            read_bytes: m.read_bytes,
            io_calls: limits.io_calls,
            // One lookahead part permits EOF after EXACTLY the requested frame count.
            // It is never transferred when it exceeds the caller's admitted maximum.
            frames: m.maximum_frames as u64 + 1,
            source_runs: 65536,
            connect_timeout_ns: limits.connect_timeout_ns,
        };
        let camera = HttpCamera::connect(
            request.route,
            camera_limits,
            access.now_ns,
            request.deadline_ns,
            access.camera,
        )
        .map_err(|e| HttpRecordingStartFailure {
            reason: e.reason.into(),
            attempted: e.attempted,
        })?;
        Ok(Self {
            camera,
            archive,
            limits,
            steps: 0,
            work,
            framing: DecodeBudget::new(m.framing_work),
            decoder: DecodeBudget::new(m.decode_work),
            wire_plan: None,
            terminal: None,
            complete: None,
            frame_check: None,
            frame_error: None,
            transferred: 0,
        })
    }
    /// Read-only original owner; no method exposes mutable acknowledgement authority.
    pub fn camera(&self) -> &HttpCamera {
        &self.camera
    }
    /// Last successfully published original prefix, including after a late ACK denial.
    pub fn pin(&self) -> HttpWirePin {
        self.archive.pin()
    }
    /// Original immutable scope; not current permission to read or retain.
    pub fn scope(&self) -> HttpWireScope {
        self.archive.scope()
    }
    /// Exact expected raw-read publication still awaiting commit/acknowledgement.
    pub fn pending_wire_plan(&self) -> Option<HttpRecordingWirePlan> {
        self.wire_plan
    }
    /// Native complete end prepared before durable terminal publication.
    pub fn prepared_completion(&self) -> Option<HttpCompletionPin> {
        self.terminal.as_ref().map(|t| t.pin())
    }
    /// Successful durable completion only, independent of delivery to an output sink.
    pub fn completion(&self) -> Option<HttpCompletionPin> {
        self.complete
    }
    /// Complete frames explicitly transferred; not merely counted by MIME parsing.
    pub fn transferred_frames(&self) -> u64 {
        self.transferred
    }
    /// Work receipts never claim measured CPU time, energy or hard real-time deadlines.
    pub fn work(&self) -> HttpRecordingWork {
        HttpRecordingWork {
            steps: self.steps,
            source: self.work.used(),
            framing: self.framing.used(),
            decode: self.decoder.used(),
        }
    }
    /// At most one native acquisition step. Every raw read and frame backpressures
    /// subsequent acquisition, including while the caller is saving a prepared pin.
    pub fn poll(
        &mut self,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRecordingStep, HttpRecordingError> {
        probe(access)?;
        if self.steps == self.limits.media.maximum_steps {
            return Err(HttpRecordingError::Limit);
        }
        self.work.charge(1)?;
        self.steps += 1;
        let step = self
            .camera
            .step(access.now_ns, access.camera, &mut self.framing)?;
        match step {
            HttpCameraStep::Pending => Ok(HttpRecordingStep::Pending),
            HttpCameraStep::Advanced => Ok(HttpRecordingStep::Advanced),
            HttpCameraStep::WireReady(wire) => {
                if let Some(plan) = self.wire_plan {
                    if plan.wire != wire {
                        return Err(HttpRecordingError::PlanMismatch);
                    }
                    return Ok(HttpRecordingStep::WirePrepared(plan));
                }
                let read = self
                    .camera
                    .pending_wire()
                    .ok_or(HttpRecordingError::NotReady)?;
                let prepared = self.archive.prepare(read, &mut self.work)?;
                let plan = HttpRecordingWirePlan {
                    wire,
                    pin: prepared.pin(),
                };
                self.wire_plan = Some(plan);
                Ok(HttpRecordingStep::WirePrepared(plan))
            }
            HttpCameraStep::FrameReady => {
                if self.camera.totals().frames > self.limits.media.maximum_frames as u64 {
                    return Err(HttpRecordingError::Limit);
                }
                if let Some(error) = self.frame_error {
                    return Err(error);
                }
                Ok(HttpRecordingStep::FrameReady(HttpRecordingFrameKey::of(
                    self.camera
                        .pending_frame()
                        .ok_or(HttpRecordingError::NotReady)?,
                )))
            }
            HttpCameraStep::Complete => {
                if let Some(pin) = self.complete {
                    return Ok(HttpRecordingStep::Complete(pin));
                }
                if self.terminal.is_none() {
                    self.terminal = Some(PreparedHttpCompletion::from_camera(
                        &self.camera,
                        &self.archive,
                        &mut self.work,
                    )?);
                }
                Ok(HttpRecordingStep::CompletionPrepared(
                    self.prepared_completion()
                        .ok_or(HttpRecordingError::NotReady)?,
                ))
            }
        }
    }
    /// Revalidate the previously exposed exact plan, publish original bytes, THEN
    /// release the parse barrier. An outer error keeps the read/plan; storage may
    /// have staged/visible work. Reopen a poisoned publisher and retry this SAME key.
    pub fn commit_wire(
        &mut self,
        expected: HttpRecordingWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRecordingWireCommit, HttpRecordingError> {
        if self.wire_plan != Some(expected) {
            return Err(HttpRecordingError::PlanMismatch);
        }
        probe(access)?;
        // Held unacknowledged input makes this an authority check, not another read.
        if self
            .camera
            .step(access.now_ns, access.camera, &mut self.framing)?
            != HttpCameraStep::WireReady(expected.wire)
        {
            return Err(HttpRecordingError::NotReady);
        }
        let read = self
            .camera
            .pending_wire()
            .ok_or(HttpRecordingError::NotReady)?;
        let prepared = self.archive.prepare(read, &mut self.work)?;
        if prepared.pin() != expected.pin {
            return Err(HttpRecordingError::PlanMismatch);
        }
        let publication =
            self.archive
                .publish(&prepared, publisher, access.storage, &mut self.work)?;
        let acknowledgement =
            self.camera
                .acknowledge_wire(expected.wire, access.now_ns, access.camera);
        if acknowledgement.is_ok() {
            self.wire_plan = None;
        }
        Ok(HttpRecordingWireCommit {
            publication,
            acknowledgement,
        })
    }
    /// Verify original custody and optionally decode the COMPLETE JPEG. Every
    /// budget is recording-wide. A failed final release keeps accepted decode work
    /// as well as the original frame; retire() transfers both without another read.
    /// A decode requires the recorded sensor; its current mask is applied to the plane.
    pub fn take_frame(
        &mut self,
        expected: HttpRecordingFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        privacy: Option<SensorMask<'_>>,
    ) -> Result<HttpRecordedFrame, HttpRecordingError> {
        probe(access)?;
        if self.limits.decode != HttpCheckDecode::None && privacy.is_none() {
            return Err(HttpRecordingError::Privacy(MaskRefusal::UnmaskedAccess));
        }
        let frame = self
            .camera
            .pending_frame()
            .ok_or(HttpRecordingError::NotReady)?;
        if HttpRecordingFrameKey::of(frame) != expected {
            return Err(HttpRecordingError::PlanMismatch);
        }
        if self.camera.totals().frames > self.limits.media.maximum_frames as u64 {
            return Err(HttpRecordingError::Limit);
        }
        if let Some(error) = self.frame_error {
            return Err(error);
        }
        if self
            .camera
            .step(access.now_ns, access.camera, &mut self.framing)?
            != HttpCameraStep::FrameReady
        {
            return Err(HttpRecordingError::NotReady);
        }
        let frame = self
            .camera
            .pending_frame()
            .ok_or(HttpRecordingError::NotReady)?;
        self.archive
            .verify_frame(publisher, frame, access.storage, &mut self.work)?;
        if self.frame_check.is_none() {
            let exposure = http_rgb_exposure(frame, &mut self.work)?;
            let interpretation = match self.limits.decode {
                HttpCheckDecode::None => None,
                HttpCheckDecode::Grayscale => Some(ComponentInterpretation::Grayscale),
                HttpCheckDecode::YCbCr => Some(ComponentInterpretation::YCbCr),
            };
            let decoded = if let (Some(interpretation), Some(sensor)) = (interpretation, privacy) {
                // The sensor's mask as of THIS frame; applied before the plane is returned.
                let mask = sensor
                    .resolve()
                    .map_err(|e| HttpRecordingError::Privacy(MaskRefusal::from(e)))?;
                let m = self.limits.media;
                match frame.decode(
                    interpretation,
                    DecodeLimits {
                        maximum_bytes: m.maximum_frame_bytes,
                        maximum_dimension: m.maximum_dimension,
                        maximum_pixels: m.maximum_pixels,
                        ..DecodeLimits::default()
                    },
                    &mut self.decoder,
                ) {
                    Ok(image) => Some(
                        mask.mask_luma(image)
                            .map_err(|e| HttpRecordingError::Privacy(MaskRefusal::from(e)))?,
                    ),
                    Err(error) => {
                        let error = HttpRecordingError::Decode {
                            ordinal: expected.ordinal,
                            error,
                        };
                        self.frame_error = Some(error);
                        return Err(error);
                    }
                }
            } else {
                None
            };
            self.frame_check = Some(HttpRecordingFrameCheck { exposure, decoded });
        }
        probe(access)?;
        self.work.charge(0)?;
        let check = self
            .frame_check
            .take()
            .ok_or(HttpRecordingError::NotReady)?;
        let frame = match self.camera.take_frame(
            expected.ordinal,
            expected.encoded,
            access.now_ns,
            access.camera,
        ) {
            Ok(frame) => frame,
            Err(error) => {
                self.frame_check = Some(check);
                return Err(error.into());
            }
        };
        // No fallible operation follows source release.
        self.transferred += 1;
        Ok(HttpRecordedFrame { frame, check })
    }
    /// Publish the actual native end's complete object closure. The pin is exposed
    /// before I/O; exact retries reuse it. No late optional check hides success.
    pub fn commit_completion(
        &mut self,
        expected: HttpCompletionPin,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<LocalPublicationReceipt, HttpRecordingError> {
        if self.prepared_completion() != Some(expected) {
            return Err(HttpRecordingError::PlanMismatch);
        }
        probe(access)?;
        if self
            .camera
            .step(access.now_ns, access.camera, &mut self.framing)?
            != HttpCameraStep::Complete
        {
            return Err(HttpRecordingError::NotReady);
        }
        let receipt = self
            .terminal
            .as_ref()
            .ok_or(HttpRecordingError::NotReady)?
            .publish(&self.archive, publisher, access.storage, &mut self.work)?;
        self.complete = Some(expected);
        Ok(receipt)
    }
    /// Stop without network I/O and hand over every unfinished source and result.
    /// Partial publication is not repaired, discarded or converted into completion.
    pub fn retire(self) -> HttpRecordingRetirement {
        let work = self.work();
        HttpRecordingRetirement {
            source: self.camera.retire(),
            archive: self.archive,
            work,
            wire_plan: self.wire_plan,
            terminal: self.terminal,
            complete: self.complete,
            frame_check: self.frame_check,
            frame_error: self.frame_error,
            transferred_frames: self.transferred,
        }
    }
}
/// Complete ownership after stop; the caller decides retention, repair or recovery.
#[must_use]
pub struct HttpRecordingRetirement {
    /// Original raw bytes, parser remainders and any untransferred complete frame.
    pub source: HttpCameraRetirement,
    /// Exact acknowledged durable prefix. Reverify it when reopening storage.
    pub archive: HttpWireArchive,
    /// Original read key needed to reconcile a failed/ambiguous publication.
    pub wire_plan: Option<HttpRecordingWirePlan>,
    /// Actual native ending, including a publication whose return may have been lost.
    pub terminal: Option<PreparedHttpCompletion>,
    /// Confirmed durable completion, if publication succeeded.
    pub complete: Option<HttpCompletionPin>,
    /// Accepted decode/source-map work retained after final release refusal.
    pub frame_check: Option<HttpRecordingFrameCheck>,
    /// Native decode failure kept separate from source failure and scene absence.
    pub frame_error: Option<HttpRecordingError>,
    /// Explicitly transferred frame count.
    pub transferred_frames: u64,
    /// Whole-recording work charged, including failed operations.
    pub work: HttpRecordingWork,
}
fn probe(access: HttpRecordingAccess<'_>) -> Result<(), HttpRecordingError> {
    if access
        .storage
        .cancel_requested(PublishCutPoint::AfterChildrenVerified)
    {
        Err(HttpRecordingError::Cancelled)
    } else {
        Ok(())
    }
}
