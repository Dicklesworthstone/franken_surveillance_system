#![forbid(unsafe_code)]
//! Durable-before-parse HTTP reacquisition, using the existing native camera and wire archive.
//!
//! Every original read exposes its exact expected pin before publication. A disconnected source
//! cannot release the next generation until all accepted bytes, including a late unacknowledged
//! read, have been published and the complete prefix reverified. Publication and camera ACK remain
//! separate outcomes. Storage refusal keeps every pending source owner available through `retire`.
//! There is no second journal, secret, repair, inferred capture time, automatic crash resume, pixel
//! decode or effect authority. Frame transfer returns authorized original compressed custody only.
//! Consumers must apply the current sensor privacy policy before decoding/disclosing pixels.
//!
//! Preserve every prepared pin and boundary independently. A boundary reports actual HTTP/MIME
//! completion or failure plus a verified original prefix; it is NOT a durable completion root,
//! capture-continuity certificate, coverage witness or proof that the scene was empty.

use fss_codec_mjpeg::http::HttpHeadIdentity;
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCutPoint};

use super::http_archive::{
    HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWirePin, HttpWirePublication,
    HttpWireScope,
};
use super::http_camera::{HttpCameraError, HttpCameraOperation, HttpCameraStep, HttpWireReceipt};
use super::http_reconnect::{
    HttpReconnect, HttpReconnectError, HttpReconnectHandoff, HttpReconnectPolicy,
    HttpReconnectReceipt, HttpReconnectReservation, HttpReconnectRetirement, HttpReconnectSlot,
    HttpReconnectStep, HttpReconnectTotals, MAX_RECONNECT_CONNECTIONS,
};
use super::http_recording::HttpRecordingAccess;

/// An explicit source-generation reservation and its independently approved raw custody scope.
#[derive(Clone, Debug)]
pub struct HttpReconnectRecordingSlot {
    /// Native route, fresh source generation and non-replenishing connection allowance.
    pub source: HttpReconnectSlot,
    /// Raw headers AND encoded media retention scope, not a storage capability.
    pub scope: HttpWireScope,
    /// Existing archive input/scan/allocation limits for this generation.
    pub archive: HttpArchiveLimits,
}
/// Frozen whole-operation plan; construction performs no filesystem or network I/O.
#[derive(Debug)]
pub struct HttpReconnectRecordingPlan {
    /// One through thirty-two explicit, strictly increasing source generations.
    pub slots: Vec<HttpReconnectRecordingSlot>,
    /// One shared native framing budget and bounded reconnect policy.
    pub policy: HttpReconnectPolicy,
    /// One source verification/publication work budget, never reset at a reconnect.
    pub source_work: u64,
    /// Complete poll allowance, including repeated pending/prepared/boundary observations.
    pub maximum_steps: u64,
    /// One absolute deadline in the independent network authority's monotonic clock.
    pub deadline_ns: u64,
}
/// Exact prepared raw-read publication; private fields prevent widening its scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpReconnectWirePlan {
    wire: HttpWireReceipt,
    pin: HttpWirePin,
}
impl HttpReconnectWirePlan {
    /// Retain this expected prefix before invoking the publication operation.
    pub fn expected_pin(self) -> HttpWirePin {
        self.pin
    }
    /// Original source, range, digest and receive-admission time, never a capture timestamp.
    pub fn wire(self) -> HttpWireReceipt {
        self.wire
    }
}
/// Exact held frame key, source-generation-bound even when part ordinals restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpReconnectFrameKey {
    head: HttpHeadIdentity,
    ordinal: u64,
    encoded: [u8; 32],
}
impl HttpReconnectFrameKey {
    /// Exact original response identity, not physical camera authentication.
    pub fn head(self) -> HttpHeadIdentity {
        self.head
    }
    /// One-based part ordinal within this response generation.
    pub fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Digest of the entire unchanged compressed frame.
    pub fn encoded_sha256(self) -> [u8; 32] {
        self.encoded
    }
    fn of(frame: &HttpJpegFrame) -> Self {
        let part = frame.part().receipt();
        Self {
            head: frame.head(),
            ordinal: part.ordinal,
            encoded: part.encoded_sha256,
        }
    }
}
/// Exact original-prefix and discontinuity handoff; independently preserve before release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpReconnectBoundary {
    /// Unchanged terminal observation, next reserved generation and local network counts.
    pub source: HttpReconnectReceipt,
    /// Every successful read in the ended source, freshly verified against durable local roots.
    pub prefix: HttpWirePin,
}
/// Bounded progress. Prepared output never silently authorizes its own publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectRecordingStep {
    /// TCP connection established; no first-frame or source-continuity claim.
    Connected(StreamBasis),
    /// One bounded source/parser operation advanced.
    Advanced,
    /// External owner must wait for readiness while checking live cancellation/deadline.
    Pending,
    /// External owner must wait until the capped backoff has elapsed.
    Waiting {
        /// Earliest reconnect time, in the caller's nanosecond clock.
        not_before_ns: u64,
    },
    /// Save the expected pin before calling `commit_wire`; no parsing or next connection yet.
    WirePrepared(HttpReconnectWirePlan),
    /// Complete part whose source is durable; `take_frame` revalidates its original custody.
    FrameReady(HttpReconnectFrameKey),
    /// Save this boundary before `release_boundary`; the next generation remains blocked.
    BoundaryReady(HttpReconnectBoundary),
    /// All ended-source handoffs were released; the plan will perform no additional network I/O.
    Stopped,
}
/// A successful disk publication cannot be hidden by a later network-authority refusal.
#[derive(Debug)]
pub struct HttpReconnectWireCommit {
    /// Actual root-last local publication, including exact retry semantics.
    pub publication: HttpWirePublication,
    /// None for an already retired source. Some(Err) still leaves the publication durable.
    pub acknowledgement: Option<Result<(), HttpReconnectError>>,
}
/// Stable typed owner refusals; none permits resetting a source generation or custody history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectRecordingError {
    /// Invalid independent plan limits or mismatched stream/custody scopes.
    Configuration,
    /// Exact prepared wire/frame/boundary key is stale or does not match.
    PlanMismatch,
    /// No source/frame/boundary is currently held for the requested operation.
    NotReady,
    /// A source has accepted bytes not yet covered by its exact durable prefix.
    IncompleteCustody,
    /// Whole-plan polling bound, never clean EOF or permission to replenish allowances.
    Limit,
    /// Current original-byte retention/read/publication authority refused.
    Cancelled,
    /// Native source/reconnect refusal with its original payload-free identity.
    Source(HttpReconnectError),
    /// Current original custody publication or verification refused.
    Archive(HttpArchiveError),
    /// Shared source/publication work allowance was exhausted or cancelled.
    Work(GeometryError),
}
impl From<HttpReconnectError> for HttpReconnectRecordingError {
    fn from(error: HttpReconnectError) -> Self {
        Self::Source(error)
    }
}
impl From<HttpArchiveError> for HttpReconnectRecordingError {
    fn from(error: HttpArchiveError) -> Self {
        Self::Archive(error)
    }
}
impl From<GeometryError> for HttpReconnectRecordingError {
    fn from(error: GeometryError) -> Self {
        Self::Work(error)
    }
}
impl std::fmt::Display for HttpReconnectRecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP reacquisition recording refused: {self:?}")
    }
}
impl std::error::Error for HttpReconnectRecordingError {}

/// Exclusive native reacquisition owner: no mutable camera or responsibility-only wire ACK escape.
pub struct HttpReconnectRecording {
    source: HttpReconnect,
    archives: Vec<HttpWireArchive>,
    index: usize,
    validated: bool,
    work: WorkBudget<'static>,
    steps: u64,
    maximum_steps: u64,
    clock: u64,
    deadline_ns: u64,
    wire_plan: Option<HttpReconnectWirePlan>,
    handoff: Option<HttpReconnectHandoff>,
    boundary: Option<HttpReconnectBoundary>,
}
impl HttpReconnectRecording {
    /// Validate every source and archive slot before any I/O. Existing namespaces are rechecked
    /// against an empty pin immediately before their connection; recovery never means reacquisition.
    pub fn new(
        plan: HttpReconnectRecordingPlan,
        now_ns: u64,
    ) -> Result<Self, HttpReconnectRecordingError> {
        if plan.slots.is_empty()
            || plan.slots.len() > MAX_RECONNECT_CONNECTIONS
            || plan.source_work == 0
            || !(1..=1_000_000).contains(&plan.maximum_steps)
        {
            return Err(HttpReconnectRecordingError::Configuration);
        }
        let mut archives = Vec::with_capacity(plan.slots.len());
        let mut sources = Vec::with_capacity(plan.slots.len());
        for slot in plan.slots {
            if slot.scope.stream != slot.source.route.basis()
                || slot.source.limits.http.wire_bytes > slot.archive.maximum_bytes
            {
                return Err(HttpReconnectRecordingError::Configuration);
            }
            archives.push(HttpWireArchive::new(slot.scope, slot.archive)?);
            sources.push(slot.source);
        }
        let source = HttpReconnect::new(sources, plan.policy, now_ns, plan.deadline_ns)?;
        Ok(Self {
            source,
            archives,
            index: 0,
            validated: false,
            work: WorkBudget::new(plan.source_work),
            steps: 0,
            maximum_steps: plan.maximum_steps,
            clock: now_ns,
            deadline_ns: plan.deadline_ns,
            wire_plan: None,
            handoff: None,
            boundary: None,
        })
    }
    /// Immutable whole-plan network/parser ceilings; reservations do not refill.
    pub fn reservation(&self) -> HttpReconnectReservation {
        self.source.reservation()
    }
    /// Actual aggregate native network/parser usage, including ended sources.
    pub fn totals(&self) -> HttpReconnectTotals {
        self.source.totals()
    }
    /// Current generation's acknowledged durable prefix, not a fresh custody re-verification.
    pub fn pin(&self) -> HttpWirePin {
        self.archives[self.index].pin()
    }
    /// Source and raw-byte retention interpretation of the current generation.
    pub fn scope(&self) -> HttpWireScope {
        self.archives[self.index].scope()
    }
    /// Consumed source/storage work across all generations and all refused operations.
    pub fn source_work_used(&self) -> u64 {
        self.work.used()
    }
    /// Admitted poll calls, including repeated pending/prepared observations.
    pub fn steps(&self) -> u64 {
        self.steps
    }
    /// Exact outstanding expected pin, including after a failed/ambiguous disk publication.
    pub fn pending_wire_plan(&self) -> Option<HttpReconnectWirePlan> {
        self.wire_plan
    }

    /// One bounded source step or custody verification. No storage mutation occurs here.
    pub fn poll(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectRecordingStep, HttpReconnectRecordingError> {
        self.admit(access)?;
        if self.steps >= self.maximum_steps {
            return Err(HttpReconnectRecordingError::Limit);
        }
        self.work.charge(1)?;
        self.steps += 1;
        if let Some(plan) = self.wire_plan {
            return Ok(HttpReconnectRecordingStep::WirePrepared(plan));
        }
        if self.handoff.is_some() {
            return self.prepare_boundary(publisher, access);
        }
        if !self.validated {
            self.reverify(publisher, access)?; // exact EMPTY namespace before any connect
            self.validated = true;
        }
        match self.source.step(access.now_ns, access.camera)? {
            HttpReconnectStep::Connected(basis) => Ok(HttpReconnectRecordingStep::Connected(basis)),
            HttpReconnectStep::Waiting { not_before_ns } => {
                Ok(HttpReconnectRecordingStep::Waiting { not_before_ns })
            }
            HttpReconnectStep::Stopped => Ok(HttpReconnectRecordingStep::Stopped),
            HttpReconnectStep::Source(HttpCameraStep::Advanced) => {
                Ok(HttpReconnectRecordingStep::Advanced)
            }
            HttpReconnectStep::Source(HttpCameraStep::Pending) => {
                Ok(HttpReconnectRecordingStep::Pending)
            }
            HttpReconnectStep::Source(HttpCameraStep::WireReady(_)) => self.prepare_wire(),
            HttpReconnectStep::Source(HttpCameraStep::FrameReady) => {
                let frame = self
                    .source
                    .camera()
                    .and_then(|c| c.pending_frame())
                    .ok_or(HttpReconnectRecordingError::NotReady)?;
                Ok(HttpReconnectRecordingStep::FrameReady(
                    HttpReconnectFrameKey::of(frame),
                ))
            }
            HttpReconnectStep::HandoffReady(_) => {
                self.handoff = self.source.take_handoff();
                self.prepare_boundary(publisher, access)
            }
            HttpReconnectStep::Source(HttpCameraStep::Complete) => {
                Err(HttpReconnectRecordingError::Configuration)
            }
        }
    }
    fn prepare_wire(&mut self) -> Result<HttpReconnectRecordingStep, HttpReconnectRecordingError> {
        let read = match &self.handoff {
            Some(h) => h.source.as_ref().and_then(|s| s.wire.as_ref()),
            None => self.source.pending_wire(),
        }
        .ok_or(HttpReconnectRecordingError::NotReady)?;
        let prepared = self.archives[self.index].prepare(read, &mut self.work)?;
        let plan = HttpReconnectWirePlan {
            wire: read.receipt(),
            pin: prepared.pin(),
        };
        self.wire_plan = Some(plan);
        Ok(HttpReconnectRecordingStep::WirePrepared(plan))
    }
    fn prepare_boundary(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectRecordingStep, HttpReconnectRecordingError> {
        let h = self
            .handoff
            .as_ref()
            .ok_or(HttpReconnectRecordingError::NotReady)?;
        let receipt = h.receipt();
        // A post-read revocation may retire raw bytes before normal WireReady preparation.
        // They remain original custody: publish under independent storage authority, never parse.
        if h.source
            .as_ref()
            .and_then(|s| s.wire.as_ref())
            .is_some_and(|w| w.receipt().range[1] > self.pin().bytes)
        {
            return self.prepare_wire();
        }
        if self.pin().bytes != receipt.totals.received_bytes {
            return Err(HttpReconnectRecordingError::IncompleteCustody);
        }
        if self.boundary.is_none() {
            self.reverify(publisher, access)?;
            self.boundary = Some(HttpReconnectBoundary {
                source: receipt,
                prefix: self.pin(),
            });
        }
        Ok(HttpReconnectRecordingStep::BoundaryReady(
            self.boundary.ok_or(HttpReconnectRecordingError::NotReady)?,
        ))
    }
    /// Revalidate the exact prepared read and publish root-last BEFORE releasing parse backpressure.
    /// On an outer error preserve the same key/source and recover the publisher, not the camera.
    pub fn commit_wire(
        &mut self,
        expected: HttpReconnectWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectWireCommit, HttpReconnectRecordingError> {
        if self.wire_plan != Some(expected) {
            return Err(HttpReconnectRecordingError::PlanMismatch);
        }
        self.admit(access)?;
        let ended = self.handoff.is_some();
        if !ended {
            let camera = self
                .source
                .camera()
                .ok_or(HttpReconnectRecordingError::NotReady)?;
            if access.now_ns >= self.deadline_ns {
                return Err(HttpReconnectError::Source(HttpCameraError::Deadline).into());
            }
            access
                .camera
                .checkpoint(
                    camera.route(),
                    HttpCameraOperation::AcknowledgeWire,
                    access.now_ns,
                    self.deadline_ns,
                )
                .map_err(|e| HttpReconnectError::Source(HttpCameraError::Denied(e)))?;
        }
        let read = match &self.handoff {
            Some(h) => h.source.as_ref().and_then(|s| s.wire.as_ref()),
            None => self.source.pending_wire(),
        }
        .ok_or(HttpReconnectRecordingError::NotReady)?;
        let archive = &mut self.archives[self.index];
        let prepared = archive.prepare(read, &mut self.work)?;
        if read.receipt() != expected.wire || prepared.pin() != expected.pin {
            return Err(HttpReconnectRecordingError::PlanMismatch);
        }
        let publication = archive.publish(&prepared, publisher, access.storage, &mut self.work)?;
        self.wire_plan = None; // durable publication remains visible even if a later ACK fails
        let acknowledgement = if ended {
            None
        } else {
            Some(
                self.source
                    .acknowledge_wire(expected.wire, access.now_ns, access.camera),
            )
        };
        Ok(HttpReconnectWireCommit {
            publication,
            acknowledgement,
        })
    }
    /// Reverify the complete encoded frame's original custody, then release it under live authority.
    /// No pixels are decoded here; downstream decoding still requires the current sensor mask.
    pub fn take_frame(
        &mut self,
        expected: HttpReconnectFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpJpegFrame, HttpReconnectRecordingError> {
        self.admit(access)?;
        let frame = self
            .source
            .camera()
            .and_then(|c| c.pending_frame())
            .ok_or(HttpReconnectRecordingError::NotReady)?;
        if HttpReconnectFrameKey::of(frame) != expected {
            return Err(HttpReconnectRecordingError::PlanMismatch);
        }
        self.archives[self.index].verify_frame(publisher, frame, access.storage, &mut self.work)?;
        Ok(self.source.take_frame(
            expected.ordinal,
            expected.encoded,
            access.now_ns,
            access.camera,
        )?)
    }
    /// Accept this exact independently preserved boundary and transfer its complete original owner.
    /// Reverify again after external delay; missing/deleted/corrupt source prevents the next attempt.
    pub fn release_boundary(
        &mut self,
        expected: HttpReconnectBoundary,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectHandoff, HttpReconnectRecordingError> {
        if self.boundary != Some(expected) || self.handoff.is_none() || self.wire_plan.is_some() {
            return Err(HttpReconnectRecordingError::PlanMismatch);
        }
        self.admit(access)?;
        self.reverify(publisher, access)?;
        if self.pin() != expected.prefix {
            return Err(HttpReconnectRecordingError::PlanMismatch);
        }
        self.source.acknowledge_handoff(expected.source)?;
        let handoff = self
            .handoff
            .take()
            .ok_or(HttpReconnectRecordingError::NotReady)?;
        self.boundary = None;
        if expected.source.next_source.is_some() {
            self.index += 1;
            self.validated = false;
        }
        Ok(handoff)
    }
    fn reverify(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), HttpReconnectRecordingError> {
        let archive = &self.archives[self.index];
        let verified = HttpWireArchive::load(
            publisher,
            archive.scope(),
            archive.pin(),
            archive.limits(),
            access.storage,
            &mut self.work,
        )?;
        self.archives[self.index] = verified;
        Ok(())
    }
    fn admit(
        &mut self,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), HttpReconnectRecordingError> {
        if access.now_ns < self.clock {
            return Err(HttpReconnectError::ClockReversed.into());
        }
        self.clock = access.now_ns;
        if access
            .storage
            .cancel_requested(PublishCutPoint::AfterChildrenVerified)
        {
            return Err(HttpReconnectRecordingError::Cancelled);
        }
        Ok(())
    }
    /// Transfer every unfinished source, exact prepared pin, boundary and archive without I/O.
    /// Nothing is repaired, silently discarded, reconnected or labelled complete during retirement.
    pub fn retire(self) -> HttpReconnectRecordingRetirement {
        HttpReconnectRecordingRetirement {
            source_work: self.work.used(),
            steps: self.steps,
            source: self.source.retire(),
            archives: self.archives,
            handoff: self.handoff,
            wire_plan: self.wire_plan,
            boundary: self.boundary,
        }
    }
}
/// Complete recording ownership for caller-led recovery, not permission to resume acquisition.
#[must_use]
pub struct HttpReconnectRecordingRetirement {
    /// Active source and any source handoff still owned by the native supervisor.
    pub source: HttpReconnectRetirement,
    /// Exact acknowledged indexes. Fresh recovery must reverify their pins against the publisher.
    pub archives: Vec<HttpWireArchive>,
    /// Ended-source bytes and parser remainders awaiting durable-custody boundary release.
    pub handoff: Option<HttpReconnectHandoff>,
    /// Exact expected raw publication to reconcile, never a request to reacquire it.
    pub wire_plan: Option<HttpReconnectWirePlan>,
    /// Boundary preserved before external release; it does not refill any resource allowance.
    pub boundary: Option<HttpReconnectBoundary>,
    /// Whole-plan storage/source work already consumed.
    pub source_work: u64,
    /// Whole-plan poll calls already consumed.
    pub steps: u64,
}

#[cfg(test)]
mod tests;
