#![forbid(unsafe_code)]
//! Durable original HTTP reads -> native RGB inference -> anonymous tracks -> zones.
//!
//! This is the exclusive recording owner for the existing RGB capture pipeline. It
//! exposes no responsibility-only acknowledgement, mutable camera, or mutable archive.
//! A prepared original-read pin must be explicitly committed before parsing can advance.
//! Original custody is reverified before inference, resumption and result transfer.
//! The existing processor retains accepted work on downstream pressure or revocation.
//!
//! Network termination, delivered perception results and durable source completion are
//! distinct states. Completion is prepared only from the drained native camera, never
//! from a timeout, frame limit, empty detection set or caller-authored EOF. Derived
//! results are transferred to the caller, NOT automatically persisted or published as
//! authoritative events. Their scores, availability and capture times keep the existing
//! explicit trust boundaries. No worker, reconnect, model download or alert is added.

use super::http_archive::{
    HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWirePin, HttpWireScope,
};
use super::http_camera::rgb::custody::{
    HttpRgbCustody, HttpRgbCustodyError, HttpRgbWireCommit, HttpRgbWirePlan,
};
use super::http_camera::rgb::{
    HttpRgbBudgets, HttpRgbCapture, HttpRgbContext, HttpRgbError, HttpRgbOutput, HttpRgbReceipt,
    HttpRgbRetirement, HttpRgbStep,
};
use super::http_camera::{HttpCameraStep, HttpCameraTotals};
use super::http_recording::HttpRecordingAccess;
use super::http_replay::check::HttpCheckLimits;
use super::http_replay::completion::{
    HttpCompletionError, HttpCompletionPin, PreparedHttpCompletion,
};
use super::rgb_detections::RgbDetectionBudget;
use super::rgb_inference::RgbRunLimits;
use super::rgb_tracking::pipeline::RgbZonePhase;
use crate::ScalarExecCx;
use fss_codec_mjpeg::DecodeBudget;
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::MAX_MANIFEST_CHILDREN;
use fss_publication::{LocalPublicationReceipt, LocalRootPublisher, PublishCutPoint};

/// Refusal never asserts a clean stream end, successful analysis, or an empty scene.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbRecordingError {
    /// Invalid independent limits, nonfresh owners or incompatible source scope.
    Configuration,
    /// Explicit current storage authority or cancellation probe refused.
    Cancelled,
    /// Complete-session work, poll or frame capacity is exhausted.
    Limit,
    /// The supplied prepared key differs; no publication or transfer was attempted.
    PlanMismatch,
    /// The native owners have not reached this operation's required boundary.
    NotReady,
    /// Native acquisition, inference wrapper or live camera authority refused.
    Capture(HttpRgbError),
    /// Existing prepare/publish/acknowledge transaction refused.
    Custody(HttpRgbCustodyError),
    /// Current retained original bytes or archive identity could not be verified.
    Archive(HttpArchiveError),
    /// Existing native-terminal publication refused.
    Completion(HttpCompletionError),
    /// The whole-session source/linking work budget refused.
    Work(GeometryError),
}
macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for HttpRgbRecordingError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}
from_error!(HttpRgbError, Capture);
from_error!(HttpRgbCustodyError, Custody);
from_error!(HttpArchiveError, Archive);
from_error!(HttpCompletionError, Completion);
from_error!(GeometryError, Work);
impl std::fmt::Display for HttpRgbRecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "durable HTTP RGB recording refused: {self:?}")
    }
}
impl std::error::Error for HttpRgbRecordingError {}

/// Attachment failure returns the entire original source/processor owner unchanged.
#[must_use]
pub struct HttpRgbRecordingAttachFailure<'model, 'temporal> {
    /// Exact refusal; no source read or acknowledgement was performed.
    pub reason: HttpRgbRecordingError,
    /// Original owner, including its connected socket and borrowed temporal state.
    pub capture: HttpRgbCapture<'model, 'temporal>,
}
impl std::fmt::Debug for HttpRgbRecordingAttachFailure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRgbRecordingAttachFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HttpRgbRecordingAttachFailure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HttpRgbRecordingAttachFailure<'_, '_> {}

/// Separate source, perception and durable-terminal progress at the owner boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRgbRecordingStep {
    /// One bounded native socket/framing operation advanced.
    Advanced,
    /// WouldBlock/Interrupted: wait under the external owner, never spin here.
    Pending,
    /// Save this exact pin before committing. Parsing is still backpressured.
    WirePrepared(HttpRgbWirePlan),
    /// Independent context is required, or accepted analysis/result remains held.
    Analysis(HttpRgbStep),
    /// Native HTTP and MIME ended after every perception result was transferred.
    /// Save this exact pin before publishing the original-source completion graph.
    CompletionPrepared(HttpCompletionPin),
    /// The native terminal graph was durably published; not a coverage/quality proof.
    Complete(HttpCompletionPin),
}

/// Whole-session source work, separate from externally owned neural/temporal budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbRecordingWork {
    /// Admitted poll calls, including ones returning Pending or an unchanged barrier.
    pub polls: u64,
    /// Original storage, source mapping and verification units consumed, including failures.
    pub source: u64,
    /// Native HTTP and MIME work consumed; never refilled on another frame.
    pub framing: u64,
    /// Complete perception results successfully transferred, not just MIME frame count.
    pub transferred: u64,
}

/// One exclusive native connection and its durable original-source/perception barriers.
/// The processor may borrow an existing temporal episode; no mutable escape is exposed.
/// Callers provide current camera AND storage authority on every state-changing operation.
/// Neural, projection and temporal budgets remain independently owned and are never reset
/// by this wrapper. Owner-selected HttpCheckLimits bound the whole recording's source work.
pub struct HttpRgbRecording<'model, 'temporal> {
    capture: HttpRgbCapture<'model, 'temporal>,
    archive: HttpWireArchive,
    limits: HttpCheckLimits,
    polls: u64,
    work: WorkBudget<'static>,
    framing: DecodeBudget<'static>,
    wire_plan: Option<HttpRgbWirePlan>,
    terminal: Option<PreparedHttpCompletion>,
    complete: Option<HttpCompletionPin>,
    transferred: u64,
}

impl<'model, 'temporal> HttpRgbRecording<'model, 'temporal> {
    /// Attach fresh acquisition/analysis and verify an EMPTY source namespace before any
    /// HTTP request is sent. The camera may already own TCP; no request/read occurs here.
    /// Reusing a retained generation is refused, not treated as permission to reconnect.
    /// A rejection returns the entire capture unchanged for explicit retirement or recovery.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        capture: HttpRgbCapture<'model, 'temporal>,
        publisher: &LocalRootPublisher,
        scope: HttpWireScope,
        limits: HttpCheckLimits,
        access: HttpRecordingAccess<'_>,
    ) -> Result<Self, HttpRgbRecordingAttachFailure<'model, 'temporal>> {
        let prepare = || -> Result<_, HttpRgbRecordingError> {
            limits
                .validate()
                .map_err(|_| HttpRgbRecordingError::Configuration)?;
            if capture.camera().totals() != HttpCameraTotals::default()
                || capture.camera().failure().is_some()
                || capture.phase() != RgbZonePhase::Ready
                || capture.last_taken().is_some()
                || capture.camera().route().basis() != scope.stream
                || limits.maximum_reads >= MAX_MANIFEST_CHILDREN
                || publisher.limits().max_children <= limits.maximum_reads
                || publisher.limits().spool.max_object_bytes
                    < limits
                        .read_bytes
                        .max(1024 + (limits.maximum_reads + 1) * 64)
            {
                return Err(HttpRgbRecordingError::Configuration);
            }
            probe(access)?;
            let mut work = WorkBudget::new(limits.source_work);
            let bounds = HttpArchiveLimits {
                maximum_reads: limits.maximum_reads,
                maximum_bytes: limits.maximum_source_bytes,
                maximum_scan_roots: limits.maximum_scan_roots,
                maximum_spool_object_bytes: limits.maximum_spool_object_bytes,
            };
            let empty = HttpWireArchive::new(scope, bounds)?;
            let archive = HttpWireArchive::load(
                publisher,
                scope,
                empty.pin(),
                bounds,
                access.storage,
                &mut work,
            )?;
            Ok((archive, work))
        };
        match prepare() {
            Err(reason) => Err(HttpRgbRecordingAttachFailure { reason, capture }),
            Ok((archive, work)) => Ok(Self {
                capture,
                archive,
                limits,
                polls: 0,
                work,
                framing: DecodeBudget::new(limits.framing_work),
                wire_plan: None,
                terminal: None,
                complete: None,
                transferred: 0,
            }),
        }
    }

    /// Read-only acquisition, mapped frame and accepted computation. Historical data is not
    /// a new disclosure grant. In particular, no camera acknowledgement can be invoked here.
    pub fn capture(&self) -> &HttpRgbCapture<'model, 'temporal> {
        &self.capture
    }
    /// Last actually published original prefix, including after a late camera ACK denial.
    pub fn pin(&self) -> HttpWirePin {
        self.archive.pin()
    }
    /// Immutable original-byte retention and receive-clock scope; not a live grant.
    pub fn scope(&self) -> HttpWireScope {
        self.archive.scope()
    }
    /// Exact prepared original-read plan, retained across publication/acknowledgement failure.
    pub fn pending_wire_plan(&self) -> Option<HttpRgbWirePlan> {
        self.wire_plan
    }
    /// Exact native terminal key prepared before storage I/O.
    pub fn prepared_completion(&self) -> Option<HttpCompletionPin> {
        self.terminal.as_ref().map(|t| t.pin())
    }
    /// Historical successful durable terminal publication, not a fresh storage verification.
    pub fn completion(&self) -> Option<HttpCompletionPin> {
        self.complete
    }
    /// Actual cumulative source/parser work and delivered perception count.
    pub fn work(&self) -> HttpRgbRecordingWork {
        HttpRgbRecordingWork {
            polls: self.polls,
            source: self.work.used(),
            framing: self.framing.used(),
            transferred: self.transferred,
        }
    }

    /// Run one bounded native acquisition operation. A pending original read cannot be
    /// parsed; accepted neural work and completed output cannot be displaced by later frames.
    pub fn poll(
        &mut self,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRgbRecordingStep, HttpRgbRecordingError> {
        probe(access)?;
        if self.polls == self.limits.maximum_steps {
            return Err(HttpRgbRecordingError::Limit);
        }
        self.work.charge(1)?;
        self.polls += 1;
        let step = self
            .capture
            .step(access.now_ns, access.camera, &mut self.framing)?;
        self.check_frame_bound()?;
        match step {
            HttpRgbStep::Source(HttpCameraStep::Advanced) => Ok(HttpRgbRecordingStep::Advanced),
            HttpRgbStep::Source(HttpCameraStep::Pending) => Ok(HttpRgbRecordingStep::Pending),
            HttpRgbStep::Source(HttpCameraStep::WireReady(wire)) => {
                if let Some(plan) = self.wire_plan {
                    if plan.wire() != wire {
                        return Err(HttpRgbRecordingError::PlanMismatch);
                    }
                    return Ok(HttpRgbRecordingStep::WirePrepared(plan));
                }
                let plan = self.capture.prepare_wire_custody(
                    &self.archive,
                    access.now_ns,
                    access.camera,
                    &mut self.work,
                )?;
                self.wire_plan = Some(plan);
                Ok(HttpRgbRecordingStep::WirePrepared(plan))
            }
            HttpRgbStep::Source(HttpCameraStep::Complete) => {
                if self.transferred != self.capture.camera().totals().frames {
                    return Err(HttpRgbRecordingError::NotReady);
                }
                if let Some(pin) = self.complete {
                    return Ok(HttpRgbRecordingStep::Complete(pin));
                }
                if self.terminal.is_none() {
                    self.terminal = Some(PreparedHttpCompletion::from_camera(
                        self.capture.camera(),
                        &self.archive,
                        &mut self.work,
                    )?);
                }
                Ok(HttpRgbRecordingStep::CompletionPrepared(
                    self.prepared_completion()
                        .ok_or(HttpRgbRecordingError::NotReady)?,
                ))
            }
            HttpRgbStep::Source(HttpCameraStep::FrameReady) => Err(HttpRgbRecordingError::NotReady),
            analysis => Ok(HttpRgbRecordingStep::Analysis(analysis)),
        }
    }

    /// Publish the exact previously prepared original read, THEN release its parse barrier.
    /// A successful disk write with a denied camera ACK returns BOTH outcomes. Recover a
    /// poisoned publisher explicitly and retry the SAME plan; no new request is issued here.
    pub fn commit_wire(
        &mut self,
        expected: HttpRgbWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRgbWireCommit, HttpRgbRecordingError> {
        if self.wire_plan != Some(expected) {
            return Err(HttpRgbRecordingError::PlanMismatch);
        }
        probe(access)?;
        let result = self.capture.retain_wire(
            expected,
            access.now_ns,
            access.camera,
            HttpRgbCustody {
                archive: &mut self.archive,
                publisher,
                cancellation: access.storage,
                work: &mut self.work,
            },
        )?;
        if result.acknowledgement().is_ok() {
            self.wire_plan = None;
        }
        // No optional post-publication check can hide a successful durable write.
        Ok(result)
    }

    fn check_frame_bound(&self) -> Result<(), HttpRgbRecordingError> {
        if self.capture.camera().totals().frames > self.limits.maximum_frames as u64 {
            Err(HttpRgbRecordingError::Limit)
        } else {
            Ok(())
        }
    }
    fn verify_frame(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), HttpRgbRecordingError> {
        probe(access)?;
        self.check_frame_bound()?;
        if self.wire_plan.is_some() {
            return Err(HttpRgbRecordingError::NotReady);
        }
        let frame = self
            .capture
            .frame()
            .ok_or(HttpRgbRecordingError::NotReady)?;
        self.archive
            .verify_frame(publisher, frame, access.storage, &mut self.work)?;
        probe(access)
    }

    /// Verify durable originals before the first native decode/inference of this part.
    /// The existing capture owner validates exact source context and resolves the named
    /// sensor's current retained privacy mask before pixels reach the frozen neural model.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze(
        &mut self,
        context: HttpRgbContext<'_>,
        limits: RgbRunLimits,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        budgets: HttpRgbBudgets<'_, '_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbRecordingError> {
        self.verify_frame(publisher, access)?;
        Ok(self
            .capture
            .analyze(context, limits, access.now_ns, access.camera, budgets, cx)?)
    }

    /// Reverify originals and resume ONLY unfinished stages. No new JPEG, model, capture
    /// context or privacy policy can replace accepted input, and no budget is refilled.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        projection: &mut RgbDetectionBudget,
        temporal: &mut WorkBudget<'_>,
        linking: &mut WorkBudget<'_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbRecordingError> {
        self.verify_frame(publisher, access)?;
        Ok(self.capture.resume(
            access.now_ns,
            access.camera,
            projection,
            temporal,
            linking,
            cx,
        )?)
    }

    /// Transfer the exact completed native result and mapped original frame together.
    /// Custody corruption between analysis and delivery is refused without discarding either
    /// owner. Success is a transfer to the caller, not a derivative/event publication.
    pub fn take_result(
        &mut self,
        expected: HttpRgbReceipt,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRgbOutput, HttpRgbRecordingError> {
        if self.capture.completion() != Some(expected) {
            return Err(HttpRgbRecordingError::PlanMismatch);
        }
        let next = self
            .transferred
            .checked_add(1)
            .ok_or(HttpRgbRecordingError::Limit)?;
        self.verify_frame(publisher, access)?;
        let output = self
            .capture
            .take_result(expected, access.now_ns, access.camera)?;
        self.transferred = next;
        // No allocation, cancellation or fallible storage operation follows the transfer.
        Ok(output)
    }

    /// Publish native terminal metadata only under the exact independently saved pin.
    /// Existing completion publication revalidates the entire original-read closure.
    pub fn commit_completion(
        &mut self,
        expected: HttpCompletionPin,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<LocalPublicationReceipt, HttpRgbRecordingError> {
        if self.prepared_completion() != Some(expected) {
            return Err(HttpRgbRecordingError::PlanMismatch);
        }
        probe(access)?;
        if self
            .capture
            .step(access.now_ns, access.camera, &mut self.framing)?
            != HttpRgbStep::Source(HttpCameraStep::Complete)
            || self.transferred != self.capture.camera().totals().frames
        {
            return Err(HttpRgbRecordingError::NotReady);
        }
        let receipt = self
            .terminal
            .as_ref()
            .ok_or(HttpRgbRecordingError::NotReady)?
            .publish(&self.archive, publisher, access.storage, &mut self.work)?;
        self.complete = Some(expected);
        Ok(receipt)
    }

    /// Close without another request and transfer every original/archive/unfinished result.
    /// Retirement is never completion, permission to reconnect, or a fabricated coverage gap.
    pub fn retire(self) -> HttpRgbRecordingRetirement {
        let work = self.work();
        HttpRgbRecordingRetirement {
            capture: self.capture.retire(),
            archive: self.archive,
            pending_wire: self.wire_plan,
            prepared_completion: self.terminal,
            completion: self.complete,
            work,
        }
    }
}

/// Entire retirement ownership, including exact pins required after a publication cut.
pub struct HttpRgbRecordingRetirement {
    /// Native source remainder, mapped frame, accepted processor state and held output.
    pub capture: HttpRgbRetirement,
    /// Actual original-read prefix inventory, including writes whose camera ACK failed.
    pub archive: HttpWireArchive,
    /// Exact original-read plan still awaiting publication or acknowledgement.
    pub pending_wire: Option<HttpRgbWirePlan>,
    /// Native terminal record prepared before storage publication, when present.
    pub prepared_completion: Option<PreparedHttpCompletion>,
    /// Historical successful durable terminal publication, when present.
    pub completion: Option<HttpCompletionPin>,
    /// Actual complete-session work and transfer counts at retirement.
    pub work: HttpRgbRecordingWork,
}

fn probe(access: HttpRecordingAccess<'_>) -> Result<(), HttpRgbRecordingError> {
    if access
        .storage
        .cancel_requested(PublishCutPoint::AfterChildrenVerified)
    {
        Err(HttpRgbRecordingError::Cancelled)
    } else {
        Ok(())
    }
}
