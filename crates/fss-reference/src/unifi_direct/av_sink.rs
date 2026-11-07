#![forbid(unsafe_code)]
//! One-segment source-custody bridge between a supervisor and the archive.
//!
//! The caller must stop polling the supervisor while `has_pending` is true.
//! This synchronous reference owner does not run a service or authenticate a
//! camera. Independently justified capture bounds and retention authority are
//! required; neither sender time nor receipt time supplies those bounds.

use asupersync::io::{AsyncRead, AsyncWrite};
use fss_container::{InitializationSegment, flv_av};
use fss_core::{CaptureInterval, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_packet::extended_flv::{aac, aac_track, stream::SourceRecord};

use super::{
    AudioCodec, VideoChannel, archive, av_recording, conversation, events, evidence, intent,
    management, motion, pipeline, receive, recording, supervisor,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_runtime::effect::CommittedEffect;
use std::time::Duration;

/// Audio configuration and its explicitly classified source.
pub enum Audio<'a> {
    /// Configuration bound to its exact original source record.
    InBand(&'a aac_track::BoundConfiguration<'a>),
    /// Configuration bytes supplied without original-source proof.
    SuppliedUnverified(&'a aac::Configuration<'a>),
}

/// A refused segment remains owned by the caller.
#[must_use]
pub struct Refusal {
    /// Why the segment was refused.
    pub reason: RefusalReason,
    /// The unchanged original segment.
    pub segment: recording::Segment,
    /// The unchanged caller-supplied capture bounds.
    pub capture: CaptureInterval,
}

/// Payload-free reason for refusing ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    /// An earlier segment has not yet reached a confirmed archive receipt.
    Pending,
    /// The segment names a different original video configuration.
    Configuration,
}

struct Pending {
    segment: recording::Segment,
    capture: CaptureInterval,
}

/// Bounded handoff owner. It retains at most one completed source segment;
/// a publication refusal leaves that exact segment and muxer state available
/// for reconciliation. The caller retains configuration source custody.
pub struct Sink<'a> {
    video_configuration: &'a SourceRecord,
    av_initialization: flv_av::Initialization,
    audio: Audio<'a>,
    muxer: av_recording::Muxer,
    retention: ContentDigest,
    evidence_limits: evidence::Limits,
    pending: Option<Pending>,
}

/// Source and state returned when an owner is deliberately retired.
#[must_use]
pub struct Retirement {
    /// Unpublished or indeterminate source and its proposed capture bounds.
    pub pending: Option<(recording::Segment, CaptureInterval)>,
    /// Muxer, including any unresolved in-memory publication fence.
    pub muxer: av_recording::Muxer,
    /// Initialization bound to that muxer.
    pub av_initialization: flv_av::Initialization,
}

impl<'a> Sink<'a> {
    /// Attach existing, caller-bound configuration and mux state. The archive
    /// independently validates their consistency when publication is attempted.
    pub fn new(
        video_configuration: &'a SourceRecord,
        av_initialization: flv_av::Initialization,
        audio: Audio<'a>,
        muxer: av_recording::Muxer,
        retention: ContentDigest,
        evidence_limits: evidence::Limits,
    ) -> Self {
        Self {
            video_configuration,
            av_initialization,
            audio,
            muxer,
            retention,
            evidence_limits,
            pending: None,
        }
    }

    /// Reattach an in-process retirement without discarding its unresolved
    /// segment or muxer fence. The caller must restore the same configuration,
    /// retention decision and journal scope; publication revalidates bindings.
    pub fn resume(
        video_configuration: &'a SourceRecord,
        audio: Audio<'a>,
        retention: ContentDigest,
        evidence_limits: evidence::Limits,
        retirement: Retirement,
    ) -> Self {
        Self {
            video_configuration,
            av_initialization: retirement.av_initialization,
            audio,
            muxer: retirement.muxer,
            retention,
            evidence_limits,
            pending: retirement
                .pending
                .map(|(segment, capture)| Pending { segment, capture }),
        }
    }

    /// Whether input polling must stop until publication is reconciled. A
    /// supplied muxer may already carry a fence whose source is not in this
    /// owner; retire and reconstruct that prior source in that case.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some() || self.muxer.pending_publication().is_some()
    }

    /// Transfer one completed supervisor segment and independently supplied
    /// capture bounds. Refusal returns the exact source without modifying the
    /// earlier pending segment or muxer.
    pub fn offer(
        &mut self,
        segment: recording::Segment,
        capture: CaptureInterval,
    ) -> Result<(), Refusal> {
        let binding = segment.configuration();
        let reason = if self.has_pending() {
            Some(RefusalReason::Pending)
        } else if binding.source_offset != self.video_configuration.offset()
            || binding.source_bytes != self.video_configuration.bytes().len()
            || binding.source_digest != ContentDigest::sha256(self.video_configuration.bytes())
        {
            Some(RefusalReason::Configuration)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Refusal {
                reason,
                segment,
                capture,
            });
        }
        self.pending = Some(Pending { segment, capture });
        Ok(())
    }

    /// Publish the pending source using the separate anchor keeper. A failure
    /// retains the pending segment, including after an indeterminate effect;
    /// cold recovery still requires reconstruction of muxer and source state.
    /// An empty sink returns `None` without touching either store.
    pub fn flush(
        &mut self,
        video_initialization: &InitializationSegment,
        deployment: &mut ReferenceDeployment,
        authority: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        journal: &mut archive::journal::Journal,
        keeper: &mut archive::journal::AnchorKeeper,
    ) -> Result<Option<archive::PublishedAvSegment>, archive::AvSegmentPublishError> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        let audio = match &self.audio {
            Audio::InBand(bound) => archive::AvSegmentAudio::InBand(bound),
            Audio::SuppliedUnverified(config) => {
                archive::AvSegmentAudio::SuppliedUnverified(config)
            }
        };
        let input = archive::AvSegmentPublication {
            segment: &pending.segment,
            video_configuration: self.video_configuration,
            video_initialization,
            av_initialization: &self.av_initialization,
            audio,
            retention: self.retention,
            capture: pending.capture,
            evidence_limits: self.evidence_limits,
        };
        let result = archive::publish_next_av_segment_anchored(
            &input,
            &mut self.muxer,
            deployment,
            authority,
            limits,
            work,
            cx,
            journal,
            keeper,
        )?;
        self.pending = None;
        Ok(Some(result))
    }

    /// Return all owned source and mux state; borrowed configuration stays with
    /// its caller. No unresolved effect is classified by retirement itself.
    pub fn retire(self) -> Retirement {
        Retirement {
            pending: self
                .pending
                .map(|pending| (pending.segment, pending.capture)),
            muxer: self.muxer,
            av_initialization: self.av_initialization,
        }
    }
}

/// A supervised step transfers non-segment results unchanged; segments stay
/// inside the guard until capture bounds and archive publication are resolved.
#[must_use]
#[derive(Debug)]
pub enum GuardStep {
    /// One completed source segment needs independent capture bounds.
    CaptureRequired,
    /// An archive attempt or previously fenced muxer must be reconciled.
    ArchivePending,
    /// The task's cancellation checkpoint was refused; retire the guard.
    Cancelled,
    /// Any other controller or media result, including explicit source custody.
    Supervisor(supervisor::Step),
}

/// Capture assignment refusal; the segment remains owned by the guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// No unbounded segment is currently held.
    NoSegment,
    /// The sink refused the segment and the guard retained it unchanged.
    Refused(RefusalReason),
}

/// Publication refusal at the guarded supervisor boundary.
#[derive(Debug)]
pub enum GuardFlushError {
    /// Independent capture bounds have not yet been supplied.
    CaptureRequired,
    /// The attached supervisor has no video initialization.
    MissingInitialization,
    /// An archive failure, possibly indeterminate; reconcile the same root.
    Archive(archive::AvSegmentPublishError),
}

/// A supervisor and sink with enforced one-segment backpressure.
/// It does not spawn work or provide a continuous service. The caller must
/// arrange independent capture bounds and supervise synchronous persistence.
pub struct Guard<'a, 'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    sink: Sink<'a>,
    awaiting_capture: Option<recording::Segment>,
}

/// All remaining owned state when a guarded supervisor is closed.
#[must_use]
pub struct GuardRetirement {
    /// A completed source segment for which capture bounds were unavailable.
    pub awaiting_capture: Option<recording::Segment>,
    /// Source and muxer state held by the sink.
    pub sink: Retirement,
    /// Both transport owners and their remaining source.
    pub supervisor: supervisor::Retirement,
}

impl<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Guard<'a, 'scope, 'task, IO> {
    /// Attach an existing task-owned supervisor and its matching sink.
    /// The caller binds their connection and configuration to the same camera.
    pub fn new(supervisor: supervisor::Supervisor<'scope, 'task, IO>, sink: Sink<'a>) -> Self {
        Self {
            supervisor,
            sink,
            awaiting_capture: None,
        }
    }

    /// Transfer a segment already returned before this guard was attached.
    /// On backpressure, the unchanged segment returns to its caller.
    pub fn hold_segment(&mut self, segment: recording::Segment) -> Result<(), recording::Segment> {
        if self.awaiting_capture.is_some() || self.sink.has_pending() {
            return Err(segment);
        }
        self.awaiting_capture = Some(segment);
        Ok(())
    }

    /// Borrow the source whose capture bounds need independent justification.
    pub fn awaiting_capture(&self) -> Option<&recording::Segment> {
        self.awaiting_capture.as_ref()
    }

    /// Assign separately justified bounds. Any refusal retains the segment.
    pub fn supply_capture(&mut self, capture: CaptureInterval) -> Result<(), CaptureError> {
        let segment = self
            .awaiting_capture
            .take()
            .ok_or(CaptureError::NoSegment)?;
        if let Err(refusal) = self.sink.offer(segment, capture) {
            self.awaiting_capture = Some(refusal.segment);
            return Err(CaptureError::Refused(refusal.reason));
        }
        Ok(())
    }

    /// Perform one bounded task-owned supervisor step. While a segment is
    /// pending, no controller or media input is polled by this method.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> GuardStep {
        if owner.cx.checkpoint().is_err() {
            return GuardStep::Cancelled;
        }
        if self.awaiting_capture.is_some() {
            return GuardStep::CaptureRequired;
        }
        if self.sink.has_pending() {
            return GuardStep::ArchivePending;
        }
        match self.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(
                segment,
            ))) => {
                self.awaiting_capture = Some(segment);
                GuardStep::CaptureRequired
            }
            other => GuardStep::Supervisor(other),
        }
    }

    /// Service only controller input while a source segment is pending. This
    /// never polls media and uses the supervisor's ordinary admission,
    /// cancellation, event and journaled time-sync rules. Callers must schedule
    /// it explicitly; synchronous `flush` cannot run concurrently in this owner.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.supervisor.step_control(owner, operation, wait).await
    }

    /// Transfer the supervisor's bounded audio observation under its normal
    /// task, cancellation and controller-admission checks.
    pub fn take_audio_event(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
    ) -> Option<pipeline::AudioEvent> {
        self.supervisor.take_audio_event(owner)
    }

    /// Prepare a source-bound camera event reply under the supervisor's checks.
    pub fn prepare_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
        timestamp: &str,
    ) -> Result<management::Intent, receive::Error> {
        self.supervisor.prepare_event_reply(owner, frame, timestamp)
    }

    /// Explicitly omit an event reply under the supervisor's checks.
    pub fn omit_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<(), receive::Error> {
        self.supervisor.omit_event_reply(owner, frame)
    }

    /// Abandon an unwritten event reply while preserving its request.
    pub fn abandon_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<u64, receive::Error> {
        self.supervisor.abandon_event_reply(owner, frame)
    }

    /// Dispatch an event reply with its separately journaled effect permit.
    pub async fn dispatch_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: management::Intent,
        current: management::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::ManagementWrite, receive::ManagementRefusal> {
        self.supervisor
            .dispatch_event_reply(owner, intent, current, permit, wait)
            .await
    }

    /// Prepare a motion-setting effect under the supervisor's checks.
    pub fn prepare_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        enabled: bool,
        timestamp: &str,
        conditions: motion::Preconditions,
    ) -> Result<motion::Intent, receive::Error> {
        self.supervisor
            .prepare_motion(owner, enabled, timestamp, conditions)
    }

    /// Dispatch a motion setting with an independently committed permit.
    pub async fn dispatch_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: motion::Intent,
        current: motion::Preconditions,
        permit: CommittedEffect,
        authority: &dyn receive::MotionAuthority,
        wait: Duration,
    ) -> Result<receive::MotionWrite, receive::MotionRefusal> {
        self.supervisor
            .dispatch_motion(owner, intent, current, permit, authority, wait)
            .await
    }

    /// Prepare an inert stream-quiesce request.
    pub fn prepare_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        channel: VideoChannel,
        audio: AudioCodec,
        timestamp: &str,
        conditions: intent::Preconditions,
    ) -> Result<intent::Intent, receive::Error> {
        self.supervisor
            .prepare_quiesce(owner, channel, audio, timestamp, conditions)
    }

    /// Abandon a locally unwritten stream request under the supervisor's checks.
    pub fn abandon_prepared_stream(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
    ) -> Result<super::AbandonedStream, receive::Error> {
        self.supervisor.abandon_prepared_stream(owner, intent)
    }

    /// Dispatch a prepared stream-quiesce request with its committed permit.
    pub async fn dispatch_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
        current: intent::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::StreamWrite, receive::StreamRefusal> {
        self.supervisor
            .dispatch_quiesce(owner, intent, current, permit, wait)
            .await
    }

    /// Resolve the pending archive attempt without releasing its source on an
    /// error. This uses synchronous reference I/O, not an async storage worker.
    pub fn flush(
        &mut self,
        deployment: &mut ReferenceDeployment,
        authority: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        journal: &mut archive::journal::Journal,
        keeper: &mut archive::journal::AnchorKeeper,
    ) -> Result<Option<archive::PublishedAvSegment>, GuardFlushError> {
        if self.awaiting_capture.is_some() {
            return Err(GuardFlushError::CaptureRequired);
        }
        let initialization = self
            .supervisor
            .initialization()
            .ok_or(GuardFlushError::MissingInitialization)?;
        self.sink
            .flush(
                initialization,
                deployment,
                authority,
                limits,
                work,
                cx,
                journal,
                keeper,
            )
            .map_err(GuardFlushError::Archive)
    }

    /// Close both transports and return every segment still held by this guard.
    pub fn retire(self) -> GuardRetirement {
        GuardRetirement {
            awaiting_capture: self.awaiting_capture,
            sink: self.sink.retire(),
            supervisor: self.supervisor.retire(),
        }
    }
}
