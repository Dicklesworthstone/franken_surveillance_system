#![forbid(unsafe_code)]
//! Select an existing acquisition owner without exposing a mutable durable-owner bypass.

use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_core::ContentDigest;
use fss_publication::LocalRootPublisher;
use fss_reference::http_reconnect_history::{
    ArchivedReconnectBoundary, BoundaryOutcome, DurableReconnectRecording, DurableReconnectStep,
    ReconnectHistoryPin,
};
use fss_reference::ingest::http_reconnect::HttpReconnectStop;
use fss_reference::ingest::http_reconnect_recording::{
    HttpReconnectBoundary, HttpReconnectFrameKey, HttpReconnectRecording,
    HttpReconnectRecordingPlan, HttpReconnectWireCommit, HttpReconnectWirePlan,
};
use fss_reference::ingest::http_recording::HttpRecordingAccess;

use super::{Failure, boundary_json, object, pin_json, sha_bytes, string};

/// Presentation can advance only the selected owner. History mode has no native boundary ACK.
pub(super) trait Recording {
    fn native(&self) -> &HttpReconnectRecording;
    fn poll_step(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<DurableReconnectStep, Failure>;
    fn commit_wire_step(
        &mut self,
        plan: HttpReconnectWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectWireCommit, Failure>;
    fn take_frame_step(
        &mut self,
        key: HttpReconnectFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpJpegFrame, Failure>;
    fn release_source_boundary(
        &mut self,
        _: HttpReconnectBoundary,
        _: &LocalRootPublisher,
        _: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        Err(Failure::Inconsistent)
    }
    fn history(&self) -> Option<&DurableReconnectRecording> {
        None
    }
    fn commit_history(
        &mut self,
        _: ReconnectHistoryPin,
        _: &mut LocalRootPublisher,
        _: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        Err(Failure::Inconsistent)
    }
    fn release_history(
        &mut self,
        _: ReconnectHistoryPin,
        _: &LocalRootPublisher,
        _: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        Err(Failure::Inconsistent)
    }
    fn retire_owner(self: Box<Self>);
}

impl Recording for HttpReconnectRecording {
    fn native(&self) -> &HttpReconnectRecording {
        self
    }
    fn poll_step(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<DurableReconnectStep, Failure> {
        Ok(DurableReconnectStep::Source(self.poll(publisher, access)?))
    }
    fn commit_wire_step(
        &mut self,
        plan: HttpReconnectWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectWireCommit, Failure> {
        Ok(self.commit_wire(plan, publisher, access)?)
    }
    fn take_frame_step(
        &mut self,
        key: HttpReconnectFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpJpegFrame, Failure> {
        Ok(self.take_frame(key, publisher, access)?)
    }
    fn release_source_boundary(
        &mut self,
        boundary: HttpReconnectBoundary,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        drop(self.release_boundary(boundary, publisher, access)?);
        Ok(())
    }
    fn retire_owner(self: Box<Self>) {
        drop((*self).retire());
    }
}

impl Recording for DurableReconnectRecording {
    fn native(&self) -> &HttpReconnectRecording {
        self.recording()
    }
    fn poll_step(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<DurableReconnectStep, Failure> {
        Ok(self.poll(publisher, access)?)
    }
    fn commit_wire_step(
        &mut self,
        plan: HttpReconnectWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectWireCommit, Failure> {
        Ok(self.commit_wire(plan, publisher, access)?)
    }
    fn take_frame_step(
        &mut self,
        key: HttpReconnectFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpJpegFrame, Failure> {
        Ok(self.take_frame(key, publisher, access)?)
    }
    fn history(&self) -> Option<&DurableReconnectRecording> {
        Some(self)
    }
    fn commit_history(
        &mut self,
        pin: ReconnectHistoryPin,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        self.commit_boundary(pin, publisher, access)?;
        Ok(())
    }
    fn release_history(
        &mut self,
        pin: ReconnectHistoryPin,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<(), Failure> {
        drop(self.release_boundary(pin, publisher, access)?);
        Ok(())
    }
    fn retire_owner(self: Box<Self>) {
        drop((*self).retire());
    }
}

pub(super) fn owner(
    plan: HttpReconnectRecordingPlan,
    session: ContentDigest,
    history_work: Option<u64>,
) -> Result<Box<dyn Recording>, Failure> {
    match history_work {
        None => Ok(Box::new(HttpReconnectRecording::new(plan, 0)?)),
        Some(work) => Ok(Box::new(DurableReconnectRecording::new(
            plan, session, work, 0,
        )?)),
    }
}

pub(super) fn history_pin_json(pin: ReconnectHistoryPin) -> String {
    object(&[
        ("session", string(&pin.session.to_text())),
        ("root", string(&pin.root.to_text())),
        ("connections", pin.connections.to_string()),
    ])
}

pub(super) enum Boundary {
    Native(HttpReconnectBoundary),
    History(ArchivedReconnectBoundary, ReconnectHistoryPin),
}
impl Boundary {
    pub(super) fn complete(&self) -> bool {
        match self {
            Self::Native(b) => matches!(
                b.source.outcome,
                fss_reference::ingest::http_reconnect::HttpReconnectOutcome::Complete
            ),
            Self::History(b, _) => b.outcome() == BoundaryOutcome::NativeComplete,
        }
    }
    pub(super) fn stop(&self) -> Option<HttpReconnectStop> {
        match self {
            Self::Native(b) => b.source.stop,
            Self::History(b, _) => b.stop(),
        }
    }
    pub(super) fn history_pin(&self) -> Option<ReconnectHistoryPin> {
        match self {
            Self::Native(_) => None,
            Self::History(_, pin) => Some(*pin),
        }
    }
    pub(super) fn json(&self, released: bool) -> String {
        let (b, pin) = match self {
            Self::Native(b) => return boundary_json(*b, released),
            Self::History(b, pin) => (b, pin),
        };
        let scope = b.scope();
        let totals = b.totals();
        object(&[
            ("connection", b.connection().to_string()),
            ("source", string(&sha_bytes(scope.stream.source))),
            ("generation", string(&scope.stream.generation.to_string())),
            ("outcome", string(b.outcome().as_str())),
            ("diagnostic", string(b.diagnostic())),
            ("prefix", pin_json(b.prefix())),
            ("admitted_ns", string(&b.admitted_ns().to_string())),
            (
                "next_generation",
                b.next_source()
                    .map_or_else(|| "null".into(), |s| string(&s.generation.to_string())),
            ),
            (
                "retry_at_ns",
                b.retry_at_ns()
                    .map_or_else(|| "null".into(), |t| string(&t.to_string())),
            ),
            (
                "stop",
                b.stop()
                    .map_or_else(|| "null".into(), |s| string(&format!("{s:?}"))),
            ),
            ("received_bytes", totals.received_bytes.to_string()),
            ("frames_parsed", totals.frames.to_string()),
            ("peer_eof", totals.peer_eof.to_string()),
            ("history_pin", history_pin_json(*pin)),
            ("released", released.to_string()),
            ("capture_continuity", "false".into()),
            ("durable_completion_root", "null".into()),
        ])
    }
}
