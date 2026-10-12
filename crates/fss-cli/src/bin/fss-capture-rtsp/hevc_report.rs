#![forbid(unsafe_code)]
//! Source and terminal ownership accounting for the typed HEVC path.

use fss_packet::hevc::HevcAssemblyStep;
use fss_reference::rtsp::hevc_client::HevcClientRetirement;
use fss_reference::rtsp::hevc_client::pictures::HevcPictureClientRetirement;
use fss_reference::rtsp::hevc_recording_capture::HevcCaptureRetirement;
use fss_reference::rtsp::hevc_recording_collector::HevcCollectedSource;
use fss_reference::rtsp::live_hevc::LiveHevcRetirement;
use fss_reference::rtsp::live_hevc_archive::{
    LiveHevcArchiveRetirement, SelectedHevcRecordingRetirement,
};
use fss_reference::rtsp::tcp::TcpRetirement;

use super::*;

pub(super) fn released_bytes(sources: &[HevcCollectedSource]) -> u64 {
    sources
        .iter()
        .map(|source| source.bytes().len() as u64)
        .sum()
}

impl Statistics {
    pub(super) fn hevc_observe(&mut self, capture: &JournaledLiveHevcArchive<'_, '_>) {
        if let Some(totals) = capture.totals() {
            self.totals = totals;
        }
        if let Some(snapshot) = capture.snapshot() {
            self.snapshot(snapshot);
        }
        self.journal_anchor = Some(capture.journal_anchor());
        self.pins = capture.pin_state().clone();
    }
    pub(super) fn hevc_transport(&mut self, retired: &TcpRetirement) {
        self.totals = retired.totals;
        self.pending_request |= retired.request.is_some();
        self.unpublished_receiver_state |= retired.unread.is_some();
    }
    fn hevc_client_retirement(&mut self, retired: &HevcClientRetirement) {
        self.remote_session_may_exist |= retired.session.remote_session_may_exist;
        self.pending_request |= retired.session.pending_cseq.is_some();
        self.unpublished_receiver_state |= retired.video.is_some()
            || !retired.wire.is_empty()
            || retired.challenge.is_some()
            || retired.retry.is_some();
    }
    fn hevc_picture_retirement(&mut self, retired: &HevcPictureClientRetirement) {
        self.hevc_client_retirement(&retired.client);
        self.unpublished_receiver_state |=
            retired.work.queued.bytes != 0 || retired.work.picture.is_some();
        self.receiver_tail |= retired.work.picture.is_some();
    }
    pub(super) fn hevc_connection_retirement(&mut self, retired: &LiveHevcRetirement) {
        self.hevc_transport(&retired.transport);
        self.pending_request |= retired.unqueued_request.is_some();
        self.hevc_picture_retirement(&retired.protocol);
    }
    fn hevc_client_event(&mut self, event: &HevcClientPoll) {
        match event {
            HevcClientPoll::Rtp {
                retirement: Some(retired),
                ..
            }
            | HevcClientPoll::Ended {
                retirement: Some(retired),
                ..
            }
            | HevcClientPoll::Fault {
                retirement: retired,
                ..
            } => self.hevc_client_retirement(retired),
            _ => {}
        }
    }
    pub(super) fn hevc_event(&mut self, event: &HevcPictureClientPoll) {
        match event {
            HevcPictureClientPoll::Client { event, work } => {
                self.hevc_client_event(event);
                if let Some(work) = work {
                    self.unpublished_receiver_state |=
                        work.queued.bytes != 0 || work.picture.is_some();
                    self.receiver_tail |= work.picture.is_some();
                }
            }
            HevcPictureClientPoll::Assembly { retirement, step } => {
                if let Some(retired) = retirement {
                    self.input_ended = true; // EOB retired the source; TCP EOF remains separate.
                    self.hevc_picture_retirement(retired);
                }
                self.receiver_tail |= match step {
                    HevcAssemblyStep::Accepted(outcome) => outcome.retired.is_some(),
                    HevcAssemblyStep::Refused(_) => true,
                };
            }
            HevcPictureClientPoll::Fault {
                retirement, source, ..
            } => {
                self.hevc_picture_retirement(retirement);
                self.hevc_client_event(source);
            }
            HevcPictureClientPoll::Ended {
                client,
                interrupted_picture,
                tail,
            } => {
                self.input_ended = true;
                if let Some(client) = client {
                    self.hevc_client_event(client);
                }
                let tail_owned = tail.as_ref().is_some_and(|tail| {
                    tail.picture.is_some() || tail.retired.is_some() || tail.standalone.is_some()
                });
                self.receiver_tail |= interrupted_picture.is_some() || tail_owned;
                self.unpublished_receiver_state |= interrupted_picture.is_some() || tail_owned;
            }
            HevcPictureClientPoll::CodecRefused { .. }
            | HevcPictureClientPoll::Gap { .. }
            | HevcPictureClientPoll::FragmentRetired { .. }
            | HevcPictureClientPoll::PictureRetired(_)
            | HevcPictureClientPoll::QueueRetired(_) => {
                self.receiver_tail = true;
                self.unpublished_receiver_state = true;
            }
            _ => {}
        }
    }
    fn hevc_held_event(&mut self, event: &HevcPictureClientPoll) {
        self.hevc_event(event);
        self.unpublished_receiver_state = true;
        if let HevcPictureClientPoll::Assembly {
            step: HevcAssemblyStep::Accepted(outcome),
            ..
        } = event
            && let Some(picture) = &outcome.picture
        {
            self.untimed_picture_bytes += picture.byte_len() as u64;
        }
    }
    pub(super) fn hevc_capture_retirement(&mut self, retired: &HevcCaptureRetirement) {
        self.unsealed_rtp_bytes += released_bytes(&retired.collection.sources);
        self.unsealed_pictures += retired.collection.pictures.len() as u64;
        if let Some(ready) = &retired.collection.ready {
            self.prepared(ready.publication_plan());
        }
        if let Some(event) = &retired.event {
            self.hevc_held_event(event);
        }
    }
    pub(super) fn hevc_recording_retirement(&mut self, retired: &SelectedHevcRecordingRetirement) {
        if let Some(connection) = &retired.connection {
            self.hevc_connection_retirement(connection);
        }
        if let Some(transport) = &retired.terminal_transport {
            self.hevc_transport(transport);
        }
        if let Some(capture) = &retired.capture {
            self.hevc_capture_retirement(capture);
        }
        if let Some(event) = &retired.unoffered_event {
            self.hevc_held_event(event);
        }
    }
    pub(super) fn hevc_retirement(&mut self, retired: &LiveHevcArchiveRetirement) {
        if let Some(recording) = &retired.recording {
            self.hevc_recording_retirement(recording);
        }
        if let Some(archive) = &retired.archive {
            self.journal_anchor = Some(archive.journal_anchor);
            self.pins = archive.pins.clone();
            if let Some(confirmation) = &archive.unrecorded_confirmation {
                self.unrecorded_work_receipt = Some(receipt_json(&confirmation.receipt));
            }
            self.snapshot(&archive.writer.archive.snapshot);
            if let Some(pending) = &archive.writer.archive.pending {
                self.prepared(pending.publication_plan());
            }
        }
        if let Some(window) = &retired.unoffered_window {
            self.prepared(window.publication_plan());
        }
    }
    pub(super) fn hevc_stopped(&mut self, step: &AutomaticHevcRecordingStep) {
        match step {
            AutomaticHevcRecordingStep::Network(LiveHevcStep::Protocol { event, transport }) => {
                if let Some(transport) = transport {
                    self.hevc_transport(transport);
                }
                self.hevc_event(event);
            }
            AutomaticHevcRecordingStep::ProtocolQueued {
                transport: Some(transport),
            } => {
                self.hevc_transport(transport);
            }
            AutomaticHevcRecordingStep::Capture { event, connection } => {
                if let Some(connection) = connection {
                    self.hevc_connection_retirement(connection);
                }
                match event.as_ref() {
                    HevcCapturePoll::Stopped { retained, .. }
                    | HevcCapturePoll::Ended {
                        retained: Some(retained),
                    } => self.hevc_capture_retirement(retained),
                    HevcCapturePoll::Receiver(event) => self.hevc_event(event),
                    HevcCapturePoll::Window(window) => self.prepared(window.publication_plan()),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

pub(super) fn stopped_failure(step: &AutomaticHevcRecordingStep) -> Failure {
    let event = match step {
        AutomaticHevcRecordingStep::Network(LiveHevcStep::Protocol { event, .. }) => Some(event),
        AutomaticHevcRecordingStep::Capture { event, .. } => match event.as_ref() {
            HevcCapturePoll::Stopped {
                reason,
                error,
                retained,
            } => {
                if *reason == fss_reference::rtsp::recording_collector::CollectionStop::Deadline
                    || matches!(error, Some(CollectorError::Deadline))
                {
                    return Failure::Deadline;
                }
                if matches!(error, Some(CollectorError::Timeline)) {
                    return Failure::Timing;
                }
                retained.event.as_deref()
            }
            HevcCapturePoll::Receiver(event) => Some(event.as_ref()),
            _ => None,
        },
        _ => None,
    };
    match event {
        Some(HevcPictureClientPoll::Client { event, .. }) => match event.as_ref() {
            HevcClientPoll::Fault { reason, .. } => client_failure(reason),
            _ => Failure::Protocol,
        },
        Some(HevcPictureClientPoll::Fault {
            reason: HevcPictureClientError::Client(error),
            ..
        }) => client_failure(error),
        _ => Failure::Protocol,
    }
}
