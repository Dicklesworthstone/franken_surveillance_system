#![forbid(unsafe_code)]
//! One separately approved source spool, synchronously drained before the next capture poll.
//! There is no source queue, retry, new network effect, or credential-bearing wire retention.

use super::super::source_mode::SourceConfig;
use super::*;
use fss_geometry::WorkBudget;
use fss_reference::rtsp::RtspEvent;
use fss_reference::rtsp::avc_client::InterleavedSource;
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramPin};
use fss_reference::rtsp::framed::RtspWireFrame;
use fss_reference::rtsp::hevc_client::{HevcClientPoll, pictures::HevcPictureClientPoll};
use fss_reference::rtsp::hevc_recording_capture::{
    HevcCapturePoll, live::AutomaticHevcRecordingStep,
};
use fss_reference::rtsp::live_hevc::LiveHevcStep;
use fss_reference::rtsp::live_hevc_archive::LiveHevcArchiveStep;

pub(super) struct SourceCustody {
    publisher: LocalRootPublisher,
    archive: DatagramArchive,
    work: WorkBudget<'static>,
    candidate: Option<DatagramPin>,
    failed: bool,
    pause: Option<(u64, u64)>,
}
impl SourceCustody {
    pub(super) fn open(
        config: &SourceConfig,
        path: &Path,
        owner: &Owner<'_, '_>,
    ) -> Result<Self, Failure> {
        if config.scope.binding != owner.binding {
            return Err(Failure::Configuration);
        }
        let guard = Guard(owner);
        guard.check()?;
        create_root(path, owner)?;
        guard.check()?;
        let publisher =
            LocalRootPublisher::open(path, config.storage).map_err(|_| Failure::Storage)?;
        guard.check()?;
        let mut work = WorkBudget::new(config.work);
        let archive = DatagramArchive::recover(
            &publisher,
            config.scope.clone(),
            config.limits,
            None,
            &guard,
            &mut work,
        )
        .map_err(|_| Failure::Storage)?;
        // A different process/connection can never adopt this source epoch.
        if archive.pin().datagrams != 0 {
            return Err(Failure::Storage);
        }
        Ok(Self {
            publisher,
            archive,
            work,
            candidate: None,
            failed: false,
            pause: None,
        })
    }

    fn record<W: Write>(
        &mut self,
        input: Input<'_>,
        owner: &Owner<'_, '_>,
        stats: &mut Statistics,
        log: &mut Transcript<'_, W>,
    ) -> Result<(), Failure> {
        let result = (|| {
            if self.failed || self.pause.is_some() {
                return Err(Failure::Storage);
            }
            let started = owner.now()?;
            let guard = Guard(owner);
            guard.check()?;
            let plan = match input {
                Input::Avc(source) => self.archive.prepare(source, &mut self.work),
                Input::Hevc(frame) => self.archive.prepare_frame(frame, &mut self.work),
            }
            .map_err(|_| Failure::Storage)?;
            self.candidate = Some(plan.pin());
            let receipt = self
                .archive
                .publish(&plan, &mut self.publisher, &guard, &mut self.work)
                .map_err(|_| Failure::Storage)?;
            self.candidate = None;
            guard.check()?;
            let r = receipt.record;
            log.emit(
                "datagram_durable",
                object(&[
                    ("prefix", prefix(r.pin)),
                    ("prior_head", string(&r.prior.head.to_text())),
                    ("channel", r.channel.to_string()),
                    ("received_ns", r.received_ns.to_string()),
                    ("datagram_bytes", r.payload_bytes.to_string()),
                    ("payload_digest", string(&r.payload_digest.to_text())),
                    ("slot", string(receipt.local.slot.as_str())),
                    ("local_durable", "true".into()),
                    ("picture_complete", "false".into()),
                    ("source_eof_asserted", "false".into()),
                ]),
                false,
            )?;
            self.pause = Some((started, owner.now()?));
            Ok(())
        })();
        self.failed |= result.is_err();
        self.observe(stats);
        result
    }

    pub(super) fn observe(&self, stats: &mut Statistics) {
        // A failed or unacknowledged source operation must never be hidden by a
        // fully drained recording window, an EOF, or a later transient read fault.
        stats.source_custody_unsettled |= self.failed || self.candidate.is_some();
        stats.source_custody = Some(self.summary());
        let pin = self.archive.pin();
        stats.source_pin = Some(fss_reference::rtsp::campaign_history::CampaignSourcePin {
            scope: pin.scope,
            head: pin.head,
            datagrams: pin.datagrams,
            bytes: pin.payload_bytes,
        });
    }

    pub(super) fn summary(&self) -> String {
        object(&[
            ("last_local_durable_prefix", prefix(self.archive.pin())),
            (
                "candidate",
                self.candidate.map_or_else(|| "null".into(), prefix),
            ),
            ("work_used", self.work.used().to_string()),
            ("work_remaining", self.work.remaining().to_string()),
            ("source_custody_refused", self.failed.to_string()),
            ("complete_input_retained", "false".into()),
            ("partial_datagrams_retained", "false".into()),
            ("control_messages_retained", "false".into()),
            ("source_encrypted", "false".into()),
            ("requires_original_configuration_for_replay", "true".into()),
        ])
    }
}
// Charge the measured synchronous source-publication/output interval as a
// storage pause. Keep the real clock for duration and native deadline checks.
pub(super) fn account_pause(
    source: &mut Option<SourceCustody>,
    progress: &mut RecordingProgress,
    playing: bool,
    enabled: bool,
    pictures: u64,
) -> Result<(), Failure> {
    if let Some((start, end)) = source.as_mut().and_then(|source| source.pause.take()) {
        progress
            .exclude_storage_interval(start, end, playing, enabled, pictures)
            .map_err(|_| Failure::State)?;
    }
    Ok(())
}

fn prefix(pin: DatagramPin) -> String {
    object(&[
        ("scope", string(&pin.scope.to_text())),
        ("head", string(&pin.head.to_text())),
        ("datagrams", pin.datagrams.to_string()),
        ("payload_bytes", pin.payload_bytes.to_string()),
    ])
}

enum Input<'a> {
    Avc(&'a InterleavedSource),
    Hevc(&'a RtspWireFrame),
}

pub(super) fn observe_avc<W: Write>(
    custody: &mut Option<SourceCustody>,
    step: &JournaledLiveArchiveStep,
    owner: &Owner<'_, '_>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let Some(custody) = custody else {
        return Ok(());
    };
    let recording = match step {
        JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(recording)) => recording.as_ref(),
        JournaledLiveArchiveStep::Stopped { trigger, .. }
        | JournaledLiveArchiveStep::Live(LiveArchiveStep::Stopped { trigger, .. }) => {
            trigger.as_ref()
        }
        _ => return Ok(()),
    };
    let network = match recording {
        LiveRecordingStep::Network(network) => network,
        LiveRecordingStep::Stopped { trigger, .. } => trigger.as_ref(),
        _ => return Ok(()),
    };
    if let LiveAvcStep::Protocol {
        event: DigestAvcPoll::Client { event, .. },
        ..
    } = network
    {
        let source = match event.as_ref() {
            AvcClientPoll::Rtp { source, .. }
            | AvcClientPoll::Rtcp { source, .. }
            | AvcClientPoll::Fault {
                source: Some(source),
                ..
            } => source,
            _ => return Ok(()),
        };
        if let Err(error) = custody.record(Input::Avc(source), owner, stats, log) {
            // This event has already transferred out of the native owner. Even
            // if source publication fails, its terminal custody and unresolved
            // remote command cannot disappear before the driver cancels input.
            observe_stopped(recording, stats);
            match step {
                JournaledLiveArchiveStep::Stopped { retained, .. } => stats.retirement(retained),
                JournaledLiveArchiveStep::Live(LiveArchiveStep::Stopped { retained, .. }) => {
                    stats.archive_retirement(retained)
                }
                _ => {}
            }
            return Err(error);
        }
    }
    Ok(())
}

pub(super) fn observe_hevc<W: Write>(
    custody: &mut Option<SourceCustody>,
    step: &LiveHevcArchiveStep,
    owner: &Owner<'_, '_>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let Some(custody) = custody else {
        return Ok(());
    };
    let recording = match step {
        LiveHevcArchiveStep::Recording(step) => step.as_ref(),
        LiveHevcArchiveStep::Stopped { trigger, .. } => trigger.as_ref(),
        _ => return Ok(()),
    };
    let event = match recording {
        AutomaticHevcRecordingStep::Network(LiveHevcStep::Protocol { event, .. }) => event,
        AutomaticHevcRecordingStep::Capture { event, .. } => match event.as_ref() {
            HevcCapturePoll::Receiver(event) => event.as_ref(),
            HevcCapturePoll::Stopped { retained, .. }
            | HevcCapturePoll::Ended {
                retained: Some(retained),
            } => {
                let Some(event) = retained.event.as_deref() else {
                    return Ok(());
                };
                event
            }
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    let client = match event {
        HevcPictureClientPoll::Client { event, .. } => event.as_ref(),
        HevcPictureClientPoll::Fault { source, .. } => source.as_ref(),
        HevcPictureClientPoll::Ended {
            client: Some(client),
            ..
        } => client.as_ref(),
        _ => return Ok(()),
    };
    let frame = match client {
        HevcClientPoll::Rtp { source, .. }
        | HevcClientPoll::Rtcp { source, .. }
        | HevcClientPoll::Fault {
            source: Some(source),
            ..
        } => source,
        _ => return Ok(()),
    };
    // A protocol failure can own a control response too. It must NEVER enter
    // media custody, even if its body starts with '$' or resembles an RTP packet.
    if matches!(frame.event(), RtspEvent::Interleaved { .. }) {
        custody.record(Input::Hevc(frame), owner, stats, log)?;
    }
    Ok(())
}

struct Guard<'a, 'b, 'task>(&'a Owner<'b, 'task>);
impl Guard<'_, '_, '_> {
    fn check(&self) -> Result<(), Failure> {
        let now = self.0.storage_check()?;
        if self.0.drain_deadline.get().is_some() {
            // This source event was already transferred from the closed native
            // receiver. Its bounded publication is cleanup, not new network work.
            return Ok(());
        }
        self.0
            .checkpoint(
                &self.0.binding,
                TcpOperation::Poll,
                now,
                self.0.live_deadline,
            )
            .map_err(|denial| {
                if denial == TcpDenial::Deadline {
                    Failure::Deadline
                } else {
                    Failure::Authority
                }
            })
    }
}
impl PublishCancellation for Guard<'_, '_, '_> {
    fn cancel_requested(&self, cut: PublishCutPoint) -> bool {
        self.0.cancel_requested(cut) || self.check().is_err()
    }
}

// Keep effectful execution in the native owner, not in the pure source parser.
// The enclosing reconnect approval delegates this exact single-session grant.
impl SourceConfig {
    pub(crate) fn execute_supervised_capture(
        &self,
        options: &Options,
        supervision: Option<Supervision>,
    ) -> Result<AttemptOutcome, &'static str> {
        execute_owned_attempt(options, supervision, Some(self))
    }
}
