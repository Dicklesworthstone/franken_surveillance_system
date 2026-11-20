#![forbid(unsafe_code)]
//! Bounded A/V bootstrap for a camera-local HTTP-started media stream.
//!
//! Each audio interpretation is paired with the recorder result from the same
//! source step before another record is read. A validated bootstrap may be
//! transferred to an idle archive worker; this module does not itself publish,
//! authenticate the camera, infer physical capture time, reconnect, or settle
//! the committed start effect. All source and effect owners remain recoverable.

use std::time::Duration;

use asupersync::{Cx, time::timeout_at};
use fss_core::ContentDigest;
use fss_runtime::execution::TaskCx;

use super::media;
use crate::unifi_direct::{
    archive, av_bootstrap, av_owned_sink, av_recording, av_unknown_worker_guard, av_worker,
    metered::MeteredClock, pipeline, recording,
};

/// One source-preserving bootstrap result.
#[must_use]
#[derive(Debug)]
pub enum Step {
    /// A configuration or first segment is retained by the collector.
    Retained,
    /// A complete recorder result and its same-step audio event remain caller-owned.
    Forward {
        /// Exact recorder output.
        push: recording::Push,
        /// The audio interpretation of the same input, if any.
        audio: Option<pipeline::AudioEvent>,
    },
    /// The source made bounded progress without emitting a record.
    Progress,
    /// A bounded wait elapsed; the same driver may be polled again.
    Idle,
    /// The source ended; retained inputs must be recovered by the caller.
    Eof,
    /// The source limit was reached; retained inputs must be recovered.
    LimitReached,
    /// The pipeline refused. Its error and any pending audio remain in custody.
    MediaError(pipeline::Error),
    /// An audio fence or unconsumed configuration requires reconciliation.
    Fenced,
    /// The collector is complete and can be validated for handoff.
    Ready,
    /// Wait bounds, clock or task binding did not match; no input was polled.
    Configuration,
}

/// The complete source, collector and committed-effect custody.
#[must_use]
pub struct Parts {
    /// The original connected stream, including its effect permit and readback.
    pub connected: media::Connected,
    /// The exact inputs retained while collecting the first A/V segment.
    pub collector: av_bootstrap::Collector,
    /// Whether further admission stopped after an error or unconsumed event.
    pub fenced: bool,
}

/// A rejected attachment returns the original connected owner.
#[must_use]
pub struct AttachRefusal {
    /// The untouched connected stream and committed-effect permit.
    pub connected: media::Connected,
    /// Explicitly supplied configuration, if any, returned unchanged.
    pub supplied_unverified_audio: Option<[u8; 2]>,
}

/// Owns an HTTP-started pipeline while collecting first-segment A/V inputs.
#[must_use = "recover the connected stream and retained inputs with into_parts"]
pub struct Driver {
    parts: Parts,
}

/// Successfully validated A/V bootstrap and the original connected owner.
#[must_use]
pub struct Handoff {
    /// The source pipeline and committed effect remain caller-owned.
    pub connected: media::Connected,
    /// The idle sink, first segment and sender-clock hypothesis.
    pub bootstrap: av_owned_sink::Bootstrap,
}

/// The connected source and an archive worker ready to accept its first segment.
#[must_use]
pub struct ArchiveHandoff {
    /// Source and committed effect custody.
    pub connected: media::Connected,
    /// Exclusive archive worker, with no operation started.
    pub worker: av_worker::UnknownTimeWorker,
    /// Original first segment, not yet offered to the worker.
    pub first_segment: recording::Segment,
    /// Sender-clock hypothesis, not a physical capture-time observation.
    pub origin: av_recording::SenderClockOrigin,
}

/// A refused archive handoff preserves all source and storage owners.
#[must_use]
pub enum ArchiveHandoffRefusal {
    /// The source and first segment carry different connection claims.
    Source {
        /// Original source and bootstrap.
        handoff: Handoff,
        /// Original exclusive archive resources.
        resources: av_unknown_worker_guard::BootstrapResources,
    },
    /// Audio tracking is inactive or has an unmatched event.
    Audio {
        /// Original source and bootstrap.
        handoff: Handoff,
        /// Original exclusive archive resources.
        resources: av_unknown_worker_guard::BootstrapResources,
    },
    /// Sink conversion was refused without consuming its inputs.
    Sink {
        /// Original source and bootstrap.
        handoff: Handoff,
        /// Original exclusive archive resources.
        resources: av_unknown_worker_guard::BootstrapResources,
    },
    /// Worker creation refused after conversion.
    Worker {
        /// Original connected source and effect owner.
        connected: media::Connected,
        /// Converted sink and exclusive storage owners.
        parts: av_worker::UnknownTimeParts,
        /// Original first segment.
        first_segment: recording::Segment,
        /// Original sender-clock hypothesis.
        origin: av_recording::SenderClockOrigin,
    },
    /// Recovered rollover custody could not be reattached.
    RecoveredWorker {
        /// Original connected source and effect owner.
        connected: media::Connected,
        /// Converted sink and exclusive storage owners.
        parts: av_worker::UnknownTimeParts,
        /// Original first segment.
        first_segment: recording::Segment,
        /// Original sender-clock hypothesis.
        origin: av_recording::SenderClockOrigin,
        /// Exact recovered rollover lineage.
        custody: archive::journal::rollover::WorkerCustody,
    },
}

impl Handoff {
    /// Transfer the bootstrap to an idle unknown-time archive worker without I/O.
    /// The segment must still be offered, published, and independently read back.
    pub fn into_archive(
        self,
        resources: av_unknown_worker_guard::BootstrapResources,
    ) -> Result<ArchiveHandoff, Box<ArchiveHandoffRefusal>> {
        if self.connected.pipeline.source_key() != self.bootstrap.first_segment.fragment().key() {
            return Err(Box::new(ArchiveHandoffRefusal::Source {
                handoff: self,
                resources,
            }));
        }
        if !self.connected.pipeline.audio_tracking_active()
            || self.connected.pipeline.has_pending_audio()
        {
            return Err(Box::new(ArchiveHandoffRefusal::Audio {
                handoff: self,
                resources,
            }));
        }
        let Handoff {
            connected,
            bootstrap,
        } = self;
        let av_owned_sink::Bootstrap {
            sink,
            first_segment,
            origin,
        } = bootstrap;
        let sink = match sink.into_unknown_time() {
            Ok(sink) => sink,
            Err(sink) => {
                return Err(Box::new(ArchiveHandoffRefusal::Sink {
                    handoff: Handoff {
                        connected,
                        bootstrap: av_owned_sink::Bootstrap {
                            sink,
                            first_segment,
                            origin,
                        },
                    },
                    resources,
                }));
            }
        };
        let parts = av_worker::UnknownTimeParts {
            sink,
            deployment: resources.deployment,
            journal: resources.journal,
            keeper: resources.keeper,
            replay: resources.replay,
            authority: resources.authority,
            limits: resources.limits,
            work_limit: resources.work_limit,
        };
        let worker = match resources.rollover_custody {
            Some(custody) => {
                match av_worker::UnknownTimeWorker::from_recovered_preverified(parts, custody) {
                    Ok(worker) => worker,
                    Err((parts, custody)) => {
                        return Err(Box::new(ArchiveHandoffRefusal::RecoveredWorker {
                            connected,
                            parts,
                            first_segment,
                            origin,
                            custody,
                        }));
                    }
                }
            }
            None => match av_worker::UnknownTimeWorker::new(parts) {
                Ok(worker) => worker,
                Err(parts) => {
                    return Err(Box::new(ArchiveHandoffRefusal::Worker {
                        connected,
                        parts,
                        first_segment,
                        origin,
                    }));
                }
            },
        };
        Ok(ArchiveHandoff {
            connected,
            worker,
            first_segment,
            origin,
        })
    }
}

/// A failed handoff preserves every original input and connected owner.
#[must_use]
pub enum HandoffRefusal {
    /// Input collection is incomplete or a source needs reconciliation.
    NotReady(Driver),
    /// A/V validation failed with all bootstrap inputs returned.
    Bootstrap {
        /// The original connected stream and effect permit.
        connected: media::Connected,
        /// Exact inputs and payload-free validation failure.
        refusal: av_owned_sink::BootstrapRefusal,
    },
}

impl Driver {
    /// Install a bounded, non-consuming name probe before processing media.
    /// The matching name is a source claim, not authenticated peer identity.
    pub fn begin_name_probe(
        &mut self,
        probe: fss_packet::extended_flv::stream::NameProbeOwner,
    ) -> Result<(), fss_packet::extended_flv::stream::NameProbeOwner> {
        if self.parts.fenced || self.parts.connected.pipeline.has_pending_audio() {
            return Err(probe);
        }
        self.parts.connected.begin_name_probe(probe)
    }

    /// Advance the probe while retaining the prefix and cumulative work.
    pub async fn probe_name_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: fss_core::TimestampNs,
    ) -> Result<crate::unifi_direct::ingress::NameProbeStep, pipeline::NameProbeError> {
        if self.parts.fenced || self.parts.connected.pipeline.has_pending_audio() {
            return Err(pipeline::NameProbeError::NotFresh);
        }
        self.parts.connected.probe_name_step(task, cx, now).await
    }

    /// Recover the probe owner without discarding its retained source prefix.
    pub fn take_name_probe(&mut self) -> Option<fss_packet::extended_flv::stream::NameProbeOwner> {
        self.parts.connected.take_name_probe()
    }

    /// Enable in-band AAC tracking on an unconsumed connected stream.
    /// A supplied, unverified audio configuration is deliberately not inferred.
    pub fn attach(
        connected: media::Connected,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
    ) -> Result<Self, AttachRefusal> {
        Self::attach_with_unverified_audio(connected, retention, policy, None)
    }

    /// Attach an optional caller-supplied AAC configuration without asserting
    /// its source, connection epoch, or suitability for the camera. A later
    /// in-band configuration remains a fence requiring reconciliation.
    pub fn attach_with_unverified_audio(
        mut connected: media::Connected,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<Self, AttachRefusal> {
        if !connected.pipeline.is_ready_for_recording()
            || connected.pipeline.audio_tracking_active()
            || connected.pipeline.has_pending_audio()
            || !valid_supplied_audio(supplied_unverified_audio, policy)
            || connected.pipeline.enable_audio_tracking().is_err()
        {
            return Err(AttachRefusal {
                connected,
                supplied_unverified_audio,
            });
        }
        Ok(Self {
            parts: Parts {
                connected,
                collector: av_bootstrap::Collector::new(
                    supplied_unverified_audio,
                    retention,
                    policy,
                ),
                fenced: false,
            },
        })
    }

    /// Recover all owners, including a pending unpaired audio event on error.
    pub fn into_parts(self) -> Parts {
        self.parts
    }

    pub(super) fn source_key(&self) -> fss_container::flv_avc::SourceKey {
        self.parts.connected.pipeline.source_key()
    }

    pub(super) fn camera_claim(&self) -> fss_core::ContentDigest {
        self.parts.connected.camera_claim()
    }

    /// Whether all bootstrap inputs are present and no audio is pending.
    pub fn is_ready(&self) -> bool {
        !self.parts.fenced
            && !self.parts.connected.pipeline.has_pending_audio()
            && self.parts.collector.ready()
    }

    pub(super) fn is_bound_to_task(&self, task: &TaskCx<'_>) -> bool {
        self.parts.connected.pipeline.is_bound_to_task(task)
    }

    /// Validate the complete inputs without polling or publishing media.
    pub fn bootstrap(self) -> Result<Handoff, HandoffRefusal> {
        if !self.is_ready() {
            return Err(HandoffRefusal::NotReady(self));
        }
        let Parts {
            connected,
            collector,
            fenced,
        } = self.parts;
        let inputs = match collector.into_inputs() {
            Ok(inputs) => inputs,
            Err(av_bootstrap::Incomplete(collector)) => {
                return Err(HandoffRefusal::NotReady(Self {
                    parts: Parts {
                        connected,
                        collector,
                        fenced,
                    },
                }));
            }
        };
        match av_owned_sink::OwnedSink::bootstrap(inputs) {
            Ok(bootstrap) => Ok(Handoff {
                connected,
                bootstrap,
            }),
            Err(refusal) => Err(HandoffRefusal::Bootstrap { connected, refusal }),
        }
    }

    /// Process at most one source step with bounded waiting and task authority.
    pub async fn step<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
    ) -> Step {
        if self.parts.fenced || self.parts.connected.pipeline.has_pending_audio() {
            return Step::Fenced;
        }
        if self.parts.collector.ready() {
            return Step::Ready;
        }
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !clock.matches(task, cx)
            || !self.parts.connected.pipeline.is_bound_to_task(task)
        {
            return Step::Configuration;
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(_) => return Step::Configuration,
        };
        match timeout_at(
            cx.now() + wait,
            self.parts.connected.pipeline.step(task, cx, now),
        )
        .await
        {
            Err(_) => Step::Idle,
            Ok(Err(error)) => {
                self.parts.fenced = true;
                Step::MediaError(error)
            }
            Ok(Ok(pipeline::Step::Recording(push))) => {
                let audio = self.parts.connected.pipeline.take_audio_event();
                match self.parts.collector.collect(push, audio) {
                    av_bootstrap::Collected::Retained => Step::Retained,
                    av_bootstrap::Collected::Forward { push, audio } => {
                        self.parts.fenced |= audio.as_ref().is_some_and(|event| matches!(event,
                            pipeline::AudioEvent::Fenced(_)
                            | pipeline::AudioEvent::Observed(
                                fss_packet::extended_flv::aac_track::Observation::Configuration { .. }
                            )));
                        Step::Forward { push, audio }
                    }
                }
            }
            Ok(Ok(pipeline::Step::Progress { .. })) => Step::Progress,
            Ok(Ok(pipeline::Step::Eof)) => {
                self.parts.fenced = true;
                Step::Eof
            }
            Ok(Ok(pipeline::Step::LimitReached)) => {
                self.parts.fenced = true;
                Step::LimitReached
            }
        }
    }
}

pub(super) fn valid_supplied_audio(
    supplied: Option<[u8; 2]>,
    policy: av_owned_sink::BootstrapPolicy,
) -> bool {
    supplied.is_none_or(|bytes| {
        fss_packet::extended_flv::aac::Configuration::parse_explicit(&bytes).is_ok_and(|config| {
            fss_packet::extended_flv::aac_clock::Clock::new(
                &config,
                0,
                policy.jitter_ms,
                policy.max_epoch_frames,
            )
            .is_ok()
        })
    })
}
