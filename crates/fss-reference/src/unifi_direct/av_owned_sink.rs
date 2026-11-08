#![forbid(unsafe_code)]
//! Owned source and muxer state for a bounded A/V archival handoff.
//!
//! This type does not start a worker. The caller must transfer it to a
//! supervised persistence boundary that drains on cancellation. The pinned
//! runtime's ordinary blocking wrapper is not such a boundary by itself.

use fss_container::{Mp4Error, Mp4Limits, flv_av, flv_avc};
use fss_core::{CaptureInterval, ContentDigest};
use fss_geometry::WorkBudget;
use fss_packet::extended_flv::{self, aac, aac_track, stream::SourceRecord};

use super::{archive, av_recording, av_sink, evidence, recording};
use crate::{ReferenceDeployment, ReplayCx};

/// Owned AAC configuration and its explicit source classification.
pub enum Audio {
    /// A source observation and the exact record it describes.
    InBand {
        /// Original AAC configuration record.
        record: SourceRecord,
        /// Connection-local observation to rebind before publication.
        observation: aac_track::Observation,
    },
    /// AudioSpecificConfig supplied without an original-source binding.
    SuppliedUnverified([u8; 2]),
}

/// Explicit limits and sender-clock assumptions for the first A/V segment.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapPolicy {
    /// Maximum allowed sender-time separation between the first audio and video.
    pub max_separation_ms: u32,
    /// Allowed timestamp jitter under the selected AAC clock hypothesis.
    pub jitter_ms: u32,
    /// Maximum audio frames admitted for this muxer epoch.
    pub max_epoch_frames: u64,
    /// Maximum audio frames in a single fragment.
    pub max_audio_frames: usize,
    /// Media construction and source-mapping limits.
    pub media_limits: Mp4Limits,
    /// Bounds on source evidence preparation.
    pub evidence_limits: evidence::Limits,
}

/// The exact original inputs returned if first-segment initialization fails.
pub struct BootstrapInputs {
    /// Original video configuration record, or a separately accounted copy.
    pub video_configuration: SourceRecord,
    /// Original in-band AAC configuration or explicitly unverified bytes.
    pub audio: Audio,
    /// First source segment, which remains caller-owned on every refusal.
    pub first_segment: recording::Segment,
    /// Caller-selected original-byte retention decision identity.
    pub retention: ContentDigest,
    /// Bounded media policy and explicitly selected clock assumptions.
    pub policy: BootstrapPolicy,
}

/// Payload-free reason why first-segment initialization was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// This is not the first fragment of the source generation.
    Sequence,
    /// The video configuration does not match the segment's binding.
    VideoBinding,
    /// The AAC configuration could not be rebound or parsed.
    AudioConfiguration,
    /// Video initialization or its source mapping was refused.
    Video(Mp4Error),
    /// The selected sender-clock hypothesis or muxer limits were refused.
    Media(av_recording::Error),
}

/// Refusal retaining every original input, including the first segment.
#[must_use]
pub struct BootstrapRefusal {
    /// Payload-free refusal class.
    pub reason: BootstrapError,
    /// Every unconsumed input.
    pub inputs: BootstrapInputs,
}

/// An idle sink, its first source segment and the selected timing hypothesis.
#[must_use]
pub struct Bootstrap {
    /// Idle sink suitable for transfer into a supervised archive worker.
    pub sink: OwnedSink,
    /// Exact original segment, still awaiting independent capture bounds.
    pub first_segment: recording::Segment,
    /// Sender-clock hypothesis; not a physical synchronization observation.
    pub origin: av_recording::SenderClockOrigin,
}

/// Inputs remain caller-owned when initialization is refused.
pub struct Inputs {
    /// Original video configuration record or a separately accounted copy.
    pub video_configuration: SourceRecord,
    /// A/V initialization tied to the same source and audio configuration.
    pub av_initialization: flv_av::Initialization,
    /// Owned audio configuration and source classification.
    pub audio: Audio,
    /// Existing muxer state, including any unresolved publication fence.
    pub muxer: av_recording::Muxer,
    /// Caller-selected original-byte retention decision identity.
    pub retention: ContentDigest,
    /// Bounds on source evidence preparation.
    pub evidence_limits: evidence::Limits,
    /// Bounds for reconstructing the video initialization from its source.
    pub video_limits: Mp4Limits,
}

/// Initialization failed; all original inputs are returned unchanged.
#[must_use]
pub struct ConstructionRefusal {
    /// Video initialization refusal.
    pub reason: Mp4Error,
    /// The unconsumed caller inputs.
    pub inputs: Inputs,
}

/// Failure preserves the pending segment and muxer for reconciliation.
#[derive(Debug)]
pub enum FlushError {
    /// The supplied or rebound AAC configuration was invalid.
    Audio,
    /// Publication was refused or may have taken effect.
    Archive(archive::AvSegmentPublishError),
}

struct Pending {
    segment: recording::Segment,
    capture: CaptureInterval,
}

/// Owned, single-segment archive handoff. Construction performs no I/O.
pub struct OwnedSink {
    inputs: Inputs,
    video: flv_avc::Muxer,
    pending: Option<Pending>,
}

/// All source and mux state returned on retirement.
#[must_use]
pub struct Retirement {
    /// Original owned configuration and mux state.
    pub inputs: Inputs,
    /// Unpublished or indeterminate original segment and capture bounds.
    pub pending: Option<(recording::Segment, CaptureInterval)>,
}

/// Resume refused without consuming the retired source or muxer.
#[must_use]
pub struct ResumeRefusal {
    /// Video initialization refusal.
    pub reason: Mp4Error,
    /// Every original input and any pending segment.
    pub retirement: Retirement,
}

/// Owned inputs for an unknown-capture-time archive sink.
pub struct UnknownTimeInputs {
    /// Exact original video-configuration record.
    pub video_configuration: SourceRecord,
    /// Initialization bound to the selected source and audio configuration.
    pub av_initialization: flv_av::Initialization,
    /// Original or explicitly unverified audio configuration.
    pub audio: Audio,
    /// Transactional muxer that never exposes an invented capture interval.
    pub muxer: archive::UnknownTimeMuxer,
    /// Identity of the separately authorized retention decision.
    pub retention: ContentDigest,
    /// Limits for source-evidence preparation.
    pub evidence_limits: evidence::Limits,
    /// Limits for reconstructing video initialization.
    pub video_limits: Mp4Limits,
}

/// A source segment returned unchanged when the unknown-time sink refuses it.
#[must_use]
pub struct UnknownTimeOfferRefusal {
    /// Payload-free refusal reason.
    pub reason: av_sink::RefusalReason,
    /// Original source segment still owned by the caller.
    pub segment: recording::Segment,
}

/// Unknown-time publication failed; the sink retains its segment and fence.
#[derive(Debug)]
pub enum UnknownTimeFlushError {
    /// The audio configuration could not be parsed or rebound.
    Audio,
    /// Publication was refused or may have taken effect.
    Archive(archive::UnknownTimeSegmentError),
}

/// One owned unknown-time segment and its transactional muxer.
#[must_use = "retire the sink to recover its owned source and muxer"]
pub struct UnknownTimeOwnedSink {
    inputs: UnknownTimeInputs,
    video: flv_avc::Muxer,
    pending: Option<recording::Segment>,
}

/// All owners returned when an unknown-time sink is retired.
#[must_use]
pub struct UnknownTimeRetirement {
    /// Exact owned configuration and transactional muxer state.
    pub inputs: UnknownTimeInputs,
    /// Unpublished or indeterminate original segment, if any.
    pub pending: Option<recording::Segment>,
}

/// A resume refusal retains all original owners and pending source.
#[must_use]
pub struct UnknownTimeResumeRefusal {
    /// Video initialization could not be reconstructed.
    pub reason: Mp4Error,
    /// Unconsumed retirement.
    pub retirement: UnknownTimeRetirement,
}

impl OwnedSink {
    /// Transfer an idle, unbound sink to unknown-time publication. A sink
    /// with a pending source, fence, or journal scope is returned unchanged.
    pub fn into_unknown_time(self) -> Result<UnknownTimeOwnedSink, Self> {
        if self.pending.is_some()
            || self.inputs.muxer.pending_publication().is_some()
            || self.inputs.muxer.publication_scope().is_some()
        {
            return Err(self);
        }
        let Self {
            inputs,
            video,
            pending,
        } = self;
        let Inputs {
            video_configuration,
            av_initialization,
            audio,
            muxer,
            retention,
            evidence_limits,
            video_limits,
        } = inputs;
        match archive::UnknownTimeMuxer::new(muxer) {
            Ok(muxer) => Ok(UnknownTimeOwnedSink {
                inputs: UnknownTimeInputs {
                    video_configuration,
                    av_initialization,
                    audio,
                    muxer,
                    retention,
                    evidence_limits,
                    video_limits,
                },
                video,
                pending: None,
            }),
            Err(muxer) => Err(Self {
                inputs: Inputs {
                    video_configuration,
                    av_initialization,
                    audio,
                    muxer,
                    retention,
                    evidence_limits,
                    video_limits,
                },
                video,
                pending,
            }),
        }
    }

    /// Initialize an idle owned sink from the first source segment. This
    /// derives an AAC sender-clock hypothesis under caller-supplied limits;
    /// it does not establish capture time, A/V synchronization, identity or
    /// retention authority. Failure returns all original inputs unchanged.
    pub fn bootstrap(inputs: BootstrapInputs) -> Result<Bootstrap, BootstrapRefusal> {
        let built = (|| {
            let segment = &inputs.first_segment;
            if segment.fragment().sequence() != 1 {
                return Err(BootstrapError::Sequence);
            }
            let binding = segment.configuration();
            let source = &inputs.video_configuration;
            if binding.source_offset != source.offset()
                || binding.source_bytes != source.bytes().len()
                || binding.source_digest != ContentDigest::sha256(source.bytes())
            {
                return Err(BootstrapError::VideoBinding);
            }
            let video =
                flv_avc::Muxer::new(segment.fragment().key(), source, inputs.policy.media_limits)
                    .map_err(BootstrapError::Video)?;
            if *video.configuration_sources() != segment.fragment().configuration_sources() {
                return Err(BootstrapError::VideoBinding);
            }
            let initialize = |config: &aac::Configuration<'_>,
                              bound: Option<&aac_track::BoundConfiguration<'_>>|
             -> Result<_, BootstrapError> {
                let origin = av_recording::segment_sender_clock_origin(
                    segment,
                    config,
                    inputs.policy.max_separation_ms,
                )
                .map_err(BootstrapError::Media)?;
                let initialization = video
                    .av_initialization(config)
                    .map_err(BootstrapError::Video)?;
                let muxer = match bound {
                    Some(bound) => av_recording::Muxer::from_source(
                        &initialization,
                        bound,
                        origin.audio_ticks,
                        inputs.policy.jitter_ms,
                        inputs.policy.max_epoch_frames,
                        inputs.policy.max_audio_frames,
                        inputs.policy.media_limits,
                    ),
                    None => av_recording::Muxer::new(
                        &initialization,
                        config,
                        origin.audio_ticks,
                        inputs.policy.jitter_ms,
                        inputs.policy.max_epoch_frames,
                        inputs.policy.max_audio_frames,
                        inputs.policy.media_limits,
                    ),
                }
                .map_err(BootstrapError::Media)?;
                Ok((initialization, muxer, origin))
            };
            let (initialization, muxer, origin) = match &inputs.audio {
                Audio::InBand {
                    record,
                    observation,
                } => {
                    let bound = observation
                        .bind_configuration(
                            record,
                            extended_flv::Limits::default(),
                            aac::Limits::default(),
                        )
                        .map_err(|_| BootstrapError::AudioConfiguration)?;
                    initialize(bound.configuration(), Some(&bound))?
                }
                Audio::SuppliedUnverified(bytes) => {
                    let config = aac::Configuration::parse_explicit(bytes)
                        .map_err(|_| BootstrapError::AudioConfiguration)?;
                    initialize(&config, None)?
                }
            };
            Ok((video, initialization, muxer, origin))
        })();
        let (video, av_initialization, muxer, origin) = match built {
            Ok(value) => value,
            Err(reason) => return Err(BootstrapRefusal { reason, inputs }),
        };
        let BootstrapInputs {
            video_configuration,
            audio,
            first_segment,
            retention,
            policy,
        } = inputs;
        Ok(Bootstrap {
            sink: Self {
                inputs: Inputs {
                    video_configuration,
                    av_initialization,
                    audio,
                    muxer,
                    retention,
                    evidence_limits: policy.evidence_limits,
                    video_limits: policy.media_limits,
                },
                video,
                pending: None,
            },
            first_segment,
            origin,
        })
    }

    /// Reconstruct video initialization from the exact owned source record.
    /// Publication later verifies it against the segment and A/V initialization.
    pub fn new(inputs: Inputs) -> Result<Self, ConstructionRefusal> {
        let video = match flv_avc::Muxer::new(
            inputs.av_initialization.source_key(),
            &inputs.video_configuration,
            inputs.video_limits,
        ) {
            Ok(video) => video,
            Err(reason) => return Err(ConstructionRefusal { reason, inputs }),
        };
        Ok(Self {
            inputs,
            video,
            pending: None,
        })
    }

    /// Restore an in-process retirement, preserving its pending source even if
    /// video-initialization reconstruction is refused.
    pub fn resume(retirement: Retirement) -> Result<Self, ResumeRefusal> {
        let video = match flv_avc::Muxer::new(
            retirement.inputs.av_initialization.source_key(),
            &retirement.inputs.video_configuration,
            retirement.inputs.video_limits,
        ) {
            Ok(video) => video,
            Err(reason) => return Err(ResumeRefusal { reason, retirement }),
        };
        Ok(Self {
            inputs: retirement.inputs,
            video,
            pending: retirement
                .pending
                .map(|(segment, capture)| Pending { segment, capture }),
        })
    }

    /// True while a segment or pre-existing muxer fence needs reconciliation.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some() || self.inputs.muxer.pending_publication().is_some()
    }

    /// Admit a single owned source segment; refusal returns it unchanged.
    pub fn offer(
        &mut self,
        segment: recording::Segment,
        capture: CaptureInterval,
    ) -> Result<(), av_sink::Refusal> {
        let binding = segment.configuration();
        let source = &self.inputs.video_configuration;
        let reason = if self.has_pending() {
            Some(av_sink::RefusalReason::Pending)
        } else if binding.source_offset != source.offset()
            || binding.source_bytes != source.bytes().len()
            || binding.source_digest != ContentDigest::sha256(source.bytes())
        {
            Some(av_sink::RefusalReason::Configuration)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(av_sink::Refusal {
                reason,
                segment,
                capture,
            });
        }
        self.pending = Some(Pending { segment, capture });
        Ok(())
    }

    /// Publish exactly the pending segment. Synchronous storage must be run
    /// by an independently supervised worker, not on a latency-sensitive task.
    /// On every refusal the original source and muxer fence remain owned here.
    pub fn flush(
        &mut self,
        deployment: &mut ReferenceDeployment,
        authority: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        journal: &mut archive::journal::Journal,
        keeper: &mut archive::journal::AnchorKeeper,
    ) -> Result<Option<archive::PublishedAvSegment>, FlushError> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        let mut publish = |audio| {
            let input = archive::AvSegmentPublication {
                segment: &pending.segment,
                video_configuration: &self.inputs.video_configuration,
                video_initialization: self.video.initialization(),
                av_initialization: &self.inputs.av_initialization,
                audio,
                retention: self.inputs.retention,
                capture: pending.capture,
                evidence_limits: self.inputs.evidence_limits,
            };
            archive::publish_next_av_segment_anchored(
                &input,
                &mut self.inputs.muxer,
                deployment,
                authority,
                limits,
                work,
                cx,
                journal,
                keeper,
            )
            .map_err(FlushError::Archive)
        };
        let result = match &self.inputs.audio {
            Audio::InBand {
                record,
                observation,
            } => {
                let bound = observation
                    .bind_configuration(
                        record,
                        extended_flv::Limits::default(),
                        aac::Limits::default(),
                    )
                    .map_err(|_| FlushError::Audio)?;
                publish(archive::AvSegmentAudio::InBand(&bound))?
            }
            Audio::SuppliedUnverified(bytes) => {
                let config =
                    aac::Configuration::parse_explicit(bytes).map_err(|_| FlushError::Audio)?;
                publish(archive::AvSegmentAudio::SuppliedUnverified(&config))?
            }
        };
        self.pending = None;
        Ok(Some(result))
    }

    /// Transfer all owned source and muxer state; unresolved effects are not
    /// classified by retirement itself.
    pub fn retire(self) -> Retirement {
        Retirement {
            inputs: self.inputs,
            pending: self.pending.map(|p| (p.segment, p.capture)),
        }
    }
}

impl UnknownTimeOwnedSink {
    /// Resume in-process ownership without discarding a pending source or fence.
    pub fn resume(retirement: UnknownTimeRetirement) -> Result<Self, UnknownTimeResumeRefusal> {
        let video = match flv_avc::Muxer::new(
            retirement.inputs.av_initialization.source_key(),
            &retirement.inputs.video_configuration,
            retirement.inputs.video_limits,
        ) {
            Ok(video) => video,
            Err(reason) => return Err(UnknownTimeResumeRefusal { reason, retirement }),
        };
        Ok(Self {
            inputs: retirement.inputs,
            video,
            pending: retirement.pending,
        })
    }

    /// Whether a segment or publication fence must be reconciled.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some() || self.inputs.muxer.pending().is_some()
    }

    /// Exact unknown-time root requiring reconciliation, when established.
    pub fn pending_publication(&self) -> Option<archive::UnknownTimePin> {
        self.inputs.muxer.pending()
    }

    /// Admit one original source segment without inventing capture bounds.
    /// A refusal returns that exact segment and leaves existing state unchanged.
    pub fn offer(&mut self, segment: recording::Segment) -> Result<(), UnknownTimeOfferRefusal> {
        let binding = segment.configuration();
        let source = &self.inputs.video_configuration;
        let reason = if self.has_pending() {
            Some(av_sink::RefusalReason::Pending)
        } else if binding.source_offset != source.offset()
            || binding.source_bytes != source.bytes().len()
            || binding.source_digest != ContentDigest::sha256(source.bytes())
        {
            Some(av_sink::RefusalReason::Configuration)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(UnknownTimeOfferRefusal { reason, segment });
        }
        self.pending = Some(segment);
        Ok(())
    }

    /// Publish one pending source under an anchored unknown-time journal.
    /// This performs synchronous I/O and must run on a supervised worker.
    /// Failure retains the segment, muxer, and any unresolved publication fence.
    pub fn flush(
        &mut self,
        deployment: &mut ReferenceDeployment,
        authority: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        journal: &mut archive::journal::UnknownTimeJournal,
        keeper: &mut archive::journal::UnknownTimeAnchorKeeper,
    ) -> Result<Option<archive::PublishedUnknownTimeAvSegment>, UnknownTimeFlushError> {
        let Some(segment) = self.pending.as_ref() else {
            return Ok(None);
        };
        let mut publish = |audio| {
            let input = archive::UnknownTimeAvSegment {
                segment,
                video_configuration: &self.inputs.video_configuration,
                video_initialization: self.video.initialization(),
                av_initialization: &self.inputs.av_initialization,
                audio,
                retention: self.inputs.retention,
                evidence_limits: self.inputs.evidence_limits,
            };
            archive::publish_next_unknown_time_av_segment_anchored(
                &input,
                &mut self.inputs.muxer,
                deployment,
                authority,
                limits,
                work,
                cx,
                journal,
                keeper,
            )
            .map_err(UnknownTimeFlushError::Archive)
        };
        let result = match &self.inputs.audio {
            Audio::InBand {
                record,
                observation,
            } => {
                let bound = observation
                    .bind_configuration(
                        record,
                        extended_flv::Limits::default(),
                        aac::Limits::default(),
                    )
                    .map_err(|_| UnknownTimeFlushError::Audio)?;
                publish(archive::AvSegmentAudio::InBand(&bound))?
            }
            Audio::SuppliedUnverified(bytes) => {
                let config = aac::Configuration::parse_explicit(bytes)
                    .map_err(|_| UnknownTimeFlushError::Audio)?;
                publish(archive::AvSegmentAudio::SuppliedUnverified(&config))?
            }
        };
        self.pending = None;
        Ok(Some(result))
    }

    /// Return all source and muxer owners without classifying unresolved effects.
    pub fn retire(self) -> UnknownTimeRetirement {
        UnknownTimeRetirement {
            inputs: self.inputs,
            pending: self.pending,
        }
    }
}
