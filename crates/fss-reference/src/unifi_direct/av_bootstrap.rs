#![forbid(unsafe_code)]
//! Bounded collection of original inputs for the first A/V archive segment.
//!
//! A caller must enable audio tracking before media processing and pair each
//! recorder result with the audio event produced by that same input, if any.
//! This collector does not poll a supervisor or authorize a camera connection.
//! When using a supervisor, drain any earlier pending event before each step.
//! After a media result, check `has_pending_audio` and transfer the event before
//! another step. If transfer is denied, keep the result and event unpaired until
//! admission returns or recover them separately during retirement.

use fss_core::ContentDigest;
use fss_packet::extended_flv::{self, aac, aac_track, stream::SourceRecord};

use super::{av_owned_sink, pipeline, recording};

/// A result either retained for bootstrap or returned with its observation.
#[must_use]
#[derive(Debug)]
pub enum Collected {
    /// One exact source record or the first segment was retained.
    Retained,
    /// Neither the recorder result nor its associated audio event was consumed.
    Forward {
        /// The original recorder result.
        push: recording::Push,
        /// The audio interpretation of the same input, if available.
        audio: Option<pipeline::AudioEvent>,
    },
}

/// Bounded bootstrap custody: at most two configuration records and one segment.
#[must_use]
pub struct Collector {
    video: Option<SourceRecord>,
    audio: Option<av_owned_sink::Audio>,
    first_segment: Option<recording::Segment>,
    retention: ContentDigest,
    policy: av_owned_sink::BootstrapPolicy,
}

/// The collector is incomplete; it retains every input it has accepted.
#[must_use]
pub struct Incomplete(pub Collector);

/// Every input retained by a collector that did not reach bootstrap.
#[must_use]
pub struct Parts {
    /// Original video configuration, if collected.
    pub video: Option<SourceRecord>,
    /// Original or explicitly unverified audio configuration, if collected.
    pub audio: Option<av_owned_sink::Audio>,
    /// Original first segment, if collected.
    pub first_segment: Option<recording::Segment>,
    /// Retention decision identity supplied by the caller.
    pub retention: ContentDigest,
    /// Original bootstrap policy.
    pub policy: av_owned_sink::BootstrapPolicy,
}

impl Collector {
    /// Start with an optional explicitly unverified out-of-band AAC config.
    /// Without it, only a matching original in-band observation is retained.
    pub fn new(
        supplied_audio: Option<[u8; 2]>,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
    ) -> Self {
        Self {
            video: None,
            audio: supplied_audio.map(av_owned_sink::Audio::SuppliedUnverified),
            first_segment: None,
            retention,
            policy,
        }
    }

    /// Admit one recorder result and the audio event for the same input.
    /// Unmatched events, duplicate configurations, later segments and all
    /// other source records are returned intact. A configuration still held
    /// inside the recorder cannot be captured by this method.
    pub fn collect(
        &mut self,
        push: recording::Push,
        audio: Option<pipeline::AudioEvent>,
    ) -> Collected {
        match (push, audio) {
            (
                recording::Push::Source {
                    record,
                    disposition: recording::SourceDisposition::Configuration,
                },
                None,
            ) if self.video.is_none() => {
                self.video = Some(record);
                Collected::Retained
            }
            (
                recording::Push::Source {
                    record,
                    disposition: _,
                },
                Some(pipeline::AudioEvent::Observed(observation)),
            ) if self.audio.is_none()
                && matches!(observation, aac_track::Observation::Configuration { .. })
                && observation
                    .bind_configuration(
                        &record,
                        extended_flv::Limits::default(),
                        aac::Limits::default(),
                    )
                    .is_ok() =>
            {
                self.audio = Some(av_owned_sink::Audio::InBand {
                    record,
                    observation,
                });
                Collected::Retained
            }
            (recording::Push::Segment(segment), None) if self.first_segment.is_none() => {
                self.first_segment = Some(segment);
                Collected::Retained
            }
            (push, audio) => Collected::Forward { push, audio },
        }
    }

    /// Whether all required inputs are present, without asserting validity.
    pub fn ready(&self) -> bool {
        self.video.is_some() && self.audio.is_some() && self.first_segment.is_some()
    }

    /// Recover all retained custody, including on cancellation or refusal.
    pub fn into_parts(self) -> Parts {
        Parts {
            video: self.video,
            audio: self.audio,
            first_segment: self.first_segment,
            retention: self.retention,
            policy: self.policy,
        }
    }

    /// Return the bounded inputs for validation, or the entire incomplete owner.
    pub fn into_inputs(self) -> Result<av_owned_sink::BootstrapInputs, Incomplete> {
        if !self.ready() {
            return Err(Incomplete(self));
        }
        let Self {
            video: Some(video_configuration),
            audio: Some(audio),
            first_segment: Some(first_segment),
            retention,
            policy,
        } = self
        else {
            unreachable!("readiness checked above")
        };
        Ok(av_owned_sink::BootstrapInputs {
            video_configuration,
            audio,
            first_segment,
            retention,
            policy,
        })
    }
}
