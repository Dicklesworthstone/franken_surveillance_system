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

impl OwnedSink {
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
