#![forbid(unsafe_code)]
//! Bounded, transactional A/V derivation from a caller-owned source segment.
//!
//! This owner does not authenticate a camera, bind the AAC configuration to
//! the source epoch, establish a shared audio/video clock, retain source bytes,
//! publish a recording, or prove that compressed samples decode. The caller
//! must establish those facts or record them as unverified.

use std::fmt;

use fss_container::{Mp4Error, Mp4Limits, flv_av};
use fss_packet::extended_flv::{self, aac, aac_adts, aac_clock};

use super::recording::Segment;

/// Payload-free refusal; neither the borrowed segment nor the clock advances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Initialization, configuration or configured limits are incompatible.
    Configuration,
    /// No raw AAC frames were present in this completed source segment.
    NoAudio,
    /// The configured per-fragment audio bound was exceeded.
    Limit,
    /// Bounded allocation failed.
    Allocation,
    /// An original source record could not be interpreted under this profile.
    Source(aac_adts::SourceError),
    /// Audio timestamps failed the caller-selected clock hypothesis.
    Clock(aac_clock::Error),
    /// The source-linked A/V muxer rejected the fragment.
    Mux(Mp4Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi A/V recording refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One caller-bound A/V initialization, source epoch and AAC clock hypothesis.
///
/// The supplied origin is expressed in AAC sample-rate ticks. It is a caller
/// decision, not a measured relationship between the audio and video clocks.
pub struct Muxer {
    configuration: [u8; 2],
    clock: aac_clock::Clock,
    session: flv_av::Session,
    limits: Mp4Limits,
    max_audio_frames: usize,
}
impl Muxer {
    /// Bind the exact A/V initialization and an explicit AAC clock origin.
    /// The caller must bind `config` to the camera connection and source epoch.
    pub fn new(
        initialization: &flv_av::Initialization,
        config: &aac::Configuration<'_>,
        origin_ticks: u64,
        jitter_ms: u32,
        max_epoch_frames: u64,
        max_audio_frames: usize,
        limits: Mp4Limits,
    ) -> Result<Self, Error> {
        limits.validate().map_err(Error::Mux)?;
        if max_audio_frames == 0 || max_audio_frames > limits.max_samples {
            return Err(Error::Configuration);
        }
        let configuration: [u8; 2] = config
            .bytes()
            .try_into()
            .map_err(|_| Error::Configuration)?;
        if initialization
            .bytes()
            .get(initialization.audio_configuration_range())
            != Some(config.bytes())
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            configuration,
            clock: aac_clock::Clock::new(config, origin_ticks, jitter_ms, max_epoch_frames)
                .map_err(Error::Clock)?,
            session: flv_av::Session::new(initialization).map_err(Error::Mux)?,
            limits,
            max_audio_frames,
        })
    }

    /// Derive one fragment while borrowing all original records from `segment`.
    ///
    /// A refusal leaves both the AAC clock and A/V session unchanged. In-stream
    /// AAC configuration tags and unsupported audio fence this attempt rather
    /// than silently changing the caller-bound epoch. The caller retains the
    /// segment and must preserve its original source and lookahead custody.
    pub fn fragment<'a>(
        &mut self,
        initialization: &flv_av::Initialization,
        segment: &'a Segment,
    ) -> Result<flv_av::Fragment<'a>, Error> {
        let config = aac::Configuration::parse_explicit(&self.configuration)
            .map_err(|_| Error::Configuration)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(segment.source().len().min(self.max_audio_frames))
            .map_err(|_| Error::Allocation)?;
        for record in segment.source() {
            if let Some(frame) = aac_adts::source_frame(
                &config,
                record,
                extended_flv::Limits::default(),
                aac::Limits::default(),
            )
            .map_err(Error::Source)?
            {
                if frames.len() == self.max_audio_frames {
                    return Err(Error::Limit);
                }
                frames.push(frame);
            }
        }
        if frames.is_empty() {
            return Err(Error::NoAudio);
        }
        let mut candidate_clock = self.clock.clone();
        let mut audio = Vec::new();
        audio
            .try_reserve_exact(frames.len())
            .map_err(|_| Error::Allocation)?;
        for frame in &frames {
            audio.push(flv_av::TimedAudio {
                frame,
                time: candidate_clock
                    .observe(frame.timestamp_ms())
                    .map_err(Error::Clock)?,
            });
        }
        let output = self
            .session
            .fragment(
                initialization,
                segment.fragment(),
                &config,
                &audio,
                self.limits,
            )
            .map_err(Error::Mux)?;
        self.clock = candidate_clock;
        Ok(output)
    }
}
