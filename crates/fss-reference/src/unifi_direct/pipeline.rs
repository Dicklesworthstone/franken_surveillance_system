#![forbid(unsafe_code)]
//! Task-owned UniFi TCP source, FLV framing and in-memory segment composition.
//!
//! This does not establish peer identity, listen for connections, publish
//! objects, or prove continuity. The caller must bind the source and recorder
//! to one authorized camera connection and generation, and retain or explicitly
//! account for every transferred source record and retirement remainder.

use super::{ingress, recording};
use asupersync::Cx;
use fss_container::InitializationSegment;
use fss_core::TimestampNs;
use fss_packet::extended_flv::{self, aac, aac_track};
use fss_runtime::execution::TaskCx;
use std::fmt;

/// One bounded source and recorder step.
#[must_use]
#[derive(Debug)]
pub enum Step {
    /// One original-source or in-memory fragment result from the recorder.
    Recording(recording::Push),
    /// Bytes were appended but no complete source record is ready.
    Progress {
        /// Original bytes appended to the framer.
        appended: usize,
    },
    /// The peer closed its send side; retire to recover the unparsed tail.
    Eof,
    /// The configured connection byte limit was reached; retire the owner.
    LimitReached,
}

/// A refusal. A recording refusal may own an unaccepted original record.
#[must_use]
#[derive(Debug)]
pub enum Error {
    /// Source authority, framing, or I/O failed; source remains owned.
    Ingress(ingress::Error),
    /// The recorder refused a record; preserve `unaccepted` and retire.
    Recording(recording::Refusal),
    /// This owner has already ended or encountered a refusal.
    Stopped,
    /// An opt-in audio observation must be transferred before reading more.
    AudioPending,
    /// Cancellation stopped the pipeline; retire to recover all owned state.
    Cancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingress(error) => write!(f, "UniFi recording source: {error}"),
            Self::Recording(refusal) => write!(f, "UniFi recording: {}", refusal.reason),
            Self::Stopped => write!(f, "UniFi recording owner stopped"),
            Self::AudioPending => write!(f, "UniFi audio observation must be transferred"),
            Self::Cancelled => write!(f, "UniFi recording owner cancelled"),
        }
    }
}
impl std::error::Error for Error {}

/// Untransferred original source and recorder state at shutdown.
#[must_use]
#[derive(Debug)]
pub struct Retirement {
    /// Remaining TCP chunk and unparsed framing bytes.
    pub ingress: ingress::Retirement,
    /// Records held for the unfinished fragment.
    pub recorder: recording::Retirement,
    /// An audio observation still owned when the pipeline was retired.
    pub pending_audio: Option<AudioEvent>,
}

/// A bounded audio-side observation. The original bytes remain with the video
/// recorder, a returned source record, or a recording refusal, not this value.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub enum AudioEvent {
    /// One connection-relative AAC observation.
    Observed(aac_track::Observation),
    /// Audio interpretation stopped; the video owner may continue separately.
    Fenced(aac_track::Error),
}

/// Refusal to attach the optional audio interpreter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioSetupError {
    /// Source processing has started or the pipeline has stopped.
    AlreadyStarted,
    /// An audio interpreter is already attached.
    AlreadyEnabled,
}
impl fmt::Display for AudioSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi audio setup refused: {self:?}")
    }
}
impl std::error::Error for AudioSetupError {}

/// One caller-bound source connection and recorder generation.
pub struct Pipeline {
    ingress: ingress::DirectIngress,
    recorder: recording::Recorder,
    audio: Option<aac_track::Track>,
    pending_audio: Option<AudioEvent>,
    started: bool,
    stopped: bool,
}
impl Pipeline {
    /// Attach a recorder to a caller-owned ingress without performing I/O.
    /// The caller must bind both to the same authorized connection and generation.
    pub fn new(ingress: ingress::DirectIngress, recorder: recording::Recorder) -> Self {
        Self {
            ingress,
            recorder,
            audio: None,
            pending_audio: None,
            started: false,
            stopped: false,
        }
    }

    /// Attach one AAC source interpreter before any pipeline step. The default
    /// video-only path is unchanged. This does not decode, mux, save, or play
    /// audio, and does not authenticate the sender or configuration epoch.
    pub fn enable_audio_tracking(&mut self) -> Result<(), AudioSetupError> {
        if self.started || self.stopped {
            return Err(AudioSetupError::AlreadyStarted);
        }
        if self.audio.is_some() {
            return Err(AudioSetupError::AlreadyEnabled);
        }
        self.audio = Some(aac_track::Track::new(
            extended_flv::Limits::default(),
            aac::Limits::default(),
        ));
        Ok(())
    }

    /// Whether an audio result must be transferred before another source read.
    pub fn has_pending_audio(&self) -> bool {
        self.pending_audio.is_some()
    }

    /// Transfer the one pending audio result without transferring source bytes.
    pub fn take_audio_event(&mut self) -> Option<AudioEvent> {
        self.pending_audio.take()
    }

    /// Current in-memory MP4 initialization, if a configuration was observed.
    /// The caller must retain source custody and publish it before fragments.
    pub fn initialization(&self) -> Option<&InitializationSegment> {
        self.recorder.initialization()
    }

    /// Derive an A/V initialization after the video configuration is observed.
    /// The caller must establish the audio configuration and clock binding.
    pub fn av_initialization(
        &self,
        audio: &aac::Configuration<'_>,
    ) -> Result<Option<fss_container::flv_av::Initialization>, fss_container::Mp4Error> {
        self.recorder.av_initialization(audio)
    }

    /// Perform at most one source step and admit at most one resulting record.
    /// The caller supplies a current canonical timestamp, supervises the wait,
    /// and consumes each returned original record or explicit omission.
    pub async fn step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<Step, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        if self.pending_audio.is_some() {
            if cx.checkpoint().is_err() {
                self.stopped = true;
                return Err(Error::Cancelled);
            }
            return Err(Error::AudioPending);
        }
        self.started = true;
        let source = match self.ingress.step(task, cx, now).await {
            Ok(source) => source,
            Err(error) => {
                self.stopped = true;
                return Err(Error::Ingress(error));
            }
        };
        match source {
            ingress::Step::Record(record) => {
                if let Some(track) = self.audio.as_mut() {
                    match track.observe(&record) {
                        Ok(aac_track::Observation::Header | aac_track::Observation::Other) => (),
                        Ok(observation) => {
                            self.pending_audio = Some(AudioEvent::Observed(observation));
                        }
                        Err(error) => {
                            self.pending_audio = Some(AudioEvent::Fenced(error));
                            self.audio = None;
                        }
                    }
                }
                match self.recorder.push(record) {
                    Ok(result) => Ok(Step::Recording(result)),
                    Err(refusal) => {
                        self.stopped = true;
                        Err(Error::Recording(refusal))
                    }
                }
            }
            ingress::Step::Progress { appended } => Ok(Step::Progress { appended }),
            ingress::Step::Eof => {
                self.stopped = true;
                Ok(Step::Eof)
            }
            ingress::Step::LimitReached => {
                self.stopped = true;
                Ok(Step::LimitReached)
            }
        }
    }

    /// Close the source and transfer every owner-held original byte.
    /// Already returned source records and a refusal's unaccepted record remain
    /// the caller's responsibility; buffered source prefixes may overlap.
    pub fn retire(self) -> Retirement {
        Retirement {
            ingress: self.ingress.retire(),
            recorder: self.recorder.retire(),
            pending_audio: self.pending_audio,
        }
    }
}
