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

/// Prefix-probing refusal; a stopped pipeline still retains source custody.
#[derive(Debug)]
pub enum ProbeError {
    /// Another pipeline operation has already begun or the owner stopped.
    NotFresh,
    /// Source admission or I/O failed.
    Ingress(ingress::Error),
}

/// Payload-free refusal while probing a connection-local name claim.
#[derive(Debug)]
pub enum NameProbeError {
    /// The pipeline is stopped or no longer in its startup probe phase.
    NotFresh,
    /// No connection-local name-probe owner was installed.
    NotConfigured,
    /// The source or metadata inspection refused progress.
    Ingress(ingress::NameProbeError),
}
impl fmt::Display for NameProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi name probe refused: {self:?}")
    }
}
impl std::error::Error for NameProbeError {}
impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi first-byte probe refused: {self:?}")
    }
}
impl std::error::Error for ProbeError {}
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
    probing: bool,
    first_byte_only: bool,
    stopped: bool,
    name_probe: Option<extended_flv::stream::NameProbeOwner>,
}
impl Pipeline {
    pub(crate) fn is_fresh(&self) -> bool {
        !self.started && !self.stopped
    }

    /// Caller-supplied connection and generation claim; this does not authenticate the peer.
    pub fn source_key(&self) -> fss_container::flv_avc::SourceKey {
        self.recorder.source_key()
    }

    /// Attach a recorder to a caller-owned ingress without performing I/O.
    /// The caller must bind both to the same authorized connection and generation.
    pub fn new(ingress: ingress::DirectIngress, recorder: recording::Recorder) -> Self {
        Self {
            ingress,
            recorder,
            audio: None,
            pending_audio: None,
            started: false,
            probing: false,
            first_byte_only: false,
            stopped: false,
            name_probe: None,
        }
    }

    /// Attach one AAC source interpreter before any ordinary pipeline step.
    /// A completed prefix probe is allowed because it cannot emit a record.
    /// This does not decode, mux, save, or play audio, and does not authenticate
    /// the sender or configuration epoch.
    pub fn enable_audio_tracking(&mut self) -> Result<(), AudioSetupError> {
        if self.stopped || (self.started && !self.first_byte_only) {
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

    /// Whether audio observation is enabled and has not fenced.
    pub fn audio_tracking_active(&self) -> bool {
        !self.stopped && self.audio.is_some()
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

    /// Distinguish an empty fresh connection from one that sent at least one
    /// byte. The byte stays in the framer for normal recording; data is not
    /// proof of a valid stream. A dropped pending probe can be polled again or
    /// replaced by ordinary `step`, with its prepaid read reservation retained.
    pub async fn probe_first_byte(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<ingress::FirstByte, ProbeError> {
        if self.name_probe.is_some() || self.stopped || (self.started && !self.probing) {
            return Err(ProbeError::NotFresh);
        }
        self.started = true;
        self.probing = true;
        let result = self.ingress.probe_first_byte(task, cx, now).await;
        self.probing = false;
        match result {
            Ok(ingress::FirstByte::Empty) => {
                self.stopped = true;
                Ok(ingress::FirstByte::Empty)
            }
            Ok(ingress::FirstByte::Data) => {
                self.first_byte_only = true;
                Ok(ingress::FirstByte::Data)
            }
            Err(error) => {
                self.stopped = true;
                Err(ProbeError::Ingress(error))
            }
        }
    }

    /// Probe at most one initial-header byte while retaining the original
    /// prefix. Invalid or incomplete connections stop but retain their bytes.
    /// A dropped pending read can resume; a valid header is not media or peer
    /// authentication. Audio may still be enabled before ordinary processing.
    pub async fn probe_header_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<ingress::HeaderProbe, ProbeError> {
        if self.name_probe.is_some() || self.stopped || (self.started && !self.probing) {
            return Err(ProbeError::NotFresh);
        }
        self.started = true;
        self.probing = true;
        match self.ingress.probe_header_step(task, cx, now).await {
            Ok(ingress::HeaderProbe::Progress) => Ok(ingress::HeaderProbe::Progress),
            Ok(ingress::HeaderProbe::Valid) => {
                self.probing = false;
                self.first_byte_only = true;
                Ok(ingress::HeaderProbe::Valid)
            }
            Ok(result) => {
                self.probing = false;
                self.stopped = true;
                Ok(result)
            }
            Err(error) => {
                self.probing = false;
                self.stopped = true;
                Err(ProbeError::Ingress(error))
            }
        }
    }

    /// Install immutable expectations and a cumulative work budget before
    /// probing or recording begins. Refusal returns the caller's owner.
    pub fn begin_name_probe(
        &mut self,
        probe: extended_flv::stream::NameProbeOwner,
    ) -> Result<(), extended_flv::stream::NameProbeOwner> {
        if self.started || self.stopped || self.name_probe.is_some() {
            return Err(probe);
        }
        self.name_probe = Some(probe);
        Ok(())
    }

    /// Transfer the current name-probe owner and its remaining work to the
    /// caller. Taking it abandons this optional probe; original source remains
    /// in the ingress until ordinary processing or retirement.
    pub fn take_name_probe(&mut self) -> Option<extended_flv::stream::NameProbeOwner> {
        self.name_probe.take()
    }

    /// Remaining work in the installed probe, if any; this is not authority.
    pub fn name_probe_work_remaining(&self) -> Option<u64> {
        self.name_probe
            .as_ref()
            .map(extended_flv::stream::NameProbeOwner::work_remaining)
    }

    /// Advance an installed connection-local probe without consuming source.
    /// Dropping a pending wait retains both the expectations and source bytes.
    /// An explicit ordinary `step` can abandon probing; callers must enforce
    /// their own selection policy and account for the retained source.
    pub async fn probe_name_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<ingress::NameProbeStep, NameProbeError> {
        if self.stopped || (self.started && !self.probing) {
            return Err(NameProbeError::NotFresh);
        }
        let probe = self
            .name_probe
            .as_mut()
            .ok_or(NameProbeError::NotConfigured)?;
        self.started = true;
        self.probing = true;
        match self.ingress.probe_name_step(task, cx, now, probe).await {
            Ok(ingress::NameProbeStep::Progress { appended }) => {
                Ok(ingress::NameProbeStep::Progress { appended })
            }
            Ok(result @ ingress::NameProbeStep::Matched { .. }) => {
                self.probing = false;
                self.first_byte_only = true;
                Ok(result)
            }
            Ok(result) => {
                self.probing = false;
                self.stopped = true;
                Ok(result)
            }
            Err(error) => {
                self.probing = false;
                self.stopped = true;
                Err(NameProbeError::Ingress(error))
            }
        }
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
        self.probing = false;
        self.first_byte_only = false;
        self.name_probe = None;
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
