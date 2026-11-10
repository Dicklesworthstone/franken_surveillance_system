#![forbid(unsafe_code)]
//! Bounded, transactional A/V derivation from a caller-owned source segment.
//!
//! This owner does not authenticate a camera, bind the AAC configuration to
//! the source epoch, establish a shared audio/video clock, retain source bytes,
//! publish a recording, or prove that compressed samples decode. The caller
//! must establish those facts or record them as unverified.

use std::{fmt, ops::Range};

use fss_container::{Mp4Error, Mp4Limits, flv_av};
use fss_core::ContentDigest;
use fss_packet::extended_flv::{self, aac, aac_adts, aac_clock, aac_track};

use super::{archive::Pin, recording::Segment};

/// Payload-free refusal; neither the borrowed segment nor the clock advances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Initialization, configuration or configured limits are incompatible.
    Configuration,
    /// No raw AAC frames were present in this completed source segment.
    NoAudio,
    /// The configured per-fragment audio bound was exceeded.
    Limit,
    /// The caller's bounded sender-clock alignment hypothesis was refused.
    Alignment,
    /// Bounded allocation failed.
    Allocation,
    /// An original source record could not be interpreted under this profile.
    Source(aac_adts::SourceError),
    /// Audio timestamps failed the caller-selected clock hypothesis.
    Clock(aac_clock::Error),
    /// The source-linked A/V muxer rejected the fragment.
    Mux(Mp4Error),
    /// A publication may have taken effect and must be reconciled first.
    PublicationPending,
    /// This owner is bound to a journaled publication path.
    JournalRequired,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi A/V recording refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A caller-requested mapping from a wrapping sender timestamp to AAC ticks.
/// It assumes the audio and video timestamps share a sender clock; it does not
/// prove physical capture-time alignment, identity, or audio completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderClockOrigin {
    /// First audio decode position in AAC sample-rate ticks, rounded down.
    pub audio_ticks: u64,
    /// Signed sender-time difference from the first video decode timestamp.
    pub audio_minus_video_ms: i64,
    /// Fractional AAC tick discarded, in thousandths of a tick.
    pub fractional_tick_thousandths: u16,
}

/// Map an audio sender timestamp to the same unwrapped millisecond epoch as
/// `video_ms`, subject to the caller's maximum separation. Half-wrap ties,
/// negative unwrapped time and arithmetic overflow are refused. This is a
/// timing hypothesis, not an independent A/V synchronization measurement.
pub fn sender_clock_origin(
    video_ms: u64,
    audio_ms: u32,
    sample_rate: u32,
    max_separation_ms: u32,
) -> Result<SenderClockOrigin, Error> {
    if sample_rate == 0 || max_separation_ms >= (1 << 31) {
        return Err(Error::Alignment);
    }
    let wrapped_delta = audio_ms.wrapping_sub(video_ms as u32);
    if wrapped_delta == (1 << 31) {
        return Err(Error::Alignment);
    }
    let delta = i64::from(wrapped_delta as i32);
    if delta.unsigned_abs() > u64::from(max_separation_ms) {
        return Err(Error::Alignment);
    }
    let unwrapped = video_ms.checked_add_signed(delta).ok_or(Error::Alignment)?;
    let scaled = u128::from(unwrapped) * u128::from(sample_rate);
    let ticks = u64::try_from(scaled / 1000).map_err(|_| Error::Alignment)?;
    Ok(SenderClockOrigin {
        audio_ticks: ticks,
        audio_minus_video_ms: delta,
        fractional_tick_thousandths: (scaled % 1000) as u16,
    })
}

/// Derive that hypothesis from the first video sample and first raw AAC
/// record of a completed, caller-owned segment. The source records remain
/// borrowed; a configuration change or unsupported audio is refused.
pub fn segment_sender_clock_origin(
    segment: &Segment,
    config: &aac::Configuration<'_>,
    max_separation_ms: u32,
) -> Result<SenderClockOrigin, Error> {
    let video_ms = segment
        .fragment()
        .samples()
        .first()
        .ok_or(Error::Alignment)?
        .decode_time_ms;
    for record in segment.source() {
        if let Some(frame) = aac_adts::source_frame(
            config,
            record,
            extended_flv::Limits::default(),
            aac::Limits::default(),
        )
        .map_err(Error::Source)?
        {
            if frame.provisional() {
                return Err(Error::Alignment);
            }
            return sender_clock_origin(
                video_ms,
                frame.timestamp_ms(),
                config.sample_rate(),
                max_separation_ms,
            );
        }
    }
    Err(Error::NoAudio)
}

/// A clock hypothesis derived from an exact copied lookahead source record.
/// The original remains on the next segment's side of the custody boundary;
/// this observation neither consumes it nor asserts audio coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookaheadClockOrigin {
    /// Sender-clock mapping relative to the first video sample.
    pub origin: SenderClockOrigin,
    /// Connection-relative offset of the copied original record.
    pub record_offset: u64,
    /// Number of original record bytes included in the copied witness.
    pub record_bytes: usize,
    /// Digest of the exact copied record, not an identity assertion.
    pub record_digest: fss_core::ContentDigest,
    /// Sender timestamp on the selected AAC frame.
    pub sender_timestamp_ms: u32,
}

/// Derive a clock hypothesis from the first usable copied lookahead AAC frame
/// only when the segment itself contains no AAC frame. This does not move the
/// record into the segment or authorize its publication as a sample there.
pub fn lookahead_sender_clock_origin(
    segment: &Segment,
    config: &aac::Configuration<'_>,
    max_separation_ms: u32,
) -> Result<LookaheadClockOrigin, Error> {
    match segment_sender_clock_origin(segment, config, max_separation_ms) {
        Err(Error::NoAudio) => (),
        Ok(_) => return Err(Error::Configuration),
        Err(error) => return Err(error),
    }
    let video_ms = segment
        .fragment()
        .samples()
        .first()
        .ok_or(Error::Alignment)?
        .decode_time_ms;
    for record in segment.lookahead_copies() {
        if let Some(frame) = aac_adts::source_frame(
            config,
            record,
            extended_flv::Limits::default(),
            aac::Limits::default(),
        )
        .map_err(Error::Source)?
        {
            if frame.provisional() {
                return Err(Error::Alignment);
            }
            let origin = sender_clock_origin(
                video_ms,
                frame.timestamp_ms(),
                config.sample_rate(),
                max_separation_ms,
            )?;
            return Ok(LookaheadClockOrigin {
                origin,
                record_offset: record.offset(),
                record_bytes: record.bytes().len(),
                record_digest: fss_core::ContentDigest::sha256(record.bytes()),
                sender_timestamp_ms: frame.timestamp_ms(),
            });
        }
    }
    Err(Error::NoAudio)
}

/// A source-record claim for the AAC configuration used by this owner.
/// It does not authenticate the sender or independently prove the epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioSourceBinding {
    /// Track-local epoch claimed by the observation.
    pub epoch: u64,
    /// Connection-relative offset of the original configuration record.
    pub record_offset: u64,
    /// Length of that original record, including its trailer.
    pub record_bytes: usize,
    /// Digest of the exact original record; custody remains caller-owned.
    pub record_digest: ContentDigest,
    /// Connection-relative byte range of the AudioSpecificConfig.
    pub configuration_source: Range<u64>,
}

/// One caller-bound A/V initialization, source epoch and AAC clock hypothesis.
///
/// The supplied origin is expressed in AAC sample-rate ticks. It is a caller
/// decision, not a measured relationship between the audio and video clocks.
pub struct Muxer {
    configuration: Vec<u8>,
    clock: aac_clock::Clock,
    session: flv_av::Session,
    limits: Mp4Limits,
    max_audio_frames: usize,
    source_binding: Option<AudioSourceBinding>,
    expected_initial_audio: Option<ExpectedInitialAudio>,
    pending_publication: Option<Pin>,
    publication_scope: Option<ContentDigest>,
}

#[derive(Clone, Copy)]
struct ExpectedInitialAudio {
    witness: LookaheadClockOrigin,
    first_video_digest: ContentDigest,
    first_video_sequence: u32,
    first_video_emitted: bool,
}

pub(crate) enum TransactionError<E> {
    Media(Error),
    Consumer(E),
}

impl Muxer {
    /// Advance a private candidate only after its consumer reports success.
    /// An error or panic does not prove that the consumer had no external
    /// effect; that outcome must be reconciled using the same source/root.
    pub(crate) fn with_fragment<'a, T, E>(
        &mut self,
        initialization: &flv_av::Initialization,
        segment: &'a Segment,
        allow_initial_video_only: bool,
        consumer: impl FnOnce(&flv_av::Fragment<'a>, &mut Option<Pin>) -> Result<T, E>,
    ) -> Result<T, TransactionError<E>> {
        let mut candidate = Self {
            configuration: self.configuration.clone(),
            clock: self.clock.clone(),
            session: self.session.clone(),
            limits: self.limits,
            max_audio_frames: self.max_audio_frames,
            source_binding: self.source_binding.clone(),
            expected_initial_audio: self.expected_initial_audio,
            // A candidate may derive the same segment while the live owner is
            // fenced; only the publication consumer may resolve that fence.
            pending_publication: None,
            publication_scope: None,
        };
        let fragment = if allow_initial_video_only
            && candidate
                .expected_initial_audio
                .is_some_and(|expected| !expected.first_video_emitted)
        {
            candidate.fragment_without_audio(initialization, segment)
        } else {
            candidate.fragment(initialization, segment)
        }
        .map_err(TransactionError::Media)?;
        let result = consumer(&fragment, &mut self.pending_publication)
            .map_err(TransactionError::Consumer)?;
        candidate.publication_scope = self.publication_scope;
        *self = candidate;
        Ok(result)
    }

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
        let configuration = config.bytes().to_vec();
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
            source_binding: None,
            expected_initial_audio: None,
            pending_publication: None,
            publication_scope: None,
        })
    }

    /// Construct a muxer whose first audio sample must match the exact copied
    /// lookahead witness from the supplied video-only initial segment. This
    /// does not consume that witness or assert coverage or physical identity.
    #[allow(clippy::too_many_arguments)]
    pub fn from_lookahead(
        initialization: &flv_av::Initialization,
        config: &aac::Configuration<'_>,
        segment: &Segment,
        max_separation_ms: u32,
        jitter_ms: u32,
        max_epoch_frames: u64,
        max_audio_frames: usize,
        limits: Mp4Limits,
    ) -> Result<(Self, LookaheadClockOrigin), Error> {
        if initialization.source_key() != segment.fragment().key()
            || initialization.video_configuration_sources()
                != segment.fragment().configuration_sources()
        {
            return Err(Error::Configuration);
        }
        let witness = lookahead_sender_clock_origin(segment, config, max_separation_ms)?;
        let mut owner = Self::new(
            initialization,
            config,
            witness.origin.audio_ticks,
            jitter_ms,
            max_epoch_frames,
            max_audio_frames,
            limits,
        )?;
        owner.expected_initial_audio = Some(ExpectedInitialAudio {
            witness,
            first_video_digest: ContentDigest::sha256(segment.fragment().bytes()),
            first_video_sequence: segment.fragment().sequence(),
            first_video_emitted: false,
        });
        Ok((owner, witness))
    }

    /// Like `from_lookahead`, also binding the exact in-band AAC configuration
    /// record and epoch. The caller must still establish common source custody.
    #[allow(clippy::too_many_arguments)]
    pub fn from_source_lookahead(
        initialization: &flv_av::Initialization,
        bound: &aac_track::BoundConfiguration<'_>,
        segment: &Segment,
        max_separation_ms: u32,
        jitter_ms: u32,
        max_epoch_frames: u64,
        max_audio_frames: usize,
        limits: Mp4Limits,
    ) -> Result<(Self, LookaheadClockOrigin), Error> {
        if bound.provisional() {
            return Err(Error::Configuration);
        }
        let (mut owner, witness) = Self::from_lookahead(
            initialization,
            bound.configuration(),
            segment,
            max_separation_ms,
            jitter_ms,
            max_epoch_frames,
            max_audio_frames,
            limits,
        )?;
        let record = bound.record();
        owner.source_binding = Some(AudioSourceBinding {
            epoch: bound.epoch(),
            record_offset: record.offset(),
            record_bytes: record.bytes().len(),
            record_digest: ContentDigest::sha256(record.bytes()),
            configuration_source: bound.source(),
        });
        Ok((owner, witness))
    }

    /// Bind an observed in-band AAC configuration to its exact source record.
    /// Provisional source boundaries are refused. The caller must still bind
    /// the observation's track and the video initialization to one connection
    /// and epoch, retain the original record and establish clock alignment.
    pub fn from_source(
        initialization: &flv_av::Initialization,
        bound: &aac_track::BoundConfiguration<'_>,
        origin_ticks: u64,
        jitter_ms: u32,
        max_epoch_frames: u64,
        max_audio_frames: usize,
        limits: Mp4Limits,
    ) -> Result<Self, Error> {
        if bound.provisional() {
            return Err(Error::Configuration);
        }
        let mut owner = Self::new(
            initialization,
            bound.configuration(),
            origin_ticks,
            jitter_ms,
            max_epoch_frames,
            max_audio_frames,
            limits,
        )?;
        let record = bound.record();
        owner.source_binding = Some(AudioSourceBinding {
            epoch: bound.epoch(),
            record_offset: record.offset(),
            record_bytes: record.bytes().len(),
            record_digest: ContentDigest::sha256(record.bytes()),
            configuration_source: bound.source(),
        });
        Ok(owner)
    }

    /// Source binding for an in-band configuration, if one was supplied.
    /// `None` means the configuration was explicitly supplied without one.
    pub fn source_binding(&self) -> Option<&AudioSourceBinding> {
        self.source_binding.as_ref()
    }

    /// Root that may have been published and must be reconciled before this
    /// owner accepts another fragment. This in-memory pin grants no authority
    /// and is not durable across a process crash.
    pub fn pending_publication(&self) -> Option<Pin> {
        self.pending_publication
    }

    pub(crate) fn restore_publication_fence(&mut self, pin: Pin) {
        self.pending_publication = Some(pin);
    }

    pub(crate) fn bind_publication_scope(&mut self, scope: ContentDigest) -> bool {
        if self
            .publication_scope
            .is_some_and(|current| current != scope)
        {
            return false;
        }
        self.publication_scope = Some(scope);
        true
    }

    pub(crate) fn publication_scope(&self) -> Option<ContentDigest> {
        self.publication_scope
    }

    /// Extend the AAC frame allowance without resetting this session's
    /// timestamp or source continuity checks. The caller must authorize and
    /// account for each extension under the same configuration epoch.
    /// A failed fragment may be retried after renewal because its input remains
    /// borrowed and neither timing nor mux state advanced on refusal.
    pub fn extend_audio_limit(&mut self, additional_frames: u64) -> Result<(), Error> {
        if self.pending_publication.is_some() {
            return Err(Error::PublicationPending);
        }
        self.clock
            .extend_limit(additional_frames)
            .map_err(Error::Clock)
    }

    /// Remaining AAC frame observations under the current caller allowance.
    pub fn remaining_audio_frames(&self) -> u64 {
        self.clock.remaining()
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
        if self.pending_publication.is_some() {
            return Err(Error::PublicationPending);
        }
        if self.publication_scope.is_some() {
            return Err(Error::JournalRequired);
        }
        let config = aac::Configuration::parse_explicit(&self.configuration)
            .map_err(|_| Error::Configuration)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(segment.source().len().min(self.max_audio_frames))
            .map_err(|_| Error::Allocation)?;
        if self
            .expected_initial_audio
            .is_some_and(|expected| !expected.first_video_emitted)
        {
            return Err(Error::Alignment);
        }
        for record in segment.source() {
            if let Some(frame) = aac_adts::source_frame(
                &config,
                record,
                extended_flv::Limits::default(),
                aac::Limits::default(),
            )
            .map_err(Error::Source)?
            {
                if frames.is_empty()
                    && self.expected_initial_audio.is_some_and(|expected| {
                        let witness = expected.witness;
                        record.offset() != witness.record_offset
                            || record.bytes().len() != witness.record_bytes
                            || ContentDigest::sha256(record.bytes()) != witness.record_digest
                            || frame.timestamp_ms() != witness.sender_timestamp_ms
                    })
                {
                    return Err(Error::Alignment);
                }
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
        self.expected_initial_audio = None;
        Ok(output)
    }

    /// Explicitly emit a video-only fragment when the segment contains no raw
    /// AAC frame. Audio clock and cursor state remain unchanged. This does not
    /// assert audio absence, authorize an omission, or publish a v1 A/V graph.
    pub fn fragment_without_audio<'a>(
        &mut self,
        initialization: &flv_av::Initialization,
        segment: &'a Segment,
    ) -> Result<flv_av::Fragment<'a>, Error> {
        if self.pending_publication.is_some() {
            return Err(Error::PublicationPending);
        }
        if self.publication_scope.is_some() {
            return Err(Error::JournalRequired);
        }
        if self.expected_initial_audio.is_some_and(|expected| {
            !expected.first_video_emitted
                && (segment.fragment().sequence() != expected.first_video_sequence
                    || ContentDigest::sha256(segment.fragment().bytes())
                        != expected.first_video_digest
                    || !segment.lookahead_copies().iter().any(|record| {
                        record.offset() == expected.witness.record_offset
                            && record.bytes().len() == expected.witness.record_bytes
                            && ContentDigest::sha256(record.bytes())
                                == expected.witness.record_digest
                    }))
        }) {
            return Err(Error::Alignment);
        }
        let config = aac::Configuration::parse_explicit(&self.configuration)
            .map_err(|_| Error::Configuration)?;
        for record in segment.source() {
            if aac_adts::source_frame(
                &config,
                record,
                extended_flv::Limits::default(),
                aac::Limits::default(),
            )
            .map_err(Error::Source)?
            .is_some()
            {
                return Err(Error::Configuration);
            }
        }
        let fragment = self
            .session
            .fragment_without_audio(initialization, segment.fragment(), &config, self.limits)
            .map_err(Error::Mux)?;
        if let Some(expected) = self.expected_initial_audio.as_mut() {
            expected.first_video_emitted = true;
        }
        Ok(fragment)
    }
}
