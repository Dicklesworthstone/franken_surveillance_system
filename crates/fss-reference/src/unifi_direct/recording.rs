#![forbid(unsafe_code)]
//! Bounded source ownership for IDR-led FLV AVC fragments.
//!
//! This synchronous owner performs no I/O, decoding, retention, or archive
//! publication. It returns original records separately from MP4 derivatives;
//! the caller must durably retain or explicitly account for every returned or
//! retired source record. The source framer's boundaries remain heuristic.

use std::fmt;

use fss_container::{
    InitializationSegment, Mp4Error, Mp4Limits,
    flv_avc::{Fragment, Muxer, SourceKey, TimedSample},
};
use fss_core::ContentDigest;
use fss_packet::extended_flv::{
    self, avc,
    stream::{RecordKind, SourceRecord},
    track::{self, Observation, Track},
};

/// Explicit memory and media-clock bounds for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum simultaneously held original records, at most 65,536.
    pub max_records: usize,
    /// Maximum simultaneously held original source bytes, at most 128 MiB.
    pub max_source_bytes: usize,
    /// Maximum copied boundary-witness bytes per fragment, at most the source bound.
    pub max_witness_bytes: usize,
    /// Largest accepted positive interval between video timestamps, at most 10 seconds.
    pub max_frame_interval_ms: u32,
    /// Independent MP4 encoding and sample-count limits.
    pub mp4: Mp4Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 16_384,
            max_source_bytes: 64 * 1024 * 1024,
            max_witness_bytes: 8 * 1024 * 1024,
            max_frame_interval_ms: 2_000,
            mp4: Mp4Limits::default(),
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        self.mp4.validate().map_err(Error::Mux)?;
        if !(1..=65_536).contains(&self.max_records)
            || !(1..=128 * 1024 * 1024).contains(&self.max_source_bytes)
            || !(1..=self.max_source_bytes).contains(&self.max_witness_bytes)
            || !(1..=10_000).contains(&self.max_frame_interval_ms)
            || self.max_records > self.mp4.max_source_spans
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// How a source record was transferred without a corresponding MP4 sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDisposition {
    /// The original stream header was returned to the caller.
    Header,
    /// The exact original AVC configuration was returned to the caller.
    Configuration,
    /// Source preceding the first IDR was explicitly returned as unrecorded pre-roll.
    PreRoll,
}

/// Exact source configuration and derived initialization binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationBinding {
    /// Original configuration-record offset within the connection.
    pub source_offset: u64,
    /// Byte length of the original record, including any trailer.
    pub source_bytes: usize,
    /// Digest of the exact original record.
    pub source_digest: ContentDigest,
    /// Digest of the exact derived MP4 initialization bytes.
    pub initialization_digest: ContentDigest,
}

/// A completed fragment and exact original records preceding its lookahead.
/// Neither source nor derivative has been persisted by this owner.
#[must_use]
#[derive(Debug)]
pub struct Segment {
    /// In-memory video-only MP4 fragment and source mappings.
    fragment: Fragment,
    /// Original source records in connection order. May include audio and metadata.
    source: Vec<SourceRecord>,
    /// Exact copies of interleaved records and the later picture used as the
    /// boundary witness. Their originals remain pending for the next segment.
    lookahead_copies: Vec<SourceRecord>,
    configuration: ConfigurationBinding,
}
impl Segment {
    /// Borrow the immutable source-linked MP4 derivative.
    pub fn fragment(&self) -> &Fragment {
        &self.fragment
    }
    /// Borrow exact original source records, in connection order.
    pub fn source(&self) -> &[SourceRecord] {
        &self.source
    }
    /// Borrow copied records that supplied the later-picture boundary witness.
    pub fn lookahead_copies(&self) -> &[SourceRecord] {
        &self.lookahead_copies
    }
    /// Exact configuration and initialization identities bound to the fragment.
    pub fn configuration(&self) -> ConfigurationBinding {
        self.configuration
    }
    /// Transfer all components; the caller remains responsible for custody.
    pub fn into_parts(
        self,
    ) -> (
        Fragment,
        Vec<SourceRecord>,
        Vec<SourceRecord>,
        ConfigurationBinding,
    ) {
        (
            self.fragment,
            self.source,
            self.lookahead_copies,
            self.configuration,
        )
    }
}

/// Result of admitting one source record.
#[must_use]
#[derive(Debug)]
pub enum Push {
    /// The source record is returned immediately for custody or explicit omission.
    Source {
        /// Original record transferred to the caller.
        record: SourceRecord,
        /// Why no MP4 sample was generated for this source record.
        disposition: SourceDisposition,
    },
    /// The source record is held until a later IDR or retirement.
    Buffered,
    /// An IDR lookahead completed a fragment; the lookahead remains held.
    Segment(Segment),
}

/// Static, payload-free reason the owner refused further input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Owner configuration or identity is invalid.
    Configuration,
    /// A previous refusal fenced this owner.
    Fenced,
    /// Input or output would exceed a configured bound.
    Limit,
    /// The source had an unsupported or ambiguous configuration transition.
    ConfigurationChange,
    /// Video arrived before an AVC configuration.
    MissingConfiguration,
    /// FLV candidate boundaries were marked provisional.
    Provisional,
    /// A source timestamp stalled, moved outside the allowed interval, or overflowed.
    Timeline,
    /// Bounded allocation could not be completed.
    Allocation,
    /// Source track interpretation refused this input.
    Track(track::Error),
    /// The MP4 reference refused this input or fragment.
    Mux(Mp4Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi recording refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A refused record. If `unaccepted` is absent it remains in the owner's
/// pending source and must be recovered by [`Recorder::retire`].
#[must_use]
#[derive(Debug)]
pub struct Refusal {
    /// Stable reason; no source bytes are reflected here.
    pub reason: Error,
    /// Original record not admitted to the buffer, if any.
    pub unaccepted: Option<SourceRecord>,
}

/// All source records still held at shutdown or after refusal.
#[must_use]
#[derive(Debug)]
pub struct Retirement {
    /// Exact pending source in connection order, including an unclosed tail.
    pub pending: Vec<SourceRecord>,
    /// Original byte count still held, without a durable-custody assertion.
    pub source_bytes: usize,
    /// Whether an earlier refusal fenced further input.
    pub fenced: bool,
}

#[derive(Clone, Copy)]
struct Video {
    index: usize,
    time_ms: u64,
}

/// One caller-bound connection and configuration epoch.
pub struct Recorder {
    key: SourceKey,
    limits: Limits,
    track: Track,
    mux: Option<Muxer>,
    configuration: Option<ConfigurationBinding>,
    pending: Vec<SourceRecord>,
    videos: Vec<Video>,
    source_bytes: usize,
    last_video_time: Option<(u32, u64)>,
    started: bool,
    fenced: bool,
}
impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("key", &self.key)
            .field("pending_records", &self.pending.len())
            .field("pending_bytes", &self.source_bytes)
            .field("fenced", &self.fenced)
            .finish_non_exhaustive()
    }
}
impl Recorder {
    /// Start a bounded owner for a caller-selected connection and generation.
    pub fn new(key: SourceKey, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if key.connection == 0 || key.generation == 0 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            key,
            limits,
            track: Track::new(extended_flv::Limits::default(), avc::Limits::default()),
            mux: None,
            configuration: None,
            pending: Vec::new(),
            videos: Vec::new(),
            source_bytes: 0,
            last_video_time: None,
            started: false,
            fenced: false,
        })
    }

    /// MP4 initialization for the current exact configuration, if observed.
    /// The caller must publish it before fragments and retain source custody.
    pub fn initialization(&self) -> Option<&InitializationSegment> {
        self.mux.as_ref().map(Muxer::initialization)
    }

    /// Derive an A/V initialization for the observed video configuration and
    /// caller-supplied AAC configuration. The caller remains responsible for
    /// binding that audio configuration and clock to this connection and epoch.
    /// The returned bytes have a distinct digest from the video-only
    /// initialization in [`ConfigurationBinding`]; the caller must bind and
    /// retain the new initialization separately.
    pub fn av_initialization(
        &self,
        audio: &fss_packet::extended_flv::aac::Configuration<'_>,
    ) -> Result<Option<fss_container::flv_av::Initialization>, Mp4Error> {
        self.mux
            .as_ref()
            .map(|mux| mux.av_initialization(audio))
            .transpose()
    }

    /// Admit one original record without losing it on refusal. On an error the
    /// owner is fenced; recover its pending source with [`Self::retire`].
    pub fn push(&mut self, record: SourceRecord) -> Result<Push, Refusal> {
        if self.fenced {
            return Err(Refusal {
                reason: Error::Fenced,
                unaccepted: Some(record),
            });
        }
        if matches!(
            record.kind(),
            RecordKind::Candidate {
                provisional: true,
                ..
            }
        ) {
            return Err(self.refuse(Error::Provisional, Some(record)));
        }
        if self.mux.is_some() && self.started {
            if self.pending.len() >= self.limits.max_records
                || self
                    .source_bytes
                    .checked_add(record.bytes().len())
                    .is_none_or(|n| n > self.limits.max_source_bytes)
            {
                return Err(self.refuse(Error::Limit, Some(record)));
            }
            if self.pending.try_reserve(1).is_err() {
                return Err(self.refuse(Error::Allocation, Some(record)));
            }
        }
        let observation = match self.track.observe(&record) {
            Ok(value) => value,
            Err(error) => return Err(self.refuse(Error::Track(error), Some(record))),
        };
        match observation {
            Observation::Header => Ok(Push::Source {
                record,
                disposition: SourceDisposition::Header,
            }),
            Observation::Configuration { .. } => {
                if self.mux.is_some() {
                    return Err(self.refuse(Error::ConfigurationChange, Some(record)));
                }
                match Muxer::new(self.key, &record, self.limits.mp4) {
                    Ok(mux) => {
                        self.configuration = Some(ConfigurationBinding {
                            source_offset: record.offset(),
                            source_bytes: record.bytes().len(),
                            source_digest: ContentDigest::sha256(record.bytes()),
                            initialization_digest: ContentDigest::sha256(
                                mux.initialization().bytes(),
                            ),
                        });
                        self.mux = Some(mux);
                    }
                    Err(error) => return Err(self.refuse(Error::Mux(error), Some(record))),
                }
                Ok(Push::Source {
                    record,
                    disposition: SourceDisposition::Configuration,
                })
            }
            Observation::UnconfiguredSample { .. } => {
                Err(self.refuse(Error::MissingConfiguration, Some(record)))
            }
            Observation::EndOfSequence => {
                Err(self.refuse(Error::ConfigurationChange, Some(record)))
            }
            Observation::Other if self.mux.is_none() => Ok(Push::Source {
                record,
                disposition: SourceDisposition::PreRoll,
            }),
            Observation::Other if !self.started => self.pre_roll(record),
            Observation::Other => self.buffer(record, None),
            Observation::Sample {
                timestamp_ms,
                contains_idr_nal_type,
                ..
            } => {
                let time = match self.unwrap_time(timestamp_ms) {
                    Ok(time) => time,
                    Err(reason) => return Err(self.refuse(reason, Some(record))),
                };
                if !self.started && !contains_idr_nal_type {
                    let result = self.pre_roll(record);
                    if result.is_ok() {
                        self.last_video_time = Some((timestamp_ms, time));
                    }
                    return result;
                }
                if self.videos.len() >= self.limits.mp4.max_samples + 1 {
                    return Err(self.refuse(Error::Limit, Some(record)));
                }
                if self.videos.try_reserve(1).is_err() {
                    return Err(self.refuse(Error::Allocation, Some(record)));
                }
                if !self.started {
                    if record.bytes().len() > self.limits.max_source_bytes {
                        return Err(self.refuse(Error::Limit, Some(record)));
                    }
                    if self.pending.try_reserve(1).is_err() {
                        return Err(self.refuse(Error::Allocation, Some(record)));
                    }
                    self.started = true;
                }
                self.last_video_time = Some((timestamp_ms, time));
                let result = self.buffer(record, Some(time));
                if contains_idr_nal_type && self.videos.len() > 1 {
                    if result.is_err() {
                        return result;
                    }
                    self.segment()
                } else {
                    result
                }
            }
        }
    }

    fn refuse(&mut self, reason: Error, unaccepted: Option<SourceRecord>) -> Refusal {
        self.fenced = true;
        Refusal { reason, unaccepted }
    }

    fn pre_roll(&mut self, record: SourceRecord) -> Result<Push, Refusal> {
        let result = self
            .mux
            .as_mut()
            .ok_or(Error::MissingConfiguration)
            .and_then(|mux| mux.advance_pre_roll(&[&record]).map_err(Error::Mux));
        match result {
            Ok(_) => Ok(Push::Source {
                record,
                disposition: SourceDisposition::PreRoll,
            }),
            Err(reason) => Err(self.refuse(reason, Some(record))),
        }
    }

    fn unwrap_time(&self, raw: u32) -> Result<u64, Error> {
        match self.last_video_time {
            None => Ok(u64::from(raw)),
            Some((previous, elapsed)) => {
                let delta = raw.wrapping_sub(previous);
                if delta == 0 || delta > self.limits.max_frame_interval_ms {
                    return Err(Error::Timeline);
                }
                elapsed.checked_add(u64::from(delta)).ok_or(Error::Timeline)
            }
        }
    }

    fn buffer(&mut self, record: SourceRecord, time: Option<u64>) -> Result<Push, Refusal> {
        let Some(total) = self.source_bytes.checked_add(record.bytes().len()) else {
            return Err(self.refuse(Error::Limit, Some(record)));
        };
        if self.pending.len() >= self.limits.max_records || total > self.limits.max_source_bytes {
            return Err(self.refuse(Error::Limit, Some(record)));
        }
        let index = self.pending.len();
        self.pending.push(record);
        self.source_bytes = total;
        if let Some(time_ms) = time {
            self.videos.push(Video { index, time_ms });
        }
        Ok(Push::Buffered)
    }

    fn segment(&mut self) -> Result<Push, Refusal> {
        let result = self.build_segment();
        match result {
            Ok(segment) => Ok(Push::Segment(segment)),
            Err(reason) => Err(self.refuse(reason, None)),
        }
    }

    fn build_segment(&mut self) -> Result<Segment, Error> {
        let configuration = self.configuration.ok_or(Error::MissingConfiguration)?;
        let count = self
            .videos
            .len()
            .checked_sub(1)
            .ok_or(Error::Configuration)?;
        if count == 0 || count > self.limits.mp4.max_samples {
            return Err(Error::Limit);
        }
        let cut = self.videos[count - 1]
            .index
            .checked_add(1)
            .ok_or(Error::Limit)?;
        let mut source = Vec::new();
        source
            .try_reserve_exact(cut)
            .map_err(|_| Error::Allocation)?;
        let suffix = self.pending.get(cut..).ok_or(Error::Configuration)?;
        let witness_bytes = suffix
            .iter()
            .try_fold(0_usize, |sum, record| sum.checked_add(record.bytes().len()))
            .ok_or(Error::Limit)?;
        if witness_bytes > self.limits.max_witness_bytes {
            return Err(Error::Limit);
        }
        let mut lookahead_copies = Vec::new();
        lookahead_copies
            .try_reserve_exact(suffix.len())
            .map_err(|_| Error::Allocation)?;
        for record in suffix {
            lookahead_copies.push(record.try_duplicate().map_err(|_| Error::Allocation)?);
        }
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for pair in self.videos.windows(2) {
            let duration = pair[1]
                .time_ms
                .checked_sub(pair[0].time_ms)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(Error::Timeline)?;
            samples.push(TimedSample {
                record: self
                    .pending
                    .get(pair[0].index)
                    .ok_or(Error::Configuration)?,
                decode_time_ms: pair[0].time_ms,
                duration_ms: duration,
            });
        }
        let mut coverage = Vec::new();
        coverage
            .try_reserve_exact(self.pending.len())
            .map_err(|_| Error::Allocation)?;
        coverage.extend(self.pending.iter());
        let lookahead = self
            .pending
            .get(self.videos[count].index)
            .ok_or(Error::Configuration)?;
        let fragment = self
            .mux
            .as_mut()
            .ok_or(Error::MissingConfiguration)?
            .fragment(&samples, lookahead, &coverage)
            .map_err(Error::Mux)?;
        source.extend(self.pending.drain(..cut));
        for record in &source {
            self.source_bytes -= record.bytes().len();
        }
        self.videos.drain(..count);
        for video in &mut self.videos {
            video.index -= cut;
        }
        Ok(Segment {
            fragment,
            source,
            lookahead_copies,
            configuration,
        })
    }

    /// Return every source record still held; an incomplete final GOP remains
    /// pending and is never turned into a fabricated finished fragment.
    pub fn retire(self) -> Retirement {
        Retirement {
            pending: self.pending,
            source_bytes: self.source_bytes,
            fenced: self.fenced,
        }
    }
}
