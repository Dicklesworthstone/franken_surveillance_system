#![forbid(unsafe_code)]
//! Connection-relative AAC configuration epochs and original-source spans.
//!
//! The caller feeds every record in order and binds this track to one owned
//! connection and generation. A structurally matching FLV boundary remains a
//! candidate. This track performs no decoding, I/O, capture-time inference,
//! sender authentication, audio output, or source persistence.

use std::{fmt, ops::Range};

use super::{
    Limits as FlvLimits, Parse, Tag, aac,
    stream::{RecordKind, SourceRecord},
};

/// Source-relative, half-open byte range within this connection.
pub type SourceSpan = Range<u64>;

/// One bounded interpretation of an original source record.
#[derive(Debug, Eq, PartialEq)]
pub enum Observation {
    /// The connection's original FLV header was consumed.
    Header,
    /// A record other than standard audio type 8 or vendor audio type 10.
    Other,
    /// One supported AAC-LC configuration and its source-relative span.
    Configuration {
        /// Monotonic connection-local configuration epoch, starting at one.
        epoch: u64,
        /// Whether the enclosing source boundary is provisional.
        provisional: bool,
        /// Original tag, including FLV framing.
        tag: SourceSpan,
        /// Exact source AudioSpecificConfig bytes.
        configuration: SourceSpan,
        /// Sample rate declared by the configuration.
        sample_rate: u32,
        /// Channel count represented by the supported configuration.
        channels: u8,
        /// Samples per configured AAC-LC frame, not a raw-tag duration proof.
        frame_samples: u16,
    },
    /// One raw AAC body tied to a previously observed configuration epoch.
    Sample {
        /// Connection-local epoch; this is not independent camera identity.
        epoch: u64,
        /// Whether this tag or its configuration boundary is provisional.
        provisional: bool,
        /// Wrapping sender-provided FLV milliseconds.
        timestamp_ms: u32,
        /// Original tag, including FLV framing.
        tag: SourceSpan,
        /// Original compressed AAC body, without the FLV audio header.
        body: SourceSpan,
    },
    /// A raw audio body appeared before an observed configuration.
    UnconfiguredSample {
        /// Whether the enclosing source boundary is provisional.
        provisional: bool,
        /// Wrapping sender-provided FLV milliseconds.
        timestamp_ms: u32,
        /// Original tag, including FLV framing.
        tag: SourceSpan,
        /// Original compressed body; this does not prove it is decodable.
        body: SourceSpan,
    },
}

/// AAC configuration borrowed from one exact original source record.
/// This binds bytes and the track's claimed epoch to that record; the caller
/// still binds the track to its connection, identity and retained source.
pub struct BoundConfiguration<'a> {
    record: &'a SourceRecord,
    configuration: aac::Configuration<'a>,
    epoch: u64,
    provisional: bool,
    source: SourceSpan,
}
impl<'a> BoundConfiguration<'a> {
    /// The original immutable record containing the configuration.
    pub fn record(&self) -> &'a SourceRecord {
        self.record
    }
    /// Parsed configuration borrowing bytes from that original record.
    pub fn configuration(&self) -> &aac::Configuration<'a> {
        &self.configuration
    }
    /// Track-local epoch claimed by the observation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Whether the enclosing source boundary was marked provisional.
    pub fn provisional(&self) -> bool {
        self.provisional
    }
    /// Exact connection-relative configuration byte range.
    pub fn source(&self) -> SourceSpan {
        self.source.clone()
    }
}

impl Observation {
    /// Rebind a configuration observation to the exact source record that
    /// produced it. Other observations, mismatched records or inconsistent
    /// spans and format claims are refused; no source is consumed.
    ///
    /// Observations are caller-visible values, so this method does not prove
    /// that the claimed epoch came from a particular `Track` instance.
    pub fn bind_configuration<'a>(
        &self,
        record: &'a SourceRecord,
        flv_limits: FlvLimits,
        aac_limits: aac::Limits,
    ) -> Result<BoundConfiguration<'a>, Error> {
        let Self::Configuration {
            epoch,
            provisional,
            tag: expected_tag,
            configuration: expected_configuration,
            sample_rate,
            channels,
            frame_samples,
        } = self
        else {
            return Err(Error::BindingMismatch);
        };
        let range = record.tag_range().ok_or(Error::BindingMismatch)?;
        let bytes = record
            .bytes()
            .get(range.clone())
            .ok_or(Error::BindingMismatch)?;
        let Parse::Complete(tag) =
            Tag::parse(bytes, flv_limits).map_err(|_| Error::BindingMismatch)?
        else {
            return Err(Error::BindingMismatch);
        };
        if tag.wire_bytes().len() != bytes.len() {
            return Err(Error::BindingMismatch);
        }
        let audio = aac::AudioTag::parse(tag, aac_limits).map_err(|_| Error::BindingMismatch)?;
        let configuration = audio.configuration().map_err(|_| Error::BindingMismatch)?;
        let tag_start = record
            .offset()
            .checked_add(u64::try_from(range.start).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let tag_end = record
            .offset()
            .checked_add(u64::try_from(record.bytes().len()).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let source = absolute(tag_start, audio.body_range())?;
        let source_provisional = matches!(
            record.kind(),
            RecordKind::Candidate {
                provisional: true,
                ..
            }
        );
        if *epoch == 0
            || *expected_tag != (tag_start..tag_end)
            || *expected_configuration != source
            || *provisional != source_provisional
            || *sample_rate != configuration.sample_rate()
            || *channels != configuration.channels()
            || *frame_samples != configuration.frame_samples()
        {
            return Err(Error::BindingMismatch);
        }
        Ok(BoundConfiguration {
            record,
            configuration,
            epoch: *epoch,
            provisional: *provisional,
            source,
        })
    }
}

/// Payload-free refusal. The caller retains the original record on failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The track was fenced by an earlier failure.
    Fenced,
    /// A header was missing, duplicated, or an input record was out of order.
    Discontinuity,
    /// An offset or configuration epoch could not be represented.
    Overflow,
    /// A source record was not exactly one structurally valid tag.
    InvalidRecord,
    /// AAC framing or a bounded configuration profile was refused.
    Aac(aac::Error),
    /// Vendor audio type 10 requires a different codec profile.
    UnsupportedAudioKind,
    /// A configuration observation does not describe the supplied source record.
    BindingMismatch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV AAC track refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
struct Current {
    epoch: u64,
    provisional: bool,
}

/// A strictly ordered source track for one caller-bound connection.
pub struct Track {
    flv_limits: FlvLimits,
    aac_limits: aac::Limits,
    next_offset: u64,
    seen_header: bool,
    fenced: bool,
    epoch: u64,
    current: Option<Current>,
}
impl fmt::Debug for Track {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Track")
            .field("next_offset", &self.next_offset)
            .field("fenced", &self.fenced)
            .field("epoch", &self.epoch)
            .field("configured", &self.current.is_some())
            .finish()
    }
}
impl Track {
    /// Start at offset zero of one caller-bound source connection.
    pub fn new(flv_limits: FlvLimits, aac_limits: aac::Limits) -> Self {
        Self {
            flv_limits,
            aac_limits,
            next_offset: 0,
            seen_header: false,
            fenced: false,
            epoch: 0,
            current: None,
        }
    }

    /// Observe every original source record in order without taking its bytes.
    /// A refusal fences this audio track; the caller retains the record.
    pub fn observe(&mut self, record: &SourceRecord) -> Result<Observation, Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        let result = self.observe_inner(record);
        if result.is_err() {
            self.fenced = true;
            self.current = None;
        }
        result
    }

    fn observe_inner(&mut self, record: &SourceRecord) -> Result<Observation, Error> {
        if record.offset() != self.next_offset {
            return Err(Error::Discontinuity);
        }
        let end = record
            .offset()
            .checked_add(u64::try_from(record.bytes().len()).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        if matches!(record.kind(), RecordKind::Header) {
            if self.seen_header {
                return Err(Error::Discontinuity);
            }
            self.seen_header = true;
            self.next_offset = end;
            return Ok(Observation::Header);
        }
        if !self.seen_header {
            return Err(Error::Discontinuity);
        }
        let range = record.tag_range().ok_or(Error::InvalidRecord)?;
        let bytes = record
            .bytes()
            .get(range.clone())
            .ok_or(Error::InvalidRecord)?;
        let Parse::Complete(tag) =
            Tag::parse(bytes, self.flv_limits).map_err(|_| Error::InvalidRecord)?
        else {
            return Err(Error::InvalidRecord);
        };
        if tag.wire_bytes().len() != bytes.len() {
            return Err(Error::InvalidRecord);
        }
        let start = record
            .offset()
            .checked_add(u64::try_from(range.start).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let provisional = matches!(
            record.kind(),
            RecordKind::Candidate {
                provisional: true,
                ..
            }
        );
        if tag.kind() == 10 {
            return Err(Error::UnsupportedAudioKind);
        }
        let output = if tag.kind() != 8 {
            Observation::Other
        } else {
            let audio = aac::AudioTag::parse(tag, self.aac_limits).map_err(Error::Aac)?;
            let body = absolute(start, audio.body_range())?;
            match audio.packet_type() {
                aac::PacketType::Configuration => {
                    let config = audio.configuration().map_err(Error::Aac)?;
                    let epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
                    self.current = Some(Current { epoch, provisional });
                    self.epoch = epoch;
                    Observation::Configuration {
                        epoch,
                        provisional,
                        tag: start..end,
                        configuration: body,
                        sample_rate: config.sample_rate(),
                        channels: config.channels(),
                        frame_samples: config.frame_samples(),
                    }
                }
                aac::PacketType::Raw => match self.current {
                    Some(config) => Observation::Sample {
                        epoch: config.epoch,
                        provisional: provisional || config.provisional,
                        timestamp_ms: audio.timestamp_ms(),
                        tag: start..end,
                        body,
                    },
                    None => Observation::UnconfiguredSample {
                        provisional,
                        timestamp_ms: audio.timestamp_ms(),
                        tag: start..end,
                        body,
                    },
                },
            }
        };
        self.next_offset = end;
        Ok(output)
    }
}

fn absolute(base: u64, relative: Range<usize>) -> Result<SourceSpan, Error> {
    let start = base
        .checked_add(u64::try_from(relative.start).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    let end = base
        .checked_add(u64::try_from(relative.end).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    Ok(start..end)
}
