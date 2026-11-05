#![forbid(unsafe_code)]
//! Bounded AVC interpretation of sequential original extended-FLV records.
//!
//! This is a source-span bridge, not a decoder, custody owner or MP4 muxer.
//! The caller retains every original record and binds this track to exactly one
//! connection and stream generation. Provisional framing propagates to every
//! dependent configuration and sample. A refusal fences the entire track.

use std::{fmt, ops::Range};

use super::{
    Limits as FlvLimits, Parse, Tag, avc,
    stream::{RecordKind, SourceRecord},
};

/// A source-relative, half-open range within the current TCP connection.
pub type SourceSpan = Range<u64>;

/// Source-preserving interpretation of one complete record.
#[derive(Debug, Eq, PartialEq)]
pub enum Observation {
    /// The FLV stream header was accepted structurally.
    Header,
    /// An audio, metadata, or other non-video record was left uninterpreted.
    Other,
    /// A new AVC configuration epoch, with exact SPS and PPS source spans.
    Configuration {
        /// Monotonically increasing connection-local epoch, beginning at one.
        epoch: u64,
        /// Whether this configuration depends on a provisional boundary.
        provisional: bool,
        /// Complete source tag span, including its FLV framing.
        tag: SourceSpan,
        /// Original SPS and PPS byte ranges, excluding their length fields.
        parameter_sets: Vec<SourceSpan>,
    },
    /// A length-framed sample linked to one exact configuration epoch.
    Sample {
        /// The configuration epoch used to parse its NAL lengths.
        epoch: u64,
        /// Whether this sample or its configuration is provisional.
        provisional: bool,
        /// Wrapping camera-provided media time, not a receive or UTC time.
        timestamp_ms: u32,
        /// Signed presentation-minus-decode offset supplied by the camera.
        composition_offset_ms: i32,
        /// Camera-provided frame type; not a decodability or keyframe proof.
        frame_type: u8,
        /// Whether a NAL header has type 5, not a complete-picture proof.
        contains_idr_nal_type: bool,
        /// Original NAL bytes in order, excluding their length fields.
        nals: Vec<SourceSpan>,
    },
    /// A sample arrived before a configuration; its NAL framing is unknown.
    UnconfiguredSample {
        /// Whether the enclosing tag boundary is provisional.
        provisional: bool,
        /// Wrapping camera-provided media timestamp.
        timestamp_ms: u32,
    },
    /// AVC end-of-sequence; the preceding configuration is no longer usable.
    EndOfSequence,
}

/// Payload-free refusal. The caller retains the original record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The track was already fenced by an earlier refusal.
    Fenced,
    /// A header was missing, duplicated, or a record was out of order.
    Discontinuity,
    /// A source offset or configuration epoch overflowed.
    Overflow,
    /// The record did not contain exactly one valid structural tag.
    InvalidRecord,
    /// AVC framing or configured limits rejected this video tag.
    Avc(avc::Error),
    /// A bounded allocation could not be completed.
    Allocation,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV AVC track refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Configuration {
    tag: Vec<u8>,
    epoch: u64,
    provisional: bool,
}

/// One strictly ordered, bounded source track. It performs no I/O.
pub struct Track {
    flv_limits: FlvLimits,
    avc_limits: avc::Limits,
    next_offset: u64,
    seen_header: bool,
    fenced: bool,
    epoch: u64,
    configuration: Option<Configuration>,
}
impl fmt::Debug for Track {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Track")
            .field("next_offset", &self.next_offset)
            .field("fenced", &self.fenced)
            .field("epoch", &self.epoch)
            .field("configured", &self.configuration.is_some())
            .finish()
    }
}

impl Track {
    /// Start at the FLV header of one connection; no identity is inferred.
    pub fn new(flv_limits: FlvLimits, avc_limits: avc::Limits) -> Self {
        Self {
            flv_limits,
            avc_limits,
            next_offset: 0,
            seen_header: false,
            fenced: false,
            epoch: 0,
            configuration: None,
        }
    }

    /// Interpret one exact original record without taking or modifying it.
    /// A refusal fences the track; the caller must retain and reconcile source.
    pub fn observe(&mut self, record: &SourceRecord) -> Result<Observation, Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        let result = self.observe_inner(record);
        if result.is_err() {
            self.fenced = true;
            self.configuration = None;
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
        let tag_start = record
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
        let result = if tag.kind() != 9 {
            Observation::Other
        } else {
            let video = avc::VideoTag::parse(tag).map_err(Error::Avc)?;
            match video.packet_type() {
                avc::PacketType::Configuration => {
                    let parsed = video.configuration(self.avc_limits).map_err(Error::Avc)?;
                    let mut parameter_sets = Vec::new();
                    let count = parsed
                        .sps()
                        .len()
                        .checked_add(parsed.pps().len())
                        .ok_or(Error::Overflow)?;
                    parameter_sets
                        .try_reserve_exact(count)
                        .map_err(|_| Error::Allocation)?;
                    for nal in parsed.sps().chain(parsed.pps()) {
                        parameter_sets.push(absolute(tag_start, nal.range())?);
                    }
                    let epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
                    let mut copy = Vec::new();
                    copy.try_reserve_exact(bytes.len())
                        .map_err(|_| Error::Allocation)?;
                    copy.extend_from_slice(bytes);
                    self.configuration = Some(Configuration {
                        tag: copy,
                        epoch,
                        provisional,
                    });
                    self.epoch = epoch;
                    Observation::Configuration {
                        epoch,
                        provisional,
                        tag: tag_start..end,
                        parameter_sets,
                    }
                }
                avc::PacketType::NalUnits => match &self.configuration {
                    None => Observation::UnconfiguredSample {
                        provisional,
                        timestamp_ms: video.timestamp_ms(),
                    },
                    Some(config) => {
                        let Parse::Complete(config_tag) = Tag::parse(&config.tag, self.flv_limits)
                            .map_err(|_| Error::InvalidRecord)?
                        else {
                            return Err(Error::InvalidRecord);
                        };
                        let config_video = avc::VideoTag::parse(config_tag).map_err(Error::Avc)?;
                        let parsed_config = config_video
                            .configuration(self.avc_limits)
                            .map_err(Error::Avc)?;
                        let units = video
                            .nal_units(&parsed_config, self.avc_limits)
                            .map_err(Error::Avc)?;
                        let mut nals = Vec::new();
                        nals.try_reserve_exact(units.len())
                            .map_err(|_| Error::Allocation)?;
                        for nal in units.iter() {
                            nals.push(absolute(tag_start, nal.range())?);
                        }
                        Observation::Sample {
                            epoch: config.epoch,
                            provisional: provisional || config.provisional,
                            timestamp_ms: video.timestamp_ms(),
                            composition_offset_ms: video.composition_offset_ms(),
                            frame_type: video.frame_type(),
                            contains_idr_nal_type: units.contains_idr_nal_type(),
                            nals,
                        }
                    }
                },
                avc::PacketType::EndOfSequence => {
                    self.configuration = None;
                    Observation::EndOfSequence
                }
            }
        };
        self.next_offset = end;
        Ok(result)
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
