#![forbid(unsafe_code)]
//! Bounded ADTS framing for an explicitly supplied AAC-LC configuration.
//!
//! This only writes a seven-byte header; it does not copy, decode, play or
//! validate the compressed body. The caller must establish that the supplied
//! configuration belongs to the sample's source connection and epoch. In
//! particular, a relay's configuration does not authenticate a camera capture.
//! The header profile and limits were checked against FFmpeg's ADTS writer:
//! <https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/adtsenc.c>.

use std::{fmt, ops::Range};

use super::{
    Limits as FlvLimits, Parse, Tag,
    aac::{self, AudioTag, Configuration, PacketType},
    stream::{RecordKind, SourceRecord},
};

const HEADER_BYTES: usize = 7;
const MAX_FRAME_BYTES: usize = 8191;

/// Payload-free refusal to represent a configuration and raw tag in ADTS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Only a raw access-unit tag can be framed.
    NotRaw,
    /// The short AAC frame mode is not representable by this ADTS profile.
    ShortFrame,
    /// The header and body exceed ADTS's 13-bit frame-size field.
    FrameTooLarge,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AAC ADTS framing refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Construct one MPEG-4 AAC-LC ADTS header without copying the source sample.
///
/// The caller must concatenate this header with the exact [`AudioTag::body`]
/// from `sample` and retain the source separately. A successful result is a
/// framing operation, not proof of a valid access unit, configuration binding,
/// sender identity, continuity, persistence, or decodability.
pub fn header(config: &Configuration<'_>, sample: AudioTag<'_>) -> Result<[u8; 7], Error> {
    if sample.packet_type() != PacketType::Raw {
        return Err(Error::NotRaw);
    }
    if config.frame_samples() != 1024 {
        return Err(Error::ShortFrame);
    }
    let frame_len = sample
        .body()
        .len()
        .checked_add(HEADER_BYTES)
        .filter(|&n| n <= MAX_FRAME_BYTES)
        .ok_or(Error::FrameTooLarge)?;
    let cfg = config.bytes();
    let rate_index = (cfg[0] & 7) << 1 | cfg[1] >> 7;
    let channel = config.channel_configuration();
    Ok([
        0xff,
        0xf1,
        (1 << 6) | (rate_index << 2) | (channel >> 2),
        (channel & 3) << 6 | ((frame_len >> 11) as u8),
        (frame_len >> 3) as u8,
        ((frame_len & 7) as u8) << 5 | 0x1f,
        0xfc,
    ])
}

/// A frame borrowing its compressed bytes from one retained source record.
/// Its ADTS header is derived; the body range refers to the original connection.
/// This value does not claim persistence, valid AAC, or a verified binding
/// between its explicitly supplied configuration and the source epoch.
pub struct SourceFrame<'a> {
    header: [u8; HEADER_BYTES],
    body: &'a [u8],
    body_range: Range<u64>,
    timestamp_ms: u32,
    provisional: bool,
}
impl fmt::Debug for SourceFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFrame")
            .field("body_range", &self.body_range)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("provisional", &self.provisional)
            .finish_non_exhaustive()
    }
}
impl<'a> SourceFrame<'a> {
    /// Derived seven-byte ADTS header, not part of the original source.
    pub fn header(&self) -> &[u8; HEADER_BYTES] {
        &self.header
    }
    /// Borrowed compressed bytes; the original record remains caller-owned.
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
    /// Body range relative to the beginning of the original connection.
    pub fn body_range(&self) -> Range<u64> {
        self.body_range.clone()
    }
    /// Wrapping sender-supplied FLV milliseconds, not authenticated capture time.
    pub fn timestamp_ms(&self) -> u32 {
        self.timestamp_ms
    }
    /// Whether the framing owner marked this source boundary provisional.
    pub fn provisional(&self) -> bool {
        self.provisional
    }
}

/// Payload-free refusal while deriving a frame from an original source record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// The source record did not contain exactly one structurally valid tag.
    InvalidRecord,
    /// A source-relative offset could not be represented.
    Overflow,
    /// Vendor type 10 requires an independently supported audio format.
    UnsupportedAudioKind,
    /// An in-stream configuration appeared; the owner must handle its epoch.
    ConfigurationObserved,
    /// AAC parsing failed.
    Aac(aac::Error),
    /// The supported ADTS profile refused this frame.
    Adts(Error),
}
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AAC source frame refusal: {self:?}")
    }
}
impl std::error::Error for SourceError {}

/// Derive a borrowed ADTS frame from one original FLV record, or return `None`
/// for a header or non-audio tag. An audio configuration tag is an explicit
/// refusal rather than being silently skipped: the caller must process changes
/// in order and bind `config` to this record's connection and epoch. This
/// stateless helper does not check ordering, timestamps, identity or continuity.
pub fn source_frame<'a>(
    config: &Configuration<'_>,
    record: &'a SourceRecord,
    flv_limits: FlvLimits,
    aac_limits: aac::Limits,
) -> Result<Option<SourceFrame<'a>>, SourceError> {
    let Some(range) = record.tag_range() else {
        return Ok(None);
    };
    let bytes = record
        .bytes()
        .get(range.clone())
        .ok_or(SourceError::InvalidRecord)?;
    let Parse::Complete(tag) =
        Tag::parse(bytes, flv_limits).map_err(|_| SourceError::InvalidRecord)?
    else {
        return Err(SourceError::InvalidRecord);
    };
    if tag.wire_bytes().len() != bytes.len() {
        return Err(SourceError::InvalidRecord);
    }
    if tag.kind() == 10 {
        return Err(SourceError::UnsupportedAudioKind);
    }
    if tag.kind() != 8 {
        return Ok(None);
    }
    let audio = AudioTag::parse(tag, aac_limits).map_err(SourceError::Aac)?;
    if audio.packet_type() == PacketType::Configuration {
        return Err(SourceError::ConfigurationObserved);
    }
    let header = header(config, audio).map_err(SourceError::Adts)?;
    let tag_start = record
        .offset()
        .checked_add(u64::try_from(range.start).map_err(|_| SourceError::Overflow)?)
        .ok_or(SourceError::Overflow)?;
    let body = audio.body_range();
    let body_start = tag_start
        .checked_add(u64::try_from(body.start).map_err(|_| SourceError::Overflow)?)
        .ok_or(SourceError::Overflow)?;
    let body_end = tag_start
        .checked_add(u64::try_from(body.end).map_err(|_| SourceError::Overflow)?)
        .ok_or(SourceError::Overflow)?;
    Ok(Some(SourceFrame {
        header,
        body: audio.body(),
        body_range: body_start..body_end,
        timestamp_ms: audio.timestamp_ms(),
        provisional: matches!(
            record.kind(),
            RecordKind::Candidate {
                provisional: true,
                ..
            }
        ),
    }))
}
