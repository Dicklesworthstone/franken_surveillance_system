#![forbid(unsafe_code)]
//! Bounded borrowed AMF0 script-data claims from structural FLV tags.
//!
//! This limited profile extracts only an event name and an optional top-level
//! `streamName` string. Neither value authenticates a camera, connection or
//! requested stream. A structural tag boundary can itself be provisional.
//! Unknown AMF types fail closed; callers must retain the original source and
//! decide how to handle unsupported or absent metadata.
//!
//! AMF0 value framing follows Adobe's AMF0 specification:
//! <https://rtmp.veriskope.com/pdf/amf0-file-format-specification.pdf>.

use super::{
    Limits, Parse, Tag,
    stream::{RecordKind, SourceRecord},
};
use std::fmt;

const MAX_PAYLOAD: usize = 256 * 1024;
const MAX_STRING: usize = 16 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 8;

/// Payload-free refusal for this deliberately restricted AMF0 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The tag is not FLV script data.
    NotScript,
    /// The payload or a declared string, array, or nesting level exceeds a bound.
    Limit,
    /// An encoded value is incomplete.
    Truncated,
    /// The payload is structurally invalid or contains trailing values.
    Invalid,
    /// An AMF0 value is outside this profile; no claim is returned.
    Unsupported,
    /// Event, key, or stream-name text is not UTF-8.
    InvalidUtf8,
    /// More than one top-level `streamName` was supplied.
    DuplicateStreamName,
    /// The top-level `streamName` was not a nonempty short string.
    InvalidStreamName,
    /// A record's tag framing did not match its retained source range.
    InvalidRecord,
    /// A previous ambiguous boundary makes this record provisional.
    Provisional,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV metadata refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Untrusted values borrowed from a single fully parsed script-data tag.
/// Debug output intentionally omits both strings and the source payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Claim<'a> {
    event: &'a str,
    stream_name: Option<&'a str>,
}
impl fmt::Debug for Claim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Claim")
            .field("has_stream_name", &self.stream_name.is_some())
            .finish_non_exhaustive()
    }
}
impl<'a> Claim<'a> {
    /// Claimed event name; it is camera-controlled and not authenticated.
    pub const fn event(self) -> &'a str {
        self.event
    }
    /// Optional top-level stream-name claim, not proof of a binding.
    pub const fn stream_name(self) -> Option<&'a str> {
        self.stream_name
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    values: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Limit)?;
        let bytes = self.bytes.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> Result<&'a str, Error> {
        let bytes = self.take(2)?;
        let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if len > MAX_STRING {
            return Err(Error::Limit);
        }
        std::str::from_utf8(self.take(len)?).map_err(|_| Error::InvalidUtf8)
    }
    fn long_len(&mut self) -> Result<usize, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    }
    fn charge(&mut self, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH || self.values == MAX_FIELDS {
            return Err(Error::Limit);
        }
        self.values += 1;
        Ok(())
    }
    fn object(&mut self, depth: usize, extract: bool) -> Result<Option<&'a str>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit);
        }
        let mut stream_name = None;
        loop {
            let key = self.short()?;
            let marker = self.byte()?;
            if key.is_empty() && marker == 9 {
                return Ok(stream_name);
            }
            if extract && key == "streamName" {
                if stream_name.is_some() {
                    return Err(Error::DuplicateStreamName);
                }
                self.charge(depth)?;
                if marker != 2 {
                    return Err(Error::InvalidStreamName);
                }
                let value = self.short()?;
                if value.is_empty() {
                    return Err(Error::InvalidStreamName);
                }
                stream_name = Some(value);
            } else {
                self.value(marker, depth)?;
            }
        }
    }
    fn value(&mut self, marker: u8, depth: usize) -> Result<(), Error> {
        self.charge(depth)?;
        match marker {
            0 => {
                self.take(8)?;
            }
            1 => {
                if self.byte()? > 1 {
                    return Err(Error::Invalid);
                }
            }
            2 => {
                self.short()?;
            }
            3 => {
                self.object(depth + 1, false)?;
            }
            5 | 6 => (),
            8 => {
                let declared = self.long_len()?;
                if declared > MAX_FIELDS {
                    return Err(Error::Limit);
                }
                self.object(depth + 1, false)?;
            }
            10 => {
                let count = self.long_len()?;
                if count > MAX_FIELDS {
                    return Err(Error::Limit);
                }
                for _ in 0..count {
                    let item = self.byte()?;
                    self.value(item, depth + 1)?;
                }
            }
            11 => {
                self.take(10)?;
            }
            12 => {
                let length = self.long_len()?;
                if length > MAX_STRING {
                    return Err(Error::Limit);
                }
                std::str::from_utf8(self.take(length)?).map_err(|_| Error::InvalidUtf8)?;
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
}

/// Interpret an AMF0 event string followed by an object or ECMA array.
/// `@setDataFrame` framing is accepted when followed by an event string.
/// Nested `streamName` fields do not qualify. Entire payload validation is
/// required before returning a borrowed claim; unsupported types do not fall
/// back to a partial result. This function never establishes source identity.
pub fn parse(tag: Tag<'_>) -> Result<Claim<'_>, Error> {
    if tag.kind() != 18 {
        return Err(Error::NotScript);
    }
    let bytes = tag.payload();
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Limit);
    }
    let mut cursor = Cursor {
        bytes,
        pos: 0,
        values: 0,
    };
    if cursor.byte()? != 2 {
        return Err(Error::Unsupported);
    }
    let mut event = cursor.short()?;
    if event == "@setDataFrame" {
        if cursor.byte()? != 2 {
            return Err(Error::Invalid);
        }
        event = cursor.short()?;
    }
    if event.is_empty() {
        return Err(Error::Invalid);
    }
    let stream_name = match cursor.byte()? {
        3 => cursor.object(1, true)?,
        8 => {
            if cursor.long_len()? > MAX_FIELDS {
                return Err(Error::Limit);
            }
            cursor.object(1, true)?
        }
        _ => return Err(Error::Unsupported),
    };
    if cursor.pos != bytes.len() {
        return Err(Error::Invalid);
    }
    Ok(Claim { event, stream_name })
}

/// Interpret a retained source record without transferring or copying it.
/// The caller still owns its original bytes and must account for them. A
/// provisional candidate is refused; a nonprovisional candidate remains only
/// a structural boundary, not an authenticated or proven camera message.
pub fn parse_record(record: &SourceRecord) -> Result<Claim<'_>, Error> {
    match record.kind() {
        RecordKind::FirstTag { tag_kind: 18, .. } => (),
        RecordKind::Candidate {
            tag_kind: 18,
            provisional: true,
            ..
        }
        | RecordKind::Candidate {
            tag_kind: 18,
            earlier_incomplete: true,
            ..
        } => {
            return Err(Error::Provisional);
        }
        RecordKind::Candidate { tag_kind: 18, .. } => (),
        _ => return Err(Error::NotScript),
    }
    let range = record.tag_range().ok_or(Error::InvalidRecord)?;
    let bytes = record.bytes().get(range).ok_or(Error::InvalidRecord)?;
    let tag = match Tag::parse(bytes, Limits::default()).map_err(|_| Error::InvalidRecord)? {
        Parse::Complete(tag) if tag.wire_bytes().len() == bytes.len() => tag,
        _ => return Err(Error::InvalidRecord),
    };
    parse(tag)
}
