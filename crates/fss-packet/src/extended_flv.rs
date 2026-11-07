//! Sans-I/O parsing for the experimental UniFi extended-FLV camera push.
//!
//! These functions borrow the caller's original bytes and do not authenticate a
//! camera, perform I/O, remove trailers, decode video, or establish continuity.
//! A structurally valid next tag is only a *candidate*: trailer bytes may mimic
//! a valid FLV tag. The owner must preserve that uncertainty and the source bytes.
//!
//! Reference: xuio/scrypted-unifi-direct at commit
//! `2920ce8896aadd603e2847d17554905592d155e8`, `src/direct-stream.ts`.

use std::{fmt, ops::Range};

/// Borrowed AAC-LC configuration and access-unit views over original FLV tags.
pub mod aac;
/// Allocation-free ADTS headers for explicitly configured AAC-LC samples.
pub mod aac_adts;
/// Bounded AAC sample-clock reconciliation against sender FLV timestamps.
pub mod aac_clock;
/// Connection-relative AAC configuration epochs and access-unit source spans.
pub mod aac_track;
/// Borrowed AVC configuration and NAL views over original extended-FLV tags.
pub mod avc;
/// Incremental framing that returns original bytes and stream-relative ranges.
pub mod stream;
/// Source-relative AVC configuration epochs and sample spans.
pub mod track;

const TAG_HEADER: usize = 11;
const TAG_SUFFIX: usize = 4;
const ABSOLUTE_MAX_PAYLOAD: usize = 4 * 1024 * 1024;
const ABSOLUTE_MAX_TRAILER: usize = 65_536;
const ABSOLUTE_MAX_HEADER: usize = 4096;

/// Hard bounds for one tag and the search for its successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum payload bytes in one tag, at most 4 MiB.
    pub max_payload: usize,
    /// Maximum bytes between adjacent candidate tags, at most 65536.
    pub max_trailer: usize,
    /// Maximum FLV header length before the first previous-tag-size field.
    pub max_header: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_payload: ABSOLUTE_MAX_PAYLOAD,
            max_trailer: ABSOLUTE_MAX_TRAILER,
            max_header: ABSOLUTE_MAX_HEADER,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.max_payload > ABSOLUTE_MAX_PAYLOAD
            || self.max_trailer > ABSOLUTE_MAX_TRAILER
            || !(9..=ABSOLUTE_MAX_HEADER).contains(&self.max_header)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// A bounded parse failure. Errors never contain camera-provided bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The caller requested limits above the implementation's absolute bounds.
    InvalidLimits,
    /// The FLV signature, version, header offset, or initial previous-tag size is invalid.
    InvalidHeader,
    /// The tag kind is not one of the observed audio, video, Opus, or metadata kinds.
    InvalidTagKind,
    /// The payload exceeds the configured bound.
    PayloadLimit,
    /// A complete tag's previous-tag-size back-reference does not match its length.
    PreviousTagSize,
    /// No complete candidate exists within the allowed trailer range.
    NoCandidate,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV parse refusal: {self:?}")
    }
}

impl std::error::Error for Error {}

/// A parse either needs more original bytes or yields a complete borrowed view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parse<T> {
    /// More bytes may change the result; no bytes have been consumed.
    NeedMore,
    /// One complete structural result. This does not establish authenticity.
    Complete(T),
}

/// The original, unmodified FLV header and its initial previous-tag-size field.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Header<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Header<'a> {
    /// Parse the beginning of the source stream without allocating or changing its flags.
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Parse<Self>, Error> {
        limits.validate()?;
        if bytes.len() < 9 {
            return Ok(Parse::NeedMore);
        }
        if &bytes[..3] != b"FLV" || bytes[3] != 1 {
            return Err(Error::InvalidHeader);
        }
        let offset = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        if !(9..=limits.max_header).contains(&offset) {
            return Err(Error::InvalidHeader);
        }
        let end = offset + TAG_SUFFIX;
        if bytes.len() < end {
            return Ok(Parse::NeedMore);
        }
        if bytes[offset..end] != [0, 0, 0, 0] {
            return Err(Error::InvalidHeader);
        }
        Ok(Parse::Complete(Self {
            bytes: &bytes[..end],
            offset,
        }))
    }

    /// Exact original header bytes, including the initial previous-tag-size field.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Offset of the initial previous-tag-size field within the original header.
    pub fn data_offset(self) -> usize {
        self.offset
    }

    /// Camera-provided FLV flags; these have not been normalized or verified.
    pub fn flags(self) -> u8 {
        self.bytes[4]
    }
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("bytes", &self.bytes.len())
            .field("data_offset", &self.offset)
            .finish()
    }
}

/// One structurally validated candidate tag, borrowing its exact source bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Tag<'a> {
    bytes: &'a [u8],
    payload_len: usize,
}

impl<'a> Tag<'a> {
    /// Parse a tag at the supplied offset. Acceptance is not codec or sender validation.
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Parse<Self>, Error> {
        limits.validate()?;
        if bytes.is_empty() {
            return Ok(Parse::NeedMore);
        }
        if !matches!(bytes[0], 8 | 9 | 10 | 18) {
            return Err(Error::InvalidTagKind);
        }
        if bytes.len() < TAG_HEADER {
            return Ok(Parse::NeedMore);
        }
        let len =
            (usize::from(bytes[1]) << 16) | (usize::from(bytes[2]) << 8) | usize::from(bytes[3]);
        if len > limits.max_payload {
            return Err(Error::PayloadLimit);
        }
        let end = TAG_HEADER + len;
        let total = end + TAG_SUFFIX;
        if bytes.len() < total {
            return Ok(Parse::NeedMore);
        }
        let previous =
            u32::from_be_bytes([bytes[end], bytes[end + 1], bytes[end + 2], bytes[end + 3]])
                as usize;
        if previous != end {
            return Err(Error::PreviousTagSize);
        }
        Ok(Parse::Complete(Self {
            bytes: &bytes[..total],
            payload_len: len,
        }))
    }

    /// Exact header, payload, and previous-tag-size bytes as received.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Tag type as received; type 10 is a vendor extension observed by the reference.
    pub fn kind(self) -> u8 {
        self.bytes[0]
    }

    /// Wrapping FLV media timestamp in milliseconds, not an authenticated wall-clock time.
    pub fn timestamp_ms(self) -> u32 {
        (u32::from(self.bytes[7]) << 24)
            | (u32::from(self.bytes[4]) << 16)
            | (u32::from(self.bytes[5]) << 8)
            | u32::from(self.bytes[6])
    }

    /// Payload byte range relative to [`Self::wire_bytes`].
    pub fn payload_range(self) -> Range<usize> {
        TAG_HEADER..TAG_HEADER + self.payload_len
    }

    /// Original encoded payload; no codec validity is implied.
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.payload_range()]
    }
}

impl fmt::Debug for Tag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tag")
            .field("kind", &self.kind())
            .field("timestamp_ms", &self.timestamp_ms())
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

/// Earliest structurally matching successor after one complete tag.
///
/// The bytes before `tag` are retained as a trailer, not interpreted or discarded.
/// This is a heuristic boundary and does not prove the camera intended the split.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Candidate<'a> {
    /// Original bytes skipped while searching for the candidate.
    pub trailer: &'a [u8],
    /// Candidate successor starting immediately after `trailer`.
    pub tag: Tag<'a>,
    /// An earlier plausible tag is incomplete. The chosen offset may change
    /// when more source bytes arrive, so it cannot be treated as stable.
    pub earlier_incomplete: bool,
}

impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("trailer_len", &self.trailer.len())
            .field("tag", &self.tag)
            .field("earlier_incomplete", &self.earlier_incomplete)
            .finish()
    }
}

/// Search after a complete tag for the earliest structurally matching successor.
///
/// At most `max_trailer + 1` offsets are examined. An earlier incomplete but
/// plausible candidate blocks a later complete one, preserving chunk-boundary
/// invariance. A caller should bound input retention and time out a peer that
/// intentionally keeps such a candidate incomplete. The supplied slice begins
/// immediately after the previous tag's four-byte back-reference.
pub fn find_next(bytes: &[u8], limits: Limits) -> Result<Parse<Candidate<'_>>, Error> {
    search(bytes, limits, false, false)
}

/// Find a complete candidate without waiting for earlier incomplete candidates.
///
/// This reduces latency but can choose a different offset once more bytes arrive.
/// `earlier_incomplete` records that uncertainty. Even when it is false, a
/// complete forged tag inside trailer bytes can be mistaken for a boundary.
/// This mode is suitable only for explicitly provisional derivatives; it does
/// not prove a stable source boundary, continuity or retained evidence.
pub fn find_next_provisional(bytes: &[u8], limits: Limits) -> Result<Parse<Candidate<'_>>, Error> {
    search(bytes, limits, true, false)
}

/// Search conservatively under the explicit assumption that accepted FLV tag
/// headers have a zero stream ID. A candidate whose complete header violates
/// that assumption is excluded even if its payload is incomplete. A partial
/// header remains unresolved. The caller must record the policy and cannot
/// infer device identity, source completeness, or an authentic boundary.
pub(crate) fn find_next_zero_stream_id(
    bytes: &[u8],
    limits: Limits,
) -> Result<Parse<Candidate<'_>>, Error> {
    search(bytes, limits, false, true)
}

fn search(
    bytes: &[u8],
    limits: Limits,
    provisional: bool,
    zero_stream_id: bool,
) -> Result<Parse<Candidate<'_>>, Error> {
    limits.validate()?;
    let mut pending = false;
    let count = bytes.len().min(limits.max_trailer + 1);
    for offset in 0..count {
        if zero_stream_id
            && bytes.len() - offset >= TAG_HEADER
            && bytes[offset + 8..offset + 11] != [0; 3]
        {
            continue;
        }
        match Tag::parse(&bytes[offset..], limits) {
            Ok(Parse::Complete(tag)) if !pending || provisional => {
                return Ok(Parse::Complete(Candidate {
                    trailer: &bytes[..offset],
                    tag,
                    earlier_incomplete: pending,
                }));
            }
            Ok(Parse::Complete(_)) | Ok(Parse::NeedMore) => pending = true,
            Err(Error::InvalidTagKind | Error::PayloadLimit | Error::PreviousTagSize) => {}
            Err(other) => return Err(other),
        }
    }
    if pending || bytes.len() <= limits.max_trailer {
        Ok(Parse::NeedMore)
    } else {
        Err(Error::NoCandidate)
    }
}
