#![forbid(unsafe_code)]
//! Incremental extended-FLV framing over contiguous original stream bytes.
//!
//! The caller owns source identity, receive clocks, custody, budgets and
//! cancellation. A structurally matching successor remains a heuristic
//! candidate even when no earlier candidate is incomplete. This code neither
//! authenticates the sender nor asserts continuity, durability or decoding.

use std::{fmt, ops::Range};

use super::{Error as ParseError, Header, Limits, Parse, Tag, find_next, find_next_provisional};

/// Maximum resident input bytes accepted by one framer.
pub const MAX_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Payload-free framing and accounting refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Limits are invalid or exceed the implementation's finite ceiling.
    Configuration,
    /// The appended bytes do not start exactly after the previous accepted bytes.
    OffsetMismatch,
    /// A stream offset would overflow its representation.
    OffsetOverflow,
    /// The bounded internal buffer cannot admit the entire supplied slice.
    BufferLimit,
    /// An allocation failed; no source bytes were discarded.
    Allocation,
    /// Existing framing rejected the source. Buffered bytes remain available.
    Parse(ParseError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV stream refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Current parser position; neither variant grants source or custody authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Waiting for the original FLV header.
    Header,
    /// Waiting for the first tag immediately following the header.
    FirstTag,
    /// Searching after the last tag for a structurally matching successor.
    Successor,
}

/// Choice of structural successor search; neither mode authenticates boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMode {
    /// Wait for every earlier plausible candidate to become complete or invalid.
    Conservative,
    /// Emit a later match even while an earlier candidate remains incomplete.
    /// The output and every subsequent record are explicitly marked provisional.
    Provisional,
}

/// Why a range of source bytes was surfaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// The original header, including its initial previous-tag-size field.
    Header,
    /// The first structurally framed tag immediately after the header.
    FirstTag {
        /// Untrusted original tag type.
        tag_kind: u8,
        /// Wrapping original FLV media timestamp, not a receive or UTC clock.
        timestamp_ms: u32,
    },
    /// Trailer bytes followed by a structurally framed successor candidate.
    Candidate {
        /// Uninterpreted bytes preceding the candidate in this record.
        trailer_bytes: usize,
        /// Untrusted original candidate tag type.
        tag_kind: u8,
        /// Wrapping original FLV media timestamp, not a receive or UTC clock.
        timestamp_ms: u32,
        /// An earlier plausible candidate was incomplete at this selection.
        earlier_incomplete: bool,
        /// This or an earlier selection skipped an incomplete candidate.
        /// Later input can change the claimed segment boundaries.
        provisional: bool,
    },
}

/// Exact original stream bytes for one emitted header or candidate segment.
///
/// Ownership transfer does not prove persistence. The caller must bind this
/// segment to its exact connection, stream generation and retained source.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct SourceRecord {
    offset: u64,
    kind: RecordKind,
    bytes: Vec<u8>,
}
impl SourceRecord {
    /// Stream-relative byte offset of the beginning of this record.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Structural classification; a candidate is not a verified boundary.
    pub fn kind(&self) -> RecordKind {
        self.kind
    }
    /// Exact original bytes, including uninterpreted candidate trailer bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Tag range relative to this record, including its header and back-reference.
    pub fn tag_range(&self) -> Option<Range<usize>> {
        match self.kind {
            RecordKind::Header => None,
            RecordKind::FirstTag { .. } => Some(0..self.bytes.len()),
            RecordKind::Candidate { trailer_bytes, .. } => Some(trailer_bytes..self.bytes.len()),
        }
    }
    /// Move the unchanged original bytes to the caller's custody owner.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for SourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceRecord")
            .field("offset", &self.offset)
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Progress from one bounded parse attempt.
#[derive(Debug, Eq, PartialEq)]
pub enum Next {
    /// A complete candidate needs more bytes; no input was consumed.
    NeedMore,
    /// Exact original bytes were moved to a new owner.
    Record(SourceRecord),
}

/// Unparsed bytes returned on shutdown or refusal.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct Remainder {
    /// Original connection-relative offset of `bytes`.
    pub offset: u64,
    /// Current structural parse phase, including an incomplete tail.
    pub phase: Phase,
    /// At least one earlier boundary was selected while an earlier candidate was incomplete.
    pub provisional: bool,
    bytes: Vec<u8>,
}
impl Remainder {
    /// Exact buffered bytes that were not emitted as records.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Move the exact remaining bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for Remainder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remainder")
            .field("offset", &self.offset)
            .field("phase", &self.phase)
            .field("provisional", &self.provisional)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// One bounded connection-local framing attempt with exact offset accounting.
pub struct Framer {
    limits: Limits,
    max_buffer: usize,
    phase: Phase,
    mode: SearchMode,
    provisional: bool,
    base: u64,
    buffer: Vec<u8>,
    head: usize,
}
impl fmt::Debug for Framer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Framer")
            .field("phase", &self.phase)
            .field("mode", &self.mode)
            .field("provisional", &self.provisional)
            .field("base", &self.base)
            .field("buffered", &self.buffered_len())
            .finish_non_exhaustive()
    }
}
impl Framer {
    /// Begin at offset zero. `max_buffer` bounds retained bytes, not total work.
    pub fn new(limits: Limits, max_buffer: usize) -> Result<Self, Error> {
        Self::with_mode(limits, max_buffer, SearchMode::Conservative)
    }

    /// Begin at offset zero with an explicit successor-search policy.
    pub fn with_mode(limits: Limits, max_buffer: usize, mode: SearchMode) -> Result<Self, Error> {
        if !(13..=MAX_BUFFER_BYTES).contains(&max_buffer) || Header::parse(&[], limits).is_err() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            limits,
            max_buffer,
            phase: Phase::Header,
            mode,
            provisional: false,
            base: 0,
            buffer: Vec::new(),
            head: 0,
        })
    }

    /// Current number of buffered original bytes.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len() - self.head
    }
    /// Maximum additional bytes admitted in one append without draining records.
    pub fn remaining_capacity(&self) -> usize {
        self.max_buffer - self.buffered_len()
    }
    /// Next required original connection-relative input offset.
    pub fn next_offset(&self) -> u64 {
        self.base + self.buffered_len() as u64
    }

    /// Copy one entire contiguous input slice. On refusal no input is accepted.
    /// The caller retains the input and may retry a smaller prefix after draining.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Error> {
        if offset != self.next_offset() {
            return Err(Error::OffsetMismatch);
        }
        let len = u64::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?;
        offset.checked_add(len).ok_or(Error::OffsetOverflow)?;
        if bytes.len() > self.remaining_capacity() {
            return Err(Error::BufferLimit);
        }
        if self.buffer.len() + bytes.len() > self.max_buffer {
            self.buffer.copy_within(self.head.., 0);
            self.buffer.truncate(self.buffered_len());
            self.head = 0;
        }
        self.buffer
            .try_reserve(bytes.len())
            .map_err(|_| Error::Allocation)?;
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Surface at most one structurally framed original-byte record.
    ///
    /// The bounded conservative search can wait on an earlier incomplete
    /// candidate. Caller-owned CPU, buffering and idle budgets remain necessary.
    /// Parse or allocation refusal leaves all buffered bytes unchanged.
    pub fn take(&mut self) -> Result<Next, Error> {
        let input = &self.buffer[self.head..];
        let (len, kind, next_phase) = match self.phase {
            Phase::Header => match Header::parse(input, self.limits).map_err(Error::Parse)? {
                Parse::NeedMore => return Ok(Next::NeedMore),
                Parse::Complete(header) => (
                    header.wire_bytes().len(),
                    RecordKind::Header,
                    Phase::FirstTag,
                ),
            },
            Phase::FirstTag => match Tag::parse(input, self.limits).map_err(Error::Parse)? {
                Parse::NeedMore => return Ok(Next::NeedMore),
                Parse::Complete(tag) => (
                    tag.wire_bytes().len(),
                    RecordKind::FirstTag {
                        tag_kind: tag.kind(),
                        timestamp_ms: tag.timestamp_ms(),
                    },
                    Phase::Successor,
                ),
            },
            Phase::Successor => match match self.mode {
                SearchMode::Conservative => find_next(input, self.limits),
                SearchMode::Provisional => find_next_provisional(input, self.limits),
            }.map_err(Error::Parse)? {
                Parse::NeedMore => return Ok(Next::NeedMore),
                Parse::Complete(candidate) => (
                    candidate.trailer.len() + candidate.tag.wire_bytes().len(),
                    RecordKind::Candidate {
                        trailer_bytes: candidate.trailer.len(),
                        tag_kind: candidate.tag.kind(),
                        timestamp_ms: candidate.tag.timestamp_ms(),
                        earlier_incomplete: candidate.earlier_incomplete,
                        provisional: self.provisional || candidate.earlier_incomplete,
                    },
                    Phase::Successor,
                ),
            },
        };
        let end = self
            .base
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&self.buffer[self.head..self.head + len]);
        self.head += len;
        let record = SourceRecord {
            offset: self.base,
            kind,
            bytes,
        };
        self.base = end;
        self.phase = next_phase;
        if let RecordKind::Candidate { provisional: true, .. } = kind {
            self.provisional = true;
        }
        Ok(Next::Record(record))
    }

    /// Retire the framer and move every unparsed byte to the caller.
    pub fn retire(mut self) -> Remainder {
        self.buffer.copy_within(self.head.., 0);
        self.buffer.truncate(self.buffered_len());
        Remainder {
            offset: self.base,
            phase: self.phase,
            provisional: self.provisional,
            bytes: self.buffer,
        }
    }
}
