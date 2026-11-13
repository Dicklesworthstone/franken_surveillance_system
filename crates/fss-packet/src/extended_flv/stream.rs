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
/// Maximum source prefix inspected for an optional initial stream-name claim.
pub const MAX_NAME_PREFIX_BYTES: usize = 256 * 1024;
/// Maximum structurally framed tags inspected in one initial claim search.
pub const MAX_NAME_PREFIX_TAGS: usize = 32;
/// Maximum work units assigned to one connection-local name-probe owner.
pub const MAX_NAME_PROBE_WORK: u64 = 64 * 1024 * 1024;

/// Result of a bounded non-consuming startup metadata inspection.
/// A match is an untrusted sender claim, not authentication or stream identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameProbe {
    /// More input may contain the requested claim within the remaining bounds.
    NeedMore,
    /// A matching event and stream-name claim was observed at this zero-based tag index.
    Matched {
        /// Zero-based position among inspected source tags.
        tag_index: usize,
    },
    /// A matching event claimed a different stream name at this zero-based tag index.
    Mismatched {
        /// Zero-based position among inspected source tags.
        tag_index: usize,
    },
    /// The configured source-prefix or tag count bound was reached.
    LimitReached {
        /// Complete tags inspected before the bound was reached.
        tags_scanned: usize,
    },
}

/// Payload-free failure while inspecting a retained startup prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameProbeError {
    /// Invalid expected values, bounds, or framer state.
    Configuration,
    /// The caller's explicit work allowance was exhausted.
    WorkLimit,
    /// An earlier incomplete candidate prevents a stable structural claim.
    Provisional,
    /// Bounded allocation for the caller's expectations failed.
    Allocation,
    /// FLV framing refused the retained bytes.
    Framing(Error),
    /// A script tag was invalid or outside the supported AMF0 profile.
    Metadata(super::metadata::Error),
}
impl fmt::Display for NameProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV name inspection refused: {self:?}")
    }
}
impl std::error::Error for NameProbeError {}

/// Connection-local expectations and remaining work for a startup name probe.
/// A caller owns this value across pending operations and cancellation. Debug
/// output omits the event and stream name, neither of which authenticates a peer.
pub struct NameProbeOwner {
    event: String,
    name: String,
    byte_limit: usize,
    tag_limit: usize,
    work_remaining: u64,
}
impl fmt::Debug for NameProbeOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameProbeOwner")
            .field("byte_limit", &self.byte_limit)
            .field("tag_limit", &self.tag_limit)
            .field("work_remaining", &self.work_remaining)
            .finish_non_exhaustive()
    }
}
impl NameProbeOwner {
    /// Bind explicit expectations and a finite cumulative work allowance.
    pub fn new(event: &str, name: &str, byte_limit: usize, tag_limit: usize, work: u64) -> Result<Self, NameProbeError> {
        validate_name_expectations(event, name, byte_limit, tag_limit)?;
        if work == 0 || work > MAX_NAME_PROBE_WORK {
            return Err(NameProbeError::Configuration);
        }
        let mut event_copy = String::new();
        event_copy.try_reserve_exact(event.len()).map_err(|_| NameProbeError::Allocation)?;
        event_copy.push_str(event);
        let mut name_copy = String::new();
        name_copy.try_reserve_exact(name.len()).map_err(|_| NameProbeError::Allocation)?;
        name_copy.push_str(name);
        Ok(Self { event: event_copy, name: name_copy, byte_limit, tag_limit, work_remaining: work })
    }
    /// Inspect without changing the framer; cumulative work cannot be reset.
    pub fn inspect(&mut self, framer: &Framer) -> Result<NameProbe, NameProbeError> {
        framer.inspect_initial_name(&self.event, &self.name, self.byte_limit, self.tag_limit, &mut self.work_remaining)
    }
    /// Bound on the source prefix this owner may inspect.
    pub const fn byte_limit(&self) -> usize { self.byte_limit }
    /// Remaining cumulative inspection work; this is not a runtime grant.
    pub const fn work_remaining(&self) -> u64 { self.work_remaining }
}

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
    /// Explicit 16-byte trailer policy did not match; buffered bytes remain available.
    TrailerPolicyMismatch,
    /// The first tag violates the explicitly selected zero-stream-ID profile.
    StreamIdMismatch,
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

/// Choice of structural successor policy; no mode authenticates boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMode {
    /// Wait for every earlier plausible candidate to become complete or invalid.
    Conservative,
    /// Emit a later match even while an earlier candidate remains incomplete.
    /// The output and every subsequent record are explicitly marked provisional.
    Provisional,
    /// Require a 16-byte trailer whose middle eight bytes are zero, followed
    /// immediately by a structurally valid tag with a zero FLV stream ID.
    /// This explicitly selected policy
    /// reflects observed devices; it does not authenticate the sender or prove
    /// that another model or firmware uses this trailer format.
    StructuredTrailer16,
    /// Require a 16-byte trailer with seven zero bytes followed by a flag
    /// matching the preceding audio (0), video (1), or metadata (1) tag, then
    /// a zero-stream-ID successor. This opt-in heuristic reflects a bounded G4
    /// observation; it rejects other preceding kinds and authenticates nothing.
    StructuredTrailer16AvFlag,
    /// Search variable trailers conservatively while excluding candidates
    /// whose complete FLV header has a nonzero stream ID. This is an explicit
    /// source-profile assumption, not proof of a tag boundary or identity.
    ZeroStreamId,
}
impl SearchMode {
    /// Stable policy identity used in source-evidence metadata.
    pub const fn evidence_id(self) -> u8 {
        match self {
            Self::Conservative => 0,
            Self::Provisional => 1,
            Self::StructuredTrailer16 => 2,
            Self::StructuredTrailer16AvFlag => 3,
            Self::ZeroStreamId => 4,
        }
    }

    /// Decode a known source-evidence policy identity; unknown IDs stay unknown.
    pub const fn from_evidence_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Conservative),
            1 => Some(Self::Provisional),
            2 => Some(Self::StructuredTrailer16),
            3 => Some(Self::StructuredTrailer16AvFlag),
            4 => Some(Self::ZeroStreamId),
            _ => None,
        }
    }
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
        /// Explicit local policy that selected this candidate; not an authenticity proof.
        policy: SearchMode,
    },
    /// Unparsed bytes recovered at shutdown; this makes no tag-boundary claim.
    Unframed {
        /// Caller-supplied local owner from which these bytes were recovered.
        origin: UnframedOrigin,
    },
}

/// Local origin of an unparsed byte range; this is not device authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnframedOrigin {
    /// Bytes remaining in the FLV framer.
    Framer,
    /// The not-yet-appended suffix of a partially transferred TCP chunk.
    BufferedSuffix,
    /// A TCP chunk not yet transferred to the framer.
    SocketPending,
}

impl UnframedOrigin {
    /// Stable source-evidence identifier.
    pub const fn evidence_id(self) -> u8 {
        match self {
            Self::Framer => 0,
            Self::BufferedSuffix => 1,
            Self::SocketPending => 2,
        }
    }

    /// Decode a known source-evidence identifier.
    pub const fn from_evidence_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Framer),
            1 => Some(Self::BufferedSuffix),
            2 => Some(Self::SocketPending),
            _ => None,
        }
    }
}

/// Invalid unframed source; the input bytes remain owned by the caller.
#[must_use]
pub struct UnframedRefusal {
    /// Original connection-relative offset claim.
    pub offset: u64,
    /// Unconsumed original bytes.
    pub bytes: Vec<u8>,
    /// Original local-origin claim.
    pub origin: UnframedOrigin,
}

/// Exact bytes for one framed range or an explicitly caller-bound unframed range.
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
    /// Wrap nonempty unparsed bytes without asserting an FLV tag boundary.
    /// The caller must bind the offset and origin to the actual source owner.
    pub fn unframed(
        offset: u64,
        bytes: Vec<u8>,
        origin: UnframedOrigin,
    ) -> Result<Self, UnframedRefusal> {
        if bytes.is_empty()
            || u64::try_from(bytes.len())
                .ok()
                .and_then(|len| offset.checked_add(len))
                .is_none()
        {
            return Err(UnframedRefusal {
                offset,
                bytes,
                origin,
            });
        }
        Ok(Self {
            offset,
            kind: RecordKind::Unframed { origin },
            bytes,
        })
    }

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
    /// Duplicate the exact record for a bounded lookahead witness. This is a
    /// copy, not a transfer of original custody or proof of persistence.
    pub fn try_duplicate(&self) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.bytes.len())
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&self.bytes);
        Ok(Self {
            offset: self.offset,
            kind: self.kind,
            bytes,
        })
    }
    /// Tag range relative to this record, including its header and back-reference.
    pub fn tag_range(&self) -> Option<Range<usize>> {
        match self.kind {
            RecordKind::Header | RecordKind::Unframed { .. } => None,
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
    last_tag_kind: Option<u8>,
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
        if !(13..=MAX_BUFFER_BYTES).contains(&max_buffer)
            || Header::parse(&[], limits).is_err()
            || (matches!(
                mode,
                SearchMode::StructuredTrailer16 | SearchMode::StructuredTrailer16AvFlag
            ) && limits.max_trailer < 16)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            limits,
            max_buffer,
            phase: Phase::Header,
            mode,
            last_tag_kind: None,
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

    /// Inspect the buffered initial header without consuming any source bytes.
    /// A complete header is structural evidence only, not authentication or
    /// proof that a subsequent media tag will be valid.
    pub fn initial_header_complete(&self) -> Result<bool, Error> {
        if self.phase != Phase::Header || self.base != 0 {
            return Err(Error::OffsetMismatch);
        }
        let input = &self.buffer[self.head..];
        let prefix_len = input.len().min(3);
        if input[..prefix_len] != b"FLV"[..prefix_len] || (input.len() >= 4 && input[3] != 1) {
            return Err(Error::Parse(super::Error::InvalidHeader));
        }
        match Header::parse(input, self.limits).map_err(Error::Parse)? {
            Parse::NeedMore => Ok(false),
            Parse::Complete(_) => Ok(true),
        }
    }

    /// Inspect a bounded initial prefix for a named AMF0 event and stream claim.
    ///
    /// This does not consume, copy, or persist source bytes. The caller owns
    /// the source, supplies fresh connection-specific expectations, meters
    /// repeated calls through `work_remaining`, and decides whether to act on
    /// the result. Even a match is neither camera authentication nor proof of
    /// a stream's identity. Incomplete or unsupported input never matches.
    pub fn inspect_initial_name(
        &self,
        expected_event: &str,
        expected_name: &str,
        byte_limit: usize,
        tag_limit: usize,
        work_remaining: &mut u64,
    ) -> Result<NameProbe, NameProbeError> {
        if self.phase != Phase::Header || self.base != 0 {
            return Err(NameProbeError::Configuration);
        }
        validate_name_expectations(expected_event, expected_name, byte_limit, tag_limit)?;
        name_probe_charge(work_remaining, 1)?;
        let all = &self.buffer[self.head..];
        let input = &all[..all.len().min(byte_limit)];
        let at_bound = all.len() >= byte_limit;
        let waiting = |tags_scanned| {
            if at_bound {
                NameProbe::LimitReached { tags_scanned }
            } else {
                NameProbe::NeedMore
            }
        };
        let prefix_len = input.len().min(3);
        if input[..prefix_len] != b"FLV"[..prefix_len] || (input.len() >= 4 && input[3] != 1) {
            return Err(NameProbeError::Framing(Error::Parse(
                ParseError::InvalidHeader,
            )));
        }
        name_probe_charge(work_remaining, input.len().min(self.limits.max_header + 4))?;
        let header = match Header::parse(input, self.limits)
            .map_err(|error| NameProbeError::Framing(Error::Parse(error)))?
        {
            Parse::NeedMore => return Ok(waiting(0)),
            Parse::Complete(header) => header,
        };
        let mut position = header.wire_bytes().len();
        let mut previous_kind = None;
        for index in 0..tag_limit {
            let rest = &input[position..];
            let tag = if index == 0 {
                name_probe_charge(work_remaining, rest.len().min(15))?;
                if self.mode == SearchMode::ZeroStreamId
                    && rest.len() >= 11
                    && rest[8..11] != [0; 3]
                {
                    return Err(NameProbeError::Framing(Error::StreamIdMismatch));
                }
                match Tag::parse(rest, self.limits)
                    .map_err(|error| NameProbeError::Framing(Error::Parse(error)))?
                {
                    Parse::NeedMore => return Ok(waiting(index)),
                    Parse::Complete(tag) => tag,
                }
            } else {
                name_probe_charge(work_remaining, rest.len().min(self.limits.max_trailer + 1))?;
                match successor(rest, self.limits, self.mode, previous_kind)
                    .map_err(NameProbeError::Framing)?
                {
                    Parse::NeedMore => return Ok(waiting(index)),
                    Parse::Complete(candidate) if candidate.earlier_incomplete => {
                        return Err(NameProbeError::Provisional);
                    }
                    Parse::Complete(candidate) => {
                        position += candidate.trailer.len();
                        candidate.tag
                    }
                }
            };
            if tag.kind() == 18 {
                name_probe_charge(work_remaining, tag.payload().len())?;
                let claim = super::metadata::parse(tag).map_err(NameProbeError::Metadata)?;
                if claim.event() == expected_event {
                    if let Some(name) = claim.stream_name() {
                        return Ok(if name == expected_name {
                            NameProbe::Matched { tag_index: index }
                        } else {
                            NameProbe::Mismatched { tag_index: index }
                        });
                    }
                }
            }
            position += tag.wire_bytes().len();
            previous_kind = Some(tag.kind());
        }
        Ok(NameProbe::LimitReached {
            tags_scanned: tag_limit,
        })
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
            Phase::FirstTag
                if self.mode == SearchMode::ZeroStreamId
                    && input.len() >= 11
                    && input[8..11] != [0; 3] =>
            {
                return Err(Error::StreamIdMismatch);
            }
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
            Phase::Successor => match successor(input, self.limits, self.mode, self.last_tag_kind)?
            {
                Parse::NeedMore => return Ok(Next::NeedMore),
                Parse::Complete(candidate) => (
                    candidate.trailer.len() + candidate.tag.wire_bytes().len(),
                    RecordKind::Candidate {
                        trailer_bytes: candidate.trailer.len(),
                        tag_kind: candidate.tag.kind(),
                        timestamp_ms: candidate.tag.timestamp_ms(),
                        earlier_incomplete: candidate.earlier_incomplete,
                        provisional: self.provisional || candidate.earlier_incomplete,
                        policy: self.mode,
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
        match kind {
            RecordKind::FirstTag { tag_kind, .. } | RecordKind::Candidate { tag_kind, .. } => {
                self.last_tag_kind = Some(tag_kind);
            }
            RecordKind::Header | RecordKind::Unframed { .. } => {}
        }
        if let RecordKind::Candidate {
            provisional: true, ..
        } = kind
        {
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

fn validate_name_expectations(event: &str, name: &str, byte_limit: usize, tag_limit: usize) -> Result<(), NameProbeError> {
    if event.is_empty() || event.len() > 128
        || name.len() != 16
        || !name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(13..=MAX_NAME_PREFIX_BYTES).contains(&byte_limit)
        || !(1..=MAX_NAME_PREFIX_TAGS).contains(&tag_limit)
    {
        return Err(NameProbeError::Configuration);
    }
    Ok(())
}

fn name_probe_charge(work_remaining: &mut u64, cost: usize) -> Result<(), NameProbeError> {
    let cost = u64::try_from(cost).map_err(|_| NameProbeError::WorkLimit)?;
    *work_remaining = work_remaining
        .checked_sub(cost)
        .ok_or(NameProbeError::WorkLimit)?;
    Ok(())
}

fn successor(
    input: &[u8],
    limits: Limits,
    mode: SearchMode,
    previous_kind: Option<u8>,
) -> Result<Parse<super::Candidate<'_>>, Error> {
    match mode {
        SearchMode::Conservative => find_next(input, limits).map_err(Error::Parse),
        SearchMode::Provisional => find_next_provisional(input, limits).map_err(Error::Parse),
        SearchMode::StructuredTrailer16 => structured_trailer_16(input, limits, None),
        SearchMode::StructuredTrailer16AvFlag => {
            let flag = match previous_kind {
                Some(8) => 0,
                Some(9 | 18) => 1,
                _ => return Err(Error::TrailerPolicyMismatch),
            };
            structured_trailer_16(input, limits, Some(flag))
        }
        SearchMode::ZeroStreamId => {
            super::find_next_zero_stream_id(input, limits).map_err(Error::Parse)
        }
    }
}

fn structured_trailer_16(
    input: &[u8],
    limits: Limits,
    flag: Option<u8>,
) -> Result<Parse<super::Candidate<'_>>, Error> {
    if input.len() < 16 {
        return Ok(Parse::NeedMore);
    }
    if input[4..11] != [0; 7] || input[11] != flag.unwrap_or(0) {
        return Err(Error::TrailerPolicyMismatch);
    }
    if input.len() >= 27 && input[24..27] != [0; 3] {
        return Err(Error::TrailerPolicyMismatch);
    }
    match Tag::parse(&input[16..], limits) {
        Ok(Parse::NeedMore) => Ok(Parse::NeedMore),
        Ok(Parse::Complete(tag)) => Ok(Parse::Complete(super::Candidate {
            trailer: &input[..16],
            tag,
            earlier_incomplete: false,
        })),
        Err(_) => Err(Error::TrailerPolicyMismatch),
    }
}
