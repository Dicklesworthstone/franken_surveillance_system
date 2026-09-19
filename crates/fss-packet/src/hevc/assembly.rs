#![forbid(unsafe_code)]

use super::{HevcPrefixError, HevcSlicePrefix, header, parse_slice_prefix};
use crate::{H265NalUnit, StreamKey};

/// Independent bounds on complete-NAL picture assembly, not decoder limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcAssemblyLimits {
    /// NALs per pending picture, including metadata, in 1..=4096.
    pub max_nals: usize,
    /// Sum of retained NAL bytes, in 3..=64 MiB.
    pub max_bytes: usize,
    /// Source-copy spans per picture, in 1..=262144.
    pub max_source_spans: usize,
    /// Fixed pending lifetime from the first NAL, in 1..=60 seconds.
    pub max_age_ns: u64,
}
impl Default for HevcAssemblyLimits {
    fn default() -> Self {
        Self { max_nals: 256, max_bytes: 16 * 1_024 * 1_024,
            max_source_spans: 16_384, max_age_ns: 2_000_000_000 }
    }
}
impl HevcAssemblyLimits {
    /// Reject invalid limits rather than silently widening policy.
    pub fn validate(self) -> Result<(), HevcAssemblyError> {
        if !(1..=4096).contains(&self.max_nals)
            || !(3..=64 * 1_024 * 1_024).contains(&self.max_bytes)
            || !(1..=262_144).contains(&self.max_source_spans)
            || !(1..=60_000_000_000).contains(&self.max_age_ns)
        { return Err(HevcAssemblyError::Configuration); }
        Ok(())
    }
}

/// Observed boundary evidence. None certifies all slices, decoded pixels or references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcBoundary {
    /// A later VCL NAL has first_slice_segment_in_pic_flag set.
    NextFirstSlice,
    /// A VPS/SPS/PPS/prefix-SEI NAL after VCL starts the following prefix.
    NextAccessUnitPrefix,
    /// A validated AUD after VCL starts the following access unit.
    AccessUnitDelimiter,
    /// An end-of-sequence NAL followed the picture.
    EndOfSequence,
    /// An end-of-bitstream NAL followed the picture.
    EndOfBitstream,
    /// Input ended without another syntax boundary; never upgrade this to a verified boundary.
    EndOfInputUnverified,
}

/// One observed single-layer picture group, retaining every accepted source-linked NAL.
#[derive(Debug, Eq, PartialEq)]
pub struct HevcPictureGroup {
    key: StreamKey,
    timestamp: u32,
    prefix: HevcSlicePrefix,
    nals: Vec<H265NalUnit>,
    bytes: usize,
    spans: usize,
    slices: usize,
    boundary: HevcBoundary,
    discontinuity_before: bool,
}
impl HevcPictureGroup {
    /// Exact owner epoch and SSRC.
    pub fn key(&self) -> StreamKey { self.key }
    /// Original sampling timestamp, not a capture-time estimate or decode-order counter.
    pub fn timestamp(&self) -> u32 { self.timestamp }
    /// First observed slice prefix. No PPS/SPS/VPS compatibility is certified.
    pub fn prefix(&self) -> HevcSlicePrefix { self.prefix }
    /// Ordered immutable NALs, with their original packet-to-NAL copy spans.
    pub fn nals(&self) -> &[H265NalUnit] { &self.nals }
    /// Sum of NAL byte lengths, without original RTP overhead.
    pub fn byte_len(&self) -> usize { self.bytes }
    /// Number of retained source-copy spans.
    pub fn source_span_count(&self) -> usize { self.spans }
    /// Number of observed VCL segments, not proof that none were lost.
    pub fn slice_count(&self) -> usize { self.slices }
    /// Why this observed grouping ended.
    pub fn boundary(&self) -> HevcBoundary { self.boundary }
    /// Whether a known input/assembly discontinuity preceded this group.
    pub fn discontinuity_before(&self) -> bool { self.discontinuity_before }
    /// Transfer original reconstructed NAL ownership, without copying or inventing bytes.
    pub fn into_nals(self) -> Vec<H265NalUnit> { self.nals }
}

/// Reason why pending derivative bytes were retired instead of emitted as a picture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcRetirementReason {
    /// Transport loss, fragment retirement or codec refusal reported by the owner.
    InputDiscontinuity,
    /// Fixed first-NAL deadline was reached.
    Deadline,
    /// Byte, count, source-span or representable-deadline limit was exceeded.
    Limit,
    /// Bounded metadata reservation failed.
    Allocation,
    /// Malformed, unsupported, overlapping or inconsistent input.
    InvalidInput,
    /// Metadata reached EOF, an end marker, or a new AUD without a first slice.
    NoPicture,
    /// Explicit owner cancellation.
    Cancelled,
}

/// Payload-free retirement accounting. Original source custody is independently owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcAssemblyRetirement {
    /// Owner epoch of all retired NALs.
    pub key: StreamKey,
    /// Exact cause; never a physical-absence assertion.
    pub reason: HevcRetirementReason,
    /// Complete NAL count retired.
    pub nals: usize,
    /// Reconstructed bytes retired.
    pub bytes: usize,
    /// Source-copy span count retired.
    pub source_spans: usize,
    /// First contributing extended RTP sequence.
    pub first_sequence: u64,
    /// Last contributing extended RTP sequence, not a continuity certificate.
    pub last_sequence: u64,
}

/// Typed assembly refusal, without payload or credential text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcAssemblyError {
    /// Invalid owner or policy bounds.
    Configuration,
    /// Wrong owner ingress/generation/SSRC; no pending state was changed.
    StreamMismatch,
    /// Assembler is closed; no new input was retained.
    Closed,
    /// Owner monotonic time reversed; no state changed.
    ClockReversed,
    /// Overlapping, repeated or backward source-copy spans.
    SourceOrder,
    /// Admitted prefix syntax was malformed or unsupported.
    Syntax(HevcPrefixError),
    /// Continuation/suffix without an observed first slice.
    MissingFirstSlice,
    /// Conflicting PPS, VCL kind, temporal ID or IRAP flag within one picture.
    PictureMismatch,
    /// NALs attributed to one picture disagree on RTP timestamp, or immediately repeat a finished timestamp.
    TimestampMismatch,
    /// A VCL continuation follows a suffix, or AUD/metadata ordering is inconsistent.
    Ordering,
    /// Byte, count, span or deadline limit.
    Limit,
    /// Bounded metadata allocation failed.
    Allocation,
}
impl std::fmt::Display for HevcAssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HEVC assembly refusal: {self:?}")
    }
}
impl std::error::Error for HevcAssemblyError {}

/// At most one completed grouping and one retirement; no unbounded callback output.
#[derive(Debug, Eq, PartialEq)]
pub struct HevcAssemblyOutput {
    /// Group ended by an observed boundary or an explicitly unverified EOF tail.
    pub picture: Option<HevcPictureGroup>,
    /// Any pending state invalidated by expiry or metadata-only termination.
    pub retired: Option<HevcAssemblyRetirement>,
    /// An end marker with no current picture, returned intact rather than silently dropped.
    pub standalone: Option<H265NalUnit>,
}
impl HevcAssemblyOutput {
    fn empty() -> Self { Self { picture: None, retired: None, standalone: None } }
}

/// Rejected input remains available to the caller, without allocating on an error path.
#[derive(Debug, Eq, PartialEq)]
pub struct HevcAssemblyRefusal {
    /// Stable refusal category.
    pub reason: HevcAssemblyError,
    /// Exact input NAL and its original source spans, unconsumed by assembly.
    pub nal: H265NalUnit,
    /// Pending grouping invalidated by the failed admission, when present.
    pub retired: Option<HevcAssemblyRetirement>,
}

/// Ownership-preserving result; not a boxed Result that allocates while handling exhaustion.
#[derive(Debug, Eq, PartialEq)]
pub enum HevcAssemblyStep {
    /// Input was retained or transferred in the bounded output.
    Accepted(HevcAssemblyOutput),
    /// Input is returned intact with any pending-state retirement.
    Refused(HevcAssemblyRefusal),
}

#[derive(Clone, Copy)]
enum Kind { Slice(HevcSlicePrefix), Prefix, Aud, Suffix, End(HevcBoundary) }

struct Pending {
    nals: Vec<H265NalUnit>,
    prefix: Option<HevcSlicePrefix>,
    timestamp: u32,
    bytes: usize,
    spans: usize,
    slices: usize,
    deadline_ns: u64,
    suffix: bool,
    discontinuity: bool,
}

/// Bounded first-slice-driven grouping in one owner epoch and layer zero.
///
/// RTP markers never flush a picture. All supported VCL prefixes and source
/// spans are checked before admitting a NAL. Parameter-set and SEI bodies remain
/// opaque source metadata, NOT parsed configuration. Every picture requires an
/// observed first slice; reference availability and completeness remain unknown.
pub struct HevcAssembler {
    key: StreamKey,
    limits: HevcAssemblyLimits,
    pending: Option<Pending>,
    last_source: Option<(u64, usize)>,
    last_picture_timestamp: Option<u32>,
    last_ns: u64,
    discontinuity: bool,
    closed: bool,
}
impl std::fmt::Debug for HevcAssembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcAssembler").field("key", &self.key)
            .field("pending_bytes", &self.pending_bytes())
            .field("deadline_ns", &self.next_wake_ns()).field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
impl HevcAssembler {
    /// Open a bounded pure derivative owner; creates no source-custody or decode authority.
    pub fn new(key: StreamKey, limits: HevcAssemblyLimits) -> Result<Self, HevcAssemblyError> {
        limits.validate()?;
        if key.ingress == 0 || key.generation == 0 { return Err(HevcAssemblyError::Configuration); }
        Ok(Self { key, limits, pending: None, last_source: None,
            last_picture_timestamp: None, last_ns: 0, discontinuity: false, closed: false })
    }
    /// Retained complete-NAL byte count, excluding independent source storage.
    pub fn pending_bytes(&self) -> usize { self.pending.as_ref().map_or(0, |p| p.bytes) }
    /// Original first-NAL deadline. New slices or markers never renew it.
    pub fn next_wake_ns(&self) -> Option<u64> { self.pending.as_ref().map(|p| p.deadline_ns) }

    /// Advance monotonic time and retire expired grouping exactly once, even without packets.
    pub fn expire(&mut self, now: u64) -> Result<Option<HevcAssemblyRetirement>, HevcAssemblyError> {
        self.check_time(now)?;
        self.last_ns = now;
        Ok(if self.next_wake_ns().is_some_and(|at| now >= at) {
            self.retire(HevcRetirementReason::Deadline)
        } else { None })
    }
    /// Propagate a known transport/codec discontinuity before any later NAL admission.
    pub fn discontinuity(&mut self, key: StreamKey, now: u64)
        -> Result<Option<HevcAssemblyRetirement>, HevcAssemblyError>
    {
        if key != self.key { return Err(HevcAssemblyError::StreamMismatch); }
        self.check_time(now)?;
        self.last_ns = now;
        self.discontinuity = true;
        Ok(self.retire(HevcRetirementReason::InputDiscontinuity))
    }
    /// Consume one ordered source-linked NAL or return it intact. Wrong-owner and
    /// reversed-clock inputs leave both the pending group and source watermark untouched.
    pub fn push(&mut self, nal: H265NalUnit, now: u64) -> HevcAssemblyStep {
        let safe_error = if nal.key() != self.key { Some(HevcAssemblyError::StreamMismatch) }
            else if self.closed { Some(HevcAssemblyError::Closed) }
            else { self.check_time(now).err() };
        if let Some(reason) = safe_error {
            return HevcAssemblyStep::Refused(HevcAssemblyRefusal { reason, nal, retired: None });
        }
        let mut retired = match self.expire(now) {
            Ok(retired) => retired,
            Err(reason) => return HevcAssemblyStep::Refused(HevcAssemblyRefusal { reason, nal, retired: None }),
        };
        let admitted = self.prepare(&nal, now, &mut retired);
        match admitted {
            Ok((kind, boundary, fresh)) => {
                let mut output = HevcAssemblyOutput { picture: None, retired, standalone: None };
                if let Some(boundary) = boundary { output.picture = self.take_picture(boundary); }
                if let Some(pending) = fresh { self.pending = Some(pending); }
                if matches!(kind, Kind::End(_)) && self.pending.as_ref().is_none_or(|p| p.prefix.is_none()) {
                    output.retired = output.retired.or_else(|| self.retire(HevcRetirementReason::NoPicture));
                    output.standalone = Some(nal);
                } else if let Some(p) = &mut self.pending {
                    p.bytes += nal.bytes().len();
                    p.spans += nal.sources().len();
                    match kind {
                        Kind::Slice(prefix) => {
                            p.prefix = p.prefix.or(Some(prefix));
                            p.slices += 1;
                        }
                        Kind::Suffix => p.suffix = true,
                        _ => {},
                    }
                    p.nals.push(nal);
                    if let Kind::End(end) = kind { output.picture = self.take_picture(end); }
                }
                if matches!(kind, Kind::End(HevcBoundary::EndOfBitstream)) { self.closed = true; }
                HevcAssemblyStep::Accepted(output)
            }
            Err(reason) => {
                let cause = match reason {
                    HevcAssemblyError::Limit => HevcRetirementReason::Limit,
                    HevcAssemblyError::Allocation => HevcRetirementReason::Allocation,
                    _ => HevcRetirementReason::InvalidInput,
                };
                let invalidated = self.retire(cause);
                self.discontinuity = true;
                HevcAssemblyStep::Refused(HevcAssemblyRefusal { reason, nal, retired: retired.or(invalidated) })
            }
        }
    }

    fn prepare(&mut self, nal: &H265NalUnit, now: u64, retired: &mut Option<HevcAssemblyRetirement>)
        -> Result<(Kind, Option<HevcBoundary>, Option<Pending>), HevcAssemblyError>
    {
        // A NAL can share an AP sequence with its neighbor, but copied byte spans
        // must remain disjoint. FU headers contribute to original wire ownership.
        let first = nal.sources().first().ok_or(HevcAssemblyError::SourceOrder)?;
        let mut end = self.last_source;
        for span in nal.sources() {
            let start = span.fragment_header_range.as_ref().map_or(span.wire_range.start, |r| r.start);
            if span.wire_range.end < start || end.is_some_and(|(seq, byte)|
                span.sequence < seq || span.sequence == seq && start < byte)
            { return Err(HevcAssemblyError::SourceOrder); }
            end = Some((span.sequence, span.wire_range.end));
        }
        let gap = self.last_source.is_some_and(|(seq, _)|
            first.sequence > seq && seq.checked_add(1) != Some(first.sequence));
        self.last_source = end;
        if gap {
            self.discontinuity = true;
            *retired = retired.take().or_else(|| self.retire(HevcRetirementReason::InputDiscontinuity));
        }
        if nal.bytes().len() > self.limits.max_bytes || nal.sources().len() > self.limits.max_source_spans {
            return Err(HevcAssemblyError::Limit);
        }
        let kind = classify(nal.bytes(), self.limits.max_bytes)?;
        let has_picture = self.pending.as_ref().is_some_and(|p| p.prefix.is_some());
        let boundary = if has_picture {
            match kind {
                Kind::Slice(prefix) if prefix.first_slice => Some(HevcBoundary::NextFirstSlice),
                Kind::Prefix => Some(HevcBoundary::NextAccessUnitPrefix),
                Kind::Aud => Some(HevcBoundary::AccessUnitDelimiter),
                _ => None,
            }
        } else { None };
        if let Some(p) = &self.pending {
            if boundary.is_some() {
                if nal.timestamp() == p.timestamp { return Err(HevcAssemblyError::TimestampMismatch); }
            } else if !matches!(kind, Kind::End(_) | Kind::Aud) && nal.timestamp() != p.timestamp {
                return Err(HevcAssemblyError::TimestampMismatch);
            }
            if let Kind::Slice(prefix) = kind {
                if !prefix.first_slice {
                    let old = p.prefix.ok_or(HevcAssemblyError::MissingFirstSlice)?;
                    if p.suffix { return Err(HevcAssemblyError::Ordering); }
                    if old.pps_id != prefix.pps_id || old.nal_type != prefix.nal_type
                        || old.temporal_id_plus_one != prefix.temporal_id_plus_one
                        || old.no_output_of_prior_pics != prefix.no_output_of_prior_pics
                    { return Err(HevcAssemblyError::PictureMismatch); }
                }
            }
        }
        if matches!(kind, Kind::Suffix | Kind::Slice(HevcSlicePrefix { first_slice: false, .. })) && !has_picture {
            return Err(HevcAssemblyError::MissingFirstSlice);
        }
        if !has_picture && matches!(kind, Kind::Aud) && self.pending.is_some() {
            *retired = retired.take().or_else(|| self.retire(HevcRetirementReason::NoPicture));
        }
        let new_group = self.pending.is_none() || boundary.is_some();
        if new_group && !matches!(kind, Kind::End(_)) {
            if self.last_picture_timestamp == Some(nal.timestamp()) { return Err(HevcAssemblyError::TimestampMismatch); }
            let deadline_ns = now.checked_add(self.limits.max_age_ns).ok_or(HevcAssemblyError::Limit)?;
            let mut nals = Vec::new();
            nals.try_reserve_exact(1).map_err(|_| HevcAssemblyError::Allocation)?;
            return Ok((kind, boundary, Some(Pending {
                nals, prefix: None, timestamp: nal.timestamp(), bytes: 0, spans: 0, slices: 0,
                deadline_ns, suffix: false, discontinuity: boundary.is_none() && self.discontinuity,
            })));
        }
        if let Some(p) = &mut self.pending {
            if p.nals.len() >= self.limits.max_nals
                || p.bytes.checked_add(nal.bytes().len()).is_none_or(|v| v > self.limits.max_bytes)
                || p.spans.checked_add(nal.sources().len()).is_none_or(|v| v > self.limits.max_source_spans)
            { return Err(HevcAssemblyError::Limit); }
            if p.nals.len() == p.nals.capacity() {
                let target = (p.nals.len() + 1).saturating_mul(2).min(self.limits.max_nals);
                p.nals.try_reserve_exact(target - p.nals.len()).map_err(|_| HevcAssemblyError::Allocation)?;
            }
        }
        Ok((kind, boundary, None))
    }

    /// End input without manufacturing a syntax boundary. An active VCL group has
    /// an explicit unverified EOF boundary; metadata-only state is retired.
    pub fn finish(&mut self, now: u64) -> Result<HevcAssemblyOutput, HevcAssemblyError> {
        let retired = self.expire(now)?;
        self.closed = true;
        let mut output = HevcAssemblyOutput { retired, ..HevcAssemblyOutput::empty() };
        if self.pending.as_ref().is_some_and(|p| p.prefix.is_some()) {
            output.picture = self.take_picture(HevcBoundary::EndOfInputUnverified);
        } else {
            output.retired = output.retired.or_else(|| self.retire(HevcRetirementReason::NoPicture));
        }
        Ok(output)
    }
    /// Cancel permanently and report pending derivative ownership exactly once.
    pub fn cancel(&mut self) -> Option<HevcAssemblyRetirement> {
        self.closed = true;
        self.retire(HevcRetirementReason::Cancelled)
    }
    fn check_time(&self, now: u64) -> Result<(), HevcAssemblyError> {
        if now < self.last_ns { Err(HevcAssemblyError::ClockReversed) } else { Ok(()) }
    }
    fn take_picture(&mut self, boundary: HevcBoundary) -> Option<HevcPictureGroup> {
        let prefix = self.pending.as_ref()?.prefix?;
        let p = self.pending.take()?;
        self.last_picture_timestamp = Some(p.timestamp);
        self.discontinuity = false;
        Some(HevcPictureGroup { key: self.key, timestamp: p.timestamp, prefix,
            nals: p.nals, bytes: p.bytes, spans: p.spans, slices: p.slices,
            boundary, discontinuity_before: p.discontinuity })
    }
    fn retire(&mut self, reason: HevcRetirementReason) -> Option<HevcAssemblyRetirement> {
        let p = self.pending.take()?;
        self.discontinuity = true;
        Some(HevcAssemblyRetirement {
            key: self.key, reason, nals: p.nals.len(), bytes: p.bytes, source_spans: p.spans,
            first_sequence: p.nals.first()?.sources().first()?.sequence,
            last_sequence: p.nals.last()?.sources().last()?.sequence,
        })
    }
}

fn classify(nal: &[u8], limit: usize) -> Result<Kind, HevcAssemblyError> {
    let syntax = HevcAssemblyError::Syntax;
    let (kind, _) = header(nal).map_err(syntax)?;
    if nal.len() < 3 { return Err(syntax(HevcPrefixError::Truncated)); }
    match kind {
        0..=9 | 16..=21 => Ok(Kind::Slice(parse_slice_prefix(nal, limit).map_err(syntax)?)),
        32..=34 | 39 => Ok(Kind::Prefix),
        35 if nal.len() == 3 && nal[2] & 31 == 16 && nal[2] >> 5 <= 2 => Ok(Kind::Aud),
        36 | 37 if nal.len() == 3 && nal[2] == 0x80 => Ok(Kind::End(
            if kind == 36 { HevcBoundary::EndOfSequence } else { HevcBoundary::EndOfBitstream })),
        38 if nal.last() == Some(&0x80) && nal[2..nal.len() - 1].iter().all(|b| *b == 0xff) => Ok(Kind::Suffix),
        40 => Ok(Kind::Suffix),
        35..=38 => Err(syntax(HevcPrefixError::Malformed)),
        _ => Err(syntax(HevcPrefixError::UnsupportedNal)),
    }
}
