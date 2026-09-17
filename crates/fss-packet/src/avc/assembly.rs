#![forbid(unsafe_code)]

use super::{AvcError, AvcPps, AvcSliceIdentity, AvcSps, AvcSyntaxLimits, parse_slice_identity};
use crate::{NalUnit, StreamKey};

/// Independent bounds on a pending picture's NALs, bytes, and lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvcAssemblyLimits {
    /// Maximum NALs in one pending picture, including prefix metadata; at most 4,096.
    pub max_nals: usize,
    /// Maximum sum of complete NAL byte lengths; at most 64 MiB.
    pub max_bytes: usize,
    /// Maximum pending lifetime in supplied monotonic nanoseconds; at most 60 seconds.
    pub max_age_ns: u64,
}

impl Default for AvcAssemblyLimits {
    fn default() -> Self {
        Self {
            max_nals: 256,
            max_bytes: 16 * 1_024 * 1_024,
            max_age_ns: 2_000_000_000,
        }
    }
}

impl AvcAssemblyLimits {
    fn validate(self) -> Result<(), AvcAssemblyError> {
        if !(1..=4_096).contains(&self.max_nals)
            || !(1..=64 * 1_024 * 1_024).contains(&self.max_bytes)
            || !(1..=60_000_000_000).contains(&self.max_age_ns)
        {
            return Err(AvcAssemblyError::Configuration);
        }
        Ok(())
    }
}

/// Why an observed picture group ended. None proves decoded-picture completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcBoundary {
    /// A later VCL prefix identifies a different primary picture.
    NextPrimaryPicture,
    /// AUD/SPS/PPS/SEI after VCL starts the next access unit's prefix.
    NextAccessUnitPrefix,
    /// The sender asserted the end through the RTP marker bit.
    RtpMarker,
    /// A syntactically valid end-of-sequence NAL followed the VCL group.
    EndOfSequence,
    /// A syntactically valid end-of-stream NAL followed the VCL group.
    EndOfStream,
    /// Input ended without another boundary witness; the tail is explicitly unverified.
    EndOfInputUnverified,
}

/// Bounded, source-linked grouping of complete NALs for one observed picture.
/// Slice bodies are not decoded: missing macroblocks, malformed entropy coding,
/// or a false RTP marker are not ruled out by constructing this object.
#[derive(Debug, Eq, PartialEq)]
pub struct AvcPictureGroup {
    key: StreamKey,
    sps: AvcSps,
    pps: AvcPps,
    identity: AvcSliceIdentity,
    timestamp: u32,
    nals: Vec<NalUnit>,
    byte_len: usize,
    boundary: AvcBoundary,
    saw_first_mb: bool,
    discontinuity_before: bool,
}

impl AvcPictureGroup {
    /// Exact owner stream epoch of every NAL in this group.
    pub fn key(&self) -> StreamKey {
        self.key
    }
    /// Exact immutable SPS used to interpret every VCL prefix.
    pub fn sps(&self) -> &AvcSps {
        &self.sps
    }
    /// Exact immutable PPS, including its exact SPS binding.
    pub fn pps(&self) -> &AvcPps {
        &self.pps
    }
    /// First observed primary-picture identity prefix.
    pub fn identity(&self) -> AvcSliceIdentity {
        self.identity
    }
    /// Original RTP sampling timestamp, not a wall-clock/capture-time conversion.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
    /// Ordered complete NALs with their original RTP source-copy spans.
    pub fn nals(&self) -> &[NalUnit] {
        &self.nals
    }
    /// Sum of retained NAL bytes, excluding original datagram overhead.
    pub fn byte_len(&self) -> usize {
        self.byte_len
    }
    /// Boundary evidence; an EOF tail remains explicitly unverified.
    pub fn boundary(&self) -> AvcBoundary {
        self.boundary
    }
    /// Whether a primary slice beginning at macroblock zero was observed.
    /// This is necessary in the admitted subset but is NOT a completeness proof.
    pub fn saw_first_macroblock(&self) -> bool {
        self.saw_first_mb
    }
    /// Whether assembly resumed after a declared input/codec/assembly discontinuity.
    pub fn discontinuity_before(&self) -> bool {
        self.discontinuity_before
    }
    /// Transfer NAL ownership without copying or discarding their source spans.
    pub fn into_nals(self) -> Vec<NalUnit> {
        self.nals
    }
}

/// Stable reasons why a pending derivative was retired instead of published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcRetirementReason {
    /// Owner reported a transport loss, fragment retirement, or codec refusal.
    InputDiscontinuity,
    /// Supplied time reached the pending picture deadline.
    Deadline,
    /// Picture NAL/byte work exceeded the configured bound.
    Limit,
    /// Bounded metadata allocation was refused.
    Allocation,
    /// Unsupported or malformed input made the pending grouping unsafe to publish.
    InvalidInput,
    /// The exact codec configuration changed within the owner epoch.
    ConfigurationChanged,
    /// End-of-input contained metadata but no primary picture.
    NoPrimaryPicture,
    /// Owner cancelled the derivative assembly.
    Cancelled,
    /// Owner explicitly reopened in a strictly newer stream generation.
    Restarted,
}

/// Payload-free accounting for retired derivative state; original custody is independent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvcAssemblyRetirement {
    /// Exact owner stream epoch.
    pub key: StreamKey,
    /// Retirement cause, not an assertion of physical absence.
    pub reason: AvcRetirementReason,
    /// Number of complete NALs retired from this grouping.
    pub nals: usize,
    /// Number of reconstructed NAL bytes retired.
    pub bytes: usize,
    /// First contributing extended RTP sequence, when any NAL was retained.
    pub first_sequence: Option<u64>,
    /// Last contributing extended RTP sequence, when any NAL was retained.
    pub last_sequence: Option<u64>,
}

/// Payload-free construction/admission refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcAssemblyError {
    /// Invalid assembly budget or owner identity.
    Configuration,
    /// Wrong ingress, stream generation, or SSRC.
    StreamMismatch,
    /// Caller must reopen with a strictly newer generation of the same ingress.
    GenerationRequired,
    /// Assembler has been cancelled, finished, or fenced by configuration change.
    Closed,
    /// Supplied monotonic time moved backwards.
    ClockReversed,
    /// A marked picture is ready; poll it before admitting another NAL.
    OutputPending,
    /// More NALs claimed a picture/timestamp that was already emitted.
    PictureAlreadyEmitted,
    /// NAL source spans overlap or move backwards in extended sequence/byte order.
    SourceOrder,
    /// Different exact SPS/PPS bytes arrived within the same stream generation.
    ConfigurationChanged,
    /// Slices claiming one picture carried different RTP timestamps.
    TimestampMismatch,
    /// Malformed or unsupported codec syntax.
    Syntax(AvcError),
    /// NAL/byte/lifetime bounds cannot admit this input.
    Limit,
    /// Bounded metadata allocation was refused.
    Allocation,
}

impl std::fmt::Display for AvcAssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AVC assembly refusal: {self:?}")
    }
}
impl std::error::Error for AvcAssemblyError {}

/// Successful admission may yield one prior/current picture and one timeout receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct AvcAssemblyOutput {
    /// At most one source-linked picture group, never called decoded/complete.
    pub picture: Option<AvcPictureGroup>,
    /// Retired state, if the previous pending deadline expired or metadata had no picture.
    pub retired: Option<AvcAssemblyRetirement>,
}

/// Rejected input stays owned and inspectable; no additional allocation is needed on failure.
#[derive(Debug, Eq, PartialEq)]
pub struct AvcAssemblyRefusal {
    /// Why the supplied NAL was refused.
    pub reason: AvcAssemblyError,
    /// Exact rejected reconstructed NAL, including source-copy spans.
    pub nal: NalUnit,
    /// Any pending derivative invalidated by the refusal.
    pub retired: Option<AvcAssemblyRetirement>,
}

/// Typed ownership-preserving admission result. An enum avoids boxing the large
/// refusal (and allocating on an allocation-failure path) merely to fit Result.
#[derive(Debug, Eq, PartialEq)]
pub enum AvcAssemblyStep {
    /// Input was retained or included in an emitted picture.
    Accepted(AvcAssemblyOutput),
    /// Input was not retained and is returned intact.
    Refused(AvcAssemblyRefusal),
}

/// Bounded timer/ready-output progress, separate from NAL admission.
#[derive(Debug, Eq, PartialEq)]
pub enum AvcAssemblyPoll {
    /// One retained marked picture is ready to transfer to the owner.
    Picture(AvcPictureGroup),
    /// Pending derivative retired once, without source-data loss claims.
    Retired(AvcAssemblyRetirement),
    /// No ready output; the owner must arrange the supplied wake if present.
    Pending {
        /// Monotonic deadline for pending data, absent when nothing is retained.
        wake_at_ns: Option<u64>,
    },
    /// The assembler is closed and quiescent.
    Ended,
}

struct Pending {
    nals: Vec<NalUnit>,
    bytes: usize,
    picture: Option<(AvcSliceIdentity, u32)>,
    saw_first_mb: bool,
    discontinuity_before: bool,
    deadline: u64,
    end: Option<AvcBoundary>,
}

#[derive(Clone, Copy)]
enum Incoming {
    Vcl(AvcSliceIdentity),
    Prefix,
    Suffix,
    EndSequence,
    EndStream,
}

/// Owner-driven picture assembly over ordered, complete transport-reconstructed NALs.
///
/// Exact SPS/PPS bytes are immutable for this stream generation. Forward every
/// transport gap, reconstruction retirement, or codec refusal to `discontinuity`
/// before admitting subsequent NALs. The owner retains original datagrams outside
/// this derivative buffer. A picture group is not a decode/completeness certificate.
pub struct AvcAssembler {
    key: StreamKey,
    sps: AvcSps,
    pps: AvcPps,
    syntax: AvcSyntaxLimits,
    limits: AvcAssemblyLimits,
    pending: Option<Pending>,
    last_source_end: Option<(u64, usize)>,
    last_picture: Option<(AvcSliceIdentity, u32)>,
    last_now_ns: u64,
    discontinuity_before: bool,
    closed: bool,
}

impl std::fmt::Debug for AvcAssembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvcAssembler")
            .field("key", &self.key)
            .field("pending_bytes", &self.pending_bytes())
            .field("deadline", &self.next_wake_ns())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl AvcAssembler {
    /// Validate exact parameter binding and independent syntax/assembly limits.
    pub fn new(
        key: StreamKey,
        sps: AvcSps,
        pps: AvcPps,
        syntax: AvcSyntaxLimits,
        limits: AvcAssemblyLimits,
    ) -> Result<Self, AvcAssemblyError> {
        if key.ingress == 0 || key.generation == 0 {
            return Err(AvcAssemblyError::Configuration);
        }
        limits.validate()?;
        sps.check_limits(syntax).map_err(AvcAssemblyError::Syntax)?;
        if pps.nal_bytes().len() > syntax.max_parameter_set_bytes {
            return Err(AvcAssemblyError::Syntax(AvcError::Limit));
        }
        if !pps.binds(&sps) {
            return Err(AvcAssemblyError::Syntax(AvcError::ParameterSetMismatch));
        }
        Ok(Self {
            key,
            sps,
            pps,
            syntax,
            limits,
            pending: None,
            last_source_end: None,
            last_picture: None,
            last_now_ns: 0,
            discontinuity_before: false,
            closed: false,
        })
    }

    /// Current retained reconstructed bytes, independent of the source spool.
    pub fn pending_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.bytes)
    }
    /// Current retained complete NAL count.
    pub fn pending_nals(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.nals.len())
    }
    /// Timer wake remains due without another packet; duplicates do not extend it.
    pub fn next_wake_ns(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| {
            if p.end.is_some() {
                self.last_now_ns
            } else {
                p.deadline
            }
        })
    }

    /// Admit one owned NAL. Binding/time/order refusals leave state unchanged.
    /// Syntax, capacity, and configuration failures retire the affected pending
    /// derivative; the rejected NAL is returned intact, never dropped by this API.
    pub fn push(&mut self, nal: NalUnit, now_ns: u64) -> AvcAssemblyStep {
        if let Err(reason) = self.preflight(&nal, now_ns) {
            return AvcAssemblyStep::Refused(AvcAssemblyRefusal {
                reason,
                nal,
                retired: None,
            });
        }
        let incoming = match self.classify(&nal) {
            Ok(incoming) => incoming,
            Err(reason) => {
                let retirement = if reason == AvcAssemblyError::ConfigurationChanged {
                    self.closed = true;
                    AvcRetirementReason::ConfigurationChanged
                } else {
                    AvcRetirementReason::InvalidInput
                };
                self.last_now_ns = now_ns;
                self.discontinuity_before = true;
                let retired = self.retire(retirement);
                return AvcAssemblyStep::Refused(AvcAssemblyRefusal {
                    reason,
                    nal,
                    retired,
                });
            }
        };
        let expires = self.pending.as_ref().is_some_and(|p| now_ns >= p.deadline);
        let boundary = self.boundary(incoming);
        if let Incoming::Vcl(identity) = incoming {
            let repeats = self.pending.as_ref().is_none_or(|p| p.picture.is_none())
                && self.last_picture.is_some_and(|(previous, timestamp)| {
                    !identity.starts_new_picture(previous) && timestamp == nal.timestamp()
                });
            if repeats {
                self.last_now_ns = now_ns;
                self.discontinuity_before = true;
                let retired = self.retire(AvcRetirementReason::InvalidInput);
                return AvcAssemblyStep::Refused(AvcAssemblyRefusal {
                    reason: AvcAssemblyError::PictureAlreadyEmitted,
                    nal,
                    retired,
                });
            }
        }
        if let (Incoming::Vcl(identity), Some(pending)) = (incoming, &self.pending)
            && let Some((previous, timestamp)) = pending.picture
            && !expires
            && !identity.starts_new_picture(previous)
            && timestamp != nal.timestamp()
        {
            self.discontinuity_before = true;
            self.last_now_ns = now_ns;
            let retired = self.retire(AvcRetirementReason::InvalidInput);
            return AvcAssemblyStep::Refused(AvcAssemblyRefusal {
                reason: AvcAssemblyError::TimestampMismatch,
                nal,
                retired,
            });
        }
        let fresh = self.pending.is_none() || boundary.is_some() || expires;
        let prior_bytes = if fresh { 0 } else { self.pending_bytes() };
        let prior_nals = if fresh { 0 } else { self.pending_nals() };
        let total = prior_bytes.checked_add(nal.bytes().len());
        if prior_nals >= self.limits.max_nals
            || total.is_none_or(|n| n > self.limits.max_bytes)
            || (fresh && now_ns.checked_add(self.limits.max_age_ns).is_none())
        {
            return self.capacity_refusal(
                nal,
                now_ns,
                AvcAssemblyError::Limit,
                AvcRetirementReason::Limit,
            );
        }
        // Reserve metadata before taking any pending publication out of the state.
        let mut next = if fresh {
            let mut nals = Vec::new();
            if nals.try_reserve_exact(1).is_err() {
                return self.capacity_refusal(
                    nal,
                    now_ns,
                    AvcAssemblyError::Allocation,
                    AvcRetirementReason::Allocation,
                );
            }
            Some(Pending {
                nals,
                bytes: 0,
                picture: None,
                saw_first_mb: false,
                discontinuity_before: self.discontinuity_before || expires,
                deadline: now_ns + self.limits.max_age_ns,
                end: None,
            })
        } else {
            let allocation_failed = self.pending.as_mut().is_some_and(|p| {
                if p.nals.len() == p.nals.capacity() {
                    let target = (p.nals.len() + 1)
                        .saturating_mul(2)
                        .min(self.limits.max_nals);
                    p.nals.try_reserve_exact(target - p.nals.len()).is_err()
                } else {
                    false
                }
            });
            if allocation_failed {
                return self.capacity_refusal(
                    nal,
                    now_ns,
                    AvcAssemblyError::Allocation,
                    AvcRetirementReason::Allocation,
                );
            }
            None
        };
        self.last_now_ns = now_ns;
        let retired = if expires {
            self.retire(AvcRetirementReason::Deadline)
        } else {
            None
        };
        let mut picture = if !expires {
            boundary.and_then(|b| self.publish(b))
        } else {
            None
        };
        if let Some(pending) = next.take() {
            self.pending = Some(pending);
        }
        self.discontinuity_before = false;
        let marker = nal.marker();
        if let Some(span) = nal.sources().last() {
            self.last_source_end = Some((span.sequence, span.wire_range.end));
        }
        if let Some(pending) = &mut self.pending {
            pending.bytes += nal.bytes().len();
            if let Incoming::Vcl(identity) = incoming {
                if pending.picture.is_none() {
                    pending.picture = Some((identity, nal.timestamp()));
                }
                pending.saw_first_mb |= identity.first_mb_in_slice() == 0;
            }
            pending.nals.push(nal);
        }
        let end = match incoming {
            Incoming::EndSequence => Some(AvcBoundary::EndOfSequence),
            Incoming::EndStream => {
                self.closed = true;
                Some(AvcBoundary::EndOfStream)
            }
            _ if marker && self.pending.as_ref().is_some_and(|p| p.picture.is_some()) => {
                Some(AvcBoundary::RtpMarker)
            }
            _ => None,
        };
        // One input can close the prior picture AND carry a marked new picture.
        // Leave the latter pending: `poll` provides a bounded second step before further admission.
        if picture.is_none() {
            picture = end.and_then(|b| self.publish(b));
        }
        if let Some(pending) = &mut self.pending {
            pending.end = end;
        }
        AvcAssemblyStep::Accepted(AvcAssemblyOutput { picture, retired })
    }

    /// Perform one bounded progress step. A push may emit the previous picture
    /// while retaining a marked new one; poll drains that ready picture before
    /// the next NAL is admitted. Deadlines are honored even without new traffic.
    pub fn poll(&mut self, now_ns: u64) -> Result<AvcAssemblyPoll, AvcAssemblyError> {
        if let Some(retired) = self.expire(now_ns)? {
            return Ok(AvcAssemblyPoll::Retired(retired));
        }
        if let Some(end) = self.pending.as_ref().and_then(|p| p.end) {
            if let Some(picture) = self.publish(end) {
                return Ok(AvcAssemblyPoll::Picture(picture));
            }
            if let Some(retired) = self.retire(AvcRetirementReason::NoPrimaryPicture) {
                return Ok(AvcAssemblyPoll::Retired(retired));
            }
        }
        if self.closed {
            Ok(AvcAssemblyPoll::Ended)
        } else {
            Ok(AvcAssemblyPoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            })
        }
    }

    /// Retire timer-expired derivative state without any new input. Clock reversal
    /// is refused before mutation. A deadline is never moved by polling.
    pub fn expire(
        &mut self,
        now_ns: u64,
    ) -> Result<Option<AvcAssemblyRetirement>, AvcAssemblyError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.pending.as_ref().is_some_and(|p| now_ns >= p.deadline) {
            self.discontinuity_before = true;
            Ok(self.retire(AvcRetirementReason::Deadline))
        } else {
            Ok(None)
        }
    }

    /// Forward a transport gap/fragment retirement/codec refusal before the next
    /// NAL. This never fabricates an empty or partially decoded picture.
    pub fn discontinuity(
        &mut self,
        key: StreamKey,
        now_ns: u64,
    ) -> Result<Option<AvcAssemblyRetirement>, AvcAssemblyError> {
        if key != self.key {
            return Err(AvcAssemblyError::StreamMismatch);
        }
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        self.discontinuity_before = true;
        Ok(self.retire(AvcRetirementReason::InputDiscontinuity))
    }

    /// End input explicitly. A remaining VCL group is an *unverified tail*;
    /// metadata without a primary picture produces only a retirement receipt.
    pub fn finish(&mut self, now_ns: u64) -> Result<AvcAssemblyOutput, AvcAssemblyError> {
        let mut retired = self.expire(now_ns)?;
        self.closed = true;
        let picture = if self.pending.as_ref().is_some_and(|p| p.picture.is_some()) {
            let boundary = self
                .pending
                .as_ref()
                .and_then(|p| p.end)
                .unwrap_or(AvcBoundary::EndOfInputUnverified);
            self.publish(boundary)
        } else {
            retired = retired.or_else(|| self.retire(AvcRetirementReason::NoPrimaryPicture));
            None
        };
        Ok(AvcAssemblyOutput { picture, retired })
    }

    /// Cancel permanently. Previously emitted groups are not retracted or repeated.
    pub fn cancel(&mut self) -> Option<AvcAssemblyRetirement> {
        self.closed = true;
        self.retire(AvcRetirementReason::Cancelled)
    }

    /// Open a strictly newer owner epoch with an exact configuration, retiring the
    /// old derivative only after all new configuration checks succeed.
    pub fn restart(
        &mut self,
        key: StreamKey,
        sps: AvcSps,
        pps: AvcPps,
    ) -> Result<(Self, Option<AvcAssemblyRetirement>), AvcAssemblyError> {
        if key.ingress != self.key.ingress {
            return Err(AvcAssemblyError::StreamMismatch);
        }
        if key.generation <= self.key.generation {
            return Err(AvcAssemblyError::GenerationRequired);
        }
        let next = Self::new(key, sps, pps, self.syntax, self.limits)?;
        self.closed = true;
        Ok((next, self.retire(AvcRetirementReason::Restarted)))
    }

    fn check_time(&self, now_ns: u64) -> Result<(), AvcAssemblyError> {
        if now_ns < self.last_now_ns {
            return Err(AvcAssemblyError::ClockReversed);
        }
        Ok(())
    }

    fn preflight(&self, nal: &NalUnit, now_ns: u64) -> Result<(), AvcAssemblyError> {
        if nal.key() != self.key {
            return Err(AvcAssemblyError::StreamMismatch);
        }
        if self.closed {
            return Err(AvcAssemblyError::Closed);
        }
        self.check_time(now_ns)?;
        if self.pending.as_ref().is_some_and(|p| p.end.is_some()) {
            return Err(AvcAssemblyError::OutputPending);
        }
        let first = nal.sources().first().ok_or(AvcAssemblyError::SourceOrder)?;
        if self.last_source_end.is_some_and(|(sequence, end)| {
            first.sequence < sequence
                || (first.sequence == sequence && first.wire_range.start < end)
        }) {
            return Err(AvcAssemblyError::SourceOrder);
        }
        Ok(())
    }

    fn classify(&self, nal: &NalUnit) -> Result<Incoming, AvcAssemblyError> {
        let bytes = nal.bytes();
        if bytes.len() > self.syntax.max_nal_bytes {
            return Err(AvcAssemblyError::Syntax(AvcError::Limit));
        }
        let syntax = |e| AvcAssemblyError::Syntax(e);
        match nal.nal_type() {
            1 | 5 => {
                let identity = parse_slice_identity(bytes, &self.sps, &self.pps, self.syntax)
                    .map_err(syntax)?;
                if identity.redundant_pic_cnt() != 0 {
                    return Err(syntax(AvcError::UnsupportedPicture));
                }
                Ok(Incoming::Vcl(identity))
            }
            7 if bytes == self.sps.nal_bytes() => Ok(Incoming::Prefix),
            8 if bytes == self.pps.nal_bytes() => Ok(Incoming::Prefix),
            7 | 8 => Err(AvcAssemblyError::ConfigurationChanged),
            6 | 9..=12 => {
                if bytes[0] & 0x60 != 0 {
                    return Err(syntax(AvcError::Malformed));
                }
                match nal.nal_type() {
                    6 if bytes.len() >= 2 => Ok(Incoming::Prefix), // SEI body is retained opaque, not interpreted.
                    9 if bytes.len() == 2 && bytes[1] & 31 == 16 => Ok(Incoming::Prefix),
                    10 if bytes == [10, 0x80] => Ok(Incoming::EndSequence),
                    11 if bytes == [11, 0x80] => Ok(Incoming::EndStream),
                    12 if bytes.len() >= 2
                        && bytes.last() == Some(&0x80)
                        && bytes[1..bytes.len() - 1].iter().all(|b| *b == 0xff) =>
                    {
                        Ok(Incoming::Suffix)
                    }
                    _ => Err(syntax(AvcError::Malformed)),
                }
            }
            _ => Err(syntax(AvcError::UnsupportedPicture)),
        }
    }

    fn boundary(&self, incoming: Incoming) -> Option<AvcBoundary> {
        let (previous, _) = self.pending.as_ref()?.picture?;
        match incoming {
            Incoming::Prefix => Some(AvcBoundary::NextAccessUnitPrefix),
            Incoming::Vcl(identity) if identity.starts_new_picture(previous) => {
                Some(AvcBoundary::NextPrimaryPicture)
            }
            _ => None,
        }
    }

    fn capacity_refusal(
        &mut self,
        nal: NalUnit,
        now_ns: u64,
        reason: AvcAssemblyError,
        cause: AvcRetirementReason,
    ) -> AvcAssemblyStep {
        self.last_now_ns = now_ns;
        self.discontinuity_before = true;
        let retired = self.retire(cause);
        AvcAssemblyStep::Refused(AvcAssemblyRefusal {
            reason,
            nal,
            retired,
        })
    }

    fn retire(&mut self, reason: AvcRetirementReason) -> Option<AvcAssemblyRetirement> {
        let pending = self.pending.take()?;
        Some(AvcAssemblyRetirement {
            key: self.key,
            reason,
            nals: pending.nals.len(),
            bytes: pending.bytes,
            first_sequence: pending
                .nals
                .first()
                .and_then(|n| n.sources().first())
                .map(|s| s.sequence),
            last_sequence: pending
                .nals
                .last()
                .and_then(|n| n.sources().last())
                .map(|s| s.sequence),
        })
    }

    fn publish(&mut self, boundary: AvcBoundary) -> Option<AvcPictureGroup> {
        let (identity, timestamp) = self.pending.as_ref()?.picture?;
        let pending = self.pending.take()?;
        self.last_picture = Some((identity, timestamp));
        Some(AvcPictureGroup {
            key: self.key,
            sps: self.sps.clone(),
            pps: self.pps.clone(),
            identity,
            timestamp,
            nals: pending.nals,
            byte_len: pending.bytes,
            boundary,
            saw_first_mb: pending.saw_first_mb,
            discontinuity_before: pending.discontinuity_before,
        })
    }
}
