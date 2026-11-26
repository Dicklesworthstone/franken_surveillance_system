#![forbid(unsafe_code)]
//! Deterministic, bounded keyframe-aware media chunker (`FSS-056`, bead `fss-x4a.12.5`).
//!
//! Groups ordered media samples into random-access chunks that strictly begin on an observed
//! keyframe (`IDR`/`IRAP`), preserving exact source byte spans, monotonic DTS discipline,
//! explicit pre-sync discard accounting, gap-interruption quarantine, and content-addressed
//! canonical chunk receipts (`INV-003`, `INV-040`, `INV-041`).
//!
//! Core invariants:
//! - Every sealed [`KeyframeChunk`] strictly begins on an observed keyframe; leading P/B frames
//!   before initial sync or after a gap are counted explicitly in `pre_sync_discarded_samples`
//!   and never emitted as broken non-random-access chunks.
//! - An open GOP that exceeds `max_duration_ns`, `max_chunk_bytes`, or `max_samples_per_chunk`
//!   without a fresh keyframe fails closed with [`ChunkerError::OpenGopExceededBounds`] rather
//!   than silently splitting mid-GOP.
//! - Gaps explicitly seal any open partial chunk with [`ChunkSealReason::GapInterrupt`]
//!   (`is_complete_gop = false`) and reset sync until the next keyframe arrives.
//! - Zero `unsafe`, zero `.expect()`, zero ambient I/O or clocks, and cooperative cancellation
//!   before mutating chunker state.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation,
};

/// Registered digest domain for canonical keyframe chunk receipts
/// (`SCHEMA-DOMAIN-CONTAINER-KEYFRAME-CHUNKER-001`).
pub const KEYFRAME_CHUNK_RECEIPT_DOMAIN: &str = "fss.container.keyframe_chunk_receipt.v1";

/// Canonical binary format version for [`KeyframeChunk`].
pub const KEYFRAME_CHUNK_FORMAT_VERSION: u32 = 1;

/// Maximum samples permitted in a single chunker policy ceiling.
pub const MAX_CHUNKER_SAMPLES: usize = 16_384;

/// Maximum chunk byte size permitted in a single chunker policy ceiling (128 MiB).
pub const MAX_CHUNKER_BYTES: usize = 128 * 1024 * 1024;

/// Hard policy governing one [`KeyframeChunker`] instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyframeChunkerPolicy {
    /// Clean non-empty stream/camera identifier.
    pub stream_id: String,
    /// Immutable active stream generation (`!= 0`).
    pub stream_generation: Generation,
    /// Target GOP chunk duration in nanoseconds (seals on next keyframe once reached).
    pub target_duration_ns: u64,
    /// Hard maximum open-GOP duration before failing closed.
    pub max_duration_ns: u64,
    /// Hard maximum payload bytes per chunk.
    pub max_chunk_bytes: usize,
    /// Hard maximum sample count per chunk.
    pub max_samples_per_chunk: usize,
    /// Maximum pre-sync non-keyframe bytes discarded while awaiting an IDR before failing closed.
    pub max_pre_sync_discard_bytes: usize,
}

impl KeyframeChunkerPolicy {
    /// Returns a bounded default 2s target / 10s max policy for `stream_id`.
    #[must_use]
    pub fn bounded_default(stream_id: impl Into<String>, stream_generation: Generation) -> Self {
        Self {
            stream_id: stream_id.into(),
            stream_generation,
            target_duration_ns: 2_000_000_000,
            max_duration_ns: 10_000_000_000,
            max_chunk_bytes: 16 * 1024 * 1024,
            max_samples_per_chunk: 600,
            max_pre_sync_discard_bytes: 4 * 1024 * 1024,
        }
    }

    /// Fails closed on zero, inverted, or out-of-range bounds without silently clamping.
    pub fn validate(&self) -> Result<(), ChunkerError> {
        if self.stream_id.is_empty()
            || self.stream_id.len() > 256
            || self
                .stream_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ChunkerError::InvalidPolicy);
        }
        if self.stream_generation.0 == 0
            || self.target_duration_ns == 0
            || self.max_duration_ns < self.target_duration_ns
            || self.max_chunk_bytes == 0
            || self.max_chunk_bytes > MAX_CHUNKER_BYTES
            || self.max_samples_per_chunk == 0
            || self.max_samples_per_chunk > MAX_CHUNKER_SAMPLES
            || self.max_pre_sync_discard_bytes == 0
            || self.max_pre_sync_discard_bytes > MAX_CHUNKER_BYTES
        {
            return Err(ChunkerError::InvalidPolicy);
        }
        Ok(())
    }
}

/// One ordered encoded access unit submitted to [`KeyframeChunker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkSampleInput {
    /// Strictly increasing stream sample sequence number.
    pub sample_seq: u64,
    /// Presentation timestamp in nanoseconds.
    pub pts_ns: i128,
    /// Monotonically non-decreasing decode timestamp in nanoseconds.
    pub dts_ns: i128,
    /// Positive sample duration in nanoseconds.
    pub duration_ns: u64,
    /// `true` iff this sample is a verified random-access keyframe (`IDR`/`IRAP`).
    pub is_keyframe: bool,
    /// Source custody byte offset of this access unit.
    pub source_byte_offset: u64,
    /// Positive encoded payload byte length.
    pub source_byte_len: u64,
    /// Content digest of the encoded sample bytes.
    pub payload_digest: ContentDigest,
    /// Stream generation bound to this sample.
    pub generation: Generation,
}

/// Exact reason why a [`KeyframeChunk`] was sealed; never conflates clean GOP boundaries with gaps.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChunkSealReason {
    /// Sealed cleanly on an incoming keyframe after meeting `target_duration_ns`.
    TargetDurationKeyframeBoundary,
    /// Sealed cleanly on an incoming keyframe before exceeding `max_chunk_bytes`.
    ByteCapKeyframeBoundary,
    /// Sealed cleanly on an incoming keyframe before exceeding `max_samples_per_chunk`.
    SampleCapKeyframeBoundary,
    /// Explicitly flushed at stream shutdown or operator request.
    ExplicitFlush,
    /// Sealed due to an explicit upstream discontinuity/gap (`is_complete_gop = false`).
    GapInterrupt,
}

impl ChunkSealReason {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetDurationKeyframeBoundary => "target_duration_keyframe_boundary",
            Self::ByteCapKeyframeBoundary => "byte_cap_keyframe_boundary",
            Self::SampleCapKeyframeBoundary => "sample_cap_keyframe_boundary",
            Self::ExplicitFlush => "explicit_flush",
            Self::GapInterrupt => "gap_interrupt",
        }
    }
}

impl CanonicalEncode for ChunkSealReason {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::TargetDurationKeyframeBoundary => 1,
            Self::ByteCapKeyframeBoundary => 2,
            Self::SampleCapKeyframeBoundary => 3,
            Self::ExplicitFlush => 4,
            Self::GapInterrupt => 5,
        });
    }
}

impl CanonicalDecode for ChunkSealReason {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::TargetDurationKeyframeBoundary),
            2 => Ok(Self::ByteCapKeyframeBoundary),
            3 => Ok(Self::SampleCapKeyframeBoundary),
            4 => Ok(Self::ExplicitFlush),
            5 => Ok(Self::GapInterrupt),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed fail-closed refusal for [`KeyframeChunker`] operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkerError {
    /// Policy bounds or stream identity are invalid.
    InvalidPolicy,
    /// Sample carried zero duration, zero byte length, or overflowing source span.
    InvalidSample(&'static str),
    /// Sample generation disagrees with chunker's pinned stream generation.
    GenerationMismatch {
        /// Expected pinned generation.
        expected: Generation,
        /// Actual sample generation.
        actual: Generation,
    },
    /// Sample sequence regressed or duplicated a previously admitted sample.
    NonMonotonicSequence {
        /// Last admitted sequence number.
        previous: u64,
        /// Rejected sequence number.
        actual: u64,
    },
    /// Decode timestamp regressed below the prior sample's DTS.
    DtsRegression {
        /// Last admitted DTS.
        previous_dts_ns: i128,
        /// Rejected DTS.
        actual_dts_ns: i128,
    },
    /// A single sample alone exceeds `max_chunk_bytes` or `max_duration_ns`.
    SingleSampleExceedsBounds,
    /// Leading non-keyframe bytes exceeded `max_pre_sync_discard_bytes` with no keyframe observed.
    PreSyncBudgetExceeded {
        /// Total pre-sync discarded bytes.
        discarded_bytes: usize,
        /// Configured ceiling.
        max_bytes: usize,
    },
    /// Active GOP exceeded duration/byte/sample limits without producing a fresh keyframe.
    OpenGopExceededBounds(&'static str),
    /// Checked arithmetic overflowed.
    ArithmeticOverflow,
    /// Cooperative cancellation observed before mutating state.
    Cancelled,
}

impl fmt::Display for ChunkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid keyframe chunker policy"),
            Self::InvalidSample(why) => write!(f, "invalid chunk sample: {why}"),
            Self::GenerationMismatch { expected, actual } => write!(
                f,
                "chunk sample generation mismatch: expected {}, got {}",
                expected.0, actual.0
            ),
            Self::NonMonotonicSequence { previous, actual } => {
                write!(f, "non-monotonic sample sequence ({actual} <= {previous})")
            }
            Self::DtsRegression {
                previous_dts_ns,
                actual_dts_ns,
            } => write!(
                f,
                "decode timestamp regression ({actual_dts_ns} < {previous_dts_ns})"
            ),
            Self::SingleSampleExceedsBounds => {
                write!(f, "single media sample exceeds chunker hard bounds")
            }
            Self::PreSyncBudgetExceeded {
                discarded_bytes,
                max_bytes,
            } => write!(
                f,
                "pre-sync non-keyframe discard budget exceeded ({discarded_bytes} > {max_bytes})"
            ),
            Self::OpenGopExceededBounds(limit) => {
                write!(f, "open GOP exceeded {limit} without a keyframe boundary")
            }
            Self::ArithmeticOverflow => write!(f, "keyframe chunker arithmetic overflow"),
            Self::Cancelled => write!(f, "keyframe chunker operation cancelled"),
        }
    }
}

impl std::error::Error for ChunkerError {}

/// Immutable, canonical, content-addressed receipt of one keyframe-aligned media chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyframeChunk {
    /// Format version (`KEYFRAME_CHUNK_FORMAT_VERSION`).
    pub format_version: u32,
    /// Owning stream identifier.
    pub stream_id: String,
    /// Monotonic 1-based chunk index within this chunker epoch.
    pub chunk_index: u64,
    /// Pinned stream generation.
    pub generation: Generation,
    /// Always `true`: every sealed chunk starts on an observed random-access keyframe.
    pub starts_with_keyframe: bool,
    /// `true` for clean keyframe-bounded GOP closure; `false` on gap interrupt or explicit partial flush.
    pub is_complete_gop: bool,
    /// Exact seal reason.
    pub seal_reason: ChunkSealReason,
    /// First sample sequence number inside this chunk.
    pub first_sample_seq: u64,
    /// Last sample sequence number inside this chunk.
    pub last_sample_seq: u64,
    /// Exact number of samples in this chunk (`>= 1`).
    pub sample_count: u64,
    /// Exact number of keyframes contained in this chunk (`>= 1`).
    pub keyframe_count: u64,
    /// First DTS in nanoseconds.
    pub first_dts_ns: i128,
    /// Last DTS in nanoseconds.
    pub last_dts_ns: i128,
    /// Minimum presentation timestamp across samples in this chunk.
    pub min_pts_ns: i128,
    /// Maximum presentation timestamp across samples in this chunk.
    pub max_pts_ns: i128,
    /// Sum of sample durations in nanoseconds.
    pub total_duration_ns: u64,
    /// Sum of encoded payload bytes in this chunk.
    pub total_bytes: u64,
    /// First sample source custody byte offset.
    pub first_source_offset: u64,
    /// Exclusive end byte offset (`offset + len`) of the last sample.
    pub last_source_end_offset: u64,
    /// Rolling chain digest binding every ordered `(sample_seq, pts_ns, dts_ns, payload_digest)`.
    pub sample_chain_digest: ContentDigest,
    /// Number of leading pre-sync non-keyframe samples discarded prior to opening this chunk.
    pub pre_sync_discarded_samples: u64,
    /// Domain-separated SHA-256 digest over all fields above.
    pub chunk_digest: ContentDigest,
}

impl KeyframeChunk {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(KEYFRAME_CHUNK_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.stream_id);
        encoder.u64(self.chunk_index);
        encoder.u64(self.generation.0);
        encoder.u8(u8::from(self.starts_with_keyframe));
        encoder.u8(u8::from(self.is_complete_gop));
        self.seal_reason.encode_canonical(&mut encoder);
        encoder.u64(self.first_sample_seq);
        encoder.u64(self.last_sample_seq);
        encoder.u64(self.sample_count);
        encoder.u64(self.keyframe_count);
        encoder.i128(self.first_dts_ns);
        encoder.i128(self.last_dts_ns);
        encoder.i128(self.min_pts_ns);
        encoder.i128(self.max_pts_ns);
        encoder.u64(self.total_duration_ns);
        encoder.u64(self.total_bytes);
        encoder.u64(self.first_source_offset);
        encoder.u64(self.last_source_end_offset);
        encoder.digest(self.sample_chain_digest);
        encoder.u64(self.pre_sync_discarded_samples);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `chunk_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.chunk_digest == self.computed_digest()
    }
}

impl CanonicalEncode for KeyframeChunk {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.stream_id);
        encoder.u64(self.chunk_index);
        encoder.u64(self.generation.0);
        encoder.u8(u8::from(self.starts_with_keyframe));
        encoder.u8(u8::from(self.is_complete_gop));
        self.seal_reason.encode_canonical(encoder);
        encoder.u64(self.first_sample_seq);
        encoder.u64(self.last_sample_seq);
        encoder.u64(self.sample_count);
        encoder.u64(self.keyframe_count);
        encoder.i128(self.first_dts_ns);
        encoder.i128(self.last_dts_ns);
        encoder.i128(self.min_pts_ns);
        encoder.i128(self.max_pts_ns);
        encoder.u64(self.total_duration_ns);
        encoder.u64(self.total_bytes);
        encoder.u64(self.first_source_offset);
        encoder.u64(self.last_source_end_offset);
        encoder.digest(self.sample_chain_digest);
        encoder.u64(self.pre_sync_discarded_samples);
        encoder.digest(self.chunk_digest);
    }
}

fn decode_bool(decoder: &mut CanonicalDecoder<'_>) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl CanonicalDecode for KeyframeChunk {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != KEYFRAME_CHUNK_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let stream_id = decoder.text()?.to_owned();
        if stream_id.is_empty()
            || stream_id.len() > 256
            || stream_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let chunk_index = decoder.u64()?;
        let generation = Generation(decoder.u64()?);
        let starts_with_keyframe = decode_bool(decoder)?;
        let is_complete_gop = decode_bool(decoder)?;
        let seal_reason = ChunkSealReason::decode_canonical(decoder)?;
        let first_sample_seq = decoder.u64()?;
        let last_sample_seq = decoder.u64()?;
        let sample_count = decoder.u64()?;
        let keyframe_count = decoder.u64()?;
        let first_dts_ns = decoder.i128()?;
        let last_dts_ns = decoder.i128()?;
        let min_pts_ns = decoder.i128()?;
        let max_pts_ns = decoder.i128()?;
        let total_duration_ns = decoder.u64()?;
        let total_bytes = decoder.u64()?;
        let first_source_offset = decoder.u64()?;
        let last_source_end_offset = decoder.u64()?;
        let sample_chain_digest = decoder.digest()?;
        let pre_sync_discarded_samples = decoder.u64()?;
        let chunk_digest = decoder.digest()?;

        // Structural chunk invariants enforced fail-closed even against forged SHA-256 payloads.
        if chunk_index == 0
            || generation.0 == 0
            || !starts_with_keyframe
            || sample_count == 0
            || keyframe_count == 0
            || keyframe_count > sample_count
            || last_sample_seq < first_sample_seq
            || last_sample_seq - first_sample_seq < sample_count - 1
            || last_dts_ns < first_dts_ns
            || max_pts_ns < min_pts_ns
            || total_duration_ns == 0
            || total_bytes == 0
            || (seal_reason == ChunkSealReason::GapInterrupt && is_complete_gop)
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let chunk = Self {
            format_version,
            stream_id,
            chunk_index,
            generation,
            starts_with_keyframe,
            is_complete_gop,
            seal_reason,
            first_sample_seq,
            last_sample_seq,
            sample_count,
            keyframe_count,
            first_dts_ns,
            last_dts_ns,
            min_pts_ns,
            max_pts_ns,
            total_duration_ns,
            total_bytes,
            first_source_offset,
            last_source_end_offset,
            sample_chain_digest,
            pre_sync_discarded_samples,
            chunk_digest,
        };
        if !chunk.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(chunk)
    }
}

#[derive(Clone, Debug)]
struct OpenChunk {
    first_sample_seq: u64,
    last_sample_seq: u64,
    sample_count: u64,
    keyframe_count: u64,
    first_dts_ns: i128,
    last_dts_ns: i128,
    min_pts_ns: i128,
    max_pts_ns: i128,
    total_duration_ns: u64,
    total_bytes: usize,
    first_source_offset: u64,
    last_source_end_offset: u64,
    sample_chain_digest: ContentDigest,
    pre_sync_discarded_samples: u64,
}

fn chain_sample_digest(prev: ContentDigest, sample: &ChunkSampleInput) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.digest(prev);
    enc.u64(sample.sample_seq);
    enc.i128(sample.pts_ns);
    enc.i128(sample.dts_ns);
    enc.u64(sample.duration_ns);
    enc.u8(u8::from(sample.is_keyframe));
    enc.u64(sample.source_byte_offset);
    enc.u64(sample.source_byte_len);
    enc.digest(sample.payload_digest);
    ContentDigest::sha256(&enc.finish())
}

/// Deterministic, bounded keyframe-aligned stream chunker.
#[derive(Clone, Debug)]
pub struct KeyframeChunker {
    policy: KeyframeChunkerPolicy,
    next_chunk_index: u64,
    last_seen_seq: Option<u64>,
    last_seen_dts_ns: Option<i128>,
    total_pre_sync_discarded_samples: u64,
    pending_pre_sync_discarded_samples: u64,
    pre_sync_discarded_bytes: usize,
    open: Option<OpenChunk>,
}

impl KeyframeChunker {
    /// Creates a new chunker after validating all hard bounds.
    pub fn new(policy: KeyframeChunkerPolicy) -> Result<Self, ChunkerError> {
        policy.validate()?;
        Ok(Self {
            policy,
            next_chunk_index: 1,
            last_seen_seq: None,
            last_seen_dts_ns: None,
            total_pre_sync_discarded_samples: 0,
            pending_pre_sync_discarded_samples: 0,
            pre_sync_discarded_bytes: 0,
            open: None,
        })
    }

    /// Returns cumulative leading non-keyframe samples discarded while waiting for random access.
    #[must_use]
    pub const fn pre_sync_discarded_samples(&self) -> u64 {
        self.total_pre_sync_discarded_samples
    }

    /// Returns `true` if a keyframe-aligned chunk is currently open and accumulating samples.
    #[must_use]
    pub const fn has_open_chunk(&self) -> bool {
        self.open.is_some()
    }

    /// Admits one ordered media sample, returning `Some(KeyframeChunk)` whenever an existing
    /// chunk seals cleanly on a keyframe boundary.
    pub fn push_sample(
        &mut self,
        sample: ChunkSampleInput,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Option<KeyframeChunk>, ChunkerError> {
        if is_cancelled() {
            return Err(ChunkerError::Cancelled);
        }
        if sample.generation != self.policy.stream_generation {
            return Err(ChunkerError::GenerationMismatch {
                expected: self.policy.stream_generation,
                actual: sample.generation,
            });
        }
        if sample.duration_ns == 0 {
            return Err(ChunkerError::InvalidSample("zero_duration"));
        }
        if sample.source_byte_len == 0 {
            return Err(ChunkerError::InvalidSample("zero_byte_len"));
        }
        let sample_end_offset = sample
            .source_byte_offset
            .checked_add(sample.source_byte_len)
            .ok_or(ChunkerError::ArithmeticOverflow)?;
        let sample_bytes = usize::try_from(sample.source_byte_len)
            .map_err(|_| ChunkerError::ArithmeticOverflow)?;
        if sample_bytes > self.policy.max_chunk_bytes
            || sample.duration_ns > self.policy.max_duration_ns
        {
            return Err(ChunkerError::SingleSampleExceedsBounds);
        }
        if let Some(prev_seq) = self.last_seen_seq
            && sample.sample_seq <= prev_seq
        {
            return Err(ChunkerError::NonMonotonicSequence {
                previous: prev_seq,
                actual: sample.sample_seq,
            });
        }
        if let Some(prev_dts) = self.last_seen_dts_ns
            && sample.dts_ns < prev_dts
        {
            return Err(ChunkerError::DtsRegression {
                previous_dts_ns: prev_dts,
                actual_dts_ns: sample.dts_ns,
            });
        }

        // Pre-sync phase: wait for an observed random-access keyframe without emitting broken chunks.
        if self.open.is_none() && !sample.is_keyframe {
            let next_discard_bytes = self
                .pre_sync_discarded_bytes
                .checked_add(sample_bytes)
                .ok_or(ChunkerError::ArithmeticOverflow)?;
            if next_discard_bytes > self.policy.max_pre_sync_discard_bytes {
                return Err(ChunkerError::PreSyncBudgetExceeded {
                    discarded_bytes: next_discard_bytes,
                    max_bytes: self.policy.max_pre_sync_discard_bytes,
                });
            }
            if is_cancelled() {
                return Err(ChunkerError::Cancelled);
            }
            self.last_seen_seq = Some(sample.sample_seq);
            self.last_seen_dts_ns = Some(sample.dts_ns);
            self.total_pre_sync_discarded_samples =
                self.total_pre_sync_discarded_samples.saturating_add(1);
            self.pending_pre_sync_discarded_samples =
                self.pending_pre_sync_discarded_samples.saturating_add(1);
            self.pre_sync_discarded_bytes = next_discard_bytes;
            return Ok(None);
        }

        // Decide whether an existing open chunk should seal or extend.
        let mut sealed: Option<KeyframeChunk> = None;
        if let Some(open) = &self.open {
            let next_bytes = open
                .total_bytes
                .checked_add(sample_bytes)
                .ok_or(ChunkerError::ArithmeticOverflow)?;
            let next_duration = open
                .total_duration_ns
                .checked_add(sample.duration_ns)
                .ok_or(ChunkerError::ArithmeticOverflow)?;
            let next_samples = open
                .sample_count
                .checked_add(1)
                .ok_or(ChunkerError::ArithmeticOverflow)?;

            if sample.is_keyframe {
                let seal_reason = if open.total_duration_ns >= self.policy.target_duration_ns
                    || next_duration > self.policy.max_duration_ns
                {
                    Some(ChunkSealReason::TargetDurationKeyframeBoundary)
                } else if next_bytes > self.policy.max_chunk_bytes {
                    Some(ChunkSealReason::ByteCapKeyframeBoundary)
                } else if next_samples > self.policy.max_samples_per_chunk as u64 {
                    Some(ChunkSealReason::SampleCapKeyframeBoundary)
                } else {
                    None
                };

                if is_cancelled() {
                    return Err(ChunkerError::Cancelled);
                }
                if let Some(reason) = seal_reason {
                    if let Some(prev_open) = self.open.take() {
                        sealed = Some(self.finalize_chunk(prev_open, reason, true)?);
                    }
                    self.open =
                        Some(self.start_open_chunk(&sample, sample_bytes, sample_end_offset));
                } else if let Some(active) = self.open.as_mut() {
                    Self::append_to_open(
                        active,
                        &sample,
                        next_bytes,
                        next_duration,
                        next_samples,
                        sample_end_offset,
                    );
                }
            } else {
                // Non-keyframe sample cannot split mid-GOP; enforce strict open-GOP hard caps.
                if next_duration > self.policy.max_duration_ns {
                    return Err(ChunkerError::OpenGopExceededBounds("max_duration_ns"));
                }
                if next_bytes > self.policy.max_chunk_bytes {
                    return Err(ChunkerError::OpenGopExceededBounds("max_chunk_bytes"));
                }
                if next_samples > self.policy.max_samples_per_chunk as u64 {
                    return Err(ChunkerError::OpenGopExceededBounds("max_samples_per_chunk"));
                }
                if is_cancelled() {
                    return Err(ChunkerError::Cancelled);
                }
                if let Some(active) = self.open.as_mut() {
                    Self::append_to_open(
                        active,
                        &sample,
                        next_bytes,
                        next_duration,
                        next_samples,
                        sample_end_offset,
                    );
                }
            }
        } else {
            // Opening first chunk after sync on a verified keyframe.
            if is_cancelled() {
                return Err(ChunkerError::Cancelled);
            }
            self.open = Some(self.start_open_chunk(&sample, sample_bytes, sample_end_offset));
        }

        self.last_seen_seq = Some(sample.sample_seq);
        self.last_seen_dts_ns = Some(sample.dts_ns);
        Ok(sealed)
    }

    /// Records an upstream transport/media gap: seals any open partial chunk with
    /// [`ChunkSealReason::GapInterrupt`] (`is_complete_gop = false`) and resets sync so the
    /// chunker requires a fresh keyframe before opening the next chunk.
    pub fn record_gap(&mut self) -> Result<Option<KeyframeChunk>, ChunkerError> {
        self.pre_sync_discarded_bytes = 0;
        if let Some(open) = self.open.take() {
            Ok(Some(self.finalize_chunk(
                open,
                ChunkSealReason::GapInterrupt,
                false,
            )?))
        } else {
            Ok(None)
        }
    }

    /// Explicitly seals any open chunk at stream end (`ChunkSealReason::ExplicitFlush`).
    pub fn flush(&mut self) -> Result<Option<KeyframeChunk>, ChunkerError> {
        if let Some(open) = self.open.take() {
            Ok(Some(self.finalize_chunk(
                open,
                ChunkSealReason::ExplicitFlush,
                false,
            )?))
        } else {
            Ok(None)
        }
    }

    fn start_open_chunk(
        &mut self,
        sample: &ChunkSampleInput,
        sample_bytes: usize,
        sample_end_offset: u64,
    ) -> OpenChunk {
        // Consume per-chunk pre-sync discard count so subsequent chunks never double-count.
        let discarded = self.pending_pre_sync_discarded_samples;
        self.pending_pre_sync_discarded_samples = 0;
        self.pre_sync_discarded_bytes = 0;
        OpenChunk {
            first_sample_seq: sample.sample_seq,
            last_sample_seq: sample.sample_seq,
            sample_count: 1,
            keyframe_count: 1,
            first_dts_ns: sample.dts_ns,
            last_dts_ns: sample.dts_ns,
            min_pts_ns: sample.pts_ns,
            max_pts_ns: sample.pts_ns,
            total_duration_ns: sample.duration_ns,
            total_bytes: sample_bytes,
            first_source_offset: sample.source_byte_offset,
            last_source_end_offset: sample_end_offset,
            sample_chain_digest: chain_sample_digest(
                ContentDigest::sha256(b"chunk-genesis"),
                sample,
            ),
            pre_sync_discarded_samples: discarded,
        }
    }

    fn append_to_open(
        open: &mut OpenChunk,
        sample: &ChunkSampleInput,
        next_bytes: usize,
        next_duration: u64,
        next_samples: u64,
        sample_end_offset: u64,
    ) {
        open.last_sample_seq = sample.sample_seq;
        open.sample_count = next_samples;
        if sample.is_keyframe {
            open.keyframe_count = open.keyframe_count.saturating_add(1);
        }
        open.last_dts_ns = sample.dts_ns;
        open.min_pts_ns = open.min_pts_ns.min(sample.pts_ns);
        open.max_pts_ns = open.max_pts_ns.max(sample.pts_ns);
        open.total_duration_ns = next_duration;
        open.total_bytes = next_bytes;
        open.last_source_end_offset = sample_end_offset;
        open.sample_chain_digest = chain_sample_digest(open.sample_chain_digest, sample);
    }

    fn finalize_chunk(
        &mut self,
        open: OpenChunk,
        seal_reason: ChunkSealReason,
        is_complete_gop: bool,
    ) -> Result<KeyframeChunk, ChunkerError> {
        let chunk_index = self.next_chunk_index;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(ChunkerError::ArithmeticOverflow)?;
        let mut chunk = KeyframeChunk {
            format_version: KEYFRAME_CHUNK_FORMAT_VERSION,
            stream_id: self.policy.stream_id.clone(),
            chunk_index,
            generation: self.policy.stream_generation,
            starts_with_keyframe: true,
            is_complete_gop,
            seal_reason,
            first_sample_seq: open.first_sample_seq,
            last_sample_seq: open.last_sample_seq,
            sample_count: open.sample_count,
            keyframe_count: open.keyframe_count,
            first_dts_ns: open.first_dts_ns,
            last_dts_ns: open.last_dts_ns,
            min_pts_ns: open.min_pts_ns,
            max_pts_ns: open.max_pts_ns,
            total_duration_ns: open.total_duration_ns,
            total_bytes: open.total_bytes as u64,
            first_source_offset: open.first_source_offset,
            last_source_end_offset: open.last_source_end_offset,
            sample_chain_digest: open.sample_chain_digest,
            pre_sync_discarded_samples: open.pre_sync_discarded_samples,
            chunk_digest: ContentDigest::sha256(b"pending"),
        };
        chunk.chunk_digest = chunk.computed_digest();
        Ok(chunk)
    }
}
