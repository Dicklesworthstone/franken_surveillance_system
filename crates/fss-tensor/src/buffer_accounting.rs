#![forbid(unsafe_code)]
//! Deterministic, sans-IO decoded-frame and tensor buffer accounting (`FSS-058`, bead `fss-x4a.12.7`).
//!
//! Tracks exact aligned memory reservations, per-class ceilings (`DecodedFrame`,
//! `TensorWorkspace`, `StagingScratch`), per-generation and per-owner live balances, peak
//! resident watermarks, pressure tiers, generation revocation fences, and content-addressed
//! accounting snapshots.
//!
//! Core invariants:
//! - Checked arithmetic everywhere; hostile sizes or alignments never wrap or panic.
//! - Zero global singletons, locks, or ambient clocks; every `BufferAccountant` instance owns
//!   its own deterministic monotonic reservation counter and exact state.
//! - Cooperative cancellation and budget/slot/generation refusals leave live balances untouched.
//! - Revoking a generation immediately blocks future reservations for that generation while
//!   preserving exact live byte accounting for already-admitted buffers until explicitly released.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::storage::MAX_STORAGE_BYTES;

/// Registered digest domain for canonical buffer accounting snapshots
/// (`SCHEMA-DOMAIN-TENSOR-BUFFER-ACCOUNTING-001`).
pub const BUFFER_ACCOUNTING_SNAPSHOT_DOMAIN: &str = "fss.tensor.buffer_accounting_snapshot.v1";

/// Canonical binary format version for [`BufferAccountingSnapshot`].
pub const BUFFER_ACCOUNTING_FORMAT_VERSION: u32 = 1;

/// Maximum configurable aggregate byte cap per accountant instance (4 GiB).
pub const MAX_ACCOUNTANT_TOTAL_BYTES: usize = MAX_STORAGE_BYTES * 16;

/// Maximum configurable live buffer slot ceiling per accountant instance.
pub const MAX_ACCOUNTANT_LIVE_BUFFERS: usize = 65_536;

/// Maximum UTF-8 byte length of an owner identifier.
pub const MAX_OWNER_ID_BYTES: usize = 256;

/// Distinct memory class so decoded frames, tensor workspaces, and scratch never conflate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BufferClass {
    /// Decoded video/image frame plane bytes (derived from source evidence).
    DecodedFrame,
    /// Model tensor input, activation, or output workspace bytes.
    TensorWorkspace,
    /// Temporary bounded staging or conversion scratch bytes.
    StagingScratch,
}

impl BufferClass {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecodedFrame => "decoded_frame",
            Self::TensorWorkspace => "tensor_workspace",
            Self::StagingScratch => "staging_scratch",
        }
    }
}

impl CanonicalEncode for BufferClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::DecodedFrame => 1,
            Self::TensorWorkspace => 2,
            Self::StagingScratch => 3,
        });
    }
}

impl CanonicalDecode for BufferClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::DecodedFrame),
            2 => Ok(Self::TensorWorkspace),
            3 => Ok(Self::StagingScratch),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Non-collapsed resident-memory pressure tier derived from exact live watermarks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BufferPressureTier {
    /// Live utilization is below the elevated threshold.
    Normal,
    /// Live utilization reached or exceeded `elevated_threshold_bps`.
    Elevated,
    /// Live utilization reached or exceeded `critical_threshold_bps`.
    Critical,
    /// Byte ceiling or live slot ceiling is completely full.
    Exhausted,
}

impl BufferPressureTier {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Exhausted => "exhausted",
        }
    }
}

impl CanonicalEncode for BufferPressureTier {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Normal => 1,
            Self::Elevated => 2,
            Self::Critical => 3,
            Self::Exhausted => 4,
        });
    }
}

impl CanonicalDecode for BufferPressureTier {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Elevated),
            3 => Ok(Self::Critical),
            4 => Ok(Self::Exhausted),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Explicit hard ceilings, alignment rule, and pressure thresholds for a [`BufferAccountant`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferAccountingPolicy {
    /// Aggregate ceiling across all buffer classes in bytes.
    pub max_total_bytes: usize,
    /// Per-class ceiling for [`BufferClass::DecodedFrame`].
    pub max_decoded_frame_bytes: usize,
    /// Per-class ceiling for [`BufferClass::TensorWorkspace`].
    pub max_tensor_workspace_bytes: usize,
    /// Per-class ceiling for [`BufferClass::StagingScratch`].
    pub max_staging_scratch_bytes: usize,
    /// Hard ceiling on simultaneously live buffer reservations.
    pub max_live_buffers: usize,
    /// Power-of-two byte alignment charged to every reservation (`1..=4096`).
    pub alignment_bytes: usize,
    /// Basis-points threshold (`1..=9999`, out of 10_000) entering [`BufferPressureTier::Elevated`].
    pub elevated_threshold_bps: u16,
    /// Basis-points threshold (`elevated_threshold_bps..=10_000`) entering [`BufferPressureTier::Critical`].
    pub critical_threshold_bps: u16,
}

impl Default for BufferAccountingPolicy {
    fn default() -> Self {
        Self {
            max_total_bytes: 256 * 1024 * 1024,
            max_decoded_frame_bytes: 192 * 1024 * 1024,
            max_tensor_workspace_bytes: 128 * 1024 * 1024,
            max_staging_scratch_bytes: 64 * 1024 * 1024,
            max_live_buffers: 1024,
            alignment_bytes: 64,
            elevated_threshold_bps: 7_500,
            critical_threshold_bps: 9_000,
        }
    }
}

impl BufferAccountingPolicy {
    /// Fails closed on zero, inverted, non-power-of-two, or absurd bounds without clamping.
    pub fn validate(self) -> Result<(), BufferAccountingError> {
        if self.max_total_bytes == 0 || self.max_total_bytes > MAX_ACCOUNTANT_TOTAL_BYTES {
            return Err(BufferAccountingError::InvalidPolicy);
        }
        if self.max_decoded_frame_bytes > self.max_total_bytes
            || self.max_tensor_workspace_bytes > self.max_total_bytes
            || self.max_staging_scratch_bytes > self.max_total_bytes
            || (self.max_decoded_frame_bytes == 0
                && self.max_tensor_workspace_bytes == 0
                && self.max_staging_scratch_bytes == 0)
        {
            return Err(BufferAccountingError::InvalidPolicy);
        }
        if self.max_live_buffers == 0 || self.max_live_buffers > MAX_ACCOUNTANT_LIVE_BUFFERS {
            return Err(BufferAccountingError::InvalidPolicy);
        }
        if self.alignment_bytes == 0
            || self.alignment_bytes > 4096
            || !self.alignment_bytes.is_power_of_two()
        {
            return Err(BufferAccountingError::InvalidPolicy);
        }
        if self.elevated_threshold_bps == 0
            || self.elevated_threshold_bps >= 10_000
            || self.critical_threshold_bps < self.elevated_threshold_bps
            || self.critical_threshold_bps > 10_000
        {
            return Err(BufferAccountingError::InvalidPolicy);
        }
        Ok(())
    }

    /// Returns the configured byte ceiling for a specific buffer class.
    #[must_use]
    pub const fn class_limit(self, class: BufferClass) -> usize {
        match class {
            BufferClass::DecodedFrame => self.max_decoded_frame_bytes,
            BufferClass::TensorWorkspace => self.max_tensor_workspace_bytes,
            BufferClass::StagingScratch => self.max_staging_scratch_bytes,
        }
    }
}

/// Deterministic per-accountant reservation identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BufferReservationId(pub u64);

/// Explicit request to admit one decoded-frame or tensor buffer reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BufferReservationRequest {
    /// Logical owner identifier (stream, stage, operator, or pool ID).
    pub owner_id: String,
    /// Distinct memory accounting class.
    pub class: BufferClass,
    /// Immutable generation pinned to this buffer.
    pub generation: Generation,
    /// Exact payload byte length requested before alignment rounding.
    pub requested_bytes: usize,
    /// Optional source/input content digest for provenance lineage.
    pub source_digest: Option<ContentDigest>,
}

/// Immutable receipt proving one buffer reservation was admitted and charged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BufferReservationReceipt {
    /// Accountant-local unique reservation ID.
    pub reservation_id: BufferReservationId,
    /// Owner bound to this reservation.
    pub owner_id: String,
    /// Class charged.
    pub class: BufferClass,
    /// Generation pinned to this reservation.
    pub generation: Generation,
    /// Unaligned requested byte count.
    pub requested_bytes: usize,
    /// Aligned byte count actually charged against live limits.
    pub charged_bytes: usize,
    /// Optional source digest recorded at admission.
    pub source_digest: Option<ContentDigest>,
    /// Pressure tier observed immediately after admission.
    pub pressure_after: BufferPressureTier,
    /// Caller-supplied admission timestamp.
    pub admitted_at_ns: TimestampNs,
}

/// Immutable receipt proving a prior reservation was released and refunded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BufferReleaseReceipt {
    /// Released reservation ID.
    pub reservation_id: BufferReservationId,
    /// Owner that matched the reservation.
    pub owner_id: String,
    /// Class refunded.
    pub class: BufferClass,
    /// Generation of the released reservation.
    pub generation: Generation,
    /// Aligned byte count refunded to live capacity.
    pub released_bytes: usize,
    /// Pressure tier observed immediately after release.
    pub pressure_after: BufferPressureTier,
    /// Caller-supplied release timestamp.
    pub released_at_ns: TimestampNs,
}

/// Typed fail-closed refusal for buffer accounting operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BufferAccountingError {
    /// Policy ceilings, alignment, or pressure thresholds are invalid.
    InvalidPolicy,
    /// Request carried an empty/malformed owner ID, zero byte count, or zero generation.
    InvalidRequest(&'static str),
    /// Checked alignment or byte-sum arithmetic overflowed.
    ArithmeticOverflow,
    /// Reservation attempted against a revoked/stale generation.
    StaleOrRevokedGeneration {
        /// The refused generation.
        generation: Generation,
    },
    /// Live buffer slot count is already at `max_live_buffers`.
    SlotLimitExceeded {
        /// Current live slot count.
        live: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Class-specific byte cap would be exceeded.
    ClassBudgetExceeded {
        /// Refused buffer class.
        class: BufferClass,
        /// Aligned byte charge requested.
        requested_aligned: usize,
        /// Remaining bytes in this class.
        remaining: usize,
    },
    /// Aggregate byte cap across all classes would be exceeded.
    TotalBudgetExceeded {
        /// Aligned byte charge requested.
        requested_aligned: usize,
        /// Remaining aggregate bytes.
        remaining: usize,
    },
    /// Release attempted on a nonexistent or already-released reservation.
    UnknownOrAlreadyReleased(BufferReservationId),
    /// Release caller owner ID does not match the reservation's owner.
    OwnerMismatch {
        /// Reservation that was protected from foreign release.
        reservation_id: BufferReservationId,
    },
    /// Cooperative cancellation was observed before admitting the reservation.
    Cancelled,
}

impl BufferAccountingError {
    /// Deterministic, operator- and agent-legible recovery guidance.
    #[must_use]
    pub const fn recovery_guidance(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => {
                "configure positive aligned ceilings and monotonic pressure thresholds"
            }
            Self::InvalidRequest(_) => {
                "supply a clean non-empty owner ID, non-zero byte length, and active generation"
            }
            Self::ArithmeticOverflow => "reduce requested byte count within checked usize bounds",
            Self::StaleOrRevokedGeneration { .. } => {
                "re-acquire an active generation fence before admitting new buffers"
            }
            Self::SlotLimitExceeded { .. } => {
                "reclaim unleased frames or release completed buffers before retrying"
            }
            Self::ClassBudgetExceeded { .. } => {
                "shed derived load in this buffer class or reclaim unleased buffers"
            }
            Self::TotalBudgetExceeded { .. } => {
                "apply media pressure degradation and reclaim unleased buffers before retrying"
            }
            Self::UnknownOrAlreadyReleased(_) => {
                "reconcile reservation ledger; never double-release or fabricate IDs"
            }
            Self::OwnerMismatch { .. } => {
                "only the owning stage or pool may release its own reservation"
            }
            Self::Cancelled => "treat reservation as uncharged and drain remaining owned buffers",
        }
    }
}

impl fmt::Display for BufferAccountingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid buffer accounting policy"),
            Self::InvalidRequest(reason) => write!(f, "invalid buffer request: {reason}"),
            Self::ArithmeticOverflow => write!(f, "buffer accounting arithmetic overflow"),
            Self::StaleOrRevokedGeneration { generation } => {
                write!(f, "generation {} is stale or revoked", generation.0)
            }
            Self::SlotLimitExceeded { live, max } => {
                write!(f, "live buffer slot cap reached ({live}/{max})")
            }
            Self::ClassBudgetExceeded {
                class,
                requested_aligned,
                remaining,
            } => write!(
                f,
                "{} buffer class budget exceeded: requested {requested_aligned} aligned bytes, {remaining} remaining",
                class.as_str()
            ),
            Self::TotalBudgetExceeded {
                requested_aligned,
                remaining,
            } => write!(
                f,
                "aggregate buffer budget exceeded: requested {requested_aligned} aligned bytes, {remaining} remaining"
            ),
            Self::UnknownOrAlreadyReleased(id) => {
                write!(
                    f,
                    "buffer reservation {} is unknown or already released",
                    id.0
                )
            }
            Self::OwnerMismatch { reservation_id } => {
                write!(
                    f,
                    "owner mismatch releasing buffer reservation {}",
                    reservation_id.0
                )
            }
            Self::Cancelled => write!(f, "buffer reservation cancelled before admission"),
        }
    }
}

impl std::error::Error for BufferAccountingError {}

/// Canonical, content-addressed point-in-time witness of buffer accounting state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BufferAccountingSnapshot {
    /// Format version (`BUFFER_ACCOUNTING_FORMAT_VERSION`).
    pub format_version: u32,
    /// Timestamp supplied by the caller when capturing this snapshot.
    pub captured_at_ns: TimestampNs,
    /// Aggregate byte ceiling.
    pub max_total_bytes: u64,
    /// Live slot ceiling.
    pub max_live_buffers: u64,
    /// Alignment granularity in bytes.
    pub alignment_bytes: u64,
    /// Current live bytes across all classes.
    pub live_bytes: u64,
    /// Historical peak live bytes observed.
    pub peak_live_bytes: u64,
    /// Current live reservation count.
    pub live_buffers: u64,
    /// Historical peak live reservation count.
    pub peak_live_buffers: u64,
    /// Live bytes per buffer class.
    pub decoded_frame_live_bytes: u64,
    /// Live bytes in tensor workspaces.
    pub tensor_workspace_live_bytes: u64,
    /// Live bytes in staging scratch.
    pub staging_scratch_live_bytes: u64,
    /// Peak bytes per buffer class.
    pub decoded_frame_peak_bytes: u64,
    /// Peak bytes in tensor workspaces.
    pub tensor_workspace_peak_bytes: u64,
    /// Peak bytes in staging scratch.
    pub staging_scratch_peak_bytes: u64,
    /// Cumulative admitted reservations.
    pub total_admitted: u64,
    /// Cumulative released reservations.
    pub total_released: u64,
    /// Cumulative refused reservations (cap/stale/invalid after preflight).
    pub total_refused: u64,
    /// Current non-collapsed pressure tier.
    pub pressure_tier: BufferPressureTier,
    /// Sorted list of `(generation, live_bytes)` for every generation with live bytes > 0.
    pub live_by_generation: Vec<(Generation, u64)>,
    /// Sorted list of explicitly revoked generations.
    pub revoked_generations: Vec<Generation>,
    /// Domain-separated SHA-256 digest over all fields above.
    pub snapshot_digest: ContentDigest,
}

impl BufferAccountingSnapshot {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(BUFFER_ACCOUNTING_SNAPSHOT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.max_total_bytes);
        encoder.u64(self.max_live_buffers);
        encoder.u64(self.alignment_bytes);
        encoder.u64(self.live_bytes);
        encoder.u64(self.peak_live_bytes);
        encoder.u64(self.live_buffers);
        encoder.u64(self.peak_live_buffers);
        encoder.u64(self.decoded_frame_live_bytes);
        encoder.u64(self.tensor_workspace_live_bytes);
        encoder.u64(self.staging_scratch_live_bytes);
        encoder.u64(self.decoded_frame_peak_bytes);
        encoder.u64(self.tensor_workspace_peak_bytes);
        encoder.u64(self.staging_scratch_peak_bytes);
        encoder.u64(self.total_admitted);
        encoder.u64(self.total_released);
        encoder.u64(self.total_refused);
        self.pressure_tier.encode_canonical(&mut encoder);
        encoder.u64(self.live_by_generation.len() as u64);
        for (gen_id, bytes) in &self.live_by_generation {
            encoder.u64(gen_id.0);
            encoder.u64(*bytes);
        }
        encoder.u64(self.revoked_generations.len() as u64);
        for gen_id in &self.revoked_generations {
            encoder.u64(gen_id.0);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `snapshot_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.snapshot_digest == self.computed_digest()
    }
}

impl CanonicalEncode for BufferAccountingSnapshot {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.max_total_bytes);
        encoder.u64(self.max_live_buffers);
        encoder.u64(self.alignment_bytes);
        encoder.u64(self.live_bytes);
        encoder.u64(self.peak_live_bytes);
        encoder.u64(self.live_buffers);
        encoder.u64(self.peak_live_buffers);
        encoder.u64(self.decoded_frame_live_bytes);
        encoder.u64(self.tensor_workspace_live_bytes);
        encoder.u64(self.staging_scratch_live_bytes);
        encoder.u64(self.decoded_frame_peak_bytes);
        encoder.u64(self.tensor_workspace_peak_bytes);
        encoder.u64(self.staging_scratch_peak_bytes);
        encoder.u64(self.total_admitted);
        encoder.u64(self.total_released);
        encoder.u64(self.total_refused);
        self.pressure_tier.encode_canonical(encoder);
        encoder.u64(self.live_by_generation.len() as u64);
        for (gen_id, bytes) in &self.live_by_generation {
            encoder.u64(gen_id.0);
            encoder.u64(*bytes);
        }
        encoder.u64(self.revoked_generations.len() as u64);
        for gen_id in &self.revoked_generations {
            encoder.u64(gen_id.0);
        }
        encoder.digest(self.snapshot_digest);
    }
}

impl CanonicalDecode for BufferAccountingSnapshot {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != BUFFER_ACCOUNTING_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let captured_at_ns = TimestampNs(decoder.i128()?);
        let max_total_bytes = decoder.u64()?;
        let max_live_buffers = decoder.u64()?;
        let alignment_bytes = decoder.u64()?;
        let live_bytes = decoder.u64()?;
        let peak_live_bytes = decoder.u64()?;
        let live_buffers = decoder.u64()?;
        let peak_live_buffers = decoder.u64()?;
        let decoded_frame_live_bytes = decoder.u64()?;
        let tensor_workspace_live_bytes = decoder.u64()?;
        let staging_scratch_live_bytes = decoder.u64()?;
        let decoded_frame_peak_bytes = decoder.u64()?;
        let tensor_workspace_peak_bytes = decoder.u64()?;
        let staging_scratch_peak_bytes = decoder.u64()?;
        let total_admitted = decoder.u64()?;
        let total_released = decoder.u64()?;
        let total_refused = decoder.u64()?;
        let pressure_tier = BufferPressureTier::decode_canonical(decoder)?;

        let gen_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if gen_count > MAX_ACCOUNTANT_LIVE_BUFFERS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut live_by_generation = Vec::with_capacity(gen_count);
        for _ in 0..gen_count {
            let g = Generation(decoder.u64()?);
            let b = decoder.u64()?;
            if g.0 == 0 || b == 0 {
                return Err(ContractError::InvalidIdentifier);
            }
            live_by_generation.push((g, b));
        }

        let rev_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if rev_count > MAX_ACCOUNTANT_LIVE_BUFFERS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut revoked_generations = Vec::with_capacity(rev_count);
        for _ in 0..rev_count {
            let g = Generation(decoder.u64()?);
            if g.0 == 0 {
                return Err(ContractError::InvalidIdentifier);
            }
            revoked_generations.push(g);
        }
        let snapshot_digest = decoder.digest()?;

        // Structural balance, policy-bound, & monotonicity invariants enforced on decode.
        let class_sum = decoded_frame_live_bytes
            .checked_add(tensor_workspace_live_bytes)
            .and_then(|v| v.checked_add(staging_scratch_live_bytes))
            .ok_or(ContractError::InvalidIdentifier)?;
        let gen_sum = live_by_generation
            .iter()
            .try_fold(0_u64, |acc, (_, b)| acc.checked_add(*b))
            .ok_or(ContractError::InvalidIdentifier)?;
        if max_total_bytes == 0
            || max_live_buffers == 0
            || alignment_bytes == 0
            || alignment_bytes > 4096
            || !alignment_bytes.is_power_of_two()
            || class_sum != live_bytes
            || gen_sum != live_bytes
            || live_bytes > peak_live_bytes
            || peak_live_bytes > max_total_bytes
            || live_buffers > peak_live_buffers
            || peak_live_buffers > max_live_buffers
            || decoded_frame_live_bytes > decoded_frame_peak_bytes
            || tensor_workspace_live_bytes > tensor_workspace_peak_bytes
            || staging_scratch_live_bytes > staging_scratch_peak_bytes
            || total_released > total_admitted
            || total_admitted - total_released != live_buffers
            || !live_by_generation.windows(2).all(|w| w[0].0 < w[1].0)
            || !revoked_generations.windows(2).all(|w| w[0] < w[1])
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let snap = Self {
            format_version,
            captured_at_ns,
            max_total_bytes,
            max_live_buffers,
            alignment_bytes,
            live_bytes,
            peak_live_bytes,
            live_buffers,
            peak_live_buffers,
            decoded_frame_live_bytes,
            tensor_workspace_live_bytes,
            staging_scratch_live_bytes,
            decoded_frame_peak_bytes,
            tensor_workspace_peak_bytes,
            staging_scratch_peak_bytes,
            total_admitted,
            total_released,
            total_refused,
            pressure_tier,
            live_by_generation,
            revoked_generations,
            snapshot_digest,
        };
        if !snap.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(snap)
    }
}

#[derive(Clone, Debug)]
struct LiveReservation {
    owner_id: String,
    class: BufferClass,
    generation: Generation,
    charged_bytes: usize,
}

/// Deterministic, instance-owned accountant for decoded-frame and tensor memory reservations.
#[derive(Clone, Debug)]
pub struct BufferAccountant {
    policy: BufferAccountingPolicy,
    next_reservation_id: u64,
    live: BTreeMap<BufferReservationId, LiveReservation>,
    live_bytes: usize,
    peak_live_bytes: usize,
    peak_live_buffers: usize,
    class_live: [usize; 3],
    class_peak: [usize; 3],
    generation_live: BTreeMap<Generation, usize>,
    owner_live: BTreeMap<String, usize>,
    revoked_generations: BTreeSet<Generation>,
    total_admitted: u64,
    total_released: u64,
    total_refused: u64,
}

const fn class_index(class: BufferClass) -> usize {
    match class {
        BufferClass::DecodedFrame => 0,
        BufferClass::TensorWorkspace => 1,
        BufferClass::StagingScratch => 2,
    }
}

fn validate_owner_id(owner_id: &str) -> Result<(), BufferAccountingError> {
    if owner_id.is_empty()
        || owner_id.len() > MAX_OWNER_ID_BYTES
        || owner_id
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(BufferAccountingError::InvalidRequest("owner_id"));
    }
    Ok(())
}

/// Checked alignment rounding up to the nearest multiple of `alignment` (must be power of two).
pub fn checked_align_up(bytes: usize, alignment: usize) -> Result<usize, BufferAccountingError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(BufferAccountingError::InvalidPolicy);
    }
    let mask = alignment - 1;
    bytes
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(BufferAccountingError::ArithmeticOverflow)
}

impl BufferAccountant {
    /// Creates a new accountant after validating all policy ceilings and thresholds.
    pub fn new(policy: BufferAccountingPolicy) -> Result<Self, BufferAccountingError> {
        policy.validate()?;
        Ok(Self {
            policy,
            next_reservation_id: 1,
            live: BTreeMap::new(),
            live_bytes: 0,
            peak_live_bytes: 0,
            peak_live_buffers: 0,
            class_live: [0; 3],
            class_peak: [0; 3],
            generation_live: BTreeMap::new(),
            owner_live: BTreeMap::new(),
            revoked_generations: BTreeSet::new(),
            total_admitted: 0,
            total_released: 0,
            total_refused: 0,
        })
    }

    /// Returns the immutable policy governing this accountant.
    #[must_use]
    pub const fn policy(&self) -> BufferAccountingPolicy {
        self.policy
    }

    /// Computes the exact current pressure tier from live byte and slot watermarks.
    #[must_use]
    pub fn pressure_tier(&self) -> BufferPressureTier {
        if self.live_bytes >= self.policy.max_total_bytes
            || self.live.len() >= self.policy.max_live_buffers
        {
            return BufferPressureTier::Exhausted;
        }
        let byte_bps = ((self.live_bytes as u128) * 10_000) / (self.policy.max_total_bytes as u128);
        let slot_bps =
            ((self.live.len() as u128) * 10_000) / (self.policy.max_live_buffers as u128);
        let max_bps = byte_bps.max(slot_bps);
        if max_bps >= u128::from(self.policy.critical_threshold_bps) {
            BufferPressureTier::Critical
        } else if max_bps >= u128::from(self.policy.elevated_threshold_bps) {
            BufferPressureTier::Elevated
        } else {
            BufferPressureTier::Normal
        }
    }

    /// Reserves aligned memory for one decoded frame, tensor workspace, or scratch buffer.
    ///
    /// Fails closed on cancellation, invalid inputs, revoked generation, overflow, or slot/class/
    /// aggregate ceiling exhaustion without mutating any live balance.
    pub fn reserve(
        &mut self,
        request: &BufferReservationRequest,
        now_ns: TimestampNs,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<BufferReservationReceipt, BufferAccountingError> {
        if is_cancelled() {
            return Err(BufferAccountingError::Cancelled);
        }
        validate_owner_id(&request.owner_id)?;
        if request.requested_bytes == 0 {
            return Err(BufferAccountingError::InvalidRequest(
                "requested_bytes_zero",
            ));
        }
        if request.generation.0 == 0 {
            return Err(BufferAccountingError::InvalidRequest("generation_zero"));
        }
        if self.revoked_generations.contains(&request.generation) {
            self.total_refused = self.total_refused.saturating_add(1);
            return Err(BufferAccountingError::StaleOrRevokedGeneration {
                generation: request.generation,
            });
        }
        let charged_bytes = checked_align_up(request.requested_bytes, self.policy.alignment_bytes)?;

        if self.live.len() >= self.policy.max_live_buffers {
            self.total_refused = self.total_refused.saturating_add(1);
            return Err(BufferAccountingError::SlotLimitExceeded {
                live: self.live.len(),
                max: self.policy.max_live_buffers,
            });
        }

        let idx = class_index(request.class);
        let class_cap = self.policy.class_limit(request.class);
        let class_after = self.class_live[idx]
            .checked_add(charged_bytes)
            .ok_or(BufferAccountingError::ArithmeticOverflow)?;
        if class_after > class_cap {
            self.total_refused = self.total_refused.saturating_add(1);
            return Err(BufferAccountingError::ClassBudgetExceeded {
                class: request.class,
                requested_aligned: charged_bytes,
                remaining: class_cap.saturating_sub(self.class_live[idx]),
            });
        }

        let total_after = self
            .live_bytes
            .checked_add(charged_bytes)
            .ok_or(BufferAccountingError::ArithmeticOverflow)?;
        if total_after > self.policy.max_total_bytes {
            self.total_refused = self.total_refused.saturating_add(1);
            return Err(BufferAccountingError::TotalBudgetExceeded {
                requested_aligned: charged_bytes,
                remaining: self.policy.max_total_bytes.saturating_sub(self.live_bytes),
            });
        }

        // Final cooperative cancellation checkpoint immediately before committing state.
        if is_cancelled() {
            return Err(BufferAccountingError::Cancelled);
        }

        let reservation_id = BufferReservationId(self.next_reservation_id);
        self.next_reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or(BufferAccountingError::ArithmeticOverflow)?;

        self.live.insert(
            reservation_id,
            LiveReservation {
                owner_id: request.owner_id.clone(),
                class: request.class,
                generation: request.generation,
                charged_bytes,
            },
        );
        self.live_bytes = total_after;
        self.peak_live_bytes = self.peak_live_bytes.max(self.live_bytes);
        self.peak_live_buffers = self.peak_live_buffers.max(self.live.len());
        self.class_live[idx] = class_after;
        self.class_peak[idx] = self.class_peak[idx].max(class_after);
        *self.generation_live.entry(request.generation).or_insert(0) += charged_bytes;
        *self.owner_live.entry(request.owner_id.clone()).or_insert(0) += charged_bytes;
        self.total_admitted = self.total_admitted.saturating_add(1);

        Ok(BufferReservationReceipt {
            reservation_id,
            owner_id: request.owner_id.clone(),
            class: request.class,
            generation: request.generation,
            requested_bytes: request.requested_bytes,
            charged_bytes,
            source_digest: request.source_digest,
            pressure_after: self.pressure_tier(),
            admitted_at_ns: now_ns,
        })
    }

    /// Releases a live reservation owned by `owner_id` and refunds its exact aligned bytes.
    pub fn release(
        &mut self,
        reservation_id: BufferReservationId,
        owner_id: &str,
        now_ns: TimestampNs,
    ) -> Result<BufferReleaseReceipt, BufferAccountingError> {
        let Some(existing) = self.live.get(&reservation_id) else {
            return Err(BufferAccountingError::UnknownOrAlreadyReleased(
                reservation_id,
            ));
        };
        if existing.owner_id != owner_id {
            return Err(BufferAccountingError::OwnerMismatch { reservation_id });
        }
        let removed = self.live.remove(&reservation_id).ok_or(
            BufferAccountingError::UnknownOrAlreadyReleased(reservation_id),
        )?;

        let idx = class_index(removed.class);
        self.live_bytes = self.live_bytes.saturating_sub(removed.charged_bytes);
        self.class_live[idx] = self.class_live[idx].saturating_sub(removed.charged_bytes);

        if let Some(gen_bytes) = self.generation_live.get_mut(&removed.generation) {
            *gen_bytes = gen_bytes.saturating_sub(removed.charged_bytes);
            if *gen_bytes == 0 {
                self.generation_live.remove(&removed.generation);
            }
        }
        if let Some(owner_bytes) = self.owner_live.get_mut(&removed.owner_id) {
            *owner_bytes = owner_bytes.saturating_sub(removed.charged_bytes);
            if *owner_bytes == 0 {
                self.owner_live.remove(&removed.owner_id);
            }
        }
        self.total_released = self.total_released.saturating_add(1);

        Ok(BufferReleaseReceipt {
            reservation_id,
            owner_id: removed.owner_id,
            class: removed.class,
            generation: removed.generation,
            released_bytes: removed.charged_bytes,
            pressure_after: self.pressure_tier(),
            released_at_ns: now_ns,
        })
    }

    /// Permanently fences a generation from admitting any future reservations while keeping
    /// accurate accounting for already-live buffers until explicitly released.
    pub fn revoke_generation(&mut self, generation: Generation) {
        if generation.0 != 0 {
            self.revoked_generations.insert(generation);
        }
    }

    /// Returns `true` if `generation` has been revoked.
    #[must_use]
    pub fn is_generation_revoked(&self, generation: Generation) -> bool {
        self.revoked_generations.contains(&generation)
    }

    /// Current live aligned bytes across all classes.
    #[must_use]
    pub const fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    /// Historical peak live aligned bytes.
    #[must_use]
    pub const fn peak_live_bytes(&self) -> usize {
        self.peak_live_bytes
    }

    /// Current count of live reservations.
    #[must_use]
    pub fn live_buffers(&self) -> usize {
        self.live.len()
    }

    /// Historical peak live reservation count.
    #[must_use]
    pub const fn peak_live_buffers(&self) -> usize {
        self.peak_live_buffers
    }

    /// Current live aligned bytes for one specific class.
    #[must_use]
    pub const fn class_live_bytes(&self, class: BufferClass) -> usize {
        self.class_live[class_index(class)]
    }

    /// Historical peak aligned bytes for one specific class.
    #[must_use]
    pub const fn class_peak_bytes(&self, class: BufferClass) -> usize {
        self.class_peak[class_index(class)]
    }

    /// Current live aligned bytes pinned to `generation`.
    #[must_use]
    pub fn generation_live_bytes(&self, generation: Generation) -> usize {
        self.generation_live.get(&generation).copied().unwrap_or(0)
    }

    /// Current live aligned bytes held by `owner_id`.
    #[must_use]
    pub fn owner_live_bytes(&self, owner_id: &str) -> usize {
        self.owner_live.get(owner_id).copied().unwrap_or(0)
    }

    /// Cumulative admitted reservations.
    #[must_use]
    pub const fn total_admitted(&self) -> u64 {
        self.total_admitted
    }

    /// Cumulative released reservations.
    #[must_use]
    pub const fn total_released(&self) -> u64 {
        self.total_released
    }

    /// Cumulative refused reservations.
    #[must_use]
    pub const fn total_refused(&self) -> u64 {
        self.total_refused
    }

    /// Produces a deterministic, content-addressed witness snapshot of all accounting balances.
    #[must_use]
    pub fn snapshot(&self, captured_at_ns: TimestampNs) -> BufferAccountingSnapshot {
        let mut snap = BufferAccountingSnapshot {
            format_version: BUFFER_ACCOUNTING_FORMAT_VERSION,
            captured_at_ns,
            max_total_bytes: self.policy.max_total_bytes as u64,
            max_live_buffers: self.policy.max_live_buffers as u64,
            alignment_bytes: self.policy.alignment_bytes as u64,
            live_bytes: self.live_bytes as u64,
            peak_live_bytes: self.peak_live_bytes as u64,
            live_buffers: self.live.len() as u64,
            peak_live_buffers: self.peak_live_buffers as u64,
            decoded_frame_live_bytes: self.class_live[0] as u64,
            tensor_workspace_live_bytes: self.class_live[1] as u64,
            staging_scratch_live_bytes: self.class_live[2] as u64,
            decoded_frame_peak_bytes: self.class_peak[0] as u64,
            tensor_workspace_peak_bytes: self.class_peak[1] as u64,
            staging_scratch_peak_bytes: self.class_peak[2] as u64,
            total_admitted: self.total_admitted,
            total_released: self.total_released,
            total_refused: self.total_refused,
            pressure_tier: self.pressure_tier(),
            live_by_generation: self
                .generation_live
                .iter()
                .map(|(g, b)| (*g, *b as u64))
                .collect(),
            revoked_generations: self.revoked_generations.iter().copied().collect(),
            snapshot_digest: ContentDigest::sha256(b"pending"),
        };
        snap.snapshot_digest = snap.computed_digest();
        snap
    }
}
