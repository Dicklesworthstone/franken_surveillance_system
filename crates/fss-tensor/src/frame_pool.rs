#![forbid(unsafe_code)]
//! Deterministic, generation-leased immutable frame pools (`FSS-119`, bead `fss-x4a.12.18`).
//!
//! Combines immutable [`TensorStorage`] backing buffers with [`BufferAccountant`] (`FSS-058`) so
//! decoded frames can be shared across live preview, analytics, and rendition consumers with
//! zero mutable aliasing, strict generation fencing, bounded concurrent lease fan-out, and
//! deterministic reclamation only when active lease count reaches zero.
//!
//! Core invariants:
//! - Backing bytes are immutable once admitted (`TensorStorage`); no consumer can mutate a leased
//!   frame or alias a different generation.
//! - A decoded frame carries its exact `source_evidence_digest`, but remains explicitly derived
//!   evidence — never raw source custody.
//! - Retiring a generation immediately fences all new admissions and lease acquisitions for that
//!   generation, reclaims unleased slots immediately, and drains leased slots cleanly as soon as
//!   their final [`FrameLease`] is returned.
//! - Zero `unsafe`, zero global singletons or locks, bounded slot/byte/lease ceilings, and
//!   cooperative cancellation before any allocation or state mutation.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::buffer_accounting::{
    BufferAccountant, BufferAccountingError, BufferAccountingPolicy, BufferClass,
    BufferPressureTier, BufferReservationId, BufferReservationRequest, MAX_OWNER_ID_BYTES,
    checked_align_up,
};
use crate::dtype::DType;
use crate::storage::{MAX_STORAGE_BYTES, TensorStorage};

/// Registered digest domain for canonical frame-pool state receipts
/// (`SCHEMA-DOMAIN-TENSOR-FRAME-POOL-001`).
pub const FRAME_POOL_RECEIPT_DOMAIN: &str = "fss.tensor.frame_pool_receipt.v1";

/// Canonical binary format version for [`FramePoolReceipt`].
pub const FRAME_POOL_FORMAT_VERSION: u32 = 1;

/// Maximum slots configurable for one frame pool.
pub const MAX_FRAME_POOL_SLOTS: usize = 4_096;

/// Maximum concurrent leases configurable for one single frame slot.
pub const MAX_LEASES_PER_FRAME: usize = 256;

/// Hard policy governing one [`FramePool`] instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePoolPolicy {
    /// Clean non-empty identifier binding all leases to this exact pool.
    pub pool_id: String,
    /// Hard ceiling on simultaneously retained decoded frame slots.
    pub max_slots: usize,
    /// Hard ceiling on total aligned decoded-frame bytes held by the pool.
    pub max_bytes: usize,
    /// Hard ceiling on concurrent immutable leases referencing one frame slot.
    pub max_leases_per_frame: usize,
    /// Power-of-two alignment granularity passed to [`BufferAccountant`].
    pub alignment_bytes: usize,
    /// Basis-points watermark entering elevated pressure.
    pub elevated_threshold_bps: u16,
    /// Basis-points watermark entering critical pressure.
    pub critical_threshold_bps: u16,
}

impl FramePoolPolicy {
    /// Returns a sensible bounded default policy for `pool_id`.
    #[must_use]
    pub fn bounded_default(pool_id: impl Into<String>) -> Self {
        Self {
            pool_id: pool_id.into(),
            max_slots: 64,
            max_bytes: 128 * 1024 * 1024,
            max_leases_per_frame: 16,
            alignment_bytes: 64,
            elevated_threshold_bps: 7_500,
            critical_threshold_bps: 9_000,
        }
    }

    /// Fails closed on invalid pool identity, zero/oversized ceilings, or invalid thresholds.
    pub fn validate(&self) -> Result<(), FramePoolError> {
        if self.pool_id.is_empty()
            || self.pool_id.len() > MAX_OWNER_ID_BYTES
            || self
                .pool_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(FramePoolError::InvalidPolicy);
        }
        if self.max_slots == 0 || self.max_slots > MAX_FRAME_POOL_SLOTS {
            return Err(FramePoolError::InvalidPolicy);
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_STORAGE_BYTES * 16 {
            return Err(FramePoolError::InvalidPolicy);
        }
        if self.max_leases_per_frame == 0 || self.max_leases_per_frame > MAX_LEASES_PER_FRAME {
            return Err(FramePoolError::InvalidPolicy);
        }
        self.to_accounting_policy()
            .validate()
            .map_err(|_| FramePoolError::InvalidPolicy)
    }

    fn to_accounting_policy(&self) -> BufferAccountingPolicy {
        BufferAccountingPolicy {
            max_total_bytes: self.max_bytes,
            max_decoded_frame_bytes: self.max_bytes,
            max_tensor_workspace_bytes: 0,
            max_staging_scratch_bytes: 0,
            max_live_buffers: self.max_slots,
            alignment_bytes: self.alignment_bytes,
            elevated_threshold_bps: self.elevated_threshold_bps,
            critical_threshold_bps: self.critical_threshold_bps,
        }
    }
}

/// Exact geometry, element dtype, generation fence, and source custody anchor of one decoded frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameDescriptor {
    /// Positive pixel width.
    pub width: u32,
    /// Positive pixel height.
    pub height: u32,
    /// Positive channel count (`1..=4`, e.g., 1=Luma, 3=RGB/YUV, 4=RGBA).
    pub channels: u8,
    /// Element sample dtype (e.g., `DType::U8`, `DType::F32`).
    pub dtype: DType,
    /// Immutable generation fence pinning camera/stream/decoder/calibration identity.
    pub generation: Generation,
    /// Monotonic frame sequence number within the stream.
    pub frame_seq: u64,
    /// Content digest of the upstream source evidence from which this frame was decoded.
    pub source_evidence_digest: ContentDigest,
}

impl FrameDescriptor {
    /// Validates descriptor fields and computes the exact checked byte length of the frame plane.
    pub fn expected_byte_len(self) -> Result<usize, FramePoolError> {
        if self.width == 0 || self.height == 0 {
            return Err(FramePoolError::InvalidDescriptor("zero_dimensions"));
        }
        if !(1..=4).contains(&self.channels) {
            return Err(FramePoolError::InvalidDescriptor("channels_out_of_range"));
        }
        if self.generation.0 == 0 {
            return Err(FramePoolError::InvalidDescriptor("generation_zero"));
        }
        let pixels = (self.width as usize)
            .checked_mul(self.height as usize)
            .ok_or(FramePoolError::ArithmeticOverflow)?;
        let samples = pixels
            .checked_mul(usize::from(self.channels))
            .ok_or(FramePoolError::ArithmeticOverflow)?;
        let bytes = samples
            .checked_mul(self.dtype.size_bytes())
            .ok_or(FramePoolError::ArithmeticOverflow)?;
        if bytes == 0 || bytes > MAX_STORAGE_BYTES {
            return Err(FramePoolError::InvalidDescriptor(
                "byte_length_out_of_bounds",
            ));
        }
        Ok(bytes)
    }
}

/// Deterministic per-pool slot identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameSlotId(pub u64);

/// Deterministic per-pool lease identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameLeaseId(pub u64);

/// Immutable, generation-pinned linear lease granting read-only zero-copy access to one pooled frame.
///
/// Deliberately does **not** implement `Clone`: every additional concurrent consumer must call
/// [`FramePool::acquire_lease`] so generation fences, `max_leases_per_frame`, and exact lease
/// accounting can never be bypassed.
#[derive(Debug)]
pub struct FrameLease {
    pool_id: String,
    lease_id: FrameLeaseId,
    slot_id: FrameSlotId,
    descriptor: FrameDescriptor,
    frame_digest: ContentDigest,
    storage: TensorStorage,
}

impl FrameLease {
    /// Identifier of the owning [`FramePool`].
    #[must_use]
    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }

    /// Unique per-pool lease handle ID.
    #[must_use]
    pub const fn lease_id(&self) -> FrameLeaseId {
        self.lease_id
    }

    /// Underlying pooled slot ID.
    #[must_use]
    pub const fn slot_id(&self) -> FrameSlotId {
        self.slot_id
    }

    /// Exact descriptor of the decoded frame.
    #[must_use]
    pub const fn descriptor(&self) -> FrameDescriptor {
        self.descriptor
    }

    /// Immutable generation fence pinned to this frame and its backing [`TensorStorage`].
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.descriptor.generation
    }

    /// Content digest over the decoded frame's exact bytes.
    #[must_use]
    pub const fn frame_digest(&self) -> ContentDigest {
        self.frame_digest
    }

    /// Read-only access to the underlying generation-pinned [`TensorStorage`].
    #[must_use]
    pub const fn storage(&self) -> &TensorStorage {
        &self.storage
    }

    /// Read-only zero-copy slice of the decoded frame bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.storage.as_slice()
    }

    /// Explicit semantic marker: pooled decoded frames are derived evidence, never source custody.
    #[must_use]
    pub const fn is_derived_evidence(&self) -> bool {
        true
    }
}

/// Typed fail-closed refusal for [`FramePool`] operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FramePoolError {
    /// Policy bounds or pool identity are invalid.
    InvalidPolicy,
    /// Descriptor dimensions, channels, or generation are invalid.
    InvalidDescriptor(&'static str),
    /// Supplied payload bytes do not match descriptor `width * height * channels * dtype`.
    ByteLengthMismatch {
        /// Exact byte count required by the descriptor.
        expected: usize,
        /// Actual byte length supplied.
        actual: usize,
    },
    /// Checked geometry or byte arithmetic overflowed.
    ArithmeticOverflow,
    /// Operation referenced a retired, revoked, or mismatched generation fence.
    StaleOrRetiredGeneration {
        /// Generation that was refused.
        generation: Generation,
    },
    /// Pool is saturated with leased frames and cannot reclaim enough capacity for the admission.
    PoolCapacityExhausted,
    /// Slot already has the maximum configured concurrent immutable leases.
    LeaseCapExceeded {
        /// Saturated slot ID.
        slot_id: FrameSlotId,
        /// Configured ceiling.
        max_leases: usize,
    },
    /// Referenced slot does not exist or has already been reclaimed.
    UnknownSlot(FrameSlotId),
    /// Lease ID is unknown or was already released.
    UnknownOrReleasedLease(FrameLeaseId),
    /// Lease belongs to a different pool instance.
    PoolMismatch,
    /// Underlying buffer accounting refused the operation.
    Accounting(BufferAccountingError),
    /// Cooperative cancellation was observed before admitting or leasing.
    Cancelled,
}

impl FramePoolError {
    /// Deterministic recovery guidance for operators and agents.
    #[must_use]
    pub const fn recovery_guidance(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => {
                "configure valid pool_id, positive slot/byte/lease caps, and alignment"
            }
            Self::InvalidDescriptor(_) => {
                "supply valid non-zero frame geometry, 1..=4 channels, and active generation"
            }
            Self::ByteLengthMismatch { .. } => {
                "ensure decoded plane bytes match exact descriptor shape and dtype"
            }
            Self::ArithmeticOverflow => "reduce frame geometry within checked usize limits",
            Self::StaleOrRetiredGeneration { .. } => {
                "rebind consumer to the active generation before acquiring leases"
            }
            Self::PoolCapacityExhausted => {
                "release finished consumer leases or invoke media pressure shedding"
            }
            Self::LeaseCapExceeded { .. } => {
                "release unused consumer leases on this slot before fanning out further"
            }
            Self::UnknownSlot(_) => {
                "refresh frame handle from active pool frontier; slot was reclaimed"
            }
            Self::UnknownOrReleasedLease(_) => {
                "never double-release or reuse a consumed FrameLease"
            }
            Self::PoolMismatch => {
                "return each FrameLease only to the exact FramePool that issued it"
            }
            Self::Accounting(err) => err.recovery_guidance(),
            Self::Cancelled => "treat frame admission/lease as uncommitted and drain active leases",
        }
    }
}

impl fmt::Display for FramePoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid frame pool policy"),
            Self::InvalidDescriptor(why) => write!(f, "invalid frame descriptor: {why}"),
            Self::ByteLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "frame byte length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ArithmeticOverflow => write!(f, "frame pool arithmetic overflow"),
            Self::StaleOrRetiredGeneration { generation } => {
                write!(f, "frame generation {} is stale or retired", generation.0)
            }
            Self::PoolCapacityExhausted => {
                write!(
                    f,
                    "frame pool capacity exhausted; all retained slots are leased"
                )
            }
            Self::LeaseCapExceeded {
                slot_id,
                max_leases,
            } => write!(
                f,
                "frame slot {} reached max concurrent lease cap ({max_leases})",
                slot_id.0
            ),
            Self::UnknownSlot(slot_id) => {
                write!(f, "frame slot {} is unknown or reclaimed", slot_id.0)
            }
            Self::UnknownOrReleasedLease(lease_id) => {
                write!(
                    f,
                    "frame lease {} is unknown or already released",
                    lease_id.0
                )
            }
            Self::PoolMismatch => write!(f, "frame lease belongs to a different frame pool"),
            Self::Accounting(err) => write!(f, "frame pool accounting error: {err}"),
            Self::Cancelled => write!(f, "frame pool operation cancelled"),
        }
    }
}

impl std::error::Error for FramePoolError {}

/// Canonical, content-addressed witness receipt of [`FramePool`] state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePoolReceipt {
    /// Format version (`FRAME_POOL_FORMAT_VERSION`).
    pub format_version: u32,
    /// Owning pool identifier.
    pub pool_id: String,
    /// Caller-supplied timestamp.
    pub captured_at_ns: TimestampNs,
    /// Configured slot ceiling.
    pub max_slots: u64,
    /// Configured byte ceiling.
    pub max_bytes: u64,
    /// Currently retained slots (leased + unleased).
    pub retained_slots: u64,
    /// Currently active leases across all slots.
    pub active_leases: u64,
    /// Slots whose generation is retired but still awaiting active lease drain.
    pub draining_retired_slots: u64,
    /// Current aligned live bytes charged in `BufferAccountant`.
    pub live_bytes: u64,
    /// Historical peak aligned live bytes.
    pub peak_live_bytes: u64,
    /// Cumulative frames admitted.
    pub total_admitted_frames: u64,
    /// Cumulative slots reclaimed (auto-evicted or explicit/retirement reclaim).
    pub total_reclaimed_slots: u64,
    /// Current non-collapsed pressure tier.
    pub pressure_tier: BufferPressureTier,
    /// Content digest of the embedded [`BufferAccountant`] snapshot at `captured_at_ns`.
    pub accounting_snapshot_digest: ContentDigest,
    /// Sorted retired generation fences.
    pub retired_generations: Vec<Generation>,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl FramePoolReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(FRAME_POOL_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.pool_id);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.max_slots);
        encoder.u64(self.max_bytes);
        encoder.u64(self.retained_slots);
        encoder.u64(self.active_leases);
        encoder.u64(self.draining_retired_slots);
        encoder.u64(self.live_bytes);
        encoder.u64(self.peak_live_bytes);
        encoder.u64(self.total_admitted_frames);
        encoder.u64(self.total_reclaimed_slots);
        self.pressure_tier.encode_canonical(&mut encoder);
        encoder.digest(self.accounting_snapshot_digest);
        encoder.u64(self.retired_generations.len() as u64);
        for g in &self.retired_generations {
            encoder.u64(g.0);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for FramePoolReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.pool_id);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.max_slots);
        encoder.u64(self.max_bytes);
        encoder.u64(self.retained_slots);
        encoder.u64(self.active_leases);
        encoder.u64(self.draining_retired_slots);
        encoder.u64(self.live_bytes);
        encoder.u64(self.peak_live_bytes);
        encoder.u64(self.total_admitted_frames);
        encoder.u64(self.total_reclaimed_slots);
        self.pressure_tier.encode_canonical(encoder);
        encoder.digest(self.accounting_snapshot_digest);
        encoder.u64(self.retired_generations.len() as u64);
        for g in &self.retired_generations {
            encoder.u64(g.0);
        }
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for FramePoolReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != FRAME_POOL_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let pool_id = decoder.text()?.to_owned();
        if pool_id.is_empty() || pool_id.len() > MAX_OWNER_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let captured_at_ns = TimestampNs(decoder.i128()?);
        let max_slots = decoder.u64()?;
        let max_bytes = decoder.u64()?;
        let retained_slots = decoder.u64()?;
        let active_leases = decoder.u64()?;
        let draining_retired_slots = decoder.u64()?;
        let live_bytes = decoder.u64()?;
        let peak_live_bytes = decoder.u64()?;
        let total_admitted_frames = decoder.u64()?;
        let total_reclaimed_slots = decoder.u64()?;
        let pressure_tier = BufferPressureTier::decode_canonical(decoder)?;
        let accounting_snapshot_digest = decoder.digest()?;
        let rev_count = decoder.u64()? as usize;
        if rev_count > MAX_FRAME_POOL_SLOTS * 4 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut retired_generations = Vec::with_capacity(rev_count);
        for _ in 0..rev_count {
            retired_generations.push(Generation(decoder.u64()?));
        }
        let receipt_digest = decoder.digest()?;

        if retained_slots > max_slots
            || draining_retired_slots > retained_slots
            || live_bytes > peak_live_bytes
            || total_reclaimed_slots > total_admitted_frames
            || total_admitted_frames - total_reclaimed_slots != retained_slots
            || !retired_generations.windows(2).all(|w| w[0] < w[1])
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            pool_id,
            captured_at_ns,
            max_slots,
            max_bytes,
            retained_slots,
            active_leases,
            draining_retired_slots,
            live_bytes,
            peak_live_bytes,
            total_admitted_frames,
            total_reclaimed_slots,
            pressure_tier,
            accounting_snapshot_digest,
            retired_generations,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

#[derive(Clone, Debug)]
struct FrameSlot {
    reservation_id: BufferReservationId,
    charged_bytes: usize,
    descriptor: FrameDescriptor,
    frame_digest: ContentDigest,
    storage: TensorStorage,
    active_leases: BTreeSet<FrameLeaseId>,
}

/// Deterministic, generation-fenced immutable decoded-frame pool backed by [`BufferAccountant`].
#[derive(Clone, Debug)]
pub struct FramePool {
    policy: FramePoolPolicy,
    accountant: BufferAccountant,
    next_slot_id: u64,
    next_lease_id: u64,
    slots: BTreeMap<FrameSlotId, FrameSlot>,
    lease_to_slot: BTreeMap<FrameLeaseId, FrameSlotId>,
    retired_generations: BTreeSet<Generation>,
    total_admitted_frames: u64,
    total_reclaimed_slots: u64,
}

impl FramePool {
    /// Creates a new bounded frame pool with its own dedicated [`BufferAccountant`].
    pub fn new(policy: FramePoolPolicy) -> Result<Self, FramePoolError> {
        policy.validate()?;
        let accountant = BufferAccountant::new(policy.to_accounting_policy())
            .map_err(FramePoolError::Accounting)?;
        Ok(Self {
            policy,
            accountant,
            next_slot_id: 1,
            next_lease_id: 1,
            slots: BTreeMap::new(),
            lease_to_slot: BTreeMap::new(),
            retired_generations: BTreeSet::new(),
            total_admitted_frames: 0,
            total_reclaimed_slots: 0,
        })
    }

    /// Returns the immutable policy governing this pool.
    #[must_use]
    pub fn policy(&self) -> &FramePoolPolicy {
        &self.policy
    }

    /// Read-only view of the underlying [`BufferAccountant`].
    #[must_use]
    pub const fn accountant(&self) -> &BufferAccountant {
        &self.accountant
    }

    /// Admits one immutable decoded frame into the pool and returns its initial [`FrameLease`].
    ///
    /// If the pool is near its slot or byte cap, deterministically reclaims oldest unleased
    /// (`active_leases == 0`) slots first. If all retained slots are leased and capacity remains
    /// insufficient, fails closed with [`FramePoolError::PoolCapacityExhausted`] without dropping
    /// any live lease or leaking accounting state.
    pub fn admit_frame(
        &mut self,
        descriptor: FrameDescriptor,
        bytes: Vec<u8>,
        now_ns: TimestampNs,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<FrameLease, FramePoolError> {
        if is_cancelled() {
            return Err(FramePoolError::Cancelled);
        }
        let expected = descriptor.expected_byte_len()?;
        if bytes.len() != expected {
            return Err(FramePoolError::ByteLengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        if self.retired_generations.contains(&descriptor.generation) {
            return Err(FramePoolError::StaleOrRetiredGeneration {
                generation: descriptor.generation,
            });
        }
        let aligned_needed = checked_align_up(expected, self.policy.alignment_bytes)
            .map_err(FramePoolError::Accounting)?;
        if aligned_needed > self.policy.max_bytes {
            return Err(FramePoolError::PoolCapacityExhausted);
        }

        // Check whether sufficient reclaimable capacity exists BEFORE evicting anything so a
        // doomed admission never needlessly destroys cached unleased frames.
        let free_slots_now = self.policy.max_slots.saturating_sub(self.slots.len());
        let free_bytes_now = self
            .policy
            .max_bytes
            .saturating_sub(self.accountant.live_bytes());
        if free_slots_now == 0 || free_bytes_now < aligned_needed {
            let mut reclaim_plan: Vec<FrameSlotId> = Vec::new();
            let mut projected_slots = free_slots_now;
            let mut projected_bytes = free_bytes_now;
            for (&slot_id, slot) in &self.slots {
                if !slot.active_leases.is_empty() {
                    continue;
                }
                reclaim_plan.push(slot_id);
                projected_slots = projected_slots.saturating_add(1);
                projected_bytes = projected_bytes.saturating_add(slot.charged_bytes);
                if projected_slots >= 1 && projected_bytes >= aligned_needed {
                    break;
                }
            }
            if projected_slots < 1 || projected_bytes < aligned_needed {
                return Err(FramePoolError::PoolCapacityExhausted);
            }
            if is_cancelled() {
                return Err(FramePoolError::Cancelled);
            }
            for slot_id in reclaim_plan {
                self.reclaim_slot_unchecked(slot_id, now_ns)?;
            }
        }

        if is_cancelled() {
            return Err(FramePoolError::Cancelled);
        }

        let frame_digest = ContentDigest::sha256(&bytes);
        let reservation = self
            .accountant
            .reserve(
                &BufferReservationRequest {
                    owner_id: self.policy.pool_id.clone(),
                    class: BufferClass::DecodedFrame,
                    generation: descriptor.generation,
                    requested_bytes: expected,
                    source_digest: Some(descriptor.source_evidence_digest),
                },
                now_ns,
                &mut is_cancelled,
            )
            .map_err(|err| match err {
                BufferAccountingError::Cancelled => FramePoolError::Cancelled,
                BufferAccountingError::StaleOrRevokedGeneration { generation } => {
                    FramePoolError::StaleOrRetiredGeneration { generation }
                }
                other => FramePoolError::Accounting(other),
            })?;

        let storage = match TensorStorage::from_vec(bytes, descriptor.generation) {
            Ok(s) => s,
            Err(_) => {
                // Roll back accounting cleanly if storage admission fails.
                let _ = self.accountant.release(
                    reservation.reservation_id,
                    &self.policy.pool_id,
                    now_ns,
                );
                return Err(FramePoolError::PoolCapacityExhausted);
            }
        };

        let slot_id = FrameSlotId(self.next_slot_id);
        self.next_slot_id = self
            .next_slot_id
            .checked_add(1)
            .ok_or(FramePoolError::ArithmeticOverflow)?;
        let lease_id = FrameLeaseId(self.next_lease_id);
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .ok_or(FramePoolError::ArithmeticOverflow)?;

        let mut active_leases = BTreeSet::new();
        active_leases.insert(lease_id);

        let lease = FrameLease {
            pool_id: self.policy.pool_id.clone(),
            lease_id,
            slot_id,
            descriptor,
            frame_digest,
            storage: storage.clone(),
        };

        self.slots.insert(
            slot_id,
            FrameSlot {
                reservation_id: reservation.reservation_id,
                charged_bytes: reservation.charged_bytes,
                descriptor,
                frame_digest,
                storage,
                active_leases,
            },
        );
        self.lease_to_slot.insert(lease_id, slot_id);
        self.total_admitted_frames = self.total_admitted_frames.saturating_add(1);
        Ok(lease)
    }

    /// Acquires an additional immutable zero-copy lease on a retained slot, fenced strictly by
    /// `expected_generation` and bounded by `max_leases_per_frame`.
    pub fn acquire_lease(
        &mut self,
        slot_id: FrameSlotId,
        expected_generation: Generation,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<FrameLease, FramePoolError> {
        if is_cancelled() {
            return Err(FramePoolError::Cancelled);
        }
        if expected_generation.0 == 0 || self.retired_generations.contains(&expected_generation) {
            return Err(FramePoolError::StaleOrRetiredGeneration {
                generation: expected_generation,
            });
        }
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or(FramePoolError::UnknownSlot(slot_id))?;
        if slot.descriptor.generation != expected_generation
            || self
                .retired_generations
                .contains(&slot.descriptor.generation)
        {
            return Err(FramePoolError::StaleOrRetiredGeneration {
                generation: slot.descriptor.generation,
            });
        }
        if slot.active_leases.len() >= self.policy.max_leases_per_frame {
            return Err(FramePoolError::LeaseCapExceeded {
                slot_id,
                max_leases: self.policy.max_leases_per_frame,
            });
        }
        if is_cancelled() {
            return Err(FramePoolError::Cancelled);
        }

        let lease_id = FrameLeaseId(self.next_lease_id);
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .ok_or(FramePoolError::ArithmeticOverflow)?;
        slot.active_leases.insert(lease_id);
        self.lease_to_slot.insert(lease_id, slot_id);

        Ok(FrameLease {
            pool_id: self.policy.pool_id.clone(),
            lease_id,
            slot_id,
            descriptor: slot.descriptor,
            frame_digest: slot.frame_digest,
            storage: slot.storage.clone(),
        })
    }

    /// Consumes a [`FrameLease`] and decrements the slot's active lease count. If the slot's
    /// generation has already been retired and this was its final lease, immediately reclaims the
    /// slot and refunds its bytes to [`BufferAccountant`].
    pub fn release_lease(
        &mut self,
        lease: FrameLease,
        now_ns: TimestampNs,
    ) -> Result<(), FramePoolError> {
        if lease.pool_id != self.policy.pool_id {
            return Err(FramePoolError::PoolMismatch);
        }
        let slot_id = self
            .lease_to_slot
            .remove(&lease.lease_id)
            .ok_or(FramePoolError::UnknownOrReleasedLease(lease.lease_id))?;
        let should_reclaim = {
            let slot = self
                .slots
                .get_mut(&slot_id)
                .ok_or(FramePoolError::UnknownSlot(slot_id))?;
            if !slot.active_leases.remove(&lease.lease_id) {
                return Err(FramePoolError::UnknownOrReleasedLease(lease.lease_id));
            }
            slot.active_leases.is_empty()
                && self
                    .retired_generations
                    .contains(&slot.descriptor.generation)
        };
        drop(lease);
        if should_reclaim {
            self.reclaim_slot_unchecked(slot_id, now_ns)?;
        }
        Ok(())
    }

    /// Retires `generation`: immediately blocks future admissions and lease acquisitions for it,
    /// reclaims every unleased slot of `generation`, and marks still-leased slots for automatic
    /// reclamation upon final lease release. Returns the number of slots reclaimed immediately.
    pub fn retire_generation(
        &mut self,
        generation: Generation,
        now_ns: TimestampNs,
    ) -> Result<usize, FramePoolError> {
        if generation.0 == 0 {
            return Err(FramePoolError::InvalidDescriptor("generation_zero"));
        }
        self.retired_generations.insert(generation);
        self.accountant.revoke_generation(generation);

        let to_reclaim: Vec<FrameSlotId> = self
            .slots
            .iter()
            .filter_map(|(&slot_id, slot)| {
                (slot.descriptor.generation == generation && slot.active_leases.is_empty())
                    .then_some(slot_id)
            })
            .collect();
        let count = to_reclaim.len();
        for slot_id in to_reclaim {
            self.reclaim_slot_unchecked(slot_id, now_ns)?;
        }
        Ok(count)
    }

    /// Deterministically reclaims all currently unleased (`active_leases == 0`) slots.
    pub fn reclaim_unleased(&mut self, now_ns: TimestampNs) -> Result<usize, FramePoolError> {
        let to_reclaim: Vec<FrameSlotId> = self
            .slots
            .iter()
            .filter_map(|(&slot_id, slot)| slot.active_leases.is_empty().then_some(slot_id))
            .collect();
        let count = to_reclaim.len();
        for slot_id in to_reclaim {
            self.reclaim_slot_unchecked(slot_id, now_ns)?;
        }
        Ok(count)
    }

    fn reclaim_slot_unchecked(
        &mut self,
        slot_id: FrameSlotId,
        now_ns: TimestampNs,
    ) -> Result<(), FramePoolError> {
        let Some(existing) = self.slots.get(&slot_id) else {
            return Err(FramePoolError::UnknownSlot(slot_id));
        };
        if !existing.active_leases.is_empty() {
            return Err(FramePoolError::PoolCapacityExhausted);
        }
        let slot = self
            .slots
            .remove(&slot_id)
            .ok_or(FramePoolError::UnknownSlot(slot_id))?;
        self.accountant
            .release(slot.reservation_id, &self.policy.pool_id, now_ns)
            .map_err(FramePoolError::Accounting)?;
        self.total_reclaimed_slots = self.total_reclaimed_slots.saturating_add(1);
        Ok(())
    }

    /// Number of currently retained frame slots (both leased and unleased).
    #[must_use]
    pub fn retained_slots(&self) -> usize {
        self.slots.len()
    }

    /// Total number of currently active leases across all slots.
    #[must_use]
    pub fn active_leases(&self) -> usize {
        self.lease_to_slot.len()
    }

    /// Active lease count on one specific slot (`None` if slot is absent/reclaimed).
    #[must_use]
    pub fn slot_active_leases(&self, slot_id: FrameSlotId) -> Option<usize> {
        self.slots.get(&slot_id).map(|s| s.active_leases.len())
    }

    /// Number of retired-generation slots still waiting for existing leases to drain.
    #[must_use]
    pub fn draining_retired_slots(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| {
                self.retired_generations
                    .contains(&slot.descriptor.generation)
            })
            .count()
    }

    /// Returns a canonical, content-addressed witness receipt of current pool state.
    #[must_use]
    pub fn receipt(&self, captured_at_ns: TimestampNs) -> FramePoolReceipt {
        let acct_snap = self.accountant.snapshot(captured_at_ns);
        let mut receipt = FramePoolReceipt {
            format_version: FRAME_POOL_FORMAT_VERSION,
            pool_id: self.policy.pool_id.clone(),
            captured_at_ns,
            max_slots: self.policy.max_slots as u64,
            max_bytes: self.policy.max_bytes as u64,
            retained_slots: self.slots.len() as u64,
            active_leases: self.lease_to_slot.len() as u64,
            draining_retired_slots: self.draining_retired_slots() as u64,
            live_bytes: self.accountant.live_bytes() as u64,
            peak_live_bytes: self.accountant.peak_live_bytes() as u64,
            total_admitted_frames: self.total_admitted_frames,
            total_reclaimed_slots: self.total_reclaimed_slots,
            pressure_tier: self.accountant.pressure_tier(),
            accounting_snapshot_digest: acct_snap.snapshot_digest,
            retired_generations: self.retired_generations.iter().copied().collect(),
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }
}
