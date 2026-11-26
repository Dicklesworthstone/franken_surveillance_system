#![forbid(unsafe_code)]
//! Deterministic alignment-aware scratch arena & buffer-reuse planner (`FSS-140`, `fss-x4a.14.11`).
//!
//! Composes directly over [`MemoryPlan`] (`memory.rs`) to produce a concrete, zero-aliasing,
//! aligned byte-offset layout for every produced activation plus dedicated per-step operator
//! kernel scratch:
//!
//! - **Output-before-retirement safety:** allocations for step `t` are placed BEFORE any tensor
//!   with `release_after == Some(t)` returns to the free list, guaranteeing a node's inputs and
//!   outputs can never alias.
//! - **Deterministic best-fit interval coalescing:** freed intervals are coalesced and chosen by
//!   strict `(interval_len, arena_offset)` order so identical graphs yield bit-identical arena
//!   layouts and commitment digests.
//! - **Independent pairwise zero-aliasing oracle (`verify_no_aliasing_overlaps`):** certifies
//!   before returning (and on every wire decode) that NO two simultaneously live tensors share
//!   even a single byte, every offset satisfies `alignment_bytes`, and every pinned graph output
//!   remains un-overwritten through execution completion.
//! - **Versioned checksummed binary wire codec (`FSSSPL01` v1):** sealed under
//!   `fss.model_ir.scratch_arena_plan.v1`; grants zero effect authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, Sha256Hasher};

use crate::memory::{MAX_MEMORY_PLAN_VALUES, MemoryPlan, MemoryPlanError};

/// Registered digest domain for [`ScratchArenaPlan`] commitments (`FSS-140`).
pub const SCRATCH_ARENA_PLAN_DOMAIN: &str = "fss.model_ir.scratch_arena_plan.v1";
/// Binary wire magic header for serialized [`ScratchArenaPlan`] envelopes.
pub const SCRATCH_PLAN_WIRE_MAGIC: [u8; 8] = *b"FSSSPL01";
/// Current durable format version for [`ScratchArenaPlan`].
pub const SCRATCH_PLAN_WIRE_VERSION: u32 = 1;
/// Default SIMD/cache-line arena alignment in bytes (64 bytes).
pub const DEFAULT_SCRATCH_ALIGNMENT: usize = 64;
/// Maximum supported power-of-two byte alignment (4 KiB page).
pub const MAX_SCRATCH_ALIGNMENT: usize = 4096;
/// Hard upper bound on total planned arena bytes (512 MiB).
pub const MAX_SCRATCH_ARENA_BYTES: usize = 512 * 1024 * 1024;
/// Hard ceiling on serialized wire bytes for [`ScratchArenaPlan`] (1 MiB).
pub const MAX_SCRATCH_PLAN_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in a tensor port name inside a scratch assignment.
pub const MAX_SCRATCH_TENSOR_NAME_BYTES: usize = 256;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Explicit caller-bounded resource budget for scratch arena planning (`FSS-140`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchPlanBudget {
    /// Maximum total arena bytes (`activation_arena_bytes + operator_scratch_bytes`).
    pub max_arena_bytes: usize,
    /// Maximum dedicated aligned operator kernel scratch bytes.
    pub max_operator_scratch_bytes: usize,
    /// Maximum produced activation slots admitted.
    pub max_slots: usize,
}

impl ScratchPlanBudget {
    /// Constructs a concrete bounded scratch planning budget.
    #[must_use]
    pub const fn new(
        max_arena_bytes: usize,
        max_operator_scratch_bytes: usize,
        max_slots: usize,
    ) -> Self {
        Self {
            max_arena_bytes,
            max_operator_scratch_bytes,
            max_slots,
        }
    }

    /// Hard ceiling budget (`MAX_SCRATCH_ARENA_BYTES`, `MAX_MEMORY_PLAN_VALUES`).
    #[must_use]
    pub const fn ceiling() -> Self {
        Self {
            max_arena_bytes: MAX_SCRATCH_ARENA_BYTES,
            max_operator_scratch_bytes: MAX_SCRATCH_ARENA_BYTES,
            max_slots: MAX_MEMORY_PLAN_VALUES,
        }
    }
}

/// Safe operator/agent recovery guidance for a refused scratch arena plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScratchPlanGuidance {
    /// Provide a power-of-two alignment in `1..=4096` and matching per-step scratch vector.
    RepairPlannerConfiguration,
    /// Raise arena/scratch budget ceilings or partition/tile the model graph.
    IncreaseBudgetOrTileGraph,
    /// Cooperative cancellation observed cleanly; safe to re-run from pinned Model IR graph.
    RetryPlanning,
    /// Reject corrupt or tampered `FSSSPL01` wire plan and recompile from frozen Model IR.
    RecompileFromModelIr,
}

/// Typed fail-closed error emitted by [`ScratchArenaPlan`].
#[derive(Clone, Debug, PartialEq)]
pub enum ScratchPlanError {
    /// Underlying [`MemoryPlan`] validation or limit failure.
    MemoryPlan(MemoryPlanError),
    /// Alignment was zero, not a power of two, or exceeded [`MAX_SCRATCH_ALIGNMENT`].
    InvalidAlignment {
        /// Invalid alignment requested.
        alignment_bytes: usize,
    },
    /// Per-step kernel scratch schedule length disagreed with `memory_plan.steps().len()`.
    ScratchScheduleLengthMismatch {
        /// Expected number of steps.
        expected: usize,
        /// Observed length supplied.
        observed: usize,
    },
    /// Total arena bytes, operator scratch bytes, or slot count exceeded budget/ceiling.
    BudgetExceeded {
        /// Budget dimension exceeded (`arena_bytes`, `operator_scratch_bytes`, `slots`).
        dimension: &'static str,
        /// Required amount.
        required: usize,
        /// Active limit.
        limit: usize,
    },
    /// Cooperative cancellation observed cleanly; no partial layout returned.
    Cancelled,
    /// Checked byte/offset arithmetic overflowed.
    Overflow,
    /// Zero-aliasing overlap oracle or structural verification detected an invariant breach.
    AliasingOrInvariantViolation(String),
    /// Wire envelope magic header mismatch.
    InvalidMagic,
    /// Wire envelope format version unsupported.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Wire envelope trailing checksum or self-digest mismatch.
    ChecksumMismatch,
    /// Wire envelope exceeded [`MAX_SCRATCH_PLAN_WIRE_BYTES`].
    WireTooLarge {
        /// Observed byte length.
        observed: usize,
        /// Configured hard limit.
        maximum: usize,
    },
    /// Wire envelope truncated or structurally malformed.
    MalformedWire(String),
}

impl ScratchPlanError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MemoryPlan(_) => "ERR-MODEL-SCRATCH-MEMORY-PLAN-001",
            Self::InvalidAlignment { .. } | Self::ScratchScheduleLengthMismatch { .. } => {
                "ERR-MODEL-SCRATCH-CONFIG-001"
            }
            Self::BudgetExceeded { .. } => "ERR-MODEL-SCRATCH-BUDGET-001",
            Self::Cancelled => "ERR-MODEL-SCRATCH-CANCELLED-001",
            Self::Overflow => "ERR-MODEL-SCRATCH-OVERFLOW-001",
            Self::AliasingOrInvariantViolation(_) => "ERR-MODEL-SCRATCH-ALIASING-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } | Self::WireTooLarge { .. } => {
                "ERR-SCHEMA-UNSUPPORTED-001"
            }
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-MODEL-SCRATCH-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> ScratchPlanGuidance {
        match self {
            Self::MemoryPlan(MemoryPlanError::Cancelled) | Self::Cancelled => {
                ScratchPlanGuidance::RetryPlanning
            }
            Self::MemoryPlan(_)
            | Self::InvalidAlignment { .. }
            | Self::ScratchScheduleLengthMismatch { .. } => {
                ScratchPlanGuidance::RepairPlannerConfiguration
            }
            Self::BudgetExceeded { .. } | Self::Overflow => {
                ScratchPlanGuidance::IncreaseBudgetOrTileGraph
            }
            Self::AliasingOrInvariantViolation(_)
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::WireTooLarge { .. }
            | Self::MalformedWire(_) => ScratchPlanGuidance::RecompileFromModelIr,
        }
    }
}

impl fmt::Display for ScratchPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for ScratchPlanError {}

impl From<MemoryPlanError> for ScratchPlanError {
    fn from(value: MemoryPlanError) -> Self {
        Self::MemoryPlan(value)
    }
}

/// Concrete aligned byte-offset assignment for one produced tensor activation inside the arena.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchSlotAssignment {
    /// Tensor output port name in the canonical Model IR graph.
    pub tensor_name: String,
    /// Zero-based topological step producing this tensor.
    pub producer_step: usize,
    /// Zero-based last-use step after which this slot returns to the free pool (`None` = pinned graph output).
    pub release_after_step: Option<usize>,
    /// Unaligned logical payload size in bytes.
    pub logical_bytes: usize,
    /// Aligned reservation size in bytes (`>= logical_bytes`, multiple of `alignment_bytes`).
    pub aligned_bytes: usize,
    /// Byte offset inside the contiguous activation scratch arena (`% alignment_bytes == 0`).
    pub arena_offset: usize,
    /// True iff this slot was carved from previously freed arena storage rather than bumping high-water.
    pub reused_from_freed_slot: bool,
}

impl ScratchSlotAssignment {
    /// Exclusive end offset inside the activation arena (`arena_offset + aligned_bytes`).
    #[must_use]
    pub fn end_offset(&self) -> Option<usize> {
        self.arena_offset.checked_add(self.aligned_bytes)
    }
}

/// Sealed, zero-aliasing, alignment-aware scratch arena layout plan (`FSS-140`, `FSSSPL01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchArenaPlan {
    /// Durable wire format version (`1`).
    pub format_version: u32,
    /// Canonical Model IR graph digest pinned by the source [`MemoryPlan`].
    pub graph_digest: ContentDigest,
    /// Underlying [`MemoryPlan`] commitment digest.
    pub memory_plan_digest: ContentDigest,
    /// Power-of-two alignment in bytes enforced on every slot and on operator scratch.
    pub alignment_bytes: usize,
    /// Contiguous byte size required for all produced activations with deterministic slot reuse.
    pub activation_arena_bytes: usize,
    /// Dedicated aligned operator-kernel scratch tail reserved separately from live activations.
    pub operator_scratch_bytes: usize,
    /// Total contiguous arena bytes (`activation_arena_bytes + operator_scratch_bytes`).
    pub total_arena_bytes: usize,
    /// Sum of aligned bytes of all produced tensors without any buffer reuse (baseline).
    pub naive_unaliased_bytes: usize,
    /// Bytes saved via lifetime-based buffer reuse (`naive_unaliased_bytes - activation_arena_bytes`).
    pub reuse_saved_bytes: usize,
    /// Number of produced activations assigned into recycled freed slots.
    pub reused_allocation_count: usize,
    /// Canonical ordered slot assignments (`(producer_step, tensor_name)`).
    pub assignments: Vec<ScratchSlotAssignment>,
    /// Domain-separated SHA-256 commitment under [`SCRATCH_ARENA_PLAN_DOMAIN`].
    pub plan_digest: ContentDigest,
}

impl ScratchArenaPlan {
    /// Memory layout planning is derived compilation metadata and NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Compiles a deterministic, aligned, zero-aliasing [`ScratchArenaPlan`] from a validated
    /// [`MemoryPlan`], per-step operator scratch byte schedule, alignment, and explicit budget.
    pub fn compile(
        memory_plan: &MemoryPlan,
        alignment_bytes: usize,
        step_scratch_bytes: &[usize],
        budget: ScratchPlanBudget,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<Self, ScratchPlanError> {
        if cancelled() {
            return Err(ScratchPlanError::Cancelled);
        }
        if alignment_bytes == 0
            || !alignment_bytes.is_power_of_two()
            || alignment_bytes > MAX_SCRATCH_ALIGNMENT
        {
            return Err(ScratchPlanError::InvalidAlignment { alignment_bytes });
        }
        let step_count = memory_plan.steps().len();
        if step_scratch_bytes.len() != step_count {
            return Err(ScratchPlanError::ScratchScheduleLengthMismatch {
                expected: step_count,
                observed: step_scratch_bytes.len(),
            });
        }

        let max_arena = budget.max_arena_bytes.min(MAX_SCRATCH_ARENA_BYTES);
        let max_scratch = budget
            .max_operator_scratch_bytes
            .min(MAX_SCRATCH_ARENA_BYTES);
        let max_slots = budget.max_slots.min(MAX_MEMORY_PLAN_VALUES);

        let mut operator_scratch_bytes = 0_usize;
        for &raw_scratch in step_scratch_bytes {
            let aligned = align_up(raw_scratch, alignment_bytes)?;
            operator_scratch_bytes = operator_scratch_bytes.max(aligned);
        }
        if operator_scratch_bytes > max_scratch {
            return Err(ScratchPlanError::BudgetExceeded {
                dimension: "operator_scratch_bytes",
                required: operator_scratch_bytes,
                limit: max_scratch,
            });
        }

        // Free intervals sorted by start offset: `(offset, length)`.
        let mut free_intervals: Vec<(usize, usize)> = Vec::new();
        let mut live_slots: std::collections::BTreeMap<String, (usize, usize)> =
            std::collections::BTreeMap::new();
        let mut activation_arena_bytes = 0_usize;
        let mut naive_unaliased_bytes = 0_usize;
        let mut reused_allocation_count = 0_usize;
        let mut assignments = Vec::new();

        for (step_idx, step) in memory_plan.steps().iter().enumerate() {
            if cancelled() {
                return Err(ScratchPlanError::Cancelled);
            }
            // 1. Allocate ALL outputs produced at `step_idx` BEFORE retiring any last-use inputs!
            let mut produced_sorted: Vec<&str> =
                step.produced().iter().map(String::as_str).collect();
            produced_sorted.sort_unstable();
            for tensor_name in produced_sorted {
                if assignments.len() >= max_slots {
                    return Err(ScratchPlanError::BudgetExceeded {
                        dimension: "slots",
                        required: assignments.len() + 1,
                        limit: max_slots,
                    });
                }
                let lifetime = memory_plan.values().get(tensor_name).ok_or_else(|| {
                    ScratchPlanError::AliasingOrInvariantViolation(format!(
                        "produced tensor '{tensor_name}' absent from MemoryPlan values"
                    ))
                })?;
                if lifetime.producer() != Some(step_idx) {
                    return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                        "tensor '{tensor_name}' producer step disagrees with MemoryStep {step_idx}"
                    )));
                }
                let logical_bytes = lifetime.bytes();
                let aligned_bytes = align_up(logical_bytes, alignment_bytes)?;
                naive_unaliased_bytes = naive_unaliased_bytes
                    .checked_add(aligned_bytes)
                    .ok_or(ScratchPlanError::Overflow)?;

                let (arena_offset, reused_from_freed_slot) = if aligned_bytes == 0 {
                    (0, false)
                } else if let Some((best_idx, (free_off, free_len))) = free_intervals
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(_, (_, len))| *len >= aligned_bytes)
                    .min_by_key(|(_, (off, len))| (*len, *off))
                {
                    free_intervals.remove(best_idx);
                    let remainder = free_len - aligned_bytes;
                    if remainder > 0 {
                        let rem_off = free_off
                            .checked_add(aligned_bytes)
                            .ok_or(ScratchPlanError::Overflow)?;
                        insert_and_coalesce_free(&mut free_intervals, rem_off, remainder)?;
                    }
                    reused_allocation_count += 1;
                    (free_off, true)
                } else {
                    let off = activation_arena_bytes;
                    activation_arena_bytes = off
                        .checked_add(aligned_bytes)
                        .ok_or(ScratchPlanError::Overflow)?;
                    if activation_arena_bytes > max_arena {
                        return Err(ScratchPlanError::BudgetExceeded {
                            dimension: "arena_bytes",
                            required: activation_arena_bytes,
                            limit: max_arena,
                        });
                    }
                    (off, false)
                };

                if aligned_bytes > 0 {
                    live_slots.insert(tensor_name.to_owned(), (arena_offset, aligned_bytes));
                }
                assignments.push(ScratchSlotAssignment {
                    tensor_name: tensor_name.to_owned(),
                    producer_step: step_idx,
                    release_after_step: lifetime.release_after(),
                    logical_bytes,
                    aligned_bytes,
                    arena_offset,
                    reused_from_freed_slot,
                });
            }

            // 2. Retire last-use intermediates AFTER step outputs are allocated and coalesce!
            for retired in step.release_after() {
                if let Some((off, len)) = live_slots.remove(retired)
                    && len > 0
                {
                    insert_and_coalesce_free(&mut free_intervals, off, len)?;
                }
            }
        }

        if cancelled() {
            return Err(ScratchPlanError::Cancelled);
        }

        let total_arena_bytes = activation_arena_bytes
            .checked_add(operator_scratch_bytes)
            .ok_or(ScratchPlanError::Overflow)?;
        if total_arena_bytes > max_arena {
            return Err(ScratchPlanError::BudgetExceeded {
                dimension: "arena_bytes",
                required: total_arena_bytes,
                limit: max_arena,
            });
        }
        let reuse_saved_bytes = naive_unaliased_bytes.saturating_sub(activation_arena_bytes);

        let mut plan = Self {
            format_version: SCRATCH_PLAN_WIRE_VERSION,
            graph_digest: memory_plan.graph_digest(),
            memory_plan_digest: memory_plan.digest(),
            alignment_bytes,
            activation_arena_bytes,
            operator_scratch_bytes,
            total_arena_bytes,
            naive_unaliased_bytes,
            reuse_saved_bytes,
            reused_allocation_count,
            assignments,
            plan_digest: ContentDigest::sha256(b"unsealed-scratch-plan"),
        };
        plan.plan_digest = plan.compute_digest()?;
        // Belt-and-suspenders: certify zero aliasing with the independent pairwise overlap oracle!
        plan.verify_no_aliasing_overlaps()?;
        plan.verify_self()?;
        Ok(plan)
    }

    /// Independent pairwise zero-aliasing overlap oracle (`FSS-140`).
    ///
    /// Exhaustively checks EVERY pair of assigned slots whose lifetimes overlap
    /// (`[a.producer_step, a.release_after_step] ∩ [b.producer_step, b.release_after_step] != ∅`,
    /// where `None` means pinned through execution completion) and proves their byte intervals
    /// `[arena_offset, arena_offset + aligned_bytes)` are strictly disjoint, aligned, and in-bounds.
    pub fn verify_no_aliasing_overlaps(&self) -> Result<(), ScratchPlanError> {
        if self.alignment_bytes == 0
            || !self.alignment_bytes.is_power_of_two()
            || self.alignment_bytes > MAX_SCRATCH_ALIGNMENT
        {
            return Err(ScratchPlanError::InvalidAlignment {
                alignment_bytes: self.alignment_bytes,
            });
        }
        let mut names = BTreeSet::new();
        let mut computed_naive = 0_usize;
        let mut computed_reused = 0_usize;
        let mut max_end = 0_usize;

        for slot in &self.assignments {
            if !names.insert(slot.tensor_name.as_str()) {
                return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                    "duplicate slot assignment for tensor '{}'",
                    slot.tensor_name
                )));
            }
            if let Some(release) = slot.release_after_step
                && release < slot.producer_step
            {
                return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                    "tensor '{}' released at step {} before production at {}",
                    slot.tensor_name, release, slot.producer_step
                )));
            }
            let expected_aligned = align_up(slot.logical_bytes, self.alignment_bytes)?;
            if slot.aligned_bytes != expected_aligned {
                return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                    "tensor '{}' aligned_bytes {} != expected {}",
                    slot.tensor_name, slot.aligned_bytes, expected_aligned
                )));
            }
            if !slot.arena_offset.is_multiple_of(self.alignment_bytes) {
                return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                    "tensor '{}' offset {} not aligned to {}",
                    slot.tensor_name, slot.arena_offset, self.alignment_bytes
                )));
            }
            let end = slot.end_offset().ok_or(ScratchPlanError::Overflow)?;
            if end > self.activation_arena_bytes {
                return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                    "tensor '{}' end {} exceeds activation_arena_bytes {}",
                    slot.tensor_name, end, self.activation_arena_bytes
                )));
            }
            if slot.aligned_bytes > 0 {
                max_end = max_end.max(end);
            }
            computed_naive = computed_naive
                .checked_add(slot.aligned_bytes)
                .ok_or(ScratchPlanError::Overflow)?;
            if slot.reused_from_freed_slot {
                computed_reused += 1;
            }
        }

        if computed_naive != self.naive_unaliased_bytes
            || computed_reused != self.reused_allocation_count
            || self.activation_arena_bytes < max_end
            || self.activation_arena_bytes > self.naive_unaliased_bytes
            || !self
                .activation_arena_bytes
                .is_multiple_of(self.alignment_bytes)
            || !self
                .operator_scratch_bytes
                .is_multiple_of(self.alignment_bytes)
            || self
                .activation_arena_bytes
                .checked_add(self.operator_scratch_bytes)
                != Some(self.total_arena_bytes)
            || self.total_arena_bytes > MAX_SCRATCH_ARENA_BYTES
            || self
                .naive_unaliased_bytes
                .saturating_sub(self.activation_arena_bytes)
                != self.reuse_saved_bytes
        {
            return Err(ScratchPlanError::AliasingOrInvariantViolation(
                "scratch arena summary totals disagree with slot assignments".to_owned(),
            ));
        }

        // Pairwise interval-overlap check across all non-empty allocations!
        for i in 0..self.assignments.len() {
            let a = &self.assignments[i];
            if a.aligned_bytes == 0 {
                continue;
            }
            let a_born = a.producer_step;
            let a_dies = a.release_after_step.unwrap_or(usize::MAX);
            let a_lo = a.arena_offset;
            let a_hi = a.arena_offset + a.aligned_bytes;

            for b in &self.assignments[(i + 1)..] {
                if b.aligned_bytes == 0 {
                    continue;
                }
                let b_born = b.producer_step;
                let b_dies = b.release_after_step.unwrap_or(usize::MAX);
                let lifetime_overlaps = a_born <= b_dies && b_born <= a_dies;
                if lifetime_overlaps {
                    let b_lo = b.arena_offset;
                    let b_hi = b.arena_offset + b.aligned_bytes;
                    let bytes_overlap = a_lo < b_hi && b_lo < a_hi;
                    if bytes_overlap {
                        return Err(ScratchPlanError::AliasingOrInvariantViolation(format!(
                            "aliasing detected: '{}' [{a_lo}..{a_hi}) overlaps live '{}' [{b_lo}..{b_hi})",
                            a.tensor_name, b.tensor_name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Computes canonical SHA-256 commitment under [`SCRATCH_ARENA_PLAN_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, ScratchPlanError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(SCRATCH_ARENA_PLAN_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.graph_digest);
        enc.digest(self.memory_plan_digest);
        enc.u64(self.alignment_bytes as u64);
        enc.u64(self.activation_arena_bytes as u64);
        enc.u64(self.operator_scratch_bytes as u64);
        enc.u64(self.total_arena_bytes as u64);
        enc.u64(self.naive_unaliased_bytes as u64);
        enc.u64(self.reuse_saved_bytes as u64);
        enc.u64(self.reused_allocation_count as u64);
        enc.u32(self.assignments.len() as u32);
        for slot in &self.assignments {
            enc.text(&slot.tensor_name);
            enc.u64(slot.producer_step as u64);
            match slot.release_after_step {
                None => enc.u8(0),
                Some(step) => {
                    enc.u8(1);
                    enc.u64(step as u64);
                }
            }
            enc.u64(slot.logical_bytes as u64);
            enc.u64(slot.aligned_bytes as u64);
            enc.u64(slot.arena_offset as u64);
            enc.u8(u8::from(slot.reused_from_freed_slot));
        }
    }

    /// Validates format version, canonical ordering, zero-aliasing invariants, and digest integrity.
    pub fn verify_self(&self) -> Result<(), ScratchPlanError> {
        if self.format_version != SCRATCH_PLAN_WIRE_VERSION {
            return Err(ScratchPlanError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        for pair in self.assignments.windows(2) {
            let k0 = (pair[0].producer_step, pair[0].tensor_name.as_str());
            let k1 = (pair[1].producer_step, pair[1].tensor_name.as_str());
            if k0 >= k1 {
                return Err(ScratchPlanError::MalformedWire(
                    "slot assignments not sorted canonically by (producer_step, tensor_name)"
                        .to_owned(),
                ));
            }
        }
        self.verify_no_aliasing_overlaps()?;
        if self.compute_digest()? != self.plan_digest {
            return Err(ScratchPlanError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes into its versioned, checksummed `FSSSPL01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ScratchPlanError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.plan_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or(ScratchPlanError::WireTooLarge {
                observed: usize::MAX,
                maximum: MAX_SCRATCH_PLAN_WIRE_BYTES,
            })?;
        if total > MAX_SCRATCH_PLAN_WIRE_BYTES {
            return Err(ScratchPlanError::WireTooLarge {
                observed: total,
                maximum: MAX_SCRATCH_PLAN_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&SCRATCH_PLAN_WIRE_MAGIC);
        out.extend_from_slice(&SCRATCH_PLAN_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(SCRATCH_ARENA_PLAN_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSSPL01` v1 binary wire envelope, failing closed on tamper or aliasing.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ScratchPlanError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(ScratchPlanError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_SCRATCH_PLAN_WIRE_BYTES {
            return Err(ScratchPlanError::WireTooLarge {
                observed: bytes.len(),
                maximum: MAX_SCRATCH_PLAN_WIRE_BYTES,
            });
        }
        if bytes[..8] != SCRATCH_PLAN_WIRE_MAGIC {
            return Err(ScratchPlanError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != SCRATCH_PLAN_WIRE_VERSION {
            return Err(ScratchPlanError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                ScratchPlanError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(ScratchPlanError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(SCRATCH_ARENA_PLAN_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(ScratchPlanError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        let graph_digest = dec
            .digest()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        let memory_plan_digest = dec
            .digest()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        let alignment_bytes = decode_usize(&mut dec)?;
        let activation_arena_bytes = decode_usize(&mut dec)?;
        let operator_scratch_bytes = decode_usize(&mut dec)?;
        let total_arena_bytes = decode_usize(&mut dec)?;
        let naive_unaliased_bytes = decode_usize(&mut dec)?;
        let reuse_saved_bytes = decode_usize(&mut dec)?;
        let reused_allocation_count = decode_usize(&mut dec)?;
        let slot_count =
            dec.u32()
                .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))? as usize;
        if slot_count > MAX_MEMORY_PLAN_VALUES {
            return Err(ScratchPlanError::MalformedWire(format!(
                "slot_count {slot_count} exceeds maximum {MAX_MEMORY_PLAN_VALUES}"
            )));
        }
        let mut assignments = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let tensor_name = dec
                .text()
                .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?
                .to_owned();
            if tensor_name.is_empty()
                || tensor_name.len() > MAX_SCRATCH_TENSOR_NAME_BYTES
                || tensor_name.chars().any(char::is_control)
            {
                return Err(ScratchPlanError::MalformedWire(
                    "invalid tensor_name in scratch slot".to_owned(),
                ));
            }
            let producer_step = decode_usize(&mut dec)?;
            let release_after_step = match dec
                .u8()
                .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?
            {
                0 => None,
                1 => Some(decode_usize(&mut dec)?),
                other => {
                    return Err(ScratchPlanError::MalformedWire(format!(
                        "unknown release_after_step tag {other}"
                    )));
                }
            };
            let logical_bytes = decode_usize(&mut dec)?;
            let aligned_bytes = decode_usize(&mut dec)?;
            let arena_offset = decode_usize(&mut dec)?;
            let reused_from_freed_slot = match dec
                .u8()
                .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?
            {
                0 => false,
                1 => true,
                other => {
                    return Err(ScratchPlanError::MalformedWire(format!(
                        "unknown reused_from_freed_slot tag {other}"
                    )));
                }
            };
            assignments.push(ScratchSlotAssignment {
                tensor_name,
                producer_step,
                release_after_step,
                logical_bytes,
                aligned_bytes,
                arena_offset,
                reused_from_freed_slot,
            });
        }
        let plan_digest = dec
            .digest()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;

        let plan = Self {
            format_version,
            graph_digest,
            memory_plan_digest,
            alignment_bytes,
            activation_arena_bytes,
            operator_scratch_bytes,
            total_arena_bytes,
            naive_unaliased_bytes,
            reuse_saved_bytes,
            reused_allocation_count,
            assignments,
            plan_digest,
        };
        plan.verify_self()?;
        Ok(plan)
    }
}

fn align_up(bytes: usize, alignment: usize) -> Result<usize, ScratchPlanError> {
    if bytes == 0 {
        return Ok(0);
    }
    let mask = alignment - 1;
    bytes
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(ScratchPlanError::Overflow)
}

fn insert_and_coalesce_free(
    free: &mut Vec<(usize, usize)>,
    offset: usize,
    len: usize,
) -> Result<(), ScratchPlanError> {
    let end = offset.checked_add(len).ok_or(ScratchPlanError::Overflow)?;
    let pos = free.partition_point(|&(off, _)| off < offset);
    free.insert(pos, (offset, len));
    // Coalesce with next interval if contiguous.
    if pos + 1 < free.len() {
        let (next_off, next_len) = free[pos + 1];
        if end == next_off {
            free[pos].1 = free[pos]
                .1
                .checked_add(next_len)
                .ok_or(ScratchPlanError::Overflow)?;
            free.remove(pos + 1);
        }
    }
    // Coalesce with previous interval if contiguous.
    if pos > 0 {
        let (prev_off, prev_len) = free[pos - 1];
        let prev_end = prev_off
            .checked_add(prev_len)
            .ok_or(ScratchPlanError::Overflow)?;
        if prev_end == free[pos].0 {
            free[pos - 1].1 = prev_len
                .checked_add(free[pos].1)
                .ok_or(ScratchPlanError::Overflow)?;
            free.remove(pos);
        }
    }
    Ok(())
}

fn decode_usize(dec: &mut CanonicalDecoder<'_>) -> Result<usize, ScratchPlanError> {
    let raw = dec
        .u64()
        .map_err(|e| ScratchPlanError::MalformedWire(e.to_string()))?;
    usize::try_from(raw).map_err(|_| ScratchPlanError::Overflow)
}
