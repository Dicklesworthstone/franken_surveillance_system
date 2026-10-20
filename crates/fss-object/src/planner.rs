#![forbid(unsafe_code)]
//! Archive cost/chunk planner (FSS-067).
//!
//! Deterministic planning of archive-part upload chunking with exact cost
//! rows — no allocation, no I/O, no floats. Given object sizes and a
//! fixed part-size policy, the planner produces the complete chunk layout
//! (offsets, lengths, part count) and a cost row (bytes on wire, part
//! count, transfer-work units) that the publication lane books before any
//! byte moves. Plans are pure functions of their inputs: identical
//! requests yield identical plans and plan digests.

use fss_core::ContentDigest;

/// Hard ceiling on parts in one plan (S3-style multipart cap, 10,000).
pub const MAX_PARTS: u64 = 10_000;
/// Minimum part size admitted (5 MiB, the de-facto object-store floor).
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
/// Maximum object size admitted (5 TiB).
pub const MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

/// Typed planner refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerError {
    /// The requested object size exceeds the ceiling.
    ObjectTooLarge {
        /// Requested bytes.
        requested: u64,
        /// Maximum admitted.
        maximum: u64,
    },
    /// The part size is outside the admitted window.
    PartSizeInvalid {
        /// Requested part size.
        requested: u64,
        /// Minimum admitted.
        minimum: u64,
    },
    /// The plan would exceed the part-count ceiling for this size and
    /// part size.
    TooManyParts {
        /// Computed part count.
        parts: u64,
        /// Maximum admitted.
        maximum: u64,
    },
}

impl std::fmt::Display for PlannerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObjectTooLarge { requested, maximum } => {
                write!(f, "object {requested} bytes exceeds the {maximum} ceiling")
            }
            Self::PartSizeInvalid { requested, minimum } => {
                write!(f, "part size {requested} below the {minimum} floor")
            }
            Self::TooManyParts { parts, maximum } => {
                write!(f, "plan needs {parts} parts, above the {maximum} ceiling")
            }
        }
    }
}

impl std::error::Error for PlannerError {}

/// Fixed chunking policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkPolicy {
    /// Part size in bytes. Every part except the last is exactly this
    /// size; the last part carries the remainder (and may be smaller than
    /// the floor — the floor constrains full parts only).
    pub part_size: u64,
}

impl Default for ChunkPolicy {
    fn default() -> Self {
        Self {
            part_size: 64 * 1024 * 1024,
        }
    }
}

/// One planned chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedChunk {
    /// Zero-based chunk index.
    pub index: u64,
    /// Byte offset from the object start.
    pub offset: u64,
    /// Chunk length in bytes.
    pub len: u64,
}

/// The complete plan with its cost row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkPlan {
    /// Total object bytes.
    pub object_bytes: u64,
    /// Part size used (from the policy).
    pub part_size: u64,
    /// Chunks in offset order.
    pub chunks: Vec<PlannedChunk>,
    /// Bytes on the wire (object bytes; uploads carry no padding).
    pub wire_bytes: u64,
    /// Transfer work units: one per part (journal + verify + complete).
    pub transfer_work: u64,
}

impl ChunkPlan {
    /// Content digest of the plan: canonical over policy + layout.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut material = Vec::new();
        material.extend_from_slice(&self.object_bytes.to_be_bytes());
        material.extend_from_slice(&self.part_size.to_be_bytes());
        for chunk in &self.chunks {
            material.extend_from_slice(&chunk.index.to_be_bytes());
            material.extend_from_slice(&chunk.offset.to_be_bytes());
            material.extend_from_slice(&chunk.len.to_be_bytes());
        }
        ContentDigest::sha256(&material)
    }
}

/// Plans the chunk layout for one archive object.
///
/// Deterministic: `(object_bytes, policy)` fully determine the plan.
///
/// # Errors
/// Typed refusals for oversize objects, sub-floor part sizes, and
/// part-count overflow.
pub fn plan_chunks(object_bytes: u64, policy: ChunkPolicy) -> Result<ChunkPlan, PlannerError> {
    if object_bytes > MAX_OBJECT_BYTES {
        return Err(PlannerError::ObjectTooLarge {
            requested: object_bytes,
            maximum: MAX_OBJECT_BYTES,
        });
    }
    if policy.part_size < MIN_PART_SIZE {
        return Err(PlannerError::PartSizeInvalid {
            requested: policy.part_size,
            minimum: MIN_PART_SIZE,
        });
    }
    if object_bytes == 0 {
        // An empty object is one zero-length chunk: uploaded as a single
        // empty part, work unit 1.
        return Ok(ChunkPlan {
            object_bytes: 0,
            part_size: policy.part_size,
            chunks: vec![PlannedChunk {
                index: 0,
                offset: 0,
                len: 0,
            }],
            wire_bytes: 0,
            transfer_work: 1,
        });
    }
    let full_parts = object_bytes / policy.part_size;
    let remainder = object_bytes % policy.part_size;
    let parts = full_parts + u64::from(remainder > 0);
    if parts > MAX_PARTS {
        return Err(PlannerError::TooManyParts {
            parts,
            maximum: MAX_PARTS,
        });
    }
    let mut chunks = Vec::with_capacity(parts as usize);
    for index in 0..parts {
        let offset = index * policy.part_size;
        let len = if index + 1 == parts && remainder > 0 {
            remainder
        } else {
            policy.part_size
        };
        chunks.push(PlannedChunk { index, offset, len });
    }
    Ok(ChunkPlan {
        object_bytes,
        part_size: policy.part_size,
        chunks,
        wire_bytes: object_bytes,
        transfer_work: parts,
    })
}
