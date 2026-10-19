#![forbid(unsafe_code)]
//! Canonical tensor byte encoding (FSS-138).
//!
//! One deterministic byte form for every tensor: content-addressed model
//! packages, provenance receipts, and replay bundles all bind tensors by
//! the digest of THIS encoding. The form is the contiguous row-major
//! semantic content — dtype, shape, generation, then storage bytes in
//! big-endian framing — independent of any transient stride or view
//! layout (materialize views before canonicalizing).
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! magic "FSTN" | version u32 | dtype tag u8 | rank u32
//! dims: u64 x rank | generation u64
//! element_count u64 | storage_len u64 | storage bytes
//! ```
//!
//! Decoding validates magic, version, and internal consistency
//! (`element_count == product(dims)` and
//! `storage_len == element_count x dtype.size_bytes()`), so a canonical
//! buffer is self-verifying before anything hashes it.

use fss_core::{ContentDigest, Generation};

use crate::dtype::DType;
use crate::shape::Shape;
use crate::tensor::Tensor;

/// Magic bytes of the canonical tensor form.
pub const CANONICAL_TENSOR_MAGIC: &[u8] = b"FSTN";
/// Current canonical-form version.
pub const CANONICAL_TENSOR_VERSION: u32 = 1;
/// Header size: magic(4) + version(4) + dtype(1) + rank(4).
const HEADER_LEN: usize = 4 + 4 + 1 + 4;

/// Typed canonical-form refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalTensorError {
    /// The buffer does not start with the magic.
    BadMagic,
    /// Unsupported canonical-form version.
    UnknownVersion(u32),
    /// Unknown dtype tag.
    UnknownDtype(u8),
    /// The buffer is shorter than its declared contents.
    Truncated,
    /// Bytes remain after the declared storage.
    Trailing,
    /// element_count != product(dims), or storage_len mismatches.
    Inconsistent {
        /// Machine-readable reason.
        reason: &'static str,
    },
}

impl std::fmt::Display for CanonicalTensorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "canonical tensor: bad magic"),
            Self::UnknownVersion(v) => write!(f, "canonical tensor: unknown version {v}"),
            Self::UnknownDtype(tag) => write!(f, "canonical tensor: unknown dtype tag {tag}"),
            Self::Truncated => write!(f, "canonical tensor: truncated"),
            Self::Trailing => write!(f, "canonical tensor: trailing bytes"),
            Self::Inconsistent { reason } => write!(f, "canonical tensor: {reason}"),
        }
    }
}

impl std::error::Error for CanonicalTensorError {}

/// Reverse tag map over the frozen dtype set.
fn dtype_for_tag(tag: u8) -> Option<DType> {
    const ALL: [DType; 13] = [
        DType::F32,
        DType::F64,
        DType::F16,
        DType::BF16,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::U16,
        DType::U32,
        DType::U64,
        DType::Bool,
    ];
    ALL.into_iter().find(|d| d.type_tag() == tag)
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Encodes the canonical form of `(dtype, shape, generation, storage)`.
///
/// # Errors
/// Typed refusal if the storage length does not match the shape's element
/// count times the dtype size.
pub fn canonical_tensor_bytes(
    dtype: DType,
    shape: &Shape,
    generation: Generation,
    storage: &[u8],
) -> Result<Vec<u8>, CanonicalTensorError> {
    let elements = shape
        .num_elements()
        .map_err(|_| CanonicalTensorError::Inconsistent {
            reason: "shape element count overflow",
        })?;
    let expected_len =
        elements
            .checked_mul(dtype.size_bytes())
            .ok_or(CanonicalTensorError::Inconsistent {
                reason: "storage length overflow",
            })?;
    if storage.len() != expected_len {
        return Err(CanonicalTensorError::Inconsistent {
            reason: "storage length does not match shape x dtype size",
        });
    }
    let mut out = Vec::with_capacity(HEADER_LEN + shape.rank() * 8 + 24 + storage.len());
    out.extend_from_slice(CANONICAL_TENSOR_MAGIC);
    put_u32(&mut out, CANONICAL_TENSOR_VERSION);
    out.push(dtype.type_tag());
    let rank = u32::try_from(shape.rank()).map_err(|_| CanonicalTensorError::Inconsistent {
        reason: "rank exceeds u32",
    })?;
    put_u32(&mut out, rank);
    for dim in shape.dims() {
        put_u64(
            &mut out,
            u64::try_from(*dim).map_err(|_| CanonicalTensorError::Inconsistent {
                reason: "dimension exceeds u64",
            })?,
        );
    }
    put_u64(&mut out, generation.get());
    put_u64(&mut out, elements as u64);
    put_u64(&mut out, storage.len() as u64);
    out.extend_from_slice(storage);
    Ok(out)
}

/// Encodes a tensor's canonical form (contiguous row-major semantic
/// content).
///
/// # Errors
/// Typed refusal on shape/storage inconsistency.
pub fn tensor_canonical_bytes(tensor: &Tensor) -> Result<Vec<u8>, CanonicalTensorError> {
    canonical_tensor_bytes(
        tensor.dtype(),
        tensor.shape(),
        tensor.generation(),
        tensor.view().storage().as_slice(),
    )
}

/// The content digest of a tensor's canonical form: the tensor identity
/// for model packages, receipts, and replay bindings.
///
/// # Errors
/// Typed refusal on shape/storage inconsistency.
pub fn tensor_canonical_digest(tensor: &Tensor) -> Result<ContentDigest, CanonicalTensorError> {
    Ok(ContentDigest::sha256(&tensor_canonical_bytes(tensor)?))
}

/// A decoded canonical tensor form (owned parts; construct a [`Tensor`]
/// with [`Tensor::from_parts`] if desired).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTensor {
    /// Element type.
    pub dtype: DType,
    /// Row-major shape.
    pub shape: Shape,
    /// Tensor generation.
    pub generation: Generation,
    /// Contiguous storage bytes.
    pub storage: Vec<u8>,
}

/// Decodes and validates a canonical tensor buffer. Self-verifying:
/// magic, version, dtype tag, exact lengths, and count consistency are
/// all checked before anything is exposed.
///
/// # Errors
/// Typed refusals for every malformed shape.
pub fn decode_canonical_tensor(bytes: &[u8]) -> Result<CanonicalTensor, CanonicalTensorError> {
    if bytes.len() < HEADER_LEN {
        return Err(CanonicalTensorError::Truncated);
    }
    if &bytes[..4] != CANONICAL_TENSOR_MAGIC {
        return Err(CanonicalTensorError::BadMagic);
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != CANONICAL_TENSOR_VERSION {
        return Err(CanonicalTensorError::UnknownVersion(version));
    }
    let dtype = dtype_for_tag(bytes[8]).ok_or(CanonicalTensorError::UnknownDtype(bytes[8]))?;
    let rank = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]) as usize;
    let dims_len = rank
        .checked_mul(8)
        .ok_or(CanonicalTensorError::Inconsistent {
            reason: "rank overflow",
        })?;
    let mut pos = HEADER_LEN;
    let dims_end = pos
        .checked_add(dims_len)
        .ok_or(CanonicalTensorError::Truncated)?;
    if dims_end + 24 > bytes.len() {
        return Err(CanonicalTensorError::Truncated);
    }
    let mut dims = Vec::with_capacity(rank);
    for _ in 0..rank {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[pos..pos + 8]);
        dims.push(u64::from_be_bytes(a) as usize);
        pos += 8;
    }
    let read_u64 = |pos: &mut usize| -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[*pos..*pos + 8]);
        *pos += 8;
        u64::from_be_bytes(a)
    };
    let generation = Generation::from_u64(read_u64(&mut pos));
    let element_count = read_u64(&mut pos) as usize;
    let storage_len = read_u64(&mut pos) as usize;
    let shape = Shape::new(dims).map_err(|_| CanonicalTensorError::Inconsistent {
        reason: "invalid shape",
    })?;
    let shape_elements = shape
        .num_elements()
        .map_err(|_| CanonicalTensorError::Inconsistent {
            reason: "shape element count overflow",
        })?;
    if shape_elements != element_count {
        return Err(CanonicalTensorError::Inconsistent {
            reason: "element count does not match shape",
        });
    }
    let expected_len = element_count.checked_mul(dtype.size_bytes()).ok_or(
        CanonicalTensorError::Inconsistent {
            reason: "storage length overflow",
        },
    )?;
    if storage_len != expected_len {
        return Err(CanonicalTensorError::Inconsistent {
            reason: "declared storage length does not match count x dtype size",
        });
    }
    let storage_end = pos
        .checked_add(storage_len)
        .ok_or(CanonicalTensorError::Truncated)?;
    if storage_end != bytes.len() {
        return if storage_end < bytes.len() {
            Err(CanonicalTensorError::Trailing)
        } else {
            Err(CanonicalTensorError::Truncated)
        };
    }
    Ok(CanonicalTensor {
        dtype,
        shape,
        generation,
        storage: bytes[pos..storage_end].to_vec(),
    })
}
