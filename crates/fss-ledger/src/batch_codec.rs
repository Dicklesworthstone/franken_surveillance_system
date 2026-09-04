//! Versioned deterministic codec for canonical evidence batches.

use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, OperationId, Plane, TimestampNs,
};

const MAGIC: [u8; 8] = *b"FSSBAT01";
const VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_DELTAS: usize = 16_384;
const MAX_CHILDREN: usize = 16_384;

/// Deterministic evidence-batch codec failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchCodecError {
    /// Input ended before one complete field.
    UnexpectedEof,
    /// File magic is not the FSS evidence-batch format.
    InvalidMagic,
    /// File format version is unsupported.
    UnsupportedVersion(u16),
    /// A bounded count or string exceeds the codec limit.
    BoundExceeded(&'static str),
    /// A string field is not UTF-8.
    InvalidUtf8,
    /// A boolean tag is not zero or one.
    InvalidBoolean(u8),
    /// A plane tag is unknown.
    InvalidPlane(u8),
    /// A digest algorithm tag is unknown.
    InvalidDigestAlgorithm(u8),
    /// Bytes remain after one complete batch.
    TrailingBytes,
    /// Decoded semantic content violates the core contract.
    Contract(ContractError),
}

impl fmt::Display for BatchCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => formatter.write_str("batch codec unexpected EOF"),
            Self::InvalidMagic => formatter.write_str("batch codec invalid magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "batch codec unsupported version {version}")
            }
            Self::BoundExceeded(field) => write!(formatter, "batch codec bound exceeded: {field}"),
            Self::InvalidUtf8 => formatter.write_str("batch codec invalid UTF-8"),
            Self::InvalidBoolean(value) => write!(formatter, "batch codec invalid boolean {value}"),
            Self::InvalidPlane(value) => write!(formatter, "batch codec invalid plane {value}"),
            Self::InvalidDigestAlgorithm(value) => {
                write!(formatter, "batch codec invalid digest algorithm {value}")
            }
            Self::TrailingBytes => formatter.write_str("batch codec trailing bytes"),
            Self::Contract(error) => write!(formatter, "batch codec semantic error: {error}"),
        }
    }
}

impl Error for BatchCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for BatchCodecError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

/// Encodes one canonical evidence batch into a stable bounded binary envelope.
pub fn encode_batch(batch: &EvidenceDeltaBatch) -> Result<Vec<u8>, BatchCodecError> {
    if !batch.is_canonically_ordered() {
        return Err(ContractError::NonCanonicalOrdering.into());
    }
    if batch.computed_digest() != batch.batch_digest {
        return Err(ContractError::DigestMismatch.into());
    }
    if batch.deltas.len() > MAX_DELTAS {
        return Err(BatchCodecError::BoundExceeded("deltas"));
    }
    if batch.children.len() > MAX_CHILDREN {
        return Err(BatchCodecError::BoundExceeded("children"));
    }

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    text(&mut out, batch.batch_id.as_str())?;
    anchor(&mut out, &batch.basis_anchor)?;
    anchor(&mut out, &batch.new_anchor)?;
    u32_count(&mut out, batch.deltas.len(), "deltas")?;
    for delta in &batch.deltas {
        text(&mut out, &delta.delta_id)?;
        text(&mut out, &delta.family)?;
        text(&mut out, delta.object_id.as_str())?;
        option_u64(&mut out, delta.prior_generation);
        out.extend_from_slice(&delta.new_generation.to_be_bytes());
        interval(&mut out, delta.validity);
        out.push(match delta.plane {
            Plane::Authority => 0,
            Plane::Cognition => 1,
            Plane::Effect => 2,
        });
        digest(&mut out, delta.payload_digest);
        option_digest(&mut out, delta.witness_digest);
        match &delta.operation_id {
            Some(operation) => {
                out.push(1);
                text(&mut out, operation.as_str())?;
            }
            None => out.push(0),
        }
    }
    u32_count(&mut out, batch.children.len(), "children")?;
    for child in &batch.children {
        digest(&mut out, *child);
    }
    digest(&mut out, batch.batch_digest);
    Ok(out)
}

/// Decodes and semantically verifies one evidence batch.
pub fn decode_batch(bytes: &[u8]) -> Result<EvidenceDeltaBatch, BatchCodecError> {
    let mut reader = Reader::new(bytes);
    if reader.array::<8>()? != MAGIC {
        return Err(BatchCodecError::InvalidMagic);
    }
    let version = reader.u16()?;
    if version != VERSION {
        return Err(BatchCodecError::UnsupportedVersion(version));
    }
    let batch_id = BatchId::parse(reader.text()?)?;
    let basis_anchor = reader.anchor()?;
    let new_anchor = reader.anchor()?;
    let delta_count = reader.count(MAX_DELTAS, "deltas")?;
    let mut deltas = Vec::with_capacity(delta_count);
    for _ in 0..delta_count {
        let delta_id = reader.text()?;
        let family = reader.text()?;
        let object_id = ObjectId::parse(reader.text()?)?;
        let prior_generation = reader.option_u64()?;
        let new_generation = reader.u64()?;
        let validity = reader.interval()?;
        let plane = match reader.u8()? {
            0 => Plane::Authority,
            1 => Plane::Cognition,
            2 => Plane::Effect,
            value => return Err(BatchCodecError::InvalidPlane(value)),
        };
        let payload_digest = reader.digest()?;
        let witness_digest = reader.option_digest()?;
        let operation_id = if reader.boolean()? {
            Some(OperationId::parse(reader.text()?)?)
        } else {
            None
        };
        deltas.push(EvidenceDelta {
            delta_id,
            family,
            object_id,
            prior_generation,
            new_generation,
            validity,
            plane,
            payload_digest,
            witness_digest,
            operation_id,
        });
    }
    let child_count = reader.count(MAX_CHILDREN, "children")?;
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(reader.digest()?);
    }
    let batch_digest = reader.digest()?;
    reader.finish()?;

    let batch = EvidenceDeltaBatch {
        batch_id,
        basis_anchor,
        new_anchor,
        deltas,
        children,
        batch_digest,
    };
    if !batch.is_canonically_ordered() {
        return Err(ContractError::NonCanonicalOrdering.into());
    }
    if batch.computed_digest() != batch.batch_digest {
        return Err(ContractError::DigestMismatch.into());
    }
    Ok(batch)
}

fn anchor(out: &mut Vec<u8>, value: &LedgerAnchor) -> Result<(), BatchCodecError> {
    text(out, &value.site_lineage)?;
    out.extend_from_slice(&value.ledger_epoch.to_be_bytes());
    out.extend_from_slice(&value.commit_sequence.to_be_bytes());
    out.extend_from_slice(&value.adapter_registry_epoch.to_be_bytes());
    out.extend_from_slice(&value.schema_epoch.to_be_bytes());
    out.extend_from_slice(&value.policy_epoch.to_be_bytes());
    out.extend_from_slice(&value.privacy_epoch.to_be_bytes());
    digest(out, value.state_root);
    Ok(())
}

fn interval(out: &mut Vec<u8>, value: CaptureInterval) {
    out.extend_from_slice(&value.earliest.0.to_be_bytes());
    out.extend_from_slice(&value.latest.0.to_be_bytes());
}

fn digest(out: &mut Vec<u8>, value: ContentDigest) {
    out.push(match value.algorithm() {
        DigestAlgorithm::Sha256 => 1,
        DigestAlgorithm::Blake3 => 2,
    });
    out.extend_from_slice(&value.bytes());
}

fn option_digest(out: &mut Vec<u8>, value: Option<ContentDigest>) {
    match value {
        Some(value) => {
            out.push(1);
            digest(out, value);
        }
        None => out.push(0),
    }
}

fn option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
        None => out.push(0),
    }
}

fn text(out: &mut Vec<u8>, value: &str) -> Result<(), BatchCodecError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(BatchCodecError::BoundExceeded("text"));
    }
    let length = u32::try_from(value.len()).map_err(|_| BatchCodecError::BoundExceeded("text"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn u32_count(out: &mut Vec<u8>, value: usize, field: &'static str) -> Result<(), BatchCodecError> {
    let value = u32::try_from(value).map_err(|_| BatchCodecError::BoundExceeded(field))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BatchCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(BatchCodecError::UnexpectedEof)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(BatchCodecError::UnexpectedEof)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(slice);
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BatchCodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, BatchCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BatchCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, BatchCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i128(&mut self) -> Result<i128, BatchCodecError> {
        Ok(i128::from_be_bytes(self.array()?))
    }

    fn boolean(&mut self) -> Result<bool, BatchCodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(BatchCodecError::InvalidBoolean(value)),
        }
    }

    fn text(&mut self) -> Result<String, BatchCodecError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| BatchCodecError::BoundExceeded("text"))?;
        if length > MAX_TEXT_BYTES {
            return Err(BatchCodecError::BoundExceeded("text"));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BatchCodecError::UnexpectedEof)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(BatchCodecError::UnexpectedEof)?;
        self.offset = end;
        String::from_utf8(slice.to_vec()).map_err(|_| BatchCodecError::InvalidUtf8)
    }

    fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize, BatchCodecError> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| BatchCodecError::BoundExceeded(field))?;
        if count > maximum {
            return Err(BatchCodecError::BoundExceeded(field));
        }
        Ok(count)
    }

    fn digest(&mut self) -> Result<ContentDigest, BatchCodecError> {
        let algorithm = match self.u8()? {
            1 => DigestAlgorithm::Sha256,
            2 => DigestAlgorithm::Blake3,
            value => return Err(BatchCodecError::InvalidDigestAlgorithm(value)),
        };
        Ok(ContentDigest::new(algorithm, self.array()?))
    }

    fn option_digest(&mut self) -> Result<Option<ContentDigest>, BatchCodecError> {
        if self.boolean()? {
            Ok(Some(self.digest()?))
        } else {
            Ok(None)
        }
    }

    fn option_u64(&mut self) -> Result<Option<u64>, BatchCodecError> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn interval(&mut self) -> Result<CaptureInterval, BatchCodecError> {
        Ok(CaptureInterval::new(
            TimestampNs(self.i128()?),
            TimestampNs(self.i128()?),
        )?)
    }

    fn anchor(&mut self) -> Result<LedgerAnchor, BatchCodecError> {
        Ok(LedgerAnchor {
            site_lineage: self.text()?,
            ledger_epoch: self.u64()?,
            commit_sequence: self.u64()?,
            adapter_registry_epoch: self.u64()?,
            schema_epoch: self.u64()?,
            policy_epoch: self.u64()?,
            privacy_epoch: self.u64()?,
            state_root: self.digest()?,
        })
    }

    fn finish(self) -> Result<(), BatchCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BatchCodecError::TrailingBytes)
        }
    }
}
