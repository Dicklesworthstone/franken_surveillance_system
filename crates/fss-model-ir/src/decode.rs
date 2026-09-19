#![forbid(unsafe_code)]
//! Bounded inverse of the existing frozen Model IR v1 canonical writer.
//!
//! This module loads data, not executable plugins. A supplied digest pins bytes; it does not
//! establish publisher trust, a license, model quality, or permission to activate a model.

use fss_core::{ContentDigest, Generation};
use fss_tensor::{DType, MAX_TENSOR_RANK, Shape};

use crate::{
    AttrValue, AttributeMap, GraphNode, MODEL_IR_DIGEST_DOMAIN, ModelIrError, ModelIrGraph,
    ModelIrVersion, OPERATOR_SPECS, TensorPort, compute_operator_table_digest,
    encode_canonical_model_ir,
};

/// Maximum encoded graph bytes accepted by this reader.
pub const MAX_MODEL_IR_BYTES: usize = 16 * 1024 * 1024;
/// Maximum nodes, declared ports, or names in a single wire collection.
pub const MAX_MODEL_IR_ITEMS: usize = 4_096;
/// Maximum UTF-8 bytes in one graph identifier, name, or attribute string.
pub const MAX_MODEL_IR_TEXT_BYTES: usize = 4_096;

/// Explicit refusal from canonical graph loading. No partial graph escapes.
#[derive(Debug)]
pub enum ModelIrDecodeError {
    /// An input ended inside a field.
    Truncated,
    /// A length, count, dimension, or metadata allocation bound was exceeded.
    Limit,
    /// Magic, version, operator table, dtype, operator, or attribute tag is unsupported.
    Unsupported,
    /// The independently supplied graph digest does not identify these bytes.
    DigestMismatch,
    /// The wire bytes are malformed or not the canonical writer's exact output.
    NonCanonical,
    /// The decoded graph violates the existing IR type, generation, or topology contract.
    Semantic(ModelIrError),
}

impl std::fmt::Display for ModelIrDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated canonical model graph",
            Self::Limit => "canonical model graph bound exceeded",
            Self::Unsupported => "unsupported canonical model graph contract",
            Self::DigestMismatch => "canonical model graph digest mismatch",
            Self::NonCanonical => "noncanonical model graph bytes",
            Self::Semantic(_) => "invalid model graph semantics",
        })
    }
}
impl std::error::Error for ModelIrDecodeError {}
impl From<ModelIrError> for ModelIrDecodeError {
    fn from(error: ModelIrError) -> Self { Self::Semantic(error) }
}

/// Loads one complete existing `fss.model_ir.v1` object by its exact expected digest.
///
/// Counts are checked against both hard ceilings and remaining wire bytes before allocation.
/// The existing semantic validator checks topology, shapes and generations. Re-encoding then
/// enforces normalized defaults, attribute order, numeric canonicalization and topological
/// tie-breaks; this reader never silently repairs a graph or substitutes an operator universe.
/// Tensor payload allocation and execution budgets belong to the executor, not this parser.
pub fn decode_canonical_model_ir(
    bytes: &[u8], expected: ContentDigest,
) -> Result<ModelIrGraph, ModelIrDecodeError> {
    if bytes.len() > MAX_MODEL_IR_BYTES { return Err(ModelIrDecodeError::Limit); }
    if ContentDigest::sha256(bytes) != expected { return Err(ModelIrDecodeError::DigestMismatch); }
    let mut r = Reader { bytes, position: 0 };
    if r.take(MODEL_IR_DIGEST_DOMAIN.len())? != MODEL_IR_DIGEST_DOMAIN
        || r.byte()? != 1 || r.u32()? != 1
    { return Err(ModelIrDecodeError::Unsupported); }
    if r.take(32)? != compute_operator_table_digest()?.bytes().as_slice() {
        return Err(ModelIrDecodeError::Unsupported);
    }
    let id = r.text()?;
    let generation = Generation(r.u64()?);
    let inputs = r.ports()?;
    let outputs = r.ports()?;
    let count = r.count(MAX_MODEL_IR_ITEMS, 24)?;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node_id = r.text()?;
        let operator_id = r.text()?;
        let op = OPERATOR_SPECS.iter().find(|spec| spec.stable_id == operator_id)
            .ok_or(ModelIrDecodeError::Unsupported)?.opcode;
        let name = r.text()?;
        let inputs = r.names()?;
        let outputs = r.names()?;
        let count = r.count(64, 5)?;
        let mut attributes = AttributeMap::new();
        let mut previous: Option<String> = None;
        for _ in 0..count {
            let key = r.text()?;
            if previous.as_ref().is_some_and(|p| p >= &key) {
                return Err(ModelIrDecodeError::NonCanonical);
            }
            previous = Some(key.clone());
            attributes.insert(key, r.attribute()?);
        }
        nodes.push(GraphNode::new(node_id, op, name, inputs, outputs, attributes)?);
    }
    if r.position != bytes.len() { return Err(ModelIrDecodeError::NonCanonical); }
    let graph = ModelIrGraph::new_validated(
        id, ModelIrVersion::V1, generation, inputs, outputs, nodes,
    )?;
    if encode_canonical_model_ir(&graph)? != bytes {
        return Err(ModelIrDecodeError::NonCanonical);
    }
    Ok(graph)
}

struct Reader<'a> { bytes: &'a [u8], position: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], ModelIrDecodeError> {
        let end = self.position.checked_add(size).ok_or(ModelIrDecodeError::Limit)?;
        let bytes = self.bytes.get(self.position..end).ok_or(ModelIrDecodeError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, ModelIrDecodeError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, ModelIrDecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ModelIrDecodeError::Truncated)?))
    }
    fn u64(&mut self) -> Result<u64, ModelIrDecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| ModelIrDecodeError::Truncated)?))
    }
    fn count(&mut self, ceiling: usize, minimum_bytes: usize) -> Result<usize, ModelIrDecodeError> {
        let n = usize::try_from(self.u32()?).map_err(|_| ModelIrDecodeError::Limit)?;
        if n > ceiling || n > (self.bytes.len() - self.position) / minimum_bytes {
            return Err(ModelIrDecodeError::Limit);
        }
        Ok(n)
    }
    fn text(&mut self) -> Result<String, ModelIrDecodeError> {
        let n = self.count(MAX_MODEL_IR_TEXT_BYTES, 1)?;
        Ok(std::str::from_utf8(self.take(n)?).map_err(|_| ModelIrDecodeError::NonCanonical)?.to_owned())
    }
    fn dtype(&mut self) -> Result<DType, ModelIrDecodeError> {
        Ok(match self.byte()? {
            1 => DType::F32, 2 => DType::F64, 3 => DType::F16, 4 => DType::BF16,
            5 => DType::I8, 6 => DType::I16, 7 => DType::I32, 8 => DType::I64,
            9 => DType::U8, 10 => DType::U16, 11 => DType::U32, 12 => DType::U64,
            13 => DType::Bool, _ => return Err(ModelIrDecodeError::Unsupported),
        })
    }
    fn shape(&mut self) -> Result<Shape, ModelIrDecodeError> {
        let count = self.count(MAX_TENSOR_RANK, 8)?;
        let mut dims = Vec::with_capacity(count);
        for _ in 0..count {
            let value = self.u64()?;
            if value > i64::MAX as u64 { return Err(ModelIrDecodeError::Limit); }
            dims.push(usize::try_from(value).map_err(|_| ModelIrDecodeError::Limit)?);
        }
        Shape::new(dims).map_err(|_| ModelIrDecodeError::Limit)
    }
    fn ports(&mut self) -> Result<Vec<TensorPort>, ModelIrDecodeError> {
        let count = self.count(MAX_MODEL_IR_ITEMS, 17)?;
        let mut ports = Vec::with_capacity(count);
        for _ in 0..count {
            let name = self.text()?;
            let dtype = self.dtype()?;
            let generation = Generation(self.u64()?);
            let shape = self.shape()?;
            ports.push(TensorPort::new(name, dtype, shape, generation)?);
        }
        Ok(ports)
    }
    fn names(&mut self) -> Result<Vec<String>, ModelIrDecodeError> {
        let count = self.count(MAX_MODEL_IR_ITEMS, 4)?;
        (0..count).map(|_| self.text()).collect()
    }
    fn float(&mut self) -> Result<f64, ModelIrDecodeError> {
        let bits = self.u64()?;
        let value = f64::from_bits(bits);
        if !value.is_finite() || bits == (-0.0_f64).to_bits() {
            return Err(ModelIrDecodeError::NonCanonical);
        }
        Ok(value)
    }
    fn attribute(&mut self) -> Result<AttrValue, ModelIrDecodeError> {
        Ok(match self.byte()? {
            1 => AttrValue::Bool(match self.byte()? {
                0 => false, 1 => true, _ => return Err(ModelIrDecodeError::NonCanonical),
            }),
            2 => AttrValue::Int(i64::from_be_bytes(self.take(8)?.try_into()
                .map_err(|_| ModelIrDecodeError::Truncated)?)),
            3 => AttrValue::Float(self.float()?),
            4 => AttrValue::String(self.text()?),
            5 => {
                let n = self.count(MAX_MODEL_IR_ITEMS, 8)?;
                let mut values = Vec::with_capacity(n);
                for _ in 0..n {
                    values.push(i64::from_be_bytes(self.take(8)?.try_into()
                        .map_err(|_| ModelIrDecodeError::Truncated)?));
                }
                AttrValue::IntList(values)
            }
            6 => {
                let n = self.count(MAX_MODEL_IR_ITEMS, 8)?;
                let values = (0..n).map(|_| self.float()).collect::<Result<Vec<_>, _>>()?;
                AttrValue::FloatList(values)
            }
            7 => AttrValue::DType(self.dtype()?),
            8 => AttrValue::Shape(self.shape()?),
            _ => return Err(ModelIrDecodeError::Unsupported),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpCode, encode_canonical_attr_value};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn graph(op: OpCode) -> Result<ModelIrGraph, Box<dyn std::error::Error>> {
        let port = |name| TensorPort::new(name, DType::F32, Shape::new(vec![1, 4])?, Generation(7));
        Ok(ModelIrGraph::new_validated("model:loader-test", ModelIrVersion::V1, Generation(7),
            vec![port("input")?], vec![port("output")?],
            vec![GraphNode::new("node:0", op, "activation", vec!["input".to_owned()],
                vec!["output".to_owned()], AttributeMap::new())?])?)
    }

    #[test]
    fn loads_existing_writer_without_new_wire_format() -> TestResult {
        for op in [OpCode::Relu, OpCode::Softmax, OpCode::Sigmoid] {
            let bytes = encode_canonical_model_ir(&graph(op)?)?;
            let restored = decode_canonical_model_ir(&bytes, ContentDigest::sha256(&bytes))?;
            assert_eq!(encode_canonical_model_ir(&restored)?, bytes);
            assert_eq!(restored.generation(), Generation(7));
        }
        Ok(())
    }

    #[test]
    fn every_truncated_prefix_and_extra_suffix_is_refused() -> TestResult {
        let bytes = encode_canonical_model_ir(&graph(OpCode::Softmax)?)?;
        for end in 0..bytes.len() {
            assert!(decode_canonical_model_ir(&bytes[..end], ContentDigest::sha256(&bytes[..end])).is_err());
        }
        let mut extended = bytes;
        extended.push(0);
        assert!(decode_canonical_model_ir(&extended, ContentDigest::sha256(&extended)).is_err());
        Ok(())
    }

    #[test]
    fn expected_digest_and_operator_universe_are_independent_gates() -> TestResult {
        let bytes = encode_canonical_model_ir(&graph(OpCode::Relu)?)?;
        assert!(matches!(decode_canonical_model_ir(&bytes, ContentDigest::sha256(b"other")),
            Err(ModelIrDecodeError::DigestMismatch)));
        for position in [0, MODEL_IR_DIGEST_DOMAIN.len(), MODEL_IR_DIGEST_DOMAIN.len() + 4,
            MODEL_IR_DIGEST_DOMAIN.len() + 5] {
            let mut changed = bytes.clone();
            changed[position] ^= 0x40;
            assert!(decode_canonical_model_ir(&changed, ContentDigest::sha256(&changed)).is_err());
        }
        Ok(())
    }

    #[test]
    fn oversized_metadata_and_hostile_counts_do_not_allocate() {
        let bytes = u32::MAX.to_be_bytes();
        let mut reader = Reader { bytes: &bytes, position: 0 };
        assert!(matches!(reader.names(), Err(ModelIrDecodeError::Limit)));
        let mut reader = Reader { bytes: &bytes, position: 0 };
        assert!(matches!(reader.shape(), Err(ModelIrDecodeError::Limit)));
        let mut reader = Reader { bytes: &bytes, position: 0 };
        assert!(matches!(reader.text(), Err(ModelIrDecodeError::Limit)));
    }

    #[test]
    fn attribute_tags_and_values_round_trip() -> TestResult {
        let values = [AttrValue::Bool(true), AttrValue::Int(-31), AttrValue::Float(0.125),
            AttrValue::String("frozen".to_owned()), AttrValue::IntList(vec![-1, 0, 2]),
            AttrValue::FloatList(vec![0.0, 0.5]), AttrValue::DType(DType::F32),
            AttrValue::Shape(Shape::new(vec![2, 3])?)];
        for value in values {
            let bytes = encode_canonical_attr_value(&value);
            let mut reader = Reader { bytes: &bytes, position: 0 };
            assert_eq!(reader.attribute()?, value);
            assert_eq!(reader.position, bytes.len());
        }
        Ok(())
    }

    #[test]
    fn unknown_tags_nonfinite_numbers_and_negative_zero_are_rejected() {
        for bytes in [vec![255], vec![1, 2], vec![7, 255],
            [vec![3], f64::NAN.to_bits().to_be_bytes().to_vec()].concat(),
            [vec![3], f64::INFINITY.to_bits().to_be_bytes().to_vec()].concat(),
            [vec![3], (-0.0_f64).to_bits().to_be_bytes().to_vec()].concat()] {
            let mut reader = Reader { bytes: &bytes, position: 0 };
            assert!(reader.attribute().is_err());
        }
    }
}
