#![forbid(unsafe_code)]
//! Source-preserving export from admitted ONNX into the existing native graph and
//! Safetensors formats. This has no filesystem, package activation or runtime effect.

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_tensor::DType;

use super::{ImportedOnnx, OnnxError, Result};

const MIB: usize = 1024 * 1024;
const IMPLEMENTATION: [&[u8]; 9] = [
    include_bytes!("../onnx.rs"),
    include_bytes!("gemm.rs"),
    include_bytes!("constants.rs"),
    include_bytes!("structure.rs"),
    include_bytes!("resize.rs"),
    include_bytes!("shape_program.rs"),
    include_bytes!("split.rs"),
    include_bytes!("export.rs"),
    include_bytes!("../canonical.rs"),
];

/// Admission ceilings for the existing native artifacts, not a new package format.
#[derive(Clone, Copy, Debug)]
pub struct OnnxExportLimits {
    /// Canonical graph bytes, at most 16 MiB.
    pub graph_bytes: usize,
    /// Complete Safetensors bytes, including its header, at most 16 MiB.
    pub weights_bytes: usize,
    /// Safetensors JSON header bytes, at most 256 KiB.
    pub header_bytes: usize,
    /// Embedded and generated parameters, at most 256 (the RGB package import ceiling).
    pub parameter_tensors: usize,
    /// Original source plus graph plus complete weights, at most 64 MiB.
    /// This counts payload bytes, including the borrowed source, not peak process memory.
    pub bundle_bytes: usize,
    /// Cumulative import plus export work; the original import's work is not refunded.
    /// These deterministic reservations are not elapsed time or hardware operations.
    pub work_units: u64,
}
impl Default for OnnxExportLimits {
    fn default() -> Self {
        Self {
            graph_bytes: 16 * MIB,
            weights_bytes: 16 * MIB,
            header_bytes: 256 * 1024,
            parameter_tensors: 256,
            bundle_bytes: 64 * MIB,
            work_units: 256 * MIB as u64,
        }
    }
}
impl OnnxExportLimits {
    fn validate(self) -> Result<()> {
        if self.graph_bytes == 0
            || self.graph_bytes > 16 * MIB
            || self.weights_bytes == 0
            || self.weights_bytes > 16 * MIB
            || self.header_bytes == 0
            || self.header_bytes > 256 * 1024
            || self.parameter_tensors > 256
            || self.bundle_bytes == 0
            || self.bundle_bytes > 64 * MIB
        {
            return Err(OnnxError::Limit);
        }
        Ok(())
    }
}

/// Complete native artifacts and the exact source from which they were converted.
/// All generated Gemm parameters are included. No tensor is renamed or omitted.
#[derive(Debug)]
pub struct OnnxArtifacts<'a> {
    source: &'a [u8],
    source_digest: ContentDigest,
    graph: Vec<u8>,
    graph_digest: ContentDigest,
    weights: Vec<u8>,
    weights_digest: ContentDigest,
    importer: ContentDigest,
    work: u64,
}
impl<'a> OnnxArtifacts<'a> {
    /// Original ONNX bytes, including metadata and documentation, without reconstruction.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    /// Independently checked original ONNX SHA-256 identity.
    pub fn source_digest(&self) -> ContentDigest {
        self.source_digest
    }
    /// Existing canonical Model IR v1 representation; no encoding version changes.
    pub fn graph_bytes(&self) -> &[u8] {
        &self.graph
    }
    /// SHA-256 of the complete canonical graph artifact.
    pub fn graph_digest(&self) -> ContentDigest {
        self.graph_digest
    }
    /// Deterministic Safetensors with sorted names, contiguous offsets and exact F32 bits.
    pub fn weights_bytes(&self) -> &[u8] {
        &self.weights
    }
    /// SHA-256 of the complete exported Safetensors artifact.
    pub fn weights_digest(&self) -> ContentDigest {
        self.weights_digest
    }
    /// Source identity of the parser, lowering, artifact export and canonical encoder.
    pub fn importer_identity(&self) -> ContentDigest {
        self.importer
    }
    /// Cumulative successful import plus export work, including hashing all new artifacts.
    pub fn work_units(&self) -> u64 {
        self.work
    }
}

/// Source-bound conversion implementation identity. Existing IR/operator identities are
/// unchanged; the package records this separate identity together with its exact source.
#[must_use]
pub fn onnx_importer_identity() -> ContentDigest {
    let mut record = CanonicalEncoder::new();
    record.text("fss.onnx_importer.v1");
    for source in IMPLEMENTATION {
        record.digest(ContentDigest::sha256(source));
    }
    ContentDigest::sha256(&record.finish())
}

struct Budget<'a> {
    used: u64,
    maximum: u64,
    cancelled: &'a dyn Fn() -> bool,
}
impl Budget<'_> {
    fn charge(&mut self, units: usize) -> Result<()> {
        if (self.cancelled)() {
            return Err(OnnxError::Cancelled);
        }
        let next = self
            .used
            .checked_add(u64::try_from(units).map_err(|_| OnnxError::Limit)?)
            .ok_or(OnnxError::Limit)?;
        if next > self.maximum {
            return Err(OnnxError::WorkBudget);
        }
        self.used = next;
        Ok(())
    }
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(OnnxError::Limit)
}

// One header writer serves the size-only preflight and the actual encoder. Escaping
// and decimal widths therefore cannot disagree about an allocation or byte ceiling.
struct Header<'a, 'b, 'c> {
    output: Option<&'a mut Vec<u8>>,
    size: usize,
    maximum: usize,
    budget: &'b mut Budget<'c>,
}
impl Header<'_, '_, '_> {
    fn text(&mut self, text: &str) -> Result<()> {
        let next = add(self.size, text.len())?;
        if next > self.maximum {
            return Err(OnnxError::Limit);
        }
        self.budget.charge(text.len())?;
        if let Some(output) = &mut self.output {
            output.extend_from_slice(text.as_bytes());
        }
        self.size = next;
        Ok(())
    }
    fn number(&mut self, number: usize) -> Result<()> {
        self.text(&number.to_string())
    }
    fn quoted(&mut self, text: &str) -> Result<()> {
        self.text("\"")?;
        for character in text.chars() {
            match character {
                '"' => self.text("\\\"")?,
                '\\' => self.text("\\\\")?,
                '\0'..='\u{1f}' => self.text(&format!("\\u{:04x}", u32::from(character)))?,
                other => self.text(other.encode_utf8(&mut [0_u8; 4]))?,
            }
        }
        self.text("\"")
    }
}

fn header(
    imported: &ImportedOnnx<'_>,
    importer: ContentDigest,
    output: &mut Header<'_, '_, '_>,
) -> Result<usize> {
    output.text("{\"__metadata__\":{\"format\":\"fss-onnx-export-v1\",\"source_sha256\":")?;
    output.quoted(&imported.source_digest.to_string())?;
    output.text(",\"importer\":")?;
    output.quoted(&importer.to_string())?;
    output.text("}")?;
    let mut offset = 0;
    for (name, tensor) in &imported.parameters {
        let bytes = tensor
            .shape()
            .size_bytes(DType::F32)
            .map_err(|_| OnnxError::Limit)?;
        let end = add(offset, bytes)?;
        output.text(",")?;
        output.quoted(name)?;
        output.text(":{\"dtype\":\"F32\",\"shape\":[")?;
        for (index, &dimension) in tensor.shape().dims().iter().enumerate() {
            if index != 0 {
                output.text(",")?;
            }
            output.number(dimension)?;
        }
        output.text("],\"data_offsets\":[")?;
        output.number(offset)?;
        output.text(",")?;
        output.number(end)?;
        output.text("]}")?;
        offset = end;
    }
    output.text("}")?;
    Ok(offset)
}

fn digest(bytes: &[u8], budget: &mut Budget<'_>) -> Result<ContentDigest> {
    let mut hash = Sha256Hasher::new();
    for chunk in bytes.chunks(64 * 1024) {
        budget.charge(chunk.len())?;
        hash.update(chunk);
    }
    Ok(ContentDigest::new(
        DigestAlgorithm::Sha256,
        hash.finalize().map_err(|_| OnnxError::Limit)?,
    ))
}

/// Export a verified import into artifacts accepted by the existing RGB package loader.
///
/// The total work limit includes the original import. Exact graph/header/data sizes
/// and the aggregate source-bearing payload are admitted before output allocation.
/// Parameter bytes are traversed without a second full parameter allocation. Finite
/// F32 bit patterns, including signed zeros and subnormals, are preserved as little
/// endian. JSON names round-trip without lossy escaping or aliases.
///
/// The Safetensors-reserved parameter name "__metadata__" refuses; it is never
/// silently renamed. Empty parameter sets are valid. The caller still supplies the
/// preprocessing/head contract, license and immutable package generation, and owns
/// durable publication. No model quality, calibration or activation is implied.
pub fn export_onnx_artifacts<'a>(
    imported: &ImportedOnnx<'a>,
    limits: OnnxExportLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<OnnxArtifacts<'a>> {
    limits.validate()?;
    let mut budget = Budget {
        used: imported.work,
        maximum: limits.work_units,
        cancelled,
    };
    budget.charge(0)?;
    if imported.source.len() > limits.bundle_bytes
        || imported.parameters.len() > limits.parameter_tensors
    {
        return Err(OnnxError::Limit);
    }
    let mut parameter_bytes = 0;
    for (name, tensor) in &imported.parameters {
        budget.charge(add(name.len(), tensor.rank())?)?;
        if name == "__metadata__" {
            return Err(OnnxError::Unsupported);
        }
        if tensor.dtype() != DType::F32
            || tensor.generation() != imported.graph.generation()
            || !tensor.is_c_contiguous()
        {
            return Err(OnnxError::Graph);
        }
        parameter_bytes = add(
            parameter_bytes,
            tensor
                .shape()
                .size_bytes(DType::F32)
                .map_err(|_| OnnxError::Limit)?,
        )?;
        if parameter_bytes > limits.weights_bytes {
            return Err(OnnxError::Limit);
        }
    }
    // Reserve both bounded native graph passes before entering the existing graph
    // validator/encoder. Its unchanged format and normalization own the graph bytes.
    let nodes = imported.graph.nodes().len();
    let ports = add(
        imported.graph.inputs().len(),
        imported.graph.outputs().len(),
    )?;
    let graph_work = nodes
        .checked_mul(add(add(nodes, ports)?, 1)?)
        .and_then(|n| n.checked_mul(2))
        .ok_or(OnnxError::Limit)?;
    budget.charge(add(graph_work, ports)?)?;
    let graph_size =
        crate::canonical::canonical_model_ir_size(&imported.graph).map_err(|_| OnnxError::Graph)?;
    budget.charge(0)?;
    if graph_size > limits.graph_bytes {
        return Err(OnnxError::Limit);
    }
    budget.charge(IMPLEMENTATION.iter().map(|source| source.len()).sum())?;
    let importer = onnx_importer_identity();
    let (header_size, described_data) = {
        let mut output = Header {
            output: None,
            size: 0,
            maximum: limits.header_bytes,
            budget: &mut budget,
        };
        let data = header(imported, importer, &mut output)?;
        (output.size, data)
    };
    if described_data != parameter_bytes {
        return Err(OnnxError::Graph);
    }
    let weights_size = add(add(8, header_size)?, parameter_bytes)?;
    let bundle_size = add(add(imported.source.len(), graph_size)?, weights_size)?;
    if weights_size > limits.weights_bytes || bundle_size > limits.bundle_bytes {
        return Err(OnnxError::Limit);
    }
    budget.charge(add(graph_size, add(8, parameter_bytes)?)?)?;
    let graph = crate::encode_canonical_model_ir(&imported.graph).map_err(|_| OnnxError::Graph)?;
    budget.charge(0)?;
    if graph.len() != graph_size {
        return Err(OnnxError::Graph);
    }
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(weights_size)
        .map_err(|_| OnnxError::Limit)?;
    weights.extend_from_slice(&(header_size as u64).to_le_bytes());
    {
        let mut output = Header {
            output: Some(&mut weights),
            size: 0,
            maximum: header_size,
            budget: &mut budget,
        };
        if header(imported, importer, &mut output)? != parameter_bytes || output.size != header_size
        {
            return Err(OnnxError::Graph);
        }
    }
    for tensor in imported.parameters.values() {
        budget.charge(0)?;
        let size = tensor
            .shape()
            .size_bytes(DType::F32)
            .map_err(|_| OnnxError::Limit)?;
        let storage = tensor.view().storage();
        let bytes = storage
            .slice_range(tensor.view().offset_bytes(), size)
            .map_err(|_| OnnxError::Graph)?;
        let (values, tail) = bytes.as_chunks::<4>();
        if !tail.is_empty() {
            return Err(OnnxError::Graph);
        }
        for (index, &bits) in values.iter().enumerate() {
            if index % 1024 == 0 {
                budget.charge(0)?;
            }
            let value = f32::from_ne_bytes(bits);
            if !value.is_finite() {
                return Err(OnnxError::NonFinite);
            }
            weights.extend_from_slice(&value.to_le_bytes());
        }
    }
    if weights.len() != weights_size {
        return Err(OnnxError::Graph);
    }
    let graph_digest = digest(&graph, &mut budget)?;
    let weights_digest = digest(&weights, &mut budget)?;
    budget.charge(0)?;
    Ok(OnnxArtifacts {
        source: imported.source,
        source_digest: imported.source_digest,
        graph,
        graph_digest,
        weights,
        weights_digest,
        importer,
        work: budget.used,
    })
}
