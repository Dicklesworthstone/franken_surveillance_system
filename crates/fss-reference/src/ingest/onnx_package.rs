#![forbid(unsafe_code)]
//! Offline, source-preserving ONNX conversion into the existing RGB detector package format.
//!
//! The caller supplies every preprocessing/head/license choice. An admitted static opset-13
//! graph is converted without downloads, retained alongside its original source, and reopened
//! through the same verifier used by package detection. Building a package does not activate it.

use fss_core::{
    CalibrationGeneration, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm,
    Generation, ModelGeneration, SchemaId,
};
use fss_model_ir::{OnnxError, OnnxExportLimits, OnnxLimits, export_onnx_artifacts, import_onnx};
use fss_object::{
    MAX_RESTRICTION_LEN, MAX_RESTRICTIONS_COUNT, MAX_SOURCE_IDENTITY_LEN, MAX_SPDX_LEN,
    MAX_UPSTREAM_REVISION_LEN, ModelId, ModelLicenseRecord, ModelManifestError, ModelManifestV1,
    ModelPackage, ModelPackageArchive, ModelPackageArtifact, ModelPackageError,
};

use super::rgb_detections::{HeadLayout, RgbDetectionContract};
use super::rgb_package::{
    GRAPH_ARTIFACT, LICENSE_ARTIFACT, MAX_RGB_PACKAGE_BYTES, NOTICE_ARTIFACT, PackageHeadSpec,
    PackageSource, RgbDetectorPackage, RgbPackageError, RgbPackageSpec, SPEC_ARTIFACT,
    WEIGHTS_ARTIFACT,
};
use crate::preprocess::ResizeFilter;
use crate::{ReplayCx, ScalarExecCx};

/// The complete original ONNX bytes are a manifest-bound provenance artifact.
pub const ONNX_SOURCE_ARTIFACT: &str = "source.onnx";
/// Each attribution document has its own finite input allowance.
pub const MAX_ATTRIBUTION_BYTES: usize = 256 * 1024;

/// Explicit operator choices; no class, preprocessing, score rule, or license is inferred.
#[derive(Clone, Debug)]
pub struct OnnxPackageRecipe {
    /// Immutable model identity.
    pub model_id: ModelId,
    /// Immutable deployment model generation, separate from the tensor generation.
    pub model_generation: ModelGeneration,
    /// Nonzero native graph/tensor generation.
    pub tensor_generation: Generation,
    /// The sole runtime image input; every other graph input must be an exact parameter.
    pub image_input: String,
    /// NCHW RGB image height and width.
    pub target: [usize; 2],
    /// Explicit resampling filter.
    pub filter: ResizeFilter,
    /// Centered, aspect-preserving letterbox padding byte.
    pub letterbox_pad: u8,
    /// Public replacement color applied to denied source pixels before resampling.
    pub masked_rgb: [u8; 3],
    /// Whether to scale input bytes to [0,1].
    pub scale_to_unit: bool,
    /// Already-decoded dense detection-head semantics.
    pub head: PackageHeadSpec,
    /// Ordered unique class labels.
    pub labels: Vec<String>,
    /// Operator-supplied upstream location; informational and never fetched here.
    pub upstream: String,
    /// Exact upstream revision (never a mutable `latest` alias).
    pub revision: String,
    /// Operator-supplied producer description; not authenticated ONNX metadata.
    pub producer: String,
    /// SPDX identifier or admitted proprietary license identity.
    pub license_id: String,
    /// Explicit owner license-use decision, subsequently checked by the existing policy.
    pub use_approved: bool,
    /// Explicit license restrictions, subsequently checked by the existing policy.
    pub restrictions: Vec<String>,
}

/// Exact original inputs and independently supplied content pins.
pub struct OnnxPackageRequest<'a> {
    /// Complete embedded-tensor ONNX source.
    pub source: &'a [u8],
    /// Independently expected SHA-256 of `source`.
    pub source_digest: ContentDigest,
    /// Exact upstream license text.
    pub license: &'a [u8],
    /// Independently expected SHA-256 of `license`.
    pub license_digest: ContentDigest,
    /// Exact attribution notice; may be empty if the license requires no notice.
    pub notice: &'a [u8],
    /// Independently expected SHA-256 of `notice`.
    pub notice_digest: ContentDigest,
    /// Complete immutable recipe.
    pub recipe: &'a OnnxPackageRecipe,
}

/// Finite conversion and verification allowances; none authorizes inference or publication.
#[derive(Clone, Copy, Debug)]
pub struct OnnxPackageLimits {
    /// Protobuf/graph conversion bounds.
    pub import: OnnxLimits,
    /// Artifact bounds; export work includes work already spent importing the source.
    pub export: OnnxExportLimits,
    /// Complete FMPK ceiling, at most the existing RGB package maximum.
    pub package_bytes: usize,
    /// Existing RGB package verifier's cumulative import-work allowance.
    pub verification_work: u64,
}

impl Default for OnnxPackageLimits {
    fn default() -> Self {
        Self {
            import: OnnxLimits::default(),
            export: OnnxExportLimits::default(),
            package_bytes: MAX_RGB_PACKAGE_BYTES,
            verification_work: 1 << 32,
        }
    }
}

/// No error exposes a partly built archive or grants model activation authority.
#[derive(Debug)]
pub enum OnnxPackageError {
    /// Source/attribution bytes contradict an independently supplied SHA-256.
    Digest,
    /// An input, aggregate archive, or allocation bound failed.
    Limit,
    /// Explicit recipe and graph input/output shape are incompatible.
    Recipe(&'static str),
    /// Cancellation was observed at an admission or conversion boundary.
    Cancelled,
    /// The source cannot be converted within the admitted profile/budget.
    Onnx(OnnxError),
    /// Existing package metadata validation failed.
    Manifest(ModelManifestError),
    /// Existing archive construction or verification failed.
    Archive(ModelPackageError),
    /// Existing RGB model/license/head verifier refused the complete package.
    Verification(RgbPackageError),
    /// A canonical typed identity could not be encoded.
    Contract(ContractError),
}

impl std::fmt::Display for OnnxPackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest => f.write_str("ONNX package input digest mismatch"),
            Self::Limit => f.write_str("ONNX package resource bound exceeded"),
            Self::Recipe(reason) => write!(f, "ONNX package recipe refused: {reason}"),
            Self::Cancelled => f.write_str("ONNX package conversion cancelled"),
            Self::Onnx(e) => write!(f, "ONNX package conversion: {e}"),
            Self::Manifest(e) => write!(f, "ONNX package manifest: {e}"),
            Self::Archive(e) => write!(f, "ONNX package archive: {e}"),
            Self::Verification(e) => write!(f, "ONNX package verification: {e}"),
            Self::Contract(e) => write!(f, "ONNX package identity: {e}"),
        }
    }
}
impl std::error::Error for OnnxPackageError {}
macro_rules! convert {
    ($from:ty, $variant:ident) => {
        impl From<$from> for OnnxPackageError {
            fn from(error: $from) -> Self {
                Self::$variant(error)
            }
        }
    };
}
convert!(OnnxError, Onnx);
convert!(ModelManifestError, Manifest);
convert!(ModelPackageError, Archive);
convert!(RgbPackageError, Verification);
convert!(ContractError, Contract);

/// A complete, verified archive ready for an explicit operator export.
#[derive(Debug)]
pub struct ImportedOnnxPackage {
    archive: Vec<u8>,
    package: RgbDetectorPackage,
    conversion_work: u64,
}
impl ImportedOnnxPackage {
    /// Exact existing-format FMPK bytes, including original ONNX/license/notice artifacts.
    pub fn archive(&self) -> &[u8] {
        &self.archive
    }
    /// The same verified model and head consumed by the existing detection/sentinel paths.
    pub fn package(&self) -> &RgbDetectorPackage {
        &self.package
    }
    /// Charged import plus artifact-export work, separate from package verification/inference.
    pub fn conversion_work(&self) -> u64 {
        self.conversion_work
    }
}

fn checkpoint(cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<(), OnnxPackageError> {
    cx.checkpoint("onnx_package:convert")
        .map_err(|_| OnnxPackageError::Cancelled)?;
    scalar
        .checkpoint("onnx_package:convert")
        .map_err(|_| OnnxPackageError::Cancelled)
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OnnxPackageError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| OnnxPackageError::Limit)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn spec(
    recipe: &OnnxPackageRecipe,
    source: ContentDigest,
    importer: ContentDigest,
) -> Result<RgbPackageSpec, OnnxPackageError> {
    let valid_text = |s: &str| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control);
    if recipe.tensor_generation.0 == 0
        || !valid_text(&recipe.upstream)
        || !valid_text(&recipe.revision)
        || !valid_text(&recipe.producer)
        || recipe.labels.len() > 256
        || recipe.labels.iter().any(|s| !valid_text(s))
        || !valid_text(&recipe.image_input)
        || !valid_text(&recipe.head.output_port)
        || !valid_text(&recipe.license_id)
        || recipe.license_id.len() > MAX_SPDX_LEN
        || recipe.upstream.len() > MAX_SOURCE_IDENTITY_LEN
        || recipe.revision.len() > MAX_UPSTREAM_REVISION_LEN
        || recipe.restrictions.len() > MAX_RESTRICTIONS_COUNT
        || recipe.restrictions.iter().any(|s| {
            s.is_empty() || s.len() > MAX_RESTRICTION_LEN || s.chars().any(char::is_control)
        })
    {
        return Err(OnnxPackageError::Recipe(
            "invalid generation, text, or labels",
        ));
    }
    let spec = RgbPackageSpec {
        image_input: recipe.image_input.clone(),
        target: recipe.target,
        filter: recipe.filter,
        letterbox_pad: recipe.letterbox_pad,
        masked_rgb: recipe.masked_rgb,
        scale_to_unit: recipe.scale_to_unit,
        head: recipe.head.clone(),
        labels: recipe.labels.clone(),
        source: PackageSource {
            upstream: recipe.upstream.clone(),
            revision: recipe.revision.clone(),
            source_sha256: source,
            producer: recipe.producer.clone(),
            opset: 13,
        },
        importer,
    };
    // Reuse strict spec and head admission before reading/converting a potentially large model.
    RgbPackageSpec::decode(&spec.encode()?)?;
    RgbDetectionContract::new(spec.detection_spec(source, spec.head.minimum_score_ppm))
        .map_err(|_| OnnxPackageError::Recipe("invalid dense detection head"))?;
    Ok(spec)
}

/// Build a source-closed package and verify it with the existing default CPU backend.
///
/// Pure local computation: this never opens files, changes a deployment, installs a model,
/// activates a generation, or turns uncalibrated detector output into an alert.
pub fn import_onnx_package(
    request: &OnnxPackageRequest<'_>,
    limits: OnnxPackageLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<ImportedOnnxPackage, OnnxPackageError> {
    checkpoint(cx, scalar)?;
    if limits.package_bytes == 0
        || limits.package_bytes > MAX_RGB_PACKAGE_BYTES
        || request.license.is_empty()
        || request.license.len() > MAX_ATTRIBUTION_BYTES
        || request.notice.len() > MAX_ATTRIBUTION_BYTES
    {
        return Err(OnnxPackageError::Limit);
    }
    for (bytes, expected) in [
        (request.license, request.license_digest),
        (request.notice, request.notice_digest),
    ] {
        checkpoint(cx, scalar)?;
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(OnnxPackageError::Digest);
        }
    }
    // The package assembler has its own source-bound identity, composed with the ONNX importer.
    let mut identity = CanonicalEncoder::new();
    identity.text("fss.onnx_rgb_package_importer.v1");
    identity.digest(fss_model_ir::onnx_importer_identity());
    identity.digest(ContentDigest::sha256(include_bytes!("onnx_package.rs")));
    let importer = ContentDigest::sha256(&identity.finish_checked()?);
    let spec = spec(request.recipe, request.source_digest, importer)?;
    let cancelled = || checkpoint(cx, scalar).is_err();
    let imported = import_onnx(
        request.source,
        request.source_digest,
        request.recipe.tensor_generation,
        limits.import,
        &cancelled,
    )?;
    if imported.runtime_inputs() != [spec.image_input.as_str()] {
        return Err(OnnxPackageError::Recipe(
            "exactly the declared image runtime input is required",
        ));
    }
    let input = imported
        .graph()
        .inputs()
        .iter()
        .find(|p| p.name() == spec.image_input)
        .ok_or(OnnxPackageError::Recipe("image input is missing"))?;
    if input.shape().dims() != [1, 3, spec.target[0], spec.target[1]] {
        return Err(OnnxPackageError::Recipe(
            "image input must match explicit [1,3,height,width]",
        ));
    }
    let output = imported
        .graph()
        .outputs()
        .iter()
        .find(|p| p.name() == spec.head.output_port)
        .ok_or(OnnxPackageError::Recipe(
            "declared detection output is missing",
        ))?;
    let shape = output.shape().dims();
    if shape.len() != 3 || shape[0] != 1 {
        return Err(OnnxPackageError::Recipe(
            "detection output must have rank three and batch one",
        ));
    }
    let (rows, fields) = match spec.head.layout {
        HeadLayout::Rows => (shape[1], shape[2]),
        HeadLayout::Channels => (shape[2], shape[1]),
    };
    if fields != 4 + usize::from(spec.head.objectness.is_some()) + spec.labels.len()
        || rows == 0
        || rows > spec.head.maximum_rows
    {
        return Err(OnnxPackageError::Recipe(
            "detection output disagrees with labels/layout/row ceiling",
        ));
    }
    let exported = export_onnx_artifacts(&imported, limits.export, &cancelled)?;
    let spec_bytes = spec.encode()?;
    let entries = [
        (ONNX_SOURCE_ARTIFACT, exported.source()),
        (GRAPH_ARTIFACT, exported.graph_bytes()),
        (WEIGHTS_ARTIFACT, exported.weights_bytes()),
        (SPEC_ARTIFACT, spec_bytes.as_slice()),
        (LICENSE_ARTIFACT, request.license),
        (NOTICE_ARTIFACT, request.notice),
    ];
    let provenance = vec![
        exported.source_digest(),
        exported.graph_digest(),
        ContentDigest::sha256(&spec_bytes),
        request.notice_digest,
    ];
    let license = ModelLicenseRecord::new(
        &request.recipe.license_id,
        Some(request.license_digest),
        request.recipe.use_approved,
        request.recipe.restrictions.clone(),
        &request.recipe.upstream,
        provenance,
        Some(request.recipe.revision.clone()),
    )?;
    let manifest = ModelManifestV1::new(
        request.recipe.model_id.clone(),
        request.recipe.model_generation.clone(),
        exported.weights_digest(),
        SchemaId::parse(format!(
            "fss.rgb_nchw_f32.1x3x{}x{}.{}",
            spec.target[0],
            spec.target[1],
            if spec.scale_to_unit { "unit" } else { "raw255" }
        ))?,
        SchemaId::parse(format!(
            "fss.rgb_decoded_head.{}x{}x{}",
            shape[0], shape[1], shape[2]
        ))?,
        CalibrationGeneration::parse("cal:uncalibrated:none")?,
        license,
    )?;
    // Exact existing archive framing: header/checksum 48; each artifact 2+name+32+8+payload.
    // Check before duplicating any input or allocating the archive itself.
    let mut archive_size = 48_usize
        .checked_add(manifest.to_canonical_bytes()?.len())
        .ok_or(OnnxPackageError::Limit)?;
    for (name, bytes) in &entries {
        archive_size = archive_size
            .checked_add(42 + name.len())
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(OnnxPackageError::Limit)?;
    }
    if archive_size > limits.package_bytes {
        return Err(OnnxPackageError::Limit);
    }
    let mut artifacts = Vec::new();
    artifacts
        .try_reserve_exact(entries.len())
        .map_err(|_| OnnxPackageError::Limit)?;
    for (name, bytes) in entries {
        checkpoint(cx, scalar)?;
        artifacts.push(ModelPackageArtifact::new(name, copy(bytes)?)?);
    }
    let package = ModelPackage::new(manifest, artifacts)?;
    checkpoint(cx, scalar)?;
    let archive = ModelPackageArchive::encode(&package)?;
    if archive.len() != archive_size {
        return Err(OnnxPackageError::Limit);
    }
    drop(package);
    checkpoint(cx, scalar)?;
    let verified = RgbDetectorPackage::load(
        &archive,
        ContentDigest::sha256(&archive),
        limits.verification_work,
        cx,
        scalar,
    )?;
    checkpoint(cx, scalar)?;
    Ok(ImportedOnnxPackage {
        archive,
        package: verified,
        conversion_work: exported.work_units(),
    })
}
