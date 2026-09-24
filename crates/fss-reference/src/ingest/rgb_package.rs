#![forbid(unsafe_code)]
//! Digest-pinned offline RGB detector packages (`FMPK` v1) loaded only through verification.
//!
//! A package is the existing immutable model-package archive: a canonical manifest, the exact
//! Safetensors weights, license text, and provenance artifacts. This module additionally
//! requires a canonical FSS Model IR graph and a canonical package spec that freezes the image
//! preprocessing and the dense detection-head interpretation. Loading refuses any archive whose
//! whole-byte digest differs from the caller's expected identity *before* parsing it, then
//! re-verifies every artifact digest, the license policy, the graph digest and the weights
//! through the existing bounded Safetensors importer. Nothing is downloaded, activated,
//! calibrated or granted effect authority; outputs remain uncalibrated model proposals.

use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};
use fss_object::{
    ModelLicenseDecision, ModelLicensePolicy, ModelLicensePolicyError, ModelManifestV1,
    ModelPackage, ModelPackageArchive, ModelPackageError, ModelPackageLimits, ModelUseProfile,
};

use super::model_import::rgb::{ImportedRgbModel, RgbImportError, RgbModelImportRequest};
use super::model_import::{ImportBudget, ImportLimits, WeightFloatPolicy};
use super::rgb_detections::{
    HeadBoxes, HeadClasses, HeadLayout, HeadScore, RgbDetectionContract, RgbDetectionError,
    RgbDetectionSpec,
};
use super::rgb_inference::{RgbInferenceModel, RgbModelSpec};
use crate::preprocess::{ResizeAspect, ResizeFilter};
use crate::{ChannelTransform, PreprocessProgram, ReplayCx, ScalarExecCx};

/// Canonical digest domain of the package spec artifact.
pub const RGB_PACKAGE_SPEC_DOMAIN: &str = "fss.rgb_detector_package_spec.v1";
/// Artifact name of the canonical FSS Model IR graph.
pub const GRAPH_ARTIFACT: &str = "graph.fssir";
/// Artifact name of the canonical package spec.
pub const SPEC_ARTIFACT: &str = "package_spec.bin";
/// Artifact name of the exact Safetensors weights (the manifest `weights_digest`).
pub const WEIGHTS_ARTIFACT: &str = "weights.safetensors";
/// Artifact name of the license text (the manifest license `text_digest`).
pub const LICENSE_ARTIFACT: &str = "LICENSE";
/// Artifact name of the upstream attribution notice.
pub const NOTICE_ARTIFACT: &str = "NOTICE";
/// Largest admitted archive; the verified YOLOX-Nano package is about 3.7 MB.
pub const MAX_RGB_PACKAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_LABELS: usize = 256;
const MAX_TEXT: usize = 512;

/// First trained detector admitted by owner decision (fss-q4ngj): YOLOX-Nano, COCO-80.
pub const YOLOX_NANO_MODEL_ID: &str = "MOD-YOLOXNANO-001";

/// Frozen dense detection-head interpretation stored inside the package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHeadSpec {
    /// Graph output interpreted as rows of four box fields, objectness, class scores.
    pub output_port: String,
    /// Tensor axis order.
    pub layout: HeadLayout,
    /// Box representation on the model grid.
    pub boxes: HeadBoxes,
    /// Class-score arithmetic.
    pub class_score: HeadScore,
    /// Objectness field and arithmetic, if any.
    pub objectness: Option<HeadScore>,
    /// Single- or multi-label emission.
    pub classes: HeadClasses,
    /// Inclusive combined-score threshold, millionths.
    pub minimum_score_ppm: u32,
    /// Class-aware NMS IoU threshold (strictly greater suppresses), millionths.
    pub nms_iou_ppm: u32,
    /// Complete row ceiling.
    pub maximum_rows: usize,
    /// Pre-NMS candidate ceiling (refusal, never truncation).
    pub maximum_candidates: usize,
    /// Post-NMS survivor ceiling (refusal, never truncation).
    pub maximum_detections: usize,
}

/// Upstream source identity recorded by the offline importer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSource {
    /// Exact upstream artifact location (informational; never fetched at runtime).
    pub upstream: String,
    /// Upstream release/tag.
    pub revision: String,
    /// SHA-256 of the exact upstream file the importer read.
    pub source_sha256: ContentDigest,
    /// Upstream producer string recorded in the source file.
    pub producer: String,
    /// Upstream operator-set version.
    pub opset: u64,
}

/// Canonical preprocessing + head + provenance record of an RGB detector package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RgbPackageSpec {
    /// Graph input receiving the preprocessed NCHW RGB tensor.
    pub image_input: String,
    /// Model input height and width.
    pub target: [usize; 2],
    /// Resampling filter.
    pub filter: ResizeFilter,
    /// Letterbox padding intensity (aspect-preserving, centered).
    pub letterbox_pad: u8,
    /// Constant substituted at privacy-denied source pixels before resampling.
    pub masked_rgb: [u8; 3],
    /// Scale bytes to [0,1] (false keeps raw 0..255 values as F32).
    pub scale_to_unit: bool,
    /// Detection head.
    pub head: PackageHeadSpec,
    /// Ordered class labels.
    pub labels: Vec<String>,
    /// Upstream identity.
    pub source: PackageSource,
    /// Identity of the offline importer implementation that produced graph and weights.
    pub importer: ContentDigest,
}

fn layout_tag(v: HeadLayout) -> u8 {
    match v {
        HeadLayout::Rows => 0,
        HeadLayout::Channels => 1,
    }
}
fn boxes_tag(v: HeadBoxes) -> u8 {
    match v {
        HeadBoxes::PixelCorners => 0,
        HeadBoxes::PixelCenterSize => 1,
        HeadBoxes::NormalizedCorners => 2,
        HeadBoxes::NormalizedCenterSize => 3,
    }
}
fn score_tag(v: HeadScore) -> u8 {
    match v {
        HeadScore::Probability => 0,
        HeadScore::Logit => 1,
    }
}
fn classes_tag(v: HeadClasses) -> u8 {
    match v {
        HeadClasses::Best => 0,
        HeadClasses::MultiLabel => 1,
    }
}
fn filter_tag(v: ResizeFilter) -> u8 {
    match v {
        ResizeFilter::Nearest => 0,
        ResizeFilter::Bilinear => 1,
    }
}

fn bounded_text(d: &mut CanonicalDecoder<'_>) -> Result<String, RgbPackageError> {
    let t = d.text()?;
    if t.is_empty() || t.len() > MAX_TEXT || t.chars().any(char::is_control) {
        return Err(RgbPackageError::InvalidSpec);
    }
    Ok(t.to_owned())
}
fn usize_of(v: u64) -> Result<usize, RgbPackageError> {
    usize::try_from(v).map_err(|_| RgbPackageError::InvalidSpec)
}

impl RgbPackageSpec {
    /// Canonical bytes; the package spec artifact is exactly these bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RgbPackageError> {
        let mut e = CanonicalEncoder::new();
        e.text(RGB_PACKAGE_SPEC_DOMAIN);
        e.text(&self.image_input);
        e.u64(self.target[0] as u64);
        e.u64(self.target[1] as u64);
        e.u8(filter_tag(self.filter));
        e.u8(self.letterbox_pad);
        e.bytes(&self.masked_rgb);
        e.bool(self.scale_to_unit);
        let h = &self.head;
        e.text(&h.output_port);
        e.u8(layout_tag(h.layout));
        e.u8(boxes_tag(h.boxes));
        e.u8(score_tag(h.class_score));
        e.u8(h.objectness.map_or(0, |s| score_tag(s) + 1));
        e.u8(classes_tag(h.classes));
        e.u32(h.minimum_score_ppm);
        e.u32(h.nms_iou_ppm);
        for n in [h.maximum_rows, h.maximum_candidates, h.maximum_detections] {
            e.u64(n as u64);
        }
        e.u64(self.labels.len() as u64);
        for label in &self.labels {
            e.text(label);
        }
        let s = &self.source;
        e.text(&s.upstream);
        e.text(&s.revision);
        e.digest(s.source_sha256);
        e.text(&s.producer);
        e.u64(s.opset);
        e.digest(self.importer);
        Ok(e.finish_checked()?)
    }

    /// Strict canonical decode: any trailing, unknown or out-of-range field is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, RgbPackageError> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != RGB_PACKAGE_SPEC_DOMAIN {
            return Err(RgbPackageError::InvalidSpec);
        }
        let image_input = bounded_text(&mut d)?;
        let target = [usize_of(d.u64()?)?, usize_of(d.u64()?)?];
        let filter = match d.u8()? {
            0 => ResizeFilter::Nearest,
            1 => ResizeFilter::Bilinear,
            _ => return Err(RgbPackageError::InvalidSpec),
        };
        let letterbox_pad = d.u8()?;
        let masked_rgb: [u8; 3] = d
            .bytes()?
            .try_into()
            .map_err(|_| RgbPackageError::InvalidSpec)?;
        let scale_to_unit = d.bool()?;
        let output_port = bounded_text(&mut d)?;
        let layout = match d.u8()? {
            0 => HeadLayout::Rows,
            1 => HeadLayout::Channels,
            _ => return Err(RgbPackageError::InvalidSpec),
        };
        let boxes = match d.u8()? {
            0 => HeadBoxes::PixelCorners,
            1 => HeadBoxes::PixelCenterSize,
            2 => HeadBoxes::NormalizedCorners,
            3 => HeadBoxes::NormalizedCenterSize,
            _ => return Err(RgbPackageError::InvalidSpec),
        };
        let score = |tag: u8| match tag {
            0 => Ok(HeadScore::Probability),
            1 => Ok(HeadScore::Logit),
            _ => Err(RgbPackageError::InvalidSpec),
        };
        let class_score = score(d.u8()?)?;
        let objectness = match d.u8()? {
            0 => None,
            tag => Some(score(tag - 1)?),
        };
        let classes = match d.u8()? {
            0 => HeadClasses::Best,
            1 => HeadClasses::MultiLabel,
            _ => return Err(RgbPackageError::InvalidSpec),
        };
        let minimum_score_ppm = d.u32()?;
        let nms_iou_ppm = d.u32()?;
        let maximum_rows = usize_of(d.u64()?)?;
        let maximum_candidates = usize_of(d.u64()?)?;
        let maximum_detections = usize_of(d.u64()?)?;
        let count = usize_of(d.u64()?)?;
        if count == 0 || count > MAX_LABELS {
            return Err(RgbPackageError::InvalidSpec);
        }
        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            labels.push(bounded_text(&mut d)?);
        }
        let upstream = bounded_text(&mut d)?;
        let revision = bounded_text(&mut d)?;
        let source_sha256 = d.digest()?;
        let producer = bounded_text(&mut d)?;
        let opset = d.u64()?;
        let importer = d.digest()?;
        d.ensure_finished()?;
        let spec = Self {
            image_input,
            target,
            filter,
            letterbox_pad,
            masked_rgb,
            scale_to_unit,
            head: PackageHeadSpec {
                output_port,
                layout,
                boxes,
                class_score,
                objectness,
                classes,
                minimum_score_ppm,
                nms_iou_ppm,
                maximum_rows,
                maximum_candidates,
                maximum_detections,
            },
            labels,
            source: PackageSource {
                upstream,
                revision,
                source_sha256,
                producer,
                opset,
            },
            importer,
        };
        if spec.encode()? != bytes
            || spec.target.contains(&0)
            || spec.target.iter().any(|n| *n > 4096)
            || [spec.source.source_sha256, spec.importer]
                .iter()
                .any(|d| d.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(RgbPackageError::InvalidSpec);
        }
        Ok(spec)
    }

    /// Existing RGB inference preprocessing implied by this spec.
    #[must_use]
    pub fn model_spec(&self) -> RgbModelSpec {
        RgbModelSpec {
            image_input: self.image_input.clone(),
            preprocess: PreprocessProgram::new(
                self.target[0],
                self.target[1],
                ChannelTransform::Rgb,
                self.scale_to_unit,
            ),
            filter: self.filter,
            aspect: ResizeAspect::Letterbox(self.letterbox_pad),
            masked_rgb: self.masked_rgb,
        }
    }

    /// Existing dense-head contract for an exact built model, optionally with another threshold.
    pub fn detection_spec(&self, model: ContentDigest, minimum_score_ppm: u32) -> RgbDetectionSpec {
        let h = &self.head;
        RgbDetectionSpec {
            model,
            output_port: h.output_port.clone(),
            labels: self.labels.clone(),
            layout: h.layout,
            boxes: h.boxes,
            class_score: h.class_score,
            objectness: h.objectness,
            classes: h.classes,
            minimum_score_ppm,
            nms_iou_ppm: h.nms_iou_ppm,
            maximum_rows: h.maximum_rows,
            maximum_candidates: h.maximum_candidates,
            maximum_detections: h.maximum_detections,
        }
    }
}

/// Typed refusal; no partially verified package or model escapes.
#[derive(Debug)]
pub enum RgbPackageError {
    /// Archive bytes differ from the independently expected package digest (tamper or wrong file).
    DigestMismatch,
    /// Archive exceeds the admitted byte bound.
    Limit,
    /// Archive, manifest or artifact structure refused by the package verifier.
    Archive(ModelPackageError),
    /// License policy refused the manifest.
    License(ModelLicensePolicyError),
    /// A required named artifact is absent or is not the one the manifest binds.
    MissingArtifact(&'static str),
    /// The package spec is malformed, non-canonical or inconsistent with the graph.
    InvalidSpec,
    /// The graph/weights import or RGB model contract refused the package.
    Import(RgbImportError),
    /// The frozen head contract refused the spec.
    Detection(RgbDetectionError),
    /// A canonical encoding failed.
    Contract(ContractError),
    /// The owner context was cancelled before a complete package was returned.
    Cancelled,
}
impl RgbPackageError {
    /// Registered stable error identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::DigestMismatch => "ERR-MODEL-PACKAGE-DIGEST-001",
            Self::License(_) => "ERR-MODEL-PACKAGE-LICENSE-001",
            Self::Limit
            | Self::Archive(_)
            | Self::MissingArtifact(_)
            | Self::InvalidSpec
            | Self::Import(_)
            | Self::Detection(_)
            | Self::Contract(_) => "ERR-MODEL-PACKAGE-INVALID-001",
            Self::Cancelled => "ERR-MODEL-PACKAGE-CANCELLED-001",
        }
    }
}
impl fmt::Display for RgbPackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch => {
                f.write_str("model package digest differs from the expected identity")
            }
            Self::Limit => f.write_str("model package exceeds its byte bound"),
            Self::Archive(e) => write!(f, "model package archive refused: {e}"),
            Self::License(e) => write!(f, "model package license refused: {e}"),
            Self::MissingArtifact(name) => {
                write!(f, "model package artifact missing or unbound: {name}")
            }
            Self::InvalidSpec => f.write_str("model package spec invalid or inconsistent"),
            Self::Import(e) => write!(f, "model package graph/weights refused: {e}"),
            Self::Detection(e) => write!(f, "model package head contract refused: {e}"),
            Self::Contract(e) => write!(f, "model package canonical encoding failed: {e}"),
            Self::Cancelled => f.write_str("model package load cancelled"),
        }
    }
}
impl std::error::Error for RgbPackageError {}
impl From<ContractError> for RgbPackageError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
impl From<ModelPackageError> for RgbPackageError {
    fn from(e: ModelPackageError) -> Self {
        Self::Archive(e)
    }
}

/// A verified, loaded RGB detector package: frozen model and its head contract.
#[derive(Debug)]
pub struct RgbDetectorPackage {
    archive_digest: ContentDigest,
    manifest: ModelManifestV1,
    manifest_digest: ContentDigest,
    license: ModelLicenseDecision,
    spec: RgbPackageSpec,
    graph_digest: ContentDigest,
    model: RgbInferenceModel,
    contract: RgbDetectionContract,
}

fn artifact<'p>(
    package: &'p ModelPackage,
    name: &'static str,
) -> Result<&'p [u8], RgbPackageError> {
    let mut found = package.artifacts.values().filter(|a| a.name == name);
    let first = found.next().ok_or(RgbPackageError::MissingArtifact(name))?;
    if found.next().is_some() {
        return Err(RgbPackageError::MissingArtifact(name));
    }
    Ok(&first.payload)
}

impl RgbDetectorPackage {
    /// Verify and load. `expected` is the independently pinned whole-archive SHA-256; any
    /// byte change is refused before parsing. Import work uses `import_work` units.
    pub fn load(
        bytes: &[u8],
        expected: ContentDigest,
        import_work: u64,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<Self, RgbPackageError> {
        cx.checkpoint("rgb_package:load")
            .map_err(|_| RgbPackageError::Cancelled)?;
        if bytes.len() > MAX_RGB_PACKAGE_BYTES {
            return Err(RgbPackageError::Limit);
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(RgbPackageError::DigestMismatch);
        }
        let package = ModelPackageArchive::decode(bytes, &ModelPackageLimits::default())?;
        let mut policy =
            ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
        policy.set_require_text_digest(true);
        let license = policy
            .check_manifest(&package.manifest)
            .map_err(RgbPackageError::License)?;
        let weights = artifact(&package, WEIGHTS_ARTIFACT)?;
        if ContentDigest::sha256(weights) != package.manifest.weights_digest() {
            return Err(RgbPackageError::MissingArtifact(WEIGHTS_ARTIFACT));
        }
        let license_text = artifact(&package, LICENSE_ARTIFACT)?;
        if Some(ContentDigest::sha256(license_text)) != package.manifest.license().text_digest() {
            return Err(RgbPackageError::MissingArtifact(LICENSE_ARTIFACT));
        }
        artifact(&package, NOTICE_ARTIFACT)?;
        let graph = artifact(&package, GRAPH_ARTIFACT)?;
        let spec = RgbPackageSpec::decode(artifact(&package, SPEC_ARTIFACT)?)?;
        let graph_digest = ContentDigest::sha256(graph);
        let request = RgbModelImportRequest {
            graph,
            graph_digest,
            weights,
            weights_digest: ContentDigest::sha256(weights),
            spec: spec.model_spec(),
            float_policy: WeightFloatPolicy::F32Only,
            bindings: Default::default(),
        };
        let model = ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(import_work),
            cx,
            scalar,
        )
        .map_err(RgbPackageError::Import)?
        .into_model();
        let contract = RgbDetectionContract::new(
            spec.detection_spec(model.digest(), spec.head.minimum_score_ppm),
        )
        .map_err(RgbPackageError::Detection)?;
        let manifest_digest = package
            .manifest
            .manifest_digest()
            .map_err(|e| RgbPackageError::Archive(e.into()))?;
        Ok(Self {
            archive_digest: expected,
            manifest: package.manifest,
            manifest_digest,
            license,
            spec,
            graph_digest,
            model,
            contract,
        })
    }
    /// Whole-archive identity the caller pinned.
    pub fn archive_digest(&self) -> ContentDigest {
        self.archive_digest
    }
    /// Canonical manifest (model id, generation, weights digest, license record).
    pub fn manifest(&self) -> &ModelManifestV1 {
        &self.manifest
    }
    /// Canonical manifest digest.
    pub fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// License-policy decision digest (surveillance-monitoring profile, text digest required).
    pub fn license_decision(&self) -> &ModelLicenseDecision {
        &self.license
    }
    /// Frozen preprocessing/head/provenance record.
    pub fn spec(&self) -> &RgbPackageSpec {
        &self.spec
    }
    /// Canonical graph artifact digest.
    pub fn graph_digest(&self) -> ContentDigest {
        self.graph_digest
    }
    /// Built frozen RGB model (graph + weights + preprocessing + implementation identity).
    pub fn model(&self) -> &RgbInferenceModel {
        &self.model
    }
    /// Package head contract at the package's own threshold.
    pub fn contract(&self) -> &RgbDetectionContract {
        &self.contract
    }
    /// The same head with another explicit threshold (for example a lower evidence floor).
    pub fn contract_with_threshold(
        &self,
        minimum_score_ppm: u32,
    ) -> Result<RgbDetectionContract, RgbPackageError> {
        RgbDetectionContract::new(
            self.spec
                .detection_spec(self.model.digest(), minimum_score_ppm),
        )
        .map_err(RgbPackageError::Detection)
    }
}
