#![forbid(unsafe_code)]
//! First-party `model:fss-activity:v1` packaged as an immutable `FMPK` v1 model package
//! (fss-2h5zq.49), loaded only through verification.
//!
//! The package reuses the existing model-package archive and the YOLOX package layout
//! ([`crate::ingest::rgb_package`]). It has the canonical manifest plus four artifacts:
//!
//! - `graph.fssir`: the canonical FSS Model IR of the activity graph;
//! - `weights.safetensors`: the single `mean_weights` tensor;
//! - `activity_spec.bin`: the frozen preprocessing and port interpretation
//!   ([`ACTIVITY_PACKAGE_SPEC_DOMAIN`]);
//! - `LICENSE`: the first-party license text, whose digest the manifest records.
//!
//! # Graph and weights (documented derivation, no training)
//!
//! `score = MatMul(Reshape((frame - reference)^2, [1, 1024]), mean_weights)`. `frame` and
//! `reference` are `[1, 1, 32, 32]` unit-scaled luma planes of two frames of one recording, and
//! `mean_weights` is a `[1024, 1]` column whose every entry is `1/1024 = 2^-10`, exact in F32.
//! The score is therefore the mean squared luma change against the reference frame, in `[0, 1]`.
//! It is an uncalibrated pixel-change measure: not a probability, not a person, intrusion or
//! object detector, and not an identity. The weights are literal constants defined here; nothing
//! is trained, downloaded or derived from third-party data.
//!
//! # Preprocessing
//!
//! Each decoded frame of any size is resized to 32x32 with the existing nearest-neighbour stretch
//! resize ([`PreprocessProgram::execute_resized_bytes`]). Luma is `0.299 R + 0.587 G + 0.114 B` in
//! the program's fixed F32 order, scaled by `1/255`. Scores of different source sizes are
//! comparable only through this recorded resize.
//!
//! # Loading
//!
//! [`VerifiedActivityPackage::load`] refuses, before any execution:
//! - archive bytes whose SHA-256 differs from the caller's independently pinned identity;
//! - archive structure, per-artifact digest or trailer-checksum failures;
//! - a model id or generation other than this model's;
//! - a license the caller's policy does not admit;
//! - any artifact the manifest does not bind;
//! - a spec other than the one this executor implements;
//! - a graph whose `compute_model_ir_digest` differs from the in-tree definition;
//! - weights that are not exactly the bound `mean_weights` tensor with the literal values.
//!
//! Nothing is activated or granted effect authority. Every invocation receipt still carries the
//! `activationGeneration` sentinel, so results stay reference-only.

use std::fmt;

use fss_core::{
    CalibrationGeneration, CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError,
    DigestAlgorithm, Generation, ModelGeneration, SchemaId,
};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrError, ModelIrGraph, OpCode, TensorPort,
    compute_model_ir_digest, decode_canonical_model_ir, encode_canonical_model_ir,
};
use fss_object::{
    ModelId, ModelLicenseDecision, ModelLicensePolicy, ModelLicensePolicyError, ModelLicenseRecord,
    ModelManifestV1, ModelPackage, ModelPackageArchive, ModelPackageArtifact, ModelPackageError,
    ModelPackageLimits, ModelUseProfile,
};
use fss_tensor::{DType, Shape, TensorError};

use crate::ingest::model_import::{ImportError, ImportLimits, read_f32_tensors};
use crate::ingest::rgb_package::{GRAPH_ARTIFACT, LICENSE_ARTIFACT, WEIGHTS_ARTIFACT};
use crate::preprocess::{ResizeAspect, ResizeFilter};
use crate::{ChannelTransform, PreprocessProgram, ScalarExecCx};

/// Canonical domain of the activity package spec artifact
/// (`SCHEMA-DOMAIN-EXECUTOR-ACTIVITY-PACKAGE-SPEC-001`).
pub const ACTIVITY_PACKAGE_SPEC_DOMAIN: &str = "fss.executor_activity_package_spec.v1";
/// Artifact name of the canonical activity package spec.
pub const ACTIVITY_SPEC_ARTIFACT: &str = "activity_spec.bin";
/// Stable model identity of the activity model.
pub const ACTIVITY_MODEL_ID: &str = "MOD-FSS-ACTIVITY-001";
/// Stable model generation string (immutable; a new model is a new generation).
pub const ACTIVITY_MODEL_GENERATION: &str = "model:fss-activity:v1";
/// License identity of first-party FSS model packages. It is not an SPDX list entry, so a policy
/// admits it only explicitly ([`activity_license_policy`]).
pub const ACTIVITY_LICENSE_IDENTITY: &str = "LicenseRef-FSS-First-Party";
/// Declared calibration state: the score is uncalibrated.
pub const ACTIVITY_CALIBRATION_GENERATION: &str = "cal:uncalibrated:none";
/// Input schema: two unit-scaled 32x32 luma planes.
pub const ACTIVITY_INPUT_SCHEMA: &str = "fss.luma_nchw_f32.1x1x32x32.unit.pair";
/// Output schema: one uncalibrated pixel-change score.
pub const ACTIVITY_OUTPUT_SCHEMA: &str = "fss.activity_score_f32.1x1.uncalibrated";
/// Source identity recorded in the license record.
pub const ACTIVITY_SOURCE_IDENTITY: &str =
    "first-party:franken_surveillance_system:crates/fss-reference/src/executor_activity_package.rs";
/// Graph input receiving the evaluated frame.
pub const ACTIVITY_FRAME_INPUT: &str = "frame";
/// Graph input receiving the reference frame of the same recording.
pub const ACTIVITY_REFERENCE_INPUT: &str = "reference";
/// Graph input bound to the package weight tensor.
pub const ACTIVITY_WEIGHTS_INPUT: &str = "mean_weights";
/// Graph output carrying the `[1, 1]` activity score.
pub const ACTIVITY_SCORE_OUTPUT: &str = "score";
/// Model input side (height and width).
pub const ACTIVITY_INPUT_SIDE: usize = 32;
/// Number of luma samples per model input.
pub const ACTIVITY_ELEMENTS: usize = ACTIVITY_INPUT_SIDE * ACTIVITY_INPUT_SIDE;
/// Tensor generation of the activity graph ports and of its input tensors.
pub const ACTIVITY_TENSOR_GENERATION: Generation = Generation(1);
/// Semantic label of a positive outcome: pixel-change activity, never a detection class.
pub const ACTIVITY_SEMANTIC_LABEL: &str = "unknown_activity:pixel_change:uncalibrated";
/// Largest admitted archive.
pub const MAX_ACTIVITY_PACKAGE_BYTES: usize = 1024 * 1024;
/// First-party license text carried in the package; the manifest records its SHA-256.
pub const ACTIVITY_LICENSE_TEXT: &str = "\
FSS first-party model package: model:fss-activity:v1 (MOD-FSS-ACTIVITY-001)

Authored as part of franken_surveillance_system. The graph and its single weight tensor are
literal constants defined in crates/fss-reference/src/executor_activity_package.rs: a uniform
mean (every weight 2^-10) of the squared luma difference between two frames of one recording.
No training, no training data, no third-party weights or code, no downloaded artifacts.

License identity: LicenseRef-FSS-First-Party. Use, modification and redistribution follow the
license of the franken_surveillance_system repository that contains this package.

The output is an uncalibrated pixel-change score. It is not a probability, not a person,
intrusion or object detection, and not an identity.
";

/// The committed immutable package (built by [`build_activity_package`]; see
/// `models/fss-activity/README.md`).
pub const ACTIVITY_PACKAGE_V1: &[u8] =
    include_bytes!("../../../models/fss-activity/fss_activity_v1.fmpk");
/// Pinned whole-archive SHA-256 of [`ACTIVITY_PACKAGE_V1`].
pub const ACTIVITY_PACKAGE_V1_SHA256: &str =
    "sha256:417ce1b61cb18192864c76fccf3606536ff4621a99052d1d84721c4915cde52e";

/// Typed refusal; no partially verified package escapes.
#[derive(Debug)]
pub enum ActivityPackageError {
    /// Archive bytes differ from the independently pinned identity (tamper or wrong file).
    DigestMismatch,
    /// Archive exceeds its byte bound.
    Limit,
    /// Archive, manifest or artifact structure refused by the package verifier.
    Archive(ModelPackageError),
    /// The license policy refused the manifest.
    License(ModelLicensePolicyError),
    /// The manifest names another model or generation.
    WrongModel {
        /// Model id in the manifest.
        model_id: String,
        /// Generation in the manifest.
        generation: String,
    },
    /// A required artifact is absent, duplicated or not the one the manifest binds.
    MissingArtifact(&'static str),
    /// The spec artifact is malformed, non-canonical or not the implemented spec.
    InvalidSpec,
    /// The graph is malformed or differs from the in-tree activity graph.
    GraphMismatch,
    /// The weights container is malformed or not exactly the bound `mean_weights` tensor.
    Weights(ImportError),
    /// The weight values or shape differ from the graph's binding.
    WeightsMismatch,
    /// The in-tree graph could not be built or digested.
    Graph(ModelIrError),
    /// A tensor or shape could not be built.
    Tensor(TensorError),
    /// A canonical encoding failed.
    Contract(ContractError),
    /// The owner context was cancelled before a complete package was returned.
    Cancelled,
}

impl ActivityPackageError {
    /// Registered stable error identity (`registries/ERRORS.md`), shared with the RGB package path.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::DigestMismatch => "ERR-MODEL-PACKAGE-DIGEST-001",
            Self::License(_) => "ERR-MODEL-PACKAGE-LICENSE-001",
            Self::Cancelled => "ERR-MODEL-PACKAGE-CANCELLED-001",
            Self::Limit
            | Self::Archive(_)
            | Self::WrongModel { .. }
            | Self::MissingArtifact(_)
            | Self::InvalidSpec
            | Self::GraphMismatch
            | Self::Weights(_)
            | Self::WeightsMismatch
            | Self::Graph(_)
            | Self::Tensor(_)
            | Self::Contract(_) => "ERR-MODEL-PACKAGE-INVALID-001",
        }
    }
}

impl fmt::Display for ActivityPackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch => {
                f.write_str("activity package digest differs from the pinned identity")
            }
            Self::Limit => f.write_str("activity package exceeds its byte bound"),
            Self::Archive(e) => write!(f, "activity package archive refused: {e}"),
            Self::License(e) => write!(f, "activity package license refused: {e}"),
            Self::WrongModel {
                model_id,
                generation,
            } => write!(
                f,
                "activity package names model {model_id} generation {generation}, expected {ACTIVITY_MODEL_ID} {ACTIVITY_MODEL_GENERATION}"
            ),
            Self::MissingArtifact(name) => {
                write!(f, "activity package artifact missing or unbound: {name}")
            }
            Self::InvalidSpec => f.write_str("activity package spec invalid or not implemented"),
            Self::GraphMismatch => {
                f.write_str("activity package graph differs from the activity graph definition")
            }
            Self::Weights(e) => write!(f, "activity package weights refused: {e}"),
            Self::WeightsMismatch => {
                f.write_str("activity package weights do not match the graph binding")
            }
            Self::Graph(e) => write!(f, "activity graph refused: {e}"),
            Self::Tensor(e) => write!(f, "activity tensor refused: {e}"),
            Self::Contract(e) => write!(f, "activity package canonical encoding failed: {e}"),
            Self::Cancelled => f.write_str("activity package load cancelled"),
        }
    }
}

impl std::error::Error for ActivityPackageError {}

impl From<ModelPackageError> for ActivityPackageError {
    fn from(e: ModelPackageError) -> Self {
        Self::Archive(e)
    }
}
impl From<ModelIrError> for ActivityPackageError {
    fn from(e: ModelIrError) -> Self {
        Self::Graph(e)
    }
}
impl From<TensorError> for ActivityPackageError {
    fn from(e: TensorError) -> Self {
        Self::Tensor(e)
    }
}
impl From<ContractError> for ActivityPackageError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}

/// Frozen preprocessing and port interpretation of the activity package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityPackageSpec {
    /// Strict-size program: target size, luma transform and unit scaling.
    pub program: PreprocessProgram,
    /// Resampling filter of the resize.
    pub filter: ResizeFilter,
    /// Aspect rule of the resize.
    pub aspect: ResizeAspect,
}

impl ActivityPackageSpec {
    /// The only spec this executor implements: 32x32 luma, unit scale, nearest stretch.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            program: PreprocessProgram::new(
                ACTIVITY_INPUT_SIDE,
                ACTIVITY_INPUT_SIDE,
                ChannelTransform::LumaOnly,
                true,
            ),
            filter: ResizeFilter::Nearest,
            aspect: ResizeAspect::Stretch,
        }
    }

    /// Versioned resize identity of the preprocessing (`fss.reference.image_resize.v1`).
    #[must_use]
    pub fn resize_digest(&self) -> ContentDigest {
        self.program.resize_digest(self.filter, self.aspect)
    }

    /// Canonical bytes; the spec artifact is exactly these bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ActivityPackageError> {
        let mut e = CanonicalEncoder::new();
        e.text(ACTIVITY_PACKAGE_SPEC_DOMAIN);
        e.text(ACTIVITY_MODEL_GENERATION);
        for port in [
            ACTIVITY_FRAME_INPUT,
            ACTIVITY_REFERENCE_INPUT,
            ACTIVITY_WEIGHTS_INPUT,
            ACTIVITY_SCORE_OUTPUT,
        ] {
            e.text(port);
        }
        e.bytes(&self.program.canonical_bytes());
        e.u8(match self.filter {
            ResizeFilter::Nearest => 1,
            ResizeFilter::Bilinear => 2,
        });
        match self.aspect {
            ResizeAspect::Stretch => e.u8(1),
            ResizeAspect::Letterbox(pad) => {
                e.u8(2);
                e.u8(pad);
            }
        }
        e.text(ACTIVITY_SEMANTIC_LABEL);
        Ok(e.finish_checked()?)
    }

    /// Strict decode: anything other than the exact canonical bytes of [`Self::v1`] is refused,
    /// because this executor implements no other interpretation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActivityPackageError> {
        let mut d = CanonicalDecoder::new(bytes);
        let expected = Self::v1();
        if d.text()? != ACTIVITY_PACKAGE_SPEC_DOMAIN || d.text()? != ACTIVITY_MODEL_GENERATION {
            return Err(ActivityPackageError::InvalidSpec);
        }
        for port in [
            ACTIVITY_FRAME_INPUT,
            ACTIVITY_REFERENCE_INPUT,
            ACTIVITY_WEIGHTS_INPUT,
            ACTIVITY_SCORE_OUTPUT,
        ] {
            if d.text()? != port {
                return Err(ActivityPackageError::InvalidSpec);
            }
        }
        if d.bytes()? != expected.program.canonical_bytes().as_slice() {
            return Err(ActivityPackageError::InvalidSpec);
        }
        if d.u8()? != 1 || d.u8()? != 1 || d.text()? != ACTIVITY_SEMANTIC_LABEL {
            return Err(ActivityPackageError::InvalidSpec);
        }
        d.ensure_finished()?;
        if expected.encode()? != bytes {
            return Err(ActivityPackageError::InvalidSpec);
        }
        Ok(expected)
    }
}

/// The in-tree activity graph definition. The packaged graph must digest identically.
pub fn activity_graph() -> Result<ModelIrGraph, ActivityPackageError> {
    let g = ACTIVITY_TENSOR_GENERATION;
    let plane = Shape::new(vec![1, 1, ACTIVITY_INPUT_SIDE, ACTIVITY_INPUT_SIDE])?;
    let mut flatten = AttributeMap::new();
    flatten.insert(
        "shape".into(),
        AttrValue::IntList(vec![1, ACTIVITY_ELEMENTS as i64]),
    );
    Ok(ModelIrGraph::builder(ACTIVITY_MODEL_GENERATION, g)
        .add_input(TensorPort::new(
            ACTIVITY_FRAME_INPUT,
            DType::F32,
            plane.clone(),
            g,
        )?)
        .add_input(TensorPort::new(
            ACTIVITY_REFERENCE_INPUT,
            DType::F32,
            plane,
            g,
        )?)
        .add_input(TensorPort::new(
            ACTIVITY_WEIGHTS_INPUT,
            DType::F32,
            Shape::new(vec![ACTIVITY_ELEMENTS, 1])?,
            g,
        )?)
        .add_output(TensorPort::new(
            ACTIVITY_SCORE_OUTPUT,
            DType::F32,
            Shape::new(vec![1, 1])?,
            g,
        )?)
        .add_node(GraphNode::new(
            "node:delta",
            OpCode::Sub,
            "luma difference against the reference frame",
            vec![ACTIVITY_FRAME_INPUT.into(), ACTIVITY_REFERENCE_INPUT.into()],
            vec!["delta".into()],
            AttributeMap::new(),
        )?)
        .add_node(GraphNode::new(
            "node:energy",
            OpCode::Mul,
            "squared difference",
            vec!["delta".into(), "delta".into()],
            vec!["energy".into()],
            AttributeMap::new(),
        )?)
        .add_node(GraphNode::new(
            "node:flatten",
            OpCode::Reshape,
            "flatten to one row",
            vec!["energy".into()],
            vec!["flat".into()],
            flatten,
        )?)
        .add_node(GraphNode::new(
            "node:mean",
            OpCode::MatMul,
            "uniform mean, an uncalibrated change score",
            vec!["flat".into(), ACTIVITY_WEIGHTS_INPUT.into()],
            vec![ACTIVITY_SCORE_OUTPUT.into()],
            AttributeMap::new(),
        )?)
        .build_and_validate()?)
}

/// The literal weight constants: `ACTIVITY_ELEMENTS` copies of `2^-10`.
#[must_use]
pub fn activity_mean_weights() -> Vec<f32> {
    vec![1.0_f32 / ACTIVITY_ELEMENTS as f32; ACTIVITY_ELEMENTS]
}

/// Deterministic Safetensors container of the weights: sorted keys, contiguous data, no padding.
fn activity_weights_safetensors() -> Vec<u8> {
    let values = activity_mean_weights();
    let mut data = Vec::with_capacity(values.len() * 4);
    for value in &values {
        data.extend_from_slice(&value.to_le_bytes());
    }
    let header = format!(
        "{{\"__metadata__\":{{\"format\":\"fss-first-party\",\"model\":\"{ACTIVITY_MODEL_GENERATION}\"}},\"{ACTIVITY_WEIGHTS_INPUT}\":{{\"dtype\":\"F32\",\"shape\":[{ACTIVITY_ELEMENTS},1],\"data_offsets\":[0,{}]}}}}",
        data.len()
    );
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend(data);
    bytes
}

/// Builds the package archive deterministically from the literal definitions in this module.
pub fn build_activity_package() -> Result<Vec<u8>, ActivityPackageError> {
    let graph = encode_canonical_model_ir(&activity_graph()?)?;
    let artifacts = vec![
        ModelPackageArtifact::new(WEIGHTS_ARTIFACT, activity_weights_safetensors())?,
        ModelPackageArtifact::new(GRAPH_ARTIFACT, graph)?,
        ModelPackageArtifact::new(ACTIVITY_SPEC_ARTIFACT, ActivityPackageSpec::v1().encode()?)?,
        ModelPackageArtifact::new(LICENSE_ARTIFACT, ACTIVITY_LICENSE_TEXT.as_bytes().to_vec())?,
    ];
    let digest_of = |name: &'static str| {
        artifacts
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.digest)
            .ok_or(ActivityPackageError::MissingArtifact(name))
    };
    let license = ModelLicenseRecord::new(
        ACTIVITY_LICENSE_IDENTITY,
        Some(ContentDigest::sha256(ACTIVITY_LICENSE_TEXT.as_bytes())),
        true,
        Vec::new(),
        ACTIVITY_SOURCE_IDENTITY,
        vec![
            digest_of(GRAPH_ARTIFACT)?,
            digest_of(ACTIVITY_SPEC_ARTIFACT)?,
        ],
        None,
    )
    .map_err(|e| ActivityPackageError::Archive(e.into()))?;
    let manifest = ModelManifestV1::new(
        ModelId::parse(ACTIVITY_MODEL_ID).map_err(|e| ActivityPackageError::Archive(e.into()))?,
        ModelGeneration::parse(ACTIVITY_MODEL_GENERATION)?,
        digest_of(WEIGHTS_ARTIFACT)?,
        SchemaId::parse(ACTIVITY_INPUT_SCHEMA)?,
        SchemaId::parse(ACTIVITY_OUTPUT_SCHEMA)?,
        CalibrationGeneration::parse(ACTIVITY_CALIBRATION_GENERATION)?,
        license,
    )
    .map_err(|e| ActivityPackageError::Archive(e.into()))?;
    Ok(ModelPackageArchive::encode(&ModelPackage::new(
        manifest, artifacts,
    )?)?)
}

/// The surveillance-monitoring default license policy plus the explicit first-party identity,
/// with a license text digest required.
pub fn activity_license_policy() -> Result<ModelLicensePolicy, ActivityPackageError> {
    let mut policy =
        ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
    policy.set_require_text_digest(true);
    policy
        .allow_license(ACTIVITY_LICENSE_IDENTITY)
        .map_err(ActivityPackageError::License)?;
    Ok(policy)
}

fn artifact<'p>(
    package: &'p ModelPackage,
    name: &'static str,
) -> Result<&'p [u8], ActivityPackageError> {
    let mut found = package.artifacts.values().filter(|a| a.name == name);
    let first = found
        .next()
        .ok_or(ActivityPackageError::MissingArtifact(name))?;
    if found.next().is_some() {
        return Err(ActivityPackageError::MissingArtifact(name));
    }
    Ok(&first.payload)
}

/// A verified activity package: manifest, license decision, frozen graph, spec and weights.
#[derive(Debug)]
pub struct VerifiedActivityPackage {
    archive_digest: ContentDigest,
    manifest: ModelManifestV1,
    manifest_digest: ContentDigest,
    license: ModelLicenseDecision,
    spec: ActivityPackageSpec,
    graph: ModelIrGraph,
    graph_digest: ContentDigest,
    weights_digest: ContentDigest,
    mean_weights: Vec<f32>,
}

impl VerifiedActivityPackage {
    /// Verifies and loads a package. `expected` is the caller's independently pinned
    /// whole-archive SHA-256; `policy` decides the license.
    pub fn load(
        bytes: &[u8],
        expected: ContentDigest,
        policy: &ModelLicensePolicy,
        cx: &ScalarExecCx,
    ) -> Result<Self, ActivityPackageError> {
        let checkpoint = |stage| {
            cx.checkpoint(stage)
                .map_err(|_| ActivityPackageError::Cancelled)
        };
        checkpoint("activity_package:admit")?;
        if bytes.len() > MAX_ACTIVITY_PACKAGE_BYTES {
            return Err(ActivityPackageError::Limit);
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(ActivityPackageError::DigestMismatch);
        }
        let package = ModelPackageArchive::decode(bytes, &ModelPackageLimits::default())?;
        let manifest = &package.manifest;
        if manifest.model_id().as_str() != ACTIVITY_MODEL_ID
            || manifest.generation().as_str() != ACTIVITY_MODEL_GENERATION
        {
            return Err(ActivityPackageError::WrongModel {
                model_id: manifest.model_id().as_str().to_owned(),
                generation: manifest.generation().as_str().to_owned(),
            });
        }
        let license = policy
            .check_manifest(manifest)
            .map_err(ActivityPackageError::License)?;
        let weights = artifact(&package, WEIGHTS_ARTIFACT)?;
        let weights_digest = ContentDigest::sha256(weights);
        if weights_digest != manifest.weights_digest() {
            return Err(ActivityPackageError::MissingArtifact(WEIGHTS_ARTIFACT));
        }
        let license_text = artifact(&package, LICENSE_ARTIFACT)?;
        if Some(ContentDigest::sha256(license_text)) != manifest.license().text_digest() {
            return Err(ActivityPackageError::MissingArtifact(LICENSE_ARTIFACT));
        }
        // A package claiming the first-party activity license identity must
        // carry exactly the committed first-party text: a different license
        // text under this identity is not a variant we published, whatever a
        // self-consistent manifest records.
        if manifest.license().spdx_or_identity() == ACTIVITY_LICENSE_IDENTITY
            && manifest.license().text_digest()
                != Some(ContentDigest::sha256(ACTIVITY_LICENSE_TEXT.as_bytes()))
        {
            return Err(ActivityPackageError::MissingArtifact(LICENSE_ARTIFACT));
        }
        let spec = ActivityPackageSpec::decode(artifact(&package, ACTIVITY_SPEC_ARTIFACT)?)?;
        checkpoint("activity_package:graph")?;
        let graph_bytes = artifact(&package, GRAPH_ARTIFACT)?;
        let graph = decode_canonical_model_ir(graph_bytes, ContentDigest::sha256(graph_bytes))
            .map_err(|_| ActivityPackageError::GraphMismatch)?;
        let graph_digest = compute_model_ir_digest(&graph)?;
        if graph_digest != compute_model_ir_digest(&activity_graph()?)? {
            return Err(ActivityPackageError::GraphMismatch);
        }
        checkpoint("activity_package:weights")?;
        let mut tensors = read_f32_tensors(weights, &ImportLimits::default())
            .map_err(ActivityPackageError::Weights)?;
        let port = graph
            .find_input(ACTIVITY_WEIGHTS_INPUT)
            .ok_or(ActivityPackageError::WeightsMismatch)?;
        let tensor = tensors
            .remove(ACTIVITY_WEIGHTS_INPUT)
            .ok_or(ActivityPackageError::WeightsMismatch)?;
        // The weights are literal first-party constants: any other value under this generation
        // would be a different model wearing the same name, so it is refused bit-exactly.
        let literal = activity_mean_weights();
        if !tensors.is_empty()
            || tensor.shape.as_slice() != port.shape().dims()
            || tensor.values.len() != literal.len()
            || tensor
                .values
                .iter()
                .zip(&literal)
                .any(|(a, b)| a.to_bits() != b.to_bits())
        {
            return Err(ActivityPackageError::WeightsMismatch);
        }
        let manifest_digest = manifest
            .manifest_digest()
            .map_err(|e| ActivityPackageError::Archive(e.into()))?;
        checkpoint("activity_package:publish")?;
        Ok(Self {
            archive_digest: expected,
            manifest: package.manifest,
            manifest_digest,
            license,
            spec,
            graph,
            graph_digest,
            weights_digest,
            mean_weights: tensor.values,
        })
    }

    /// Verifies and loads the committed [`ACTIVITY_PACKAGE_V1`] against its pinned digest under
    /// [`activity_license_policy`].
    pub fn load_committed(cx: &ScalarExecCx) -> Result<Self, ActivityPackageError> {
        Self::load(
            ACTIVITY_PACKAGE_V1,
            ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?,
            &activity_license_policy()?,
            cx,
        )
    }

    /// Whole-archive identity the caller pinned.
    #[must_use]
    pub const fn archive_digest(&self) -> ContentDigest {
        self.archive_digest
    }
    /// Canonical manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ModelManifestV1 {
        &self.manifest
    }
    /// Canonical manifest digest: the receipt's `modelPackageRoot`.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// License-policy decision.
    #[must_use]
    pub const fn license_decision(&self) -> &ModelLicenseDecision {
        &self.license
    }
    /// Frozen preprocessing and port interpretation.
    #[must_use]
    pub const fn spec(&self) -> &ActivityPackageSpec {
        &self.spec
    }
    /// Verified graph.
    #[must_use]
    pub const fn graph(&self) -> &ModelIrGraph {
        &self.graph
    }
    /// `compute_model_ir_digest` of the verified graph.
    #[must_use]
    pub const fn graph_digest(&self) -> ContentDigest {
        self.graph_digest
    }
    /// SHA-256 of the exact weights artifact.
    #[must_use]
    pub const fn weights_digest(&self) -> ContentDigest {
        self.weights_digest
    }
    /// Verified `mean_weights` values.
    #[must_use]
    pub fn mean_weights(&self) -> &[f32] {
        &self.mean_weights
    }
}
