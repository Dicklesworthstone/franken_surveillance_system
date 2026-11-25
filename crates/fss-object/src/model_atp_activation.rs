#![forbid(unsafe_code)]
//! Model package RaptorQ/GF(256) protection and root-last ATP activation (`FSS-147`, `fss-x4a.14.18`).
//!
//! Composes [`ModelManifestV1`], [`ModelLicensePolicy`], [`ObjectManifest`],
//! [`ClosureVerifier`] (`FSS-127`), [`PostRepairDigestGate`] & [`Gf256Codec`] (`FSS-128`), and
//! [`IndependentArchiveReconstructor`] (`FSS-135`) into a deterministic, non-collapsed custody
//! and activation state machine for immutable pure-Rust model packages:
//!
//! - **No `latest`, ever:** every generation identifier is validated via [`reject_latest_alias`]
//!   and pinned to an explicit generation tuple `(model_generation, preprocess_generation,
//!   numeric_generation, kernel_generation, memory_plan_generation, calibration_generation)`.
//! - **Non-collapsed custody lattice (`ModelPackageAtpState`):** separates `Staged`, `Verified`,
//!   `Durable`, `Protected`, `Retrievable`, `Active`, `Quarantined`, `RolledBack`, and
//!   `Indeterminate` so ATP byte delivery NEVER silently activates a model generation.
//! - **Systematic GF(256) repair protection (`protect_package`):** encodes model weights, license
//!   text, and binary manifest into deterministic `FSS-128` `RepairPlan`s + `RepairSymbolEnvelope`s
//!   and verifies post-repair canonical digest recovery (`recover_artifact_via_repair`) without
//!   ever carrying effect authority (`XFER-INV-006`).
//! - **Root-last license- & closure-gated ATP activation (`activate_generation`):** requires
//!   (1) passing [`ModelLicensePolicy::check_manifest`], (2) `FSS-127` complete closure verification
//!   of the model package `ObjectManifest` root, (3) `FSS-135` independent manifest-only
//!   reconstruction matching the root bit-identically (including GF(256) recovery drills!), and
//!   (4) explicit owner-approved [`ModelActivationAuthority`].
//! - **Instant atomic rollback (`rollback_to_prior`):** preserves the superseded active generation
//!   and emits a sealed bounded [`ModelAtpActivationReceipt`] (`FSSMATP1` v1, domain
//!   `fss.atp_model_activation_receipt.v1`).

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ModelGeneration, TimestampNs,
};

use crate::ObjectManifest;
use crate::independent_reconstruct::{
    ColdArchiveBlobSet, IndependentArchiveReconstructor, ReconstructionVerdict,
    RepairFallbackBundle,
};
use crate::model_license_policy::{ModelLicensePolicy, ModelLicensePolicyError};
use crate::model_manifest::{ModelManifestV1, reject_latest_alias};
use crate::repair_gate::{
    PostRepairDigestGate, RepairAuthorityContext, RepairGateState, RepairLease, RepairPlan,
    RepairSymbolEnvelope,
};

/// Registered digest domain for sealed [`ModelAtpActivationReceipt`] commitments (`FSS-147`).
pub const ATP_MODEL_ACTIVATION_RECEIPT_DOMAIN: &str = "fss.atp_model_activation_receipt.v1";
/// Binary wire header magic for serialized model ATP activation receipts.
pub const MODEL_ATP_RECEIPT_MAGIC: [u8; 8] = *b"FSSMATP1";
/// Supported durable format version for [`ModelAtpActivationReceipt`].
pub const MODEL_ATP_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on diagnostic label bytes in receipts.
pub const MAX_MODEL_ATP_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_MODEL_ATP_WIRE_BYTES: usize = 512 * 1024;

/// Non-collapsed custody and activation state of an immutable model package generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelPackageAtpState {
    /// Artifacts received locally; not yet verified or durable.
    Staged = 1,
    /// Artifacts verified against canonical SHA-256 digests and `ModelManifestV1`.
    Verified = 2,
    /// Artifacts and package root manifest persisted durably (still NOT active).
    Durable = 3,
    /// GF(256) repair symbols generated and bound to exact generation plans.
    Protected = 4,
    /// Independent manifest-only reconstruction & optional repair recovery drill verified.
    Retrievable = 5,
    /// Explicitly activated as the live immutable generation after license + closure + authority gates.
    Active = 6,
    /// Corrupt, tampered, license-rejected, or post-repair mismatched; quarantined from activation.
    Quarantined = 7,
    /// Previously active generation rolled back atomically to its verified predecessor.
    RolledBack = 8,
    /// Activation or transfer boundary interrupted ambiguously; awaits reconciliation.
    Indeterminate = 9,
}

impl ModelPackageAtpState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Durable => "durable",
            Self::Protected => "protected",
            Self::Retrievable => "retrievable",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::RolledBack => "rolled_back",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Durable),
            4 => Ok(Self::Protected),
            5 => Ok(Self::Retrievable),
            6 => Ok(Self::Active),
            7 => Ok(Self::Quarantined),
            8 => Ok(Self::RolledBack),
            9 => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused model protection or activation operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAtpGuidance {
    /// Repair invalid generation labels, remove `latest`, or fix GF(256) symbol parameters.
    RepairModelPackageInputs,
    /// Obtain a compliant license approval for the target operational profile before activating.
    ResolveLicensePolicyRejection,
    /// Quarantine corrupt artifacts and recover via verified GF(256) repair or healthy replica.
    QuarantineAndRepairPackage,
    /// Re-authorize activation capability, privacy, authority generation, or owner approval token.
    ReauthorizeActivation,
    /// Cooperative cancellation observed; safe to retry cleanly without partial activation.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary activation receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`ModelAtpActivator`] or [`ModelAtpActivationReceipt`] codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelAtpError {
    /// Invalid generation (`latest` refused), digest mismatch, or malformed artifact geometry.
    InvalidInput(String),
    /// License policy refused activation for the target operational profile.
    LicenseRejected(String),
    /// Closure verification, independent reconstruction, or post-repair digest check failed.
    IntegrityOrRepairFailed(String),
    /// Capability, privacy, generation, owner approval, or forbidden transfer-effect escalation refused.
    AuthorityRefused(String),
    /// Rollback requested when no verified prior active generation exists.
    NoPriorGenerationForRollback,
    /// Cooperative cancellation observed before activation committed.
    Cancelled,
    /// Wire length exceeded hard bounds.
    BoundsExceeded {
        /// Observed size.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary receipt lacked [`MODEL_ATP_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl ModelAtpError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-MODEL-ATP-INVALID-INPUT-001",
            Self::LicenseRejected(_) => "ERR-MODEL-ATP-LICENSE-REJECTED-001",
            Self::IntegrityOrRepairFailed(_) => "ERR-MODEL-ATP-INTEGRITY-REPAIR-001",
            Self::AuthorityRefused(_) => "ERR-MODEL-ATP-AUTHORITY-001",
            Self::NoPriorGenerationForRollback => "ERR-MODEL-ATP-NO-ROLLBACK-TARGET-001",
            Self::Cancelled => "ERR-MODEL-ATP-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-MODEL-ATP-BOUNDS-001",
            Self::InvalidMagic => "ERR-MODEL-ATP-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-MODEL-ATP-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-MODEL-ATP-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-MODEL-ATP-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-MODEL-ATP-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> ModelAtpGuidance {
        match self {
            Self::InvalidInput(_) | Self::NoPriorGenerationForRollback => {
                ModelAtpGuidance::RepairModelPackageInputs
            }
            Self::LicenseRejected(_) => ModelAtpGuidance::ResolveLicensePolicyRejection,
            Self::IntegrityOrRepairFailed(_) => ModelAtpGuidance::QuarantineAndRepairPackage,
            Self::AuthorityRefused(_) => ModelAtpGuidance::ReauthorizeActivation,
            Self::Cancelled => ModelAtpGuidance::RetryWhenReady,
            Self::BoundsExceeded { .. }
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => ModelAtpGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for ModelAtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ModelAtpError {}

impl From<ModelLicensePolicyError> for ModelAtpError {
    fn from(value: ModelLicensePolicyError) -> Self {
        Self::LicenseRejected(value.to_string())
    }
}

/// Complete immutable execution generation tuple pinned alongside a model package (`FSS-147`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelExecutionGenerationPin {
    /// Immutable model package generation (`latest` forbidden).
    pub model_generation: String,
    /// Preprocessing pipeline generation (`latest` forbidden).
    pub preprocess_generation: String,
    /// Numeric quantization/precision generation (`latest` forbidden).
    pub numeric_generation: String,
    /// Safe pure-Rust kernel generation (`latest` forbidden).
    pub kernel_generation: String,
    /// Deterministic static memory-plan generation (`latest` forbidden).
    pub memory_plan_generation: String,
    /// Sensor calibration generation (`latest` forbidden).
    pub calibration_generation: String,
}

impl ModelExecutionGenerationPin {
    /// Validates every pinned generation label and refuses `latest` in any slot.
    pub fn validate(&self) -> Result<(), ModelAtpError> {
        for (name, val) in [
            ("model_generation", &self.model_generation),
            ("preprocess_generation", &self.preprocess_generation),
            ("numeric_generation", &self.numeric_generation),
            ("kernel_generation", &self.kernel_generation),
            ("memory_plan_generation", &self.memory_plan_generation),
            ("calibration_generation", &self.calibration_generation),
        ] {
            validate_label(val, MAX_MODEL_ATP_LABEL_BYTES, name)?;
            reject_latest_alias(val).map_err(|_| {
                ModelAtpError::InvalidInput(format!("{name} cannot contain 'latest' alias"))
            })?;
        }
        Ok(())
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.model_generation);
        enc.text(&self.preprocess_generation);
        enc.text(&self.numeric_generation);
        enc.text(&self.kernel_generation);
        enc.text(&self.memory_plan_generation);
        enc.text(&self.calibration_generation);
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ModelAtpError> {
        let pin = Self {
            model_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
            preprocess_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
            numeric_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
            kernel_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
            memory_plan_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
            calibration_generation: dec
                .text()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                .to_owned(),
        };
        pin.validate()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        Ok(pin)
    }
}

/// Explicit authority required to activate or roll back a verified model generation.
///
/// ATP byte delivery NEVER carries activation authority on its own (`XFER-INV-006`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelActivationAuthority {
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while model activation capability remains active.
    pub activation_capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// Non-zero owner approval commitment authorizing activation of this specific generation.
    pub owner_approval_digest: Option<ContentDigest>,
}

impl ModelActivationAuthority {
    fn validate_for_activation(&self) -> Result<ContentDigest, ModelAtpError> {
        if !self.activation_capability_active || !self.privacy_active {
            return Err(ModelAtpError::AuthorityRefused(
                "model activation capability or privacy authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(ModelAtpError::AuthorityRefused(format!(
                "stale authority generation {} != expected {}",
                self.authority_generation, self.expected_authority_generation
            )));
        }
        let approval = self.owner_approval_digest.ok_or_else(|| {
            ModelAtpError::AuthorityRefused(
                "explicit owner_approval_digest required; ATP byte delivery cannot activate silently"
                    .to_owned(),
            )
        })?;
        if approval.bytes().iter().all(|&b| b == 0) {
            return Err(ModelAtpError::AuthorityRefused(
                "owner_approval_digest cannot be zero".to_owned(),
            ));
        }
        Ok(approval)
    }

    fn as_repair_authority(&self) -> RepairAuthorityContext {
        RepairAuthorityContext::active(
            self.contract_basis_digest,
            self.authority_generation,
            self.privacy_epoch,
        )
    }
}

/// Protected GF(256) repair bundle for one immutable model artifact (weights, license, or manifest).
#[derive(Clone, Debug)]
pub struct ProtectedModelArtifact {
    /// Artifact role (`"weights"`, `"license"`, `"manifest"`).
    pub role: String,
    /// Verified canonical SHA-256 digest of the artifact bytes.
    pub digest: ContentDigest,
    /// Exact artifact byte length.
    pub byte_len: u64,
    /// Sealed `FSS-128` immutable GF(256) repair plan pinned to this generation.
    pub repair_plan: RepairPlan,
    /// Generated source + repair symbol envelopes (`k + r` symbols).
    pub symbols: Vec<RepairSymbolEnvelope>,
}

/// One RaptorQ/GF(256)-protected immutable model package ready for retrievability drill & ATP activation.
#[derive(Clone, Debug)]
pub struct ProtectedModelPackage {
    /// Immutable `ModelManifestV1`.
    pub manifest: ModelManifestV1,
    /// Complete execution generation pin tuple.
    pub generation_pin: ModelExecutionGenerationPin,
    /// Content-addressed `ObjectManifest` root binding manifest + weights + license digests (root last).
    pub package_root_manifest: ObjectManifest,
    /// Raw immutable blobs keyed by SHA-256 digest (can drop any blob to test GF(256) repair!).
    pub cold_blobs: ColdArchiveBlobSet,
    /// Protected artifact repair plans and symbol sets keyed by canonical digest.
    pub protected_artifacts: BTreeMap<ContentDigest, ProtectedModelArtifact>,
    /// Current non-collapsed custody/activation state.
    pub state: ModelPackageAtpState,
}

impl ProtectedModelPackage {
    /// Stages, verifies, persists, and GF(256)-protects a model package (weights + optional license
    /// text + binary `ModelManifestV1`) into a root-last `ObjectManifest` WITHOUT activating it.
    #[allow(clippy::too_many_arguments)]
    pub fn protect_package(
        manifest: ModelManifestV1,
        generation_pin: ModelExecutionGenerationPin,
        weights_bytes: Vec<u8>,
        license_text_bytes: Option<Vec<u8>>,
        symbol_size: u32,
        repair_symbol_count: u32,
        source_generation: u64,
        contract_basis_digest: ContentDigest,
        expected_authority_generation: u64,
        cancelled: bool,
    ) -> Result<Self, ModelAtpError> {
        if cancelled {
            return Err(ModelAtpError::Cancelled);
        }
        manifest
            .validate()
            .map_err(|e| ModelAtpError::InvalidInput(e.to_string()))?;
        generation_pin.validate()?;
        if generation_pin.model_generation != manifest.generation().as_str() {
            return Err(ModelAtpError::InvalidInput(
                "generation_pin.model_generation disagrees with manifest.generation".to_owned(),
            ));
        }
        if generation_pin.calibration_generation != manifest.calibration_generation().as_str() {
            return Err(ModelAtpError::InvalidInput(
                "generation_pin.calibration_generation disagrees with manifest.calibration_generation"
                    .to_owned(),
            ));
        }
        if weights_bytes.is_empty() {
            return Err(ModelAtpError::InvalidInput(
                "weights_bytes must be non-empty".to_owned(),
            ));
        }
        let observed_weights_digest = ContentDigest::sha256(&weights_bytes);
        if observed_weights_digest != manifest.weights_digest() {
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "weights_bytes SHA-256 disagrees with manifest.weights_digest".to_owned(),
            ));
        }
        if let Some(ref lic_bytes) = license_text_bytes {
            let obs_lic = ContentDigest::sha256(lic_bytes);
            if manifest.license().text_digest() != Some(obs_lic) {
                return Err(ModelAtpError::IntegrityOrRepairFailed(
                    "license_text_bytes SHA-256 disagrees with manifest.license().text_digest()"
                        .to_owned(),
                ));
            }
        } else if manifest.license().text_digest().is_some() {
            return Err(ModelAtpError::InvalidInput(
                "manifest declares license text_digest but license_text_bytes was omitted"
                    .to_owned(),
            ));
        }

        let manifest_bytes = manifest
            .to_canonical_bytes()
            .map_err(|e| ModelAtpError::Encoding(e.to_string()))?;
        let manifest_blob_digest = ContentDigest::sha256(&manifest_bytes);

        // Assemble root-last ObjectManifest binding weights + optional license + manifest metadata!
        // Note: ObjectManifest::new automatically inserts `metadata_digest` into `children`.
        let mut children = vec![observed_weights_digest];
        if let Some(ref lic_bytes) = license_text_bytes {
            let lic_digest = ContentDigest::sha256(lic_bytes);
            if lic_digest != observed_weights_digest && lic_digest != manifest_blob_digest {
                children.push(lic_digest);
            }
        }
        let package_root_manifest =
            ObjectManifest::new("model_package_atp", children, Some(manifest_blob_digest))
                .map_err(|e| ModelAtpError::InvalidInput(e.to_string()))?;
        let root_bytes = package_root_manifest.canonical_bytes();
        let sealed_root_digest = package_root_manifest.root();

        let mut cold_blobs = ColdArchiveBlobSet::new();
        cold_blobs.insert_verified_blob(weights_bytes.clone());
        cold_blobs.insert_verified_blob(manifest_bytes.clone());
        if let Some(ref lic_bytes) = license_text_bytes {
            cold_blobs.insert_verified_blob(lic_bytes.clone());
        }
        cold_blobs.insert_verified_blob(root_bytes);

        let mut protected_artifacts = BTreeMap::new();
        for (role, raw) in [("weights", weights_bytes), ("manifest", manifest_bytes)]
            .into_iter()
            .chain(license_text_bytes.into_iter().map(|b| ("license", b)))
        {
            let art = build_protected_artifact(
                role,
                &raw,
                sealed_root_digest,
                source_generation,
                contract_basis_digest,
                expected_authority_generation,
                symbol_size,
                repair_symbol_count,
            )?;
            protected_artifacts.insert(art.digest, art);
        }

        Ok(Self {
            manifest,
            generation_pin,
            package_root_manifest,
            cold_blobs,
            protected_artifacts,
            state: ModelPackageAtpState::Protected,
        })
    }

    /// Simulates or recovers an erased/missing child blob via `FSS-128` GF(256) repair symbols
    /// and verifies canonical SHA-256 equality before admitting the recovered bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_artifact_via_repair(
        &mut self,
        target_digest: ContentDigest,
        authority: &RepairAuthorityContext,
        lease: &RepairLease,
        min_fence: u64,
        available_symbols: &[RepairSymbolEnvelope],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<Vec<u8>, ModelAtpError> {
        if cancelled {
            return Err(ModelAtpError::Cancelled);
        }
        let art = self
            .protected_artifacts
            .get(&target_digest)
            .ok_or_else(|| {
                ModelAtpError::InvalidInput(
                    "target_digest not found in protected model package".to_owned(),
                )
            })?;
        let res = PostRepairDigestGate::reconstruct_and_verify(
            &art.repair_plan,
            authority,
            lease,
            min_fence,
            available_symbols,
            now,
            false,
            false,
        )
        .map_err(|e| ModelAtpError::IntegrityOrRepairFailed(e.to_string()))?;
        if res.receipt.state != RepairGateState::VerifiedCanonicalMatch {
            self.state = ModelPackageAtpState::Quarantined;
            return Err(ModelAtpError::IntegrityOrRepairFailed(format!(
                "post-repair digest gate returned {}",
                res.receipt.state.as_str()
            )));
        }
        let bytes = res.verified_bytes.ok_or_else(|| {
            self.state = ModelPackageAtpState::Quarantined;
            ModelAtpError::IntegrityOrRepairFailed("missing verified_bytes after repair".to_owned())
        })?;
        if ContentDigest::sha256(&bytes) != target_digest {
            self.state = ModelPackageAtpState::Quarantined;
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "repaired artifact SHA-256 disagrees with target_digest".to_owned(),
            ));
        }
        self.cold_blobs.insert_verified_blob(bytes.clone());
        Ok(bytes)
    }

    /// Verifies that `manifest`, `generation_pin`, and `package_root_manifest` remain mutually
    /// bound and untampered (weights digest, manifest metadata digest, and optional license digest
    /// all committed under the exact root-last `ObjectManifest`).
    pub fn verify_package_bindings(&self) -> Result<(), ModelAtpError> {
        self.manifest
            .validate()
            .map_err(|e| ModelAtpError::InvalidInput(e.to_string()))?;
        self.generation_pin.validate()?;
        if self.generation_pin.model_generation != self.manifest.generation().as_str() {
            return Err(ModelAtpError::InvalidInput(
                "generation_pin.model_generation disagrees with manifest.generation".to_owned(),
            ));
        }
        if self.generation_pin.calibration_generation
            != self.manifest.calibration_generation().as_str()
        {
            return Err(ModelAtpError::InvalidInput(
                "generation_pin.calibration_generation disagrees with manifest.calibration_generation"
                    .to_owned(),
            ));
        }
        let manifest_bytes = self
            .manifest
            .to_canonical_bytes()
            .map_err(|e| ModelAtpError::Encoding(e.to_string()))?;
        let manifest_blob_digest = ContentDigest::sha256(&manifest_bytes);
        if self.package_root_manifest.metadata_digest() != Some(manifest_blob_digest) {
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "package_root_manifest metadata_digest disagrees with ModelManifestV1 bytes"
                    .to_owned(),
            ));
        }
        if !self
            .package_root_manifest
            .children()
            .contains(&self.manifest.weights_digest())
        {
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "package_root_manifest does not commit to manifest.weights_digest".to_owned(),
            ));
        }
        if let Some(lic_digest) = self.manifest.license().text_digest()
            && !self.package_root_manifest.children().contains(&lic_digest)
        {
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "package_root_manifest does not commit to manifest.license().text_digest()"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Runs an `FSS-135` independent manifest-only retrievability & GF(256) repair drill on this
    /// package root (zero store/index metadata!) and transitions `Protected -> Retrievable` ONLY
    /// upon `ReconstructionVerdict::VerifiedComplete`.
    pub fn verify_retrievability_drill(
        &mut self,
        authority: &RepairAuthorityContext,
        repair_fallbacks: Vec<(ContentDigest, RepairFallbackBundle)>,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<ContentDigest, ModelAtpError> {
        if cancelled {
            return Err(ModelAtpError::Cancelled);
        }
        self.verify_package_bindings()?;
        let mut blobs = self.cold_blobs.clone();
        for (target, bundle) in repair_fallbacks {
            blobs.insert_repair_fallback(target, bundle);
        }
        let proof = IndependentArchiveReconstructor::reconstruct_root(
            &blobs,
            self.package_root_manifest.root(),
            authority,
            now,
            false,
        )
        .map_err(|e| ModelAtpError::IntegrityOrRepairFailed(e.to_string()))?;
        if proof.verdict != ReconstructionVerdict::VerifiedComplete {
            self.state = ModelPackageAtpState::Quarantined;
            return Err(ModelAtpError::IntegrityOrRepairFailed(format!(
                "independent manifest reconstruction verdict was {} ({} defects)",
                proof.verdict.as_str(),
                proof.defects.len()
            )));
        }
        self.state = ModelPackageAtpState::Retrievable;
        Ok(proof.proof_digest)
    }
}

/// Sealed binary receipt certifying root-last ATP model activation or rollback (`FSSMATP1` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAtpActivationReceipt {
    /// Wire format version (`MODEL_ATP_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Stable model family identity.
    pub model_id: String,
    /// Pinned immutable execution generation tuple (`latest` forbidden).
    pub generation_pin: ModelExecutionGenerationPin,
    /// Superseded prior active generation, when any.
    pub prior_active_generation: Option<String>,
    /// Root-last `ObjectManifest` digest of the model package.
    pub package_root_digest: ContentDigest,
    /// Exact immutable weights SHA-256 digest.
    pub weights_digest: ContentDigest,
    /// Sealed `ModelLicenseDecision` policy approval digest.
    pub license_decision_digest: ContentDigest,
    /// Sealed `FSS-135` independent manifest reconstruction proof digest.
    pub reconstruction_proof_digest: ContentDigest,
    /// Exact `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Owner approval commitment authorizing this transition.
    pub owner_approval_digest: ContentDigest,
    /// Authority generation verified at activation time.
    pub authority_generation: u64,
    /// Privacy policy epoch verified at activation time.
    pub privacy_epoch: u64,
    /// Non-collapsed terminal state (`Active` or `RolledBack`).
    pub state: ModelPackageAtpState,
    /// Timestamp when this receipt was sealed.
    pub sealed_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_model_activation_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl ModelAtpActivationReceipt {
    /// Recomputes the domain-separated SHA-256 commitment (`fss.atp_model_activation_receipt.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, ModelAtpError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_MODEL_ACTIVATION_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ModelAtpError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural invariants, `latest` prohibition, terminal state, and self-digest.
    pub fn verify_self(&self) -> Result<(), ModelAtpError> {
        if self.format_version != MODEL_ATP_RECEIPT_VERSION {
            return Err(ModelAtpError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.model_id, MAX_MODEL_ATP_LABEL_BYTES, "model_id")
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        self.generation_pin
            .validate()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        if let Some(ref prior) = self.prior_active_generation {
            validate_label(prior, MAX_MODEL_ATP_LABEL_BYTES, "prior_active_generation")
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
            reject_latest_alias(prior).map_err(|_| {
                ModelAtpError::MalformedWire(
                    "prior_active_generation cannot contain 'latest'".to_owned(),
                )
            })?;
        }
        if !matches!(
            self.state,
            ModelPackageAtpState::Active | ModelPackageAtpState::RolledBack
        ) {
            return Err(ModelAtpError::MalformedWire(
                "activation receipt state must be Active or RolledBack".to_owned(),
            ));
        }
        for (name, digest) in [
            ("package_root_digest", self.package_root_digest),
            ("weights_digest", self.weights_digest),
            ("license_decision_digest", self.license_decision_digest),
            (
                "reconstruction_proof_digest",
                self.reconstruction_proof_digest,
            ),
            ("contract_basis_digest", self.contract_basis_digest),
            ("owner_approval_digest", self.owner_approval_digest),
        ] {
            if digest.bytes().iter().all(|&b| b == 0) {
                return Err(ModelAtpError::MalformedWire(format!(
                    "{name} cannot be zero"
                )));
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(ModelAtpError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.model_id);
        self.generation_pin.encode_canonical(enc);
        match &self.prior_active_generation {
            Some(p) => {
                enc.u8(1);
                enc.text(p);
            }
            None => enc.u8(0),
        }
        enc.digest(self.package_root_digest);
        enc.digest(self.weights_digest);
        enc.digest(self.license_decision_digest);
        enc.digest(self.reconstruction_proof_digest);
        enc.digest(self.contract_basis_digest);
        enc.digest(self.owner_approval_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.u8(self.state.tag());
        self.sealed_at.encode_canonical(enc);
    }

    /// Encodes this receipt into bounded checksummed binary bytes (`FSSMATP1` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ModelAtpError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| ModelAtpError::Encoding(e.to_string()))?;
        let total = MODEL_ATP_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_MODEL_ATP_WIRE_BYTES {
            return Err(ModelAtpError::BoundsExceeded {
                observed: total,
                maximum: MAX_MODEL_ATP_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MODEL_ATP_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ModelAtpActivationReceipt`] (`FSSMATP1` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ModelAtpError> {
        if bytes.len() > MAX_MODEL_ATP_WIRE_BYTES {
            return Err(ModelAtpError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_MODEL_ATP_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != MODEL_ATP_RECEIPT_MAGIC {
            return Err(ModelAtpError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != MODEL_ATP_RECEIPT_VERSION {
            return Err(ModelAtpError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(ModelAtpError::UnsupportedVersion {
                version: format_version,
            });
        }
        let model_id = dec
            .text()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
            .to_owned();
        let generation_pin = ModelExecutionGenerationPin::decode_canonical(&mut dec)?;
        let prior_active_generation = match dec
            .u8()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.text()
                    .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?
                    .to_owned(),
            ),
            other => {
                return Err(ModelAtpError::MalformedWire(format!(
                    "invalid prior_active_generation tag {other}"
                )));
            }
        };
        let package_root_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let weights_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let license_decision_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let reconstruction_proof_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let owner_approval_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let state = ModelPackageAtpState::from_tag(
            dec.u8()
                .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let sealed_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| ModelAtpError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ModelAtpError::MalformedWire("trailing bytes after model ATP receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            model_id,
            generation_pin,
            prior_active_generation,
            package_root_digest,
            weights_digest,
            license_decision_digest,
            reconstruction_proof_digest,
            contract_basis_digest,
            owner_approval_digest,
            authority_generation,
            privacy_epoch,
            state,
            sealed_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Root-last ATP model generation activator with deterministic rollback (`FSS-147`).
#[derive(Clone, Debug, Default)]
pub struct ModelAtpActivator {
    active_by_model: BTreeMap<String, ModelAtpActivationReceipt>,
    prior_by_model: BTreeMap<String, ModelAtpActivationReceipt>,
    seen_generation_roots: BTreeMap<(String, String), (ContentDigest, ModelExecutionGenerationPin)>,
}

impl ModelAtpActivator {
    /// Creates an empty model activator with zero active generations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the currently active verified generation receipt for `model_id`, if any.
    #[must_use]
    pub fn active_receipt(&self, model_id: &str) -> Option<&ModelAtpActivationReceipt> {
        self.active_by_model.get(model_id)
    }

    /// Performs root-last ATP model generation activation after verifying:
    /// 1. Explicit owner-approved [`ModelActivationAuthority`];
    /// 2. [`ModelLicensePolicy::check_manifest`] approval;
    /// 3. `FSS-135` independent manifest-only reconstruction (`VerifiedComplete`) of `package` root;
    /// 4. Non-`latest` immutable generation pinning.
    pub fn activate_generation(
        &mut self,
        package: &mut ProtectedModelPackage,
        license_policy: &ModelLicensePolicy,
        authority: &ModelActivationAuthority,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<ModelAtpActivationReceipt, ModelAtpError> {
        if cancelled {
            return Err(ModelAtpError::Cancelled);
        }
        let approval_digest = authority.validate_for_activation()?;
        package.verify_package_bindings()?;
        let model_id = package.manifest.model_id().as_str().to_owned();

        // Guard immutable generation identity across ALL previously activated generations
        // (including superseded or rolled-back generations!) and preserve rollback target on duplicate activation!
        let gen_key = (
            model_id.clone(),
            package.generation_pin.model_generation.clone(),
        );
        if let Some((seen_root, seen_pin)) = self.seen_generation_roots.get(&gen_key)
            && (*seen_root != package.package_root_manifest.root()
                || *seen_pin != package.generation_pin)
        {
            return Err(ModelAtpError::IntegrityOrRepairFailed(
                "immutable model_generation cannot be rebound to a different package root or pin"
                    .to_owned(),
            ));
        }
        if let Some(current) = self.active_by_model.get(&model_id)
            && current.generation_pin.model_generation == package.generation_pin.model_generation
        {
            return Err(ModelAtpError::InvalidInput(
                "model generation is already active".to_owned(),
            ));
        }

        // Gate 1: License policy evaluation (fail closed on unapproved/incompatible/expired terms).
        let license_decision = license_policy.check_manifest(&package.manifest)?;
        let license_decision_digest = license_decision.decision_digest();

        // Gate 2: Root-last independent manifest reconstruction verifying every child blob!
        let repair_auth = authority.as_repair_authority();
        let reconstruction_proof_digest =
            package.verify_retrievability_drill(&repair_auth, vec![], now, false)?;

        // Gate 3: Publish root-last activation and retain prior generation for atomic rollback!
        let prior = self.active_by_model.get(&model_id).cloned();
        let prior_active_generation = prior
            .as_ref()
            .map(|r| r.generation_pin.model_generation.clone());

        let mut receipt = ModelAtpActivationReceipt {
            format_version: MODEL_ATP_RECEIPT_VERSION,
            model_id: model_id.clone(),
            generation_pin: package.generation_pin.clone(),
            prior_active_generation,
            package_root_digest: package.package_root_manifest.root(),
            weights_digest: package.manifest.weights_digest(),
            license_decision_digest,
            reconstruction_proof_digest,
            contract_basis_digest: authority.contract_basis_digest,
            owner_approval_digest: approval_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            state: ModelPackageAtpState::Active,
            sealed_at: now,
            receipt_digest: ContentDigest::sha256(b"unsealed-model-atp-activation-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.verify_self()?;

        if let Some(prev) = prior {
            self.prior_by_model.insert(model_id.clone(), prev);
        }
        self.seen_generation_roots.insert(
            gen_key,
            (
                package.package_root_manifest.root(),
                package.generation_pin.clone(),
            ),
        );
        self.active_by_model.insert(model_id, receipt.clone());
        package.state = ModelPackageAtpState::Active;
        Ok(receipt)
    }

    /// Atomically rolls `model_id` back to its verified prior active generation, requiring active
    /// authority and emitting a sealed [`ModelPackageAtpState::RolledBack`] receipt.
    pub fn rollback_to_prior(
        &mut self,
        model_id: &str,
        authority: &ModelActivationAuthority,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<ModelAtpActivationReceipt, ModelAtpError> {
        if cancelled {
            return Err(ModelAtpError::Cancelled);
        }
        let approval_digest = authority.validate_for_activation()?;
        let prior = self
            .prior_by_model
            .get(model_id)
            .cloned()
            .ok_or(ModelAtpError::NoPriorGenerationForRollback)?;
        if authority.contract_basis_digest != prior.contract_basis_digest {
            return Err(ModelAtpError::AuthorityRefused(
                "rollback authority contract_basis_digest disagrees with prior active generation"
                    .to_owned(),
            ));
        }
        let rolled_from = self
            .active_by_model
            .get(model_id)
            .map(|r| r.generation_pin.model_generation.clone());

        let mut restored = prior.clone();
        restored.prior_active_generation = rolled_from;
        restored.owner_approval_digest = approval_digest;
        restored.authority_generation = authority.authority_generation;
        restored.privacy_epoch = authority.privacy_epoch;
        restored.state = ModelPackageAtpState::RolledBack;
        restored.sealed_at = now;
        restored.receipt_digest = restored.compute_digest()?;
        restored.verify_self()?;

        // Commit rollback atomically only after all validation & sealing checks succeed!
        self.prior_by_model.remove(model_id);
        self.active_by_model.insert(model_id.to_owned(), prior);
        Ok(restored)
    }

    /// Helper to verify a model generation string against `latest` refusal cleanly.
    pub fn parse_pinned_generation(raw: &str) -> Result<ModelGeneration, ModelAtpError> {
        reject_latest_alias(raw).map_err(|_| {
            ModelAtpError::InvalidInput("model generation cannot be 'latest'".to_owned())
        })?;
        ModelGeneration::parse(raw).map_err(|e| ModelAtpError::InvalidInput(e.to_string()))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_protected_artifact(
    role: &str,
    raw: &[u8],
    sealed_root_digest: ContentDigest,
    source_generation: u64,
    contract_basis_digest: ContentDigest,
    expected_authority_generation: u64,
    symbol_size: u32,
    repair_symbol_count: u32,
) -> Result<ProtectedModelArtifact, ModelAtpError> {
    if symbol_size == 0 || repair_symbol_count == 0 {
        return Err(ModelAtpError::InvalidInput(
            "symbol_size and repair_symbol_count must be >= 1".to_owned(),
        ));
    }
    let digest = ContentDigest::sha256(raw);
    let plan = RepairPlan::seal(
        sealed_root_digest,
        digest,
        raw.len() as u64,
        source_generation,
        contract_basis_digest,
        expected_authority_generation,
        symbol_size,
        repair_symbol_count,
    )
    .map_err(|e| ModelAtpError::InvalidInput(e.to_string()))?;
    let symbols = plan
        .encode_symbols(raw)
        .map_err(|e| ModelAtpError::IntegrityOrRepairFailed(e.to_string()))?;
    Ok(ProtectedModelArtifact {
        role: role.to_owned(),
        digest,
        byte_len: raw.len() as u64,
        repair_plan: plan,
        symbols,
    })
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), ModelAtpError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ModelAtpError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ModelAtpError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
