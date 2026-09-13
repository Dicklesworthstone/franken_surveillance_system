#![forbid(unsafe_code)]
//! Realization of hydration ladder level H4: laboratory_expansion (AGT-H4, fss-x4a.30.82.16).
//!
//! Normative row (`registries/AGENT_ABSTRACTIONS.md`):
//! - Level: `H4`
//! - Name: `laboratory_expansion`
//! - Content: `replay bundle, intermediates, alternate decoders/models, and oracle comparisons`
//! - Owner: `fss-laboratory/oracle`
//!
//! Constitutional hard gates and invariants:
//! 1. Quarantined from production: Laboratory expansion material is strictly quarantined
//!    from the production runtime and release closure (DEP-CLASS-F4, non-production-quarantine-only).
//! 2. No production authority: Laboratory outputs may NEVER claim authority or be used as an
//!    irreversible-effect premise (`may_claim_authority() == false`, `may_authorize_effects() == false`,
//!    `is_production_safe() == false`).
//! 3. Admission gated: Access requires explicit qualification (`HydrationPurpose::Qualification`)
//!    or an explicit debugging grant (`HydrationPurpose::Debugging`). Routine requests or
//!    `LaboratoryAccess::Unavailable` fail closed with `HydrationError::LaboratoryGrantRequired`.
//! 4. Concrete content: Must contain all 4 normative elements: replay bundle reference, intermediate
//!    artifacts, alternate decoders/models, and oracle comparisons. Empty collections are rejected.
//! 5. Proof bound: Must contain the subject digest in `proof_roots` along with at least one
//!    independent evidence anchor. Completeness must not be Unknown, NotObservable, Unauthorized, or Stale.
//! 6. Deterministic canonical encoding: Implements `CanonicalEncode` and `CanonicalDecode`.
//!    `decode_canonical` bounds collection lengths against remaining input bytes and hard bounds BEFORE
//!    allocating with `Vec::with_capacity` to prevent memory exhaustion attacks (`u32::MAX`).
//!    `decode_canonical` invokes `expansion.validate()?` to kill mutant R22.

use std::collections::BTreeSet;

use super::{
    completeness_code, Completeness, HydrationArtifact, HydrationError,
    HydrationLevel, HydrationPurpose, LaboratoryAccess,
};
use crate::canonical::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
};
use crate::contract::ContractError;
use crate::{
    BudgetVector, ContentDigest, ContractBasis, LedgerAnchor, TimestampNs,
};

/// Stable identifier for hydration ladder level H4.
pub const H4_LEVEL_ID: &str = "H4";

/// Stable name for hydration ladder level H4.
pub const H4_LEVEL_NAME: &str = "laboratory_expansion";

/// Normative content declaration for hydration ladder level H4 from the agent abstraction registry.
pub const H4_CONTENT: &str =
    "replay bundle, intermediates, alternate decoders/models, and oracle comparisons";

/// Owning subsystem for hydration ladder level H4.
pub const H4_OWNER: &str = "fss-laboratory/oracle";

/// Canonical schema discriminator tag for H4 laboratory expansion binary envelopes.
pub const H4_SCHEMA: &str = "fss.h4_laboratory_expansion.v1";

/// Maximum allowed intermediate artifacts in one H4 expansion.
pub const MAX_H4_INTERMEDIATES: usize = 256;

/// Maximum allowed alternate systems in one H4 expansion.
pub const MAX_H4_ALTERNATE_SYSTEMS: usize = 32;

/// Maximum allowed oracle comparisons in one H4 expansion.
pub const MAX_H4_ORACLE_COMPARISONS: usize = 256;

/// Maximum allowed proof roots in one H4 expansion.
pub const MAX_H4_PROOF_ROOTS: usize = 1_024;

/// Maximum length of an identifier string in H4 descriptors.
pub const MAX_H4_IDENTIFIER_LEN: usize = 128;

/// Maximum length of a version or framework string in H4 descriptors.
pub const MAX_H4_METADATA_LEN: usize = 64;

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn completeness_from_code(code: u8) -> Result<Completeness, ContractError> {
    match code {
        1 => Ok(Completeness::Complete),
        2 => Ok(Completeness::Bounded),
        3 => Ok(Completeness::Partial),
        4 => Ok(Completeness::Unknown),
        5 => Ok(Completeness::NotObservable),
        6 => Ok(Completeness::Unauthorized),
        7 => Ok(Completeness::Stale),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

/// A reference to an immutable, self-verifying replay bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBundleRef {
    /// Canonical bundle identifier.
    pub bundle_id: String,
    /// Exact content digest of the replay bundle.
    pub bundle_digest: ContentDigest,
    /// Root manifest digest of the replay bundle.
    pub manifest_root: ContentDigest,
    /// Deterministic PRNG seed used for replay.
    pub seed: u64,
    /// Number of delta batches included in the replay.
    pub delta_batch_count: u32,
    /// Content digest of the verified replay environment.
    pub environment_digest: ContentDigest,
}

impl ReplayBundleRef {
    /// Validates the replay bundle reference invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.bundle_id, MAX_H4_IDENTIFIER_LEN) {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.bundle_digest.bytes().iter().all(|&b| b == 0)
            || self.manifest_root.bytes().iter().all(|&b| b == 0)
            || self.environment_digest.bytes().iter().all(|&b| b == 0)
        {
            return Err(ContractError::InvalidDigest);
        }
        if self.delta_batch_count == 0 {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }
}

impl CanonicalEncode for ReplayBundleRef {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.bundle_id);
        encoder.digest(self.bundle_digest);
        encoder.digest(self.manifest_root);
        encoder.u64(self.seed);
        encoder.u32(self.delta_batch_count);
        encoder.digest(self.environment_digest);
    }
}

impl CanonicalDecode for ReplayBundleRef {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let bundle_id = decoder.text()?.to_owned();
        let bundle_digest = decoder.digest()?;
        let manifest_root = decoder.digest()?;
        let seed = decoder.u64()?;
        let delta_batch_count = decoder.u32()?;
        let environment_digest = decoder.digest()?;
        let r = Self {
            bundle_id,
            bundle_digest,
            manifest_root,
            seed,
            delta_batch_count,
            environment_digest,
        };
        r.validate()?;
        Ok(r)
    }
}

/// An intermediate execution state, activation tensor, or feature map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntermediateArtifact {
    /// Pipeline stage name (e.g. `backbone.layer3`, `audio.spectrogram`).
    pub stage_name: String,
    /// Media or tensor content type.
    pub content_type: String,
    /// Content digest of the intermediate data.
    pub digest: ContentDigest,
    /// Tensor or feature map shape dimensions.
    pub shape: Vec<u64>,
    /// Byte size of the intermediate representation.
    pub byte_count: u64,
}

impl IntermediateArtifact {
    /// Validates the intermediate artifact invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.stage_name, MAX_H4_IDENTIFIER_LEN)
            || !valid_text(&self.content_type, MAX_H4_IDENTIFIER_LEN)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        if self.byte_count == 0 {
            return Err(ContractError::EvidenceRequired);
        }
        if self.shape.len() > 16 {
            return Err(ContractError::ArithmeticOverflow);
        }
        Ok(())
    }
}

impl CanonicalEncode for IntermediateArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let shape_len = match u32::try_from(self.shape.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        encoder.text(&self.stage_name);
        encoder.text(&self.content_type);
        encoder.digest(self.digest);
        encoder.u32(shape_len);
        for &dim in &self.shape {
            encoder.u64(dim);
        }
        encoder.u64(self.byte_count);
    }
}

impl CanonicalDecode for IntermediateArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let stage_name = decoder.text()?.to_owned();
        let content_type = decoder.text()?.to_owned();
        let digest = decoder.digest()?;
        let raw_shape_len = decoder.u32()?;
        let shape_len = usize::try_from(raw_shape_len)
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        if shape_len > 16 || shape_len > decoder.remaining() / 8 {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut shape = Vec::with_capacity(shape_len);
        for _ in 0..shape_len {
            shape.push(decoder.u64()?);
        }
        let byte_count = decoder.u64()?;
        let r = Self {
            stage_name,
            content_type,
            digest,
            shape,
            byte_count,
        };
        r.validate()?;
        Ok(r)
    }
}

/// An alternate foreign decoder, reference runtime, or comparison model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternateSystem {
    /// Identifier of the foreign or reference system (e.g. `oracle:ffmpeg-6.1`).
    pub system_id: String,
    /// Version string of the alternate system.
    pub version: String,
    /// Framework name (e.g. `ffmpeg`, `opencv`, `onnxruntime`).
    pub framework: String,
    /// Quarantine boundary receipt digest proving non-production execution.
    pub quarantine_digest: ContentDigest,
}

impl AlternateSystem {
    /// Validates the alternate system invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.system_id, MAX_H4_IDENTIFIER_LEN)
            || !valid_text(&self.version, MAX_H4_METADATA_LEN)
            || !valid_text(&self.framework, MAX_H4_METADATA_LEN)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.quarantine_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        Ok(())
    }
}

impl CanonicalEncode for AlternateSystem {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.system_id);
        encoder.text(&self.version);
        encoder.text(&self.framework);
        encoder.digest(self.quarantine_digest);
    }
}

impl CanonicalDecode for AlternateSystem {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let system_id = decoder.text()?.to_owned();
        let version = decoder.text()?.to_owned();
        let framework = decoder.text()?.to_owned();
        let quarantine_digest = decoder.digest()?;
        let r = Self {
            system_id,
            version,
            framework,
            quarantine_digest,
        };
        r.validate()?;
        Ok(r)
    }
}

/// Differential comparison metric against a laboratory oracle.
#[derive(Clone, Debug, PartialEq)]
pub struct OracleComparison {
    /// Unique comparison operation identifier.
    pub comparison_id: String,
    /// Reference system ID of the comparison oracle.
    pub oracle_id: String,
    /// Metric name (e.g. `max_absolute_error`, `psnr`, `ssim`, `iou`).
    pub metric_name: String,
    /// Observed discrepancy score between native and oracle output.
    pub discrepancy_score: f64,
    /// Maximum permissible tolerance threshold.
    pub tolerance_threshold: f64,
    /// Whether the discrepancy is within the permissible tolerance.
    pub within_tolerance: bool,
    /// Oracle release or environment version.
    pub oracle_version: String,
}

impl OracleComparison {
    /// Validates the oracle comparison invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.comparison_id, MAX_H4_IDENTIFIER_LEN)
            || !valid_text(&self.oracle_id, MAX_H4_IDENTIFIER_LEN)
            || !valid_text(&self.metric_name, MAX_H4_METADATA_LEN)
            || !valid_text(&self.oracle_version, MAX_H4_METADATA_LEN)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if !self.discrepancy_score.is_finite()
            || self.discrepancy_score < 0.0
            || !self.tolerance_threshold.is_finite()
            || self.tolerance_threshold < 0.0
        {
            return Err(ContractError::ArithmeticOverflow);
        }
        let expected_within = self.discrepancy_score <= self.tolerance_threshold;
        if self.within_tolerance != expected_within {
            return Err(ContractError::EventRevisionMalformed);
        }
        Ok(())
    }
}

impl CanonicalEncode for OracleComparison {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.comparison_id);
        encoder.text(&self.oracle_id);
        encoder.text(&self.metric_name);
        encoder.u64(self.discrepancy_score.to_bits());
        encoder.u64(self.tolerance_threshold.to_bits());
        encoder.bool(self.within_tolerance);
        encoder.text(&self.oracle_version);
    }
}

impl CanonicalDecode for OracleComparison {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let comparison_id = decoder.text()?.to_owned();
        let oracle_id = decoder.text()?.to_owned();
        let metric_name = decoder.text()?.to_owned();
        let discrepancy_score = f64::from_bits(decoder.u64()?);
        let tolerance_threshold = f64::from_bits(decoder.u64()?);
        let within_tolerance = decoder.bool()?;
        let oracle_version = decoder.text()?.to_owned();
        let r = Self {
            comparison_id,
            oracle_id,
            metric_name,
            discrepancy_score,
            tolerance_threshold,
            within_tolerance,
            oracle_version,
        };
        r.validate()?;
        Ok(r)
    }
}

/// Proof of non-production quarantine and process isolation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaboratoryQuarantine {
    /// Must be strictly `true`. Laboratory outputs are quarantined from production.
    pub quarantined_from_production: bool,
    /// Digest of the sealed laboratory execution receipt.
    pub quarantine_receipt_digest: ContentDigest,
    /// Name or descriptor of the isolation boundary (e.g. `sealed_process_container`).
    pub isolation_boundary: String,
    /// Content digest witnessing that the process tree was fully drained.
    pub process_drain_witness: ContentDigest,
}

impl LaboratoryQuarantine {
    /// Validates quarantine invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !self.quarantined_from_production {
            return Err(ContractError::DerivedLayerAuthorityForbidden);
        }
        if self.quarantine_receipt_digest.bytes().iter().all(|&b| b == 0)
            || self.process_drain_witness.bytes().iter().all(|&b| b == 0)
        {
            return Err(ContractError::InvalidDigest);
        }
        if !valid_text(&self.isolation_boundary, MAX_H4_IDENTIFIER_LEN) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }
}

impl CanonicalEncode for LaboratoryQuarantine {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bool(self.quarantined_from_production);
        encoder.digest(self.quarantine_receipt_digest);
        encoder.text(&self.isolation_boundary);
        encoder.digest(self.process_drain_witness);
    }
}

impl CanonicalDecode for LaboratoryQuarantine {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let quarantined_from_production = decoder.bool()?;
        let quarantine_receipt_digest = decoder.digest()?;
        let isolation_boundary = decoder.text()?.to_owned();
        let process_drain_witness = decoder.digest()?;
        let r = Self {
            quarantined_from_production,
            quarantine_receipt_digest,
            isolation_boundary,
            process_drain_witness,
        };
        r.validate()?;
        Ok(r)
    }
}

/// Parameters used to construct an [`H4LaboratoryExpansion`] descriptor directly.
#[derive(Clone, Debug, PartialEq)]
pub struct H4LaboratoryExpansionParams {
    /// Content-derived handle identifier.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Replay bundle reference for deterministic reproduction.
    pub replay_bundle: ReplayBundleRef,
    /// Intermediate execution states, tensor activations, or layer representations.
    pub intermediates: Vec<IntermediateArtifact>,
    /// Alternate non-production foreign decoders or models used as reference benchmarks.
    pub alternate_systems: Vec<AlternateSystem>,
    /// Differential comparison records against oracle outputs.
    pub oracle_comparisons: Vec<OracleComparison>,
    /// Laboratory quarantine and process drain verification record.
    pub quarantine: LaboratoryQuarantine,
    /// Laboratory access policy from the handle descriptor.
    pub laboratory_access: LaboratoryAccess,
    /// Purpose under which H4 material is accessed.
    pub purpose: HydrationPurpose,
    /// Authority anchor of this descriptor revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost to hydrate at H4.
    pub estimated_cost: BudgetVector,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Time after which this descriptor returns an expired state.
    pub retention_until: TimestampNs,
    /// Retained provenance roots plus subject digest.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness of this expansion at H4.
    pub completeness: Completeness,
}

/// Strongly typed representation of hydration ladder level H4: laboratory_expansion.
///
/// Encapsulates the content specified by normative row H4:
/// replay bundle, intermediates, alternate decoders/models, and oracle comparisons.
///
/// Under constitutional rules (DEP-CLASS-F4, INV-022), laboratory materials are strictly
/// quarantined from production runtime and release closures.
#[derive(Clone, Debug, PartialEq)]
pub struct H4LaboratoryExpansion {
    /// Content-derived handle identifier.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Replay bundle reference for deterministic reproduction.
    pub replay_bundle: ReplayBundleRef,
    /// Intermediate execution states, tensor activations, or layer representations.
    pub intermediates: Vec<IntermediateArtifact>,
    /// Alternate non-production foreign decoders or models used as reference benchmarks.
    pub alternate_systems: Vec<AlternateSystem>,
    /// Differential comparison records against oracle outputs.
    pub oracle_comparisons: Vec<OracleComparison>,
    /// Laboratory quarantine and process drain verification record.
    pub quarantine: LaboratoryQuarantine,
    /// Laboratory access policy from the handle descriptor.
    pub laboratory_access: LaboratoryAccess,
    /// Purpose under which H4 material is accessed.
    pub purpose: HydrationPurpose,
    /// Authority anchor of this descriptor revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost to hydrate at H4.
    pub estimated_cost: BudgetVector,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Time after which this descriptor returns an expired state.
    pub retention_until: TimestampNs,
    /// Retained provenance roots plus subject digest.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness of this expansion at H4.
    pub completeness: Completeness,
    /// Content digest of this complete expansion descriptor.
    pub expansion_digest: ContentDigest,
}

impl H4LaboratoryExpansion {
    /// Constructs an [`H4LaboratoryExpansion`] from strongly typed parameters and validates all invariants.
    pub fn new(params: H4LaboratoryExpansionParams) -> Result<Self, HydrationError> {
        let mut expansion = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            replay_bundle: params.replay_bundle,
            intermediates: params.intermediates,
            alternate_systems: params.alternate_systems,
            oracle_comparisons: params.oracle_comparisons,
            quarantine: params.quarantine,
            laboratory_access: params.laboratory_access,
            purpose: params.purpose,
            anchor: params.anchor,
            contract_basis: params.contract_basis,
            estimated_cost: params.estimated_cost,
            published_at: params.published_at,
            retention_until: params.retention_until,
            proof_roots: params.proof_roots,
            completeness: params.completeness,
            expansion_digest: ContentDigest::sha256(b"unpublished-h4-expansion"),
        };
        expansion.validate()?;
        expansion.expansion_digest = expansion.computed_digest();
        Ok(expansion)
    }

    /// Validates all normative, structural, security, and plane invariants for H4.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.handle_id, MAX_H4_IDENTIFIER_LEN)
            || !valid_text(&self.subject_id, MAX_H4_IDENTIFIER_LEN)
        {
            return Err(ContractError::InvalidIdentifier.into());
        }
        if self.subject_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest.into());
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::DerivedBeliefMissingAnchor.into());
        }
        if self.published_at >= self.retention_until {
            return Err(ContractError::InvertedTimeInterval.into());
        }
        if !self.estimated_cost.is_valid() {
            return Err(ContractError::ArithmeticOverflow.into());
        }

        // Validate quarantine: strictly non-production
        self.quarantine.validate()?;

        // Laboratory access gating:
        // Unavailable policy rejects access; Routine purpose is prohibited;
        // QualificationOnly requires Qualification purpose.
        match self.laboratory_access {
            LaboratoryAccess::Unavailable => {
                return Err(HydrationError::LaboratoryGrantRequired);
            }
            LaboratoryAccess::QualificationOnly => {
                if self.purpose != HydrationPurpose::Qualification {
                    return Err(HydrationError::LaboratoryGrantRequired);
                }
            }
            LaboratoryAccess::QualificationOrDebugGrant => {
                if self.purpose != HydrationPurpose::Qualification
                    && self.purpose != HydrationPurpose::Debugging
                {
                    return Err(HydrationError::LaboratoryGrantRequired);
                }
            }
        }

        // Validate replay bundle
        self.replay_bundle.validate()?;

        // Intermediates must be non-empty and bounded
        if self.intermediates.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }
        if self.intermediates.len() > MAX_H4_INTERMEDIATES {
            return Err(ContractError::ArithmeticOverflow.into());
        }
        for item in &self.intermediates {
            item.validate()?;
        }

        // Alternate systems must be non-empty and bounded
        if self.alternate_systems.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }
        if self.alternate_systems.len() > MAX_H4_ALTERNATE_SYSTEMS {
            return Err(ContractError::ArithmeticOverflow.into());
        }
        for item in &self.alternate_systems {
            item.validate()?;
        }

        // Oracle comparisons must be non-empty and bounded
        if self.oracle_comparisons.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }
        if self.oracle_comparisons.len() > MAX_H4_ORACLE_COMPARISONS {
            return Err(ContractError::ArithmeticOverflow.into());
        }
        for item in &self.oracle_comparisons {
            item.validate()?;
        }

        // Proof roots must contain subject_digest and at least one independent proof root
        if self.proof_roots.is_empty()
            || self.proof_roots.len() > MAX_H4_PROOF_ROOTS
            || !self.proof_roots.contains(&self.subject_digest)
            || !self.proof_roots.iter().any(|r| *r != self.subject_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }

        // Completeness must not be indeterminate or degraded
        if matches!(
            self.completeness,
            Completeness::Unknown
                | Completeness::NotObservable
                | Completeness::Unauthorized
                | Completeness::Stale
        ) {
            return Err(ContractError::EvidenceRequired.into());
        }

        Ok(())
    }

    /// Returns the exact hydration level (`HydrationLevel::H4`).
    #[must_use]
    pub const fn level(&self) -> HydrationLevel {
        HydrationLevel::H4
    }

    /// Constitutional hard gate: Laboratory expansion may NEVER claim authority.
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        false
    }

    /// Constitutional hard gate: Laboratory expansion may NEVER authorize effects.
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Constitutional rule: Laboratory material is quarantined and excluded from production.
    #[must_use]
    pub const fn is_production_safe(&self) -> bool {
        false
    }

    /// Returns whether this expansion is verifiably quarantined from production.
    #[must_use]
    pub const fn is_quarantined(&self) -> bool {
        self.quarantine.quarantined_from_production
    }

    /// Computes the deterministic canonical digest of this H4 expansion.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Encodes the body of this expansion (all fields except expansion_digest itself).
    fn encode_canonical_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(H4_SCHEMA);
        encoder.text(&self.handle_id);
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        self.replay_bundle.encode_canonical(encoder);

        let int_len = match u32::try_from(self.intermediates.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        encoder.u32(int_len);
        for item in &self.intermediates {
            item.encode_canonical(encoder);
        }

        let alt_len = match u32::try_from(self.alternate_systems.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        encoder.u32(alt_len);
        for item in &self.alternate_systems {
            item.encode_canonical(encoder);
        }

        let comp_len = match u32::try_from(self.oracle_comparisons.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        encoder.u32(comp_len);
        for item in &self.oracle_comparisons {
            item.encode_canonical(encoder);
        }

        self.quarantine.encode_canonical(encoder);
        self.laboratory_access.encode_canonical(encoder);
        self.purpose.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        self.contract_basis.encode_canonical(encoder);

        // BudgetVector encoded as 84 canonical bytes
        let mut cost_enc = CanonicalEncoder::new();
        self.estimated_cost.encode_to_canonical(&mut cost_enc);
        encoder.bytes(&cost_enc.finish());

        self.published_at.encode_canonical(encoder);
        self.retention_until.encode_canonical(encoder);

        let roots_len = match u32::try_from(self.proof_roots.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        encoder.u32(roots_len);
        for root in &self.proof_roots {
            encoder.digest(*root);
        }

        encoder.u8(completeness_code(self.completeness));
    }

    /// Packages this H4 laboratory expansion into a published [`HydrationArtifact`].
    pub fn to_hydration_artifact(&self) -> Result<HydrationArtifact, HydrationError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let payload = encoder.finish();
        HydrationArtifact::publish(
            HydrationLevel::H4,
            "application/vnd.fss.h4-laboratory-expansion+canonical",
            payload,
            self.proof_roots.clone(),
            self.completeness,
            Some("quarantined_laboratory_expansion".to_owned()),
        )
    }
}

impl CanonicalEncode for H4LaboratoryExpansion {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_canonical_body(encoder);
        encoder.digest(self.expansion_digest);
    }
}

impl CanonicalDecode for H4LaboratoryExpansion {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H4_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_owned();
        let subject_id = decoder.text()?.to_owned();
        let subject_digest = decoder.digest()?;
        let replay_bundle = ReplayBundleRef::decode_canonical(decoder)?;

        let raw_int_len = decoder.u32()?;
        let int_len = usize::try_from(raw_int_len)
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        if int_len > MAX_H4_INTERMEDIATES || int_len > decoder.remaining() / 16 {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut intermediates = Vec::with_capacity(int_len);
        for _ in 0..int_len {
            intermediates.push(IntermediateArtifact::decode_canonical(decoder)?);
        }

        let raw_alt_len = decoder.u32()?;
        let alt_len = usize::try_from(raw_alt_len)
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        if alt_len > MAX_H4_ALTERNATE_SYSTEMS || alt_len > decoder.remaining() / 20 {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut alternate_systems = Vec::with_capacity(alt_len);
        for _ in 0..alt_len {
            alternate_systems.push(AlternateSystem::decode_canonical(decoder)?);
        }

        let raw_comp_len = decoder.u32()?;
        let comp_len = usize::try_from(raw_comp_len)
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        if comp_len > MAX_H4_ORACLE_COMPARISONS || comp_len > decoder.remaining() / 20 {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut oracle_comparisons = Vec::with_capacity(comp_len);
        for _ in 0..comp_len {
            oracle_comparisons.push(OracleComparison::decode_canonical(decoder)?);
        }

        let quarantine = LaboratoryQuarantine::decode_canonical(decoder)?;
        let laboratory_access = LaboratoryAccess::decode_canonical(decoder)?;
        let purpose = HydrationPurpose::decode_canonical(decoder)?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let contract_basis = ContractBasis::decode_canonical(decoder)?;

        let cost_bytes = decoder.bytes()?;
        let estimated_cost = BudgetVector::decode_canonical(cost_bytes)
            .map_err(|_| ContractError::ArithmeticOverflow)?;

        let published_at = TimestampNs::decode_canonical(decoder)?;
        let retention_until = TimestampNs::decode_canonical(decoder)?;

        let raw_roots_len = decoder.u32()?;
        let roots_len = usize::try_from(raw_roots_len)
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        if roots_len > MAX_H4_PROOF_ROOTS || roots_len > decoder.remaining() / 33 {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut proof_roots = BTreeSet::new();
        for _ in 0..roots_len {
            proof_roots.insert(decoder.digest()?);
        }

        let completeness_raw = decoder.u8()?;
        let completeness = completeness_from_code(completeness_raw)?;

        let expansion_digest = decoder.digest()?;

        let expansion = Self {
            handle_id,
            subject_id,
            subject_digest,
            replay_bundle,
            intermediates,
            alternate_systems,
            oracle_comparisons,
            quarantine,
            laboratory_access,
            purpose,
            anchor,
            contract_basis,
            estimated_cost,
            published_at,
            retention_until,
            proof_roots,
            completeness,
            expansion_digest,
        };

        // Re-run validation to kill mutant R22 and enforce all invariants
        expansion.validate().map_err(|err| match err {
            HydrationError::Contract(contract_err) => contract_err,
            HydrationError::LaboratoryGrantRequired => ContractError::DerivedLayerAuthorityForbidden,
            _ => ContractError::EventRevisionMalformed,
        })?;

        // Verify content digest matches computed digest
        if expansion.computed_digest() != expansion_digest {
            return Err(ContractError::DigestMismatch);
        }

        Ok(expansion)
    }
}
