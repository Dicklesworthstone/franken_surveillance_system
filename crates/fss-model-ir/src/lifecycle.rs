#![forbid(unsafe_code)]
//! Deterministic model generation lifecycle: verification, qualification,
//! shadow evaluation, two-phase authorized activation, atomic reader
//! snapshots, rollback, quarantine, revocation, and canonical journal replay
//! (FSS-074 / `fss-x4a.14.5`).
//!
//! ## Architectural contracts
//!
//! - **Immutable generations (`INV-044`):** every registered model generation
//!   binds an explicit `ModelGeneration` identifier (the floating alias
//!   `"latest"` is refused unconditionally), exact package/IR/preprocess/
//!   calibration/license/device/kernel/numeric identities (`INV-045`), and
//!   monotonic `sequence_order`. Re-registering the exact same descriptor is
//!   idempotent; conflicting digests are refused; terminal tombstones
//!   (`Revoked`, `Retired`) can never be reused or renumbered.
//! - **Type-distinct cognitive vs. effect planes (`INV-002`):** verification,
//!   qualification, and shadow evaluation are observational and never grant
//!   activation authority. Activation, rollback, revocation, and retirement
//!   require an explicit [`EffectAuthority`] carrying the configured
//!   capability and a monotonic lease fence.
//! - **Atomic reader snapshots (`FORMAL-007`):** [`ModelLifecycleManager::reader_snapshot`]
//!   returns an immutable [`ActiveModelSnapshot`] pinned to one monotonic
//!   `activation_epoch`. Concurrent/in-flight readers keep observing their
//!   exact snapshot while newer activations or rollbacks atomically advance
//!   the head epoch.
//! - **Explicit two-phase effect and reconciliation (`INV-013`):**
//!   `prepare` -> `commit` (or `cancel` / `mark_indeterminate` ->
//!   `reconcile_indeterminate`) ensures no crash or lost acknowledgement
//!   silently activates or overwrites state.
//! - **Resource pressure and safety (`DOC-029`, `DOC-045`):** new activations
//!   honor [`MemoryAdmission`] against [`ResourcePressure`]; emergency
//!   rollback remains admissible even under `ResourcePressure::Critical` while
//!   still enforcing revocation and anti-rollback floor invariants.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::effect::EffectAuthority;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, Generation, ModelGeneration, OperationId, ResourcePressure,
    TimestampNs,
};

use crate::canonical::compute_model_ir_digest;
use crate::graph::ModelIrGraph;
use crate::invocation::{InvocationOutcome, ModelReceipt};
use crate::quotas::MemoryAdmission;

/// Hard upper bound on generations tracked by one lifecycle manager.
pub const MAX_GENERATIONS: usize = 256;
/// Hard upper bound on retained rollback entries.
pub const MAX_ROLLBACK_DEPTH: usize = 32;
/// Hard upper bound on shadow observations stored per generation.
pub const MAX_SHADOW_OBSERVATIONS: usize = 4_096;
/// Hard upper bound on canonical journal entries retained in memory.
pub const MAX_JOURNAL_ENTRIES: usize = 16_384;
/// Maximum UTF-8 byte length of a reason or note string.
pub const MAX_REASON_BYTES: usize = 512;
/// Maximum UTF-8 byte length of a profile/device/kernel/numeric label.
pub const MAX_LABEL_BYTES: usize = 128;
/// Denominator for parts-per-million rates (`1_000_000`).
pub const PPM_SCALE: u64 = 1_000_000;

/// Lifecycle stage of one immutable model generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModelGenerationStage {
    /// Registered from offline package metadata; not yet verified.
    Staged,
    /// Offline artifacts, IR graph digest, license, and use profile verified.
    Verified,
    /// Deterministic qualification suite passed with zero failures/quarantines.
    Qualified,
    /// Shadow evaluation active (observational only; never serves production).
    Shadowing,
    /// Currently serving production traffic at the head activation epoch.
    Active,
    /// Previously active generation retained immutably as a rollback target.
    RetainedRollback,
    /// Quarantined due to validation, runtime, or shadow fault; non-activatable.
    Quarantined,
    /// Terminally revoked (security/provenance/anti-rollback tombstone).
    Revoked,
    /// Terminally retired after rollback retention constraints are satisfied.
    Retired,
}

impl ModelGenerationStage {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Qualified => "qualified",
            Self::Shadowing => "shadowing",
            Self::Active => "active",
            Self::RetainedRollback => "retained_rollback",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
            Self::Retired => "retired",
        }
    }

    /// True iff this stage is a permanent tombstone.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Retired)
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Staged => 1,
            Self::Verified => 2,
            Self::Qualified => 3,
            Self::Shadowing => 4,
            Self::Active => 5,
            Self::RetainedRollback => 6,
            Self::Quarantined => 7,
            Self::Revoked => 8,
            Self::Retired => 9,
        }
    }

    const fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Qualified),
            4 => Ok(Self::Shadowing),
            5 => Ok(Self::Active),
            6 => Ok(Self::RetainedRollback),
            7 => Ok(Self::Quarantined),
            8 => Ok(Self::Revoked),
            9 => Ok(Self::Retired),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for ModelGenerationStage {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
    }
}

impl CanonicalDecode for ModelGenerationStage {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?)
    }
}

/// Lifecycle governance policy (explicit bounds, authority scopes, shadow gates,
/// rollback retention floor, and resource-pressure admission).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecyclePolicy {
    /// Capability required in [`EffectAuthority`] to activate a generation.
    pub required_activate_capability: String,
    /// Capability required in [`EffectAuthority`] to roll back to a prior generation.
    pub required_rollback_capability: String,
    /// Capability required in [`EffectAuthority`] to revoke a generation.
    pub required_revoke_capability: String,
    /// Capability required in [`EffectAuthority`] to retire a generation.
    pub required_retire_capability: String,
    /// Whether shadow evaluation must run before activation is permitted.
    pub require_shadow_before_activate: bool,
    /// Minimum shadow observations required when shadow evaluation is mandatory.
    pub min_shadow_samples: u64,
    /// Maximum allowed shadow divergence rate in parts-per-million (`0..=1_000_000`).
    pub max_shadow_divergence_ppm: u32,
    /// Maximum allowed shadow abstention rate in parts-per-million (`0..=1_000_000`).
    pub max_shadow_abstention_ppm: u32,
    /// Minimum number of retained rollback generations preserved before retirement is allowed.
    pub rollback_retention_floor: usize,
    /// Maximum retained rollback depth (clamped to [`MAX_ROLLBACK_DEPTH`]).
    pub max_rollback_depth: usize,
    /// Memory-pressure admission gate for new activations (rollbacks bypass pressure).
    pub activation_pressure_policy: MemoryAdmission,
    /// Automatically quarantine a shadowing candidate if any shadow receipt is `Quarantined`.
    pub auto_quarantine_on_shadow_quarantine: bool,
    /// Enforce monotonic anti-rollback floor on activations and rollbacks.
    pub enforce_anti_rollback_floor: bool,
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            required_activate_capability: "model:activate".to_owned(),
            required_rollback_capability: "model:rollback".to_owned(),
            required_revoke_capability: "model:revoke".to_owned(),
            required_retire_capability: "model:retire".to_owned(),
            require_shadow_before_activate: true,
            min_shadow_samples: 1,
            max_shadow_divergence_ppm: 0,
            max_shadow_abstention_ppm: 0,
            rollback_retention_floor: 1,
            max_rollback_depth: 8,
            activation_pressure_policy: MemoryAdmission::RefuseConstrained,
            auto_quarantine_on_shadow_quarantine: true,
            enforce_anti_rollback_floor: true,
        }
    }
}

impl LifecyclePolicy {
    /// Validates policy bounds and capability labels.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        for (field, val) in [
            (
                "required_activate_capability",
                self.required_activate_capability.as_str(),
            ),
            (
                "required_rollback_capability",
                self.required_rollback_capability.as_str(),
            ),
            (
                "required_revoke_capability",
                self.required_revoke_capability.as_str(),
            ),
            (
                "required_retire_capability",
                self.required_retire_capability.as_str(),
            ),
        ] {
            validate_label(field, val)?;
        }
        if self.max_shadow_divergence_ppm as u64 > PPM_SCALE
            || self.max_shadow_abstention_ppm as u64 > PPM_SCALE
        {
            return Err(LifecycleError::InvalidInput {
                field: "shadow_ppm_bound",
                detail: "parts-per-million bound must not exceed 1_000_000".to_owned(),
            });
        }
        if self.max_rollback_depth == 0 || self.max_rollback_depth > MAX_ROLLBACK_DEPTH {
            return Err(LifecycleError::InvalidInput {
                field: "max_rollback_depth",
                detail: format!("must be in 1..={MAX_ROLLBACK_DEPTH}"),
            });
        }
        if self.rollback_retention_floor > self.max_rollback_depth {
            return Err(LifecycleError::InvalidInput {
                field: "rollback_retention_floor",
                detail: "cannot exceed max_rollback_depth".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable descriptor binding a model generation to every provenance,
/// preprocess, calibration, license, device, kernel, and numeric identity
/// (`INV-044`, `INV-045`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelGenerationDescriptor {
    /// Explicit immutable model generation identifier (never `"latest"`).
    pub generation: ModelGeneration,
    /// Strictly positive monotonic version order (`>= 1`) used for anti-rollback floors.
    pub sequence_order: u64,
    /// Immutable offline model package root digest.
    pub model_root: ContentDigest,
    /// Canonical digest of the validated `ModelIrGraph`.
    pub ir_digest: ContentDigest,
    /// Generation pinned on the IR graph and input ports.
    pub ir_generation: Generation,
    /// Preprocessing pipeline generation.
    pub preprocess_generation: Generation,
    /// Optional calibration table generation.
    pub calibration_generation: Option<Generation>,
    /// Digest of the offline license policy & license artifact proof.
    pub license_policy_digest: ContentDigest,
    /// Operator use profile (e.g. `"owner_private_site"`).
    pub use_profile: String,
    /// Target accelerator/host device generation (`INV-045`).
    pub device_generation: String,
    /// Kernel family generation (`INV-045`).
    pub kernel_generation: String,
    /// Deterministic or tolerance-certified numeric contract identifier (`INV-045`).
    pub numeric_contract: String,
}

impl ModelGenerationDescriptor {
    /// Validates every field and enforces the anti-`"latest"` prohibition.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        validate_model_generation_id(&self.generation)?;
        if self.sequence_order == 0 {
            return Err(LifecycleError::InvalidInput {
                field: "sequence_order",
                detail: "must be >= 1".to_owned(),
            });
        }
        validate_digest("model_root", self.model_root)?;
        validate_digest("ir_digest", self.ir_digest)?;
        validate_digest("license_policy_digest", self.license_policy_digest)?;
        validate_label("use_profile", &self.use_profile)?;
        validate_label("device_generation", &self.device_generation)?;
        validate_label("kernel_generation", &self.kernel_generation)?;
        validate_label("numeric_contract", &self.numeric_contract)?;
        Ok(())
    }

    /// Canonical content digest over every field of this immutable descriptor.
    #[must_use]
    pub fn descriptor_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_lifecycle_descriptor.v1");
        self.encode_canonical(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }
}

impl CanonicalEncode for ModelGenerationDescriptor {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.generation.encode_canonical(encoder);
        encoder.u64(self.sequence_order);
        encoder.digest(self.model_root);
        encoder.digest(self.ir_digest);
        encoder.u64(self.ir_generation.get());
        encoder.u64(self.preprocess_generation.get());
        match self.calibration_generation {
            Some(cal) => {
                encoder.bool(true);
                encoder.u64(cal.get());
            }
            None => encoder.bool(false),
        }
        encoder.digest(self.license_policy_digest);
        encoder.text(&self.use_profile);
        encoder.text(&self.device_generation);
        encoder.text(&self.kernel_generation);
        encoder.text(&self.numeric_contract);
    }
}

impl CanonicalDecode for ModelGenerationDescriptor {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let generation = ModelGeneration::decode_canonical(decoder)?;
        let sequence_order = decoder.u64()?;
        let model_root = decoder.digest()?;
        let ir_digest = decoder.digest()?;
        let ir_generation = Generation::from_u64(decoder.u64()?);
        let preprocess_generation = Generation::from_u64(decoder.u64()?);
        let calibration_generation = if decoder.bool()? {
            Some(Generation::from_u64(decoder.u64()?))
        } else {
            None
        };
        let license_policy_digest = decoder.digest()?;
        let use_profile = decoder.text()?.to_owned();
        let device_generation = decoder.text()?.to_owned();
        let kernel_generation = decoder.text()?.to_owned();
        let numeric_contract = decoder.text()?.to_owned();
        let descriptor = Self {
            generation,
            sequence_order,
            model_root,
            ir_digest,
            ir_generation,
            preprocess_generation,
            calibration_generation,
            license_policy_digest,
            use_profile,
            device_generation,
            kernel_generation,
            numeric_contract,
        };
        descriptor
            .validate()
            .map_err(|_| ContractError::InvalidIdentifier)?;
        Ok(descriptor)
    }
}

/// Offline package, license, and use-profile verification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationEvidence {
    /// Digest proving offline artifact integrity and manifest verification.
    pub package_verification_digest: ContentDigest,
    /// True iff license policy admitted this model under `use_profile`.
    pub license_approved: bool,
    /// True iff use-profile constraints were verified.
    pub profile_approved: bool,
    /// True iff the package was verified completely offline (no network acquisition).
    pub offline_only_verified: bool,
}

impl VerificationEvidence {
    fn validate(&self) -> Result<(), LifecycleError> {
        validate_digest(
            "package_verification_digest",
            self.package_verification_digest,
        )
    }
}

impl CanonicalEncode for VerificationEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.package_verification_digest);
        encoder.bool(self.license_approved);
        encoder.bool(self.profile_approved);
        encoder.bool(self.offline_only_verified);
    }
}

impl CanonicalDecode for VerificationEvidence {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            package_verification_digest: decoder.digest()?,
            license_approved: decoder.bool()?,
            profile_approved: decoder.bool()?,
            offline_only_verified: decoder.bool()?,
        })
    }
}

/// Deterministic qualification suite results bound to a contract basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationReport {
    /// Digest of the deterministic qualification fixture suite & golden oracle.
    pub suite_digest: ContentDigest,
    /// Digest of the governing `ContractBasis` active during qualification.
    pub contract_basis_digest: ContentDigest,
    /// Number of qualification test cases passed.
    pub passed_cases: u64,
    /// Number of qualification test cases failed.
    pub failed_cases: u64,
    /// Number of qualification test cases that abstained.
    pub abstained_cases: u64,
    /// Number of qualification test cases that triggered quarantine.
    pub quarantined_cases: u64,
    /// Highest resource pressure observed during qualification.
    pub max_observed_pressure: ResourcePressure,
}

impl QualificationReport {
    fn validate(&self) -> Result<(), LifecycleError> {
        validate_digest("suite_digest", self.suite_digest)?;
        validate_digest("contract_basis_digest", self.contract_basis_digest)?;
        Ok(())
    }

    /// Canonical digest binding all fields of this qualification report.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_qualification_report.v1");
        self.encode_canonical(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }
}

impl CanonicalEncode for QualificationReport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.suite_digest);
        encoder.digest(self.contract_basis_digest);
        encoder.u64(self.passed_cases);
        encoder.u64(self.failed_cases);
        encoder.u64(self.abstained_cases);
        encoder.u64(self.quarantined_cases);
        encoder.u8(pressure_to_tag(self.max_observed_pressure));
    }
}

impl CanonicalDecode for QualificationReport {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            suite_digest: decoder.digest()?,
            contract_basis_digest: decoder.digest()?,
            passed_cases: decoder.u64()?,
            failed_cases: decoder.u64()?,
            abstained_cases: decoder.u64()?,
            quarantined_cases: decoder.u64()?,
            max_observed_pressure: pressure_from_tag(decoder.u8()?)?,
        })
    }
}

/// Observational receipt proving qualification completed.
/// Qualification is cognitive-only and NEVER grants activation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationReceipt {
    /// Qualified model generation.
    pub generation: ModelGeneration,
    /// Descriptor digest bound at qualification time.
    pub descriptor_digest: ContentDigest,
    /// Qualification report digest.
    pub report_digest: ContentDigest,
    /// Caller timestamp when qualification succeeded.
    pub qualified_at: TimestampNs,
    /// Explicitly false: qualification never confers effect authority.
    pub grants_activation_authority: bool,
    /// Canonical receipt digest.
    pub receipt_digest: ContentDigest,
}

/// Honest classification of one shadow evaluation run against an optional
/// active baseline. Uncertainty (`Abstained`, `Quarantined`, `BaselineUnavailable`)
/// is never flattened into `Matched`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowOutcome {
    /// Candidate completed and matched the baseline outputs (or no active baseline existed).
    Matched,
    /// Candidate and baseline both completed, but outputs diverged.
    Diverged {
        /// Digest of the candidate output tuple.
        candidate_outputs_digest: ContentDigest,
        /// Digest of the baseline output tuple.
        baseline_outputs_digest: ContentDigest,
    },
    /// Candidate completed, while baseline did not produce a completed output.
    BaselineUnavailable,
    /// Candidate abstained on an unbound operator.
    CandidateAbstained {
        /// Node that abstained.
        node_id: String,
        /// Stable op identifier.
        op: String,
    },
    /// Candidate quarantined during shadow evaluation.
    CandidateQuarantined {
        /// Machine-readable quarantine reason.
        reason: String,
    },
}

impl CanonicalEncode for ShadowOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Matched => encoder.u8(1),
            Self::Diverged {
                candidate_outputs_digest,
                baseline_outputs_digest,
            } => {
                encoder.u8(2);
                encoder.digest(*candidate_outputs_digest);
                encoder.digest(*baseline_outputs_digest);
            }
            Self::BaselineUnavailable => encoder.u8(3),
            Self::CandidateAbstained { node_id, op } => {
                encoder.u8(4);
                encoder.text(node_id);
                encoder.text(op);
            }
            Self::CandidateQuarantined { reason } => {
                encoder.u8(5);
                encoder.text(reason);
            }
        }
    }
}

impl CanonicalDecode for ShadowOutcome {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Matched),
            2 => Ok(Self::Diverged {
                candidate_outputs_digest: decoder.digest()?,
                baseline_outputs_digest: decoder.digest()?,
            }),
            3 => Ok(Self::BaselineUnavailable),
            4 => Ok(Self::CandidateAbstained {
                node_id: decoder.text()?.to_owned(),
                op: decoder.text()?.to_owned(),
            }),
            5 => Ok(Self::CandidateQuarantined {
                reason: decoder.text()?.to_owned(),
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Recorded shadow observation tying candidate receipt, baseline receipt, and
/// honest outcome together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowObservation {
    /// Candidate invocation idempotency key (`ModelReceipt::invocation`).
    pub candidate_invocation: ContentDigest,
    /// Optional baseline invocation idempotency key.
    pub baseline_invocation: Option<ContentDigest>,
    /// Honest classification of this shadow run.
    pub outcome: ShadowOutcome,
    /// Caller timestamp when observed.
    pub observed_at: TimestampNs,
}

impl CanonicalEncode for ShadowObservation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.candidate_invocation);
        match self.baseline_invocation {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(d);
            }
            None => encoder.bool(false),
        }
        self.outcome.encode_canonical(encoder);
        encoder.i128(self.observed_at.0);
    }
}

impl CanonicalDecode for ShadowObservation {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let candidate_invocation = decoder.digest()?;
        let baseline_invocation = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        let outcome = ShadowOutcome::decode_canonical(decoder)?;
        let observed_at = TimestampNs(decoder.i128()?);
        Ok(Self {
            candidate_invocation,
            baseline_invocation,
            outcome,
            observed_at,
        })
    }
}

/// Aggregated shadow evaluation counters for one generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShadowSummary {
    /// Total shadow runs recorded.
    pub total_runs: u64,
    /// Runs where candidate matched baseline (or ran cleanly without baseline).
    pub matched_runs: u64,
    /// Runs where candidate outputs diverged from baseline.
    pub diverged_runs: u64,
    /// Runs where candidate completed while baseline was unavailable.
    pub baseline_unavailable_runs: u64,
    /// Runs where candidate abstained.
    pub abstained_runs: u64,
    /// Runs where candidate quarantined.
    pub quarantined_runs: u64,
}

impl ShadowSummary {
    /// Divergence rate in parts-per-million (`0..=1_000_000`), ceiling-rounded
    /// so any non-zero divergence is never rounded down to `0`.
    #[must_use]
    pub const fn divergence_ppm(&self) -> u32 {
        ceil_ppm(self.diverged_runs, self.total_runs)
    }

    /// Abstention rate in parts-per-million (`0..=1_000_000`), ceiling-rounded.
    #[must_use]
    pub const fn abstention_ppm(&self) -> u32 {
        ceil_ppm(self.abstained_runs, self.total_runs)
    }

    fn record(&mut self, outcome: &ShadowOutcome) {
        self.total_runs = self.total_runs.saturating_add(1);
        match outcome {
            ShadowOutcome::Matched => {
                self.matched_runs = self.matched_runs.saturating_add(1);
            }
            ShadowOutcome::Diverged { .. } => {
                self.diverged_runs = self.diverged_runs.saturating_add(1);
            }
            ShadowOutcome::BaselineUnavailable => {
                self.baseline_unavailable_runs = self.baseline_unavailable_runs.saturating_add(1);
            }
            ShadowOutcome::CandidateAbstained { .. } => {
                self.abstained_runs = self.abstained_runs.saturating_add(1);
            }
            ShadowOutcome::CandidateQuarantined { .. } => {
                self.quarantined_runs = self.quarantined_runs.saturating_add(1);
            }
        }
    }
}

/// Decision-card-ready evidence view over a candidate's shadow readiness
/// (feeds downstream `FSS-148`). Strictly observational: never authorizes activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowDecisionEvidence {
    /// Candidate generation.
    pub generation: ModelGeneration,
    /// Current lifecycle stage.
    pub stage: ModelGenerationStage,
    /// Aggregated shadow counts.
    pub summary: ShadowSummary,
    /// Divergence rate in ppm (ceiling-rounded).
    pub divergence_ppm: u32,
    /// Abstention rate in ppm (ceiling-rounded).
    pub abstention_ppm: u32,
    /// Whether policy shadow gates are currently satisfied.
    pub shadow_gate_satisfied: bool,
    /// Concrete blocking reasons if not yet eligible for activation.
    pub blocking_reasons: Vec<String>,
    /// Explicitly false: evidence never grants effect authority.
    pub grants_activation_authority: bool,
}

/// Immutable point-in-time reader snapshot of the active model generation
/// (`FORMAL-007`). In-flight readers hold a clone of this snapshot and observe
/// a completely atomic, consistent generation even while a newer activation or
/// rollback advances the manager's head epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveModelSnapshot {
    /// Strictly monotone activation epoch (`>= 1`).
    pub activation_epoch: u64,
    /// Active immutable model generation descriptor.
    pub active: ModelGenerationDescriptor,
    /// Top retained rollback target at this epoch, if any.
    pub rollback_target: Option<ModelGeneration>,
    /// Caller timestamp when this epoch became active.
    pub activated_at: TimestampNs,
    /// Contract basis digest bound to this activation.
    pub contract_basis_digest: ContentDigest,
    /// Principal that authorized this epoch.
    pub authority_principal: String,
    /// Canonical digest over every field of this snapshot.
    pub snapshot_digest: ContentDigest,
}

impl ActiveModelSnapshot {
    fn compute_digest(
        activation_epoch: u64,
        active: &ModelGenerationDescriptor,
        rollback_target: Option<&ModelGeneration>,
        activated_at: TimestampNs,
        contract_basis_digest: ContentDigest,
        authority_principal: &str,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_active_snapshot.v1");
        enc.u64(activation_epoch);
        active.encode_canonical(&mut enc);
        match rollback_target {
            Some(rb) => {
                enc.bool(true);
                rb.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        enc.i128(activated_at.0);
        enc.digest(contract_basis_digest);
        enc.text(authority_principal);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Kind of authority-bearing head transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    /// Activate a qualified (and shadow-gated) candidate generation.
    Activate,
    /// Roll back to a retained non-revoked, non-quarantined prior generation.
    Rollback,
}

impl TransitionKind {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Rollback => "rollback",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Activate => 1,
            Self::Rollback => 2,
        }
    }

    const fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Activate),
            2 => Ok(Self::Rollback),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for TransitionKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
    }
}

impl CanonicalDecode for TransitionKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?)
    }
}

/// State of an in-flight prepared activation or rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingTransitionState {
    /// Prepared and validated; awaiting explicit `commit` or `cancel`.
    Prepared,
    /// Commit outcome is uncertain (e.g. crash/lost-ACK at commit boundary);
    /// blocks new transitions until explicitly reconciled.
    Indeterminate {
        /// Recorded non-empty reason for indeterminacy.
        reason: String,
        /// Caller timestamp when marked indeterminate.
        recorded_at: TimestampNs,
    },
}

/// Prepared, digest-bound activation or rollback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedTransition {
    /// Stable owner operation identifier.
    pub operation_id: OperationId,
    /// Whether this transition activates a candidate or rolls back.
    pub kind: TransitionKind,
    /// Exact target generation bound at prepare time.
    pub target_generation: ModelGeneration,
    /// Active generation observed at prepare time (if any).
    pub previous_active: Option<ModelGeneration>,
    /// Head activation epoch observed at prepare time (`0` before first activation).
    pub expected_epoch: u64,
    /// Governing contract basis digest bound to this transition.
    pub contract_basis_digest: ContentDigest,
    /// Explicit effect authority that authorized preparation.
    pub authority: EffectAuthority,
    /// Caller timestamp when prepared.
    pub prepared_at: TimestampNs,
    /// Current state (`Prepared` or `Indeterminate`).
    pub state: PendingTransitionState,
    /// Canonical digest binding every field of the prepared plan.
    pub plan_digest: ContentDigest,
}

impl PreparedTransition {
    #[allow(clippy::too_many_arguments)]
    fn compute_plan_digest(
        operation_id: &OperationId,
        kind: TransitionKind,
        target_generation: &ModelGeneration,
        previous_active: Option<&ModelGeneration>,
        expected_epoch: u64,
        contract_basis_digest: ContentDigest,
        authority: &EffectAuthority,
        prepared_at: TimestampNs,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_prepared_transition.v1");
        enc.text(operation_id.as_str());
        kind.encode_canonical(&mut enc);
        target_generation.encode_canonical(&mut enc);
        match previous_active {
            Some(prev) => {
                enc.bool(true);
                prev.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        enc.u64(expected_epoch);
        enc.digest(contract_basis_digest);
        authority.encode_canonical(&mut enc);
        enc.i128(prepared_at.0);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Request to prepare an activation or rollback effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionRequest {
    /// Owner operation identifier.
    pub operation_id: OperationId,
    /// Target generation to activate or roll back to.
    pub target_generation: ModelGeneration,
    /// Governing `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Explicit effect authority with capability and optional monotonic lease fence.
    pub authority: EffectAuthority,
}

/// Receipt proving an activation or rollback committed atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    /// Bound operation identifier.
    pub operation_id: OperationId,
    /// Kind of transition (`Activate` or `Rollback`).
    pub kind: TransitionKind,
    /// Plan digest from the prepared transition.
    pub plan_digest: ContentDigest,
    /// Newly active immutable snapshot (`FORMAL-007`).
    pub snapshot: ActiveModelSnapshot,
    /// Displaced active generation (moved to `RetainedRollback` if healthy).
    pub previous_active: Option<ModelGeneration>,
    /// Caller timestamp when committed.
    pub committed_at: TimestampNs,
    /// Canonical digest over every field of this receipt.
    pub receipt_digest: ContentDigest,
}

/// Conclusive external observation used to resolve an `Indeterminate` transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationObservation {
    /// External/durable evidence proved the exact prepared transition took effect.
    ConfirmedCommitted {
        /// Non-zero digest of the confirming evidence artifact.
        evidence_digest: ContentDigest,
    },
    /// External/durable evidence proved the prepared transition never took effect.
    ConfirmedNotCommitted {
        /// Non-zero digest of the confirming evidence artifact.
        evidence_digest: ContentDigest,
    },
}

impl CanonicalEncode for ReconciliationObservation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::ConfirmedCommitted { evidence_digest } => {
                encoder.u8(1);
                encoder.digest(*evidence_digest);
            }
            Self::ConfirmedNotCommitted { evidence_digest } => {
                encoder.u8(2);
                encoder.digest(*evidence_digest);
            }
        }
    }
}

impl CanonicalDecode for ReconciliationObservation {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::ConfirmedCommitted {
                evidence_digest: decoder.digest()?,
            }),
            2 => Ok(Self::ConfirmedNotCommitted {
                evidence_digest: decoder.digest()?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Receipt proving an indeterminate transition was resolved conclusively.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationReceipt {
    /// Plan digest that was reconciled.
    pub plan_digest: ContentDigest,
    /// Resulting transition receipt if `ConfirmedCommitted`, else `None`.
    pub committed: Option<TransitionReceipt>,
    /// Caller timestamp when reconciled.
    pub reconciled_at: TimestampNs,
}

/// Stored record for one registered model generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationRecord {
    /// Immutable generation descriptor.
    pub descriptor: ModelGenerationDescriptor,
    /// Current lifecycle stage.
    pub stage: ModelGenerationStage,
    /// Timestamp when staged.
    pub staged_at: TimestampNs,
    /// Offline verification proof, once verified.
    pub verification: Option<VerificationEvidence>,
    /// Qualification report, once qualified.
    pub qualification: Option<QualificationReport>,
    /// Aggregated shadow summary.
    pub shadow_summary: ShadowSummary,
    /// Bounded shadow observations.
    pub shadow_observations: Vec<ShadowObservation>,
    /// Last quarantine or revocation reason, if any.
    pub terminal_or_quarantine_reason: Option<String>,
}

/// Bounded operation-cost accounting counters for lifecycle work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LifecycleMetrics {
    /// Total generation registrations accepted.
    pub staged: u64,
    /// Total offline verifications completed.
    pub verified: u64,
    /// Total qualifications completed.
    pub qualified: u64,
    /// Total shadow runs recorded.
    pub shadow_runs: u64,
    /// Total activations committed.
    pub activations: u64,
    /// Total rollbacks committed.
    pub rollbacks: u64,
    /// Total prepared transitions cancelled cleanly.
    pub cancellations: u64,
    /// Total indeterminate transitions recorded.
    pub indeterminates: u64,
    /// Total quarantines recorded.
    pub quarantines: u64,
    /// Total revocations recorded.
    pub revocations: u64,
    /// Total retirements recorded.
    pub retirements: u64,
    /// Total typed refusals emitted.
    pub refusals: u64,
}

/// Canonical event recorded in the append-only lifecycle journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleJournalEvent {
    /// Generation registered in `Staged`.
    Staged {
        /// Immutable descriptor.
        descriptor: ModelGenerationDescriptor,
    },
    /// Offline verification completed (`Staged -> Verified`).
    Verified {
        /// Generation verified.
        generation: ModelGeneration,
        /// Verification proof.
        evidence: VerificationEvidence,
    },
    /// Qualification succeeded (`Verified -> Qualified`).
    Qualified {
        /// Generation qualified.
        generation: ModelGeneration,
        /// Qualification report.
        report: QualificationReport,
    },
    /// Shadow evaluation started (`Qualified -> Shadowing`).
    ShadowStarted {
        /// Generation entering shadow mode.
        generation: ModelGeneration,
    },
    /// Shadow observation appended.
    ShadowObserved {
        /// Generation under shadow evaluation.
        generation: ModelGeneration,
        /// Recorded shadow observation.
        observation: ShadowObservation,
    },
    /// Activation or rollback prepared (phase 1).
    TransitionPrepared {
        /// Bound operation ID.
        operation_id: OperationId,
        /// Activate or Rollback.
        kind: TransitionKind,
        /// Target generation.
        target_generation: ModelGeneration,
        /// Active generation at prepare time.
        previous_active: Option<ModelGeneration>,
        /// Head epoch at prepare time.
        expected_epoch: u64,
        /// Contract basis digest.
        contract_basis_digest: ContentDigest,
        /// Effect authority.
        authority: EffectAuthority,
        /// Prepared plan digest.
        plan_digest: ContentDigest,
    },
    /// Prepared transition cancelled cleanly before commit.
    TransitionCancelled {
        /// Cancelled plan digest.
        plan_digest: ContentDigest,
    },
    /// Prepared transition entered `Indeterminate` after ambiguous commit.
    TransitionIndeterminate {
        /// Ambiguous plan digest.
        plan_digest: ContentDigest,
        /// Recorded non-empty reason.
        reason: String,
    },
    /// Transition committed atomically (phase 2 or confirmed reconciliation).
    TransitionCommitted {
        /// Committed plan digest.
        plan_digest: ContentDigest,
        /// New activation epoch.
        new_epoch: u64,
    },
    /// Indeterminate transition confirmed not committed and cleared.
    TransitionReconciledNotCommitted {
        /// Cleared plan digest.
        plan_digest: ContentDigest,
        /// Confirming evidence digest.
        evidence_digest: ContentDigest,
    },
    /// Generation quarantined (fail-closed if active).
    Quarantined {
        /// Quarantined generation.
        generation: ModelGeneration,
        /// Recorded reason.
        reason: String,
    },
    /// Generation terminally revoked (and optional anti-rollback floor bump).
    Revoked {
        /// Revoked generation.
        generation: ModelGeneration,
        /// Authorizing effect authority.
        authority: EffectAuthority,
        /// Recorded reason.
        reason: String,
        /// Updated minimum allowed `sequence_order`.
        new_min_sequence_order: u64,
    },
    /// Generation terminally retired.
    Retired {
        /// Retired generation.
        generation: ModelGeneration,
        /// Authorizing effect authority.
        authority: EffectAuthority,
    },
}

impl CanonicalEncode for LifecycleJournalEvent {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Staged { descriptor } => {
                encoder.u8(1);
                descriptor.encode_canonical(encoder);
            }
            Self::Verified {
                generation,
                evidence,
            } => {
                encoder.u8(2);
                generation.encode_canonical(encoder);
                evidence.encode_canonical(encoder);
            }
            Self::Qualified { generation, report } => {
                encoder.u8(3);
                generation.encode_canonical(encoder);
                report.encode_canonical(encoder);
            }
            Self::ShadowStarted { generation } => {
                encoder.u8(4);
                generation.encode_canonical(encoder);
            }
            Self::ShadowObserved {
                generation,
                observation,
            } => {
                encoder.u8(5);
                generation.encode_canonical(encoder);
                observation.encode_canonical(encoder);
            }
            Self::TransitionPrepared {
                operation_id,
                kind,
                target_generation,
                previous_active,
                expected_epoch,
                contract_basis_digest,
                authority,
                plan_digest,
            } => {
                encoder.u8(6);
                encoder.text(operation_id.as_str());
                kind.encode_canonical(encoder);
                target_generation.encode_canonical(encoder);
                match previous_active {
                    Some(prev) => {
                        encoder.bool(true);
                        prev.encode_canonical(encoder);
                    }
                    None => encoder.bool(false),
                }
                encoder.u64(*expected_epoch);
                encoder.digest(*contract_basis_digest);
                authority.encode_canonical(encoder);
                encoder.digest(*plan_digest);
            }
            Self::TransitionCancelled { plan_digest } => {
                encoder.u8(7);
                encoder.digest(*plan_digest);
            }
            Self::TransitionIndeterminate {
                plan_digest,
                reason,
            } => {
                encoder.u8(8);
                encoder.digest(*plan_digest);
                encoder.text(reason);
            }
            Self::TransitionCommitted {
                plan_digest,
                new_epoch,
            } => {
                encoder.u8(9);
                encoder.digest(*plan_digest);
                encoder.u64(*new_epoch);
            }
            Self::TransitionReconciledNotCommitted {
                plan_digest,
                evidence_digest,
            } => {
                encoder.u8(10);
                encoder.digest(*plan_digest);
                encoder.digest(*evidence_digest);
            }
            Self::Quarantined { generation, reason } => {
                encoder.u8(11);
                generation.encode_canonical(encoder);
                encoder.text(reason);
            }
            Self::Revoked {
                generation,
                authority,
                reason,
                new_min_sequence_order,
            } => {
                encoder.u8(12);
                generation.encode_canonical(encoder);
                authority.encode_canonical(encoder);
                encoder.text(reason);
                encoder.u64(*new_min_sequence_order);
            }
            Self::Retired {
                generation,
                authority,
            } => {
                encoder.u8(13);
                generation.encode_canonical(encoder);
                authority.encode_canonical(encoder);
            }
        }
    }
}

impl CanonicalDecode for LifecycleJournalEvent {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Staged {
                descriptor: ModelGenerationDescriptor::decode_canonical(decoder)?,
            }),
            2 => Ok(Self::Verified {
                generation: ModelGeneration::decode_canonical(decoder)?,
                evidence: VerificationEvidence::decode_canonical(decoder)?,
            }),
            3 => Ok(Self::Qualified {
                generation: ModelGeneration::decode_canonical(decoder)?,
                report: QualificationReport::decode_canonical(decoder)?,
            }),
            4 => Ok(Self::ShadowStarted {
                generation: ModelGeneration::decode_canonical(decoder)?,
            }),
            5 => Ok(Self::ShadowObserved {
                generation: ModelGeneration::decode_canonical(decoder)?,
                observation: ShadowObservation::decode_canonical(decoder)?,
            }),
            6 => {
                let operation_id = OperationId::parse(decoder.text()?)?;
                let kind = TransitionKind::decode_canonical(decoder)?;
                let target_generation = ModelGeneration::decode_canonical(decoder)?;
                let previous_active = if decoder.bool()? {
                    Some(ModelGeneration::decode_canonical(decoder)?)
                } else {
                    None
                };
                let expected_epoch = decoder.u64()?;
                let contract_basis_digest = decoder.digest()?;
                let authority = EffectAuthority::decode_canonical(decoder)?;
                let plan_digest = decoder.digest()?;
                Ok(Self::TransitionPrepared {
                    operation_id,
                    kind,
                    target_generation,
                    previous_active,
                    expected_epoch,
                    contract_basis_digest,
                    authority,
                    plan_digest,
                })
            }
            7 => Ok(Self::TransitionCancelled {
                plan_digest: decoder.digest()?,
            }),
            8 => Ok(Self::TransitionIndeterminate {
                plan_digest: decoder.digest()?,
                reason: decoder.text()?.to_owned(),
            }),
            9 => Ok(Self::TransitionCommitted {
                plan_digest: decoder.digest()?,
                new_epoch: decoder.u64()?,
            }),
            10 => Ok(Self::TransitionReconciledNotCommitted {
                plan_digest: decoder.digest()?,
                evidence_digest: decoder.digest()?,
            }),
            11 => Ok(Self::Quarantined {
                generation: ModelGeneration::decode_canonical(decoder)?,
                reason: decoder.text()?.to_owned(),
            }),
            12 => Ok(Self::Revoked {
                generation: ModelGeneration::decode_canonical(decoder)?,
                authority: EffectAuthority::decode_canonical(decoder)?,
                reason: decoder.text()?.to_owned(),
                new_min_sequence_order: decoder.u64()?,
            }),
            13 => Ok(Self::Retired {
                generation: ModelGeneration::decode_canonical(decoder)?,
                authority: EffectAuthority::decode_canonical(decoder)?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One hash-chained, sequence-numbered canonical lifecycle journal entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleJournalEntry {
    /// One-based strictly monotonic sequence number.
    pub sequence: u64,
    /// Digest of the immediately preceding journal entry (zero digest for sequence 1).
    pub prev_digest: ContentDigest,
    /// Caller timestamp when this entry was recorded.
    pub recorded_at: TimestampNs,
    /// Canonical lifecycle event payload.
    pub event: LifecycleJournalEvent,
    /// Canonical hash binding `(sequence, prev_digest, recorded_at, event)`.
    pub entry_digest: ContentDigest,
}

impl LifecycleJournalEntry {
    fn compute_digest(
        sequence: u64,
        prev_digest: ContentDigest,
        recorded_at: TimestampNs,
        event: &LifecycleJournalEvent,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_lifecycle_journal_entry.v1");
        enc.u64(sequence);
        enc.digest(prev_digest);
        enc.i128(recorded_at.0);
        event.encode_canonical(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }

    /// Encodes this entry into canonical binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, LifecycleError> {
        let mut enc = CanonicalEncoder::new();
        self.encode_canonical(&mut enc);
        enc.finish_checked()
            .map_err(|e| LifecycleError::JournalCorrupt {
                detail: format!("canonical encode failed: {e}"),
            })
    }

    /// Decodes and verifies the entry digest from canonical binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LifecycleError> {
        let mut dec = CanonicalDecoder::new(bytes);
        let entry =
            Self::decode_canonical(&mut dec).map_err(|e| LifecycleError::JournalCorrupt {
                detail: format!("canonical decode failed: {e}"),
            })?;
        dec.ensure_finished()
            .map_err(|e| LifecycleError::JournalCorrupt {
                detail: format!("trailing canonical bytes: {e}"),
            })?;
        let recomputed = Self::compute_digest(
            entry.sequence,
            entry.prev_digest,
            entry.recorded_at,
            &entry.event,
        );
        if recomputed != entry.entry_digest {
            return Err(LifecycleError::JournalCorrupt {
                detail: format!(
                    "entry {} digest mismatch: expected {}, observed {}",
                    entry.sequence, entry.entry_digest, recomputed
                ),
            });
        }
        Ok(entry)
    }
}

impl CanonicalEncode for LifecycleJournalEntry {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.sequence);
        encoder.digest(self.prev_digest);
        encoder.i128(self.recorded_at.0);
        self.event.encode_canonical(encoder);
        encoder.digest(self.entry_digest);
    }
}

impl CanonicalDecode for LifecycleJournalEntry {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let sequence = decoder.u64()?;
        let prev_digest = decoder.digest()?;
        let recorded_at = TimestampNs(decoder.i128()?);
        let event = LifecycleJournalEvent::decode_canonical(decoder)?;
        let entry_digest = decoder.digest()?;
        Ok(Self {
            sequence,
            prev_digest,
            recorded_at,
            event,
            entry_digest,
        })
    }
}

/// Typed, machine-actionable lifecycle refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// Floating `"latest"` alias is strictly forbidden (`INV-044`).
    ForbiddenLatestAlias {
        /// The rejected generation string.
        raw: String,
    },
    /// Invalid field value or bound violation.
    InvalidInput {
        /// Field name.
        field: &'static str,
        /// Machine-readable detail.
        detail: String,
    },
    /// Caller timestamp regressed below the manager's last observed timestamp.
    ClockRegression {
        /// Previous observed timestamp.
        previous: TimestampNs,
        /// Supplied regressed timestamp.
        observed: TimestampNs,
    },
    /// Generation identifier already registered with conflicting immutable digests.
    GenerationConflict {
        /// Conflicting generation.
        generation: ModelGeneration,
    },
    /// Referenced generation is unknown to this lifecycle manager.
    UnknownGeneration {
        /// Missing generation.
        generation: ModelGeneration,
    },
    /// Generation is in a stage that prohibits the requested operation.
    InvalidStage {
        /// Target generation.
        generation: ModelGeneration,
        /// Current stage.
        current: ModelGenerationStage,
        /// Requested action.
        action: &'static str,
    },
    /// Offline verification failed (IR digest mismatch, invalid graph, unapproved license/profile, or online claim).
    VerificationFailed {
        /// Target generation.
        generation: ModelGeneration,
        /// Failure cause.
        reason: String,
    },
    /// Qualification report failed, abstained, or quarantined.
    QualificationFailed {
        /// Target generation.
        generation: ModelGeneration,
        /// Failure cause.
        reason: String,
    },
    /// Shadow evaluation gate not satisfied before activation.
    ShadowGateNotMet {
        /// Target generation.
        generation: ModelGeneration,
        /// Exact unmet gate details.
        reasons: Vec<String>,
    },
    /// Receipt supplied to shadow recording does not match this generation's IR identity.
    StaleGenerationReceipt {
        /// Target generation.
        generation: ModelGeneration,
        /// Expected IR digest.
        expected_ir_digest: ContentDigest,
        /// Observed receipt IR digest.
        observed_ir_digest: ContentDigest,
    },
    /// Missing/invalid effect authority, wrong capability, or regressed lease fence.
    AuthorityRefused {
        /// Refusal detail.
        detail: String,
    },
    /// Memory pressure refused new activation (`DOC-029`).
    PressureRefused {
        /// Target generation.
        generation: ModelGeneration,
        /// Observed resource pressure.
        pressure: ResourcePressure,
    },
    /// Anti-rollback floor refused activating or rolling back to an older version (`DOC-045`).
    AntiRollbackRefused {
        /// Target generation.
        generation: ModelGeneration,
        /// Candidate sequence order.
        candidate_order: u64,
        /// Enforced minimum allowed sequence order.
        minimum_order: u64,
    },
    /// Operation cancelled cleanly at a request -> drain -> finalize checkpoint.
    Cancelled {
        /// Cancelled operation name.
        action: &'static str,
    },
    /// An in-flight `Prepared` or `Indeterminate` transition blocks conflicting mutations.
    PendingTransitionActive {
        /// Active plan digest.
        plan_digest: ContentDigest,
        /// True if the pending transition is `Indeterminate` and requires reconciliation.
        indeterminate: bool,
    },
    /// Commit/cancel/reconcile referenced an unknown or mismatched plan digest or stale epoch.
    TransitionMismatch {
        /// Refusal detail.
        detail: String,
    },
    /// No eligible retained rollback generation is available.
    NoRollbackTarget {
        /// Detail explaining why rollback is unavailable.
        detail: String,
    },
    /// Retirement refused because generation is active, pending, or needed for rollback retention floor.
    RetirementBlocked {
        /// Target generation.
        generation: ModelGeneration,
        /// Refusal reason.
        reason: String,
    },
    /// Capacity bound reached (`MAX_GENERATIONS`, `MAX_SHADOW_OBSERVATIONS`, `MAX_JOURNAL_ENTRIES`).
    CapacityExceeded {
        /// Exhausted bound name.
        bound: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// Journal replay detected sequence gap, hash-chain break, or illegal transition.
    JournalCorrupt {
        /// Corruption detail.
        detail: String,
    },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenLatestAlias { raw } => {
                write!(f, "floating 'latest' model alias is forbidden: '{raw}'")
            }
            Self::InvalidInput { field, detail } => write!(f, "invalid {field}: {detail}"),
            Self::ClockRegression { previous, observed } => write!(
                f,
                "clock regression: observed {} < previous {}",
                observed.0, previous.0
            ),
            Self::GenerationConflict { generation } => {
                write!(f, "conflicting immutable descriptor for '{generation}'")
            }
            Self::UnknownGeneration { generation } => {
                write!(f, "unknown generation '{generation}'")
            }
            Self::InvalidStage {
                generation,
                current,
                action,
            } => write!(
                f,
                "generation '{generation}' in stage '{}' cannot perform '{action}'",
                current.as_str()
            ),
            Self::VerificationFailed { generation, reason } => {
                write!(f, "verification refused for '{generation}': {reason}")
            }
            Self::QualificationFailed { generation, reason } => {
                write!(f, "qualification refused for '{generation}': {reason}")
            }
            Self::ShadowGateNotMet {
                generation,
                reasons,
            } => write!(
                f,
                "shadow gate not met for '{generation}': {}",
                reasons.join("; ")
            ),
            Self::StaleGenerationReceipt {
                generation,
                expected_ir_digest,
                observed_ir_digest,
            } => write!(
                f,
                "stale receipt for '{generation}': expected IR {expected_ir_digest}, observed {observed_ir_digest}"
            ),
            Self::AuthorityRefused { detail } => write!(f, "authority refused: {detail}"),
            Self::PressureRefused {
                generation,
                pressure,
            } => write!(
                f,
                "resource pressure '{}' refused activation of '{generation}'",
                pressure.as_str()
            ),
            Self::AntiRollbackRefused {
                generation,
                candidate_order,
                minimum_order,
            } => write!(
                f,
                "anti-rollback floor refused '{generation}' (order {candidate_order} < min {minimum_order})"
            ),
            Self::Cancelled { action } => {
                write!(f, "lifecycle action '{action}' cancelled cleanly")
            }
            Self::PendingTransitionActive {
                plan_digest,
                indeterminate,
            } => write!(
                f,
                "pending transition {plan_digest} blocks mutation (indeterminate={indeterminate})"
            ),
            Self::TransitionMismatch { detail } => write!(f, "transition mismatch: {detail}"),
            Self::NoRollbackTarget { detail } => write!(f, "no rollback target: {detail}"),
            Self::RetirementBlocked { generation, reason } => {
                write!(f, "retirement blocked for '{generation}': {reason}")
            }
            Self::CapacityExceeded { bound, limit } => {
                write!(f, "lifecycle bound '{bound}' exceeded (max {limit})")
            }
            Self::JournalCorrupt { detail } => write!(f, "lifecycle journal corrupt: {detail}"),
        }
    }
}

impl Error for LifecycleError {}

/// Deterministic, replayable state machine owning model verification,
/// qualification, shadow evaluation, authorized two-phase activation,
/// atomic reader snapshots (`FORMAL-007`), rollback, quarantine, revocation,
/// and retirement.
#[derive(Clone, Debug)]
pub struct ModelLifecycleManager {
    policy: LifecyclePolicy,
    generations: BTreeMap<ModelGeneration, GenerationRecord>,
    active_snapshot: Option<ActiveModelSnapshot>,
    activation_epoch: u64,
    rollback_stack: Vec<ModelGeneration>,
    pending_transition: Option<PreparedTransition>,
    min_allowed_sequence_order: u64,
    highest_lease_fence: u64,
    last_timestamp: Option<TimestampNs>,
    journal: Vec<LifecycleJournalEntry>,
    metrics: LifecycleMetrics,
}

impl ModelLifecycleManager {
    /// Creates an empty lifecycle manager enforcing `policy`.
    pub fn new(policy: LifecyclePolicy) -> Result<Self, LifecycleError> {
        policy.validate()?;
        Ok(Self {
            policy,
            generations: BTreeMap::new(),
            active_snapshot: None,
            activation_epoch: 0,
            rollback_stack: Vec::new(),
            pending_transition: None,
            min_allowed_sequence_order: 1,
            highest_lease_fence: 0,
            last_timestamp: None,
            journal: Vec::new(),
            metrics: LifecycleMetrics::default(),
        })
    }

    /// Governing policy.
    #[must_use]
    pub const fn policy(&self) -> &LifecyclePolicy {
        &self.policy
    }

    /// Bounded operation metrics.
    #[must_use]
    pub const fn metrics(&self) -> LifecycleMetrics {
        self.metrics
    }

    /// Monotonic head activation epoch (`0` before first activation).
    #[must_use]
    pub const fn activation_epoch(&self) -> u64 {
        self.activation_epoch
    }

    /// Current anti-rollback minimum sequence order floor.
    #[must_use]
    pub const fn min_allowed_sequence_order(&self) -> u64 {
        self.min_allowed_sequence_order
    }

    /// Returns an immutable, atomic point-in-time snapshot of the active model
    /// generation (`FORMAL-007`), or `None` when no generation is active
    /// (including fail-closed state after active quarantine or revocation).
    #[must_use]
    pub fn reader_snapshot(&self) -> Option<ActiveModelSnapshot> {
        self.active_snapshot.clone()
    }

    /// True iff `snapshot` still matches the manager's current head activation epoch
    /// and canonical snapshot digest.
    #[must_use]
    pub fn is_snapshot_current(&self, snapshot: &ActiveModelSnapshot) -> bool {
        self.active_snapshot.as_ref().is_some_and(|head| {
            head.activation_epoch == snapshot.activation_epoch
                && head.snapshot_digest == snapshot.snapshot_digest
        })
    }

    /// Current pending or indeterminate transition, if any.
    #[must_use]
    pub fn pending_transition(&self) -> Option<&PreparedTransition> {
        self.pending_transition.as_ref()
    }

    /// Ordered retained rollback stack (most recently displaced active generation last).
    #[must_use]
    pub fn rollback_stack(&self) -> &[ModelGeneration] {
        &self.rollback_stack
    }

    /// Looks up one registered generation record.
    #[must_use]
    pub fn record(&self, generation: &ModelGeneration) -> Option<&GenerationRecord> {
        self.generations.get(generation)
    }

    /// Append-only canonical lifecycle journal.
    #[must_use]
    pub fn journal(&self) -> &[LifecycleJournalEntry] {
        &self.journal
    }

    /// Canonical digest over the entire lifecycle state (policy-independent state
    /// commitment: active epoch/snapshot, rollback stack, anti-rollback floor,
    /// pending transition, and sorted generation records).
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("model_lifecycle_state.v1");
        enc.u64(self.activation_epoch);
        enc.u64(self.min_allowed_sequence_order);
        enc.u64(self.highest_lease_fence);
        match &self.active_snapshot {
            Some(snap) => {
                enc.bool(true);
                enc.digest(snap.snapshot_digest);
            }
            None => enc.bool(false),
        }
        enc.u64(self.rollback_stack.len() as u64);
        for rb in &self.rollback_stack {
            rb.encode_canonical(&mut enc);
        }
        match &self.pending_transition {
            Some(pending) => {
                enc.bool(true);
                enc.digest(pending.plan_digest);
                match &pending.state {
                    PendingTransitionState::Prepared => enc.u8(1),
                    PendingTransitionState::Indeterminate {
                        reason,
                        recorded_at,
                    } => {
                        enc.u8(2);
                        enc.text(reason);
                        enc.i128(recorded_at.0);
                    }
                }
            }
            None => enc.bool(false),
        }
        enc.u64(self.generations.len() as u64);
        for (gen_id, rec) in &self.generations {
            gen_id.encode_canonical(&mut enc);
            enc.digest(rec.descriptor.descriptor_digest());
            rec.stage.encode_canonical(&mut enc);
            enc.u64(rec.shadow_summary.total_runs);
            enc.u64(rec.shadow_summary.matched_runs);
            enc.u64(rec.shadow_summary.diverged_runs);
            enc.u64(rec.shadow_summary.abstained_runs);
            enc.u64(rec.shadow_summary.quarantined_runs);
        }
        ContentDigest::sha256(&enc.finish())
    }

    /// Step 1: Registers an immutable model generation in `Staged`.
    /// Idempotent when the exact same descriptor is re-supplied while still `Staged`;
    /// refuses conflicting descriptors and refuses reusing any terminal tombstone.
    pub fn stage_generation(
        &mut self,
        descriptor: ModelGenerationDescriptor,
        now: TimestampNs,
    ) -> Result<ContentDigest, LifecycleError> {
        if let Err(err) = self.check_clock(now) {
            self.metrics.refusals = self.metrics.refusals.saturating_add(1);
            return Err(err);
        }
        if let Err(err) = descriptor.validate() {
            self.metrics.refusals = self.metrics.refusals.saturating_add(1);
            return Err(err);
        }
        if let Some(existing) = self.generations.get(&descriptor.generation) {
            if existing.descriptor == descriptor && !existing.stage.is_terminal() {
                return Ok(existing.descriptor.descriptor_digest());
            }
            self.metrics.refusals = self.metrics.refusals.saturating_add(1);
            return Err(LifecycleError::GenerationConflict {
                generation: descriptor.generation,
            });
        }
        if self.generations.len() >= MAX_GENERATIONS {
            self.metrics.refusals = self.metrics.refusals.saturating_add(1);
            return Err(LifecycleError::CapacityExceeded {
                bound: "MAX_GENERATIONS",
                limit: MAX_GENERATIONS,
            });
        }
        let digest = descriptor.descriptor_digest();
        self.append_and_apply(LifecycleJournalEvent::Staged { descriptor }, now)?;
        Ok(digest)
    }

    /// Step 2: Verifies offline package integrity, license/profile approval,
    /// and exact `ModelIrGraph` validation + canonical IR digest parity
    /// (`Staged -> Verified`).
    pub fn verify_generation(
        &mut self,
        generation: &ModelGeneration,
        graph: &ModelIrGraph,
        evidence: VerificationEvidence,
        now: TimestampNs,
    ) -> Result<ContentDigest, LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        evidence.validate().inspect_err(|_| self.bump_refusal())?;

        let (stage, expected_ir_digest, expected_ir_generation) = {
            let Some(rec) = self.generations.get(generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: generation.clone(),
                });
            };
            (
                rec.stage,
                rec.descriptor.ir_digest,
                rec.descriptor.ir_generation,
            )
        };
        if stage != ModelGenerationStage::Staged {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "verify_generation",
            });
        }
        if !evidence.offline_only_verified {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: "offline-only provenance not verified (INV-044)".to_owned(),
            });
        }
        if !evidence.license_approved {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: "license policy did not approve model package".to_owned(),
            });
        }
        if !evidence.profile_approved {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: "use profile not approved".to_owned(),
            });
        }
        if let Err(err) = graph.validate() {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: format!("IR graph validation failed: {err}"),
            });
        }
        let actual_ir_digest = compute_model_ir_digest(graph).map_err(|err| {
            self.bump_refusal();
            LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: format!("IR canonical digest failed: {err}"),
            }
        })?;
        if actual_ir_digest != expected_ir_digest {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: format!(
                    "IR digest mismatch: descriptor {expected_ir_digest}, graph {actual_ir_digest}"
                ),
            });
        }
        if graph.generation() != expected_ir_generation {
            self.bump_refusal();
            return Err(LifecycleError::VerificationFailed {
                generation: generation.clone(),
                reason: format!(
                    "IR generation mismatch: descriptor {}, graph {}",
                    expected_ir_generation.get(),
                    graph.generation().get()
                ),
            });
        }

        let pkg_digest = evidence.package_verification_digest;
        self.append_and_apply(
            LifecycleJournalEvent::Verified {
                generation: generation.clone(),
                evidence,
            },
            now,
        )?;
        Ok(pkg_digest)
    }

    /// Step 3: Evaluates deterministic qualification results (`Verified -> Qualified`).
    /// If any case triggered quarantine, transitions the generation to `Quarantined`.
    /// Never grants activation authority.
    pub fn qualify_generation(
        &mut self,
        generation: &ModelGeneration,
        report: QualificationReport,
        now: TimestampNs,
    ) -> Result<QualificationReceipt, LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        report.validate().inspect_err(|_| self.bump_refusal())?;

        let (stage, descriptor_digest) = {
            let Some(rec) = self.generations.get(generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: generation.clone(),
                });
            };
            (rec.stage, rec.descriptor.descriptor_digest())
        };
        if stage != ModelGenerationStage::Verified {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "qualify_generation",
            });
        }

        if report.quarantined_cases > 0 {
            let reason = format!(
                "qualification observed {} quarantined case(s)",
                report.quarantined_cases
            );
            self.append_and_apply(
                LifecycleJournalEvent::Quarantined {
                    generation: generation.clone(),
                    reason: reason.clone(),
                },
                now,
            )?;
            self.bump_refusal();
            return Err(LifecycleError::QualificationFailed {
                generation: generation.clone(),
                reason,
            });
        }
        if report.passed_cases == 0 || report.failed_cases > 0 || report.abstained_cases > 0 {
            self.bump_refusal();
            return Err(LifecycleError::QualificationFailed {
                generation: generation.clone(),
                reason: format!(
                    "qualification incomplete or failed (passed={}, failed={}, abstained={})",
                    report.passed_cases, report.failed_cases, report.abstained_cases
                ),
            });
        }

        let report_digest = report.digest();
        self.append_and_apply(
            LifecycleJournalEvent::Qualified {
                generation: generation.clone(),
                report,
            },
            now,
        )?;

        let mut enc = CanonicalEncoder::new();
        enc.text("model_qualification_receipt.v1");
        generation.encode_canonical(&mut enc);
        enc.digest(descriptor_digest);
        enc.digest(report_digest);
        enc.i128(now.0);
        enc.bool(false);
        let receipt_digest = ContentDigest::sha256(&enc.finish());

        Ok(QualificationReceipt {
            generation: generation.clone(),
            descriptor_digest,
            report_digest,
            qualified_at: now,
            grants_activation_authority: false,
            receipt_digest,
        })
    }

    /// Step 4a: Starts observational shadow evaluation (`Qualified -> Shadowing`).
    /// Never alters the active generation or reader snapshots.
    pub fn start_shadow(
        &mut self,
        generation: &ModelGeneration,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        let Some(stage) = self.generations.get(generation).map(|rec| rec.stage) else {
            self.bump_refusal();
            return Err(LifecycleError::UnknownGeneration {
                generation: generation.clone(),
            });
        };
        if stage != ModelGenerationStage::Qualified {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "start_shadow",
            });
        }
        self.append_and_apply(
            LifecycleJournalEvent::ShadowStarted {
                generation: generation.clone(),
            },
            now,
        )
    }

    /// Step 4b: Records one shadow evaluation run from real [`ModelReceipt`]s
    /// (from `fss_model_ir::invocation` / `fss_model_ir::quotas`).
    ///
    /// - Refuses stale/mismatched IR digests or generations.
    /// - Never flattens `Abstained` or `Quarantined` into `Matched`.
    /// - Auto-quarantines the candidate if `Quarantined` is observed and
    ///   `policy.auto_quarantine_on_shadow_quarantine` is enabled.
    pub fn record_shadow_run(
        &mut self,
        generation: &ModelGeneration,
        candidate_receipt: &ModelReceipt,
        baseline_receipt: Option<&ModelReceipt>,
        now: TimestampNs,
    ) -> Result<ShadowOutcome, LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        let (stage, obs_len, expected_ir_digest, expected_ir_generation) = {
            let Some(rec) = self.generations.get(generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: generation.clone(),
                });
            };
            (
                rec.stage,
                rec.shadow_observations.len(),
                rec.descriptor.ir_digest,
                rec.descriptor.ir_generation,
            )
        };
        if stage != ModelGenerationStage::Shadowing {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "record_shadow_run",
            });
        }
        if obs_len >= MAX_SHADOW_OBSERVATIONS {
            self.bump_refusal();
            return Err(LifecycleError::CapacityExceeded {
                bound: "MAX_SHADOW_OBSERVATIONS",
                limit: MAX_SHADOW_OBSERVATIONS,
            });
        }
        if candidate_receipt.ir_digest != expected_ir_digest
            || candidate_receipt.ir_generation != expected_ir_generation
        {
            self.bump_refusal();
            return Err(LifecycleError::StaleGenerationReceipt {
                generation: generation.clone(),
                expected_ir_digest,
                observed_ir_digest: candidate_receipt.ir_digest,
            });
        }

        let outcome = classify_shadow_outcome(candidate_receipt, baseline_receipt);
        let observation = ShadowObservation {
            candidate_invocation: candidate_receipt.invocation,
            baseline_invocation: baseline_receipt.map(|r| r.invocation),
            outcome: outcome.clone(),
            observed_at: now,
        };
        self.append_and_apply(
            LifecycleJournalEvent::ShadowObserved {
                generation: generation.clone(),
                observation,
            },
            now,
        )?;

        if let ShadowOutcome::CandidateQuarantined { ref reason } = outcome
            && self.policy.auto_quarantine_on_shadow_quarantine
        {
            let truncated = clamp_reason(&format!("shadow quarantine: {reason}"));
            self.append_and_apply(
                LifecycleJournalEvent::Quarantined {
                    generation: generation.clone(),
                    reason: truncated,
                },
                now,
            )?;
        }
        Ok(outcome)
    }

    /// Observational Decision-Card evidence summary for a generation (`FSS-148`).
    /// Pure read: never mutates state and never grants activation authority.
    pub fn shadow_decision_evidence(
        &self,
        generation: &ModelGeneration,
    ) -> Result<ShadowDecisionEvidence, LifecycleError> {
        let rec =
            self.generations
                .get(generation)
                .ok_or_else(|| LifecycleError::UnknownGeneration {
                    generation: generation.clone(),
                })?;
        let reasons = self.activation_blocking_reasons(rec);
        Ok(ShadowDecisionEvidence {
            generation: generation.clone(),
            stage: rec.stage,
            summary: rec.shadow_summary.clone(),
            divergence_ppm: rec.shadow_summary.divergence_ppm(),
            abstention_ppm: rec.shadow_summary.abstention_ppm(),
            shadow_gate_satisfied: reasons.is_empty(),
            blocking_reasons: reasons,
            grants_activation_authority: false,
        })
    }

    /// Phase 1 of activation: validates authority, lease fence, cancellation,
    /// resource pressure (`MemoryAdmission`), anti-rollback floor, qualification,
    /// and shadow gates. Does NOT alter `reader_snapshot()` until `commit_transition`.
    pub fn prepare_activation(
        &mut self,
        request: TransitionRequest,
        pressure: ResourcePressure,
        cancelled: bool,
        now: TimestampNs,
    ) -> Result<PreparedTransition, LifecycleError> {
        self.check_clock_counted(now)?;
        self.ensure_no_pending_transition()?;
        validate_model_generation_id(&request.target_generation)
            .inspect_err(|_| self.bump_refusal())?;
        validate_digest("contract_basis_digest", request.contract_basis_digest)
            .inspect_err(|_| self.bump_refusal())?;
        if let Err(err) = self.check_authority(
            &request.authority,
            &self.policy.required_activate_capability,
        ) {
            self.bump_refusal();
            return Err(err);
        }

        if cancelled {
            self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
            return Err(LifecycleError::Cancelled {
                action: "prepare_activation",
            });
        }
        if !self.policy.activation_pressure_policy.admits(pressure) {
            self.bump_refusal();
            return Err(LifecycleError::PressureRefused {
                generation: request.target_generation,
                pressure,
            });
        }

        let (order, stage, blocking) = {
            let Some(rec) = self.generations.get(&request.target_generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: request.target_generation,
                });
            };
            (
                rec.descriptor.sequence_order,
                rec.stage,
                self.shadow_blocking_reasons(rec),
            )
        };

        if self.policy.enforce_anti_rollback_floor && order < self.min_allowed_sequence_order {
            self.bump_refusal();
            return Err(LifecycleError::AntiRollbackRefused {
                generation: request.target_generation,
                candidate_order: order,
                minimum_order: self.min_allowed_sequence_order,
            });
        }

        let eligible_stage = if self.policy.require_shadow_before_activate {
            stage == ModelGenerationStage::Shadowing
        } else {
            matches!(
                stage,
                ModelGenerationStage::Qualified | ModelGenerationStage::Shadowing
            )
        };
        if !eligible_stage {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: request.target_generation,
                current: stage,
                action: "prepare_activation",
            });
        }

        if !blocking.is_empty() {
            self.bump_refusal();
            return Err(LifecycleError::ShadowGateNotMet {
                generation: request.target_generation,
                reasons: blocking,
            });
        }

        self.record_prepared_transition(TransitionKind::Activate, request, now)
    }

    /// Phase 1 of rollback: validates authority, lease fence, cancellation, and
    /// anti-rollback/revocation safety. Remains admissible even under
    /// `ResourcePressure::Critical` because rollback is an emergency safety control.
    ///
    /// If `target_generation` is `None`, selects the most recent eligible
    /// `RetainedRollback` generation from the rollback stack.
    pub fn prepare_rollback(
        &mut self,
        operation_id: OperationId,
        target_generation: Option<ModelGeneration>,
        contract_basis_digest: ContentDigest,
        authority: EffectAuthority,
        cancelled: bool,
        now: TimestampNs,
    ) -> Result<PreparedTransition, LifecycleError> {
        self.check_clock_counted(now)?;
        self.ensure_no_pending_transition()?;
        validate_digest("contract_basis_digest", contract_basis_digest)
            .inspect_err(|_| self.bump_refusal())?;
        if let Err(err) =
            self.check_authority(&authority, &self.policy.required_rollback_capability)
        {
            self.bump_refusal();
            return Err(err);
        }

        if cancelled {
            self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
            return Err(LifecycleError::Cancelled {
                action: "prepare_rollback",
            });
        }

        let target = match target_generation {
            Some(explicit) => {
                validate_model_generation_id(&explicit).inspect_err(|_| self.bump_refusal())?;
                explicit
            }
            None => self.latest_eligible_rollback_target().ok_or_else(|| {
                self.bump_refusal();
                LifecycleError::NoRollbackTarget {
                    detail: "no eligible retained rollback generation meets safety and anti-rollback rules"
                        .to_owned(),
                }
            })?,
        };

        let (stage, order) = {
            let Some(rec) = self.generations.get(&target) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration { generation: target });
            };
            (rec.stage, rec.descriptor.sequence_order)
        };
        if stage != ModelGenerationStage::RetainedRollback {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: target,
                current: stage,
                action: "prepare_rollback",
            });
        }
        if self.policy.enforce_anti_rollback_floor && order < self.min_allowed_sequence_order {
            self.bump_refusal();
            return Err(LifecycleError::AntiRollbackRefused {
                generation: target,
                candidate_order: order,
                minimum_order: self.min_allowed_sequence_order,
            });
        }

        self.record_prepared_transition(
            TransitionKind::Rollback,
            TransitionRequest {
                operation_id,
                target_generation: target,
                contract_basis_digest,
                authority,
            },
            now,
        )
    }

    /// Cleanly cancels a `Prepared` transition before commit (`request -> drain -> finalize`).
    /// Refuses cancelling an `Indeterminate` transition (must reconcile instead).
    pub fn cancel_prepared_transition(
        &mut self,
        plan_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        self.check_clock_counted(now)?;
        let (pending_digest, is_indeterminate) = {
            let Some(pending) = self.pending_transition.as_ref() else {
                self.bump_refusal();
                return Err(LifecycleError::TransitionMismatch {
                    detail: "no pending transition to cancel".to_owned(),
                });
            };
            (
                pending.plan_digest,
                matches!(pending.state, PendingTransitionState::Indeterminate { .. }),
            )
        };
        if pending_digest != plan_digest {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: format!(
                    "plan digest mismatch: pending {pending_digest}, requested {plan_digest}"
                ),
            });
        }
        if is_indeterminate {
            self.bump_refusal();
            return Err(LifecycleError::PendingTransitionActive {
                plan_digest,
                indeterminate: true,
            });
        }
        self.append_and_apply(
            LifecycleJournalEvent::TransitionCancelled { plan_digest },
            now,
        )
    }

    /// Phase 2 of activation or rollback: revalidates the bound plan digest,
    /// expected epoch, target eligibility, and cancellation, then atomically
    /// publishes the new [`ActiveModelSnapshot`] (`FORMAL-007`).
    pub fn commit_transition(
        &mut self,
        plan_digest: ContentDigest,
        expected_epoch: u64,
        cancelled: bool,
        now: TimestampNs,
    ) -> Result<TransitionReceipt, LifecycleError> {
        self.check_clock_counted(now)?;
        let pending = self.pending_transition.clone().ok_or_else(|| {
            self.bump_refusal();
            LifecycleError::TransitionMismatch {
                detail: "no pending transition to commit".to_owned(),
            }
        })?;
        if pending.plan_digest != plan_digest {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: format!(
                    "plan digest mismatch: pending {}, requested {}",
                    pending.plan_digest, plan_digest
                ),
            });
        }
        if matches!(pending.state, PendingTransitionState::Indeterminate { .. }) {
            self.bump_refusal();
            return Err(LifecycleError::PendingTransitionActive {
                plan_digest,
                indeterminate: true,
            });
        }
        if cancelled {
            self.append_and_apply(
                LifecycleJournalEvent::TransitionCancelled { plan_digest },
                now,
            )?;
            return Err(LifecycleError::Cancelled {
                action: "commit_transition",
            });
        }
        if expected_epoch != self.activation_epoch
            || pending.expected_epoch != self.activation_epoch
        {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: format!(
                    "stale activation epoch: expected {}, current {}",
                    expected_epoch, self.activation_epoch
                ),
            });
        }
        self.revalidate_pending_target(&pending)?;

        let new_epoch = self.activation_epoch.saturating_add(1);
        self.append_and_apply(
            LifecycleJournalEvent::TransitionCommitted {
                plan_digest,
                new_epoch,
            },
            now,
        )?;
        self.build_transition_receipt(&pending, now)
    }

    /// Records an ambiguous commit boundary (crash / lost acknowledgement).
    /// Blocks all new prepares/commits until [`Self::reconcile_indeterminate`]
    /// settles the bound plan conclusively.
    pub fn mark_transition_indeterminate(
        &mut self,
        plan_digest: ContentDigest,
        reason: &str,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        self.check_clock_counted(now)?;
        validate_reason(reason).inspect_err(|_| self.bump_refusal())?;
        let (pending_digest, already_indeterminate) = {
            let Some(pending) = self.pending_transition.as_ref() else {
                self.bump_refusal();
                return Err(LifecycleError::TransitionMismatch {
                    detail: "no pending transition to mark indeterminate".to_owned(),
                });
            };
            (
                pending.plan_digest,
                matches!(pending.state, PendingTransitionState::Indeterminate { .. }),
            )
        };
        if pending_digest != plan_digest {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: format!(
                    "plan digest mismatch: pending {pending_digest}, requested {plan_digest}"
                ),
            });
        }
        if already_indeterminate {
            return Ok(());
        }
        self.append_and_apply(
            LifecycleJournalEvent::TransitionIndeterminate {
                plan_digest,
                reason: reason.to_owned(),
            },
            now,
        )
    }

    /// Conclusively reconciles an `Indeterminate` transition using verified
    /// external/durable evidence.
    pub fn reconcile_indeterminate(
        &mut self,
        plan_digest: ContentDigest,
        observation: ReconciliationObservation,
        now: TimestampNs,
    ) -> Result<ReconciliationReceipt, LifecycleError> {
        self.check_clock_counted(now)?;
        let pending = self.pending_transition.clone().ok_or_else(|| {
            self.bump_refusal();
            LifecycleError::TransitionMismatch {
                detail: "no indeterminate transition to reconcile".to_owned(),
            }
        })?;
        if pending.plan_digest != plan_digest {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: format!(
                    "plan digest mismatch: pending {}, requested {}",
                    pending.plan_digest, plan_digest
                ),
            });
        }
        if !matches!(pending.state, PendingTransitionState::Indeterminate { .. }) {
            self.bump_refusal();
            return Err(LifecycleError::TransitionMismatch {
                detail: "pending transition is Prepared, not Indeterminate".to_owned(),
            });
        }

        match observation {
            ReconciliationObservation::ConfirmedCommitted { evidence_digest } => {
                validate_digest("evidence_digest", evidence_digest)
                    .inspect_err(|_| self.bump_refusal())?;
                self.revalidate_pending_target(&pending)?;
                let new_epoch = self.activation_epoch.saturating_add(1);
                self.append_and_apply(
                    LifecycleJournalEvent::TransitionCommitted {
                        plan_digest,
                        new_epoch,
                    },
                    now,
                )?;
                let receipt = self.build_transition_receipt(&pending, now)?;
                Ok(ReconciliationReceipt {
                    plan_digest,
                    committed: Some(receipt),
                    reconciled_at: now,
                })
            }
            ReconciliationObservation::ConfirmedNotCommitted { evidence_digest } => {
                validate_digest("evidence_digest", evidence_digest)
                    .inspect_err(|_| self.bump_refusal())?;
                self.append_and_apply(
                    LifecycleJournalEvent::TransitionReconciledNotCommitted {
                        plan_digest,
                        evidence_digest,
                    },
                    now,
                )?;
                Ok(ReconciliationReceipt {
                    plan_digest,
                    committed: None,
                    reconciled_at: now,
                })
            }
        }
    }

    /// Quarantines a generation after a runtime fault (OOM, hang, crash,
    /// malformed output, validator refusal). If currently `Active`, fails closed
    /// (clears active snapshot) and returns the best eligible rollback target
    /// for an explicit authorized rollback — never silently auto-activating.
    pub fn quarantine_generation(
        &mut self,
        generation: &ModelGeneration,
        reason: &str,
        now: TimestampNs,
    ) -> Result<Option<ModelGeneration>, LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        validate_reason(reason).inspect_err(|_| self.bump_refusal())?;
        let Some(stage) = self.generations.get(generation).map(|rec| rec.stage) else {
            self.bump_refusal();
            return Err(LifecycleError::UnknownGeneration {
                generation: generation.clone(),
            });
        };
        if stage.is_terminal() {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "quarantine_generation",
            });
        }
        self.append_and_apply(
            LifecycleJournalEvent::Quarantined {
                generation: generation.clone(),
                reason: reason.to_owned(),
            },
            now,
        )?;
        Ok(self.latest_eligible_rollback_target())
    }

    /// Terminally revokes a generation (`DOC-045`). Optionally advances the
    /// anti-rollback floor to `revoked.sequence_order + 1` so neither this
    /// generation nor any older generation can be activated or rolled back to.
    pub fn revoke_generation(
        &mut self,
        generation: &ModelGeneration,
        authority: EffectAuthority,
        reason: &str,
        advance_anti_rollback_floor: bool,
        now: TimestampNs,
    ) -> Result<u64, LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        validate_reason(reason).inspect_err(|_| self.bump_refusal())?;
        if let Err(err) = self.check_authority(&authority, &self.policy.required_revoke_capability)
        {
            self.bump_refusal();
            return Err(err);
        }
        let (stage, order) = {
            let Some(rec) = self.generations.get(generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: generation.clone(),
                });
            };
            (rec.stage, rec.descriptor.sequence_order)
        };
        if stage == ModelGenerationStage::Revoked {
            return Ok(self.min_allowed_sequence_order);
        }
        let new_min = if advance_anti_rollback_floor {
            self.min_allowed_sequence_order.max(order.saturating_add(1))
        } else {
            self.min_allowed_sequence_order
        };
        self.append_and_apply(
            LifecycleJournalEvent::Revoked {
                generation: generation.clone(),
                authority,
                reason: reason.to_owned(),
                new_min_sequence_order: new_min,
            },
            now,
        )?;
        Ok(self.min_allowed_sequence_order)
    }

    /// Terminally retires an inactive generation once rollback retention
    /// constraints are satisfied. Refuses retiring `Active`, pending-transition
    /// targets, or retained rollback entries required by `rollback_retention_floor`.
    pub fn retire_generation(
        &mut self,
        generation: &ModelGeneration,
        authority: EffectAuthority,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        self.check_clock_counted(now)?;
        validate_model_generation_id(generation).inspect_err(|_| self.bump_refusal())?;
        if let Err(err) = self.check_authority(&authority, &self.policy.required_retire_capability)
        {
            self.bump_refusal();
            return Err(err);
        }

        let Some(stage) = self.generations.get(generation).map(|rec| rec.stage) else {
            self.bump_refusal();
            return Err(LifecycleError::UnknownGeneration {
                generation: generation.clone(),
            });
        };
        if stage == ModelGenerationStage::Active {
            self.bump_refusal();
            return Err(LifecycleError::RetirementBlocked {
                generation: generation.clone(),
                reason: "cannot retire the active generation".to_owned(),
            });
        }
        if stage.is_terminal() {
            self.bump_refusal();
            return Err(LifecycleError::InvalidStage {
                generation: generation.clone(),
                current: stage,
                action: "retire_generation",
            });
        }
        if self
            .pending_transition
            .as_ref()
            .is_some_and(|p| p.target_generation == *generation)
        {
            self.bump_refusal();
            return Err(LifecycleError::RetirementBlocked {
                generation: generation.clone(),
                reason: "generation is bound to a pending transition".to_owned(),
            });
        }
        if stage == ModelGenerationStage::RetainedRollback {
            let eligible_rollbacks = self
                .rollback_stack
                .iter()
                .filter(|g| {
                    self.generations
                        .get(*g)
                        .is_some_and(|r| r.stage == ModelGenerationStage::RetainedRollback)
                })
                .count();
            if eligible_rollbacks <= self.policy.rollback_retention_floor {
                self.bump_refusal();
                return Err(LifecycleError::RetirementBlocked {
                    generation: generation.clone(),
                    reason: format!(
                        "retaining {} rollback target(s) is required by rollback_retention_floor={}",
                        eligible_rollbacks, self.policy.rollback_retention_floor
                    ),
                });
            }
        }
        self.append_and_apply(
            LifecycleJournalEvent::Retired {
                generation: generation.clone(),
                authority,
            },
            now,
        )
    }

    /// Deterministically reconstructs an exact [`ModelLifecycleManager`] by
    /// replaying a verified hash-chained canonical journal (crash/restart proof).
    pub fn replay_journal(
        policy: LifecyclePolicy,
        entries: &[LifecycleJournalEntry],
    ) -> Result<Self, LifecycleError> {
        let mut manager = Self::new(policy)?;
        let mut expected_prev = zero_digest();
        for (idx, entry) in entries.iter().enumerate() {
            let expected_seq = (idx as u64).saturating_add(1);
            if entry.sequence != expected_seq {
                return Err(LifecycleError::JournalCorrupt {
                    detail: format!(
                        "sequence gap or reorder: expected {expected_seq}, observed {}",
                        entry.sequence
                    ),
                });
            }
            if entry.prev_digest != expected_prev {
                return Err(LifecycleError::JournalCorrupt {
                    detail: format!("hash chain break at sequence {}", entry.sequence),
                });
            }
            let recomputed = LifecycleJournalEntry::compute_digest(
                entry.sequence,
                entry.prev_digest,
                entry.recorded_at,
                &entry.event,
            );
            if recomputed != entry.entry_digest {
                return Err(LifecycleError::JournalCorrupt {
                    detail: format!("entry digest mismatch at sequence {}", entry.sequence),
                });
            }
            if let Some(prev_ts) = manager.last_timestamp
                && entry.recorded_at < prev_ts
            {
                return Err(LifecycleError::JournalCorrupt {
                    detail: format!(
                        "timestamp regression at sequence {}: {} < {}",
                        entry.sequence, entry.recorded_at.0, prev_ts.0
                    ),
                });
            }
            manager.apply_event(entry.event.clone(), entry.recorded_at)?;
            manager.last_timestamp = Some(entry.recorded_at);
            manager.journal.push(entry.clone());
            expected_prev = entry.entry_digest;
        }
        Ok(manager)
    }

    // ---- Internal helpers ----------------------------------------------------

    fn bump_refusal(&mut self) {
        self.metrics.refusals = self.metrics.refusals.saturating_add(1);
    }

    fn check_clock(&self, now: TimestampNs) -> Result<(), LifecycleError> {
        if let Some(prev) = self.last_timestamp
            && now < prev
        {
            return Err(LifecycleError::ClockRegression {
                previous: prev,
                observed: now,
            });
        }
        Ok(())
    }

    fn check_clock_counted(&mut self, now: TimestampNs) -> Result<(), LifecycleError> {
        if let Err(err) = self.check_clock(now) {
            self.bump_refusal();
            return Err(err);
        }
        Ok(())
    }

    fn ensure_no_pending_transition(&mut self) -> Result<(), LifecycleError> {
        if let Some(pending) = &self.pending_transition {
            let plan_digest = pending.plan_digest;
            let indeterminate =
                matches!(pending.state, PendingTransitionState::Indeterminate { .. });
            self.bump_refusal();
            return Err(LifecycleError::PendingTransitionActive {
                plan_digest,
                indeterminate,
            });
        }
        Ok(())
    }

    fn check_authority(
        &self,
        authority: &EffectAuthority,
        required_capability: &str,
    ) -> Result<(), LifecycleError> {
        if authority.principal.trim().is_empty()
            || authority.principal.len() > MAX_LABEL_BYTES
            || authority.principal.chars().any(char::is_control)
        {
            return Err(LifecycleError::AuthorityRefused {
                detail: "invalid effect authority principal".to_owned(),
            });
        }
        if authority.capability != required_capability {
            return Err(LifecycleError::AuthorityRefused {
                detail: format!(
                    "capability mismatch: required '{required_capability}', supplied '{}'",
                    authority.capability
                ),
            });
        }
        if let Some(fence) = authority.lease_fence
            && fence < self.highest_lease_fence
        {
            return Err(LifecycleError::AuthorityRefused {
                detail: format!(
                    "stale lease fence {fence} < highest committed {}",
                    self.highest_lease_fence
                ),
            });
        }
        Ok(())
    }

    fn shadow_blocking_reasons(&self, rec: &GenerationRecord) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.policy.require_shadow_before_activate
            && rec.shadow_summary.total_runs < self.policy.min_shadow_samples
        {
            reasons.push(format!(
                "shadow samples {} < required {}",
                rec.shadow_summary.total_runs, self.policy.min_shadow_samples
            ));
        }
        if rec.shadow_summary.quarantined_runs > 0 {
            reasons.push(format!(
                "shadow observed {} quarantined run(s)",
                rec.shadow_summary.quarantined_runs
            ));
        }
        let div_ppm = rec.shadow_summary.divergence_ppm();
        if div_ppm > self.policy.max_shadow_divergence_ppm {
            reasons.push(format!(
                "shadow divergence {div_ppm} ppm exceeds bound {} ppm",
                self.policy.max_shadow_divergence_ppm
            ));
        }
        let abs_ppm = rec.shadow_summary.abstention_ppm();
        if abs_ppm > self.policy.max_shadow_abstention_ppm {
            reasons.push(format!(
                "shadow abstention {abs_ppm} ppm exceeds bound {} ppm",
                self.policy.max_shadow_abstention_ppm
            ));
        }
        reasons
    }

    fn activation_blocking_reasons(&self, rec: &GenerationRecord) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.policy.enforce_anti_rollback_floor
            && rec.descriptor.sequence_order < self.min_allowed_sequence_order
        {
            reasons.push(format!(
                "sequence_order {} < anti-rollback floor {}",
                rec.descriptor.sequence_order, self.min_allowed_sequence_order
            ));
        }
        let stage_ok = if self.policy.require_shadow_before_activate {
            rec.stage == ModelGenerationStage::Shadowing
        } else {
            matches!(
                rec.stage,
                ModelGenerationStage::Qualified | ModelGenerationStage::Shadowing
            )
        };
        if !stage_ok {
            reasons.push(format!(
                "stage '{}' not ready for activation",
                rec.stage.as_str()
            ));
        }
        reasons.extend(self.shadow_blocking_reasons(rec));
        reasons
    }

    fn latest_eligible_rollback_target(&self) -> Option<ModelGeneration> {
        self.rollback_stack
            .iter()
            .rev()
            .find(|gen_id| {
                self.generations.get(*gen_id).is_some_and(|rec| {
                    rec.stage == ModelGenerationStage::RetainedRollback
                        && (!self.policy.enforce_anti_rollback_floor
                            || rec.descriptor.sequence_order >= self.min_allowed_sequence_order)
                })
            })
            .cloned()
    }

    fn record_prepared_transition(
        &mut self,
        kind: TransitionKind,
        request: TransitionRequest,
        now: TimestampNs,
    ) -> Result<PreparedTransition, LifecycleError> {
        let previous_active = self
            .active_snapshot
            .as_ref()
            .map(|snap| snap.active.generation.clone());
        let expected_epoch = self.activation_epoch;
        let plan_digest = PreparedTransition::compute_plan_digest(
            &request.operation_id,
            kind,
            &request.target_generation,
            previous_active.as_ref(),
            expected_epoch,
            request.contract_basis_digest,
            &request.authority,
            now,
        );
        self.append_and_apply(
            LifecycleJournalEvent::TransitionPrepared {
                operation_id: request.operation_id,
                kind,
                target_generation: request.target_generation,
                previous_active,
                expected_epoch,
                contract_basis_digest: request.contract_basis_digest,
                authority: request.authority,
                plan_digest,
            },
            now,
        )?;
        self.pending_transition
            .clone()
            .ok_or_else(|| LifecycleError::JournalCorrupt {
                detail: "prepared transition missing after apply".to_owned(),
            })
    }

    fn revalidate_pending_target(
        &mut self,
        pending: &PreparedTransition,
    ) -> Result<(), LifecycleError> {
        let (order, stage, blocking) = {
            let Some(rec) = self.generations.get(&pending.target_generation) else {
                self.bump_refusal();
                return Err(LifecycleError::UnknownGeneration {
                    generation: pending.target_generation.clone(),
                });
            };
            (
                rec.descriptor.sequence_order,
                rec.stage,
                self.shadow_blocking_reasons(rec),
            )
        };
        if self.policy.enforce_anti_rollback_floor && order < self.min_allowed_sequence_order {
            self.bump_refusal();
            return Err(LifecycleError::AntiRollbackRefused {
                generation: pending.target_generation.clone(),
                candidate_order: order,
                minimum_order: self.min_allowed_sequence_order,
            });
        }
        match pending.kind {
            TransitionKind::Activate => {
                let stage_ok = if self.policy.require_shadow_before_activate {
                    stage == ModelGenerationStage::Shadowing
                } else {
                    matches!(
                        stage,
                        ModelGenerationStage::Qualified | ModelGenerationStage::Shadowing
                    )
                };
                if !stage_ok {
                    self.bump_refusal();
                    return Err(LifecycleError::InvalidStage {
                        generation: pending.target_generation.clone(),
                        current: stage,
                        action: "commit_activation",
                    });
                }
                if !blocking.is_empty() {
                    self.bump_refusal();
                    return Err(LifecycleError::ShadowGateNotMet {
                        generation: pending.target_generation.clone(),
                        reasons: blocking,
                    });
                }
            }
            TransitionKind::Rollback => {
                if stage != ModelGenerationStage::RetainedRollback {
                    self.bump_refusal();
                    return Err(LifecycleError::InvalidStage {
                        generation: pending.target_generation.clone(),
                        current: stage,
                        action: "commit_rollback",
                    });
                }
            }
        }
        Ok(())
    }

    fn build_transition_receipt(
        &self,
        pending: &PreparedTransition,
        committed_at: TimestampNs,
    ) -> Result<TransitionReceipt, LifecycleError> {
        let snapshot =
            self.active_snapshot
                .clone()
                .ok_or_else(|| LifecycleError::JournalCorrupt {
                    detail: "active snapshot missing immediately after commit".to_owned(),
                })?;
        let mut enc = CanonicalEncoder::new();
        enc.text("model_transition_receipt.v1");
        enc.text(pending.operation_id.as_str());
        pending.kind.encode_canonical(&mut enc);
        enc.digest(pending.plan_digest);
        enc.digest(snapshot.snapshot_digest);
        match &pending.previous_active {
            Some(prev) => {
                enc.bool(true);
                prev.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        enc.i128(committed_at.0);
        let receipt_digest = ContentDigest::sha256(&enc.finish());
        Ok(TransitionReceipt {
            operation_id: pending.operation_id.clone(),
            kind: pending.kind,
            plan_digest: pending.plan_digest,
            snapshot,
            previous_active: pending.previous_active.clone(),
            committed_at,
            receipt_digest,
        })
    }

    fn append_and_apply(
        &mut self,
        event: LifecycleJournalEvent,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        if self.journal.len() >= MAX_JOURNAL_ENTRIES {
            self.bump_refusal();
            return Err(LifecycleError::CapacityExceeded {
                bound: "MAX_JOURNAL_ENTRIES",
                limit: MAX_JOURNAL_ENTRIES,
            });
        }
        let sequence = (self.journal.len() as u64).saturating_add(1);
        let prev_digest = self
            .journal
            .last()
            .map_or_else(zero_digest, |e| e.entry_digest);
        let entry_digest =
            LifecycleJournalEntry::compute_digest(sequence, prev_digest, now, &event);
        self.apply_event(event.clone(), now)?;
        self.last_timestamp = Some(now);
        self.journal.push(LifecycleJournalEntry {
            sequence,
            prev_digest,
            recorded_at: now,
            event,
            entry_digest,
        });
        Ok(())
    }

    fn apply_event(
        &mut self,
        event: LifecycleJournalEvent,
        now: TimestampNs,
    ) -> Result<(), LifecycleError> {
        match event {
            LifecycleJournalEvent::Staged { descriptor } => {
                descriptor.validate()?;
                let gen_id = descriptor.generation.clone();
                if self.generations.contains_key(&gen_id) {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!("duplicate staged generation '{gen_id}'"),
                    });
                }
                self.generations.insert(
                    gen_id,
                    GenerationRecord {
                        descriptor,
                        stage: ModelGenerationStage::Staged,
                        staged_at: now,
                        verification: None,
                        qualification: None,
                        shadow_summary: ShadowSummary::default(),
                        shadow_observations: Vec::new(),
                        terminal_or_quarantine_reason: None,
                    },
                );
                self.metrics.staged = self.metrics.staged.saturating_add(1);
            }
            LifecycleJournalEvent::Verified {
                generation,
                evidence,
            } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("verified unknown generation '{generation}'"),
                    }
                })?;
                if rec.stage != ModelGenerationStage::Staged {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!(
                            "illegal verified transition from '{}'",
                            rec.stage.as_str()
                        ),
                    });
                }
                rec.stage = ModelGenerationStage::Verified;
                rec.verification = Some(evidence);
                self.metrics.verified = self.metrics.verified.saturating_add(1);
            }
            LifecycleJournalEvent::Qualified { generation, report } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("qualified unknown generation '{generation}'"),
                    }
                })?;
                if rec.stage != ModelGenerationStage::Verified {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!(
                            "illegal qualified transition from '{}'",
                            rec.stage.as_str()
                        ),
                    });
                }
                rec.stage = ModelGenerationStage::Qualified;
                rec.qualification = Some(report);
                self.metrics.qualified = self.metrics.qualified.saturating_add(1);
            }
            LifecycleJournalEvent::ShadowStarted { generation } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("shadow_started unknown generation '{generation}'"),
                    }
                })?;
                if rec.stage != ModelGenerationStage::Qualified {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!(
                            "illegal shadow_started transition from '{}'",
                            rec.stage.as_str()
                        ),
                    });
                }
                rec.stage = ModelGenerationStage::Shadowing;
            }
            LifecycleJournalEvent::ShadowObserved {
                generation,
                observation,
            } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("shadow_observed unknown generation '{generation}'"),
                    }
                })?;
                if rec.stage != ModelGenerationStage::Shadowing {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!(
                            "illegal shadow_observed in stage '{}'",
                            rec.stage.as_str()
                        ),
                    });
                }
                rec.shadow_summary.record(&observation.outcome);
                rec.shadow_observations.push(observation);
                self.metrics.shadow_runs = self.metrics.shadow_runs.saturating_add(1);
            }
            LifecycleJournalEvent::TransitionPrepared {
                operation_id,
                kind,
                target_generation,
                previous_active,
                expected_epoch,
                contract_basis_digest,
                authority,
                plan_digest,
            } => {
                if self.pending_transition.is_some() {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "overlapping prepared transition in journal".to_owned(),
                    });
                }
                let recomputed = PreparedTransition::compute_plan_digest(
                    &operation_id,
                    kind,
                    &target_generation,
                    previous_active.as_ref(),
                    expected_epoch,
                    contract_basis_digest,
                    &authority,
                    now,
                );
                if recomputed != plan_digest {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "prepared transition plan_digest mismatch".to_owned(),
                    });
                }
                if let Some(fence) = authority.lease_fence {
                    self.highest_lease_fence = self.highest_lease_fence.max(fence);
                }
                self.pending_transition = Some(PreparedTransition {
                    operation_id,
                    kind,
                    target_generation,
                    previous_active,
                    expected_epoch,
                    contract_basis_digest,
                    authority,
                    prepared_at: now,
                    state: PendingTransitionState::Prepared,
                    plan_digest,
                });
            }
            LifecycleJournalEvent::TransitionCancelled { plan_digest } => {
                let Some(pending) = &self.pending_transition else {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "cancelled transition without pending plan".to_owned(),
                    });
                };
                if pending.plan_digest != plan_digest {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "cancelled transition plan_digest mismatch".to_owned(),
                    });
                }
                self.pending_transition = None;
                self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
            }
            LifecycleJournalEvent::TransitionIndeterminate {
                plan_digest,
                reason,
            } => {
                let Some(pending) = &mut self.pending_transition else {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "indeterminate transition without pending plan".to_owned(),
                    });
                };
                if pending.plan_digest != plan_digest {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "indeterminate transition plan_digest mismatch".to_owned(),
                    });
                }
                pending.state = PendingTransitionState::Indeterminate {
                    reason,
                    recorded_at: now,
                };
                self.metrics.indeterminates = self.metrics.indeterminates.saturating_add(1);
            }
            LifecycleJournalEvent::TransitionCommitted {
                plan_digest,
                new_epoch,
            } => {
                let pending = self.pending_transition.take().ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: "committed transition without pending plan".to_owned(),
                    }
                })?;
                if pending.plan_digest != plan_digest {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "committed transition plan_digest mismatch".to_owned(),
                    });
                }
                if new_epoch != self.activation_epoch.saturating_add(1) {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: format!(
                            "non-monotonic epoch on commit: expected {}, observed {new_epoch}",
                            self.activation_epoch.saturating_add(1)
                        ),
                    });
                }

                // Move displaced active generation (if still Active) into RetainedRollback.
                if let Some(prev_snap) = self.active_snapshot.take() {
                    let prev_id = prev_snap.active.generation;
                    if prev_id != pending.target_generation
                        && let Some(prev_rec) = self.generations.get_mut(&prev_id)
                        && prev_rec.stage == ModelGenerationStage::Active
                    {
                        prev_rec.stage = ModelGenerationStage::RetainedRollback;
                        self.rollback_stack.retain(|g| g != &prev_id);
                        self.rollback_stack.push(prev_id);
                        while self.rollback_stack.len() > self.policy.max_rollback_depth {
                            self.rollback_stack.remove(0);
                        }
                    }
                }

                // Remove target from rollback stack if this was a rollback, and activate atomically.
                self.rollback_stack
                    .retain(|g| g != &pending.target_generation);
                let target_descriptor = {
                    let target_rec = self
                        .generations
                        .get_mut(&pending.target_generation)
                        .ok_or_else(|| LifecycleError::JournalCorrupt {
                            detail: format!(
                                "commit target '{}' missing from registry",
                                pending.target_generation
                            ),
                        })?;
                    target_rec.stage = ModelGenerationStage::Active;
                    target_rec.descriptor.clone()
                };

                self.activation_epoch = new_epoch;
                let rollback_target = self.latest_eligible_rollback_target();
                let snapshot_digest = ActiveModelSnapshot::compute_digest(
                    new_epoch,
                    &target_descriptor,
                    rollback_target.as_ref(),
                    now,
                    pending.contract_basis_digest,
                    &pending.authority.principal,
                );
                self.active_snapshot = Some(ActiveModelSnapshot {
                    activation_epoch: new_epoch,
                    active: target_descriptor,
                    rollback_target,
                    activated_at: now,
                    contract_basis_digest: pending.contract_basis_digest,
                    authority_principal: pending.authority.principal,
                    snapshot_digest,
                });
                match pending.kind {
                    TransitionKind::Activate => {
                        self.metrics.activations = self.metrics.activations.saturating_add(1);
                    }
                    TransitionKind::Rollback => {
                        self.metrics.rollbacks = self.metrics.rollbacks.saturating_add(1);
                    }
                }
            }
            LifecycleJournalEvent::TransitionReconciledNotCommitted { plan_digest, .. } => {
                let Some(pending) = &self.pending_transition else {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "reconciled-not-committed without pending plan".to_owned(),
                    });
                };
                if pending.plan_digest != plan_digest {
                    return Err(LifecycleError::JournalCorrupt {
                        detail: "reconciled-not-committed plan_digest mismatch".to_owned(),
                    });
                }
                self.pending_transition = None;
            }
            LifecycleJournalEvent::Quarantined { generation, reason } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("quarantined unknown generation '{generation}'"),
                    }
                })?;
                rec.stage = ModelGenerationStage::Quarantined;
                rec.terminal_or_quarantine_reason = Some(reason);
                self.rollback_stack.retain(|g| g != &generation);
                if self
                    .active_snapshot
                    .as_ref()
                    .is_some_and(|s| s.active.generation == generation)
                {
                    // Fail closed: active generation quarantined -> no active generation until
                    // explicit authorized rollback commits.
                    self.active_snapshot = None;
                }
                if self.pending_transition.as_ref().is_some_and(|p| {
                    p.target_generation == generation
                        && matches!(p.state, PendingTransitionState::Prepared)
                }) {
                    self.pending_transition = None;
                }
                self.metrics.quarantines = self.metrics.quarantines.saturating_add(1);
            }
            LifecycleJournalEvent::Revoked {
                generation,
                authority,
                reason,
                new_min_sequence_order,
            } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("revoked unknown generation '{generation}'"),
                    }
                })?;
                rec.stage = ModelGenerationStage::Revoked;
                rec.terminal_or_quarantine_reason = Some(reason);
                if let Some(fence) = authority.lease_fence {
                    self.highest_lease_fence = self.highest_lease_fence.max(fence);
                }
                self.min_allowed_sequence_order =
                    self.min_allowed_sequence_order.max(new_min_sequence_order);
                self.rollback_stack.retain(|g| g != &generation);
                if self
                    .active_snapshot
                    .as_ref()
                    .is_some_and(|s| s.active.generation == generation)
                {
                    self.active_snapshot = None;
                }
                if self.pending_transition.as_ref().is_some_and(|p| {
                    p.target_generation == generation
                        && matches!(p.state, PendingTransitionState::Prepared)
                }) {
                    self.pending_transition = None;
                }
                self.metrics.revocations = self.metrics.revocations.saturating_add(1);
            }
            LifecycleJournalEvent::Retired {
                generation,
                authority,
            } => {
                let rec = self.generations.get_mut(&generation).ok_or_else(|| {
                    LifecycleError::JournalCorrupt {
                        detail: format!("retired unknown generation '{generation}'"),
                    }
                })?;
                rec.stage = ModelGenerationStage::Retired;
                if let Some(fence) = authority.lease_fence {
                    self.highest_lease_fence = self.highest_lease_fence.max(fence);
                }
                self.rollback_stack.retain(|g| g != &generation);
                self.metrics.retirements = self.metrics.retirements.saturating_add(1);
            }
        }
        Ok(())
    }
}

fn validate_model_generation_id(generation: &ModelGeneration) -> Result<(), LifecycleError> {
    let raw = generation.as_str();
    if raw.trim().is_empty() || raw.len() > MAX_LABEL_BYTES || raw.chars().any(char::is_control) {
        return Err(LifecycleError::InvalidInput {
            field: "generation",
            detail: "must be non-empty printable ASCII/UTF-8 within bound".to_owned(),
        });
    }
    let lower = raw.to_ascii_lowercase();
    if lower
        .split([':', '/', '-', '_', '.'])
        .any(|token| token == "latest")
    {
        return Err(LifecycleError::ForbiddenLatestAlias {
            raw: raw.to_owned(),
        });
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), LifecycleError> {
    if value.trim().is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(LifecycleError::InvalidInput {
            field,
            detail: format!("must be 1..={MAX_LABEL_BYTES} non-control bytes"),
        });
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), LifecycleError> {
    if reason.trim().is_empty()
        || reason.len() > MAX_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        return Err(LifecycleError::InvalidInput {
            field: "reason",
            detail: format!("must be 1..={MAX_REASON_BYTES} non-control bytes"),
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: ContentDigest) -> Result<(), LifecycleError> {
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(LifecycleError::InvalidInput {
            field,
            detail: "must be a non-zero SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn zero_digest() -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])
}

const fn pressure_to_tag(pressure: ResourcePressure) -> u8 {
    match pressure {
        ResourcePressure::Nominal => 1,
        ResourcePressure::Elevated => 2,
        ResourcePressure::Constrained => 3,
        ResourcePressure::Critical => 4,
    }
}

const fn pressure_from_tag(tag: u8) -> Result<ResourcePressure, ContractError> {
    match tag {
        1 => Ok(ResourcePressure::Nominal),
        2 => Ok(ResourcePressure::Elevated),
        3 => Ok(ResourcePressure::Constrained),
        4 => Ok(ResourcePressure::Critical),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

const fn ceil_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 || numerator == 0 {
        return 0;
    }
    let scaled = (numerator as u128).saturating_mul(PPM_SCALE as u128);
    let denom = denominator as u128;
    let ceil = scaled.saturating_add(denom.saturating_sub(1)) / denom;
    if ceil > PPM_SCALE as u128 {
        PPM_SCALE as u32
    } else {
        ceil as u32
    }
}

fn digest_outputs(outputs: &[(String, ContentDigest)]) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("model_invocation_outputs.v1");
    enc.u64(outputs.len() as u64);
    for (name, digest) in outputs {
        enc.text(name);
        enc.digest(*digest);
    }
    ContentDigest::sha256(&enc.finish())
}

fn classify_shadow_outcome(
    candidate: &ModelReceipt,
    baseline: Option<&ModelReceipt>,
) -> ShadowOutcome {
    match &candidate.outcome {
        InvocationOutcome::Quarantined { reason } => ShadowOutcome::CandidateQuarantined {
            reason: clamp_reason(reason),
        },
        InvocationOutcome::Abstained { node_id, op, .. } => ShadowOutcome::CandidateAbstained {
            node_id: clamp_label(node_id),
            op: clamp_label(op),
        },
        InvocationOutcome::Completed {
            outputs: cand_outputs,
            ..
        } => match baseline {
            None => ShadowOutcome::Matched,
            Some(base) => match &base.outcome {
                InvocationOutcome::Completed {
                    outputs: base_outputs,
                    ..
                } => {
                    let cand_digest = digest_outputs(cand_outputs);
                    let base_digest = digest_outputs(base_outputs);
                    if cand_digest == base_digest {
                        ShadowOutcome::Matched
                    } else {
                        ShadowOutcome::Diverged {
                            candidate_outputs_digest: cand_digest,
                            baseline_outputs_digest: base_digest,
                        }
                    }
                }
                InvocationOutcome::Abstained { .. } | InvocationOutcome::Quarantined { .. } => {
                    ShadowOutcome::BaselineUnavailable
                }
            },
        },
    }
}

fn clamp_reason(text: &str) -> String {
    let sanitized: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if sanitized.len() <= MAX_REASON_BYTES {
        sanitized
    } else {
        let mut end = MAX_REASON_BYTES;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_owned()
    }
}

fn clamp_label(text: &str) -> String {
    let sanitized: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if sanitized.len() <= MAX_LABEL_BYTES {
        sanitized
    } else {
        let mut end = MAX_LABEL_BYTES;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_owned()
    }
}
