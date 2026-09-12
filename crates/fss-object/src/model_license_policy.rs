#![forbid(unsafe_code)]
//! Pure-Rust model license and operational profile policy checker (FSS-075 / fss-x4a.14.6).
//!
//! Provides deterministic fail-closed policy validation for model packages:
//! - Evaluates model licenses against target operational profiles (`ResearchOnly`,
//!   `InternalEvaluation`, `CommercialProduction`, `SurveillanceMonitoring`, or custom profiles).
//! - Rejects missing, empty, or whitespace-only licenses and profiles.
//! - Rejects unknown licenses not present in the admitted license set.
//! - Evaluates compound SPDX license expressions (`AND`, `OR`, `WITH`), enforcing that all
//!   conjunctions satisfy operational profile constraints and at least one disjunction branch is admitted.
//! - Rejects expired licenses where an expiry timestamp is in the past relative to the evaluation clock,
//!   and fails closed if an expiry restriction is present but no evaluation time is configured.
//! - Rejects any package whose license terms or restrictions conflict with the requested operational
//!   profile (e.g. non-commercial or evaluation-only terms in a commercial production profile;
//!   surveillance prohibitions in a surveillance monitoring profile).
//! - Enforces the invariant that **unknown license terms are never treated as permissive**: any
//!   unrecognized restriction or clause fails closed immediately.
//! - Enforces typed restriction categories (`Permissive`, `NonCommercial`, `SurveillanceForbidden`,
//!   `MilitaryForbidden`, `CustomRestricted`) to prevent registered custom terms from becoming permissive.
//! - Refuses surveillance-incompatible licenses (e.g. `OpenRAIL-M`, `CreativeML-OpenRAIL-M`) when
//!   evaluating under surveillance operational profiles.
//! - Rejects unapproved licenses (`use_approved == false`) and missing legal text digests when
//!   required by policy.
//! - Enforces strict hard bounds on profile names, policy names, allowed license counts, forbidden
//!   restriction counts, and known term counts.
//! - Returns a deterministic, verified [`ModelLicenseDecision`] receipt binding manifest identity
//!   via the root canonical domain tag (`fss.canonical.v1`).

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{CanonicalEncoder, ContentDigest, ContractError, ModelGeneration, TimestampNs};

use crate::model_manifest::{ModelId, ModelLicenseRecord, ModelManifestError, ModelManifestV1};

/// Maximum byte length for a policy name.
pub const MAX_POLICY_NAME_LEN: usize = 64;

/// Minimum byte length for a policy name.
pub const MIN_POLICY_NAME_LEN: usize = 1;

/// Maximum byte length for an operational profile name string.
pub const MAX_PROFILE_NAME_LEN: usize = 64;

/// Minimum byte length for an operational profile name string.
pub const MIN_PROFILE_NAME_LEN: usize = 1;

/// Maximum byte length for an individual license restriction or term.
pub const MAX_LICENSE_TERM_LEN: usize = 256;

/// Maximum allowed number of permitted licenses in a single policy configuration.
pub const MAX_POLICY_ALLOWED_LICENSES_COUNT: usize = 256;

/// Maximum allowed number of forbidden restrictions in a single policy configuration.
pub const MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT: usize = 256;

/// Maximum allowed number of recognized known terms in a single policy configuration.
pub const MAX_POLICY_KNOWN_TERMS_COUNT: usize = 256;

/// Prefix for timestamps defining exclusive license validity expiration (`valid_until:<ns>`).
pub const RESTRICTION_VALID_UNTIL_PREFIX: &str = "valid_until:";

/// Prefix for timestamps defining exclusive license validity expiration (`expires_at:<ns>`).
pub const RESTRICTION_EXPIRES_AT_PREFIX: &str = "expires_at:";

/// Category of a license restriction term, used for semantic profile compatibility checking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RestrictionCategory {
    /// Permissive restriction that does not restrict operational use profile (e.g. attribution, notice).
    Permissive,
    /// Restriction prohibiting commercial production or use (e.g. non-commercial, research-only).
    NonCommercial,
    /// Restriction prohibiting surveillance, facial recognition, or biometric processing.
    SurveillanceForbidden,
    /// Restriction prohibiting military or weapon applications.
    MilitaryForbidden,
    /// Custom restricted term requiring explicit operational profile clearance.
    CustomRestricted,
}

/// Operational profile representing the intended purpose and environment for model execution.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModelUseProfile {
    /// Internal research and development; strictly non-production.
    ResearchOnly,
    /// Internal offline or staged evaluation and benchmarking.
    InternalEvaluation,
    /// Commercial production deployment for general inference.
    CommercialProduction,
    /// Live physical surveillance and sensor monitoring.
    SurveillanceMonitoring,
    /// Custom named operational profile.
    Custom(String),
}

impl ModelUseProfile {
    /// Parses an operational profile identifier from string, validating structural bounds.
    pub fn parse(s: &str) -> Result<Self, ModelLicensePolicyError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ModelLicensePolicyError::MissingProfile);
        }
        if s.len() > MAX_PROFILE_NAME_LEN {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "profile_name_len",
                limit: MAX_PROFILE_NAME_LEN,
                actual: s.len(),
            });
        }
        match s {
            "research_only" => Ok(Self::ResearchOnly),
            "internal_evaluation" => Ok(Self::InternalEvaluation),
            "commercial_production" => Ok(Self::CommercialProduction),
            "surveillance_monitoring" => Ok(Self::SurveillanceMonitoring),
            custom => {
                for b in custom.bytes() {
                    if !b.is_ascii_alphanumeric() && b != b'_' && b != b'-' && b != b'.' {
                        return Err(ModelLicensePolicyError::InvalidProfileIdentifier {
                            name: custom.to_string(),
                        });
                    }
                }
                Ok(Self::Custom(custom.to_string()))
            }
        }
    }

    /// Returns the string slice representation of the profile.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ResearchOnly => "research_only",
            Self::InternalEvaluation => "internal_evaluation",
            Self::CommercialProduction => "commercial_production",
            Self::SurveillanceMonitoring => "surveillance_monitoring",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for ModelUseProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed errors returned by the model license and profile policy checker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelLicensePolicyError {
    /// License specification is missing or empty.
    MissingLicense,
    /// Profile specification is missing or empty.
    MissingProfile,
    /// Required license legal text digest is missing.
    MissingLicenseTextDigest,
    /// Evaluation time is required to evaluate expiry restriction, but was not configured.
    MissingEvaluationTimeForExpiry {
        /// Offending restriction string.
        restriction: String,
    },
    /// Invalid operational profile identifier syntax.
    InvalidProfileIdentifier {
        /// Offending profile name.
        name: String,
    },
    /// License is unknown or not admitted in the policy's allowed license registry.
    UnknownLicense {
        /// Unadmitted SPDX identifier or license identity.
        spdx_or_identity: String,
    },
    /// License restriction or clause is unrecognized; unknown terms are never treated as permissive.
    UnknownLicenseTerm {
        /// Unrecognized restriction term.
        term: String,
    },
    /// License has expired relative to the evaluation clock.
    LicenseExpired {
        /// Expiry timestamp from the license.
        expiry: TimestampNs,
        /// Evaluation timestamp against which expiry was checked.
        evaluated_at: TimestampNs,
    },
    /// Expiry timestamp restriction has an invalid integer or format string.
    InvalidExpiryFormat {
        /// Raw unparseable restriction string.
        raw: String,
    },
    /// Model license has not been explicitly approved for use (`use_approved == false`).
    UseNotApproved,
    /// License terms or restrictions explicitly forbid the requested operational use profile.
    NotPermittedForUse {
        /// Requested operational use profile.
        requested_profile: ModelUseProfile,
        /// Conflicting restriction found in the license.
        conflicting_restriction: String,
    },
    /// License identity is fundamentally incompatible with the requested profile.
    LicenseIncompatibleWithProfile {
        /// Incompatible license SPDX or identity.
        spdx_or_identity: String,
        /// Requested operational use profile.
        requested_profile: ModelUseProfile,
    },
    /// A restriction explicitly forbidden by policy was present in the license.
    ForbiddenRestriction {
        /// Forbidden restriction term.
        restriction: String,
    },
    /// A configured resource bound or limit was strictly exceeded.
    BoundExceeded {
        /// Name of the bound.
        bound: &'static str,
        /// Maximum allowed limit.
        limit: usize,
        /// Observed length or count.
        actual: usize,
    },
    /// Model manifest error during policy validation.
    Manifest(ModelManifestError),
    /// Underlying contract error.
    Contract(ContractError),
}

impl fmt::Display for ModelLicensePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLicense => f.write_str("model license specification is missing or empty"),
            Self::MissingProfile => {
                f.write_str("operational profile specification is missing or empty")
            }
            Self::MissingLicenseTextDigest => {
                f.write_str("required license legal text digest is missing")
            }
            Self::MissingEvaluationTimeForExpiry { restriction } => {
                write!(
                    f,
                    "evaluation time is required to evaluate expiry restriction '{restriction}', but none was configured"
                )
            }
            Self::InvalidProfileIdentifier { name } => {
                write!(f, "invalid operational profile identifier: '{name}'")
            }
            Self::UnknownLicense { spdx_or_identity } => {
                write!(
                    f,
                    "model license '{spdx_or_identity}' is unknown or not admitted"
                )
            }
            Self::UnknownLicenseTerm { term } => {
                write!(
                    f,
                    "unknown license term '{term}' is never treated as permissive"
                )
            }
            Self::LicenseExpired {
                expiry,
                evaluated_at,
            } => {
                write!(
                    f,
                    "model license expired at ns {} (evaluated at ns {})",
                    expiry.0, evaluated_at.0
                )
            }
            Self::InvalidExpiryFormat { raw } => {
                write!(f, "invalid license expiry timestamp format: '{raw}'")
            }
            Self::UseNotApproved => f.write_str("model license has not been approved for use"),
            Self::NotPermittedForUse {
                requested_profile,
                conflicting_restriction,
            } => {
                write!(
                    f,
                    "restriction '{conflicting_restriction}' forbids requested profile '{requested_profile}'"
                )
            }
            Self::LicenseIncompatibleWithProfile {
                spdx_or_identity,
                requested_profile,
            } => {
                write!(
                    f,
                    "license '{spdx_or_identity}' is incompatible with requested profile '{requested_profile}'"
                )
            }
            Self::ForbiddenRestriction { restriction } => {
                write!(
                    f,
                    "restriction '{restriction}' is strictly forbidden by policy"
                )
            }
            Self::BoundExceeded {
                bound,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "policy bound '{bound}' exceeded: limit {limit}, actual {actual}"
                )
            }
            Self::Manifest(err) => write!(f, "model manifest error: {err}"),
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl Error for ModelLicensePolicyError {}

impl From<ContractError> for ModelLicensePolicyError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<ModelManifestError> for ModelLicensePolicyError {
    fn from(err: ModelManifestError) -> Self {
        Self::Manifest(err)
    }
}

/// Deterministic receipt and record emitted upon successful policy qualification of a model license.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelLicenseDecision {
    admitted_spdx: String,
    target_profile: ModelUseProfile,
    evaluated_at: Option<TimestampNs>,
    verified_restrictions_count: usize,
    model_id: Option<ModelId>,
    generation: Option<ModelGeneration>,
    manifest_digest: Option<ContentDigest>,
    decision_digest: ContentDigest,
}

impl ModelLicenseDecision {
    /// Admitted SPDX license identifier.
    pub fn admitted_spdx(&self) -> &str {
        &self.admitted_spdx
    }

    /// Target operational use profile for which the license was admitted.
    pub const fn target_profile(&self) -> &ModelUseProfile {
        &self.target_profile
    }

    /// Optional evaluation timestamp against which expiry was validated.
    pub const fn evaluated_at(&self) -> Option<TimestampNs> {
        self.evaluated_at
    }

    /// Number of verified, admitted restrictions in the license record.
    pub const fn verified_restrictions_count(&self) -> usize {
        self.verified_restrictions_count
    }

    /// Model ID bound to this decision, if evaluated against a manifest.
    pub const fn model_id(&self) -> Option<&ModelId> {
        self.model_id.as_ref()
    }

    /// Model generation bound to this decision, if evaluated against a manifest.
    pub const fn generation(&self) -> Option<&ModelGeneration> {
        self.generation.as_ref()
    }

    /// Manifest digest bound to this decision, if evaluated against a manifest.
    pub const fn manifest_digest(&self) -> Option<ContentDigest> {
        self.manifest_digest
    }

    /// Cryptographic SHA-256 digest binding the full decision tuple.
    pub const fn decision_digest(&self) -> ContentDigest {
        self.decision_digest
    }
}

/// Context for binding manifest identity into a license qualification decision.
struct ManifestDecisionContext<'a> {
    model_id: &'a ModelId,
    generation: &'a ModelGeneration,
    manifest_digest: ContentDigest,
}

/// Bounded deterministic policy checker for model licenses and operational profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelLicensePolicy {
    policy_name: String,
    target_profile: ModelUseProfile,
    evaluation_time: Option<TimestampNs>,
    allowed_licenses: BTreeSet<String>,
    forbidden_restrictions: BTreeSet<String>,
    known_restrictions: BTreeSet<String>,
    term_categories: BTreeMap<String, RestrictionCategory>,
    require_use_approved: bool,
    require_text_digest: bool,
}

impl ModelLicensePolicy {
    /// Constructs a new policy with an empty allowed license set and default known restriction terms.
    pub fn new(
        policy_name: impl Into<String>,
        target_profile: ModelUseProfile,
    ) -> Result<Self, ModelLicensePolicyError> {
        let name = policy_name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "policy_name_len",
                limit: MAX_POLICY_NAME_LEN,
                actual: 0,
            });
        }
        if name.len() > MAX_POLICY_NAME_LEN {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "policy_name_len",
                limit: MAX_POLICY_NAME_LEN,
                actual: name.len(),
            });
        }

        let mut known = BTreeSet::new();
        let mut categories = BTreeMap::new();
        populate_standard_known_restrictions(&mut known, &mut categories);

        Ok(Self {
            policy_name: name,
            target_profile,
            evaluation_time: None,
            allowed_licenses: BTreeSet::new(),
            forbidden_restrictions: BTreeSet::new(),
            known_restrictions: known,
            term_categories: categories,
            require_use_approved: true,
            require_text_digest: false,
        })
    }

    /// Constructs a default policy configured for a given target operational profile.
    ///
    /// Pre-populates standard open source licenses (`Apache-2.0`, `MIT`, `BSD-2-Clause`,
    /// `BSD-3-Clause`, `ISC`, `CC-BY-4.0`, `CC0-1.0`). Note that `OpenRAIL-M` and
    /// `CreativeML-OpenRAIL-M` are excluded from surveillance monitoring profiles because
    /// their terms prohibit biometric surveillance and facial recognition.
    pub fn default_for_profile(target_profile: ModelUseProfile) -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert("Apache-2.0".to_string());
        allowed.insert("MIT".to_string());
        allowed.insert("BSD-2-Clause".to_string());
        allowed.insert("BSD-3-Clause".to_string());
        allowed.insert("ISC".to_string());
        allowed.insert("CC-BY-4.0".to_string());
        allowed.insert("CC0-1.0".to_string());

        let norm_profile = normalize_term(target_profile.as_str());
        if target_profile != ModelUseProfile::SurveillanceMonitoring
            && !norm_profile.contains("surveillance")
        {
            allowed.insert("OpenRAIL-M".to_string());
            allowed.insert("CreativeML-OpenRAIL-M".to_string());
        }

        let mut known = BTreeSet::new();
        let mut categories = BTreeMap::new();
        populate_standard_known_restrictions(&mut known, &mut categories);

        Self {
            policy_name: format!("default-{}", target_profile.as_str()),
            target_profile,
            evaluation_time: None,
            allowed_licenses: allowed,
            forbidden_restrictions: BTreeSet::new(),
            known_restrictions: known,
            term_categories: categories,
            require_use_approved: true,
            require_text_digest: false,
        }
    }

    /// Returns the policy name.
    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Returns the target operational profile.
    pub const fn target_profile(&self) -> &ModelUseProfile {
        &self.target_profile
    }

    /// Returns the configured evaluation timestamp, if any.
    pub const fn evaluation_time(&self) -> Option<TimestampNs> {
        self.evaluation_time
    }

    /// Returns the set of admitted licenses.
    pub const fn allowed_licenses(&self) -> &BTreeSet<String> {
        &self.allowed_licenses
    }

    /// Returns the set of forbidden restrictions.
    pub const fn forbidden_restrictions(&self) -> &BTreeSet<String> {
        &self.forbidden_restrictions
    }

    /// Returns the set of recognized known restriction terms.
    pub const fn known_restrictions(&self) -> &BTreeSet<String> {
        &self.known_restrictions
    }

    /// Returns the map of restriction categories for known terms.
    pub const fn term_categories(&self) -> &BTreeMap<String, RestrictionCategory> {
        &self.term_categories
    }

    /// Whether approved license status is required.
    pub const fn require_use_approved(&self) -> bool {
        self.require_use_approved
    }

    /// Whether license legal text digest is required.
    pub const fn require_text_digest(&self) -> bool {
        self.require_text_digest
    }

    /// Sets the target operational profile.
    pub fn set_target_profile(&mut self, profile: ModelUseProfile) {
        self.target_profile = profile;
    }

    /// Sets the reference evaluation timestamp against which expiry is checked.
    pub fn set_evaluation_time(&mut self, time: Option<TimestampNs>) {
        self.evaluation_time = time;
    }

    /// Sets whether `use_approved == true` is strictly required.
    pub fn set_require_use_approved(&mut self, require: bool) {
        self.require_use_approved = require;
    }

    /// Sets whether `text_digest` is strictly required.
    pub fn set_require_text_digest(&mut self, require: bool) {
        self.require_text_digest = require;
    }

    /// Adds an admitted SPDX license identifier or proprietary identity to the policy.
    pub fn allow_license(
        &mut self,
        spdx: impl Into<String>,
    ) -> Result<(), ModelLicensePolicyError> {
        let spdx = spdx.into();
        if self.allowed_licenses.len() >= MAX_POLICY_ALLOWED_LICENSES_COUNT
            && !self.allowed_licenses.contains(&spdx)
        {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "allowed_licenses_count",
                limit: MAX_POLICY_ALLOWED_LICENSES_COUNT,
                actual: self.allowed_licenses.len() + 1,
            });
        }
        self.allowed_licenses.insert(spdx);
        Ok(())
    }

    /// Removes an admitted SPDX identifier or proprietary identity from the policy.
    pub fn disallow_license(&mut self, spdx: &str) {
        self.allowed_licenses.remove(spdx);
    }

    /// Adds a restriction that is strictly forbidden by policy.
    pub fn forbid_restriction(
        &mut self,
        restriction: impl Into<String>,
    ) -> Result<(), ModelLicensePolicyError> {
        let r = restriction.into();
        if self.forbidden_restrictions.len() >= MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT
            && !self.forbidden_restrictions.contains(&r)
        {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "forbidden_restrictions_count",
                limit: MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT,
                actual: self.forbidden_restrictions.len() + 1,
            });
        }
        self.forbidden_restrictions.insert(r);
        Ok(())
    }

    /// Removes a forbidden restriction from the policy.
    pub fn remove_forbidden_restriction(&mut self, restriction: &str) {
        self.forbidden_restrictions.remove(restriction);
    }

    /// Registers an additional recognized known restriction term in the policy, inferring its category.
    pub fn register_known_term(
        &mut self,
        term: impl Into<String>,
    ) -> Result<(), ModelLicensePolicyError> {
        let t = term.into();
        let norm = normalize_term(&t);
        let category = infer_restriction_category(&norm);
        self.register_known_term_with_category(t, category)
    }

    /// Registers an additional recognized known restriction term with an explicit category.
    pub fn register_known_term_with_category(
        &mut self,
        term: impl Into<String>,
        category: RestrictionCategory,
    ) -> Result<(), ModelLicensePolicyError> {
        let t = term.into();
        let norm = normalize_term(&t);
        if norm.is_empty() {
            return Err(ModelLicensePolicyError::UnknownLicenseTerm { term: t });
        }
        if t.len() > MAX_LICENSE_TERM_LEN {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "license_term_len",
                limit: MAX_LICENSE_TERM_LEN,
                actual: t.len(),
            });
        }
        if self.known_restrictions.len() >= MAX_POLICY_KNOWN_TERMS_COUNT
            && !self.known_restrictions.contains(&t)
        {
            return Err(ModelLicensePolicyError::BoundExceeded {
                bound: "known_terms_count",
                limit: MAX_POLICY_KNOWN_TERMS_COUNT,
                actual: self.known_restrictions.len() + 1,
            });
        }
        self.known_restrictions.insert(t);
        self.term_categories.insert(norm, category);
        Ok(())
    }

    /// Validates an immutable model manifest against the policy.
    pub fn check_manifest(
        &self,
        manifest: &ModelManifestV1,
    ) -> Result<ModelLicenseDecision, ModelLicensePolicyError> {
        let manifest_digest = manifest.manifest_digest()?;
        let ctx = ManifestDecisionContext {
            model_id: manifest.model_id(),
            generation: manifest.generation(),
            manifest_digest,
        };
        self.check_license_with_context(manifest.license(), Some(&ctx))
    }

    /// Validates a license record against the policy, returning a [`ModelLicenseDecision`] on success.
    pub fn check_license(
        &self,
        license: &ModelLicenseRecord,
    ) -> Result<ModelLicenseDecision, ModelLicensePolicyError> {
        self.check_license_with_context(license, None)
    }

    fn check_license_with_context(
        &self,
        license: &ModelLicenseRecord,
        manifest_ctx: Option<&ManifestDecisionContext<'_>>,
    ) -> Result<ModelLicenseDecision, ModelLicensePolicyError> {
        let spdx = license.spdx_or_identity().trim();
        if spdx.is_empty() {
            return Err(ModelLicensePolicyError::MissingLicense);
        }

        if self.require_use_approved && !license.is_use_approved() {
            return Err(ModelLicensePolicyError::UseNotApproved);
        }

        if self.require_text_digest && license.text_digest().is_none() {
            return Err(ModelLicensePolicyError::MissingLicenseTextDigest);
        }

        // Evaluate license expression / identity against allowed licenses and profile compatibility
        if let Some(expr) = parse_spdx(spdx) {
            self.eval_spdx_expr(&expr, spdx)?;
        } else {
            self.check_single_license(spdx)?;
        }

        // Validate individual restrictions
        for restriction in license.restrictions() {
            let normalized = normalize_term(restriction);
            if normalized.is_empty() {
                return Err(ModelLicensePolicyError::UnknownLicenseTerm {
                    term: restriction.clone(),
                });
            }

            // 1. Check forbidden restrictions configured on policy
            let is_forbidden = self
                .forbidden_restrictions
                .iter()
                .any(|f| f == restriction || normalize_term(f) == normalized);
            if is_forbidden {
                return Err(ModelLicensePolicyError::ForbiddenRestriction {
                    restriction: restriction.clone(),
                });
            }

            // 2. Expiry restriction checks
            if let Some(rest) = restriction.strip_prefix(RESTRICTION_VALID_UNTIL_PREFIX) {
                self.evaluate_expiry(restriction, rest)?;
                continue;
            }
            if let Some(rest) = restriction.strip_prefix(RESTRICTION_EXPIRES_AT_PREFIX) {
                self.evaluate_expiry(restriction, rest)?;
                continue;
            }
            if let Some(rest) = normalized.strip_prefix("valid_until:") {
                self.evaluate_expiry(restriction, rest)?;
                continue;
            }
            if let Some(rest) = normalized.strip_prefix("expires_at:") {
                self.evaluate_expiry(restriction, rest)?;
                continue;
            }

            // 3. Unknown terms are never treated as permissive
            let category = match self.term_categories.get(&normalized) {
                Some(&cat) => cat,
                None => {
                    if self.known_restrictions.contains(restriction)
                        || self
                            .known_restrictions
                            .iter()
                            .any(|k| normalize_term(k) == normalized)
                    {
                        infer_restriction_category(&normalized)
                    } else {
                        return Err(ModelLicensePolicyError::UnknownLicenseTerm {
                            term: restriction.clone(),
                        });
                    }
                }
            };

            // 4. Requested operational profile conflicts
            match &self.target_profile {
                ModelUseProfile::CommercialProduction => {
                    if category == RestrictionCategory::NonCommercial
                        || category == RestrictionCategory::CustomRestricted
                        || is_non_commercial_restriction(&normalized)
                    {
                        return Err(ModelLicensePolicyError::NotPermittedForUse {
                            requested_profile: ModelUseProfile::CommercialProduction,
                            conflicting_restriction: restriction.clone(),
                        });
                    }
                }
                ModelUseProfile::SurveillanceMonitoring => {
                    if category == RestrictionCategory::SurveillanceForbidden
                        || category == RestrictionCategory::NonCommercial
                        || category == RestrictionCategory::CustomRestricted
                        || is_surveillance_forbidden_restriction(&normalized)
                        || is_non_commercial_restriction(&normalized)
                    {
                        return Err(ModelLicensePolicyError::NotPermittedForUse {
                            requested_profile: ModelUseProfile::SurveillanceMonitoring,
                            conflicting_restriction: restriction.clone(),
                        });
                    }
                }
                ModelUseProfile::Custom(name) => {
                    let profile_norm = normalize_term(name);
                    let is_surv = profile_norm.contains("surveillance")
                        || profile_norm.contains("monitoring")
                        || profile_norm.contains("camera");
                    let is_comm =
                        profile_norm.contains("commercial") || profile_norm.contains("production");

                    if is_surv
                        && (category == RestrictionCategory::SurveillanceForbidden
                            || is_surveillance_forbidden_restriction(&normalized))
                    {
                        return Err(ModelLicensePolicyError::NotPermittedForUse {
                            requested_profile: self.target_profile.clone(),
                            conflicting_restriction: restriction.clone(),
                        });
                    }
                    if (is_comm || is_surv)
                        && (category == RestrictionCategory::NonCommercial
                            || is_non_commercial_restriction(&normalized))
                    {
                        return Err(ModelLicensePolicyError::NotPermittedForUse {
                            requested_profile: self.target_profile.clone(),
                            conflicting_restriction: restriction.clone(),
                        });
                    }
                }
                _ => {}
            }
        }

        // Construct canonical decision digest using CanonicalEncoder and root domain tag
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text("model_license_decision");
        encoder.text(spdx);
        encoder.text(self.target_profile.as_str());
        if let Some(time) = self.evaluation_time {
            encoder.bool(true);
            encoder.i128(time.0);
        } else {
            encoder.bool(false);
        }
        encoder.u64(license.restrictions().len() as u64);
        for r in license.restrictions() {
            encoder.text(r);
        }
        if let Some(ctx) = manifest_ctx {
            encoder.bool(true);
            encoder.text(ctx.model_id.as_str());
            encoder.text(ctx.generation.as_str());
            encoder.digest(ctx.manifest_digest);
        } else {
            encoder.bool(false);
        }
        let decision_digest = ContentDigest::sha256(&encoder.finish());

        Ok(ModelLicenseDecision {
            admitted_spdx: spdx.to_string(),
            target_profile: self.target_profile.clone(),
            evaluated_at: self.evaluation_time,
            verified_restrictions_count: license.restrictions().len(),
            model_id: manifest_ctx.map(|ctx| ctx.model_id.clone()),
            generation: manifest_ctx.map(|ctx| ctx.generation.clone()),
            manifest_digest: manifest_ctx.map(|ctx| ctx.manifest_digest),
            decision_digest,
        })
    }

    fn evaluate_expiry(&self, raw: &str, rest: &str) -> Result<(), ModelLicensePolicyError> {
        let eval_time = match self.evaluation_time {
            Some(t) => t,
            None => {
                return Err(ModelLicensePolicyError::MissingEvaluationTimeForExpiry {
                    restriction: raw.to_string(),
                });
            }
        };
        let expiry_ns =
            rest.parse::<i128>()
                .map_err(|_| ModelLicensePolicyError::InvalidExpiryFormat {
                    raw: raw.to_string(),
                })?;
        let expiry = TimestampNs(expiry_ns);
        if eval_time.0 >= expiry.0 {
            return Err(ModelLicensePolicyError::LicenseExpired {
                expiry,
                evaluated_at: eval_time,
            });
        }
        Ok(())
    }

    fn check_single_license(&self, name: &str) -> Result<(), ModelLicensePolicyError> {
        if !self.allowed_licenses.contains(name) {
            return Err(ModelLicensePolicyError::UnknownLicense {
                spdx_or_identity: name.to_string(),
            });
        }
        self.check_license_profile_compatibility(name)?;
        Ok(())
    }

    fn check_license_profile_compatibility(
        &self,
        spdx: &str,
    ) -> Result<(), ModelLicensePolicyError> {
        match &self.target_profile {
            ModelUseProfile::CommercialProduction => {
                if is_non_commercial_license(spdx) {
                    return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                        spdx_or_identity: spdx.to_string(),
                        requested_profile: ModelUseProfile::CommercialProduction,
                    });
                }
            }
            ModelUseProfile::SurveillanceMonitoring => {
                if is_non_commercial_license(spdx) || is_surveillance_forbidden_license(spdx) {
                    return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                        spdx_or_identity: spdx.to_string(),
                        requested_profile: ModelUseProfile::SurveillanceMonitoring,
                    });
                }
            }
            ModelUseProfile::Custom(name) => {
                let norm = normalize_term(name);
                let is_surv = norm.contains("surveillance")
                    || norm.contains("monitoring")
                    || norm.contains("camera");
                let is_comm = norm.contains("commercial") || norm.contains("production");

                if (is_surv || is_comm) && is_non_commercial_license(spdx) {
                    return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                        spdx_or_identity: spdx.to_string(),
                        requested_profile: self.target_profile.clone(),
                    });
                }
                if is_surv && is_surveillance_forbidden_license(spdx) {
                    return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                        spdx_or_identity: spdx.to_string(),
                        requested_profile: self.target_profile.clone(),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn eval_spdx_expr(&self, expr: &SpdxExpr, raw: &str) -> Result<(), ModelLicensePolicyError> {
        match expr {
            SpdxExpr::License(name) => self.check_single_license(name),
            SpdxExpr::WithException { license, exception } => {
                let full = format!("{license} WITH {exception}");
                if self.allowed_licenses.contains(&full) {
                    self.check_license_profile_compatibility(&full)
                } else {
                    self.check_single_license(license)
                }
            }
            SpdxExpr::And(items) => {
                for item in items {
                    self.eval_spdx_expr(item, raw)?;
                }
                Ok(())
            }
            SpdxExpr::Or(items) => {
                let mut last_err = None;
                let mut any_ok = false;
                for item in items {
                    match self.eval_spdx_expr(item, raw) {
                        Ok(()) => {
                            any_ok = true;
                            break;
                        }
                        Err(err) => {
                            last_err = Some(err);
                        }
                    }
                }
                if any_ok {
                    Ok(())
                } else {
                    Err(
                        last_err.unwrap_or_else(|| ModelLicensePolicyError::UnknownLicense {
                            spdx_or_identity: raw.to_string(),
                        }),
                    )
                }
            }
        }
    }
}

/// Normalizes restriction terms and identifiers to lowercase underscore format.
pub fn normalize_term(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_delim = false;
    for ch in s.trim().chars() {
        if ch == '_' || ch == '-' || ch.is_whitespace() {
            if !last_was_delim && !out.is_empty() {
                out.push('_');
                last_was_delim = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            last_was_delim = false;
        }
    }
    if out.ends_with('_') {
        out.pop();
    }
    out
}

fn populate_standard_known_restrictions(
    known: &mut BTreeSet<String>,
    categories: &mut BTreeMap<String, RestrictionCategory>,
) {
    let terms = [
        (
            "internal_evaluation_only",
            RestrictionCategory::NonCommercial,
        ),
        ("research_only", RestrictionCategory::NonCommercial),
        ("academic_only", RestrictionCategory::NonCommercial),
        ("no_commercial_use", RestrictionCategory::NonCommercial),
        ("non_commercial", RestrictionCategory::NonCommercial),
        ("non_commercial_only", RestrictionCategory::NonCommercial),
        ("not_for_commercial_use", RestrictionCategory::NonCommercial),
        (
            "no_surveillance",
            RestrictionCategory::SurveillanceForbidden,
        ),
        (
            "no_facial_recognition",
            RestrictionCategory::SurveillanceForbidden,
        ),
        ("no_biometrics", RestrictionCategory::SurveillanceForbidden),
        (
            "strictly_no_surveillance",
            RestrictionCategory::SurveillanceForbidden,
        ),
        ("no_military_use", RestrictionCategory::MilitaryForbidden),
        ("no_weapons", RestrictionCategory::MilitaryForbidden),
        (
            "no_unredacted_retention",
            RestrictionCategory::CustomRestricted,
        ),
        ("no_redistribution", RestrictionCategory::CustomRestricted),
        ("attribution_required", RestrictionCategory::Permissive),
        ("share_alike", RestrictionCategory::Permissive),
        (
            "notice_preservation_required",
            RestrictionCategory::Permissive,
        ),
    ];
    for (t, cat) in terms {
        known.insert(t.to_string());
        categories.insert(normalize_term(t), cat);
    }
}

fn infer_restriction_category(normalized: &str) -> RestrictionCategory {
    if is_surveillance_forbidden_restriction(normalized) {
        RestrictionCategory::SurveillanceForbidden
    } else if normalized.contains("military")
        || normalized.contains("weapon")
        || normalized.contains("defense")
        || normalized.contains("warfare")
    {
        RestrictionCategory::MilitaryForbidden
    } else if is_non_commercial_restriction(normalized) {
        RestrictionCategory::NonCommercial
    } else if normalized == "attribution_required"
        || normalized == "notice_preservation_required"
        || normalized == "share_alike"
        || normalized == "copyleft"
        || normalized == "source_code_disclosure"
    {
        RestrictionCategory::Permissive
    } else {
        RestrictionCategory::CustomRestricted
    }
}

fn is_surveillance_forbidden_license(spdx: &str) -> bool {
    let upper = spdx.to_ascii_uppercase();
    upper.contains("OPENRAIL") || upper.contains("CREATIVEML") || upper.contains("BIGCODE-OPENRAIL")
}

fn is_non_commercial_license(spdx: &str) -> bool {
    let norm = normalize_term(spdx);
    if norm.contains("non_commercial")
        || norm.contains("no_commercial")
        || norm.contains("research_only")
        || norm.contains("academic_only")
        || norm.contains("evaluation_only")
    {
        return true;
    }
    for part in norm.split(['_', '.']) {
        if part == "nc" {
            return true;
        }
    }
    false
}

fn is_non_commercial_restriction(normalized: &str) -> bool {
    matches!(
        normalized,
        "internal_evaluation_only"
            | "research_only"
            | "academic_only"
            | "no_commercial_use"
            | "non_commercial"
            | "non_commercial_only"
            | "not_for_commercial_use"
    ) || normalized.contains("non_commercial")
        || normalized.contains("no_commercial")
        || normalized.contains("research_only")
        || normalized.contains("academic_only")
}

fn is_surveillance_forbidden_restriction(normalized: &str) -> bool {
    matches!(
        normalized,
        "no_surveillance"
            | "no_facial_recognition"
            | "no_biometrics"
            | "strictly_no_surveillance"
            | "no_monitoring"
    ) || normalized.contains("surveillance")
        || normalized.contains("facial_recognition")
        || normalized.contains("biometric")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SpdxToken {
    Ident(String),
    And,
    Or,
    With,
    OpenParen,
    CloseParen,
}

fn tokenize_spdx(input: &str) -> Vec<SpdxToken> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
        } else if ch == '(' {
            tokens.push(SpdxToken::OpenParen);
            chars.next();
        } else if ch == ')' {
            tokens.push(SpdxToken::CloseParen);
            chars.next();
        } else {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '(' || c == ')' {
                    break;
                }
                word.push(c);
                chars.next();
            }
            if word.eq_ignore_ascii_case("AND") {
                tokens.push(SpdxToken::And);
            } else if word.eq_ignore_ascii_case("OR") {
                tokens.push(SpdxToken::Or);
            } else if word.eq_ignore_ascii_case("WITH") {
                tokens.push(SpdxToken::With);
            } else {
                tokens.push(SpdxToken::Ident(word));
            }
        }
    }
    tokens
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SpdxExpr {
    License(String),
    WithException { license: String, exception: String },
    And(Vec<SpdxExpr>),
    Or(Vec<SpdxExpr>),
}

struct SpdxParser<'a> {
    tokens: &'a [SpdxToken],
    pos: usize,
}

impl<'a> SpdxParser<'a> {
    const fn new(tokens: &'a [SpdxToken]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&'a SpdxToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a SpdxToken> {
        let tok = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(tok)
    }

    fn parse_or(&mut self) -> Option<SpdxExpr> {
        let first = self.parse_and()?;
        let mut items = vec![first];
        while let Some(SpdxToken::Or) = self.peek() {
            self.next();
            let next_item = self.parse_and()?;
            items.push(next_item);
        }
        if items.len() == 1 {
            items.pop()
        } else {
            Some(SpdxExpr::Or(items))
        }
    }

    fn parse_and(&mut self) -> Option<SpdxExpr> {
        let first = self.parse_with()?;
        let mut items = vec![first];
        while let Some(SpdxToken::And) = self.peek() {
            self.next();
            let next_item = self.parse_with()?;
            items.push(next_item);
        }
        if items.len() == 1 {
            items.pop()
        } else {
            Some(SpdxExpr::And(items))
        }
    }

    fn parse_with(&mut self) -> Option<SpdxExpr> {
        let expr = self.parse_primary()?;
        if let Some(SpdxToken::With) = self.peek() {
            self.next();
            match self.next()? {
                SpdxToken::Ident(exception) => {
                    let lic_name = match expr {
                        SpdxExpr::License(name) => name,
                        _ => return None,
                    };
                    Some(SpdxExpr::WithException {
                        license: lic_name,
                        exception: exception.clone(),
                    })
                }
                _ => None,
            }
        } else {
            Some(expr)
        }
    }

    fn parse_primary(&mut self) -> Option<SpdxExpr> {
        match self.next()? {
            SpdxToken::Ident(name) => Some(SpdxExpr::License(name.clone())),
            SpdxToken::OpenParen => {
                let inner = self.parse_or()?;
                if let Some(SpdxToken::CloseParen) = self.next() {
                    Some(inner)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn parse_spdx(input: &str) -> Option<SpdxExpr> {
    let tokens = tokenize_spdx(input);
    if tokens.is_empty() {
        return None;
    }
    let mut parser = SpdxParser::new(&tokens);
    let expr = parser.parse_or()?;
    if parser.pos == parser.tokens.len() {
        Some(expr)
    } else {
        None
    }
}
