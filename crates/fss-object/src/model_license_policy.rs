#![forbid(unsafe_code)]
//! Pure-Rust model license and operational profile policy checker (FSS-075 / fss-x4a.14.6).
//!
//! Provides deterministic fail-closed policy validation for model packages:
//! - Evaluates model licenses against target operational profiles (`ResearchOnly`,
//!   `InternalEvaluation`, `CommercialProduction`, `SurveillanceMonitoring`, or custom profiles).
//! - Rejects missing, empty, or whitespace-only licenses and profiles.
//! - Rejects unknown licenses not present in the admitted license set.
//! - Rejects expired licenses where an expiry timestamp is in the past relative to the evaluation
//!   clock.
//! - Rejects any package whose license terms or restrictions conflict with the requested operational
//!   profile (e.g. non-commercial or evaluation-only terms in a commercial production profile;
//!   surveillance prohibitions in a surveillance monitoring profile).
//! - Enforces the invariant that **unknown license terms are never treated as permissive**: any
//!   unrecognized restriction or clause fails closed immediately.
//! - Rejects unapproved licenses (`use_approved == false`) and missing legal text digests when
//!   required by policy.
//! - Enforces strict hard bounds on profile names, policy names, allowed license counts, forbidden
//!   restriction counts, and known term counts.
//! - Returns a deterministic, verified [`ModelLicenseDecision`] receipt upon success.

use core::fmt;
use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{ContentDigest, ContractError, TimestampNs};

use crate::model_manifest::{ModelLicenseRecord, ModelManifestV1};

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
    /// Underlying contract error.
    Contract(ContractError),
}

impl fmt::Display for ModelLicensePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLicense => f.write_str("model license specification is missing or empty"),
            Self::MissingProfile => f.write_str("operational profile specification is missing or empty"),
            Self::MissingLicenseTextDigest => {
                f.write_str("required license legal text digest is missing")
            }
            Self::InvalidProfileIdentifier { name } => {
                write!(f, "invalid operational profile identifier: '{name}'")
            }
            Self::UnknownLicense { spdx_or_identity } => {
                write!(f, "model license '{spdx_or_identity}' is unknown or not admitted")
            }
            Self::UnknownLicenseTerm { term } => {
                write!(f, "unknown license term '{term}' is never treated as permissive")
            }
            Self::LicenseExpired { expiry, evaluated_at } => {
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
                write!(f, "restriction '{restriction}' is strictly forbidden by policy")
            }
            Self::BoundExceeded { bound, limit, actual } => {
                write!(f, "policy bound '{bound}' exceeded: limit {limit}, actual {actual}")
            }
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

/// Deterministic receipt and record emitted upon successful policy qualification of a model license.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelLicenseDecision {
    admitted_spdx: String,
    target_profile: ModelUseProfile,
    evaluated_at: Option<TimestampNs>,
    verified_restrictions_count: usize,
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

    /// Cryptographic SHA-256 digest binding the full decision tuple.
    pub const fn decision_digest(&self) -> ContentDigest {
        self.decision_digest
    }
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
        populate_standard_known_restrictions(&mut known);

        Ok(Self {
            policy_name: name,
            target_profile,
            evaluation_time: None,
            allowed_licenses: BTreeSet::new(),
            forbidden_restrictions: BTreeSet::new(),
            known_restrictions: known,
            require_use_approved: true,
            require_text_digest: false,
        })
    }

    /// Constructs a default policy configured for a given target operational profile.
    ///
    /// Pre-populates standard open source and model licenses (`Apache-2.0`, `MIT`, `BSD-2-Clause`,
    /// `BSD-3-Clause`, `ISC`, `CC-BY-4.0`, `CC0-1.0`, `OpenRAIL-M`, `CreativeML-OpenRAIL-M`).
    pub fn default_for_profile(target_profile: ModelUseProfile) -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert("Apache-2.0".to_string());
        allowed.insert("MIT".to_string());
        allowed.insert("BSD-2-Clause".to_string());
        allowed.insert("BSD-3-Clause".to_string());
        allowed.insert("ISC".to_string());
        allowed.insert("CC-BY-4.0".to_string());
        allowed.insert("CC0-1.0".to_string());
        allowed.insert("OpenRAIL-M".to_string());
        allowed.insert("CreativeML-OpenRAIL-M".to_string());

        let mut known = BTreeSet::new();
        populate_standard_known_restrictions(&mut known);

        Self {
            policy_name: format!("default-{}", target_profile.as_str()),
            target_profile,
            evaluation_time: None,
            allowed_licenses: allowed,
            forbidden_restrictions: BTreeSet::new(),
            known_restrictions: known,
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
    pub fn allow_license(&mut self, spdx: impl Into<String>) -> Result<(), ModelLicensePolicyError> {
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

    /// Registers an additional recognized known restriction term in the policy.
    pub fn register_known_term(
        &mut self,
        term: impl Into<String>,
    ) -> Result<(), ModelLicensePolicyError> {
        let t = term.into();
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
        Ok(())
    }

    /// Validates an immutable model manifest against the policy.
    pub fn check_manifest(
        &self,
        manifest: &ModelManifestV1,
    ) -> Result<ModelLicenseDecision, ModelLicensePolicyError> {
        self.check_license(manifest.license())
    }

    /// Validates a license record against the policy, returning a [`ModelLicenseDecision`] on success.
    pub fn check_license(
        &self,
        license: &ModelLicenseRecord,
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

        if !self.allowed_licenses.contains(spdx) {
            return Err(ModelLicensePolicyError::UnknownLicense {
                spdx_or_identity: license.spdx_or_identity().to_string(),
            });
        }

        // Profile-level license identity compatibility
        match &self.target_profile {
            ModelUseProfile::CommercialProduction if is_non_commercial_license(spdx) => {
                return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                    spdx_or_identity: license.spdx_or_identity().to_string(),
                    requested_profile: ModelUseProfile::CommercialProduction,
                });
            }
            ModelUseProfile::SurveillanceMonitoring if is_non_commercial_license(spdx) => {
                return Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
                    spdx_or_identity: license.spdx_or_identity().to_string(),
                    requested_profile: ModelUseProfile::SurveillanceMonitoring,
                });
            }
            _ => {}
        }

        // Validate individual restrictions
        for restriction in license.restrictions() {
            // Check forbidden restrictions configured on the policy
            if self.forbidden_restrictions.contains(restriction) {
                return Err(ModelLicensePolicyError::ForbiddenRestriction {
                    restriction: restriction.clone(),
                });
            }

            // Expiry restriction checks
            if let Some(rest) = restriction.strip_prefix(RESTRICTION_VALID_UNTIL_PREFIX) {
                let expiry_ns = rest.parse::<i128>().map_err(|_| {
                    ModelLicensePolicyError::InvalidExpiryFormat {
                        raw: restriction.clone(),
                    }
                })?;
                let expiry = TimestampNs(expiry_ns);
                if let Some(eval_time) = self.evaluation_time
                    && eval_time.0 > expiry.0
                {
                    return Err(ModelLicensePolicyError::LicenseExpired {
                        expiry,
                        evaluated_at: eval_time,
                    });
                }
                continue;
            }
            if let Some(rest) = restriction.strip_prefix(RESTRICTION_EXPIRES_AT_PREFIX) {
                let expiry_ns = rest.parse::<i128>().map_err(|_| {
                    ModelLicensePolicyError::InvalidExpiryFormat {
                        raw: restriction.clone(),
                    }
                })?;
                let expiry = TimestampNs(expiry_ns);
                if let Some(eval_time) = self.evaluation_time
                    && eval_time.0 > expiry.0
                {
                    return Err(ModelLicensePolicyError::LicenseExpired {
                        expiry,
                        evaluated_at: eval_time,
                    });
                }
                continue;
            }

            // Unknown terms are never treated as permissive
            if !self.known_restrictions.contains(restriction) {
                return Err(ModelLicensePolicyError::UnknownLicenseTerm {
                    term: restriction.clone(),
                });
            }

            // Requested operational profile conflicts
            match &self.target_profile {
                ModelUseProfile::CommercialProduction
                    if is_non_commercial_restriction(restriction) =>
                {
                    return Err(ModelLicensePolicyError::NotPermittedForUse {
                        requested_profile: ModelUseProfile::CommercialProduction,
                        conflicting_restriction: restriction.clone(),
                    });
                }
                ModelUseProfile::SurveillanceMonitoring
                    if is_surveillance_forbidden_restriction(restriction)
                        || is_non_commercial_restriction(restriction) =>
                {
                    return Err(ModelLicensePolicyError::NotPermittedForUse {
                        requested_profile: ModelUseProfile::SurveillanceMonitoring,
                        conflicting_restriction: restriction.clone(),
                    });
                }
                _ => {}
            }
        }

        // Construct canonical decision digest
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(spdx.as_bytes());
        digest_input.push(0x00);
        digest_input.extend_from_slice(self.target_profile.as_str().as_bytes());
        digest_input.push(0x00);
        if let Some(time) = self.evaluation_time {
            digest_input.extend_from_slice(&time.0.to_le_bytes());
        }
        digest_input.push(0x00);
        for r in license.restrictions() {
            digest_input.extend_from_slice(r.as_bytes());
            digest_input.push(0x00);
        }
        let decision_digest = ContentDigest::sha256(&digest_input);

        Ok(ModelLicenseDecision {
            admitted_spdx: spdx.to_string(),
            target_profile: self.target_profile.clone(),
            evaluated_at: self.evaluation_time,
            verified_restrictions_count: license.restrictions().len(),
            decision_digest,
        })
    }
}

fn populate_standard_known_restrictions(known: &mut BTreeSet<String>) {
    let terms = [
        "internal_evaluation_only",
        "research_only",
        "academic_only",
        "no_commercial_use",
        "non_commercial",
        "non_commercial_only",
        "no_surveillance",
        "no_facial_recognition",
        "no_biometrics",
        "no_military_use",
        "no_weapons",
        "no_unredacted_retention",
        "no_redistribution",
        "attribution_required",
        "share_alike",
        "notice_preservation_required",
    ];
    for t in terms {
        known.insert(t.to_string());
    }
}

fn is_non_commercial_license(spdx: &str) -> bool {
    let upper = spdx.to_ascii_uppercase();
    upper.contains("-NC")
        || upper.contains("NONCOMMERCIAL")
        || upper.contains("NON-COMMERCIAL")
        || upper.contains("RESEARCH-ONLY")
}

fn is_non_commercial_restriction(restriction: &str) -> bool {
    matches!(
        restriction,
        "internal_evaluation_only"
            | "research_only"
            | "academic_only"
            | "no_commercial_use"
            | "non_commercial"
            | "non_commercial_only"
    )
}

fn is_surveillance_forbidden_restriction(restriction: &str) -> bool {
    matches!(
        restriction,
        "no_surveillance" | "no_facial_recognition" | "no_biometrics"
    )
}
