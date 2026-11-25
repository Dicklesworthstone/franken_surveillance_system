#![forbid(unsafe_code)]
//! Normative realization of `SCHEMA-DECISION-CARD-001` (`fss.decision_card.v1`, `fss-x4a.30.14`)
//! and its embedded `EvidenceAnchorRecordV1` (`schemas/evidence_anchor.v1.json`).
//!
//! Enforces every constraint of `schemas/decision_card.v1.json` and the registry compatibility rule
//! `"hard constraints and alternatives retained; no silent rewrite"`:
//!
//! - **Exact schema parity:** all 11 required root properties (`schema`, `decisionId`,
//!   `decisionClass`, `anchor`, `policyId`, `alternatives`, `selectedId`, `hardConstraints`,
//!   `evidenceIds`, `decisionPathDigest`, `createdAt`) with zero unknown properties allowed in
//!   JSON decoding (`additionalProperties: false`).
//! - **Hard-clamp non-bypassability:** `alternatives` must be non-empty with unique IDs and finite
//!   utilities; every inadmissible alternative (`admissible == false`) must retain at least one
//!   explicit rejection reason; `selectedId` MUST name an existing alternative with
//!   `admissible == true`.
//! - **Immutable non-rewrite compatibility (`verify_supersedes`):** a superseding decision card
//!   must carry a fresh `decision_id`, advance monotonically on the same deployment, retain every
//!   prior hard constraint, and retain every prior alternative ID (never silently dropping clamps
//!   or rewriting history).
//! - **Bounded versioned binary (`FSSDCV01` v1) + strict canonical JSON round-trip:** seals under
//!   registered digest domain `fss.decision_card.canonical.v1` with allocation-bomb guards and
//!   full validation on decode. No decision card grants effect authority (`grants_effect_authority() == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::json_input::{self, Value};

/// Registered schema identity (`SCHEMA-DECISION-CARD-001`).
pub const DECISION_CARD_V1_SCHEMA: &str = DecisionCardV1::SCHEMA;
/// Registered canonical digest domain (`SCHEMA-DOMAIN-DECISION-CARD-CANONICAL-001`).
pub const DECISION_CARD_CANONICAL_DOMAIN: &str = "fss.decision_card.canonical.v1";
/// Binary wire header magic for serialized [`DecisionCardV1`] envelopes.
pub const DECISION_CARD_WIRE_MAGIC: [u8; 8] = *b"FSSDCV01";
/// Supported durable format version for [`DecisionCardV1`].
pub const DECISION_CARD_FORMAT_VERSION: u32 = 1;

/// Maximum UTF-8 bytes in short identifiers/labels (`schemas/decision_card.v1.json`).
pub const MAX_DECISION_LABEL_LEN: usize = 256;
/// Maximum UTF-8 bytes in rejection or uncertainty reasons.
pub const MAX_DECISION_REASON_LEN: usize = 1_024;
/// Hard ceiling on candidate alternatives in one decision card.
pub const MAX_DECISION_ALTERNATIVES: usize = 256;
/// Hard ceiling on rejection reasons per alternative.
pub const MAX_REJECTION_REASONS_PER_ALT: usize = 64;
/// Hard ceiling on hard constraint entries in one decision card.
pub const MAX_HARD_CONSTRAINTS: usize = 256;
/// Hard ceiling on cited evidence identities in one decision card.
pub const MAX_DECISION_EVIDENCE_IDS: usize = 1_024;
/// Hard ceiling on serialized binary wire bytes (512 KiB).
pub const MAX_DECISION_CARD_WIRE_BYTES: usize = 512 * 1024;

/// Safe operator/agent recovery guidance for a refused [`DecisionCardV1`] operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionCardGuidance {
    /// Fix invalid identifiers, pattern-mismatched digests, non-finite utilities, or inverted times.
    RepairDecisionCardFields,
    /// Ensure every inadmissible option names rejection reasons and `selected_id` is admissible.
    EnforceHardConstraintsAndSelection,
    /// Preserve all prior hard constraints and alternative IDs when superseding an immutable card.
    PreserveSupersessionLineage,
    /// Reject corrupt, truncated, unknown-field, or unsupported-version wire/JSON input.
    RejectCorruptOrUnsupportedPayload,
}

/// Typed error returned by [`DecisionCardV1`] validation, supersession, binary, or JSON codecs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionCardError {
    /// Field failed syntax, regex pattern, control-char, finite-number, or interval validation.
    InvalidField {
        /// Offending field path.
        field: &'static str,
        /// Secret-free diagnostic detail.
        detail: String,
    },
    /// Selection or hard-constraint invariant failed (e.g., selecting an inadmissible alternative).
    HardConstraintViolation(String),
    /// Supersession attempted to silently drop hard constraints, drop alternatives, or reuse ID.
    SilentRewriteRefused(String),
    /// Array count or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Field or payload name.
        field: &'static str,
        /// Observed count/bytes.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary envelope lacked [`DECISION_CARD_WIRE_MAGIC`].
    InvalidMagic,
    /// Binary envelope declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Schema discriminator did not match expected constant.
    SchemaMismatch {
        /// Expected schema string.
        expected: &'static str,
        /// Observed schema string.
        observed: String,
    },
    /// Binary or JSON payload was malformed, truncated, or carried unknown/duplicate fields.
    MalformedPayload(String),
    /// Binary envelope trailing SHA-256 digest disagreed with canonical body.
    ChecksumMismatch,
    /// Canonical encoder failed.
    Encoding(String),
}

impl DecisionCardError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidField { .. } => "ERR-DECISION-CARD-INVALID-FIELD-001",
            Self::HardConstraintViolation(_) => "ERR-DECISION-CARD-HARD-CONSTRAINT-001",
            Self::SilentRewriteRefused(_) => "ERR-DECISION-CARD-SILENT-REWRITE-001",
            Self::BoundsExceeded { .. } => "ERR-DECISION-CARD-BOUNDS-001",
            Self::InvalidMagic => "ERR-DECISION-CARD-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-DECISION-CARD-UNSUPPORTED-VERSION-001",
            Self::SchemaMismatch { .. } => "ERR-DECISION-CARD-SCHEMA-MISMATCH-001",
            Self::MalformedPayload(_) => "ERR-DECISION-CARD-MALFORMED-001",
            Self::ChecksumMismatch => "ERR-DECISION-CARD-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-DECISION-CARD-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> DecisionCardGuidance {
        match self {
            Self::InvalidField { .. } | Self::BoundsExceeded { .. } => {
                DecisionCardGuidance::RepairDecisionCardFields
            }
            Self::HardConstraintViolation(_) => {
                DecisionCardGuidance::EnforceHardConstraintsAndSelection
            }
            Self::SilentRewriteRefused(_) => DecisionCardGuidance::PreserveSupersessionLineage,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::SchemaMismatch { .. }
            | Self::MalformedPayload(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => DecisionCardGuidance::RejectCorruptOrUnsupportedPayload,
        }
    }
}

impl fmt::Display for DecisionCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for DecisionCardError {}

/// Exact wire-schema realization of `schemas/evidence_anchor.v1.json` (`fss.evidence_anchor.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAnchorRecordV1 {
    /// Deployment lineage identity (`1..=256`).
    pub deployment_id: String,
    /// Observation / ledger epoch (`>= 0`).
    pub observation_epoch: u64,
    /// Capsule / commit sequence (`>= 0`).
    pub capsule_sequence: u64,
    /// Authority state root (`^[a-z0-9][a-z0-9:+._-]{7,255}$`).
    pub authority_root: String,
    /// Pinned device generation identity.
    pub device_generation: String,
    /// Pinned stream generation identity.
    pub stream_generation: String,
    /// Schema epoch.
    pub schema_epoch: u64,
    /// Policy epoch.
    pub policy_epoch: u64,
    /// Adapter registry epoch.
    pub adapter_epoch: u64,
    /// Optional immutable model generation.
    pub model_generation: Option<String>,
    /// Optional immutable calibration generation.
    pub calibration_generation: Option<String>,
    /// Optional immutable graph generation.
    pub graph_generation: Option<String>,
    /// Optional immutable search generation.
    pub search_generation: Option<String>,
    /// Optional native `LedgerAnchor` privacy epoch.
    pub privacy_epoch: Option<u64>,
}

impl EvidenceAnchorRecordV1 {
    /// Normative schema identity (`schemas/evidence_anchor.v1.json`).
    pub const SCHEMA: &str = "fss.evidence_anchor.v1";

    /// Projects a native [`LedgerAnchor`] plus pinned device/stream generations into an
    /// [`EvidenceAnchorRecordV1`].
    pub fn from_ledger_anchor(
        anchor: &LedgerAnchor,
        device_generation: impl Into<String>,
        stream_generation: impl Into<String>,
    ) -> Result<Self, DecisionCardError> {
        let rec = Self {
            deployment_id: anchor.site_lineage.clone(),
            observation_epoch: anchor.ledger_epoch,
            capsule_sequence: anchor.commit_sequence,
            authority_root: anchor.state_root.to_text(),
            device_generation: device_generation.into(),
            stream_generation: stream_generation.into(),
            schema_epoch: anchor.schema_epoch,
            policy_epoch: anchor.policy_epoch,
            adapter_epoch: anchor.adapter_registry_epoch,
            model_generation: None,
            calibration_generation: None,
            graph_generation: None,
            search_generation: None,
            privacy_epoch: Some(anchor.privacy_epoch),
        };
        rec.validate()?;
        Ok(rec)
    }

    /// Validates all required/optional fields against `schemas/evidence_anchor.v1.json`.
    pub fn validate(&self) -> Result<(), DecisionCardError> {
        validate_short_text(&self.deployment_id, "anchor.deploymentId")?;
        validate_lower_token(&self.authority_root, "anchor.authorityRoot")?;
        validate_lower_token(&self.device_generation, "anchor.deviceGeneration")?;
        validate_lower_token(&self.stream_generation, "anchor.streamGeneration")?;
        if let Some(ref v) = self.model_generation {
            validate_lower_token(v, "anchor.modelGeneration")?;
        }
        if let Some(ref v) = self.calibration_generation {
            validate_lower_token(v, "anchor.calibrationGeneration")?;
        }
        if let Some(ref v) = self.graph_generation {
            validate_lower_token(v, "anchor.graphGeneration")?;
        }
        if let Some(ref v) = self.search_generation {
            validate_lower_token(v, "anchor.searchGeneration")?;
        }
        Ok(())
    }

    pub(crate) fn write_canonical_json(&self, out: &mut String) {
        out.push('{');
        push_json_kv_str(out, "adapterEpoch", None, false);
        out.push_str(&self.adapter_epoch.to_string());
        out.push(',');
        push_json_kv_str(out, "authorityRoot", Some(&self.authority_root), false);
        out.push(',');
        push_json_kv_opt_str(
            out,
            "calibrationGeneration",
            self.calibration_generation.as_deref(),
        );
        out.push(',');
        push_json_key(out, "capsuleSequence");
        out.push_str(&self.capsule_sequence.to_string());
        out.push(',');
        push_json_kv_str(out, "deploymentId", Some(&self.deployment_id), false);
        out.push(',');
        push_json_kv_str(
            out,
            "deviceGeneration",
            Some(&self.device_generation),
            false,
        );
        out.push(',');
        push_json_kv_opt_str(out, "graphGeneration", self.graph_generation.as_deref());
        out.push(',');
        push_json_kv_opt_str(out, "modelGeneration", self.model_generation.as_deref());
        out.push(',');
        push_json_key(out, "observationEpoch");
        out.push_str(&self.observation_epoch.to_string());
        out.push(',');
        push_json_key(out, "policyEpoch");
        out.push_str(&self.policy_epoch.to_string());
        if let Some(pe) = self.privacy_epoch {
            out.push(',');
            push_json_key(out, "privacyEpoch");
            out.push_str(&pe.to_string());
        }
        out.push(',');
        push_json_kv_str(out, "schema", Some(Self::SCHEMA), false);
        out.push(',');
        push_json_key(out, "schemaEpoch");
        out.push_str(&self.schema_epoch.to_string());
        out.push(',');
        push_json_kv_opt_str(out, "searchGeneration", self.search_generation.as_deref());
        out.push(',');
        push_json_kv_str(
            out,
            "streamGeneration",
            Some(&self.stream_generation),
            false,
        );
        out.push('}');
    }

    pub(crate) fn from_json_value(val: &Value) -> Result<Self, DecisionCardError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "deploymentId",
            "observationEpoch",
            "capsuleSequence",
            "authorityRoot",
            "deviceGeneration",
            "streamGeneration",
            "schemaEpoch",
            "policyEpoch",
            "adapterEpoch",
            "modelGeneration",
            "calibrationGeneration",
            "graphGeneration",
            "searchGeneration",
            "privacyEpoch",
        ];
        let obj = require_object(val, "anchor")?;
        reject_unknown_keys(obj, ALLOWED, "anchor")?;
        let schema = require_str(obj, "schema", "anchor.schema")?;
        if schema != Self::SCHEMA {
            return Err(DecisionCardError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let rec = Self {
            deployment_id: require_str(obj, "deploymentId", "anchor.deploymentId")?.to_owned(),
            observation_epoch: require_u64(obj, "observationEpoch", "anchor.observationEpoch")?,
            capsule_sequence: require_u64(obj, "capsuleSequence", "anchor.capsuleSequence")?,
            authority_root: require_str(obj, "authorityRoot", "anchor.authorityRoot")?.to_owned(),
            device_generation: require_str(obj, "deviceGeneration", "anchor.deviceGeneration")?
                .to_owned(),
            stream_generation: require_str(obj, "streamGeneration", "anchor.streamGeneration")?
                .to_owned(),
            schema_epoch: require_u64(obj, "schemaEpoch", "anchor.schemaEpoch")?,
            policy_epoch: require_u64(obj, "policyEpoch", "anchor.policyEpoch")?,
            adapter_epoch: require_u64(obj, "adapterEpoch", "anchor.adapterEpoch")?,
            model_generation: require_nullable_str(
                obj,
                "modelGeneration",
                "anchor.modelGeneration",
            )?,
            calibration_generation: require_nullable_str(
                obj,
                "calibrationGeneration",
                "anchor.calibrationGeneration",
            )?,
            graph_generation: require_nullable_str(
                obj,
                "graphGeneration",
                "anchor.graphGeneration",
            )?,
            search_generation: require_nullable_str(
                obj,
                "searchGeneration",
                "anchor.searchGeneration",
            )?,
            privacy_epoch: optional_u64(obj, "privacyEpoch", "anchor.privacyEpoch")?,
        };
        rec.validate()?;
        Ok(rec)
    }
}

impl CanonicalEncode for EvidenceAnchorRecordV1 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.deployment_id);
        encoder.u64(self.observation_epoch);
        encoder.u64(self.capsule_sequence);
        encoder.text(&self.authority_root);
        encoder.text(&self.device_generation);
        encoder.text(&self.stream_generation);
        encoder.u64(self.schema_epoch);
        encoder.u64(self.policy_epoch);
        encoder.u64(self.adapter_epoch);
        encode_opt_str(self.model_generation.as_deref(), encoder);
        encode_opt_str(self.calibration_generation.as_deref(), encoder);
        encode_opt_str(self.graph_generation.as_deref(), encoder);
        encode_opt_str(self.search_generation.as_deref(), encoder);
        match self.privacy_epoch {
            Some(v) => {
                encoder.bool(true);
                encoder.u64(v);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for EvidenceAnchorRecordV1 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, crate::ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(crate::ContractError::InvalidIdentifier);
        }
        let rec = Self {
            deployment_id: decoder.text()?.to_owned(),
            observation_epoch: decoder.u64()?,
            capsule_sequence: decoder.u64()?,
            authority_root: decoder.text()?.to_owned(),
            device_generation: decoder.text()?.to_owned(),
            stream_generation: decoder.text()?.to_owned(),
            schema_epoch: decoder.u64()?,
            policy_epoch: decoder.u64()?,
            adapter_epoch: decoder.u64()?,
            model_generation: decode_opt_str(decoder)?,
            calibration_generation: decode_opt_str(decoder)?,
            graph_generation: decode_opt_str(decoder)?,
            search_generation: decode_opt_str(decoder)?,
            privacy_epoch: if decoder.bool()? {
                Some(decoder.u64()?)
            } else {
                None
            },
        };
        rec.validate()
            .map_err(|_| crate::ContractError::InvalidIdentifier)?;
        Ok(rec)
    }
}

/// One retained decision alternative inside [`DecisionCardV1`].
#[derive(Clone, Debug, PartialEq)]
pub struct DecisionAlternativeV1 {
    /// Stable alternative identifier (`1..=256`).
    pub id: String,
    /// Finite scalar utility score (canonicalized: `-0.0` normalized to `0.0`).
    pub utility: f64,
    /// True iff this alternative passed every hard constraint.
    pub admissible: bool,
    /// Explicit rejection reasons when `admissible == false` (retained, never dropped!).
    pub rejection_reasons: Vec<String>,
}

impl DecisionAlternativeV1 {
    /// Canonical finite utility bits (`-0.0` normalized to `+0.0`).
    #[must_use]
    pub fn canonical_utility(&self) -> f64 {
        if self.utility == 0.0 {
            0.0
        } else {
            self.utility
        }
    }

    /// Validates identifier, finite utility, admissibility, and rejection reasons.
    pub fn validate(&self) -> Result<(), DecisionCardError> {
        validate_short_text(&self.id, "alternatives[].id")?;
        if !self.utility.is_finite() {
            return Err(DecisionCardError::InvalidField {
                field: "alternatives[].utility",
                detail: "utility must be a finite IEEE-754 number".to_owned(),
            });
        }
        if self.rejection_reasons.len() > MAX_REJECTION_REASONS_PER_ALT {
            return Err(DecisionCardError::BoundsExceeded {
                field: "alternatives[].rejectionReasons",
                observed: self.rejection_reasons.len(),
                maximum: MAX_REJECTION_REASONS_PER_ALT,
            });
        }
        if !self.admissible && self.rejection_reasons.is_empty() {
            return Err(DecisionCardError::HardConstraintViolation(format!(
                "inadmissible alternative '{}' must retain at least one rejection_reason",
                self.id
            )));
        }
        if self.admissible && !self.rejection_reasons.is_empty() {
            return Err(DecisionCardError::HardConstraintViolation(format!(
                "admissible alternative '{}' must not carry rejection_reasons",
                self.id
            )));
        }
        for reason in &self.rejection_reasons {
            if reason.is_empty()
                || reason.len() > MAX_DECISION_REASON_LEN
                || has_disallowed_control(reason)
            {
                return Err(DecisionCardError::InvalidField {
                    field: "alternatives[].rejectionReasons[]",
                    detail: "rejection reason must be non-empty, <= 1024 bytes, control-free"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn write_canonical_json(&self, out: &mut String) {
        out.push('{');
        push_json_key(out, "admissible");
        out.push_str(if self.admissible { "true" } else { "false" });
        out.push(',');
        push_json_kv_str(out, "id", Some(&self.id), false);
        if !self.rejection_reasons.is_empty() {
            out.push(',');
            push_json_key(out, "rejectionReasons");
            push_json_str_array(out, &self.rejection_reasons);
        }
        out.push(',');
        push_json_key(out, "utility");
        push_json_f64(out, self.canonical_utility());
        out.push('}');
    }

    pub(crate) fn from_json_value(val: &Value) -> Result<Self, DecisionCardError> {
        const ALLOWED: &[&str] = &["id", "utility", "admissible", "rejectionReasons"];
        let obj = require_object(val, "alternatives[]")?;
        reject_unknown_keys(obj, ALLOWED, "alternatives[]")?;
        let id = require_str(obj, "id", "alternatives[].id")?.to_owned();
        let utility = require_f64(obj, "utility", "alternatives[].utility")?;
        let admissible = require_bool(obj, "admissible", "alternatives[].admissible")?;
        let rejection_reasons = match obj.get("rejectionReasons") {
            None => Vec::new(),
            Some(v) => require_str_vec(
                v,
                "alternatives[].rejectionReasons",
                MAX_REJECTION_REASONS_PER_ALT,
            )?,
        };
        let alt = Self {
            id,
            utility: if utility == 0.0 { 0.0 } else { utility },
            admissible,
            rejection_reasons,
        };
        alt.validate()?;
        Ok(alt)
    }
}

/// Conservative bounded decision timestamp matching `schemas/decision_card.v1.json#/properties/createdAt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionTimestampV1 {
    /// Earliest possible creation timestamp in nanoseconds.
    pub earliest_ns: i64,
    /// Latest possible creation timestamp in nanoseconds (`>= earliest_ns`).
    pub latest_ns: i64,
    /// Explicit clock basis label (`1..=256`).
    pub clock_basis: String,
    /// Optional explicit clock uncertainty reason (`<= 1024`).
    pub uncertainty_reason: Option<String>,
}

impl DecisionTimestampV1 {
    /// Validates timestamp monotonicity, clock basis, and optional uncertainty reason.
    pub fn validate(&self) -> Result<(), DecisionCardError> {
        if self.latest_ns < self.earliest_ns {
            return Err(DecisionCardError::InvalidField {
                field: "createdAt",
                detail: format!(
                    "latestNs ({}) < earliestNs ({})",
                    self.latest_ns, self.earliest_ns
                ),
            });
        }
        validate_short_text(&self.clock_basis, "createdAt.clockBasis")?;
        if let Some(ref reason) = self.uncertainty_reason
            && (reason.len() > MAX_DECISION_REASON_LEN || has_disallowed_control(reason))
        {
            return Err(DecisionCardError::InvalidField {
                field: "createdAt.uncertaintyReason",
                detail: "uncertaintyReason exceeds 1024 bytes or contains control chars".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn write_canonical_json(&self, out: &mut String) {
        out.push('{');
        push_json_kv_str(out, "clockBasis", Some(&self.clock_basis), false);
        out.push(',');
        push_json_key(out, "earliestNs");
        out.push_str(&self.earliest_ns.to_string());
        out.push(',');
        push_json_key(out, "latestNs");
        out.push_str(&self.latest_ns.to_string());
        if let Some(ref reason) = self.uncertainty_reason {
            out.push(',');
            push_json_kv_str(out, "uncertaintyReason", Some(reason), false);
        }
        out.push('}');
    }

    pub(crate) fn from_json_value(val: &Value) -> Result<Self, DecisionCardError> {
        const ALLOWED: &[&str] = &["earliestNs", "latestNs", "clockBasis", "uncertaintyReason"];
        let obj = require_object(val, "createdAt")?;
        reject_unknown_keys(obj, ALLOWED, "createdAt")?;
        let ts = Self {
            earliest_ns: require_i64(obj, "earliestNs", "createdAt.earliestNs")?,
            latest_ns: require_i64(obj, "latestNs", "createdAt.latestNs")?,
            clock_basis: require_str(obj, "clockBasis", "createdAt.clockBasis")?.to_owned(),
            uncertainty_reason: match obj.get("uncertaintyReason") {
                None => None,
                Some(v) => Some(
                    v.text()
                        .ok_or_else(|| {
                            DecisionCardError::MalformedPayload(
                                "createdAt.uncertaintyReason must be string".to_owned(),
                            )
                        })?
                        .to_owned(),
                ),
            },
        };
        ts.validate()?;
        Ok(ts)
    }
}

/// Normative realization of `SCHEMA-DECISION-CARD-001` (`fss.decision_card.v1`).
///
/// Retains all hard constraints and candidate alternatives without silent rewrite, and never
/// grants effect execution authority (`grants_effect_authority() == false`).
#[derive(Clone, Debug, PartialEq)]
pub struct DecisionCardV1 {
    /// Stable decision identity (`1..=256`).
    pub decision_id: String,
    /// Registered decision class label (`1..=256`).
    pub decision_class: String,
    /// Exact pinned evidence anchor (`fss.evidence_anchor.v1`).
    pub anchor: EvidenceAnchorRecordV1,
    /// Policy identity governing this decision (`1..=256`).
    pub policy_id: String,
    /// Retained candidate alternatives (`1..=MAX_DECISION_ALTERNATIVES`, unique IDs).
    pub alternatives: Vec<DecisionAlternativeV1>,
    /// Selected alternative ID (MUST name an existing `admissible == true` alternative).
    pub selected_id: String,
    /// Retained hard constraints enforced before selection (`<= MAX_HARD_CONSTRAINTS`).
    pub hard_constraints: Vec<String>,
    /// Cited canonical evidence IDs (`<= MAX_DECISION_EVIDENCE_IDS`, pattern validated).
    pub evidence_ids: Vec<String>,
    /// Deterministic decision-path digest (`^[a-z0-9][a-z0-9:+._-]{7,255}$`).
    pub decision_path_digest: String,
    /// Conservative creation timestamp interval and clock basis.
    pub created_at: DecisionTimestampV1,
}

impl DecisionCardV1 {
    /// Normative schema identity (`SCHEMA-DECISION-CARD-001`).
    pub const SCHEMA: &str = "fss.decision_card.v1";

    /// Decision cards live in cognition/policy-evidence and NEVER carry effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Validates every schema, bound, hard-constraint, admissibility, and selection invariant.
    pub fn validate(&self) -> Result<(), DecisionCardError> {
        validate_short_text(&self.decision_id, "decisionId")?;
        validate_short_text(&self.decision_class, "decisionClass")?;
        self.anchor.validate()?;
        validate_short_text(&self.policy_id, "policyId")?;
        validate_short_text(&self.selected_id, "selectedId")?;
        validate_lower_token(&self.decision_path_digest, "decisionPathDigest")?;
        self.created_at.validate()?;

        if self.alternatives.is_empty() || self.alternatives.len() > MAX_DECISION_ALTERNATIVES {
            return Err(DecisionCardError::BoundsExceeded {
                field: "alternatives",
                observed: self.alternatives.len(),
                maximum: MAX_DECISION_ALTERNATIVES,
            });
        }
        let mut alt_ids = BTreeSet::new();
        let mut selected_admissible: Option<bool> = None;
        for alt in &self.alternatives {
            alt.validate()?;
            if !alt_ids.insert(alt.id.as_str()) {
                return Err(DecisionCardError::InvalidField {
                    field: "alternatives",
                    detail: format!("duplicate alternative id '{}'", alt.id),
                });
            }
            if alt.id == self.selected_id {
                selected_admissible = Some(alt.admissible);
            }
        }
        match selected_admissible {
            None => {
                return Err(DecisionCardError::HardConstraintViolation(format!(
                    "selectedId '{}' is not present in alternatives",
                    self.selected_id
                )));
            }
            Some(false) => {
                return Err(DecisionCardError::HardConstraintViolation(format!(
                    "selectedId '{}' names an inadmissible alternative; hard constraints cannot be bypassed",
                    self.selected_id
                )));
            }
            Some(true) => {}
        }

        if self.hard_constraints.len() > MAX_HARD_CONSTRAINTS {
            return Err(DecisionCardError::BoundsExceeded {
                field: "hardConstraints",
                observed: self.hard_constraints.len(),
                maximum: MAX_HARD_CONSTRAINTS,
            });
        }
        let mut seen_hc = BTreeSet::new();
        for hc in &self.hard_constraints {
            validate_short_text(hc, "hardConstraints[]")?;
            if !seen_hc.insert(hc.as_str()) {
                return Err(DecisionCardError::InvalidField {
                    field: "hardConstraints",
                    detail: format!("duplicate hard constraint '{hc}'"),
                });
            }
        }

        if self.evidence_ids.len() > MAX_DECISION_EVIDENCE_IDS {
            return Err(DecisionCardError::BoundsExceeded {
                field: "evidenceIds",
                observed: self.evidence_ids.len(),
                maximum: MAX_DECISION_EVIDENCE_IDS,
            });
        }
        let mut seen_ev = BTreeSet::new();
        for ev in &self.evidence_ids {
            validate_lower_token(ev, "evidenceIds[]")?;
            if !seen_ev.insert(ev.as_str()) {
                return Err(DecisionCardError::InvalidField {
                    field: "evidenceIds",
                    detail: format!("duplicate evidence id '{ev}'"),
                });
            }
        }
        Ok(())
    }

    /// Enforces the `SCHEMA-DECISION-CARD-001` immutable compatibility rule when `self` supersedes
    /// `prior`: `"hard constraints and alternatives retained; no silent rewrite"`.
    pub fn verify_supersedes(&self, prior: &Self) -> Result<(), DecisionCardError> {
        self.validate()?;
        prior.validate()?;
        if self.decision_id == prior.decision_id {
            return Err(DecisionCardError::SilentRewriteRefused(
                "superseding decision card must allocate a fresh decisionId rather than rewriting in place"
                    .to_owned(),
            ));
        }
        if self.anchor.deployment_id != prior.anchor.deployment_id
            || self.anchor.observation_epoch < prior.anchor.observation_epoch
            || (self.anchor.observation_epoch == prior.anchor.observation_epoch
                && self.anchor.capsule_sequence < prior.anchor.capsule_sequence)
        {
            return Err(DecisionCardError::SilentRewriteRefused(
                "superseding decision card anchor must advance monotonically on the same deployment"
                    .to_owned(),
            ));
        }
        let current_hc: BTreeSet<&str> = self.hard_constraints.iter().map(String::as_str).collect();
        for hc in &prior.hard_constraints {
            if !current_hc.contains(hc.as_str()) {
                return Err(DecisionCardError::SilentRewriteRefused(format!(
                    "hard constraint '{hc}' was silently dropped during supersession"
                )));
            }
        }
        let current_alts: BTreeSet<&str> =
            self.alternatives.iter().map(|a| a.id.as_str()).collect();
        for alt in &prior.alternatives {
            if !current_alts.contains(alt.id.as_str()) {
                return Err(DecisionCardError::SilentRewriteRefused(format!(
                    "prior alternative '{}' was silently dropped during supersession",
                    alt.id
                )));
            }
        }
        Ok(())
    }

    /// Computes the domain-separated SHA-256 commitment digest (`fss.decision_card.canonical.v1`).
    pub fn canonical_digest(&self) -> Result<ContentDigest, DecisionCardError> {
        self.validate()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(DECISION_CARD_CANONICAL_DOMAIN);
        self.encode_canonical(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| DecisionCardError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Encodes this validated decision card into bounded checksummed binary bytes (`FSSDCV01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DecisionCardError> {
        let digest = self.canonical_digest()?;
        let mut enc = CanonicalEncoder::new();
        enc.u32(DECISION_CARD_FORMAT_VERSION);
        self.encode_canonical(&mut enc);
        enc.digest(digest);
        let body = enc
            .finish_checked()
            .map_err(|e| DecisionCardError::Encoding(e.to_string()))?;
        let total = DECISION_CARD_WIRE_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_DECISION_CARD_WIRE_BYTES {
            return Err(DecisionCardError::BoundsExceeded {
                field: "wire_bytes",
                observed: total,
                maximum: MAX_DECISION_CARD_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&DECISION_CARD_WIRE_MAGIC);
        out.extend_from_slice(&DECISION_CARD_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and cryptographically verifies binary [`DecisionCardV1`] bytes (`FSSDCV01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecisionCardError> {
        if bytes.len() > MAX_DECISION_CARD_WIRE_BYTES {
            return Err(DecisionCardError::BoundsExceeded {
                field: "wire_bytes",
                observed: bytes.len(),
                maximum: MAX_DECISION_CARD_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != DECISION_CARD_WIRE_MAGIC {
            return Err(DecisionCardError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != DECISION_CARD_FORMAT_VERSION {
            return Err(DecisionCardError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let body_ver = dec
            .u32()
            .map_err(|e| DecisionCardError::MalformedPayload(e.to_string()))?;
        if body_ver != header_ver {
            return Err(DecisionCardError::UnsupportedVersion { version: body_ver });
        }
        let card = Self::decode_canonical(&mut dec)
            .map_err(|e| DecisionCardError::MalformedPayload(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| DecisionCardError::MalformedPayload(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            DecisionCardError::MalformedPayload(
                "trailing bytes after DecisionCardV1 wire envelope".to_owned(),
            )
        })?;
        if card.canonical_digest()? != stored_digest {
            return Err(DecisionCardError::ChecksumMismatch);
        }
        Ok(card)
    }

    /// Emits deterministic canonical JSON conforming strictly to `schemas/decision_card.v1.json`.
    pub fn to_canonical_json(&self) -> Result<String, DecisionCardError> {
        self.validate()?;
        let mut out = String::with_capacity(512);
        out.push('{');
        push_json_key(&mut out, "alternatives");
        out.push('[');
        for (i, alt) in self.alternatives.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            alt.write_canonical_json(&mut out);
        }
        out.push(']');
        out.push(',');
        push_json_key(&mut out, "anchor");
        self.anchor.write_canonical_json(&mut out);
        out.push(',');
        push_json_key(&mut out, "createdAt");
        self.created_at.write_canonical_json(&mut out);
        out.push(',');
        push_json_kv_str(&mut out, "decisionClass", Some(&self.decision_class), false);
        out.push(',');
        push_json_kv_str(&mut out, "decisionId", Some(&self.decision_id), false);
        out.push(',');
        push_json_kv_str(
            &mut out,
            "decisionPathDigest",
            Some(&self.decision_path_digest),
            false,
        );
        out.push(',');
        push_json_key(&mut out, "evidenceIds");
        push_json_str_array(&mut out, &self.evidence_ids);
        out.push(',');
        push_json_key(&mut out, "hardConstraints");
        push_json_str_array(&mut out, &self.hard_constraints);
        out.push(',');
        push_json_kv_str(&mut out, "policyId", Some(&self.policy_id), false);
        out.push(',');
        push_json_kv_str(&mut out, "schema", Some(Self::SCHEMA), false);
        out.push(',');
        push_json_kv_str(&mut out, "selectedId", Some(&self.selected_id), false);
        out.push('}');
        Ok(out)
    }

    /// Strictly parses and validates a JSON document against `schemas/decision_card.v1.json`,
    /// rejecting unknown properties, duplicate keys, wrong schema, non-finite numbers, and trailing text.
    pub fn from_json(text: &str) -> Result<Self, DecisionCardError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "decisionId",
            "decisionClass",
            "anchor",
            "policyId",
            "alternatives",
            "selectedId",
            "hardConstraints",
            "evidenceIds",
            "decisionPathDigest",
            "createdAt",
        ];
        let value = json_input::parse(text)
            .map_err(|e| DecisionCardError::MalformedPayload(e.to_string()))?;
        let obj = require_object(&value, "$")?;
        reject_unknown_keys(obj, ALLOWED, "$")?;
        let schema = require_str(obj, "schema", "schema")?;
        if schema != Self::SCHEMA {
            return Err(DecisionCardError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let alts_val = obj.get("alternatives").ok_or_else(|| {
            DecisionCardError::MalformedPayload("missing alternatives".to_owned())
        })?;
        let alts_arr = alts_val.array().ok_or_else(|| {
            DecisionCardError::MalformedPayload("alternatives must be an array".to_owned())
        })?;
        if alts_arr.is_empty() || alts_arr.len() > MAX_DECISION_ALTERNATIVES {
            return Err(DecisionCardError::BoundsExceeded {
                field: "alternatives",
                observed: alts_arr.len(),
                maximum: MAX_DECISION_ALTERNATIVES,
            });
        }
        let mut alternatives = Vec::with_capacity(alts_arr.len());
        for item in alts_arr {
            alternatives.push(DecisionAlternativeV1::from_json_value(item)?);
        }
        let anchor_val = obj
            .get("anchor")
            .ok_or_else(|| DecisionCardError::MalformedPayload("missing anchor".to_owned()))?;
        let created_val = obj
            .get("createdAt")
            .ok_or_else(|| DecisionCardError::MalformedPayload("missing createdAt".to_owned()))?;
        let hc_val = obj.get("hardConstraints").ok_or_else(|| {
            DecisionCardError::MalformedPayload("missing hardConstraints".to_owned())
        })?;
        let ev_val = obj
            .get("evidenceIds")
            .ok_or_else(|| DecisionCardError::MalformedPayload("missing evidenceIds".to_owned()))?;

        let card = Self {
            decision_id: require_str(obj, "decisionId", "decisionId")?.to_owned(),
            decision_class: require_str(obj, "decisionClass", "decisionClass")?.to_owned(),
            anchor: EvidenceAnchorRecordV1::from_json_value(anchor_val)?,
            policy_id: require_str(obj, "policyId", "policyId")?.to_owned(),
            alternatives,
            selected_id: require_str(obj, "selectedId", "selectedId")?.to_owned(),
            hard_constraints: require_str_vec(hc_val, "hardConstraints", MAX_HARD_CONSTRAINTS)?,
            evidence_ids: require_str_vec(ev_val, "evidenceIds", MAX_DECISION_EVIDENCE_IDS)?,
            decision_path_digest: require_str(obj, "decisionPathDigest", "decisionPathDigest")?
                .to_owned(),
            created_at: DecisionTimestampV1::from_json_value(created_val)?,
        };
        card.validate()?;
        Ok(card)
    }
}

impl CanonicalEncode for DecisionCardV1 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.decision_id);
        encoder.text(&self.decision_class);
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.policy_id);
        encoder.u32(self.alternatives.len() as u32);
        for alt in &self.alternatives {
            encoder.text(&alt.id);
            encoder.u64(alt.canonical_utility().to_bits());
            encoder.bool(alt.admissible);
            encoder.u32(alt.rejection_reasons.len() as u32);
            for r in &alt.rejection_reasons {
                encoder.text(r);
            }
        }
        encoder.text(&self.selected_id);
        encoder.u32(self.hard_constraints.len() as u32);
        for hc in &self.hard_constraints {
            encoder.text(hc);
        }
        encoder.u32(self.evidence_ids.len() as u32);
        for ev in &self.evidence_ids {
            encoder.text(ev);
        }
        encoder.text(&self.decision_path_digest);
        encoder.i128(i128::from(self.created_at.earliest_ns));
        encoder.i128(i128::from(self.created_at.latest_ns));
        encoder.text(&self.created_at.clock_basis);
        encode_opt_str(self.created_at.uncertainty_reason.as_deref(), encoder);
    }
}

impl CanonicalDecode for DecisionCardV1 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, crate::ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(crate::ContractError::InvalidIdentifier);
        }
        let decision_id = decoder.text()?.to_owned();
        let decision_class = decoder.text()?.to_owned();
        let anchor = EvidenceAnchorRecordV1::decode_canonical(decoder)?;
        let policy_id = decoder.text()?.to_owned();
        let alt_count = decoder.u32()? as usize;
        if alt_count == 0
            || alt_count > MAX_DECISION_ALTERNATIVES
            || alt_count.saturating_mul(16) > decoder.remaining()
        {
            return Err(crate::ContractError::CountBoundExceeded);
        }
        let mut alternatives = Vec::with_capacity(alt_count);
        for _ in 0..alt_count {
            let id = decoder.text()?.to_owned();
            let raw_bits = decoder.u64()?;
            let utility = f64::from_bits(raw_bits);
            // Reject non-canonical negative zero or NaN/Inf on wire!
            if !utility.is_finite() || (utility == 0.0 && raw_bits != 0.0_f64.to_bits()) {
                return Err(crate::ContractError::InvalidIdentifier);
            }
            let admissible = decoder.bool()?;
            let reason_count = decoder.u32()? as usize;
            if reason_count > MAX_REJECTION_REASONS_PER_ALT
                || reason_count.saturating_mul(8) > decoder.remaining()
            {
                return Err(crate::ContractError::CountBoundExceeded);
            }
            let mut rejection_reasons = Vec::with_capacity(reason_count);
            for _ in 0..reason_count {
                rejection_reasons.push(decoder.text()?.to_owned());
            }
            alternatives.push(DecisionAlternativeV1 {
                id,
                utility,
                admissible,
                rejection_reasons,
            });
        }
        let selected_id = decoder.text()?.to_owned();
        let hc_count = decoder.u32()? as usize;
        if hc_count > MAX_HARD_CONSTRAINTS || hc_count.saturating_mul(8) > decoder.remaining() {
            return Err(crate::ContractError::CountBoundExceeded);
        }
        let mut hard_constraints = Vec::with_capacity(hc_count);
        for _ in 0..hc_count {
            hard_constraints.push(decoder.text()?.to_owned());
        }
        let ev_count = decoder.u32()? as usize;
        if ev_count > MAX_DECISION_EVIDENCE_IDS || ev_count.saturating_mul(8) > decoder.remaining()
        {
            return Err(crate::ContractError::CountBoundExceeded);
        }
        let mut evidence_ids = Vec::with_capacity(ev_count);
        for _ in 0..ev_count {
            evidence_ids.push(decoder.text()?.to_owned());
        }
        let decision_path_digest = decoder.text()?.to_owned();
        let earliest_i128 = decoder.i128()?;
        let latest_i128 = decoder.i128()?;
        let earliest_ns =
            i64::try_from(earliest_i128).map_err(|_| crate::ContractError::InvalidIdentifier)?;
        let latest_ns =
            i64::try_from(latest_i128).map_err(|_| crate::ContractError::InvalidIdentifier)?;
        let clock_basis = decoder.text()?.to_owned();
        let uncertainty_reason = decode_opt_str(decoder)?;

        let card = Self {
            decision_id,
            decision_class,
            anchor,
            policy_id,
            alternatives,
            selected_id,
            hard_constraints,
            evidence_ids,
            decision_path_digest,
            created_at: DecisionTimestampV1 {
                earliest_ns,
                latest_ns,
                clock_basis,
                uncertainty_reason,
            },
        };
        card.validate()
            .map_err(|_| crate::ContractError::InvalidIdentifier)?;
        Ok(card)
    }
}

fn encode_opt_str(val: Option<&str>, encoder: &mut CanonicalEncoder) {
    match val {
        Some(s) => {
            encoder.bool(true);
            encoder.text(s);
        }
        None => encoder.bool(false),
    }
}

fn decode_opt_str(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<String>, crate::ContractError> {
    if decoder.bool()? {
        Ok(Some(decoder.text()?.to_owned()))
    } else {
        Ok(None)
    }
}

fn has_disallowed_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn validate_short_text(value: &str, field: &'static str) -> Result<(), DecisionCardError> {
    if value.is_empty() || value.len() > MAX_DECISION_LABEL_LEN {
        return Err(DecisionCardError::InvalidField {
            field,
            detail: format!(
                "length {} outside 1..={MAX_DECISION_LABEL_LEN}",
                value.len()
            ),
        });
    }
    if has_disallowed_control(value) {
        return Err(DecisionCardError::InvalidField {
            field,
            detail: "contains disallowed control characters".to_owned(),
        });
    }
    Ok(())
}

/// Validates regex `^[a-z0-9][a-z0-9:+._-]{7,255}$` from `schemas/decision_card.v1.json`.
fn validate_lower_token(value: &str, field: &'static str) -> Result<(), DecisionCardError> {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes.len() > 256 {
        return Err(DecisionCardError::InvalidField {
            field,
            detail: format!("length {} outside 8..=256", bytes.len()),
        });
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(DecisionCardError::InvalidField {
            field,
            detail: "must start with [a-z0-9]".to_owned(),
        });
    }
    if !bytes[1..].iter().all(|&b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b':' | b'+' | b'.' | b'_' | b'-')
    }) {
        return Err(DecisionCardError::InvalidField {
            field,
            detail: "contains character outside [a-z0-9:+._-]".to_owned(),
        });
    }
    Ok(())
}

fn push_json_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_escaped_str(out, key);
    out.push(':');
}

fn push_json_kv_str(out: &mut String, key: &str, val: Option<&str>, nullable: bool) {
    push_json_key(out, key);
    match val {
        Some(v) => push_json_escaped_str(out, v),
        None if nullable => out.push_str("null"),
        None => {}
    }
}

fn push_json_kv_opt_str(out: &mut String, key: &str, val: Option<&str>) {
    push_json_kv_str(out, key, val, true);
}

fn push_json_str_array(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_escaped_str(out, item);
    }
    out.push(']');
}

fn push_json_f64(out: &mut String, v: f64) {
    let norm = if v == 0.0 { 0.0 } else { v };
    out.push_str(&norm.to_string());
}

fn require_object<'a>(
    val: &'a Value,
    path: &'static str,
) -> Result<&'a BTreeMap<String, Value>, DecisionCardError> {
    val.object()
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("{path} must be a JSON object")))
}

fn reject_unknown_keys(
    obj: &BTreeMap<String, Value>,
    allowed: &[&str],
    path: &'static str,
) -> Result<(), DecisionCardError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(DecisionCardError::MalformedPayload(format!(
                "unknown property '{k}' in {path} (additionalProperties: false)"
            )));
        }
    }
    Ok(())
}

fn require_str<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<&'a str, DecisionCardError> {
    obj.get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?
        .text()
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("{path} must be a string")))
}

fn require_nullable_str(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<Option<String>, DecisionCardError> {
    match obj
        .get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?
    {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s.clone())),
        _ => Err(DecisionCardError::MalformedPayload(format!(
            "{path} must be string or null"
        ))),
    }
}

fn require_u64(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<u64, DecisionCardError> {
    let val = obj
        .get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?;
    let n = match val {
        Value::Number(s) => s.parse::<u64>().map_err(|_| {
            DecisionCardError::MalformedPayload(format!("{path} must be a non-negative integer"))
        })?,
        _ => {
            return Err(DecisionCardError::MalformedPayload(format!(
                "{path} must be an integer"
            )));
        }
    };
    Ok(n)
}

fn optional_u64(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<Option<u64>, DecisionCardError> {
    match obj.get(key) {
        None => Ok(None),
        Some(Value::Number(s)) => s.parse::<u64>().map(Some).map_err(|_| {
            DecisionCardError::MalformedPayload(format!("{path} must be a non-negative integer"))
        }),
        Some(_) => Err(DecisionCardError::MalformedPayload(format!(
            "{path} must be an integer"
        ))),
    }
}

fn require_i64(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<i64, DecisionCardError> {
    let val = obj
        .get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?;
    match val {
        Value::Number(s) => s.parse::<i64>().map_err(|_| {
            DecisionCardError::MalformedPayload(format!("{path} must be a signed 64-bit integer"))
        }),
        _ => Err(DecisionCardError::MalformedPayload(format!(
            "{path} must be an integer"
        ))),
    }
}

fn require_f64(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<f64, DecisionCardError> {
    let val = obj
        .get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?;
    match val {
        Value::Number(s) => {
            let n = s.parse::<f64>().map_err(|_| {
                DecisionCardError::MalformedPayload(format!("{path} must be a finite number"))
            })?;
            if !n.is_finite() {
                return Err(DecisionCardError::InvalidField {
                    field: path,
                    detail: "number must be finite".to_owned(),
                });
            }
            Ok(n)
        }
        _ => Err(DecisionCardError::MalformedPayload(format!(
            "{path} must be a JSON number"
        ))),
    }
}

fn require_bool(
    obj: &BTreeMap<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<bool, DecisionCardError> {
    obj.get(key)
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("missing required {path}")))?
        .boolean()
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("{path} must be a boolean")))
}

fn require_str_vec(
    val: &Value,
    field: &'static str,
    max_items: usize,
) -> Result<Vec<String>, DecisionCardError> {
    let arr = val
        .array()
        .ok_or_else(|| DecisionCardError::MalformedPayload(format!("{field} must be an array")))?;
    if arr.len() > max_items {
        return Err(DecisionCardError::BoundsExceeded {
            field,
            observed: arr.len(),
            maximum: max_items,
        });
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.text().ok_or_else(|| {
            DecisionCardError::MalformedPayload(format!("{field} elements must be strings"))
        })?;
        out.push(s.to_owned());
    }
    Ok(out)
}
