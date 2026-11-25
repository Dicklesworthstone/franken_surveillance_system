#![forbid(unsafe_code)]
//! Versioned binary wire codecs, canonical decoding, strict JSON codecs, and
//! compatibility validators for `SCHEMA-AGENT-SESSION-001` (`fss.agent_session.v1`)
//! and `SCHEMA-AGENT-WORKSPACE-001` (`fss.agent_session_capsule.v1`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::{
    AgentSession, AgentSessionParams, SessionCapsule, SessionCapsuleParams, has_disallowed_control,
    validate_decision_digest, validate_schema_token,
};
use crate::agent::ContractBasis;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{BudgetVector, ContractError};
use crate::contract_basis::{
    CANONICAL_SEMANTIC_PROTOCOL, ContractBasisError, SCHEMA_CONTRACT_BASIS, validate_contract_basis,
};
use crate::decision_card_v1::{DecisionCardError, EvidenceAnchorRecordV1};
use crate::digest::{ContentDigest, Sha256Hasher};
use crate::evidence::LedgerAnchor;
use crate::ids::{MissionId, PrincipalId, SessionId};
use crate::json_input::{self, Value};

/// Maximum token budget permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_TOKEN_BUDGET: u64 = 1_000_000;
/// Maximum capability entries permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_CAPABILITIES: usize = 256;
/// Maximum privacy-scope entries permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_PRIVACY_SCOPES: usize = 128;
/// Maximum session symbol bindings permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_SYMBOLS: usize = 1024;
/// Maximum continuation tokens permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_CONTINUATIONS: usize = 64;
/// Maximum subscription identities permitted by `schemas/agent_session.v1.json`.
pub const MAX_AGENT_SESSION_SUBSCRIPTIONS: usize = 64;
/// Magic 8-byte header for canonical `AgentSession` binary wire envelopes.
pub const AGENT_SESSION_WIRE_MAGIC: [u8; 8] = *b"FSSAGS01";
/// Current format version for `AgentSession` binary wire envelopes.
pub const AGENT_SESSION_FORMAT_VERSION: u32 = 1;
/// Hard upper bound on serialized `AgentSession` binary wire bytes (128 KiB).
pub const MAX_AGENT_SESSION_WIRE_BYTES: usize = 128 * 1024;

/// Maximum list items for general workspace capsule arrays (`schemas/agent_session_capsule.v1.json`).
pub const MAX_CAPSULE_LIST_ITEMS: usize = 4096;
/// Maximum epistemic-debt items (`schemas/agent_session_capsule.v1.json`).
pub const MAX_CAPSULE_EPISTEMIC_DEBT: usize = 1024;
/// Maximum byte length per workspace capsule list item (`schemas/agent_session_capsule.v1.json`).
pub const MAX_CAPSULE_ITEM_BYTES: usize = 4096;
/// Magic 8-byte header for canonical `SessionCapsule` binary wire envelopes.
pub const SESSION_CAPSULE_WIRE_MAGIC: [u8; 8] = *b"FSSAWC01";
/// Current format version for `SessionCapsule` binary wire envelopes.
pub const SESSION_CAPSULE_FORMAT_VERSION: u32 = 1;
/// Hard upper bound on serialized `SessionCapsule` binary wire bytes (512 KiB).
pub const MAX_SESSION_CAPSULE_WIRE_BYTES: usize = 512 * 1024;

/// Typed sentinel reason emitted for `lastAcknowledgedSituationFingerprint` when no situation is pinned.
pub const NO_ACKNOWLEDGED_SITUATION_REASON: &str = "no_acknowledged_situation_since_refresh";

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;
const DEFAULT_DEBT_DEFERRED_REASON: &str = "Carried as debt: the anchor it was bound to is no longer the workspace anchor, or a newer orientation no longer restates it.";
const DEFAULT_DEBT_CONSEQUENCE: &str =
    "Not recorded: the workspace retains the assumption statement only.";
const DEFAULT_DEBT_CHEAPEST_TEST: &str =
    "Orient at the current head and restate or retire the assumption.";
const DEFAULT_DEBT_REVIEW_TRIGGER: &str = "The next rebase or handoff of this session.";

/// Typed codec and compatibility errors for `SCHEMA-AGENT-SESSION-001` and
/// `SCHEMA-AGENT-WORKSPACE-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentContractCodecError {
    /// Underlying contract validation error.
    Contract(ContractError),
    /// Embedded `ContractBasis` validation error.
    Basis(ContractBasisError),
    /// JSON `schema` field did not match the expected registered schema identity.
    SchemaMismatch {
        /// Expected schema identity.
        expected: &'static str,
        /// Observed schema identity.
        observed: String,
    },
    /// Wire envelope magic header mismatch.
    InvalidMagic,
    /// Wire envelope format version unsupported.
    UnsupportedVersion {
        /// Observed unsupported wire version.
        version: u32,
    },
    /// Trailing SHA-256 checksum mismatch.
    ChecksumMismatch,
    /// Wire envelope exceeded configured size limit.
    WireTooLarge {
        /// Observed wire length in bytes.
        observed: usize,
        /// Maximum permitted wire length in bytes.
        maximum: usize,
    },
    /// Structural JSON or wire payload violation.
    MalformedPayload(String),
    /// Compatibility/immutability invariant violated across session refresh or workspace supersession.
    CompatibilityViolation(String),
}

impl AgentContractCodecError {
    /// Stable error identity aligned with `registries/ERRORS.md`.
    #[must_use]
    pub fn error_id(&self) -> &'static str {
        match self {
            Self::Contract(_) => "ERR-AGENT-CONTRACT-001",
            Self::Basis(err) => err.error_id(),
            Self::SchemaMismatch { .. }
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::WireTooLarge { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedPayload(_) => "ERR-AGENT-CONTRACT-MALFORMED-001",
            Self::CompatibilityViolation(_) => "ERR-AGENT-CONTRACT-COMPAT-001",
        }
    }
}

impl fmt::Display for AgentContractCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(err) => write!(f, "agent contract error: {err}"),
            Self::Basis(err) => write!(f, "agent contract basis error: {err}"),
            Self::SchemaMismatch { expected, observed } => write!(
                f,
                "agent contract schema mismatch: expected '{expected}', observed '{observed}'"
            ),
            Self::InvalidMagic => write!(f, "agent contract wire magic mismatch"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported agent contract wire version {version}")
            }
            Self::ChecksumMismatch => write!(f, "agent contract wire checksum mismatch"),
            Self::WireTooLarge { observed, maximum } => write!(
                f,
                "agent contract wire length {observed} exceeds maximum {maximum}"
            ),
            Self::MalformedPayload(detail) => write!(f, "malformed agent contract: {detail}"),
            Self::CompatibilityViolation(detail) => {
                write!(f, "agent contract compatibility violation: {detail}")
            }
        }
    }
}

impl Error for AgentContractCodecError {}

impl From<ContractError> for AgentContractCodecError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ContractBasisError> for AgentContractCodecError {
    fn from(value: ContractBasisError) -> Self {
        Self::Basis(value)
    }
}

impl AgentSession {
    /// Session records declare capability scope and never grant direct effect authority on their own.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Returns whether the session is within its explicit `[created_at_ns, expires_at_ns)` window.
    #[must_use]
    pub const fn is_active_at(&self, now_ns: i128) -> bool {
        now_ns >= self.created_at_ns && now_ns < self.expires_at_ns
    }

    /// Enforces `SCHEMA-AGENT-SESSION-001` continuity invariants across a session refresh:
    /// session/mission/principal identity and creation timestamp remain immutable, symbol-table
    /// generation is monotone, and the authority anchor cannot regress.
    pub fn verify_refresh_preserves_identity(
        &self,
        prior: &Self,
    ) -> Result<(), AgentContractCodecError> {
        self.validate()?;
        prior.validate()?;
        if self.session_id != prior.session_id {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "session_id changed across refresh".to_owned(),
            ));
        }
        if self.mission_id != prior.mission_id {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "mission_id changed across refresh".to_owned(),
            ));
        }
        if self.principal_id != prior.principal_id {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "principal_id changed across refresh".to_owned(),
            ));
        }
        if self.created_at_ns != prior.created_at_ns {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "created_at_ns mutated across refresh".to_owned(),
            ));
        }
        if self.symbol_table_generation < prior.symbol_table_generation {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "symbol_table_generation regressed across refresh".to_owned(),
            ));
        }
        if self.current_anchor.site_lineage != prior.current_anchor.site_lineage
            || self.current_anchor.ledger_epoch != prior.current_anchor.ledger_epoch
            || (
                self.current_anchor.commit_sequence,
                self.current_anchor.adapter_registry_epoch,
            ) < (
                prior.current_anchor.commit_sequence,
                prior.current_anchor.adapter_registry_epoch,
            )
        {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "current_anchor regressed or switched lineage across refresh".to_owned(),
            ));
        }
        Ok(())
    }

    /// Encodes this session into its versioned, checksummed canonical binary wire envelope
    /// (`FSSAGS01` v1 + trailing SHA-256 over [`Self::SCHEMA`]).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AgentContractCodecError> {
        self.validate()?;
        encode_wire_envelope(
            self,
            Self::SCHEMA,
            AGENT_SESSION_WIRE_MAGIC,
            AGENT_SESSION_FORMAT_VERSION,
            MAX_AGENT_SESSION_WIRE_BYTES,
        )
    }

    /// Strictly decodes an `FSSAGS01` v1 binary wire envelope into an [`AgentSession`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AgentContractCodecError> {
        decode_wire_envelope(
            bytes,
            Self::SCHEMA,
            AGENT_SESSION_WIRE_MAGIC,
            AGENT_SESSION_FORMAT_VERSION,
            MAX_AGENT_SESSION_WIRE_BYTES,
        )
    }

    /// Emits deterministic canonical JSON strictly conforming to `schemas/agent_session.v1.json`.
    pub fn to_canonical_json(
        &self,
        basis: &ContractBasis,
        device_generation: &str,
        stream_generation: &str,
    ) -> Result<String, AgentContractCodecError> {
        self.validate()?;
        validate_contract_basis(basis)?;
        let anchor_rec = EvidenceAnchorRecordV1::from_ledger_anchor(
            &self.current_anchor,
            device_generation,
            stream_generation,
        )
        .map_err(|e| AgentContractCodecError::MalformedPayload(e.to_string()))?;
        let fingerprint = self.last_acknowledged_situation_fingerprint.map_or_else(
            || {
                not_applicable_sentinel(
                    Self::SCHEMA,
                    "lastAcknowledgedSituationFingerprint",
                    NO_ACKNOWLEDGED_SITUATION_REASON,
                )
            },
            |d| d.to_text(),
        );
        let mut out = String::with_capacity(1024);
        out.push('{');
        push_key(&mut out, "capabilities");
        write_str_iter(&mut out, self.capabilities.iter().map(String::as_str));
        out.push(',');
        push_key(&mut out, "contractBasis");
        write_contract_basis_json(&mut out, basis);
        out.push(',');
        push_key(&mut out, "createdAtNs");
        out.push_str(&self.created_at_ns.to_string());
        out.push(',');
        push_key(&mut out, "currentAnchor");
        anchor_rec.write_canonical_json(&mut out);
        out.push(',');
        push_key(&mut out, "expiresAtNs");
        out.push_str(&self.expires_at_ns.to_string());
        out.push(',');
        push_kv_str(
            &mut out,
            "lastAcknowledgedSituationFingerprint",
            &fingerprint,
        );
        out.push(',');
        push_kv_str(&mut out, "missionId", self.mission_id.as_str());
        out.push(',');
        push_kv_str(&mut out, "principalId", self.principal_id.as_str());
        out.push(',');
        push_key(&mut out, "privacyScope");
        write_str_iter(&mut out, self.privacy_scope.iter().map(String::as_str));
        out.push(',');
        push_kv_str(&mut out, "schema", Self::SCHEMA);
        out.push(',');
        push_kv_str(&mut out, "sessionId", self.session_id.as_str());
        out.push(',');
        push_key(&mut out, "symbolTableGeneration");
        out.push_str(&self.symbol_table_generation.to_string());
        out.push(',');
        push_key(&mut out, "tokenBudget");
        out.push_str(&self.token_budget.to_string());
        out.push(',');
        push_kv_str(&mut out, "viewId", self.view.id());
        out.push('}');
        Ok(out)
    }

    /// Strictly parses and validates a JSON document against `schemas/agent_session.v1.json`,
    /// returning the validated `(AgentSession, ContractBasis)` pair.
    ///
    /// Enforces `additionalProperties: false`, `uniqueItems: true` on `capabilities` and
    /// `privacyScope`, exact nested `contractBasis` and `currentAnchor` schemas, bounded
    /// `tokenBudget`, and full validation of optional `symbols`, `continuations`,
    /// `subscriptions`, and `parentHandoffId` fields when present.
    pub fn from_json(text: &str) -> Result<(Self, ContractBasis), AgentContractCodecError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "contractBasis",
            "sessionId",
            "missionId",
            "principalId",
            "capabilities",
            "privacyScope",
            "currentAnchor",
            "viewId",
            "tokenBudget",
            "symbolTableGeneration",
            "symbols",
            "continuations",
            "subscriptions",
            "lastAcknowledgedSituationFingerprint",
            "parentHandoffId",
            "createdAtNs",
            "expiresAtNs",
        ];
        let val = json_input::parse(text)
            .map_err(|e| AgentContractCodecError::MalformedPayload(e.to_string()))?;
        let obj = val.object().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("root must be a JSON object".to_owned())
        })?;
        reject_unknown_keys(obj, ALLOWED, "agent_session")?;
        let schema = req_str(obj, "schema")?;
        if schema != Self::SCHEMA {
            return Err(AgentContractCodecError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let basis = parse_contract_basis_json(obj.get("contractBasis").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing contractBasis".to_owned())
        })?)?;
        let session_id = SessionId::parse(req_str(obj, "sessionId")?)?;
        let mission_id = MissionId::parse(req_str(obj, "missionId")?)?;
        let principal_id = PrincipalId::parse(req_str(obj, "principalId")?)?;
        let capabilities =
            req_unique_token_set(obj, "capabilities", MAX_AGENT_SESSION_CAPABILITIES)?;
        let privacy_scope =
            req_unique_token_set(obj, "privacyScope", MAX_AGENT_SESSION_PRIVACY_SCOPES)?;
        let current_anchor = parse_anchor_json(obj.get("currentAnchor").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing currentAnchor".to_owned())
        })?)?;
        let view_id = req_str(obj, "viewId")?.to_owned();
        let token_budget = req_u64(obj, "tokenBudget")?;
        let symbol_table_generation = req_u64(obj, "symbolTableGeneration")?;
        let fp_raw = req_str(obj, "lastAcknowledgedSituationFingerprint")?;
        let last_acknowledged_situation_fingerprint = if is_valid_fss_na_sentinel(fp_raw) {
            None
        } else {
            Some(ContentDigest::parse(fp_raw)?)
        };
        let created_at_ns = req_i128(obj, "createdAtNs")?;
        let expires_at_ns = req_i128(obj, "expiresAtNs")?;

        if let Some(symbols_val) = obj.get("symbols") {
            validate_symbols_json(symbols_val)?;
        }
        if let Some(cont_val) = obj.get("continuations") {
            validate_token_array(cont_val, "continuations", MAX_AGENT_SESSION_CONTINUATIONS)?;
        }
        if let Some(subs_val) = obj.get("subscriptions") {
            validate_token_array(subs_val, "subscriptions", MAX_AGENT_SESSION_SUBSCRIPTIONS)?;
        }
        if let Some(parent_val) = obj.get("parentHandoffId") {
            match parent_val {
                Value::Null => {}
                Value::Text(s) => validate_schema_token(s)?,
                _ => {
                    return Err(AgentContractCodecError::MalformedPayload(
                        "parentHandoffId must be a valid token string or null".to_owned(),
                    ));
                }
            }
        }

        let session = Self::new(AgentSessionParams {
            session_id,
            mission_id,
            principal_id,
            capabilities,
            privacy_scope,
            current_anchor,
            view_id,
            token_budget,
            symbol_table_generation,
            last_acknowledged_situation_fingerprint,
            created_at_ns,
            expires_at_ns,
        })?;
        Ok((session, basis))
    }
}

impl CanonicalDecode for AgentSession {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        if decoder.text()? != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let session_id = SessionId::parse(decoder.text()?)?;
        let mission_id = MissionId::parse(decoder.text()?)?;
        let principal_id = PrincipalId::parse(decoder.text()?)?;
        let capabilities = decode_strict_set(decoder, MAX_AGENT_SESSION_CAPABILITIES)?;
        let privacy_scope = decode_strict_set(decoder, MAX_AGENT_SESSION_PRIVACY_SCOPES)?;
        let current_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let view_id = decoder.text()?.to_owned();
        let token_budget = decoder.u64()?;
        let symbol_table_generation = decoder.u64()?;
        let last_acknowledged_situation_fingerprint = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        let created_at_ns = decoder.i128()?;
        let expires_at_ns = decoder.i128()?;
        Self::new(AgentSessionParams {
            session_id,
            mission_id,
            principal_id,
            capabilities,
            privacy_scope,
            current_anchor,
            view_id,
            token_budget,
            symbol_table_generation,
            last_acknowledged_situation_fingerprint,
            created_at_ns,
            expires_at_ns,
        })
    }
}

impl SessionCapsule {
    /// Workspace continuity capsules never grant direct effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Enforces `SCHEMA-AGENT-WORKSPACE-001` compatibility rule:
    /// *"workspace revisions are immutable and resume records stale and invalidated state"*.
    ///
    /// Verifies same `session_id`, strictly increasing `revision`, non-regressing `current_anchor`
    /// in the same lineage and epoch, distinct canonical digest, and that whenever the anchor
    /// advanced, every prior `next_actions` entry dropped from `self.next_actions` is explicitly
    /// accounted for in `invalidated_items` or `self.epistemic_debt`.
    pub fn verify_supersedes(
        &self,
        prior: &Self,
        invalidated_items: &[String],
    ) -> Result<(), AgentContractCodecError> {
        self.validate()?;
        prior.validate()?;
        if self.session_id != prior.session_id {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "workspace capsule session_id changed across revisions".to_owned(),
            ));
        }
        if self.revision <= prior.revision {
            return Err(AgentContractCodecError::CompatibilityViolation(format!(
                "workspace revision {} must strictly supersede prior revision {} (immutable revisions)",
                self.revision, prior.revision
            )));
        }
        if self.capsule_digest() == prior.capsule_digest() {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "superseding workspace capsule digest identical to prior revision".to_owned(),
            ));
        }
        if self.current_anchor.site_lineage != prior.current_anchor.site_lineage
            || self.current_anchor.ledger_epoch != prior.current_anchor.ledger_epoch
            || (
                self.current_anchor.commit_sequence,
                self.current_anchor.adapter_registry_epoch,
            ) < (
                prior.current_anchor.commit_sequence,
                prior.current_anchor.adapter_registry_epoch,
            )
        {
            return Err(AgentContractCodecError::CompatibilityViolation(
                "workspace current_anchor regressed or switched lineage across revisions"
                    .to_owned(),
            ));
        }
        if self.current_anchor != prior.current_anchor {
            for prior_action in &prior.next_actions {
                let retained = self.next_actions.contains(prior_action);
                let recorded_invalidated = invalidated_items.contains(prior_action);
                let recorded_debt = self
                    .epistemic_debt
                    .iter()
                    .any(|entry| entry.contains(prior_action.as_str()));
                if !retained && !recorded_invalidated && !recorded_debt {
                    return Err(AgentContractCodecError::CompatibilityViolation(format!(
                        "anchor rebase silently dropped prior next_action '{prior_action}' without recording invalidated_items or epistemic_debt"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Encodes this workspace capsule into its versioned, checksummed canonical binary wire
    /// envelope (`FSSAWC01` v1 + trailing SHA-256 over [`Self::SCHEMA`]).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AgentContractCodecError> {
        self.validate()?;
        encode_wire_envelope(
            self,
            Self::SCHEMA,
            SESSION_CAPSULE_WIRE_MAGIC,
            SESSION_CAPSULE_FORMAT_VERSION,
            MAX_SESSION_CAPSULE_WIRE_BYTES,
        )
    }

    /// Strictly decodes an `FSSAWC01` v1 binary wire envelope into a [`SessionCapsule`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AgentContractCodecError> {
        decode_wire_envelope(
            bytes,
            Self::SCHEMA,
            SESSION_CAPSULE_WIRE_MAGIC,
            SESSION_CAPSULE_FORMAT_VERSION,
            MAX_SESSION_CAPSULE_WIRE_BYTES,
        )
    }

    /// Emits deterministic canonical JSON strictly conforming to
    /// `schemas/agent_session_capsule.v1.json`.
    pub fn to_canonical_json(
        &self,
        basis: &ContractBasis,
        invalidated_items: &[String],
        device_generation: &str,
        stream_generation: &str,
    ) -> Result<String, AgentContractCodecError> {
        self.validate()?;
        validate_contract_basis(basis)?;
        if invalidated_items.len() > MAX_CAPSULE_LIST_ITEMS {
            return Err(AgentContractCodecError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        for item in invalidated_items {
            if item.len() > MAX_CAPSULE_ITEM_BYTES || has_disallowed_control(item) {
                return Err(AgentContractCodecError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        let base_anchor_rec = EvidenceAnchorRecordV1::from_ledger_anchor(
            &self.base_anchor,
            device_generation,
            stream_generation,
        )
        .map_err(|e| AgentContractCodecError::MalformedPayload(e.to_string()))?;
        let current_anchor_rec = EvidenceAnchorRecordV1::from_ledger_anchor(
            &self.current_anchor,
            device_generation,
            stream_generation,
        )
        .map_err(|e| AgentContractCodecError::MalformedPayload(e.to_string()))?;
        let mut out = String::with_capacity(2048);
        out.push('{');
        push_key(&mut out, "activeHypotheses");
        write_str_iter(&mut out, self.active_hypotheses.iter().map(String::as_str));
        out.push(',');
        push_key(&mut out, "assumptions");
        write_str_iter(&mut out, self.assumptions.iter().map(String::as_str));
        out.push(',');
        push_key(&mut out, "baseAnchor");
        base_anchor_rec.write_canonical_json(&mut out);
        out.push(',');
        push_key(&mut out, "bookmarkedEvidence");
        out.push('[');
        for (i, d) in self.bookmarked_evidence.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_escaped_str(&mut out, &d.to_text());
        }
        out.push(']');
        out.push(',');
        push_key(&mut out, "budgetLedger");
        write_budget_json(&mut out, self.budget_ledger);
        out.push(',');
        push_key(&mut out, "capabilityProjection");
        write_str_iter(
            &mut out,
            self.capability_projection.iter().map(String::as_str),
        );
        out.push(',');
        push_key(&mut out, "contractBasis");
        write_contract_basis_json(&mut out, basis);
        out.push(',');
        push_key(&mut out, "currentAnchor");
        current_anchor_rec.write_canonical_json(&mut out);
        out.push(',');
        push_kv_str(&mut out, "decisionDigest", &self.decision_digest);
        out.push(',');
        push_key(&mut out, "epistemicDebt");
        out.push('[');
        for (i, entry) in self.epistemic_debt.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_epistemic_debt_item_json(&mut out, entry)?;
        }
        out.push(']');
        out.push(',');
        push_key(&mut out, "invalidatedItems");
        write_str_iter(&mut out, invalidated_items.iter().map(String::as_str));
        out.push(',');
        push_key(&mut out, "nextActions");
        write_str_iter(&mut out, self.next_actions.iter().map(String::as_str));
        out.push(',');
        push_key(&mut out, "notObservableDomains");
        write_str_iter(
            &mut out,
            self.not_observable_domains.iter().map(String::as_str),
        );
        out.push(',');
        push_kv_str(&mut out, "objectiveDigest", &self.objective_digest);
        out.push(',');
        push_key(&mut out, "openObligations");
        write_str_iter(&mut out, self.open_obligations.iter().map(String::as_str));
        out.push(',');
        push_kv_str(&mut out, "principal", &self.principal);
        out.push(',');
        push_key(&mut out, "revision");
        out.push_str(&self.revision.to_string());
        out.push(',');
        push_kv_str(&mut out, "schema", Self::SCHEMA);
        out.push(',');
        push_kv_str(&mut out, "sessionId", self.session_id.as_str());
        out.push(',');
        push_kv_str(
            &mut out,
            "situationCapsuleDigest",
            &self.situation_capsule_digest,
        );
        out.push(',');
        push_key(&mut out, "unknowns");
        write_str_iter(&mut out, self.unknowns.iter().map(String::as_str));
        out.push('}');
        Ok(out)
    }

    /// Strictly parses and validates a JSON document against
    /// `schemas/agent_session_capsule.v1.json`, returning `(SessionCapsule, ContractBasis, invalidated_items)`.
    pub fn from_json(
        text: &str,
    ) -> Result<(Self, ContractBasis, Vec<String>), AgentContractCodecError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "contractBasis",
            "sessionId",
            "revision",
            "priorCapsuleDigest",
            "principal",
            "role",
            "capabilityProjection",
            "objectiveDigest",
            "baseAnchor",
            "currentAnchor",
            "situationCapsuleDigest",
            "situationFrameDigest",
            "hypothesisWorkspaceDigest",
            "activeHypotheses",
            "assumptions",
            "unknowns",
            "notObservableDomains",
            "epistemicDebt",
            "activePlanDigest",
            "planFrontier",
            "openObligations",
            "leases",
            "approvals",
            "budgetLedger",
            "bookmarkedEvidence",
            "decisionReceipts",
            "effectReceipts",
            "learningProposalIds",
            "invalidatedItems",
            "nextActions",
            "reanchorTriggers",
            "decisionDigest",
        ];
        let val = json_input::parse(text)
            .map_err(|e| AgentContractCodecError::MalformedPayload(e.to_string()))?;
        let obj = val.object().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("root must be a JSON object".to_owned())
        })?;
        reject_unknown_keys(obj, ALLOWED, "agent_session_capsule")?;
        let schema = req_str(obj, "schema")?;
        if schema != Self::SCHEMA {
            return Err(AgentContractCodecError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let basis = parse_contract_basis_json(obj.get("contractBasis").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing contractBasis".to_owned())
        })?)?;
        let session_id = SessionId::parse(req_str(obj, "sessionId")?)?;
        let revision = req_u64(obj, "revision")?;
        let principal = req_str(obj, "principal")?.to_owned();
        let capability_projection =
            req_bounded_str_vec(obj, "capabilityProjection", MAX_CAPSULE_LIST_ITEMS)?;
        let objective_digest = req_str(obj, "objectiveDigest")?.to_owned();
        let base_anchor = parse_anchor_json(obj.get("baseAnchor").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing baseAnchor".to_owned())
        })?)?;
        let current_anchor = parse_anchor_json(obj.get("currentAnchor").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing currentAnchor".to_owned())
        })?)?;
        let situation_capsule_digest = req_str(obj, "situationCapsuleDigest")?.to_owned();
        let active_hypotheses =
            req_bounded_str_vec(obj, "activeHypotheses", MAX_CAPSULE_LIST_ITEMS)?;
        let assumptions = req_bounded_str_vec(obj, "assumptions", MAX_CAPSULE_LIST_ITEMS)?;
        let unknowns = req_bounded_str_vec(obj, "unknowns", MAX_CAPSULE_LIST_ITEMS)?;
        let not_observable_domains =
            req_bounded_str_vec(obj, "notObservableDomains", MAX_CAPSULE_LIST_ITEMS)?;
        let epistemic_debt =
            parse_epistemic_debt_json(obj.get("epistemicDebt").ok_or_else(|| {
                AgentContractCodecError::MalformedPayload("missing epistemicDebt".to_owned())
            })?)?;
        let open_obligations = req_bounded_str_vec(obj, "openObligations", MAX_CAPSULE_LIST_ITEMS)?;
        let budget_ledger = parse_budget_json(obj.get("budgetLedger").ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("missing budgetLedger".to_owned())
        })?)?;
        let raw_bookmarks = req_bounded_str_vec(obj, "bookmarkedEvidence", MAX_CAPSULE_LIST_ITEMS)?;
        let mut bookmarked_evidence = Vec::with_capacity(raw_bookmarks.len());
        for raw in raw_bookmarks {
            bookmarked_evidence.push(ContentDigest::parse(&raw)?);
        }
        let next_actions = req_bounded_str_vec(obj, "nextActions", MAX_CAPSULE_LIST_ITEMS)?;
        let decision_digest = req_str(obj, "decisionDigest")?.to_owned();

        // Validate optional fields strictly when present.
        for opt_digest in [
            "priorCapsuleDigest",
            "hypothesisWorkspaceDigest",
            "activePlanDigest",
        ] {
            if let Some(v) = obj.get(opt_digest) {
                match v {
                    Value::Null => {}
                    Value::Text(s) => validate_decision_digest(s)?,
                    _ => {
                        return Err(AgentContractCodecError::MalformedPayload(format!(
                            "{opt_digest} must be a decision digest string or null"
                        )));
                    }
                }
            }
        }
        if let Some(v) = obj.get("situationFrameDigest") {
            let s = v.text().ok_or_else(|| {
                AgentContractCodecError::MalformedPayload(
                    "situationFrameDigest must be string".to_owned(),
                )
            })?;
            validate_decision_digest(s)?;
        }
        if let Some(v) = obj.get("role") {
            match v {
                Value::Null => {}
                Value::Text(s) if s.len() <= 256 && !has_disallowed_control(s) => {}
                _ => {
                    return Err(AgentContractCodecError::MalformedPayload(
                        "role must be null or bounded control-free string".to_owned(),
                    ));
                }
            }
        }
        for opt_list in [
            "planFrontier",
            "leases",
            "approvals",
            "decisionReceipts",
            "effectReceipts",
            "learningProposalIds",
            "reanchorTriggers",
        ] {
            if let Some(v) = obj.get(opt_list) {
                let _ = parse_bounded_str_array(v, opt_list, MAX_CAPSULE_LIST_ITEMS)?;
            }
        }
        let invalidated_items = match obj.get("invalidatedItems") {
            None => Vec::new(),
            Some(v) => parse_bounded_str_array(v, "invalidatedItems", MAX_CAPSULE_LIST_ITEMS)?,
        };

        let capsule = Self::new(SessionCapsuleParams {
            session_id,
            revision,
            principal,
            capability_projection,
            objective_digest,
            base_anchor,
            current_anchor,
            situation_capsule_digest,
            active_hypotheses,
            assumptions,
            unknowns,
            not_observable_domains,
            epistemic_debt,
            open_obligations,
            budget_ledger,
            bookmarked_evidence,
            next_actions,
            decision_digest,
        })?;
        Ok((capsule, basis, invalidated_items))
    }
}

impl CanonicalDecode for SessionCapsule {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        if decoder.text()? != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let session_id = SessionId::parse(decoder.text()?)?;
        let revision = decoder.u64()?;
        let principal = decoder.text()?.to_owned();
        let capability_projection = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let objective_digest = decoder.text()?.to_owned();
        let base_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let current_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let situation_capsule_digest = decoder.text()?.to_owned();
        let active_hypotheses = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let assumptions = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let unknowns = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let not_observable_domains = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let epistemic_debt = decode_bounded_vec(decoder, MAX_CAPSULE_EPISTEMIC_DEBT)?;
        let open_obligations = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let budget_ledger = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        let bookmark_count = decoder.u32()? as usize;
        if bookmark_count > MAX_CAPSULE_LIST_ITEMS
            || bookmark_count.saturating_mul(32) > decoder.remaining()
        {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut bookmarked_evidence = Vec::with_capacity(bookmark_count);
        for _ in 0..bookmark_count {
            bookmarked_evidence.push(decoder.digest()?);
        }
        let next_actions = decode_bounded_vec(decoder, MAX_CAPSULE_LIST_ITEMS)?;
        let decision_digest = decoder.text()?.to_owned();
        Self::new(SessionCapsuleParams {
            session_id,
            revision,
            principal,
            capability_projection,
            objective_digest,
            base_anchor,
            current_anchor,
            situation_capsule_digest,
            active_hypotheses,
            assumptions,
            unknowns,
            not_observable_domains,
            epistemic_debt,
            open_obligations,
            budget_ledger,
            bookmarked_evidence,
            next_actions,
            decision_digest,
        })
    }
}

fn encode_wire_envelope<T: CanonicalEncode>(
    value: &T,
    domain: &str,
    magic: [u8; 8],
    version: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, AgentContractCodecError> {
    let mut encoder = CanonicalEncoder::new();
    value.encode_canonical(&mut encoder);
    let payload = encoder.finish_checked()?;
    let total_len = WIRE_HEADER_BYTES
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
        .ok_or(AgentContractCodecError::WireTooLarge {
            observed: usize::MAX,
            maximum: max_bytes,
        })?;
    if total_len > max_bytes {
        return Err(AgentContractCodecError::WireTooLarge {
            observed: total_len,
            maximum: max_bytes,
        });
    }
    let payload_len_u32 =
        u32::try_from(payload.len()).map_err(|_| AgentContractCodecError::WireTooLarge {
            observed: total_len,
            maximum: max_bytes,
        })?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&payload_len_u32.to_be_bytes());
    out.extend_from_slice(&payload);
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&out);
    let checksum = hasher.finalize()?;
    out.extend_from_slice(&checksum);
    Ok(out)
}

fn decode_wire_envelope<T: CanonicalDecode>(
    bytes: &[u8],
    domain: &str,
    expected_magic: [u8; 8],
    expected_version: u32,
    max_bytes: usize,
) -> Result<T, AgentContractCodecError> {
    let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
    if bytes.len() < min_len {
        return Err(AgentContractCodecError::MalformedPayload(format!(
            "wire envelope length {} below minimum {min_len}",
            bytes.len()
        )));
    }
    if bytes.len() > max_bytes {
        return Err(AgentContractCodecError::WireTooLarge {
            observed: bytes.len(),
            maximum: max_bytes,
        });
    }
    if bytes[..8] != expected_magic {
        return Err(AgentContractCodecError::InvalidMagic);
    }
    let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != expected_version {
        return Err(AgentContractCodecError::UnsupportedVersion { version });
    }
    let declared_len = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let expected_total = WIRE_HEADER_BYTES
        .checked_add(declared_len)
        .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
        .ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("declared payload length overflow".to_owned())
        })?;
    if bytes.len() != expected_total {
        return Err(AgentContractCodecError::MalformedPayload(format!(
            "wire length {} disagrees with declared payload length {declared_len}",
            bytes.len()
        )));
    }
    let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
    let (body, trailer) = bytes.split_at(split_at);
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(body);
    let computed = hasher.finalize()?;
    if computed.as_slice() != trailer {
        return Err(AgentContractCodecError::ChecksumMismatch);
    }
    let payload = &body[WIRE_HEADER_BYTES..];
    let mut decoder = CanonicalDecoder::new(payload);
    let value = T::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    Ok(value)
}

fn decode_strict_set(
    decoder: &mut CanonicalDecoder<'_>,
    max_items: usize,
) -> Result<BTreeSet<String>, ContractError> {
    let count = decoder.u32()? as usize;
    if count > max_items || count.saturating_mul(8) > decoder.remaining() {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut out = BTreeSet::new();
    for _ in 0..count {
        let value = decoder.text()?;
        if out
            .last()
            .is_some_and(|prev: &String| prev.as_str() >= value)
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        out.insert(value.to_owned());
    }
    Ok(out)
}

fn decode_bounded_vec(
    decoder: &mut CanonicalDecoder<'_>,
    max_items: usize,
) -> Result<Vec<String>, ContractError> {
    let count = decoder.u32()? as usize;
    if count > max_items || count.saturating_mul(8) > decoder.remaining() {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decoder.text()?.to_owned());
    }
    Ok(out)
}

fn not_applicable_sentinel(schema: &str, field: &str, reason: &str) -> String {
    let digest = ContentDigest::sha256(format!("{schema}/sentinel/{field}/{reason}").as_bytes());
    let text = digest.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, h)| h);
    format!("fss-na:{hex}")
}

fn is_valid_fss_na_sentinel(raw: &str) -> bool {
    raw.strip_prefix("fss-na:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn is_valid_symbol_alias(alias: &str) -> bool {
    let bytes = alias.as_bytes();
    (3..=8).contains(&bytes.len())
        && bytes[0] == b'@'
        && bytes[1].is_ascii_lowercase()
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn validate_symbols_json(val: &Value) -> Result<(), AgentContractCodecError> {
    const ALLOWED: &[&str] = &[
        "alias",
        "objectId",
        "objectRevision",
        "anchorFingerprint",
        "expiresAtNs",
        "invalidators",
    ];
    let arr = val.array().ok_or_else(|| {
        AgentContractCodecError::MalformedPayload("symbols must be array".to_owned())
    })?;
    if arr.len() > MAX_AGENT_SESSION_SYMBOLS {
        return Err(AgentContractCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    for item in arr {
        let obj = item.object().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("symbols[] must be JSON object".to_owned())
        })?;
        reject_unknown_keys(obj, ALLOWED, "symbols[]")?;
        let alias = req_str(obj, "alias")?;
        if !is_valid_symbol_alias(alias) {
            return Err(AgentContractCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        validate_schema_token(req_str(obj, "objectId")?)?;
        let _ = req_u64(obj, "objectRevision")?;
        let fp = req_str(obj, "anchorFingerprint")?;
        if !is_valid_fss_na_sentinel(fp) {
            let _ = ContentDigest::parse(fp)?;
        }
        let exp = req_i128(obj, "expiresAtNs")?;
        if exp < 0 {
            return Err(AgentContractCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if let Some(inv_val) = obj.get("invalidators") {
            let inv_arr = inv_val.array().ok_or_else(|| {
                AgentContractCodecError::MalformedPayload(
                    "symbols[].invalidators must be array".to_owned(),
                )
            })?;
            if inv_arr.len() > 64 {
                return Err(AgentContractCodecError::Contract(
                    ContractError::CountBoundExceeded,
                ));
            }
            for entry in inv_arr {
                let s = entry.text().ok_or_else(|| {
                    AgentContractCodecError::MalformedPayload(
                        "symbols[].invalidators items must be strings".to_owned(),
                    )
                })?;
                if s.is_empty() || s.len() > 1024 || has_disallowed_control(s) {
                    return Err(AgentContractCodecError::Contract(
                        ContractError::InvalidIdentifier,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_token_array(
    val: &Value,
    field: &str,
    max_items: usize,
) -> Result<(), AgentContractCodecError> {
    let arr = val.array().ok_or_else(|| {
        AgentContractCodecError::MalformedPayload(format!("{field} must be array"))
    })?;
    if arr.len() > max_items {
        return Err(AgentContractCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    for item in arr {
        let s = item.text().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload(format!("{field} items must be strings"))
        })?;
        validate_schema_token(s)?;
    }
    Ok(())
}

fn write_contract_basis_json(out: &mut String, basis: &ContractBasis) {
    out.push('{');
    if let Some(ref nightly) = basis.accepted_nightly {
        push_kv_str(out, "acceptedNightly", nightly);
        out.push(',');
    }
    push_kv_str(
        out,
        "capabilityRegistryDigest",
        &basis.capability_registry_digest.to_text(),
    );
    out.push(',');
    push_kv_str(
        out,
        "costRegistryDigest",
        &basis.cost_registry_digest.to_text(),
    );
    out.push(',');
    push_kv_str(
        out,
        "errorRegistryDigest",
        &basis.error_registry_digest.to_text(),
    );
    out.push(',');
    push_kv_str(out, "ontologyGenerationId", &basis.ontology_generation_id);
    out.push(',');
    push_kv_str(
        out,
        "operationRegistryDigest",
        &basis.operation_registry_digest.to_text(),
    );
    out.push(',');
    push_kv_str(out, "producerReleaseId", &basis.producer_release_id);
    out.push(',');
    push_kv_str(out, "schema", SCHEMA_CONTRACT_BASIS);
    out.push(',');
    push_kv_str(
        out,
        "schemaCatalogDigest",
        &basis.schema_catalog_digest.to_text(),
    );
    out.push(',');
    push_kv_str(out, "semanticProtocol", &basis.semantic_protocol);
    out.push(',');
    push_kv_str(
        out,
        "viewRegistryDigest",
        &basis.view_registry_digest.to_text(),
    );
    out.push('}');
}

fn parse_contract_basis_json(val: &Value) -> Result<ContractBasis, AgentContractCodecError> {
    const ALLOWED: &[&str] = &[
        "schema",
        "semanticProtocol",
        "schemaCatalogDigest",
        "ontologyGenerationId",
        "operationRegistryDigest",
        "viewRegistryDigest",
        "capabilityRegistryDigest",
        "errorRegistryDigest",
        "costRegistryDigest",
        "producerReleaseId",
        "acceptedNightly",
        "compatibilityNotes",
    ];
    let obj = val.object().ok_or_else(|| {
        AgentContractCodecError::MalformedPayload("contractBasis must be JSON object".to_owned())
    })?;
    reject_unknown_keys(obj, ALLOWED, "contractBasis")?;
    let schema = req_str(obj, "schema")?;
    if schema != SCHEMA_CONTRACT_BASIS {
        return Err(AgentContractCodecError::SchemaMismatch {
            expected: SCHEMA_CONTRACT_BASIS,
            observed: schema.to_owned(),
        });
    }
    let semantic_protocol = req_str(obj, "semanticProtocol")?.to_owned();
    if semantic_protocol != CANONICAL_SEMANTIC_PROTOCOL {
        return Err(AgentContractCodecError::Basis(
            ContractBasisError::IncompatibleProtocol {
                expected: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
                actual: semantic_protocol,
            },
        ));
    }
    let ontology_generation_id = req_str(obj, "ontologyGenerationId")?.to_owned();
    validate_schema_token(&ontology_generation_id)?;
    let producer_release_id = req_str(obj, "producerReleaseId")?.to_owned();
    validate_schema_token(&producer_release_id)?;
    let accepted_nightly = match obj.get("acceptedNightly") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) if s.len() <= 128 => Some(s.clone()),
        Some(_) => {
            return Err(AgentContractCodecError::MalformedPayload(
                "acceptedNightly must be null or string <= 128 bytes".to_owned(),
            ));
        }
    };
    if let Some(notes_val) = obj.get("compatibilityNotes") {
        let arr = notes_val.array().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload("compatibilityNotes must be array".to_owned())
        })?;
        if arr.len() > 64 {
            return Err(AgentContractCodecError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        for item in arr {
            let s = item.text().ok_or_else(|| {
                AgentContractCodecError::MalformedPayload(
                    "compatibilityNotes items must be strings".to_owned(),
                )
            })?;
            if s.is_empty() || s.len() > 1024 || has_disallowed_control(s) {
                return Err(AgentContractCodecError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
    }
    let basis = ContractBasis {
        semantic_protocol,
        schema_catalog_digest: ContentDigest::parse(req_str(obj, "schemaCatalogDigest")?)?,
        ontology_generation_id,
        operation_registry_digest: ContentDigest::parse(req_str(obj, "operationRegistryDigest")?)?,
        view_registry_digest: ContentDigest::parse(req_str(obj, "viewRegistryDigest")?)?,
        capability_registry_digest: ContentDigest::parse(req_str(
            obj,
            "capabilityRegistryDigest",
        )?)?,
        error_registry_digest: ContentDigest::parse(req_str(obj, "errorRegistryDigest")?)?,
        cost_registry_digest: ContentDigest::parse(req_str(obj, "costRegistryDigest")?)?,
        producer_release_id,
        accepted_nightly,
    };
    validate_contract_basis(&basis)?;
    Ok(basis)
}

fn parse_anchor_json(val: &Value) -> Result<LedgerAnchor, AgentContractCodecError> {
    let rec = EvidenceAnchorRecordV1::from_json_value(val).map_err(|e| match e {
        DecisionCardError::SchemaMismatch { expected, observed } => {
            AgentContractCodecError::SchemaMismatch { expected, observed }
        }
        other => AgentContractCodecError::MalformedPayload(other.to_string()),
    })?;
    let state_root = ContentDigest::parse(&rec.authority_root)?;
    Ok(LedgerAnchor {
        site_lineage: rec.deployment_id,
        ledger_epoch: rec.observation_epoch,
        commit_sequence: rec.capsule_sequence,
        adapter_registry_epoch: rec.adapter_epoch,
        schema_epoch: rec.schema_epoch,
        policy_epoch: rec.policy_epoch,
        privacy_epoch: rec.privacy_epoch.unwrap_or(1),
        state_root,
    })
}

fn write_epistemic_debt_item_json(
    out: &mut String,
    entry: &str,
) -> Result<(), AgentContractCodecError> {
    let (debt_id, assumption) = entry.split_once(": ").unwrap_or((entry, entry));
    if debt_id.is_empty() || debt_id.len() > 256 {
        return Err(AgentContractCodecError::Contract(
            ContractError::InvalidIdentifier,
        ));
    }
    out.push('{');
    push_kv_str(out, "assumption", assumption);
    out.push(',');
    push_kv_str(out, "cheapestTest", DEFAULT_DEBT_CHEAPEST_TEST);
    out.push(',');
    push_kv_str(out, "consequenceIfWrong", DEFAULT_DEBT_CONSEQUENCE);
    out.push(',');
    push_kv_str(out, "debtId", debt_id);
    out.push(',');
    push_kv_str(out, "deferredReason", DEFAULT_DEBT_DEFERRED_REASON);
    out.push(',');
    push_key(out, "dependentDecisions");
    out.push_str("[]");
    out.push(',');
    push_kv_str(out, "reviewTrigger", DEFAULT_DEBT_REVIEW_TRIGGER);
    out.push('}');
    Ok(())
}

fn parse_epistemic_debt_json(val: &Value) -> Result<Vec<String>, AgentContractCodecError> {
    const ALLOWED: &[&str] = &[
        "debtId",
        "assumption",
        "deferredReason",
        "dependentDecisions",
        "consequenceIfWrong",
        "cheapestTest",
        "reviewTrigger",
    ];
    let arr = val.array().ok_or_else(|| {
        AgentContractCodecError::MalformedPayload("epistemicDebt must be array".to_owned())
    })?;
    if arr.len() > MAX_CAPSULE_EPISTEMIC_DEBT {
        return Err(AgentContractCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item.object().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload(
                "epistemicDebt[] must be JSON object".to_owned(),
            )
        })?;
        reject_unknown_keys(obj, ALLOWED, "epistemicDebt[]")?;
        let debt_id = req_str(obj, "debtId")?;
        if debt_id.is_empty() || debt_id.len() > 256 || has_disallowed_control(debt_id) {
            return Err(AgentContractCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        let assumption = req_str(obj, "assumption")?;
        let deferred_reason = req_str(obj, "deferredReason")?;
        let _ = parse_bounded_str_array(
            obj.get("dependentDecisions").ok_or_else(|| {
                AgentContractCodecError::MalformedPayload(
                    "missing epistemicDebt[].dependentDecisions".to_owned(),
                )
            })?,
            "epistemicDebt[].dependentDecisions",
            MAX_CAPSULE_LIST_ITEMS,
        )?;
        let consequence = req_str(obj, "consequenceIfWrong")?;
        let cheapest_test = req_str(obj, "cheapestTest")?;
        let review_trigger = req_str(obj, "reviewTrigger")?;
        for text_field in [deferred_reason, consequence, cheapest_test, review_trigger] {
            if has_disallowed_control(text_field) {
                return Err(AgentContractCodecError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        let entry = if debt_id == assumption {
            debt_id.to_owned()
        } else {
            format!("{debt_id}: {assumption}")
        };
        if entry.len() > MAX_CAPSULE_ITEM_BYTES || has_disallowed_control(&entry) {
            return Err(AgentContractCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        out.push(entry);
    }
    Ok(out)
}

fn write_budget_json(out: &mut String, b: BudgetVector) {
    out.push('{');
    push_key(out, "acceleratorMillis");
    out.push_str(&b.accelerator_millis.to_string());
    out.push(',');
    push_key(out, "bytes");
    out.push_str(&b.bytes.to_string());
    out.push(',');
    push_key(out, "cpuMillis");
    out.push_str(&b.cpu_millis.to_string());
    out.push(',');
    push_key(out, "energyMilliJoules");
    out.push_str(&b.energy_millijoules.to_string());
    out.push(',');
    push_key(out, "latencyMs");
    out.push_str(&b.latency_ms.to_string());
    out.push(',');
    push_key(out, "modelCalls");
    out.push_str(&b.model_calls.to_string());
    out.push(',');
    push_key(out, "networkBytes");
    out.push_str(&b.network_bytes.to_string());
    out.push(',');
    push_key(out, "operatorAttentionSeconds");
    write_f64(out, b.operator_attention_seconds());
    out.push(',');
    push_key(out, "privacyExposure");
    write_f64(out, b.privacy_exposure());
    out.push(',');
    push_key(out, "storageOperations");
    out.push_str(&b.storage_operations.to_string());
    out.push(',');
    push_key(out, "tokens");
    out.push_str(&b.tokens.to_string());
    out.push('}');
}

fn parse_budget_json(val: &Value) -> Result<BudgetVector, AgentContractCodecError> {
    const ALLOWED: &[&str] = &[
        "latencyMs",
        "tokens",
        "bytes",
        "modelCalls",
        "cpuMillis",
        "acceleratorMillis",
        "energyMilliJoules",
        "networkBytes",
        "storageOperations",
        "privacyExposure",
        "operatorAttentionSeconds",
    ];
    let obj = val.object().ok_or_else(|| {
        AgentContractCodecError::MalformedPayload("budgetLedger must be JSON object".to_owned())
    })?;
    reject_unknown_keys(obj, ALLOWED, "budgetLedger")?;
    let model_calls = u32::try_from(req_u64(obj, "modelCalls")?).map_err(|_| {
        AgentContractCodecError::MalformedPayload("modelCalls exceeds u32".to_owned())
    })?;
    BudgetVector::builder()
        .latency_ms(req_u64(obj, "latencyMs")?)
        .tokens(req_u64(obj, "tokens")?)
        .bytes(req_u64(obj, "bytes")?)
        .model_calls(model_calls)
        .cpu_millis(req_u64(obj, "cpuMillis")?)
        .accelerator_millis(req_u64(obj, "acceleratorMillis")?)
        .energy_millijoules(req_u64(obj, "energyMilliJoules")?)
        .network_bytes(req_u64(obj, "networkBytes")?)
        .storage_operations(req_u64(obj, "storageOperations")?)
        .privacy_exposure(req_f64(obj, "privacyExposure")?)
        .operator_attention_seconds(req_f64(obj, "operatorAttentionSeconds")?)
        .build()
        .map_err(|e| AgentContractCodecError::Contract(e.into()))
}

fn reject_unknown_keys(
    obj: &BTreeMap<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), AgentContractCodecError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(AgentContractCodecError::MalformedPayload(format!(
                "unknown property '{k}' in {context} (additionalProperties: false)"
            )));
        }
    }
    Ok(())
}

fn push_escaped_str(out: &mut String, s: &str) {
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

fn push_key(out: &mut String, key: &str) {
    push_escaped_str(out, key);
    out.push(':');
}

fn push_kv_str(out: &mut String, key: &str, val: &str) {
    push_key(out, key);
    push_escaped_str(out, val);
}

fn write_str_iter<'a>(out: &mut String, items: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_escaped_str(out, item);
    }
    out.push(']');
}

fn write_f64(out: &mut String, v: f64) {
    let norm = if v == 0.0 { 0.0 } else { v };
    out.push_str(&norm.to_string());
}

fn req_str<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, AgentContractCodecError> {
    obj.get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?
        .text()
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("{key} must be string")))
}

fn req_u64(obj: &BTreeMap<String, Value>, key: &str) -> Result<u64, AgentContractCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(raw) => raw
            .parse::<u64>()
            .map_err(|_| AgentContractCodecError::MalformedPayload(format!("{key} must be u64"))),
        _ => Err(AgentContractCodecError::MalformedPayload(format!(
            "{key} must be integer"
        ))),
    }
}

fn req_i128(obj: &BTreeMap<String, Value>, key: &str) -> Result<i128, AgentContractCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(raw) => raw
            .parse::<i128>()
            .map_err(|_| AgentContractCodecError::MalformedPayload(format!("{key} must be i128"))),
        _ => Err(AgentContractCodecError::MalformedPayload(format!(
            "{key} must be integer"
        ))),
    }
}

fn req_f64(obj: &BTreeMap<String, Value>, key: &str) -> Result<f64, AgentContractCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(raw) => {
            let v = raw.parse::<f64>().map_err(|_| {
                AgentContractCodecError::MalformedPayload(format!("{key} must be number"))
            })?;
            if !v.is_finite() || v < 0.0 {
                return Err(AgentContractCodecError::MalformedPayload(format!(
                    "{key} must be finite >= 0"
                )));
            }
            Ok(if v == 0.0 { 0.0 } else { v })
        }
        _ => Err(AgentContractCodecError::MalformedPayload(format!(
            "{key} must be number"
        ))),
    }
}

fn req_unique_token_set(
    obj: &BTreeMap<String, Value>,
    key: &str,
    max_items: usize,
) -> Result<BTreeSet<String>, AgentContractCodecError> {
    let arr = obj
        .get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?
        .array()
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("{key} must be array")))?;
    if arr.len() > max_items {
        return Err(AgentContractCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    let mut set = BTreeSet::new();
    for item in arr {
        let s = item.text().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload(format!("{key} items must be strings"))
        })?;
        validate_schema_token(s)?;
        if !set.insert(s.to_owned()) {
            return Err(AgentContractCodecError::MalformedPayload(format!(
                "duplicate item '{s}' in {key} (uniqueItems: true)"
            )));
        }
    }
    Ok(set)
}

fn req_bounded_str_vec(
    obj: &BTreeMap<String, Value>,
    key: &str,
    max_items: usize,
) -> Result<Vec<String>, AgentContractCodecError> {
    let val = obj
        .get(key)
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("missing {key}")))?;
    parse_bounded_str_array(val, key, max_items)
}

fn parse_bounded_str_array(
    val: &Value,
    key: &str,
    max_items: usize,
) -> Result<Vec<String>, AgentContractCodecError> {
    let arr = val
        .array()
        .ok_or_else(|| AgentContractCodecError::MalformedPayload(format!("{key} must be array")))?;
    if arr.len() > max_items {
        return Err(AgentContractCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.text().ok_or_else(|| {
            AgentContractCodecError::MalformedPayload(format!("{key} items must be strings"))
        })?;
        if s.len() > MAX_CAPSULE_ITEM_BYTES || has_disallowed_control(s) {
            return Err(AgentContractCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        out.push(s.to_owned());
    }
    Ok(out)
}
