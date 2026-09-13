//! Idempotent effect preparation, terminal-proof obligations, and reconciliation.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError,
};
pub use crate::{IdempotencyKey, ObligationId, OperationId, TimestampNs};

/// Maximum allowed length of an effect class identifier.
pub const MAX_EFFECT_CLASS_LEN: usize = 128;
/// Maximum allowed length of a terminal predicate description.
pub const MAX_TERMINAL_PREDICATE_LEN: usize = 256;
/// Maximum allowed length of a provider failure error code.
pub const MAX_ERROR_CODE_LEN: usize = 128;
/// Maximum allowed length of a reconciliation detail/reason message.
pub const MAX_DETAIL_LEN: usize = 512;

/// Schema string for effect intent v1.
pub const EFFECT_INTENT_SCHEMA: &str = EffectIntent::SCHEMA;
/// Schema string for prepared effect v1.
pub const PREPARED_EFFECT_SCHEMA: &str = PreparedEffect::SCHEMA;
/// Schema string for provider observation receipt v1.
pub const PROVIDER_OBSERVATION_RECEIPT_SCHEMA: &str = ProviderObservationReceipt::SCHEMA;
/// Schema string for provider failure receipt v1.
pub const PROVIDER_FAILURE_RECEIPT_SCHEMA: &str = ProviderFailureReceipt::SCHEMA;
/// Schema string for effect reconciliation v1.
pub const EFFECT_RECONCILIATION_SCHEMA: &str = EffectReconciliationRecord::SCHEMA;

/// Typed error for prepared effect and receipt schema validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectSchemaError {
    /// Schema mismatch in JSON or envelope.
    SchemaMismatch {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier found.
        found: String,
    },
    /// A bounded field strictly exceeds its declared hard bound.
    OverLimitLength {
        /// Name of the bounded field.
        field: &'static str,
        /// Maximum allowed limit.
        limit: usize,
        /// Actual length found.
        actual: usize,
    },
    /// Required field is empty or missing.
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
    /// Invalid outcome configuration (e.g. Verified outcome missing evidence digest).
    InvalidOutcome {
        /// The outcome name.
        outcome: &'static str,
        /// Reason the outcome is invalid.
        reason: &'static str,
    },
    /// Receipt lookup verification failed (unissued receipt or mismatched nonce).
    UnverifiedReceipt {
        /// Detail explaining the verification failure.
        detail: String,
    },
    /// Receipt lookup verification was indeterminate (e.g. provider partition or timeout).
    IndeterminateLookup {
        /// Detail explaining the indeterminate lookup state.
        detail: String,
    },
    /// JSON parsing or syntax error.
    JsonError {
        /// Detail of the parsing error.
        detail: String,
    },
    /// Contract violation.
    Contract(ContractError),
}

impl core::fmt::Display for EffectSchemaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected '{expected}', found '{found}'")
            }
            Self::OverLimitLength {
                field,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' length {actual} strictly exceeds bound {limit}"
                )
            }
            Self::MissingField { field } => {
                write!(f, "required field '{field}' is missing or empty")
            }
            Self::InvalidOutcome { outcome, reason } => {
                write!(f, "invalid outcome '{outcome}': {reason}")
            }
            Self::UnverifiedReceipt { detail } => {
                write!(f, "receipt unverified by provider lookup: {detail}")
            }
            Self::IndeterminateLookup { detail } => {
                write!(f, "receipt lookup indeterminate: {detail}")
            }
            Self::JsonError { detail } => {
                write!(f, "JSON decoding error: {detail}")
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for EffectSchemaError {}

impl From<ContractError> for EffectSchemaError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Effect lifecycle. Transport acceptance is not terminal success.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EffectState {
    /// Immutable intent and preconditions were durably prepared.
    Prepared,
    /// Dispatch authority was committed.
    Committed,
    /// The external adapter accepted the request.
    AdapterAccepted,
    /// A resulting physical or provider state was observed.
    Observed,
    /// Terminal postconditions were proved.
    Verified,
    /// Cancellation completed without an unresolved external effect.
    Cancelled,
    /// The operation failed with a known terminal outcome.
    Failed,
    /// The effect may have happened but cannot yet be established.
    Indeterminate,
}

impl EffectState {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::AdapterAccepted => "adapter_accepted",
            Self::Observed => "observed",
            Self::Verified => "verified",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Returns true for a terminal state that permits no ordinary progress transition.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Cancelled | Self::Failed)
    }

    /// Returns true if this state can legally transition to the target state.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Committed)
                | (Self::Prepared, Self::Cancelled)
                | (Self::Prepared, Self::Failed)
                | (Self::Committed, Self::AdapterAccepted)
                | (Self::Committed, Self::Indeterminate)
                | (Self::Committed, Self::Failed)
                | (Self::AdapterAccepted, Self::Observed)
                | (Self::AdapterAccepted, Self::Indeterminate)
                | (Self::AdapterAccepted, Self::Failed)
                | (Self::Observed, Self::Verified)
                | (Self::Observed, Self::Indeterminate)
                | (Self::Indeterminate, Self::Observed)
                | (Self::Indeterminate, Self::Failed)
        )
    }
}

impl CanonicalEncode for EffectState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for EffectState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        match text {
            "prepared" => Ok(Self::Prepared),
            "committed" => Ok(Self::Committed),
            "adapter_accepted" => Ok(Self::AdapterAccepted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Immutable effect intent prepared before crossing an external boundary.
///
/// # Plane boundary (ADR-0001)
///
/// An `EffectIntent` is an effect-plane value. It is built only through
/// [`EffectIntent::new`] (or canonical decoding) from explicit operation, idempotency,
/// request, and precondition identities. No cognition value converts into it.
///
/// Invariant 2: a cognition output cannot directly construct an `EffectIntent`.
///
/// ```compile_fail,E0277
/// use fss_core::belief::BeliefInterval;
/// use fss_core::effect::EffectIntent;
///
/// fn forbidden_intent(belief: BeliefInterval) {
///     // adr-0001/inv-2: no `From<BeliefInterval>` exists for `EffectIntent`.
///     let intent: EffectIntent = belief.into();
///     let _ = intent;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectIntent {
    /// Operation identity.
    pub operation_id: OperationId,
    /// Replay identity.
    pub idempotency_key: IdempotencyKey,
    /// Stable effect class.
    pub effect_class: String,
    /// Digest of the exact request.
    pub request_digest: ContentDigest,
    /// Digest of the exact preconditions.
    pub precondition_digest: ContentDigest,
}

impl CanonicalEncode for EffectIntent {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.operation_id.encode_canonical(encoder);
        self.idempotency_key.encode_canonical(encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
    }
}

impl CanonicalDecode for EffectIntent {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let operation_id = OperationId::decode_canonical(decoder)?;
        let idempotency_key = IdempotencyKey::decode_canonical(decoder)?;
        let effect_class = decoder.text()?.to_string();
        if effect_class.is_empty() || effect_class.len() > MAX_EFFECT_CLASS_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        let request_digest = decoder.digest()?;
        let precondition_digest = decoder.digest()?;
        Ok(Self {
            operation_id,
            idempotency_key,
            effect_class,
            request_digest,
            precondition_digest,
        })
    }
}

impl EffectIntent {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.effect_intent.v1";

    /// Creates a validated effect intent.
    pub fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        effect_class: impl Into<String>,
        request_digest: ContentDigest,
        precondition_digest: ContentDigest,
    ) -> Result<Self, EffectSchemaError> {
        let effect_class = effect_class.into();
        if effect_class.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "effectClass",
            });
        }
        if effect_class.len() > MAX_EFFECT_CLASS_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "effectClass",
                limit: MAX_EFFECT_CLASS_LEN,
                actual: effect_class.len(),
            });
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            effect_class,
            request_digest,
            precondition_digest,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str("\"effectClass\":");
        json_write_str(&mut out, &self.effect_class);
        out.push_str(",\"idempotencyKey\":");
        json_write_str(&mut out, self.idempotency_key.as_str());
        out.push_str(",\"operationId\":");
        json_write_str(&mut out, self.operation_id.as_str());
        out.push_str(",\"preconditionDigest\":");
        json_write_str(&mut out, &self.precondition_digest.to_text());
        out.push_str(",\"requestDigest\":");
        json_write_str(&mut out, &self.request_digest.to_text());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push('}');
        out
    }

    /// Parses an effect intent from canonical JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "effectIntent",
            &[
                "effectClass",
                "idempotencyKey",
                "operationId",
                "preconditionDigest",
                "requestDigest",
                "schema",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        Self::from_json_obj(&obj)
    }

    fn from_json_obj(obj: &JsonObject<'_>) -> Result<Self, EffectSchemaError> {
        let op_raw = obj.str("operationId")?;
        let operation_id = OperationId::parse(op_raw)?;

        let idem_raw = obj.str("idempotencyKey")?;
        let idempotency_key = IdempotencyKey::parse(idem_raw)?;

        let effect_class = obj.str("effectClass")?.to_string();
        if effect_class.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "effectClass",
            });
        }
        if effect_class.len() > MAX_EFFECT_CLASS_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "effectClass",
                limit: MAX_EFFECT_CLASS_LEN,
                actual: effect_class.len(),
            });
        }

        let req_raw = obj.str("requestDigest")?;
        let request_digest = ContentDigest::parse(req_raw)?;

        let pre_raw = obj.str("preconditionDigest")?;
        let precondition_digest = ContentDigest::parse(pre_raw)?;

        Ok(Self {
            operation_id,
            idempotency_key,
            effect_class,
            request_digest,
            precondition_digest,
        })
    }

    /// Encodes to canonical versioned binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EffectSchemaError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        Ok(encoder.finish())
    }

    /// Decodes from canonical versioned binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EffectSchemaError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder.text().map_err(EffectSchemaError::Contract)?;
        if tag != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: tag.to_string(),
            });
        }
        let intent = Self::decode_canonical(&mut decoder).map_err(EffectSchemaError::Contract)?;
        decoder
            .ensure_finished()
            .map_err(EffectSchemaError::Contract)?;
        if intent.effect_class.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "effectClass",
            });
        }
        if intent.effect_class.len() > MAX_EFFECT_CLASS_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "effectClass",
                limit: MAX_EFFECT_CLASS_LEN,
                actual: intent.effect_class.len(),
            });
        }
        Ok(intent)
    }

    /// Computes the canonical content digest of the intent.
    #[must_use]
    pub fn intent_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_canonical_bytes().unwrap_or_default())
    }

    /// Computes the unique canonical terminal proof digest binding full intent and terminal predicate.
    #[must_use]
    pub fn terminal_proof(&self, terminal_predicate: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_proof.terminal.v1");
        self.operation_id.encode_canonical(&mut encoder);
        self.idempotency_key.encode_canonical(&mut encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
        encoder.text(terminal_predicate);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Computes the unique canonical failure proof digest binding full intent and failure error code.
    #[must_use]
    pub fn failure_proof(&self, error_code: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_proof.failure.v1");
        self.operation_id.encode_canonical(&mut encoder);
        self.idempotency_key.encode_canonical(&mut encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
        encoder.text(error_code);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Immutable prepared operation binding intent, obligation, and predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedEffect {
    /// Prepared effect intent.
    pub intent: EffectIntent,
    /// Associated obligation id.
    pub obligation_id: ObligationId,
    /// Terminal predicate description.
    pub terminal_predicate: String,
    /// Preparation timestamp.
    pub prepared_at: TimestampNs,
}

/// Stable type alias for prepared operation.
pub type PreparedOperation = PreparedEffect;

impl PreparedEffect {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.prepared_effect.v1";

    /// Creates a validated prepared effect.
    pub fn new(
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        prepared_at: TimestampNs,
    ) -> Result<Self, EffectSchemaError> {
        let terminal_predicate = terminal_predicate.into();
        if terminal_predicate.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "terminalPredicate",
            });
        }
        if terminal_predicate.len() > MAX_TERMINAL_PREDICATE_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "terminalPredicate",
                limit: MAX_TERMINAL_PREDICATE_LEN,
                actual: terminal_predicate.len(),
            });
        }
        Ok(Self {
            intent,
            obligation_id,
            terminal_predicate,
            prepared_at,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        out.push_str("\"intent\":");
        out.push_str(&self.intent.to_canonical_json());
        out.push_str(",\"obligationId\":");
        json_write_str(&mut out, self.obligation_id.as_str());
        out.push_str(",\"preparedAt\":");
        out.push_str(&self.prepared_at.0.to_string());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push_str(",\"terminalPredicate\":");
        json_write_str(&mut out, &self.terminal_predicate);
        out.push('}');
        out
    }

    /// Parses a prepared effect from canonical JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "preparedEffect",
            &[
                "intent",
                "obligationId",
                "preparedAt",
                "schema",
                "terminalPredicate",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let intent_val = obj.get("intent")?;
        let intent_obj = JsonObject::closed(
            intent_val,
            "intent",
            &[
                "effectClass",
                "idempotencyKey",
                "operationId",
                "preconditionDigest",
                "requestDigest",
                "schema",
            ],
        )?;
        let intent_schema = intent_obj.str("schema")?;
        if intent_schema != EffectIntent::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: EffectIntent::SCHEMA,
                found: intent_schema.to_string(),
            });
        }
        let intent = EffectIntent::from_json_obj(&intent_obj)?;

        let ob_raw = obj.str("obligationId")?;
        let obligation_id = ObligationId::parse(ob_raw)?;

        let terminal_predicate = obj.str("terminalPredicate")?.to_string();
        if terminal_predicate.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "terminalPredicate",
            });
        }
        if terminal_predicate.len() > MAX_TERMINAL_PREDICATE_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "terminalPredicate",
                limit: MAX_TERMINAL_PREDICATE_LEN,
                actual: terminal_predicate.len(),
            });
        }

        let prepared_at = obj.get("preparedAt")?.as_timestamp()?;

        Ok(Self {
            intent,
            obligation_id,
            terminal_predicate,
            prepared_at,
        })
    }

    /// Encodes to canonical versioned binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EffectSchemaError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        Ok(encoder.finish())
    }

    /// Decodes from canonical versioned binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EffectSchemaError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder.text().map_err(EffectSchemaError::Contract)?;
        if tag != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: tag.to_string(),
            });
        }
        let prepared = Self::decode_canonical(&mut decoder).map_err(EffectSchemaError::Contract)?;
        decoder
            .ensure_finished()
            .map_err(EffectSchemaError::Contract)?;
        if prepared.terminal_predicate.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "terminalPredicate",
            });
        }
        if prepared.terminal_predicate.len() > MAX_TERMINAL_PREDICATE_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "terminalPredicate",
                limit: MAX_TERMINAL_PREDICATE_LEN,
                actual: prepared.terminal_predicate.len(),
            });
        }
        Ok(prepared)
    }

    /// Computes the canonical content digest of the prepared effect.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_canonical_bytes().unwrap_or_default())
    }
}

impl CanonicalEncode for PreparedEffect {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.intent.encode_canonical(encoder);
        self.obligation_id.encode_canonical(encoder);
        encoder.text(&self.terminal_predicate);
        self.prepared_at.encode_canonical(encoder);
    }
}

impl CanonicalDecode for PreparedEffect {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let intent = EffectIntent::decode_canonical(decoder)?;
        let obligation_id = ObligationId::decode_canonical(decoder)?;
        let terminal_predicate = decoder.text()?.to_string();
        if terminal_predicate.is_empty() || terminal_predicate.len() > MAX_TERMINAL_PREDICATE_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        let prepared_at = TimestampNs::decode_canonical(decoder)?;
        Ok(Self {
            intent,
            obligation_id,
            terminal_predicate,
            prepared_at,
        })
    }
}

/// Three-valued status for provider receipt lookup to prevent flattening indeterminate states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptLookupStatus {
    /// Receipt was authentically issued by the provider.
    Found,
    /// Provider confirmed no such receipt exists.
    NotFound,
    /// Lookup outcome is unresolved (timeout, network partition, or provider unavailable).
    Indeterminate,
}

/// Provider-generated observation receipt for a delivered message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderObservationReceipt {
    /// Nonce generated by provider; cannot be derived from intent alone.
    pub provider_nonce: ContentDigest,
    /// Message digest of the dispatched intent.
    pub message_digest: ContentDigest,
    /// Prepared effect digest binding this observation to a specific prepared effect.
    pub prepared_effect_digest: ContentDigest,
    /// Idempotency key binding this observation to a unique intent.
    pub idempotency_key: IdempotencyKey,
}

impl ProviderObservationReceipt {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.provider_observation_receipt.v1";

    /// Creates an observation receipt.
    #[must_use]
    pub fn new(
        provider_nonce: ContentDigest,
        message_digest: ContentDigest,
        prepared_effect_digest: ContentDigest,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
        }
    }

    /// Canonical encoded bytes of the observation receipt.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// SHA-256 digest of the canonical receipt proof bytes.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str("\"idempotencyKey\":");
        json_write_str(&mut out, self.idempotency_key.as_str());
        out.push_str(",\"messageDigest\":");
        json_write_str(&mut out, &self.message_digest.to_text());
        out.push_str(",\"preparedEffectDigest\":");
        json_write_str(&mut out, &self.prepared_effect_digest.to_text());
        out.push_str(",\"providerNonce\":");
        json_write_str(&mut out, &self.provider_nonce.to_text());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push('}');
        out
    }

    /// Parses an observation receipt from canonical JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "providerObservationReceipt",
            &[
                "idempotencyKey",
                "messageDigest",
                "preparedEffectDigest",
                "providerNonce",
                "schema",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let idem_raw = obj.str("idempotencyKey")?;
        let idempotency_key = IdempotencyKey::parse(idem_raw)?;

        let msg_raw = obj.str("messageDigest")?;
        let message_digest = ContentDigest::parse(msg_raw)?;

        let prep_raw = obj.str("preparedEffectDigest")?;
        let prepared_effect_digest = ContentDigest::parse(prep_raw)?;

        let nonce_raw = obj.str("providerNonce")?;
        let provider_nonce = ContentDigest::parse(nonce_raw)?;

        Ok(Self {
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
        })
    }

    /// Encodes to canonical versioned binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EffectSchemaError> {
        Ok(self.canonical_bytes())
    }

    /// Decodes from canonical versioned binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EffectSchemaError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder.text().map_err(EffectSchemaError::Contract)?;
        if tag != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: tag.to_string(),
            });
        }
        let receipt = Self::decode_canonical(&mut decoder).map_err(EffectSchemaError::Contract)?;
        decoder
            .ensure_finished()
            .map_err(EffectSchemaError::Contract)?;
        Ok(receipt)
    }

    /// Verifies that this observation receipt was authentically issued by the provider lookup store.
    pub fn verify_lookup(
        &self,
        lookup: &impl ProviderReceiptLookup,
    ) -> Result<(), EffectSchemaError> {
        match lookup.contains_observation(&self.provider_nonce, &self.message_digest) {
            ReceiptLookupStatus::Found => Ok(()),
            ReceiptLookupStatus::NotFound => Err(EffectSchemaError::UnverifiedReceipt {
                detail: format!(
                    "provider has no record of observation receipt with nonce {} for message {}",
                    self.provider_nonce, self.message_digest,
                ),
            }),
            ReceiptLookupStatus::Indeterminate => Err(EffectSchemaError::IndeterminateLookup {
                detail: format!(
                    "provider lookup was indeterminate for observation receipt with nonce {} for message {}",
                    self.provider_nonce, self.message_digest,
                ),
            }),
        }
    }
}

impl CanonicalEncode for ProviderObservationReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.provider_nonce);
        encoder.digest(self.message_digest);
        encoder.digest(self.prepared_effect_digest);
        self.idempotency_key.encode_canonical(encoder);
    }
}

impl CanonicalDecode for ProviderObservationReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let provider_nonce = decoder.digest()?;
        let message_digest = decoder.digest()?;
        let prepared_effect_digest = decoder.digest()?;
        let idempotency_key = IdempotencyKey::decode_canonical(decoder)?;
        Ok(Self {
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
        })
    }
}

/// Typed failure proof issued by the provider oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailureReceipt {
    /// Independent provider-generated dispatch nonce.
    pub provider_nonce: ContentDigest,
    /// Canonical digest of the dispatched intent payload.
    pub message_digest: ContentDigest,
    /// Prepared effect digest binding this failure to a specific prepared effect.
    pub prepared_effect_digest: ContentDigest,
    /// Idempotency key binding this failure to a unique intent.
    pub idempotency_key: IdempotencyKey,
    /// Error code or failure reason issued by the provider.
    pub error_code: String,
}

impl ProviderFailureReceipt {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.provider_failure_receipt.v1";

    /// Creates a validated failure receipt.
    pub fn new(
        provider_nonce: ContentDigest,
        message_digest: ContentDigest,
        prepared_effect_digest: ContentDigest,
        idempotency_key: IdempotencyKey,
        error_code: impl Into<String>,
    ) -> Result<Self, EffectSchemaError> {
        let error_code = error_code.into();
        if error_code.is_empty() {
            return Err(EffectSchemaError::MissingField { field: "errorCode" });
        }
        if error_code.len() > MAX_ERROR_CODE_LEN {
            return Err(EffectSchemaError::OverLimitLength {
                field: "errorCode",
                limit: MAX_ERROR_CODE_LEN,
                actual: error_code.len(),
            });
        }
        Ok(Self {
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
            error_code,
        })
    }

    /// Canonical encoded bytes of the failure receipt.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// SHA-256 digest of the canonical receipt proof bytes.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str("\"errorCode\":");
        json_write_str(&mut out, &self.error_code);
        out.push_str(",\"idempotencyKey\":");
        json_write_str(&mut out, self.idempotency_key.as_str());
        out.push_str(",\"messageDigest\":");
        json_write_str(&mut out, &self.message_digest.to_text());
        out.push_str(",\"preparedEffectDigest\":");
        json_write_str(&mut out, &self.prepared_effect_digest.to_text());
        out.push_str(",\"providerNonce\":");
        json_write_str(&mut out, &self.provider_nonce.to_text());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push('}');
        out
    }

    /// Parses a failure receipt from canonical JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "providerFailureReceipt",
            &[
                "errorCode",
                "idempotencyKey",
                "messageDigest",
                "preparedEffectDigest",
                "providerNonce",
                "schema",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let error_code = obj.str("errorCode")?.to_string();
        let idem_raw = obj.str("idempotencyKey")?;
        let idempotency_key = IdempotencyKey::parse(idem_raw)?;
        let msg_raw = obj.str("messageDigest")?;
        let message_digest = ContentDigest::parse(msg_raw)?;
        let prep_raw = obj.str("preparedEffectDigest")?;
        let prepared_effect_digest = ContentDigest::parse(prep_raw)?;
        let nonce_raw = obj.str("providerNonce")?;
        let provider_nonce = ContentDigest::parse(nonce_raw)?;

        Self::new(
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
            error_code,
        )
    }

    /// Encodes to canonical versioned binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EffectSchemaError> {
        Ok(self.canonical_bytes())
    }

    /// Decodes from canonical versioned binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EffectSchemaError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder.text().map_err(EffectSchemaError::Contract)?;
        if tag != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: tag.to_string(),
            });
        }
        let receipt = Self::decode_canonical(&mut decoder).map_err(EffectSchemaError::Contract)?;
        decoder
            .ensure_finished()
            .map_err(EffectSchemaError::Contract)?;
        Ok(receipt)
    }

    /// Verifies that this failure receipt was authentically issued by the provider lookup store.
    pub fn verify_lookup(
        &self,
        lookup: &impl ProviderFailureLookup,
    ) -> Result<(), EffectSchemaError> {
        match lookup.contains_failure(&self.provider_nonce, &self.message_digest, &self.error_code)
        {
            ReceiptLookupStatus::Found => Ok(()),
            ReceiptLookupStatus::NotFound => Err(EffectSchemaError::UnverifiedReceipt {
                detail: format!(
                    "provider has no record of failure receipt with nonce {} for message {}",
                    self.provider_nonce, self.message_digest,
                ),
            }),
            ReceiptLookupStatus::Indeterminate => Err(EffectSchemaError::IndeterminateLookup {
                detail: format!(
                    "provider lookup was indeterminate for failure receipt with nonce {} for message {}",
                    self.provider_nonce, self.message_digest,
                ),
            }),
        }
    }
}

impl CanonicalEncode for ProviderFailureReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.provider_nonce);
        encoder.digest(self.message_digest);
        encoder.digest(self.prepared_effect_digest);
        self.idempotency_key.encode_canonical(encoder);
        encoder.text(&self.error_code);
    }
}

impl CanonicalDecode for ProviderFailureReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let provider_nonce = decoder.digest()?;
        let message_digest = decoder.digest()?;
        let prepared_effect_digest = decoder.digest()?;
        let idempotency_key = IdempotencyKey::decode_canonical(decoder)?;
        let error_code = decoder.text()?.to_string();
        if error_code.is_empty() || error_code.len() > MAX_ERROR_CODE_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            provider_nonce,
            message_digest,
            prepared_effect_digest,
            idempotency_key,
            error_code,
        })
    }
}

/// Trait for verifying provider-issued observation receipts by lookup.
/// Receipts cannot be verified without consulting the issuing provider oracle.
pub trait ProviderReceiptLookup {
    /// Returns 3-valued status for whether the given observation receipt was authentically issued by the provider.
    fn contains_observation(
        &self,
        nonce: &ContentDigest,
        message_digest: &ContentDigest,
    ) -> ReceiptLookupStatus;
}

impl ProviderReceiptLookup for BTreeSet<(ContentDigest, ContentDigest)> {
    fn contains_observation(
        &self,
        nonce: &ContentDigest,
        message_digest: &ContentDigest,
    ) -> ReceiptLookupStatus {
        if self.contains(&(*nonce, *message_digest)) {
            ReceiptLookupStatus::Found
        } else {
            ReceiptLookupStatus::NotFound
        }
    }
}

/// Trait for verifying provider-issued failure receipts by lookup.
pub trait ProviderFailureLookup {
    /// Returns 3-valued status for whether the given failure receipt was authentically issued by the provider.
    fn contains_failure(
        &self,
        nonce: &ContentDigest,
        message_digest: &ContentDigest,
        error_code: &str,
    ) -> ReceiptLookupStatus;
}

impl ProviderFailureLookup for BTreeSet<(ContentDigest, ContentDigest, String)> {
    fn contains_failure(
        &self,
        nonce: &ContentDigest,
        message_digest: &ContentDigest,
        error_code: &str,
    ) -> ReceiptLookupStatus {
        if self.contains(&(*nonce, *message_digest, error_code.to_string())) {
            ReceiptLookupStatus::Found
        } else {
            ReceiptLookupStatus::NotFound
        }
    }
}

/// Four-valued effect reconciliation outcome.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReconciliationOutcome {
    /// Dispatched message was delivered by the external provider.
    Delivered,
    /// Operation failed with a terminal failure proof.
    Failed,
    /// Effect outcome remains unresolved or indeterminate.
    Indeterminate,
    /// Terminal postconditions were verified with independent evidence.
    Verified,
}

impl ReconciliationOutcome {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
            Self::Verified => "verified",
        }
    }

    /// Parses a reconciliation outcome from string.
    pub fn parse(s: &str) -> Result<Self, EffectSchemaError> {
        match s {
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            "verified" => Ok(Self::Verified),
            _ => Err(EffectSchemaError::JsonError {
                detail: format!("unknown reconciliation outcome '{s}'"),
            }),
        }
    }
}

impl CanonicalEncode for ReconciliationOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for ReconciliationOutcome {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        match text {
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            "verified" => Ok(Self::Verified),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Canonical reconciliation record for an effect operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReconciliationRecord {
    /// Target operation identity.
    pub operation_id: OperationId,
    /// Idempotency key binding this reconciliation to a unique intent.
    pub idempotency_key: IdempotencyKey,
    /// Prepared effect digest binding this reconciliation to the exact prepared operation.
    pub prepared_effect_digest: ContentDigest,
    /// Reconciled four-valued outcome.
    pub outcome: ReconciliationOutcome,
    /// Independent verification or observation evidence digest. Required for Verified and Delivered; None for Indeterminate.
    pub evidence_digest: Option<ContentDigest>,
    /// Reconciliation timestamp.
    pub reconciled_at: TimestampNs,
    /// Terminal detail or error reason. Required for Failed and Indeterminate; minLength 1 if present.
    pub detail: Option<String>,
}

impl EffectReconciliationRecord {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.effect_reconciliation.v1";

    /// Creates and validates a reconciliation record.
    pub fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        prepared_effect_digest: ContentDigest,
        outcome: ReconciliationOutcome,
        evidence_digest: Option<ContentDigest>,
        reconciled_at: TimestampNs,
        detail: Option<String>,
    ) -> Result<Self, EffectSchemaError> {
        if outcome == ReconciliationOutcome::Verified && evidence_digest.is_none() {
            return Err(EffectSchemaError::InvalidOutcome {
                outcome: "verified",
                reason: "evidence_digest is required for verified outcome",
            });
        }
        if outcome == ReconciliationOutcome::Delivered && evidence_digest.is_none() {
            return Err(EffectSchemaError::InvalidOutcome {
                outcome: "delivered",
                reason: "evidence_digest is required for delivered outcome; transport acceptance is not terminal success",
            });
        }
        if outcome == ReconciliationOutcome::Failed {
            match &detail {
                Some(d) if !d.is_empty() => {}
                _ => {
                    return Err(EffectSchemaError::InvalidOutcome {
                        outcome: "failed",
                        reason: "detail reason is required for failed outcome",
                    });
                }
            }
        }
        if outcome == ReconciliationOutcome::Indeterminate {
            if evidence_digest.is_some() {
                return Err(EffectSchemaError::InvalidOutcome {
                    outcome: "indeterminate",
                    reason: "indeterminate outcome cannot carry verified evidence digest",
                });
            }
            match &detail {
                Some(d) if !d.is_empty() => {}
                _ => {
                    return Err(EffectSchemaError::InvalidOutcome {
                        outcome: "indeterminate",
                        reason: "detail explanation is required for indeterminate outcome",
                    });
                }
            }
        }
        if let Some(ref d) = detail {
            if d.is_empty() {
                return Err(EffectSchemaError::InvalidOutcome {
                    outcome: outcome.as_str(),
                    reason: "detail must not be empty string (minLength 1)",
                });
            }
            if d.len() > MAX_DETAIL_LEN {
                return Err(EffectSchemaError::OverLimitLength {
                    field: "detail",
                    limit: MAX_DETAIL_LEN,
                    actual: d.len(),
                });
            }
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            prepared_effect_digest,
            outcome,
            evidence_digest,
            reconciled_at,
            detail,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str("\"detail\":");
        match &self.detail {
            Some(d) => json_write_str(&mut out, d),
            None => out.push_str("null"),
        }
        out.push_str(",\"evidenceDigest\":");
        match self.evidence_digest {
            Some(d) => json_write_str(&mut out, &d.to_text()),
            None => out.push_str("null"),
        }
        out.push_str(",\"idempotencyKey\":");
        json_write_str(&mut out, self.idempotency_key.as_str());
        out.push_str(",\"operationId\":");
        json_write_str(&mut out, self.operation_id.as_str());
        out.push_str(",\"outcome\":");
        json_write_str(&mut out, self.outcome.as_str());
        out.push_str(",\"preparedEffectDigest\":");
        json_write_str(&mut out, &self.prepared_effect_digest.to_text());
        out.push_str(",\"reconciledAt\":");
        out.push_str(&self.reconciled_at.0.to_string());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push('}');
        out
    }

    /// Parses an effect reconciliation record from canonical JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "effectReconciliation",
            &[
                "detail",
                "evidenceDigest",
                "idempotencyKey",
                "operationId",
                "outcome",
                "preparedEffectDigest",
                "reconciledAt",
                "schema",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let op_raw = obj.str("operationId")?;
        let operation_id = OperationId::parse(op_raw)?;

        let idem_raw = obj.str("idempotencyKey")?;
        let idempotency_key = IdempotencyKey::parse(idem_raw)?;

        let prep_raw = obj.str("preparedEffectDigest")?;
        let prepared_effect_digest = ContentDigest::parse(prep_raw)?;

        let outcome_str = obj.str("outcome")?;
        let outcome = ReconciliationOutcome::parse(outcome_str)?;

        let evidence_digest = match obj.find("evidenceDigest") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(s)) => Some(ContentDigest::parse(s)?),
            Some(_) => {
                return Err(EffectSchemaError::JsonError {
                    detail: "evidenceDigest must be string or null".to_string(),
                });
            }
        };

        let reconciled_at = obj.get("reconciledAt")?.as_timestamp()?;

        let detail = match obj.find("detail") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(EffectSchemaError::JsonError {
                    detail: "detail must be string or null".to_string(),
                });
            }
        };

        Self::new(
            operation_id,
            idempotency_key,
            prepared_effect_digest,
            outcome,
            evidence_digest,
            reconciled_at,
            detail,
        )
    }

    /// Encodes to canonical versioned binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EffectSchemaError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        Ok(encoder.finish())
    }

    /// Decodes from canonical versioned binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EffectSchemaError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder.text().map_err(EffectSchemaError::Contract)?;
        if tag != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: tag.to_string(),
            });
        }
        let record = Self::decode_canonical(&mut decoder).map_err(EffectSchemaError::Contract)?;
        decoder
            .ensure_finished()
            .map_err(EffectSchemaError::Contract)?;
        Ok(record)
    }

    /// Computes the canonical content digest of the reconciliation record.
    #[must_use]
    pub fn record_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_canonical_bytes().unwrap_or_default())
    }
}

impl CanonicalEncode for EffectReconciliationRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.operation_id.encode_canonical(encoder);
        self.idempotency_key.encode_canonical(encoder);
        encoder.digest(self.prepared_effect_digest);
        self.outcome.encode_canonical(encoder);
        match self.evidence_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(d);
            }
            None => encoder.bool(false),
        }
        self.reconciled_at.encode_canonical(encoder);
        match &self.detail {
            Some(d) => {
                encoder.bool(true);
                encoder.text(d);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for EffectReconciliationRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let operation_id = OperationId::decode_canonical(decoder)?;
        let idempotency_key = IdempotencyKey::decode_canonical(decoder)?;
        let prepared_effect_digest = decoder.digest()?;
        let outcome = ReconciliationOutcome::decode_canonical(decoder)?;
        let evidence_digest = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        let reconciled_at = TimestampNs::decode_canonical(decoder)?;
        let detail = if decoder.bool()? {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        Self::new(
            operation_id,
            idempotency_key,
            prepared_effect_digest,
            outcome,
            evidence_digest,
            reconciled_at,
            detail,
        )
        .map_err(|_| ContractError::InvalidIdentifier)
    }
}

/// Explicit authority granting permission to prepare and execute effects.
///
/// # Plane boundary (ADR-0001)
///
/// `EffectAuthority` belongs to the authority plane. It is created only by
/// [`EffectAuthority::new`] (or [`EffectAuthority::system_default`]) from an explicit
/// principal and capability, and it has no conversion to or from any cognition type.
///
/// Invariant 1: a cognition output (belief interval, model score, recommendation) can never
/// convert into, or otherwise grant, `EffectAuthority`.
///
/// ```compile_fail,E0277
/// use fss_core::belief::BeliefInterval;
/// use fss_core::effect::EffectAuthority;
///
/// fn execute_guarded_effect(_authority: EffectAuthority) {}
///
/// fn forbidden_grant(belief: BeliefInterval) {
///     // adr-0001/inv-1: no `From<BeliefInterval>` exists for `EffectAuthority`.
///     let granted: EffectAuthority = belief.into();
///     execute_guarded_effect(granted);
/// }
/// ```
///
/// Invariant 3: effect authority cannot convert into a cognition belief. Authority is a
/// canonical fact, never a probabilistic epistemic estimate.
///
/// ```compile_fail,E0277
/// use fss_core::belief::BeliefInterval;
/// use fss_core::effect::EffectAuthority;
///
/// fn forbidden_belief(authority: EffectAuthority) {
///     // adr-0001/inv-3: no `From<EffectAuthority>` exists for `BeliefInterval`.
///     let belief: BeliefInterval = authority.into();
///     let _ = belief;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAuthority {
    /// Identity of the authorizing principal.
    pub principal: String,
    /// Capability token authorizing this specific effect class and scope.
    pub capability: String,
    /// Optional monotonic lease fence protecting against stale execution across reboots/restarts.
    pub lease_fence: Option<u64>,
}

impl EffectAuthority {
    /// Creates a validated effect authority.
    pub fn new(
        principal: impl Into<String>,
        capability: impl Into<String>,
        lease_fence: Option<u64>,
    ) -> Result<Self, EffectSchemaError> {
        let principal = principal.into();
        let capability = capability.into();
        if principal.is_empty() {
            return Err(EffectSchemaError::MissingField { field: "principal" });
        }
        if capability.is_empty() {
            return Err(EffectSchemaError::MissingField {
                field: "capability",
            });
        }
        Ok(Self {
            principal,
            capability,
            lease_fence,
        })
    }

    /// System internal default authority.
    #[must_use]
    pub fn system_default() -> Self {
        Self {
            principal: "system:operator".to_string(),
            capability: "effect:execute".to_string(),
            lease_fence: None,
        }
    }
}

impl CanonicalEncode for EffectAuthority {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.principal);
        encoder.text(&self.capability);
        match self.lease_fence {
            Some(fence) => {
                encoder.bool(true);
                encoder.u64(fence);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for EffectAuthority {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let principal = decoder.text()?.to_string();
        let capability = decoder.text()?.to_string();
        let lease_fence = if decoder.bool()? {
            Some(decoder.u64()?)
        } else {
            None
        };
        Self::new(principal, capability, lease_fence).map_err(|_| ContractError::InvalidIdentifier)
    }
}

/// Why an operation entered `indeterminate`, kept on its receipt through reconciliation.
///
/// Reconciliation keeps the indeterminate reason in [`OperationReceipt::error_code`] as
/// provenance, so a later observed, verified, or failed receipt may still carry it. This marker is
/// what tells that inherited reason apart from an error code attached without any indeterminate
/// episode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndeterminateEffectReason {
    /// The indeterminate transition recorded this non-empty reason.
    Recorded(String),
    /// A legacy journal entry, written before a reason was required, recorded the indeterminate
    /// transition without one. Replay keeps it explicitly unrecorded instead of inventing a reason.
    Unrecorded,
}

/// Durable operation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    /// Prepared intent.
    pub intent: EffectIntent,
    /// Current effect state.
    pub state: EffectState,
    /// Explicit authority that authorized this effect operation.
    pub authority: EffectAuthority,
    /// Prepare timestamp.
    pub prepared_at: TimestampNs,
    /// Commit timestamp, when committed.
    pub committed_at: Option<TimestampNs>,
    /// Last transition timestamp.
    pub updated_at: TimestampNs,
    /// Result or observation digest.
    pub result_digest: Option<ContentDigest>,
    /// Stable error code.
    pub error_code: Option<String>,
    /// Why the operation entered `indeterminate`, when it ever did; kept through reconciliation.
    ///
    /// Like `updated_at`, it is not part of the JSON projection.
    pub indeterminate_reason: Option<IndeterminateEffectReason>,
}

impl OperationReceipt {
    /// Schema identity.
    pub const SCHEMA: &'static str = "fss.operation_receipt.v1";

    /// Returns the receipt digest.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }

    /// Emits a deterministic canonical JSON string projection per schemas/operation_receipt.v1.json.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        out.push_str("\"authority\":{");
        out.push_str("\"capability\":");
        json_write_str(&mut out, &self.authority.capability);
        out.push_str(",\"leaseFence\":");
        match self.authority.lease_fence {
            Some(f) => out.push_str(&f.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"principal\":");
        json_write_str(&mut out, &self.authority.principal);
        out.push('}');
        out.push_str(",\"effectClass\":");
        json_write_str(&mut out, &self.intent.effect_class);
        if let Some(ref err) = self.error_code {
            out.push_str(",\"errorId\":");
            json_write_str(&mut out, err);
        }
        out.push_str(",\"idempotencyKey\":");
        json_write_str(&mut out, self.intent.idempotency_key.as_str());
        out.push_str(",\"operationId\":");
        json_write_str(&mut out, self.intent.operation_id.as_str());
        out.push_str(",\"preconditionDigest\":");
        json_write_str(&mut out, &self.intent.precondition_digest.to_text());
        out.push_str(",\"requestDigest\":");
        json_write_str(&mut out, &self.intent.request_digest.to_text());
        out.push_str(",\"resultDigest\":");
        match self.result_digest {
            Some(d) => json_write_str(&mut out, &d.to_text()),
            None => out.push_str("null"),
        }
        out.push_str(",\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push_str(",\"state\":");
        json_write_str(&mut out, self.state.as_str());
        out.push_str(",\"timestamps\":{");
        out.push_str("\"committedNs\":");
        match self.committed_at {
            Some(ts) => out.push_str(&ts.0.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"observedNs\":null");
        out.push_str(",\"preparedNs\":");
        out.push_str(&self.prepared_at.0.to_string());
        out.push_str(",\"requestedNs\":");
        out.push_str(&self.prepared_at.0.to_string());
        out.push_str(",\"verifiedNs\":null");
        out.push('}');
        out.push('}');
        out
    }

    /// Parses an operation receipt from canonical JSON string per schemas/operation_receipt.v1.json.
    pub fn from_json(json_str: &str) -> Result<Self, EffectSchemaError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;
        let obj = JsonObject::closed(
            &root,
            "operationReceipt",
            &[
                "authority",
                "effectClass",
                "errorId",
                "idempotencyKey",
                "operationId",
                "preconditionDigest",
                "requestDigest",
                "resultDigest",
                "schema",
                "state",
                "timestamps",
            ],
        )?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EffectSchemaError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let op_raw = obj.str("operationId")?;
        let operation_id = OperationId::parse(op_raw)?;

        let idem_raw = obj.str("idempotencyKey")?;
        let idempotency_key = IdempotencyKey::parse(idem_raw)?;

        let effect_class = obj.str("effectClass")?.to_string();

        let state_str = obj.str("state")?;
        let state = match state_str {
            "prepared" => EffectState::Prepared,
            "committed" => EffectState::Committed,
            "adapter_accepted" => EffectState::AdapterAccepted,
            "observed" => EffectState::Observed,
            "verified" => EffectState::Verified,
            "cancelled" => EffectState::Cancelled,
            "failed" => EffectState::Failed,
            "indeterminate" => EffectState::Indeterminate,
            _ => {
                return Err(EffectSchemaError::JsonError {
                    detail: format!("unknown effect state '{state_str}'"),
                });
            }
        };

        let auth_val = obj.get("authority")?;
        let auth_obj = JsonObject::closed(
            auth_val,
            "authority",
            &["capability", "leaseFence", "principal"],
        )?;
        let principal = auth_obj.str("principal")?;
        let capability = auth_obj.str("capability")?;
        let lease_fence = match auth_obj.get("leaseFence")? {
            JsonValue::Null => None,
            JsonValue::Number(n) => {
                if *n < 0 {
                    return Err(EffectSchemaError::JsonError {
                        detail: "leaseFence must be non-negative".to_string(),
                    });
                }
                Some(*n as u64)
            }
            _ => {
                return Err(EffectSchemaError::JsonError {
                    detail: "leaseFence must be integer or null".to_string(),
                });
            }
        };
        let authority = EffectAuthority::new(principal, capability, lease_fence)?;

        let req_raw = obj.str("requestDigest")?;
        let request_digest = ContentDigest::parse(req_raw)?;

        let precondition_digest = match obj.find("preconditionDigest") {
            None | Some(JsonValue::Null) => ContentDigest::sha256(b""),
            Some(JsonValue::String(s)) => ContentDigest::parse(s)?,
            Some(_) => {
                return Err(EffectSchemaError::JsonError {
                    detail: "preconditionDigest must be string or null".to_string(),
                });
            }
        };

        let intent = EffectIntent::new(
            operation_id,
            idempotency_key,
            effect_class,
            request_digest,
            precondition_digest,
        )?;

        let ts_val = obj.get("timestamps")?;
        let ts_obj = JsonObject::closed(
            ts_val,
            "timestamps",
            &[
                "committedNs",
                "observedNs",
                "preparedNs",
                "requestedNs",
                "verifiedNs",
            ],
        )?;
        let prepared_at = ts_obj.get("requestedNs")?.as_timestamp()?;
        let committed_at = match ts_obj.find("committedNs") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_timestamp()?),
        };

        let result_digest = match obj.find("resultDigest") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(s)) => Some(ContentDigest::parse(s)?),
            Some(_) => {
                return Err(EffectSchemaError::JsonError {
                    detail: "resultDigest must be string or null".to_string(),
                });
            }
        };

        let error_code = match obj.find("errorId") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(EffectSchemaError::JsonError {
                    detail: "errorId must be string or null".to_string(),
                });
            }
        };

        Ok(Self {
            intent,
            state,
            authority,
            prepared_at,
            committed_at,
            updated_at: prepared_at,
            result_digest,
            error_code,
            indeterminate_reason: None,
        })
    }
}

impl CanonicalEncode for OperationReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.intent.encode_canonical(encoder);
        encoder.text(self.state.as_str());
        self.authority.encode_canonical(encoder);
        self.prepared_at.encode_canonical(encoder);
        match self.committed_at {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.updated_at.encode_canonical(encoder);
        match self.result_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        // The error-code flag byte doubles as the tag for the indeterminate reason. Tags 0 and 1 are
        // the original `bool` encoding, so a receipt without an indeterminate reason keeps its exact
        // bytes and digest; tags 2 and 3 append the reason.
        let tag = u8::from(self.error_code.is_some())
            | (u8::from(self.indeterminate_reason.is_some()) << 1);
        encoder.u8(tag);
        if let Some(value) = &self.error_code {
            encoder.text(value);
        }
        match &self.indeterminate_reason {
            Some(IndeterminateEffectReason::Recorded(reason)) => {
                encoder.u8(1);
                encoder.text(reason);
            }
            Some(IndeterminateEffectReason::Unrecorded) => encoder.u8(0),
            None => {}
        }
    }
}

impl CanonicalDecode for OperationReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let intent = EffectIntent::decode_canonical(decoder)?;
        let state = EffectState::decode_canonical(decoder)?;
        let authority = EffectAuthority::decode_canonical(decoder)?;
        let prepared_at = TimestampNs::decode_canonical(decoder)?;
        let committed_at = if decoder.bool()? {
            Some(TimestampNs::decode_canonical(decoder)?)
        } else {
            None
        };
        let updated_at = TimestampNs::decode_canonical(decoder)?;
        let result_digest = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        let tag = decoder.u8()?;
        if tag > 3 {
            return Err(ContractError::InvalidIdentifier);
        }
        let error_code = if tag & 1 == 1 {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let indeterminate_reason = if tag & 2 == 2 {
            Some(match decoder.u8()? {
                0 => IndeterminateEffectReason::Unrecorded,
                1 => IndeterminateEffectReason::Recorded(decoder.text()?.to_string()),
                _ => return Err(ContractError::InvalidIdentifier),
            })
        } else {
            None
        };
        Ok(Self {
            intent,
            state,
            authority,
            prepared_at,
            committed_at,
            updated_at,
            result_digest,
            error_code,
            indeterminate_reason,
        })
    }
}

/// Terminal-proof obligation state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObligationState {
    /// Terminal predicate has not yet been proved.
    Pending,
    /// Terminal predicate is proved.
    Verified,
    /// A known terminal failure is proved.
    Failed,
    /// An external outcome remains unresolved.
    Indeterminate,
    /// Cancellation completed before external commitment.
    Cancelled,
}

/// Durable obligation tied to one effect operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Obligation {
    /// Obligation identity.
    pub obligation_id: ObligationId,
    /// Owning operation.
    pub operation_id: OperationId,
    /// Terminal predicate description.
    pub terminal_predicate: String,
    /// Current state.
    pub state: ObligationState,
    /// Proof digest, when terminal.
    pub proof_digest: Option<ContentDigest>,
}

/// Canonical transition record for durable journal replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectJournalTransition {
    /// Effect preparation transition.
    Prepare {
        /// Prepared effect intent.
        intent: EffectIntent,
        /// Associated obligation id.
        obligation_id: ObligationId,
        /// Terminal predicate to be proven.
        terminal_predicate: String,
        /// Preparation timestamp.
        now: TimestampNs,
    },
    /// General effect state transition.
    Transition {
        /// Target operation id.
        operation_id: OperationId,
        /// Next effect state.
        next: EffectState,
        /// Transition timestamp.
        now: TimestampNs,
        /// Optional observation or proof digest.
        result_digest: Option<ContentDigest>,
        /// Optional error code or reason.
        error_code: Option<String>,
    },
    /// Verified reconciliation transition.
    ReconcileVerified {
        /// Target operation id.
        operation_id: OperationId,
        /// Independent proof digest.
        proof_digest: ContentDigest,
        /// Reconciliation timestamp.
        now: TimestampNs,
    },
    /// Failed reconciliation transition.
    ReconcileFailed {
        /// Target operation id.
        operation_id: OperationId,
        /// Independent failure proof digest.
        proof_digest: ContentDigest,
        /// Reconciliation timestamp.
        now: TimestampNs,
        /// Terminal failure reason.
        reason: String,
    },
}

impl CanonicalEncode for EffectJournalTransition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.effect_transition.v1");
        match self {
            Self::Prepare {
                intent,
                obligation_id,
                terminal_predicate,
                now,
            } => {
                encoder.u8(1);
                intent.encode_canonical(encoder);
                obligation_id.encode_canonical(encoder);
                encoder.text(terminal_predicate);
                now.encode_canonical(encoder);
            }
            Self::Transition {
                operation_id,
                next,
                now,
                result_digest,
                error_code,
            } => {
                encoder.u8(2);
                operation_id.encode_canonical(encoder);
                next.encode_canonical(encoder);
                now.encode_canonical(encoder);
                match result_digest {
                    Some(digest) => {
                        encoder.bool(true);
                        encoder.digest(*digest);
                    }
                    None => encoder.bool(false),
                }
                match error_code {
                    Some(code) => {
                        encoder.bool(true);
                        encoder.text(code);
                    }
                    None => encoder.bool(false),
                }
            }
            Self::ReconcileVerified {
                operation_id,
                proof_digest,
                now,
            } => {
                encoder.u8(3);
                operation_id.encode_canonical(encoder);
                encoder.digest(*proof_digest);
                now.encode_canonical(encoder);
            }
            Self::ReconcileFailed {
                operation_id,
                proof_digest,
                now,
                reason,
            } => {
                encoder.u8(4);
                operation_id.encode_canonical(encoder);
                encoder.digest(*proof_digest);
                now.encode_canonical(encoder);
                encoder.text(reason);
            }
        }
    }
}

impl CanonicalDecode for EffectJournalTransition {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let magic = decoder.text()?;
        if magic != "fss.effect_transition.v1" {
            return Err(ContractError::InvalidIdentifier);
        }
        let tag = decoder.tag()?;
        match tag {
            1 => {
                let intent = EffectIntent::decode_canonical(decoder)?;
                let obligation_id = ObligationId::decode_canonical(decoder)?;
                let terminal_predicate = decoder.text()?.to_string();
                let now = TimestampNs::decode_canonical(decoder)?;
                Ok(Self::Prepare {
                    intent,
                    obligation_id,
                    terminal_predicate,
                    now,
                })
            }
            2 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let next = EffectState::decode_canonical(decoder)?;
                let now = TimestampNs::decode_canonical(decoder)?;
                let result_digest = if decoder.bool()? {
                    Some(decoder.digest()?)
                } else {
                    None
                };
                let error_code = if decoder.bool()? {
                    Some(decoder.text()?.to_string())
                } else {
                    None
                };
                Ok(Self::Transition {
                    operation_id,
                    next,
                    now,
                    result_digest,
                    error_code,
                })
            }
            3 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let proof_digest = decoder.digest()?;
                let now = TimestampNs::decode_canonical(decoder)?;
                Ok(Self::ReconcileVerified {
                    operation_id,
                    proof_digest,
                    now,
                })
            }
            4 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let proof_digest = decoder.digest()?;
                let now = TimestampNs::decode_canonical(decoder)?;
                let reason = decoder.text()?.to_string();
                Ok(Self::ReconcileFailed {
                    operation_id,
                    proof_digest,
                    now,
                    reason,
                })
            }
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Deterministic in-memory effect and obligation journal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EffectJournal {
    operations: BTreeMap<OperationId, OperationReceipt>,
    idempotency: BTreeMap<IdempotencyKey, OperationId>,
    obligations: BTreeMap<ObligationId, Obligation>,
}

impl EffectJournal {
    /// Creates an empty journal.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            obligations: BTreeMap::new(),
        }
    }

    /// Prepares an effect exactly once with explicit authority, and returns the existing receipt on an exact retry.
    pub fn prepare_with_authority(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        authority: EffectAuthority,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, ContractError> {
        if let Some(existing_id) = self.idempotency.get(&intent.idempotency_key) {
            let existing = self
                .operations
                .get(existing_id)
                .ok_or(ContractError::NotFound)?;
            if existing.intent == intent {
                return Ok(existing);
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if self.operations.contains_key(&intent.operation_id) {
            return Err(ContractError::IdempotencyConflict);
        }
        if self.obligations.contains_key(&obligation_id) {
            return Err(ContractError::ObligationConflict);
        }
        let operation_id = intent.operation_id.clone();
        let idempotency_key = intent.idempotency_key.clone();
        self.operations.insert(
            operation_id.clone(),
            OperationReceipt {
                intent,
                state: EffectState::Prepared,
                authority,
                prepared_at: now,
                committed_at: None,
                updated_at: now,
                result_digest: None,
                error_code: None,
                indeterminate_reason: None,
            },
        );
        self.idempotency
            .insert(idempotency_key, operation_id.clone());
        self.obligations.insert(
            obligation_id.clone(),
            Obligation {
                obligation_id,
                operation_id: operation_id.clone(),
                terminal_predicate: terminal_predicate.into(),
                state: ObligationState::Pending,
                proof_digest: None,
            },
        );
        self.operations
            .get(&operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Prepares an effect exactly once and returns the existing receipt on an exact retry.
    pub fn prepare(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, ContractError> {
        self.prepare_with_authority(
            intent,
            obligation_id,
            terminal_predicate,
            EffectAuthority::system_default(),
            now,
        )
    }

    /// Prepares an effect from a validated `PreparedEffect` with explicit authority.
    ///
    /// # Plane boundary (ADR-0001)
    ///
    /// This is the legal path from cognition to an authorized effect: cognition may inform
    /// the plan only through content digests bound into the effect-plane `EffectIntent`
    /// preconditions, the effect plane builds its own `PreparedEffect`, and authority arrives
    /// separately as an explicit `EffectAuthority`.
    ///
    /// ```
    /// use fss_core::TimestampNs;
    /// use fss_core::belief::BeliefInterval;
    /// use fss_core::effect::{EffectAuthority, EffectIntent, EffectState, PreparedEffect};
    /// use fss_core::{ContentDigest, EffectJournal, IdempotencyKey, ObligationId, OperationId};
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     // adr-0001/legal-path
    ///     // Cognition: a derived belief about the situation. It grants nothing by itself.
    ///     let belief = BeliefInterval::new(850_000, 950_000)?;
    ///
    ///     // Recommendation -> prepared plan: the effect plane constructs its own intent and
    ///     // binds only the digest of the supporting belief as a precondition.
    ///     let intent = EffectIntent::new(
    ///         OperationId::parse("op-alert-0001")?,
    ///         IdempotencyKey::parse("idem-alert-0001")?,
    ///         "alert.notify",
    ///         ContentDigest::sha256(b"alert request body"),
    ///         belief.interval_digest(),
    ///     )?;
    ///     let prepared = PreparedEffect::new(
    ///         intent,
    ///         ObligationId::parse("obl-alert-0001")?,
    ///         "provider_delivery_observed",
    ///         TimestampNs(1_000),
    ///     )?;
    ///
    ///     // Authority check: authority comes from the authority plane, explicitly.
    ///     let authority = EffectAuthority::new("principal:owner", "effect:alert.notify", Some(7))?;
    ///     let mut journal = EffectJournal::new();
    ///     let receipt = journal.prepare_effect(prepared, authority.clone())?;
    ///
    ///     assert_eq!(receipt.state, EffectState::Prepared);
    ///     assert_eq!(receipt.authority, authority);
    ///     assert_eq!(receipt.intent.precondition_digest, belief.interval_digest());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// Invariant 4: effect preparation requires a prepared effect plan and rejects a cognition
    /// value passed in its place.
    ///
    /// ```compile_fail,E0308
    /// use fss_core::belief::BeliefInterval;
    /// use fss_core::effect::{EffectAuthority, EffectJournal};
    ///
    /// fn forbidden_prepare(
    ///     journal: &mut EffectJournal,
    ///     belief: BeliefInterval,
    ///     authority: EffectAuthority,
    /// ) {
    ///     // adr-0001/inv-4: `prepare_effect` takes a `PreparedEffect`, not a belief.
    ///     let _ = journal.prepare_effect(belief, authority);
    /// }
    /// ```
    pub fn prepare_effect(
        &mut self,
        prepared: PreparedEffect,
        authority: EffectAuthority,
    ) -> Result<&OperationReceipt, ContractError> {
        self.prepare_with_authority(
            prepared.intent,
            prepared.obligation_id,
            prepared.terminal_predicate,
            authority,
            prepared.prepared_at,
        )
    }

    /// Advances an operation through a valid lifecycle transition.
    pub fn transition(
        &mut self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        self.transition_under(
            operation_id,
            next,
            now,
            result_digest,
            error_code,
            TransitionRules::Current,
        )
    }

    /// Applies one transition under `rules`: the current rules for every new transition, the
    /// legacy rules only while replaying persisted history.
    fn transition_under(
        &mut self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<String>,
        rules: TransitionRules,
    ) -> Result<&OperationReceipt, ContractError> {
        {
            let receipt = self
                .operations
                .get_mut(operation_id)
                .ok_or(ContractError::NotFound)?;
            check_transition(
                receipt,
                next,
                now,
                result_digest,
                error_code.as_deref(),
                rules,
            )?;
            if next == EffectState::Committed && receipt.committed_at.is_none() {
                receipt.committed_at = Some(now);
            }
            receipt.state = next;
            receipt.updated_at = now;
            if result_digest.is_some() {
                receipt.result_digest = result_digest;
            }
            if next == EffectState::Indeterminate {
                // The current rules guarantee a non-empty reason; only legacy replay reaches the
                // unrecorded arm, which keeps the missing reason explicit (fss-deir9).
                receipt.indeterminate_reason = Some(
                    match error_code.as_deref().filter(|reason| !reason.is_empty()) {
                        Some(reason) => IndeterminateEffectReason::Recorded(reason.to_owned()),
                        None => IndeterminateEffectReason::Unrecorded,
                    },
                );
            }
            if error_code.is_some() {
                receipt.error_code = error_code;
            }
        }
        let obligation_state = match next {
            EffectState::Verified => Some(ObligationState::Verified),
            EffectState::Cancelled => Some(ObligationState::Cancelled),
            EffectState::Failed => Some(ObligationState::Failed),
            EffectState::Indeterminate => Some(ObligationState::Indeterminate),
            _ => None,
        };
        if let Some(state) = obligation_state {
            for obligation in self
                .obligations
                .values_mut()
                .filter(|obligation| obligation.operation_id == *operation_id)
            {
                obligation.state = state;
                if matches!(
                    state,
                    ObligationState::Verified
                        | ObligationState::Failed
                        | ObligationState::Cancelled
                ) {
                    obligation.proof_digest = result_digest;
                }
            }
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Marks an operation indeterminate after dispatch without a trustworthy terminal result.
    pub fn mark_indeterminate(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        self.transition(
            operation_id,
            EffectState::Indeterminate,
            now,
            None,
            Some(reason),
        )
    }

    /// Reconciles an observed operation using independently observed terminal proof.
    pub fn reconcile_verified(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, ContractError> {
        {
            let current = self
                .operations
                .get(operation_id)
                .ok_or(ContractError::NotFound)?;
            if current.state == EffectState::Verified {
                if current.result_digest == Some(proof_digest) {
                    return Ok(current);
                }
                return Err(ContractError::IdempotencyConflict);
            }
            if now <= current.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if current.state != EffectState::Observed {
                return Err(ContractError::InvalidEffectTransition);
            }
            let obs_digest = current
                .result_digest
                .ok_or(ContractError::EvidenceRequired)?;
            if proof_digest != obs_digest {
                return Err(ContractError::InvalidDigest);
            }
        }
        let receipt = self
            .operations
            .get_mut(operation_id)
            .ok_or(ContractError::NotFound)?;
        receipt.state = EffectState::Verified;
        receipt.updated_at = now;
        receipt.result_digest = Some(proof_digest);
        // Reconciliation preserves indeterminate error_code in receipt history
        for obligation in self
            .obligations
            .values_mut()
            .filter(|obligation| obligation.operation_id == *operation_id)
        {
            obligation.state = ObligationState::Verified;
            obligation.proof_digest = Some(proof_digest);
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Reconciles an indeterminate operation to a terminal failure using proof.
    pub fn reconcile_failed(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        {
            let current = self
                .operations
                .get(operation_id)
                .ok_or(ContractError::NotFound)?;
            if current.state == EffectState::Failed {
                if current.result_digest == Some(proof_digest)
                    && current.error_code.as_deref() == Some(&reason)
                {
                    return Ok(current);
                }
                return Err(ContractError::IdempotencyConflict);
            }
            if now <= current.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if !current.state.can_transition_to(EffectState::Failed) {
                return Err(ContractError::InvalidEffectTransition);
            }
        }
        let receipt = self
            .operations
            .get_mut(operation_id)
            .ok_or(ContractError::NotFound)?;
        receipt.state = EffectState::Failed;
        receipt.updated_at = now;
        receipt.result_digest = Some(proof_digest);
        receipt.error_code = Some(reason);
        for obligation in self
            .obligations
            .values_mut()
            .filter(|obligation| obligation.operation_id == *operation_id)
        {
            obligation.state = ObligationState::Failed;
            obligation.proof_digest = Some(proof_digest);
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Pre-validates a prepare request without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent retry of an existing identical prepare,
    /// or `Ok(None)` if it is a valid new prepare.
    pub fn validate_prepare(
        &self,
        intent: &EffectIntent,
        obligation_id: &ObligationId,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        if let Some(existing_id) = self.idempotency.get(&intent.idempotency_key) {
            let existing = self
                .operations
                .get(existing_id)
                .ok_or(ContractError::NotFound)?;
            if &existing.intent == intent {
                return Ok(Some(existing));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if self.operations.contains_key(&intent.operation_id) {
            return Err(ContractError::IdempotencyConflict);
        }
        if self.obligations.contains_key(obligation_id) {
            return Err(ContractError::ObligationConflict);
        }
        Ok(None)
    }

    /// Pre-validates a transition without mutating the journal.
    pub fn validate_transition(
        &self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<&str>,
    ) -> Result<&OperationReceipt, ContractError> {
        let receipt = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        // The same checker as `transition`, so the durable path never writes a record the journal
        // would then refuse (fss-deir9).
        check_transition(
            receipt,
            next,
            now,
            result_digest,
            error_code,
            TransitionRules::Current,
        )?;
        Ok(receipt)
    }

    /// Pre-validates reconcile_verified without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent no-op (already Verified with matching proof),
    /// or `Ok(None)` if it is a valid transition from Observed to Verified.
    pub fn validate_reconcile_verified(
        &self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        let current = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        if current.state == EffectState::Verified {
            if current.result_digest == Some(proof_digest) {
                return Ok(Some(current));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if now <= current.updated_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        if current.state != EffectState::Observed {
            return Err(ContractError::InvalidEffectTransition);
        }
        let obs_digest = current
            .result_digest
            .ok_or(ContractError::EvidenceRequired)?;
        if proof_digest != obs_digest {
            return Err(ContractError::InvalidDigest);
        }
        Ok(None)
    }

    /// Pre-validates reconcile_failed without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent no-op (already Failed with matching proof/reason),
    /// or `Ok(None)` if it is a valid failure reconciliation.
    pub fn validate_reconcile_failed(
        &self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
        reason: &str,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        let current = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        if current.state == EffectState::Failed {
            if current.result_digest == Some(proof_digest)
                && current.error_code.as_deref() == Some(reason)
            {
                return Ok(Some(current));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if now <= current.updated_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        if current.state != EffectState::Indeterminate
            && current.state != EffectState::Committed
            && current.state != EffectState::AdapterAccepted
        {
            return Err(ContractError::InvalidEffectTransition);
        }
        Ok(None)
    }

    /// Returns one operation receipt.
    #[must_use]
    pub fn operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt> {
        self.operations.get(operation_id)
    }

    /// Returns all obligations in canonical identity order.
    pub fn obligations(&self) -> impl Iterator<Item = &Obligation> {
        self.obligations.values()
    }

    /// Returns all operation receipts in canonical identity order.
    pub fn operations(&self) -> impl Iterator<Item = &OperationReceipt> {
        self.operations.values()
    }

    /// Replays a sequence of transitions from a durable log, reconstructing the exact in-memory state.
    pub fn replay(
        transitions: impl IntoIterator<Item = EffectJournalTransition>,
    ) -> Result<Self, ContractError> {
        let mut journal = Self::new();
        for transition in transitions {
            let _receipt = journal.replay_transition(transition)?;
        }
        Ok(journal)
    }

    /// Applies one persisted transition under the rules it was written under.
    ///
    /// History is replayed with the legacy transition rules, so a record the journal accepted
    /// before a rule was tightened (such as a reason-less `indeterminate`) still loads. It is kept
    /// as recorded, with an unrecorded indeterminate reason made explicit, and is never refused or
    /// rewritten (fss-deir9). New transitions, including [`Self::apply_transition`], use the
    /// current rules.
    fn replay_transition(
        &mut self,
        transition: EffectJournalTransition,
    ) -> Result<&OperationReceipt, ContractError> {
        match transition {
            EffectJournalTransition::Transition {
                operation_id,
                next,
                now,
                result_digest,
                error_code,
            } => self.transition_under(
                &operation_id,
                next,
                now,
                result_digest,
                error_code,
                TransitionRules::Legacy,
            ),
            other => self.apply_transition(other),
        }
    }

    /// Applies one transition to the journal, returning receipt or error on invariant failure.
    pub fn apply_transition(
        &mut self,
        transition: EffectJournalTransition,
    ) -> Result<&OperationReceipt, ContractError> {
        match transition {
            EffectJournalTransition::Prepare {
                intent,
                obligation_id,
                terminal_predicate,
                now,
            } => self.prepare(intent, obligation_id, terminal_predicate, now),
            EffectJournalTransition::Transition {
                operation_id,
                next,
                now,
                result_digest,
                error_code,
            } => self.transition(&operation_id, next, now, result_digest, error_code),
            EffectJournalTransition::ReconcileVerified {
                operation_id,
                proof_digest,
                now,
            } => self.reconcile_verified(&operation_id, proof_digest, now),
            EffectJournalTransition::ReconcileFailed {
                operation_id,
                proof_digest,
                now,
                reason,
            } => self.reconcile_failed(&operation_id, proof_digest, now, reason),
        }
    }

    /// Computes a canonical journal root.
    #[must_use]
    pub fn journal_root(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_journal.v1");
        encoder.u64(self.operations.len() as u64);
        for receipt in self.operations.values() {
            receipt.encode_canonical(&mut encoder);
        }
        encoder.u64(self.obligations.len() as u64);
        for obligation in self.obligations.values() {
            obligation.obligation_id.encode_canonical(&mut encoder);
            obligation.operation_id.encode_canonical(&mut encoder);
            encoder.text(&obligation.terminal_predicate);
            encoder.u8(match obligation.state {
                ObligationState::Pending => 1,
                ObligationState::Verified => 2,
                ObligationState::Failed => 3,
                ObligationState::Indeterminate => 4,
                ObligationState::Cancelled => 5,
            });
            match obligation.proof_digest {
                Some(value) => {
                    encoder.bool(true);
                    encoder.digest(value);
                }
                None => encoder.bool(false),
            }
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

const MAX_JSON_DEPTH: usize = 16;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn json_write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                let code = u32::from(control) as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX_DIGITS[code >> 4]));
                out.push(char::from(HEX_DIGITS[code & 0xf]));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(i128),
    String(String),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_str(&self) -> Result<&str, EffectSchemaError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            _ => Err(EffectSchemaError::JsonError {
                detail: "expected string".to_string(),
            }),
        }
    }

    fn as_i128(&self) -> Result<i128, EffectSchemaError> {
        match self {
            Self::Number(n) => Ok(*n),
            _ => Err(EffectSchemaError::JsonError {
                detail: "expected number".to_string(),
            }),
        }
    }

    fn as_timestamp(&self) -> Result<TimestampNs, EffectSchemaError> {
        let n = self.as_i128()?;
        if n < 0 {
            return Err(EffectSchemaError::JsonError {
                detail: "negative timestamp".to_string(),
            });
        }
        Ok(TimestampNs(n))
    }
}

struct JsonObject<'a> {
    fields: &'a [(String, JsonValue)],
}

impl<'a> JsonObject<'a> {
    fn closed(
        val: &'a JsonValue,
        context: &'static str,
        allowed: &[&str],
    ) -> Result<Self, EffectSchemaError> {
        match val {
            JsonValue::Object(fields) => {
                for (k, _) in fields {
                    if !allowed.contains(&k.as_str()) {
                        return Err(EffectSchemaError::JsonError {
                            detail: format!("unknown field '{k}' in {context}"),
                        });
                    }
                }
                Ok(Self { fields })
            }
            _ => Err(EffectSchemaError::JsonError {
                detail: format!("expected object for {context}"),
            }),
        }
    }

    fn find(&self, key: &str) -> Option<&'a JsonValue> {
        for (k, v) in self.fields {
            if k == key {
                return Some(v);
            }
        }
        None
    }

    fn get(&self, key: &str) -> Result<&'a JsonValue, EffectSchemaError> {
        for (k, v) in self.fields {
            if k == key {
                return Ok(v);
            }
        }
        Err(EffectSchemaError::MissingField {
            field: string_to_static_field(key),
        })
    }

    fn str(&self, key: &str) -> Result<&'a str, EffectSchemaError> {
        self.get(key)?.as_str()
    }
}

fn string_to_static_field(key: &str) -> &'static str {
    match key {
        "schema" => "schema",
        "operationId" => "operationId",
        "idempotencyKey" => "idempotencyKey",
        "effectClass" => "effectClass",
        "requestDigest" => "requestDigest",
        "preconditionDigest" => "preconditionDigest",
        "intent" => "intent",
        "obligationId" => "obligationId",
        "terminalPredicate" => "terminalPredicate",
        "preparedAt" => "preparedAt",
        "providerNonce" => "providerNonce",
        "messageDigest" => "messageDigest",
        "errorCode" => "errorCode",
        "outcome" => "outcome",
        "evidenceDigest" => "evidenceDigest",
        "reconciledAt" => "reconciledAt",
        "detail" => "detail",
        "preparedEffectDigest" => "preparedEffectDigest",
        "authority" => "authority",
        "principal" => "principal",
        "capability" => "capability",
        "leaseFence" => "leaseFence",
        _ => "unknown",
    }
}

struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        let bytes = self.input.as_bytes();
        if self.pos < bytes.len() {
            Some(bytes[self.pos])
        } else {
            None
        }
    }

    fn ensure_finished(&mut self) -> Result<(), EffectSchemaError> {
        self.skip_whitespace();
        if self.pos < self.input.len() {
            Err(EffectSchemaError::JsonError {
                detail: format!(
                    "unexpected trailing data at byte offset {}: '{}'",
                    self.pos,
                    &self.input[self.pos..std::cmp::min(self.pos + 20, self.input.len())]
                ),
            })
        } else {
            Ok(())
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, EffectSchemaError> {
        self.skip_whitespace();
        let b = self.peek().ok_or_else(|| EffectSchemaError::JsonError {
            detail: "unexpected end of input".to_string(),
        })?;

        match b {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(JsonValue::String),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(EffectSchemaError::JsonError {
                detail: format!(
                    "unexpected character '{}' at offset {}",
                    other as char, self.pos
                ),
            }),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, EffectSchemaError> {
        if self.input[self.pos..].starts_with("null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(EffectSchemaError::JsonError {
                detail: "invalid literal, expected 'null'".to_string(),
            })
        }
    }

    fn parse_bool(&mut self) -> Result<JsonValue, EffectSchemaError> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(EffectSchemaError::JsonError {
                detail: "invalid boolean literal".to_string(),
            })
        }
    }

    fn parse_string(&mut self) -> Result<String, EffectSchemaError> {
        let bytes = self.input.as_bytes();
        if self.pos >= bytes.len() || bytes[self.pos] != b'"' {
            return Err(EffectSchemaError::JsonError {
                detail: "expected string starting with '\"'".to_string(),
            });
        }
        self.pos += 1;
        let mut result = String::new();
        while self.pos < bytes.len() {
            let b = bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(result),
                b'\\' => {
                    if self.pos >= bytes.len() {
                        return Err(EffectSchemaError::JsonError {
                            detail: "unterminated string escape".to_string(),
                        });
                    }
                    let esc = bytes[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            if self.pos + 4 > bytes.len() {
                                return Err(EffectSchemaError::JsonError {
                                    detail: "truncated \\u escape".to_string(),
                                });
                            }
                            let hex_str = &self.input[self.pos..self.pos + 4];
                            let code = u16::from_str_radix(hex_str, 16).map_err(|_| {
                                EffectSchemaError::JsonError {
                                    detail: format!("invalid \\u escape: {hex_str}"),
                                }
                            })?;
                            self.pos += 4;
                            let ch = char::from_u32(code as u32).ok_or_else(|| {
                                EffectSchemaError::JsonError {
                                    detail: format!("invalid unicode code point: {code}"),
                                }
                            })?;
                            result.push(ch);
                        }
                        other => {
                            return Err(EffectSchemaError::JsonError {
                                detail: format!("invalid escape char '{}'", other as char),
                            });
                        }
                    }
                }
                c if c < 0x20 => {
                    return Err(EffectSchemaError::JsonError {
                        detail: format!("unescaped control character 0x{c:02x} in string"),
                    });
                }
                _ => {
                    let start = self.pos - 1;
                    let ch = self.input[start..].chars().next().ok_or_else(|| {
                        EffectSchemaError::JsonError {
                            detail: "invalid UTF-8".to_string(),
                        }
                    })?;
                    self.pos = start + ch.len_utf8();
                    result.push(ch);
                }
            }
        }
        Err(EffectSchemaError::JsonError {
            detail: "unterminated string".to_string(),
        })
    }

    fn parse_number(&mut self) -> Result<JsonValue, EffectSchemaError> {
        let start = self.pos;
        let bytes = self.input.as_bytes();
        if self.pos < bytes.len() && bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        if self.pos >= bytes.len() || !bytes[self.pos].is_ascii_digit() {
            return Err(EffectSchemaError::JsonError {
                detail: "invalid number".to_string(),
            });
        }
        while self.pos < bytes.len() && bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let num_str = &self.input[start..self.pos];
        let val: i128 = num_str.parse().map_err(|_| EffectSchemaError::JsonError {
            detail: format!("number out of bounds: '{num_str}'"),
        })?;
        Ok(JsonValue::Number(val))
    }

    fn parse_object(&mut self) -> Result<JsonValue, EffectSchemaError> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(EffectSchemaError::JsonError {
                detail: "maximum JSON depth exceeded".to_string(),
            });
        }
        self.depth += 1;
        self.pos += 1; // skip '{'
        self.skip_whitespace();
        let mut fields = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(JsonValue::Object(fields));
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(EffectSchemaError::JsonError {
                    detail: "expected string key in object".to_string(),
                });
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(EffectSchemaError::JsonError {
                    detail: "expected ':' after object key".to_string(),
                });
            }
            self.pos += 1; // skip ':'
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(EffectSchemaError::JsonError {
                        detail: "expected ',' or '}' in object".to_string(),
                    });
                }
            }
        }
        self.depth -= 1;
        Ok(JsonValue::Object(fields))
    }
}

/// Which transition rules apply: the current rules for every new transition, the legacy rules
/// only while replaying persisted history (fss-deir9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionRules {
    Current,
    Legacy,
}

/// Checks one transition of `receipt` to `next`.
///
/// [`EffectJournal::transition`] and [`EffectJournal::validate_transition`] both use it, so they
/// cannot disagree. The legacy rules are exactly the rules history was written under; the current
/// rules add the payload each state may carry, so every receipt the journal produces is one the
/// situation guard accepts.
fn check_transition(
    receipt: &OperationReceipt,
    next: EffectState,
    now: TimestampNs,
    result_digest: Option<ContentDigest>,
    error_code: Option<&str>,
    rules: TransitionRules,
) -> Result<(), ContractError> {
    if now <= receipt.updated_at {
        return Err(ContractError::InvertedTimeInterval);
    }
    if !valid_transition(receipt.state, next) {
        return Err(if receipt.state == EffectState::Indeterminate {
            ContractError::ReconciliationRequired
        } else {
            ContractError::InvalidEffectTransition
        });
    }
    if matches!(
        next,
        EffectState::Observed | EffectState::Verified | EffectState::Cancelled
    ) && result_digest.is_none()
    {
        return Err(ContractError::EvidenceRequired);
    }
    if next == EffectState::Verified {
        let obs_digest = receipt
            .result_digest
            .ok_or(ContractError::EvidenceRequired)?;
        if result_digest != Some(obs_digest) {
            return Err(ContractError::InvalidDigest);
        }
    }
    let names_a_reason = error_code.is_some_and(|reason| !reason.is_empty());
    if next == EffectState::Failed && (result_digest.is_none() || !names_a_reason) {
        return Err(ContractError::EvidenceRequired);
    }
    if rules == TransitionRules::Legacy {
        return Ok(());
    }
    // Exhaustive over `EffectState`, so a new state must choose its payload rule here instead of
    // passing through a default (fss-deir9).
    match next {
        // Nothing transitions into `prepared`; `valid_transition` already refused it above.
        EffectState::Prepared => Err(ContractError::InvalidEffectTransition),
        // Commit and adapter acceptance carry neither a result nor an error.
        EffectState::Committed | EffectState::AdapterAccepted => {
            if result_digest.is_some() || error_code.is_some() {
                Err(ContractError::InvalidEffectTransition)
            } else {
                Ok(())
            }
        }
        // An observed or verified receipt may only inherit the reason of an earlier indeterminate
        // episode; it never gains a new error code.
        EffectState::Observed | EffectState::Verified => {
            if error_code.is_some() {
                Err(ContractError::InvalidEffectTransition)
            } else {
                Ok(())
            }
        }
        // A cancellation reason is optional, but never empty.
        EffectState::Cancelled => {
            if error_code.is_some_and(str::is_empty) {
                Err(ContractError::EvidenceRequired)
            } else {
                Ok(())
            }
        }
        // A failure's proof and non-empty reason are checked above, under every rule set.
        EffectState::Failed => Ok(()),
        // An indeterminate outcome must name why it is unproved, as `mark_indeterminate` requires.
        EffectState::Indeterminate => {
            if names_a_reason {
                Ok(())
            } else {
                Err(ContractError::EvidenceRequired)
            }
        }
    }
}

/// Validates whether a state transition from `current` to `next` is permitted.
pub const fn valid_transition(current: EffectState, next: EffectState) -> bool {
    current.can_transition_to(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(request: &[u8]) -> Result<EffectIntent, ContractError> {
        Ok(EffectIntent {
            operation_id: OperationId::parse("operation:alert:one")?,
            idempotency_key: IdempotencyKey::parse("idem:alert:one")?,
            effect_class: "alert.dispatch".to_owned(),
            request_digest: ContentDigest::sha256(request),
            precondition_digest: ContentDigest::sha256(b"event-corroborated"),
        })
    }

    #[test]
    fn exact_retry_is_idempotent_and_conflicting_retry_fails() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let first = intent(b"same")?;
        let _ = journal.prepare(
            first.clone(),
            ObligationId::parse("obligation:one")?,
            "provider delivery is independently observed",
            TimestampNs(1),
        )?;
        let _ = journal.prepare(
            first,
            ObligationId::parse("obligation:unused")?,
            "unused",
            TimestampNs(2),
        )?;
        assert_eq!(
            journal.prepare(
                intent(b"different")?,
                ObligationId::parse("obligation:two")?,
                "different",
                TimestampNs(3),
            ),
            Err(ContractError::IdempotencyConflict)
        );
        Ok(())
    }

    #[test]
    fn lost_ack_requires_reconciliation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"alert")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect.clone(),
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation_id, TimestampNs(3), "lost_ack")?;
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Committed,
                TimestampNs(4),
                None,
                None,
            ),
            Err(ContractError::ReconciliationRequired)
        );
        let obs_proof = ContentDigest::sha256(b"delivery-observation");
        let _ = journal.transition(
            &operation_id,
            EffectState::Observed,
            TimestampNs(5),
            Some(obs_proof),
            None,
        )?;
        let _ = journal.reconcile_verified(&operation_id, obs_proof, TimestampNs(6))?;
        assert_eq!(
            journal
                .operation(&operation_id)
                .map(|receipt| receipt.state),
            Some(EffectState::Verified)
        );
        Ok(())
    }

    #[test]
    fn backward_transition_is_rejected_without_mutation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"ordered")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect,
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(10),
        )?;
        let before = journal
            .operation(&operation_id)
            .ok_or(ContractError::NotFound)?
            .clone();
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Committed,
                TimestampNs(9),
                None,
                None,
            ),
            Err(ContractError::InvertedTimeInterval)
        );
        assert_eq!(journal.operation(&operation_id), Some(&before));
        Ok(())
    }

    #[test]
    fn failed_outcome_requires_terminal_proof() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"failed")?;
        let operation_id = effect.operation_id.clone();
        let obligation_id = ObligationId::parse("obligation:one")?;
        let _ = journal.prepare(
            effect,
            obligation_id.clone(),
            "known non-delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Failed,
                TimestampNs(3),
                None,
                Some("provider_failed_before_delivery".to_owned()),
            ),
            Err(ContractError::EvidenceRequired)
        );

        let proof = ContentDigest::sha256(b"provider-known-failure");
        let receipt = journal.transition(
            &operation_id,
            EffectState::Failed,
            TimestampNs(3),
            Some(proof),
            Some("provider_failed_before_delivery".to_owned()),
        )?;
        assert_eq!(receipt.result_digest, Some(proof));
        let obligation = journal
            .obligations()
            .find(|item| item.obligation_id == obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Failed);
        assert_eq!(obligation.proof_digest, Some(proof));
        Ok(())
    }

    #[test]
    fn backward_reconciliation_is_rejected_without_mutation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"reconcile-order")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect,
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation_id, TimestampNs(4), "lost_ack")?;
        let before = journal
            .operation(&operation_id)
            .ok_or(ContractError::NotFound)?
            .clone();
        assert_eq!(
            journal.reconcile_verified(
                &operation_id,
                ContentDigest::sha256(b"provider-delivery"),
                TimestampNs(3),
            ),
            Err(ContractError::InvertedTimeInterval)
        );
        assert_eq!(journal.operation(&operation_id), Some(&before));
        Ok(())
    }

    #[test]
    fn test_journal_transitions_codec_and_replay() -> Result<(), ContractError> {
        let mut live = EffectJournal::new();
        let effect = intent(b"replay-test")?;
        let op = effect.operation_id.clone();
        let obl = ObligationId::parse("obligation:replay:test")?;
        let t1 = TimestampNs(10);
        let t2 = TimestampNs(20);
        let t3 = TimestampNs(30);
        let t4 = TimestampNs(40);
        let t5 = TimestampNs(50);

        let tr1 = EffectJournalTransition::Prepare {
            intent: effect.clone(),
            obligation_id: obl.clone(),
            terminal_predicate: "delivery_proved".to_string(),
            now: t1,
        };
        let tr2 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::Committed,
            now: t2,
            result_digest: None,
            error_code: None,
        };
        let tr3 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::AdapterAccepted,
            now: t3,
            result_digest: None,
            error_code: None,
        };
        let obs_proof = ContentDigest::sha256(b"obs-proof");
        let tr4 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::Observed,
            now: t4,
            result_digest: Some(obs_proof),
            error_code: None,
        };
        let tr5 = EffectJournalTransition::ReconcileVerified {
            operation_id: op.clone(),
            proof_digest: obs_proof,
            now: t5,
        };

        let transitions = vec![tr1, tr2, tr3, tr4, tr5];
        let mut decoded_transitions = Vec::new();
        for tr in &transitions {
            let bytes = tr.canonical_bytes();
            let decoded = EffectJournalTransition::from_canonical_bytes(&bytes)?;
            assert_eq!(&decoded, tr);
            decoded_transitions.push(decoded);
        }

        for tr in &transitions {
            live.apply_transition(tr.clone())?;
        }

        let replayed = EffectJournal::replay(decoded_transitions)?;
        assert_eq!(replayed, live);
        assert_eq!(replayed.journal_root(), live.journal_root());
        Ok(())
    }
}
