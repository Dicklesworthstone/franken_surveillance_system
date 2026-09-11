//! Pure-Rust four-valued operation outcomes and stable errors (FSS-004).
//!
//! # Architecture and Invariants
//!
//! The Franken Surveillance System operates under strict semantic planes: authority,
//! cognition, and effect records are type-distinct (INV-001). Consequential effects
//! and operational invocations must never collapse uncertainty, absence, or refusal
//! into a standard binary `Result<T, E>`.
//!
//! In particular:
//! - An operational outcome is strictly four-valued:
//!   1. [`OperationOutcome::Success`]: Work completed definitively with a typed payload.
//!   2. [`OperationOutcome::Failed`]: Work failed with an expected, typed error.
//!   3. [`OperationOutcome::Indeterminate`]: Work dispatch or execution state cannot be
//!      verified; side-effects may or may not have occurred, requiring explicit reconciliation
//!      before retry.
//!   4. [`OperationOutcome::UnauthorizedOrNotObservable`]: Operation was refused because the
//!      principal lacks required authority/capability, or because the target domain/interval
//!      was not observable under the active sensor coverage.
//! - **Non-Upgradability Invariant**: An [`OperationOutcome::Indeterminate`] or
//!   [`OperationOutcome::UnauthorizedOrNotObservable`] outcome can **never** be upgraded to
//!   [`OperationOutcome::Success`] by any combinator (`map`, `and_then`, `or_else`, etc.).
//! - **No Implicit Result Conversion**: Implicit conversion between [`OperationOutcome`] and
//!   [`Result`] is forbidden (`From` implementations are intentionally absent) to prevent
//!   callers from silently coercing indeterminate or refusal states into generic error variants.
//! - **Stable Error Identities**: Every [`OperationError`] carries a stable machine identifier
//!   matching the registry pattern `^ERR-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$` along with
//!   structured guidance fields ([`RecoveryClass`], `safe_retry`, `resnapshot_required`,
//!   `reconciliation_required`, `rebase_guidance`, and `backoff_ms`).

use core::fmt;
use core::ops::Deref;
use core::str::FromStr;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, RecoveryClass};

// ---------------------------------------------------------------------------
// Stable Error Identifier Constants (Registered in registries/ERRORS.md)
// ---------------------------------------------------------------------------

/// Operation execution failed with expected domain error.
pub const ERR_OP_EXECUTION_FAILED_001: &str = "ERR-OP-EXECUTION-FAILED-001";

/// Operation precondition or basis anchor invalidated.
pub const ERR_OP_PRECONDITION_FAILED_001: &str = "ERR-OP-PRECONDITION-FAILED-001";

/// Operation effect outcome cannot be verified and must be reconciled.
pub const ERR_OP_INDETERMINATE_001: &str = "ERR-OP-INDETERMINATE-001";

/// Operation refused due to missing authority or capability.
pub const ERR_OP_UNAUTHORIZED_001: &str = "ERR-OP-UNAUTHORIZED-001";

/// Operation domain is not observable under current coverage.
pub const ERR_OP_NOT_OBSERVABLE_001: &str = "ERR-OP-NOT-OBSERVABLE-001";

/// Operation budget or deadline expired before completion.
pub const ERR_OP_TIMEOUT_001: &str = "ERR-OP-TIMEOUT-001";

/// Pending unresolved operation must be reconciled before further mutation.
pub const ERR_OP_RECONCILIATION_REQUIRED_001: &str = "ERR-OP-RECONCILIATION-REQUIRED-001";

/// Error identity does not conform to stable ERR pattern.
pub const ERR_OP_ID_MALFORMED_001: &str = "ERR-OP-ID-MALFORMED-001";

/// Operation outcome state transition or representation is invalid.
pub const ERR_OP_INVALID_OUTCOME_001: &str = "ERR-OP-INVALID-OUTCOME-001";

// ---------------------------------------------------------------------------
// ErrorId
// ---------------------------------------------------------------------------

/// Validates that an error identifier conforms to the stable machine-readable
/// pattern: `^ERR-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$` with bounded length (7..=128).
pub fn validate_error_id(value: &str) -> Result<(), ContractError> {
    if value.len() < 7 || value.len() > 128 {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut parts = value.split('-');
    let first = parts.next().ok_or(ContractError::InvalidIdentifier)?;
    if first != "ERR" {
        return Err(ContractError::InvalidIdentifier);
    }
    let prev_segment = parts.next().ok_or(ContractError::InvalidIdentifier)?;
    if prev_segment.is_empty()
        || !prev_segment
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut last_segment: Option<&str> = None;
    for segment in parts {
        if last_segment.is_some_and(|prev| {
            prev.is_empty()
                || !prev
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        }) {
            return Err(ContractError::InvalidIdentifier);
        }
        last_segment = Some(segment);
    }
    let suffix = match last_segment {
        Some(s) => s,
        None => return Err(ContractError::InvalidIdentifier),
    };
    if suffix.len() != 3 || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// A validated stable error identity conforming to `^ERR-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ErrorId(String);

impl ErrorId {
    /// Parses and validates a stable error identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_error_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, returning the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ErrorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for ErrorId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ErrorId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for ErrorId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl CanonicalEncode for ErrorId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.0);
    }
}

impl CanonicalDecode for ErrorId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text)
    }
}

// ---------------------------------------------------------------------------
// RecoveryClass helpers & Canonical Codec
// ---------------------------------------------------------------------------

impl RecoveryClass {
    /// Returns the canonical machine-readable identifier for this recovery class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverUnchanged => "never_unchanged",
            Self::SafeReadRetry => "safe_read_retry",
            Self::RefreshAndRetry => "refresh_and_retry",
            Self::RebaseRequired => "rebase_required",
            Self::Backoff => "backoff",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::OperatorActionRequired => "operator_action_required",
            Self::ResumeFromContinuation => "resume_from_continuation",
        }
    }

    /// Parses from the canonical machine-readable string.
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "never_unchanged" => Ok(Self::NeverUnchanged),
            "safe_read_retry" => Ok(Self::SafeReadRetry),
            "refresh_and_retry" => Ok(Self::RefreshAndRetry),
            "rebase_required" => Ok(Self::RebaseRequired),
            "backoff" => Ok(Self::Backoff),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            "operator_action_required" => Ok(Self::OperatorActionRequired),
            "resume_from_continuation" => Ok(Self::ResumeFromContinuation),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for RecoveryClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for RecoveryClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text)
    }
}

// ---------------------------------------------------------------------------
// OperationError
// ---------------------------------------------------------------------------

/// Structured, stable operational error carrying recovery, retry, rebase, and reconciliation guidance.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OperationError {
    /// Stable machine error identity.
    pub error_id: ErrorId,
    /// Human-readable explanation.
    pub message: String,
    /// Recovery classification.
    pub recovery_class: RecoveryClass,
    /// Whether this operation may be safely retried.
    pub safe_retry: bool,
    /// Whether a fresh situation/snapshot anchor must be acquired before retrying.
    pub resnapshot_required: bool,
    /// Whether external effect/ledger reconciliation must precede retry.
    pub reconciliation_required: bool,
    /// Optional guidance on how to rebase the operation against an updated basis.
    pub rebase_guidance: Option<String>,
    /// Optional backoff interval in milliseconds before retrying.
    pub backoff_ms: Option<u64>,
}

impl OperationError {
    /// Constructs a basic operational error with default retry/rebase flags (false/None).
    pub fn new(
        error_id: ErrorId,
        message: impl Into<String>,
        recovery_class: RecoveryClass,
    ) -> Self {
        Self {
            error_id,
            message: message.into(),
            recovery_class,
            safe_retry: false,
            resnapshot_required: false,
            reconciliation_required: false,
            rebase_guidance: None,
            backoff_ms: None,
        }
    }

    /// Convenience constructor for execution failure.
    pub fn execution_failed(message: impl Into<String>) -> Result<Self, ContractError> {
        Ok(Self::new(
            ErrorId::parse(ERR_OP_EXECUTION_FAILED_001)?,
            message,
            RecoveryClass::NeverUnchanged,
        ))
    }

    /// Convenience constructor for precondition or anchor staleness.
    pub fn precondition_failed(
        message: impl Into<String>,
        rebase_guidance: impl Into<String>,
    ) -> Result<Self, ContractError> {
        Ok(Self::new(
            ErrorId::parse(ERR_OP_PRECONDITION_FAILED_001)?,
            message,
            RecoveryClass::RebaseRequired,
        )
        .with_resnapshot(true)
        .with_rebase_guidance(rebase_guidance))
    }

    /// Convenience constructor for operations requiring external reconciliation.
    pub fn reconciliation_required_error(
        message: impl Into<String>,
    ) -> Result<Self, ContractError> {
        Ok(Self::new(
            ErrorId::parse(ERR_OP_RECONCILIATION_REQUIRED_001)?,
            message,
            RecoveryClass::ReconciliationRequired,
        )
        .with_reconciliation(true)
        .with_resnapshot(true))
    }

    /// Sets the safe_retry flag.
    #[must_use]
    pub fn with_safe_retry(mut self, safe_retry: bool) -> Self {
        self.safe_retry = safe_retry;
        self
    }

    /// Sets the resnapshot_required flag.
    #[must_use]
    pub fn with_resnapshot(mut self, resnapshot_required: bool) -> Self {
        self.resnapshot_required = resnapshot_required;
        self
    }

    /// Sets the reconciliation_required flag.
    #[must_use]
    pub fn with_reconciliation(mut self, reconciliation_required: bool) -> Self {
        self.reconciliation_required = reconciliation_required;
        self
    }

    /// Sets optional rebase guidance.
    #[must_use]
    pub fn with_rebase_guidance(mut self, guidance: impl Into<String>) -> Self {
        self.rebase_guidance = Some(guidance.into());
        self
    }

    /// Sets optional backoff in milliseconds.
    #[must_use]
    pub fn with_backoff_ms(mut self, backoff_ms: u64) -> Self {
        self.backoff_ms = Some(backoff_ms);
        self
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {} (safe_retry={}, resnapshot={}, reconcile={})",
            self.recovery_class.as_str(),
            self.error_id,
            self.message,
            self.safe_retry,
            self.resnapshot_required,
            self.reconciliation_required
        )?;
        if let Some(ref guidance) = self.rebase_guidance {
            write!(f, " rebase: {guidance}")?;
        }
        if let Some(backoff) = self.backoff_ms {
            write!(f, " backoff_ms: {backoff}")?;
        }
        Ok(())
    }
}

impl std::error::Error for OperationError {}

impl CanonicalEncode for OperationError {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.error_id.encode_canonical(encoder);
        encoder.text(&self.message);
        self.recovery_class.encode_canonical(encoder);
        encoder.bool(self.safe_retry);
        encoder.bool(self.resnapshot_required);
        encoder.bool(self.reconciliation_required);
        encoder.bool(self.rebase_guidance.is_some());
        if let Some(ref guidance) = self.rebase_guidance {
            encoder.text(guidance);
        }
        encoder.bool(self.backoff_ms.is_some());
        if let Some(backoff) = self.backoff_ms {
            encoder.u64(backoff);
        }
    }
}

impl CanonicalDecode for OperationError {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let error_id = ErrorId::decode_canonical(decoder)?;
        let message = decoder.text()?.to_string();
        let recovery_class = RecoveryClass::decode_canonical(decoder)?;
        let safe_retry = decoder.bool()?;
        let resnapshot_required = decoder.bool()?;
        let reconciliation_required = decoder.bool()?;
        let has_rebase = decoder.bool()?;
        let rebase_guidance = if has_rebase {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let has_backoff = decoder.bool()?;
        let backoff_ms = if has_backoff {
            Some(decoder.u64()?)
        } else {
            None
        };
        Ok(Self {
            error_id,
            message,
            recovery_class,
            safe_retry,
            resnapshot_required,
            reconciliation_required,
            rebase_guidance,
            backoff_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// RefusalReason & RefusalDetail
// ---------------------------------------------------------------------------

/// Discriminator for why an operation was refused or unobservable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RefusalReason {
    /// Operation refused because caller lacks required capability, authority, or policy grant.
    Unauthorized,
    /// Operation cannot be answered because the target domain, interval, or object is not observable.
    NotObservable,
}

impl RefusalReason {
    /// Returns the canonical machine-readable string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::NotObservable => "not_observable",
        }
    }

    /// Parses from the canonical machine-readable string.
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "unauthorized" => Ok(Self::Unauthorized),
            "not_observable" => Ok(Self::NotObservable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for RefusalReason {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for RefusalReason {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text)
    }
}

/// Structured explanation when an operation is unauthorized or not observable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RefusalDetail {
    /// Exact refusal classification.
    pub reason: RefusalReason,
    /// Human-readable explanation of why the operation was refused.
    pub message: String,
    /// Required capability identifier if the reason is `Unauthorized`.
    pub required_capability: Option<String>,
    /// Whether establishing a `CoverageWitness` could make the domain observable.
    pub coverage_witness_required: bool,
}

impl RefusalDetail {
    /// Constructs an authorization refusal detail.
    pub fn unauthorized(
        message: impl Into<String>,
        required_capability: Option<impl Into<String>>,
    ) -> Self {
        Self {
            reason: RefusalReason::Unauthorized,
            message: message.into(),
            required_capability: required_capability.map(Into::into),
            coverage_witness_required: false,
        }
    }

    /// Constructs an observability refusal detail.
    pub fn not_observable(message: impl Into<String>, coverage_witness_required: bool) -> Self {
        Self {
            reason: RefusalReason::NotObservable,
            message: message.into(),
            required_capability: None,
            coverage_witness_required,
        }
    }
}

impl fmt::Display for RefusalDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.message)?;
        if let Some(ref cap) = self.required_capability {
            write!(f, " (required_capability: {cap})")?;
        }
        if self.coverage_witness_required {
            write!(f, " [coverage witness required]")?;
        }
        Ok(())
    }
}

impl CanonicalEncode for RefusalDetail {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.reason.encode_canonical(encoder);
        encoder.text(&self.message);
        encoder.bool(self.required_capability.is_some());
        if let Some(ref cap) = self.required_capability {
            encoder.text(cap);
        }
        encoder.bool(self.coverage_witness_required);
    }
}

impl CanonicalDecode for RefusalDetail {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let reason = RefusalReason::decode_canonical(decoder)?;
        let message = decoder.text()?.to_string();
        let has_cap = decoder.bool()?;
        let required_capability = if has_cap {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let coverage_witness_required = decoder.bool()?;
        Ok(Self {
            reason,
            message,
            required_capability,
            coverage_witness_required,
        })
    }
}

// ---------------------------------------------------------------------------
// IndeterminateDetail
// ---------------------------------------------------------------------------

/// Structured diagnostic when an operation's completion or external effect is indeterminate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndeterminateDetail {
    /// Operational lifecycle phase in which determinism was lost (e.g., "dispatch", "ack", "commit").
    pub phase: String,
    /// Detailed diagnostic reason.
    pub reason: String,
    /// Prescribed reconciliation steps to prove or safely negate the outcome.
    pub reconciliation_guidance: String,
    /// Correlation or idempotency identifier associated with the in-flight effect, if any.
    pub pending_id: Option<String>,
    /// Whether a fresh situation/snapshot anchor is required before reconciliation.
    pub resnapshot_required: bool,
}

impl IndeterminateDetail {
    /// Constructs a new indeterminate diagnostic.
    pub fn new(
        phase: impl Into<String>,
        reason: impl Into<String>,
        reconciliation_guidance: impl Into<String>,
    ) -> Self {
        Self {
            phase: phase.into(),
            reason: reason.into(),
            reconciliation_guidance: reconciliation_guidance.into(),
            pending_id: None,
            resnapshot_required: true,
        }
    }

    /// Sets the pending correlation identifier.
    #[must_use]
    pub fn with_pending_id(mut self, pending_id: impl Into<String>) -> Self {
        self.pending_id = Some(pending_id.into());
        self
    }

    /// Sets the resnapshot_required flag.
    #[must_use]
    pub fn with_resnapshot(mut self, resnapshot_required: bool) -> Self {
        self.resnapshot_required = resnapshot_required;
        self
    }
}

impl fmt::Display for IndeterminateDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "indeterminate in phase '{}': {} (guidance: {})",
            self.phase, self.reason, self.reconciliation_guidance
        )?;
        if let Some(ref pid) = self.pending_id {
            write!(f, " [pending_id: {pid}]")?;
        }
        Ok(())
    }
}

impl CanonicalEncode for IndeterminateDetail {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.phase);
        encoder.text(&self.reason);
        encoder.text(&self.reconciliation_guidance);
        encoder.bool(self.pending_id.is_some());
        if let Some(ref pid) = self.pending_id {
            encoder.text(pid);
        }
        encoder.bool(self.resnapshot_required);
    }
}

impl CanonicalDecode for IndeterminateDetail {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let phase = decoder.text()?.to_string();
        let reason = decoder.text()?.to_string();
        let reconciliation_guidance = decoder.text()?.to_string();
        let has_pending = decoder.bool()?;
        let pending_id = if has_pending {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let resnapshot_required = decoder.bool()?;
        Ok(Self {
            phase,
            reason,
            reconciliation_guidance,
            pending_id,
            resnapshot_required,
        })
    }
}

// ---------------------------------------------------------------------------
// OperationOutcome<T, E>
// ---------------------------------------------------------------------------

/// Four-valued operational outcome contract (FSS-004).
///
/// Disallows implicit conversion to/from standard [`Result`] to prevent accidental
/// erasure of indeterminate effects or observation refusals.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum OperationOutcome<T, E = OperationError> {
    /// Work completed definitively with a typed payload.
    Success(T),
    /// Work failed with a stable, typed error.
    Failed(E),
    /// Work execution or effect cannot be definitively verified; reconciliation required.
    Indeterminate(IndeterminateDetail),
    /// Operation was refused due to missing authority/capability or unobservable domain.
    UnauthorizedOrNotObservable(RefusalDetail),
}

impl<T, E> OperationOutcome<T, E> {
    /// Creates a [`Success`](Self::Success) outcome.
    pub const fn success(val: T) -> Self {
        Self::Success(val)
    }

    /// Creates a [`Failed`](Self::Failed) outcome.
    pub const fn failed(err: E) -> Self {
        Self::Failed(err)
    }

    /// Creates an [`Indeterminate`](Self::Indeterminate) outcome.
    pub const fn indeterminate(detail: IndeterminateDetail) -> Self {
        Self::Indeterminate(detail)
    }

    /// Creates an [`UnauthorizedOrNotObservable`](Self::UnauthorizedOrNotObservable) outcome.
    pub const fn unauthorized_or_not_observable(refusal: RefusalDetail) -> Self {
        Self::UnauthorizedOrNotObservable(refusal)
    }

    /// Convenience constructor for an authorization refusal.
    pub fn unauthorized(
        message: impl Into<String>,
        required_capability: Option<impl Into<String>>,
    ) -> Self {
        Self::UnauthorizedOrNotObservable(RefusalDetail::unauthorized(message, required_capability))
    }

    /// Convenience constructor for an unobservable domain refusal.
    pub fn not_observable(message: impl Into<String>, coverage_witness_required: bool) -> Self {
        Self::UnauthorizedOrNotObservable(RefusalDetail::not_observable(
            message,
            coverage_witness_required,
        ))
    }

    /// Returns `true` if the outcome is [`Success`](Self::Success).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns `true` if the outcome is [`Failed`](Self::Failed).
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Returns `true` if the outcome is [`Indeterminate`](Self::Indeterminate).
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate(_))
    }

    /// Returns `true` if the outcome is [`UnauthorizedOrNotObservable`](Self::UnauthorizedOrNotObservable).
    #[must_use]
    pub const fn is_unauthorized_or_not_observable(&self) -> bool {
        matches!(self, Self::UnauthorizedOrNotObservable(_))
    }

    /// Returns a reference to the contained success value, if any.
    #[must_use]
    pub const fn as_success(&self) -> Option<&T> {
        match self {
            Self::Success(val) => Some(val),
            _ => None,
        }
    }

    /// Returns a mutable reference to the contained success value, if any.
    pub const fn as_success_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Success(val) => Some(val),
            _ => None,
        }
    }

    /// Returns a reference to the contained failure error, if any.
    #[must_use]
    pub const fn as_failed(&self) -> Option<&E> {
        match self {
            Self::Failed(err) => Some(err),
            _ => None,
        }
    }

    /// Returns a mutable reference to the contained failure error, if any.
    pub const fn as_failed_mut(&mut self) -> Option<&mut E> {
        match self {
            Self::Failed(err) => Some(err),
            _ => None,
        }
    }

    /// Returns a reference to the contained indeterminate diagnostic, if any.
    #[must_use]
    pub const fn as_indeterminate(&self) -> Option<&IndeterminateDetail> {
        match self {
            Self::Indeterminate(detail) => Some(detail),
            _ => None,
        }
    }

    /// Returns a reference to the contained refusal detail, if any.
    #[must_use]
    pub const fn as_unauthorized_or_not_observable(&self) -> Option<&RefusalDetail> {
        match self {
            Self::UnauthorizedOrNotObservable(refusal) => Some(refusal),
            _ => None,
        }
    }

    /// Consumes `self`, returning the success value if present.
    #[must_use]
    pub fn into_success(self) -> Option<T> {
        match self {
            Self::Success(val) => Some(val),
            _ => None,
        }
    }

    /// Consumes `self`, returning the failure error if present.
    #[must_use]
    pub fn into_failed(self) -> Option<E> {
        match self {
            Self::Failed(err) => Some(err),
            _ => None,
        }
    }

    /// Consumes `self`, returning the indeterminate diagnostic if present.
    #[must_use]
    pub fn into_indeterminate(self) -> Option<IndeterminateDetail> {
        match self {
            Self::Indeterminate(detail) => Some(detail),
            _ => None,
        }
    }

    /// Consumes `self`, returning the refusal detail if present.
    #[must_use]
    pub fn into_unauthorized_or_not_observable(self) -> Option<RefusalDetail> {
        match self {
            Self::UnauthorizedOrNotObservable(refusal) => Some(refusal),
            _ => None,
        }
    }

    /// Maps an `OperationOutcome<T, E>` to `OperationOutcome<&T, &E>`.
    pub fn as_ref(&self) -> OperationOutcome<&T, &E> {
        match self {
            Self::Success(val) => OperationOutcome::Success(val),
            Self::Failed(err) => OperationOutcome::Failed(err),
            Self::Indeterminate(detail) => OperationOutcome::Indeterminate(detail.clone()),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal.clone())
            }
        }
    }

    /// Maps an `OperationOutcome<T, E>` to `OperationOutcome<&mut T, &mut E>`.
    pub fn as_mut(&mut self) -> OperationOutcome<&mut T, &mut E> {
        match self {
            Self::Success(val) => OperationOutcome::Success(val),
            Self::Failed(err) => OperationOutcome::Failed(err),
            Self::Indeterminate(detail) => OperationOutcome::Indeterminate(detail.clone()),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal.clone())
            }
        }
    }

    /// Maps a `OperationOutcome<T, E>` to `OperationOutcome<U, E>` by applying a function
    /// to a contained `Success` value, leaving `Failed`, `Indeterminate`, and
    /// `UnauthorizedOrNotObservable` untouched.
    ///
    /// # Invariant
    /// An indeterminate or refused outcome is never upgraded or transformed into success.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> OperationOutcome<U, E> {
        match self {
            Self::Success(val) => OperationOutcome::Success(f(val)),
            Self::Failed(err) => OperationOutcome::Failed(err),
            Self::Indeterminate(ind) => OperationOutcome::Indeterminate(ind),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal)
            }
        }
    }

    /// Maps a `OperationOutcome<T, E>` to `OperationOutcome<T, O>` by applying a function
    /// to a contained `Failed` error, leaving `Success`, `Indeterminate`, and
    /// `UnauthorizedOrNotObservable` untouched.
    ///
    /// # Invariant
    /// An indeterminate or refused outcome is never upgraded or transformed into success.
    pub fn map_err<O, F: FnOnce(E) -> O>(self, f: F) -> OperationOutcome<T, O> {
        match self {
            Self::Success(val) => OperationOutcome::Success(val),
            Self::Failed(err) => OperationOutcome::Failed(f(err)),
            Self::Indeterminate(ind) => OperationOutcome::Indeterminate(ind),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal)
            }
        }
    }

    /// Calls `f` if the outcome is `Success`, otherwise returns the non-success outcome.
    ///
    /// # Invariant
    /// If `self` is `Indeterminate` or `UnauthorizedOrNotObservable`, `f` is never executed
    /// and the indeterminate/refusal state is strictly preserved.
    pub fn and_then<U, F: FnOnce(T) -> OperationOutcome<U, E>>(
        self,
        f: F,
    ) -> OperationOutcome<U, E> {
        match self {
            Self::Success(val) => f(val),
            Self::Failed(err) => OperationOutcome::Failed(err),
            Self::Indeterminate(ind) => OperationOutcome::Indeterminate(ind),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal)
            }
        }
    }

    /// Calls `f` if the outcome is `Failed`, otherwise returns the outcome unchanged.
    ///
    /// # Invariant
    /// If `self` is `Indeterminate`, `f` is **never** executed. An indeterminate effect
    /// cannot be caught and replaced with a success value via `or_else`.
    pub fn or_else<O, F: FnOnce(E) -> OperationOutcome<T, O>>(
        self,
        f: F,
    ) -> OperationOutcome<T, O> {
        match self {
            Self::Success(val) => OperationOutcome::Success(val),
            Self::Failed(err) => f(err),
            Self::Indeterminate(ind) => OperationOutcome::Indeterminate(ind),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal)
            }
        }
    }

    /// Calls the provided closure with a reference to the contained value if `Success`.
    pub fn inspect<F: FnOnce(&T)>(self, f: F) -> Self {
        if let Self::Success(ref val) = self {
            f(val);
        }
        self
    }

    /// Calls the provided closure with a reference to the contained error if `Failed`.
    pub fn inspect_err<F: FnOnce(&E)>(self, f: F) -> Self {
        if let Self::Failed(ref err) = self {
            f(err);
        }
        self
    }

    /// Calls the provided closure with a reference to the contained diagnostic if `Indeterminate`.
    pub fn inspect_indeterminate<F: FnOnce(&IndeterminateDetail)>(self, f: F) -> Self {
        if let Self::Indeterminate(ref ind) = self {
            f(ind);
        }
        self
    }

    /// Calls the provided closure with a reference to the contained refusal if `UnauthorizedOrNotObservable`.
    pub fn inspect_unauthorized_or_not_observable<F: FnOnce(&RefusalDetail)>(self, f: F) -> Self {
        if let Self::UnauthorizedOrNotObservable(ref refusal) = self {
            f(refusal);
        }
        self
    }
}

impl<T, E> OperationOutcome<OperationOutcome<T, E>, E> {
    /// Flattens an `OperationOutcome<OperationOutcome<T, E>, E>` into an `OperationOutcome<T, E>`.
    ///
    /// # Invariant
    /// If either outer or inner outcome is `Indeterminate` or `UnauthorizedOrNotObservable`,
    /// that state is strictly preserved and never upgraded to `Success`.
    pub fn flatten(self) -> OperationOutcome<T, E> {
        match self {
            Self::Success(inner) => inner,
            Self::Failed(err) => OperationOutcome::Failed(err),
            Self::Indeterminate(ind) => OperationOutcome::Indeterminate(ind),
            Self::UnauthorizedOrNotObservable(refusal) => {
                OperationOutcome::UnauthorizedOrNotObservable(refusal)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical Codec for OperationOutcome
// ---------------------------------------------------------------------------

impl<T: CanonicalEncode, E: CanonicalEncode> CanonicalEncode for OperationOutcome<T, E> {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Success(val) => {
                encoder.tag(0);
                val.encode_canonical(encoder);
            }
            Self::Failed(err) => {
                encoder.tag(1);
                err.encode_canonical(encoder);
            }
            Self::Indeterminate(detail) => {
                encoder.tag(2);
                detail.encode_canonical(encoder);
            }
            Self::UnauthorizedOrNotObservable(refusal) => {
                encoder.tag(3);
                refusal.encode_canonical(encoder);
            }
        }
    }
}

impl<T: CanonicalDecode, E: CanonicalDecode> CanonicalDecode for OperationOutcome<T, E> {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.tag()?;
        match tag {
            0 => T::decode_canonical(decoder).map(Self::Success),
            1 => E::decode_canonical(decoder).map(Self::Failed),
            2 => IndeterminateDetail::decode_canonical(decoder).map(Self::Indeterminate),
            3 => RefusalDetail::decode_canonical(decoder).map(Self::UnauthorizedOrNotObservable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Canonical Codec (Enables OperationOutcome<()>)
// ---------------------------------------------------------------------------

impl CanonicalEncode for () {
    fn encode_canonical(&self, _encoder: &mut CanonicalEncoder) {}
}

impl CanonicalDecode for () {
    fn decode_canonical(_decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(())
    }
}
