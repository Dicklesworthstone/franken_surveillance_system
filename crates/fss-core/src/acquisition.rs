#![forbid(unsafe_code)]
//! Cross-adapter acquisition lifecycle state machine and witness contract (FSS-007 / ACQ-LIFECYCLE-001).
//!
//! Defines one adapter-neutral acquisition state machine used by UVC, RTSP/RTP/ONVIF, replay/import,
//! and authorized proprietary laboratory adapters:
//!
//! `Requested → Authenticated → AdapterAccepted → FirstFrameObserved → ContinuityVerified`,
//! with explicit `Degraded`, `Failed`, `Cancelled`, and `Indeterminate` branches.
//!
//! Non-negotiable lifecycle rules:
//! 1. Adapter acceptance is NEVER called "streaming" (INV-005).
//! 2. A decoded frame is NOT continuity; continuity requires an explicit sequence window and [`CoverageWitness`].
//! 3. Every transition carries the adapter/device identity and justification witness.
//! 4. Illegal transitions fail closed with typed [`AcquisitionError::IllegalTransition`].
//! 5. Reconnect creates a strictly monotonically newer [`StreamGeneration`]; reusing generations fails closed.
//! 6. Negative absence claims are forbidden until [`ContinuityVerified`] with certified coverage.
//! 7. `Indeterminate` states must stay indeterminate until explicitly reconciled, never flattened.
//! 8. Accept-then-silence deadlines fail closed to [`AcquisitionStateKind::Failed`]; no success is inferred from elapsed time.
//! 9. Identifiers must use canonical prefixes only (`src:`, `device:`, `adapter:`).

use core::fmt;
use std::collections::BTreeSet;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::evidence::{CoverageContinuity, CoverageStopReason, CoverageWitness, LedgerAnchor};
use crate::identity::{
    AdapterCapabilities, AdapterIdentity, CredentialMethod, DeviceIdentity, SourceIdentity,
};
use crate::ids::{AdapterId, DeviceId, SourceId, StreamGeneration};
use crate::sensor_capsule::{DecodeState, ExplicitOmission, OmissionReason, SourceCustody};
use crate::time::TimestampNs;
use crate::{Completeness, ContentDigest, ContractError};

/// Canonical schema for acquisition request envelopes.
pub const SCHEMA_ACQUISITION_REQUEST: &str = "fss.acquisition.request.v1";
/// Canonical schema for secret-free authentication receipts.
pub const SCHEMA_AUTH_RECEIPT: &str = "fss.acquisition.auth_receipt.v1";
/// Canonical schema for adapter acknowledgement receipts.
pub const SCHEMA_ADAPTER_ACK: &str = "fss.acquisition.adapter_ack.v1";
/// Canonical schema for first observed frame witnesses.
pub const SCHEMA_FIRST_FRAME: &str = "fss.acquisition.first_frame.v1";
/// Canonical schema for continuity verification witnesses.
pub const SCHEMA_CONTINUITY: &str = "fss.acquisition.continuity.v1";
/// Canonical schema for stream degradation evidence.
pub const SCHEMA_DEGRADATION: &str = "fss.acquisition.degradation.v1";
/// Canonical schema for acquisition failure witnesses.
pub const SCHEMA_FAILURE: &str = "fss.acquisition.failure.v1";
/// Canonical schema for cancellation quiescence receipts.
pub const SCHEMA_QUIESCENCE: &str = "fss.acquisition.quiescence.v1";
/// Canonical schema for indeterminate acquisition witnesses.
pub const SCHEMA_INDETERMINATE: &str = "fss.acquisition.indeterminate.v1";
/// Canonical schema for transition audit records.
pub const SCHEMA_TRANSITION_RECORD: &str = "fss.acquisition.transition_record.v1";
/// Architecture constraint identifier for DJI Flip Mobile SDK non-dependency (NEG-001).
pub const CONSTRAINT_NEG_001: &str = "NEG-001";
/// Canonical schema for negative-evidence scenario logs.
pub const SCHEMA_NEG001_SCENARIO_LOG: &str = "fss.negative_evidence.scenario_log.v1";

/// Maximum length of session handle string.
pub const MAX_SESSION_HANDLE_LEN: usize = 128;
/// Maximum length of error code string.
pub const MAX_ERROR_CODE_LEN: usize = 64;
/// Maximum length of error message string.
pub const MAX_ERROR_MSG_LEN: usize = 512;
/// Maximum number of degraded dimensions recorded.
pub const MAX_LOST_DIMENSIONS: usize = 32;
/// Maximum length of a single dimension name string.
pub const MAX_DIMENSION_NAME_LEN: usize = 64;
/// Maximum number of invalidated negative claims recorded.
pub const MAX_INVALIDATED_CLAIMS: usize = 64;
/// Maximum length of a claim identifier string.
pub const MAX_CLAIM_NAME_LEN: usize = 128;
/// Maximum number of unresolved obligations in indeterminate witness.
pub const MAX_OBLIGATIONS: usize = 64;
/// Maximum length of an obligation name string.
pub const MAX_OBLIGATION_NAME_LEN: usize = 128;
/// Maximum length of an indeterminate reason string.
pub const MAX_REASON_LEN: usize = 512;
/// Maximum length of a transition diagnostic note.
pub const MAX_NOTE_LEN: usize = 256;
/// Maximum number of audit transitions retained in memory.
pub const MAX_HISTORY_LEN: usize = 1024;

/// Discriminator and classification for acquisition lifecycle states.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AcquisitionStateKind {
    /// Initial request submitted; binding identities and capability scope.
    Requested = 1,
    /// Caller and adapter authentication verified with secret-free receipt.
    Authenticated = 2,
    /// Target adapter acknowledged request; stream resources bound but NOT yet streaming.
    AdapterAccepted = 3,
    /// First decodable frame observed and linked to source custody or omission.
    FirstFrameObserved = 4,
    /// Unbroken continuity window verified with sequence bounds and coverage witness.
    ContinuityVerified = 5,
    /// Stream is active but degraded (e.g. packet loss, jitter, dropped dimensions).
    Degraded = 6,
    /// Terminal failure; requires clean reconnect with new stream generation.
    Failed = 7,
    /// Cleanly cancelled after verified resource quiescence.
    Cancelled = 8,
    /// Outcome indeterminate; must be preserved and reconciled, never flattened.
    Indeterminate = 9,
}

impl AcquisitionStateKind {
    /// Returns canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authenticated => "authenticated",
            Self::AdapterAccepted => "adapter_accepted",
            Self::FirstFrameObserved => "first_frame_observed",
            Self::ContinuityVerified => "continuity_verified",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Parses state kind from canonical string.
    pub fn parse(s: &str) -> Result<Self, AcquisitionError> {
        match s {
            "requested" => Ok(Self::Requested),
            "authenticated" => Ok(Self::Authenticated),
            "adapter_accepted" => Ok(Self::AdapterAccepted),
            "first_frame_observed" => Ok(Self::FirstFrameObserved),
            "continuity_verified" => Ok(Self::ContinuityVerified),
            "degraded" => Ok(Self::Degraded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!("unknown acquisition state kind '{s}'"),
            }),
        }
    }

    /// Returns true if this state is terminal (no forward transitions except reconnect).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }

    /// Returns true if the session is currently active.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::AdapterAccepted
                | Self::FirstFrameObserved
                | Self::ContinuityVerified
                | Self::Degraded
                | Self::Indeterminate
        )
    }

    /// Returns true if this state guarantees verified continuous streaming.
    ///
    /// Non-negotiable: Returns `true` ONLY for [`Self::ContinuityVerified`].
    /// Stream acceptance is never called streaming.
    #[must_use]
    pub const fn is_streaming(self) -> bool {
        matches!(self, Self::ContinuityVerified)
    }

    /// Returns true if continuity is certified.
    #[must_use]
    pub const fn has_continuity(self) -> bool {
        matches!(self, Self::ContinuityVerified)
    }
}

impl fmt::Display for AcquisitionStateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for AcquisitionStateKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for AcquisitionStateKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Requested),
            2 => Ok(Self::Authenticated),
            3 => Ok(Self::AdapterAccepted),
            4 => Ok(Self::FirstFrameObserved),
            5 => Ok(Self::ContinuityVerified),
            6 => Ok(Self::Degraded),
            7 => Ok(Self::Failed),
            8 => Ok(Self::Cancelled),
            9 => Ok(Self::Indeterminate),
            _ => Err(ContractError::NonCanonicalOrdering),
        }
    }
}

/// Retry classification for transition recovery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RetryClass {
    /// Non-retryable terminal failure; requires reconfiguration or operator intervention.
    NonRetryable = 1,
    /// Can retry immediately with fresh sequence/window.
    Immediate = 2,
    /// Must back off before retrying.
    Backoff = 3,
    /// Requires re-authentication before retry.
    Reauthenticate = 4,
    /// Requires parameter reconfiguration before retry.
    Reconfigure = 5,
}

impl RetryClass {
    /// Returns canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonRetryable => "non_retryable",
            Self::Immediate => "immediate",
            Self::Backoff => "backoff",
            Self::Reauthenticate => "reauthenticate",
            Self::Reconfigure => "reconfigure",
        }
    }

    /// Parses retry class from string.
    pub fn parse(s: &str) -> Result<Self, AcquisitionError> {
        match s {
            "non_retryable" => Ok(Self::NonRetryable),
            "immediate" => Ok(Self::Immediate),
            "backoff" => Ok(Self::Backoff),
            "reauthenticate" => Ok(Self::Reauthenticate),
            "reconfigure" => Ok(Self::Reconfigure),
            _ => Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!("unknown retry class '{s}'"),
            }),
        }
    }
}

impl fmt::Display for RetryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for RetryClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for RetryClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::NonRetryable),
            2 => Ok(Self::Immediate),
            3 => Ok(Self::Backoff),
            4 => Ok(Self::Reauthenticate),
            5 => Ok(Self::Reconfigure),
            _ => Err(ContractError::NonCanonicalOrdering),
        }
    }
}

/// Static entry in the versioned transition rule table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionTransitionRule {
    /// Source state kind.
    pub from: AcquisitionStateKind,
    /// Target state kind.
    pub to: AcquisitionStateKind,
    /// Schema or contract name of required witness.
    pub required_witness: &'static str,
    /// Whether target state is terminal.
    pub terminal: bool,
    /// Retry classification on break/failure.
    pub retry_class: RetryClass,
    /// Invalidation conditions for this transition.
    pub invalidators: &'static [&'static str],
}

/// Versioned static acquisition transition table.
pub static ACQUISITION_TRANSITION_TABLE: &[AcquisitionTransitionRule] = &[
    // From Requested
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Requested,
        to: AcquisitionStateKind::Authenticated,
        required_witness: SCHEMA_AUTH_RECEIPT,
        terminal: false,
        retry_class: RetryClass::Reauthenticate,
        invalidators: &["invalid_credentials", "expired_token"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Requested,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Requested,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    // From Authenticated
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Authenticated,
        to: AcquisitionStateKind::AdapterAccepted,
        required_witness: SCHEMA_ADAPTER_ACK,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["adapter_unreachable", "device_busy", "resource_exhausted"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Authenticated,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Authenticated,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    // From AdapterAccepted
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::AdapterAccepted,
        to: AcquisitionStateKind::FirstFrameObserved,
        required_witness: SCHEMA_FIRST_FRAME,
        terminal: false,
        retry_class: RetryClass::Immediate,
        invalidators: &["frame_corrupt", "codec_mismatch", "silence_timeout"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::AdapterAccepted,
        to: AcquisitionStateKind::Degraded,
        required_witness: SCHEMA_DEGRADATION,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["packet_loss", "timing_jitter"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::AdapterAccepted,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::AdapterAccepted,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::AdapterAccepted,
        to: AcquisitionStateKind::Indeterminate,
        required_witness: SCHEMA_INDETERMINATE,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["unobserved_drop", "driver_hang"],
    },
    // From FirstFrameObserved
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::FirstFrameObserved,
        to: AcquisitionStateKind::ContinuityVerified,
        required_witness: SCHEMA_CONTINUITY,
        terminal: false,
        retry_class: RetryClass::Immediate,
        invalidators: &[
            "packet_gap",
            "frame_drop",
            "jitter_exceeded",
            "coverage_loss",
        ],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::FirstFrameObserved,
        to: AcquisitionStateKind::Degraded,
        required_witness: SCHEMA_DEGRADATION,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["packet_loss", "timing_jitter"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::FirstFrameObserved,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::FirstFrameObserved,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::FirstFrameObserved,
        to: AcquisitionStateKind::Indeterminate,
        required_witness: SCHEMA_INDETERMINATE,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["unobserved_drop", "driver_hang"],
    },
    // From ContinuityVerified
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::ContinuityVerified,
        to: AcquisitionStateKind::ContinuityVerified,
        required_witness: SCHEMA_CONTINUITY,
        terminal: false,
        retry_class: RetryClass::Immediate,
        invalidators: &["packet_gap", "frame_drop", "jitter_exceeded"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::ContinuityVerified,
        to: AcquisitionStateKind::Degraded,
        required_witness: SCHEMA_DEGRADATION,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["packet_loss", "timing_jitter", "frame_gap"],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::ContinuityVerified,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::ContinuityVerified,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::ContinuityVerified,
        to: AcquisitionStateKind::Indeterminate,
        required_witness: SCHEMA_INDETERMINATE,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["unobserved_drop", "driver_hang"],
    },
    // From Degraded
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Degraded,
        to: AcquisitionStateKind::ContinuityVerified,
        required_witness: SCHEMA_CONTINUITY,
        terminal: false,
        retry_class: RetryClass::Immediate,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Degraded,
        to: AcquisitionStateKind::Degraded,
        required_witness: SCHEMA_DEGRADATION,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Degraded,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Degraded,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Degraded,
        to: AcquisitionStateKind::Indeterminate,
        required_witness: SCHEMA_INDETERMINATE,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &["unobserved_drop", "driver_hang"],
    },
    // From Indeterminate (reconciliation transitions)
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Indeterminate,
        to: AcquisitionStateKind::ContinuityVerified,
        required_witness: SCHEMA_CONTINUITY,
        terminal: false,
        retry_class: RetryClass::Immediate,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Indeterminate,
        to: AcquisitionStateKind::Degraded,
        required_witness: SCHEMA_DEGRADATION,
        terminal: false,
        retry_class: RetryClass::Backoff,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Indeterminate,
        to: AcquisitionStateKind::Failed,
        required_witness: SCHEMA_FAILURE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
    AcquisitionTransitionRule {
        from: AcquisitionStateKind::Indeterminate,
        to: AcquisitionStateKind::Cancelled,
        required_witness: SCHEMA_QUIESCENCE,
        terminal: true,
        retry_class: RetryClass::NonRetryable,
        invalidators: &[],
    },
];

/// Returns the static transition rule for a pair of states, if registered.
#[must_use]
pub fn get_transition_rule(
    from: AcquisitionStateKind,
    to: AcquisitionStateKind,
) -> Option<&'static AcquisitionTransitionRule> {
    ACQUISITION_TRANSITION_TABLE
        .iter()
        .find(|rule| rule.from == from && rule.to == to)
}

/// Returns true if a direct transition from `from` to `to` is legally registered.
#[must_use]
pub fn is_allowed_transition(from: AcquisitionStateKind, to: AcquisitionStateKind) -> bool {
    get_transition_rule(from, to).is_some()
}

/// Typed acquisition lifecycle errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionError {
    /// Attempted an illegal or unregistered state transition.
    IllegalTransition {
        /// Origin state.
        from: AcquisitionStateKind,
        /// Attempted destination state.
        to: AcquisitionStateKind,
    },
    /// A required witness was missing or incomplete for the transition.
    MissingWitness {
        /// State requiring witness.
        state: AcquisitionStateKind,
        /// Description of missing witness.
        witness_type: &'static str,
    },
    /// Witness data did not match expected session identities or digest.
    WitnessMismatch {
        /// Detailed mismatch description.
        detail: String,
    },
    /// Stream generation conflict: reconnect generation must be strictly monotonic.
    GenerationConflict {
        /// Current generation.
        current_generation: StreamGeneration,
        /// Attempted generation.
        attempted_generation: StreamGeneration,
    },
    /// Quiescence receipt failed verification (resources still active/open).
    QuiescenceViolation {
        /// Active tasks remaining.
        active_tasks: u32,
        /// Open descriptors remaining.
        open_descriptors: u32,
    },
    /// Coverage witness failed verification or cannot certify absence.
    InvalidCoverageWitness {
        /// Details of coverage failure.
        detail: String,
    },
    /// Continuity window contained packet loss, gaps, or excessive jitter.
    ContinuityGapDetected {
        /// Details of continuity gap.
        detail: String,
    },
    /// Negative absence claim is forbidden in current lifecycle state.
    AbsenceClaimForbidden {
        /// Current lifecycle state.
        state: AcquisitionStateKind,
        /// Explanation why absence claims cannot be made.
        detail: &'static str,
    },
    /// Adapter accepted the session but silence timeout elapsed before first frame.
    AcceptSilenceTimeout {
        /// Configured deadline nanoseconds.
        deadline_ns: u64,
        /// Elapsed nanoseconds since acceptance.
        elapsed_ns: u64,
    },
    /// Indeterminate state was not explicitly reconciled before operation.
    IndeterminateStateUnresolved {
        /// Detail of unresolved condition.
        detail: String,
    },
    /// Bounds violation on bounded field.
    BoundsViolation {
        /// Field name.
        field: &'static str,
        /// Maximum allowed limit.
        max: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// Live capture route is unsupported by architectural or negative constraint (NEG-001).
    UnsupportedLiveRoute {
        /// Constraint identifier (e.g. "NEG-001").
        constraint_id: &'static str,
        /// Detail of unsupported route.
        detail: String,
    },
    /// Live capture route is temporarily unavailable.
    UnavailableLiveRoute {
        /// Detail of unavailable route.
        detail: String,
    },
    /// Frame decodability verification failed.
    DecodabilityError {
        /// Decode error details.
        detail: String,
    },
    /// Non-canonical encoding encountered.
    NonCanonicalEncoding {
        /// Detail of encoding defect.
        detail: String,
    },
    /// Timestamp overflow or invalid negative value.
    InvalidTimestamp {
        /// Detail of timestamp violation.
        detail: String,
    },
    /// Underlying contract or validation error.
    Contract(ContractError),
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal acquisition transition from {from} to {to}")
            }
            Self::MissingWitness {
                state,
                witness_type,
            } => {
                write!(
                    f,
                    "missing required witness '{witness_type}' for state {state}"
                )
            }
            Self::WitnessMismatch { detail } => {
                write!(f, "witness verification mismatch: {detail}")
            }
            Self::GenerationConflict {
                current_generation,
                attempted_generation,
            } => {
                write!(
                    f,
                    "stream generation conflict: attempted {attempted_generation} is not strictly greater than current {current_generation}"
                )
            }
            Self::QuiescenceViolation {
                active_tasks,
                open_descriptors,
            } => {
                write!(
                    f,
                    "quiescence violation: {active_tasks} active tasks and {open_descriptors} open descriptors remaining"
                )
            }
            Self::InvalidCoverageWitness { detail } => {
                write!(f, "invalid coverage witness: {detail}")
            }
            Self::ContinuityGapDetected { detail } => {
                write!(f, "continuity gap detected: {detail}")
            }
            Self::AbsenceClaimForbidden { state, detail } => {
                write!(f, "absence claim forbidden in state {state}: {detail}")
            }
            Self::AcceptSilenceTimeout {
                deadline_ns,
                elapsed_ns,
            } => {
                write!(
                    f,
                    "accept silence timeout: elapsed {elapsed_ns}ns exceeded deadline {deadline_ns}ns"
                )
            }
            Self::IndeterminateStateUnresolved { detail } => {
                write!(f, "indeterminate state unresolved: {detail}")
            }
            Self::BoundsViolation { field, max, actual } => {
                write!(
                    f,
                    "bounds violation on '{field}': limit {max}, got {actual}"
                )
            }
            Self::UnsupportedLiveRoute {
                constraint_id,
                detail,
            } => write!(f, "unsupported live route ({constraint_id}): {detail}"),
            Self::UnavailableLiveRoute { detail } => {
                write!(f, "unavailable live route: {detail}")
            }
            Self::DecodabilityError { detail } => write!(f, "frame decodability error: {detail}"),
            Self::NonCanonicalEncoding { detail } => {
                write!(f, "non-canonical encoding error: {detail}")
            }
            Self::InvalidTimestamp { detail } => write!(f, "invalid timestamp: {detail}"),
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for AcquisitionError {}

impl From<ContractError> for AcquisitionError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Canonical request to start an acquisition session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionRequest {
    /// Target source identity.
    pub source_identity: SourceIdentity,
    /// Physical or virtual device hosting the stream.
    pub device_identity: DeviceIdentity,
    /// Adapter driver performing acquisition.
    pub adapter_identity: AdapterIdentity,
    /// Capability scope requested from the adapter.
    pub requested_capabilities: AdapterCapabilities,
    /// Timestamp when acquisition was requested.
    pub requested_at_ns: TimestampNs,
}

impl AcquisitionRequest {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_ACQUISITION_REQUEST;

    /// Validates field invariants and mutual consistency across identities.
    pub fn verify(&self) -> Result<(), AcquisitionError> {
        self.source_identity
            .verify()
            .map_err(AcquisitionError::Contract)?;
        self.device_identity
            .verify()
            .map_err(AcquisitionError::Contract)?;
        self.adapter_identity
            .verify()
            .map_err(AcquisitionError::Contract)?;

        if !self
            .source_identity
            .source_id
            .as_str()
            .starts_with(SourceId::PREFIX)
        {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "source_id '{}' does not use canonical prefix '{}'",
                    self.source_identity.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if !self
            .device_identity
            .device_id
            .as_str()
            .starts_with(DeviceId::PREFIX)
        {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "device_id '{}' does not use canonical prefix '{}'",
                    self.device_identity.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self
            .adapter_identity
            .adapter_id
            .as_str()
            .starts_with(AdapterId::PREFIX)
        {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_identity.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }

        if self.source_identity.device_id != self.device_identity.device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "source device_id '{}' != device identity device_id '{}'",
                    self.source_identity.device_id, self.device_identity.device_id
                ),
            });
        }

        if self.source_identity.adapter_id != self.adapter_identity.adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "source adapter_id '{}' != adapter identity adapter_id '{}'",
                    self.source_identity.adapter_id, self.adapter_identity.adapter_id
                ),
            });
        }

        if !self
            .adapter_identity
            .capabilities
            .contains(self.requested_capabilities)
        {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "adapter capabilities {:?} do not contain requested capabilities {:?}",
                    self.adapter_identity.capabilities, self.requested_capabilities
                ),
            });
        }

        if self.is_dji_flip()
            && self
                .requested_capabilities
                .contains(AdapterCapabilities::STREAMING)
        {
            return Err(AcquisitionError::UnsupportedLiveRoute {
                constraint_id: CONSTRAINT_NEG_001,
                detail: "DJI Flip live streaming acquisition request is prohibited by NEG-001; manual capture/import only".to_string(),
            });
        }

        Ok(())
    }

    /// Returns true if this request identifies a DJI Flip device by adapter ID, device ID,
    /// or device identity manufacturer and model (NEG-001).
    #[must_use]
    pub fn is_dji_flip(&self) -> bool {
        let adapter_str = self.adapter_identity.adapter_id.as_str().to_lowercase();
        let device_str = self.device_identity.device_id.as_str().to_lowercase();
        let mfg = self.device_identity.manufacturer.to_lowercase();
        let model = self.device_identity.model.to_lowercase();
        (adapter_str.contains("dji") && adapter_str.contains("flip"))
            || (device_str.contains("dji") && device_str.contains("flip"))
            || (mfg.contains("dji") && (model.contains("flip") || model == "flip"))
            || model.contains("dji flip")
            || model.contains("flip drone")
            || (mfg.contains("dji")
                && self
                    .device_identity
                    .hardware_revision
                    .to_lowercase()
                    .contains("flip"))
    }

    /// Computes the domain-separated canonical digest of this acquisition request.
    #[must_use]
    pub fn request_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }
}

impl CanonicalEncode for AcquisitionRequest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.source_identity.encode_canonical(encoder);
        self.device_identity.encode_canonical(encoder);
        self.adapter_identity.encode_canonical(encoder);
        self.requested_capabilities.encode_canonical(encoder);
        self.requested_at_ns.encode_canonical(encoder);
    }
}

impl CanonicalDecode for AcquisitionRequest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let source_identity = SourceIdentity::decode_canonical(decoder)?;
        let device_identity = DeviceIdentity::decode_canonical(decoder)?;
        let adapter_identity = AdapterIdentity::decode_canonical(decoder)?;
        let requested_capabilities = AdapterCapabilities::decode_canonical(decoder)?;
        let requested_at_ns = TimestampNs::decode_canonical(decoder)?;
        Ok(Self {
            source_identity,
            device_identity,
            adapter_identity,
            requested_capabilities,
            requested_at_ns,
        })
    }
}

/// Secret-free receipt proving authentication of caller and adapter capability scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthReceipt {
    /// Adapter ID authorized.
    pub adapter_id: AdapterId,
    /// Device ID authorized.
    pub device_id: DeviceId,
    /// Credential method used for authentication.
    pub method: CredentialMethod,
    /// Digest of the principal or certificate (strictly secret-free).
    pub principal_digest: ContentDigest,
    /// Capabilities authorized by the credential.
    pub authorized_capabilities: AdapterCapabilities,
    /// Timestamp when authentication succeeded.
    pub authorized_at_ns: TimestampNs,
    /// Timestamp when authentication expires.
    pub expires_at_ns: TimestampNs,
}

impl AuthReceipt {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_AUTH_RECEIPT;

    /// Computes the domain-separated canonical digest of this auth receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies that this receipt satisfies the requested capabilities and is valid at `at_ns`.
    pub fn verify(
        &self,
        expected_adapter_id: &AdapterId,
        expected_device_id: &DeviceId,
        requested_caps: AdapterCapabilities,
        at_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "auth receipt adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "auth receipt device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "auth receipt adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "auth receipt device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.expires_at_ns < self.authorized_at_ns {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "auth expiry timestamp precedes authorization timestamp".to_string(),
            });
        }
        if at_ns < self.authorized_at_ns || at_ns > self.expires_at_ns {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "auth receipt not valid at timestamp {at_ns:?} (valid {}..={})",
                    self.authorized_at_ns.0, self.expires_at_ns.0
                ),
            });
        }
        if !self.authorized_capabilities.contains(requested_caps) {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "authorized capabilities {:?} do not cover requested {:?}",
                    self.authorized_capabilities, requested_caps
                ),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for AuthReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.method.encode_canonical(encoder);
        encoder.digest(self.principal_digest);
        self.authorized_capabilities.encode_canonical(encoder);
        self.authorized_at_ns.encode_canonical(encoder);
        self.expires_at_ns.encode_canonical(encoder);
    }
}

impl CanonicalDecode for AuthReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let method = CredentialMethod::decode_canonical(decoder)?;
        let principal_digest = decoder.digest()?;
        let authorized_capabilities = AdapterCapabilities::decode_canonical(decoder)?;
        let authorized_at_ns = TimestampNs::decode_canonical(decoder)?;
        let expires_at_ns = TimestampNs::decode_canonical(decoder)?;
        Ok(Self {
            adapter_id,
            device_id,
            method,
            principal_digest,
            authorized_capabilities,
            authorized_at_ns,
            expires_at_ns,
        })
    }
}

/// Adapter acknowledgement confirming receipt and acceptance of an acquisition request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterAck {
    /// Adapter that accepted the request.
    pub adapter_id: AdapterId,
    /// Exact canonical digest of the acquisition request acknowledged.
    pub request_digest: ContentDigest,
    /// Timestamp when adapter accepted.
    pub ack_timestamp_ns: TimestampNs,
    /// Adapter session or handle string (bounded).
    pub session_handle: String,
    /// Number of ring buffer frames allocated.
    pub allocated_buffer_frames: u32,
}

impl AdapterAck {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_ADAPTER_ACK;

    /// Computes the domain-separated canonical digest of this adapter ACK.
    #[must_use]
    pub fn ack_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies adapter ACK against expected request digest and adapter ID.
    pub fn verify(
        &self,
        expected_request_digest: &ContentDigest,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "adapter ACK adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "adapter ACK adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.request_digest != *expected_request_digest {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "adapter ACK request_digest '{}' != expected '{}'",
                    self.request_digest, expected_request_digest
                ),
            });
        }
        if self.session_handle.is_empty() || self.session_handle.len() > MAX_SESSION_HANDLE_LEN {
            return Err(AcquisitionError::BoundsViolation {
                field: "session_handle",
                max: MAX_SESSION_HANDLE_LEN,
                actual: self.session_handle.len(),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for AdapterAck {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        encoder.digest(self.request_digest);
        self.ack_timestamp_ns.encode_canonical(encoder);
        encoder.text(&self.session_handle);
        encoder.u32(self.allocated_buffer_frames);
    }
}

impl CanonicalDecode for AdapterAck {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let request_digest = decoder.digest()?;
        let ack_timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let session_handle = decoder.text()?.to_string();
        let allocated_buffer_frames = decoder.u32()?;
        Ok(Self {
            adapter_id,
            request_digest,
            ack_timestamp_ns,
            session_handle,
            allocated_buffer_frames,
        })
    }
}

/// Witness proving observation of the first decodable frame in the session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstFrameWitness {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Evidence source ID.
    pub source_id: SourceId,
    /// Sequence number of first observed frame.
    pub sequence_number: u64,
    /// Presentation timestamp of first frame.
    pub pts_ns: TimestampNs,
    /// Byte length of captured frame payload.
    pub frame_bytes: u64,
    /// Verification decode state (must be Verified).
    pub decode_state: DecodeState,
    /// Source custody record.
    pub source_custody: SourceCustody,
    /// Explicit omission record.
    pub explicit_omission: ExplicitOmission,
}

impl FirstFrameWitness {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_FIRST_FRAME;

    /// Computes the domain-separated canonical digest of this first frame witness.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies first frame witness requirements.
    pub fn verify(
        &self,
        expected_source_id: &SourceId,
        expected_device_id: &DeviceId,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "first frame adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "first frame device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "first frame source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "first frame adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "first frame device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "first frame source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.decode_state != DecodeState::Verified {
            return Err(AcquisitionError::DecodabilityError {
                detail: format!(
                    "first frame decode state is '{:?}', must be Verified",
                    self.decode_state
                ),
            });
        }
        if !self.source_custody.is_retained() && !self.explicit_omission.is_omitted() {
            return Err(AcquisitionError::MissingWitness {
                state: AcquisitionStateKind::FirstFrameObserved,
                witness_type: "source_custody (retained) or explicit_omission (omitted)",
            });
        }
        if matches!(
            &self.explicit_omission,
            ExplicitOmission::Omitted {
                reason: OmissionReason::None,
                ..
            }
        ) {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "omission reason cannot be None when omitted".to_string(),
            });
        }
        if matches!(
            &self.source_custody,
            SourceCustody::Retained {
                source_bytes: 0,
                ..
            }
        ) {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "retained custody declared 0 source bytes".to_string(),
            });
        }
        if self.frame_bytes == 0 && !self.explicit_omission.is_omitted() {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "frame bytes zero without explicit omission".to_string(),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for FirstFrameWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        encoder.u64(self.sequence_number);
        self.pts_ns.encode_canonical(encoder);
        encoder.u64(self.frame_bytes);
        encoder.u8(self.decode_state as u8);
        encode_source_custody(&self.source_custody, encoder);
        encode_explicit_omission(&self.explicit_omission, encoder);
    }
}

impl CanonicalDecode for FirstFrameWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let sequence_number = decoder.u64()?;
        let pts_ns = TimestampNs::decode_canonical(decoder)?;
        let frame_bytes = decoder.u64()?;
        let decode_state = match decoder.u8()? {
            1 => DecodeState::NotAttempted,
            2 => DecodeState::Verified,
            3 => DecodeState::ConcealedErrors,
            4 => DecodeState::Failed,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let source_custody = decode_source_custody(decoder)?;
        let explicit_omission = decode_explicit_omission(decoder)?;
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            sequence_number,
            pts_ns,
            frame_bytes,
            decode_state,
            source_custody,
            explicit_omission,
        })
    }
}

/// Witness proving continuous unbroken frame and packet reception across a sequence window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityWitness {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Evidence source ID.
    pub source_id: SourceId,
    /// Sequence number at start of continuity window.
    pub window_start_seq: u64,
    /// Sequence number at end of continuity window.
    pub window_end_seq: u64,
    /// Presentation timestamp at window start.
    pub window_start_pts_ns: TimestampNs,
    /// Presentation timestamp at window end.
    pub window_end_pts_ns: TimestampNs,
    /// Exact count of observed frames in this window.
    pub frames_observed: u64,
    /// Sequence discontinuities detected (must be 0 for verified continuity).
    pub discontinuities: u32,
    /// Dropped packets detected (must be 0 for verified continuity).
    pub packet_loss: u32,
    /// Measured jitter in nanoseconds across window.
    pub observed_jitter_ns: u64,
    /// Maximum allowed jitter threshold in nanoseconds.
    pub max_jitter_threshold_ns: u64,
    /// Proof of observation coverage across domain.
    pub coverage_witness: CoverageWitness,
}

impl ContinuityWitness {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_CONTINUITY;

    /// Computes the domain-separated canonical digest of this continuity witness.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies continuity criteria.
    pub fn verify(
        &self,
        expected_source_id: &SourceId,
        expected_device_id: &DeviceId,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "continuity witness adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "continuity witness device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "continuity witness source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "continuity witness adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "continuity witness device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "continuity witness source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.window_end_seq < self.window_start_seq {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!(
                    "window end seq {} < start seq {}",
                    self.window_end_seq, self.window_start_seq
                ),
            });
        }
        let expected_frames = self
            .window_end_seq
            .saturating_sub(self.window_start_seq)
            .saturating_add(1);
        if self.frames_observed != expected_frames {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!(
                    "frame count mismatch: expected {expected_frames}, got {}",
                    self.frames_observed
                ),
            });
        }
        if self.frames_observed < 2 {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!(
                    "continuity requires multi-frame window (frames_observed >= 2), got {}",
                    self.frames_observed
                ),
            });
        }
        if self.discontinuities > 0 {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!("discontinuities {} > 0", self.discontinuities),
            });
        }
        if self.packet_loss > 0 {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!("packet loss {} > 0", self.packet_loss),
            });
        }
        if self.observed_jitter_ns > self.max_jitter_threshold_ns {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: format!(
                    "observed jitter {}ns > max threshold {}ns",
                    self.observed_jitter_ns, self.max_jitter_threshold_ns
                ),
            });
        }
        if self.window_end_pts_ns < self.window_start_pts_ns {
            return Err(AcquisitionError::ContinuityGapDetected {
                detail: "window end pts precedes start pts".to_string(),
            });
        }
        if self.coverage_witness.continuity != CoverageContinuity::Continuous {
            return Err(AcquisitionError::InvalidCoverageWitness {
                detail: format!(
                    "coverage witness continuity is '{:?}', must be Continuous",
                    self.coverage_witness.continuity
                ),
            });
        }
        if !self
            .coverage_witness
            .authorized_domain
            .contains(self.source_id.as_str())
        {
            return Err(AcquisitionError::InvalidCoverageWitness {
                detail: format!(
                    "coverage witness authorized_domain does not contain source_id '{}'",
                    self.source_id
                ),
            });
        }
        if !self
            .coverage_witness
            .observed_domain
            .contains(self.source_id.as_str())
        {
            return Err(AcquisitionError::InvalidCoverageWitness {
                detail: format!(
                    "coverage witness observed_domain does not contain source_id '{}'",
                    self.source_id
                ),
            });
        }
        if self.coverage_witness.completeness != Completeness::Complete {
            return Err(AcquisitionError::InvalidCoverageWitness {
                detail: format!(
                    "coverage witness completeness is '{:?}', must be Complete",
                    self.coverage_witness.completeness
                ),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for ContinuityWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        encoder.u64(self.window_start_seq);
        encoder.u64(self.window_end_seq);
        self.window_start_pts_ns.encode_canonical(encoder);
        self.window_end_pts_ns.encode_canonical(encoder);
        encoder.u64(self.frames_observed);
        encoder.u32(self.discontinuities);
        encoder.u32(self.packet_loss);
        encoder.u64(self.observed_jitter_ns);
        encoder.u64(self.max_jitter_threshold_ns);
        self.coverage_witness.encode_canonical(encoder);
    }
}

impl CanonicalDecode for ContinuityWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let window_start_seq = decoder.u64()?;
        let window_end_seq = decoder.u64()?;
        let window_start_pts_ns = TimestampNs::decode_canonical(decoder)?;
        let window_end_pts_ns = TimestampNs::decode_canonical(decoder)?;
        let frames_observed = decoder.u64()?;
        let discontinuities = decoder.u32()?;
        let packet_loss = decoder.u32()?;
        let observed_jitter_ns = decoder.u64()?;
        let max_jitter_threshold_ns = decoder.u64()?;
        let coverage_witness = decode_coverage_witness(decoder)?;
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            window_start_seq,
            window_end_seq,
            window_start_pts_ns,
            window_end_pts_ns,
            frames_observed,
            discontinuities,
            packet_loss,
            observed_jitter_ns,
            max_jitter_threshold_ns,
            coverage_witness,
        })
    }
}

/// Evidence documenting stream degradation, naming lost dimensions and invalidated claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradationEvidence {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Evidence source ID.
    pub source_id: SourceId,
    /// Timestamp when degradation was observed.
    pub degraded_at_ns: TimestampNs,
    /// Explicit list of lost or degraded dimensions (e.g. "packet_loss", "timing_jitter").
    pub lost_dimensions: Vec<String>,
    /// Negative absence claims invalidated by this degradation.
    pub invalidated_negative_claims: Vec<String>,
    /// Observed packet loss count.
    pub observed_packet_loss: u32,
    /// Measured jitter in nanoseconds exceeding threshold.
    pub observed_jitter_ns: u64,
}

impl DegradationEvidence {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_DEGRADATION;

    /// Computes the domain-separated canonical digest of this degradation evidence.
    #[must_use]
    pub fn evidence_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies degradation evidence invariants.
    pub fn verify(
        &self,
        expected_source_id: &SourceId,
        expected_device_id: &DeviceId,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "degradation adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "degradation device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "degradation source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "degradation adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "degradation device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "degradation source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.lost_dimensions.is_empty() {
            return Err(AcquisitionError::MissingWitness {
                state: AcquisitionStateKind::Degraded,
                witness_type: "lost_dimensions must not be empty",
            });
        }
        if self.lost_dimensions.len() > MAX_LOST_DIMENSIONS {
            return Err(AcquisitionError::BoundsViolation {
                field: "lost_dimensions",
                max: MAX_LOST_DIMENSIONS,
                actual: self.lost_dimensions.len(),
            });
        }
        for dim in &self.lost_dimensions {
            if dim.is_empty() || dim.len() > MAX_DIMENSION_NAME_LEN {
                return Err(AcquisitionError::BoundsViolation {
                    field: "dimension_name",
                    max: MAX_DIMENSION_NAME_LEN,
                    actual: dim.len(),
                });
            }
        }
        if self.invalidated_negative_claims.len() > MAX_INVALIDATED_CLAIMS {
            return Err(AcquisitionError::BoundsViolation {
                field: "invalidated_negative_claims",
                max: MAX_INVALIDATED_CLAIMS,
                actual: self.invalidated_negative_claims.len(),
            });
        }
        for claim in &self.invalidated_negative_claims {
            if claim.is_empty() || claim.len() > MAX_CLAIM_NAME_LEN {
                return Err(AcquisitionError::BoundsViolation {
                    field: "claim_name",
                    max: MAX_CLAIM_NAME_LEN,
                    actual: claim.len(),
                });
            }
        }
        Ok(())
    }
}

impl CanonicalEncode for DegradationEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        self.degraded_at_ns.encode_canonical(encoder);
        encoder.u32(self.lost_dimensions.len() as u32);
        for dim in &self.lost_dimensions {
            encoder.text(dim);
        }
        encoder.u32(self.invalidated_negative_claims.len() as u32);
        for claim in &self.invalidated_negative_claims {
            encoder.text(claim);
        }
        encoder.u32(self.observed_packet_loss);
        encoder.u64(self.observed_jitter_ns);
    }
}

impl CanonicalDecode for DegradationEvidence {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let degraded_at_ns = TimestampNs::decode_canonical(decoder)?;
        let dim_count = decoder.u32()? as usize;
        if dim_count > MAX_LOST_DIMENSIONS {
            return Err(ContractError::NonCanonicalOrdering);
        }
        let mut lost_dimensions = Vec::with_capacity(dim_count);
        for _ in 0..dim_count {
            lost_dimensions.push(decoder.text()?.to_string());
        }
        let claim_count = decoder.u32()? as usize;
        if claim_count > MAX_INVALIDATED_CLAIMS {
            return Err(ContractError::NonCanonicalOrdering);
        }
        let mut invalidated_negative_claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            invalidated_negative_claims.push(decoder.text()?.to_string());
        }
        let observed_packet_loss = decoder.u32()?;
        let observed_jitter_ns = decoder.u64()?;
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            degraded_at_ns,
            lost_dimensions,
            invalidated_negative_claims,
            observed_packet_loss,
            observed_jitter_ns,
        })
    }
}

/// Witness proving terminal failure of the acquisition session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureWitness {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Evidence source ID.
    pub source_id: SourceId,
    /// Timestamp of failure.
    pub failed_at_ns: TimestampNs,
    /// Machine-readable error code.
    pub error_code: String,
    /// Explanatory diagnostic message.
    pub error_message: String,
    /// Whether the failure condition is classified as retryable.
    pub retryable: bool,
}

impl FailureWitness {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_FAILURE;

    /// Computes the domain-separated canonical digest of this failure witness.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies failure witness invariants.
    pub fn verify(
        &self,
        expected_source_id: &SourceId,
        expected_device_id: &DeviceId,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "failure witness adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "failure witness device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "failure witness source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "failure witness adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "failure witness device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "failure witness source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.error_code.is_empty() || self.error_code.len() > MAX_ERROR_CODE_LEN {
            return Err(AcquisitionError::BoundsViolation {
                field: "error_code",
                max: MAX_ERROR_CODE_LEN,
                actual: self.error_code.len(),
            });
        }
        if self.error_message.is_empty() || self.error_message.len() > MAX_ERROR_MSG_LEN {
            return Err(AcquisitionError::BoundsViolation {
                field: "error_message",
                max: MAX_ERROR_MSG_LEN,
                actual: self.error_message.len(),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for FailureWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        self.failed_at_ns.encode_canonical(encoder);
        encoder.text(&self.error_code);
        encoder.text(&self.error_message);
        encoder.bool(self.retryable);
    }
}

impl CanonicalDecode for FailureWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let failed_at_ns = TimestampNs::decode_canonical(decoder)?;
        let error_code = decoder.text()?.to_string();
        let error_message = decoder.text()?.to_string();
        let retryable = decoder.bool()?;
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            failed_at_ns,
            error_code,
            error_message,
            retryable,
        })
    }
}

/// Quiescence receipt proving clean teardown, drained buffers, and zero remaining tasks/descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuiescenceReceipt {
    /// Adapter performing clean cancellation.
    pub adapter_id: AdapterId,
    /// Device being cancelled.
    pub device_id: DeviceId,
    /// Source being cancelled.
    pub source_id: SourceId,
    /// Timestamp when quiescence was verified.
    pub cancelled_at_ns: TimestampNs,
    /// Active asynchronous tasks remaining (must be 0).
    pub active_tasks: u32,
    /// Open file/device descriptors remaining (must be 0).
    pub open_descriptors: u32,
    /// Whether capture ring buffers have been drained.
    pub buffers_drained: bool,
}

impl QuiescenceReceipt {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_QUIESCENCE;

    /// Computes the domain-separated canonical digest of this quiescence receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies quiescence receipt invariants.
    pub fn verify(
        &self,
        expected_adapter_id: &AdapterId,
        expected_device_id: &DeviceId,
        expected_source_id: &SourceId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "quiescence receipt adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "quiescence receipt device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "quiescence receipt source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "quiescence receipt adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "quiescence receipt device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "quiescence receipt source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.active_tasks != 0 || self.open_descriptors != 0 || !self.buffers_drained {
            return Err(AcquisitionError::QuiescenceViolation {
                active_tasks: self.active_tasks,
                open_descriptors: self.open_descriptors,
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for QuiescenceReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        self.cancelled_at_ns.encode_canonical(encoder);
        encoder.u32(self.active_tasks);
        encoder.u32(self.open_descriptors);
        encoder.bool(self.buffers_drained);
    }
}

impl CanonicalDecode for QuiescenceReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let cancelled_at_ns = TimestampNs::decode_canonical(decoder)?;
        let active_tasks = decoder.u32()?;
        let open_descriptors = decoder.u32()?;
        let buffers_drained = decoder.bool()?;
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            cancelled_at_ns,
            active_tasks,
            open_descriptors,
            buffers_drained,
        })
    }
}

/// Witness recording entry into indeterminate state requiring explicit reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateWitness {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Evidence source ID.
    pub source_id: SourceId,
    /// Timestamp when state became indeterminate.
    pub indeterminate_at_ns: TimestampNs,
    /// Reason or classification of indeterminacy.
    pub reason: String,
    /// Specific outstanding obligations requiring reconciliation.
    pub unresolved_obligations: Vec<String>,
}

impl IndeterminateWitness {
    /// Canonical schema constant.
    pub const SCHEMA: &'static str = SCHEMA_INDETERMINATE;

    /// Computes the domain-separated canonical digest of this indeterminate witness.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Verifies indeterminate witness invariants.
    pub fn verify(
        &self,
        expected_source_id: &SourceId,
        expected_device_id: &DeviceId,
        expected_adapter_id: &AdapterId,
    ) -> Result<(), AcquisitionError> {
        if !self.adapter_id.as_str().starts_with(AdapterId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "indeterminate witness adapter_id '{}' does not use canonical prefix '{}'",
                    self.adapter_id,
                    AdapterId::PREFIX
                ),
            });
        }
        if !self.device_id.as_str().starts_with(DeviceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "indeterminate witness device_id '{}' does not use canonical prefix '{}'",
                    self.device_id,
                    DeviceId::PREFIX
                ),
            });
        }
        if !self.source_id.as_str().starts_with(SourceId::PREFIX) {
            return Err(AcquisitionError::NonCanonicalEncoding {
                detail: format!(
                    "indeterminate witness source_id '{}' does not use canonical prefix '{}'",
                    self.source_id,
                    SourceId::PREFIX
                ),
            });
        }
        if self.adapter_id != *expected_adapter_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "indeterminate witness adapter_id '{}' != expected '{}'",
                    self.adapter_id, expected_adapter_id
                ),
            });
        }
        if self.device_id != *expected_device_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "indeterminate witness device_id '{}' != expected '{}'",
                    self.device_id, expected_device_id
                ),
            });
        }
        if self.source_id != *expected_source_id {
            return Err(AcquisitionError::WitnessMismatch {
                detail: format!(
                    "indeterminate witness source_id '{}' != expected '{}'",
                    self.source_id, expected_source_id
                ),
            });
        }
        if self.reason.is_empty() || self.reason.len() > MAX_REASON_LEN {
            return Err(AcquisitionError::BoundsViolation {
                field: "reason",
                max: MAX_REASON_LEN,
                actual: self.reason.len(),
            });
        }
        if self.unresolved_obligations.len() > MAX_OBLIGATIONS {
            return Err(AcquisitionError::BoundsViolation {
                field: "unresolved_obligations",
                max: MAX_OBLIGATIONS,
                actual: self.unresolved_obligations.len(),
            });
        }
        for obl in &self.unresolved_obligations {
            if obl.is_empty() || obl.len() > MAX_OBLIGATION_NAME_LEN {
                return Err(AcquisitionError::BoundsViolation {
                    field: "obligation_name",
                    max: MAX_OBLIGATION_NAME_LEN,
                    actual: obl.len(),
                });
            }
        }
        Ok(())
    }
}

impl CanonicalEncode for IndeterminateWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        self.indeterminate_at_ns.encode_canonical(encoder);
        encoder.text(&self.reason);
        encoder.u32(self.unresolved_obligations.len() as u32);
        for obl in &self.unresolved_obligations {
            encoder.text(obl);
        }
    }
}

impl CanonicalDecode for IndeterminateWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let source_id = decode_canonical_source_id(decoder)?;
        let indeterminate_at_ns = TimestampNs::decode_canonical(decoder)?;
        let reason = decoder.text()?.to_string();
        let obl_count = decoder.u32()? as usize;
        if obl_count > MAX_OBLIGATIONS {
            return Err(ContractError::NonCanonicalOrdering);
        }
        let mut unresolved_obligations = Vec::with_capacity(obl_count);
        for _ in 0..obl_count {
            unresolved_obligations.push(decoder.text()?.to_string());
        }
        Ok(Self {
            adapter_id,
            device_id,
            source_id,
            indeterminate_at_ns,
            reason,
            unresolved_obligations,
        })
    }
}

/// Audit record of an executed lifecycle state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionTransitionRecord {
    /// Adapter ID.
    pub adapter_id: AdapterId,
    /// Device ID.
    pub device_id: DeviceId,
    /// Origin state.
    pub from: AcquisitionStateKind,
    /// Destination state.
    pub to: AcquisitionStateKind,
    /// Timestamp when transition occurred.
    pub timestamp_ns: TimestampNs,
    /// Canonical digest of the witness that justified this transition.
    pub witness_digest: ContentDigest,
    /// Diagnostic note explaining transition context.
    pub note: String,
}

impl CanonicalEncode for AcquisitionTransitionRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(SCHEMA_TRANSITION_RECORD);
        self.adapter_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.from.encode_canonical(encoder);
        self.to.encode_canonical(encoder);
        self.timestamp_ns.encode_canonical(encoder);
        encoder.digest(self.witness_digest);
        encoder.text(&self.note);
    }
}

impl CanonicalDecode for AcquisitionTransitionRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != SCHEMA_TRANSITION_RECORD {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = decode_canonical_adapter_id(decoder)?;
        let device_id = decode_canonical_device_id(decoder)?;
        let from = AcquisitionStateKind::decode_canonical(decoder)?;
        let to = AcquisitionStateKind::decode_canonical(decoder)?;
        let timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let witness_digest = decoder.digest()?;
        let note = decoder.text()?.to_string();
        Ok(Self {
            adapter_id,
            device_id,
            from,
            to,
            timestamp_ns,
            witness_digest,
            note,
        })
    }
}

/// Full lifecycle state carrying all accumulated witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionState {
    /// Initial request submitted.
    Requested(Box<AcquisitionRequest>),
    /// Authentication verified.
    Authenticated {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Secret-free auth receipt.
        auth: AuthReceipt,
    },
    /// Adapter acknowledged session.
    AdapterAccepted {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Auth receipt.
        auth: AuthReceipt,
        /// Adapter ACK.
        ack: AdapterAck,
    },
    /// First frame observed.
    FirstFrameObserved {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Auth receipt.
        auth: AuthReceipt,
        /// Adapter ACK.
        ack: AdapterAck,
        /// First frame witness.
        first_frame: Box<FirstFrameWitness>,
    },
    /// Continuity verified.
    ContinuityVerified {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Auth receipt.
        auth: AuthReceipt,
        /// Adapter ACK.
        ack: AdapterAck,
        /// First frame witness.
        first_frame: Box<FirstFrameWitness>,
        /// Continuity witness.
        continuity: Box<ContinuityWitness>,
    },
    /// Stream active but degraded.
    Degraded {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Auth receipt.
        auth: AuthReceipt,
        /// Adapter ACK.
        ack: AdapterAck,
        /// First frame witness if observed prior to degradation.
        first_frame: Option<Box<FirstFrameWitness>>,
        /// Last continuity witness if observed prior to degradation.
        last_continuity: Option<Box<ContinuityWitness>>,
        /// Degradation evidence.
        degradation: Box<DegradationEvidence>,
    },
    /// Terminal failure.
    Failed {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Failure witness.
        failure: FailureWitness,
        /// Prior state kind before failure.
        prior_state: AcquisitionStateKind,
    },
    /// Clean cancellation with verified quiescence.
    Cancelled {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Quiescence receipt.
        quiescence: QuiescenceReceipt,
        /// Prior state kind before cancellation.
        prior_state: AcquisitionStateKind,
    },
    /// Indeterminate state requiring explicit reconciliation.
    Indeterminate {
        /// Base request.
        request: Box<AcquisitionRequest>,
        /// Indeterminate witness.
        witness: Box<IndeterminateWitness>,
        /// Prior state before becoming indeterminate.
        prior_state: Box<AcquisitionState>,
    },
}

impl AcquisitionState {
    /// Returns the kind of this state.
    #[must_use]
    pub const fn kind(&self) -> AcquisitionStateKind {
        match self {
            Self::Requested(_) => AcquisitionStateKind::Requested,
            Self::Authenticated { .. } => AcquisitionStateKind::Authenticated,
            Self::AdapterAccepted { .. } => AcquisitionStateKind::AdapterAccepted,
            Self::FirstFrameObserved { .. } => AcquisitionStateKind::FirstFrameObserved,
            Self::ContinuityVerified { .. } => AcquisitionStateKind::ContinuityVerified,
            Self::Degraded { .. } => AcquisitionStateKind::Degraded,
            Self::Failed { .. } => AcquisitionStateKind::Failed,
            Self::Cancelled { .. } => AcquisitionStateKind::Cancelled,
            Self::Indeterminate { .. } => AcquisitionStateKind::Indeterminate,
        }
    }

    /// Returns a reference to the session's base acquisition request.
    #[must_use]
    pub fn request(&self) -> &AcquisitionRequest {
        match self {
            Self::Requested(req) => req,
            Self::Authenticated { request, .. }
            | Self::AdapterAccepted { request, .. }
            | Self::FirstFrameObserved { request, .. }
            | Self::ContinuityVerified { request, .. }
            | Self::Degraded { request, .. }
            | Self::Failed { request, .. }
            | Self::Cancelled { request, .. }
            | Self::Indeterminate { request, .. } => request,
        }
    }

    /// Returns true if this state is terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.kind().is_terminal()
    }

    /// Returns true if this state is actively streaming.
    ///
    /// Non-negotiable: Returns `true` ONLY for [`Self::ContinuityVerified`].
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        self.kind().is_streaming()
    }

    /// Returns true if continuity is certified.
    #[must_use]
    pub const fn has_continuity(&self) -> bool {
        self.kind().has_continuity()
    }
}

/// Lifecycle session manager tracking active state, witnesses, and transition audit trail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionSession {
    state: AcquisitionState,
    history: Vec<AcquisitionTransitionRecord>,
}

impl AcquisitionSession {
    /// Creates a new acquisition session in the [`AcquisitionStateKind::Requested`] state.
    pub fn new(request: AcquisitionRequest) -> Result<Self, AcquisitionError> {
        request.verify()?;
        let initial_record = AcquisitionTransitionRecord {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            from: AcquisitionStateKind::Requested,
            to: AcquisitionStateKind::Requested,
            timestamp_ns: request.requested_at_ns,
            witness_digest: request.request_digest(),
            note: "session requested".to_string(),
        };
        Ok(Self {
            state: AcquisitionState::Requested(Box::new(request)),
            history: vec![initial_record],
        })
    }

    /// Returns the current acquisition state.
    #[must_use]
    pub const fn state(&self) -> &AcquisitionState {
        &self.state
    }

    /// Returns the current state kind.
    #[must_use]
    pub const fn state_kind(&self) -> AcquisitionStateKind {
        self.state.kind()
    }

    /// Returns the base acquisition request.
    #[must_use]
    pub fn request(&self) -> &AcquisitionRequest {
        self.state.request()
    }

    /// Returns the recorded transition history.
    #[must_use]
    pub fn history(&self) -> &[AcquisitionTransitionRecord] {
        &self.history
    }

    /// Returns true if the session is currently in verified continuous streaming.
    ///
    /// Returns true ONLY in [`AcquisitionStateKind::ContinuityVerified`].
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        self.state.is_streaming()
    }

    /// Returns true if continuity is verified.
    #[must_use]
    pub const fn has_continuity(&self) -> bool {
        self.state.has_continuity()
    }

    /// Verifies whether coverage-dependent consumers may claim negative absence.
    ///
    /// Fails closed with [`AcquisitionError::AbsenceClaimForbidden`] if not in
    /// [`AcquisitionStateKind::ContinuityVerified`], or [`AcquisitionError::InvalidCoverageWitness`]
    /// if the coverage witness does not certify absence.
    pub fn check_absence_claim_allowed(&self) -> Result<&CoverageWitness, AcquisitionError> {
        match &self.state {
            AcquisitionState::ContinuityVerified { continuity, .. } => {
                if !continuity.coverage_witness.certifies_absence() {
                    return Err(AcquisitionError::InvalidCoverageWitness {
                        detail: "coverage witness does not certify absence across declared domain"
                            .to_string(),
                    });
                }
                Ok(&continuity.coverage_witness)
            }
            other => Err(AcquisitionError::AbsenceClaimForbidden {
                state: other.kind(),
                detail: "absence claims require verified continuity (ContinuityVerified)",
            }),
        }
    }

    fn record_transition(
        &mut self,
        from: AcquisitionStateKind,
        to: AcquisitionStateKind,
        timestamp_ns: TimestampNs,
        witness_digest: ContentDigest,
        note: &str,
    ) {
        if self.history.len() >= MAX_HISTORY_LEN {
            self.history.remove(0);
        }
        let mut end = note.len().min(MAX_NOTE_LEN);
        while end > 0 && !note.is_char_boundary(end) {
            end -= 1;
        }
        let bounded_note = note[..end].to_string();
        let adapter_id = self.request().adapter_identity.adapter_id.clone();
        let device_id = self.request().device_identity.device_id.clone();
        self.history.push(AcquisitionTransitionRecord {
            adapter_id,
            device_id,
            from,
            to,
            timestamp_ns,
            witness_digest,
            note: bounded_note,
        });
    }

    /// Transitions from [`AcquisitionStateKind::Requested`] to [`AcquisitionStateKind::Authenticated`].
    pub fn authenticate(
        &mut self,
        auth: AuthReceipt,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::Authenticated) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::Authenticated,
            });
        }
        let req = self.request().clone();
        auth.verify(
            &req.adapter_identity.adapter_id,
            &req.device_identity.device_id,
            req.requested_capabilities,
            now_ns,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Authenticated,
            now_ns,
            auth.receipt_digest(),
            "authentication verified",
        );
        self.state = AcquisitionState::Authenticated {
            request: Box::new(req),
            auth,
        };
        Ok(())
    }

    /// Transitions from [`AcquisitionStateKind::Authenticated`] to [`AcquisitionStateKind::AdapterAccepted`].
    pub fn accept(&mut self, ack: AdapterAck, now_ns: TimestampNs) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::AdapterAccepted) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::AdapterAccepted,
            });
        }
        let (request, auth) = match &self.state {
            AcquisitionState::Authenticated { request, auth } => (request.clone(), auth.clone()),
            _ => {
                return Err(AcquisitionError::IllegalTransition {
                    from: from_kind,
                    to: AcquisitionStateKind::AdapterAccepted,
                });
            }
        };
        ack.verify(
            &request.request_digest(),
            &request.adapter_identity.adapter_id,
        )?;
        if request.is_dji_flip()
            && request
                .requested_capabilities
                .contains(AdapterCapabilities::STREAMING)
        {
            return Err(AcquisitionError::UnsupportedLiveRoute {
                constraint_id: CONSTRAINT_NEG_001,
                detail: "DJI Flip live streaming adapter acceptance is prohibited by NEG-001; manual capture/import only".to_string(),
            });
        }
        self.record_transition(
            from_kind,
            AcquisitionStateKind::AdapterAccepted,
            now_ns,
            ack.ack_digest(),
            "adapter accepted acquisition request",
        );
        self.state = AcquisitionState::AdapterAccepted { request, auth, ack };
        Ok(())
    }

    /// Transitions from [`AcquisitionStateKind::AdapterAccepted`] to [`AcquisitionStateKind::FirstFrameObserved`].
    pub fn observe_first_frame(
        &mut self,
        witness: FirstFrameWitness,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::FirstFrameObserved) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::FirstFrameObserved,
            });
        }
        let (request, auth, ack) = match &self.state {
            AcquisitionState::AdapterAccepted { request, auth, ack } => {
                (request.clone(), auth.clone(), ack.clone())
            }
            _ => {
                return Err(AcquisitionError::IllegalTransition {
                    from: from_kind,
                    to: AcquisitionStateKind::FirstFrameObserved,
                });
            }
        };
        witness.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::FirstFrameObserved,
            now_ns,
            witness.witness_digest(),
            "first decodable frame observed",
        );
        self.state = AcquisitionState::FirstFrameObserved {
            request,
            auth,
            ack,
            first_frame: Box::new(witness),
        };
        Ok(())
    }

    /// Transitions to [`AcquisitionStateKind::ContinuityVerified`] from FirstFrameObserved, Degraded, or ContinuityVerified.
    pub fn verify_continuity(
        &mut self,
        witness: ContinuityWitness,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::ContinuityVerified) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::ContinuityVerified,
            });
        }
        let (request, auth, ack, first_frame, prior_continuity) = match &self.state {
            AcquisitionState::FirstFrameObserved {
                request,
                auth,
                ack,
                first_frame,
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                first_frame.clone(),
                None,
            ),
            AcquisitionState::ContinuityVerified {
                request,
                auth,
                ack,
                first_frame,
                continuity,
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                first_frame.clone(),
                Some(continuity.clone()),
            ),
            AcquisitionState::Degraded {
                request,
                auth,
                ack,
                first_frame: Some(ff),
                last_continuity,
                ..
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                ff.clone(),
                last_continuity.clone(),
            ),
            AcquisitionState::Degraded {
                first_frame: None, ..
            } => {
                return Err(AcquisitionError::MissingWitness {
                    state: AcquisitionStateKind::ContinuityVerified,
                    witness_type: "FirstFrameWitness required before continuity",
                });
            }
            AcquisitionState::Indeterminate {
                request,
                prior_state,
                ..
            } => match prior_state.as_ref() {
                AcquisitionState::FirstFrameObserved {
                    auth,
                    ack,
                    first_frame,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    first_frame.clone(),
                    None,
                ),
                AcquisitionState::ContinuityVerified {
                    auth,
                    ack,
                    first_frame,
                    continuity,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    first_frame.clone(),
                    Some(continuity.clone()),
                ),
                AcquisitionState::Degraded {
                    auth,
                    ack,
                    first_frame: Some(ff),
                    last_continuity,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    ff.clone(),
                    last_continuity.clone(),
                ),
                _ => {
                    return Err(AcquisitionError::MissingWitness {
                        state: AcquisitionStateKind::ContinuityVerified,
                        witness_type: "FirstFrameWitness required before continuity",
                    });
                }
            },
            _ => {
                return Err(AcquisitionError::IllegalTransition {
                    from: from_kind,
                    to: AcquisitionStateKind::ContinuityVerified,
                });
            }
        };

        if let Some(prior) = &prior_continuity {
            let expected_next = prior.window_end_seq.saturating_add(1);
            if witness.window_start_seq != expected_next {
                return Err(AcquisitionError::ContinuityGapDetected {
                    detail: format!(
                        "sequence gap detected: prior window ended at {}, next window started at {}",
                        prior.window_end_seq, witness.window_start_seq
                    ),
                });
            }
        } else {
            let ff_seq = first_frame.sequence_number;
            if witness.window_start_seq != ff_seq
                && witness.window_start_seq != ff_seq.saturating_add(1)
            {
                return Err(AcquisitionError::ContinuityGapDetected {
                    detail: format!(
                        "sequence jump detected: first frame seq {}, continuity start seq {}",
                        ff_seq, witness.window_start_seq
                    ),
                });
            }
        }

        witness.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::ContinuityVerified,
            now_ns,
            witness.witness_digest(),
            "stream continuity verified",
        );
        self.state = AcquisitionState::ContinuityVerified {
            request,
            auth,
            ack,
            first_frame,
            continuity: Box::new(witness),
        };
        Ok(())
    }

    /// Transitions to [`AcquisitionStateKind::Degraded`].
    pub fn degrade(
        &mut self,
        evidence: DegradationEvidence,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::Degraded) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::Degraded,
            });
        }
        let (request, auth, ack, first_frame, last_continuity) = match &self.state {
            AcquisitionState::AdapterAccepted { request, auth, ack } => {
                (request.clone(), auth.clone(), ack.clone(), None, None)
            }
            AcquisitionState::FirstFrameObserved {
                request,
                auth,
                ack,
                first_frame,
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                Some(first_frame.clone()),
                None,
            ),
            AcquisitionState::ContinuityVerified {
                request,
                auth,
                ack,
                first_frame,
                continuity,
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                Some(first_frame.clone()),
                Some(continuity.clone()),
            ),
            AcquisitionState::Degraded {
                request,
                auth,
                ack,
                first_frame,
                last_continuity,
                ..
            } => (
                request.clone(),
                auth.clone(),
                ack.clone(),
                first_frame.clone(),
                last_continuity.clone(),
            ),
            AcquisitionState::Indeterminate {
                request,
                prior_state,
                ..
            } => match prior_state.as_ref() {
                AcquisitionState::AdapterAccepted { auth, ack, .. } => {
                    (request.clone(), auth.clone(), ack.clone(), None, None)
                }
                AcquisitionState::FirstFrameObserved {
                    auth,
                    ack,
                    first_frame,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    Some(first_frame.clone()),
                    None,
                ),
                AcquisitionState::ContinuityVerified {
                    auth,
                    ack,
                    first_frame,
                    continuity,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    Some(first_frame.clone()),
                    Some(continuity.clone()),
                ),
                AcquisitionState::Degraded {
                    auth,
                    ack,
                    first_frame,
                    last_continuity,
                    ..
                } => (
                    request.clone(),
                    auth.clone(),
                    ack.clone(),
                    first_frame.clone(),
                    last_continuity.clone(),
                ),
                _ => {
                    return Err(AcquisitionError::IllegalTransition {
                        from: from_kind,
                        to: AcquisitionStateKind::Degraded,
                    });
                }
            },
            _ => {
                return Err(AcquisitionError::IllegalTransition {
                    from: from_kind,
                    to: AcquisitionStateKind::Degraded,
                });
            }
        };
        evidence.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Degraded,
            now_ns,
            evidence.evidence_digest(),
            "stream entered degraded mode",
        );
        self.state = AcquisitionState::Degraded {
            request,
            auth,
            ack,
            first_frame,
            last_continuity,
            degradation: Box::new(evidence),
        };
        Ok(())
    }

    /// Transitions to terminal [`AcquisitionStateKind::Failed`].
    pub fn fail(
        &mut self,
        failure: FailureWitness,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::Failed) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::Failed,
            });
        }
        let request = self.request().clone();
        failure.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Failed,
            now_ns,
            failure.witness_digest(),
            "acquisition failed",
        );
        self.state = AcquisitionState::Failed {
            request: Box::new(request),
            failure,
            prior_state: from_kind,
        };
        Ok(())
    }

    /// Transitions to terminal [`AcquisitionStateKind::Cancelled`] upon verified quiescence.
    pub fn cancel(
        &mut self,
        quiescence: QuiescenceReceipt,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::Cancelled) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::Cancelled,
            });
        }
        let request = self.request().clone();
        quiescence.verify(
            &request.adapter_identity.adapter_id,
            &request.device_identity.device_id,
            &request.source_identity.source_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Cancelled,
            now_ns,
            quiescence.receipt_digest(),
            "acquisition cleanly cancelled with quiescence",
        );
        self.state = AcquisitionState::Cancelled {
            request: Box::new(request),
            quiescence,
            prior_state: from_kind,
        };
        Ok(())
    }

    /// Transitions to [`AcquisitionStateKind::Indeterminate`].
    pub fn mark_indeterminate(
        &mut self,
        witness: IndeterminateWitness,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let from_kind = self.state_kind();
        if !is_allowed_transition(from_kind, AcquisitionStateKind::Indeterminate) {
            return Err(AcquisitionError::IllegalTransition {
                from: from_kind,
                to: AcquisitionStateKind::Indeterminate,
            });
        }
        let request = self.request().clone();
        witness.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )?;
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Indeterminate,
            now_ns,
            witness.witness_digest(),
            "acquisition state became indeterminate",
        );
        let prior_state = Box::new(self.state.clone());
        self.state = AcquisitionState::Indeterminate {
            request: Box::new(request),
            witness: Box::new(witness),
            prior_state,
        };
        Ok(())
    }

    /// Reconciles an [`AcquisitionStateKind::Indeterminate`] state into a resolved state.
    pub fn reconcile(
        &mut self,
        resolved_state: AcquisitionState,
        note: &str,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        if self.state_kind() != AcquisitionStateKind::Indeterminate {
            return Err(AcquisitionError::IllegalTransition {
                from: self.state_kind(),
                to: resolved_state.kind(),
            });
        }
        let target_kind = resolved_state.kind();
        if target_kind == AcquisitionStateKind::Indeterminate {
            return Err(AcquisitionError::IndeterminateStateUnresolved {
                detail: "cannot reconcile indeterminate state back into indeterminate".to_string(),
            });
        }
        if !is_allowed_transition(AcquisitionStateKind::Indeterminate, target_kind) {
            return Err(AcquisitionError::IllegalTransition {
                from: AcquisitionStateKind::Indeterminate,
                to: target_kind,
            });
        }
        if resolved_state.request().source_identity.source_id
            != self.request().source_identity.source_id
            || resolved_state.request().device_identity.device_id
                != self.request().device_identity.device_id
            || resolved_state.request().adapter_identity.adapter_id
                != self.request().adapter_identity.adapter_id
        {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "reconciled state identity mismatch".to_string(),
            });
        }

        let witness_digest = match &resolved_state {
            AcquisitionState::ContinuityVerified { continuity, .. } => {
                continuity.verify(
                    &self.request().source_identity.source_id,
                    &self.request().device_identity.device_id,
                    &self.request().adapter_identity.adapter_id,
                )?;
                continuity.witness_digest()
            }
            AcquisitionState::Degraded { degradation, .. } => {
                degradation.verify(
                    &self.request().source_identity.source_id,
                    &self.request().device_identity.device_id,
                    &self.request().adapter_identity.adapter_id,
                )?;
                degradation.evidence_digest()
            }
            AcquisitionState::Failed {
                failure,
                prior_state,
                ..
            } => {
                if *prior_state != AcquisitionStateKind::Indeterminate {
                    return Err(AcquisitionError::WitnessMismatch {
                        detail: "reconciled Failed state must have prior_state Indeterminate"
                            .to_string(),
                    });
                }
                failure.verify(
                    &self.request().source_identity.source_id,
                    &self.request().device_identity.device_id,
                    &self.request().adapter_identity.adapter_id,
                )?;
                failure.witness_digest()
            }
            AcquisitionState::Cancelled {
                quiescence,
                prior_state,
                ..
            } => {
                if *prior_state != AcquisitionStateKind::Indeterminate {
                    return Err(AcquisitionError::WitnessMismatch {
                        detail: "reconciled Cancelled state must have prior_state Indeterminate"
                            .to_string(),
                    });
                }
                quiescence.verify(
                    &self.request().adapter_identity.adapter_id,
                    &self.request().device_identity.device_id,
                    &self.request().source_identity.source_id,
                )?;
                quiescence.receipt_digest()
            }
            _ => {
                return Err(AcquisitionError::IllegalTransition {
                    from: AcquisitionStateKind::Indeterminate,
                    to: target_kind,
                });
            }
        };

        self.record_transition(
            AcquisitionStateKind::Indeterminate,
            target_kind,
            now_ns,
            witness_digest,
            note,
        );
        self.state = resolved_state;
        Ok(())
    }

    /// Checks if silence timeout has elapsed while waiting in [`AcquisitionStateKind::AdapterAccepted`].
    ///
    /// If `now_ns > deadline_ns`, transitions to [`AcquisitionStateKind::Failed`] with
    /// `accept_silence_timeout` and returns [`AcquisitionError::AcceptSilenceTimeout`].
    /// Does NOT infer success or advance to FirstFrameObserved.
    pub fn check_accept_silence(
        &mut self,
        deadline_ns: TimestampNs,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let deadline_u64 =
            u64::try_from(deadline_ns.0).map_err(|_| AcquisitionError::InvalidTimestamp {
                detail: format!(
                    "deadline timestamp {} is negative or exceeds u64 bounds",
                    deadline_ns.0
                ),
            })?;

        if self.state_kind() == AcquisitionStateKind::AdapterAccepted && now_ns > deadline_ns {
            let elapsed_i128 = now_ns.0.saturating_sub(deadline_ns.0);
            let elapsed_ns = u64::try_from(elapsed_i128).unwrap_or(u64::MAX);

            let failure = FailureWitness {
                adapter_id: self.request().adapter_identity.adapter_id.clone(),
                device_id: self.request().device_identity.device_id.clone(),
                source_id: self.request().source_identity.source_id.clone(),
                failed_at_ns: now_ns,
                error_code: "accept_silence_timeout".to_string(),
                error_message: format!(
                    "deadline expired waiting for first frame after adapter acceptance: elapsed {elapsed_ns}ns"
                ),
                retryable: true,
            };
            self.fail(failure, now_ns)?;
            return Err(AcquisitionError::AcceptSilenceTimeout {
                deadline_ns: deadline_u64,
                elapsed_ns,
            });
        }
        Ok(())
    }

    /// Reconnects the session with a new acquisition request.
    ///
    /// Strict invariant: `new_request.source_identity.stream_generation` MUST be strictly
    /// monotonically greater than the current stream generation. Attempting to reuse or decrement
    /// generation fails closed with [`AcquisitionError::GenerationConflict`].
    pub fn reconnect(
        &mut self,
        new_request: AcquisitionRequest,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let current_gen = &self.request().source_identity.stream_generation;
        let attempted_gen = &new_request.source_identity.stream_generation;

        if attempted_gen <= current_gen {
            return Err(AcquisitionError::GenerationConflict {
                current_generation: current_gen.clone(),
                attempted_generation: attempted_gen.clone(),
            });
        }

        new_request.verify()?;
        let from_kind = self.state_kind();
        let digest = new_request.request_digest();
        self.record_transition(
            from_kind,
            AcquisitionStateKind::Requested,
            now_ns,
            digest,
            "session reconnected with incremented stream generation",
        );
        self.state = AcquisitionState::Requested(Box::new(new_request));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical Encoding / Decoding Helpers for Nested Types
// ---------------------------------------------------------------------------

fn encode_source_custody(custody: &SourceCustody, encoder: &mut CanonicalEncoder) {
    match custody {
        SourceCustody::NotRetained => {
            encoder.u8(0);
        }
        SourceCustody::Retained {
            source_digest,
            source_bytes,
            storage_handle,
        } => {
            encoder.u8(1);
            encoder.digest(*source_digest);
            encoder.u64(*source_bytes);
            encoder.text(storage_handle);
        }
    }
}

fn decode_source_custody(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<SourceCustody, ContractError> {
    match decoder.u8()? {
        0 => Ok(SourceCustody::NotRetained),
        1 => {
            let source_digest = decoder.digest()?;
            let source_bytes = decoder.u64()?;
            let storage_handle = decoder.text()?.to_string();
            Ok(SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            })
        }
        _ => Err(ContractError::NonCanonicalOrdering),
    }
}

fn encode_explicit_omission(omission: &ExplicitOmission, encoder: &mut CanonicalEncoder) {
    match omission {
        ExplicitOmission::None => {
            encoder.u8(0);
        }
        ExplicitOmission::Omitted {
            reason,
            policy_rule,
            omitted_bytes,
            omitted_frames,
        } => {
            encoder.u8(1);
            encoder.u8(*reason as u8);
            encoder.text(policy_rule);
            encoder.u64(*omitted_bytes);
            encoder.u32(*omitted_frames);
        }
    }
}

fn decode_explicit_omission(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<ExplicitOmission, ContractError> {
    match decoder.u8()? {
        0 => Ok(ExplicitOmission::None),
        1 => {
            let reason_u8 = decoder.u8()?;
            let reason = match reason_u8 {
                0 => OmissionReason::None,
                1 => OmissionReason::PrivacyRedaction,
                2 => OmissionReason::ResourcePressure,
                3 => OmissionReason::RetentionPolicy,
                4 => OmissionReason::CapabilityFiltered,
                5 => OmissionReason::TransientPreviewOnly,
                6 => OmissionReason::UpstreamMissing,
                _ => return Err(ContractError::InvalidIdentifier),
            };
            let policy_rule = decoder.text()?.to_string();
            let omitted_bytes = decoder.u64()?;
            let omitted_frames = decoder.u32()?;
            Ok(ExplicitOmission::Omitted {
                reason,
                policy_rule,
                omitted_bytes,
                omitted_frames,
            })
        }
        _ => Err(ContractError::NonCanonicalOrdering),
    }
}

fn decode_ledger_anchor(decoder: &mut CanonicalDecoder<'_>) -> Result<LedgerAnchor, ContractError> {
    let site_lineage = decoder.text()?.to_string();
    let ledger_epoch = decoder.u64()?;
    let commit_sequence = decoder.u64()?;
    let adapter_registry_epoch = decoder.u64()?;
    let schema_epoch = decoder.u64()?;
    let policy_epoch = decoder.u64()?;
    let privacy_epoch = decoder.u64()?;
    let state_root = decoder.digest()?;
    Ok(LedgerAnchor {
        site_lineage,
        ledger_epoch,
        commit_sequence,
        adapter_registry_epoch,
        schema_epoch,
        policy_epoch,
        privacy_epoch,
        state_root,
    })
}

fn decode_set(decoder: &mut CanonicalDecoder<'_>) -> Result<BTreeSet<String>, ContractError> {
    let count = decoder.u64()? as usize;
    let mut set = BTreeSet::new();
    for _ in 0..count {
        set.insert(decoder.text()?.to_string());
    }
    Ok(set)
}

fn decode_coverage_witness(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<CoverageWitness, ContractError> {
    let anchor = decode_ledger_anchor(decoder)?;
    let authorized_domain = decode_set(decoder)?;
    let observed_domain = decode_set(decoder)?;
    let excluded_domain = decode_set(decoder)?;
    let continuity = match decoder.u8()? {
        1 => CoverageContinuity::Continuous,
        2 => CoverageContinuity::Gapped,
        3 => CoverageContinuity::Unknown,
        _ => return Err(ContractError::NonCanonicalOrdering),
    };
    let completeness = match decoder.u8()? {
        1 => Completeness::Complete,
        2 => Completeness::Bounded,
        3 => Completeness::Partial,
        4 => Completeness::Unknown,
        5 => Completeness::NotObservable,
        6 => Completeness::Unauthorized,
        7 => Completeness::Stale,
        _ => return Err(ContractError::NonCanonicalOrdering),
    };
    let negative_predicate = decoder.text()?.to_string();
    let stop_reason = match decoder.u8()? {
        1 => CoverageStopReason::Complete,
        2 => CoverageStopReason::BudgetExhausted,
        3 => CoverageStopReason::Cancelled,
        4 => CoverageStopReason::SourceGap,
        5 => CoverageStopReason::AuthorizationFiltered,
        6 => CoverageStopReason::Unsupported,
        7 => CoverageStopReason::Error,
        _ => return Err(ContractError::NonCanonicalOrdering),
    };
    let authorized_generation = decoder.u64()?;
    let observed_generation = decoder.u64()?;
    Ok(CoverageWitness {
        anchor,
        authorized_domain,
        observed_domain,
        excluded_domain,
        continuity,
        completeness,
        negative_predicate,
        stop_reason,
        authorized_generation,
        observed_generation,
    })
}

fn decode_canonical_source_id(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<SourceId, ContractError> {
    let raw = decoder.text()?;
    if !raw.starts_with(SourceId::PREFIX) {
        return Err(ContractError::NonCanonicalOrdering);
    }
    SourceId::parse(raw)
}

fn decode_canonical_adapter_id(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<AdapterId, ContractError> {
    let raw = decoder.text()?;
    if !raw.starts_with(AdapterId::PREFIX) {
        return Err(ContractError::NonCanonicalOrdering);
    }
    AdapterId::parse(raw)
}

fn decode_canonical_device_id(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<DeviceId, ContractError> {
    let raw = decoder.text()?;
    if !raw.starts_with(DeviceId::PREFIX) {
        return Err(ContractError::NonCanonicalOrdering);
    }
    DeviceId::parse(raw)
}

// =========================================================================
// Capture Device Tuple and Route Evaluation Contract (NEG-001 / GATE-100)
// =========================================================================

/// Exact capture device tuple pinning hardware, firmware, controller, app, platform, and account.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CaptureDeviceTuple {
    /// Device model identity (e.g. "DJI Flip", "Wyze Cam v4").
    pub device_model: String,
    /// Exact firmware version string (e.g. "v01.00.0100").
    pub firmware_version: String,
    /// Controller hardware identifier (e.g. "DJI RC-N3", "none").
    pub controller_hardware: String,
    /// Controller application and version (e.g. "DJI Fly v1.14.0", "none").
    pub controller_app: String,
    /// Host operating system and platform (e.g. "linux-x86_64").
    pub host_platform: String,
    /// Authorized account or capability scope (e.g. "owner-authorized-lab", "production").
    pub account_scope: String,
}

impl CaptureDeviceTuple {
    /// Constructs and validates an exact capture device tuple.
    pub fn new(
        device_model: impl Into<String>,
        firmware_version: impl Into<String>,
        controller_hardware: impl Into<String>,
        controller_app: impl Into<String>,
        host_platform: impl Into<String>,
        account_scope: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let dm = device_model.into();
        let fv = firmware_version.into();
        let ch = controller_hardware.into();
        let ca = controller_app.into();
        let hp = host_platform.into();
        let as_ = account_scope.into();

        if dm.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if fv.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if ch.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if ca.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if hp.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if as_.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }

        Ok(Self {
            device_model: dm,
            firmware_version: fv,
            controller_hardware: ch,
            controller_app: ca,
            host_platform: hp,
            account_scope: as_,
        })
    }

    /// Returns true if this tuple identifies a DJI Flip device.
    #[must_use]
    pub fn is_dji_flip(&self) -> bool {
        let model = self.device_model.to_lowercase();
        (model.contains("dji") && model.contains("flip"))
            || model.contains("flip drone")
            || model == "flip"
            || model.starts_with("flip ")
            || model.ends_with(" flip")
            || model.contains("dji-flip")
            || model.contains("dji_flip")
    }

    /// Returns true if this device tuple represents an established hardware and platform configuration.
    #[must_use]
    pub fn is_established(&self) -> bool {
        let dm = self.device_model.to_lowercase();
        let fv = self.firmware_version.to_lowercase();
        let ch = self.controller_hardware.to_lowercase();
        let ca = self.controller_app.to_lowercase();
        let hp = self.host_platform.to_lowercase();

        if dm.contains("unestablished")
            || dm.contains("unsupported")
            || dm.contains("unknown")
            || dm.contains("generic")
        {
            return false;
        }
        if fv.contains("unestablished")
            || fv.contains("unsupported")
            || fv.contains("unknown")
            || fv.contains("beta")
        {
            return false;
        }
        if ch.contains("unestablished") || ch.contains("unsupported") || ch.contains("unknown") {
            return false;
        }
        if ca.contains("unestablished") || ca.contains("unsupported") || ca.contains("unknown") {
            return false;
        }
        if hp.contains("unestablished") || hp.contains("unsupported") || hp.contains("unknown") {
            return false;
        }

        true
    }
}

impl CanonicalEncode for CaptureDeviceTuple {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.device_model);
        encoder.text(&self.firmware_version);
        encoder.text(&self.controller_hardware);
        encoder.text(&self.controller_app);
        encoder.text(&self.host_platform);
        encoder.text(&self.account_scope);
    }
}

impl CanonicalDecode for CaptureDeviceTuple {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let device_model = decoder.text()?.to_string();
        let firmware_version = decoder.text()?.to_string();
        let controller_hardware = decoder.text()?.to_string();
        let controller_app = decoder.text()?.to_string();
        let host_platform = decoder.text()?.to_string();
        let account_scope = decoder.text()?.to_string();
        Self::new(
            device_model,
            firmware_version,
            controller_hardware,
            controller_app,
            host_platform,
            account_scope,
        )
    }
}

/// Category of capture route requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CaptureRouteKind {
    /// Bounded recorded-file media/telemetry import (GATE-100 supported for DJI Flip).
    RecordedFileImport,
    /// Owner-authorized capture-bridge laboratory experiment (GATE-100 supported for DJI Flip lab).
    OwnerAuthorizedLabBridge,
    /// Live video/audio streaming route (unestablished / unsupported for DJI Flip).
    LiveStreaming,
    /// Vendor proprietary mobile SDK live capture (prohibited by NEG-001).
    ProprietarySdkLiveCapture,
}

impl fmt::Display for CaptureRouteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordedFileImport => write!(f, "recorded_file_import"),
            Self::OwnerAuthorizedLabBridge => write!(f, "owner_authorized_lab_bridge"),
            Self::LiveStreaming => write!(f, "live_streaming"),
            Self::ProprietarySdkLiveCapture => write!(f, "proprietary_sdk_live_capture"),
        }
    }
}

impl CanonicalEncode for CaptureRouteKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::RecordedFileImport => 1,
            Self::OwnerAuthorizedLabBridge => 2,
            Self::LiveStreaming => 3,
            Self::ProprietarySdkLiveCapture => 4,
        });
    }
}

impl CanonicalDecode for CaptureRouteKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::RecordedFileImport),
            2 => Ok(Self::OwnerAuthorizedLabBridge),
            3 => Ok(Self::LiveStreaming),
            4 => Ok(Self::ProprietarySdkLiveCapture),
            _ => Err(ContractError::NonCanonicalOrdering),
        }
    }
}

/// Readiness classification for capture routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CaptureReadinessState {
    /// Fully qualified, authorized, and ready for capture.
    QualifiedReady,
    /// Route is unsupported by architecture or negative constraint (e.g. NEG-001).
    Unsupported,
    /// Route is temporarily unavailable (e.g. auth revoked, disconnected, scope mismatch).
    Unavailable,
}

impl fmt::Display for CaptureReadinessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QualifiedReady => write!(f, "qualified_ready"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

impl CanonicalEncode for CaptureReadinessState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::QualifiedReady => 1,
            Self::Unsupported => 2,
            Self::Unavailable => 3,
        });
    }
}

impl CanonicalDecode for CaptureReadinessState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::QualifiedReady),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::Unavailable),
            _ => Err(ContractError::NonCanonicalOrdering),
        }
    }
}

/// Specific reason why a capture route is unsupported.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum UnsupportedCaptureReason {
    /// Prohibited vendor SDK dependency (NEG-001).
    ProhibitedSdkDependency {
        /// Prohibited SDK name.
        sdk_name: String,
        /// Negative constraint identifier.
        constraint_id: &'static str,
    },
    /// Live capture route is not supported for this device model.
    UnsupportedLiveRouteForDevice {
        /// Device model.
        device_model: String,
        /// Route kind.
        route_kind: CaptureRouteKind,
        /// Negative constraint identifier.
        constraint_id: &'static str,
    },
    /// Tuple members are unestablished or uncertified.
    UnestablishedDeviceTuple {
        /// Missing or unestablished dimension.
        missing_dimension: String,
    },
    /// Tuple drift detected between authorized reference and requested runtime.
    TupleDrift {
        /// Expected dimension.
        expected: String,
        /// Observed actual dimension.
        actual: String,
    },
    /// Misleading vendor claim: marketing claims live support but no compatible capture surface exists.
    MisleadingVendorClaim {
        /// Stated claim.
        claim: String,
        /// Technical finding.
        finding: String,
    },
}

impl fmt::Display for UnsupportedCaptureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProhibitedSdkDependency {
                sdk_name,
                constraint_id,
            } => {
                write!(
                    f,
                    "prohibited SDK dependency '{sdk_name}' ({constraint_id})"
                )
            }
            Self::UnsupportedLiveRouteForDevice {
                device_model,
                route_kind,
                constraint_id,
            } => {
                write!(
                    f,
                    "unsupported live route {route_kind} for '{device_model}' ({constraint_id})"
                )
            }
            Self::UnestablishedDeviceTuple { missing_dimension } => {
                write!(f, "unestablished device tuple: {missing_dimension}")
            }
            Self::TupleDrift { expected, actual } => {
                write!(f, "tuple drift: expected {expected}, got {actual}")
            }
            Self::MisleadingVendorClaim { claim, finding } => {
                write!(f, "misleading vendor claim '{claim}': {finding}")
            }
        }
    }
}

/// Specific reason why a capture route is unavailable.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum UnavailableCaptureReason {
    /// Owner authorization has been revoked or expired.
    AuthRevoked {
        /// Revocation detail.
        detail: String,
    },
    /// Operation or session was cancelled.
    Cancelled {
        /// Cancellation detail.
        detail: String,
    },
    /// Hardware device is disconnected or offline.
    HardwareDisconnected {
        /// Disconnect detail.
        detail: String,
    },
    /// Privacy taint or capability scope exceeded.
    PrivacyScopeExceeded {
        /// Current scope.
        scope: String,
        /// Required scope.
        required: String,
    },
}

impl fmt::Display for UnavailableCaptureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthRevoked { detail } => write!(f, "authority revoked: {detail}"),
            Self::Cancelled { detail } => write!(f, "operation cancelled: {detail}"),
            Self::HardwareDisconnected { detail } => write!(f, "hardware disconnected: {detail}"),
            Self::PrivacyScopeExceeded { scope, required } => {
                write!(
                    f,
                    "privacy scope exceeded: '{scope}' does not satisfy '{required}'"
                )
            }
        }
    }
}

/// Details of an established, permitted capture route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstablishedCaptureRoute {
    /// Device tuple.
    pub tuple: CaptureDeviceTuple,
    /// Route kind.
    pub route_kind: CaptureRouteKind,
    /// Promotion gate.
    pub promotion_gate: &'static str,
    /// Lease identifier.
    pub authority_lease_id: String,
    /// Whether an adapter has been accepted for this route.
    pub adapter_accepted: bool,
}

/// Details of an unsupported capture route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedCaptureRoute {
    /// Device tuple.
    pub tuple: CaptureDeviceTuple,
    /// Route kind.
    pub route_kind: CaptureRouteKind,
    /// Reason route is unsupported.
    pub reason: UnsupportedCaptureReason,
    /// Bound negative constraint identifier, if any.
    pub constraint_id: Option<&'static str>,
    /// Actionable repair guidance.
    pub remediation: String,
}

/// Details of an unavailable capture route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnavailableCaptureRoute {
    /// Device tuple.
    pub tuple: CaptureDeviceTuple,
    /// Route kind.
    pub route_kind: CaptureRouteKind,
    /// Reason route is unavailable.
    pub reason: UnavailableCaptureReason,
    /// Detail.
    pub detail: String,
}

/// Typed result of evaluating a capture route.
///
/// Invariants:
/// - [`Self::Unsupported`] and [`Self::Unavailable`] CANNOT be reported as adapter acceptance,
///   streaming, or readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveCaptureRouteResult {
    /// Route is supported and established.
    Established(EstablishedCaptureRoute),
    /// Route is unsupported; cannot be reported as adapter acceptance, streaming, or readiness.
    Unsupported(UnsupportedCaptureRoute),
    /// Route is unavailable; cannot be reported as adapter acceptance, streaming, or readiness.
    Unavailable(UnavailableCaptureRoute),
}

impl LiveCaptureRouteResult {
    /// Non-negotiable invariant: unsupported or unavailable routes NEVER report as adapter acceptance.
    #[must_use]
    pub const fn is_adapter_accepted(&self) -> bool {
        match self {
            Self::Established(est) => est.adapter_accepted,
            Self::Unsupported(_) | Self::Unavailable(_) => false,
        }
    }

    /// Non-negotiable invariant (INV-005): route evaluation NEVER reports as streaming unless
    /// established for live streaming.
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        match self {
            Self::Established(est) => matches!(est.route_kind, CaptureRouteKind::LiveStreaming),
            Self::Unsupported(_) | Self::Unavailable(_) => false,
        }
    }

    /// Non-negotiable invariant: unsupported or unavailable routes NEVER report as ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Established(_))
    }

    /// Returns the typed readiness state.
    #[must_use]
    pub fn readiness_state(&self) -> CaptureReadinessState {
        match self {
            Self::Established(_) => CaptureReadinessState::QualifiedReady,
            Self::Unsupported(_) => CaptureReadinessState::Unsupported,
            Self::Unavailable(_) => CaptureReadinessState::Unavailable,
        }
    }
}

/// Evaluates a requested capture route for a device tuple against architecture constraints (including NEG-001).
pub fn evaluate_capture_route(
    tuple: &CaptureDeviceTuple,
    route_kind: CaptureRouteKind,
    authority_active: bool,
    privacy_scope_matches: bool,
) -> LiveCaptureRouteResult {
    if !authority_active {
        return LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnavailableCaptureReason::AuthRevoked {
                detail: "owner authority lease has expired or been revoked".to_string(),
            },
            detail: "active authority lease required for capture operations".to_string(),
        });
    }

    if !privacy_scope_matches {
        return LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnavailableCaptureReason::PrivacyScopeExceeded {
                scope: tuple.account_scope.clone(),
                required: "owner-authorized-lab".to_string(),
            },
            detail: "privacy or account scope exceeds authorized boundary".to_string(),
        });
    }

    if route_kind == CaptureRouteKind::ProprietarySdkLiveCapture {
        let sdk_name = if tuple.is_dji_flip() {
            "DJI Mobile SDK".to_string()
        } else {
            format!("Proprietary SDK for {}", tuple.device_model)
        };
        return LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnsupportedCaptureReason::ProhibitedSdkDependency {
                sdk_name,
                constraint_id: CONSTRAINT_NEG_001,
            },
            constraint_id: Some(CONSTRAINT_NEG_001),
            remediation: "NEG-001 forbids proprietary mobile SDK architectural dependency; use open standards-first routes or recorded-file import".to_string(),
        });
    }

    if tuple.is_dji_flip() {
        match route_kind {
            CaptureRouteKind::ProprietarySdkLiveCapture => {
                LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
                    tuple: tuple.clone(),
                    route_kind,
                    reason: UnsupportedCaptureReason::ProhibitedSdkDependency {
                        sdk_name: "DJI Mobile SDK".to_string(),
                        constraint_id: CONSTRAINT_NEG_001,
                    },
                    constraint_id: Some(CONSTRAINT_NEG_001),
                    remediation: "NEG-001 forbids DJI Mobile SDK architectural dependency; use GATE-100 recorded-file import or owner-authorized capture bridge".to_string(),
                })
            }
            CaptureRouteKind::LiveStreaming => {
                LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
                    tuple: tuple.clone(),
                    route_kind,
                    reason: UnsupportedCaptureReason::UnsupportedLiveRouteForDevice {
                        device_model: tuple.device_model.clone(),
                        route_kind,
                        constraint_id: CONSTRAINT_NEG_001,
                    },
                    constraint_id: Some(CONSTRAINT_NEG_001),
                    remediation: "DJI Flip has no established live streaming surface; use GATE-100 recorded-file import or owner-authorized capture bridge".to_string(),
                })
            }
            CaptureRouteKind::RecordedFileImport => {
                if !tuple.account_scope.starts_with("owner-authorized") {
                    LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
                        tuple: tuple.clone(),
                        route_kind,
                        reason: UnavailableCaptureReason::PrivacyScopeExceeded {
                            scope: tuple.account_scope.clone(),
                            required: "owner-authorized-lab".to_string(),
                        },
                        detail: "privacy or account scope exceeds authorized boundary; owner-authorized scope required".to_string(),
                    })
                } else {
                    LiveCaptureRouteResult::Established(EstablishedCaptureRoute {
                        tuple: tuple.clone(),
                        route_kind,
                        promotion_gate: "GATE-100",
                        authority_lease_id: format!("lease:{}:recorded-import", tuple.device_model),
                        adapter_accepted: false,
                    })
                }
            }
            CaptureRouteKind::OwnerAuthorizedLabBridge => {
                if !tuple.account_scope.starts_with("owner-authorized") {
                    LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
                        tuple: tuple.clone(),
                        route_kind,
                        reason: UnavailableCaptureReason::PrivacyScopeExceeded {
                            scope: tuple.account_scope.clone(),
                            required: "owner-authorized-lab".to_string(),
                        },
                        detail: "privacy or account scope exceeds authorized boundary; owner-authorized scope required".to_string(),
                    })
                } else {
                    LiveCaptureRouteResult::Established(EstablishedCaptureRoute {
                        tuple: tuple.clone(),
                        route_kind,
                        promotion_gate: "GATE-100",
                        authority_lease_id: format!("lease:{}:lab-bridge", tuple.device_model),
                        adapter_accepted: false,
                    })
                }
            }
        }
    } else if !tuple.is_established() {
        let missing_dim = if tuple.device_model.to_lowercase().contains("generic")
            || tuple.device_model.to_lowercase().contains("unestablished")
            || tuple.device_model.to_lowercase().contains("unknown")
        {
            format!("device model '{}' is unestablished", tuple.device_model)
        } else if tuple
            .controller_hardware
            .to_lowercase()
            .contains("unestablished")
            || tuple
                .controller_hardware
                .to_lowercase()
                .contains("unsupported")
            || tuple.controller_hardware.to_lowercase().contains("unknown")
        {
            format!(
                "controller hardware '{}' is unestablished",
                tuple.controller_hardware
            )
        } else if tuple.host_platform.to_lowercase().contains("unsupported")
            || tuple.host_platform.to_lowercase().contains("unestablished")
            || tuple.host_platform.to_lowercase().contains("unknown")
        {
            format!("host platform '{}' is unsupported", tuple.host_platform)
        } else if tuple
            .firmware_version
            .to_lowercase()
            .contains("unestablished")
            || tuple.firmware_version.to_lowercase().contains("beta")
            || tuple.firmware_version.to_lowercase().contains("unknown")
        {
            format!(
                "firmware version '{}' is unestablished",
                tuple.firmware_version
            )
        } else if tuple
            .controller_app
            .to_lowercase()
            .contains("unestablished")
            || tuple.controller_app.to_lowercase().contains("unsupported")
            || tuple.controller_app.to_lowercase().contains("unknown")
        {
            format!("controller app '{}' is unestablished", tuple.controller_app)
        } else {
            "device tuple contains unestablished or unsupported dimensions".to_string()
        };

        LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnsupportedCaptureReason::UnestablishedDeviceTuple {
                missing_dimension: missing_dim,
            },
            constraint_id: None,
            remediation: "device tuple must be established with verified hardware, firmware, controller, and platform".to_string(),
        })
    } else if !tuple.account_scope.starts_with("owner-authorized") {
        LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnavailableCaptureReason::PrivacyScopeExceeded {
                scope: tuple.account_scope.clone(),
                required: "owner-authorized-lab".to_string(),
            },
            detail: "privacy or account scope exceeds authorized boundary; owner-authorized scope required".to_string(),
        })
    } else {
        LiveCaptureRouteResult::Established(EstablishedCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            promotion_gate: "GATE-020",
            authority_lease_id: format!("lease:{}:route", tuple.device_model),
            adapter_accepted: false,
        })
    }
}

/// Evaluates a requested capture route comparing actual device tuple against an authorized reference tuple.
/// Fails closed with [`UnsupportedCaptureReason::TupleDrift`] if any tuple coordinate differs.
pub fn evaluate_capture_route_with_reference(
    actual: &CaptureDeviceTuple,
    reference: &CaptureDeviceTuple,
    route_kind: CaptureRouteKind,
    authority_active: bool,
    privacy_scope_matches: bool,
) -> LiveCaptureRouteResult {
    if actual != reference {
        let mut diffs = Vec::new();
        if actual.device_model != reference.device_model {
            diffs.push(format!(
                "device_model (expected '{}', got '{}')",
                reference.device_model, actual.device_model
            ));
        }
        if actual.firmware_version != reference.firmware_version {
            diffs.push(format!(
                "firmware_version (expected '{}', got '{}')",
                reference.firmware_version, actual.firmware_version
            ));
        }
        if actual.controller_hardware != reference.controller_hardware {
            diffs.push(format!(
                "controller_hardware (expected '{}', got '{}')",
                reference.controller_hardware, actual.controller_hardware
            ));
        }
        if actual.controller_app != reference.controller_app {
            diffs.push(format!(
                "controller_app (expected '{}', got '{}')",
                reference.controller_app, actual.controller_app
            ));
        }
        if actual.host_platform != reference.host_platform {
            diffs.push(format!(
                "host_platform (expected '{}', got '{}')",
                reference.host_platform, actual.host_platform
            ));
        }
        if actual.account_scope != reference.account_scope {
            diffs.push(format!(
                "account_scope (expected '{}', got '{}')",
                reference.account_scope, actual.account_scope
            ));
        }
        let detail = diffs.join("; ");
        return LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
            tuple: actual.clone(),
            route_kind,
            reason: UnsupportedCaptureReason::TupleDrift {
                expected: format!("{reference:?}"),
                actual: format!("{actual:?}"),
            },
            constraint_id: Some(CONSTRAINT_NEG_001),
            remediation: format!(
                "tuple drift detected: {detail}; re-qualify or update reference tuple"
            ),
        });
    }
    evaluate_capture_route(actual, route_kind, authority_active, privacy_scope_matches)
}

/// Evaluates a vendor support claim against NEG-001 negative evidence.
/// Returns [`UnsupportedCaptureReason::MisleadingVendorClaim`] if the claim alleges official SDK or live streaming support.
pub fn evaluate_capture_route_vendor_claim(
    tuple: &CaptureDeviceTuple,
    claim: &str,
    route_kind: CaptureRouteKind,
) -> LiveCaptureRouteResult {
    let lower_claim = claim.to_lowercase();
    let is_misleading = (tuple.is_dji_flip() || lower_claim.contains("flip"))
        && (lower_claim.contains("sdk")
            || lower_claim.contains("streaming")
            || lower_claim.contains("live capture")
            || lower_claim.contains("official support"));

    if is_misleading {
        LiveCaptureRouteResult::Unsupported(UnsupportedCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnsupportedCaptureReason::MisleadingVendorClaim {
                claim: claim.to_string(),
                finding: "NEG-001 research finding: cited public materials do not establish DJI Flip SDK live streaming support".to_string(),
            },
            constraint_id: Some(CONSTRAINT_NEG_001),
            remediation: "reject uncorroborated vendor claim; enforce NEG-001 manual capture/import constraint".to_string(),
        })
    } else {
        evaluate_capture_route(tuple, route_kind, true, true)
    }
}

/// Options or conditions affecting capture route availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureAvailabilityConditions {
    /// True if owner authority lease is active.
    pub authority_active: bool,
    /// True if privacy scope and account boundaries match.
    pub privacy_scope_matches: bool,
    /// True if hardware device is connected.
    pub hardware_connected: bool,
    /// True if the operation has been cancelled.
    pub cancelled: bool,
}

impl Default for CaptureAvailabilityConditions {
    fn default() -> Self {
        Self {
            authority_active: true,
            privacy_scope_matches: true,
            hardware_connected: true,
            cancelled: false,
        }
    }
}

/// Evaluates a requested capture route with explicit availability conditions (including cancellation and disconnect).
pub fn evaluate_capture_route_with_conditions(
    tuple: &CaptureDeviceTuple,
    route_kind: CaptureRouteKind,
    conditions: CaptureAvailabilityConditions,
) -> LiveCaptureRouteResult {
    if conditions.cancelled {
        return LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnavailableCaptureReason::Cancelled {
                detail: "capture route evaluation or acquisition operation was cancelled"
                    .to_string(),
            },
            detail: "operation cancelled before route establishment".to_string(),
        });
    }
    if !conditions.hardware_connected {
        return LiveCaptureRouteResult::Unavailable(UnavailableCaptureRoute {
            tuple: tuple.clone(),
            route_kind,
            reason: UnavailableCaptureReason::HardwareDisconnected {
                detail: format!("device '{}' is disconnected or offline", tuple.device_model),
            },
            detail: "hardware connection required for capture route establishment".to_string(),
        });
    }
    evaluate_capture_route(
        tuple,
        route_kind,
        conditions.authority_active,
        conditions.privacy_scope_matches,
    )
}

/// Bounded, secret-free structured JSONL log entry for NEG-001 negative-evidence qualification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neg001ScenarioLog {
    /// Canonical schema identifier.
    pub schema_version: &'static str,
    /// Unique run identifier.
    pub run_id: String,
    /// Negative constraint identifier.
    pub neg_id: &'static str,
    /// Content digest of source evidence.
    pub source_digest: ContentDigest,
    /// Content digest of adapter registry.
    pub registry_digest: ContentDigest,
    /// Exact device tuple evaluated.
    pub tuple: CaptureDeviceTuple,
    /// Capture route kind evaluated.
    pub route_kind: CaptureRouteKind,
    /// Authority scope name.
    pub authority_scope: String,
    /// Privacy scope name.
    pub privacy_scope: String,
    /// Hypothesis state.
    pub hypothesis_state: &'static str,
    /// Finding state.
    pub finding_state: &'static str,
    /// Decision state.
    pub decision_state: &'static str,
    /// Expected readiness.
    pub expected_readiness: CaptureReadinessState,
    /// Observed readiness.
    pub observed_readiness: CaptureReadinessState,
    /// Whether adapter acceptance was reported (must be false for unsupported).
    pub is_adapter_accepted: bool,
    /// Whether streaming was reported (must be false).
    pub is_streaming: bool,
    /// Whether official revival condition is met.
    pub revival_condition_met: bool,
    /// Proof hash.
    pub proof_hash: ContentDigest,
    /// Reproduction command without credentials.
    pub reproduction_command: String,
}

impl Neg001ScenarioLog {
    /// Formats this scenario record as a single-line secret-free JSON string.
    #[must_use]
    pub fn to_jsonl_line(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"run_id\":\"{}\",\"neg_id\":\"{}\",\"source_digest\":\"{}\",\"registry_digest\":\"{}\",\"tuple\":{{\"device_model\":\"{}\",\"firmware_version\":\"{}\",\"controller_hardware\":\"{}\",\"controller_app\":\"{}\",\"host_platform\":\"{}\",\"account_scope\":\"{}\"}},\"route_kind\":\"{}\",\"authority_scope\":\"{}\",\"privacy_scope\":\"{}\",\"hypothesis_state\":\"{}\",\"finding_state\":\"{}\",\"decision_state\":\"{}\",\"expected_readiness\":\"{}\",\"observed_readiness\":\"{}\",\"is_adapter_accepted\":{},\"is_streaming\":{},\"revival_condition_met\":{},\"proof_hash\":\"{}\",\"reproduction_command\":\"{}\"}}",
            self.schema_version,
            self.run_id,
            self.neg_id,
            self.source_digest,
            self.registry_digest,
            self.tuple.device_model,
            self.tuple.firmware_version,
            self.tuple.controller_hardware,
            self.tuple.controller_app,
            self.tuple.host_platform,
            self.tuple.account_scope,
            self.route_kind,
            self.authority_scope,
            self.privacy_scope,
            self.hypothesis_state,
            self.finding_state,
            self.decision_state,
            self.expected_readiness,
            self.observed_readiness,
            self.is_adapter_accepted,
            self.is_streaming,
            self.revival_condition_met,
            self.proof_hash,
            self.reproduction_command,
        )
    }
}
