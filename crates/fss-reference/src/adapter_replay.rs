#![forbid(unsafe_code)]
//! Deterministic replay adapter realizing row ADP-REPLAY-001.
//!
//! Provides a pure-Rust, in-process virtual device adapter that replays canonical
//! [`ReplayBundle`] workloads with reproducible state roots, verified bounds,
//! cooperative cancellation, and divergence detection.

use std::error::Error;
use std::fmt;

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContentDigest,
    ContractError, CredentialMethod, IsolationMode,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::InMemoryObjectStore;

use crate::{DeliveryMutation, ReferenceCapture, ReferenceError, ReplayBundle, ReplayBundleError};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_REPLAY_ROW_ID: &str = "ADP-REPLAY-001";

/// Surface name for the deterministic replay adapter.
pub const ADP_REPLAY_SURFACE: &str = "deterministic replay";

/// Device adapter tier (pure-Rust reference implementation).
pub const ADP_REPLAY_TIER: &str = "T0";

/// Current qualification lifecycle state.
pub const ADP_REPLAY_CURRENT_STATE: &str = "specified";

/// Promotion gate requirement.
pub const ADP_REPLAY_PROMOTION_GATE: &str = "GATE-010";

/// Pinned adapter generation identifier.
pub const ADP_REPLAY_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile string for virtual in-process replay.
pub const ADP_REPLAY_PROTOCOL_PROFILE: &str = "fss/1";

/// Diagnostic finding code emitted when replay diverges from expected state root.
pub const ERR_REPLAY_DIVERGED: &str = "ERR-REPLAY-DIVERGED-001";

/// Operational bounds configuration for [`ReplayAdapter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAdapterConfig {
    /// Maximum allowed packet count per replay execution.
    pub max_packets: usize,
    /// Maximum allowed packet payload bytes per packet.
    pub max_bytes: usize,
    /// Expected adapter generation string.
    pub generation: String,
}

impl Default for ReplayAdapterConfig {
    fn default() -> Self {
        Self {
            max_packets: 10_000,
            max_bytes: 64 * 1024 * 1024,
            generation: ADP_REPLAY_GENERATION.to_string(),
        }
    }
}

/// Execution request envelope for deterministic replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayExecutionRequest {
    /// Canonical self-verifying replay bundle.
    pub bundle: ReplayBundle,
    /// Caller-specified generation anchor.
    pub generation: String,
    /// Cooperative cancellation flag.
    pub cancel_requested: bool,
    /// Optional hard limit on total packets allowed.
    pub max_packet_budget: Option<usize>,
}

impl ReplayExecutionRequest {
    /// Constructs a default request for the provided replay bundle.
    #[must_use]
    pub fn new(bundle: ReplayBundle) -> Self {
        Self {
            bundle,
            generation: ADP_REPLAY_GENERATION.to_string(),
            cancel_requested: false,
            max_packet_budget: None,
        }
    }
}

/// Cryptographic and statistical audit record produced by replay execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAuditRecord {
    /// Merkle state root of the capture session.
    pub state_root: ContentDigest,
    /// Domain-separated audit digest over all replay outputs and witnesses.
    pub audit_hash: ContentDigest,
    /// Total count of delivery packets processed.
    pub packets_delivered: usize,
    /// Count of packets with applied mutations (corruption, etc.).
    pub packets_mutated: usize,
}

/// Output envelope returned upon successful replay execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayExecutionOutput {
    /// Published reference capture containing retained objects and ledger anchor.
    pub capture: ReferenceCapture,
    /// Retained audit record for divergence verification.
    pub audit_record: ReplayAuditRecord,
}

/// Fail-closed error type for deterministic replay adapter operations.
#[derive(Debug)]
pub enum ReplayAdapterError {
    /// Requested generation does not match the pinned adapter generation.
    IncompatibleGeneration {
        /// Pinned generation expected by the adapter.
        expected: String,
        /// Actual generation passed in request.
        actual: String,
    },
    /// Replay was aborted via cooperative cancellation request.
    CancellationRequested,
    /// Requested packet count exceeds caller-specified budget.
    BudgetExhausted {
        /// Packets requested by the replay bundle.
        requested: usize,
        /// Maximum packet budget permitted.
        limit: usize,
    },
    /// Operational bound exceeded (e.g. packet count or byte capacity).
    BoundExceeded(&'static str),
    /// Replayed state root diverged from independently retained reference root.
    ReplayDiverged {
        /// Expected cryptographic reference state root.
        expected_root: ContentDigest,
        /// Actual cryptographic state root produced by replay.
        actual_root: ContentDigest,
    },
    /// Core contract error.
    Contract(ContractError),
    /// Replay bundle decoding or validation error.
    Bundle(ReplayBundleError),
    /// Underlying reference engine error.
    Reference(ReferenceError),
}

impl fmt::Display for ReplayAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleGeneration { expected, actual } => {
                write!(
                    f,
                    "incompatible adapter generation: expected {expected}, actual {actual}"
                )
            }
            Self::CancellationRequested => f.write_str("cooperative cancellation requested"),
            Self::BudgetExhausted { requested, limit } => {
                write!(
                    f,
                    "packet budget exhausted: requested {requested}, limit {limit}"
                )
            }
            Self::BoundExceeded(bound) => {
                write!(f, "bound exceeded: {bound}")
            }
            Self::ReplayDiverged {
                expected_root,
                actual_root,
            } => {
                write!(
                    f,
                    "[{ERR_REPLAY_DIVERGED}] replay state root diverged: expected {expected_root}, actual {actual_root}"
                )
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
            Self::Bundle(err) => write!(f, "bundle error: {err}"),
            Self::Reference(err) => write!(f, "reference error: {err}"),
        }
    }
}

impl Error for ReplayAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(err) => Some(err),
            Self::Bundle(err) => Some(err),
            Self::Reference(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ContractError> for ReplayAdapterError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<ReplayBundleError> for ReplayAdapterError {
    fn from(err: ReplayBundleError) -> Self {
        Self::Bundle(err)
    }
}

impl From<ReferenceError> for ReplayAdapterError {
    fn from(err: ReferenceError) -> Self {
        Self::Reference(err)
    }
}

/// Deterministic replay adapter realizing row ADP-REPLAY-001.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAdapter {
    config: ReplayAdapterConfig,
    identity: AdapterIdentity,
}

impl ReplayAdapter {
    /// Constructs a deterministic replay adapter with default bounds.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError`] if identifier parsing or verification fails.
    pub fn new() -> Result<Self, ReplayAdapterError> {
        Self::with_config(ReplayAdapterConfig::default())
    }

    /// Constructs a deterministic replay adapter with custom bounds configuration.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError`] if identifier parsing or verification fails.
    pub fn with_config(config: ReplayAdapterConfig) -> Result<Self, ReplayAdapterError> {
        let adapter_id = AdapterId::parse("adapter:adp-replay-001")?;
        let generation = AdapterGeneration::parse(&config.generation)?;
        let identity = AdapterIdentity {
            adapter_id,
            generation,
            adapter_kind: AdapterKind::VirtualSimulated,
            protocol_profile: ADP_REPLAY_PROTOCOL_PROFILE.to_string(),
            isolation_mode: IsolationMode::NativePureRust,
            credential_method: CredentialMethod::None,
            capabilities: AdapterCapabilities::NONE,
            max_bandwidth_bytes_per_sec: 1_000_000_000,
            max_buffer_frames: 1024,
            request_timeout_ns: 10_000_000_000,
        };
        identity.verify()?;
        Ok(Self { config, identity })
    }

    /// Normative registry row identifier.
    #[must_use]
    pub const fn row_id(&self) -> &'static str {
        ADP_REPLAY_ROW_ID
    }

    /// Normative registry surface description.
    #[must_use]
    pub const fn surface(&self) -> &'static str {
        ADP_REPLAY_SURFACE
    }

    /// Normative registry adapter tier.
    #[must_use]
    pub const fn tier(&self) -> &'static str {
        ADP_REPLAY_TIER
    }

    /// Normative registry qualification state.
    #[must_use]
    pub const fn current_state(&self) -> &'static str {
        ADP_REPLAY_CURRENT_STATE
    }

    /// Normative registry promotion gate.
    #[must_use]
    pub const fn promotion_gate(&self) -> &'static str {
        ADP_REPLAY_PROMOTION_GATE
    }

    /// Effective adapter generation string.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.config.generation
    }

    /// Immutable typed adapter identity.
    #[must_use]
    pub const fn identity(&self) -> &AdapterIdentity {
        &self.identity
    }

    /// Executes the replay request deterministically against the provided object store and ledger.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::IncompatibleGeneration`] if the generation mismatches.
    /// Returns [`ReplayAdapterError::CancellationRequested`] if cancellation was signaled.
    /// Returns [`ReplayAdapterError::BoundExceeded`] if bundle bounds exceed configuration limits.
    /// Returns [`ReplayAdapterError::BudgetExhausted`] if packet count exceeds request budget.
    pub fn execute(
        &self,
        request: &ReplayExecutionRequest,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
    ) -> Result<ReplayExecutionOutput, ReplayAdapterError> {
        if request.generation != self.config.generation {
            return Err(ReplayAdapterError::IncompatibleGeneration {
                expected: self.config.generation.clone(),
                actual: request.generation.clone(),
            });
        }
        if request.cancel_requested {
            return Err(ReplayAdapterError::CancellationRequested);
        }
        let packet_count = request.bundle.spec().packet_count as usize;
        if packet_count > self.config.max_packets {
            return Err(ReplayAdapterError::BoundExceeded("packet_count"));
        }
        if request.bundle.spec().packet_bytes > self.config.max_bytes {
            return Err(ReplayAdapterError::BoundExceeded("packet_bytes"));
        }
        if let Some(budget) = request.max_packet_budget {
            if packet_count > budget {
                return Err(ReplayAdapterError::BudgetExhausted {
                    requested: packet_count,
                    limit: budget,
                });
            }
        }

        let capture = request.bundle.replay(objects, ledger)?;
        let state_root = capture.receipt.capture_root;
        let packets_delivered = capture.receipt.delivered_packet_count;
        let packets_mutated = request
            .bundle
            .plan()
            .directives()
            .iter()
            .filter(|d| d.mutation != DeliveryMutation::Exact)
            .count();

        let mut hasher_bytes = Vec::new();
        hasher_bytes.extend_from_slice(b"fss.adapter_replay.audit.v1\0");
        hasher_bytes.extend_from_slice(&state_root.bytes());
        hasher_bytes.extend_from_slice(&(packets_delivered as u64).to_be_bytes());
        hasher_bytes.extend_from_slice(&(packets_mutated as u64).to_be_bytes());
        hasher_bytes.extend_from_slice(&capture.receipt.source_root.bytes());
        hasher_bytes.extend_from_slice(&capture.receipt.delivery_root.bytes());
        hasher_bytes.extend_from_slice(&capture.receipt.continuity_digest.bytes());
        let audit_hash = ContentDigest::sha256(&hasher_bytes);

        let audit_record = ReplayAuditRecord {
            state_root,
            audit_hash,
            packets_delivered,
            packets_mutated,
        };

        Ok(ReplayExecutionOutput {
            capture,
            audit_record,
        })
    }

    /// Executes replay and verifies the resulting state root against `expected_root`.
    ///
    /// Fails closed with [`ReplayAdapterError::ReplayDiverged`] if the actual root differs.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::ReplayDiverged`] if `expected_root` does not match.
    /// Returns any execution error returned by [`Self::execute`].
    pub fn verify_against_expected(
        &self,
        request: &ReplayExecutionRequest,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
        expected_root: &ContentDigest,
    ) -> Result<ReplayExecutionOutput, ReplayAdapterError> {
        let output = self.execute(request, objects, ledger)?;
        if output.audit_record.state_root != *expected_root {
            return Err(ReplayAdapterError::ReplayDiverged {
                expected_root: *expected_root,
                actual_root: output.audit_record.state_root,
            });
        }
        Ok(output)
    }
}
