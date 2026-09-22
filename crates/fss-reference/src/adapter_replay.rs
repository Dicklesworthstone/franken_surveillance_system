#![forbid(unsafe_code)]
//! Deterministic replay adapter realizing row ADP-REPLAY-001.
//!
//! Provides a pure-Rust, in-process virtual device adapter that replays canonical
//! [`ReplayBundle`] workloads with reproducible state roots, verified bounds,
//! cooperative cancellation via [`ReplayCx`], explicit I/O authority via [`ReplayIoAuthority`],
//! and fail-closed divergence detection.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContentDigest,
    ContextAuthority, ContractError, CredentialMethod, IsolationMode,
};
use fss_ledger::{DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, JournalError};
use fss_object::InMemoryObjectStore;

use crate::{
    DeliveryMutation, ReferenceCapture, ReferenceError, ReplayBundle, ReplayBundleError,
    source::MAX_VIRTUAL_PACKET_BYTES,
};

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
pub const ERR_ADAPTER_REPLAY_DIVERGED: &str = "ERR-ADAPTER-REPLAY-DIVERGED-001";

/// Backward-compatible alias for the replay divergence finding code.
pub const ERR_REPLAY_DIVERGED: &str = ERR_ADAPTER_REPLAY_DIVERGED;

/// Hard ceiling on packet payload bytes (aligned with VirtualCameraSpec limits).
pub const ADP_REPLAY_MAX_PACKET_BYTES: usize = MAX_VIRTUAL_PACKET_BYTES; // 4096

/// Default maximum packet count per replay execution.
pub const ADP_REPLAY_MAX_PACKETS: usize = 10_000;

/// Default aggregate byte bound across all replayed packets.
pub const ADP_REPLAY_MAX_TOTAL_BYTES: usize = ADP_REPLAY_MAX_PACKETS * ADP_REPLAY_MAX_PACKET_BYTES;

/// Pinned golden reference state root for the canonical sample replay bundle.
pub const ADP_REPLAY_GOLDEN_STATE_ROOT: &str =
    "sha256:3fda1ae905c2331ffcf6a6f9b790b6b2e7c9e57c502c6e39f68c1afa76862b68";

/// Pinned golden reference audit hash for the canonical sample replay bundle.
pub const ADP_REPLAY_GOLDEN_AUDIT_HASH: &str =
    "sha256:fbf3b421bcbe2bf30c95cd723496087902ac25eb1a1087d63352f564a9a7e100";

/// Explicit I/O authority capability required for journal persistence and ledger access.
///
/// Unforgeable capability: cannot be fabricated without validating an authorized principal
/// and explicit capability grant matching row `ADP-REPLAY-001` from a validated [`ContextAuthority`].
///
/// Not cloneable: prevents unauthorized duplication or survival across context finalization.
///
/// # Unforgeable Authority Invariants
///
/// External crates cannot forge a [`ReplayIoAuthority`]:
///
/// ```rust,compile_fail
/// // ReplayIoAuthority::authorize_internal is private and cannot be called from outside.
/// use fss_reference::ReplayIoAuthority;
/// let _ = ReplayIoAuthority::authorize_internal(
///     "attacker",
///     "ADP-REPLAY-001",
///     std::path::PathBuf::new(),
///     std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
///     std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
/// );
/// ```
///
/// ```rust,compile_fail
/// // ReplayIoAuthority cannot be constructed with a struct literal from outside its module.
/// use fss_reference::ReplayIoAuthority;
/// let _ = ReplayIoAuthority {
///     principal: String::new(),
///     capability: String::new(),
///     root_dir: std::path::PathBuf::new(),
///     state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
///     dir_counter: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
/// };
/// ```
///
/// ```rust,compile_fail
/// // ReplayIoAuthority does not implement Clone.
/// use fss_reference::ReplayIoAuthority;
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<ReplayIoAuthority>();
/// ```
#[derive(Debug)]
pub struct ReplayIoAuthority {
    principal: String,
    capability: String,
    root_dir: PathBuf,
    state: Arc<AtomicU8>,
    dir_counter: Arc<AtomicUsize>,
}

impl PartialEq for ReplayIoAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.principal == other.principal
            && self.capability == other.capability
            && self.root_dir == other.root_dir
            && self.state.load(Ordering::SeqCst) == other.state.load(Ordering::SeqCst)
    }
}

impl Eq for ReplayIoAuthority {}

impl ReplayIoAuthority {
    fn authorize_internal(
        principal: impl Into<String>,
        capability: impl Into<String>,
        root_dir: PathBuf,
        state: Arc<AtomicU8>,
        dir_counter: Arc<AtomicUsize>,
    ) -> Result<Self, ReplayAdapterError> {
        let principal = principal.into();
        let capability = capability.into();
        if principal.trim().is_empty() {
            return Err(ReplayAdapterError::Unauthorized {
                reason: "principal cannot be empty",
            });
        }
        if capability.trim().is_empty() {
            return Err(ReplayAdapterError::Unauthorized {
                reason: "capability cannot be empty",
            });
        }
        if capability != ADP_REPLAY_ROW_ID && capability != "io:adapter:adp-replay-001" {
            return Err(ReplayAdapterError::Unauthorized {
                reason: "capability does not grant ADP-REPLAY-001 I/O authority",
            });
        }
        std::fs::create_dir_all(&root_dir).map_err(ReplayAdapterError::Io)?;
        Ok(Self {
            principal,
            capability,
            root_dir,
            state,
            dir_counter,
        })
    }

    /// Acquires authority directly from a validated root [`ContextAuthority`] with an explicit root directory.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::Unauthorized`] if the context authority lacks the required capability.
    pub fn from_context_authority(
        auth: &ContextAuthority,
        root_dir: impl Into<PathBuf>,
    ) -> Result<Self, ReplayAdapterError> {
        if !auth
            .capabilities()
            .iter()
            .any(|c| c == ADP_REPLAY_ROW_ID || c == "io:adapter:adp-replay-001")
        {
            return Err(ReplayAdapterError::Unauthorized {
                reason: "ContextAuthority does not grant ADP-REPLAY-001 capability",
            });
        }
        let root_dir = root_dir.into();
        let state = Arc::new(AtomicU8::new(STATE_ACTIVE));
        let dir_counter = Arc::new(AtomicUsize::new(0));
        Self::authorize_internal(
            &auth.principal,
            ADP_REPLAY_ROW_ID,
            root_dir,
            state,
            dir_counter,
        )
    }

    /// Alias for [`Self::from_context_authority`] with an explicit root directory.
    pub fn from_context_authority_with_root_dir(
        auth: &ContextAuthority,
        root_dir: impl Into<PathBuf>,
    ) -> Result<Self, ReplayAdapterError> {
        Self::from_context_authority(auth, root_dir)
    }

    /// Authorized principal identity.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Authorized capability string.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Base filesystem root directory for scoped ledger directories.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns `true` if authority is active and not revoked.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.state.load(Ordering::SeqCst) == STATE_ACTIVE
    }

    /// Revokes this authority, transitioning its lifecycle state to `Finalized`.
    pub fn revoke(&self) {
        self.state.store(STATE_FINALIZED, Ordering::SeqCst);
    }
}

/// Execution lifecycle state for [`ReplayCx`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReplayLifecycleState {
    /// Context is active and accepting replay execution steps.
    Active,
    /// Cancellation has been requested; rejecting new work and preparing to drain.
    CancellationRequested,
    /// Actively draining in-flight work and discarding uncommitted staging.
    Draining,
    /// Quiescence reached; terminal state after complete drain.
    Finalized,
}

impl ReplayLifecycleState {
    /// Returns the stable string representation of this lifecycle state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CancellationRequested => "cancellation_requested",
            Self::Draining => "draining",
            Self::Finalized => "finalized",
        }
    }
}

const STATE_ACTIVE: u8 = 0;
const STATE_CANCEL_REQUESTED: u8 = 1;
const STATE_DRAINING: u8 = 2;
const STATE_FINALIZED: u8 = 3;

/// Execution capability and cooperative cancellation context for replay operations.
///
/// # Unforgeable Authority Invariants
///
/// Constructing a `ReplayCx` requires a valid [`ReplayIoAuthority`]; an
/// external crate cannot fabricate one:
///
/// ```rust,compile_fail
/// use fss_reference::ReplayCx;
/// let _ = ReplayCx::for_test();
/// ```
#[derive(Debug)]
pub struct ReplayCx {
    state: Arc<AtomicU8>,
    checkpoints: AtomicUsize,
    io: ReplayIoAuthority,
    cancel_at_stage: Mutex<Option<&'static str>>,
}

impl ReplayCx {
    /// Constructs a new replay execution context with explicit I/O authority.
    #[must_use]
    pub fn new(io: ReplayIoAuthority) -> Self {
        let state = io.state.clone();
        if !io.is_valid() {
            state.store(STATE_FINALIZED, Ordering::SeqCst);
        }
        Self {
            state,
            checkpoints: AtomicUsize::new(0),
            io,
            cancel_at_stage: Mutex::new(None),
        }
    }

    /// Constructs a new replay execution context directly from a validated [`ContextAuthority`]
    /// with an explicit filesystem root directory.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::Unauthorized`] if the context authority lacks the required capability.
    pub fn from_context_authority(
        auth: &ContextAuthority,
        root_dir: impl Into<PathBuf>,
    ) -> Result<Self, ReplayAdapterError> {
        let io = ReplayIoAuthority::from_context_authority(auth, root_dir)?;
        Ok(Self::new(io))
    }

    /// Injects cooperative cancellation when the specified checkpoint stage is reached.
    /// Driver/test support for cancellation-drain evidence.
    pub fn set_cancel_at_checkpoint(&self, stage: &'static str) {
        if let Ok(mut guard) = self.cancel_at_stage.lock() {
            *guard = Some(stage);
        }
    }

    /// Current lifecycle state of this execution context.
    #[must_use]
    pub fn lifecycle_state(&self) -> ReplayLifecycleState {
        match self.state.load(Ordering::SeqCst) {
            STATE_CANCEL_REQUESTED => ReplayLifecycleState::CancellationRequested,
            STATE_DRAINING => ReplayLifecycleState::Draining,
            STATE_FINALIZED => ReplayLifecycleState::Finalized,
            _ => ReplayLifecycleState::Active,
        }
    }

    /// Signals a cooperative cancellation request, transitioning state from `Active` to `CancellationRequested`.
    pub fn request_cancellation(&self) {
        let _ = self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_CANCEL_REQUESTED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// Returns `true` if cancellation has been requested or the context has begun draining.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::SeqCst) != STATE_ACTIVE
    }

    /// Initiates the drain phase of cancellation (`CancellationRequested` -> `Draining`).
    pub fn drain(&self) {
        let _ = self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_CANCEL_REQUESTED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let _ = self.state.compare_exchange(
            STATE_CANCEL_REQUESTED,
            STATE_DRAINING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// Completes finalization of cancellation (`Draining` -> `Finalized`), revoking I/O authority.
    pub fn finalize(&self) {
        let _ = self.state.compare_exchange(
            STATE_DRAINING,
            STATE_FINALIZED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.io.revoke();
    }

    /// Completes the drain and finalize lifecycle phase, ensuring no half-published state remains.
    pub fn drain_and_finalize(&self) {
        self.drain();
        self.finalize();
    }

    /// Returns `true` if the drain/finalize cycle completed.
    #[must_use]
    pub fn is_drain_completed(&self) -> bool {
        self.state.load(Ordering::SeqCst) == STATE_FINALIZED
    }

    /// Number of cooperative checkpoints passed during execution.
    #[must_use]
    pub fn checkpoints_reached(&self) -> usize {
        self.checkpoints.load(Ordering::SeqCst)
    }

    /// Cooperative checkpoint during execution. Fails closed with [`ReplayAdapterError::CancellationRequested`]
    /// if cancellation was requested, completing the drain/finalize cycle.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::CancellationRequested`] if cancellation was signaled.
    pub fn checkpoint(&self, _stage: &'static str) -> Result<(), ReplayAdapterError> {
        self.checkpoints.fetch_add(1, Ordering::SeqCst);
        if let Ok(guard) = self.cancel_at_stage.lock()
            && let Some(target) = *guard
            && target == _stage
        {
            self.request_cancellation();
        }
        if self.is_cancelled() {
            self.drain_and_finalize();
            Err(ReplayAdapterError::CancellationRequested)
        } else {
            Ok(())
        }
    }

    /// Root filesystem path used by this context.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        self.io.root_dir()
    }

    /// Next monotonically increasing sequence number for scoped directory creation in this context.
    #[must_use]
    pub fn next_dir_sequence(&self) -> usize {
        self.io.dir_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Current sequence counter for scoped directories in this context (without incrementing).
    #[must_use]
    pub fn current_dir_sequence(&self) -> usize {
        self.io.dir_counter.load(Ordering::SeqCst)
    }

    /// Post-commit checkpoint: increments checkpoint counter and handles cancellation,
    /// but never returns an error so already-committed work is not reported as cancelled.
    pub fn checkpoint_post_commit(&self, _stage: &'static str) {
        self.checkpoints.fetch_add(1, Ordering::SeqCst);
        if let Ok(guard) = self.cancel_at_stage.lock()
            && let Some(target) = *guard
            && target == _stage
        {
            self.request_cancellation();
        }
        if self.is_cancelled() {
            self.drain_and_finalize();
        }
    }

    /// Records that execution reached the registered cooperative stage `stage`.
    ///
    /// Unlike [`Self::checkpoint`] it neither drains nor reports: the caller reads
    /// [`Self::is_cancelled`] and decides how to honor a pending cancellation at that stage.
    pub(crate) fn reach_stage(&self, _stage: &'static str) {
        self.checkpoints.fetch_add(1, Ordering::SeqCst);
        if let Ok(guard) = self.cancel_at_stage.lock()
            && let Some(target) = *guard
            && target == _stage
        {
            self.request_cancellation();
        }
    }

    /// Explicit I/O authority held by this context.
    #[must_use]
    pub const fn io_authority(&self) -> &ReplayIoAuthority {
        &self.io
    }
}

/// Maximum retry attempts to create a collision-free scoped directory.
pub const MAX_SCOPED_DIR_ATTEMPTS: usize = 10_000;

/// Default maximum existing target store objects for rollback snapshot protection.
pub const DEFAULT_MAX_ROLLBACK_SNAPSHOT_OBJECTS: usize = 65_536;

/// Default maximum existing target store bytes for rollback snapshot protection.
pub const DEFAULT_MAX_ROLLBACK_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

fn validate_scoped_dir_prefix(prefix: &str) -> Result<(), std::io::Error> {
    if prefix.is_empty()
        || !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid scoped directory prefix: must match [A-Za-z0-9_-]+ with no path separators or traversal",
        ));
    }
    Ok(())
}

fn create_exclusive_scoped_dir(
    root_dir: &Path,
    prefix: &str,
    dir_counter: &AtomicUsize,
) -> Result<PathBuf, std::io::Error> {
    validate_scoped_dir_prefix(prefix)?;
    std::fs::create_dir_all(root_dir)?;
    for _ in 0..MAX_SCOPED_DIR_ATTEMPTS {
        let seq = dir_counter.fetch_add(1, Ordering::SeqCst);
        let candidate = root_dir.join(format!("{prefix}-{seq}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "exhausted bounded retry attempts for collision-free scoped directory",
    ))
}

/// Scoped ledger directory managed with explicit I/O authority.
#[derive(Debug)]
pub struct ScopedLedgerDir {
    path: PathBuf,
    principal: String,
    created_by_instance: bool,
}

impl ScopedLedgerDir {
    /// Creates a new scoped directory requiring active execution context and unrevoked I/O authority.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] with [`std::io::ErrorKind::PermissionDenied`] if context is finalized or cancelled.
    /// Returns [`std::io::Error`] if directory prefix validation fails or creation fails.
    pub fn new(prefix: &str, cx: &ReplayCx) -> Result<Self, std::io::Error> {
        if !cx.io_authority().is_valid() || cx.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "ReplayIoAuthority revoked: context is not active",
            ));
        }
        let path = create_exclusive_scoped_dir(cx.root_dir(), prefix, &cx.io.dir_counter)?;
        Ok(Self {
            path,
            principal: cx.io_authority().principal().to_string(),
            created_by_instance: true,
        })
    }

    /// Creates a new scoped directory directly from an active [`ReplayIoAuthority`].
    ///
    /// # Errors
    /// Returns [`std::io::Error`] with [`std::io::ErrorKind::PermissionDenied`] if authority is revoked.
    /// Returns [`std::io::Error`] if directory prefix validation fails or creation fails.
    pub fn from_authority(prefix: &str, auth: &ReplayIoAuthority) -> Result<Self, std::io::Error> {
        if !auth.is_valid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "ReplayIoAuthority revoked: authority is not active",
            ));
        }
        let path = create_exclusive_scoped_dir(auth.root_dir(), prefix, &auth.dir_counter)?;
        Ok(Self {
            path,
            principal: auth.principal().to_string(),
            created_by_instance: true,
        })
    }

    /// Constructs the journal path for a named ledger in this scoped directory.
    #[must_use]
    pub fn journal_path(&self, name: &str) -> PathBuf {
        self.path.join(format!("{name}.journal"))
    }

    /// Filesystem path of this scoped directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Authorized principal who created this directory.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

impl Drop for ScopedLedgerDir {
    fn drop(&mut self) {
        if self.created_by_instance {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Operational bounds configuration for [`ReplayAdapter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAdapterConfig {
    /// Maximum allowed packet count per replay execution.
    pub max_packets: usize,
    /// Maximum allowed packet payload bytes per packet (capped by [`ADP_REPLAY_MAX_PACKET_BYTES`]).
    pub max_bytes: usize,
    /// Aggregate byte limit across all packets in the replay execution.
    pub max_total_bytes: usize,
    /// Expected adapter generation string.
    pub generation: String,
    /// Maximum allowed existing target store objects for rollback snapshot protection.
    pub max_snapshot_objects: usize,
    /// Maximum allowed existing target store bytes for rollback snapshot protection.
    pub max_snapshot_bytes: u64,
}

impl Default for ReplayAdapterConfig {
    fn default() -> Self {
        Self {
            max_packets: ADP_REPLAY_MAX_PACKETS,
            max_bytes: ADP_REPLAY_MAX_PACKET_BYTES,
            max_total_bytes: ADP_REPLAY_MAX_TOTAL_BYTES,
            generation: ADP_REPLAY_GENERATION.to_string(),
            max_snapshot_objects: DEFAULT_MAX_ROLLBACK_SNAPSHOT_OBJECTS,
            max_snapshot_bytes: DEFAULT_MAX_ROLLBACK_SNAPSHOT_BYTES,
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

/// Terminal execution status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayTerminalStatus {
    /// Replay completed and committed successfully.
    Committed,
    /// Replay committed successfully, but cancellation was requested after commit.
    CancelledAfterCommit,
}

/// Output envelope returned upon successful replay execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayExecutionOutput {
    /// Published reference capture containing retained objects and ledger anchor.
    pub capture: ReferenceCapture,
    /// Retained audit record for divergence verification.
    pub audit_record: ReplayAuditRecord,
    /// Terminal execution status.
    pub status: ReplayTerminalStatus,
}

/// Computes the domain-separated audit hash bound to the bundle digest, generation, and row ID.
#[must_use]
pub fn compute_audit_hash(
    bundle_digest: &ContentDigest,
    state_root: &ContentDigest,
    packets_delivered: usize,
    packets_mutated: usize,
    source_root: &ContentDigest,
    delivery_root: &ContentDigest,
    continuity_digest: &ContentDigest,
) -> ContentDigest {
    let mut hasher_bytes = Vec::new();
    hasher_bytes.extend_from_slice(b"fss.adapter_replay.audit.v1\0");
    hasher_bytes.extend_from_slice(ADP_REPLAY_ROW_ID.as_bytes());
    hasher_bytes.push(0);
    hasher_bytes.extend_from_slice(ADP_REPLAY_GENERATION.as_bytes());
    hasher_bytes.push(0);
    hasher_bytes.extend_from_slice(&bundle_digest.bytes());
    hasher_bytes.extend_from_slice(&state_root.bytes());
    hasher_bytes.extend_from_slice(&(packets_delivered as u64).to_be_bytes());
    hasher_bytes.extend_from_slice(&(packets_mutated as u64).to_be_bytes());
    hasher_bytes.extend_from_slice(&source_root.bytes());
    hasher_bytes.extend_from_slice(&delivery_root.bytes());
    hasher_bytes.extend_from_slice(&continuity_digest.bytes());
    ContentDigest::sha256(&hasher_bytes)
}

/// Details of cryptographic state or audit hash divergence during replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDivergence {
    /// Expected cryptographic reference state root.
    pub expected_root: ContentDigest,
    /// Actual cryptographic state root produced by replay.
    pub actual_root: ContentDigest,
    /// Expected cryptographic reference audit hash.
    pub expected_audit_hash: ContentDigest,
    /// Actual cryptographic audit hash produced by replay.
    pub actual_audit_hash: ContentDigest,
}

impl fmt::Display for ReplayDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected root {} (got {}), expected audit {} (got {})",
            self.expected_root, self.actual_root, self.expected_audit_hash, self.actual_audit_hash
        )
    }
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
    /// Replayed state root or audit hash diverged from independently retained reference proof.
    ReplayDiverged(Box<ReplayDivergence>),
    /// Discrepancy between code constants and machine registry.
    RegistryDrift {
        /// Field name that drifted.
        field: &'static str,
        /// Expected value in code.
        expected: String,
        /// Actual value found in registry.
        actual: String,
    },
    /// Unauthorized I/O authority capability or missing permissions.
    Unauthorized {
        /// Rationale for authorization denial.
        reason: &'static str,
    },
    /// Filesystem or directory operation error.
    Io(std::io::Error),
    /// Core contract error.
    Contract(ContractError),
    /// Replay bundle decoding or validation error.
    Bundle(ReplayBundleError),
    /// Underlying reference engine error.
    Reference(ReferenceError),
    /// Ledger append or journal failure.
    Ledger(JournalError),
    /// Durable reference ledger failure.
    DurableLedger(DurableLedgerError),
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
            Self::ReplayDiverged(div) => {
                write!(
                    f,
                    "[{ERR_ADAPTER_REPLAY_DIVERGED}] replay state diverged: {div}"
                )
            }
            Self::RegistryDrift {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "registry drift on field '{field}': expected '{expected}', found '{actual}'"
                )
            }
            Self::Unauthorized { reason } => write!(f, "unauthorized: {reason}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Contract(err) => write!(f, "contract error: {err}"),
            Self::Bundle(err) => write!(f, "bundle error: {err}"),
            Self::Reference(err) => write!(f, "reference error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::DurableLedger(err) => write!(f, "durable ledger error: {err}"),
        }
    }
}

impl Error for ReplayAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Contract(err) => Some(err),
            Self::Bundle(err) => Some(err),
            Self::Reference(err) => Some(err),
            Self::Ledger(err) => Some(err),
            Self::DurableLedger(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ReplayAdapterError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
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

impl From<JournalError> for ReplayAdapterError {
    fn from(err: JournalError) -> Self {
        Self::Ledger(err)
    }
}

impl From<DurableLedgerError> for ReplayAdapterError {
    fn from(err: DurableLedgerError) -> Self {
        Self::DurableLedger(err)
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
    /// Fails closed if any bound is zero, if packet payload bound exceeds [`ADP_REPLAY_MAX_PACKET_BYTES`],
    /// or if the generation string does not match [`ADP_REPLAY_GENERATION`].
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError`] if bounds are invalid, generation mismatches, or identity verification fails.
    pub fn with_config(config: ReplayAdapterConfig) -> Result<Self, ReplayAdapterError> {
        if config.max_packets == 0 {
            return Err(ReplayAdapterError::BoundExceeded(
                "max_packets cannot be zero",
            ));
        }
        if config.max_bytes == 0 || config.max_bytes > ADP_REPLAY_MAX_PACKET_BYTES {
            return Err(ReplayAdapterError::BoundExceeded("packet_bytes"));
        }
        if config.max_total_bytes == 0 {
            return Err(ReplayAdapterError::BoundExceeded(
                "max_total_bytes cannot be zero",
            ));
        }
        if config.max_snapshot_objects == 0 {
            return Err(ReplayAdapterError::BoundExceeded(
                "max_snapshot_objects cannot be zero",
            ));
        }
        if config.max_snapshot_bytes == 0 {
            return Err(ReplayAdapterError::BoundExceeded(
                "max_snapshot_bytes cannot be zero",
            ));
        }
        if config.generation != ADP_REPLAY_GENERATION {
            return Err(ReplayAdapterError::IncompatibleGeneration {
                expected: ADP_REPLAY_GENERATION.to_string(),
                actual: config.generation,
            });
        }

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

    /// Active operational configuration.
    #[must_use]
    pub const fn config(&self) -> &ReplayAdapterConfig {
        &self.config
    }

    /// Verifies that `architecture/device_adapters.json` contains a row matching
    /// the normative constants for this adapter.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::RegistryDrift`] if any field disagrees.
    pub fn verify_registry_row_constants() -> Result<(), ReplayAdapterError> {
        Self::verify_registry_row_json(include_str!("../../../architecture/device_adapters.json"))
    }

    /// Verifies that a JSON representation contains a row matching
    /// the normative constants for this adapter.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::RegistryDrift`] if any field disagrees or is missing.
    pub fn verify_registry_row_json(json_text: &str) -> Result<(), ReplayAdapterError> {
        let id_needle = format!("\"id\": \"{ADP_REPLAY_ROW_ID}\"");
        let id_pos = match json_text.find(&id_needle) {
            Some(pos) => pos,
            None => {
                return Err(ReplayAdapterError::RegistryDrift {
                    field: "id",
                    expected: ADP_REPLAY_ROW_ID.to_string(),
                    actual: "missing from architecture/device_adapters.json".to_string(),
                });
            }
        };

        let start = json_text[..id_pos].rfind('{').unwrap_or(0);
        let end = json_text[id_pos..]
            .find('}')
            .map_or(json_text.len(), |p| id_pos + p);
        let block = &json_text[start..=end];

        let checks = [
            ("surface", format!("\"surface\": \"{ADP_REPLAY_SURFACE}\"")),
            ("tier", format!("\"tier\": \"{ADP_REPLAY_TIER}\"")),
            (
                "currentState",
                format!("\"currentState\": \"{ADP_REPLAY_CURRENT_STATE}\""),
            ),
            (
                "promotionGate",
                format!("\"promotionGate\": \"{ADP_REPLAY_PROMOTION_GATE}\""),
            ),
            (
                "generation",
                format!("\"generation\": \"{ADP_REPLAY_GENERATION}\""),
            ),
        ];

        for (field, needle) in checks {
            if !block.contains(&needle) {
                return Err(ReplayAdapterError::RegistryDrift {
                    field,
                    expected: needle,
                    actual: block.to_string(),
                });
            }
        }
        Ok(())
    }

    fn preflight_request(
        &self,
        cx: &ReplayCx,
        request: &ReplayExecutionRequest,
    ) -> Result<(), ReplayAdapterError> {
        if request.generation != ADP_REPLAY_GENERATION {
            return Err(ReplayAdapterError::IncompatibleGeneration {
                expected: ADP_REPLAY_GENERATION.to_string(),
                actual: request.generation.clone(),
            });
        }
        if self.config.generation != ADP_REPLAY_GENERATION {
            return Err(ReplayAdapterError::IncompatibleGeneration {
                expected: ADP_REPLAY_GENERATION.to_string(),
                actual: self.config.generation.clone(),
            });
        }
        if request.cancel_requested || cx.is_cancelled() {
            cx.request_cancellation();
            cx.drain_and_finalize();
            return Err(ReplayAdapterError::CancellationRequested);
        }

        let packet_count = request.bundle.spec().packet_count as usize;
        let packet_bytes = request.bundle.spec().packet_bytes;

        if packet_count == 0 || packet_count > self.config.max_packets {
            return Err(ReplayAdapterError::BoundExceeded("packet_count"));
        }
        if packet_bytes == 0 || packet_bytes > self.config.max_bytes {
            return Err(ReplayAdapterError::BoundExceeded("packet_bytes"));
        }

        let total_bytes = match packet_count.checked_mul(packet_bytes) {
            Some(tb) => tb,
            None => return Err(ReplayAdapterError::BoundExceeded("total_bytes_overflow")),
        };
        if total_bytes > self.config.max_total_bytes {
            return Err(ReplayAdapterError::BoundExceeded("max_total_bytes"));
        }

        if let Some(budget) = request.max_packet_budget
            && packet_count > budget
        {
            return Err(ReplayAdapterError::BudgetExhausted {
                requested: packet_count,
                limit: budget,
            });
        }

        Ok(())
    }

    fn build_audit_record(
        &self,
        request: &ReplayExecutionRequest,
        capture: &ReferenceCapture,
    ) -> ReplayAuditRecord {
        let state_root = capture.receipt.capture_root;
        let packets_delivered = capture.receipt.delivered_packet_count;
        let packets_mutated = request
            .bundle
            .plan()
            .directives()
            .iter()
            .filter(|d| d.mutation != DeliveryMutation::Exact)
            .count();

        let bundle_digest = request.bundle.digest();
        let audit_hash = compute_audit_hash(
            &bundle_digest,
            &state_root,
            packets_delivered,
            packets_mutated,
            &capture.receipt.source_root,
            &capture.receipt.delivery_root,
            &capture.receipt.continuity_digest,
        );

        ReplayAuditRecord {
            state_root,
            audit_hash,
            packets_delivered,
            packets_mutated,
        }
    }

    /// Executes the replay request deterministically against the provided object store and ledger.
    ///
    /// Requires an explicit [`ReplayCx`] execution context.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::IncompatibleGeneration`] if the generation mismatches.
    /// Returns [`ReplayAdapterError::CancellationRequested`] if cancellation was signaled.
    /// Returns [`ReplayAdapterError::BoundExceeded`] if bundle bounds exceed configuration limits.
    /// Returns [`ReplayAdapterError::BudgetExhausted`] if packet count exceeds request budget.
    pub fn execute(
        &self,
        cx: &ReplayCx,
        request: &ReplayExecutionRequest,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
    ) -> Result<ReplayExecutionOutput, ReplayAdapterError> {
        cx.checkpoint("preflight")?;
        self.preflight_request(cx, request)?;

        // Pre-commit checkpoint (Mutant R6b)
        cx.checkpoint("run_replay")?;

        // Bound check on target store to protect rollback snapshot
        if objects.object_count() > self.config.max_snapshot_objects
            || objects.total_bytes() > self.config.max_snapshot_bytes
        {
            return Err(ReplayAdapterError::BoundExceeded(
                "target_store_exceeds_rollback_bound",
            ));
        }

        // Target commit with rollback on partial publish failure (Mutant M3)
        let backup_objects = objects.clone();
        let capture = match request.bundle.replay(objects, ledger) {
            Ok(c) => c,
            Err(err) => {
                *objects = backup_objects;
                return Err(ReplayAdapterError::Bundle(err));
            }
        };

        // Post-commit checkpoint (Mutants R6b, cancel-after-commit)
        cx.checkpoint_post_commit("compute_audit");
        let audit_record = self.build_audit_record(request, &capture);

        // Explicit terminal status: never report CancellationRequested while committed effect stands
        let status = if cx.is_cancelled() {
            ReplayTerminalStatus::CancelledAfterCommit
        } else {
            ReplayTerminalStatus::Committed
        };

        Ok(ReplayExecutionOutput {
            capture,
            audit_record,
            status,
        })
    }

    /// Executes replay against expected reference state root and audit hash.
    ///
    /// # Preflight and Validation
    /// Validates request generation, cancellation state, packet bounds, byte bounds,
    /// and caller budget via [`ReplayAdapter::preflight_request`] before isolated staging.
    ///
    /// # Staging and Fail-Closed Semantics
    /// Replay is performed in an isolated staging journal and staging object store.
    /// Both the replayed state root and the audit hash are compared against expected values.
    /// If divergence is detected, fails closed with [`ReplayAdapterError::ReplayDiverged`],
    /// discarding staging files and leaving target `objects` and `ledger` completely untouched.
    /// Only upon exact cryptographic match is publication committed into target stores.
    /// If target publication encounters a failure, target `objects` is restored to its
    /// pre-publication state to prevent orphan staged objects.
    ///
    /// # Errors
    /// Returns [`ReplayAdapterError::IncompatibleGeneration`] on generation mismatch.
    /// Returns [`ReplayAdapterError::CancellationRequested`] on cooperative cancellation.
    /// Returns [`ReplayAdapterError::BoundExceeded`] or [`ReplayAdapterError::BudgetExhausted`] on limit violations.
    /// Returns [`ReplayAdapterError::ReplayDiverged`] if `expected_root` or `expected_audit_hash` does not match.
    pub fn verify_against_expected(
        &self,
        cx: &ReplayCx,
        request: &ReplayExecutionRequest,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
        expected_root: &ContentDigest,
        expected_audit_hash: &ContentDigest,
    ) -> Result<ReplayExecutionOutput, ReplayAdapterError> {
        cx.checkpoint("preflight")?;
        self.preflight_request(cx, request)?;

        // 1. ISOLATED STAGING REPLAY
        let staging_dir = ScopedLedgerDir::new("staging_replay", cx)?;
        let staging_journal_path = staging_dir.journal_path("staging_journal");
        let mut staging_ledger = DurableReferenceLedger::open(
            &staging_journal_path,
            request.bundle.site_lineage(),
            IncompleteTailPolicy::Reject,
        )?;
        let mut staging_objects = InMemoryObjectStore::new(objects.limits());

        cx.checkpoint("staging_execute")?;
        let staged_capture = request
            .bundle
            .replay(&mut staging_objects, &mut staging_ledger)?;
        let staged_audit = self.build_audit_record(request, &staged_capture);

        // 2. COMPARE BEFORE PUBLISHING: state_root (Mutant R3) AND audit_hash (Mutant R2)
        if staged_audit.state_root != *expected_root
            || staged_audit.audit_hash != *expected_audit_hash
        {
            // Staging dir drops here and cleans up staging files (Mutant R10).
            // Neither `objects` nor `ledger` are touched.
            return Err(ReplayAdapterError::ReplayDiverged(Box::new(
                ReplayDivergence {
                    expected_root: *expected_root,
                    actual_root: staged_audit.state_root,
                    expected_audit_hash: *expected_audit_hash,
                    actual_audit_hash: staged_audit.audit_hash,
                },
            )));
        }

        // 3. CHECK CANCELLATION BEFORE COMMIT
        cx.checkpoint("publish_on_match")?;

        // 4. Bound check on target store to protect rollback snapshot
        if objects.object_count() > self.config.max_snapshot_objects
            || objects.total_bytes() > self.config.max_snapshot_bytes
        {
            return Err(ReplayAdapterError::BoundExceeded(
                "target_store_exceeds_rollback_bound",
            ));
        }

        // 5. ONLY PUBLISH ON EXACT MATCH (Root-last publication, Mutant M2 rollback)
        let backup_objects = objects.clone();
        let capture = match request.bundle.replay(objects, ledger) {
            Ok(c) => c,
            Err(err) => {
                *objects = backup_objects;
                return Err(ReplayAdapterError::Bundle(err));
            }
        };

        // 6. Explicit terminal status: if cancelled after commit, never report CancellationRequested
        // while committed effect stands.
        cx.checkpoint_post_commit("post_publish");
        let status = if cx.is_cancelled() {
            ReplayTerminalStatus::CancelledAfterCommit
        } else {
            ReplayTerminalStatus::Committed
        };

        Ok(ReplayExecutionOutput {
            capture,
            audit_record: staged_audit,
            status,
        })
    }
}
