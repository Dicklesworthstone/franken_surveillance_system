#![forbid(unsafe_code)]
//! Typed non-disclosing error surface and stable error identifiers for `fss-daemon`.
//!
//! Semantic plane: `"support"`.

use std::fmt;
use std::io;

use fss_core::{ContractError, OperationId, RegionError};
use fss_ipc::IpcError;
use fss_ledger::EpochLedgerError;
use fss_pack::{ERR_STORAGE_QUOTA_PINNED_001, PackError};
use fss_projection_store::{CombinerError, ProjectionError};
use fss_reference::ingest::live_corroborate::LiveCorroborateError;
use fss_reference::ingest::model_pool::ModelPoolError;
use fss_reference::ingest::osd_mask::OsdMaskError;
use fss_runtime::authority::AuthorityError;
use fss_runtime::effect_journal::EffectPersistenceError;
use fss_vault::SecretError;

use crate::supervisor_types::DaemonShutdownReport;

/// Plaintext secret or inline credential detected in a site manifest (`site.json`).
pub const ERR_DAEMON_SECRET_IN_MANIFEST_001: &str = "ERR-DAEMON-SECRET-IN-MANIFEST-001";
/// Site manifest failed schema, range, topology, or syntax validation.
pub const ERR_DAEMON_MANIFEST_INVALID_001: &str = "ERR-DAEMON-MANIFEST-INVALID-001";
/// Bounded control request lacked the exact canonical approval digest.
pub const ERR_DAEMON_CONTROL_APPROVAL_001: &str = "ERR-DAEMON-CONTROL-APPROVAL-001";
/// Bounded control request named an unregistered camera identifier.
pub const ERR_DAEMON_UNKNOWN_CAMERA_001: &str = "ERR-DAEMON-UNKNOWN-CAMERA-001";
/// Asupersync / canonical region tree or authority check failed.
pub const ERR_DAEMON_REGION_ERROR_001: &str = "ERR-DAEMON-REGION-ERROR-001";
/// Storage subsystem (packfile, epoch ledger, MVCC projection, or combiner) failed.
pub const ERR_DAEMON_STORAGE_001: &str = "ERR-DAEMON-STORAGE-001";
/// Perception cascade, model pool, or live corroboration subsystem failed.
pub const ERR_DAEMON_PERCEPTION_001: &str = "ERR-DAEMON-PERCEPTION-001";
/// Local UDS IPC server or client failed.
pub const ERR_DAEMON_IPC_001: &str = "ERR-DAEMON-IPC-001";
/// Vault secret resolution failed.
pub const ERR_DAEMON_VAULT_001: &str = "ERR-DAEMON-VAULT-001";
/// Filesystem or OS I/O error inside the daemon.
pub const ERR_DAEMON_IO_001: &str = "ERR-DAEMON-IO-001";
/// Daemon shutdown or lifecycle invariant failed.
pub const ERR_DAEMON_SHUTDOWN_001: &str = "ERR-DAEMON-SHUTDOWN-001";

/// Typed, non-disclosing errors returned across all `fss-daemon` subsystems.
#[derive(Debug)]
pub enum DaemonError {
    /// Site manifest contained plaintext credentials or forbidden secret fields.
    SecretInManifest {
        /// Non-secret location description (e.g., camera index or field name; never the secret).
        location: String,
        /// Non-secret explanation of why the value was refused.
        detail: String,
    },
    /// Site manifest JSON parsing or contract validation failed.
    InvalidManifest {
        /// Non-secret explanation of the validation error.
        detail: String,
    },
    /// Configuration or runtime argument is invalid.
    InvalidConfig {
        /// Non-secret explanation of the configuration error.
        detail: String,
    },
    /// Retention ring capacity is critical and 100% pinned by active holds/obligations/events.
    StorageQuotaPinned {
        /// Bytes currently pinned by holds, obligations, or active events.
        pinned_bytes: u64,
        /// Configured deployment ring capacity ceiling in bytes.
        cap_bytes: u64,
    },
    /// Underlying `fss-core` contract violation.
    Contract(ContractError),
    /// Underlying `fss-core` region tree violation.
    Region(RegionError),
    /// Underlying `fss-runtime` explicit authority violation.
    Authority(AuthorityError),
    /// Underlying `fss-pack` sealed packfile / retention / scrub error.
    Pack(PackError),
    /// Underlying `fss-ledger` segmented epoch ledger error.
    Ledger(EpochLedgerError),
    /// Underlying `fss-projection-store` MVCC projection error.
    Projection(ProjectionError),
    /// Underlying `fss-projection-store` commit coalescer error.
    Combiner(CombinerError),
    /// Underlying `fss-ipc` UDS transport or handshake error.
    Ipc(IpcError),
    /// Underlying `C5` resident model pool / two-stage cascade error.
    ModelPool(ModelPoolError),
    /// Underlying `C3` OSD ignore-region validation error.
    OsdMask(OsdMaskError),
    /// Underlying `C8` live corroboration engine error.
    Corroborate(LiveCorroborateError),
    /// Underlying `fss-vault` secret-store error.
    Vault(SecretError),
    /// Durable control custody failed; retained work must never be silently redispatched.
    ControlHistory(EffectPersistenceError),
    /// Internal synchronization primitive was poisoned.
    LockPoisoned {
        /// Static subsystem identifier.
        component: &'static str,
    },
    /// Bounded OS I/O error with static operation label.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Sanitized error detail.
        detail: String,
    },
    /// Shutdown quiescence or obligation-leak check failed.
    ShutdownViolation {
        /// Non-secret description of the unclosed work or leaked obligation.
        detail: String,
    },
    /// New supervision work was refused after admission closed for shutdown.
    ShutdownRequested,
    /// A command failed after transfer to its executor and may have changed state.
    /// It must not be automatically redispatched without reconciliation.
    ControlExecutionIndeterminate {
        /// Exact accepted command whose effects require inspection or reconciliation.
        operation_id: OperationId,
        /// Original execution error, without implying no effect occurred.
        cause: Box<DaemonError>,
    },
    /// A tick failed, but cleanup succeeded and settled accepted control ownership.
    /// Retain the verified receipt instead of losing its operation dispositions.
    RunWithControlDisposition {
        /// Original supervision failure.
        run: Box<DaemonError>,
        /// Verified cleanup and process-local control disposition.
        shutdown: Box<DaemonShutdownReport>,
    },
    /// Cleanup failed while also settling accepted control ownership. These lists
    /// describe process-local disposition, not durable recovery or effect completion.
    ShutdownWithControlDisposition {
        /// Original cleanup failure.
        cause: Box<DaemonError>,
        /// Commands cancelled before their subsystem started executing them.
        cancelled_before_execution: Vec<OperationId>,
        /// Commands whose effects require reconciliation before retry.
        indeterminate: Vec<OperationId>,
    },
    /// A supervision tick failed and its mandatory drain/finalization also failed.
    RunAndShutdown {
        /// Original supervision failure, retained as the primary machine error identity.
        run: Box<DaemonError>,
        /// Independent failure encountered while draining and finalizing the daemon.
        shutdown: Box<DaemonError>,
    },
}

impl DaemonError {
    /// Wraps an `std::io::Error` with a static operation label.
    #[must_use]
    pub fn io(operation: &'static str, err: io::Error) -> Self {
        Self::Io {
            operation,
            detail: err.to_string(),
        }
    }

    /// Returns the stable machine-readable error identifier (`ERR-...-NNN`).
    #[must_use]
    pub fn error_id(&self) -> &str {
        match self {
            Self::SecretInManifest { .. } => ERR_DAEMON_SECRET_IN_MANIFEST_001,
            Self::InvalidManifest { .. } | Self::InvalidConfig { .. } | Self::Contract(_) => {
                ERR_DAEMON_MANIFEST_INVALID_001
            }
            Self::StorageQuotaPinned { .. } => ERR_STORAGE_QUOTA_PINNED_001,
            Self::Region(_) | Self::Authority(_) => ERR_DAEMON_REGION_ERROR_001,
            Self::Pack(_) | Self::Ledger(_) | Self::Projection(_) | Self::Combiner(_) => {
                ERR_DAEMON_STORAGE_001
            }
            Self::Ipc(err) => err.error_id(),
            Self::ModelPool(err) => err.stable_id(),
            Self::OsdMask(err) => err.stable_id(),
            Self::Corroborate(err) => err.stable_id(),
            Self::Vault(err) => err.error_id(),
            Self::ControlHistory(EffectPersistenceError::Capacity) => "ERR-BUDGET-EXHAUSTED-001",
            Self::ControlHistory(_) => fss_core::ERR_OP_RECONCILIATION_REQUIRED_001,
            Self::LockPoisoned { .. } | Self::ShutdownViolation { .. } => ERR_DAEMON_SHUTDOWN_001,
            Self::Io { .. } => ERR_DAEMON_IO_001,
            Self::ShutdownRequested => fss_ipc::ERR_IPC_SERVER_SHUTDOWN_001,
            Self::ControlExecutionIndeterminate { .. } => "ERR-EFFECT-INDETERMINATE-001",
            Self::RunWithControlDisposition { run, .. } | Self::RunAndShutdown { run, .. } => {
                run.error_id()
            }
            Self::ShutdownWithControlDisposition { cause, .. } => cause.error_id(),
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretInManifest { location, detail } => write!(
                f,
                "{ERR_DAEMON_SECRET_IN_MANIFEST_001}: plaintext secret refused at {location}: {detail}"
            ),
            Self::InvalidManifest { detail } => {
                write!(
                    f,
                    "{ERR_DAEMON_MANIFEST_INVALID_001}: invalid site manifest: {detail}"
                )
            }
            Self::InvalidConfig { detail } => {
                write!(
                    f,
                    "{ERR_DAEMON_MANIFEST_INVALID_001}: invalid daemon config: {detail}"
                )
            }
            Self::StorageQuotaPinned {
                pinned_bytes,
                cap_bytes,
            } => write!(
                f,
                "{ERR_STORAGE_QUOTA_PINNED_001}: storage ring pinned at {pinned_bytes}/{cap_bytes} bytes by active holds, obligations, or events"
            ),
            Self::Contract(err) => write!(f, "contract error: {err}"),
            Self::Region(err) => write!(f, "region tree error: {err}"),
            Self::Authority(err) => write!(f, "runtime authority error: {err}"),
            Self::Pack(err) => write!(f, "pack store error: {err}"),
            Self::Ledger(err) => write!(f, "epoch ledger error: {err}"),
            Self::Projection(err) => write!(f, "projection store error: {err}"),
            Self::Combiner(err) => write!(f, "commit combiner error: {err}"),
            Self::Ipc(err) => write!(f, "local IPC error: {err}"),
            Self::ModelPool(err) => write!(f, "model pool error: {err}"),
            Self::OsdMask(err) => write!(f, "OSD ignore-region error: {err}"),
            Self::Corroborate(err) => write!(f, "live corroboration error: {err}"),
            Self::Vault(err) => write!(f, "vault error: {err}"),
            Self::ControlHistory(err) => write!(
                f,
                "durable control history: {err}; preserve custody and inspect before retry; no command replay authorized"
            ),
            Self::LockPoisoned { component } => {
                write!(
                    f,
                    "internal lock poisoned in daemon component `{component}`"
                )
            }
            Self::Io { operation, detail } => {
                write!(f, "daemon I/O error during {operation}: {detail}")
            }
            Self::ShutdownViolation { detail } => {
                write!(
                    f,
                    "{ERR_DAEMON_SHUTDOWN_001}: shutdown quiescence failed: {detail}"
                )
            }
            Self::ShutdownRequested => {
                write!(
                    f,
                    "daemon shutdown requested; no new supervision tick admitted"
                )
            }
            Self::ControlExecutionIndeterminate {
                operation_id,
                cause,
            } => write!(
                f,
                "ERR-EFFECT-INDETERMINATE-001: operation {operation_id} may have changed state: {cause}; inspect or reconcile before retry"
            ),
            Self::RunWithControlDisposition { run, shutdown } => write!(
                f,
                "{run}; daemon cleanup verified: receipt={} control_disposition={}",
                shutdown.receipt_digest.to_text(),
                shutdown.control_disposition.to_json(),
            ),
            Self::ShutdownWithControlDisposition {
                cause,
                cancelled_before_execution,
                indeterminate,
            } => write!(
                f,
                "{cause}; process-local controls cancelled_before_execution={cancelled_before_execution:?} indeterminate={indeterminate:?}; no durable control recovery claimed"
            ),
            Self::RunAndShutdown { run, shutdown } => {
                write!(f, "{run}; daemon shutdown also failed: {shutdown}")
            }
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ControlHistory(error) => Some(error),
            Self::RunWithControlDisposition { run, .. } | Self::RunAndShutdown { run, .. } => {
                Some(run.as_ref())
            }
            Self::ControlExecutionIndeterminate { cause, .. }
            | Self::ShutdownWithControlDisposition { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

impl From<ContractError> for DaemonError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<RegionError> for DaemonError {
    fn from(value: RegionError) -> Self {
        Self::Region(value)
    }
}
impl From<AuthorityError> for DaemonError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}
impl From<PackError> for DaemonError {
    fn from(value: PackError) -> Self {
        Self::Pack(value)
    }
}
impl From<EpochLedgerError> for DaemonError {
    fn from(value: EpochLedgerError) -> Self {
        Self::Ledger(value)
    }
}
impl From<ProjectionError> for DaemonError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}
impl From<CombinerError> for DaemonError {
    fn from(value: CombinerError) -> Self {
        Self::Combiner(value)
    }
}
impl From<IpcError> for DaemonError {
    fn from(value: IpcError) -> Self {
        Self::Ipc(value)
    }
}
impl From<ModelPoolError> for DaemonError {
    fn from(value: ModelPoolError) -> Self {
        Self::ModelPool(value)
    }
}
impl From<OsdMaskError> for DaemonError {
    fn from(value: OsdMaskError) -> Self {
        Self::OsdMask(value)
    }
}
impl From<LiveCorroborateError> for DaemonError {
    fn from(value: LiveCorroborateError) -> Self {
        Self::Corroborate(value)
    }
}
impl From<SecretError> for DaemonError {
    fn from(value: SecretError) -> Self {
        Self::Vault(value)
    }
}
