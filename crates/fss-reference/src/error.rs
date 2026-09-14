//! Stable deterministic-reference error taxonomy.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use fss_core::{ContentDigest, ContractError, TimestampNs};
use fss_ledger::{DurableLedgerError, JournalError, RepairError};
use fss_object::{ObjectError, SpoolError};
use fss_publication::{CapacityResource, LocalPublicationError, PublicationError, RootLedgerError};

use crate::durable_effect::DurableEffectError;

/// Failures from virtual source generation, transport replay, custody, or publication.
#[derive(Debug)]
pub enum ReferenceError {
    /// Core identifier/time/evidence contract failure.
    Contract(ContractError),
    /// Immutable object custody failure.
    Object(ObjectError),
    /// Child-first authority publication failure.
    Publication(PublicationError),
    /// Virtual-camera specification violates a declared bound.
    InvalidSpec(&'static str),
    /// Delivery plan names a source sequence outside the capture.
    UnknownSourceSequence(u64),
    /// Checked arithmetic for virtual time or indexing overflowed.
    ArithmeticOverflow,
    /// A stored object digest disagreed with the reference packet digest.
    DigestMismatch,
    /// An attempt to step virtual time backwards was rejected to preserve monotonicity.
    BackwardStepAttempt {
        /// Current virtual time.
        current: TimestampNs,
        /// Attempted non-monotonic virtual time.
        attempted: TimestampNs,
    },
    /// Virtual clock configuration or parameter is invalid.
    InvalidClockParameter(&'static str),
    /// Virtual source emission produced an indeterminate or non-success outcome.
    IndeterminateSourceCapture {
        /// 1-based packet sequence where indeterminacy occurred.
        sequence: u64,
        /// Reason for indeterminate read.
        reason: String,
    },
    /// Virtual source emission was refused or unobservable.
    UnobservableSourceCapture {
        /// 1-based packet sequence where unobservability occurred.
        sequence: u64,
        /// Reason for unobservable read.
        reason: String,
    },
    /// Virtual source emission encountered an operational execution failure.
    ExecutionFailedSourceCapture {
        /// 1-based packet sequence where execution failure occurred.
        sequence: u64,
        /// Reason for failure.
        reason: String,
    },
    /// Insufficient synchronization samples were provided to compute an offset/skew fit.
    InsufficientSyncSamples {
        /// Number of samples provided.
        count: usize,
        /// Minimum required samples.
        minimum_required: usize,
    },
    /// Synchronization samples are non-monotonic in reference or sensor time.
    NonMonotonicSyncSamples {
        /// Previous timestamp.
        previous: TimestampNs,
        /// Current non-monotonic timestamp.
        current: TimestampNs,
    },
    /// Synchronization samples have non-monotonic sequence numbers.
    NonMonotonicSyncSequence {
        /// Previous sequence number.
        previous: u64,
        /// Current non-monotonic sequence number.
        current: u64,
    },
    /// Synchronization fit is dominated by outliers exceeding tolerance.
    OutlierDominatedFit {
        /// Number of outliers detected.
        outlier_count: usize,
        /// Total sample count.
        total_samples: usize,
        /// Maximum residual observed in nanoseconds.
        max_residual_ns: u64,
    },
    /// Clock synchronization estimate has expired or is requested outside its validity interval.
    StaleEstimatePastValidity {
        /// Timestamp requested.
        requested: TimestampNs,
        /// Upper bound of estimate validity.
        valid_until: TimestampNs,
    },
    /// A new synchronization sample contradicts the active clock estimate.
    ContradictedEstimate {
        /// Expected offset in nanoseconds.
        expected_offset_ns: i64,
        /// Observed offset in nanoseconds.
        observed_offset_ns: i64,
        /// Absolute deviation in nanoseconds.
        deviation_ns: u64,
    },
    /// Clock offset/skew estimator configuration violates a documented bound.
    InvalidEstimatorConfig {
        /// Offending `EstimatorConfig` field name.
        parameter: &'static str,
        /// Offending value.
        value: u64,
        /// The documented bound the value violates.
        requirement: &'static str,
    },
    /// Event authority in the ledger is stale or has moved since the alert plan was prepared.
    StaleEventAuthority,
    /// Durable journal transition write failure.
    DurableTransitionFailed(Box<crate::durable_effect::DurableEffectError>),
    /// Durable event authority could not be read or verified at alert dispatch (a missing path,
    /// an I/O failure, or an unresolved ledger append). Dispatch fails closed: it is refused and
    /// the prepared operation is cancelled.
    AuthorityLedgerUnreadable(Box<fss_ledger::DurableLedgerError>),
    /// The reference deployment root is already locked by another active instance.
    DeploymentLocked {
        /// Filesystem path of the root or lock file that is locked.
        path: PathBuf,
    },
    /// A deployment journal ends in an incomplete tail; repair is required.
    IncompleteJournalTail {
        /// Byte offset where the incomplete record begins.
        offset: u64,
        /// Journal path.
        path: PathBuf,
        /// Next affordance guidance for repair.
        next_affordance: String,
    },
    /// Cooperative cancellation was requested at the named checkpoint stage.
    CancellationRequested {
        /// The checkpoint stage where cancellation was requested.
        stage: &'static str,
    },
    /// A directory exists and is non-empty but is not a valid deployment root (missing LAYOUT).
    NotADeployment {
        /// Root path that failed deployment validation.
        path: PathBuf,
    },
    /// A deployment capacity limit was exceeded.
    CapacityExceeded {
        /// Named limit.
        limit: &'static str,
        /// Declared maximum bound.
        maximum: u64,
        /// Actual requested value.
        actual: u64,
    },
    /// A bounded publication directory scan found more entries than its bound admits.
    ///
    /// The scan stops at the first entry past `maximum` and never lists the rest of the
    /// directory, so the entry count is known only as the lower bound `at_least`. `maximum` is
    /// `scan_max_objects` for the `roots/` and `tombstones/` directories, and a fixed internal
    /// bound for the publisher's top-level directory.
    ScanLimitExceeded {
        /// Directory whose scan stopped.
        directory: PathBuf,
        /// Scan bound applied to that directory.
        maximum: u64,
        /// Lower bound on the directory's entry count; it may hold more.
        at_least: u64,
    },
    /// A reserved ledger delta family was offered to the public batch append.
    ///
    /// Such a delta is committed only through its guarded entry point, named here.
    ReservedDeltaFamily {
        /// The reserved family offered.
        family: String,
        /// The deployment entry point that owns the family.
        entry_point: &'static str,
    },
    /// Recovery was refused because foreign bytes contain a structurally valid committed record.
    RecoverCorruptHistory {
        /// Journal path containing the corrupt history.
        path: PathBuf,
        /// Byte offset where a structurally valid record was discovered.
        offset: u64,
    },
    /// Recovery was refused because the supplied repair plan digest does not match the journal plan.
    PlanDigestMismatch {
        /// Expected plan digest.
        expected: ContentDigest,
        /// Computed actual plan digest.
        actual: ContentDigest,
    },
    /// Recovery was requested to truncate an incomplete tail but no incomplete tail was found.
    NoIncompleteTail {
        /// Journal path inspected.
        path: PathBuf,
    },
    /// Deployment site lineage does not match the configured or expected lineage.
    SiteLineageMismatch {
        /// Expected site lineage.
        expected: String,
        /// Actual site lineage found in layout.
        actual: String,
    },
    /// Deployment limits digest does not match the configured limits digest.
    LimitsDigestMismatch {
        /// Expected limits digest.
        expected: ContentDigest,
        /// Actual limits digest found in layout.
        actual: ContentDigest,
    },
    /// Ledger repair operation failure.
    Repair(Box<RepairError>),
    /// Low-level journal framing or I/O failure.
    Journal(JournalError),
    /// Local root publication failure.
    LocalPublication(Box<LocalPublicationError>),
    /// Root-ledger coordinator failure.
    RootLedger(Box<RootLedgerError>),
    /// Durable ledger failure.
    DurableLedger(Box<DurableLedgerError>),
    /// Durable effect journal failure.
    DurableEffect(Box<DurableEffectError>),
    /// Host filesystem I/O failure.
    Io(std::io::Error),
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "reference contract error: {error}"),
            Self::Object(error) => write!(formatter, "reference object error: {error}"),
            Self::Publication(error) => write!(formatter, "reference publication error: {error}"),
            Self::InvalidSpec(field) => {
                write!(formatter, "invalid virtual-camera specification: {field}")
            }
            Self::UnknownSourceSequence(sequence) => {
                write!(
                    formatter,
                    "delivery plan names unknown source sequence {sequence}"
                )
            }
            Self::ArithmeticOverflow => formatter.write_str("reference arithmetic overflow"),
            Self::DigestMismatch => formatter.write_str("reference object digest mismatch"),
            Self::BackwardStepAttempt { current, attempted } => {
                write!(
                    formatter,
                    "virtual clock backward-step attempt rejected: current {current}, attempted {attempted}"
                )
            }
            Self::InvalidClockParameter(param) => {
                write!(formatter, "invalid virtual clock parameter: {param}")
            }
            Self::IndeterminateSourceCapture { sequence, reason } => {
                write!(
                    formatter,
                    "virtual source emission indeterminate at sequence {sequence}: {reason}"
                )
            }
            Self::UnobservableSourceCapture { sequence, reason } => {
                write!(
                    formatter,
                    "virtual source emission unobservable at sequence {sequence}: {reason}"
                )
            }
            Self::ExecutionFailedSourceCapture { sequence, reason } => {
                write!(
                    formatter,
                    "virtual source emission failed at sequence {sequence}: {reason}"
                )
            }
            Self::InsufficientSyncSamples {
                count,
                minimum_required,
            } => {
                write!(
                    formatter,
                    "insufficient synchronization samples: {count} provided, minimum {minimum_required} required"
                )
            }
            Self::NonMonotonicSyncSamples { previous, current } => {
                write!(
                    formatter,
                    "synchronization samples are non-monotonic: previous {previous}, current {current}"
                )
            }
            Self::NonMonotonicSyncSequence { previous, current } => {
                write!(
                    formatter,
                    "synchronization sequences are non-monotonic: previous {previous}, current {current}"
                )
            }
            Self::OutlierDominatedFit {
                outlier_count,
                total_samples,
                max_residual_ns,
            } => {
                write!(
                    formatter,
                    "clock sync fit is outlier-dominated: {outlier_count}/{total_samples} outliers, max residual {max_residual_ns} ns"
                )
            }
            Self::StaleEstimatePastValidity {
                requested,
                valid_until,
            } => {
                write!(
                    formatter,
                    "clock sync estimate is stale past validity interval: requested {requested}, valid until {valid_until}"
                )
            }
            Self::ContradictedEstimate {
                expected_offset_ns,
                observed_offset_ns,
                deviation_ns,
            } => {
                write!(
                    formatter,
                    "clock sync estimate contradicted by new sample: expected offset {expected_offset_ns} ns, observed {observed_offset_ns} ns, deviation {deviation_ns} ns"
                )
            }
            Self::InvalidEstimatorConfig {
                parameter,
                value,
                requirement,
            } => {
                write!(
                    formatter,
                    "invalid clock estimator configuration: {parameter} = {value} ({requirement})"
                )
            }
            Self::StaleEventAuthority => {
                formatter.write_str("event authority in the ledger is stale or has moved")
            }
            Self::DurableTransitionFailed(error) => {
                write!(formatter, "durable journal transition failed: {error}")
            }
            Self::AuthorityLedgerUnreadable(error) => {
                write!(
                    formatter,
                    "event authority ledger could not be verified: {error}"
                )
            }
            Self::DeploymentLocked { path } => {
                write!(
                    formatter,
                    "reference deployment is locked: {}",
                    path.display()
                )
            }
            Self::IncompleteJournalTail {
                offset,
                path,
                next_affordance,
            } => {
                write!(
                    formatter,
                    "incomplete journal tail at offset {offset} in {}: {next_affordance}",
                    path.display()
                )
            }
            Self::CancellationRequested { stage } => {
                write!(
                    formatter,
                    "cooperative cancellation requested at stage '{stage}'"
                )
            }
            Self::NotADeployment { path } => {
                write!(
                    formatter,
                    "directory is not a valid reference deployment: {}",
                    path.display()
                )
            }
            Self::CapacityExceeded {
                limit,
                maximum,
                actual,
            } => {
                write!(
                    formatter,
                    "deployment capacity limit exceeded: {limit} (maximum {maximum}, actual {actual})"
                )
            }
            Self::ScanLimitExceeded {
                directory,
                maximum,
                at_least,
            } => {
                write!(
                    formatter,
                    "deployment directory {} holds at least {at_least} entries; its scan bound is {maximum}",
                    directory.display()
                )
            }
            Self::ReservedDeltaFamily {
                family,
                entry_point,
            } => {
                write!(
                    formatter,
                    "ledger delta family {family} is reserved; commit it through {entry_point}"
                )
            }
            Self::RecoverCorruptHistory { path, offset } => {
                write!(
                    formatter,
                    "refusing recovery due to corrupt committed history at offset {offset} in {}",
                    path.display()
                )
            }
            Self::PlanDigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "repair plan digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::NoIncompleteTail { path } => {
                write!(
                    formatter,
                    "no incomplete journal tail found in {}",
                    path.display()
                )
            }
            Self::SiteLineageMismatch { expected, actual } => {
                write!(
                    formatter,
                    "deployment site_lineage mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::LimitsDigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "deployment limits_digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::Repair(error) => write!(formatter, "reference ledger repair error: {error}"),
            Self::Journal(error) => write!(formatter, "reference journal error: {error}"),
            Self::LocalPublication(error) => {
                write!(formatter, "reference local publication error: {error}")
            }
            Self::RootLedger(error) => {
                write!(formatter, "reference root ledger error: {error}")
            }
            Self::DurableLedger(error) => {
                write!(formatter, "reference durable ledger error: {error}")
            }
            Self::DurableEffect(error) => {
                write!(formatter, "reference durable effect error: {error}")
            }
            Self::Io(error) => write!(formatter, "reference io error: {error}"),
        }
    }
}

impl ReferenceError {
    /// Returns true if this error indicates the deployment root is locked.
    #[must_use]
    pub const fn is_deployment_locked(&self) -> bool {
        matches!(self, Self::DeploymentLocked { .. })
    }

    /// Returns true if this error indicates the path is not a deployment root.
    #[must_use]
    pub const fn is_not_a_deployment(&self) -> bool {
        matches!(self, Self::NotADeployment { .. })
    }

    /// Returns true if this error indicates a capacity limit was exceeded, including a bounded
    /// directory scan that stopped past its bound.
    #[must_use]
    pub const fn is_capacity_exceeded(&self) -> bool {
        matches!(
            self,
            Self::CapacityExceeded { .. } | Self::ScanLimitExceeded { .. }
        )
    }

    /// Returns true if this error indicates recovery was refused due to corrupt history.
    #[must_use]
    pub const fn is_recover_corrupt_history(&self) -> bool {
        matches!(self, Self::RecoverCorruptHistory { .. })
    }
}

impl Error for ReferenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::Repair(error) => Some(error.as_ref()),
            Self::Journal(error) => Some(error),
            Self::LocalPublication(error) => Some(error.as_ref()),
            Self::RootLedger(error) => Some(error.as_ref()),
            Self::DurableLedger(error) => Some(error.as_ref()),
            Self::DurableEffect(error) => Some(error.as_ref()),
            Self::Io(error) => Some(error),
            Self::InvalidSpec(_)
            | Self::UnknownSourceSequence(_)
            | Self::ArithmeticOverflow
            | Self::DigestMismatch
            | Self::BackwardStepAttempt { .. }
            | Self::InvalidClockParameter(_)
            | Self::IndeterminateSourceCapture { .. }
            | Self::UnobservableSourceCapture { .. }
            | Self::ExecutionFailedSourceCapture { .. }
            | Self::InsufficientSyncSamples { .. }
            | Self::NonMonotonicSyncSamples { .. }
            | Self::NonMonotonicSyncSequence { .. }
            | Self::OutlierDominatedFit { .. }
            | Self::StaleEstimatePastValidity { .. }
            | Self::ContradictedEstimate { .. }
            | Self::InvalidEstimatorConfig { .. }
            | Self::StaleEventAuthority
            | Self::DeploymentLocked { .. }
            | Self::IncompleteJournalTail { .. }
            | Self::CancellationRequested { .. }
            | Self::NotADeployment { .. }
            | Self::CapacityExceeded { .. }
            | Self::ScanLimitExceeded { .. }
            | Self::ReservedDeltaFamily { .. }
            | Self::RecoverCorruptHistory { .. }
            | Self::PlanDigestMismatch { .. }
            | Self::NoIncompleteTail { .. }
            | Self::SiteLineageMismatch { .. }
            | Self::LimitsDigestMismatch { .. } => None,
            Self::DurableTransitionFailed(error) => Some(error.as_ref()),
            Self::AuthorityLedgerUnreadable(error) => Some(error.as_ref()),
        }
    }
}

impl From<ContractError> for ReferenceError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ObjectError> for ReferenceError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<PublicationError> for ReferenceError {
    fn from(value: PublicationError) -> Self {
        Self::Publication(value)
    }
}

impl From<RepairError> for ReferenceError {
    fn from(value: RepairError) -> Self {
        Self::Repair(Box::new(value))
    }
}

impl From<JournalError> for ReferenceError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<LocalPublicationError> for ReferenceError {
    fn from(value: LocalPublicationError) -> Self {
        match value {
            LocalPublicationError::Locked { path } => Self::DeploymentLocked { path },
            LocalPublicationError::Cancelled { point } => Self::CancellationRequested {
                stage: crate::reference_deployment::publish_cut_point_stage(point),
            },
            LocalPublicationError::Spool(SpoolError::ByteQuotaExceeded {
                current,
                requested,
                maximum,
            }) => Self::CapacityExceeded {
                limit: "spool_total_max_bytes",
                maximum,
                actual: current.saturating_add(requested),
            },
            LocalPublicationError::Spool(SpoolError::ObjectCountLimit { current, maximum }) => {
                Self::CapacityExceeded {
                    limit: "spool_max_objects",
                    maximum: maximum as u64,
                    actual: (current + 1) as u64,
                }
            }
            LocalPublicationError::Spool(SpoolError::ObjectTooLarge { length, maximum }) => {
                Self::CapacityExceeded {
                    limit: "spool_object_max_bytes",
                    maximum: maximum as u64,
                    actual: length as u64,
                }
            }
            LocalPublicationError::Capacity {
                resource,
                current,
                maximum,
            } => {
                let limit = match resource {
                    CapacityResource::Roots => "max_roots",
                    CapacityResource::Tombstones => "max_tombstones",
                };
                Self::CapacityExceeded {
                    limit,
                    maximum: maximum as u64,
                    actual: (current + 1) as u64,
                }
            }
            LocalPublicationError::ManifestChildBound { count, maximum } => {
                Self::CapacityExceeded {
                    limit: "manifest_children_max",
                    maximum: maximum as u64,
                    actual: count as u64,
                }
            }
            LocalPublicationError::EntryLimit {
                directory,
                maximum,
                at_least,
            } => Self::ScanLimitExceeded {
                directory,
                maximum: maximum as u64,
                at_least: at_least as u64,
            },
            other => Self::LocalPublication(Box::new(other)),
        }
    }
}

impl From<RootLedgerError> for ReferenceError {
    fn from(value: RootLedgerError) -> Self {
        match value {
            RootLedgerError::Local(local) => Self::from(local),
            other => Self::RootLedger(Box::new(other)),
        }
    }
}

impl From<DurableLedgerError> for ReferenceError {
    fn from(value: DurableLedgerError) -> Self {
        Self::DurableLedger(Box::new(value))
    }
}

impl From<DurableEffectError> for ReferenceError {
    fn from(value: DurableEffectError) -> Self {
        Self::DurableEffect(Box::new(value))
    }
}

impl From<std::io::Error> for ReferenceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
