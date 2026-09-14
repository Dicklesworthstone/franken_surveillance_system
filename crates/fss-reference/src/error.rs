//! Stable deterministic-reference error taxonomy.

use std::error::Error;
use std::fmt;

use fss_core::{ContractError, TimestampNs};
use fss_object::ObjectError;
use fss_publication::PublicationError;

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
        }
    }
}

impl Error for ReferenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Publication(error) => Some(error),
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
            | Self::StaleEventAuthority => None,
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
