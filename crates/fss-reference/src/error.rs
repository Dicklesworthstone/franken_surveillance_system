//! Stable deterministic-reference error taxonomy.

use std::error::Error;
use std::fmt;

use fss_core::ContractError;
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
            | Self::DigestMismatch => None,
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
