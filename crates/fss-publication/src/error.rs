//! Publication-coordinator error taxonomy.

use std::error::Error;
use std::fmt;

use fss_ledger::DurableLedgerError;
use fss_object::ObjectError;

/// Failures while proving child custody or publishing authority state.
#[derive(Debug)]
pub enum PublicationError {
    /// Required immutable child object is missing, unverified, or corrupt.
    Object(ObjectError),
    /// Durable authority publication or reconciliation failed.
    Ledger(DurableLedgerError),
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Object(error) => write!(formatter, "publication object error: {error}"),
            Self::Ledger(error) => write!(formatter, "publication ledger error: {error}"),
        }
    }
}

impl Error for PublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            Self::Ledger(error) => Some(error),
        }
    }
}

impl From<ObjectError> for PublicationError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<DurableLedgerError> for PublicationError {
    fn from(value: DurableLedgerError) -> Self {
        Self::Ledger(value)
    }
}
