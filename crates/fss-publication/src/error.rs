//! Publication-coordinator error taxonomy.

use std::error::Error;
use std::fmt;

use fss_core::BatchId;
use fss_ledger::DurableLedgerError;
use fss_object::ObjectError;

/// Failures while proving child custody or publishing authority state.
#[derive(Debug)]
pub enum PublicationError {
    /// Required immutable child object is missing, unverified, or corrupt.
    Object(ObjectError),
    /// Durable authority publication or reconciliation failed.
    Ledger(DurableLedgerError),
    /// A different batch carrying an already-committed batch ID was submitted.
    DuplicateBatchId(BatchId),
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Object(error) => write!(formatter, "publication object error: {error}"),
            Self::Ledger(error) => write!(formatter, "publication ledger error: {error}"),
            Self::DuplicateBatchId(batch_id) => {
                write!(formatter, "publication duplicate batch ID: {batch_id}")
            }
        }
    }
}

impl Error for PublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::DuplicateBatchId(_) => None,
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
