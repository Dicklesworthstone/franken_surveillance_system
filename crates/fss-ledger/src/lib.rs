#![forbid(unsafe_code)]
//! Crash-classifying append journal for FSS reference persistence.
//!
//! This crate is synchronous and dependency-free by design. It owns the deterministic
//! reference semantics for durable append/recovery. Production Asupersync and FrankenSQLite
//! adapters must prove observational equivalence to this surface before admission.

mod batch_codec;
mod durable;
mod error;
mod format;
mod journal;
mod recovery;

#[cfg(test)]
mod durable_reconciliation_tests;
#[cfg(test)]
mod journal_reconciliation_tests;
#[cfg(test)]
mod tests;

pub use batch_codec::{BatchCodecError, decode_batch, encode_batch};
pub use durable::{
    DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger,
};
pub use error::{AppendPhase, CorruptionKind, JournalError};
pub use journal::{AppendReconciliation, IncompleteTailPolicy, Journal};
pub use recovery::{JournalRecord, RecoveryReport, inspect};

/// Maximum payload accepted by one reference-journal record.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
