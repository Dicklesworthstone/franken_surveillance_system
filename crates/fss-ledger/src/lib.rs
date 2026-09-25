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
mod oracle;
mod recovery;
mod repair;
mod sealed_lineage;
mod store_pin;

#[cfg(test)]
mod durable_reconciliation_tests;
#[cfg(test)]
mod journal_reconciliation_tests;
#[cfg(test)]
mod open_preflight_tests;
#[cfg(test)]
mod tests;

pub use batch_codec::{BatchCodecError, decode_batch, encode_batch};
pub use durable::{
    CommittedBatchPosition, DurableAppendReconciliation, DurableLedgerError, DurableLedgerLimits,
    DurableLedgerStatus, DurableReferenceLedger, ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001,
    HostJournalReadIo, JournalFileMetadata, JournalReadIo, LedgerInspection,
    committed_batch_positions, inspect_durable, inspect_durable_with_io,
};
pub use error::{
    AppendPhase, CorruptionKind, ERR_LEDGER_LENGTH_OVERFLOW_001, ExternalMutationKind, JournalError,
};
pub use journal::{AppendReconciliation, IncompleteTailPolicy, Journal};
pub use oracle::{
    AnchorField, AnchoredView, CommitReceipt, LEDGER_ORACLE_HISTORY_DOMAIN, LedgerOracle,
    MAX_ORACLE_BATCHES, MAX_ORACLE_CHILDREN_PER_BATCH, MAX_ORACLE_DELTAS_PER_BATCH,
    MAX_ORACLE_OBJECTS, MAX_ORACLE_TEXT_BYTES, ObjectRead, OracleBoundField, OracleConfigField,
    OracleError, OracleFingerprint, OracleGuidance, OracleLimits, OracleReadError,
    OracleReplayError, StagedBatch,
};
pub use recovery::{JournalRecord, RecoveryReport, inspect, recover_bytes};
pub use repair::{
    DoctorReport, ForeignRange, JournalDoctorReport, MAX_QUARANTINE_TEMP_ATTEMPTS,
    RepairDoctorReport, RepairError, RepairPlan, RepairReceipt, SealedRepairPlan, apply, doctor,
    doctor_bounded, doctor_bounded_with_io, doctor_path, plan, plan_with_cut, quarantine_path_for,
    quarantine_temp_path_for,
};
pub use sealed_lineage::{
    ERR_LEDGER_SEALED_NAMESPACE_001, LINEAGE_WRITE_SEAL_DOMAIN, SEALED_LINEAGE_FAMILIES,
    SEALED_LINEAGE_OBJECT_PREFIX, first_sealed_lineage_delta, is_sealed_lineage_batch,
    is_sealed_lineage_delta, lineage_write_seal,
};
pub use store_pin::{
    STORE_PIN_DOMAIN, STORE_ROLE_AUTHORITY_LEDGER, STORE_ROLE_EFFECT_JOURNAL, pin_is_current,
    store_pin_at, store_pin_of,
};

/// Maximum payload accepted by one reference-journal record.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
