#![forbid(unsafe_code)]
//! Crash-classifying append journal for FSS reference persistence.
//!
//! This crate is synchronous and dependency-free by design. It owns the deterministic
//! reference semantics for durable append/recovery. Production Asupersync and FrankenSQLite
//! adapters must prove observational equivalence to this surface before admission.

mod backend;
mod batch_codec;
mod combiner;
/// Counterfactual branch overlay and live-intent recompilation (`FSS-108`, `fss-x4a.9.15`).
pub mod counterfactual;
mod cursor;
mod durable;
pub mod epochs;
mod error;
mod format;
mod high_water;
mod journal;
/// Intent-replay / structural / commutative merge certificate ladder (`FSS-105`, `fss-x4a.9.12`).
pub mod merge_ladder;
pub mod merkle;
mod oracle;
mod recovery;
mod repair;
/// Versioned ledger schema catalog and crash-safe root-last v1 -> v2 durable migration engine (`FSS-033`, `fss-x4a.9.3`).
pub mod schema_migrations;
mod sealed_lineage;
/// Negative-read phantom and SSI write-skew schedule corpus (`FSS-106`, `fss-x4a.9.13`).
pub mod ssi_corpus;
/// FrankenSQLite storage integration trait and reference/durable/Merkle adapters (`FSS-031`, `fss-x4a.9.1`).
pub mod storage_adapter;
/// Deterministic FrankenSQLite API qualification suite and certificate (`FSS-032`, `fss-x4a.9.2`).
pub mod storage_qualification;
mod store_pin;
mod witness;

#[cfg(test)]
mod durable_reconciliation_tests;
#[cfg(test)]
mod journal_reconciliation_tests;
#[cfg(test)]
mod open_preflight_tests;
#[cfg(test)]
mod tests;

pub use backend::CanonicalLedgerBackend;
pub use batch_codec::{BatchCodecError, decode_batch, encode_batch};
pub use combiner::{
    CombinerGuidance, CombiningRoundOutcome, CommitCombinerError, CommitIntent, ConflictKind,
    ConflictWitness, DeterministicCommitCombiner, IntentAuthorityContext, IntentCommitReceipt,
    IntentOutcome, LEDGER_COMMIT_COMBINER_ROUND_DOMAIN, LEDGER_COMMIT_INTENT_DOMAIN,
    MAX_COMBINER_ROUND_INTENTS, MAX_IDEMPOTENCY_HISTORY, MAX_INTENT_CHILDREN, MAX_INTENT_ID_BYTES,
    MAX_INTENT_READ_WITNESSES, MAX_INTENT_WRITES,
};
pub use counterfactual::{
    BranchAuthorityContext, COUNTERFACTUAL_RECEIPT_MAGIC, COUNTERFACTUAL_RECEIPT_VERSION,
    CounterfactualBranchOverlay, CounterfactualError, CounterfactualGuidance,
    CounterfactualRecompileReceipt, LEDGER_COUNTERFACTUAL_RECEIPT_DOMAIN,
    MAX_COUNTERFACTUAL_LABEL_BYTES, MAX_COUNTERFACTUAL_WIRE_BYTES, MAX_OVERLAY_DELTAS,
    OverlayReadState, RecompileOutcome, RecompileRefusalReason, RecompileStrategy,
};
pub use cursor::{
    LEDGER_REPLAY_CURSOR_DOMAIN, LEDGER_REPLAY_CURSOR_MAGIC, LEDGER_REPLAY_CURSOR_VERSION,
    LedgerReplayCursor, MAX_REPLAY_CURSOR_BYTES, MAX_REPLAY_PAGE_BATCHES, MAX_REPLAY_PAGE_BYTES,
    ReplayCursorError, ReplayCursorGuidance, ReplayPage, ReplayPageBudget,
};
pub use durable::{
    CommittedBatchPosition, DurableAppendReconciliation, DurableLedgerError, DurableLedgerLimits,
    DurableLedgerStatus, DurableReferenceLedger, ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001,
    HostJournalReadIo, JournalFileMetadata, JournalReadIo, LedgerInspection,
    committed_batch_positions, inspect_durable, inspect_durable_with_io,
};
pub use epochs::{
    ArchivedEpochEntry, CHECKPOINT_DOMAIN, CHECKPOINT_FORMAT_VERSION, CHECKPOINT_MAGIC,
    CheckpointCorruptionKind, CheckpointData, CheckpointSummary, DEFAULT_CHECKPOINT_STRIDE,
    DEFAULT_MAX_BATCHES_PER_EPOCH, DEFAULT_MAX_EPOCH_BYTES, EPOCH_ARCHIVAL_RECEIPT_DOMAIN,
    EPOCH_ARCHIVAL_RECEIPT_MAGIC, EPOCH_ARCHIVAL_RECEIPT_VERSION, EPOCH_FILE_MAGIC,
    EPOCH_FORMAT_VERSION, EPOCH_HEADER_DOMAIN, EPOCH_HEADER_LEN, EPOCH_HISTORY_DOMAIN,
    EPOCH_RECORD_HEADER_LEN, EPOCH_RECORD_MAGIC, EPOCH_RECORD_TRAILER_LEN, EPOCH_TRAILER_MAGIC,
    EpochAppendReconciliation, EpochArchivalError, EpochArchivalPolicy, EpochArchivalReceipt,
    EpochCorruptionKind, EpochHeader, EpochLedgerConfig, EpochLedgerError, EpochLedgerInspection,
    EpochRecord, EpochScanReport, EpochVerificationReport, MIN_MAX_EPOCH_BYTES, MerkleEpochLedger,
    OpenRecoverySummary, archive_sealed_epochs, checkpoint_file_path, crc32_ieee, epoch_file_path,
    genesis_history_root_v2, inspect_epochs_readonly, read_and_verify_checkpoint,
    successor_history_root_v2,
};
pub use error::{
    AppendPhase, CorruptionKind, ERR_LEDGER_LENGTH_OVERFLOW_001, ExternalMutationKind, JournalError,
};
pub use high_water::{
    DERIVED_HIGH_WATER_DOMAIN, DerivedCacheKind, DerivedGenerationPin, DerivedHighWaterState,
    HIGH_WATER_MAGIC, HIGH_WATER_VERSION, HighWaterError, HighWaterGuidance, HighWaterPlan,
    HighWaterProtocol, MAX_HIGH_WATER_WIRE_BYTES, RebuildReason,
};
pub use journal::{AppendReconciliation, IncompleteTailPolicy, Journal};
pub use merge_ladder::{
    CommutativeFamilyRegistry, IntentReplayFn, LEDGER_MERGE_CERTIFICATE_DOMAIN,
    MAX_MERGE_CERT_WIRE_BYTES, MAX_MERGE_INTERVENING_BATCHES, MAX_MERGE_LABEL_BYTES,
    MERGE_CERT_MAGIC, MERGE_CERT_VERSION, MergeCertificate, MergeGuidance, MergeLadder,
    MergeLadderError, MergeOutcome, MergeRefusalReason, MergeRung,
};
pub use merkle::{
    KEY_NIBBLE_LEN, MERKLE_EMPTY_DOMAIN, MERKLE_KEY_DOMAIN, MERKLE_LEAF_DOMAIN, MERKLE_NODE_DOMAIN,
    MerkleError, MerkleNodeSnapshot, MerkleProof, MerkleProofError, MerkleProofKind,
    MerkleProofStep, NonInclusionReason, RadixMerkleTrie, empty_root, expand_nibbles,
    internal_node_digest, key_hash_for_object, leaf_digest, merkle_genesis_anchor, nibble_at,
    verify_proof,
};
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
pub use schema_migrations::{
    LEDGER_MIGRATION_RECEIPT_MAGIC, LEDGER_MIGRATION_RECEIPT_VERSION, LEDGER_SCHEMA_CATALOG,
    LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN, LedgerMigrationError, LedgerMigrationReceipt,
    LedgerSchemaCatalog, LedgerSchemaEntry, LedgerSchemaMigrator, MAX_LEDGER_MIGRATION_WIRE_BYTES,
    MIGRATION_RECEIPT_FILENAME, MigrationGuidance, MigrationOutcomeState, MigrationStage,
    SchemaLifecycleState,
};
pub use sealed_lineage::{
    ERR_LEDGER_SEALED_NAMESPACE_001, LINEAGE_WRITE_SEAL_DOMAIN, SEALED_LINEAGE_FAMILIES,
    SEALED_LINEAGE_OBJECT_PREFIX, first_sealed_lineage_delta, is_sealed_lineage_batch,
    is_sealed_lineage_delta, lineage_write_seal,
};
pub use ssi_corpus::{
    LEDGER_SSI_CORPUS_RECEIPT_DOMAIN, MAX_CORPUS_CASES, MAX_CORPUS_LABEL_BYTES,
    MAX_EXCLUDED_DIMENSIONS, MAX_SSI_CORPUS_WIRE_BYTES, SSI_CORPUS_MAGIC, SSI_CORPUS_VERSION,
    ScheduleCaseResult, ScheduleCorpusReceipt, ScheduleVerdict, SsiCorpusError, SsiCorpusGuidance,
    SsiCorpusRunner,
};
pub use storage_adapter::{
    DurableJournalStorage, FrankenSqliteStorageAdapter, LEDGER_STORAGE_ADAPTER_RECEIPT_DOMAIN,
    MAX_STORAGE_COMMIT_WITNESSES, MAX_STORAGE_LABEL_BYTES, MAX_STORAGE_WIRE_BYTES,
    MerkleEpochStorage, ReferenceOracleStorage, STORAGE_RECEIPT_MAGIC, STORAGE_RECEIPT_VERSION,
    StorageAuthorityScope, StorageCommitReceipt, StorageCommitState, StorageError, StorageGuidance,
    StorageMigrationPlan, StorageRecoveryOutcome, StorageRecoverySummary, StorageSchemaVersion,
};
pub use storage_qualification::{
    ApiCheckOutcome, ApiCheckResult, LEDGER_STORAGE_API_QUALIFICATION_DOMAIN,
    MAX_STORAGE_QUALIFICATION_WIRE_BYTES, QualificationVerdict, STORAGE_QUALIFICATION_MAGIC,
    STORAGE_QUALIFICATION_VERSION, StorageApiCapability, StorageApiQualificationCertificate,
    StorageApiQualifier, StorageQualificationError,
};
pub use store_pin::{
    STORE_PIN_DOMAIN, STORE_ROLE_AUTHORITY_LEDGER, STORE_ROLE_EFFECT_JOURNAL, pin_is_current,
    store_pin_at, store_pin_of,
};
pub use witness::{
    HierarchicalWitness, LEDGER_SEMANTIC_WITNESS_DOMAIN, MAX_HIERARCHICAL_CHILDREN,
    MAX_WITNESS_DEPTH, MAX_WITNESS_LABEL_BYTES, MAX_WITNESS_WIRE_BYTES, NegativeWitness,
    PositiveWitness, SEMANTIC_WITNESS_MAGIC, SEMANTIC_WITNESS_VERSION, SemanticWitness,
    WitnessError, WitnessGuidance,
};

/// Maximum payload accepted by one reference-journal record.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
