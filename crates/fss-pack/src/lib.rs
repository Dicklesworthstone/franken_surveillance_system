#![forbid(unsafe_code)]
//! Append-only sealed packfile object store, bounded open-FD pool, derived rebuildable index,
//! unbounded virtual root catalog, and coarse-grained GOP media chunk container (`FSMC`).
//!
//! # Architecture
//!
//! - **Sealed Packfiles (`packfile`, `format`, `crc32c`)**: Zero-Serde `FSSP` framed records
//!   appended in group-commit batches with a single `sync_data`/`sync_all` durability barrier,
//!   rotating cleanly into immutable sealed packfiles carrying sorted `FSSF`..`FSSE` footers
//!   and whole-pack SHA-256 digests.
//! - **Bounded Open-FD LRU Cache (`fd_pool`)**: Lock-free positional reads (`pread`) over an
//!   LRU-bounded open `File` pool (default 48 on macOS, 256 elsewhere) so 10,000+ packfiles
//!   never exhaust OS file descriptor limits (`EMFILE`).
//! - **Derived Rebuildable Index (`index`)**: Compact `FSSI` snapshot with SHA-256 trailer and
//!   inventory validation; automatically rebuilt from sealed pack footers + active pack tail if
//!   missing, stale, or corrupt.
//! - **Unbounded Virtual Root Catalog (`catalog`)**: Append-only CRC32C-framed `FSSR` journal +
//!   periodic atomic `FSSS` snapshot supporting 100,000+ roots with root-last publication
//!   enforcement, supersession, permanent tombstones, and O(1) lookup.
//! - **Coarse-Grained Media Chunk Container (`media_chunk`)**: Deterministic `FSMC` GOP/window
//!   container collapsing multi-frame bursts into one packfile object while preserving per-frame
//!   SHA-256 digests and O(1) zero-copy frame slicing.

pub mod archive;
pub mod catalog;
pub mod compaction;
pub mod crc32c;
pub mod crypto;
pub mod error;
pub mod fd_pool;
pub mod format;
pub mod index;
pub mod media_chunk;
pub mod packfile;
pub mod retention;
pub mod scrubber;
pub mod store;

pub use archive::{
    COLD_ARCHIVE_MANIFEST_VERSION, ColdArchivePolicy, ColdAuditConfig, ColdGetResponse,
    ColdPackArchiveManifest, ColdPackArchiveReceipt, ColdPackRestoreReceipt, ColdPackTransport,
    ColdProviderKind, ColdPutReceipt, ColdRangeResponse, ColdRangeSampleResult,
    ColdRetrievabilityAuditReceipt, ColdRetrievabilityVerdict, ColdS3Credentials, ColdS3Endpoint,
    ColdS3Limits, ColdStorageTier, ColdUploadMode, DEFAULT_COLD_MAX_PACK_BYTES,
    DEFAULT_COLD_MIN_PACK_BYTES, DEFAULT_COLD_TARGET_PACK_BYTES, DEFAULT_MULTIPART_PART_BYTES,
    DEFAULT_MULTIPART_THRESHOLD_BYTES, LocalPackEvictionReceipt, MAX_COLD_MANIFEST_DOWNLOAD_BYTES,
    PACK_COLD_ARCHIVE_MANIFEST_DOMAIN, PACK_COLD_ENDPOINT_DOMAIN,
    PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN, S3CompatiblePackTransport, archive_sealed_pack,
    audit_cold_pack_retrievability, evict_local_sealed_pack, fetch_cold_pack_manifest,
    restore_cold_pack, restore_cold_pack_to_dir,
};
pub use catalog::{
    CATALOG_FORMAT_VERSION, CATALOG_JOURNAL_MAGIC, CATALOG_SNAPSHOT_MAGIC, CatalogRecoveryReport,
    CatalogRootEntry, CompactionReceipt, MAX_CATALOG_SNAPSHOT_BYTES, MAX_JOURNAL_BODY_BYTES,
    MAX_ROOT_ID_BYTES, MAX_ROOT_KIND_BYTES, PACK_VIRTUAL_ROOT_RECORD_DOMAIN, QuotaStatus, RootPage,
    RootPublishReceipt, RootStatus, VirtualRootCatalog, VirtualRootRecord, validate_root_id,
};
pub use compaction::{
    COMPACT_STAGING_SUFFIX, CompactionPassReport, CompactionPolicy,
    DEFAULT_COMPACTION_LIVE_RATIO_PPM, DEFAULT_READER_DRAIN_TIMEOUT_MS,
    PACK_COMPACTION_RECEIPT_DOMAIN, PackCompactionAction, PackCompactionReceipt, PackLiveStats,
    ReaderEpochGuard, ReaderEpochTracker, compact_staging_file_name,
};
pub use crc32c::{Crc32cHasher, crc32c};
pub use crypto::{
    AEAD_FRAME_HEADER_LEN, AEAD_FRAME_MAGIC, AEAD_FRAME_OVERHEAD_LEN, AEAD_FRAME_VERSION,
    AeadFrameHeader, AeadRecordContext, CipherSuite, CryptoErasureReceipt,
    DEFAULT_ENCRYPTION_CHUNK_BYTES, DataEncryptionKey, DecryptedPackReceipt, DekId,
    ENCRYPTED_PACK_END_MAGIC, ENCRYPTED_PACK_HEADER_LEN, ENCRYPTED_PACK_MAGIC,
    ENCRYPTED_PACK_TRAILER_LEN, ENCRYPTED_PACK_TRAILER_MAGIC, ENCRYPTED_PACK_VERSION,
    ERR_CRYPTO_AUTH_FAILED_001, ERR_CRYPTO_KEY_ERASED_001, EncryptedPackHeader,
    EncryptedPackReader, EncryptedPackReceipt, EncryptedPackTrailer, EncryptedPackWriter,
    EncryptedRecordReceipt, EncryptedStreamKind, ErasedDekTombstone, KEY_CATALOG_MAGIC,
    KEY_CATALOG_VERSION, KekRotationReceipt, KeyEncryptionKey, KeyEnvelopeCatalog, KeyEpoch,
    MAX_AEAD_FRAME_PLAINTEXT_BYTES, MAX_ERASURE_TEXT_LEN, MAX_KEY_CATALOG_BYTES,
    PACK_AEAD_RECORD_AAD_DOMAIN, PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN, PACK_DEK_WRAP_AAD_DOMAIN,
    PACK_KEK_SUBKEY_DOMAIN, PACK_KEY_CATALOG_HEADER_DOMAIN, SCHEMA_EPOCH_LEDGER_EPOCH,
    SCHEMA_EPOCH_PACKFILE, WRAPPED_DEK_CIPHERTEXT_LEN, WrappedDekEnvelope, build_record_aad,
    decrypt_aead_frame, decrypt_and_verify_ledger_epoch_segment, decrypt_and_verify_pack_bytes,
    decrypt_and_verify_pack_file, encrypt_aead_frame, encrypt_ledger_epoch_segment,
    encrypt_pack_bytes, encrypt_pack_file,
};
pub use error::{PackCutPoint, PackError, PackIoOperation, QuotaResource};
pub use fd_pool::{DEFAULT_MAX_OPEN_PACKS, FdPool, FdPoolStats};
pub use format::{
    DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_READ_BYTES, DEFAULT_TARGET_PACK_BYTES, DurabilityMode,
    MAX_INTERRUPTED_ATTEMPTS, MAX_STANDARD_TARGET_PACK_BYTES, MIN_CONFIGURABLE_TARGET_PACK_BYTES,
    MIN_STANDARD_TARGET_PACK_BYTES, PACK_FOOTER_END_MAGIC, PACK_FOOTER_ENTRY_LEN,
    PACK_FOOTER_MAGIC, PACK_FOOTER_PREFIX_LEN, PACK_FOOTER_TAIL_LEN, PACK_FORMAT_VERSION,
    PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PACK_KIND_OBJECT_MANIFEST, PACK_KIND_RAW_PAYLOAD,
    PACK_RECORD_HEADER_LEN, PACK_RECORD_MAGIC, PACK_RECORD_OVERHEAD_LEN, PACK_RECORD_TRAILER_LEN,
    PackFooter, PackFooterEntry, PackFooterTail, PackId, PackLocation, PackObjectInput,
    PackObjectState, PackRecordHeader, decode_footer_tail, decode_record_header,
    decode_sealed_footer, encode_record_into, encode_sealed_footer, verify_record_slice,
};
pub use index::{
    IndexLoadOutcome, IndexRebuildReason, MAX_INDEX_SNAPSHOT_BYTES, PACK_INDEX_MAGIC,
    PACK_INDEX_VERSION, PackIndex, PackInventoryEntry,
};
pub use media_chunk::{
    BuiltMediaChunk, MAX_MEDIA_CHUNK_FRAMES, MAX_STREAM_ID_BYTES, MEDIA_CHUNK_MAGIC,
    MEDIA_CHUNK_VERSION, MEDIA_FRAME_ENTRY_LEN, MEDIA_FRAME_FLAG_CONFIG,
    MEDIA_FRAME_FLAG_DISCONTINUITY, MEDIA_FRAME_FLAG_KEYFRAME, MediaChunkBuilder, MediaChunkView,
    MediaCodec, MediaFrameEntry, MediaFrameReceipt,
};
pub use packfile::{
    PackConfig, PackRecoveryReport, PackWriter, QuotaPolicy, SealedPackReceipt, verify_sealed_pack,
};
pub use retention::{
    CapacityPressure, DEFAULT_WATERMARK_HARD_PCT, DEFAULT_WATERMARK_SOFT_PCT, DeletionTombstone,
    ERR_EVIDENCE_DELETED_001, ERR_STORAGE_QUOTA_PINNED_001, EvictionReason, OBJECT_TOMBSTONE_MAGIC,
    OBJECT_TOMBSTONE_RECORD_LEN, OBJECT_TOMBSTONE_VERSION, ObjectTombstoneLog,
    PACK_RETENTION_EVICTION_BATCH_DOMAIN, PACK_TOMBSTONE_COMMIT_PROOF_DOMAIN, RetentionCandidate,
    RetentionEvictionBatch, RetentionImportRecord, RetentionPlanOutcome, RetentionRingConfig,
    SensorRetentionPolicy, TombstoneCommitProof, plan_retention,
};
pub use scrubber::{
    BackgroundScrubber, MAX_VERIFIED_FRACTION_PPM, PACK_SCRUB_REPORT_DOMAIN, PackScrubReport,
    ScrubBudget, ScrubCursor, ScrubFailureKind, ScrubFinding, ScrubVerdict,
};
pub use store::{
    GraphPublishReceipt, PackReadBudget, PackReader, PackStore, PackTelemetrySnapshot,
    StoreRecoveryReport,
};
