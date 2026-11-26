#![forbid(unsafe_code)]
//! Crash-resumable derived-index rebuild cursor over v1 and v2 ledgers (`FSS-034`, `fss-x4a.9.4`).
//!
//! Composes [`DurableReferenceLedger`] (`v1`), [`inspect_epochs_readonly`] (`v2` Radix-Merkle),
//! [`DerivedGenerationPin`] (`FSS-107`), [`ReplayPageBudget`] (`FSS-102`), and
//! [`StorageAuthorityScope`] (`FSS-031`) to drive any derived secondary index ([`DerivedIndexSink`]):
//!
//! - **Bounded page-by-page catch-up:** advances at most `budget.max_batches` / `budget.max_bytes`
//!   canonical `EvidenceDeltaBatch` records per step, honoring cooperative cancellation cleanly.
//! - **Generation/lineage/fork invalidation:** ANY drift in [`DerivedGenerationPin`], site lineage,
//!   or history anchor triggers an explicit reset-and-rebuild from genesis (`RebuiltFromGenesis`)
//!   rather than silently mixing derived entries across incompatible generations.
//! - **Crash-safe durable cursor checkpointing (`FSSDIC01` v1):** sealed under
//!   `fss.ledger_derived_rebuild_cursor.v1` and persisted atomically (temp + `sync_all()` + rename
//!   + parent directory sync) so stepping across crashes reproduces the EXACT same derived index
//!   digest as a single-shot fresh rebuild from genesis.
//! - **Derived cognition only:** carries zero write or effect authority (`grants_effect_authority() == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane, Sha256Hasher,
};

use crate::batch_codec::encode_batch;
use crate::cursor::ReplayPageBudget;
use crate::durable::DurableReferenceLedger;
use crate::epochs::{genesis_history_root_v2, inspect_epochs_readonly, successor_history_root_v2};
use crate::high_water::DerivedGenerationPin;
use crate::merkle::merkle_genesis_anchor;
use crate::oracle::{genesis_history_root, successor_history_root};
use crate::storage_adapter::{MAX_STORAGE_LABEL_BYTES, StorageAuthorityScope};

/// Registered digest domain for [`DerivedRebuildCursorState`] (`FSS-034`).
pub const LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN: &str = "fss.ledger_derived_rebuild_cursor.v1";
/// Binary wire magic header for durable [`DerivedRebuildCursorState`] checkpoints.
pub const DERIVED_REBUILD_CURSOR_MAGIC: [u8; 8] = *b"FSSDIC01";
/// Current wire format version for [`DerivedRebuildCursorState`].
pub const DERIVED_REBUILD_CURSOR_VERSION: u32 = 1;
/// Hard ceiling on serialized cursor checkpoint wire bytes (32 KiB).
pub const MAX_DERIVED_REBUILD_CURSOR_WIRE_BYTES: usize = 32 * 1024;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;
static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Non-collapsed execution phase returned by [`DerivedIndexRebuildCursor`] step operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildCursorStatus {
    /// Derived index is already synchronized to the exact ledger head at the pinned generation.
    UpToDate = 1,
    /// Advanced incrementally by one bounded page; additional committed batches remain.
    ProgressedIncremental = 2,
    /// Generation/lineage/fork drift or explicit corruption forced a genesis reset and rebuild step.
    RebuiltFromGenesis = 3,
    /// Source ledger carries an unresolved pending append or incomplete tail; cursor paused safely.
    BlockedPendingReconciliation = 4,
}

impl RebuildCursorStatus {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::ProgressedIncremental => "progressed_incremental",
            Self::RebuiltFromGenesis => "rebuilt_from_genesis",
            Self::BlockedPendingReconciliation => "blocked_pending_reconciliation",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, RebuildCursorError> {
        match tag {
            1 => Ok(Self::UpToDate),
            2 => Ok(Self::ProgressedIncremental),
            3 => Ok(Self::RebuiltFromGenesis),
            4 => Ok(Self::BlockedPendingReconciliation),
            other => Err(RebuildCursorError::MalformedWire(format!(
                "unknown RebuildCursorStatus tag {other}"
            ))),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused rebuild cursor operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildCursorGuidance {
    /// Re-authorize with active capability, privacy scope, and current authority generation.
    ReauthorizeReader,
    /// Reconcile pending source ledger appends before resuming derived index rebuild.
    ReconcileSourceLedgerFirst,
    /// Raise bounded page budget so the next canonical batch fits within `max_bytes`.
    IncreaseReplayPageBudget,
    /// Cooperative cancellation observed cleanly; safe to resume from last durable checkpoint.
    ResumeFromCheckpoint,
    /// Reject corrupt cursor checkpoint and reset derived index from genesis.
    ResetDerivedIndexFromGenesis,
}

/// Typed fail-closed error emitted by [`DerivedIndexRebuildCursor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebuildCursorError {
    /// Caller lacked active authority, privacy, or current authority generation.
    AuthorityRefused(String),
    /// Invalid generation pin, budget, or site lineage.
    InvalidInput(String),
    /// Cooperative cancellation observed cleanly before committing next page.
    Cancelled,
    /// Next canonical batch alone exceeded `ReplayPageBudget::max_bytes`.
    BatchExceedsPageBudget {
        /// Sequence number of oversized batch.
        sequence: u64,
        /// Encoded wire size in bytes.
        batch_bytes: u64,
        /// Configured page byte budget.
        budget_bytes: u64,
    },
    /// Source ledger integrity check failed.
    SourceLedgerError(String),
    /// Filesystem I/O error persisting or reading cursor checkpoint.
    Io(String),
    /// Wire checkpoint magic header mismatch.
    InvalidMagic,
    /// Wire checkpoint version unsupported.
    UnsupportedVersion {
        /// Observed wire version.
        version: u32,
    },
    /// Wire checkpoint checksum or state digest mismatch.
    ChecksumMismatch,
    /// Wire checkpoint truncated, oversized, or malformed.
    MalformedWire(String),
}

impl RebuildCursorError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-LEDGER-REBUILD-AUTH-001",
            Self::InvalidInput(_) => "ERR-LEDGER-REBUILD-INPUT-001",
            Self::Cancelled => "ERR-LEDGER-REBUILD-CANCELLED-001",
            Self::BatchExceedsPageBudget { .. } => "ERR-LEDGER-REBUILD-BUDGET-001",
            Self::SourceLedgerError(_) => "ERR-LEDGER-REBUILD-SOURCE-001",
            Self::Io(_) => "ERR-LEDGER-REBUILD-IO-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-LEDGER-REBUILD-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> RebuildCursorGuidance {
        match self {
            Self::AuthorityRefused(_) => RebuildCursorGuidance::ReauthorizeReader,
            Self::SourceLedgerError(_) => RebuildCursorGuidance::ReconcileSourceLedgerFirst,
            Self::BatchExceedsPageBudget { .. } => RebuildCursorGuidance::IncreaseReplayPageBudget,
            Self::Cancelled => RebuildCursorGuidance::ResumeFromCheckpoint,
            Self::InvalidInput(_)
            | Self::Io(_)
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::MalformedWire(_) => RebuildCursorGuidance::ResetDerivedIndexFromGenesis,
        }
    }
}

impl fmt::Display for RebuildCursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for RebuildCursorError {}

/// Pluggable deterministic derived secondary index rebuilt from canonical ledger batches.
pub trait DerivedIndexSink {
    /// Clears all derived entries back to empty genesis state.
    fn reset_to_genesis(&mut self);

    /// Deterministically folds one canonical [`EvidenceDeltaBatch`] into the derived index.
    fn apply_batch(&mut self, batch: &EvidenceDeltaBatch);

    /// Canonical SHA-256 commitment of the complete derived index state.
    fn state_digest(&self) -> ContentDigest;

    /// Number of live indexed entries.
    fn entry_count(&self) -> u64;
}

/// Production reference secondary index indexing live objects by `(Plane, family)` and `ObjectId`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecondaryFamilyIndex {
    /// Live object metadata `(plane, family, generation, payload_digest)`.
    objects: BTreeMap<ObjectId, (Plane, String, u64, ContentDigest)>,
    /// Inverted index `(plane, family) -> sorted ObjectIds`.
    by_family: BTreeMap<(Plane, String), BTreeSet<ObjectId>>,
}

impl SecondaryFamilyIndex {
    /// Creates an empty genesis secondary index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queries all live [`ObjectId`]s belonging to `(plane, family)` in canonical sorted order.
    #[must_use]
    pub fn lookup_family(&self, plane: Plane, family: &str) -> Vec<ObjectId> {
        self.by_family
            .get(&(plane, family.to_owned()))
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Queries the latest indexed `(plane, family, generation, payload_digest)` of `object_id`.
    #[must_use]
    pub fn lookup_object(
        &self,
        object_id: &ObjectId,
    ) -> Option<&(Plane, String, u64, ContentDigest)> {
        self.objects.get(object_id)
    }
}

impl DerivedIndexSink for SecondaryFamilyIndex {
    fn reset_to_genesis(&mut self) {
        self.objects.clear();
        self.by_family.clear();
    }

    fn apply_batch(&mut self, batch: &EvidenceDeltaBatch) {
        for delta in &batch.deltas {
            if let Some((old_plane, old_family, _, _)) = self.objects.insert(
                delta.object_id.clone(),
                (
                    delta.plane,
                    delta.family.clone(),
                    delta.new_generation,
                    delta.payload_digest,
                ),
            ) && (old_plane != delta.plane || old_family != delta.family)
            {
                let old_key = (old_plane, old_family);
                let remove_empty = if let Some(bucket) = self.by_family.get_mut(&old_key) {
                    bucket.remove(&delta.object_id);
                    bucket.is_empty()
                } else {
                    false
                };
                if remove_empty {
                    self.by_family.remove(&old_key);
                }
            }
            self.by_family
                .entry((delta.plane, delta.family.clone()))
                .or_default()
                .insert(delta.object_id.clone());
        }
    }

    fn state_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.ledger_derived_rebuild_cursor.v1/secondary_family_index");
        enc.u64(self.objects.len() as u64);
        for (oid, (plane, family, gen_num, payload)) in &self.objects {
            enc.text(oid.as_str());
            enc.u8(match plane {
                Plane::Authority => 1,
                Plane::Cognition => 2,
                Plane::Effect => 3,
            });
            enc.text(family);
            enc.u64(*gen_num);
            enc.digest(*payload);
        }
        ContentDigest::sha256(&enc.finish())
    }

    fn entry_count(&self) -> u64 {
        self.objects.len() as u64
    }
}

/// Durable, checksummed cursor checkpoint (`FSSDIC01` v1) persisted between bounded rebuild steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedRebuildCursorState {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Stable derived index identifier.
    pub index_id: String,
    /// Pinned ledger site lineage.
    pub site_lineage: String,
    /// Complete generation pin (`FSS-107`) used to detect silent schema/policy/model/kernel drift.
    pub generation_pin_digest: ContentDigest,
    /// Last applied canonical ledger anchor (`commit_sequence == 0` at genesis).
    pub applied_anchor: LedgerAnchor,
    /// Canonical ledger history root corresponding to `applied_anchor`.
    pub applied_history_root: ContentDigest,
    /// Canonical digest of the derived index state at `applied_anchor`.
    pub derived_state_digest: ContentDigest,
    /// Number of live derived index entries at `applied_anchor`.
    pub derived_entry_count: u64,
    /// Total genesis resets executed across this cursor's lifetime.
    pub rebuild_epoch: u64,
    /// True if external inspection flagged index corruption (forces genesis rebuild on next step).
    pub corruption_flagged: bool,
    /// Last step status observed.
    pub last_status: RebuildCursorStatus,
    /// Domain-separated SHA-256 commitment under [`LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN`].
    pub cursor_digest: ContentDigest,
}

impl DerivedRebuildCursorState {
    /// Derived rebuild cursors are read-only cognition metadata and NEVER grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Initializes a v1 genesis checkpoint pinned to `(index_id, site_lineage, pin, empty_sink)`.
    pub fn genesis<S: DerivedIndexSink>(
        index_id: &str,
        site_lineage: &str,
        pin: &DerivedGenerationPin,
        sink: &S,
    ) -> Result<Self, RebuildCursorError> {
        let anchor = LedgerAnchor::genesis(site_lineage);
        let history_root = genesis_history_root(&anchor)
            .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
        Self::genesis_with_root(index_id, site_lineage, pin, sink, anchor, history_root)
    }

    /// Initializes a v2 Merkle-epoch genesis checkpoint pinned to `(index_id, site_lineage, pin, empty_sink)`.
    pub fn genesis_v2<S: DerivedIndexSink>(
        index_id: &str,
        site_lineage: &str,
        pin: &DerivedGenerationPin,
        sink: &S,
    ) -> Result<Self, RebuildCursorError> {
        let anchor = merkle_genesis_anchor(site_lineage);
        let history_root = genesis_history_root_v2(&anchor)
            .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
        Self::genesis_with_root(index_id, site_lineage, pin, sink, anchor, history_root)
    }

    fn genesis_with_root<S: DerivedIndexSink>(
        index_id: &str,
        site_lineage: &str,
        pin: &DerivedGenerationPin,
        sink: &S,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
    ) -> Result<Self, RebuildCursorError> {
        validate_label(index_id, MAX_STORAGE_LABEL_BYTES, "index_id")?;
        validate_label(site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        let generation_pin_digest = pin
            .canonical_digest()
            .map_err(|e| RebuildCursorError::InvalidInput(e.to_string()))?;
        let mut state = Self {
            format_version: DERIVED_REBUILD_CURSOR_VERSION,
            index_id: index_id.to_owned(),
            site_lineage: site_lineage.to_owned(),
            generation_pin_digest,
            applied_anchor: anchor,
            applied_history_root: history_root,
            derived_state_digest: sink.state_digest(),
            derived_entry_count: sink.entry_count(),
            rebuild_epoch: 0,
            corruption_flagged: false,
            last_status: RebuildCursorStatus::UpToDate,
            cursor_digest: ContentDigest::sha256(b"unsealed-rebuild-cursor"),
        };
        state.cursor_digest = state.compute_digest()?;
        Ok(state)
    }

    /// Computes canonical SHA-256 commitment under [`LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, RebuildCursorError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.index_id);
        enc.text(&self.site_lineage);
        enc.digest(self.generation_pin_digest);
        self.applied_anchor.encode_canonical(enc);
        enc.digest(self.applied_history_root);
        enc.digest(self.derived_state_digest);
        enc.u64(self.derived_entry_count);
        enc.u64(self.rebuild_epoch);
        enc.u8(u8::from(self.corruption_flagged));
        enc.u8(self.last_status.tag());
    }

    /// Validates structural invariants and verifies canonical digest integrity.
    pub fn verify_self(&self) -> Result<(), RebuildCursorError> {
        if self.format_version != DERIVED_REBUILD_CURSOR_VERSION {
            return Err(RebuildCursorError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.index_id, MAX_STORAGE_LABEL_BYTES, "index_id")?;
        validate_label(&self.site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        if self.applied_anchor.site_lineage != self.site_lineage {
            return Err(RebuildCursorError::MalformedWire(
                "applied_anchor site_lineage disagrees with cursor site_lineage".to_owned(),
            ));
        }
        if self.compute_digest()? != self.cursor_digest {
            return Err(RebuildCursorError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes into its versioned, checksummed `FSSDIC01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RebuildCursorError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.cursor_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| RebuildCursorError::MalformedWire("wire length overflow".to_owned()))?;
        if total > MAX_DERIVED_REBUILD_CURSOR_WIRE_BYTES {
            return Err(RebuildCursorError::MalformedWire(format!(
                "wire length {total} exceeds ceiling {MAX_DERIVED_REBUILD_CURSOR_WIRE_BYTES}"
            )));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&DERIVED_REBUILD_CURSOR_MAGIC);
        out.extend_from_slice(&DERIVED_REBUILD_CURSOR_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSDIC01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RebuildCursorError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(RebuildCursorError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_DERIVED_REBUILD_CURSOR_WIRE_BYTES {
            return Err(RebuildCursorError::MalformedWire(format!(
                "wire length {} exceeds ceiling {MAX_DERIVED_REBUILD_CURSOR_WIRE_BYTES}",
                bytes.len()
            )));
        }
        if bytes[..8] != DERIVED_REBUILD_CURSOR_MAGIC {
            return Err(RebuildCursorError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != DERIVED_REBUILD_CURSOR_VERSION {
            return Err(RebuildCursorError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                RebuildCursorError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(RebuildCursorError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(RebuildCursorError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let index_id = dec
            .text()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?
            .to_owned();
        let site_lineage = dec
            .text()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?
            .to_owned();
        let generation_pin_digest = dec
            .digest()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let applied_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let applied_history_root = dec
            .digest()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let derived_state_digest = dec
            .digest()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let derived_entry_count = dec
            .u64()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let rebuild_epoch = dec
            .u64()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        let corruption_flagged = match dec
            .u8()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?
        {
            0 => false,
            1 => true,
            other => {
                return Err(RebuildCursorError::MalformedWire(format!(
                    "unknown corruption_flagged tag {other}"
                )));
            }
        };
        let last_status = RebuildCursorStatus::from_tag(
            dec.u8()
                .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?,
        )?;
        let cursor_digest = dec
            .digest()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| RebuildCursorError::MalformedWire(e.to_string()))?;

        let state = Self {
            format_version,
            index_id,
            site_lineage,
            generation_pin_digest,
            applied_anchor,
            applied_history_root,
            derived_state_digest,
            derived_entry_count,
            rebuild_epoch,
            corruption_flagged,
            last_status,
            cursor_digest,
        };
        state.verify_self()?;
        Ok(state)
    }

    /// Atomically persists this verified cursor checkpoint to `path` (`temp + sync_all + rename`).
    pub fn save_atomic(&self, path: &Path) -> Result<(), RebuildCursorError> {
        let bytes = self.to_canonical_bytes()?;
        let parent = path.parent().ok_or_else(|| {
            RebuildCursorError::InvalidInput("checkpoint path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|e| RebuildCursorError::Io(e.to_string()))?;
        let name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
            RebuildCursorError::InvalidInput("invalid checkpoint filename".to_owned())
        })?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
        if let Err(err) = fs::write(&tmp, &bytes)
            .and_then(|()| fs::File::open(&tmp).and_then(|file| file.sync_all()))
        {
            let _ = fs::remove_file(&tmp);
            return Err(RebuildCursorError::Io(err.to_string()));
        }
        if let Err(err) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(RebuildCursorError::Io(err.to_string()));
        }
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Loads and cryptographically verifies a durable `FSSDIC01` checkpoint from `path`.
    pub fn load_verified(path: &Path) -> Result<Self, RebuildCursorError> {
        let bytes = fs::read(path).map_err(|e| RebuildCursorError::Io(e.to_string()))?;
        Self::from_canonical_bytes(&bytes)
    }
}

/// Summary of one bounded rebuild cursor step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuildStepReport {
    /// Non-collapsed status of this step.
    pub status: RebuildCursorStatus,
    /// Number of canonical batches applied during this step.
    pub batches_applied: usize,
    /// Wire bytes accounted across batches applied during this step.
    pub bytes_processed: u64,
    /// True iff additional committed batches remain behind head after this step.
    pub has_more: bool,
    /// Updated verified cursor checkpoint state.
    pub cursor_state: DerivedRebuildCursorState,
}

/// Bounded, generation-pinned, crash-resumable derived-index rebuild cursor (`FSS-034`).
pub struct DerivedIndexRebuildCursor;

impl DerivedIndexRebuildCursor {
    /// Advances a derived index sink by one bounded page against a live v1
    /// [`DurableReferenceLedger`], automatically triggering a genesis reset & rebuild on
    /// generation drift, lineage/anchor fork, or corruption flag.
    #[allow(clippy::too_many_arguments)]
    pub fn step_v1<S: DerivedIndexSink>(
        ledger: &DurableReferenceLedger,
        authority: &StorageAuthorityScope,
        pin: &DerivedGenerationPin,
        cursor: &mut DerivedRebuildCursorState,
        sink: &mut S,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<RebuildStepReport, RebuildCursorError> {
        if cancelled {
            return Err(RebuildCursorError::Cancelled);
        }
        authority
            .validate()
            .map_err(|e| RebuildCursorError::AuthorityRefused(e.to_string()))?;
        pin.validate()
            .map_err(|e| RebuildCursorError::InvalidInput(e.to_string()))?;
        cursor.verify_self()?;

        if ledger.pending_append_sequence().is_some() {
            cursor.last_status = RebuildCursorStatus::BlockedPendingReconciliation;
            cursor.cursor_digest = cursor.compute_digest()?;
            return Ok(RebuildStepReport {
                status: RebuildCursorStatus::BlockedPendingReconciliation,
                batches_applied: 0,
                bytes_processed: 0,
                has_more: true,
                cursor_state: cursor.clone(),
            });
        }

        let batches = ledger.batches();
        let genesis = LedgerAnchor::genesis(&ledger.current().anchor.site_lineage);
        let genesis_root = genesis_history_root(&genesis)
            .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
        step_batches_common(
            HistoryRootKind::V1,
            &genesis,
            genesis_root,
            &ledger.current().anchor,
            ledger.head_history_root(),
            batches,
            authority,
            pin,
            cursor,
            sink,
            budget,
        )
    }

    /// Advances a derived index sink by one bounded page against a live on-disk v2
    /// `MerkleEpochLedger` directory via strictly read-only [`inspect_epochs_readonly`].
    #[allow(clippy::too_many_arguments)]
    pub fn step_v2_dir<S: DerivedIndexSink>(
        ledger_dir: &Path,
        site_lineage: &str,
        authority: &StorageAuthorityScope,
        pin: &DerivedGenerationPin,
        cursor: &mut DerivedRebuildCursorState,
        sink: &mut S,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<RebuildStepReport, RebuildCursorError> {
        if cancelled {
            return Err(RebuildCursorError::Cancelled);
        }
        authority
            .validate()
            .map_err(|e| RebuildCursorError::AuthorityRefused(e.to_string()))?;
        pin.validate()
            .map_err(|e| RebuildCursorError::InvalidInput(e.to_string()))?;
        cursor.verify_self()?;

        let inspection = inspect_epochs_readonly(ledger_dir, site_lineage)
            .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
        if inspection.incomplete_tail {
            cursor.last_status = RebuildCursorStatus::BlockedPendingReconciliation;
            cursor.cursor_digest = cursor.compute_digest()?;
            return Ok(RebuildStepReport {
                status: RebuildCursorStatus::BlockedPendingReconciliation,
                batches_applied: 0,
                bytes_processed: 0,
                has_more: true,
                cursor_state: cursor.clone(),
            });
        }

        let genesis_root = genesis_history_root_v2(&inspection.genesis_anchor)
            .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
        step_batches_common(
            HistoryRootKind::V2,
            &inspection.genesis_anchor,
            genesis_root,
            &inspection.head_anchor,
            inspection.history_root,
            &inspection.batches,
            authority,
            pin,
            cursor,
            sink,
            budget,
        )
    }
}

#[derive(Clone, Copy)]
enum HistoryRootKind {
    V1,
    V2,
}

impl HistoryRootKind {
    fn successor(
        self,
        previous: ContentDigest,
        batch: &EvidenceDeltaBatch,
    ) -> Result<ContentDigest, RebuildCursorError> {
        let seq = batch.new_anchor.commit_sequence;
        let digest = batch.batch_digest;
        match self {
            Self::V1 => successor_history_root(previous, seq, digest, &batch.new_anchor)
                .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string())),
            Self::V2 => successor_history_root_v2(previous, seq, digest, &batch.new_anchor)
                .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string())),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn step_batches_common<S: DerivedIndexSink>(
    history_kind: HistoryRootKind,
    genesis_anchor: &LedgerAnchor,
    genesis_history_root: ContentDigest,
    head_anchor: &LedgerAnchor,
    head_history_root: ContentDigest,
    batches: &[EvidenceDeltaBatch],
    authority: &StorageAuthorityScope,
    pin: &DerivedGenerationPin,
    cursor: &mut DerivedRebuildCursorState,
    sink: &mut S,
    budget: ReplayPageBudget,
) -> Result<RebuildStepReport, RebuildCursorError> {
    if batches.len() as u64 != head_anchor.commit_sequence {
        return Err(RebuildCursorError::SourceLedgerError(format!(
            "source ledger batch count {} disagrees with head commit_sequence {}",
            batches.len(),
            head_anchor.commit_sequence
        )));
    }

    // Enforce plane isolation BEFORE mutating cursor or sink state.
    for batch in batches {
        for delta in &batch.deltas {
            if !authority.allowed_planes.contains(&delta.plane) {
                return Err(RebuildCursorError::AuthorityRefused(format!(
                    "derived rebuild cursor lacks authority for plane {:?} in batch {}",
                    delta.plane, batch.batch_id
                )));
            }
        }
    }

    let expected_pin_digest = pin
        .canonical_digest()
        .map_err(|e| RebuildCursorError::InvalidInput(e.to_string()))?;
    let head_seq = head_anchor.commit_sequence;
    let cur_seq = cursor.applied_anchor.commit_sequence;

    // Detect any generation drift, lineage change, corruption flag, ahead-of-head cursor,
    // sink state/count divergence, or forked anchor / history-chain root at cur_seq.
    let mut needs_reset = cursor.corruption_flagged
        || cursor.generation_pin_digest != expected_pin_digest
        || cursor.site_lineage != genesis_anchor.site_lineage
        || cur_seq > head_seq
        || cursor.derived_state_digest != sink.state_digest()
        || cursor.derived_entry_count != sink.entry_count();

    if !needs_reset {
        if cur_seq == 0 {
            if cursor.applied_anchor != *genesis_anchor
                || cursor.applied_history_root != genesis_history_root
            {
                needs_reset = true;
            }
        } else {
            let idx = (cur_seq - 1) as usize;
            match batches.get(idx) {
                Some(b) if b.new_anchor == cursor.applied_anchor => {
                    let mut running = genesis_history_root;
                    for prefix_batch in &batches[..=idx] {
                        running = history_kind.successor(running, prefix_batch)?;
                    }
                    if running != cursor.applied_history_root {
                        needs_reset = true;
                    }
                }
                _ => needs_reset = true,
            }
        }
    }

    // Stage the entire page BEFORE mutating `sink` or `cursor` so any error leaves both intact.
    let start_seq = if needs_reset { 0 } else { cur_seq };
    let base_history_root = if needs_reset {
        genesis_history_root
    } else {
        cursor.applied_history_root
    };
    let start_idx = start_seq as usize;

    let mut staged_page: Vec<(&EvidenceDeltaBatch, ContentDigest)> = Vec::new();
    let mut bytes_used = 0_u64;
    let mut running_root = base_history_root;
    let mut final_anchor = if needs_reset {
        genesis_anchor.clone()
    } else {
        cursor.applied_anchor.clone()
    };

    if start_seq < head_seq {
        for batch in &batches[start_idx..] {
            if staged_page.len() >= budget.max_batches() {
                break;
            }
            let encoded = encode_batch(batch)
                .map_err(|e| RebuildCursorError::SourceLedgerError(e.to_string()))?;
            let batch_len = encoded.len() as u64;
            if staged_page.is_empty() && batch_len > budget.max_bytes() {
                return Err(RebuildCursorError::BatchExceedsPageBudget {
                    sequence: batch.new_anchor.commit_sequence,
                    batch_bytes: batch_len,
                    budget_bytes: budget.max_bytes(),
                });
            }
            if bytes_used.saturating_add(batch_len) > budget.max_bytes() {
                break;
            }
            running_root = history_kind.successor(running_root, batch)?;
            bytes_used = bytes_used.saturating_add(batch_len);
            final_anchor = batch.new_anchor.clone();
            staged_page.push((batch, running_root));
        }
    }

    let has_more = final_anchor.commit_sequence < head_seq;
    if !has_more && running_root != head_history_root {
        return Err(RebuildCursorError::SourceLedgerError(
            "computed canonical history root at head disagrees with source ledger head_history_root"
                .to_owned(),
        ));
    }

    // Commit staged transitions atomically to `sink` and `cursor`.
    if needs_reset {
        sink.reset_to_genesis();
        cursor.site_lineage = genesis_anchor.site_lineage.clone();
        cursor.generation_pin_digest = expected_pin_digest;
        cursor.applied_anchor = genesis_anchor.clone();
        cursor.applied_history_root = genesis_history_root;
        cursor.rebuild_epoch = cursor.rebuild_epoch.saturating_add(1);
        cursor.corruption_flagged = false;
    }

    let applied = staged_page.len();
    for (batch, next_root) in staged_page {
        sink.apply_batch(batch);
        cursor.applied_anchor = batch.new_anchor.clone();
        cursor.applied_history_root = next_root;
    }
    if applied == 0 && start_seq == head_seq {
        cursor.applied_history_root = head_history_root;
    }

    cursor.derived_state_digest = sink.state_digest();
    cursor.derived_entry_count = sink.entry_count();
    cursor.last_status = if needs_reset {
        RebuildCursorStatus::RebuiltFromGenesis
    } else if applied == 0 {
        RebuildCursorStatus::UpToDate
    } else {
        RebuildCursorStatus::ProgressedIncremental
    };
    cursor.cursor_digest = cursor.compute_digest()?;

    Ok(RebuildStepReport {
        status: cursor.last_status,
        batches_applied: applied,
        bytes_processed: bytes_used,
        has_more,
        cursor_state: cursor.clone(),
    })
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), RebuildCursorError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(RebuildCursorError::InvalidInput(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}
