#![forbid(unsafe_code)]
//! Cryptographic migration equivalence receipt (`fss.migration_receipt.v1`) and independent
//! post-migration equivalence verifier.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::json_input::{Value, parse_migration_receipt};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, LedgerAnchor};
use fss_ledger::{
    DurableLedgerStatus, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger,
    inspect_durable,
};
use fss_pack::{DurabilityMode, PackConfig, PackStore};
use fss_projection_store::{
    HistoryChainMode, MvccProjectionStore, ProjectionStore, ProjectionStoreConfig, WalSyncPolicy,
};

use crate::deletion::DeletionIndex;
use crate::durable_effect::DurableEffectJournal;
use crate::reference_deployment::DeploymentLimits;

use super::v1_to_v2::{
    MigrationPayloadResolver, collect_agent_file_inventory, collect_referenced_and_orphan_objects,
    read_bounded_bytes,
};
use super::{DeploymentFormatVersion, MigrationError, detect_deployment_format, escape_json_str};

/// Canonical JSON interchange schema identifier for a v1-to-v2 migration equivalence receipt.
pub const MIGRATION_RECEIPT_SCHEMA: &str = "fss.migration_receipt.v1";
/// Registered canonical digest domain tag for [`MigrationEquivalenceReceipt::receipt_digest`].
pub const MIGRATION_RECEIPT_DOMAIN: &str = "fss.migration.equivalence_receipt.v1";
/// Canonical filename where the receipt JSON is persisted inside a migrated v2 deployment root.
pub const MIGRATION_RECEIPT_FILENAME: &str = "migration_receipt.json";

/// Cryptographic equivalence receipt sealing a completed non-destructive v1-to-v2 migration.
///
/// Pins exact source v1 and destination v2 anchors, Merkle and history roots, migrated entity
/// counts, explicitly excluded v1 unreferenced spool orphans, effect/agent verification results,
/// materialized MVCC projection state digest, and a domain-separated canonical `receipt_digest`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationEquivalenceReceipt {
    /// Receipt schema identifier (`fss.migration_receipt.v1`).
    pub schema: String,
    /// Deployment site lineage preserved identically from v1 to v2.
    pub site_lineage: String,
    /// Canonical head [`LedgerAnchor`] observed in the v1 source ledger.
    pub source_v1_anchor: LedgerAnchor,
    /// Last durable journal record root observed in the v1 `ledger/journal.fssj`.
    pub source_v1_ledger_root: ContentDigest,
    /// Canonical head [`LedgerAnchor`] committed in the v2 [`MerkleEpochLedger`].
    pub dest_v2_anchor: LedgerAnchor,
    /// Head v2 Radix-Merkle state root (`dest_v2_anchor.state_root`).
    pub dest_v2_merkle_root: ContentDigest,
    /// Head v2 segmented epoch history-chain root.
    pub dest_v2_history_root: ContentDigest,
    /// Exact number of committed `EvidenceDeltaBatch` records streamed from v1 to v2.
    pub batches_migrated: u64,
    /// Exact number of referenced content-addressed objects packed and SHA-256 verified.
    pub objects_migrated: u64,
    /// Exact number of live publication roots migrated into the v2 virtual root catalog.
    pub roots_migrated: u64,
    /// Number of distinct live events materialized in the v2 MVCC projection store.
    pub events_migrated: u64,
    /// Number of distinct evidence holds materialized in the v2 MVCC projection store.
    pub holds_migrated: u64,
    /// Number of distinct per-sensor privacy mask policies materialized in v2 MVCC projections.
    pub masks_migrated: u64,
    /// Number of distinct deletion tombstones migrated across canonical history and custody.
    pub tombstones_migrated: u64,
    /// Sorted list of admitted v1 spool objects not referenced by any live root or ledger batch.
    /// Reported explicitly and NEVER silently adopted into v2 packfiles or destroyed in v1.
    pub source_unreferenced_orphans: Vec<ContentDigest>,
    /// True iff `effects/journal.fssj` was copied, SHA-256 verified, and cleanly re-inspected.
    pub effects_verified: bool,
    /// Exact SHA-256 of the copied `effects/journal.fssj`, when present.
    pub effects_journal_digest: Option<ContentDigest>,
    /// Number of regular files under `agent/` copied and SHA-256 verified (0 if `agent/` absent).
    pub agent_files_verified: u64,
    /// Canonical deterministic [`fss_projection_store::ProjectionSnapshot::state_digest`] of the
    /// materialized v2 MVCC projection store.
    pub projection_state_digest: ContentDigest,
    /// True iff full post-migration cryptographic and semantic equivalence verification succeeded.
    pub semantic_equivalence_verified: bool,
    /// Domain-separated SHA-256 digest sealing every preceding field under
    /// [`MIGRATION_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl MigrationEquivalenceReceipt {
    /// Loads the canonical receipt without consulting the migrated-from deployment. The caller
    /// must still check its destination commitment against the current v2 canonical history.
    pub(crate) fn read_from_root(root: &Path, max_bytes: usize) -> Result<Self, MigrationError> {
        let bytes = read_bounded_bytes(&root.join(MIGRATION_RECEIPT_FILENAME), max_bytes)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| receipt_error("migration receipt is not UTF-8"))?;
        Self::from_canonical_json(text, max_bytes)
    }

    fn from_canonical_json(text: &str, max_bytes: usize) -> Result<Self, MigrationError> {
        let value = parse_migration_receipt(text, max_bytes)
            .map_err(|err| receipt_error(format!("invalid receipt JSON: {err}")))?;
        let fields = value
            .object()
            .ok_or_else(|| receipt_error("expected receipt object"))?;
        let digests = fields
            .get("source_unreferenced_orphans")
            .and_then(Value::array)
            .ok_or_else(|| receipt_error("expected source_unreferenced_orphans array"))?;
        let source_unreferenced_orphans = digests
            .iter()
            .map(decode_digest)
            .collect::<Result<Vec<_>, _>>()?;
        let effects_journal_digest = match fields.get("effects_journal_digest") {
            Some(Value::Null) => None,
            Some(value) => Some(decode_digest(value)?),
            None => return Err(receipt_error("missing effects_journal_digest")),
        };
        let receipt = Self {
            schema: read_text(fields, "schema")?.to_owned(),
            site_lineage: read_text(fields, "site_lineage")?.to_owned(),
            source_v1_anchor: read_anchor(fields, "source_v1_anchor")?,
            source_v1_ledger_root: read_digest(fields, "source_v1_ledger_root")?,
            dest_v2_anchor: read_anchor(fields, "dest_v2_anchor")?,
            dest_v2_merkle_root: read_digest(fields, "dest_v2_merkle_root")?,
            dest_v2_history_root: read_digest(fields, "dest_v2_history_root")?,
            batches_migrated: read_count(fields, "batches_migrated")?,
            objects_migrated: read_count(fields, "objects_migrated")?,
            roots_migrated: read_count(fields, "roots_migrated")?,
            events_migrated: read_count(fields, "events_migrated")?,
            holds_migrated: read_count(fields, "holds_migrated")?,
            masks_migrated: read_count(fields, "masks_migrated")?,
            tombstones_migrated: read_count(fields, "tombstones_migrated")?,
            source_unreferenced_orphans,
            effects_verified: read_bool(fields, "effects_verified")?,
            effects_journal_digest,
            agent_files_verified: read_count(fields, "agent_files_verified")?,
            projection_state_digest: read_digest(fields, "projection_state_digest")?,
            semantic_equivalence_verified: read_bool(fields, "semantic_equivalence_verified")?,
            receipt_digest: read_digest(fields, "receipt_digest")?,
        };
        // Exact re-encoding also checks the derived orphan count, field set and order.
        if receipt.to_json() != text {
            return Err(receipt_error("migration receipt is not canonical JSON"));
        }
        receipt.verify_self_digest()?;
        Ok(receipt)
    }

    /// Recomputes the canonical domain-separated SHA-256 digest over all receipt fields except
    /// `receipt_digest` itself under [`MIGRATION_RECEIPT_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(MIGRATION_RECEIPT_DOMAIN);
        enc.text(&self.schema);
        enc.text(&self.site_lineage);
        self.source_v1_anchor.encode_canonical(&mut enc);
        enc.digest(self.source_v1_ledger_root);
        self.dest_v2_anchor.encode_canonical(&mut enc);
        enc.digest(self.dest_v2_merkle_root);
        enc.digest(self.dest_v2_history_root);
        enc.u64(self.batches_migrated);
        enc.u64(self.objects_migrated);
        enc.u64(self.roots_migrated);
        enc.u64(self.events_migrated);
        enc.u64(self.holds_migrated);
        enc.u64(self.masks_migrated);
        enc.u64(self.tombstones_migrated);
        enc.u64(self.source_unreferenced_orphans.len() as u64);
        for orphan in &self.source_unreferenced_orphans {
            enc.digest(*orphan);
        }
        enc.bool(self.effects_verified);
        match self.effects_journal_digest {
            Some(digest) => {
                enc.bool(true);
                enc.digest(digest);
            }
            None => enc.bool(false),
        }
        enc.u64(self.agent_files_verified);
        enc.digest(self.projection_state_digest);
        enc.bool(self.semantic_equivalence_verified);
        let bytes = enc.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies that `self.receipt_digest` matches [`Self::compute_digest`] and basic invariants.
    pub fn verify_self_digest(&self) -> Result<(), MigrationError> {
        if self.schema != MIGRATION_RECEIPT_SCHEMA {
            return Err(MigrationError::VerificationFailed {
                detail: format!("unexpected receipt schema '{}'", self.schema),
            });
        }
        if !self.semantic_equivalence_verified {
            return Err(MigrationError::VerificationFailed {
                detail: "receipt marks semantic_equivalence_verified=false".to_owned(),
            });
        }
        if crate::reference_deployment::validate_site_lineage(&self.site_lineage).is_err()
            || self.source_v1_anchor.site_lineage != self.site_lineage
            || self.dest_v2_anchor.site_lineage != self.site_lineage
            || self.source_v1_anchor.commit_sequence != self.batches_migrated
            || self.dest_v2_anchor.commit_sequence != self.batches_migrated
            || self.dest_v2_anchor.state_root != self.dest_v2_merkle_root
        {
            return Err(receipt_error(
                "receipt anchor, lineage, or migration count mismatch",
            ));
        }
        if self
            .source_unreferenced_orphans
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(receipt_error("receipt orphan list is not strictly ordered"));
        }
        let expected = self
            .compute_digest()
            .map_err(|err| MigrationError::VerificationFailed {
                detail: format!("receipt canonical encoding failed: {err}"),
            })?;
        if expected != self.receipt_digest {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "receipt_digest mismatch: expected {}, recorded {}",
                    expected.to_text(),
                    self.receipt_digest.to_text()
                ),
            });
        }
        Ok(())
    }

    /// Independently re-verifies cryptographic and semantic equivalence between `source_v1_root`
    /// and `dest_v2_root` against every commitment sealed in this receipt.
    pub fn verify_equivalence(
        &self,
        source_v1_root: &Path,
        dest_v2_root: &Path,
    ) -> Result<(), MigrationError> {
        self.verify_equivalence_with_limits(
            source_v1_root,
            dest_v2_root,
            DeploymentLimits::standard(),
            64 * 1024 * 1024,
        )
    }

    /// Independently re-verifies equivalence under explicit deployment and journal byte bounds.
    pub fn verify_equivalence_with_limits(
        &self,
        source_v1_root: &Path,
        dest_v2_root: &Path,
        deployment_limits: DeploymentLimits,
        max_journal_bytes: usize,
    ) -> Result<(), MigrationError> {
        self.verify_self_digest()?;

        let v1_layout = match detect_deployment_format(source_v1_root)? {
            DeploymentFormatVersion::V1 { layout } => layout,
            other => {
                return Err(MigrationError::VerificationFailed {
                    detail: format!("source is not a v1 deployment: {other:?}"),
                });
            }
        };
        let v2_layout = match detect_deployment_format(dest_v2_root)? {
            DeploymentFormatVersion::V2 { layout } => layout,
            other => {
                return Err(MigrationError::VerificationFailed {
                    detail: format!("destination is not a complete v2 deployment: {other:?}"),
                });
            }
        };

        if v1_layout.site_lineage != self.site_lineage
            || v2_layout.site_lineage != self.site_lineage
        {
            return Err(MigrationError::VerificationFailed {
                detail: "site_lineage mismatch between v1, v2, and receipt".to_owned(),
            });
        }

        // 1. Re-inspect v1 source read-only.
        let v1_ledger = inspect_durable(
            source_v1_root.join(&v1_layout.ledger_relpath),
            &v1_layout.site_lineage,
            max_journal_bytes,
        )
        .map_err(|err| MigrationError::VerificationFailed {
            detail: format!("v1 ledger inspection failed: {err}"),
        })?;
        if v1_ledger.status != DurableLedgerStatus::Present || !v1_ledger.is_clean() {
            return Err(MigrationError::VerificationFailed {
                detail: "source v1 ledger is not present and clean".to_owned(),
            });
        }
        if v1_ledger.snapshot.anchor != self.source_v1_anchor {
            return Err(MigrationError::VerificationFailed {
                detail: "source_v1_anchor mismatch".to_owned(),
            });
        }
        if v1_ledger.last_root != self.source_v1_ledger_root {
            return Err(MigrationError::VerificationFailed {
                detail: "source_v1_ledger_root mismatch".to_owned(),
            });
        }
        if v1_ledger.batches.len() as u64 != self.batches_migrated {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "batches_migrated mismatch: v1 has {}, receipt has {}",
                    v1_ledger.batches.len(),
                    self.batches_migrated
                ),
            });
        }

        let v1_objects_dir = source_v1_root.join(&v1_layout.objects_relpath);
        let v1_local =
            fss_publication::inspect(&v1_objects_dir, deployment_limits.to_publication_limits())
                .map_err(|err| MigrationError::VerificationFailed {
                    detail: format!("v1 publication inspect failed: {err}"),
                })?;

        let max_obj_bytes =
            usize::try_from(deployment_limits.spool_object_max_bytes).unwrap_or(usize::MAX);
        let (referenced_to_pack, orphans) = collect_referenced_and_orphan_objects(
            &v1_objects_dir,
            &v1_local,
            &v1_ledger.batches,
            max_obj_bytes,
        )?;
        if referenced_to_pack.len() as u64 != self.objects_migrated {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "objects_migrated mismatch: expected {}, receipt has {}",
                    referenced_to_pack.len(),
                    self.objects_migrated
                ),
            });
        }
        if orphans != self.source_unreferenced_orphans {
            return Err(MigrationError::VerificationFailed {
                detail: "source_unreferenced_orphans set mismatch".to_owned(),
            });
        }

        // 2. Verify v2 MerkleEpochLedger full chain and live object equivalence.
        let v2_ledger_dir = dest_v2_root.join(&v2_layout.ledger_relpath);
        let epoch_ledger = MerkleEpochLedger::open(
            &v2_ledger_dir,
            v2_layout.site_lineage.clone(),
            EpochLedgerConfig::default(),
            IncompleteTailPolicy::Reject,
        )
        .map_err(|err| MigrationError::Ledger(err.to_string()))?;
        let chain_report =
            epoch_ledger
                .verify_full_chain()
                .map_err(|err| MigrationError::VerificationFailed {
                    detail: format!("v2 full chain verification failed: {err}"),
                })?;
        if chain_report.batches_verified != self.batches_migrated {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "v2 verified batch count {} differs from receipt {}",
                    chain_report.batches_verified, self.batches_migrated
                ),
            });
        }
        if epoch_ledger.head_anchor() != &self.dest_v2_anchor
            || epoch_ledger.state_root() != self.dest_v2_merkle_root
            || epoch_ledger.history_root() != self.dest_v2_history_root
        {
            return Err(MigrationError::VerificationFailed {
                detail: "v2 ledger head anchor, merkle root, or history root mismatch".to_owned(),
            });
        }
        if epoch_ledger.snapshot_objects() != v1_ledger.snapshot.objects {
            return Err(MigrationError::VerificationFailed {
                detail: "v2 Merkle ledger live object map differs from v1 snapshot".to_owned(),
            });
        }

        // 3. Verify v2 PackStore: every referenced object SHA-256 matches, zero orphans adopted,
        //    and every live v1 root is registered in the VirtualRootCatalog.
        let pack_store = PackStore::open(dest_v2_root, PackConfig::default())
            .map_err(|err| MigrationError::Pack(err.to_string()))?;
        for &digest in &referenced_to_pack {
            let v1_bytes = fss_publication::read_verified(&v1_objects_dir, digest, max_obj_bytes)
                .map_err(|err| MigrationError::VerificationFailed {
                detail: format!("failed reading v1 object {}: {err}", digest.to_text()),
            })?;
            let v2_bytes = pack_store.read_verified(&digest).map_err(|err| {
                MigrationError::VerificationFailed {
                    detail: format!(
                        "missing or corrupt v2 packed object {}: {err}",
                        digest.to_text()
                    ),
                }
            })?;
            if v1_bytes != v2_bytes || ContentDigest::sha256(&v2_bytes) != digest {
                return Err(MigrationError::VerificationFailed {
                    detail: format!("byte mismatch for packed object {}", digest.to_text()),
                });
            }
        }
        for &orphan in &orphans {
            if pack_store
                .lookup(&orphan)
                .map_err(|err| MigrationError::Pack(err.to_string()))?
                .is_some()
            {
                return Err(MigrationError::VerificationFailed {
                    detail: format!(
                        "unreferenced v1 orphan {} was unexpectedly adopted into v2 packs",
                        orphan.to_text()
                    ),
                });
            }
        }
        if v1_local.report.roots.len() as u64 != self.roots_migrated {
            return Err(MigrationError::VerificationFailed {
                detail: "roots_migrated count mismatch".to_owned(),
            });
        }
        for root in &v1_local.report.roots {
            let entry = pack_store
                .get_root(root.slot.as_str())
                .map_err(|err| MigrationError::Pack(err.to_string()))?
                .ok_or_else(|| MigrationError::VerificationFailed {
                    detail: format!("missing migrated virtual root '{}'", root.slot.as_str()),
                })?;
            if entry.record.root_digest != root.root {
                return Err(MigrationError::VerificationFailed {
                    detail: format!(
                        "virtual root '{}' digest mismatch: expected {}, found {}",
                        root.slot.as_str(),
                        root.root.to_text(),
                        entry.record.root_digest.to_text()
                    ),
                });
            }
        }

        // 4. Verify v2 MVCC ProjectionStore matches projection_state_digest and anchor.
        let deletion =
            DeletionIndex::from_batches::<MigrationError>(&v1_ledger.batches, |digest| {
                fss_publication::read_verified(&v1_objects_dir, digest, max_obj_bytes).map_err(
                    |err| MigrationError::VerificationFailed {
                        detail: format!("deletion custody read failed: {err}"),
                    },
                )
            })?;
        let mut deleted_digests: BTreeSet<ContentDigest> = deletion.deleted_objects();
        deleted_digests.extend(v1_local.report.tombstones.iter().copied());

        let resolver = MigrationPayloadResolver::new(pack_store.reader(), deleted_digests);
        let proj_config = ProjectionStoreConfig {
            durability: DurabilityMode::Fsync,
            wal_sync: WalSyncPolicy::FlushOnly,
            history_mode: HistoryChainMode::V2MerkleEpoch,
            ..ProjectionStoreConfig::default()
        };
        let proj_dir = dest_v2_root.join(&v2_layout.projections_relpath);
        let proj_store = MvccProjectionStore::open_or_rebuild_with_config(
            &proj_dir,
            &epoch_ledger,
            &resolver,
            proj_config,
        )
        .map_err(|err| MigrationError::Projection(err.to_string()))?;
        let snap = proj_store.snapshot_latest();
        if snap.state_digest() != self.projection_state_digest {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "projection_state_digest mismatch: expected {}, computed {}",
                    self.projection_state_digest.to_text(),
                    snap.state_digest().to_text()
                ),
            });
        }
        if snap.anchor().commit_sequence != self.dest_v2_anchor.commit_sequence
            || snap.anchor().authority_root != self.dest_v2_merkle_root
            || snap.anchor().history_root != self.dest_v2_history_root
        {
            return Err(MigrationError::VerificationFailed {
                detail: "v2 MVCC projection anchor disagrees with v2 Merkle epoch ledger"
                    .to_owned(),
            });
        }

        // 5. Verify effects/journal.fssj byte-for-byte SHA-256 and clean inspection.
        let v1_effects_path = source_v1_root.join(&v1_layout.effects_relpath);
        let v2_effects_path = dest_v2_root.join(&v2_layout.effects_relpath);
        let v1_effects_bytes = read_bounded_bytes(&v1_effects_path, max_journal_bytes)?;
        let v2_effects_bytes = read_bounded_bytes(&v2_effects_path, max_journal_bytes)?;
        let v1_effects_sha = ContentDigest::sha256(&v1_effects_bytes);
        let v2_effects_sha = ContentDigest::sha256(&v2_effects_bytes);
        if v1_effects_bytes != v2_effects_bytes
            || v1_effects_sha != v2_effects_sha
            || self.effects_journal_digest != Some(v2_effects_sha)
            || !self.effects_verified
        {
            return Err(MigrationError::VerificationFailed {
                detail: "effects/journal.fssj SHA-256 verification failed".to_owned(),
            });
        }
        let v2_effects_inspect = DurableEffectJournal::inspect(&v2_effects_path, max_journal_bytes)
            .map_err(|err| MigrationError::VerificationFailed {
                detail: format!("v2 effects journal inspect failed: {err}"),
            })?;
        if !v2_effects_inspect.is_clean() {
            return Err(MigrationError::VerificationFailed {
                detail: "v2 effects journal is not clean".to_owned(),
            });
        }

        // 6. Verify agent/ directory files byte-for-byte if present in source.
        let v1_agent_inv = collect_agent_file_inventory(source_v1_root, max_journal_bytes)?;
        let v2_agent_inv = collect_agent_file_inventory(dest_v2_root, max_journal_bytes)?;
        if v1_agent_inv != v2_agent_inv || v2_agent_inv.len() as u64 != self.agent_files_verified {
            return Err(MigrationError::VerificationFailed {
                detail: "agent/ subtree inventory mismatch between v1 and v2".to_owned(),
            });
        }

        // 7. Confirm persisted migration_receipt.json exists and matches canonical JSON.
        if Self::read_from_root(dest_v2_root, self.to_json().len())? != *self {
            return Err(receipt_error(
                "persisted migration receipt differs from verified receipt",
            ));
        }

        Ok(())
    }

    /// Renders this receipt as canonical zero-Serde RFC 8259 JSON (`fss.migration_receipt.v1`).
    #[must_use]
    pub fn to_json(&self) -> String {
        let orphans_json: Vec<String> = self
            .source_unreferenced_orphans
            .iter()
            .map(|d| format!("\"{}\"", escape_json_str(&d.to_text())))
            .collect();
        let effects_digest_json = match self.effects_journal_digest {
            Some(d) => format!("\"{}\"", escape_json_str(&d.to_text())),
            None => "null".to_owned(),
        };
        format!(
            concat!(
                "{{",
                "\"schema\":\"{}\",",
                "\"site_lineage\":\"{}\",",
                "\"source_v1_anchor\":{},",
                "\"source_v1_ledger_root\":\"{}\",",
                "\"dest_v2_anchor\":{},",
                "\"dest_v2_merkle_root\":\"{}\",",
                "\"dest_v2_history_root\":\"{}\",",
                "\"batches_migrated\":{},",
                "\"objects_migrated\":{},",
                "\"roots_migrated\":{},",
                "\"events_migrated\":{},",
                "\"holds_migrated\":{},",
                "\"masks_migrated\":{},",
                "\"tombstones_migrated\":{},",
                "\"source_unreferenced_orphans\":[{}],",
                "\"source_unreferenced_orphan_count\":{},",
                "\"effects_verified\":{},",
                "\"effects_journal_digest\":{},",
                "\"agent_files_verified\":{},",
                "\"projection_state_digest\":\"{}\",",
                "\"semantic_equivalence_verified\":{},",
                "\"receipt_digest\":\"{}\"",
                "}}"
            ),
            escape_json_str(&self.schema),
            escape_json_str(&self.site_lineage),
            anchor_to_json(&self.source_v1_anchor),
            escape_json_str(&self.source_v1_ledger_root.to_text()),
            anchor_to_json(&self.dest_v2_anchor),
            escape_json_str(&self.dest_v2_merkle_root.to_text()),
            escape_json_str(&self.dest_v2_history_root.to_text()),
            self.batches_migrated,
            self.objects_migrated,
            self.roots_migrated,
            self.events_migrated,
            self.holds_migrated,
            self.masks_migrated,
            self.tombstones_migrated,
            orphans_json.join(","),
            self.source_unreferenced_orphans.len(),
            self.effects_verified,
            effects_digest_json,
            self.agent_files_verified,
            escape_json_str(&self.projection_state_digest.to_text()),
            self.semantic_equivalence_verified,
            escape_json_str(&self.receipt_digest.to_text()),
        )
    }
}

fn receipt_error(detail: impl Into<String>) -> MigrationError {
    MigrationError::VerificationFailed {
        detail: detail.into(),
    }
}

fn read_text<'a>(
    fields: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, MigrationError> {
    fields
        .get(key)
        .and_then(Value::text)
        .ok_or_else(|| receipt_error(format!("expected receipt string: {key}")))
}

fn read_count(fields: &BTreeMap<String, Value>, key: &str) -> Result<u64, MigrationError> {
    fields
        .get(key)
        .and_then(Value::integer)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or_else(|| receipt_error(format!("expected receipt u64: {key}")))
}

fn read_bool(fields: &BTreeMap<String, Value>, key: &str) -> Result<bool, MigrationError> {
    fields
        .get(key)
        .and_then(Value::boolean)
        .ok_or_else(|| receipt_error(format!("expected receipt boolean: {key}")))
}

fn decode_digest(value: &Value) -> Result<ContentDigest, MigrationError> {
    let text = value
        .text()
        .ok_or_else(|| receipt_error("expected receipt digest string"))?;
    ContentDigest::parse(text).map_err(|_| receipt_error("invalid receipt digest"))
}

fn read_digest(
    fields: &BTreeMap<String, Value>,
    key: &str,
) -> Result<ContentDigest, MigrationError> {
    decode_digest(
        fields
            .get(key)
            .ok_or_else(|| receipt_error(format!("missing receipt digest: {key}")))?,
    )
}

fn read_anchor(
    fields: &BTreeMap<String, Value>,
    key: &str,
) -> Result<LedgerAnchor, MigrationError> {
    let anchor = fields
        .get(key)
        .and_then(Value::object)
        .ok_or_else(|| receipt_error(format!("expected receipt anchor: {key}")))?;
    Ok(LedgerAnchor {
        site_lineage: read_text(anchor, "site_lineage")?.to_owned(),
        ledger_epoch: read_count(anchor, "ledger_epoch")?,
        commit_sequence: read_count(anchor, "commit_sequence")?,
        adapter_registry_epoch: read_count(anchor, "adapter_registry_epoch")?,
        schema_epoch: read_count(anchor, "schema_epoch")?,
        policy_epoch: read_count(anchor, "policy_epoch")?,
        privacy_epoch: read_count(anchor, "privacy_epoch")?,
        state_root: read_digest(anchor, "state_root")?,
    })
}

fn anchor_to_json(anchor: &LedgerAnchor) -> String {
    format!(
        "{{\"site_lineage\":\"{}\",\"ledger_epoch\":{},\"commit_sequence\":{},\"state_root\":\"{}\",\"adapter_registry_epoch\":{},\"schema_epoch\":{},\"policy_epoch\":{},\"privacy_epoch\":{}}}",
        escape_json_str(&anchor.site_lineage),
        anchor.ledger_epoch,
        anchor.commit_sequence,
        escape_json_str(&anchor.state_root.to_text()),
        anchor.adapter_registry_epoch,
        anchor.schema_epoch,
        anchor.policy_epoch,
        anchor.privacy_epoch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_reader_requires_exact_bytes_consistent_anchors_and_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let v1 = LedgerAnchor::genesis("site:receipt");
        let mut v2 = v1.clone();
        v2.state_root = ContentDigest::sha256(b"v2");
        let root = ContentDigest::sha256(b"fixture");
        let mut receipt = MigrationEquivalenceReceipt {
            schema: MIGRATION_RECEIPT_SCHEMA.to_owned(),
            site_lineage: v1.site_lineage.clone(),
            source_v1_anchor: v1,
            source_v1_ledger_root: root,
            dest_v2_merkle_root: v2.state_root,
            dest_v2_anchor: v2,
            dest_v2_history_root: root,
            batches_migrated: 0,
            objects_migrated: u64::MAX,
            roots_migrated: 0,
            events_migrated: 0,
            holds_migrated: 0,
            masks_migrated: 0,
            tombstones_migrated: 0,
            source_unreferenced_orphans: vec![root],
            effects_verified: true,
            effects_journal_digest: Some(root),
            agent_files_verified: 0,
            projection_state_digest: root,
            semantic_equivalence_verified: true,
            receipt_digest: root,
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        let json = receipt.to_json();
        let parse = |text: &str| MigrationEquivalenceReceipt::from_canonical_json(text, text.len());
        assert_eq!(parse(&json)?, receipt);
        assert!(MigrationEquivalenceReceipt::from_canonical_json(&json, json.len() - 1).is_err());
        assert!(parse(&format!("{json}\n")).is_err());
        assert!(
            parse(&json.replace(
                "\"source_unreferenced_orphan_count\":1",
                "\"source_unreferenced_orphan_count\":2"
            ))
            .is_err()
        );
        assert!(parse(&json.replace("\"masks_migrated\":0", "\"masks_migrated\":1")).is_err());
        for case in 0..3 {
            let mut changed = receipt.clone();
            match case {
                0 => changed.batches_migrated = 1,
                1 => changed.source_v1_anchor.site_lineage = "site:other".to_owned(),
                _ => changed.dest_v2_merkle_root = root,
            }
            changed.receipt_digest = changed.compute_digest()?;
            assert!(parse(&changed.to_json()).is_err());
        }
        Ok(())
    }
}
