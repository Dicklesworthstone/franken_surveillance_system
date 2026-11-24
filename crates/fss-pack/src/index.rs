#![forbid(unsafe_code)]
//! Derived, rebuildable content-address index (`<root>/objects/index/pack-index.fssi`).
//!
//! Per the repository truth hierarchy, this index is strictly a derived cache over the
//! append-only packfiles. If `pack-index.fssi` is missing, corrupt, or stale relative to
//! the packfiles currently on disk, [`crate::PackStore::open`] discards it and deterministically
//! rebuilds the exact same mapping from sealed pack footers and the active pack tail.
//!
//! # Compact Binary Snapshot Layout (`FSSI` v1, big-endian)
//!
//! ```text
//! [magic(4) = b"FSSI" | version(u16=1) | flags(u16=0)
//!  | pack_count(u64) | entry_count(u64)
//!  | sorted_packs:  (epoch:u32, seq:u64, file_len:u64, sealed:u8) * pack_count
//!  | sorted_entries:(sha256:[u8;32], epoch:u32, seq:u64, offset:u64, len:u64,
//!                    object_kind:u16, flags:u16, state:u8) * entry_count
//!  | sha256_trailer(32)]
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, sha256};

use crate::error::{PackError, PackIoOperation};
use crate::format::{
    DurabilityMode, PackId, PackLocation, PackObjectState, sync_dir, write_all_bounded,
};

/// Magic prefix of the compact binary index snapshot file.
pub const PACK_INDEX_MAGIC: [u8; 4] = *b"FSSI";
/// Supported index snapshot format version.
pub const PACK_INDEX_VERSION: u16 = 1;

const INDEX_HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8; // 24
const PACK_INVENTORY_ENTRY_LEN: usize = 4 + 8 + 8 + 1; // 21
const INDEX_ENTRY_LEN: usize = 32 + 4 + 8 + 8 + 8 + 2 + 2 + 1; // 65
const INDEX_TRAILER_LEN: usize = 32;
/// Maximum index snapshot bytes admitted on open (256 MiB, covering >4M objects).
pub const MAX_INDEX_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;

/// Recorded metadata for one packfile in the index inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackInventoryEntry {
    /// Pack identifier.
    pub pack_id: PackId,
    /// Exact on-disk byte length of the packfile when indexed.
    pub file_len: u64,
    /// Whether this packfile has a verified `FSSF`..`FSSE` sealed footer.
    pub sealed: bool,
}

/// Reason why the derived index was rebuilt from packfiles on open.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IndexRebuildReason {
    /// `pack-index.fssi` did not exist on disk.
    Missing,
    /// `pack-index.fssi` failed magic, version, structural, or SHA-256 verification.
    Corrupt,
    /// `pack-index.fssi` did not match the exact packfile inventory and byte lengths on disk.
    StaleInventory,
    /// An unsealed active pack required tail recovery or truncation.
    ActivePackRecovered,
}

/// Result of attempting to load `pack-index.fssi` against the observed on-disk pack inventory.
#[derive(Debug)]
pub enum IndexLoadOutcome {
    /// Snapshot verified and matched the exact packfiles on disk.
    Loaded(PackIndex),
    /// Snapshot could not be trusted and must be rebuilt deterministically from packfiles.
    NeedsRebuild(IndexRebuildReason),
}

/// In-memory content-address index mapping SHA-256 [`ContentDigest`]s to [`PackLocation`]s.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackIndex {
    entries: HashMap<[u8; 32], PackLocation>,
    packs: BTreeMap<PackId, PackInventoryEntry>,
    total_payload_bytes: u64,
}

impl PackIndex {
    /// Creates an empty pack index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of unique content-addressed objects indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no objects are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns cumulative unique logical payload bytes across all indexed objects.
    #[must_use]
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    /// Returns the indexed packfile inventory keyed by [`PackId`].
    #[must_use]
    pub const fn packs(&self) -> &BTreeMap<PackId, PackInventoryEntry> {
        &self.packs
    }

    /// Looks up a SHA-256 content digest in O(1) time.
    #[must_use]
    pub fn get(&self, digest: &ContentDigest) -> Option<PackLocation> {
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return None;
        }
        self.entries.get(&digest.bytes()).copied()
    }

    /// Looks up a raw 32-byte SHA-256 digest in O(1) time.
    #[must_use]
    pub fn get_sha256(&self, sha256_bytes: &[u8; 32]) -> Option<PackLocation> {
        self.entries.get(sha256_bytes).copied()
    }

    /// Returns true if `digest` is currently indexed.
    #[must_use]
    pub fn contains(&self, digest: &ContentDigest) -> bool {
        self.get(digest).is_some()
    }

    /// Inserts a location for `sha256_bytes` if not already present (first writer wins for dedup).
    ///
    /// Returns `true` if newly inserted or `false` if already present.
    pub fn insert_if_absent(
        &mut self,
        sha256_bytes: [u8; 32],
        location: PackLocation,
    ) -> Result<bool, PackError> {
        if self.entries.contains_key(&sha256_bytes) {
            return Ok(false);
        }
        self.total_payload_bytes = self
            .total_payload_bytes
            .checked_add(location.len)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.entries.insert(sha256_bytes, location);
        Ok(true)
    }

    /// Inserts or atomically replaces the location for `sha256_bytes`, updating payload accounting.
    ///
    /// Used during online packfile compaction and deterministic index rebuilds so live objects
    /// point to their newest compacted sealed packfile without losing payload accounting.
    pub fn insert_or_replace(
        &mut self,
        sha256_bytes: [u8; 32],
        location: PackLocation,
    ) -> Result<Option<PackLocation>, PackError> {
        let previous = self.entries.insert(sha256_bytes, location);
        if let Some(prev) = previous {
            self.total_payload_bytes = self
                .total_payload_bytes
                .saturating_sub(prev.len)
                .checked_add(location.len)
                .ok_or(PackError::ArithmeticOverflow)?;
        } else {
            self.total_payload_bytes = self
                .total_payload_bytes
                .checked_add(location.len)
                .ok_or(PackError::ArithmeticOverflow)?;
        }
        Ok(previous)
    }

    /// Removes a tombstoned or superseded digest from the index, updating payload byte accounting.
    pub fn remove_sha256(&mut self, sha256_bytes: &[u8; 32]) -> Option<PackLocation> {
        let removed = self.entries.remove(sha256_bytes)?;
        self.total_payload_bytes = self.total_payload_bytes.saturating_sub(removed.len);
        Some(removed)
    }

    /// Removes `pack_id` from the packfile inventory table after physical unlink.
    pub fn remove_pack(&mut self, pack_id: PackId) -> Option<PackInventoryEntry> {
        self.packs.remove(&pack_id)
    }

    /// Returns metadata for `pack_id` if present in the inventory.
    #[must_use]
    pub fn pack_entry(&self, pack_id: PackId) -> Option<PackInventoryEntry> {
        self.packs.get(&pack_id).copied()
    }

    /// Returns all sealed [`PackId`]s in deterministic ascending order.
    #[must_use]
    pub fn sealed_pack_ids(&self) -> Vec<PackId> {
        self.packs
            .values()
            .filter(|entry| entry.sealed)
            .map(|entry| entry.pack_id)
            .collect()
    }

    /// Records or updates packfile inventory metadata.
    pub fn upsert_pack(&mut self, entry: PackInventoryEntry) {
        self.packs.insert(entry.pack_id, entry);
    }

    /// Marks every indexed object in `pack_id` as [`PackObjectState::Sealed`] and updates its
    /// inventory byte length.
    pub fn mark_pack_sealed(&mut self, pack_id: PackId, sealed_file_len: u64) {
        for loc in self.entries.values_mut() {
            if loc.pack_id == pack_id {
                loc.state = PackObjectState::Sealed;
            }
        }
        self.packs.insert(
            pack_id,
            PackInventoryEntry {
                pack_id,
                file_len: sealed_file_len,
                sealed: true,
            },
        );
    }

    /// Returns all indexed digests and locations in deterministic ascending digest order.
    #[must_use]
    pub fn sorted_entries(&self) -> Vec<([u8; 32], PackLocation)> {
        let mut items: Vec<([u8; 32], PackLocation)> =
            self.entries.iter().map(|(&k, &v)| (k, v)).collect();
        items.sort_unstable_by_key(|a| a.0);
        items
    }

    /// Encodes the index deterministically into compact `FSSI` binary bytes with SHA-256 trailer.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, PackError> {
        let sorted = self.sorted_entries();
        let packs_bytes = self
            .packs
            .len()
            .checked_mul(PACK_INVENTORY_ENTRY_LEN)
            .ok_or(PackError::ArithmeticOverflow)?;
        let entries_bytes = sorted
            .len()
            .checked_mul(INDEX_ENTRY_LEN)
            .ok_or(PackError::ArithmeticOverflow)?;
        let total = INDEX_HEADER_LEN
            .checked_add(packs_bytes)
            .and_then(|v| v.checked_add(entries_bytes))
            .and_then(|v| v.checked_add(INDEX_TRAILER_LEN))
            .ok_or(PackError::ArithmeticOverflow)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&PACK_INDEX_MAGIC);
        out.extend_from_slice(&PACK_INDEX_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&(self.packs.len() as u64).to_be_bytes());
        out.extend_from_slice(&(sorted.len() as u64).to_be_bytes());

        for pack in self.packs.values() {
            out.extend_from_slice(&pack.pack_id.epoch.to_be_bytes());
            out.extend_from_slice(&pack.pack_id.seq.to_be_bytes());
            out.extend_from_slice(&pack.file_len.to_be_bytes());
            out.push(u8::from(pack.sealed));
        }

        for (digest_bytes, loc) in sorted {
            out.extend_from_slice(&digest_bytes);
            out.extend_from_slice(&loc.pack_id.epoch.to_be_bytes());
            out.extend_from_slice(&loc.pack_id.seq.to_be_bytes());
            out.extend_from_slice(&loc.offset.to_be_bytes());
            out.extend_from_slice(&loc.len.to_be_bytes());
            out.extend_from_slice(&loc.object_kind.to_be_bytes());
            out.extend_from_slice(&loc.flags.to_be_bytes());
            out.push(loc.state.to_tag());
        }

        let trailer = sha256(&out);
        out.extend_from_slice(&trailer);
        Ok(out)
    }

    /// Decodes and verifies a compact `FSSI` binary snapshot byte slice.
    pub fn decode_snapshot(raw: &[u8]) -> Result<Self, PackError> {
        if raw.len() < INDEX_HEADER_LEN + INDEX_TRAILER_LEN {
            return Err(PackError::CorruptIndex {
                detail: "index snapshot shorter than header + trailer".to_owned(),
            });
        }
        let body_len = raw.len() - INDEX_TRAILER_LEN;
        let (body, trailer) = raw.split_at(body_len);
        let expected_trailer = sha256(body);
        if trailer != expected_trailer {
            return Err(PackError::CorruptIndex {
                detail: "index snapshot SHA-256 trailer mismatch".to_owned(),
            });
        }
        if body[0..4] != PACK_INDEX_MAGIC {
            return Err(PackError::CorruptIndex {
                detail: "invalid FSSI index magic".to_owned(),
            });
        }
        let version = u16::from_be_bytes([body[4], body[5]]);
        if version != PACK_INDEX_VERSION {
            return Err(PackError::CorruptIndex {
                detail: format!("unsupported FSSI index version {version}"),
            });
        }
        let flags = u16::from_be_bytes([body[6], body[7]]);
        if flags != 0 {
            return Err(PackError::CorruptIndex {
                detail: format!("unsupported FSSI index flags {flags}"),
            });
        }

        let pack_count_u64 = u64::from_be_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]);
        let entry_count_u64 = u64::from_be_bytes([
            body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
        ]);
        let pack_count = usize::try_from(pack_count_u64).map_err(|_| PackError::CorruptIndex {
            detail: "pack_count overflows usize".to_owned(),
        })?;
        let entry_count =
            usize::try_from(entry_count_u64).map_err(|_| PackError::CorruptIndex {
                detail: "entry_count overflows usize".to_owned(),
            })?;

        let expected_body_len = INDEX_HEADER_LEN
            .checked_add(
                pack_count
                    .checked_mul(PACK_INVENTORY_ENTRY_LEN)
                    .ok_or(PackError::ArithmeticOverflow)?,
            )
            .and_then(|v| {
                v.checked_add(
                    entry_count
                        .checked_mul(INDEX_ENTRY_LEN)
                        .ok_or(PackError::ArithmeticOverflow)
                        .ok()?,
                )
            })
            .ok_or(PackError::ArithmeticOverflow)?;
        if body.len() != expected_body_len {
            return Err(PackError::CorruptIndex {
                detail: format!(
                    "index body length mismatch: expected {expected_body_len}, observed {}",
                    body.len()
                ),
            });
        }

        let mut cursor = INDEX_HEADER_LEN;
        let mut packs = BTreeMap::new();
        let mut prev_pack_id: Option<PackId> = None;
        for _ in 0..pack_count {
            let epoch = u32::from_be_bytes([
                body[cursor],
                body[cursor + 1],
                body[cursor + 2],
                body[cursor + 3],
            ]);
            let seq = u64::from_be_bytes([
                body[cursor + 4],
                body[cursor + 5],
                body[cursor + 6],
                body[cursor + 7],
                body[cursor + 8],
                body[cursor + 9],
                body[cursor + 10],
                body[cursor + 11],
            ]);
            let file_len = u64::from_be_bytes([
                body[cursor + 12],
                body[cursor + 13],
                body[cursor + 14],
                body[cursor + 15],
                body[cursor + 16],
                body[cursor + 17],
                body[cursor + 18],
                body[cursor + 19],
            ]);
            let sealed_byte = body[cursor + 20];
            let sealed = match sealed_byte {
                0 => false,
                1 => true,
                _ => {
                    return Err(PackError::CorruptIndex {
                        detail: format!("invalid sealed flag byte {sealed_byte}"),
                    });
                }
            };
            cursor += PACK_INVENTORY_ENTRY_LEN;

            let pack_id = PackId::new(epoch, seq);
            if epoch == 0 || seq == 0 {
                return Err(PackError::CorruptIndex {
                    detail: "pack id contains zero epoch or seq".to_owned(),
                });
            }
            if let Some(prev) = prev_pack_id
                && prev >= pack_id
            {
                return Err(PackError::CorruptIndex {
                    detail: "pack inventory not strictly sorted".to_owned(),
                });
            }
            prev_pack_id = Some(pack_id);
            packs.insert(
                pack_id,
                PackInventoryEntry {
                    pack_id,
                    file_len,
                    sealed,
                },
            );
        }

        let mut entries = HashMap::with_capacity(entry_count);
        let mut total_payload_bytes = 0_u64;
        let mut prev_digest: Option<[u8; 32]> = None;
        for _ in 0..entry_count {
            let mut sha256_bytes = [0_u8; 32];
            sha256_bytes.copy_from_slice(&body[cursor..cursor + 32]);
            let epoch = u32::from_be_bytes([
                body[cursor + 32],
                body[cursor + 33],
                body[cursor + 34],
                body[cursor + 35],
            ]);
            let seq = u64::from_be_bytes([
                body[cursor + 36],
                body[cursor + 37],
                body[cursor + 38],
                body[cursor + 39],
                body[cursor + 40],
                body[cursor + 41],
                body[cursor + 42],
                body[cursor + 43],
            ]);
            let offset = u64::from_be_bytes([
                body[cursor + 44],
                body[cursor + 45],
                body[cursor + 46],
                body[cursor + 47],
                body[cursor + 48],
                body[cursor + 49],
                body[cursor + 50],
                body[cursor + 51],
            ]);
            let len = u64::from_be_bytes([
                body[cursor + 52],
                body[cursor + 53],
                body[cursor + 54],
                body[cursor + 55],
                body[cursor + 56],
                body[cursor + 57],
                body[cursor + 58],
                body[cursor + 59],
            ]);
            let object_kind = u16::from_be_bytes([body[cursor + 60], body[cursor + 61]]);
            let entry_flags = u16::from_be_bytes([body[cursor + 62], body[cursor + 63]]);
            let state = PackObjectState::from_tag(body[cursor + 64]).ok_or_else(|| {
                PackError::CorruptIndex {
                    detail: format!("invalid object state tag {}", body[cursor + 64]),
                }
            })?;
            cursor += INDEX_ENTRY_LEN;

            if let Some(prev) = prev_digest
                && prev >= sha256_bytes
            {
                return Err(PackError::CorruptIndex {
                    detail: "index entries not strictly sorted by digest".to_owned(),
                });
            }
            prev_digest = Some(sha256_bytes);

            let pack_id = PackId::new(epoch, seq);
            let Some(pack_meta) = packs.get(&pack_id) else {
                return Err(PackError::CorruptIndex {
                    detail: format!("index entry references unknown pack {pack_id}"),
                });
            };
            let record_end = offset
                .checked_add(crate::format::PACK_RECORD_OVERHEAD_LEN as u64)
                .and_then(|v| v.checked_add(len))
                .ok_or(PackError::ArithmeticOverflow)?;
            if record_end > pack_meta.file_len {
                return Err(PackError::CorruptIndex {
                    detail: format!(
                        "index entry span {offset}..{record_end} exceeds pack {pack_id} length {}",
                        pack_meta.file_len
                    ),
                });
            }
            total_payload_bytes = total_payload_bytes
                .checked_add(len)
                .ok_or(PackError::ArithmeticOverflow)?;
            entries.insert(
                sha256_bytes,
                PackLocation {
                    pack_id,
                    offset,
                    len,
                    object_kind,
                    flags: entry_flags,
                    state,
                },
            );
        }

        Ok(Self {
            entries,
            packs,
            total_payload_bytes,
        })
    }

    /// Atomically persists the index snapshot (`pack-index.fssi.tmp` -> sync -> rename -> dir sync).
    pub fn save_atomic(
        &self,
        index_dir: &Path,
        durability: DurabilityMode,
    ) -> Result<usize, PackError> {
        let encoded = self.encode_snapshot()?;
        let tmp_path = index_dir.join("pack-index.fssi.tmp");
        let final_path = index_dir.join("pack-index.fssi");

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        write_all_bounded(&mut file, &encoded)?;
        durability.sync_file(&file)?;
        drop(file);

        fs::rename(&tmp_path, &final_path)
            .map_err(|err| PackError::io(PackIoOperation::Rename, err))?;
        sync_dir(index_dir, durability)?;
        Ok(encoded.len())
    }

    /// Attempts to load `pack-index.fssi` and checks that its pack inventory exactly matches
    /// the on-disk packfiles `(PackId -> file_len)`.
    pub fn load_verified(
        index_path: &Path,
        on_disk_packs: &BTreeMap<PackId, u64>,
    ) -> IndexLoadOutcome {
        let mut file = match File::open(index_path) {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Missing);
            }
            Err(_) => return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt),
        };
        let Ok(meta) = file.metadata() else {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt);
        };
        if meta.len() > MAX_INDEX_SNAPSHOT_BYTES {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt);
        }
        let Ok(expected_len) = usize::try_from(meta.len()) else {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt);
        };
        let mut raw = Vec::with_capacity(expected_len);
        if file.read_to_end(&mut raw).is_err() {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt);
        }
        let Ok(index) = Self::decode_snapshot(&raw) else {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::Corrupt);
        };

        if index.packs.len() != on_disk_packs.len() {
            return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::StaleInventory);
        }
        for (pack_id, &disk_len) in on_disk_packs {
            match index.packs.get(pack_id) {
                Some(entry) if entry.file_len == disk_len => {}
                _ => return IndexLoadOutcome::NeedsRebuild(IndexRebuildReason::StaleInventory),
            }
        }

        IndexLoadOutcome::Loaded(index)
    }
}
