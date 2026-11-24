#![forbid(unsafe_code)]
//! Virtual root records, lifecycle status types, and receipts for [`crate::VirtualRootCatalog`].

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use crate::error::{PackError, QuotaResource};

/// Canonical digest domain tag for [`VirtualRootRecord`].
pub const PACK_VIRTUAL_ROOT_RECORD_DOMAIN: &str = "fss.pack.virtual_root_record.v1";

/// Maximum UTF-8 byte length of a virtual root identifier.
pub const MAX_ROOT_ID_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a virtual root kind tag.
pub const MAX_ROOT_KIND_BYTES: usize = 256;

/// Validates a stable virtual root identifier (`1..=128` ASCII `[a-zA-Z0-9._:-]`).
pub fn validate_root_id(root_id: &str) -> Result<(), PackError> {
    if root_id.is_empty() || root_id.len() > MAX_ROOT_ID_BYTES {
        return Err(PackError::InvalidRootRecord {
            detail: format!(
                "root_id length {} must be in 1..={MAX_ROOT_ID_BYTES}",
                root_id.len()
            ),
        });
    }
    if !root_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(PackError::InvalidRootRecord {
            detail: format!("root_id contains illegal character: {root_id}"),
        });
    }
    Ok(())
}

/// Immutable descriptor of one published virtual root in the catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualRootRecord {
    /// Stable unique identifier (never renumbered or reused once published).
    pub root_id: String,
    /// SHA-256 content identity of the root object or canonical manifest stored in a packfile.
    pub root_digest: ContentDigest,
    /// Semantic kind tag (e.g., `"media-gop-v1"`, `"event-manifest-v1"`).
    pub kind: String,
    /// Number of child objects in the published closure.
    pub child_count: u64,
    /// Logical payload bytes referenced by this root.
    pub total_payload_bytes: u64,
    /// Monotonic generation (`>= 1`).
    pub generation: u64,
    /// Caller-supplied creation timestamp (no ambient clock).
    pub created_at_ns: TimestampNs,
    /// Optional content digest of an attached metadata object.
    pub metadata_digest: Option<ContentDigest>,
}

impl VirtualRootRecord {
    /// Constructs and validates a [`VirtualRootRecord`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_id: impl Into<String>,
        root_digest: ContentDigest,
        kind: impl Into<String>,
        child_count: u64,
        total_payload_bytes: u64,
        generation: u64,
        created_at_ns: TimestampNs,
        metadata_digest: Option<ContentDigest>,
    ) -> Result<Self, PackError> {
        let record = Self {
            root_id: root_id.into(),
            root_digest,
            kind: kind.into(),
            child_count,
            total_payload_bytes,
            generation,
            created_at_ns,
            metadata_digest,
        };
        record.validate()?;
        Ok(record)
    }

    /// Constructs a [`VirtualRootRecord`] directly from a validated [`SlotName`] and [`ObjectManifest`].
    pub fn from_manifest(
        slot: &SlotName,
        manifest: &ObjectManifest,
        total_payload_bytes: u64,
        generation: u64,
        created_at_ns: TimestampNs,
    ) -> Result<Self, PackError> {
        Self::new(
            slot.as_str(),
            manifest.root(),
            manifest.kind(),
            manifest.children().len() as u64,
            total_payload_bytes,
            generation,
            created_at_ns,
            manifest.metadata_digest(),
        )
    }

    /// Validates all structural and algorithm invariants of this root record.
    pub fn validate(&self) -> Result<(), PackError> {
        validate_root_id(&self.root_id)?;
        if self.kind.is_empty() || self.kind.len() > MAX_ROOT_KIND_BYTES {
            return Err(PackError::InvalidRootRecord {
                detail: format!(
                    "root kind length {} must be in 1..={MAX_ROOT_KIND_BYTES}",
                    self.kind.len()
                ),
            });
        }
        if self.generation == 0 {
            return Err(PackError::InvalidRootRecord {
                detail: "root generation must be >= 1".to_owned(),
            });
        }
        if self.root_digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(
                self.root_digest.algorithm(),
            ));
        }
        if let Some(meta) = self.metadata_digest
            && meta.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(PackError::UnsupportedDigestAlgorithm(meta.algorithm()));
        }
        Ok(())
    }

    /// Computes the domain-separated canonical digest under [`PACK_VIRTUAL_ROOT_RECORD_DOMAIN`].
    #[must_use]
    pub fn record_digest(&self) -> ContentDigest {
        self.canonical_digest(PACK_VIRTUAL_ROOT_RECORD_DOMAIN)
    }
}

impl CanonicalEncode for VirtualRootRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.root_id);
        encoder.digest(self.root_digest);
        encoder.text(&self.kind);
        encoder.u64(self.child_count);
        encoder.u64(self.total_payload_bytes);
        encoder.u64(self.generation);
        self.created_at_ns.encode_canonical(encoder);
        match self.metadata_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(d);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for VirtualRootRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let root_id = decoder.text()?.to_owned();
        let root_digest = decoder.digest()?;
        let kind = decoder.text()?.to_owned();
        let child_count = decoder.u64()?;
        let total_payload_bytes = decoder.u64()?;
        let generation = decoder.u64()?;
        let created_at_ns = TimestampNs::decode_canonical(decoder)?;
        let metadata_digest = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        Ok(Self {
            root_id,
            root_digest,
            kind,
            child_count,
            total_payload_bytes,
            generation,
            created_at_ns,
            metadata_digest,
        })
    }
}

/// Lifecycle state of a cataloged virtual root (superseded and tombstoned entries remain retained).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootStatus {
    /// Currently active and live.
    Live,
    /// Atomically superseded by a newer stable root identifier.
    Superseded {
        /// Identifier of the replacement root.
        superseded_by: String,
        /// Journal sequence number at which supersession occurred.
        superseded_at_seq: u64,
    },
    /// Permanently tombstoned with an explicit reason/authority digest.
    Tombstoned {
        /// Digest witnessing the tombstone rationale or deletion authority.
        reason_digest: ContentDigest,
        /// Journal sequence number at which tombstoning occurred.
        tombstoned_at_seq: u64,
    },
}

/// Complete catalog entry stored for one virtual root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogRootEntry {
    /// Journal sequence number at which this root was originally published.
    pub sequence: u64,
    /// Immutable root descriptor.
    pub record: VirtualRootRecord,
    /// Optional predecessor root identifier if created via `supersede_root`.
    pub predecessor: Option<String>,
    /// Current lifecycle status (`Live`, `Superseded`, or `Tombstoned`).
    pub status: RootStatus,
}

impl CanonicalEncode for CatalogRootEntry {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.sequence);
        self.record.encode_canonical(encoder);
        match &self.predecessor {
            Some(pred) => {
                encoder.bool(true);
                encoder.text(pred);
            }
            None => encoder.bool(false),
        }
        match &self.status {
            RootStatus::Live => encoder.tag(1),
            RootStatus::Superseded {
                superseded_by,
                superseded_at_seq,
            } => {
                encoder.tag(2);
                encoder.text(superseded_by);
                encoder.u64(*superseded_at_seq);
            }
            RootStatus::Tombstoned {
                reason_digest,
                tombstoned_at_seq,
            } => {
                encoder.tag(3);
                encoder.digest(*reason_digest);
                encoder.u64(*tombstoned_at_seq);
            }
        }
    }
}

impl CanonicalDecode for CatalogRootEntry {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let sequence = decoder.u64()?;
        let record = VirtualRootRecord::decode_canonical(decoder)?;
        let predecessor = if decoder.bool()? {
            Some(decoder.text()?.to_owned())
        } else {
            None
        };
        let status = match decoder.tag()? {
            1 => RootStatus::Live,
            2 => {
                let superseded_by = decoder.text()?.to_owned();
                let superseded_at_seq = decoder.u64()?;
                RootStatus::Superseded {
                    superseded_by,
                    superseded_at_seq,
                }
            }
            3 => {
                let reason_digest = decoder.digest()?;
                let tombstoned_at_seq = decoder.u64()?;
                RootStatus::Tombstoned {
                    reason_digest,
                    tombstoned_at_seq,
                }
            }
            _ => return Err(ContractError::InvalidIdentifier),
        };
        Ok(Self {
            sequence,
            record,
            predecessor,
            status,
        })
    }
}

/// Soft quota observation returned with each root publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaStatus {
    /// Within all configured soft and hard limits.
    WithinPolicy,
    /// Succeeded, but live root count exceeded the configured soft threshold.
    SoftLimitExceeded {
        /// Dimension that crossed its soft threshold.
        resource: QuotaResource,
        /// Current usage after the operation.
        current: u64,
        /// Configured soft threshold.
        soft_limit: u64,
    },
}

/// Receipt emitted after a root publication or supersession is durably fsynced to `catalog.fssr`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPublishReceipt {
    /// Newly published catalog entry.
    pub entry: CatalogRootEntry,
    /// Quota policy status after publication.
    pub quota_status: QuotaStatus,
}

/// One deterministically ordered page of catalog root entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPage {
    /// Entries returned for this page in ascending `root_id` order.
    pub entries: Vec<CatalogRootEntry>,
    /// Opaque pagination cursor (`root_id` of the last returned entry) when `has_more` is true.
    pub next_cursor: Option<String>,
    /// True if additional entries follow beyond this page.
    pub has_more: bool,
}

/// Receipt emitted after compacting the catalog into `catalog.snap`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionReceipt {
    /// Journal sequence committed into the snapshot.
    pub snapshot_seq: u64,
    /// Total retained entries (live + superseded + tombstoned) written to `catalog.snap`.
    pub total_entries: u64,
    /// Live entries count at snapshot time.
    pub live_entries: u64,
    /// Final snapshot file byte length.
    pub snapshot_bytes: usize,
}

/// Summary of catalog recovery performed on open.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CatalogRecoveryReport {
    /// Sequence loaded from `catalog.snap` (0 if no snapshot existed).
    pub snapshot_seq: u64,
    /// Number of valid journal frames replayed from `catalog.fssr` after `snapshot_seq`.
    pub replayed_frames: u64,
    /// Trailing incomplete or corrupt bytes truncated from `catalog.fssr` on open.
    pub truncated_journal_bytes: u64,
    /// Total entries present after recovery.
    pub total_entries: u64,
    /// Live entries present after recovery.
    pub live_entries: u64,
}
