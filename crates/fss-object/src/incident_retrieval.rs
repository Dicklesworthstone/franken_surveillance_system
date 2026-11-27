#![forbid(unsafe_code)]
//! Deterministic incident archive retrieval and independent verification (`FSS-068`, `fss-x4a.13.8`).
//!
//! Verifies an archived incident object graph independently of local source media (`INV-046`,
//! `INV-047`, `INV-048`, `INV-066`, `INV-067`, `INV-075`):
//! - **Authority-before-read:** checks explicit principal capability scope and allowed incident
//!   roots BEFORE touching any retrieved payload bytes or expanding manifest children.
//! - **Non-collapse custody ladder:** enforces [`CustodyLevel`] floors (`Staged`, `Verified`,
//!   `Visible`, `Durable`, `Replicated`, `Protected`, `Retrievable`) so a staged or merely
//!   replicated object NEVER satisfies `Retrievable`.
//! - **Independent rehash + closure + encryption-context binding:** independently rehashes every
//!   retrieved object (`ContentDigest::sha256(&bytes) == digest`), parses every [`ObjectManifest`]
//!   via canonical bytes, traverses the full child closure without cycles, and verifies optional
//!   [`EncryptionContextManifest`] coverage for every retrieved leaf object without exposing secrets.
//! - **Honest uncertainty preservation:** missing, corrupt, tombstoned, below-floor, or remote
//!   `indeterminate` observations NEVER upgrade to `VerifiedRetrievableComplete` and retain partial
//!   verified evidence alongside exact diagnostic lists in a tamper-evident [`IncidentRetrievalReceipt`].

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::ObjectManifest;
use crate::closure::CustodyLevel;
use crate::encryption::EncryptionContextManifest;

/// Registered digest domain for canonical incident retrieval verification receipts
/// (`SCHEMA-DOMAIN-OBJECT-INCIDENT-RETRIEVAL-001`).
pub const INCIDENT_RETRIEVAL_RECEIPT_DOMAIN: &str = "fss.object.incident_retrieval_receipt.v1";

/// Canonical binary format version for [`IncidentRetrievalReceipt`].
pub const INCIDENT_RETRIEVAL_FORMAT_VERSION: u32 = 1;

/// Maximum objects traversed in one bounded incident retrieval verification pass.
pub const MAX_INCIDENT_OBJECTS: usize = 65_536;

/// Maximum cumulative bytes verified in one bounded incident retrieval pass (512 MiB).
pub const MAX_INCIDENT_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum UTF-8 bytes in incident or principal labels.
pub const MAX_INCIDENT_LABEL_BYTES: usize = 128;

/// Explicit owner/operator authority scope required prior to reading or expanding an incident graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentRetrievalAuthority {
    /// Clean non-empty incident identifier.
    pub incident_id: String,
    /// Clean non-empty authorized principal identifier.
    pub principal_id: String,
    /// Content digest of the explicit authority grant / capability lease.
    pub authority_grant_digest: ContentDigest,
    /// Pinned archive/policy generation (`!= 0`).
    pub generation: Generation,
    /// Explicit set of incident root digests this authority grant is permitted to retrieve.
    pub allowed_incident_roots: BTreeSet<ContentDigest>,
    /// Minimum custody level required for every object in the verified incident closure.
    pub required_custody_floor: CustodyLevel,
    /// Hard object traversal ceiling (`1..=MAX_INCIDENT_OBJECTS`).
    pub max_objects: usize,
    /// Hard cumulative byte ceiling (`1..=MAX_INCIDENT_BYTES`).
    pub max_bytes: u64,
}

impl IncidentRetrievalAuthority {
    /// Fails closed on empty/malformed labels, zero generation, or invalid bounds.
    pub fn validate(&self) -> Result<(), IncidentRetrievalError> {
        if !is_clean_label(&self.incident_id)
            || !is_clean_label(&self.principal_id)
            || self.generation.0 == 0
            || self.max_objects == 0
            || self.max_objects > MAX_INCIDENT_OBJECTS
            || self.max_bytes == 0
            || self.max_bytes > MAX_INCIDENT_BYTES
        {
            return Err(IncidentRetrievalError::InvalidAuthority);
        }
        Ok(())
    }
}

/// One remotely retrieved archive object presented for independent verification (never from local
/// raw source custody).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievedObjectRecord {
    /// Expected content digest of this object.
    pub digest: ContentDigest,
    /// Exact retrieved bytes to rehash independently.
    pub bytes: Vec<u8>,
    /// Observed archive custody state reported for this object.
    pub observed_custody: CustodyLevel,
    /// Whether this object is an [`ObjectManifest`] whose child closure must be expanded.
    pub is_manifest: bool,
    /// Whether this object has been tombstoned/deleted under retention/deletion policy.
    pub tombstoned: bool,
    /// Whether remote observation for this object remained indeterminate (e.g., ambiguous S3 head).
    pub indeterminate_remote_state: bool,
}

/// Non-collapsed verification verdict for one incident archive retrieval drill.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IncidentRetrievalStatus {
    /// Complete incident closure verified via independent rehash, custody floor, and encryption context.
    VerifiedRetrievableComplete,
    /// Authority check refused before touching object bytes or expanding graph edges.
    UnauthorizedScope,
    /// One or more objects were missing, corrupt, tombstoned, uncovered by encryption context, or
    /// below the required custody floor; valid partial objects are preserved honestly.
    PartialCorruptOrMissing,
    /// One or more objects had indeterminate remote completion/visibility; never promoted to verified.
    IndeterminateRemoteObservation,
}

impl IncidentRetrievalStatus {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedRetrievableComplete => "verified_retrievable_complete",
            Self::UnauthorizedScope => "unauthorized_scope",
            Self::PartialCorruptOrMissing => "partial_corrupt_or_missing",
            Self::IndeterminateRemoteObservation => "indeterminate_remote_observation",
        }
    }
}

impl CanonicalEncode for IncidentRetrievalStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::VerifiedRetrievableComplete => 1,
            Self::UnauthorizedScope => 2,
            Self::PartialCorruptOrMissing => 3,
            Self::IndeterminateRemoteObservation => 4,
        });
    }
}

impl CanonicalDecode for IncidentRetrievalStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::VerifiedRetrievableComplete),
            2 => Ok(Self::UnauthorizedScope),
            3 => Ok(Self::PartialCorruptOrMissing),
            4 => Ok(Self::IndeterminateRemoteObservation),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed fail-closed refusal for incident retrieval operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IncidentRetrievalError {
    /// Authority configuration, labels, or bounds are invalid.
    InvalidAuthority,
    /// Object count or cumulative byte budget exceeded before completing traversal.
    BudgetExceeded {
        /// Observed object count.
        objects: usize,
        /// Observed byte count.
        bytes: u64,
    },
    /// Cooperative cancellation observed before sealing verification receipt.
    Cancelled,
}

impl fmt::Display for IncidentRetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthority => write!(f, "invalid incident retrieval authority"),
            Self::BudgetExceeded { objects, bytes } => {
                write!(
                    f,
                    "incident retrieval budget exceeded (objects={objects}, bytes={bytes})"
                )
            }
            Self::Cancelled => write!(f, "incident retrieval verification cancelled"),
        }
    }
}

impl std::error::Error for IncidentRetrievalError {}

fn is_clean_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_INCIDENT_LABEL_BYTES
        && !s
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

fn custody_to_u8(level: CustodyLevel) -> u8 {
    match level {
        CustodyLevel::Staged => 1,
        CustodyLevel::Verified => 2,
        CustodyLevel::Visible => 3,
        CustodyLevel::Durable => 4,
        CustodyLevel::Replicated => 5,
        CustodyLevel::Protected => 6,
        CustodyLevel::Retrievable => 7,
    }
}

fn custody_from_u8(tag: u8) -> Result<CustodyLevel, ContractError> {
    match tag {
        1 => Ok(CustodyLevel::Staged),
        2 => Ok(CustodyLevel::Verified),
        3 => Ok(CustodyLevel::Visible),
        4 => Ok(CustodyLevel::Durable),
        5 => Ok(CustodyLevel::Replicated),
        6 => Ok(CustodyLevel::Protected),
        7 => Ok(CustodyLevel::Retrievable),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

/// Canonical, tamper-evident witness receipt for an incident archive retrieval & verification pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentRetrievalReceipt {
    /// Format version (`INCIDENT_RETRIEVAL_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable incident identifier.
    pub incident_id: String,
    /// Authorized principal identifier.
    pub principal_id: String,
    /// Authority grant digest.
    pub authority_grant_digest: ContentDigest,
    /// Pinned archive generation.
    pub generation: Generation,
    /// Target incident root manifest digest.
    pub incident_root: ContentDigest,
    /// Required custody floor evaluated against every node.
    pub required_custody_floor: CustodyLevel,
    /// Optional bound encryption-context manifest digest verified against all leaves.
    pub encryption_context_digest: Option<ContentDigest>,
    /// Verification timestamp.
    pub verified_at_ns: TimestampNs,
    /// Non-collapsed verification outcome.
    pub status: IncidentRetrievalStatus,
    /// Sorted unique digests of objects verified via independent SHA-256 rehash & custody floor.
    pub verified_objects: Vec<ContentDigest>,
    /// Cumulative verified bytes across `verified_objects`.
    pub verified_bytes: u64,
    /// Sorted unique digests missing from retrieved storage.
    pub missing_digests: Vec<ContentDigest>,
    /// Sorted unique digests whose bytes failed SHA-256 or canonical manifest decode.
    pub corrupt_digests: Vec<ContentDigest>,
    /// Sorted unique digests observed below `required_custody_floor`.
    pub below_custody_floor_digests: Vec<ContentDigest>,
    /// Sorted unique digests tombstoned/deleted.
    pub tombstoned_digests: Vec<ContentDigest>,
    /// Sorted unique digests whose remote observation remained indeterminate.
    pub indeterminate_digests: Vec<ContentDigest>,
    /// Sorted unique leaf digests not covered by the bound `EncryptionContextManifest`.
    pub uncovered_encryption_digests: Vec<ContentDigest>,
    /// Always `false`: retrieval verification operates strictly without reading local raw source.
    pub read_local_source: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl IncidentRetrievalReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(INCIDENT_RETRIEVAL_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.incident_id);
        encoder.text(&self.principal_id);
        encoder.digest(self.authority_grant_digest);
        encoder.u64(self.generation.0);
        encoder.digest(self.incident_root);
        encoder.u8(custody_to_u8(self.required_custody_floor));
        match self.encryption_context_digest {
            Some(d) => {
                encoder.u8(1);
                encoder.digest(d);
            }
            None => encoder.u8(0),
        }
        encoder.i128(self.verified_at_ns.0);
        self.status.encode_canonical(&mut encoder);
        encode_digest_list(&mut encoder, &self.verified_objects);
        encoder.u64(self.verified_bytes);
        encode_digest_list(&mut encoder, &self.missing_digests);
        encode_digest_list(&mut encoder, &self.corrupt_digests);
        encode_digest_list(&mut encoder, &self.below_custody_floor_digests);
        encode_digest_list(&mut encoder, &self.tombstoned_digests);
        encode_digest_list(&mut encoder, &self.indeterminate_digests);
        encode_digest_list(&mut encoder, &self.uncovered_encryption_digests);
        encoder.u8(u8::from(self.read_local_source));
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

fn encode_digest_list(encoder: &mut CanonicalEncoder, list: &[ContentDigest]) {
    encoder.u64(list.len() as u64);
    for d in list {
        encoder.digest(*d);
    }
}

fn decode_sorted_digest_list(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Vec<ContentDigest>, ContractError> {
    let count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
    // Prevent hostile wire pre-allocation beyond both MAX_INCIDENT_OBJECTS and remaining bytes
    // (each canonical ContentDigest occupies 1 algorithm tag byte + 32 digest bytes = 33 bytes).
    if count > MAX_INCIDENT_OBJECTS || count > decoder.remaining() / 33 {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decoder.digest()?);
    }
    if !out.windows(2).all(|w| w[0] < w[1]) {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(out)
}

impl CanonicalEncode for IncidentRetrievalReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.incident_id);
        encoder.text(&self.principal_id);
        encoder.digest(self.authority_grant_digest);
        encoder.u64(self.generation.0);
        encoder.digest(self.incident_root);
        encoder.u8(custody_to_u8(self.required_custody_floor));
        match self.encryption_context_digest {
            Some(d) => {
                encoder.u8(1);
                encoder.digest(d);
            }
            None => encoder.u8(0),
        }
        encoder.i128(self.verified_at_ns.0);
        self.status.encode_canonical(encoder);
        encode_digest_list(encoder, &self.verified_objects);
        encoder.u64(self.verified_bytes);
        encode_digest_list(encoder, &self.missing_digests);
        encode_digest_list(encoder, &self.corrupt_digests);
        encode_digest_list(encoder, &self.below_custody_floor_digests);
        encode_digest_list(encoder, &self.tombstoned_digests);
        encode_digest_list(encoder, &self.indeterminate_digests);
        encode_digest_list(encoder, &self.uncovered_encryption_digests);
        encoder.u8(u8::from(self.read_local_source));
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for IncidentRetrievalReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != INCIDENT_RETRIEVAL_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let incident_id = decoder.text()?.to_owned();
        let principal_id = decoder.text()?.to_owned();
        let authority_grant_digest = decoder.digest()?;
        let generation = Generation(decoder.u64()?);
        let incident_root = decoder.digest()?;
        let required_custody_floor = custody_from_u8(decoder.u8()?)?;
        let encryption_context_digest = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.digest()?),
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let verified_at_ns = TimestampNs(decoder.i128()?);
        let status = IncidentRetrievalStatus::decode_canonical(decoder)?;
        let verified_objects = decode_sorted_digest_list(decoder)?;
        let verified_bytes = decoder.u64()?;
        let missing_digests = decode_sorted_digest_list(decoder)?;
        let corrupt_digests = decode_sorted_digest_list(decoder)?;
        let below_custody_floor_digests = decode_sorted_digest_list(decoder)?;
        let tombstoned_digests = decode_sorted_digest_list(decoder)?;
        let indeterminate_digests = decode_sorted_digest_list(decoder)?;
        let uncovered_encryption_digests = decode_sorted_digest_list(decoder)?;
        let read_local_source = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let receipt_digest = decoder.digest()?;

        if !is_clean_label(&incident_id)
            || !is_clean_label(&principal_id)
            || generation.0 == 0
            || read_local_source
            || verified_bytes > MAX_INCIDENT_BYTES
            || (verified_objects.is_empty() && verified_bytes != 0)
        {
            return Err(ContractError::InvalidIdentifier);
        }

        // Every digest across verified and defect sets must be pairwise disjoint and bounded.
        let mut all_seen = BTreeSet::new();
        for list in [
            &verified_objects,
            &missing_digests,
            &corrupt_digests,
            &below_custody_floor_digests,
            &tombstoned_digests,
            &indeterminate_digests,
            &uncovered_encryption_digests,
        ] {
            for &d in list {
                if !all_seen.insert(d) || all_seen.len() > MAX_INCIDENT_OBJECTS {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
        }

        // Strict non-collapse status invariants enforced even against recomputed SHA-256 forgeries!
        let has_hard_defect = !missing_digests.is_empty()
            || !corrupt_digests.is_empty()
            || !below_custody_floor_digests.is_empty()
            || !tombstoned_digests.is_empty()
            || !uncovered_encryption_digests.is_empty();
        let has_indeterminate = !indeterminate_digests.is_empty();
        let status_valid = match status {
            IncidentRetrievalStatus::VerifiedRetrievableComplete => {
                verified_objects.binary_search(&incident_root).is_ok()
                    && !has_hard_defect
                    && !has_indeterminate
            }
            IncidentRetrievalStatus::UnauthorizedScope => {
                verified_objects.is_empty()
                    && verified_bytes == 0
                    && !has_hard_defect
                    && !has_indeterminate
            }
            IncidentRetrievalStatus::PartialCorruptOrMissing => has_hard_defect,
            IncidentRetrievalStatus::IndeterminateRemoteObservation => {
                !has_hard_defect && has_indeterminate
            }
        };
        if !status_valid {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            incident_id,
            principal_id,
            authority_grant_digest,
            generation,
            incident_root,
            required_custody_floor,
            encryption_context_digest,
            verified_at_ns,
            status,
            verified_objects,
            verified_bytes,
            missing_digests,
            corrupt_digests,
            below_custody_floor_digests,
            tombstoned_digests,
            indeterminate_digests,
            uncovered_encryption_digests,
            read_local_source,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

/// Independently verifies an archived incident object graph starting from `incident_root`,
/// strictly enforcing authority-before-read, independent SHA-256 verification, non-collapsed
/// [`CustodyLevel`] floors, optional [`EncryptionContextManifest`] coverage, bounded work, and
/// cooperative cancellation.
pub fn verify_incident_retrieval(
    authority: &IncidentRetrievalAuthority,
    incident_root: ContentDigest,
    retrieved_objects: &BTreeMap<ContentDigest, RetrievedObjectRecord>,
    encryption_context: Option<&EncryptionContextManifest>,
    verified_at_ns: TimestampNs,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<IncidentRetrievalReceipt, IncidentRetrievalError> {
    authority.validate()?;
    if is_cancelled() {
        return Err(IncidentRetrievalError::Cancelled);
    }

    if let Some(ctx) = encryption_context
        && (ctx.generation.0 == 0 || ctx.protected_objects.is_empty())
    {
        return Err(IncidentRetrievalError::InvalidAuthority);
    }
    let enc_ctx_digest = encryption_context.map(EncryptionContextManifest::digest);

    // Authority-before-read: unauthorized root NEVER reads object bytes or expands graph edges!
    if !authority.allowed_incident_roots.contains(&incident_root) {
        let mut receipt = IncidentRetrievalReceipt {
            format_version: INCIDENT_RETRIEVAL_FORMAT_VERSION,
            incident_id: authority.incident_id.clone(),
            principal_id: authority.principal_id.clone(),
            authority_grant_digest: authority.authority_grant_digest,
            generation: authority.generation,
            incident_root,
            required_custody_floor: authority.required_custody_floor,
            encryption_context_digest: enc_ctx_digest,
            verified_at_ns,
            status: IncidentRetrievalStatus::UnauthorizedScope,
            verified_objects: Vec::new(),
            verified_bytes: 0,
            missing_digests: Vec::new(),
            corrupt_digests: Vec::new(),
            below_custody_floor_digests: Vec::new(),
            tombstoned_digests: Vec::new(),
            indeterminate_digests: Vec::new(),
            uncovered_encryption_digests: Vec::new(),
            read_local_source: false,
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        return Ok(receipt);
    }

    let protected_set: Option<BTreeSet<ContentDigest>> =
        encryption_context.map(|ctx| ctx.protected_objects.iter().copied().collect());

    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();
    queue.push_back(incident_root);
    visited.insert(incident_root);

    let mut verified_objects = BTreeSet::new();
    let mut verified_bytes: u64 = 0;
    let mut scanned_bytes: u64 = 0;
    let mut missing_digests = BTreeSet::new();
    let mut corrupt_digests = BTreeSet::new();
    let mut below_custody_floor_digests = BTreeSet::new();
    let mut tombstoned_digests = BTreeSet::new();
    let mut indeterminate_digests = BTreeSet::new();
    let mut uncovered_encryption_digests = BTreeSet::new();
    let mut visited_count: usize = 0;

    while let Some(digest) = queue.pop_front() {
        if is_cancelled() {
            return Err(IncidentRetrievalError::Cancelled);
        }
        visited_count = visited_count.saturating_add(1);
        if visited_count > authority.max_objects {
            return Err(IncidentRetrievalError::BudgetExceeded {
                objects: visited_count,
                bytes: scanned_bytes,
            });
        }

        let Some(record) = retrieved_objects.get(&digest) else {
            missing_digests.insert(digest);
            continue;
        };

        if record.tombstoned {
            tombstoned_digests.insert(digest);
            continue;
        }

        if record.indeterminate_remote_state {
            indeterminate_digests.insert(digest);
            continue;
        }

        // Enforce cumulative byte scan budget BEFORE SHA-256 hashing so even a flood of corrupt
        // or below-floor blobs cannot exceed `authority.max_bytes` total hashed bytes.
        let obj_len = record.bytes.len() as u64;
        let next_scanned =
            scanned_bytes
                .checked_add(obj_len)
                .ok_or(IncidentRetrievalError::BudgetExceeded {
                    objects: visited_count,
                    bytes: u64::MAX,
                })?;
        if next_scanned > authority.max_bytes {
            return Err(IncidentRetrievalError::BudgetExceeded {
                objects: visited_count,
                bytes: next_scanned,
            });
        }
        scanned_bytes = next_scanned;

        // Independent SHA-256 digest check over retrieved bytes.
        if record.digest != digest || ContentDigest::sha256(&record.bytes) != digest {
            corrupt_digests.insert(digest);
            continue;
        }

        // Non-collapsed custody floor enforcement.
        if record.observed_custody < authority.required_custody_floor {
            below_custody_floor_digests.insert(digest);
            continue;
        }

        let next_bytes =
            verified_bytes
                .checked_add(obj_len)
                .ok_or(IncidentRetrievalError::BudgetExceeded {
                    objects: visited_count,
                    bytes: u64::MAX,
                })?;
        if next_bytes > authority.max_bytes {
            return Err(IncidentRetrievalError::BudgetExceeded {
                objects: visited_count,
                bytes: next_bytes,
            });
        }

        // Incident root MUST be a valid ObjectManifest; a non-manifest root cannot stand in for closure.
        if digest == incident_root && !record.is_manifest {
            corrupt_digests.insert(digest);
            continue;
        }

        if record.is_manifest {
            let Ok(manifest) = ObjectManifest::from_canonical_bytes(&record.bytes) else {
                corrupt_digests.insert(digest);
                continue;
            };
            if manifest.root() != digest {
                corrupt_digests.insert(digest);
                continue;
            }
            for &child in manifest.children() {
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        } else if let Some(ref protected) = protected_set
            && !protected.contains(&digest)
        {
            uncovered_encryption_digests.insert(digest);
            continue;
        }

        verified_objects.insert(digest);
        verified_bytes = next_bytes;
    }

    let has_hard_defect = !missing_digests.is_empty()
        || !corrupt_digests.is_empty()
        || !below_custody_floor_digests.is_empty()
        || !tombstoned_digests.is_empty()
        || !uncovered_encryption_digests.is_empty();
    let status = if has_hard_defect {
        IncidentRetrievalStatus::PartialCorruptOrMissing
    } else if !indeterminate_digests.is_empty() {
        IncidentRetrievalStatus::IndeterminateRemoteObservation
    } else {
        IncidentRetrievalStatus::VerifiedRetrievableComplete
    };

    let mut receipt = IncidentRetrievalReceipt {
        format_version: INCIDENT_RETRIEVAL_FORMAT_VERSION,
        incident_id: authority.incident_id.clone(),
        principal_id: authority.principal_id.clone(),
        authority_grant_digest: authority.authority_grant_digest,
        generation: authority.generation,
        incident_root,
        required_custody_floor: authority.required_custody_floor,
        encryption_context_digest: enc_ctx_digest,
        verified_at_ns,
        status,
        verified_objects: verified_objects.into_iter().collect(),
        verified_bytes,
        missing_digests: missing_digests.into_iter().collect(),
        corrupt_digests: corrupt_digests.into_iter().collect(),
        below_custody_floor_digests: below_custody_floor_digests.into_iter().collect(),
        tombstoned_digests: tombstoned_digests.into_iter().collect(),
        indeterminate_digests: indeterminate_digests.into_iter().collect(),
        uncovered_encryption_digests: uncovered_encryption_digests.into_iter().collect(),
        read_local_source: false,
        receipt_digest: ContentDigest::sha256(b"pending"),
    };
    receipt.receipt_digest = receipt.computed_digest();
    Ok(receipt)
}
