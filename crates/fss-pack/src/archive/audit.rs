#![forbid(unsafe_code)]
//! Cold-tier Range-GET + whole-pack retrievability audit and verified restore into [`PackStore`]
//! (`COMPREHENSIVE_PLAN §13.8–§13.9`).
//!
//! # Honest Verification Rule
//!
//! Partial Range-GET sampling or HEAD-only inspection NEVER produces
//! [`ColdRetrievabilityVerdict::Verified`]. Earning `Verified` requires BOTH every sampled
//! Range-GET byte slice matching the manifest ETag and full-object bytes AND the exact
//! whole-pack `ciphertext_sha256` and `ciphertext_bytes` matching [`ColdPackArchiveManifest`].

use std::path::Path;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs, sha256,
};
use fss_vault::constant_time_eq;

use crate::archive::manifest::ColdPackArchiveManifest;
use crate::archive::s3_pack::ColdPackTransport;
use crate::crypto::envelope::{KeyEncryptionKey, SCHEMA_EPOCH_PACKFILE};
use crate::crypto::erasure::escape_json_str;
use crate::crypto::keyring::KeyEnvelopeCatalog;
use crate::crypto::pack_io::{
    EncryptedStreamKind, decrypt_and_verify_pack_bytes, publish_restored_pack,
};
use crate::error::PackError;
use crate::format::{
    DurabilityMode, PACK_FOOTER_PREFIX_LEN, PACK_FOOTER_TAIL_LEN, PACK_RECORD_OVERHEAD_LEN, PackId,
    PackLocation, PackObjectInput, decode_footer_tail, decode_sealed_footer, verify_record_slice,
};
use crate::store::PackStore;

/// Canonical digest domain for [`ColdRetrievabilityAuditReceipt::receipt_digest`].
pub const PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN: &str = "fss.pack.cold_retrievability_audit.v1";

/// Explicit cold-tier retrievability verdict (`COMPREHENSIVE_PLAN §13.9`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ColdRetrievabilityVerdict {
    /// Every Range-GET sample AND the full whole-pack ciphertext SHA-256 matched the manifest.
    Verified,
    /// Remote bytes failed ETag consistency, length, range cross-check, or whole-pack SHA-256.
    Corrupted,
    /// Cold object was not found at the remote endpoint (HTTP 404).
    Missing,
    /// Transient transport failure OR partial-only check (never upgraded to `Verified`).
    Unknown,
}

impl ColdRetrievabilityVerdict {
    /// Encodes as a canonical 1-byte wire tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::Corrupted => 2,
            Self::Missing => 3,
            Self::Unknown => 4,
        }
    }

    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Corrupted => "corrupted",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }
}

/// Configuration for [`audit_cold_pack_retrievability`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdAuditConfig {
    /// Optional explicit `(start_offset, byte_len)` sample ranges in addition to deterministic ones.
    pub explicit_sample_ranges: Vec<(u64, u64)>,
    /// Number of deterministic head/mid/tail Range-GET samples (`0..=8`, default `3`).
    pub deterministic_sample_count: u32,
    /// Target byte length of each deterministic Range-GET sample (default `4096`).
    pub sample_range_bytes: u64,
    /// Whether to download and hash the entire ciphertext pack (MUST be `true` to emit `Verified`).
    pub verify_whole_pack: bool,
    /// Hard upper bound on bytes downloaded during whole-pack verification (`256 MiB` default).
    pub max_download_bytes: usize,
}

impl Default for ColdAuditConfig {
    fn default() -> Self {
        Self {
            explicit_sample_ranges: Vec::new(),
            deterministic_sample_count: 3,
            sample_range_bytes: 4096,
            verify_whole_pack: true,
            max_download_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Verification record for one bounded signed HTTP Range-GET sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColdRangeSampleResult {
    /// Inclusive start byte offset sampled.
    pub offset: u64,
    /// Number of bytes sampled.
    pub len: u64,
    /// SHA-256 computed over the sampled range bytes.
    pub sample_sha256: ContentDigest,
    /// Whether the returned ETag matched the manifest ETag.
    pub etag_matched: bool,
}

/// Canonical digest-bound receipt emitted by [`audit_cold_pack_retrievability`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdRetrievabilityAuditReceipt {
    /// Digest of the [`ColdPackArchiveManifest`] audited.
    pub manifest_digest: ContentDigest,
    /// Audited sealed pack identifier.
    pub pack_id: PackId,
    /// Opaque cold object key audited.
    pub object_key: String,
    /// Expected encrypted pack SHA-256 from the manifest.
    pub expected_ciphertext_sha256: ContentDigest,
    /// Observed encrypted pack SHA-256 when whole-pack verification completed.
    pub observed_ciphertext_sha256: Option<ContentDigest>,
    /// Observed remote ETag, if any response was received.
    pub observed_etag: Option<String>,
    /// Number of Range-GET samples planned.
    pub range_samples_requested: u32,
    /// Number of Range-GET samples that returned exact bounded bytes with matching ETag.
    pub range_samples_verified: u32,
    /// Individual sample results in deterministic offset order.
    pub sample_results: Vec<ColdRangeSampleResult>,
    /// `true` ONLY when full whole-pack SHA-256 and exact byte length matched the manifest.
    pub whole_pack_sha256_verified: bool,
    /// Cumulative verified bytes read across range samples and whole-pack verification.
    pub bytes_verified: u64,
    /// Explicit retrievability verdict (`Verified`, `Corrupted`, `Missing`, `Unknown`).
    pub verdict: ColdRetrievabilityVerdict,
    /// `true` whenever `Corrupted` or `Missing` requires creating a repair obligation.
    pub requires_repair_obligation: bool,
    /// Non-secret diagnostic explanation.
    pub detail: String,
    /// Explicit caller-supplied audit timestamp.
    pub audited_at_ns: TimestampNs,
    /// Canonical SHA-256 receipt digest under [`PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl ColdRetrievabilityAuditReceipt {
    /// Recomputes and verifies [`Self::receipt_digest`].
    pub fn verify_digest(&self) -> Result<(), PackError> {
        let expected = compute_audit_receipt_digest(self)?;
        if expected != self.receipt_digest {
            return Err(PackError::DigestMismatch {
                expected: self.receipt_digest,
                actual: expected,
            });
        }
        Ok(())
    }

    /// Renders a deterministic, zero-Serde, secret-free JSONL line for audit logs.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let observed_sha = self
            .observed_ciphertext_sha256
            .map_or_else(|| "null".to_owned(), |d| format!("\"{d}\""));
        let observed_etag = self.observed_etag.as_deref().map_or_else(
            || "null".to_owned(),
            |e| format!("\"{}\"", escape_json_str(e)),
        );
        format!(
            "{{\"schema\":\"{PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN}\",\"manifest_digest\":\"{}\",\"pack_id\":\"{}\",\"object_key\":\"{}\",\"expected_ciphertext_sha256\":\"{}\",\"observed_ciphertext_sha256\":{observed_sha},\"observed_etag\":{observed_etag},\"range_samples_requested\":{},\"range_samples_verified\":{},\"whole_pack_sha256_verified\":{},\"bytes_verified\":{},\"verdict\":\"{}\",\"requires_repair_obligation\":{},\"detail\":\"{}\",\"audited_at_ns\":{},\"receipt_digest\":\"{}\"}}",
            self.manifest_digest,
            self.pack_id,
            escape_json_str(&self.object_key),
            self.expected_ciphertext_sha256,
            self.range_samples_requested,
            self.range_samples_verified,
            self.whole_pack_sha256_verified,
            self.bytes_verified,
            self.verdict.as_str(),
            self.requires_repair_obligation,
            escape_json_str(&self.detail),
            self.audited_at_ns.0,
            self.receipt_digest,
        )
    }
}

/// Receipt emitted after verifying, decrypting, and restoring a cold pack into [`PackStore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdPackRestoreReceipt {
    /// Restored pack identifier.
    pub pack_id: PackId,
    /// Manifest digest verified during restore.
    pub manifest_digest: ContentDigest,
    /// Number of inner verified `FSSP` objects restored into the local store.
    pub restored_object_count: usize,
    /// Sorted content digests of every restored inner object.
    pub restored_digests: Vec<ContentDigest>,
    /// Assigned local [`PackLocation`]s returned by `PackStore::append_batch`.
    pub restored_locations: Vec<PackLocation>,
    /// Verified whole-file plaintext `.fssp` SHA-256.
    pub plaintext_pack_sha256: ContentDigest,
    /// Verified whole-file encrypted `.fsep` SHA-256.
    pub ciphertext_sha256: ContentDigest,
    /// Explicit caller-supplied restoration timestamp.
    pub restored_at_ns: TimestampNs,
}

/// Performs bounded signed HTTP Range-GET sampling + whole-pack SHA-256 verification against
/// `transport` (`COMPREHENSIVE_PLAN §13.8–§13.9`).
///
/// Never upgrades partial sampling (`config.verify_whole_pack == false`) to `Verified`.
pub fn audit_cold_pack_retrievability(
    transport: &mut dyn ColdPackTransport,
    manifest: &ColdPackArchiveManifest,
    config: &ColdAuditConfig,
    now_ns: TimestampNs,
) -> Result<ColdRetrievabilityAuditReceipt, PackError> {
    manifest.verify_digest()?;
    if config.deterministic_sample_count > 8 || config.sample_range_bytes == 0 {
        return Err(PackError::InvalidConfig {
            detail: "invalid ColdAuditConfig range sample parameters".to_owned(),
        });
    }

    let ranges = build_audit_ranges(manifest.ciphertext_bytes, config);
    let requested_count = u32::try_from(ranges.len()).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut sample_results = Vec::with_capacity(ranges.len());
    let mut verified_samples = 0_u32;
    let mut bytes_verified = 0_u64;
    let mut observed_etag: Option<String> = None;

    for (start, end) in ranges {
        match transport.get_object_range(&manifest.object_key, start, end, now_ns) {
            Ok(resp) => {
                let etag_matched = resp.etag == manifest.etag;
                observed_etag = Some(resp.etag.clone());
                let sample_sha = ContentDigest::sha256(&resp.body);
                let len = resp.body.len() as u64;
                sample_results.push(ColdRangeSampleResult {
                    offset: start,
                    len,
                    sample_sha256: sample_sha,
                    etag_matched,
                });
                let exact_range = resp.object_key == manifest.object_key
                    && resp.start_inclusive == start
                    && resp.end_inclusive == end
                    && len == end - start + 1;
                if !etag_matched || !exact_range {
                    return finalize_audit_receipt(
                        manifest,
                        None,
                        observed_etag,
                        requested_count,
                        verified_samples,
                        sample_results,
                        false,
                        bytes_verified,
                        ColdRetrievabilityVerdict::Corrupted,
                        "Range-GET identity, interval, length, or ETag differs from request".to_owned(),
                        now_ns,
                    );
                }
                bytes_verified = bytes_verified.saturating_add(len);
                verified_samples = verified_samples.saturating_add(1);
            }
            Err(PackError::ArchiveMissing { .. }) => {
                return finalize_audit_receipt(
                    manifest,
                    None,
                    observed_etag,
                    requested_count,
                    verified_samples,
                    sample_results,
                    false,
                    bytes_verified,
                    ColdRetrievabilityVerdict::Missing,
                    "cold pack object missing at remote endpoint (HTTP 404)".to_owned(),
                    now_ns,
                );
            }
            Err(PackError::ArchiveIntegrity { detail }) => {
                return finalize_audit_receipt(
                    manifest,
                    None,
                    observed_etag,
                    requested_count,
                    verified_samples,
                    sample_results,
                    false,
                    bytes_verified,
                    ColdRetrievabilityVerdict::Corrupted,
                    detail,
                    now_ns,
                );
            }
            Err(err) => {
                return finalize_audit_receipt(
                    manifest,
                    None,
                    observed_etag,
                    requested_count,
                    verified_samples,
                    sample_results,
                    false,
                    bytes_verified,
                    ColdRetrievabilityVerdict::Unknown,
                    format!("Range-GET transport indeterminate: {err}"),
                    now_ns,
                );
            }
        }
    }

    if !config.verify_whole_pack {
        return finalize_audit_receipt(
            manifest,
            None,
            observed_etag,
            requested_count,
            verified_samples,
            sample_results,
            false,
            bytes_verified,
            ColdRetrievabilityVerdict::Unknown,
            "partial Range-GET sampling passed; whole-pack SHA-256 verification required for Verified"
                .to_owned(),
            now_ns,
        );
    }

    let get_resp =
        match transport.get_object(&manifest.object_key, config.max_download_bytes, now_ns) {
            Ok(r) => r,
            Err(PackError::ArchiveMissing { .. }) => {
                return finalize_audit_receipt(
                    manifest,
                    None,
                    observed_etag,
                    requested_count,
                    verified_samples,
                    sample_results,
                    false,
                    bytes_verified,
                    ColdRetrievabilityVerdict::Missing,
                    "cold pack disappeared before whole-pack GET (HTTP 404)".to_owned(),
                    now_ns,
                );
            }
            Err(err) => {
                return finalize_audit_receipt(
                    manifest,
                    None,
                    observed_etag,
                    requested_count,
                    verified_samples,
                    sample_results,
                    false,
                    bytes_verified,
                    ColdRetrievabilityVerdict::Unknown,
                    format!("whole-pack GET transport indeterminate: {err}"),
                    now_ns,
                );
            }
        };

    observed_etag = Some(get_resp.etag.clone());
    let observed_sha = ContentDigest::sha256(&get_resp.body);

    if get_resp.object_key != manifest.object_key || get_resp.etag != manifest.etag {
        return finalize_audit_receipt(
            manifest,
            Some(observed_sha),
            observed_etag,
            requested_count,
            verified_samples,
            sample_results,
            false,
            bytes_verified,
            ColdRetrievabilityVerdict::Corrupted,
            "whole-pack GET object key or ETag mismatch against manifest".to_owned(),
            now_ns,
        );
    }
    if get_resp.body.len() as u64 != manifest.ciphertext_bytes {
        return finalize_audit_receipt(
            manifest,
            Some(observed_sha),
            observed_etag,
            requested_count,
            verified_samples,
            sample_results,
            false,
            bytes_verified,
            ColdRetrievabilityVerdict::Corrupted,
            format!(
                "whole-pack byte length {} != manifest ciphertext_bytes {}",
                get_resp.body.len(),
                manifest.ciphertext_bytes
            ),
            now_ns,
        );
    }
    for sample in &sample_results {
        let offset = sample.offset;
        let start = usize::try_from(offset).map_err(|_| PackError::ArithmeticOverflow)?;
        let len = usize::try_from(sample.len).map_err(|_| PackError::ArithmeticOverflow)?;
        let end = start.checked_add(len).ok_or(PackError::ArithmeticOverflow)?;
        if get_resp.body.get(start..end).map(ContentDigest::sha256) != Some(sample.sample_sha256) {
            return finalize_audit_receipt(
                manifest,
                Some(observed_sha),
                observed_etag,
                requested_count,
                verified_samples,
                sample_results,
                false,
                bytes_verified,
                ColdRetrievabilityVerdict::Corrupted,
                format!("Range-GET sample at offset {offset} diverged from whole-pack bytes"),
                now_ns,
            );
        }
    }
    if observed_sha != manifest.ciphertext_sha256 {
        return finalize_audit_receipt(
            manifest,
            Some(observed_sha),
            observed_etag,
            requested_count,
            verified_samples,
            sample_results,
            false,
            bytes_verified,
            ColdRetrievabilityVerdict::Corrupted,
            "whole-pack ciphertext SHA-256 mismatch against manifest".to_owned(),
            now_ns,
        );
    }

    finalize_audit_receipt(
        manifest,
        Some(observed_sha),
        observed_etag,
        requested_count,
        verified_samples,
        sample_results,
        true,
        bytes_verified.saturating_add(manifest.ciphertext_bytes),
        ColdRetrievabilityVerdict::Verified,
        "all Range-GET samples and whole-pack ciphertext SHA-256 verified".to_owned(),
        now_ns,
    )
}

/// Downloads an encrypted cold pack, verifies `ciphertext_sha256`, decrypts via
/// [`KeyEnvelopeCatalog`] + [`KeyEncryptionKey`], verifies `plaintext_pack_sha256` and every inner
/// `FSSP` record's CRC32C + `ContentDigest`, and restores all verified objects into `store`.
#[allow(clippy::too_many_arguments)]
pub fn restore_cold_pack(
    transport: &mut dyn ColdPackTransport,
    manifest: &ColdPackArchiveManifest,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    store: &PackStore,
    max_download_bytes: usize,
    now_ns: TimestampNs,
) -> Result<ColdPackRestoreReceipt, PackError> {
    let (plaintext_pack, verified_records) = download_decrypt_and_verify_pack(
        transport,
        manifest,
        catalog,
        kek,
        max_download_bytes,
        now_ns,
    )?;

    let mut inputs = Vec::with_capacity(verified_records.len());
    let mut restored_digests = Vec::with_capacity(verified_records.len());
    for rec in &verified_records {
        inputs.push(PackObjectInput::with_digest(
            rec.object_kind,
            rec.flags,
            &plaintext_pack[rec.payload_start..rec.payload_end],
            rec.digest,
        ));
        restored_digests.push(rec.digest);
    }
    let restored_locations = store.append_batch(&inputs)?;
    restored_digests.sort_unstable();

    Ok(ColdPackRestoreReceipt {
        pack_id: manifest.pack_id,
        manifest_digest: manifest.manifest_digest,
        restored_object_count: restored_digests.len(),
        restored_digests,
        restored_locations,
        plaintext_pack_sha256: manifest.plaintext_pack_sha256,
        ciphertext_sha256: manifest.ciphertext_sha256,
        restored_at_ns: now_ns,
    })
}

/// Downloads, decrypts, verifies every inner record, and atomically writes the restored `.fssp`
/// sealed packfile directly into `packs_dir` (for offline store restoration before reopen).
#[allow(clippy::too_many_arguments)]
pub fn restore_cold_pack_to_dir(
    transport: &mut dyn ColdPackTransport,
    manifest: &ColdPackArchiveManifest,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    packs_dir: &Path,
    durability: DurabilityMode,
    max_download_bytes: usize,
    now_ns: TimestampNs,
) -> Result<Vec<ContentDigest>, PackError> {
    let (plaintext_pack, verified_records) = download_decrypt_and_verify_pack(
        transport,
        manifest,
        catalog,
        kek,
        max_download_bytes,
        now_ns,
    )?;
    publish_restored_pack(packs_dir, manifest.pack_id, &plaintext_pack, durability)?;
    let mut digests: Vec<ContentDigest> = verified_records.into_iter().map(|r| r.digest).collect();
    digests.sort_unstable();
    Ok(digests)
}

struct VerifiedInnerRecord {
    digest: ContentDigest,
    object_kind: u16,
    flags: u16,
    payload_start: usize,
    payload_end: usize,
}

fn download_decrypt_and_verify_pack(
    transport: &mut dyn ColdPackTransport,
    manifest: &ColdPackArchiveManifest,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    max_download_bytes: usize,
    now_ns: TimestampNs,
) -> Result<(Vec<u8>, Vec<VerifiedInnerRecord>), PackError> {
    manifest.verify_digest()?;
    if manifest.ciphertext_bytes > max_download_bytes as u64 {
        return Err(PackError::ObjectTooLarge {
            length: manifest.ciphertext_bytes,
            maximum: max_download_bytes as u64,
        });
    }
    let resp = transport.get_object(&manifest.object_key, max_download_bytes, now_ns)?;
    if resp.object_key != manifest.object_key {
        return Err(PackError::ArchiveIntegrity {
            detail: "downloaded ciphertext belongs to a different object key".to_owned(),
        });
    }
    if resp.body.len() as u64 != manifest.ciphertext_bytes {
        return Err(PackError::ArchiveIntegrity {
            detail: format!(
                "downloaded ciphertext length {} != manifest ciphertext_bytes {}",
                resp.body.len(),
                manifest.ciphertext_bytes
            ),
        });
    }
    let observed_ct_sha = ContentDigest::sha256(&resp.body);
    if observed_ct_sha != manifest.ciphertext_sha256 {
        return Err(PackError::ArchiveIntegrity {
            detail: "downloaded ciphertext SHA-256 does not match ColdPackArchiveManifest"
                .to_owned(),
        });
    }

    let (plaintext_pack, dec_receipt) = decrypt_and_verify_pack_bytes(
        &resp.body,
        manifest.pack_id,
        EncryptedStreamKind::SealedPackChunks,
        SCHEMA_EPOCH_PACKFILE,
        catalog,
        kek,
    )?;
    if dec_receipt.dek_id != manifest.dek_id || dec_receipt.origin_key_epoch != manifest.key_epoch {
        return Err(PackError::ArchiveIntegrity {
            detail: "decrypted stream key metadata diverged from manifest".to_owned(),
        });
    }
    if plaintext_pack.len() as u64 != manifest.plaintext_bytes
        || dec_receipt.plaintext_sha256 != manifest.plaintext_pack_sha256
    {
        return Err(PackError::ArchiveIntegrity {
            detail: "decrypted plaintext pack length or SHA-256 diverged from manifest".to_owned(),
        });
    }

    let verified_records = verify_sealed_pack_bytes(manifest.pack_id, &plaintext_pack)?;
    Ok((plaintext_pack, verified_records))
}

fn verify_sealed_pack_bytes(
    pack_id: PackId,
    raw: &[u8],
) -> Result<Vec<VerifiedInnerRecord>, PackError> {
    if raw.len() < PACK_FOOTER_PREFIX_LEN + PACK_FOOTER_TAIL_LEN {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: 0,
            detail: "restored packfile shorter than minimum sealed footer".to_owned(),
        });
    }
    let tail_start = raw.len() - PACK_FOOTER_TAIL_LEN;
    let tail_arr: &[u8; PACK_FOOTER_TAIL_LEN] =
        raw[tail_start..]
            .try_into()
            .map_err(|_| PackError::CorruptPack {
                pack_id,
                offset: tail_start as u64,
                detail: "failed to slice restored footer tail".to_owned(),
            })?;
    let tail = decode_footer_tail(tail_arr).ok_or_else(|| PackError::CorruptPack {
        pack_id,
        offset: tail_start as u64,
        detail: "restored packfile missing FSSE footer end magic".to_owned(),
    })?;
    let footer_offset_usize =
        usize::try_from(tail.footer_offset).map_err(|_| PackError::ArithmeticOverflow)?;
    if footer_offset_usize >= tail_start {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: tail.footer_offset,
            detail: "restored footer_offset out of bounds".to_owned(),
        });
    }
    let footer = decode_sealed_footer(pack_id, tail.footer_offset, &raw[footer_offset_usize..])?;

    let whole_sha = sha256(&raw[..raw.len() - 36]);
    if !constant_time_eq(&whole_sha, &footer.whole_pack_sha256) {
        return Err(PackError::DigestMismatch {
            expected: ContentDigest::new(DigestAlgorithm::Sha256, footer.whole_pack_sha256),
            actual: ContentDigest::new(DigestAlgorithm::Sha256, whole_sha),
        });
    }

    let mut records = Vec::with_capacity(footer.entries.len());
    for entry in &footer.entries {
        let start = usize::try_from(entry.offset).map_err(|_| PackError::ArithmeticOverflow)?;
        let rec_len = usize::try_from(entry.len)
            .ok()
            .and_then(|n| n.checked_add(PACK_RECORD_OVERHEAD_LEN))
            .ok_or(PackError::ArithmeticOverflow)?;
        let end = start
            .checked_add(rec_len)
            .ok_or(PackError::ArithmeticOverflow)?;
        if end > footer_offset_usize {
            return Err(PackError::CorruptPack {
                pack_id,
                offset: entry.offset,
                detail: "restored inner FSSP record exceeds footer offset".to_owned(),
            });
        }
        let (hdr, _payload) = verify_record_slice(
            pack_id,
            entry.offset,
            &raw[start..end],
            Some(entry.digest()),
        )?;
        let payload_start = start + crate::format::PACK_RECORD_HEADER_LEN;
        let payload_end = end - crate::format::PACK_RECORD_TRAILER_LEN;
        records.push(VerifiedInnerRecord {
            digest: hdr.digest(),
            object_kind: hdr.object_kind,
            flags: hdr.flags,
            payload_start,
            payload_end,
        });
    }
    Ok(records)
}

fn build_audit_ranges(total_bytes: u64, config: &ColdAuditConfig) -> Vec<(u64, u64)> {
    if total_bytes == 0 {
        return Vec::new();
    }
    let last_byte = total_bytes - 1;
    let span = config.sample_range_bytes.min(total_bytes);
    let mut ranges = Vec::new();

    let n = config.deterministic_sample_count;
    if n >= 1 {
        ranges.push((0, (span - 1).min(last_byte)));
    }
    if n >= 2 {
        let tail_start = total_bytes.saturating_sub(span);
        ranges.push((tail_start, last_byte));
    }
    if n >= 3 {
        let mid_start = (total_bytes / 2).saturating_sub(span / 2);
        let mid_end = mid_start.saturating_add(span - 1).min(last_byte);
        ranges.push((mid_start, mid_end));
    }
    if n > 3 {
        for idx in 3..n {
            let frac_start = (total_bytes.saturating_mul(u64::from(idx))) / u64::from(n + 1);
            let start = frac_start.min(last_byte);
            let end = start.saturating_add(span - 1).min(last_byte);
            ranges.push((start, end));
        }
    }
    for &(start, len) in &config.explicit_sample_ranges {
        if len > 0 && start <= last_byte {
            let end = start.saturating_add(len - 1).min(last_byte);
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

#[allow(clippy::too_many_arguments)]
fn finalize_audit_receipt(
    manifest: &ColdPackArchiveManifest,
    observed_ciphertext_sha256: Option<ContentDigest>,
    observed_etag: Option<String>,
    range_samples_requested: u32,
    range_samples_verified: u32,
    sample_results: Vec<ColdRangeSampleResult>,
    whole_pack_sha256_verified: bool,
    bytes_verified: u64,
    verdict: ColdRetrievabilityVerdict,
    detail: String,
    audited_at_ns: TimestampNs,
) -> Result<ColdRetrievabilityAuditReceipt, PackError> {
    let requires_repair_obligation = matches!(
        verdict,
        ColdRetrievabilityVerdict::Corrupted | ColdRetrievabilityVerdict::Missing
    );
    let mut receipt = ColdRetrievabilityAuditReceipt {
        manifest_digest: manifest.manifest_digest,
        pack_id: manifest.pack_id,
        object_key: manifest.object_key.clone(),
        expected_ciphertext_sha256: manifest.ciphertext_sha256,
        observed_ciphertext_sha256,
        observed_etag,
        range_samples_requested,
        range_samples_verified,
        sample_results,
        whole_pack_sha256_verified,
        bytes_verified,
        verdict,
        requires_repair_obligation,
        detail,
        audited_at_ns,
        receipt_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
    };
    receipt.receipt_digest = compute_audit_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn compute_audit_receipt_digest(
    receipt: &ColdRetrievabilityAuditReceipt,
) -> Result<ContentDigest, PackError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN);
    enc.digest(receipt.manifest_digest);
    enc.u32(receipt.pack_id.epoch);
    enc.u64(receipt.pack_id.seq);
    enc.text(&receipt.object_key);
    enc.digest(receipt.expected_ciphertext_sha256);
    match receipt.observed_ciphertext_sha256 {
        Some(d) => {
            enc.bool(true);
            enc.digest(d);
        }
        None => enc.bool(false),
    }
    match &receipt.observed_etag {
        Some(e) => {
            enc.bool(true);
            enc.text(e);
        }
        None => enc.bool(false),
    }
    enc.u32(receipt.range_samples_requested);
    enc.u32(receipt.range_samples_verified);
    enc.u64(receipt.sample_results.len() as u64);
    for sample in &receipt.sample_results {
        enc.u64(sample.offset);
        enc.u64(sample.len);
        enc.digest(sample.sample_sha256);
        enc.bool(sample.etag_matched);
    }
    enc.bool(receipt.whole_pack_sha256_verified);
    enc.u64(receipt.bytes_verified);
    enc.tag(receipt.verdict.to_tag());
    enc.bool(receipt.requires_repair_obligation);
    enc.text(&receipt.detail);
    receipt.audited_at_ns.encode_canonical(&mut enc);
    let bytes = enc.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}
