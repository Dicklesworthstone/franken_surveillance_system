#![forbid(unsafe_code)]
//! Cold-tier whole-pack encrypted archival to S3 / Cloudflare R2 / Backblaze B2, root-last
//! manifest publication, local hot-pack eviction, Range-GET retrievability audits, and verified
//! cold restore into [`crate::PackStore`].

pub mod audit;
pub mod manifest;
pub mod recovery;
pub mod s3_pack;
mod s3_wire;

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use fss_core::{ContentDigest, TimestampNs};
use fss_vault::EntropySource;

use crate::crypto::envelope::{KeyEncryptionKey, SCHEMA_EPOCH_PACKFILE};
use crate::crypto::keyring::KeyEnvelopeCatalog;
use crate::crypto::pack_io::{EncryptedStreamKind, encrypt_pack_bytes, write_file_atomic};
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, PackId, sync_dir};

pub use audit::{
    ColdAuditConfig, ColdPackRestoreReceipt, ColdRangeSampleResult, ColdRetrievabilityAuditReceipt,
    ColdRetrievabilityVerdict, PACK_COLD_RETRIEVABILITY_AUDIT_DOMAIN,
    audit_cold_pack_retrievability, audit_cold_pack_retrievability_with_cancel, restore_cold_pack,
    restore_cold_pack_to_dir,
};
pub use manifest::{
    COLD_ARCHIVE_MANIFEST_VERSION, ColdArchivePolicy, ColdPackArchiveManifest, ColdProviderKind,
    ColdStorageTier, DEFAULT_COLD_MAX_PACK_BYTES, DEFAULT_COLD_MIN_PACK_BYTES,
    DEFAULT_COLD_TARGET_PACK_BYTES, DEFAULT_MULTIPART_PART_BYTES,
    DEFAULT_MULTIPART_THRESHOLD_BYTES, PACK_COLD_ARCHIVE_MANIFEST_DOMAIN,
};
pub use recovery::{MAX_COLD_MANIFEST_DOWNLOAD_BYTES, fetch_cold_pack_manifest};
pub use s3_pack::{
    ColdGetResponse, ColdPackTransport, ColdPutReceipt, ColdRangeResponse, ColdS3Credentials,
    ColdS3Endpoint, ColdS3Limits, PACK_COLD_ENDPOINT_DOMAIN, S3CompatiblePackTransport,
};

/// Wire upload strategy executed for a cold pack archive transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColdUploadMode {
    /// Single signed HTTP `PUT` (ciphertext strictly below `multipart_threshold_bytes`).
    SinglePut,
    /// Signed S3 multipart upload (`POST ?uploads=`, `PUT ?partNumber=`, `POST ?uploadId=`).
    Multipart {
        /// Number of uploaded parts.
        part_count: u32,
    },
}

/// Receipt emitted after encrypting, uploading, and root-last publishing a cold pack archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdPackArchiveReceipt {
    /// Published root-last archive manifest.
    pub manifest: ColdPackArchiveManifest,
    /// Upload strategy executed for the encrypted pack blob.
    pub upload_mode: ColdUploadMode,
    /// Opaque cold object key where the root-last manifest bytes were published.
    pub manifest_object_key: String,
    /// Remote provider ETag returned when publishing the root-last manifest.
    pub manifest_etag: String,
    /// Number of `FSAE` v1 AEAD frames inside the uploaded `.fsep` blob.
    pub encryption_frame_count: u64,
}

/// Receipt emitted after evicting a local hot sealed `.fssp` packfile that is archived in cold storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPackEvictionReceipt {
    /// Evicted local sealed pack identifier.
    pub pack_id: PackId,
    /// Local disk bytes freed by unlinking the hot `.fssp` packfile.
    pub evicted_bytes: u64,
    /// Verified SHA-256 of the evicted local `.fssp` packfile.
    pub plaintext_pack_sha256: ContentDigest,
    /// Cold manifest digest witnessing the archived copy.
    pub manifest_digest: ContentDigest,
    /// Optional verified retrievability audit digest checked prior to eviction.
    pub verified_by_audit_digest: Option<ContentDigest>,
}

/// Encrypts a verified sealed packfile (`pack_id`) under a fresh wrapped DEK, uploads the whole
/// encrypted `.fsep` blob via single PUT or multipart upload, and publishes the
/// [`ColdPackArchiveManifest`] root LAST only after every part upload succeeds.
#[allow(clippy::too_many_arguments)]
pub fn archive_sealed_pack(
    packs_dir: &Path,
    pack_id: PackId,
    policy: &ColdArchivePolicy,
    catalog: &mut KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    transport: &mut dyn ColdPackTransport,
    entropy: &mut dyn EntropySource,
    local_manifest_dir: Option<&Path>,
    durability: DurabilityMode,
    now_ns: TimestampNs,
) -> Result<ColdPackArchiveReceipt, PackError> {
    archive_sealed_pack_with_pin(
        packs_dir,
        pack_id,
        None,
        policy,
        catalog,
        kek,
        transport,
        entropy,
        local_manifest_dir,
        durability,
        now_ns,
    )
}

/// Archives a sealed pack after checking its optional, independently supplied FSSF
/// whole-pack digest against the actual verified plaintext selected for encryption.
/// A mismatched approval is refused before key creation or any transport operation.
/// Pass `None` to select the current contents, as in [`archive_sealed_pack`].
#[allow(clippy::too_many_arguments)]
pub fn archive_sealed_pack_with_pin(
    packs_dir: &Path,
    pack_id: PackId,
    expected_whole_pack_sha256: Option<ContentDigest>,
    policy: &ColdArchivePolicy,
    catalog: &mut KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    transport: &mut dyn ColdPackTransport,
    entropy: &mut dyn EntropySource,
    local_manifest_dir: Option<&Path>,
    durability: DurabilityMode,
    now_ns: TimestampNs,
) -> Result<ColdPackArchiveReceipt, PackError> {
    policy.validate()?;
    // 1. Verify the same bounded bytes that encryption will consume.
    let pack_path = packs_dir.join(pack_id.file_name());
    let mut file =
        File::open(&pack_path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let file_len = file
        .metadata()
        .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
        .len();
    if file_len < policy.min_pack_bytes {
        return Err(PackError::InvalidConfig {
            detail: format!(
                "sealed pack {pack_id} ({file_len} B) is below whole-pack archival minimum {} B",
                policy.min_pack_bytes
            ),
        });
    }
    if file_len > policy.max_pack_bytes {
        return Err(PackError::ObjectTooLarge {
            length: file_len,
            maximum: policy.max_pack_bytes,
        });
    }

    let len = usize::try_from(file_len).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut plaintext_pack = vec![0; len];
    file.read_exact(&mut plaintext_pack)
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;
    if file
        .read(&mut [0; 1])
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?
        != 0
    {
        return Err(PackError::ArchiveIntegrity {
            detail: "sealed pack grew during archive admission".to_owned(),
        });
    }
    let (actual, _) = audit::verify_sealed_pack_bytes(pack_id, &plaintext_pack)?;
    if let Some(expected) = expected_whole_pack_sha256
        && actual != expected
    {
        return Err(PackError::DigestMismatch { expected, actual });
    }

    // 2. Mint and wrap a per-pack 256-bit DEK under the active site KEK.
    let (dek, wrapped_env) = catalog.create_and_wrap_dek(kek, entropy, &[pack_id], now_ns)?;
    let wrapped_dek_digest = wrapped_env.envelope_digest();

    // 3. Encrypt whole sealed packfile into FSEP v1 ciphertext + compute digests.
    let (ciphertext_pack, enc_receipt) = encrypt_pack_bytes(
        pack_id,
        EncryptedStreamKind::SealedPackChunks,
        SCHEMA_EPOCH_PACKFILE,
        &plaintext_pack,
        &dek,
        wrapped_env.origin_key_epoch,
        policy.encryption_chunk_bytes,
        entropy,
    )?;

    // 4. Upload encrypted ciphertext blob BEFORE publishing any archive manifest root.
    let pack_object_key = policy.opaque_pack_object_key(pack_id, enc_receipt.ciphertext_sha256);
    let (put_receipt, upload_mode, expected_parts) =
        if enc_receipt.ciphertext_bytes >= policy.multipart_threshold_bytes {
            let receipt = transport.put_object_multipart(
                &pack_object_key,
                &ciphertext_pack,
                policy.multipart_part_bytes,
                now_ns,
            )?;
            let mode = ColdUploadMode::Multipart {
                part_count: receipt.part_count,
            };
            (
                receipt,
                mode,
                ciphertext_pack.len().div_ceil(policy.multipart_part_bytes),
            )
        } else {
            let receipt = transport.put_object(
                &pack_object_key,
                &ciphertext_pack,
                enc_receipt.ciphertext_sha256,
                now_ns,
            )?;
            (receipt, ColdUploadMode::SinglePut, 1)
        };

    check_put_receipt(
        &put_receipt,
        &pack_object_key,
        enc_receipt.ciphertext_sha256,
        enc_receipt.ciphertext_bytes,
        expected_parts,
    )?;

    // 5. Root-last publication: build and publish ColdPackArchiveManifest ONLY AFTER upload succeeds.
    let manifest = ColdPackArchiveManifest::build(
        pack_id,
        wrapped_env.origin_key_epoch,
        wrapped_env.dek_id,
        wrapped_dek_digest,
        enc_receipt.plaintext_sha256,
        enc_receipt.plaintext_bytes,
        enc_receipt.ciphertext_sha256,
        enc_receipt.ciphertext_bytes,
        pack_object_key,
        put_receipt.etag,
        policy.storage_tier,
        put_receipt.part_count,
        now_ns,
    )?;
    let manifest_bytes = manifest.to_canonical_bytes()?;
    let manifest_sha = ContentDigest::sha256(&manifest_bytes);
    let manifest_object_key = policy.published_manifest_object_key(&manifest);
    let manifest_put =
        transport.put_object(&manifest_object_key, &manifest_bytes, manifest_sha, now_ns)?;

    check_put_receipt(
        &manifest_put,
        &manifest_object_key,
        manifest_sha,
        manifest_bytes.len() as u64,
        1,
    )?;

    if let Some(dir) = local_manifest_dir {
        let local_path = dir.join(format!(
            "pack-{:08}-{:012}.manifest.fssc",
            pack_id.epoch, pack_id.seq
        ));
        write_file_atomic(&local_path, &manifest_bytes, durability)?;
    }

    Ok(ColdPackArchiveReceipt {
        manifest,
        upload_mode,
        manifest_object_key,
        manifest_etag: manifest_put.etag,
        encryption_frame_count: enc_receipt.frame_count,
    })
}

fn check_put_receipt(
    receipt: &ColdPutReceipt,
    key: &str,
    digest: ContentDigest,
    bytes: u64,
    parts: usize,
) -> Result<(), PackError> {
    if receipt.object_key != key
        || receipt.content_sha256 != digest
        || receipt.bytes_uploaded != bytes
        || usize::try_from(receipt.part_count).ok() != Some(parts)
        || receipt.etag.is_empty()
        || receipt.etag.len() > 1024
        || receipt.etag.chars().any(char::is_control)
    {
        return Err(PackError::ArchiveIntegrity {
            detail: "cold upload receipt does not acknowledge the exact object".to_owned(),
        });
    }
    Ok(())
}

/// Evicts a local hot sealed `.fssp` packfile after verifying its cold archive manifest
/// (and optionally a `Verified` [`ColdRetrievabilityAuditReceipt`]) and exact local SHA-256.
pub fn evict_local_sealed_pack(
    packs_dir: &Path,
    manifest: &ColdPackArchiveManifest,
    audit_receipt: Option<&ColdRetrievabilityAuditReceipt>,
    require_verified_audit: bool,
    durability: DurabilityMode,
) -> Result<LocalPackEvictionReceipt, PackError> {
    manifest.verify_digest()?;
    let verified_by_audit_digest = if let Some(audit) = audit_receipt {
        audit.verify_digest()?;
        if audit.manifest_digest != manifest.manifest_digest || audit.pack_id != manifest.pack_id {
            return Err(PackError::ArchiveIntegrity {
                detail: "retrievability audit receipt does not match target manifest".to_owned(),
            });
        }
        if require_verified_audit
            && (audit.verdict != ColdRetrievabilityVerdict::Verified
                || !audit.whole_pack_sha256_verified)
        {
            return Err(PackError::ArchiveIntegrity {
                detail: format!(
                    "refusing local pack eviction without Verified retrievability audit (got {})",
                    audit.verdict.as_str()
                ),
            });
        }
        Some(audit.receipt_digest)
    } else if require_verified_audit {
        return Err(PackError::ArchiveIntegrity {
            detail: "refusing local pack eviction without Verified retrievability audit".to_owned(),
        });
    } else {
        None
    };

    let pack_path = packs_dir.join(manifest.pack_id.file_name());
    let mut file =
        File::open(&pack_path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;
    let local_sha = ContentDigest::sha256(&raw);
    if raw.len() as u64 != manifest.plaintext_bytes || local_sha != manifest.plaintext_pack_sha256 {
        return Err(PackError::ArchiveIntegrity {
            detail: "local sealed packfile bytes diverge from cold archive manifest".to_owned(),
        });
    }
    drop(file);

    fs::remove_file(&pack_path).map_err(|err| PackError::io(PackIoOperation::Remove, err))?;
    sync_dir(packs_dir, durability)?;

    Ok(LocalPackEvictionReceipt {
        pack_id: manifest.pack_id,
        evicted_bytes: raw.len() as u64,
        plaintext_pack_sha256: local_sha,
        manifest_digest: manifest.manifest_digest,
        verified_by_audit_digest,
    })
}
