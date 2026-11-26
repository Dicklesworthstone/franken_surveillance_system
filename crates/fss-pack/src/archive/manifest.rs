#![forbid(unsafe_code)]
//! Canonical root-last cold pack archive manifest (`ColdPackArchiveManifest`) and sizing policy
//! (`COMPREHENSIVE_PLAN §13.7–§13.8`).

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, TimestampNs,
};

use crate::crypto::envelope::{DekId, KeyEpoch, encode_hex_lower};
use crate::crypto::erasure::escape_json_str;
use crate::crypto::pack_io::DEFAULT_ENCRYPTION_CHUNK_BYTES;
use crate::error::PackError;
use crate::format::PackId;

/// Canonical digest domain for root-last [`ColdPackArchiveManifest::manifest_digest`].
pub const PACK_COLD_ARCHIVE_MANIFEST_DOMAIN: &str = "fss.pack.cold_archive_manifest.v1";
/// Supported schema version for [`ColdPackArchiveManifest`].
pub const COLD_ARCHIVE_MANIFEST_VERSION: u16 = 1;

/// Default minimum sealed packfile size for production cold-tier archival (`64 MiB`).
pub const DEFAULT_COLD_MIN_PACK_BYTES: u64 = 64 * 1024 * 1024;
/// Default target sealed packfile size for production cold-tier archival (`128 MiB`).
pub const DEFAULT_COLD_TARGET_PACK_BYTES: u64 = 128 * 1024 * 1024;
/// Default maximum sealed packfile size accepted for cold-tier archival (`256 MiB`).
pub const DEFAULT_COLD_MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;
/// Default multipart upload threshold (`16 MiB`).
pub const DEFAULT_MULTIPART_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
/// Default multipart part size (`8 MiB`).
pub const DEFAULT_MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;

/// Target remote cold-tier storage class recorded in [`ColdPackArchiveManifest`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ColdStorageTier {
    /// Standard S3-compatible object storage.
    Standard,
    /// Infrequent-access cold object tier (e.g., S3 Standard-IA).
    InfrequentAccess,
    /// Deep cold archival tier (e.g., S3 Glacier Instant Retrieval / Deep Archive).
    ColdArchive,
    /// Cloudflare R2 zero-egress S3-compatible storage.
    CloudflareR2,
    /// Backblaze B2 S3-compatible cold storage.
    BackblazeB2,
}

impl ColdStorageTier {
    /// Encodes as a canonical 1-byte wire tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Standard => 1,
            Self::InfrequentAccess => 2,
            Self::ColdArchive => 3,
            Self::CloudflareR2 => 4,
            Self::BackblazeB2 => 5,
        }
    }

    /// Decodes from a canonical 1-byte wire tag.
    pub fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Standard),
            2 => Ok(Self::InfrequentAccess),
            3 => Ok(Self::ColdArchive),
            4 => Ok(Self::CloudflareR2),
            5 => Ok(Self::BackblazeB2),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::InfrequentAccess => "infrequent_access",
            Self::ColdArchive => "cold_archive",
            Self::CloudflareR2 => "cloudflare_r2",
            Self::BackblazeB2 => "backblaze_b2",
        }
    }
}

/// Supported S3-compatible remote archival provider families.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ColdProviderKind {
    /// Amazon S3.
    AwsS3,
    /// Cloudflare R2 (S3-compatible API).
    CloudflareR2,
    /// Backblaze B2 (S3-compatible API).
    BackblazeB2,
    /// Local / loopback S3-compatible server (MinIO, lab oracle, or unit test mock).
    LocalS3Compatible,
}

impl ColdProviderKind {
    /// Encodes as a canonical 1-byte wire tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::AwsS3 => 1,
            Self::CloudflareR2 => 2,
            Self::BackblazeB2 => 3,
            Self::LocalS3Compatible => 4,
        }
    }

    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsS3 => "aws_s3",
            Self::CloudflareR2 => "cloudflare_r2",
            Self::BackblazeB2 => "backblaze_b2",
            Self::LocalS3Compatible => "local_s3_compatible",
        }
    }
}

/// Whole-pack sizing, multipart threshold, and key-prefix policy for cold archival.
///
/// Enforces whole-pack archival (`64–128 MiB` in production, configurable in tests) rather than
/// uploading tiny 1-second fragments that explode PUT/HEAD/GET request counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdArchivePolicy {
    /// Minimum sealed packfile size eligible for cold archival (refuses tiny unbatched objects).
    pub min_pack_bytes: u64,
    /// Maximum sealed packfile size accepted for a single cold archive object.
    pub max_pack_bytes: u64,
    /// Ciphertext size threshold at or above which multipart upload is used instead of single PUT.
    pub multipart_threshold_bytes: u64,
    /// Fixed byte size per multipart upload part (except the final part).
    pub multipart_part_bytes: usize,
    /// Plaintext chunk size per `FSAE` v1 frame inside the encrypted `.fsep` cold blob.
    pub encryption_chunk_bytes: usize,
    /// Target remote storage tier recorded in the published manifest.
    pub storage_tier: ColdStorageTier,
    /// Non-secret opaque bucket key prefix (e.g., `"fss-cold/v1"`).
    pub key_prefix: String,
}

impl ColdArchivePolicy {
    /// Returns the production whole-pack archival policy (`64 MiB` min, `256 MiB` max, `16 MiB`
    /// multipart threshold, `8 MiB` parts).
    #[must_use]
    pub fn production_default(storage_tier: ColdStorageTier) -> Self {
        Self {
            min_pack_bytes: DEFAULT_COLD_MIN_PACK_BYTES,
            max_pack_bytes: DEFAULT_COLD_MAX_PACK_BYTES,
            multipart_threshold_bytes: DEFAULT_MULTIPART_THRESHOLD_BYTES,
            multipart_part_bytes: DEFAULT_MULTIPART_PART_BYTES,
            encryption_chunk_bytes: DEFAULT_ENCRYPTION_CHUNK_BYTES,
            storage_tier,
            key_prefix: "fss-cold/v1".to_owned(),
        }
    }

    /// Creates a configurable archival policy for deterministic tests and small-pack drills.
    pub fn for_testing(
        min_pack_bytes: u64,
        multipart_threshold_bytes: u64,
        multipart_part_bytes: usize,
        storage_tier: ColdStorageTier,
    ) -> Result<Self, PackError> {
        let policy = Self {
            min_pack_bytes,
            max_pack_bytes: DEFAULT_COLD_MAX_PACK_BYTES,
            multipart_threshold_bytes,
            multipart_part_bytes,
            encryption_chunk_bytes: 16 * 1024,
            storage_tier,
            key_prefix: "fss-cold/v1".to_owned(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates all sizing bounds, part limits, and key prefix syntax.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.min_pack_bytes == 0 || self.min_pack_bytes > self.max_pack_bytes {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "cold archive min_pack_bytes ({}) must be in 1..={}",
                    self.min_pack_bytes, self.max_pack_bytes
                ),
            });
        }
        if self.multipart_threshold_bytes == 0 || self.multipart_part_bytes == 0 {
            return Err(PackError::InvalidConfig {
                detail: "multipart_threshold_bytes and multipart_part_bytes must be >= 1"
                    .to_owned(),
            });
        }
        if self.encryption_chunk_bytes == 0 {
            return Err(PackError::InvalidConfig {
                detail: "encryption_chunk_bytes must be >= 1".to_owned(),
            });
        }
        if self.key_prefix.is_empty()
            || self.key_prefix.len() > 256
            || self.key_prefix.starts_with('/')
            || self.key_prefix.ends_with('/')
            || !self
                .key_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        {
            return Err(PackError::InvalidConfig {
                detail: "cold archive key_prefix must be bounded safe ASCII without leading/trailing '/'"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Builds an opaque privacy-preserving cold object key for an encrypted packfile.
    ///
    /// Never embeds sensor names, camera labels, or event metadata.
    #[must_use]
    pub fn opaque_pack_object_key(
        &self,
        pack_id: PackId,
        ciphertext_sha256: ContentDigest,
    ) -> String {
        let hash = encode_hex_lower(&ciphertext_sha256.bytes());
        format!(
            "{}/packs/pack-{:08}-{:012}-{hash}.fsep",
            self.key_prefix, pack_id.epoch, pack_id.seq
        )
    }

    /// Returns the pack-id-only locator used by older publications. Retained receipts using
    /// this locator can still be recovered by their independent manifest digest.
    #[must_use]
    pub fn opaque_manifest_object_key(&self, pack_id: PackId) -> String {
        format!(
            "{}/manifests/pack-{:08}-{:012}.manifest.fssc",
            self.key_prefix, pack_id.epoch, pack_id.seq
        )
    }

    /// Builds the immutable remote locator for one exact publication of a sealed pack.
    #[must_use]
    pub fn published_manifest_object_key(&self, manifest: &ColdPackArchiveManifest) -> String {
        let hash = encode_hex_lower(&manifest.manifest_digest.bytes());
        format!(
            "{}/manifests/pack-{:08}-{:012}-{hash}.manifest.fssc",
            self.key_prefix, manifest.pack_id.epoch, manifest.pack_id.seq
        )
    }
}

/// Root-last canonical archive manifest published ONLY AFTER every encrypted pack part upload
/// succeeds and is verified (`COMPREHENSIVE_PLAN §13.4, §13.8`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdPackArchiveManifest {
    /// Manifest schema version (must be [`COLD_ARCHIVE_MANIFEST_VERSION`]).
    pub schema_version: u16,
    /// Archived immutable sealed packfile identifier.
    pub pack_id: PackId,
    /// Origin KEK epoch under which the pack's DEK was issued.
    pub key_epoch: KeyEpoch,
    /// 128-bit DEK identifier required to decrypt the cold ciphertext pack.
    pub dek_id: DekId,
    /// Canonical SHA-256 digest of the `WrappedDekEnvelope` at archival time.
    pub wrapped_dek_digest: ContentDigest,
    /// Whole-file SHA-256 of the plaintext sealed `.fssp` packfile (exact content identity).
    pub plaintext_pack_sha256: ContentDigest,
    /// Exact byte length of the plaintext sealed `.fssp` packfile.
    pub plaintext_bytes: u64,
    /// Whole-file SHA-256 of the uploaded encrypted `.fsep` ciphertext blob.
    pub ciphertext_sha256: ContentDigest,
    /// Exact byte length of the uploaded encrypted `.fsep` ciphertext blob.
    pub ciphertext_bytes: u64,
    /// Opaque cold bucket object key storing the encrypted `.fsep` blob.
    pub object_key: String,
    /// Remote provider ETag returned on completed upload.
    pub etag: String,
    /// Storage tier classification recorded at publication time.
    pub storage_tier: ColdStorageTier,
    /// Number of uploaded parts (`1` for single PUT, `>= 1` for multipart upload).
    pub part_count: u32,
    /// Explicit caller-supplied publication timestamp (no ambient clock).
    pub published_at_ns: TimestampNs,
    /// Canonical domain-separated SHA-256 digest under [`PACK_COLD_ARCHIVE_MANIFEST_DOMAIN`].
    pub manifest_digest: ContentDigest,
}

impl ColdPackArchiveManifest {
    /// Builds and signs a validated [`ColdPackArchiveManifest`] with its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        pack_id: PackId,
        key_epoch: KeyEpoch,
        dek_id: DekId,
        wrapped_dek_digest: ContentDigest,
        plaintext_pack_sha256: ContentDigest,
        plaintext_bytes: u64,
        ciphertext_sha256: ContentDigest,
        ciphertext_bytes: u64,
        object_key: String,
        etag: String,
        storage_tier: ColdStorageTier,
        part_count: u32,
        published_at_ns: TimestampNs,
    ) -> Result<Self, PackError> {
        let key_epoch = KeyEpoch::new(key_epoch.0)?;
        validate_sha256(wrapped_dek_digest)?;
        validate_sha256(plaintext_pack_sha256)?;
        validate_sha256(ciphertext_sha256)?;
        if ciphertext_bytes == 0 || part_count == 0 {
            return Err(PackError::ArchiveIntegrity {
                detail: "ciphertext_bytes and part_count must be >= 1".to_owned(),
            });
        }
        if object_key.is_empty()
            || object_key.len() > 1024
            || object_key.chars().any(char::is_control)
        {
            return Err(PackError::ArchiveIntegrity {
                detail: "manifest object_key is invalid".to_owned(),
            });
        }
        if etag.is_empty() || etag.len() > 1024 || etag.chars().any(char::is_control) {
            return Err(PackError::ArchiveIntegrity {
                detail: "manifest etag is invalid".to_owned(),
            });
        }

        let mut manifest = Self {
            schema_version: COLD_ARCHIVE_MANIFEST_VERSION,
            pack_id,
            key_epoch,
            dek_id,
            wrapped_dek_digest,
            plaintext_pack_sha256,
            plaintext_bytes,
            ciphertext_sha256,
            ciphertext_bytes,
            object_key,
            etag,
            storage_tier,
            part_count,
            published_at_ns,
            manifest_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
        };
        manifest.manifest_digest = manifest.compute_manifest_digest()?;
        Ok(manifest)
    }

    /// Recomputes and verifies [`Self::manifest_digest`], failing closed on any tampering.
    pub fn verify_digest(&self) -> Result<(), PackError> {
        if self.schema_version != COLD_ARCHIVE_MANIFEST_VERSION {
            return Err(PackError::ArchiveIntegrity {
                detail: format!(
                    "unsupported manifest schema_version {}",
                    self.schema_version
                ),
            });
        }
        let expected = self.compute_manifest_digest()?;
        if expected != self.manifest_digest {
            return Err(PackError::DigestMismatch {
                expected: self.manifest_digest,
                actual: expected,
            });
        }
        Ok(())
    }

    /// Serializes this manifest into deterministic canonical binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PackError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(PACK_COLD_ARCHIVE_MANIFEST_DOMAIN);
        self.encode_canonical(&mut enc);
        Ok(enc.finish_checked()?)
    }

    /// Deserializes and cryptographically verifies a canonical [`ColdPackArchiveManifest`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PackError> {
        let mut dec = CanonicalDecoder::new(bytes);
        let domain = dec.text()?;
        if domain != PACK_COLD_ARCHIVE_MANIFEST_DOMAIN {
            return Err(PackError::ArchiveIntegrity {
                detail: "cold archive manifest domain mismatch".to_owned(),
            });
        }
        let manifest = Self::decode_canonical(&mut dec)?;
        dec.ensure_finished()?;
        manifest.verify_digest()?;
        Ok(manifest)
    }

    /// Renders a deterministic, zero-Serde, secret-free JSONL line for audit logs.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"schema\":\"{PACK_COLD_ARCHIVE_MANIFEST_DOMAIN}\",\"schema_version\":{},\"pack_id\":\"{}\",\"key_epoch\":{},\"dek_id\":\"{}\",\"wrapped_dek_digest\":\"{}\",\"plaintext_pack_sha256\":\"{}\",\"plaintext_bytes\":{},\"ciphertext_sha256\":\"{}\",\"ciphertext_bytes\":{},\"object_key\":\"{}\",\"etag\":\"{}\",\"storage_tier\":\"{}\",\"part_count\":{},\"published_at_ns\":{},\"manifest_digest\":\"{}\"}}",
            self.schema_version,
            self.pack_id,
            self.key_epoch.0,
            self.dek_id,
            self.wrapped_dek_digest,
            self.plaintext_pack_sha256,
            self.plaintext_bytes,
            self.ciphertext_sha256,
            self.ciphertext_bytes,
            escape_json_str(&self.object_key),
            escape_json_str(&self.etag),
            self.storage_tier.as_str(),
            self.part_count,
            self.published_at_ns.0,
            self.manifest_digest,
        )
    }

    fn compute_manifest_digest(&self) -> Result<ContentDigest, PackError> {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(PACK_COLD_ARCHIVE_MANIFEST_DOMAIN);
        enc.u32(u32::from(self.schema_version));
        enc.u32(self.pack_id.epoch);
        enc.u64(self.pack_id.seq);
        self.key_epoch.encode_canonical(&mut enc);
        self.dek_id.encode_canonical(&mut enc);
        enc.digest(self.wrapped_dek_digest);
        enc.digest(self.plaintext_pack_sha256);
        enc.u64(self.plaintext_bytes);
        enc.digest(self.ciphertext_sha256);
        enc.u64(self.ciphertext_bytes);
        enc.text(&self.object_key);
        enc.text(&self.etag);
        enc.tag(self.storage_tier.to_tag());
        enc.u32(self.part_count);
        self.published_at_ns.encode_canonical(&mut enc);
        let bytes = enc.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

impl CanonicalEncode for ColdPackArchiveManifest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(u32::from(self.schema_version));
        encoder.u32(self.pack_id.epoch);
        encoder.u64(self.pack_id.seq);
        self.key_epoch.encode_canonical(encoder);
        self.dek_id.encode_canonical(encoder);
        encoder.digest(self.wrapped_dek_digest);
        encoder.digest(self.plaintext_pack_sha256);
        encoder.u64(self.plaintext_bytes);
        encoder.digest(self.ciphertext_sha256);
        encoder.u64(self.ciphertext_bytes);
        encoder.text(&self.object_key);
        encoder.text(&self.etag);
        encoder.tag(self.storage_tier.to_tag());
        encoder.u32(self.part_count);
        self.published_at_ns.encode_canonical(encoder);
        encoder.digest(self.manifest_digest);
    }
}

impl CanonicalDecode for ColdPackArchiveManifest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema_version_u32 = decoder.u32()?;
        let schema_version =
            u16::try_from(schema_version_u32).map_err(|_| ContractError::InvalidIdentifier)?;
        let pack_epoch = decoder.u32()?;
        let pack_seq = decoder.u64()?;
        let key_epoch = KeyEpoch::decode_canonical(decoder)?;
        let dek_id = DekId::decode_canonical(decoder)?;
        let wrapped_dek_digest = decoder.digest()?;
        let plaintext_pack_sha256 = decoder.digest()?;
        let plaintext_bytes = decoder.u64()?;
        let ciphertext_sha256 = decoder.digest()?;
        let ciphertext_bytes = decoder.u64()?;
        let object_key = decoder.text()?.to_owned();
        let etag = decoder.text()?.to_owned();
        let storage_tier = ColdStorageTier::from_tag(decoder.tag()?)?;
        let part_count = decoder.u32()?;
        let published_at_ns = TimestampNs::decode_canonical(decoder)?;
        let manifest_digest = decoder.digest()?;
        Ok(Self {
            schema_version,
            pack_id: PackId::new(pack_epoch, pack_seq),
            key_epoch,
            dek_id,
            wrapped_dek_digest,
            plaintext_pack_sha256,
            plaintext_bytes,
            ciphertext_sha256,
            ciphertext_bytes,
            object_key,
            etag,
            storage_tier,
            part_count,
            published_at_ns,
            manifest_digest,
        })
    }
}

fn validate_sha256(digest: ContentDigest) -> Result<(), PackError> {
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(PackError::UnsupportedDigestAlgorithm(digest.algorithm()));
    }
    Ok(())
}
