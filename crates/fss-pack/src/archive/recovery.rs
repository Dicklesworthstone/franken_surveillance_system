#![forbid(unsafe_code)]
//! Recover a published cold archive root from an independently retained manifest identity.

use fss_core::{ContentDigest, DigestAlgorithm, TimestampNs};

use super::manifest::ColdPackArchiveManifest;
use super::s3_pack::ColdPackTransport;
use super::s3_wire::validate_object_key;
use crate::error::PackError;

/// Maximum canonical cold manifest response, including its bounded object key and ETag.
/// One recovery performs exactly one GET with this ceiling before any ciphertext request.
pub const MAX_COLD_MANIFEST_DOWNLOAD_BYTES: usize = 16 * 1024;

/// Fetches the remote root-last manifest and checks its complete canonical identity against
/// the `manifest_digest` retained from an independent upload receipt or trusted backup.
///
/// The returned manifest can be passed to the ordinary cold audit and restore functions.
/// Its embedded digest alone is insufficient. The remote provider cannot select a different
/// pack, ciphertext, key envelope, or length by rewriting both the document and that digest.
/// This operation reads one bounded metadata object, without creating local output or
/// granting key access. Current vault and key-catalog authority is still required to restore.
pub fn fetch_cold_pack_manifest(
    transport: &mut dyn ColdPackTransport,
    manifest_object_key: &str,
    expected_manifest_digest: ContentDigest,
    now_ns: TimestampNs,
) -> Result<ColdPackArchiveManifest, PackError> {
    validate_object_key(manifest_object_key)?;
    if expected_manifest_digest.algorithm() != DigestAlgorithm::Sha256
        || expected_manifest_digest.bytes() == [0; 32]
    {
        return Err(PackError::InvalidConfig {
            detail: "remote recovery requires an independent nonzero SHA-256 manifest digest"
                .to_owned(),
        });
    }
    let response = transport.get_object(
        manifest_object_key,
        MAX_COLD_MANIFEST_DOWNLOAD_BYTES,
        now_ns,
    )?;
    if response.object_key != manifest_object_key
        || response.body.len() > MAX_COLD_MANIFEST_DOWNLOAD_BYTES
    {
        return Err(PackError::ArchiveIntegrity {
            detail: "remote manifest response exceeded its scope or byte bound".to_owned(),
        });
    }
    let manifest = ColdPackArchiveManifest::from_canonical_bytes(&response.body)?;
    if manifest.manifest_digest != expected_manifest_digest {
        return Err(PackError::DigestMismatch {
            expected: expected_manifest_digest,
            actual: manifest.manifest_digest,
        });
    }
    Ok(manifest)
}
