#![forbid(unsafe_code)]
//! Binary wire format and canonical snapshot codec for `vault.fssv`.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, EntropySource, VAULT_SNAPSHOT_AAD_DOMAIN,
    aead_encrypt, compute_master_verifier, derive_snapshot_key,
};
use crate::error::SecretError;
use crate::scope::SecretHandle;
use crate::secret::{SecretId, constant_time_eq};

/// Four-byte file magic prefix identifying an FSS encrypted vault file.
pub const VAULT_MAGIC: [u8; 4] = *b"FSSV";

/// Current binary vault format version.
pub const VAULT_FORMAT_VERSION: u16 = 1;

/// Canonical snapshot payload domain string.
pub const VAULT_SNAPSHOT_DOMAIN: &str = "fss.vault.snapshot.v1";

/// Canonical header integrity digest domain string.
pub const VAULT_HEADER_DOMAIN: &str = "fss.vault.header.v1";

/// Maximum admitted vault file size on disk (16 MiB).
pub const MAX_VAULT_FILE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of secret handles stored in a single vault file.
pub const MAX_VAULT_ENTRIES: usize = 4_096;

/// Header byte length prior to the 32-byte header digest:
/// `magic(4) + version(2) + kdf_iterations(4) + salt(32) + verifier(32) + nonce(12)`.
const VAULT_HEADER_PREFIX_LEN: usize = 86;

/// Total unencrypted binary header length including the 32-byte `header_digest`.
pub const VAULT_HEADER_LEN: usize = VAULT_HEADER_PREFIX_LEN + 32;

/// Iteration sentinel encoding direct KEK mode (HKDF-Extract over OS-wrapped KEK).
pub(crate) const KEK_MODE_ITERATIONS: u32 = 0;

pub(crate) struct VaultEntry {
    pub(crate) handle: SecretHandle,
    pub(crate) nonce: [u8; AEAD_NONCE_LEN],
    pub(crate) ciphertext: Vec<u8>,
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

pub(crate) struct ParsedHeader {
    pub(crate) version: u16,
    pub(crate) kdf_iterations: u32,
    pub(crate) kdf_salt: [u8; 32],
    pub(crate) verifier_tag: [u8; 32],
    pub(crate) snapshot_nonce: [u8; AEAD_NONCE_LEN],
}

pub(crate) fn compute_header_digest(header_prefix: &[u8]) -> [u8; 32] {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_HEADER_DOMAIN);
    encoder.bytes(header_prefix);
    ContentDigest::sha256(&encoder.finish()).bytes()
}

pub(crate) fn build_snapshot_aad(header_bytes: &[u8]) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_SNAPSHOT_AAD_DOMAIN);
    encoder.bytes(header_bytes);
    encoder.finish()
}

pub(crate) fn encode_vault_file(
    master_kek: &[u8; AEAD_KEY_LEN],
    kdf_salt: &[u8; 32],
    kdf_iterations: u32,
    entries: &BTreeMap<SecretId, VaultEntry>,
    entropy: &mut dyn EntropySource,
) -> Result<Vec<u8>, SecretError> {
    let mut snapshot_nonce = [0_u8; AEAD_NONCE_LEN];
    entropy.fill_bytes(&mut snapshot_nonce)?;

    let verifier_tag =
        compute_master_verifier(master_kek, VAULT_FORMAT_VERSION, kdf_iterations, kdf_salt);

    let mut header = Vec::with_capacity(VAULT_HEADER_LEN);
    header.extend_from_slice(&VAULT_MAGIC);
    header.extend_from_slice(&VAULT_FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&kdf_iterations.to_be_bytes());
    header.extend_from_slice(kdf_salt);
    header.extend_from_slice(&verifier_tag);
    header.extend_from_slice(&snapshot_nonce);
    let header_digest = compute_header_digest(&header);
    header.extend_from_slice(&header_digest);

    let snapshot_plain = encode_snapshot(entries)?;
    let snapshot_key = derive_snapshot_key(master_kek, kdf_salt);
    let snapshot_aad = build_snapshot_aad(&header);
    let ciphertext = aead_encrypt(
        &snapshot_key,
        &snapshot_nonce,
        &snapshot_aad,
        &snapshot_plain,
    )?;

    let mut out = Vec::with_capacity(header.len() + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub(crate) fn parse_and_verify_header(
    bytes: &[u8],
) -> Result<(ParsedHeader, &[u8], &[u8]), SecretError> {
    if bytes.len() < VAULT_HEADER_LEN + AEAD_TAG_LEN {
        return Err(SecretError::Tampered {
            detail: "vault file truncated below minimum header and AEAD tag length",
        });
    }
    if bytes[0..4] != VAULT_MAGIC {
        return Err(SecretError::Tampered {
            detail: "vault magic mismatch",
        });
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != VAULT_FORMAT_VERSION {
        return Err(SecretError::Tampered {
            detail: "unsupported vault format version",
        });
    }
    let expected_digest = compute_header_digest(&bytes[..VAULT_HEADER_PREFIX_LEN]);
    let stored_digest = &bytes[VAULT_HEADER_PREFIX_LEN..VAULT_HEADER_LEN];
    if !constant_time_eq(&expected_digest, stored_digest) {
        return Err(SecretError::Tampered {
            detail: "vault header integrity digest mismatch",
        });
    }

    let kdf_iterations = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let mut kdf_salt = [0_u8; 32];
    kdf_salt.copy_from_slice(&bytes[10..42]);
    let mut verifier_tag = [0_u8; 32];
    verifier_tag.copy_from_slice(&bytes[42..74]);
    let mut snapshot_nonce = [0_u8; AEAD_NONCE_LEN];
    snapshot_nonce.copy_from_slice(&bytes[74..86]);

    Ok((
        ParsedHeader {
            version,
            kdf_iterations,
            kdf_salt,
            verifier_tag,
            snapshot_nonce,
        },
        &bytes[..VAULT_HEADER_LEN],
        &bytes[VAULT_HEADER_LEN..],
    ))
}

fn encode_snapshot(
    entries: &BTreeMap<SecretId, VaultEntry>,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_SNAPSHOT_DOMAIN);
    encoder.u64(entries.len() as u64);
    for entry in entries.values() {
        entry.handle.encode_canonical(&mut encoder);
        encoder.bytes(&entry.nonce);
        encoder.bytes(&entry.ciphertext);
    }
    let bytes = encoder
        .finish_checked()
        .map_err(|_| SecretError::Tampered {
            detail: "failed to encode canonical vault snapshot",
        })?;
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<BTreeMap<SecretId, VaultEntry>, SecretError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    let domain = decoder.text().map_err(|_| SecretError::Tampered {
        detail: "invalid vault snapshot domain encoding",
    })?;
    if domain != VAULT_SNAPSHOT_DOMAIN {
        return Err(SecretError::Tampered {
            detail: "vault snapshot domain mismatch",
        });
    }
    let count_u64 = decoder.u64().map_err(|_| SecretError::Tampered {
        detail: "invalid vault snapshot entry count",
    })?;
    let count = usize::try_from(count_u64).map_err(|_| SecretError::Tampered {
        detail: "vault snapshot entry count overflow",
    })?;
    if count > MAX_VAULT_ENTRIES {
        return Err(SecretError::Tampered {
            detail: "vault snapshot exceeds maximum entry limit",
        });
    }

    let mut entries = BTreeMap::new();
    let mut prev_id: Option<SecretId> = None;
    for _ in 0..count {
        let handle =
            SecretHandle::decode_canonical(&mut decoder).map_err(|_| SecretError::Tampered {
                detail: "invalid secret handle inside vault snapshot",
            })?;
        if let Some(prev) = &prev_id
            && &handle.secret_id <= prev
        {
            return Err(SecretError::Tampered {
                detail: "non-canonical secret ordering in vault snapshot",
            });
        }
        let nonce_slice = decoder.bytes().map_err(|_| SecretError::Tampered {
            detail: "invalid secret nonce inside vault snapshot",
        })?;
        let nonce: [u8; AEAD_NONCE_LEN] =
            nonce_slice.try_into().map_err(|_| SecretError::Tampered {
                detail: "secret entry nonce length mismatch",
            })?;
        let ciphertext = decoder
            .bytes()
            .map_err(|_| SecretError::Tampered {
                detail: "invalid secret ciphertext inside vault snapshot",
            })?
            .to_vec();

        if handle.revoked {
            if !ciphertext.is_empty() || nonce != [0_u8; AEAD_NONCE_LEN] {
                return Err(SecretError::Tampered {
                    detail: "revoked secret entry must have scrubbed ciphertext and nonce",
                });
            }
        } else if ciphertext.len() < AEAD_TAG_LEN {
            return Err(SecretError::Tampered {
                detail: "active secret entry ciphertext truncated",
            });
        }

        prev_id = Some(handle.secret_id.clone());
        entries.insert(
            handle.secret_id.clone(),
            VaultEntry {
                handle,
                nonce,
                ciphertext,
            },
        );
    }
    decoder
        .ensure_finished()
        .map_err(|_| SecretError::Tampered {
            detail: "trailing bytes after vault snapshot",
        })?;
    Ok(entries)
}
