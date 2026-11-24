#![forbid(unsafe_code)]
//! Binary `FSKC` v1 framing, DEK wrap/unwrap AEAD helpers, and atomic `0600` persistence for
//! [`crate::crypto::keyring::KeyEnvelopeCatalog`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    TimestampNs,
};
use fss_vault::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, EntropySource, VAULT_FILE_MODE, aead_decrypt_zeroizing,
    aead_encrypt, constant_time_eq,
};
use zeroize::{Zeroize, Zeroizing};

use crate::crc32c::crc32c;
use crate::crypto::envelope::{
    DataEncryptionKey, DekId, KeyEncryptionKey, KeyEpoch, PACK_DEK_WRAP_AAD_DOMAIN,
};
use crate::crypto::erasure::ErasedDekTombstone;
use crate::crypto::keyring::{
    KEY_CATALOG_MAGIC, KEY_CATALOG_VERSION, MAX_KEY_CATALOG_BYTES, PACK_KEY_CATALOG_HEADER_DOMAIN,
    WrappedDekEnvelope,
};
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, PackId, sync_dir, write_all_bounded};

const CATALOG_HEADER_LEN: usize = 4 + 2 + 2 + 4 + 4; // 16
const CATALOG_TRAILER_LEN: usize = 4 + 32; // CRC32C + domain SHA-256 = 36

static CATALOG_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

pub(super) fn build_dek_wrap_aad(
    dek_id: DekId,
    origin_key_epoch: KeyEpoch,
    active_kek_epoch: KeyEpoch,
    scope_digest: ContentDigest,
    created_at_ns: TimestampNs,
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.text(PACK_DEK_WRAP_AAD_DOMAIN);
    dek_id.encode_canonical(&mut enc);
    origin_key_epoch.encode_canonical(&mut enc);
    active_kek_epoch.encode_canonical(&mut enc);
    enc.digest(scope_digest);
    created_at_ns.encode_canonical(&mut enc);
    enc.finish()
}

pub(super) fn wrap_dek_under_kek(
    dek: &DataEncryptionKey,
    kek: &KeyEncryptionKey,
    origin_key_epoch: KeyEpoch,
    created_at_ns: TimestampNs,
    rotated_at_ns: Option<TimestampNs>,
    bound_pack_ids: Vec<PackId>,
    entropy: &mut dyn EntropySource,
) -> Result<WrappedDekEnvelope, PackError> {
    let mut wrap_nonce = [0_u8; AEAD_NONCE_LEN];
    entropy
        .fill_bytes(&mut wrap_nonce)
        .map_err(|err| PackError::CryptoEntropy {
            detail: format!("failed to generate DEK wrap nonce: {err}"),
        })?;
    let subkey = kek.derive_wrap_subkey();
    let aad = build_dek_wrap_aad(
        dek.dek_id(),
        origin_key_epoch,
        kek.epoch(),
        kek.scope_digest(),
        created_at_ns,
    );
    let wrapped_dek_ciphertext = aead_encrypt(&subkey, &wrap_nonce, &aad, dek.key_bytes())
        .map_err(|_| PackError::CryptoAuthFailed {
            detail: "failed to wrap DEK under KEK".to_owned(),
        })?;
    Ok(WrappedDekEnvelope {
        dek_id: dek.dek_id(),
        origin_key_epoch,
        active_kek_epoch: kek.epoch(),
        scope_digest: kek.scope_digest(),
        created_at_ns,
        rotated_at_ns,
        wrap_nonce,
        wrapped_dek_ciphertext,
        bound_pack_ids,
    })
}

pub(super) fn unwrap_dek_with_kek(
    envelope: &WrappedDekEnvelope,
    kek: &KeyEncryptionKey,
) -> Result<DataEncryptionKey, PackError> {
    let subkey = kek.derive_wrap_subkey();
    let aad = build_dek_wrap_aad(
        envelope.dek_id,
        envelope.origin_key_epoch,
        envelope.active_kek_epoch,
        envelope.scope_digest,
        envelope.created_at_ns,
    );
    let mut plain = aead_decrypt_zeroizing(
        &subkey,
        &envelope.wrap_nonce,
        &aad,
        &envelope.wrapped_dek_ciphertext,
        "DEK envelope unwrap authentication failed",
    )
    .map_err(|_| PackError::CryptoAuthFailed {
        detail: format!(
            "failed to unwrap DEK {} under {}",
            envelope.dek_id,
            kek.epoch()
        ),
    })?;
    if plain.len() != AEAD_KEY_LEN {
        plain.zeroize();
        return Err(PackError::CryptoAuthFailed {
            detail: "unwrapped DEK length mismatch".to_owned(),
        });
    }
    let mut raw = Zeroizing::new([0_u8; AEAD_KEY_LEN]);
    raw.copy_from_slice(&plain);
    plain.zeroize();
    DataEncryptionKey::from_raw_zeroizing(envelope.dek_id, raw)
}

pub(super) fn encode_catalog_bytes(
    active_kek_epoch: KeyEpoch,
    scope_digest: ContentDigest,
    revoked_epochs: &BTreeSet<KeyEpoch>,
    envelopes: &BTreeMap<DekId, WrappedDekEnvelope>,
    tombstones: &BTreeMap<DekId, ErasedDekTombstone>,
) -> Result<(Vec<u8>, ContentDigest), PackError> {
    let mut enc = CanonicalEncoder::new();
    active_kek_epoch.encode_canonical(&mut enc);
    enc.digest(scope_digest);
    enc.u64(revoked_epochs.len() as u64);
    for epoch in revoked_epochs {
        epoch.encode_canonical(&mut enc);
    }
    enc.u64(envelopes.len() as u64);
    for env in envelopes.values() {
        env.encode_canonical(&mut enc);
    }
    enc.u64(tombstones.len() as u64);
    for tomb in tombstones.values() {
        tomb.encode_canonical(&mut enc);
    }
    let body = enc.finish_checked()?;
    let body_len_u32 = u32::try_from(body.len()).map_err(|_| PackError::ArithmeticOverflow)?;
    let total_len = CATALOG_HEADER_LEN
        .checked_add(body.len())
        .and_then(|n| n.checked_add(CATALOG_TRAILER_LEN))
        .ok_or(PackError::ArithmeticOverflow)?;
    if total_len as u64 > MAX_KEY_CATALOG_BYTES {
        return Err(PackError::CryptoFormat {
            detail: format!("encoded catalog size {total_len} exceeds {MAX_KEY_CATALOG_BYTES}"),
        });
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&KEY_CATALOG_MAGIC);
    out.extend_from_slice(&KEY_CATALOG_VERSION.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&active_kek_epoch.0.to_be_bytes());
    out.extend_from_slice(&body_len_u32.to_be_bytes());
    out.extend_from_slice(&body);

    let crc = crc32c(&out);
    let digest = compute_catalog_domain_digest(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&digest.bytes());
    Ok((out, digest))
}

#[allow(clippy::type_complexity)]
pub(super) fn decode_catalog_bytes(
    raw: &[u8],
) -> Result<
    (
        KeyEpoch,
        ContentDigest,
        BTreeSet<KeyEpoch>,
        BTreeMap<DekId, WrappedDekEnvelope>,
        BTreeMap<DekId, ErasedDekTombstone>,
        ContentDigest,
    ),
    PackError,
> {
    if raw.len() < CATALOG_HEADER_LEN + CATALOG_TRAILER_LEN {
        return Err(PackError::CryptoFormat {
            detail: "key envelope catalog truncated".to_owned(),
        });
    }
    if raw[0..4] != KEY_CATALOG_MAGIC {
        return Err(PackError::CryptoFormat {
            detail: "invalid FSKC key catalog magic".to_owned(),
        });
    }
    let version = u16::from_be_bytes([raw[4], raw[5]]);
    if version != KEY_CATALOG_VERSION {
        return Err(PackError::CryptoFormat {
            detail: format!("unsupported FSKC key catalog version {version}"),
        });
    }
    let flags = u16::from_be_bytes([raw[6], raw[7]]);
    if flags != 0 {
        return Err(PackError::CryptoFormat {
            detail: format!("non-zero FSKC flags 0x{flags:04x}"),
        });
    }
    let header_epoch = KeyEpoch::new(u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]))?;
    let body_len = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
    let expected_total = CATALOG_HEADER_LEN
        .checked_add(body_len)
        .and_then(|n| n.checked_add(CATALOG_TRAILER_LEN))
        .ok_or(PackError::ArithmeticOverflow)?;
    if raw.len() != expected_total {
        return Err(PackError::CryptoFormat {
            detail: format!(
                "FSKC catalog size mismatch: expected {expected_total}, got {}",
                raw.len()
            ),
        });
    }

    let crc_offset = CATALOG_HEADER_LEN + body_len;
    let stored_crc = u32::from_be_bytes([
        raw[crc_offset],
        raw[crc_offset + 1],
        raw[crc_offset + 2],
        raw[crc_offset + 3],
    ]);
    let computed_crc = crc32c(&raw[..crc_offset]);
    if stored_crc != computed_crc {
        return Err(PackError::CrcMismatch {
            expected: stored_crc,
            actual: computed_crc,
        });
    }

    let stored_sha = &raw[crc_offset + 4..crc_offset + 36];
    let computed_digest = compute_catalog_domain_digest(&raw[..crc_offset]);
    if !constant_time_eq(stored_sha, &computed_digest.bytes()) {
        return Err(PackError::CryptoAuthFailed {
            detail: "FSKC catalog domain SHA-256 verification failed".to_owned(),
        });
    }

    let mut decoder = CanonicalDecoder::new(&raw[CATALOG_HEADER_LEN..crc_offset]);
    let body_epoch = KeyEpoch::decode_canonical(&mut decoder)?;
    if body_epoch != header_epoch {
        return Err(PackError::CryptoFormat {
            detail: "FSKC catalog header/body active_kek_epoch mismatch".to_owned(),
        });
    }
    let scope_digest = decoder.digest()?;
    let revoked_count =
        usize::try_from(decoder.u64()?).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut revoked_epochs = BTreeSet::new();
    for _ in 0..revoked_count {
        let ep = KeyEpoch::decode_canonical(&mut decoder)?;
        revoked_epochs.insert(ep);
    }

    let env_count = usize::try_from(decoder.u64()?).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut envelopes = BTreeMap::new();
    for _ in 0..env_count {
        let env = WrappedDekEnvelope::decode_canonical(&mut decoder)?;
        if envelopes.insert(env.dek_id, env).is_some() {
            return Err(PackError::CryptoFormat {
                detail: "duplicate wrapped DEK envelope in FSKC catalog".to_owned(),
            });
        }
    }

    let tomb_count = usize::try_from(decoder.u64()?).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut tombstones = BTreeMap::new();
    for _ in 0..tomb_count {
        let tomb = ErasedDekTombstone::decode_canonical(&mut decoder)?;
        if envelopes.contains_key(&tomb.dek_id) {
            return Err(PackError::CryptoFormat {
                detail: "DEK appears in both active envelopes and erased tombstones".to_owned(),
            });
        }
        if tombstones.insert(tomb.dek_id, tomb).is_some() {
            return Err(PackError::CryptoFormat {
                detail: "duplicate erased DEK tombstone in FSKC catalog".to_owned(),
            });
        }
    }
    decoder.ensure_finished()?;

    Ok((
        body_epoch,
        scope_digest,
        revoked_epochs,
        envelopes,
        tombstones,
        computed_digest,
    ))
}

fn compute_catalog_domain_digest(header_and_body: &[u8]) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(PACK_KEY_CATALOG_HEADER_DOMAIN);
    enc.bytes(header_and_body);
    ContentDigest::sha256(&enc.finish())
}

pub(super) fn write_catalog_atomic(
    path: &Path,
    bytes: &[u8],
    durability: DurabilityMode,
) -> Result<(), PackError> {
    let parent = path.parent().ok_or_else(|| PackError::InvalidConfig {
        detail: "catalog path has no parent directory".to_owned(),
    })?;
    fs::create_dir_all(parent).map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;

    let seq = CATALOG_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name =
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PackError::InvalidConfig {
                detail: "catalog filename must be valid UTF-8".to_owned(),
            })?;
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(VAULT_FILE_MODE);
    }

    let mut temp_file = options
        .open(&temp_path)
        .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let write_res = (|| -> Result<(), PackError> {
        write_all_bounded(&mut temp_file, bytes)?;
        durability.sync_file(&temp_file)?;
        Ok(())
    })();
    if let Err(err) = write_res {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(temp_file);

    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(PackError::io(PackIoOperation::Rename, err));
    }
    sync_dir(parent, durability)?;
    Ok(())
}
