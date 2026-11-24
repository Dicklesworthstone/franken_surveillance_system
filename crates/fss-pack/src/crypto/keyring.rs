#![forbid(unsafe_code)]
//! Durable atomic CRC32C-framed [`KeyEnvelopeCatalog`] (`FSKC` v1) with zero-rewrite KEK rotation
//! and durable cryptographic erasure tombstones.
//!
//! Rotating the site KEK re-wraps every active DEK envelope atomically without touching or rewriting
//! any sealed packfile. Erasing a DEK zeroizes its wrapped ciphertext and overwrites the catalog
//! atomically with an [`ErasedDekTombstone`] so the erased wrapped DEK cannot be recovered from disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};
use fss_vault::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, AdapterFamily, EntropySource, SecretScope,
};
use zeroize::Zeroize;

use crate::crypto::envelope::{
    DataEncryptionKey, DekId, KeyEncryptionKey, KeyEpoch, PACK_DEK_WRAP_AAD_DOMAIN,
};
use crate::crypto::erasure::{CryptoErasureReceipt, ErasedDekTombstone};
use crate::crypto::keyring_codec::{
    decode_catalog_bytes, encode_catalog_bytes, unwrap_dek_with_kek, wrap_dek_under_kek,
    write_catalog_atomic,
};
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, PackId};

/// Magic prefix identifying a durable [`KeyEnvelopeCatalog`] file (`FSKC`).
pub const KEY_CATALOG_MAGIC: [u8; 4] = *b"FSKC";
/// Supported binary format version for `KeyEnvelopeCatalog`.
pub const KEY_CATALOG_VERSION: u16 = 1;
/// Canonical SHA-256 domain authenticating the `FSKC` v1 catalog header and body.
pub const PACK_KEY_CATALOG_HEADER_DOMAIN: &str = "fss.pack.key_catalog_header.v1";
/// Maximum catalog file size admitted on open (`16 MiB`).
pub const MAX_KEY_CATALOG_BYTES: u64 = 16 * 1024 * 1024;
/// Exact byte length of a ChaCha20-Poly1305 wrapped 256-bit DEK (`32 + 16 = 48`).
pub const WRAPPED_DEK_CIPHERTEXT_LEN: usize = AEAD_KEY_LEN + AEAD_TAG_LEN;

/// AEAD-wrapped 256-bit DEK entry stored in [`KeyEnvelopeCatalog`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedDekEnvelope {
    /// Non-secret 128-bit DEK identifier.
    pub dek_id: DekId,
    /// Original KEK epoch under which this DEK was created (bound in `FSAE` pack headers).
    pub origin_key_epoch: KeyEpoch,
    /// Active KEK epoch currently wrapping `wrapped_dek_ciphertext` (updated by `rotate_kek`).
    pub active_kek_epoch: KeyEpoch,
    /// Canonical scope digest of the `StorageKek` [`SecretScope`].
    pub scope_digest: ContentDigest,
    /// Explicit creation timestamp.
    pub created_at_ns: TimestampNs,
    /// Most recent KEK rotation timestamp, if rotated.
    pub rotated_at_ns: Option<TimestampNs>,
    /// Fresh 96-bit nonce used to wrap the 32-byte DEK under the derived KEK subkey.
    pub wrap_nonce: [u8; AEAD_NONCE_LEN],
    /// Exact 48-byte ChaCha20-Poly1305 ciphertext + tag protecting the 32-byte DEK.
    pub wrapped_dek_ciphertext: Vec<u8>,
    /// Sorted, deduplicated packfile identifiers encrypted under this DEK.
    pub bound_pack_ids: Vec<PackId>,
}

impl WrappedDekEnvelope {
    /// Computes the canonical SHA-256 digest of this wrapped envelope (used in cold manifests).
    #[must_use]
    pub fn envelope_digest(&self) -> ContentDigest {
        self.canonical_digest(PACK_DEK_WRAP_AAD_DOMAIN)
    }

    /// Explicitly zeroes the wrapped DEK ciphertext and wrap nonce in place.
    pub fn zeroize_secret_material(&mut self) {
        self.wrap_nonce.zeroize();
        self.wrapped_dek_ciphertext.zeroize();
        self.wrapped_dek_ciphertext.clear();
    }
}

impl CanonicalEncode for WrappedDekEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.dek_id.encode_canonical(encoder);
        self.origin_key_epoch.encode_canonical(encoder);
        self.active_kek_epoch.encode_canonical(encoder);
        encoder.digest(self.scope_digest);
        self.created_at_ns.encode_canonical(encoder);
        match self.rotated_at_ns {
            Some(ts) => {
                encoder.bool(true);
                ts.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        encoder.bytes(&self.wrap_nonce);
        encoder.bytes(&self.wrapped_dek_ciphertext);
        encoder.u64(self.bound_pack_ids.len() as u64);
        for pack_id in &self.bound_pack_ids {
            encoder.u32(pack_id.epoch);
            encoder.u64(pack_id.seq);
        }
    }
}

impl CanonicalDecode for WrappedDekEnvelope {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let dek_id = DekId::decode_canonical(decoder)?;
        let origin_key_epoch = KeyEpoch::decode_canonical(decoder)?;
        let active_kek_epoch = KeyEpoch::decode_canonical(decoder)?;
        let scope_digest = decoder.digest()?;
        let created_at_ns = TimestampNs::decode_canonical(decoder)?;
        let rotated_at_ns = if decoder.bool()? {
            Some(TimestampNs::decode_canonical(decoder)?)
        } else {
            None
        };
        let nonce_slice = decoder.bytes()?;
        let wrap_nonce: [u8; AEAD_NONCE_LEN] = nonce_slice
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        let wrapped_dek_ciphertext = decoder.bytes()?.to_vec();
        if wrapped_dek_ciphertext.len() != WRAPPED_DEK_CIPHERTEXT_LEN {
            return Err(ContractError::InvalidDigest);
        }
        let pack_count_u64 = decoder.u64()?;
        let pack_count =
            usize::try_from(pack_count_u64).map_err(|_| ContractError::InvalidDigest)?;
        if pack_count > 100_000 {
            return Err(ContractError::InvalidDigest);
        }
        let mut bound_pack_ids = Vec::with_capacity(pack_count);
        for _ in 0..pack_count {
            let epoch = decoder.u32()?;
            let seq = decoder.u64()?;
            bound_pack_ids.push(PackId::new(epoch, seq));
        }
        Ok(Self {
            dek_id,
            origin_key_epoch,
            active_kek_epoch,
            scope_digest,
            created_at_ns,
            rotated_at_ns,
            wrap_nonce,
            wrapped_dek_ciphertext,
            bound_pack_ids,
        })
    }
}

/// Receipt emitted after an atomic zero-rewrite KEK rotation across [`KeyEnvelopeCatalog`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KekRotationReceipt {
    /// Retired/revoked KEK epoch.
    pub old_epoch: KeyEpoch,
    /// Newly activated KEK epoch.
    pub new_epoch: KeyEpoch,
    /// Number of active DEK envelopes re-wrapped under `new_epoch`.
    pub rewrapped_dek_count: u64,
    /// Number of erased DEK tombstones preserved untouched.
    pub preserved_erased_tombstones: u64,
    /// Explicit timestamp when rotation committed.
    pub rotated_at_ns: TimestampNs,
    /// Canonical SHA-256 digest of the newly persisted `FSKC` catalog.
    pub catalog_digest: ContentDigest,
}

/// Durable atomic CRC32C-framed catalog storing wrapped DEK envelopes, active/revoked KEK epochs,
/// and permanent [`ErasedDekTombstone`]s.
pub struct KeyEnvelopeCatalog {
    path: PathBuf,
    durability: DurabilityMode,
    active_kek_epoch: KeyEpoch,
    scope_digest: ContentDigest,
    revoked_epochs: BTreeSet<KeyEpoch>,
    envelopes: BTreeMap<DekId, WrappedDekEnvelope>,
    tombstones: BTreeMap<DekId, ErasedDekTombstone>,
    catalog_digest: ContentDigest,
}

impl KeyEnvelopeCatalog {
    /// Opens an existing `FSKC` catalog or creates and atomically persists a new one.
    pub fn open_or_create(
        path: impl AsRef<Path>,
        initial_kek_epoch: KeyEpoch,
        scope: &SecretScope,
        durability: DurabilityMode,
    ) -> Result<Self, PackError> {
        let initial_kek_epoch = KeyEpoch::new(initial_kek_epoch.0)?;
        if scope.adapter_family() != AdapterFamily::StorageKek {
            return Err(PackError::CryptoAuthority {
                detail: format!(
                    "KeyEnvelopeCatalog requires AdapterFamily::StorageKek, got {}",
                    scope.adapter_family()
                ),
            });
        }
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let loaded = Self::open_existing(&path, durability)?;
            if loaded.scope_digest != scope.scope_digest() {
                return Err(PackError::CryptoAuthority {
                    detail:
                        "existing KeyEnvelopeCatalog scope digest does not match supplied scope"
                            .to_owned(),
                });
            }
            return Ok(loaded);
        }
        let mut catalog = Self {
            path,
            durability,
            active_kek_epoch: initial_kek_epoch,
            scope_digest: scope.scope_digest(),
            revoked_epochs: BTreeSet::new(),
            envelopes: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            catalog_digest: ContentDigest::sha256(b""),
        };
        let digest = catalog.persist_state(
            catalog.active_kek_epoch,
            &catalog.revoked_epochs,
            &catalog.envelopes,
            &catalog.tombstones,
        )?;
        catalog.catalog_digest = digest;
        Ok(catalog)
    }

    /// Opens and verifies an existing `FSKC` v1 catalog from disk, failing closed on corruption.
    pub fn open_existing(
        path: impl AsRef<Path>,
        durability: DurabilityMode,
    ) -> Result<Self, PackError> {
        let path = path.as_ref().to_path_buf();
        let meta = fs::symlink_metadata(&path)
            .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(PackError::CryptoFormat {
                detail: "key envelope catalog must be a regular non-symlink file".to_owned(),
            });
        }
        if meta.len() > MAX_KEY_CATALOG_BYTES {
            return Err(PackError::CryptoFormat {
                detail: format!(
                    "key envelope catalog size {} exceeds maximum {MAX_KEY_CATALOG_BYTES}",
                    meta.len()
                ),
            });
        }
        let mut file =
            File::open(&path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        let mut raw = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        file.read_to_end(&mut raw)
            .map_err(|err| PackError::io(PackIoOperation::Read, err))?;

        let (active_kek_epoch, scope_digest, revoked_epochs, envelopes, tombstones, catalog_digest) =
            decode_catalog_bytes(&raw)?;

        Ok(Self {
            path,
            durability,
            active_kek_epoch,
            scope_digest,
            revoked_epochs,
            envelopes,
            tombstones,
            catalog_digest,
        })
    }

    /// Returns the on-disk file path of this catalog.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the currently active site [`KeyEpoch`].
    #[must_use]
    pub const fn active_kek_epoch(&self) -> KeyEpoch {
        self.active_kek_epoch
    }

    /// Returns the canonical scope digest bound to this catalog.
    #[must_use]
    pub const fn scope_digest(&self) -> ContentDigest {
        self.scope_digest
    }

    /// Returns the SHA-256 digest of the most recently persisted catalog state.
    #[must_use]
    pub const fn catalog_digest(&self) -> ContentDigest {
        self.catalog_digest
    }

    /// Returns `true` if `epoch` was retired/revoked by a prior KEK rotation.
    #[must_use]
    pub fn is_epoch_revoked(&self, epoch: KeyEpoch) -> bool {
        self.revoked_epochs.contains(&epoch)
    }

    /// Returns the count of currently active (non-erased) wrapped DEK envelopes.
    #[must_use]
    pub fn active_dek_count(&self) -> usize {
        self.envelopes.len()
    }

    /// Returns the count of permanently erased DEK tombstones.
    #[must_use]
    pub fn erased_dek_count(&self) -> usize {
        self.tombstones.len()
    }

    /// Looks up an active [`WrappedDekEnvelope`] by [`DekId`].
    #[must_use]
    pub fn get_envelope(&self, dek_id: DekId) -> Option<&WrappedDekEnvelope> {
        self.envelopes.get(&dek_id)
    }

    /// Looks up an [`ErasedDekTombstone`] by [`DekId`].
    #[must_use]
    pub fn get_tombstone(&self, dek_id: DekId) -> Option<&ErasedDekTombstone> {
        self.tombstones.get(&dek_id)
    }

    /// Generates a fresh 256-bit DEK, wraps it under `kek`, persists atomically, and returns both.
    pub fn create_and_wrap_dek(
        &mut self,
        kek: &KeyEncryptionKey,
        entropy: &mut dyn EntropySource,
        bound_packs: &[PackId],
        now_ns: TimestampNs,
    ) -> Result<(DataEncryptionKey, WrappedDekEnvelope), PackError> {
        let dek = DataEncryptionKey::generate(entropy)?;
        let envelope = self.register_and_wrap_dek(&dek, kek, entropy, bound_packs, now_ns)?;
        Ok((dek, envelope))
    }

    /// Wraps an explicit [`DataEncryptionKey`] under the active `kek` and persists atomically.
    pub fn register_and_wrap_dek(
        &mut self,
        dek: &DataEncryptionKey,
        kek: &KeyEncryptionKey,
        entropy: &mut dyn EntropySource,
        bound_packs: &[PackId],
        now_ns: TimestampNs,
    ) -> Result<WrappedDekEnvelope, PackError> {
        self.validate_active_kek(kek)?;
        if let Some(tomb) = self.tombstones.get(&dek.dek_id()) {
            return Err(PackError::CryptoKeyErased {
                dek_id: dek.dek_id().to_hex(),
                reason: tomb.reason.clone(),
            });
        }
        if self.envelopes.contains_key(&dek.dek_id()) {
            return Err(PackError::InvalidConfig {
                detail: format!("DEK {} is already registered in catalog", dek.dek_id()),
            });
        }

        let mut packs = bound_packs.to_vec();
        packs.sort_unstable();
        packs.dedup();
        let envelope = wrap_dek_under_kek(dek, kek, kek.epoch(), now_ns, None, packs, entropy)?;

        let mut staged = self.envelopes.clone();
        staged.insert(dek.dek_id(), envelope.clone());
        let digest = self.persist_state(
            self.active_kek_epoch,
            &self.revoked_epochs,
            &staged,
            &self.tombstones,
        )?;
        self.envelopes = staged;
        self.catalog_digest = digest;
        Ok(envelope)
    }

    /// Records an additional [`PackId`] encrypted under `dek_id` and persists atomically.
    pub fn bind_pack_to_dek(&mut self, dek_id: DekId, pack_id: PackId) -> Result<(), PackError> {
        if let Some(tomb) = self.tombstones.get(&dek_id) {
            return Err(PackError::CryptoKeyErased {
                dek_id: dek_id.to_hex(),
                reason: tomb.reason.clone(),
            });
        }
        let mut staged = self.envelopes.clone();
        let entry = staged
            .get_mut(&dek_id)
            .ok_or_else(|| PackError::CryptoKeyNotFound {
                dek_id: dek_id.to_hex(),
            })?;
        if !entry.bound_pack_ids.contains(&pack_id) {
            entry.bound_pack_ids.push(pack_id);
            entry.bound_pack_ids.sort_unstable();
            let digest = self.persist_state(
                self.active_kek_epoch,
                &self.revoked_epochs,
                &staged,
                &self.tombstones,
            )?;
            self.envelopes = staged;
            self.catalog_digest = digest;
        }
        Ok(())
    }

    /// Unwraps the 256-bit DEK identified by `dek_id` using `kek`.
    pub fn unwrap_dek(
        &self,
        dek_id: DekId,
        kek: &KeyEncryptionKey,
    ) -> Result<DataEncryptionKey, PackError> {
        if let Some(tomb) = self.tombstones.get(&dek_id) {
            return Err(PackError::CryptoKeyErased {
                dek_id: dek_id.to_hex(),
                reason: tomb.reason.clone(),
            });
        }
        let envelope = self
            .envelopes
            .get(&dek_id)
            .ok_or_else(|| PackError::CryptoKeyNotFound {
                dek_id: dek_id.to_hex(),
            })?;
        if kek.scope_digest() != self.scope_digest || kek.scope_digest() != envelope.scope_digest {
            return Err(PackError::CryptoAuthFailed {
                detail: "KEK scope digest does not match wrapped DEK envelope".to_owned(),
            });
        }
        if self.is_epoch_revoked(kek.epoch()) {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("KEK {} has been revoked by rotation", kek.epoch()),
            });
        }
        if kek.epoch() != envelope.active_kek_epoch {
            return Err(PackError::CryptoAuthFailed {
                detail: format!(
                    "KEK {} cannot unwrap DEK envelope bound to {}",
                    kek.epoch(),
                    envelope.active_kek_epoch
                ),
            });
        }
        unwrap_dek_with_kek(envelope, kek)
    }

    /// Atomically rotates the site KEK from `old_kek` to `new_kek` (`new_epoch > active_kek_epoch`),
    /// re-wrapping every active DEK envelope with ZERO re-encryption of immutable packfiles.
    pub fn rotate_kek(
        &mut self,
        old_kek: &KeyEncryptionKey,
        new_kek: &KeyEncryptionKey,
        new_epoch: KeyEpoch,
        entropy: &mut dyn EntropySource,
        now_ns: TimestampNs,
    ) -> Result<KekRotationReceipt, PackError> {
        let new_epoch = KeyEpoch::new(new_epoch.0)?;
        self.validate_active_kek(old_kek)?;
        if new_kek.epoch() != new_epoch {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "new_kek epoch {} does not match requested new_epoch {new_epoch}",
                    new_kek.epoch()
                ),
            });
        }
        if new_epoch.0 <= self.active_kek_epoch.0 {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "new_epoch {} must be strictly greater than active epoch {}",
                    new_epoch.0, self.active_kek_epoch.0
                ),
            });
        }
        if new_kek.scope_digest() != self.scope_digest {
            return Err(PackError::CryptoAuthority {
                detail: "new KEK scope digest does not match KeyEnvelopeCatalog scope".to_owned(),
            });
        }

        let mut rotated_envelopes = BTreeMap::new();
        for (&dek_id, old_env) in &self.envelopes {
            let dek = unwrap_dek_with_kek(old_env, old_kek)?;
            let new_env = wrap_dek_under_kek(
                &dek,
                new_kek,
                old_env.origin_key_epoch,
                old_env.created_at_ns,
                Some(now_ns),
                old_env.bound_pack_ids.clone(),
                entropy,
            )?;
            rotated_envelopes.insert(dek_id, new_env);
        }

        let old_epoch = self.active_kek_epoch;
        let mut staged_revoked = self.revoked_epochs.clone();
        staged_revoked.insert(old_epoch);

        let catalog_digest = self.persist_state(
            new_epoch,
            &staged_revoked,
            &rotated_envelopes,
            &self.tombstones,
        )?;

        let rewrapped_dek_count = rotated_envelopes.len() as u64;
        for env in self.envelopes.values_mut() {
            env.zeroize_secret_material();
        }
        self.envelopes = rotated_envelopes;
        self.revoked_epochs = staged_revoked;
        self.active_kek_epoch = new_epoch;
        self.catalog_digest = catalog_digest;

        Ok(KekRotationReceipt {
            old_epoch,
            new_epoch,
            rewrapped_dek_count,
            preserved_erased_tombstones: self.tombstones.len() as u64,
            rotated_at_ns: now_ns,
            catalog_digest,
        })
    }

    /// Permanently destroys (zeroizes and replaces with [`ErasedDekTombstone`]) the wrapped DEK
    /// envelope for `dek_id`, persisting atomically and returning a canonical [`CryptoErasureReceipt`].
    pub fn crypto_erase_dek(
        &mut self,
        dek_id: DekId,
        reason: &str,
        actor: &str,
        timestamp_ns: TimestampNs,
    ) -> Result<CryptoErasureReceipt, PackError> {
        self.crypto_erase_dek_internal(dek_id, None, reason, actor, timestamp_ns)
    }

    /// Permanently destroys the wrapped DEK envelope for `dek_id` and signs the emitted
    /// [`CryptoErasureReceipt`] with `signing_kek`.
    pub fn crypto_erase_dek_signed(
        &mut self,
        dek_id: DekId,
        signing_kek: &KeyEncryptionKey,
        reason: &str,
        actor: &str,
        timestamp_ns: TimestampNs,
    ) -> Result<CryptoErasureReceipt, PackError> {
        self.validate_active_kek(signing_kek)?;
        self.crypto_erase_dek_internal(dek_id, Some(signing_kek), reason, actor, timestamp_ns)
    }

    fn crypto_erase_dek_internal(
        &mut self,
        dek_id: DekId,
        signing_kek: Option<&KeyEncryptionKey>,
        reason: &str,
        actor: &str,
        timestamp_ns: TimestampNs,
    ) -> Result<CryptoErasureReceipt, PackError> {
        if let Some(tomb) = self.tombstones.get(&dek_id) {
            return Err(PackError::CryptoKeyErased {
                dek_id: dek_id.to_hex(),
                reason: tomb.reason.clone(),
            });
        }
        let target_env =
            self.envelopes
                .get(&dek_id)
                .ok_or_else(|| PackError::CryptoKeyNotFound {
                    dek_id: dek_id.to_hex(),
                })?;

        let receipt = CryptoErasureReceipt::build(
            dek_id,
            target_env.origin_key_epoch,
            target_env.active_kek_epoch,
            target_env.bound_pack_ids.clone(),
            reason,
            actor,
            timestamp_ns,
            target_env.envelope_digest(),
            self.scope_digest,
            signing_kek,
        )?;
        let tombstone = receipt.to_tombstone();

        let mut staged_envelopes = self.envelopes.clone();
        if let Some(mut removed) = staged_envelopes.remove(&dek_id) {
            removed.zeroize_secret_material();
        }
        let mut staged_tombstones = self.tombstones.clone();
        staged_tombstones.insert(dek_id, tombstone);

        let digest = self.persist_state(
            self.active_kek_epoch,
            &self.revoked_epochs,
            &staged_envelopes,
            &staged_tombstones,
        )?;

        if let Some(mut old) = self.envelopes.remove(&dek_id) {
            old.zeroize_secret_material();
        }
        self.envelopes = staged_envelopes;
        self.tombstones = staged_tombstones;
        self.catalog_digest = digest;

        Ok(receipt)
    }

    fn validate_active_kek(&self, kek: &KeyEncryptionKey) -> Result<(), PackError> {
        if kek.scope_digest() != self.scope_digest {
            return Err(PackError::CryptoAuthFailed {
                detail: "KEK scope digest does not match KeyEnvelopeCatalog scope".to_owned(),
            });
        }
        if self.is_epoch_revoked(kek.epoch()) {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("KEK {} has been revoked", kek.epoch()),
            });
        }
        if kek.epoch() != self.active_kek_epoch {
            return Err(PackError::CryptoAuthFailed {
                detail: format!(
                    "KEK {} does not match active catalog {}",
                    kek.epoch(),
                    self.active_kek_epoch
                ),
            });
        }
        Ok(())
    }

    fn persist_state(
        &self,
        active_kek_epoch: KeyEpoch,
        revoked_epochs: &BTreeSet<KeyEpoch>,
        envelopes: &BTreeMap<DekId, WrappedDekEnvelope>,
        tombstones: &BTreeMap<DekId, ErasedDekTombstone>,
    ) -> Result<ContentDigest, PackError> {
        let (encoded, digest) = encode_catalog_bytes(
            active_kek_epoch,
            self.scope_digest,
            revoked_epochs,
            envelopes,
            tombstones,
        )?;
        write_catalog_atomic(&self.path, &encoded, self.durability)?;
        Ok(digest)
    }
}

impl Drop for KeyEnvelopeCatalog {
    fn drop(&mut self) {
        for env in self.envelopes.values_mut() {
            env.zeroize_secret_material();
        }
    }
}
