#![forbid(unsafe_code)]
//! Cross-platform AEAD-encrypted local operator vault (`<dir>/vault.fssv`).
//!
//! Zero plaintext secret bytes or metadata handles ever touch disk. Every file
//! write uses owner-only `0600` permissions inside an owner-only `0700` directory
//! with atomic temp -> fsync -> rename -> dirsync durability.

use core::fmt;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, EntropySource, KdfParams, MAX_PBKDF2_ITERATIONS, OsEntropy,
    aead_decrypt_zeroizing, compute_master_verifier, derive_snapshot_key, hkdf_sha256_extract,
    open_secret_entry, pbkdf2_hmac_sha256, seal_secret_entry,
};
use crate::error::SecretError;
use crate::fs_guard::{read_secure_file, write_secure_atomic};
use crate::scope::{
    AdapterFamily, CAP_SECRET_READ_001, SecretAccessCx, SecretBackendKind, SecretHandle,
    SecretOperation,
};
use crate::secret::{SecretBytes, SecretId, constant_time_eq};
use crate::store::{FetchedSecret, SecretStore};
use crate::vault_format::{
    KEK_MODE_ITERATIONS, ParsedHeader, VaultEntry, build_snapshot_aad, decode_snapshot,
    encode_vault_file, parse_and_verify_header,
};
pub use crate::vault_format::{
    MAX_VAULT_ENTRIES, MAX_VAULT_FILE_BYTES, VAULT_FORMAT_VERSION, VAULT_HEADER_DOMAIN,
    VAULT_HEADER_LEN, VAULT_MAGIC, VAULT_SNAPSHOT_DOMAIN,
};

/// Canonical filename created inside the vault directory.
pub const VAULT_FILENAME: &str = "vault.fssv";

struct UnlockedState {
    master_kek: Zeroizing<[u8; AEAD_KEY_LEN]>,
    kdf_salt: [u8; 32],
    kdf_iterations: u32,
    entries: BTreeMap<SecretId, VaultEntry>,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.kdf_salt.zeroize();
        self.entries.clear();
    }
}

enum VaultUnlockState {
    Locked,
    Unlocked(UnlockedState),
}

/// Cross-platform ChaCha20-Poly1305 encrypted local operator vault.
///
/// Supports explicit operator `unlock`/`lock` sessions, per-secret scope-bound
/// AEAD envelopes, generation rotation, tombstoned revocation, and owner-only
/// atomic persistence.
pub struct LocalEncryptedVault<E: EntropySource = OsEntropy> {
    vault_dir: PathBuf,
    vault_path: PathBuf,
    kdf_params: KdfParams,
    entropy: E,
    backend_kind: SecretBackendKind,
    state: VaultUnlockState,
}

impl LocalEncryptedVault<OsEntropy> {
    /// Opens a handle to a local encrypted vault using production KDF defaults (`100_000` rounds)
    /// and [`OsEntropy`]. The vault starts in the locked state.
    #[must_use]
    pub fn open(vault_dir: impl Into<PathBuf>) -> Self {
        Self::open_with_entropy(vault_dir, KdfParams::default(), OsEntropy::new())
    }
}

impl<E: EntropySource> LocalEncryptedVault<E> {
    /// Opens a handle to a local encrypted vault with explicit [`KdfParams`] and [`EntropySource`].
    #[must_use]
    pub fn open_with_entropy(
        vault_dir: impl Into<PathBuf>,
        kdf_params: KdfParams,
        entropy: E,
    ) -> Self {
        let vault_dir = vault_dir.into();
        let vault_path = vault_dir.join(VAULT_FILENAME);
        Self {
            vault_dir,
            vault_path,
            kdf_params,
            entropy,
            backend_kind: SecretBackendKind::LocalEncryptedVault,
            state: VaultUnlockState::Locked,
        }
    }

    pub(crate) fn set_backend_kind(&mut self, backend_kind: SecretBackendKind) {
        self.backend_kind = backend_kind;
    }

    /// Returns the directory containing `vault.fssv`.
    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Returns the full path to `vault.fssv`.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Returns `true` if `vault.fssv` currently exists on disk.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Returns `true` when the vault currently holds an active unlocked master KEK in memory.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultUnlockState::Unlocked(_))
    }

    /// Locks the vault immediately, zeroizing the master KEK and all cached entry buffers.
    pub fn lock(&mut self) {
        self.state = VaultUnlockState::Locked;
    }

    /// Initializes a brand-new passphrase-protected `vault.fssv` and leaves it unlocked.
    pub fn initialize(&mut self, passphrase: &SecretBytes) -> Result<(), SecretError> {
        if self.vault_path.exists() {
            return Err(SecretError::InvalidInput {
                detail: "vault file already exists; use unlock instead of initialize".to_string(),
            });
        }
        let mut kdf_salt = [0_u8; 32];
        self.entropy.fill_bytes(&mut kdf_salt)?;
        let iterations = self.kdf_params.iterations();
        let master_kek = pbkdf2_hmac_sha256(passphrase.as_slice(), &kdf_salt, iterations)?;
        self.initialize_state(master_kek, kdf_salt, iterations)
    }

    /// Unlocks an existing passphrase-protected `vault.fssv` after verifying permissions,
    /// header integrity, passphrase verifier tag, and snapshot AEAD authentication.
    pub fn unlock(&mut self, passphrase: &SecretBytes) -> Result<(), SecretError> {
        let bytes = read_secure_file(&self.vault_path, MAX_VAULT_FILE_BYTES)?;
        let (header, header_slice, ciphertext) = parse_and_verify_header(&bytes)?;
        if header.kdf_iterations == KEK_MODE_ITERATIONS
            || header.kdf_iterations > MAX_PBKDF2_ITERATIONS
        {
            return Err(SecretError::AuthFailed);
        }
        let master_kek = pbkdf2_hmac_sha256(
            passphrase.as_slice(),
            &header.kdf_salt,
            header.kdf_iterations,
        )?;
        self.finish_unlock(header, header_slice, ciphertext, master_kek)
    }

    /// Initializes a brand-new KEK-protected `vault.fssv` (e.g. OS keychain wrapped KEK).
    pub fn initialize_with_kek(
        &mut self,
        raw_kek: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Result<(), SecretError> {
        if self.vault_path.exists() {
            return Err(SecretError::InvalidInput {
                detail: "vault file already exists; use unlock_with_kek instead".to_string(),
            });
        }
        let mut kdf_salt = [0_u8; 32];
        self.entropy.fill_bytes(&mut kdf_salt)?;
        let master_kek = hkdf_sha256_extract(&kdf_salt, &*raw_kek);
        self.initialize_state(master_kek, kdf_salt, KEK_MODE_ITERATIONS)
    }

    /// Unlocks an existing KEK-protected `vault.fssv`.
    pub fn unlock_with_kek(
        &mut self,
        raw_kek: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Result<(), SecretError> {
        let bytes = read_secure_file(&self.vault_path, MAX_VAULT_FILE_BYTES)?;
        let (header, header_slice, ciphertext) = parse_and_verify_header(&bytes)?;
        if header.kdf_iterations != KEK_MODE_ITERATIONS {
            return Err(SecretError::AuthFailed);
        }
        let master_kek = hkdf_sha256_extract(&header.kdf_salt, &*raw_kek);
        self.finish_unlock(header, header_slice, ciphertext, master_kek)
    }

    /// Lists all handles across adapter families for an authorized [`AdapterFamily::OperatorSession`].
    pub fn list_all_handles_for_operator(
        &self,
        cx: &SecretAccessCx,
    ) -> Result<Vec<SecretHandle>, SecretError> {
        cx.authorize(SecretOperation::List, None, None)?;
        if cx.scope().adapter_family() != AdapterFamily::OperatorSession {
            return Err(SecretError::Unauthorized {
                required_capability: CAP_SECRET_READ_001,
                detail: "cross-scope handle listing requires OperatorSession scope".to_string(),
            });
        }
        let unlocked = self.require_unlocked()?;
        Ok(unlocked
            .entries
            .values()
            .map(|entry| entry.handle.clone())
            .collect())
    }

    fn initialize_state(
        &mut self,
        master_kek: Zeroizing<[u8; AEAD_KEY_LEN]>,
        kdf_salt: [u8; 32],
        kdf_iterations: u32,
    ) -> Result<(), SecretError> {
        let unlocked = UnlockedState {
            master_kek,
            kdf_salt,
            kdf_iterations,
            entries: BTreeMap::new(),
        };
        let encoded = encode_vault_file(
            &unlocked.master_kek,
            &unlocked.kdf_salt,
            unlocked.kdf_iterations,
            &unlocked.entries,
            &mut self.entropy,
        )?;
        write_secure_atomic(&self.vault_dir, VAULT_FILENAME, &encoded)?;
        self.state = VaultUnlockState::Unlocked(unlocked);
        Ok(())
    }

    fn finish_unlock(
        &mut self,
        header: ParsedHeader,
        header_slice: &[u8],
        ciphertext: &[u8],
        master_kek: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Result<(), SecretError> {
        let expected_verifier = compute_master_verifier(
            &master_kek,
            header.version,
            header.kdf_iterations,
            &header.kdf_salt,
        );
        if !constant_time_eq(&expected_verifier, &header.verifier_tag) {
            return Err(SecretError::AuthFailed);
        }
        let snapshot_key = derive_snapshot_key(&master_kek, &header.kdf_salt);
        let snapshot_aad = build_snapshot_aad(header_slice);
        let plaintext = aead_decrypt_zeroizing(
            &snapshot_key,
            &header.snapshot_nonce,
            &snapshot_aad,
            ciphertext,
            "vault snapshot AEAD authentication failed",
        )?;
        let entries = decode_snapshot(&plaintext)?;
        self.state = VaultUnlockState::Unlocked(UnlockedState {
            master_kek,
            kdf_salt: header.kdf_salt,
            kdf_iterations: header.kdf_iterations,
            entries,
        });
        Ok(())
    }

    fn require_unlocked(&self) -> Result<&UnlockedState, SecretError> {
        match &self.state {
            VaultUnlockState::Unlocked(state) => Ok(state),
            VaultUnlockState::Locked => Err(SecretError::VaultLocked),
        }
    }

    fn persist_unlocked(&mut self) -> Result<(), SecretError> {
        let encoded = match &self.state {
            VaultUnlockState::Unlocked(state) => encode_vault_file(
                &state.master_kek,
                &state.kdf_salt,
                state.kdf_iterations,
                &state.entries,
                &mut self.entropy,
            )?,
            VaultUnlockState::Locked => return Err(SecretError::VaultLocked),
        };
        write_secure_atomic(&self.vault_dir, VAULT_FILENAME, &encoded)
    }
}

impl<E: EntropySource> SecretStore for LocalEncryptedVault<E> {
    fn backend_kind(&self) -> SecretBackendKind {
        self.backend_kind
    }

    fn store(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        cx.authorize(SecretOperation::Write, Some(secret_id), None)?;
        let backend_kind = self.backend_kind;
        let (nonce, ciphertext, handle) = {
            let state = match &self.state {
                VaultUnlockState::Unlocked(s) => s,
                VaultUnlockState::Locked => return Err(SecretError::VaultLocked),
            };
            if let Some(existing) = state.entries.get(secret_id) {
                if existing.handle.revoked {
                    return Err(SecretError::Revoked {
                        secret_id: secret_id.as_str().to_string(),
                        generation: existing.handle.generation,
                    });
                }
                return Err(SecretError::InvalidInput {
                    detail: format!(
                        "secret '{secret_id}' already exists; use rotate to advance generation"
                    ),
                });
            }
            if state.entries.len() >= MAX_VAULT_ENTRIES {
                return Err(SecretError::InvalidInput {
                    detail: format!("vault reached maximum entry count of {MAX_VAULT_ENTRIES}"),
                });
            }
            let scope = cx.scope().clone();
            let scope_digest = scope.scope_digest();
            let (nonce, ciphertext) = seal_secret_entry(
                &state.master_kek,
                secret_id,
                1,
                scope_digest,
                &value,
                &mut self.entropy,
            )?;
            let handle = SecretHandle {
                secret_id: secret_id.clone(),
                scope,
                generation: 1,
                scope_digest,
                created_at_ns: cx.now(),
                rotated_at_ns: cx.now(),
                revoked: false,
                backend_kind,
            };
            (nonce, ciphertext, handle)
        };

        if let VaultUnlockState::Unlocked(state) = &mut self.state {
            state.entries.insert(
                secret_id.clone(),
                VaultEntry {
                    handle: handle.clone(),
                    nonce,
                    ciphertext,
                },
            );
        }
        if let Err(err) = self.persist_unlocked() {
            if let VaultUnlockState::Unlocked(state) = &mut self.state {
                let _ = state.entries.remove(secret_id);
            }
            return Err(err);
        }
        Ok(handle)
    }

    fn fetch(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<FetchedSecret, SecretError> {
        cx.authorize(SecretOperation::Read, Some(secret_id), None)?;
        let state = self.require_unlocked()?;
        let entry = state
            .entries
            .get(secret_id)
            .ok_or_else(|| SecretError::NotFound {
                secret_id: secret_id.as_str().to_string(),
            })?;
        cx.authorize(
            SecretOperation::Read,
            Some(secret_id),
            Some(&entry.handle.scope),
        )?;
        if entry.handle.revoked {
            return Err(SecretError::Revoked {
                secret_id: secret_id.as_str().to_string(),
                generation: entry.handle.generation,
            });
        }
        entry.handle.validate()?;
        let secret = open_secret_entry(
            &state.master_kek,
            &entry.handle.secret_id,
            entry.handle.generation,
            entry.handle.scope_digest,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        Ok(FetchedSecret::new(entry.handle.clone(), secret))
    }

    fn rotate(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        new_value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        cx.authorize(SecretOperation::Rotate, Some(secret_id), None)?;
        let (new_handle, new_nonce, new_ciphertext) = {
            let state = match &self.state {
                VaultUnlockState::Unlocked(s) => s,
                VaultUnlockState::Locked => return Err(SecretError::VaultLocked),
            };
            let existing = state
                .entries
                .get(secret_id)
                .ok_or_else(|| SecretError::NotFound {
                    secret_id: secret_id.as_str().to_string(),
                })?;
            cx.authorize(
                SecretOperation::Rotate,
                Some(secret_id),
                Some(&existing.handle.scope),
            )?;
            if existing.handle.revoked {
                return Err(SecretError::Revoked {
                    secret_id: secret_id.as_str().to_string(),
                    generation: existing.handle.generation,
                });
            }
            let next_generation = existing.handle.generation.checked_add(1).ok_or_else(|| {
                SecretError::InvalidInput {
                    detail: "secret generation overflow".to_string(),
                }
            })?;
            let (nonce, ciphertext) = seal_secret_entry(
                &state.master_kek,
                secret_id,
                next_generation,
                existing.handle.scope_digest,
                &new_value,
                &mut self.entropy,
            )?;
            let mut updated = existing.handle.clone();
            updated.generation = next_generation;
            updated.rotated_at_ns = cx.now();
            (updated, nonce, ciphertext)
        };

        let previous = if let VaultUnlockState::Unlocked(state) = &mut self.state {
            state.entries.insert(
                secret_id.clone(),
                VaultEntry {
                    handle: new_handle.clone(),
                    nonce: new_nonce,
                    ciphertext: new_ciphertext,
                },
            )
        } else {
            return Err(SecretError::VaultLocked);
        };
        if let Err(err) = self.persist_unlocked() {
            if let (VaultUnlockState::Unlocked(state), Some(prev)) = (&mut self.state, previous) {
                state.entries.insert(secret_id.clone(), prev);
            }
            return Err(err);
        }
        Ok(new_handle)
    }

    fn revoke(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<SecretHandle, SecretError> {
        cx.authorize(SecretOperation::Revoke, Some(secret_id), None)?;
        let updated_handle = {
            let state = self.require_unlocked()?;
            let existing = state
                .entries
                .get(secret_id)
                .ok_or_else(|| SecretError::NotFound {
                    secret_id: secret_id.as_str().to_string(),
                })?;
            cx.authorize(
                SecretOperation::Revoke,
                Some(secret_id),
                Some(&existing.handle.scope),
            )?;
            if existing.handle.revoked {
                return Err(SecretError::Revoked {
                    secret_id: secret_id.as_str().to_string(),
                    generation: existing.handle.generation,
                });
            }
            let mut updated = existing.handle.clone();
            updated.revoked = true;
            updated.rotated_at_ns = cx.now();
            updated
        };

        let previous = if let VaultUnlockState::Unlocked(state) = &mut self.state {
            state.entries.insert(
                secret_id.clone(),
                VaultEntry {
                    handle: updated_handle.clone(),
                    nonce: [0_u8; AEAD_NONCE_LEN],
                    ciphertext: Vec::new(),
                },
            )
        } else {
            return Err(SecretError::VaultLocked);
        };
        if let Err(err) = self.persist_unlocked() {
            if let (VaultUnlockState::Unlocked(state), Some(prev)) = (&mut self.state, previous) {
                state.entries.insert(secret_id.clone(), prev);
            }
            return Err(err);
        }
        Ok(updated_handle)
    }

    fn list_handles(&self, cx: &SecretAccessCx) -> Result<Vec<SecretHandle>, SecretError> {
        cx.authorize(SecretOperation::List, None, None)?;
        let state = self.require_unlocked()?;
        let scope = cx.scope();
        Ok(state
            .entries
            .values()
            .filter(|entry| &entry.handle.scope == scope)
            .map(|entry| entry.handle.clone())
            .collect())
    }
}

impl<E: EntropySource> fmt::Debug for LocalEncryptedVault<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count = match &self.state {
            VaultUnlockState::Unlocked(s) => Some(s.entries.len()),
            VaultUnlockState::Locked => None,
        };
        f.debug_struct("LocalEncryptedVault")
            .field("vault_path", &self.vault_path)
            .field("backend_kind", &self.backend_kind)
            .field("unlocked", &self.is_unlocked())
            .field("entry_count", &entry_count)
            .finish()
    }
}
