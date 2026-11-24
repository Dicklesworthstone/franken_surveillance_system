#![forbid(unsafe_code)]
//! [`VaultManager`] composing OS Keychain/Keyring KEK custody with [`LocalEncryptedVault`].

use core::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::crypto::{AEAD_KEY_LEN, EntropySource, KdfParams, OsEntropy};
use crate::error::SecretError;
use crate::local_vault::LocalEncryptedVault;
use crate::os_transport::{OsKekCustodian, validate_os_label};
use crate::scope::{SecretAccessCx, SecretBackendKind, SecretHandle};
use crate::secret::{SecretBytes, SecretId};
use crate::store::{FetchedSecret, SecretStore};

/// Composes an OS Keychain / Secret-Service KEK custodian with [`LocalEncryptedVault`],
/// falling back cleanly to passphrase-backed local encryption when the OS backend is unavailable.
pub struct VaultManager<E: EntropySource = OsEntropy> {
    vault: LocalEncryptedVault<E>,
    used_os_kek: bool,
}

impl<E: EntropySource> VaultManager<E> {
    /// Opens or initializes a managed vault: prefers OS-wrapped KEK via `os_custodian`,
    /// falling back to `fallback_passphrase` ONLY on [`SecretError::BackendUnavailable`].
    pub fn open_with_os_kek_or_fallback(
        vault_dir: impl Into<PathBuf>,
        vault_id: &str,
        os_custodian: &dyn OsKekCustodian,
        fallback_passphrase: Option<&SecretBytes>,
        kdf_params: KdfParams,
        mut entropy: E,
    ) -> Result<Self, SecretError> {
        validate_os_label("vault_id", vault_id)?;
        let vault_dir = vault_dir.into();

        match os_custodian.load_kek(vault_id) {
            Ok(Some(kek)) => {
                let mut vault =
                    LocalEncryptedVault::open_with_entropy(vault_dir, kdf_params, entropy);
                vault.set_backend_kind(SecretBackendKind::ComposedOsKekLocalVault);
                if vault.exists() {
                    vault.unlock_with_kek(kek)?;
                } else {
                    vault.initialize_with_kek(kek)?;
                }
                Ok(Self {
                    vault,
                    used_os_kek: true,
                })
            }
            Ok(None) => {
                let mut raw_kek = Zeroizing::new([0_u8; AEAD_KEY_LEN]);
                entropy.fill_bytes(&mut *raw_kek)?;
                match os_custodian.store_kek(vault_id, &raw_kek) {
                    Ok(()) => {
                        let mut vault =
                            LocalEncryptedVault::open_with_entropy(vault_dir, kdf_params, entropy);
                        vault.set_backend_kind(SecretBackendKind::ComposedOsKekLocalVault);
                        vault.initialize_with_kek(raw_kek)?;
                        Ok(Self {
                            vault,
                            used_os_kek: true,
                        })
                    }
                    Err(SecretError::BackendUnavailable { .. }) => {
                        Self::open_fallback(vault_dir, fallback_passphrase, kdf_params, entropy)
                    }
                    Err(err) => Err(err),
                }
            }
            Err(SecretError::BackendUnavailable { .. }) => {
                Self::open_fallback(vault_dir, fallback_passphrase, kdf_params, entropy)
            }
            Err(err) => Err(err),
        }
    }

    fn open_fallback(
        vault_dir: PathBuf,
        fallback_passphrase: Option<&SecretBytes>,
        kdf_params: KdfParams,
        entropy: E,
    ) -> Result<Self, SecretError> {
        let passphrase = fallback_passphrase.ok_or_else(|| SecretError::BackendUnavailable {
            backend: "os_kek_custodian",
            detail: "OS backend unavailable and no fallback passphrase supplied".to_string(),
        })?;
        let mut vault = LocalEncryptedVault::open_with_entropy(vault_dir, kdf_params, entropy);
        if vault.exists() {
            vault.unlock(passphrase)?;
        } else {
            vault.initialize(passphrase)?;
        }
        Ok(Self {
            vault,
            used_os_kek: false,
        })
    }

    /// Returns `true` if the OS keychain/keyring supplied the local vault KEK.
    #[must_use]
    pub const fn used_os_kek(&self) -> bool {
        self.used_os_kek
    }

    /// Locks the underlying local vault, zeroizing in-memory key material.
    pub fn lock(&mut self) {
        self.vault.lock();
    }

    /// Returns `true` if the underlying vault is currently unlocked.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.vault.is_unlocked()
    }
}

impl<E: EntropySource> fmt::Debug for VaultManager<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultManager")
            .field("used_os_kek", &self.used_os_kek)
            .field("vault", &self.vault)
            .finish()
    }
}

impl<E: EntropySource> SecretStore for VaultManager<E> {
    fn backend_kind(&self) -> SecretBackendKind {
        self.vault.backend_kind()
    }

    fn store(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        self.vault.store(cx, secret_id, value)
    }

    fn fetch(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<FetchedSecret, SecretError> {
        self.vault.fetch(cx, secret_id)
    }

    fn rotate(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        new_value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        self.vault.rotate(cx, secret_id, new_value)
    }

    fn revoke(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<SecretHandle, SecretError> {
        self.vault.revoke(cx, secret_id)
    }

    fn list_handles(&self, cx: &SecretAccessCx) -> Result<Vec<SecretHandle>, SecretError> {
        self.vault.list_handles(cx)
    }
}
