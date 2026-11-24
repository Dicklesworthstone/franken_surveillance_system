#![forbid(unsafe_code)]
//! Native macOS Keychain and Linux Secret-Service / Keyring [`SecretStore`] backends.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::crypto::{AEAD_KEY_LEN, EntropySource, OsEntropy};
use crate::error::SecretError;
pub use crate::manager::VaultManager;
pub use crate::os_transport::{
    CommandInvocation, CommandOutput, KeychainTransport, KeyringTransport, OS_ENVELOPE_MAGIC,
    OS_ENVELOPE_VERSION, OsKekCustodian, SecretToolKeyringTransport, SecurityCliKeychainTransport,
};
use crate::os_transport::{
    bytes_to_kek, decode_hex_zeroizing, encode_hex_zeroizing, open_os_envelope, seal_os_envelope,
    trim_ascii_whitespace, validate_os_label,
};
use crate::scope::{SecretAccessCx, SecretBackendKind, SecretHandle, SecretOperation};
use crate::secret::{SecretBytes, SecretId};
use crate::store::{FetchedSecret, SecretStore};

/// Native macOS Keychain backend storing AEAD-wrapped, scope-bound secrets via stdin-only IPC.
pub struct MacOsKeychainBackend<
    T: KeychainTransport = SecurityCliKeychainTransport,
    E: EntropySource = OsEntropy,
> {
    service_name: String,
    wrapping_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    transport: T,
    entropy: E,
    handles: BTreeMap<SecretId, SecretHandle>,
}

impl<T: KeychainTransport, E: EntropySource> MacOsKeychainBackend<T, E> {
    /// Creates a macOS Keychain backend bound to an explicit service namespace and wrapping key.
    pub fn new(
        service_name: impl Into<String>,
        wrapping_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
        transport: T,
        entropy: E,
    ) -> Result<Self, SecretError> {
        let service_name = service_name.into();
        validate_os_label("service_name", &service_name)?;
        Ok(Self {
            service_name,
            wrapping_key,
            transport,
            entropy,
            handles: BTreeMap::new(),
        })
    }

    /// Borrows the underlying transport for diagnostics or mock inspection.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    fn write_hex_item(&self, account: &str, hex_payload: &str) -> Result<(), SecretError> {
        validate_os_label("account", account)?;
        let script = format!(
            "add-generic-password -U -a {account} -s {} -X {hex_payload}\n",
            self.service_name
        );
        let stdin = SecretBytes::new(script.into_bytes())?;
        let output = self.transport.execute(CommandInvocation {
            program: "/usr/bin/security",
            args: vec!["-i".to_string()],
            stdin: Some(stdin),
        })?;
        if !output.success {
            return Err(SecretError::BackendUnavailable {
                backend: "macos_keychain",
                detail: format!(
                    "security add-generic-password failed: {:?}",
                    output.exit_code
                ),
            });
        }
        Ok(())
    }

    fn read_hex_item(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        validate_os_label("account", account)?;
        let script = format!(
            "find-generic-password -w -a {account} -s {}\n",
            self.service_name
        );
        let stdin = SecretBytes::new(script.into_bytes())?;
        let output = self.transport.execute(CommandInvocation {
            program: "/usr/bin/security",
            args: vec!["-i".to_string()],
            stdin: Some(stdin),
        })?;
        if !output.success {
            if output.exit_code == Some(44) {
                return Ok(None);
            }
            return Err(SecretError::BackendUnavailable {
                backend: "macos_keychain",
                detail: format!(
                    "security find-generic-password failed: {:?}",
                    output.exit_code
                ),
            });
        }
        let text = trim_ascii_whitespace(&output.stdout);
        if text.is_empty() {
            return Ok(None);
        }
        decode_hex_zeroizing(text).map(Some)
    }

    fn delete_item(&self, account: &str) -> Result<(), SecretError> {
        validate_os_label("account", account)?;
        let script = format!(
            "delete-generic-password -a {account} -s {}\n",
            self.service_name
        );
        let stdin = SecretBytes::new(script.into_bytes())?;
        let output = self.transport.execute(CommandInvocation {
            program: "/usr/bin/security",
            args: vec!["-i".to_string()],
            stdin: Some(stdin),
        })?;
        if !output.success && output.exit_code != Some(44) {
            return Err(SecretError::BackendUnavailable {
                backend: "macos_keychain",
                detail: format!(
                    "security delete-generic-password failed: {:?}",
                    output.exit_code
                ),
            });
        }
        Ok(())
    }
}

impl<T: KeychainTransport, E: EntropySource> fmt::Debug for MacOsKeychainBackend<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacOsKeychainBackend")
            .field("service_name", &self.service_name)
            .field("handle_count", &self.handles.len())
            .finish()
    }
}

impl<T: KeychainTransport, E: EntropySource> SecretStore for MacOsKeychainBackend<T, E> {
    fn backend_kind(&self) -> SecretBackendKind {
        SecretBackendKind::MacOsKeychain
    }

    fn store(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        let handle = prepare_store_handle(
            cx,
            secret_id,
            &self.handles,
            SecretBackendKind::MacOsKeychain,
        )?;
        let sealed = seal_os_envelope(&self.wrapping_key, &handle, &value, &mut self.entropy)?;
        let hex = encode_hex_zeroizing(&sealed);
        self.write_hex_item(secret_id.as_str(), &hex)?;
        self.handles.insert(secret_id.clone(), handle.clone());
        Ok(handle)
    }

    fn fetch(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<FetchedSecret, SecretError> {
        let handle = authorize_existing(cx, secret_id, &self.handles, SecretOperation::Read)?;
        let raw = self
            .read_hex_item(secret_id.as_str())?
            .ok_or_else(|| SecretError::NotFound {
                secret_id: secret_id.as_str().to_string(),
            })?;
        let secret = open_os_envelope(&self.wrapping_key, handle, &raw)?;
        Ok(FetchedSecret::new(handle.clone(), secret))
    }

    fn rotate(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        new_value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        let updated = prepare_rotate_handle(cx, secret_id, &self.handles)?;
        let sealed = seal_os_envelope(&self.wrapping_key, &updated, &new_value, &mut self.entropy)?;
        let hex = encode_hex_zeroizing(&sealed);
        self.write_hex_item(secret_id.as_str(), &hex)?;
        self.handles.insert(secret_id.clone(), updated.clone());
        Ok(updated)
    }

    fn revoke(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<SecretHandle, SecretError> {
        let updated = prepare_revoke_handle(cx, secret_id, &self.handles)?;
        self.delete_item(secret_id.as_str())?;
        self.handles.insert(secret_id.clone(), updated.clone());
        Ok(updated)
    }

    fn list_handles(&self, cx: &SecretAccessCx) -> Result<Vec<SecretHandle>, SecretError> {
        list_scoped_handles(cx, &self.handles)
    }
}

impl<T: KeychainTransport, E: EntropySource> OsKekCustodian for MacOsKeychainBackend<T, E> {
    fn os_backend_kind(&self) -> SecretBackendKind {
        SecretBackendKind::MacOsKeychain
    }

    fn store_kek(&self, vault_id: &str, kek: &[u8; AEAD_KEY_LEN]) -> Result<(), SecretError> {
        let hex = encode_hex_zeroizing(kek);
        self.write_hex_item(&format!("kek:{vault_id}"), &hex)
    }

    fn load_kek(
        &self,
        vault_id: &str,
    ) -> Result<Option<Zeroizing<[u8; AEAD_KEY_LEN]>>, SecretError> {
        match self.read_hex_item(&format!("kek:{vault_id}"))? {
            None => Ok(None),
            Some(bytes) => bytes_to_kek(&bytes).map(Some),
        }
    }

    fn delete_kek(&self, vault_id: &str) -> Result<(), SecretError> {
        self.delete_item(&format!("kek:{vault_id}"))
    }
}

/// Native Linux Secret-Service / Keyring backend storing AEAD-wrapped secrets via stdin-only `secret-tool`.
pub struct LinuxKeyringBackend<
    T: KeyringTransport = SecretToolKeyringTransport,
    E: EntropySource = OsEntropy,
> {
    service_name: String,
    wrapping_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    transport: T,
    entropy: E,
    handles: BTreeMap<SecretId, SecretHandle>,
}

impl<T: KeyringTransport, E: EntropySource> LinuxKeyringBackend<T, E> {
    /// Creates a Linux Secret-Service backend bound to an explicit service namespace and wrapping key.
    pub fn new(
        service_name: impl Into<String>,
        wrapping_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
        transport: T,
        entropy: E,
    ) -> Result<Self, SecretError> {
        let service_name = service_name.into();
        validate_os_label("service_name", &service_name)?;
        Ok(Self {
            service_name,
            wrapping_key,
            transport,
            entropy,
            handles: BTreeMap::new(),
        })
    }

    /// Borrows the underlying transport for diagnostics or mock inspection.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    fn write_hex_item(&self, account: &str, hex_payload: &str) -> Result<(), SecretError> {
        validate_os_label("account", account)?;
        let stdin = SecretBytes::from_slice(hex_payload.as_bytes())?;
        let output = self.transport.execute(CommandInvocation {
            program: "secret-tool",
            args: vec![
                "store".to_string(),
                format!("--label=fss-vault:{account}"),
                "service".to_string(),
                self.service_name.clone(),
                "account".to_string(),
                account.to_string(),
            ],
            stdin: Some(stdin),
        })?;
        if !output.success {
            return Err(SecretError::BackendUnavailable {
                backend: "linux_secret_service",
                detail: format!("secret-tool store failed: {:?}", output.exit_code),
            });
        }
        Ok(())
    }

    fn read_hex_item(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        validate_os_label("account", account)?;
        let output = self.transport.execute(CommandInvocation {
            program: "secret-tool",
            args: vec![
                "lookup".to_string(),
                "service".to_string(),
                self.service_name.clone(),
                "account".to_string(),
                account.to_string(),
            ],
            stdin: None,
        })?;
        if !output.success {
            if output.exit_code == Some(1) {
                return Ok(None);
            }
            return Err(SecretError::BackendUnavailable {
                backend: "linux_secret_service",
                detail: format!("secret-tool lookup failed: {:?}", output.exit_code),
            });
        }
        let text = trim_ascii_whitespace(&output.stdout);
        if text.is_empty() {
            return Ok(None);
        }
        decode_hex_zeroizing(text).map(Some)
    }

    fn delete_item(&self, account: &str) -> Result<(), SecretError> {
        validate_os_label("account", account)?;
        let output = self.transport.execute(CommandInvocation {
            program: "secret-tool",
            args: vec![
                "clear".to_string(),
                "service".to_string(),
                self.service_name.clone(),
                "account".to_string(),
                account.to_string(),
            ],
            stdin: None,
        })?;
        if !output.success && output.exit_code != Some(1) {
            return Err(SecretError::BackendUnavailable {
                backend: "linux_secret_service",
                detail: format!("secret-tool clear failed: {:?}", output.exit_code),
            });
        }
        Ok(())
    }
}

impl<T: KeyringTransport, E: EntropySource> fmt::Debug for LinuxKeyringBackend<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxKeyringBackend")
            .field("service_name", &self.service_name)
            .field("handle_count", &self.handles.len())
            .finish()
    }
}

impl<T: KeyringTransport, E: EntropySource> SecretStore for LinuxKeyringBackend<T, E> {
    fn backend_kind(&self) -> SecretBackendKind {
        SecretBackendKind::LinuxSecretService
    }

    fn store(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        let handle = prepare_store_handle(
            cx,
            secret_id,
            &self.handles,
            SecretBackendKind::LinuxSecretService,
        )?;
        let sealed = seal_os_envelope(&self.wrapping_key, &handle, &value, &mut self.entropy)?;
        let hex = encode_hex_zeroizing(&sealed);
        self.write_hex_item(secret_id.as_str(), &hex)?;
        self.handles.insert(secret_id.clone(), handle.clone());
        Ok(handle)
    }

    fn fetch(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<FetchedSecret, SecretError> {
        let handle = authorize_existing(cx, secret_id, &self.handles, SecretOperation::Read)?;
        let raw = self
            .read_hex_item(secret_id.as_str())?
            .ok_or_else(|| SecretError::NotFound {
                secret_id: secret_id.as_str().to_string(),
            })?;
        let secret = open_os_envelope(&self.wrapping_key, handle, &raw)?;
        Ok(FetchedSecret::new(handle.clone(), secret))
    }

    fn rotate(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        new_value: SecretBytes,
    ) -> Result<SecretHandle, SecretError> {
        let updated = prepare_rotate_handle(cx, secret_id, &self.handles)?;
        let sealed = seal_os_envelope(&self.wrapping_key, &updated, &new_value, &mut self.entropy)?;
        let hex = encode_hex_zeroizing(&sealed);
        self.write_hex_item(secret_id.as_str(), &hex)?;
        self.handles.insert(secret_id.clone(), updated.clone());
        Ok(updated)
    }

    fn revoke(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<SecretHandle, SecretError> {
        let updated = prepare_revoke_handle(cx, secret_id, &self.handles)?;
        self.delete_item(secret_id.as_str())?;
        self.handles.insert(secret_id.clone(), updated.clone());
        Ok(updated)
    }

    fn list_handles(&self, cx: &SecretAccessCx) -> Result<Vec<SecretHandle>, SecretError> {
        list_scoped_handles(cx, &self.handles)
    }
}

impl<T: KeyringTransport, E: EntropySource> OsKekCustodian for LinuxKeyringBackend<T, E> {
    fn os_backend_kind(&self) -> SecretBackendKind {
        SecretBackendKind::LinuxSecretService
    }

    fn store_kek(&self, vault_id: &str, kek: &[u8; AEAD_KEY_LEN]) -> Result<(), SecretError> {
        let hex = encode_hex_zeroizing(kek);
        self.write_hex_item(&format!("kek:{vault_id}"), &hex)
    }

    fn load_kek(
        &self,
        vault_id: &str,
    ) -> Result<Option<Zeroizing<[u8; AEAD_KEY_LEN]>>, SecretError> {
        match self.read_hex_item(&format!("kek:{vault_id}"))? {
            None => Ok(None),
            Some(bytes) => bytes_to_kek(&bytes).map(Some),
        }
    }

    fn delete_kek(&self, vault_id: &str) -> Result<(), SecretError> {
        self.delete_item(&format!("kek:{vault_id}"))
    }
}

fn prepare_store_handle(
    cx: &SecretAccessCx,
    secret_id: &SecretId,
    handles: &BTreeMap<SecretId, SecretHandle>,
    backend_kind: SecretBackendKind,
) -> Result<SecretHandle, SecretError> {
    cx.authorize(SecretOperation::Write, Some(secret_id), None)?;
    if let Some(existing) = handles.get(secret_id) {
        if existing.revoked {
            return Err(SecretError::Revoked {
                secret_id: secret_id.as_str().to_string(),
                generation: existing.generation,
            });
        }
        return Err(SecretError::InvalidInput {
            detail: format!("secret '{secret_id}' already exists; use rotate"),
        });
    }
    let scope = cx.scope().clone();
    Ok(SecretHandle {
        secret_id: secret_id.clone(),
        scope_digest: scope.scope_digest(),
        scope,
        generation: 1,
        created_at_ns: cx.now(),
        rotated_at_ns: cx.now(),
        revoked: false,
        backend_kind,
    })
}

fn authorize_existing<'a>(
    cx: &SecretAccessCx,
    secret_id: &SecretId,
    handles: &'a BTreeMap<SecretId, SecretHandle>,
    operation: SecretOperation,
) -> Result<&'a SecretHandle, SecretError> {
    cx.authorize(operation, Some(secret_id), None)?;
    let handle = handles
        .get(secret_id)
        .ok_or_else(|| SecretError::NotFound {
            secret_id: secret_id.as_str().to_string(),
        })?;
    cx.authorize(operation, Some(secret_id), Some(&handle.scope))?;
    if handle.revoked {
        return Err(SecretError::Revoked {
            secret_id: secret_id.as_str().to_string(),
            generation: handle.generation,
        });
    }
    Ok(handle)
}

fn prepare_rotate_handle(
    cx: &SecretAccessCx,
    secret_id: &SecretId,
    handles: &BTreeMap<SecretId, SecretHandle>,
) -> Result<SecretHandle, SecretError> {
    let existing = authorize_existing(cx, secret_id, handles, SecretOperation::Rotate)?;
    let mut updated = existing.clone();
    updated.generation =
        updated
            .generation
            .checked_add(1)
            .ok_or_else(|| SecretError::InvalidInput {
                detail: "secret generation overflow".to_string(),
            })?;
    updated.rotated_at_ns = cx.now();
    Ok(updated)
}

fn prepare_revoke_handle(
    cx: &SecretAccessCx,
    secret_id: &SecretId,
    handles: &BTreeMap<SecretId, SecretHandle>,
) -> Result<SecretHandle, SecretError> {
    let existing = authorize_existing(cx, secret_id, handles, SecretOperation::Revoke)?;
    let mut updated = existing.clone();
    updated.revoked = true;
    updated.rotated_at_ns = cx.now();
    Ok(updated)
}

fn list_scoped_handles(
    cx: &SecretAccessCx,
    handles: &BTreeMap<SecretId, SecretHandle>,
) -> Result<Vec<SecretHandle>, SecretError> {
    cx.authorize(SecretOperation::List, None, None)?;
    Ok(handles
        .values()
        .filter(|handle| &handle.scope == cx.scope())
        .cloned()
        .collect())
}
