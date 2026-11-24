#![forbid(unsafe_code)]
//! Typed vault error identities and redaction-safe error variants.
//!
//! Every error carries a stable machine-readable identifier verified against
//! [`fss_core::validate_error_id`]. No variant ever stores or formats raw secret
//! bytes, passphrases, or key material.

use core::fmt;

use fss_core::{ContentDigest, ContractError, ErrorId, OperationError, RecoveryClass};

/// Cross-adapter, cross-sensor, or cross-endpoint secret scope mismatch.
pub const ERR_SECRET_SCOPE_MISMATCH_001: &str = "ERR-SECRET-SCOPE-MISMATCH-001";

/// Caller lacks the required `CAP-SECRET-*` capability grant.
pub const ERR_SECRET_UNAUTHORIZED_001: &str = "ERR-SECRET-UNAUTHORIZED-001";

/// Requested secret identifier does not exist in the vault.
pub const ERR_SECRET_NOT_FOUND_001: &str = "ERR-SECRET-NOT-FOUND-001";

/// Requested secret has been revoked and tombstoned.
pub const ERR_SECRET_REVOKED_001: &str = "ERR-SECRET-REVOKED-001";

/// Operation requires an unlocked vault session.
pub const ERR_SECRET_VAULT_LOCKED_001: &str = "ERR-SECRET-VAULT-LOCKED-001";

/// Operator passphrase or key-encryption key failed authentication.
pub const ERR_SECRET_AUTH_FAILED_001: &str = "ERR-SECRET-AUTH-FAILED-001";

/// Vault header, snapshot, or per-secret AEAD authentication failed.
pub const ERR_SECRET_TAMPERED_001: &str = "ERR-SECRET-TAMPERED-001";

/// Caller `Cx` context was cancelled or exceeded its deadline.
pub const ERR_SECRET_CANCELLED_001: &str = "ERR-SECRET-CANCELLED-001";

/// Configured OS keychain, keyring, or entropy backend is unavailable.
pub const ERR_SECRET_BACKEND_UNAVAILABLE_001: &str = "ERR-SECRET-BACKEND-UNAVAILABLE-001";

/// Secret identifier, scope, size bound, or KDF parameter was invalid.
pub const ERR_SECRET_INVALID_INPUT_001: &str = "ERR-SECRET-INVALID-INPUT-001";

/// Vault directory or file violated owner-only (`0700`/`0600`) or symlink policy.
pub const ERR_SECRET_PERMISSION_DENIED_001: &str = "ERR-SECRET-PERMISSION-DENIED-001";

/// Durable filesystem read, write, fsync, or rename operation failed.
pub const ERR_SECRET_STORAGE_IO_001: &str = "ERR-SECRET-STORAGE-IO-001";

/// Complete list of all stable error identifiers owned by `fss-vault`.
pub const ALL_VAULT_ERROR_IDS: &[&str] = &[
    ERR_SECRET_SCOPE_MISMATCH_001,
    ERR_SECRET_UNAUTHORIZED_001,
    ERR_SECRET_NOT_FOUND_001,
    ERR_SECRET_REVOKED_001,
    ERR_SECRET_VAULT_LOCKED_001,
    ERR_SECRET_AUTH_FAILED_001,
    ERR_SECRET_TAMPERED_001,
    ERR_SECRET_CANCELLED_001,
    ERR_SECRET_BACKEND_UNAVAILABLE_001,
    ERR_SECRET_INVALID_INPUT_001,
    ERR_SECRET_PERMISSION_DENIED_001,
    ERR_SECRET_STORAGE_IO_001,
];

/// Typed, redaction-safe error returned by all `fss-vault` operations.
///
/// No variant carries secret values, passphrases, or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretError {
    /// Caller's `SecretScope` did not match the stored secret's bound scope.
    ScopeMismatch {
        /// Identifier of the secret whose scope did not match.
        secret_id: String,
        /// Digest of the scope bound to the stored secret.
        expected_scope_digest: ContentDigest,
        /// Digest of the scope presented by the caller `Cx`.
        requested_scope_digest: ContentDigest,
    },
    /// Caller `Cx` did not hold the required `CAP-SECRET-*` capability.
    Unauthorized {
        /// Required stable capability string.
        required_capability: &'static str,
        /// Non-secret explanation of the authorization failure.
        detail: String,
    },
    /// No secret exists under the requested identifier.
    NotFound {
        /// Missing secret identifier.
        secret_id: String,
    },
    /// Secret was revoked and permanently tombstoned.
    Revoked {
        /// Revoked secret identifier.
        secret_id: String,
        /// Last active generation prior to or at revocation.
        generation: u64,
    },
    /// Vault must be unlocked before accessing or mutating secrets.
    VaultLocked,
    /// Passphrase or KEK did not match the vault verifier tag.
    AuthFailed,
    /// Cryptographic authentication or format integrity verification failed.
    Tampered {
        /// Non-secret diagnostic identifying the failed verification stage.
        detail: &'static str,
    },
    /// Caller `Cx` was cancelled or past its deadline before completion.
    Cancelled {
        /// Non-secret cancellation reason.
        reason: String,
    },
    /// Underlying OS keychain, keyring, or entropy source is unavailable.
    BackendUnavailable {
        /// Backend name.
        backend: &'static str,
        /// Non-secret diagnostic explanation.
        detail: String,
    },
    /// Caller supplied malformed identifier, scope, bounds, or parameters.
    InvalidInput {
        /// Non-secret validation explanation.
        detail: String,
    },
    /// Vault directory or file failed symlink, link-count, or POSIX mode checks.
    InsecurePermissions {
        /// Non-secret permission policy diagnostic.
        detail: String,
    },
    /// Filesystem read, write, sync, or atomic rename failed.
    StorageIo {
        /// Failed storage operation name.
        operation: &'static str,
        /// `std::io::ErrorKind` diagnostic name.
        kind: String,
    },
}

impl SecretError {
    /// Returns the stable machine-readable error identifier (`ERR-SECRET-*`).
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::ScopeMismatch { .. } => ERR_SECRET_SCOPE_MISMATCH_001,
            Self::Unauthorized { .. } => ERR_SECRET_UNAUTHORIZED_001,
            Self::NotFound { .. } => ERR_SECRET_NOT_FOUND_001,
            Self::Revoked { .. } => ERR_SECRET_REVOKED_001,
            Self::VaultLocked => ERR_SECRET_VAULT_LOCKED_001,
            Self::AuthFailed => ERR_SECRET_AUTH_FAILED_001,
            Self::Tampered { .. } => ERR_SECRET_TAMPERED_001,
            Self::Cancelled { .. } => ERR_SECRET_CANCELLED_001,
            Self::BackendUnavailable { .. } => ERR_SECRET_BACKEND_UNAVAILABLE_001,
            Self::InvalidInput { .. } => ERR_SECRET_INVALID_INPUT_001,
            Self::InsecurePermissions { .. } => ERR_SECRET_PERMISSION_DENIED_001,
            Self::StorageIo { .. } => ERR_SECRET_STORAGE_IO_001,
        }
    }

    /// Maps this error to a canonical FSS [`RecoveryClass`].
    #[must_use]
    pub const fn recovery_class(&self) -> RecoveryClass {
        match self {
            Self::ScopeMismatch { .. }
            | Self::Unauthorized { .. }
            | Self::NotFound { .. }
            | Self::Revoked { .. }
            | Self::InvalidInput { .. }
            | Self::Cancelled { .. } => RecoveryClass::NeverUnchanged,
            Self::VaultLocked
            | Self::AuthFailed
            | Self::Tampered { .. }
            | Self::InsecurePermissions { .. } => RecoveryClass::OperatorActionRequired,
            Self::BackendUnavailable { .. } | Self::StorageIo { .. } => RecoveryClass::Backoff,
        }
    }

    /// Converts this vault error into a canonical [`fss_core::OperationError`].
    pub fn to_operation_error(&self) -> Result<OperationError, ContractError> {
        let error_id = ErrorId::parse(self.error_id())?;
        OperationError::new(error_id, self.to_string(), self.recovery_class())
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopeMismatch {
                secret_id,
                expected_scope_digest,
                requested_scope_digest,
            } => write!(
                f,
                "[{}] scope mismatch for '{}': expected {}, requested {}",
                self.error_id(),
                secret_id,
                expected_scope_digest,
                requested_scope_digest
            ),
            Self::Unauthorized {
                required_capability,
                detail,
            } => write!(
                f,
                "[{}] unauthorized (requires {}): {}",
                self.error_id(),
                required_capability,
                detail
            ),
            Self::NotFound { secret_id } => {
                write!(f, "[{}] secret '{}' not found", self.error_id(), secret_id)
            }
            Self::Revoked {
                secret_id,
                generation,
            } => write!(
                f,
                "[{}] secret '{}' generation {} is revoked",
                self.error_id(),
                secret_id,
                generation
            ),
            Self::VaultLocked => write!(f, "[{}] vault is locked", self.error_id()),
            Self::AuthFailed => write!(f, "[{}] vault authentication failed", self.error_id()),
            Self::Tampered { detail } => {
                write!(
                    f,
                    "[{}] vault integrity failure: {}",
                    self.error_id(),
                    detail
                )
            }
            Self::Cancelled { reason } => {
                write!(f, "[{}] operation cancelled: {}", self.error_id(), reason)
            }
            Self::BackendUnavailable { backend, detail } => write!(
                f,
                "[{}] secret backend '{}' unavailable: {}",
                self.error_id(),
                backend,
                detail
            ),
            Self::InvalidInput { detail } => {
                write!(f, "[{}] invalid input: {}", self.error_id(), detail)
            }
            Self::InsecurePermissions { detail } => {
                write!(f, "[{}] insecure permissions: {}", self.error_id(), detail)
            }
            Self::StorageIo { operation, kind } => write!(
                f,
                "[{}] storage I/O failed during {}: {}",
                self.error_id(),
                operation,
                kind
            ),
        }
    }
}

impl std::error::Error for SecretError {}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::validate_error_id;

    #[test]
    fn all_error_ids_satisfy_core_registry_format() -> Result<(), ContractError> {
        for &id in ALL_VAULT_ERROR_IDS {
            validate_error_id(id)?;
        }
        Ok(())
    }
}
