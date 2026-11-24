#![forbid(unsafe_code)]
//! Unified `Cx`-scoped [`SecretStore`] trait and redacted fetch result types.

use core::fmt;

use crate::error::SecretError;
use crate::scope::{SecretAccessCx, SecretBackendKind, SecretHandle};
use crate::secret::{REDACTED_SECRET_DISPLAY, SecretBytes, SecretId};

/// Result of a scope-verified secret fetch pairing non-secret metadata with zeroizing bytes.
///
/// [`fmt::Debug`] and [`fmt::Display`] display only the non-secret [`SecretHandle`]
/// and `"[REDACTED]"` for the secret payload.
#[derive(Clone, Eq, PartialEq)]
pub struct FetchedSecret {
    handle: SecretHandle,
    secret: SecretBytes,
}

impl FetchedSecret {
    /// Constructs a fetched secret bundle.
    #[must_use]
    pub const fn new(handle: SecretHandle, secret: SecretBytes) -> Self {
        Self { handle, secret }
    }

    /// Returns the non-secret handle metadata for this secret.
    #[must_use]
    pub const fn handle(&self) -> &SecretHandle {
        &self.handle
    }

    /// Borrows the zeroizing secret payload.
    #[must_use]
    pub const fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// Consumes this bundle into its `(SecretHandle, SecretBytes)` parts.
    #[must_use]
    pub fn into_parts(self) -> (SecretHandle, SecretBytes) {
        (self.handle, self.secret)
    }
}

impl fmt::Debug for FetchedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchedSecret")
            .field("handle", &self.handle)
            .field("secret", &REDACTED_SECRET_DISPLAY)
            .finish()
    }
}

impl fmt::Display for FetchedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.handle, REDACTED_SECRET_DISPLAY)
    }
}

/// Unified `Cx`-authorized secret store contract implemented by all vault backends.
///
/// Every method requires an explicit [`SecretAccessCx`] carrying capability grants,
/// cancellation state, explicit timestamp, and exact [`crate::SecretScope`].
pub trait SecretStore {
    /// Reports the concrete storage backend kind backing this store.
    fn backend_kind(&self) -> SecretBackendKind;

    /// Stores a new secret at generation `1`, strictly bound to `cx.scope()`.
    ///
    /// Fails closed if `cx` is cancelled or lacks `CAP-SECRET-WRITE-001`, if the
    /// store is locked, or if `secret_id` already exists (active or revoked).
    fn store(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        value: SecretBytes,
    ) -> Result<SecretHandle, SecretError>;

    /// Fetches and decrypts a secret strictly within `cx.scope()`.
    ///
    /// Fails closed on cancelled `cx`, missing `CAP-SECRET-READ-001`, locked vault,
    /// missing or revoked secret, scope mismatch (`ERR-SECRET-SCOPE-MISMATCH-001`),
    /// or AEAD authentication failure (`ERR-SECRET-TAMPERED-001`).
    fn fetch(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<FetchedSecret, SecretError>;

    /// Fetches a secret only if its current active generation equals `expected_generation`.
    ///
    /// Old or superseded generations fail closed with [`SecretError::InvalidInput`].
    fn fetch_generation(
        &self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        expected_generation: u64,
    ) -> Result<FetchedSecret, SecretError> {
        let fetched = self.fetch(cx, secret_id)?;
        if fetched.handle().generation != expected_generation {
            return Err(SecretError::InvalidInput {
                detail: format!(
                    "secret '{}' generation {} superseded by generation {}",
                    secret_id,
                    expected_generation,
                    fetched.handle().generation
                ),
            });
        }
        Ok(fetched)
    }

    /// Rotates an active secret to `generation + 1`, invalidating the previous generation.
    ///
    /// Requires `CAP-SECRET-ROTATE-001` and an exact scope match.
    fn rotate(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        new_value: SecretBytes,
    ) -> Result<SecretHandle, SecretError>;

    /// Permanently revokes and tombstones a secret, scrubbing its ciphertext.
    ///
    /// Requires `CAP-SECRET-ROTATE-001` (or `CAP-SECRET-WRITE-001`) and an exact scope match.
    fn revoke(
        &mut self,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
    ) -> Result<SecretHandle, SecretError>;

    /// Lists non-secret [`SecretHandle`] metadata matching `cx.scope()`, in canonical order.
    ///
    /// Never returns secret bytes and never exposes handles belonging to other scopes.
    fn list_handles(&self, cx: &SecretAccessCx) -> Result<Vec<SecretHandle>, SecretError>;
}
