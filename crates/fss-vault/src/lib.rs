#![forbid(unsafe_code)]
//! `Cx`-scoped secret storage, scope-bound credential isolation, native macOS Keychain &
//! Linux Secret-Service adapters, and ChaCha20-Poly1305 encrypted local operator vault
//! for Franken Surveillance System.
//!
//! # Security Guarantees
//! - Every secret payload is held in [`SecretBytes`] (`Zeroizing<Vec<u8>>`) whose `Debug`
//!   and `Display` implementations unconditionally emit `"[REDACTED]"`.
//! - Every secret is strictly bound to an immutable [`SecretScope`] (`AdapterFamily`,
//!   `sensor_or_target_id`, `endpoint_scope`), enforced both by [`SecretAccessCx`] and by
//!   per-record ChaCha20-Poly1305 AEAD associated data (`fss.vault.entry_aad.v1`).
//! - Zero plaintext credentials or handles touch disk: [`LocalEncryptedVault`] enforces
//!   `0700` directory and `0600` regular-file permissions, symlink/hardlink refusal, and
//!   atomic temp -> fsync -> rename -> dirsync writes.
//! - OS keychain/keyring adapters never pass raw secret bytes or sealed envelopes in
//!   subprocess `argv` or environment variables; all sensitive data moves over piped `stdin`.

pub mod access_cx;
pub mod crypto;
pub mod error;
pub mod fs_guard;
pub mod local_vault;
pub mod manager;
pub mod os_backend;
pub mod os_transport;
pub mod scope;
pub mod secret;
pub mod store;
pub mod taint;
pub mod vault_format;

pub use access_cx::{
    CAP_SECRET_READ_001, CAP_SECRET_ROTATE_001, CAP_SECRET_WRITE_001, SecretAccessCx,
    SecretOperation,
};
pub use crypto::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, DEFAULT_PBKDF2_ITERATIONS, EntropySource,
    KdfParams, LabEntropy, MAX_HKDF_OUTPUT_LEN, MAX_PBKDF2_ITERATIONS,
    MIN_PRODUCTION_PBKDF2_ITERATIONS, MIN_TEST_PBKDF2_ITERATIONS, OsEntropy,
    VAULT_ENTRY_AAD_DOMAIN, VAULT_LAB_ENTROPY_DOMAIN, VAULT_OS_ENVELOPE_AAD_DOMAIN,
    VAULT_RECORD_KEY_DOMAIN, VAULT_SNAPSHOT_AAD_DOMAIN, VAULT_SNAPSHOT_KEY_DOMAIN,
    VAULT_VERIFIER_DOMAIN, aead_decrypt_zeroizing, aead_encrypt, build_entry_aad,
    compute_master_verifier, derive_record_key, derive_snapshot_key, hkdf_sha256_expand,
    hkdf_sha256_expand_32, hkdf_sha256_extract, hmac_sha256, open_secret_entry, pbkdf2_hmac_sha256,
    seal_secret_entry,
};
pub use error::{
    ALL_VAULT_ERROR_IDS, ERR_SECRET_AUTH_FAILED_001, ERR_SECRET_BACKEND_UNAVAILABLE_001,
    ERR_SECRET_CANCELLED_001, ERR_SECRET_INVALID_INPUT_001, ERR_SECRET_NOT_FOUND_001,
    ERR_SECRET_PERMISSION_DENIED_001, ERR_SECRET_REVOKED_001, ERR_SECRET_SCOPE_MISMATCH_001,
    ERR_SECRET_STORAGE_IO_001, ERR_SECRET_TAMPERED_001, ERR_SECRET_UNAUTHORIZED_001,
    ERR_SECRET_VAULT_LOCKED_001, SecretError,
};
pub use fs_guard::{VAULT_DIR_MODE, VAULT_FILE_MODE};
pub use local_vault::{LocalEncryptedVault, VAULT_FILENAME};
pub use manager::VaultManager;
pub use os_backend::{LinuxKeyringBackend, MacOsKeychainBackend};
pub use os_transport::{
    CommandInvocation, CommandOutput, KeychainTransport, KeyringTransport, OS_ENVELOPE_MAGIC,
    OS_ENVELOPE_VERSION, OsKekCustodian, SecretToolKeyringTransport, SecurityCliKeychainTransport,
};
pub use scope::{
    AdapterFamily, MAX_ENDPOINT_SCOPE_LEN, MAX_SCOPE_TARGET_LEN, SecretBackendKind, SecretHandle,
    SecretScope, VAULT_SCOPE_DOMAIN,
};
pub use secret::{
    MAX_SECRET_BYTES, MAX_SECRET_ID_LEN, REDACTED_SECRET_DISPLAY, SecretBytes, SecretId,
    constant_time_eq,
};
pub use store::{FetchedSecret, SecretStore};
pub use taint::{CanaryLeakScanner, LeakEncoding, LeakFinding, LeakReport, MIN_CANARY_LEN};
pub use vault_format::{
    MAX_VAULT_ENTRIES, MAX_VAULT_FILE_BYTES, VAULT_FORMAT_VERSION, VAULT_HEADER_DOMAIN,
    VAULT_HEADER_LEN, VAULT_MAGIC, VAULT_SNAPSHOT_DOMAIN,
};
