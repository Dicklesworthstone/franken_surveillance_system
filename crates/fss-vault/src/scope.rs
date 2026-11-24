#![forbid(unsafe_code)]
//! Adapter-family secret scopes, backend kinds, and non-secret metadata handles.

use core::fmt;
use core::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

pub use crate::access_cx::{
    CAP_SECRET_READ_001, CAP_SECRET_ROTATE_001, CAP_SECRET_WRITE_001, SecretAccessCx,
    SecretOperation,
};
use crate::error::SecretError;
use crate::secret::SecretId;

/// Canonical digest domain for [`SecretScope`].
pub const VAULT_SCOPE_DOMAIN: &str = "fss.vault.secret_scope.v1";

/// Maximum ASCII byte length for a scope target or sensor identifier.
pub const MAX_SCOPE_TARGET_LEN: usize = 128;

/// Maximum ASCII byte length for an endpoint scope string.
pub const MAX_ENDPOINT_SCOPE_LEN: usize = 256;

/// Typed adapter or subsystem family owning a scoped credential.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdapterFamily {
    /// RTSP camera stream credentials.
    Rtsp,
    /// TUTK / P2P camera credentials.
    Tutk,
    /// ONVIF device management credentials.
    Onvif,
    /// UniFi Protect controller or camera credentials.
    UniFiProtect,
    /// Outbound alert webhook signing or bearer credentials.
    AlertWebhook,
    /// Outbound alert relay credentials.
    AlertRelay,
    /// Local storage key-encryption key.
    StorageKek,
    /// S3-compatible archive bucket credentials.
    ArchiveS3,
    /// Operator vault/CLI administrative session credentials.
    OperatorSession,
}

impl AdapterFamily {
    /// Returns the canonical machine-readable string name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtsp => "rtsp",
            Self::Tutk => "tutk",
            Self::Onvif => "onvif",
            Self::UniFiProtect => "unifi_protect",
            Self::AlertWebhook => "alert_webhook",
            Self::AlertRelay => "alert_relay",
            Self::StorageKek => "storage_kek",
            Self::ArchiveS3 => "archive_s3",
            Self::OperatorSession => "operator_session",
        }
    }

    /// Returns the canonical wire discriminator tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Rtsp => 1,
            Self::Tutk => 2,
            Self::Onvif => 3,
            Self::UniFiProtect => 4,
            Self::AlertWebhook => 5,
            Self::AlertRelay => 6,
            Self::StorageKek => 7,
            Self::ArchiveS3 => 8,
            Self::OperatorSession => 9,
        }
    }

    /// Parses an adapter family from its canonical wire tag.
    pub fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Rtsp),
            2 => Ok(Self::Tutk),
            3 => Ok(Self::Onvif),
            4 => Ok(Self::UniFiProtect),
            5 => Ok(Self::AlertWebhook),
            6 => Ok(Self::AlertRelay),
            7 => Ok(Self::StorageKek),
            8 => Ok(Self::ArchiveS3),
            9 => Ok(Self::OperatorSession),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for AdapterFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AdapterFamily {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rtsp" => Ok(Self::Rtsp),
            "tutk" => Ok(Self::Tutk),
            "onvif" => Ok(Self::Onvif),
            "unifi_protect" => Ok(Self::UniFiProtect),
            "alert_webhook" => Ok(Self::AlertWebhook),
            "alert_relay" => Ok(Self::AlertRelay),
            "storage_kek" => Ok(Self::StorageKek),
            "archive_s3" => Ok(Self::ArchiveS3),
            "operator_session" => Ok(Self::OperatorSession),
            _ => Err(SecretError::InvalidInput {
                detail: format!("unknown adapter family '{s}'"),
            }),
        }
    }
}

impl CanonicalEncode for AdapterFamily {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(self.tag());
    }
}

impl CanonicalDecode for AdapterFamily {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.tag()?)
    }
}

/// Exact adapter, target, and endpoint binding for a stored credential.
///
/// Cross-adapter, cross-sensor, or cross-endpoint reuse is refused at both the
/// access-control layer and the per-record AEAD associated-data layer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretScope {
    adapter_family: AdapterFamily,
    sensor_or_target_id: String,
    endpoint_scope: String,
}

impl SecretScope {
    /// Constructs and validates an immutable [`SecretScope`].
    pub fn new(
        adapter_family: AdapterFamily,
        sensor_or_target_id: impl Into<String>,
        endpoint_scope: impl Into<String>,
    ) -> Result<Self, SecretError> {
        let sensor_or_target_id = sensor_or_target_id.into();
        let endpoint_scope = endpoint_scope.into();
        validate_scope_text(
            "sensor_or_target_id",
            &sensor_or_target_id,
            MAX_SCOPE_TARGET_LEN,
        )?;
        validate_scope_text("endpoint_scope", &endpoint_scope, MAX_ENDPOINT_SCOPE_LEN)?;
        Ok(Self {
            adapter_family,
            sensor_or_target_id,
            endpoint_scope,
        })
    }

    /// Returns the bound adapter family.
    #[must_use]
    pub const fn adapter_family(&self) -> AdapterFamily {
        self.adapter_family
    }

    /// Returns the bound sensor or target identifier.
    #[must_use]
    pub fn sensor_or_target_id(&self) -> &str {
        &self.sensor_or_target_id
    }

    /// Returns the bound endpoint scope string.
    #[must_use]
    pub fn endpoint_scope(&self) -> &str {
        &self.endpoint_scope
    }

    /// Computes the canonical SHA-256 scope digest under [`VAULT_SCOPE_DOMAIN`].
    #[must_use]
    pub fn scope_digest(&self) -> ContentDigest {
        self.canonical_digest(VAULT_SCOPE_DOMAIN)
    }
}

fn validate_scope_text(field: &str, value: &str, max_len: usize) -> Result<(), SecretError> {
    if value.is_empty() || value.len() > max_len {
        return Err(SecretError::InvalidInput {
            detail: format!("{field} length must be within 1..={max_len}"),
        });
    }
    if !value.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(SecretError::InvalidInput {
            detail: format!("{field} must contain printable non-whitespace ASCII only"),
        });
    }
    Ok(())
}

impl fmt::Display for SecretScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.adapter_family, self.sensor_or_target_id, self.endpoint_scope
        )
    }
}

impl CanonicalEncode for SecretScope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.adapter_family.encode_canonical(encoder);
        encoder.text(&self.sensor_or_target_id);
        encoder.text(&self.endpoint_scope);
    }
}

impl CanonicalDecode for SecretScope {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let adapter_family = AdapterFamily::decode_canonical(decoder)?;
        let sensor_or_target_id = decoder.text()?.to_string();
        let endpoint_scope = decoder.text()?.to_string();
        Self::new(adapter_family, sensor_or_target_id, endpoint_scope)
            .map_err(|_| ContractError::InvalidIdentifier)
    }
}

/// Concrete storage backend backing a secret handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretBackendKind {
    /// Cross-platform ChaCha20-Poly1305 encrypted local operator vault.
    LocalEncryptedVault,
    /// Native macOS Keychain backend.
    MacOsKeychain,
    /// Native Linux Secret-Service / keyring backend.
    LinuxSecretService,
    /// Local encrypted vault whose master KEK is wrapped by the OS keychain/keyring.
    ComposedOsKekLocalVault,
}

impl SecretBackendKind {
    /// Returns the canonical machine-readable backend identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalEncryptedVault => "local_encrypted_vault",
            Self::MacOsKeychain => "macos_keychain",
            Self::LinuxSecretService => "linux_secret_service",
            Self::ComposedOsKekLocalVault => "composed_os_kek_local_vault",
        }
    }

    /// Returns the canonical wire discriminator tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::LocalEncryptedVault => 1,
            Self::MacOsKeychain => 2,
            Self::LinuxSecretService => 3,
            Self::ComposedOsKekLocalVault => 4,
        }
    }

    /// Parses a backend kind from its canonical wire tag.
    pub fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::LocalEncryptedVault),
            2 => Ok(Self::MacOsKeychain),
            3 => Ok(Self::LinuxSecretService),
            4 => Ok(Self::ComposedOsKekLocalVault),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for SecretBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for SecretBackendKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(self.tag());
    }
}

impl CanonicalDecode for SecretBackendKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.tag()?)
    }
}

/// Non-secret metadata handle for a stored credential.
///
/// Safe to serialize, log, and inspect; never stores or references raw secret bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretHandle {
    /// Canonical secret identifier.
    pub secret_id: SecretId,
    /// Exact adapter/target/endpoint scope bound to this secret.
    pub scope: SecretScope,
    /// Monotonically increasing secret generation (starts at 1).
    pub generation: u64,
    /// Canonical SHA-256 digest of `scope` under [`VAULT_SCOPE_DOMAIN`].
    pub scope_digest: ContentDigest,
    /// Timestamp when generation 1 was created.
    pub created_at_ns: TimestampNs,
    /// Timestamp of the most recent rotation or revocation.
    pub rotated_at_ns: TimestampNs,
    /// Whether this secret has been permanently revoked and tombstoned.
    pub revoked: bool,
    /// Backend that stores or protects this secret.
    pub backend_kind: SecretBackendKind,
}

impl SecretHandle {
    /// Validates internal invariants (`generation >= 1`, matching `scope_digest`).
    pub fn validate(&self) -> Result<(), SecretError> {
        if self.generation == 0 {
            return Err(SecretError::Tampered {
                detail: "secret handle generation must be >= 1",
            });
        }
        if self.scope_digest != self.scope.scope_digest() {
            return Err(SecretError::Tampered {
                detail: "secret handle scope_digest does not match scope",
            });
        }
        Ok(())
    }
}

impl fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (gen={}, scope={}, backend={}, revoked={})",
            self.secret_id, self.generation, self.scope, self.backend_kind, self.revoked
        )
    }
}

impl CanonicalEncode for SecretHandle {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.secret_id.encode_canonical(encoder);
        self.scope.encode_canonical(encoder);
        encoder.u64(self.generation);
        encoder.digest(self.scope_digest);
        self.created_at_ns.encode_canonical(encoder);
        self.rotated_at_ns.encode_canonical(encoder);
        encoder.bool(self.revoked);
        self.backend_kind.encode_canonical(encoder);
    }
}

impl CanonicalDecode for SecretHandle {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let secret_id = SecretId::decode_canonical(decoder)?;
        let scope = SecretScope::decode_canonical(decoder)?;
        let generation = decoder.u64()?;
        let scope_digest = decoder.digest()?;
        let created_at_ns = TimestampNs::decode_canonical(decoder)?;
        let rotated_at_ns = TimestampNs::decode_canonical(decoder)?;
        let revoked = decoder.bool()?;
        let backend_kind = SecretBackendKind::decode_canonical(decoder)?;
        let handle = Self {
            secret_id,
            scope,
            generation,
            scope_digest,
            created_at_ns,
            rotated_at_ns,
            revoked,
            backend_kind,
        };
        handle
            .validate()
            .map_err(|_| ContractError::InvalidDigest)?;
        Ok(handle)
    }
}
