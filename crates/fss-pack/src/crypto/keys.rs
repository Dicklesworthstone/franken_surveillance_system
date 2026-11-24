#![forbid(unsafe_code)]
//! Versioned KEK/DEK key types and explicit secret-authority loaders (`fss-vault`).
//!
//! All raw key material is held in `Zeroizing` / [`SecretBytes`] wrappers whose `Debug` and
//! `Display` implementations unconditionally emit `"[REDACTED]"`.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, RegionTree, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_vault::{
    AEAD_KEY_LEN, AdapterFamily, CAP_SECRET_READ_001, EntropySource, REDACTED_SECRET_DISPLAY,
    SecretAccessCx, SecretBytes, SecretId, SecretOperation, SecretScope, SecretStore,
    constant_time_eq, hkdf_sha256_expand_32, hkdf_sha256_extract,
};
use zeroize::Zeroizing;

use crate::error::PackError;

/// Canonical HKDF-SHA256 info domain deriving epoch- and scope-bound KEK wrapping subkeys.
pub const PACK_KEK_SUBKEY_DOMAIN: &str = "fss.pack.kek_subkey.v1";

/// Strictly monotonic site Key Encryption Key (KEK) epoch (`>= 1`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyEpoch(pub u32);

impl KeyEpoch {
    /// Validates and constructs a [`KeyEpoch`], rejecting epoch `0`.
    pub fn new(epoch: u32) -> Result<Self, PackError> {
        if epoch == 0 {
            return Err(PackError::InvalidConfig {
                detail: "KeyEpoch must be >= 1".to_owned(),
            });
        }
        Ok(Self(epoch))
    }

    /// Returns the raw `u32` epoch counter.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "kek-epoch-{}", self.0)
    }
}

impl CanonicalEncode for KeyEpoch {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.0);
    }
}

impl CanonicalDecode for KeyEpoch {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let raw = decoder.u32()?;
        if raw == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(raw))
    }
}

/// Unique 128-bit non-secret identifier for a Data Encryption Key (DEK).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DekId(pub [u8; 16]);

impl DekId {
    /// Constructs a validated [`DekId`], rejecting the all-zero sentinel.
    pub fn new(bytes: [u8; 16]) -> Result<Self, PackError> {
        if bytes == [0_u8; 16] {
            return Err(PackError::InvalidConfig {
                detail: "DekId must not be all zeros".to_owned(),
            });
        }
        Ok(Self(bytes))
    }

    /// Generates a fresh 128-bit [`DekId`] from an explicit [`EntropySource`].
    pub fn generate(entropy: &mut dyn EntropySource) -> Result<Self, PackError> {
        let mut bytes = [0_u8; 16];
        entropy
            .fill_bytes(&mut bytes)
            .map_err(|err| PackError::CryptoEntropy {
                detail: format!("failed to generate DekId entropy: {err}"),
            })?;
        if bytes == [0_u8; 16] {
            return Err(PackError::CryptoEntropy {
                detail: "entropy source produced all-zero DekId".to_owned(),
            });
        }
        Ok(Self(bytes))
    }

    /// Encodes the 128-bit identifier as a 32-character lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex_lower(&self.0)
    }

    /// Decodes a 32-character hexadecimal string into a [`DekId`].
    pub fn from_hex(hex: &str) -> Result<Self, PackError> {
        if hex.len() != 32 {
            return Err(PackError::CryptoFormat {
                detail: format!("DekId hex must be 32 chars, got {}", hex.len()),
            });
        }
        let mut bytes = [0_u8; 16];
        let raw = hex.as_bytes();
        for i in 0..16 {
            let hi = decode_hex_nibble(raw[i * 2]).ok_or_else(|| PackError::CryptoFormat {
                detail: "invalid hex character in DekId".to_owned(),
            })?;
            let lo = decode_hex_nibble(raw[i * 2 + 1]).ok_or_else(|| PackError::CryptoFormat {
                detail: "invalid hex character in DekId".to_owned(),
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Self::new(bytes)
    }
}

impl fmt::Debug for DekId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DekId({})", self.to_hex())
    }
}

impl fmt::Display for DekId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl CanonicalEncode for DekId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bytes(&self.0);
    }
}

impl CanonicalDecode for DekId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let raw = decoder.bytes()?;
        let arr: [u8; 16] = raw.try_into().map_err(|_| ContractError::InvalidDigest)?;
        if arr == [0_u8; 16] {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(arr))
    }
}

/// Per-pack or per-event-scope 256-bit ChaCha20-Poly1305 Data Encryption Key (DEK).
///
/// Key bytes are held in [`Zeroizing`] memory and are never formatted in `Debug` or `Display`.
#[derive(Clone)]
pub struct DataEncryptionKey {
    dek_id: DekId,
    key_bytes: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

impl DataEncryptionKey {
    /// Generates a fresh CSPRNG 256-bit DEK and 128-bit [`DekId`] from explicit `entropy`.
    pub fn generate(entropy: &mut dyn EntropySource) -> Result<Self, PackError> {
        let dek_id = DekId::generate(entropy)?;
        let mut raw = Zeroizing::new([0_u8; AEAD_KEY_LEN]);
        entropy
            .fill_bytes(&mut *raw)
            .map_err(|err| PackError::CryptoEntropy {
                detail: format!("failed to generate DEK entropy: {err}"),
            })?;
        if *raw == [0_u8; AEAD_KEY_LEN] {
            return Err(PackError::CryptoEntropy {
                detail: "entropy source produced all-zero DEK".to_owned(),
            });
        }
        Ok(Self {
            dek_id,
            key_bytes: raw,
        })
    }

    /// Constructs a [`DataEncryptionKey`] from an explicit 32-byte [`SecretBytes`] buffer.
    pub fn from_secret_bytes(dek_id: DekId, secret: SecretBytes) -> Result<Self, PackError> {
        if secret.len() != AEAD_KEY_LEN {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "DEK material must be exactly {AEAD_KEY_LEN} bytes, got {}",
                    secret.len()
                ),
            });
        }
        let mut raw = Zeroizing::new([0_u8; AEAD_KEY_LEN]);
        raw.copy_from_slice(secret.as_slice());
        if *raw == [0_u8; AEAD_KEY_LEN] {
            return Err(PackError::InvalidConfig {
                detail: "DEK material must not be all zeros".to_owned(),
            });
        }
        Ok(Self {
            dek_id,
            key_bytes: raw,
        })
    }

    /// Returns this DEK's non-secret 128-bit identifier.
    #[must_use]
    pub const fn dek_id(&self) -> DekId {
        self.dek_id
    }

    /// Constant-time comparison of DEK identifier and key material.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.dek_id == other.dek_id && constant_time_eq(&*self.key_bytes, &*other.key_bytes)
    }

    pub(crate) fn key_bytes(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.key_bytes
    }

    pub(crate) fn from_raw_zeroizing(
        dek_id: DekId,
        raw: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Result<Self, PackError> {
        if *raw == [0_u8; AEAD_KEY_LEN] {
            return Err(PackError::CryptoAuthFailed {
                detail: "unwrapped DEK is all zeros".to_owned(),
            });
        }
        Ok(Self {
            dek_id,
            key_bytes: raw,
        })
    }
}

impl fmt::Debug for DataEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataEncryptionKey")
            .field("dek_id", &self.dek_id)
            .field("key_bytes", &REDACTED_SECRET_DISPLAY)
            .finish()
    }
}

impl fmt::Display for DataEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DataEncryptionKey(id={}, key={REDACTED_SECRET_DISPLAY})",
            self.dek_id
        )
    }
}

/// Versioned site Key Encryption Key (KEK) obtained via explicit secret-authority scope.
///
/// Enforces [`AdapterFamily::StorageKek`], wraps key bytes in [`Zeroizing`], and unconditionally
/// redacts key bytes in `Debug` and `Display`.
#[derive(Clone)]
pub struct KeyEncryptionKey {
    epoch: KeyEpoch,
    scope: SecretScope,
    key_bytes: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

impl KeyEncryptionKey {
    /// Constructs a [`KeyEncryptionKey`] from validated [`SecretBytes`] and an explicit
    /// `StorageKek` [`SecretScope`].
    pub fn from_secret_bytes(
        epoch: KeyEpoch,
        scope: SecretScope,
        secret: SecretBytes,
    ) -> Result<Self, PackError> {
        let epoch = KeyEpoch::new(epoch.0)?;
        if scope.adapter_family() != AdapterFamily::StorageKek {
            return Err(PackError::CryptoAuthority {
                detail: format!(
                    "KEK requires AdapterFamily::StorageKek, got {}",
                    scope.adapter_family()
                ),
            });
        }
        if secret.len() != AEAD_KEY_LEN {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "KEK material must be exactly {AEAD_KEY_LEN} bytes, got {}",
                    secret.len()
                ),
            });
        }
        let mut raw = Zeroizing::new([0_u8; AEAD_KEY_LEN]);
        raw.copy_from_slice(secret.as_slice());
        if *raw == [0_u8; AEAD_KEY_LEN] {
            return Err(PackError::InvalidConfig {
                detail: "KEK material must not be all zeros".to_owned(),
            });
        }
        Ok(Self {
            epoch,
            scope,
            key_bytes: raw,
        })
    }

    /// Loads a [`KeyEncryptionKey`] from an explicit [`SecretStore`] under caller [`SecretAccessCx`].
    ///
    /// Enforces `CAP-SECRET-READ-001`, cancellation/deadline checks, and exact `StorageKek` scope.
    pub fn from_vault(
        store: &dyn SecretStore,
        cx: &SecretAccessCx,
        secret_id: &SecretId,
        epoch: KeyEpoch,
    ) -> Result<Self, PackError> {
        let epoch = KeyEpoch::new(epoch.0)?;
        if cx.scope().adapter_family() != AdapterFamily::StorageKek {
            return Err(PackError::CryptoAuthority {
                detail: format!(
                    "SecretAccessCx for KEK requires AdapterFamily::StorageKek, got {}",
                    cx.scope().adapter_family()
                ),
            });
        }
        cx.authorize(SecretOperation::Read, Some(secret_id), None)?;
        let (handle, secret) = store.fetch(cx, secret_id)?.into_parts();
        Self::from_secret_bytes(epoch, handle.scope, secret)
    }

    /// Loads a [`KeyEncryptionKey`] from a [`SecretStore`] using a live runtime [`AuthorityCx`]
    /// and [`RegionTree`], propagating region cancellation before fetching secret bytes.
    pub fn from_authority_cx(
        store: &dyn SecretStore,
        authority_cx: &AuthorityCx,
        tree: &RegionTree,
        scope: SecretScope,
        now: TimestampNs,
        secret_id: &SecretId,
        epoch: KeyEpoch,
    ) -> Result<Self, PackError> {
        if authority_cx.is_cancel_requested(tree)? {
            return Err(PackError::Cancelled);
        }
        let secret_cx = SecretAccessCx::from_runtime_region(
            authority_cx,
            tree,
            &[CAP_SECRET_READ_001],
            scope,
            now,
        )?;
        Self::from_vault(store, &secret_cx, secret_id, epoch)
    }

    /// Returns this KEK's monotonic [`KeyEpoch`].
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Returns the immutable [`SecretScope`] bound to this KEK.
    #[must_use]
    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }

    /// Returns the canonical SHA-256 scope digest binding this KEK.
    #[must_use]
    pub fn scope_digest(&self) -> ContentDigest {
        self.scope.scope_digest()
    }

    /// Derives an epoch- and scope-bound 256-bit DEK wrapping subkey via HKDF-SHA256.
    pub(crate) fn derive_wrap_subkey(&self) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
        let mut salt_enc = CanonicalEncoder::new();
        salt_enc.text(PACK_KEK_SUBKEY_DOMAIN);
        salt_enc.digest(self.scope.scope_digest());
        let prk = hkdf_sha256_extract(&salt_enc.finish(), &*self.key_bytes);

        let mut info = CanonicalEncoder::new();
        info.text(PACK_KEK_SUBKEY_DOMAIN);
        info.u32(self.epoch.0);
        info.digest(self.scope.scope_digest());
        hkdf_sha256_expand_32(&prk, &info.finish())
    }

    /// Derives a domain-separated 256-bit HMAC key for signing canonical erasure receipts.
    pub(crate) fn derive_erasure_signing_key(&self, domain: &str) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
        let mut salt_enc = CanonicalEncoder::new();
        salt_enc.text(domain);
        salt_enc.digest(self.scope.scope_digest());
        let prk = hkdf_sha256_extract(&salt_enc.finish(), &*self.key_bytes);

        let mut info = CanonicalEncoder::new();
        info.text(domain);
        info.u32(self.epoch.0);
        info.digest(self.scope.scope_digest());
        hkdf_sha256_expand_32(&prk, &info.finish())
    }
}

impl fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEncryptionKey")
            .field("epoch", &self.epoch)
            .field("scope", &self.scope)
            .field("key_bytes", &REDACTED_SECRET_DISPLAY)
            .finish()
    }
}

impl fmt::Display for KeyEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "KeyEncryptionKey(epoch={}, scope={}, key={REDACTED_SECRET_DISPLAY})",
            self.epoch, self.scope
        )
    }
}

/// Encodes arbitrary bytes as lowercase hexadecimal.
#[must_use]
pub(crate) fn encode_hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
