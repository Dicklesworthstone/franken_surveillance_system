#![forbid(unsafe_code)]
//! Redacted zeroizing secret buffers and validated canonical secret identifiers.

use core::fmt;
use core::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError,
    validate_id,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::SecretError;

/// Maximum allowed byte length for a single secret payload (64 KiB).
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Maximum allowed ASCII byte length for a canonical [`SecretId`].
pub const MAX_SECRET_ID_LEN: usize = 128;

/// Unconditional redaction marker emitted by [`SecretBytes`] formatting.
pub const REDACTED_SECRET_DISPLAY: &str = "[REDACTED]";

/// Constant-time byte-slice equality without secret-dependent early returns.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let len_diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    let mut diff = 0_u8;
    for index in 0..max_len {
        let a = if index < left.len() { left[index] } else { 0 };
        let b = if index < right.len() { right[index] } else { 0 };
        diff |= a ^ b;
    }
    len_diff == 0 && diff == 0
}

/// Zeroizing, size-bounded secret byte buffer that never formats its contents.
///
/// Both [`fmt::Debug`] and [`fmt::Display`] unconditionally emit `"[REDACTED]"`,
/// and equality uses [`constant_time_eq`].
#[derive(Clone)]
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Wraps an owned byte vector in a zeroizing buffer after enforcing bounds.
    ///
    /// Rejects empty buffers and buffers larger than [`MAX_SECRET_BYTES`],
    /// zeroizing the rejected vector before returning an error.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(SecretError::InvalidInput {
                detail: "secret bytes must not be empty".to_string(),
            });
        }
        if bytes.len() > MAX_SECRET_BYTES {
            let len = bytes.len();
            bytes.zeroize();
            return Err(SecretError::InvalidInput {
                detail: format!("secret length {len} exceeds maximum of {MAX_SECRET_BYTES} bytes"),
            });
        }
        Ok(Self {
            inner: Zeroizing::new(bytes),
        })
    }

    /// Copies a byte slice into a zeroizing secret buffer after enforcing bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            return Err(SecretError::InvalidInput {
                detail: "secret bytes must not be empty".to_string(),
            });
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretError::InvalidInput {
                detail: format!(
                    "secret length {} exceeds maximum of {MAX_SECRET_BYTES} bytes",
                    bytes.len()
                ),
            });
        }
        let mut owned = Vec::with_capacity(bytes.len());
        owned.extend_from_slice(bytes);
        Ok(Self {
            inner: Zeroizing::new(owned),
        })
    }

    /// Borrows the underlying secret bytes for immediate cryptographic or protocol use.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Returns the length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the secret buffer has length zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Compares two secret buffers in constant time.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_slice(), other.as_slice())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_SECRET_DISPLAY)
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_SECRET_DISPLAY)
    }
}

/// Validated canonical secret identifier in the form `secret:<namespace>:<name>`.
///
/// Bounded to [`MAX_SECRET_ID_LEN`] (128) ASCII characters with no whitespace or
/// control characters, compatible with [`fss_core::validate_id`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretId(String);

impl SecretId {
    /// Parses and validates a canonical secret identifier (`secret:<namespace>:<name>`).
    pub fn parse(value: impl Into<String>) -> Result<Self, SecretError> {
        let value = value.into();
        validate_secret_id(&value)?;
        Ok(Self(value))
    }

    /// Constructs a canonical [`SecretId`] from separate `namespace` and `name` segments.
    pub fn new(namespace: &str, name: &str) -> Result<Self, SecretError> {
        if namespace.contains(':') {
            return Err(SecretError::InvalidInput {
                detail: "secret namespace must not contain ':'".to_string(),
            });
        }
        Self::parse(format!("secret:{namespace}:{name}"))
    }

    /// Returns the full canonical identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the namespace segment between the first and second colons.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.0
            .strip_prefix("secret:")
            .and_then(|rest| rest.split_once(':'))
            .map_or("", |(ns, _)| ns)
    }

    /// Returns the name segment after `secret:<namespace>:`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0
            .strip_prefix("secret:")
            .and_then(|rest| rest.split_once(':'))
            .map_or("", |(_, name)| name)
    }
}

fn validate_secret_id(value: &str) -> Result<(), SecretError> {
    if value.is_empty() || value.len() > MAX_SECRET_ID_LEN {
        return Err(SecretError::InvalidInput {
            detail: format!("secret_id length must be within 1..={MAX_SECRET_ID_LEN}"),
        });
    }
    if value
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || !b.is_ascii())
    {
        return Err(SecretError::InvalidInput {
            detail: "secret_id must be printable non-whitespace ASCII".to_string(),
        });
    }
    validate_id(value).map_err(|_| SecretError::InvalidInput {
        detail: "secret_id contains disallowed characters outside FSS canonical alphabet"
            .to_string(),
    })?;
    let rest = value
        .strip_prefix("secret:")
        .ok_or_else(|| SecretError::InvalidInput {
            detail: "secret_id must start with 'secret:'".to_string(),
        })?;
    let (namespace, name) = rest
        .split_once(':')
        .ok_or_else(|| SecretError::InvalidInput {
            detail: "secret_id must follow 'secret:<namespace>:<name>'".to_string(),
        })?;
    if namespace.is_empty() || name.is_empty() {
        return Err(SecretError::InvalidInput {
            detail: "secret_id namespace and name must be non-empty".to_string(),
        });
    }
    if name.starts_with(':') || name.ends_with(':') || name.contains("::") {
        return Err(SecretError::InvalidInput {
            detail: "secret_id name must not contain empty colon segments".to_string(),
        });
    }
    Ok(())
}

impl AsRef<str> for SecretId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretId {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl CanonicalEncode for SecretId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for SecretId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text).map_err(|_| ContractError::InvalidIdentifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_always_redacts_debug_and_display() -> Result<(), SecretError> {
        let secret = SecretBytes::from_slice(b"super-secret-token-12345")?;
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(secret.len(), 24);
        assert!(!secret.is_empty());
        assert_eq!(secret.as_slice(), b"super-secret-token-12345");
        Ok(())
    }

    #[test]
    fn secret_bytes_enforces_bounds_and_ct_eq() -> Result<(), SecretError> {
        assert!(SecretBytes::new(Vec::new()).is_err());
        assert!(SecretBytes::new(vec![0xAA; MAX_SECRET_BYTES + 1]).is_err());
        let a = SecretBytes::from_slice(b"alpha-beta")?;
        let b = SecretBytes::from_slice(b"alpha-beta")?;
        let c = SecretBytes::from_slice(b"alpha-betb")?;
        let d = SecretBytes::from_slice(b"alpha")?;
        assert!(a.ct_eq(&b));
        assert_eq!(a, b);
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
        Ok(())
    }

    #[test]
    fn secret_id_validates_format() -> Result<(), SecretError> {
        let id = SecretId::parse("secret:rtsp:cam-front-01")?;
        assert_eq!(id.namespace(), "rtsp");
        assert_eq!(id.name(), "cam-front-01");
        assert!(SecretId::parse("rtsp:cam-front-01").is_err());
        assert!(SecretId::parse("secret::cam").is_err());
        assert!(SecretId::parse("secret:rtsp:").is_err());
        assert!(SecretId::parse("secret:rtsp:cam front").is_err());
        assert!(SecretId::parse("secret:rtsp:cam\nfront").is_err());
        assert!(SecretId::parse(format!("secret:rtsp:{}", "a".repeat(120))).is_err());
        Ok(())
    }
}
