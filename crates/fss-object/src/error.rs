//! Stable object-custody error taxonomy.

use std::error::Error;
use std::fmt;

use fss_core::ContentDigest;

/// Failures from immutable object staging, verification, or root publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectError {
    /// One object exceeds the per-object bound.
    ObjectTooLarge {
        /// Attempted byte length.
        length: usize,
        /// Maximum admitted byte length.
        maximum: usize,
    },
    /// Adding a new unique object would exceed the configured object-count bound.
    ObjectCountLimit {
        /// Current unique object count.
        current: usize,
        /// Maximum admitted count.
        maximum: usize,
    },
    /// Adding a new unique object would exceed the configured total-byte quota.
    ByteQuotaExceeded {
        /// Bytes already staged by unique digest.
        current: u64,
        /// Additional bytes requested.
        requested: u64,
        /// Maximum admitted staged bytes.
        maximum: u64,
    },
    /// A requested content digest is absent.
    Missing(ContentDigest),
    /// An object exists but has not passed digest verification.
    NotVerified(ContentDigest),
    /// Stored bytes no longer match their content identity.
    Corrupt(ContentDigest),
    /// Two different byte strings produced the same declared content digest.
    DigestCollision(ContentDigest),
    /// Manifest kind is empty or too large.
    InvalidManifestKind,
    /// Manifest fan-out exceeds the format bound.
    ManifestChildren {
        /// Number of unique child roots.
        count: usize,
        /// Maximum admitted child roots.
        maximum: usize,
    },
    /// A requested manifest root has not been published.
    ManifestNotPublished(ContentDigest),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectTooLarge { length, maximum } => {
                write!(formatter, "object size {length} exceeds maximum {maximum}")
            }
            Self::ObjectCountLimit { current, maximum } => {
                write!(
                    formatter,
                    "object count {current} reached maximum {maximum}"
                )
            }
            Self::ByteQuotaExceeded {
                current,
                requested,
                maximum,
            } => write!(
                formatter,
                "object bytes {current} + {requested} exceed quota {maximum}"
            ),
            Self::Missing(digest) => write!(formatter, "object is missing: {digest}"),
            Self::NotVerified(digest) => write!(formatter, "object is not verified: {digest}"),
            Self::Corrupt(digest) => write!(formatter, "object bytes are corrupt: {digest}"),
            Self::DigestCollision(digest) => {
                write!(formatter, "content digest collision detected: {digest}")
            }
            Self::InvalidManifestKind => formatter.write_str("manifest kind is empty or too large"),
            Self::ManifestChildren { count, maximum } => write!(
                formatter,
                "manifest child count {count} exceeds maximum {maximum}"
            ),
            Self::ManifestNotPublished(digest) => {
                write!(formatter, "manifest root is not published: {digest}")
            }
        }
    }
}

impl Error for ObjectError {}
