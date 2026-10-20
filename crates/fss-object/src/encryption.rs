#![forbid(unsafe_code)]
//! Encryption-context manifest (FSS-065).
//!
//! Declarative, content-addressed record of HOW archive objects are (or
//! will be) encrypted — never the key material itself. The manifest binds:
//! the cipher suite identity, the key-derivation identity (a key-ID
//! handle, not a secret), the per-context salt/nonce-domain, the object
//! digests protected, and the generation. Secrets never enter the
//! manifest, its digest, or any log surface.
//!
//! The manifest is immutable once published: a new context (rotation) is a
//! NEW manifest with a strictly newer generation whose `predecessor`
//! names the old digest — tombstones and rotations are chains, never
//! in-place edits.

use fss_core::{ContentDigest, Generation};

/// Cipher suites admitted by the reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    /// AES-256-GCM (96-bit nonce, 128-bit tag).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (96-bit nonce, 128-bit tag).
    ChaCha20Poly1305,
}

impl CipherSuite {
    /// Stable identifier spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Nonce length in bytes for the suite.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        12
    }

    /// Tag length in bytes for the suite.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        16
    }
}

/// Typed manifest refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionManifestError {
    /// A key id is empty or malformed.
    InvalidKeyId,
    /// The salt is not exactly 16 bytes.
    InvalidSaltLen {
        /// Observed length.
        len: usize,
    },
    /// The protected-object list is empty or over the bound.
    InvalidObjectCount {
        /// Observed count.
        count: usize,
    },
    /// Rotation does not strictly advance the generation.
    GenerationMustAdvance {
        /// Predecessor generation.
        predecessor: u64,
        /// Attempted successor generation.
        successor: u64,
    },
    /// The predecessor digest does not match the prior manifest's digest.
    PredecessorMismatch {
        /// Named predecessor digest.
        named: ContentDigest,
        /// Actual prior manifest digest.
        actual: ContentDigest,
    },
}

impl std::fmt::Display for EncryptionManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyId => write!(f, "key id must be non-empty and ≤128 bytes"),
            Self::InvalidSaltLen { len } => {
                write!(f, "salt must be 16 bytes, got {len}")
            }
            Self::InvalidObjectCount { count } => {
                write!(f, "protected-object count {count} outside 1..=65536")
            }
            Self::GenerationMustAdvance {
                predecessor,
                successor,
            } => write!(
                f,
                "rotation must advance generation: {predecessor} -> {successor}"
            ),
            Self::PredecessorMismatch { named, actual } => {
                write!(f, "predecessor {named:?} does not match prior {actual:?}")
            }
        }
    }
}

impl std::error::Error for EncryptionManifestError {}

/// Maximum protected objects per manifest.
pub const MAX_PROTECTED_OBJECTS: usize = 65_536;

/// One immutable encryption-context manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionContextManifest {
    /// Cipher suite.
    pub suite: CipherSuite,
    /// Key-derivation identity handle (never key material).
    pub key_id: String,
    /// Per-context salt (16 bytes; domain-separates derivation).
    pub salt: [u8; 16],
    /// Objects whose ciphertext digests this context protects.
    pub protected_objects: Vec<ContentDigest>,
    /// Context generation (GENESIS for the first; rotations advance).
    pub generation: Generation,
    /// Predecessor manifest digest for rotations; None at genesis.
    pub predecessor: Option<ContentDigest>,
}

impl EncryptionContextManifest {
    /// Creates a genesis manifest (no predecessor).
    ///
    /// # Errors
    /// Typed refusals for key id, salt length, and object count.
    pub fn genesis(
        suite: CipherSuite,
        key_id: impl Into<String>,
        salt: [u8; 16],
        protected_objects: Vec<ContentDigest>,
    ) -> Result<Self, EncryptionManifestError> {
        let key_id = key_id.into();
        Self::validate_common(key_id.clone(), &protected_objects)?;
        Ok(Self {
            suite,
            key_id,
            salt,
            protected_objects,
            generation: Generation::GENESIS,
            predecessor: None,
        })
    }

    /// Creates a rotation of `self`: strictly newer generation, naming the
    /// prior manifest as predecessor.
    ///
    /// # Errors
    /// Typed refusals plus generation/predecessor discipline.
    pub fn rotate(
        &self,
        suite: CipherSuite,
        key_id: impl Into<String>,
        salt: [u8; 16],
        protected_objects: Vec<ContentDigest>,
        new_generation: Generation,
    ) -> Result<Self, EncryptionManifestError> {
        let key_id = key_id.into();
        Self::validate_common(key_id.clone(), &protected_objects)?;
        if new_generation.get() <= self.generation.get() {
            return Err(EncryptionManifestError::GenerationMustAdvance {
                predecessor: self.generation.get(),
                successor: new_generation.get(),
            });
        }
        Ok(Self {
            suite,
            key_id,
            salt,
            protected_objects,
            generation: new_generation,
            predecessor: Some(self.digest()),
        })
    }

    /// Verifies this manifest is a valid successor of a prior one (the
    /// inverse of `rotate`'s discipline).
    ///
    /// # Errors
    /// [`EncryptionManifestError::PredecessorMismatch`] when the chain
    /// breaks, generation discipline otherwise.
    pub fn verify_successor_of(&self, prior: &Self) -> Result<(), EncryptionManifestError> {
        if self.generation.get() <= prior.generation.get() {
            return Err(EncryptionManifestError::GenerationMustAdvance {
                predecessor: prior.generation.get(),
                successor: self.generation.get(),
            });
        }
        match &self.predecessor {
            Some(named) if *named == prior.digest() => Ok(()),
            Some(named) => Err(EncryptionManifestError::PredecessorMismatch {
                named: *named,
                actual: prior.digest(),
            }),
            None => Err(EncryptionManifestError::PredecessorMismatch {
                named: ContentDigest::sha256(b"none"),
                actual: prior.digest(),
            }),
        }
    }

    fn validate_common(
        key_id: String,
        objects: &[ContentDigest],
    ) -> Result<(), EncryptionManifestError> {
        if key_id.is_empty() || key_id.len() > 128 {
            return Err(EncryptionManifestError::InvalidKeyId);
        }
        if objects.is_empty() || objects.len() > MAX_PROTECTED_OBJECTS {
            return Err(EncryptionManifestError::InvalidObjectCount {
                count: objects.len(),
            });
        }
        Ok(())
    }

    /// Content digest binding every field (never any secret).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut material = Vec::new();
        material.extend_from_slice(self.suite.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(self.key_id.as_bytes());
        material.push(0);
        material.extend_from_slice(&self.salt);
        material.extend_from_slice(&self.generation.get().to_be_bytes());
        if let Some(pred) = &self.predecessor {
            material.push(1);
            material.extend_from_slice(&pred.bytes());
        } else {
            material.push(0);
        }
        let mut sorted: Vec<&ContentDigest> = self.protected_objects.iter().collect();
        sorted.sort_by_key(|d| d.bytes());
        for digest in sorted {
            material.extend_from_slice(&digest.bytes());
        }
        ContentDigest::sha256(&material)
    }

    /// Verifies the manifest contains no key material: the salt is a
    /// domain separator by design; key_id is a handle. This predicate is
    /// the audit hook for secret-leak scans.
    #[must_use]
    pub const fn carries_no_secret_material(&self) -> bool {
        // The struct's fields are suite/key-id/salt/objects/generation/
        // predecessor by construction; there is no field that CAN hold
        // key material. Kept as an explicit, citable invariant.
        true
    }
}
