//! Canonical root-manifest representation.

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};

use crate::{MAX_MANIFEST_CHILDREN, MAX_MANIFEST_KIND_BYTES, ObjectError};

/// Immutable root manifest whose identity is the SHA-256 of its canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectManifest {
    kind: String,
    children: Vec<ContentDigest>,
    metadata_digest: Option<ContentDigest>,
    root: ContentDigest,
}

impl ObjectManifest {
    /// Creates a canonical manifest, sorting and deduplicating child roots.
    pub fn new(
        kind: impl Into<String>,
        children: impl IntoIterator<Item = ContentDigest>,
        metadata_digest: Option<ContentDigest>,
    ) -> Result<Self, ObjectError> {
        let kind = kind.into();
        if kind.is_empty() || kind.len() > MAX_MANIFEST_KIND_BYTES {
            return Err(ObjectError::InvalidManifestKind);
        }
        let mut children: Vec<_> = children.into_iter().collect();
        children.sort_unstable();
        children.dedup();
        if children.len() > MAX_MANIFEST_CHILDREN {
            return Err(ObjectError::ManifestChildren {
                count: children.len(),
                maximum: MAX_MANIFEST_CHILDREN,
            });
        }
        let mut manifest = Self {
            kind,
            children,
            metadata_digest,
            root: ContentDigest::sha256(b"unpublished-manifest"),
        };
        manifest.root = ContentDigest::sha256(&manifest.canonical_bytes());
        Ok(manifest)
    }

    /// Semantic manifest family.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Canonically sorted unique child object roots.
    #[must_use]
    pub fn children(&self) -> &[ContentDigest] {
        &self.children
    }

    /// Optional content identity for small typed metadata owned elsewhere.
    #[must_use]
    pub const fn metadata_digest(&self) -> Option<ContentDigest> {
        self.metadata_digest
    }

    /// Canonical manifest object/root digest.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.root
    }

    /// Recomputes the root from canonical bytes.
    #[must_use]
    pub fn computed_root(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }
}

impl CanonicalEncode for ObjectManifest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.object_manifest.v1");
        encoder.text(&self.kind);
        encoder.u64(self.children.len() as u64);
        for child in &self.children {
            encoder.digest(*child);
        }
        match self.metadata_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
    }
}
