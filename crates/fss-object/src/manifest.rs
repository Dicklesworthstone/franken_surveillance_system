//! Canonical root-manifest representation.

use std::collections::BTreeSet;

use fss_core::{CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest};

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
    /// Creates a canonical manifest with validated unique children and canonical sorting.
    ///
    /// A metadata digest is a custody-bearing reference, not merely an identity decoration, so it
    /// is also inserted into the canonical child closure. It remains separately encoded to retain
    /// its typed role. Duplicate children are rejected with [`ObjectError::DuplicateChild`].
    pub fn new(
        kind: impl Into<String>,
        children: impl IntoIterator<Item = ContentDigest>,
        metadata_digest: Option<ContentDigest>,
    ) -> Result<Self, ObjectError> {
        let kind = kind.into();
        if kind.is_empty() || kind.len() > MAX_MANIFEST_KIND_BYTES {
            return Err(ObjectError::InvalidManifestKind);
        }
        let input_children: Vec<_> = children.into_iter().collect();
        let total_input_count = input_children.len() + usize::from(metadata_digest.is_some());
        if total_input_count > MAX_MANIFEST_CHILDREN {
            return Err(ObjectError::ManifestChildren {
                count: total_input_count,
                maximum: MAX_MANIFEST_CHILDREN,
            });
        }
        let mut seen = BTreeSet::new();
        for child in &input_children {
            if !seen.insert(*child) {
                return Err(ObjectError::DuplicateChild(*child));
            }
        }
        if let Some(metadata) = metadata_digest
            && !seen.insert(metadata)
        {
            return Err(ObjectError::DuplicateChild(metadata));
        }
        let mut children = input_children;
        if let Some(metadata) = metadata_digest {
            children.push(metadata);
        }
        children.sort_unstable();
        let mut manifest = Self {
            kind,
            children,
            metadata_digest,
            root: ContentDigest::sha256(b"unpublished-manifest"),
        };
        manifest.root = ContentDigest::sha256(&manifest.canonical_bytes());
        Ok(manifest)
    }

    /// Decodes a canonical object manifest from its exact canonical byte serialization.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ObjectError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let tag = decoder
            .text()
            .map_err(|_| ObjectError::InvalidManifestKind)?;
        if tag != "fss.object_manifest.v1" {
            return Err(ObjectError::InvalidManifestKind);
        }
        let kind = decoder
            .text()
            .map_err(|_| ObjectError::InvalidManifestKind)?
            .to_owned();
        if kind.is_empty() || kind.len() > MAX_MANIFEST_KIND_BYTES {
            return Err(ObjectError::InvalidManifestKind);
        }
        let child_count = decoder
            .u64()
            .map_err(|_| ObjectError::InvalidManifestKind)?;
        let child_count_usize =
            usize::try_from(child_count).map_err(|_| ObjectError::ManifestChildren {
                count: usize::MAX,
                maximum: MAX_MANIFEST_CHILDREN,
            })?;
        if child_count_usize > MAX_MANIFEST_CHILDREN {
            return Err(ObjectError::ManifestChildren {
                count: child_count_usize,
                maximum: MAX_MANIFEST_CHILDREN,
            });
        }
        let mut children = Vec::with_capacity(child_count_usize);
        for _ in 0..child_count_usize {
            let digest = decoder
                .digest()
                .map_err(|_| ObjectError::Corrupt(ContentDigest::sha256(bytes)))?;
            children.push(digest);
        }
        if !children.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ObjectError::Corrupt(ContentDigest::sha256(bytes)));
        }
        let has_metadata = decoder
            .bool()
            .map_err(|_| ObjectError::InvalidManifestKind)?;
        let metadata_digest = if has_metadata {
            let meta = decoder
                .digest()
                .map_err(|_| ObjectError::Corrupt(ContentDigest::sha256(bytes)))?;
            if !children.contains(&meta) {
                return Err(ObjectError::Corrupt(ContentDigest::sha256(bytes)));
            }
            Some(meta)
        } else {
            None
        };
        decoder
            .ensure_finished()
            .map_err(|_| ObjectError::InvalidManifestKind)?;

        let manifest = Self {
            kind,
            children,
            metadata_digest,
            root: ContentDigest::sha256(bytes),
        };
        if manifest.computed_root() != manifest.root {
            return Err(ObjectError::Corrupt(manifest.root));
        }
        Ok(manifest)
    }

    /// Semantic manifest family.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Canonically sorted unique direct object roots, including typed metadata when present.
    #[must_use]
    pub fn children(&self) -> &[ContentDigest] {
        &self.children
    }

    /// Optional content identity for the manifest's typed metadata object.
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
