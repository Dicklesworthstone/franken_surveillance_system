use super::*;

/// One complete artifact published at an exact hydration level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HydrationArtifact {
    /// Delivered hydration level.
    pub level: HydrationLevel,
    /// Stable media or semantic content type.
    pub content_type: String,
    /// Exact bounded payload.
    pub payload: Vec<u8>,
    /// Digest of the exact payload.
    pub payload_digest: ContentDigest,
    /// Retained provenance roots plus the payload-integrity root.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness of this artifact at its declared level.
    pub completeness: Completeness,
    /// Transform applied to this artifact, when any.
    pub applied_transform: Option<String>,
    /// Digest of the complete artifact.
    pub artifact_digest: ContentDigest,
}

impl HydrationArtifact {
    /// Publishes and seals one complete bounded artifact.
    pub fn publish(
        level: HydrationLevel,
        content_type: impl Into<String>,
        payload: Vec<u8>,
        proof_roots: impl IntoIterator<Item = ContentDigest>,
        completeness: Completeness,
        applied_transform: Option<String>,
    ) -> Result<Self, HydrationError> {
        let payload_digest = ContentDigest::sha256(&payload);
        let mut roots: BTreeSet<_> = proof_roots.into_iter().collect();
        if roots.is_empty() || roots.iter().all(|root| *root == payload_digest) {
            return Err(ContractError::EvidenceRequired.into());
        }
        roots.insert(payload_digest);
        let mut artifact = Self {
            level,
            content_type: content_type.into(),
            payload,
            payload_digest,
            proof_roots: roots,
            completeness,
            applied_transform,
            artifact_digest: ContentDigest::sha256(b"unpublished-hydration-artifact"),
        };
        artifact.validate_body()?;
        artifact.artifact_digest = artifact.computed_digest();
        Ok(artifact)
    }

    /// Recomputes the complete artifact digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies payload and artifact integrity.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate_body()?;
        if self.payload_digest != ContentDigest::sha256(&self.payload)
            || self.artifact_digest != self.computed_digest()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.content_type)
            || self.payload.is_empty()
            || self.payload.len() > MAX_ARTIFACT_BYTES
            || !self.proof_roots.contains(&self.payload_digest)
            || !self
                .proof_roots
                .iter()
                .any(|root| *root != self.payload_digest)
            || self
                .applied_transform
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || matches!(
                self.completeness,
                Completeness::Unknown
                    | Completeness::NotObservable
                    | Completeness::Unauthorized
                    | Completeness::Stale
            )
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_hydration_artifact.v1");
        self.level.encode_canonical(encoder);
        encoder.text(&self.content_type);
        encoder.bytes(&self.payload);
        encoder.digest(self.payload_digest);
        encode_digest_set(&self.proof_roots, encoder);
        encoder.u8(completeness_code(self.completeness));
        encode_optional_text(self.applied_transform.as_deref(), encoder);
    }
}

impl CanonicalEncode for HydrationArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.artifact_digest);
    }
}
