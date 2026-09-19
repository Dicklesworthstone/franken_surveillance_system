use super::*;

const LABORATORY_CONTENT_TYPE: &str = "application/vnd.fss.h4-laboratory-expansion+canonical";

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

    /// Verifies payload and artifact integrity, including laboratory-origin quarantine.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate_body()?;
        let expected_payload = ContentDigest::sha256(&self.payload);
        if self.payload_digest != expected_payload || self.artifact_digest != self.computed_digest()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Returns whether the declared level or recognized payload origin requires quarantine.
    ///
    /// Public envelope fields can be changed and resealed. Relabeling an H4 payload as a
    /// production level, including changing its media type, must not remove quarantine.
    #[must_use]
    pub fn is_quarantined(&self) -> bool {
        matches!(self.level, HydrationLevel::H4) || self.has_laboratory_origin()
    }

    /// Checks artifact integrity and excludes recognized laboratory material from production.
    ///
    /// This is an artifact-local gate, not a substitute for request authorization or
    /// descriptor-bound delivery validation.
    #[must_use]
    pub fn is_production_safe(&self) -> bool {
        !self.is_quarantined() && self.verify().is_ok()
    }

    /// Rejects corrupt or laboratory artifacts as effect premises; does not grant authority.
    #[must_use]
    pub fn may_authorize_effects(&self) -> bool {
        self.is_production_safe()
    }

    fn has_laboratory_origin(&self) -> bool {
        let media_type = self
            .content_type
            .split_once(';')
            .map_or(self.content_type.as_str(), |(media_type, _)| media_type);
        if media_type
            .trim()
            .eq_ignore_ascii_case(LABORATORY_CONTENT_TYPE)
        {
            return true;
        }

        // Inspect only the bounded canonical discriminator, without allocating or decoding
        // laboratory contents. Unknown/old H4 versions remain quarantined as well.
        CanonicalDecoder::new(&self.payload)
            .text()
            .is_ok_and(|schema| schema.starts_with("fss.h4_laboratory_expansion."))
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
        if self.level != HydrationLevel::H4 && self.has_laboratory_origin() {
            return Err(ContractError::ProhibitedEvidencePromotion.into());
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

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    fn publish(
        level: HydrationLevel,
        content_type: &str,
        payload: Vec<u8>,
    ) -> Result<HydrationArtifact, HydrationError> {
        HydrationArtifact::publish(
            level,
            content_type,
            payload,
            [ContentDigest::sha256(b"independent-subject-root")],
            Completeness::Complete,
            None,
        )
    }

    fn laboratory_payload(schema: &str) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(schema);
        encoder.text("quarantined-body");
        encoder.finish()
    }

    #[test]
    fn laboratory_media_type_cannot_be_promoted_to_any_production_level() {
        for level in HydrationLevel::ALL.into_iter().take(4) {
            for content_type in [
                LABORATORY_CONTENT_TYPE,
                "APPLICATION/VND.FSS.H4-LABORATORY-EXPANSION+CANONICAL",
                "application/vnd.fss.h4-laboratory-expansion+canonical; version=2",
            ] {
                assert_eq!(
                    publish(level, content_type, b"opaque laboratory bytes".to_vec()),
                    Err(HydrationError::Contract(
                        ContractError::ProhibitedEvidencePromotion
                    )),
                );
            }
        }
    }

    #[test]
    fn canonical_origin_is_checked_even_when_the_media_type_is_relabelled() {
        for schema in [
            H4_SCHEMA,
            "fss.h4_laboratory_expansion.v1",
            "fss.h4_laboratory_expansion.v999",
        ] {
            for level in HydrationLevel::ALL.into_iter().take(4) {
                assert_eq!(
                    publish(
                        level,
                        "application/octet-stream",
                        laboratory_payload(schema)
                    ),
                    Err(HydrationError::Contract(
                        ContractError::ProhibitedEvidencePromotion
                    )),
                );
            }
        }
    }

    #[test]
    fn resealing_both_outer_tags_does_not_remove_quarantine() -> Result<(), HydrationError> {
        let mut artifact = publish(
            HydrationLevel::H4,
            LABORATORY_CONTENT_TYPE,
            laboratory_payload(H4_SCHEMA),
        )?;
        artifact.level = HydrationLevel::H1;
        artifact.content_type = "application/octet-stream".to_owned();
        artifact.artifact_digest = artifact.computed_digest();
        assert!(artifact.is_quarantined());
        assert!(!artifact.is_production_safe());
        assert!(!artifact.may_authorize_effects());
        assert_eq!(
            artifact.verify(),
            Err(HydrationError::Contract(
                ContractError::ProhibitedEvidencePromotion
            )),
        );
        Ok(())
    }

    #[test]
    fn corrupt_production_artifact_cannot_be_an_effect_premise() -> Result<(), HydrationError> {
        let mut artifact = publish(
            HydrationLevel::H1,
            "application/fss+json",
            b"semantic synopsis".to_vec(),
        )?;
        assert!(artifact.is_production_safe());
        artifact.payload.push(b'!');
        assert!(!artifact.is_production_safe());
        assert!(!artifact.may_authorize_effects());
        Ok(())
    }

    #[test]
    fn ordinary_production_artifacts_keep_their_existing_behavior() -> Result<(), HydrationError> {
        for level in HydrationLevel::ALL.into_iter().take(4) {
            let artifact = publish(level, "application/octet-stream", vec![0xff, 0, 1])?;
            artifact.verify()?;
            assert!(!artifact.is_quarantined());
            assert!(artifact.is_production_safe());
            assert!(artifact.may_authorize_effects());
        }
        Ok(())
    }

    #[test]
    fn opaque_h4_artifacts_remain_quarantined() -> Result<(), HydrationError> {
        let artifact = publish(
            HydrationLevel::H4,
            "application/octet-stream",
            b"laboratory fixture".to_vec(),
        )?;
        artifact.verify()?;
        assert!(artifact.is_quarantined());
        assert!(!artifact.is_production_safe());
        assert!(!artifact.may_authorize_effects());
        Ok(())
    }
}
