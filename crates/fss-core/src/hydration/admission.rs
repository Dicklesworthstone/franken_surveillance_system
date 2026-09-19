//! Shared admission rules for producers and independent hydration-receipt verification.

use super::*;

impl SemanticHandle {
    /// Resolves availability at service time without erasing an explicit terminal disposition.
    #[must_use]
    pub fn availability_at(&self, now: TimestampNs) -> HandleAvailability {
        if self.availability == HandleAvailability::Available && now >= self.retention_until {
            HandleAvailability::Expired
        } else {
            self.availability
        }
    }
}

impl HydrationRequest {
    /// Verifies the exact descriptor, disclosure scope, time, and continuation policy.
    ///
    /// Capability and privacy sets must already be projected by the authority-owning caller.
    /// These reference contracts do not authenticate a principal or grant new authority.
    pub fn validate_for(
        &self,
        handle: &SemanticHandle,
        now: TimestampNs,
    ) -> Result<(), HydrationError> {
        self.verify()?;
        handle.verify()?;
        if now < self.issued_at {
            return Err(ContractError::InvertedTimeInterval.into());
        }
        if self.issued_at < handle.published_at || self.anchor != handle.anchor {
            return Err(ContractError::StaleAnchor.into());
        }
        if self.contract_basis != handle.contract_basis {
            return Err(ContractError::GenerationConflict.into());
        }
        if self.handle_id != handle.handle_id
            || self.expected_descriptor_digest != handle.descriptor_digest
            || self.expected_subject_digest != handle.subject_digest
        {
            return Err(ContractError::DigestMismatch.into());
        }
        if !self
            .authorized_privacy_classes
            .contains(&handle.privacy_class)
        {
            return Err(HydrationError::PrivacyDenied);
        }
        if let Some(cursor) = &self.continuation {
            cursor.validate_at(now)?;
            let maximum = handle
                .maximum_level()
                .ok_or(HydrationError::LevelUnavailable)?;
            if cursor.source_digest != handle.ladder_policy_digest()
                || cursor.upper_bound != u64::from(maximum.ordinal()) + 1
                || cursor.position == 0
                || cursor.position > u64::from(maximum.ordinal())
                || cursor.issued_at < handle.published_at
                || cursor.expires_at > handle.retention_until
            {
                return Err(HydrationError::WrongContinuation);
            }
        }
        Ok(())
    }

    /// Checks one complete artifact against the exact request and returns its quoted cost.
    ///
    /// A lower level needs explicit consent. Subject identity, transform, privacy, capability,
    /// H4 purpose, every budget component, and the payload-byte floor are checked independently
    /// of a producer's receipt. A quote is not a measurement of actual runtime resource use.
    pub fn validate_delivery(
        &self,
        handle: &SemanticHandle,
        artifact: &HydrationArtifact,
        now: TimestampNs,
    ) -> Result<BudgetVector, HydrationError> {
        self.validate_for(handle, now)?;
        artifact.verify()?;
        let level = artifact.level;
        if level == HydrationLevel::H4
            && (now >= handle.retention_until
                || handle.availability_at(now) == HandleAvailability::Expired)
        {
            return Err(ContractError::LaboratoryExpansionExpired.into());
        }
        if handle.availability_at(now) != HandleAvailability::Available
            || !handle.levels.contains(&level)
            || level > self.requested_level
            || (level < self.requested_level && !self.allow_lower_level)
        {
            return Err(HydrationError::LevelUnavailable);
        }
        if !artifact.proof_roots.contains(&handle.subject_digest)
            || artifact.applied_transform != handle.applied_transform
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let required = handle
            .capabilities_for(level)
            .ok_or(HydrationError::LevelUnavailable)?;
        if !required.is_subset(&self.available_capabilities) {
            return Err(HydrationError::CapabilityDenied);
        }
        // Reserved canonical identity payloads are checked against descriptor-owned bytes,
        // not merely against caller-supplied proof roots. Keep legacy opaque formats intact.
        if artifact.has_h0_identity_origin() {
            artifact.validate_h0_identity_for(handle)?;
        }
        if level == HydrationLevel::H4 {
            let permitted = match handle.laboratory_access {
                LaboratoryAccess::Unavailable => false,
                LaboratoryAccess::QualificationOnly => {
                    self.purpose == HydrationPurpose::Qualification
                }
                LaboratoryAccess::QualificationOrDebugGrant => {
                    self.purpose == HydrationPurpose::Qualification
                        || (self.purpose == HydrationPurpose::Debugging
                            && handle.debug_capability.as_ref().is_some_and(|capability| {
                                self.available_capabilities.contains(capability)
                            }))
                }
            };
            if !permitted {
                return Err(HydrationError::LaboratoryGrantRequired);
            }

            // Decode H4 expansion from canonical payload
            let expansion = H4LaboratoryExpansion::from_canonical_bytes(&artifact.payload)
                .map_err(HydrationError::Contract)?;
            expansion.validate()?;
            if expansion.computed_digest() != expansion.expansion_digest() {
                return Err(ContractError::DigestMismatch.into());
            }

            // Envelope verification against decoded expansion
            if artifact.content_type != "application/vnd.fss.h4-laboratory-expansion+canonical" {
                return Err(ContractError::InvalidIdentifier.into());
            }
            if artifact.completeness != expansion.completeness() {
                return Err(ContractError::EvidenceRequired.into());
            }
            let mut expected_roots = expansion.proof_roots().clone();
            expected_roots.insert(artifact.payload_digest);
            if artifact.proof_roots != expected_roots {
                return Err(ContractError::DigestMismatch.into());
            }

            // Bind expansion to this handle and request
            if expansion.handle_id() != handle.handle_id {
                return Err(ContractError::LaboratoryExpansionHandleMismatch.into());
            }
            if expansion.subject_id() != handle.subject_id {
                return Err(ContractError::LaboratoryExpansionSubjectMismatch.into());
            }
            if expansion.subject_digest() != handle.subject_digest {
                return Err(ContractError::LaboratoryExpansionSubjectDigestMismatch.into());
            }
            if expansion.anchor() != &handle.anchor {
                return Err(ContractError::LaboratoryExpansionAnchorMismatch.into());
            }
            if expansion.contract_basis() != &handle.contract_basis {
                return Err(ContractError::LaboratoryExpansionBasisMismatch.into());
            }
            if expansion.retention_until() != handle.retention_until {
                return Err(ContractError::LaboratoryExpansionRetentionMismatch.into());
            }
            if now >= expansion.retention_until() {
                return Err(ContractError::LaboratoryExpansionExpired.into());
            }
            if expansion.applied_transform() != handle.applied_transform.as_deref() {
                return Err(ContractError::LaboratoryExpansionTransformMismatch.into());
            }
            if expansion.laboratory_access() != handle.laboratory_access {
                return Err(HydrationError::LaboratoryGrantRequired);
            }
            if expansion.purpose() != self.purpose {
                return Err(HydrationError::LaboratoryGrantRequired);
            }
        }
        let cost = handle
            .estimated_cost(level)
            .ok_or(HydrationError::LevelUnavailable)?;
        if !cost.fits_within(self.budget) || artifact.payload.len() as u64 > cost.bytes {
            return Err(HydrationError::BudgetExceeded);
        }
        Ok(cost)
    }
}

impl HydrationArtifact {
    /// Canonical content type for a descriptor-bound H0 identity artifact.
    pub const H0_CONTENT_TYPE: &'static str = "application/vnd.fss.h0-identity+canonical";

    /// Generates a complete H0 identity directly from a verified immutable descriptor.
    ///
    /// Source, bounds, privacy, authority, capabilities, cost, and retention are taken from
    /// the descriptor. This does not authorize disclosure; use `validate_delivery` at the
    /// request boundary to enforce capabilities, privacy, service time, and budget.
    pub fn publish_h0_identity(handle: &SemanticHandle) -> Result<Self, HydrationError> {
        let identity = H0Identity::from_semantic_handle(handle)?;
        let mut encoder = CanonicalEncoder::new();
        identity.encode_canonical(&mut encoder);
        Self::publish(
            HydrationLevel::H0,
            Self::H0_CONTENT_TYPE,
            encoder.finish_checked()?,
            [handle.subject_digest, handle.descriptor_digest],
            Completeness::Complete,
            handle.applied_transform.clone(),
        )
    }

    /// Verifies the complete canonical H0 payload and envelope against an exact descriptor.
    ///
    /// Regenerating descriptor-owned bytes avoids trusting independently authored metadata
    /// and rejects trailing bytes, alternate encodings, and mismatched descriptor revisions
    /// without allocating collections from an untrusted payload.
    pub fn validate_h0_identity_for(&self, handle: &SemanticHandle) -> Result<(), HydrationError> {
        self.verify()?;
        if self.level != HydrationLevel::H0 || self.content_type != Self::H0_CONTENT_TYPE {
            return Err(ContractError::InvalidIdentifier.into());
        }
        let identity = H0Identity::from_semantic_handle(handle)?;
        let mut encoder = CanonicalEncoder::new();
        identity.encode_canonical(&mut encoder);
        let expected_roots = BTreeSet::from([
            handle.subject_digest,
            handle.descriptor_digest,
            self.payload_digest,
        ]);
        if self.payload != encoder.finish_checked()?
            || self.applied_transform != handle.applied_transform
            || self.proof_roots != expected_roots
        {
            return Err(ContractError::DigestMismatch.into());
        }
        if self.completeness != Completeness::Complete {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(())
    }

    fn has_h0_identity_origin(&self) -> bool {
        let media_type = self
            .content_type
            .split_once(';')
            .map_or(self.content_type.as_str(), |(media_type, _)| media_type);
        media_type.trim().eq_ignore_ascii_case(Self::H0_CONTENT_TYPE)
            || CanonicalDecoder::new(&self.payload)
                .text()
                .is_ok_and(|schema| schema.starts_with("fss.h0_identity."))
    }

    /// Preserves artifact completeness, marking any permitted lower-level delivery partial.
    #[must_use]
    pub fn completeness_for(&self, requested_level: HydrationLevel) -> Completeness {
        if self.level == requested_level {
            self.completeness
        } else {
            Completeness::Partial
        }
    }
}

#[cfg(test)]
mod identity_delivery_tests {
    use super::*;
    use crate::ContractBasisRegistryBytes;

    fn handle_spec() -> Result<SemanticHandleSpec, HydrationError> {
        let capabilities = BTreeSet::from(["capability:identity".to_owned()]);
        let h0_cost = BudgetVector::builder()
            .bytes(16_384)
            .tokens(256)
            .build()
            .map_err(ContractError::from)?;
        let h1_cost = BudgetVector::builder()
            .bytes(32_768)
            .tokens(512)
            .build()
            .map_err(ContractError::from)?;
        Ok(SemanticHandleSpec {
            contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "identity-delivery:test",
            )),
            anchor: LedgerAnchor::genesis("site:identity"),
            subject_id: "subject:identity".to_owned(),
            subject_digest: ContentDigest::sha256(b"exact identity subject"),
            semantic_type: "evidence_bundle".to_owned(),
            source_id: "sensor:identity".to_owned(),
            capture_interval: None,
            spatial_scope: None,
            privacy_class: "private:property".to_owned(),
            applied_transform: Some("redaction:test".to_owned()),
            availability: HandleAvailability::Available,
            retention_until: TimestampNs(100),
            required_capabilities: BTreeMap::from([
                (HydrationLevel::H0, capabilities.clone()),
                (HydrationLevel::H1, capabilities),
            ]),
            estimated_costs: BTreeMap::from([
                (HydrationLevel::H0, h0_cost),
                (HydrationLevel::H1, h1_cost),
            ]),
            levels: BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1]),
            laboratory_access: LaboratoryAccess::Unavailable,
            debug_capability: None,
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        })
    }

    fn request_spec(handle: &SemanticHandle) -> Result<HydrationRequestSpec, HydrationError> {
        Ok(HydrationRequestSpec {
            contract_basis: handle.contract_basis.clone(),
            session_id: SessionId::parse("session:identity")?,
            handle_id: handle.handle_id.clone(),
            expected_descriptor_digest: handle.descriptor_digest,
            expected_subject_digest: handle.subject_digest,
            anchor: handle.anchor.clone(),
            requested_level: HydrationLevel::H0,
            allow_lower_level: false,
            available_capabilities: BTreeSet::from(["capability:identity".to_owned()]),
            authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
            budget: BudgetVector::builder()
                .bytes(65_536)
                .tokens(1_024)
                .build()
                .map_err(ContractError::from)?,
            purpose: HydrationPurpose::Routine,
            continuation: None,
            issued_at: TimestampNs(10),
        })
    }

    fn receipt(
        request: &HydrationRequest,
        handle: &SemanticHandle,
        artifact: &HydrationArtifact,
    ) -> Result<HydrationReceipt, HydrationError> {
        let mut roots = artifact.proof_roots.clone();
        roots.extend([
            handle.descriptor_digest,
            request.request_digest,
            artifact.artifact_digest,
        ]);
        HydrationReceipt::publish(HydrationReceiptSpec {
            request_digest: request.request_digest,
            handle_id: handle.handle_id.clone(),
            descriptor_digest: handle.descriptor_digest,
            subject_digest: handle.subject_digest,
            anchor: handle.anchor.clone(),
            requested_level: request.requested_level,
            delivered_level: Some(artifact.level),
            availability: HandleAvailability::Available,
            cost: handle
                .estimated_cost(artifact.level)
                .ok_or(HydrationError::LevelUnavailable)?,
            completeness: artifact.completeness_for(request.requested_level),
            artifact_digest: Some(artifact.artifact_digest),
            proof_roots: roots,
            continuation: None,
            invalidators: BTreeSet::from(["descriptor-and-disclosure-policy".to_owned()]),
            issued_at: TimestampNs(11),
        })
    }

    fn reseal(artifact: &mut HydrationArtifact) {
        artifact.proof_roots.remove(&artifact.payload_digest);
        artifact.payload_digest = ContentDigest::sha256(&artifact.payload);
        artifact.proof_roots.insert(artifact.payload_digest);
        artifact.artifact_digest = artifact.computed_digest();
    }

    #[test]
    fn canonical_identity_round_trips_through_delivery_and_receipt() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let request = HydrationRequest::publish(request_spec(&handle)?)?;
        let artifact = HydrationArtifact::publish_h0_identity(&handle)?;
        artifact.validate_h0_identity_for(&handle)?;
        assert_eq!(
            H0Identity::from_canonical_bytes(&artifact.payload)?,
            H0Identity::from_semantic_handle(&handle)?,
        );
        assert_eq!(
            request.validate_delivery(&handle, &artifact, TimestampNs(11))?,
            handle
                .estimated_cost(HydrationLevel::H0)
                .ok_or(HydrationError::LevelUnavailable)?,
        );
        receipt(&request, &handle, &artifact)?.validate_for(&request, &handle, Some(&artifact))?;
        Ok(())
    }

    #[test]
    fn substituted_metadata_cannot_pass_with_matching_roots() -> Result<(), HydrationError> {
        let original_spec = handle_spec()?;
        let handle = SemanticHandle::publish(original_spec.clone())?;
        let request = HydrationRequest::publish(request_spec(&handle)?)?;
        for field in [
            "subject", "source", "privacy", "scope", "anchor", "publication", "retention", "cost",
        ] {
            let mut foreign_spec = original_spec.clone();
            match field {
                "subject" => {
                    foreign_spec.subject_digest = ContentDigest::sha256(b"another subject");
                }
                "source" => foreign_spec.source_id = "sensor:another".to_owned(),
                "privacy" => foreign_spec.privacy_class = "private:another".to_owned(),
                "scope" => foreign_spec.spatial_scope = Some("zone:another".to_owned()),
                "anchor" => foreign_spec.anchor = LedgerAnchor::genesis("site:another"),
                "publication" => foreign_spec.published_at = TimestampNs(2),
                "retention" => foreign_spec.retention_until = TimestampNs(200),
                "cost" => {
                    foreign_spec.estimated_costs.insert(
                        HydrationLevel::H0,
                        BudgetVector::builder()
                            .bytes(20_000)
                            .tokens(256)
                            .build()
                            .map_err(ContractError::from)?,
                    );
                }
                _ => unreachable!(),
            }
            let foreign = SemanticHandle::publish(foreign_spec)?;
            let mut artifact = HydrationArtifact::publish_h0_identity(&foreign)?;
            // Rebuild every externally checked root to match the accepted descriptor.
            // Only the descriptor-owned payload comparison can catch this substitution.
            artifact.proof_roots = BTreeSet::from([
                handle.subject_digest,
                handle.descriptor_digest,
                artifact.payload_digest,
            ]);
            reseal(&mut artifact);
            artifact.verify()?;
            assert_eq!(
                request.validate_delivery(&handle, &artifact, TimestampNs(11)),
                Err(HydrationError::Contract(ContractError::DigestMismatch)),
                "foreign {field} must not be accepted",
            );
            assert!(
                receipt(&request, &handle, &artifact)?
                    .validate_for(&request, &handle, Some(&artifact))
                    .is_err(),
                "a rehashed receipt must not legitimize foreign {field}",
            );
        }
        Ok(())
    }

    #[test]
    fn rehashed_payload_and_envelope_mutations_are_rejected() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let mut spec = request_spec(&handle)?;
        spec.requested_level = HydrationLevel::H1;
        spec.allow_lower_level = true;
        let request = HydrationRequest::publish(spec)?;
        let original = HydrationArtifact::publish_h0_identity(&handle)?;
        for mutation in [
            "trailing",
            "roots",
            "transform",
            "completeness",
            "level",
            "media-type",
        ] {
            let mut artifact = original.clone();
            match mutation {
                "trailing" => artifact.payload.push(0),
                "roots" => {
                    artifact
                        .proof_roots
                        .insert(ContentDigest::sha256(b"invented evidence"));
                }
                "transform" => artifact.applied_transform = Some("redaction:another".to_owned()),
                "completeness" => artifact.completeness = Completeness::Partial,
                "level" => artifact.level = HydrationLevel::H1,
                "media-type" => artifact.content_type = "application/octet-stream".to_owned(),
                _ => unreachable!(),
            }
            reseal(&mut artifact);
            artifact.verify()?;
            assert!(
                request
                    .validate_delivery(&handle, &artifact, TimestampNs(11))
                    .is_err(),
                "rehashed {mutation} must not pass admission",
            );
            assert!(
                receipt(&request, &handle, &artifact)?
                    .validate_for(&request, &handle, Some(&artifact))
                    .is_err(),
                "rehashed {mutation} must not pass receipt verification",
            );
        }
        Ok(())
    }

    #[test]
    fn lower_identity_delivery_requires_consent_and_stays_partial() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let artifact = HydrationArtifact::publish_h0_identity(&handle)?;
        let mut spec = request_spec(&handle)?;
        spec.requested_level = HydrationLevel::H1;
        let denied = HydrationRequest::publish(spec.clone())?;
        assert_eq!(
            denied.validate_delivery(&handle, &artifact, TimestampNs(11)),
            Err(HydrationError::LevelUnavailable),
        );
        spec.allow_lower_level = true;
        let allowed = HydrationRequest::publish(spec)?;
        allowed.validate_delivery(&handle, &artifact, TimestampNs(11))?;
        let receipt = receipt(&allowed, &handle, &artifact)?;
        assert_eq!(receipt.completeness, Completeness::Partial);
        receipt.validate_for(&allowed, &handle, Some(&artifact))?;
        Ok(())
    }

    #[test]
    fn canonical_identity_does_not_bypass_privacy_or_capabilities() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let artifact = HydrationArtifact::publish_h0_identity(&handle)?;
        let mut spec = request_spec(&handle)?;
        spec.authorized_privacy_classes.clear();
        let denied = HydrationRequest::publish(spec)?;
        assert_eq!(
            denied.validate_delivery(&handle, &artifact, TimestampNs(11)),
            Err(HydrationError::PrivacyDenied),
        );
        let mut spec = request_spec(&handle)?;
        spec.available_capabilities.clear();
        let denied = HydrationRequest::publish(spec)?;
        assert_eq!(
            denied.validate_delivery(&handle, &artifact, TimestampNs(11)),
            Err(HydrationError::CapabilityDenied),
        );
        Ok(())
    }

    #[test]
    fn identity_expires_at_the_exact_retention_boundary() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let artifact = HydrationArtifact::publish_h0_identity(&handle)?;
        let request = HydrationRequest::publish(request_spec(&handle)?)?;
        request.validate_delivery(&handle, &artifact, TimestampNs(99))?;
        assert_eq!(
            request.validate_delivery(&handle, &artifact, TimestampNs(100)),
            Err(HydrationError::LevelUnavailable),
        );
        Ok(())
    }

    #[test]
    fn identity_enforces_budget_and_payload_floor() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let artifact = HydrationArtifact::publish_h0_identity(&handle)?;
        let mut spec = request_spec(&handle)?;
        spec.budget = BudgetVector::builder()
            .bytes(1)
            .tokens(1_024)
            .build()
            .map_err(ContractError::from)?;
        assert_eq!(
            HydrationRequest::publish(spec)?.validate_delivery(&handle, &artifact, TimestampNs(11)),
            Err(HydrationError::BudgetExceeded),
        );

        let mut spec = handle_spec()?;
        spec.estimated_costs.insert(
            HydrationLevel::H0,
            BudgetVector::builder()
                .bytes(1)
                .tokens(256)
                .build()
                .map_err(ContractError::from)?,
        );
        let underquoted = SemanticHandle::publish(spec)?;
        let artifact = HydrationArtifact::publish_h0_identity(&underquoted)?;
        assert_eq!(
            HydrationRequest::publish(request_spec(&underquoted)?)?
                .validate_delivery(&underquoted, &artifact, TimestampNs(11)),
            Err(HydrationError::BudgetExceeded),
        );
        Ok(())
    }

    #[test]
    fn legacy_opaque_artifacts_are_not_silently_reinterpreted() -> Result<(), HydrationError> {
        let handle = SemanticHandle::publish(handle_spec()?)?;
        let request = HydrationRequest::publish(request_spec(&handle)?)?;
        let artifact = HydrationArtifact::publish(
            HydrationLevel::H0,
            "application/fss+json",
            b"legacy identity envelope".to_vec(),
            [handle.subject_digest],
            Completeness::Complete,
            handle.applied_transform.clone(),
        )?;
        request.validate_delivery(&handle, &artifact, TimestampNs(11))?;
        assert!(artifact.validate_h0_identity_for(&handle).is_err());
        Ok(())
    }
}
