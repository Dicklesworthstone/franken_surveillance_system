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
        if !self.authorized_privacy_classes.contains(&handle.privacy_class) {
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
