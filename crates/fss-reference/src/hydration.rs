//! Deterministic reference catalog for immutable semantic-handle hydration.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::hydration::{
    HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest, HydrationResponse,
    LaboratoryAccess, SemanticHandle,
};
use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContinuationCursor, ContinuationScope, ContractError,
    TimestampNs,
};

/// In-memory deterministic oracle for exact descriptor revisions and hydration artifacts.
#[derive(Clone, Debug, Default)]
pub struct ReferenceHydrationCatalog {
    descriptors: BTreeMap<(String, ContentDigest), SemanticHandle>,
    artifacts: BTreeMap<(String, ContentDigest, HydrationLevel), HydrationArtifact>,
}

impl ReferenceHydrationCatalog {
    /// Creates an empty reference catalog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descriptors: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    /// Registers one exact descriptor revision without rebinding its immutable handle identity.
    pub fn register_descriptor(
        &mut self,
        descriptor: SemanticHandle,
    ) -> Result<(), HydrationError> {
        descriptor.verify()?;
        for ((handle_id, _), existing) in &self.descriptors {
            if handle_id == &descriptor.handle_id
                && existing.identity_digest() != descriptor.identity_digest()
            {
                return Err(HydrationError::HandleRebound);
            }
        }
        let key = (
            descriptor.handle_id.clone(),
            descriptor.descriptor_digest,
        );
        match self.descriptors.get(&key) {
            Some(existing) if existing == &descriptor => return Ok(()),
            Some(_) => return Err(ContractError::DigestMismatch.into()),
            None => {}
        }
        self.descriptors.insert(key, descriptor);
        Ok(())
    }

    /// Registers one exact artifact under one descriptor revision and hydration level.
    pub fn register_artifact(
        &mut self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
        artifact: HydrationArtifact,
    ) -> Result<(), HydrationError> {
        artifact.verify()?;
        let descriptor = self
            .descriptors
            .get(&(handle_id.to_owned(), descriptor_digest))
            .ok_or(HydrationError::DescriptorNotFound)?;
        if artifact.level > descriptor.maximum_level().ok_or(HydrationError::LevelUnavailable)?
            || !descriptor.levels.contains(&artifact.level)
            || !artifact.proof_roots.contains(&descriptor.subject_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let key = (
            handle_id.to_owned(),
            descriptor_digest,
            artifact.level,
        );
        match self.artifacts.get(&key) {
            Some(existing) if existing == &artifact => return Ok(()),
            Some(_) => return Err(ContractError::DigestMismatch.into()),
            None => {}
        }
        self.artifacts.insert(key, artifact);
        Ok(())
    }

    /// Resolves one exact descriptor revision.
    #[must_use]
    pub fn descriptor(
        &self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
    ) -> Option<&SemanticHandle> {
        self.descriptors
            .get(&(handle_id.to_owned(), descriptor_digest))
    }

    /// Hydrates the richest explicitly permitted level without silently changing the subject.
    pub fn hydrate(
        &self,
        request: &HydrationRequest,
        now: TimestampNs,
    ) -> Result<HydrationResponse, HydrationError> {
        request.verify()?;
        if now < request.issued_at {
            return Err(ContractError::InvertedTimeInterval.into());
        }
        let descriptor = self
            .descriptor(&request.handle_id, request.expected_descriptor_digest)
            .ok_or(HydrationError::DescriptorNotFound)?;
        descriptor.verify()?;
        validate_request_basis(request, descriptor)?;

        let availability = effective_availability(descriptor, now);
        if availability != HandleAvailability::Available {
            return unavailable_response(request, descriptor, availability, now);
        }
        if !request
            .authorized_privacy_classes
            .contains(&descriptor.privacy_class)
        {
            return Err(HydrationError::PrivacyDenied);
        }

        let mut saw_level = false;
        let mut saw_capability_denial = false;
        let mut saw_budget_denial = false;
        let mut saw_laboratory_denial = false;
        let minimum = if request.allow_lower_level {
            HydrationLevel::H0.ordinal()
        } else {
            request.requested_level.ordinal()
        };
        let mut selected = None;
        for ordinal in (minimum..=request.requested_level.ordinal()).rev() {
            let level = HydrationLevel::from_ordinal(ordinal)
                .ok_or(HydrationError::LevelUnavailable)?;
            if !descriptor.levels.contains(&level) {
                continue;
            }
            let key = (
                descriptor.handle_id.clone(),
                descriptor.descriptor_digest,
                level,
            );
            let Some(artifact) = self.artifacts.get(&key) else {
                continue;
            };
            saw_level = true;
            if level == HydrationLevel::H4
                && !laboratory_access_permits(descriptor, request)
            {
                saw_laboratory_denial = true;
                continue;
            }
            let required = descriptor
                .capabilities_for(level)
                .ok_or(HydrationError::LevelUnavailable)?;
            if !required.is_subset(&request.available_capabilities) {
                saw_capability_denial = true;
                continue;
            }
            let cost = descriptor
                .estimated_cost(level)
                .ok_or(HydrationError::LevelUnavailable)?;
            if !cost.fits_within(request.budget) {
                saw_budget_denial = true;
                continue;
            }
            selected = Some((level, cost, artifact.clone()));
            break;
        }

        let Some((delivered_level, cost, artifact)) = selected else {
            return Err(if saw_laboratory_denial {
                HydrationError::LaboratoryGrantRequired
            } else if saw_capability_denial {
                HydrationError::CapabilityDenied
            } else if saw_budget_denial {
                HydrationError::BudgetExceeded
            } else if saw_level {
                HydrationError::LevelUnavailable
            } else {
                HydrationError::LevelUnavailable
            });
        };

        let continuation = self.next_cursor(request, descriptor, &artifact, delivered_level, now)?;
        let mut proof_roots = artifact.proof_roots.clone();
        proof_roots.insert(artifact.payload_digest);
        proof_roots.insert(artifact.artifact_digest);
        proof_roots.insert(descriptor.subject_digest);
        proof_roots.insert(descriptor.descriptor_digest);
        let completeness = response_completeness(
            artifact.completeness,
            delivered_level,
            request.requested_level,
        );
        let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
            request_digest: request.request_digest,
            handle_id: descriptor.handle_id.clone(),
            descriptor_digest: descriptor.descriptor_digest,
            subject_digest: descriptor.subject_digest,
            anchor: descriptor.anchor.clone(),
            requested_level: request.requested_level,
            delivered_level: Some(delivered_level),
            availability,
            cost,
            completeness,
            artifact_digest: Some(artifact.artifact_digest),
            proof_roots,
            continuation,
            invalidators: invalidators(descriptor, delivered_level, request.requested_level),
            issued_at: now,
        })?;
        let response = HydrationResponse {
            artifact: Some(artifact),
            receipt,
        };
        response.validate_for(request, descriptor)?;
        Ok(response)
    }

    fn next_cursor(
        &self,
        request: &HydrationRequest,
        descriptor: &SemanticHandle,
        artifact: &HydrationArtifact,
        delivered_level: HydrationLevel,
        now: TimestampNs,
    ) -> Result<Option<ContinuationCursor>, HydrationError> {
        let Some(next) = delivered_level.successor() else {
            return Ok(None);
        };
        let Some(maximum) = descriptor.maximum_level() else {
            return Ok(None);
        };
        if next > maximum
            || !self.artifacts.contains_key(&(
                descriptor.handle_id.clone(),
                descriptor.descriptor_digest,
                next,
            ))
        {
            return Ok(None);
        }
        Ok(Some(ContinuationCursor::publish(
            ContinuationScope::EvidenceHydration,
            descriptor.handle_id.clone(),
            descriptor.contract_basis.clone(),
            request.session_id.clone(),
            HYDRATION_VIEW_ID,
            descriptor.anchor.clone(),
            descriptor.anchor.clone(),
            descriptor.ladder_policy_digest(),
            u64::from(next.ordinal()),
            u64::from(maximum.ordinal()) + 1,
            artifact.artifact_digest,
            None,
            now,
            descriptor.retention_until,
        )?))
    }
}

fn validate_request_basis(
    request: &HydrationRequest,
    descriptor: &SemanticHandle,
) -> Result<(), HydrationError> {
    if request.contract_basis != descriptor.contract_basis {
        return Err(ContractError::GenerationConflict.into());
    }
    if request.anchor != descriptor.anchor {
        return Err(ContractError::StaleAnchor.into());
    }
    if request.expected_subject_digest != descriptor.subject_digest
        || request.expected_descriptor_digest != descriptor.descriptor_digest
        || request.handle_id != descriptor.handle_id
    {
        return Err(ContractError::DigestMismatch.into());
    }
    Ok(())
}

fn effective_availability(
    descriptor: &SemanticHandle,
    now: TimestampNs,
) -> HandleAvailability {
    if now > descriptor.retention_until {
        HandleAvailability::Expired
    } else {
        descriptor.availability
    }
}

fn unavailable_response(
    request: &HydrationRequest,
    descriptor: &SemanticHandle,
    availability: HandleAvailability,
    now: TimestampNs,
) -> Result<HydrationResponse, HydrationError> {
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: descriptor.handle_id.clone(),
        descriptor_digest: descriptor.descriptor_digest,
        subject_digest: descriptor.subject_digest,
        anchor: descriptor.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: None,
        availability,
        cost: BudgetVector::default(),
        completeness: availability.unavailable_completeness(),
        artifact_digest: None,
        proof_roots: BTreeSet::from([
            descriptor.subject_digest,
            descriptor.descriptor_digest,
        ]),
        continuation: None,
        invalidators: invalidators(descriptor, HydrationLevel::H0, request.requested_level),
        issued_at: now,
    })?;
    let response = HydrationResponse {
        artifact: None,
        receipt,
    };
    response.validate_for(request, descriptor)?;
    Ok(response)
}

fn laboratory_access_permits(
    descriptor: &SemanticHandle,
    request: &HydrationRequest,
) -> bool {
    match descriptor.laboratory_access {
        LaboratoryAccess::Unavailable => false,
        LaboratoryAccess::QualificationOnly => {
            request.purpose == HydrationPurpose::Qualification
        }
        LaboratoryAccess::QualificationOrDebugGrant => {
            request.purpose == HydrationPurpose::Qualification
                || (request.purpose == HydrationPurpose::Debugging
                    && descriptor.debug_capability.as_ref().is_some_and(|capability| {
                        request.available_capabilities.contains(capability)
                    }))
        }
    }
}

fn response_completeness(
    artifact: Completeness,
    delivered: HydrationLevel,
    requested: HydrationLevel,
) -> Completeness {
    if delivered == requested {
        artifact
    } else {
        match artifact {
            Completeness::Complete | Completeness::Bounded => Completeness::Bounded,
            other => other,
        }
    }
}

fn invalidators(
    descriptor: &SemanticHandle,
    delivered: HydrationLevel,
    requested: HydrationLevel,
) -> BTreeSet<String> {
    let mut values = BTreeSet::from([
        format!("descriptor:{}", descriptor.descriptor_digest),
        format!("subject:{}", descriptor.subject_digest),
        format!("retention:until:{}", descriptor.retention_until.0),
        format!("privacy-class:{}", descriptor.privacy_class),
    ]);
    if delivered != requested {
        values.insert(format!(
            "explicit-downgrade:{}-to-{}",
            requested.as_str(),
            delivered.as_str()
        ));
    }
    values
}
