#![forbid(unsafe_code)]
//! Non-authorizing custody commitments carried by the existing replay-protection checkpoint.
//! A missing descriptor or source may remain missing; its former binding may not be replaced.

use std::collections::BTreeMap;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, HydrationError};

use super::{HydrationLevel, ReferenceHydrationCatalog, SourceObjectBinding};
use crate::deletion::belief::hydration::DeploymentSourceAuthority;

pub(super) const MAX_SOURCE_BINDINGS: usize = 65_536;
pub(super) type SourceBindingPins = BTreeMap<ContentDigest, ContentDigest>;

/// The descriptor is the map key. Exact payload length and artifact bytes are independently
/// reverified by the existing source owner; this commitment fences its pre-read custody profile.
fn profile_digest(
    publication_root: ContentDigest,
    subject: ContentDigest,
    authority: Option<DeploymentSourceAuthority>,
) -> ContentDigest {
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.source_custody_binding.v1");
    encoded.digest(publication_root);
    encoded.digest(subject);
    encoded.bool(authority.is_some());
    if let Some(authority) = authority {
        encoded.digest(authority.store_pin());
        encoded.digest(authority.journal_root());
        encoded.digest(authority.publication_record());
    }
    ContentDigest::sha256(&encoded.finish())
}

impl SourceObjectBinding {
    /// Commitment to this exact source's custody profile, not proof of current availability.
    ///
    /// Includes the manifest, subject, standalone/deployment distinction and, for deployments,
    /// the original native journal identity, canonical head and publication record. It is used
    /// only in protected local recovery metadata, never as a source-read capability.
    #[must_use]
    pub fn custody_binding_digest(&self) -> ContentDigest {
        profile_digest(
            self.publication_root(),
            self.subject_digest(),
            self.deployment_authority(),
        )
    }
}

/// A later checkpoint cannot discard source identity even after all cursors have expired.
pub(super) fn validate_successor(
    next: &SourceBindingPins,
    prior: &SourceBindingPins,
) -> Result<(), HydrationError> {
    if prior.iter().any(|(descriptor, pin)| next.get(descriptor) != Some(pin)) {
        return Err(ContractError::DigestMismatch.into());
    }
    Ok(())
}

pub(super) fn decode(decoder: &mut CanonicalDecoder<'_>) -> Result<SourceBindingPins, HydrationError> {
    let count = usize::try_from(decoder.u64()?).map_err(|_| HydrationError::CapacityExceeded)?;
    // Two algorithm-qualified fixed-width digests per entry. Check before map allocation.
    if count == 0 || count > MAX_SOURCE_BINDINGS || count > decoder.remaining() / 66 {
        return Err(HydrationError::CapacityExceeded);
    }
    let mut pins = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let descriptor = decoder.digest()?;
        if previous.is_some_and(|prior| prior >= descriptor) {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        previous = Some(descriptor);
        pins.insert(descriptor, decoder.digest()?);
    }
    Ok(pins)
}

pub(super) fn encode(pins: &SourceBindingPins, encoder: &mut CanonicalEncoder) {
    encoder.u64(pins.len() as u64);
    for (descriptor, pin) in pins {
        encoder.digest(*descriptor);
        encoder.digest(*pin);
    }
}

impl ReferenceHydrationCatalog {
    /// A recovered custody requirement for an exact descriptor, without reconstructing source.
    ///
    /// This can remain present when the descriptor or deleted/expired source is unavailable.
    /// Rebuilding metadata never makes its bytes available or creates a grant. Requirements
    /// become crash-durable only when their enclosing checkpoint is committed by its owner.
    #[must_use]
    pub fn source_binding_requirement(&self, descriptor: ContentDigest) -> Option<ContentDigest> {
        self.source_requirements.get(&descriptor).copied()
    }

    pub(super) fn checkpoint_source_bindings(&self) -> Result<SourceBindingPins, HydrationError> {
        self.validate_source_requirements(&self.source_requirements)?;
        let ceiling = self.limits.max_descriptors.min(MAX_SOURCE_BINDINGS);
        let mut pins = self.source_requirements.clone();
        for ((_, descriptor), binding) in &self.source_bindings {
            if !pins.contains_key(descriptor) && pins.len() >= ceiling {
                return Err(HydrationError::CapacityExceeded);
            }
            let digest = binding.custody_binding_digest();
            if pins.get(descriptor).is_some_and(|prior| *prior != digest) {
                return Err(ContractError::DigestMismatch.into());
            }
            pins.insert(*descriptor, digest);
        }
        Ok(pins)
    }

    pub(super) fn validate_source_requirements(
        &self,
        pins: &SourceBindingPins,
    ) -> Result<(), HydrationError> {
        if pins.len() > self.limits.max_descriptors.min(MAX_SOURCE_BINDINGS) {
            return Err(HydrationError::CapacityExceeded);
        }
        validate_successor(pins, &self.source_requirements)?;
        for ((_, descriptor), binding) in &self.source_bindings {
            if pins.get(descriptor).is_some_and(|pin| *pin != binding.custody_binding_digest()) {
                return Err(ContractError::DigestMismatch.into());
            }
        }
        // Catch a weaker catalog already populated before cold recovery, not only later writes.
        if self.artifacts.keys().any(|(_, descriptor, level)| {
            *level == HydrationLevel::H3 && pins.contains_key(descriptor)
        }) {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    pub(super) fn check_source_binding_profile(
        &self,
        descriptor: ContentDigest,
        root: ContentDigest,
        subject: ContentDigest,
        authority: Option<DeploymentSourceAuthority>,
    ) -> Result<(), HydrationError> {
        if let Some(expected) = self.source_requirements.get(&descriptor) {
            if *expected != profile_digest(root, subject, authority) {
                return Err(ContractError::DigestMismatch.into());
            }
        } else if !self.source_bindings.keys().any(|(_, digest)| *digest == descriptor) {
            // Missing historical bindings retain their slots. A new binding may not bypass the
            // cumulative recovery-metadata ceiling by waiting until the next disclosure commit.
            let unpinned = self.source_bindings.keys()
                .filter(|(_, digest)| !self.source_requirements.contains_key(digest)).count();
            let used = self.source_requirements.len().checked_add(unpinned)
                .ok_or(HydrationError::CapacityExceeded)?;
            if used >= self.limits.max_descriptors.min(MAX_SOURCE_BINDINGS) {
                return Err(HydrationError::CapacityExceeded);
            }
        }
        Ok(())
    }
}
