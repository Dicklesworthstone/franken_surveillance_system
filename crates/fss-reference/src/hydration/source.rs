//! Live, root-scoped H3 disclosure without a second source-payload cache.

mod local;

use core::fmt;
use std::collections::BTreeSet;

use fss_core::hydration::{
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationRequest,
    HydrationResponse, SemanticHandle,
};
use fss_core::{Completeness, ContentDigest, TimestampNs};
use fss_object::{InMemoryObjectStore, MAX_OBJECT_BYTES, ObjectError};

use super::ReferenceHydrationCatalog;

/// Media type for an exact, untransformed source object (the payload is not a wrapper).
pub const SOURCE_OBJECT_CONTENT_TYPE: &str = "application/vnd.fss.h3-source-object";

/// Source-custody failures remain distinct from authorization and hydration failures.
#[derive(Debug)]
pub enum SourceHydrationError {
    /// Existing request, descriptor, budget, or continuation refusal.
    Hydration(HydrationError),
    /// The custody owner refused an exact object or its publication closure.
    Object(ObjectError),
    /// The local publication or its on-disk source custody failed verification.
    Publication(Box<fss_publication::LocalPublicationError>),
    /// A fresh disk inspection disagrees with the live lock-owning publication authority.
    SnapshotChanged,
    /// The source is not reachable from the explicitly authorized publication root.
    NotReachable,
    /// Exact source delivery cannot stand in for a privacy transform.
    TransformedSource,
    /// A descriptor already has a different binding or a separately cached H3 artifact.
    BindingConflict,
    /// A reader returned bytes inconsistent with the registered source identity or length.
    SourceMismatch,
}

impl SourceHydrationError {
    /// Stable diagnostic code; display never includes source bytes or filesystem paths.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Hydration(error) => error.code(),
            Self::Object(_) => "source_hydration_custody_failed",
            Self::Publication(_) => "source_hydration_local_publication_failed",
            Self::SnapshotChanged => "source_hydration_snapshot_changed",
            Self::NotReachable => "source_hydration_not_reachable",
            Self::TransformedSource => "source_hydration_transform_required",
            Self::BindingConflict => "source_hydration_binding_conflict",
            Self::SourceMismatch => "source_hydration_source_mismatch",
        }
    }
}

impl fmt::Display for SourceHydrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SourceHydrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hydration(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Publication(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<HydrationError> for SourceHydrationError {
    fn from(error: HydrationError) -> Self {
        Self::Hydration(error)
    }
}

impl From<ObjectError> for SourceHydrationError {
    fn from(error: ObjectError) -> Self {
        Self::Object(error)
    }
}

impl From<fss_publication::LocalPublicationError> for SourceHydrationError {
    fn from(error: fss_publication::LocalPublicationError) -> Self {
        Self::Publication(Box::new(error))
    }
}

/// Explicit read-only custody capability supplied by the authority-owning caller.
///
/// Implementations must reverify publication, complete closure, tombstones, and exact bytes on
/// every call; staged objects are insufficient. They must enforce the byte ceiling before
/// allocating output and route I/O through their owning capability. No implementation may infer
/// authority from the requested digest. The hydration service checks grants before calling this
/// boundary and independently checks returned bytes. This trait itself authenticates no user.
pub trait PublishedSourceReader {
    /// Opens one exact object reachable from a currently published, verified root.
    fn read_published_source(
        &self,
        publication_root: ContentDigest,
        subject_digest: ContentDigest,
        max_payload_bytes: u64,
    ) -> Result<Vec<u8>, SourceHydrationError>;
}

impl PublishedSourceReader for InMemoryObjectStore {
    fn read_published_source(
        &self,
        publication_root: ContentDigest,
        subject_digest: ContentDigest,
        max_payload_bytes: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.published_manifest(publication_root)?;
        let mut seen = BTreeSet::from([publication_root]);
        let mut pending = vec![publication_root];
        while let Some(digest) = pending.pop() {
            self.read_verified(digest)?;
            match self.published_manifest(digest) {
                Ok(manifest) => {
                    for child in manifest.children().iter().rev() {
                        if seen.insert(*child) {
                            pending.push(*child);
                        }
                    }
                }
                // Match the custody owner's bottom-up rule: unregistered leaves are opaque.
                Err(ObjectError::ManifestNotPublished(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !seen.contains(&subject_digest) {
            return Err(SourceHydrationError::NotReachable);
        }
        let bytes = self.read_verified(subject_digest)?;
        if bytes.len() as u64 > max_payload_bytes || bytes.len() > MAX_OBJECT_BYTES {
            return Err(HydrationError::BudgetExceeded.into());
        }
        Ok(bytes.to_vec())
    }
}

/// Immutable metadata binding one descriptor revision to one source publication.
///
/// Contains no source payload. At most one binding exists per retained descriptor, so descriptor
/// limits also bound this map. Its artifact digest allows H3-to-H4 continuation without keeping
/// deleted source bytes in the catalog. Binding is not a durability or future-availability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceObjectBinding {
    publication_root: ContentDigest,
    subject_digest: ContentDigest,
    payload_bytes: u64,
    artifact_digest: ContentDigest,
}

impl SourceObjectBinding {
    /// Independently checks an H3 response against this trusted source-custody binding.
    ///
    /// Ordinary receipt validation checks request admission and internal artifact integrity;
    /// it does not by itself prove that a payload is the original source. This additional
    /// consumer-side check requires exact source bytes, descriptor and publication roots,
    /// the bound artifact identity, and an untransformed complete H3 delivery. Lower-level
    /// previews and unavailable responses cannot be mistaken for disclosed source evidence.
    ///
    /// The binding and descriptor must come from a trusted publication/situation, not from
    /// the same untrusted response being checked. This proves their consistency, not current
    /// remote custody or authentication. A previously valid response does not prove present
    /// availability after retention expiry or deletion; request a fresh authorized disclosure.
    pub fn validate_response(
        &self,
        request: &HydrationRequest,
        descriptor: &SemanticHandle,
        response: &HydrationResponse,
    ) -> Result<(), SourceHydrationError> {
        response.validate_for(request, descriptor)?;
        let artifact = response
            .artifact
            .as_ref()
            .ok_or(HydrationError::LevelUnavailable)?;
        if artifact.level != HydrationLevel::H3 {
            return Err(HydrationError::LevelUnavailable.into());
        }
        if artifact.applied_transform.is_some() || descriptor.applied_transform.is_some() {
            return Err(SourceHydrationError::TransformedSource);
        }
        if self.subject_digest != descriptor.subject_digest
            || artifact.payload_digest != self.subject_digest
            || artifact.payload.len() as u64 != self.payload_bytes
            || artifact.artifact_digest != self.artifact_digest
            || artifact.content_type != SOURCE_OBJECT_CONTENT_TYPE
            || artifact.completeness != Completeness::Complete
            || !artifact.proof_roots.contains(&self.publication_root)
            || !artifact.proof_roots.contains(&descriptor.descriptor_digest)
        {
            return Err(SourceHydrationError::SourceMismatch);
        }
        Ok(())
    }

    /// Exact publication root which must be reverified at disclosure time.
    #[must_use]
    pub const fn publication_root(&self) -> ContentDigest {
        self.publication_root
    }

    /// Exact source identity; it is also the delivered payload digest.
    #[must_use]
    pub const fn subject_digest(&self) -> ContentDigest {
        self.subject_digest
    }

    /// Source payload byte count, excluding artifact-envelope overhead.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Expected ordinary H3 artifact identity, including descriptor and publication roots.
    #[must_use]
    pub const fn artifact_digest(&self) -> ContentDigest {
        self.artifact_digest
    }
}

impl ReferenceHydrationCatalog {
    /// Returns immutable source-binding metadata, not permission to read an object.
    #[must_use]
    pub fn source_binding(
        &self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
    ) -> Option<&SourceObjectBinding> {
        self.source_bindings.get(&(handle_id.to_owned(), descriptor_digest))
    }

    /// Binds a current descriptor to exact source bytes in a root-last publication.
    ///
    /// This registration boundary belongs to the authority owner, not to an untrusted request.
    /// It checks actual custody and retains only metadata. Identical retries reverify custody;
    /// conflicting bindings and cached H3 payloads fail without changing any catalog state.
    pub fn bind_source_object(
        &mut self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
        publication_root: ContentDigest,
        reader: &dyn PublishedSourceReader,
    ) -> Result<SourceObjectBinding, SourceHydrationError> {
        let descriptor = self.current_exact(handle_id, descriptor_digest)?;
        descriptor.verify()?;
        if descriptor.availability != HandleAvailability::Available
            || !descriptor.levels.contains(&HydrationLevel::H3)
        {
            return Err(HydrationError::LevelUnavailable.into());
        }
        if descriptor.applied_transform.is_some() {
            return Err(SourceHydrationError::TransformedSource);
        }
        let key = (handle_id.to_owned(), descriptor_digest);
        if self.artifacts.contains_key(&(handle_id.to_owned(), descriptor_digest, HydrationLevel::H3))
            || self.source_bindings.get(&key).is_some_and(|prior| prior.publication_root != publication_root)
        {
            return Err(SourceHydrationError::BindingConflict);
        }
        let quote = descriptor.estimated_cost(HydrationLevel::H3).ok_or(HydrationError::LevelUnavailable)?;
        let ceiling = quote.bytes.min(self.source_payload_ceiling());
        let payload = reader.read_published_source(publication_root, descriptor.subject_digest, ceiling)?;
        let artifact = source_artifact(descriptor, publication_root, payload, ceiling)?;
        let binding = SourceObjectBinding {
            publication_root,
            subject_digest: descriptor.subject_digest,
            payload_bytes: artifact.payload.len() as u64,
            artifact_digest: artifact.artifact_digest,
        };
        if self.source_bindings.get(&key).is_some_and(|prior| prior != &binding) {
            return Err(SourceHydrationError::SourceMismatch);
        }
        self.source_bindings.insert(key, binding.clone());
        Ok(binding)
    }

    /// Hydrates through live source custody, reusing ordinary receipts and single-use cursors.
    ///
    /// Grants, privacy, retention, exact descriptor identity, full-vector quote, and input cursor
    /// are checked before source I/O. No H3 bytes enter the catalog cache. A custody failure is
    /// an error, not physical absence or silent downgrade. Explicit policy/budget downgrades
    /// remain available through the existing ladder. The caller supplies trusted service time
    /// and already authenticated, projected grants exactly as for `hydrate`.
    pub fn hydrate_from_source(
        &mut self,
        request: &HydrationRequest,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<HydrationResponse, SourceHydrationError> {
        request.verify()?;
        let descriptor = self.current_exact(&request.handle_id, request.expected_descriptor_digest)?.clone();
        request.validate_for(&descriptor, now)?;
        if descriptor.availability_at(now) != HandleAvailability::Available
            || request.requested_level < HydrationLevel::H3
        {
            return self.hydrate(request, now).map_err(Into::into);
        }
        let _ = self.continuation_record(request, &descriptor, now)?;
        let binding = self.source_binding(&descriptor.handle_id, descriptor.descriptor_digest)
            .cloned().ok_or(HydrationError::LevelUnavailable)?;
        // Do not read H3 merely because H4 was requested. Prefer a valid H4, and never
        // downgrade an exact continuation or conceal a malformed laboratory artifact.
        if request.requested_level == HydrationLevel::H4 {
            if let Some(artifact) = self.artifacts.get(&(descriptor.handle_id.clone(), descriptor.descriptor_digest, HydrationLevel::H4)) {
                match request.validate_delivery(&descriptor, artifact, now) {
                    Ok(_) => return self.hydrate(request, now).map_err(Into::into),
                    Err(HydrationError::LevelUnavailable | HydrationError::CapabilityDenied
                        | HydrationError::LaboratoryGrantRequired | HydrationError::BudgetExceeded) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !request.allow_lower_level {
                return self.hydrate(request, now).map_err(Into::into);
            }
        }
        let quote = descriptor.estimated_cost(HydrationLevel::H3).ok_or(HydrationError::LevelUnavailable)?;
        let required = descriptor.capabilities_for(HydrationLevel::H3).ok_or(HydrationError::LevelUnavailable)?;
        let ceiling = quote.bytes.min(self.source_payload_ceiling());
        let refusal = if !required.is_subset(&request.available_capabilities) {
            Some(HydrationError::CapabilityDenied)
        } else if !quote.fits_within(request.budget) || binding.payload_bytes > ceiling {
            Some(HydrationError::BudgetExceeded)
        } else {
            None
        };
        if let Some(error) = refusal {
            if request.allow_lower_level {
                return self.hydrate(request, now).map_err(Into::into);
            }
            return Err(error.into());
        }
        let payload = reader.read_published_source(binding.publication_root, binding.subject_digest, ceiling)?;
        let artifact = source_artifact(&descriptor, binding.publication_root, payload, ceiling)?;
        if artifact.artifact_digest != binding.artifact_digest || artifact.payload.len() as u64 != binding.payload_bytes {
            return Err(SourceHydrationError::SourceMismatch);
        }
        self.hydrate_resolved(request, now, Some(artifact)).map_err(Into::into)
    }

    fn source_payload_ceiling(&self) -> u64 {
        self.limits.max_payload_bytes.saturating_sub(self.stored_payload_bytes).min(MAX_OBJECT_BYTES) as u64
    }
}

fn source_artifact(
    descriptor: &SemanticHandle,
    publication_root: ContentDigest,
    payload: Vec<u8>,
    ceiling: u64,
) -> Result<HydrationArtifact, SourceHydrationError> {
    if payload.len() as u64 > ceiling {
        return Err(HydrationError::BudgetExceeded.into());
    }
    if descriptor.applied_transform.is_some() {
        return Err(SourceHydrationError::TransformedSource);
    }
    if ContentDigest::sha256(&payload) != descriptor.subject_digest {
        return Err(SourceHydrationError::SourceMismatch);
    }
    Ok(HydrationArtifact::publish(
        HydrationLevel::H3,
        SOURCE_OBJECT_CONTENT_TYPE,
        payload,
        [descriptor.subject_digest, descriptor.descriptor_digest, publication_root],
        Completeness::Complete,
        None,
    )?)
}
