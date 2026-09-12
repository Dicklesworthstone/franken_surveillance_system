//! Bounded deterministic catalog for immutable semantic-handle hydration.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::hydration::{
    HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HydrationReceipt, HydrationReceiptSpec, HydrationRequest, HydrationResponse, SemanticHandle,
};
use fss_core::{
    BudgetVector, ContentDigest, ContinuationCursor, ContinuationCursorPublishParams,
    ContinuationScope, ContractError, SessionId, TimestampNs,
};

/// Explicit storage ceilings for the in-memory reference catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceHydrationLimits {
    /// Maximum number of retained immutable descriptor revisions, including history.
    pub max_descriptors: usize,
    /// Maximum aggregate artifact payload bytes; does not measure allocator or metadata overhead.
    pub max_payload_bytes: usize,
    /// Maximum number of retained cursor records (active and consumed).
    pub max_issued_cursors: usize,
}

impl Default for ReferenceHydrationLimits {
    fn default() -> Self {
        Self {
            max_descriptors: 4_096,
            max_payload_bytes: 64 * 1_024 * 1_024,
            max_issued_cursors: 4_096,
        }
    }
}

/// Reference record of one continuation cursor issued by the catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedCursorRecord {
    /// Exact canonical digest of the issued cursor.
    pub cursor_digest: ContentDigest,
    /// Session authorized to resume this cursor.
    pub session_id: SessionId,
    /// Stable handle identity denotable by this cursor.
    pub handle_id: String,
    /// Authoritative expiry granted at issuance.
    pub expires_at: TimestampNs,
    /// Exact ladder ordinal resumed by this cursor.
    pub next_ordinal: u8,
    /// Whether this cursor has already been consumed by a successful continuation request.
    pub consumed: bool,
}

/// In-memory oracle with exact historical identities and one current descriptor per handle.
///
/// The caller supplies authority-projected descriptors and request grants. This reference store
/// is not a production authentication service, durable custody journal, or deletion proof.
#[derive(Clone, Debug)]
pub struct ReferenceHydrationCatalog {
    descriptors: BTreeMap<(String, ContentDigest), SemanticHandle>,
    current: BTreeMap<String, ContentDigest>,
    artifacts: BTreeMap<(String, ContentDigest, HydrationLevel), HydrationArtifact>,
    issued_cursors: BTreeMap<ContentDigest, IssuedCursorRecord>,
    limits: ReferenceHydrationLimits,
    stored_payload_bytes: usize,
}

impl Default for ReferenceHydrationCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceHydrationCatalog {
    /// Creates an empty catalog with 4,096 descriptor slots and a 64 MiB payload ceiling.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(ReferenceHydrationLimits {
            max_descriptors: 4_096,
            max_payload_bytes: 64 * 1_024 * 1_024,
            max_issued_cursors: 4_096,
        })
    }

    /// Creates a catalog with explicit ceilings. A zero ceiling refuses the corresponding writes.
    #[must_use]
    pub const fn with_limits(limits: ReferenceHydrationLimits) -> Self {
        Self {
            descriptors: BTreeMap::new(),
            current: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            issued_cursors: BTreeMap::new(),
            limits,
            stored_payload_bytes: 0,
        }
    }

    /// Returns the configured storage ceilings.
    #[must_use]
    pub const fn limits(&self) -> ReferenceHydrationLimits {
        self.limits
    }

    /// Returns retained artifact payload bytes, excluding metadata and allocator overhead.
    #[must_use]
    pub const fn stored_payload_bytes(&self) -> usize {
        self.stored_payload_bytes
    }

    /// Returns the issuance record for an exact cursor digest, when issued by this catalog.
    #[must_use]
    pub fn issued_cursor(&self, cursor_digest: &ContentDigest) -> Option<&IssuedCursorRecord> {
        self.issued_cursors.get(cursor_digest)
    }

    /// Returns the number of active cursor issuance records retained by this catalog.
    #[must_use]
    pub fn issued_cursor_count(&self) -> usize {
        self.issued_cursors.len()
    }

    /// Prunes expired cursor issuance records whose retention lease has lapsed.
    pub fn prune_expired_cursors(&mut self, now: TimestampNs) {
        self.issued_cursors
            .retain(|_, record| now < record.expires_at);
    }

    /// Prunes consumed cursor issuance records to reclaim cursor capacity.
    pub fn prune_consumed_cursors(&mut self) {
        self.issued_cursors.retain(|_, record| !record.consumed);
    }

    /// Registers an exact revision without allowing rollback, equal-anchor forks, or resurrection.
    ///
    /// An exact retry is a no-op even after supersession; it never makes the old revision current.
    /// Changed descriptors require a strictly newer commit in the same ledger epoch and a
    /// nondecreasing publication time. Epoch changes require rebuilding the reference catalog.
    pub fn register_descriptor(
        &mut self,
        descriptor: SemanticHandle,
    ) -> Result<(), HydrationError> {
        descriptor.verify()?;
        let key = (descriptor.handle_id.clone(), descriptor.descriptor_digest);
        match self.descriptors.get(&key) {
            Some(existing) if existing == &descriptor => return Ok(()),
            Some(_) => return Err(ContractError::DigestMismatch.into()),
            None => {}
        }
        if let Some(existing) = self.current_descriptor(&descriptor.handle_id) {
            if existing.identity_digest() != descriptor.identity_digest() {
                return Err(HydrationError::HandleRebound);
            }
            if existing.anchor.site_lineage != descriptor.anchor.site_lineage
                || existing.anchor.ledger_epoch != descriptor.anchor.ledger_epoch
            {
                return Err(ContractError::GenerationConflict.into());
            }
            if descriptor.anchor.commit_sequence <= existing.anchor.commit_sequence
                || descriptor.published_at < existing.published_at
            {
                return Err(ContractError::StaleAnchor.into());
            }
            let prior = existing.availability_at(descriptor.published_at);
            if (prior == HandleAvailability::Deleted
                && descriptor.availability != HandleAvailability::Deleted)
                || (prior == HandleAvailability::Expired
                    && !matches!(
                        descriptor.availability,
                        HandleAvailability::Expired | HandleAvailability::Deleted
                    ))
            {
                return Err(ContractError::GenerationConflict.into());
            }
        }
        if self.descriptors.len() >= self.limits.max_descriptors {
            return Err(HydrationError::BudgetExceeded);
        }
        let handle_id = descriptor.handle_id.clone();
        let digest = descriptor.descriptor_digest;
        self.descriptors.insert(key, descriptor);
        self.current.insert(handle_id, digest);
        Ok(())
    }

    /// Registers an exact subject- and transform-bound artifact under the current descriptor.
    ///
    /// Duplicate registration does not consume capacity twice. Rejected writes leave both the
    /// catalog and its payload accounting unchanged.
    pub fn register_artifact(
        &mut self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
        artifact: HydrationArtifact,
    ) -> Result<(), HydrationError> {
        artifact.verify()?;
        let descriptor = self.current_exact(handle_id, descriptor_digest)?;
        if !descriptor.levels.contains(&artifact.level)
            || !artifact.proof_roots.contains(&descriptor.subject_digest)
            || artifact.applied_transform != descriptor.applied_transform
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let key = (handle_id.to_owned(), descriptor_digest, artifact.level);
        match self.artifacts.get(&key) {
            Some(existing) if existing == &artifact => return Ok(()),
            Some(_) => return Err(ContractError::DigestMismatch.into()),
            None => {}
        }
        let new_bytes = self
            .stored_payload_bytes
            .checked_add(artifact.payload.len())
            .ok_or(HydrationError::BudgetExceeded)?;
        if new_bytes > self.limits.max_payload_bytes {
            return Err(HydrationError::BudgetExceeded);
        }
        self.artifacts.insert(key, artifact);
        self.stored_payload_bytes = new_bytes;
        Ok(())
    }

    /// Resolves historical metadata only; this lookup does not authorize serving its payload.
    #[must_use]
    pub fn descriptor(
        &self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
    ) -> Option<&SemanticHandle> {
        self.descriptors
            .get(&(handle_id.to_owned(), descriptor_digest))
    }

    /// Resolves the current immutable descriptor revision without retargeting an exact request.
    #[must_use]
    pub fn current_descriptor(&self, handle_id: &str) -> Option<&SemanticHandle> {
        self.current
            .get(handle_id)
            .and_then(|digest| self.descriptor(handle_id, *digest))
    }

    /// Hydrates the richest permitted level, revalidating policy and availability at service time.
    ///
    /// Replays are deterministic for the same request, catalog, and service time. A retry at a
    /// later time is revalidated rather than replaying cached disclosure past retention expiry.
    pub fn hydrate(
        &mut self,
        request: &HydrationRequest,
        now: TimestampNs,
    ) -> Result<HydrationResponse, HydrationError> {
        request.verify()?;
        let descriptor = self
            .current_exact(&request.handle_id, request.expected_descriptor_digest)?
            .clone();
        request.validate_for(&descriptor, now)?;
        let availability = descriptor.availability_at(now);
        if availability != HandleAvailability::Available {
            return unavailable_response(request, &descriptor, availability, now);
        }
        let prior_record = if let Some(cursor) = &request.continuation {
            let record = self
                .issued_cursors
                .get(&cursor.cursor_digest)
                .ok_or(HydrationError::ContinuationUnissued)?
                .clone();
            if record.consumed {
                return Err(HydrationError::ContinuationAlreadyConsumed);
            }
            if record.session_id != request.session_id {
                return Err(HydrationError::ContinuationCrossSession);
            }
            if record.handle_id != descriptor.handle_id {
                return Err(HydrationError::WrongContinuation);
            }
            if now >= record.expires_at {
                return Err(HydrationError::ContinuationExpired);
            }
            let ordinal =
                u8::try_from(cursor.position).map_err(|_| HydrationError::WrongContinuation)?;
            if ordinal != record.next_ordinal {
                return Err(HydrationError::WrongContinuation);
            }
            let prior_level = ordinal
                .checked_sub(1)
                .and_then(HydrationLevel::from_ordinal)
                .ok_or(HydrationError::WrongContinuation)?;
            let prior = self
                .artifacts
                .get(&(
                    descriptor.handle_id.clone(),
                    descriptor.descriptor_digest,
                    prior_level,
                ))
                .ok_or(HydrationError::WrongContinuation)?;
            prior.verify()?;
            if cursor.selection_witness != prior.artifact_digest {
                return Err(HydrationError::WrongContinuation);
            }
            Some(record)
        } else {
            None
        };
        let minimum = if request.allow_lower_level {
            0
        } else {
            request.requested_level.ordinal()
        };
        let mut first_failure = None;
        for ordinal in (minimum..=request.requested_level.ordinal()).rev() {
            let level =
                HydrationLevel::from_ordinal(ordinal).ok_or(HydrationError::LevelUnavailable)?;
            let key = (
                descriptor.handle_id.clone(),
                descriptor.descriptor_digest,
                level,
            );
            let Some(artifact) = self.artifacts.get(&key).cloned() else {
                first_failure.get_or_insert(HydrationError::LevelUnavailable);
                continue;
            };
            let cost = match request.validate_delivery(&descriptor, &artifact, now) {
                Ok(cost) => cost,
                Err(
                    error @ (HydrationError::LevelUnavailable
                    | HydrationError::CapabilityDenied
                    | HydrationError::LaboratoryGrantRequired
                    | HydrationError::BudgetExceeded),
                ) => {
                    first_failure.get_or_insert(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let continuation =
                self.next_cursor(request, &descriptor, &artifact, prior_record.as_ref(), now)?;
            let mut proof_roots = artifact.proof_roots.clone();
            proof_roots.extend([
                artifact.artifact_digest,
                descriptor.subject_digest,
                descriptor.descriptor_digest,
                request.request_digest,
            ]);
            let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
                request_digest: request.request_digest,
                handle_id: descriptor.handle_id.clone(),
                descriptor_digest: descriptor.descriptor_digest,
                subject_digest: descriptor.subject_digest,
                anchor: descriptor.anchor.clone(),
                requested_level: request.requested_level,
                delivered_level: Some(level),
                availability,
                cost,
                completeness: artifact.completeness_for(request.requested_level),
                artifact_digest: Some(artifact.artifact_digest),
                proof_roots,
                continuation: continuation.clone(),
                invalidators: invalidators(&descriptor, Some(level), request.requested_level),
                issued_at: now,
            })?;
            let response = HydrationResponse {
                artifact: Some(artifact),
                receipt,
            };
            response.validate_for(request, &descriptor)?;
            if let Some(cursor) = &request.continuation
                && let Some(record) = self.issued_cursors.get_mut(&cursor.cursor_digest)
            {
                record.consumed = true;
            }
            if let Some(cursor) = &continuation {
                let next_ordinal =
                    u8::try_from(cursor.position).map_err(|_| HydrationError::WrongContinuation)?;
                if self.issued_cursors.len() >= self.limits.max_issued_cursors {
                    self.prune_expired_cursors(now);
                }
                if self.issued_cursors.len() >= self.limits.max_issued_cursors {
                    self.prune_consumed_cursors();
                }
                if self.issued_cursors.len() >= self.limits.max_issued_cursors {
                    if let Some(prior_cursor) = &request.continuation
                        && let Some(record) =
                            self.issued_cursors.get_mut(&prior_cursor.cursor_digest)
                    {
                        record.consumed = false;
                    }
                    return Err(HydrationError::CapacityExceeded);
                }
                self.issued_cursors.insert(
                    cursor.cursor_digest,
                    IssuedCursorRecord {
                        cursor_digest: cursor.cursor_digest,
                        session_id: request.session_id.clone(),
                        handle_id: descriptor.handle_id.clone(),
                        expires_at: cursor.expires_at,
                        next_ordinal,
                        consumed: false,
                    },
                );
            }
            return Ok(response);
        }
        Err(first_failure.unwrap_or(HydrationError::LevelUnavailable))
    }

    fn current_exact(
        &self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
    ) -> Result<&SemanticHandle, HydrationError> {
        let descriptor = self
            .descriptor(handle_id, descriptor_digest)
            .ok_or(HydrationError::DescriptorNotFound)?;
        if self.current.get(handle_id) != Some(&descriptor_digest) {
            return Err(ContractError::StaleAnchor.into());
        }
        Ok(descriptor)
    }

    fn next_cursor(
        &self,
        request: &HydrationRequest,
        descriptor: &SemanticHandle,
        artifact: &HydrationArtifact,
        prior_record: Option<&IssuedCursorRecord>,
        now: TimestampNs,
    ) -> Result<Option<ContinuationCursor>, HydrationError> {
        let Some(next) = artifact.level.successor() else {
            return Ok(None);
        };
        let maximum = descriptor
            .maximum_level()
            .ok_or(HydrationError::LevelUnavailable)?;
        if next > maximum
            || !self.artifacts.contains_key(&(
                descriptor.handle_id.clone(),
                descriptor.descriptor_digest,
                next,
            ))
        {
            return Ok(None);
        }
        let predecessor = request
            .continuation
            .as_ref()
            .map(|prior| prior.cursor_digest);
        let expiry = prior_record.map_or(descriptor.retention_until, |record| {
            record.expires_at.min(descriptor.retention_until)
        });
        Ok(Some(ContinuationCursor::publish(
            ContinuationCursorPublishParams {
                scope: ContinuationScope::EvidenceHydration,
                stream_id: descriptor.handle_id.clone(),
                contract_basis: descriptor.contract_basis.clone(),
                session_id: request.session_id.clone(),
                view_id: HYDRATION_VIEW_ID.to_owned(),
                basis_anchor: descriptor.anchor.clone(),
                resume_anchor: descriptor.anchor.clone(),
                source_digest: descriptor.ladder_policy_digest(),
                position: u64::from(next.ordinal()),
                upper_bound: u64::from(maximum.ordinal()) + 1,
                selection_witness: artifact.artifact_digest,
                predecessor_digest: predecessor,
                issued_at: now,
                expires_at: expiry,
            },
        )?))
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
            request.request_digest,
        ]),
        continuation: None,
        invalidators: invalidators(descriptor, None, request.requested_level),
        issued_at: now,
    })?;
    let response = HydrationResponse {
        artifact: None,
        receipt,
    };
    response.validate_for(request, descriptor)?;
    Ok(response)
}

fn invalidators(
    descriptor: &SemanticHandle,
    delivered: Option<HydrationLevel>,
    requested: HydrationLevel,
) -> BTreeSet<String> {
    let mut values = BTreeSet::from([
        format!("descriptor:{}", descriptor.descriptor_digest),
        format!("subject:{}", descriptor.subject_digest),
        format!("retention:until:{}", descriptor.retention_until.0),
        format!("privacy-class:{}", descriptor.privacy_class),
    ]);
    if let Some(delivered) = delivered
        && delivered != requested
    {
        values.insert(format!(
            "explicit-downgrade:{}-to-{}",
            requested.as_str(),
            delivered.as_str()
        ));
    }
    values
}
