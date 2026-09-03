use super::*;

/// Inputs used to publish one hydration receipt.
#[derive(Clone, Debug, PartialEq)]
pub struct HydrationReceiptSpec {
    /// Exact request digest.
    pub request_digest: ContentDigest,
    /// Stable handle identity.
    pub handle_id: String,
    /// Exact descriptor digest.
    pub descriptor_digest: ContentDigest,
    /// Immutable subject digest.
    pub subject_digest: ContentDigest,
    /// Exact authority anchor.
    pub anchor: LedgerAnchor,
    /// Richest requested level.
    pub requested_level: HydrationLevel,
    /// Actual delivered level, absent for an unavailable subject.
    pub delivered_level: Option<HydrationLevel>,
    /// Availability observed for the exact subject.
    pub availability: HandleAvailability,
    /// Full resource cost charged by the reference operation.
    pub cost: BudgetVector,
    /// Completeness of the response.
    pub completeness: Completeness,
    /// Delivered artifact digest, when any.
    pub artifact_digest: Option<ContentDigest>,
    /// Retained proof roots.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Exact next progressive hydration cursor, when richer material remains.
    pub continuation: Option<ContinuationCursor>,
    /// Conditions that invalidate reuse of this receipt.
    pub invalidators: BTreeSet<String>,
    /// Deterministic publication time.
    pub issued_at: TimestampNs,
}

/// Proof-bearing outcome of one exact hydration request.
#[derive(Clone, Debug, PartialEq)]
pub struct HydrationReceipt {
    /// Content-derived receipt identity.
    pub receipt_id: String,
    /// Exact request digest.
    pub request_digest: ContentDigest,
    /// Stable handle identity.
    pub handle_id: String,
    /// Exact descriptor digest.
    pub descriptor_digest: ContentDigest,
    /// Immutable subject digest.
    pub subject_digest: ContentDigest,
    /// Exact authority anchor.
    pub anchor: LedgerAnchor,
    /// Richest requested level.
    pub requested_level: HydrationLevel,
    /// Actual delivered level, absent for an unavailable subject.
    pub delivered_level: Option<HydrationLevel>,
    /// Availability observed for the exact subject.
    pub availability: HandleAvailability,
    /// Full resource cost charged by the reference operation.
    pub cost: BudgetVector,
    /// Completeness of the response.
    pub completeness: Completeness,
    /// Delivered artifact digest, when any.
    pub artifact_digest: Option<ContentDigest>,
    /// Retained proof roots.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Exact next progressive hydration cursor, when richer material remains.
    pub continuation: Option<ContinuationCursor>,
    /// Conditions that invalidate reuse of this receipt.
    pub invalidators: BTreeSet<String>,
    /// Deterministic publication time.
    pub issued_at: TimestampNs,
    /// Digest of the complete receipt body.
    pub receipt_digest: ContentDigest,
}

impl HydrationReceipt {
    /// Publishes and seals one receipt.
    pub fn publish(spec: HydrationReceiptSpec) -> Result<Self, HydrationError> {
        let mut receipt = Self {
            receipt_id: String::new(),
            request_digest: spec.request_digest,
            handle_id: spec.handle_id,
            descriptor_digest: spec.descriptor_digest,
            subject_digest: spec.subject_digest,
            anchor: spec.anchor,
            requested_level: spec.requested_level,
            delivered_level: spec.delivered_level,
            availability: spec.availability,
            cost: spec.cost,
            completeness: spec.completeness,
            artifact_digest: spec.artifact_digest,
            proof_roots: spec.proof_roots,
            continuation: spec.continuation,
            invalidators: spec.invalidators,
            issued_at: spec.issued_at,
            receipt_digest: ContentDigest::sha256(b"unpublished-hydration-receipt"),
        };
        receipt.validate_body()?;
        receipt.receipt_digest = receipt.computed_digest();
        receipt.receipt_id = format!("hydration-receipt:{}", receipt.receipt_digest);
        Ok(receipt)
    }

    /// Recomputes the complete receipt digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Cross-checks this receipt against the exact request, handle descriptor, and artifact.
    pub fn validate_for(
        &self,
        request: &HydrationRequest,
        handle: &SemanticHandle,
        artifact: Option<&HydrationArtifact>,
    ) -> Result<(), HydrationError> {
        self.validate_body()?;
        request.verify()?;
        handle.verify()?;
        if self.receipt_digest != self.computed_digest()
            || self.receipt_id != format!("hydration-receipt:{}", self.receipt_digest)
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let effective_availability = if request.issued_at >= handle.retention_until {
            HandleAvailability::Expired
        } else {
            handle.availability
        };
        if self.request_digest != request.request_digest
            || self.handle_id != request.handle_id
            || self.handle_id != handle.handle_id
            || self.descriptor_digest != request.expected_descriptor_digest
            || self.descriptor_digest != handle.descriptor_digest
            || self.subject_digest != request.expected_subject_digest
            || self.subject_digest != handle.subject_digest
            || self.anchor != request.anchor
            || self.anchor != handle.anchor
            || self.requested_level != request.requested_level
            || self.availability != effective_availability
            || self.issued_at != request.issued_at
            || !self.cost.fits_within(request.budget)
        {
            return Err(ContractError::DigestMismatch.into());
        }
        match (
            self.availability,
            self.delivered_level,
            self.artifact_digest,
            artifact,
        ) {
            (HandleAvailability::Available, Some(level), Some(digest), Some(artifact)) => {
                artifact.verify()?;
                if level != artifact.level
                    || digest != artifact.artifact_digest
                    || level > request.requested_level
                    || !handle.levels.contains(&level)
                    || !self.proof_roots.contains(&artifact.payload_digest)
                    || !self.proof_roots.contains(&artifact.artifact_digest)
                {
                    return Err(ContractError::DigestMismatch.into());
                }
            }
            (HandleAvailability::Available, _, _, _) => {
                return Err(ContractError::EvidenceRequired.into());
            }
            (_, None, None, None) => {}
            _ => return Err(ContractError::EvidenceRequired.into()),
        }
        if let Some(cursor) = &self.continuation {
            cursor.validate_at(self.issued_at)?;
            let Some(delivered) = self.delivered_level else {
                return Err(ContractError::EvidenceRequired.into());
            };
            if cursor.scope != ContinuationScope::EvidenceHydration
                || cursor.stream_id != self.handle_id
                || cursor.contract_basis != request.contract_basis
                || cursor.session_id != request.session_id
                || cursor.view_id != HYDRATION_VIEW_ID
                || cursor.basis_anchor != self.anchor
                || cursor.resume_anchor != self.anchor
                || cursor.position != u64::from(delivered.ordinal()) + 1
            {
                return Err(HydrationError::WrongContinuation);
            }
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.handle_id)
            || !self.cost.is_valid()
            || self.invalidators.is_empty()
            || self.invalidators.iter().any(|value| !valid_text(value))
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        if self.availability == HandleAvailability::Available {
            if self.delivered_level.is_none()
                || self.artifact_digest.is_none()
                || self.proof_roots.is_empty()
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
        } else if self.delivered_level.is_some()
            || self.artifact_digest.is_some()
            || self.continuation.is_some()
            || self.cost != BudgetVector::default()
            || self.completeness != self.availability.unavailable_completeness()
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_hydration_receipt.v1");
        encoder.digest(self.request_digest);
        encoder.text(&self.handle_id);
        encoder.digest(self.descriptor_digest);
        encoder.digest(self.subject_digest);
        self.anchor.encode_canonical(encoder);
        self.requested_level.encode_canonical(encoder);
        match self.delivered_level {
            Some(level) => {
                encoder.bool(true);
                level.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.availability.encode_canonical(encoder);
        encode_budget(self.cost, encoder);
        encoder.u8(completeness_code(self.completeness));
        match self.artifact_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
        encode_digest_set(&self.proof_roots, encoder);
        match &self.continuation {
            Some(cursor) => {
                encoder.bool(true);
                cursor.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        encode_text_set(&self.invalidators, encoder);
        self.issued_at.encode_canonical(encoder);
    }
}

impl CanonicalEncode for HydrationReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.receipt_digest);
    }
}

/// Hydration payload and its proof-bearing receipt.
#[derive(Clone, Debug, PartialEq)]
pub struct HydrationResponse {
    /// Artifact delivered at the selected level, absent for an unavailable exact subject.
    pub artifact: Option<HydrationArtifact>,
    /// Exact operation receipt.
    pub receipt: HydrationReceipt,
}

impl HydrationResponse {
    /// Verifies the response against exact request and handle inputs.
    pub fn validate_for(
        &self,
        request: &HydrationRequest,
        handle: &SemanticHandle,
    ) -> Result<(), HydrationError> {
        self.receipt
            .validate_for(request, handle, self.artifact.as_ref())
    }
}
