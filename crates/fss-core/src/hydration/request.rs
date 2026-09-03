use super::*;

/// Inputs used to publish one exact hydration request.
#[derive(Clone, Debug, PartialEq)]
pub struct HydrationRequestSpec {
    /// Exact semantic contract universe expected by the caller.
    pub contract_basis: ContractBasis,
    /// Session receiving the hydrated material.
    pub session_id: SessionId,
    /// Stable handle identity.
    pub handle_id: String,
    /// Exact descriptor revision expected by the caller.
    pub expected_descriptor_digest: ContentDigest,
    /// Exact immutable subject digest expected by the caller.
    pub expected_subject_digest: ContentDigest,
    /// Authority anchor expected by the caller.
    pub anchor: LedgerAnchor,
    /// Richest level requested in this operation.
    pub requested_level: HydrationLevel,
    /// Whether an explicit lower level may be returned when the requested level is unavailable.
    pub allow_lower_level: bool,
    /// Capabilities delegated to this request.
    pub available_capabilities: BTreeSet<String>,
    /// Privacy classes delegated to this request.
    pub authorized_privacy_classes: BTreeSet<String>,
    /// Full resource ceiling for this operation.
    pub budget: BudgetVector,
    /// Declared purpose governing H4 access.
    pub purpose: HydrationPurpose,
    /// Exact prior continuation when progressively hydrating.
    pub continuation: Option<ContinuationCursor>,
    /// Deterministic request time.
    pub issued_at: TimestampNs,
}

/// Exact, content-bound request for one semantic-handle hydration step.
#[derive(Clone, Debug, PartialEq)]
pub struct HydrationRequest {
    /// Content-derived request identity.
    pub request_id: String,
    /// Exact semantic contract universe expected by the caller.
    pub contract_basis: ContractBasis,
    /// Session receiving the hydrated material.
    pub session_id: SessionId,
    /// Stable handle identity.
    pub handle_id: String,
    /// Exact descriptor revision expected by the caller.
    pub expected_descriptor_digest: ContentDigest,
    /// Exact immutable subject digest expected by the caller.
    pub expected_subject_digest: ContentDigest,
    /// Authority anchor expected by the caller.
    pub anchor: LedgerAnchor,
    /// Richest level requested in this operation.
    pub requested_level: HydrationLevel,
    /// Whether an explicit lower level may be returned when the requested level is unavailable.
    pub allow_lower_level: bool,
    /// Capabilities delegated to this request.
    pub available_capabilities: BTreeSet<String>,
    /// Privacy classes delegated to this request.
    pub authorized_privacy_classes: BTreeSet<String>,
    /// Full resource ceiling for this operation.
    pub budget: BudgetVector,
    /// Declared purpose governing H4 access.
    pub purpose: HydrationPurpose,
    /// Exact prior continuation when progressively hydrating.
    pub continuation: Option<ContinuationCursor>,
    /// Deterministic request time.
    pub issued_at: TimestampNs,
    /// Digest of the complete request body.
    pub request_digest: ContentDigest,
}

impl HydrationRequest {
    /// Publishes and validates one exact request.
    pub fn publish(spec: HydrationRequestSpec) -> Result<Self, HydrationError> {
        let mut request = Self {
            request_id: String::new(),
            contract_basis: spec.contract_basis,
            session_id: spec.session_id,
            handle_id: spec.handle_id,
            expected_descriptor_digest: spec.expected_descriptor_digest,
            expected_subject_digest: spec.expected_subject_digest,
            anchor: spec.anchor,
            requested_level: spec.requested_level,
            allow_lower_level: spec.allow_lower_level,
            available_capabilities: spec.available_capabilities,
            authorized_privacy_classes: spec.authorized_privacy_classes,
            budget: spec.budget,
            purpose: spec.purpose,
            continuation: spec.continuation,
            issued_at: spec.issued_at,
            request_digest: ContentDigest::sha256(b"unpublished-hydration-request"),
        };
        request.validate_body()?;
        request.request_digest = request.computed_digest();
        request.request_id = format!("hydration-request:{}", request.request_digest);
        Ok(request)
    }

    /// Recomputes the request body digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies content identity and continuation integrity.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate_body()?;
        if self.request_digest != self.computed_digest()
            || self.request_id != format!("hydration-request:{}", self.request_digest)
        {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), HydrationError> {
        if self.contract_basis.semantic_protocol != "fss/1"
            || !valid_text(&self.handle_id)
            || !self.budget.is_valid()
            || self.available_capabilities.iter().any(|value| !valid_text(value))
            || self.authorized_privacy_classes.iter().any(|value| !valid_text(value))
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        if let Some(cursor) = &self.continuation {
            cursor.validate_at(self.issued_at)?;
            if cursor.scope != ContinuationScope::EvidenceHydration
                || cursor.stream_id != self.handle_id
                || cursor.contract_basis != self.contract_basis
                || cursor.session_id != self.session_id
                || cursor.view_id != HYDRATION_VIEW_ID
                || cursor.basis_anchor != self.anchor
                || cursor.resume_anchor != self.anchor
                || cursor.position != u64::from(self.requested_level.ordinal())
            {
                return Err(HydrationError::WrongContinuation);
            }
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_hydration_request.v1");
        self.contract_basis.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.handle_id);
        encoder.digest(self.expected_descriptor_digest);
        encoder.digest(self.expected_subject_digest);
        self.anchor.encode_canonical(encoder);
        self.requested_level.encode_canonical(encoder);
        encoder.bool(self.allow_lower_level);
        encode_text_set(&self.available_capabilities, encoder);
        encode_text_set(&self.authorized_privacy_classes, encoder);
        encode_budget(self.budget, encoder);
        self.purpose.encode_canonical(encoder);
        match &self.continuation {
            Some(cursor) => {
                encoder.bool(true);
                cursor.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.issued_at.encode_canonical(encoder);
    }
}

impl CanonicalEncode for HydrationRequest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.request_digest);
    }
}
