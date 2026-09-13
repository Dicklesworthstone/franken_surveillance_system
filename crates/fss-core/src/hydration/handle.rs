use super::*;

/// Inputs used to publish one versioned descriptor for an immutable semantic subject.
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticHandleSpec {
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Authority anchor of this descriptor revision.
    pub anchor: LedgerAnchor,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Digest of the exact subject bytes or canonical semantic object.
    pub subject_digest: ContentDigest,
    /// Registered semantic type.
    pub semantic_type: String,
    /// Stable source identity.
    pub source_id: String,
    /// Optional conservative capture interval.
    pub capture_interval: Option<CaptureInterval>,
    /// Optional spatial or graph scope.
    pub spatial_scope: Option<String>,
    /// Privacy class independently authorized at hydration time.
    pub privacy_class: String,
    /// Privacy or derivation transform already applied to this exact subject.
    pub applied_transform: Option<String>,
    /// Current availability of this exact subject.
    pub availability: HandleAvailability,
    /// Time after which this descriptor must return an expired state.
    pub retention_until: TimestampNs,
    /// Contiguous levels published for this subject.
    pub levels: BTreeSet<HydrationLevel>,
    /// Capability IDs required at each level.
    pub required_capabilities: BTreeMap<HydrationLevel, BTreeSet<String>>,
    /// Conservative full resource cost at each level.
    pub estimated_costs: BTreeMap<HydrationLevel, BudgetVector>,
    /// H4 access policy.
    pub laboratory_access: LaboratoryAccess,
    /// Capability required for debugging H4, when supported.
    pub debug_capability: Option<String>,
    /// Stable handles for derivative subjects, never replacement bindings.
    pub derivative_handles: BTreeSet<String>,
    /// Deterministic publication time.
    pub published_at: TimestampNs,
}

/// Stable semantic handle whose identity never rebinds across descriptor revisions.
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticHandle {
    /// Content-derived identity of the immutable subject.
    pub handle_id: String,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Authority anchor of this descriptor revision.
    pub anchor: LedgerAnchor,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Digest of the exact subject bytes or canonical semantic object.
    pub subject_digest: ContentDigest,
    /// Registered semantic type.
    pub semantic_type: String,
    /// Stable source identity.
    pub source_id: String,
    /// Optional conservative capture interval.
    pub capture_interval: Option<CaptureInterval>,
    /// Optional spatial or graph scope.
    pub spatial_scope: Option<String>,
    /// Privacy class independently authorized at hydration time.
    pub privacy_class: String,
    /// Privacy or derivation transform already applied to this exact subject.
    pub applied_transform: Option<String>,
    /// Current availability of this exact subject.
    pub availability: HandleAvailability,
    /// Time after which this descriptor must return an expired state.
    pub retention_until: TimestampNs,
    /// Contiguous levels published for this subject.
    pub levels: BTreeSet<HydrationLevel>,
    /// Capability IDs required at each level.
    pub required_capabilities: BTreeMap<HydrationLevel, BTreeSet<String>>,
    /// Conservative full resource cost at each level.
    pub estimated_costs: BTreeMap<HydrationLevel, BudgetVector>,
    /// H4 access policy.
    pub laboratory_access: LaboratoryAccess,
    /// Capability required for debugging H4, when supported.
    pub debug_capability: Option<String>,
    /// Stable handles for derivative subjects, never replacement bindings.
    pub derivative_handles: BTreeSet<String>,
    /// Deterministic publication time.
    pub published_at: TimestampNs,
    /// Digest of the complete descriptor revision.
    pub descriptor_digest: ContentDigest,
}

impl SemanticHandle {
    /// Publishes a validated descriptor while deriving its immutable handle identity.
    pub fn publish(spec: SemanticHandleSpec) -> Result<Self, HydrationError> {
        let mut handle = Self {
            handle_id: String::new(),
            contract_basis: spec.contract_basis,
            anchor: spec.anchor,
            subject_id: spec.subject_id,
            subject_digest: spec.subject_digest,
            semantic_type: spec.semantic_type,
            source_id: spec.source_id,
            capture_interval: spec.capture_interval,
            spatial_scope: spec.spatial_scope,
            privacy_class: spec.privacy_class,
            applied_transform: spec.applied_transform,
            availability: spec.availability,
            retention_until: spec.retention_until,
            levels: spec.levels,
            required_capabilities: spec.required_capabilities,
            estimated_costs: spec.estimated_costs,
            laboratory_access: spec.laboratory_access,
            debug_capability: spec.debug_capability,
            derivative_handles: spec.derivative_handles,
            published_at: spec.published_at,
            descriptor_digest: ContentDigest::sha256(b"unpublished-semantic-handle"),
        };
        handle.validate_body()?;
        handle.handle_id = format!("semantic-handle:{}", handle.identity_digest());
        handle.descriptor_digest = handle.computed_descriptor_digest();
        Ok(handle)
    }

    /// Recomputes the immutable identity core shared by every descriptor revision.
    #[must_use]
    pub fn identity_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.semantic_handle_identity.v1");
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        encoder.text(&self.semantic_type);
        encoder.text(&self.source_id);
        encode_optional_interval(self.capture_interval, &mut encoder);
        encode_optional_text(self.spatial_scope.as_deref(), &mut encoder);
        encode_optional_text(self.applied_transform.as_deref(), &mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Recomputes the complete descriptor digest with identity digests omitted.
    #[must_use]
    pub fn computed_descriptor_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_descriptor_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies stable identity and complete descriptor integrity.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate_body()?;
        if self.handle_id != format!("semantic-handle:{}", self.identity_digest()) {
            return Err(HydrationError::HandleRebound);
        }
        if self.descriptor_digest != self.computed_descriptor_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Returns the maximum published hydration level.
    #[must_use]
    pub fn maximum_level(&self) -> Option<HydrationLevel> {
        self.levels.last().copied()
    }

    /// Returns the conservative cost of one exact level.
    #[must_use]
    pub fn estimated_cost(&self, level: HydrationLevel) -> Option<BudgetVector> {
        self.estimated_costs.get(&level).copied()
    }

    /// Returns the exact capabilities required for one level.
    #[must_use]
    pub fn capabilities_for(&self, level: HydrationLevel) -> Option<&BTreeSet<String>> {
        self.required_capabilities.get(&level)
    }

    /// Returns a digest of the published ladder policy without artifact payloads.
    #[must_use]
    pub fn ladder_policy_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.semantic_handle_ladder_policy.v1");
        encoder.text(&self.handle_id);
        encoder.digest(self.descriptor_digest);
        encode_levels(&self.levels, &mut encoder);
        encode_capability_map(&self.required_capabilities, &mut encoder);
        encode_cost_map(&self.estimated_costs, &mut encoder);
        self.laboratory_access.encode_canonical(&mut encoder);
        encode_optional_text(self.debug_capability.as_deref(), &mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    fn validate_body(&self) -> Result<(), HydrationError> {
        if self.contract_basis.semantic_protocol != "fss/1"
            || !valid_text(&self.subject_id)
            || !valid_text(&self.semantic_type)
            || !valid_text(&self.source_id)
            || !valid_text(&self.privacy_class)
            || self
                .spatial_scope
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || self
                .applied_transform
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || self
                .debug_capability
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || self.retention_until <= self.published_at
            || self
                .derivative_handles
                .iter()
                .any(|value| !valid_text(value))
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        validate_contiguous_levels(&self.levels)?;
        if self
            .required_capabilities
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != self.levels
            || self
                .estimated_costs
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != self.levels
            || self
                .required_capabilities
                .values()
                .flatten()
                .any(|value| !valid_text(value))
            || self.estimated_costs.values().any(|cost| !cost.is_valid())
        {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        let has_h4 = self.levels.contains(&HydrationLevel::H4);
        match self.laboratory_access {
            LaboratoryAccess::Unavailable => {
                if has_h4 || self.debug_capability.is_some() {
                    return Err(HydrationError::LaboratoryGrantRequired);
                }
            }
            LaboratoryAccess::QualificationOnly => {
                if !has_h4 || self.debug_capability.is_some() {
                    return Err(HydrationError::LaboratoryGrantRequired);
                }
            }
            LaboratoryAccess::QualificationOrDebugGrant => {
                if !has_h4 || self.debug_capability.is_none() {
                    return Err(HydrationError::LaboratoryGrantRequired);
                }
            }
        }
        Ok(())
    }

    fn encode_descriptor_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_handle_descriptor.v1");
        encoder.text(&self.handle_id);
        self.contract_basis.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        encoder.text(&self.semantic_type);
        encoder.text(&self.source_id);
        encode_optional_interval(self.capture_interval, encoder);
        encode_optional_text(self.spatial_scope.as_deref(), encoder);
        encoder.text(&self.privacy_class);
        encode_optional_text(self.applied_transform.as_deref(), encoder);
        self.availability.encode_canonical(encoder);
        self.retention_until.encode_canonical(encoder);
        encode_levels(&self.levels, encoder);
        encode_capability_map(&self.required_capabilities, encoder);
        encode_cost_map(&self.estimated_costs, encoder);
        self.laboratory_access.encode_canonical(encoder);
        encode_optional_text(self.debug_capability.as_deref(), encoder);
        encode_text_set(&self.derivative_handles, encoder);
        self.published_at.encode_canonical(encoder);
    }
}

impl CanonicalEncode for SemanticHandle {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_descriptor_body(encoder);
        encoder.digest(self.descriptor_digest);
    }
}
