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

    /// Publishes a request for an exact expansion slot in a session's context pack.
    ///
    /// The supplied identity fields must agree with the published binding; they are
    /// never rewritten to a newer descriptor or a different subject. Capability and
    /// privacy grants, budget, downgrade consent, and continuation remain caller-owned.
    /// This validates the request, not delivery: use the normal hydration service and
    /// receipt checks to enforce availability, per-level grants, and actual artifacts.
    pub fn publish_for_context_slot(
        spec: HydrationRequestSpec,
        pack: &crate::SemanticContextPack,
        receipt: &crate::SemanticCompressionReceipt,
        bindings: &crate::ContextExpansionBindingSet,
        slot_id: &str,
        handle: &SemanticHandle,
    ) -> Result<Self, crate::ContextBindingError> {
        let request = Self::publish(spec)?;
        request.validate_for_context_slot(
            pack,
            receipt,
            bindings,
            slot_id,
            handle,
            request.issued_at,
        )?;
        Ok(request)
    }

    /// Revalidates an expansion request against its exact context and descriptor.
    ///
    /// Call this at the service boundary with authoritative time, including on replay.
    /// A binding set is proof of what the pack offered, not a capability grant. The
    /// selected descriptor must still be supplied from an authority-owned catalog;
    /// verifying self-consistent digests alone does not authenticate its publisher.
    pub fn validate_for_context_slot(
        &self,
        pack: &crate::SemanticContextPack,
        receipt: &crate::SemanticCompressionReceipt,
        bindings: &crate::ContextExpansionBindingSet,
        slot_id: &str,
        handle: &SemanticHandle,
        now: TimestampNs,
    ) -> Result<(), crate::ContextBindingError> {
        bindings.validate_for(pack, receipt)?;
        let binding = bindings
            .binding_for_slot(slot_id)
            .ok_or_else(|| crate::ContextBindingError::MissingSlot(slot_id.to_owned()))?;
        binding.validate_for(handle)?;
        if self.session_id != pack.session_id {
            return Err(HydrationError::ContinuationCrossSession.into());
        }
        if self.contract_basis != pack.contract_basis {
            return Err(ContractError::GenerationConflict.into());
        }
        if self.issued_at < pack.created_at {
            return Err(ContractError::StaleAnchor.into());
        }
        if self.requested_level != binding.reference.hydration_level {
            return Err(HydrationError::LevelUnavailable.into());
        }
        self.validate_for(handle, now)?;
        Ok(())
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
        if self.available_capabilities.len() > MAX_REQUEST_SET_ITEMS
            || self.authorized_privacy_classes.len() > MAX_REQUEST_SET_ITEMS
        {
            return Err(HydrationError::CapacityExceeded);
        }
        if self.contract_basis.semantic_protocol != "fss/1"
            || !valid_text(&self.handle_id)
            || !self.budget.is_valid()
            || self
                .available_capabilities
                .iter()
                .any(|value| !valid_text(value))
            || self
                .authorized_privacy_classes
                .iter()
                .any(|value| !valid_text(value))
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        if let Some(cursor) = &self.continuation {
            if self.allow_lower_level {
                return Err(HydrationError::WrongContinuation);
            }
            cursor.validate_at(self.issued_at)?;
            if cursor.session_id != self.session_id {
                return Err(HydrationError::ContinuationCrossSession);
            }
            if cursor.scope != ContinuationScope::EvidenceHydration
                || cursor.stream_id != self.handle_id
                || cursor.contract_basis != self.contract_basis
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

#[cfg(test)]
mod context_slot_tests {
    use super::*;
    use crate::{
        CompressionCompleteness, CompressionLossClass, CompressionStopReason,
        CompressionTransform, CompressionTransformKind, ContextBindingError,
        ContextExpansionBinding, ContextExpansionBindingSet, ContextItem,
        ContractBasisRegistryBytes, CriticalPreservation, ExpansionHandle, KnowledgeState,
        MissionId, SemanticCompressionReceipt, SemanticContextPack,
        SemanticContextPackPublishParams,
    };
    use std::error::Error;

    type TestResult<T> = Result<T, Box<dyn Error>>;

    struct Fixture {
        pack: SemanticContextPack,
        receipt: SemanticCompressionReceipt,
        bindings: ContextExpansionBindingSet,
        handle: SemanticHandle,
        spec: HydrationRequestSpec,
    }

    impl Fixture {
        fn publish(&self, spec: HydrationRequestSpec) -> Result<HydrationRequest, ContextBindingError> {
            HydrationRequest::publish_for_context_slot(
                spec,
                &self.pack,
                &self.receipt,
                &self.bindings,
                "slot:evidence",
                &self.handle,
            )
        }
    }

    fn fixture() -> TestResult<Fixture> {
        let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "fss-context-request:test",
        ));
        let anchor = LedgerAnchor::genesis("site:context-request");
        let cost = BudgetVector::builder().tokens(128).bytes(1_024).build()?;
        let capabilities = BTreeSet::from(["capability:hydrate:h1".to_owned()]);
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis.clone(),
            anchor: anchor.clone(),
            subject_id: "evidence:context-request".to_owned(),
            subject_digest: ContentDigest::sha256(b"immutable evidence"),
            semantic_type: "evidence_bundle".to_owned(),
            source_id: "sensor:context-request".to_owned(),
            capture_interval: None,
            spatial_scope: None,
            privacy_class: "private:property".to_owned(),
            applied_transform: None,
            availability: HandleAvailability::Available,
            retention_until: TimestampNs(10_000),
            levels: BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1]),
            required_capabilities: BTreeMap::from([
                (HydrationLevel::H0, capabilities.clone()),
                (HydrationLevel::H1, capabilities.clone()),
            ]),
            estimated_costs: BTreeMap::from([
                (HydrationLevel::H0, cost),
                (HydrationLevel::H1, cost),
            ]),
            laboratory_access: LaboratoryAccess::Unavailable,
            debug_capability: None,
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        })?;
        let pack = SemanticContextPack::publish(SemanticContextPackPublishParams {
            pack_id: "context-pack:request".to_owned(),
            contract_basis: basis.clone(),
            mission_id: MissionId::parse("mission:context-request")?,
            session_id: SessionId::parse("session:context-request")?,
            view_id: "AVIEW-001".to_owned(),
            anchor: anchor.clone(),
            situation_fingerprint: ContentDigest::sha256(b"situation"),
            items: vec![ContextItem {
                item_id: "context:knowledge".to_owned(),
                kind: "knowledge".to_owned(),
                epistemic_state: KnowledgeState::Known,
                content: "A bounded evidence synopsis is available.".to_owned(),
                basis: BTreeSet::from(["claim:evidence".to_owned()]),
                expansion_handles: BTreeSet::from(["slot:evidence".to_owned()]),
            }],
            compression_receipt_id: "compression:context-request".to_owned(),
            continuation: Some("continuation:context-request".to_owned()),
            created_at: TimestampNs(2),
        })?;
        let receipt = SemanticCompressionReceipt {
            receipt_id: "compression:context-request".to_owned(),
            source_anchor: anchor.clone(),
            view_id: pack.view_id.clone(),
            target_tokens: pack.token_count + 1_024,
            selected_classes: BTreeSet::from(["knowledge".to_owned()]),
            omitted_classes: BTreeSet::from(["knowledge".to_owned()]),
            transforms: vec![CompressionTransform {
                kind: CompressionTransformKind::Select,
                scope: "knowledge".to_owned(),
                loss_class: CompressionLossClass::BoundedLoss,
                details: Some("Omitted detail is available through its exact slot.".to_owned()),
            }],
            completeness: vec![CompressionCompleteness {
                domain: "knowledge".to_owned(),
                state: Completeness::Bounded,
                omitted_count: 1,
            }],
            critical_preservation: CriticalPreservation {
                known_critical_items: 0,
                omitted_critical_items: 0,
                omitted_invalidations: 0,
                omitted_contradictions: 0,
            },
            actual_tokens: pack.token_count,
            actual_bytes: pack.encoded_bytes(),
            expansion_handles: vec![ExpansionHandle {
                handle: "slot:evidence".to_owned(),
                purpose: "Hydrate exact evidence.".to_owned(),
                estimated_cost: cost,
            }],
            selection_frontier_digest: Some(ContentDigest::sha256(b"frontier")),
            stop_reason: CompressionStopReason::TargetBudget,
            output_digest: pack.pack_digest,
        };
        let bindings = ContextExpansionBindingSet::publish(
            &pack,
            &receipt,
            vec![ContextExpansionBinding::publish(
                "slot:evidence", &handle, HydrationLevel::H1, "Hydrate exact evidence.",
            )?],
        )?;
        let spec = HydrationRequestSpec {
            contract_basis: basis,
            session_id: pack.session_id.clone(),
            handle_id: handle.handle_id.clone(),
            expected_descriptor_digest: handle.descriptor_digest,
            expected_subject_digest: handle.subject_digest,
            anchor,
            requested_level: HydrationLevel::H1,
            allow_lower_level: false,
            available_capabilities: capabilities,
            authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
            budget: cost,
            purpose: HydrationPurpose::IncidentAdjudication,
            continuation: None,
            issued_at: TimestampNs(20),
        };
        Ok(Fixture { pack, receipt, bindings, handle, spec })
    }

    #[test]
    fn exact_slot_uses_existing_request_identity_and_replays_deterministically() -> TestResult<()> {
        let fixture = fixture()?;
        let request = fixture.publish(fixture.spec.clone())?;
        assert_eq!(request, HydrationRequest::publish(fixture.spec.clone())?);
        assert_eq!(request, fixture.publish(fixture.spec.clone())?);
        request.validate_for_context_slot(
            &fixture.pack, &fixture.receipt, &fixture.bindings, "slot:evidence",
            &fixture.handle, TimestampNs(21),
        )?;
        Ok(())
    }

    #[test]
    fn another_session_cannot_expand_the_pack() -> TestResult<()> {
        let fixture = fixture()?;
        let mut spec = fixture.spec.clone();
        spec.session_id = SessionId::parse("session:other")?;
        assert_eq!(
            fixture.publish(spec),
            Err(ContextBindingError::Hydration(HydrationError::ContinuationCrossSession)),
        );
        Ok(())
    }

    #[test]
    fn wrong_subject_descriptor_and_anchor_are_not_silently_rebound() -> TestResult<()> {
        let fixture = fixture()?;
        for field in 0..3 {
            let mut spec = fixture.spec.clone();
            match field {
                0 => spec.expected_subject_digest = ContentDigest::sha256(b"other subject"),
                1 => spec.expected_descriptor_digest = ContentDigest::sha256(b"new descriptor"),
                _ => spec.anchor.commit_sequence += 1,
            }
            assert!(fixture.publish(spec).is_err());
        }
        Ok(())
    }

    #[test]
    fn wrong_basis_level_and_prepublication_time_are_rejected() -> TestResult<()> {
        let fixture = fixture()?;
        for field in 0..3 {
            let mut spec = fixture.spec.clone();
            match field {
                0 => spec.contract_basis = ContractBasis::from_registry_bytes(
                    ContractBasisRegistryBytes::new(
                        b"other schemas", b"operations", b"views", b"capabilities",
                        b"errors", b"costs", "fss-context-request:test",
                    ),
                ),
                1 => spec.requested_level = HydrationLevel::H0,
                _ => spec.issued_at = TimestampNs(1),
            }
            assert!(fixture.publish(spec).is_err());
        }
        Ok(())
    }

    #[test]
    fn unknown_slot_and_tampered_binding_set_fail_closed() -> TestResult<()> {
        let mut fixture = fixture()?;
        assert_eq!(
            HydrationRequest::publish_for_context_slot(
                fixture.spec.clone(), &fixture.pack, &fixture.receipt, &fixture.bindings,
                "slot:missing", &fixture.handle,
            ),
            Err(ContextBindingError::MissingSlot("slot:missing".to_owned())),
        );
        fixture.bindings.binding_set_digest = ContentDigest::sha256(b"tampered");
        assert!(fixture.publish(fixture.spec.clone()).is_err());
        Ok(())
    }

    #[test]
    fn context_binding_never_invents_capabilities_or_budget() -> TestResult<()> {
        let fixture = fixture()?;
        let mut spec = fixture.spec.clone();
        spec.available_capabilities.clear();
        spec.budget = BudgetVector::builder().tokens(1).bytes(1).build()?;
        spec.allow_lower_level = true;
        let request = fixture.publish(spec.clone())?;
        assert_eq!(request.available_capabilities, spec.available_capabilities);
        assert_eq!(request.authorized_privacy_classes, spec.authorized_privacy_classes);
        assert_eq!(request.budget, spec.budget);
        assert!(request.allow_lower_level);
        let artifact = HydrationArtifact::publish(
            HydrationLevel::H1, "application/fss+json", b"synopsis".to_vec(),
            [fixture.handle.subject_digest], Completeness::Complete, None,
        )?;
        assert_eq!(
            request.validate_delivery(&fixture.handle, &artifact, TimestampNs(21)),
            Err(HydrationError::CapabilityDenied),
        );
        Ok(())
    }

    #[test]
    fn privacy_denial_and_future_request_time_remain_enforced() -> TestResult<()> {
        let fixture = fixture()?;
        let mut spec = fixture.spec.clone();
        spec.authorized_privacy_classes.clear();
        assert_eq!(
            fixture.publish(spec),
            Err(ContextBindingError::Hydration(HydrationError::PrivacyDenied)),
        );
        let request = fixture.publish(fixture.spec.clone())?;
        assert!(request.validate_for_context_slot(
            &fixture.pack, &fixture.receipt, &fixture.bindings, "slot:evidence",
            &fixture.handle, TimestampNs(19),
        ).is_err());
        Ok(())
    }
}
