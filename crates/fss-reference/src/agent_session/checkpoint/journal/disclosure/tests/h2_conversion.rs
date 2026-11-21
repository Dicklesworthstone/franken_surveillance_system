#![forbid(unsafe_code)]
//! Typed H2 conversion through the actual catalog and durable disclosure owner.

use super::*;
use fss_core::{
    DecisionArtifactKind, GraphNeighborhoodArtifact, H2DecisionArtifact, RedactionTransform,
    RetainedProvenance,
};

const QUERY_CAPABILITY: &str = "CAP-AGENT-QUERY-001";
const HYDRATE_CAPABILITY: &str = "CAP-AGENT-EVIDENCE-HYDRATE-001";
const DECISION_PAYLOAD: &[u8] = b"bounded redacted graph: 3 nodes, 2 support-incidence arcs";

struct DecisionFixture {
    directory: Directory,
    params: AgentSessionParams,
    handle: SemanticHandle,
    typed: H2DecisionArtifact,
    blueprint: ReferenceHydrationCatalog,
    alias: SessionAlias,
    _objects: InMemoryObjectStore,
}

impl DecisionFixture {
    fn new() -> TestResult<(Self, DurableDisclosureStore)> {
        let directory = Directory::new()?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(16, 65_536));
        let subject = objects.put_verified(b"retained event revision for H2 conversion")?;
        let provenance = objects
            .publish_manifest(ObjectManifest::new("event-revision", [], Some(subject))?)?
            .root;
        let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s",
            b"o",
            b"v",
            b"c",
            b"e",
            b"cost",
            "h2-conversion:test",
        ));
        let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
        let quote = BudgetVector::builder()
            .bytes(65_536)
            .tokens(32_000)
            .build()?;
        let capabilities =
            BTreeSet::from([QUERY_CAPABILITY.to_owned(), HYDRATE_CAPABILITY.to_owned()]);
        let transform = RedactionTransform::GraphNeighborhoodRedact
            .as_str()
            .to_owned();
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis.clone(),
            anchor: LedgerAnchor::genesis("site:h2-conversion"),
            subject_id: "event:h2-conversion".to_owned(),
            subject_digest: subject,
            semantic_type: "event_revision".to_owned(),
            source_id: "sensor:h2-conversion".to_owned(),
            capture_interval: None,
            spatial_scope: None,
            privacy_class: "private:property".to_owned(),
            applied_transform: Some(transform.clone()),
            availability: HandleAvailability::Available,
            retention_until: TimestampNs(100),
            required_capabilities: levels
                .iter()
                .map(|level| (*level, capabilities.clone()))
                .collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
            levels,
            laboratory_access: LaboratoryAccess::Unavailable,
            debug_capability: None,
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        })?;
        let typed = handle.to_h2_decision_artifact(
            DecisionArtifactKind::GraphNeighborhood(GraphNeighborhoodArtifact::new(
                "event:h2-conversion",
                2,
                3,
                2,
                ContentDigest::sha256(b"bounded synthetic support-incidence graph"),
                BTreeSet::from(["raw_media_bytes".to_owned()]),
            )?),
            DECISION_PAYLOAD.to_vec(),
            RetainedProvenance::new([provenance])?,
            transform.clone(),
            "grant:h2-conversion-fixture",
            Completeness::Complete,
        )?;
        let mut blueprint = ReferenceHydrationCatalog::new();
        blueprint.register_descriptor(handle.clone())?;
        blueprint.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            HydrationArtifact::publish_h0_identity(&handle)?,
        )?;
        blueprint.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            HydrationArtifact::publish(
                HydrationLevel::H1,
                "text/plain",
                b"Synthetic retained graph metadata; physical presence remains unknown".to_vec(),
                [subject, provenance],
                Completeness::Complete,
                Some(transform),
            )?,
        )?;
        let universal = typed.to_hydration_artifact()?;
        let before = blueprint.stored_payload_bytes();
        // Reconstruct the old producer bug: a typed H2 seal is invalid in the universal domain.
        let mut wrong_domain = universal.clone();
        wrong_domain.artifact_digest = typed.artifact_digest();
        assert_eq!(
            blueprint.register_artifact(&handle.handle_id, handle.descriptor_digest, wrong_domain,),
            Err(HydrationError::Contract(
                fss_core::ContractError::DigestMismatch
            ))
        );
        assert_eq!(blueprint.stored_payload_bytes(), before);
        blueprint.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            universal.clone(),
        )?;
        let after = blueprint.stored_payload_bytes();
        assert_eq!(after, before + DECISION_PAYLOAD.len());
        blueprint.register_artifact(&handle.handle_id, handle.descriptor_digest, universal)?;
        assert_eq!(blueprint.stored_payload_bytes(), after);

        let params = AgentSessionParams {
            session_id: SessionId::parse("session:h2-conversion")?,
            mission_id: MissionId::parse("mission:h2-conversion")?,
            principal_id: PrincipalId::parse("principal:h2-conversion")?,
            capabilities,
            privacy_scope: BTreeSet::from([handle.privacy_class.clone()]),
            current_anchor: handle.anchor.clone(),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 100_000,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 1_000,
        };
        let mut owner = DurableDisclosureStore::create(
            directory.0.join("sessions.journal"),
            DurableSessionLimits::default(),
            blueprint.clone(),
        )?;
        owner.open_session(params.clone(), basis, TimestampNs(10))?;
        let alias = owner.bind(
            &params.principal_id,
            &SessionBindingRequest {
                session_id: params.session_id.clone(),
                generation: 0,
                handle_id: handle.handle_id.clone(),
                descriptor_digest: handle.descriptor_digest,
            },
            TimestampNs(10),
        )?;
        Ok((
            Self {
                directory,
                params,
                handle,
                typed,
                blueprint,
                alias,
                _objects: objects,
            },
            owner,
        ))
    }

    fn path(&self) -> PathBuf {
        self.directory.0.join("sessions.journal")
    }

    fn request(&self, level: HydrationLevel) -> TestResult<HydrationRequest> {
        Ok(HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: self.handle.contract_basis.clone(),
            session_id: self.params.session_id.clone(),
            handle_id: self.handle.handle_id.clone(),
            expected_descriptor_digest: self.handle.descriptor_digest,
            expected_subject_digest: self.handle.subject_digest,
            anchor: self.handle.anchor.clone(),
            requested_level: level,
            allow_lower_level: false,
            available_capabilities: self.params.capabilities.clone(),
            authorized_privacy_classes: self.params.privacy_scope.clone(),
            budget: self.handle.estimated_cost(level).ok_or("quote missing")?,
            purpose: HydrationPurpose::Routine,
            continuation: None,
            issued_at: TimestampNs(10),
        })?)
    }

    fn remaining(&self, owner: &mut DurableDisclosureStore) -> TestResult<u64> {
        Ok(owner.remaining_token_budget(
            &self.params.principal_id,
            &self.params.session_id,
            TimestampNs(20),
        )?)
    }

    fn admission_count(
        &self,
        owner: &mut DurableDisclosureStore,
        request: &HydrationRequest,
        maximum: usize,
    ) -> TestResult<usize> {
        Ok(owner
            .admissions(
                &self.params.principal_id,
                &self.params.session_id,
                request.request_digest,
                maximum,
                TimestampNs(20),
            )?
            .len())
    }
}

#[test]
fn typed_h2_catalog_delivery_and_direct_retry_retain_exact_charges_across_restart() -> TestResult {
    let (fixture, mut owner) = DecisionFixture::new()?;
    let typed_bytes = fixture.typed.to_canonical_bytes()?;
    let typed_digest = fixture.typed.artifact_digest();
    let universal = fixture.typed.to_hydration_artifact()?;
    let request = fixture.request(HydrationLevel::H2)?;
    let first = owner.hydrate(
        &fixture.params.principal_id,
        &fixture.alias,
        &request,
        TimestampNs(20),
    )?;
    first.response.validate_for(&request, &fixture.handle)?;
    assert_eq!(first.response.artifact, Some(universal.clone()));
    assert_eq!(
        first.response.receipt.artifact_digest,
        Some(universal.artifact_digest)
    );
    assert_eq!(first.admission.charged_tokens(), 32_000);
    assert_eq!(first.response.receipt.continuation, None);
    assert_eq!(fixture.remaining(&mut owner)?, 68_000);
    let root = owner.committed_root();
    drop(owner);

    let mut owner = DurableDisclosureStore::open_existing(
        fixture.path(),
        root,
        DurableSessionLimits::default(),
        fixture.blueprint.clone(),
    )?;
    assert_eq!(fixture.remaining(&mut owner)?, 68_000);
    // Direct repetition is another disclosure, never a refund or free cached response.
    let second = owner.hydrate(
        &fixture.params.principal_id,
        &fixture.alias,
        &request,
        TimestampNs(20),
    )?;
    assert_eq!(second.response.artifact, Some(universal));
    assert_eq!(second.admission.charged_tokens(), 32_000);
    assert_eq!(fixture.remaining(&mut owner)?, 36_000);
    assert_eq!(fixture.admission_count(&mut owner, &request, 2)?, 2);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        fixture.path(),
        root,
        DurableSessionLimits::default(),
        fixture.blueprint.clone(),
    )?;
    assert_eq!(fixture.remaining(&mut owner)?, 36_000);
    assert_eq!(fixture.admission_count(&mut owner, &request, 2)?, 2);
    assert_eq!(fixture.typed.artifact_digest(), typed_digest);
    assert_eq!(fixture.typed.to_canonical_bytes()?, typed_bytes);
    let journal = std::fs::read(fixture.path())?;
    assert!(
        !journal
            .windows(DECISION_PAYLOAD.len())
            .any(|bytes| bytes == DECISION_PAYLOAD)
    );
    Ok(())
}

#[test]
fn typed_h2_consumed_continuation_stays_consumed_after_catalog_rebuild() -> TestResult {
    let (fixture, mut owner) = DecisionFixture::new()?;
    let synopsis_request = fixture.request(HydrationLevel::H1)?;
    let first = owner.hydrate(
        &fixture.params.principal_id,
        &fixture.alias,
        &synopsis_request,
        TimestampNs(20),
    )?;
    let cursor = first
        .response
        .receipt
        .continuation
        .ok_or("H2 cursor missing")?;
    let mut request = fixture.request(HydrationLevel::H2)?;
    request.continuation = Some(cursor.clone());
    request.issued_at = TimestampNs(20);
    reseal(&mut request);
    owner.hydrate(
        &fixture.params.principal_id,
        &fixture.alias,
        &request,
        TimestampNs(20),
    )?;
    assert_eq!(fixture.remaining(&mut owner)?, 36_000);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        fixture.path(),
        root,
        DurableSessionLimits::default(),
        fixture.blueprint.clone(),
    )?;
    let stable = std::fs::read(fixture.path())?;
    assert!(matches!(
        owner.hydrate(
            &fixture.params.principal_id,
            &fixture.alias,
            &request,
            TimestampNs(20),
        ),
        Err(DisclosureError::Session(ReferenceSessionError::Hydration(
            HydrationError::ContinuationAlreadyConsumed
        )))
    ));
    assert_eq!(fixture.remaining(&mut owner)?, 36_000);
    assert_eq!(
        fixture.admission_count(&mut owner, &synopsis_request, 1)?,
        1
    );
    assert_eq!(fixture.admission_count(&mut owner, &request, 1)?, 1);
    assert_eq!(owner.committed_root(), root);
    assert_eq!(std::fs::read(fixture.path())?, stable);
    assert!(
        owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("cursor missing")?
            .consumed
    );
    Ok(())
}
