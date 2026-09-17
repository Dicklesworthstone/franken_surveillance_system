#![forbid(unsafe_code)]
//! End-to-end publication -> session admission -> exact evidence delivery regressions.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose,
    LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    AgentSession, AgentSessionParams, BudgetVector, CapsuleId, CaptureInterval,
    Completeness, ContentDigest, ContextExpansionBindingSet, ContractBasis,
    ContractBasisRegistryBytes, ContractError, EventId, LedgerAnchor, MissionId,
    PrincipalId, ProbabilityInterval, ResourcePressure, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::agent_session::context_hydration::{
    BoundContextHydration, ContextHydrationError, ContextSlotRead,
};
use fss_reference::{
    BoundReferenceSituationPublication, ReferenceExpansionBindingSpec, ReferenceHydrationCatalog,
    ReferenceProjectionSpec, ReferenceSessionError, ReferenceSessionLimits, ReferenceSessionStore,
    ReferenceSituation, ReferenceSituationRequest, SessionRefresh, VirtualCameraSpec,
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceModelObservation,
    compile_reference_situation, evaluate_unknown_presence, execute_mock_model,
    project_reference_situation, publish_reference_event, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "fss-reference:context-slot-test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

struct RunDirectory(std::path::PathBuf);

impl RunDirectory {
    fn new() -> TestResult<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| option_env!("CARGO_TARGET_TMPDIR").map(std::path::PathBuf::from))
            .unwrap_or_else(std::env::temp_dir);
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = base.join(format!("fss-context-hydration-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("exhausted exclusive hydration fixture directories".into())
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn situation() -> TestResult<ReferenceSituation> {
    let run_dir = RunDirectory::new()?;
    let mut authority = DurableReferenceLedger::open(
        run_dir.0.join("authority.journal"), "site:bound-context", IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024));
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:bound-context")?,
        sensor_id: SensorId::parse("sensor:bound-context")?,
        seed: 60,
        packet_count: 3,
        packet_bytes: 32,
        start_ns: 100,
        period_ns: 100,
        uncertainty_ns: 1,
    };
    let capture = run_reference_capture(
        &spec, &DeliveryPlan::identity(spec.packet_count)?, &mut objects, &mut authority,
    )?;
    let model = MockModelSpec::new("mock:bound-context:v1", MockModelScript::Fixed {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.9, 1.0)?,
    })?;
    let observation = ReferenceModelObservation::new(
        execute_mock_model(&model, &capture, &mut objects)?,
        "power:bound-context",
        CaptureInterval::new(
            capture.source_packets.first().ok_or(ContractError::NotFound)?.capture.earliest,
            capture.source_packets.last().ok_or(ContractError::NotFound)?.capture.latest,
        )?,
    )?;
    let decision = evaluate_unknown_presence(EventId::parse("event:bound-context")?, vec![observation])?;
    let receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;
    Ok(compile_reference_situation(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:bound-context")?,
        session_id: SessionId::parse("session:bound-context")?,
        principal_id: PrincipalId::parse("principal:bound-context")?,
        objective_id: "objective:bound-context".to_owned(),
        revision: 1,
        contract_basis: basis(),
        previous_anchor: None,
        predecessor_publication: None,
        decision: &decision,
        event_receipt: &receipt,
        alert_plan: None,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
        created_at: TimestampNs(1_000),
    }, &authority)?)
}

fn projection_spec() -> TestResult<ReferenceProjectionSpec> {
    Ok(ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector::builder()
            .latency_ms(10_000).tokens(20_000).bytes(1_000_000).model_calls(10)
            .cpu_millis(10_000).accelerator_millis(10_000).energy_millijoules(1_000_000)
            .network_bytes(1_000_000).storage_operations(10_000).privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0).build()?,
        reserved_resources: BudgetVector::builder()
            .latency_ms(100).tokens(100).bytes(1_000).storage_operations(1).build()?,
        pressure: ResourcePressure::Elevated,
        degraded_dimensions: BTreeSet::from(["model_calls".to_owned()]),
        target_tokens: 2_000,
    })
}

fn costs() -> TestResult<BTreeMap<HydrationLevel, BudgetVector>> {
    Ok(BTreeMap::from([
        (HydrationLevel::H0, BudgetVector::builder()
            .latency_ms(10).tokens(32).bytes(256).storage_operations(1).build()?),
        (HydrationLevel::H1, BudgetVector::builder()
            .latency_ms(100).tokens(1_024).bytes(16_384).cpu_millis(10)
            .storage_operations(1).privacy_exposure(0.1).build()?),
        (HydrationLevel::H2, BudgetVector::builder()
            .latency_ms(200).tokens(2_048).bytes(32_768).cpu_millis(20)
            .storage_operations(1).privacy_exposure(0.2).build()?),
    ]))
}

fn descriptor(slot: &str, anchor: &LedgerAnchor) -> TestResult<SemanticHandle> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor.clone(),
        subject_id: format!("context-expansion-subject:{slot}"),
        subject_digest: ContentDigest::sha256(slot.as_bytes()),
        semantic_type: "semantic_context_expansion".to_owned(),
        source_id: "context-pack:bound-context".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("decision_preserving_summary".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        required_capabilities: levels.iter().map(|level| {
            (*level, BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]))
        }).collect(),
        estimated_costs: costs()?,
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

struct Fixture {
    publication: BoundReferenceSituationPublication,
    catalog: ReferenceHydrationCatalog,
    store: ReferenceSessionStore,
    session: AgentSession,
    read: ContextSlotRead,
}

impl Fixture {
    fn new(older_descriptor: bool) -> TestResult<Self> {
        let publication = project_reference_situation(situation()?, &projection_spec()?)?;
        let mut evidence_anchor = publication.context_pack.anchor.clone();
        if older_descriptor {
            evidence_anchor.commit_sequence = evidence_anchor.commit_sequence.checked_sub(1)
                .ok_or(ContractError::NotFound)?;
        }
        let specs = ContextExpansionBindingSet::required_slots(
            &publication.context_pack, &publication.compression_receipt,
        ).into_iter().map(|slot_id| {
            Ok(ReferenceExpansionBindingSpec {
                descriptor: descriptor(&slot_id, &evidence_anchor)?,
                slot_id,
                hydration_level: HydrationLevel::H1,
                purpose: "Expand exact supporting evidence; this text grants nothing.".to_owned(),
            })
        }).collect::<TestResult<Vec<_>>>()?;
        let publication = BoundReferenceSituationPublication::publish(publication, specs)?;
        let mut catalog = ReferenceHydrationCatalog::new();
        for descriptor in &publication.descriptors {
            catalog.register_descriptor(descriptor.clone())?;
            for level in [HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2] {
                let artifact = HydrationArtifact::publish(
                    level,
                    "application/fss+json",
                    b"{\"evidence\":true}".to_vec(),
                    [descriptor.subject_digest],
                    Completeness::Complete,
                    descriptor.applied_transform.clone(),
                )?;
                catalog.register_artifact(
                    &descriptor.handle_id, descriptor.descriptor_digest, artifact,
                )?;
            }
        }
        let capsule = &publication.publication.situation.capsule;
        // Zero symbol capacity proves that this bridge does not leak implicit alias allocations.
        let mut store = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
            max_symbols_per_session: 0,
            ..ReferenceSessionLimits::default()
        });
        let session = store.open(AgentSessionParams {
            session_id: capsule.session_id.clone(),
            mission_id: capsule.mission_id.clone(),
            principal_id: capsule.principal_id.clone(),
            capabilities: BTreeSet::from([
                "capability:hydrate:H0".to_owned(),
                "capability:hydrate:H1".to_owned(),
                "capability:hydrate:H2".to_owned(),
            ]),
            privacy_scope: BTreeSet::from(["private:property".to_owned()]),
            current_anchor: capsule.anchor.clone(),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 5_000,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 900,
            expires_at_ns: 20_000,
        }, basis(), TimestampNs(900))?;
        let binding = publication.expansion_bindings.bindings.first()
            .ok_or(ContractError::NotFound)?;
        let read = ContextSlotRead {
            session_id: session.session_id.clone(),
            generation: session.symbol_table_generation,
            expected_publication_digest: publication.bound_publication_digest,
            slot_id: binding.slot_id.clone(),
            requested_level: binding.reference.hydration_level,
            allow_lower_level: false,
            budget: binding.estimated_cost,
            purpose: HydrationPurpose::IncidentAdjudication,
            continuation: None,
            issued_at: TimestampNs(1_001),
        };
        Ok(Self { publication, catalog, store, session, read })
    }

    fn deliver(&mut self, now: TimestampNs) -> Result<BoundContextHydration, ContextHydrationError> {
        self.store.hydrate_context_slot(
            &self.session.principal_id, &self.publication, &self.read, &mut self.catalog, now,
        )
    }

    fn remaining(&mut self, now: TimestampNs) -> TestResult<u64> {
        Ok(self.store.remaining_token_budget(
            &self.session.principal_id, &self.session.session_id, now,
        )?)
    }

    fn refresh(&mut self, capabilities: BTreeSet<String>, privacy: BTreeSet<String>) -> TestResult {
        self.session = self.store.refresh(
            &self.session.principal_id,
            &self.session.session_id,
            SessionRefresh {
                expected_session_digest: self.session.session_digest(),
                current_anchor: self.session.current_anchor.clone(),
                capabilities,
                privacy_scope: privacy,
            },
            TimestampNs(1_001),
        )?;
        self.read.generation = self.session.symbol_table_generation;
        Ok(())
    }
}

#[test]
fn exact_slot_delivers_with_two_anchors_and_no_alias_capacity() -> TestResult {
    for older in [false, true] {
        let mut fixture = Fixture::new(older)?;
        let session_digest = fixture.session.session_digest();
        let delivery = fixture.deliver(TimestampNs(1_001))?;
        delivery.verify_for(&fixture.publication, &fixture.session)?;
        assert_eq!(delivery.response.receipt.delivered_level, Some(HydrationLevel::H1));
        let publication_anchor = &fixture.publication.publication.context_pack.anchor;
        assert_eq!(delivery.request.anchor.commit_sequence,
            publication_anchor.commit_sequence - u64::from(older));
        assert_eq!(&fixture.session.current_anchor, publication_anchor);
        assert_eq!(delivery.session_digest, session_digest);
        assert_eq!(delivery.request.available_capabilities, fixture.session.capabilities);
        assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000 - 1_024);
        let actual = fixture.store.session(
            &fixture.session.principal_id, &fixture.session.session_id, TimestampNs(1_001),
        )?;
        assert_eq!(actual.session_digest(), session_digest);
    }
    Ok(())
}

#[test]
fn continuation_failure_does_not_spend_tokens_or_consume_the_cursor() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let first = fixture.deliver(TimestampNs(1_001))?;
    let cursor = first.response.receipt.continuation.ok_or(ContractError::NotFound)?;
    fixture.read.continuation = Some(cursor.clone());
    fixture.read.requested_level = HydrationLevel::H2;
    // The H1 quote is too small for H2. The continuation must survive this refusal.
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::Hydration(
            HydrationError::BudgetExceeded
        )))
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 3_976);
    assert!(!fixture.catalog.issued_cursor(&cursor.cursor_digest)
        .ok_or(ContractError::NotFound)?.consumed);
    fixture.read.budget = *costs()?.get(&HydrationLevel::H2).ok_or(ContractError::NotFound)?;
    let second = fixture.deliver(TimestampNs(1_001))?;
    second.verify_for(&fixture.publication, &fixture.session)?;
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 1_928);
    fixture.read.budget = *costs()?.get(&HydrationLevel::H1).ok_or(ContractError::NotFound)?;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::Hydration(
            HydrationError::ContinuationAlreadyConsumed
        )))
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 1_928);
    Ok(())
}

#[test]
fn repeated_reads_charge_each_delivery_and_exhaust_the_session_grant() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let first = fixture.deliver(TimestampNs(1_001))?;
    for _ in 0..3 {
        assert_eq!(fixture.deliver(TimestampNs(1_001))?, first);
    }
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 904);
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::BudgetExceeded))
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 904);
    assert_eq!(fixture.catalog.issued_cursor_count(), 1);
    Ok(())
}

#[test]
fn absent_and_ungranted_targets_have_the_same_non_disclosing_failure() -> TestResult {
    for denial in 0..3 {
        let mut fixture = Fixture::new(true)?;
        if denial == 0 {
            fixture.read.slot_id = "slot:absent".to_owned();
        } else if denial == 1 {
            fixture.refresh(BTreeSet::new(), fixture.session.privacy_scope.clone())?;
        } else {
            fixture.refresh(fixture.session.capabilities.clone(), BTreeSet::new())?;
        }
        let Err(error) = fixture.deliver(TimestampNs(1_001)) else {
            return Err(ContractError::EvidenceRequired.into());
        };
        assert!(matches!(error, ContextHydrationError::SlotUnavailable));
        assert_eq!(error.to_string(), "context slot unavailable");
        assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000);
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    }
    Ok(())
}

#[test]
fn selected_level_is_not_authorized_by_the_pack_or_purpose_text() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.refresh(
        BTreeSet::from(["capability:hydrate:H0".to_owned()]),
        fixture.session.privacy_scope.clone(),
    )?;
    fixture.read.purpose = HydrationPurpose::Qualification;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::Hydration(
            HydrationError::CapabilityDenied
        )))
    ));
    fixture.read.requested_level = HydrationLevel::H2;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::WrongInitialLevel)
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000);
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn binding_and_payload_tampering_invalidate_the_delivery_proof() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let delivery = fixture.deliver(TimestampNs(1_001))?;
    let mut tampered = delivery.clone();
    tampered.response.artifact.as_mut().ok_or(ContractError::NotFound)?.payload.push(0);
    assert!(tampered.verify_for(&fixture.publication, &fixture.session).is_err());
    let mut tampered = delivery.clone();
    tampered.binding_digest = ContentDigest::sha256(b"other-binding");
    tampered.delivery_digest = tampered.computed_digest();
    assert!(tampered.verify_for(&fixture.publication, &fixture.session).is_err());
    let mut other_session = fixture.session.clone();
    other_session.principal_id = PrincipalId::parse("principal:other")?;
    assert!(delivery.verify_for(&fixture.publication, &other_session).is_err());
    fixture.publication.expansion_bindings.bindings.first_mut()
        .ok_or(ContractError::NotFound)?.purpose.push_str(" changed");
    assert!(fixture.deliver(TimestampNs(1_001)).is_err());
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 3_976);
    assert_eq!(fixture.catalog.issued_cursor_count(), 1);
    Ok(())
}

#[test]
fn superseded_descriptor_is_not_resurrected_by_a_self_contained_pack() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let binding = fixture.publication.expansion_bindings.binding_for_slot(&fixture.read.slot_id)
        .ok_or(ContractError::NotFound)?;
    let mut newer = fixture.catalog.current_descriptor(&binding.reference.handle_id)
        .ok_or(ContractError::NotFound)?.clone();
    newer.anchor.commit_sequence += 1;
    newer.published_at = TimestampNs(1_001);
    newer.descriptor_digest = newer.computed_descriptor_digest();
    newer.verify()?;
    fixture.catalog.register_descriptor(newer)?;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::SlotUnavailable)
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000);
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn expired_evidence_returns_zero_cost_unavailability_not_fabricated_absence() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.read.issued_at = TimestampNs(10_000);
    let delivery = fixture.deliver(TimestampNs(10_000))?;
    delivery.verify_for(&fixture.publication, &fixture.session)?;
    assert!(delivery.response.artifact.is_none());
    assert_eq!(delivery.response.receipt.availability, HandleAvailability::Expired);
    assert_eq!(delivery.response.receipt.completeness, Completeness::Stale);
    assert_eq!(fixture.remaining(TimestampNs(10_000))?, 5_000);
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn stale_root_generation_clock_and_wrong_principal_are_refused_before_disclosure() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let other = PrincipalId::parse("principal:other")?;
    assert!(matches!(fixture.store.hydrate_context_slot(
        &other, &fixture.publication, &fixture.read, &mut fixture.catalog, TimestampNs(1_001),
    ), Err(ContextHydrationError::Session(ReferenceSessionError::Unavailable))));
    let original = fixture.read.expected_publication_digest;
    fixture.read.expected_publication_digest = ContentDigest::sha256(b"other-publication");
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::StaleBasis))
    ));
    fixture.read.expected_publication_digest = original;
    fixture.read.generation += 1;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::StaleGeneration))
    ));
    fixture.read.generation -= 1;
    fixture.read.issued_at = TimestampNs(1_002);
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::StaleBasis))
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000);
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn current_session_anchor_cannot_be_replaced_by_an_older_publication() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let mut newer_anchor = fixture.session.current_anchor.clone();
    newer_anchor.commit_sequence += 1;
    fixture.session = fixture.store.refresh(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        SessionRefresh {
            expected_session_digest: fixture.session.session_digest(),
            current_anchor: newer_anchor,
            capabilities: fixture.session.capabilities.clone(),
            privacy_scope: fixture.session.privacy_scope.clone(),
        },
        TimestampNs(1_001),
    )?;
    fixture.read.generation = fixture.session.symbol_table_generation;
    assert!(matches!(fixture.deliver(TimestampNs(1_001)),
        Err(ContextHydrationError::Session(ReferenceSessionError::StaleBasis))
    ));
    assert_eq!(fixture.remaining(TimestampNs(1_001))?, 5_000);
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}
