#![forbid(unsafe_code)]
//! Public-API regression coverage for context -> session -> live source custody (FSS-210).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    AgentSession, AgentSessionParams, BudgetVector, CapsuleId, CaptureInterval, Completeness,
    ContentDigest, ContextExpansionBindingSet, ContractBasis, ContractBasisRegistryBytes,
    ContractError, EventId, Generation, HandleAvailability, HydrationArtifact, HydrationError,
    HydrationLevel, HydrationPurpose, LaboratoryAccess, MissionId, ObjectId, PrincipalId,
    ProbabilityInterval, ResourcePressure, SemanticHandle, SemanticHandleSpec, SensorId, SessionId,
    TimestampNs, TombstoneReason, TombstoneRecord,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_reference::agent_session::context_hydration::{
    BoundContextHydration, ContextHydrationError, ContextSlotRead,
};
use fss_reference::{
    BoundReferenceSituationPublication, DeliveryPlan, MockModelScript, MockModelSpec,
    MockSemanticLabel, PublishedSourceReader, ReferenceExpansionBindingSpec,
    ReferenceHydrationCatalog, ReferenceModelObservation, ReferenceProjectionSpec,
    ReferenceSessionError, ReferenceSessionLimits, ReferenceSessionStore,
    ReferenceSituationRequest, SessionRefresh, SourceHydrationError, VirtualCameraSpec,
    compile_reference_situation, evaluate_unknown_presence, execute_mock_model,
    project_reference_situation, publish_reference_event, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SOURCE: &[u8] = b"exact source evidence";
const NOW: TimestampNs = TimestampNs(1_001);

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
            let path = base.join(format!("fss-context-source-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive context-source fixture directory unavailable".into())
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CountedCustody {
    objects: InMemoryObjectStore,
    calls: Cell<usize>,
}

impl PublishedSourceReader for CountedCustody {
    fn read_published_source(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        ceiling: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.calls.set(self.calls.get() + 1);
        self.objects.read_published_source(root, subject, ceiling)
    }
}

struct WrongBytes;

impl PublishedSourceReader for WrongBytes {
    fn read_published_source(
        &self,
        _: ContentDigest,
        _: ContentDigest,
        _: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        Ok(b"forged source".to_vec())
    }
}

struct Fixture {
    publication: BoundReferenceSituationPublication,
    descriptor: SemanticHandle,
    catalog: ReferenceHydrationCatalog,
    sessions: ReferenceSessionStore,
    session: AgentSession,
    read: ContextSlotRead,
    custody: CountedCustody,
    metadata: ContentDigest,
}

impl Fixture {
    fn new(slot_level: HydrationLevel) -> TestResult<Self> {
        // Use the public compilation path, not an unsealed hand-built SituationCapsule.
        let run_dir = RunDirectory::new()?;
        let mut authority = DurableReferenceLedger::open(
            run_dir.0.join("authority.journal"),
            "site:context-source",
            IncompleteTailPolicy::Reject,
        )?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(2_048, 32 * 1_024 * 1_024));
        let camera = VirtualCameraSpec {
            capture_id: CapsuleId::parse("capture:context-source")?,
            sensor_id: SensorId::parse("sensor:context-source")?,
            seed: 60,
            packet_count: 3,
            packet_bytes: 32,
            start_ns: 100,
            period_ns: 100,
            uncertainty_ns: 1,
        };
        let capture = run_reference_capture(
            &camera,
            &DeliveryPlan::identity(camera.packet_count)?,
            &mut objects,
            &mut authority,
        )?;
        let model = MockModelSpec::new(
            "mock:context-source:v1",
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.9, 1.0)?,
            },
        )?;
        let observation = ReferenceModelObservation::new(
            execute_mock_model(&model, &capture, &mut objects)?,
            "power:context-source",
            CaptureInterval::new(
                capture
                    .source_packets
                    .first()
                    .ok_or(ContractError::NotFound)?
                    .capture
                    .earliest,
                capture
                    .source_packets
                    .last()
                    .ok_or(ContractError::NotFound)?
                    .capture
                    .latest,
            )?,
        )?;
        let decision =
            evaluate_unknown_presence(EventId::parse("event:context-source")?, vec![observation])?;
        let event = publish_reference_event(&decision, &mut objects, &mut authority)?;
        let basis = ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss-reference:context-source-test",
            )
            .with_accepted_nightly("nightly-2026-08-31"),
        );
        let situation = compile_reference_situation(
            ReferenceSituationRequest {
                mission_id: MissionId::parse("mission:context-source")?,
                session_id: SessionId::parse("session:context-source")?,
                principal_id: PrincipalId::parse("principal:context-source")?,
                objective_id: "objective:context-source".to_owned(),
                revision: 1,
                contract_basis: basis.clone(),
                previous_anchor: None,
                predecessor_publication: None,
                decision: &decision,
                event_receipt: &event,
                alert_plan: None,
                alert_outcome: None,
                coverage_witness: None,
                available_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
                created_at: TimestampNs(1_000),
            },
            &authority,
        )?;
        let available = BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(20_000)
            .bytes(1_000_000)
            .model_calls(10)
            .cpu_millis(10_000)
            .accelerator_millis(10_000)
            .energy_millijoules(1_000_000)
            .network_bytes(1_000_000)
            .storage_operations(10_000)
            .privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0)
            .build()?;
        let publication = project_reference_situation(
            situation,
            &ReferenceProjectionSpec {
                view_id: "AVIEW-001".to_owned(),
                available_resources: available,
                reserved_resources: BudgetVector::ZERO,
                pressure: ResourcePressure::Elevated,
                degraded_dimensions: BTreeSet::from(["model_calls".to_owned()]),
                target_tokens: 2_000,
            },
        )?;
        let source = objects.put_verified(SOURCE)?;
        let metadata = objects.put_verified(b"context source provenance")?;
        let root = objects
            .publish_manifest(ObjectManifest::new(
                "context-source",
                [source],
                Some(metadata),
            )?)?
            .root;
        let mut evidence_anchor = publication.context_pack.anchor.clone();
        evidence_anchor.commit_sequence = evidence_anchor
            .commit_sequence
            .checked_sub(1)
            .ok_or(ContractError::NotFound)?;
        let levels = BTreeSet::from([
            HydrationLevel::H0,
            HydrationLevel::H1,
            HydrationLevel::H2,
            HydrationLevel::H3,
        ]);
        let fallback_quote = BudgetVector::builder()
            .tokens(512)
            .bytes(16_384)
            .latency_ms(100)
            .cpu_millis(10)
            .storage_operations(1)
            .build()?;
        let mut specs = Vec::new();
        for slot_id in ContextExpansionBindingSet::required_slots(
            &publication.context_pack,
            &publication.compression_receipt,
        ) {
            // Receipt-level prices are normative, not test-selected substitutes.
            let quote = publication
                .compression_receipt
                .expansion_handles
                .iter()
                .find(|expansion| expansion.handle == slot_id)
                .map_or(fallback_quote, |expansion| expansion.estimated_cost);
            assert!(quote.bytes >= SOURCE.len() as u64 && quote.tokens > 0);
            let descriptor = SemanticHandle::publish(SemanticHandleSpec {
                contract_basis: basis.clone(),
                anchor: evidence_anchor.clone(),
                subject_id: format!("source-for:{slot_id}"),
                subject_digest: source,
                semantic_type: "source_object".to_owned(),
                source_id: "sensor:context-source".to_owned(),
                capture_interval: None,
                spatial_scope: None,
                privacy_class: "private:property".to_owned(),
                applied_transform: None,
                availability: HandleAvailability::Available,
                retention_until: TimestampNs(10_000),
                required_capabilities: levels
                    .iter()
                    .map(|level| {
                        let cap = if *level == HydrationLevel::H3 {
                            "capability:source"
                        } else {
                            "capability:preview"
                        };
                        (*level, BTreeSet::from([cap.to_owned()]))
                    })
                    .collect(),
                estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
                levels: levels.clone(),
                laboratory_access: LaboratoryAccess::Unavailable,
                debug_capability: None,
                derivative_handles: BTreeSet::new(),
                published_at: TimestampNs(1),
            })?;
            specs.push(ReferenceExpansionBindingSpec {
                slot_id,
                descriptor,
                hydration_level: slot_level,
                purpose: "Read exact source; the description conveys no authority.".to_owned(),
            });
        }
        let publication = BoundReferenceSituationPublication::publish(publication, specs)?;
        let binding = publication
            .expansion_bindings
            .bindings
            .first()
            .ok_or(ContractError::NotFound)?;
        let descriptor = publication
            .descriptors
            .iter()
            .find(|descriptor| descriptor.handle_id == binding.reference.handle_id)
            .ok_or(ContractError::NotFound)?
            .clone();
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(descriptor.clone())?;
        catalog.register_artifact(
            &descriptor.handle_id,
            descriptor.descriptor_digest,
            HydrationArtifact::publish(
                HydrationLevel::H2,
                "text/plain",
                b"preview".to_vec(),
                [source],
                Completeness::Complete,
                None,
            )?,
        )?;
        let custody = CountedCustody {
            objects,
            calls: Cell::new(0),
        };
        catalog.bind_source_object(
            &descriptor.handle_id,
            descriptor.descriptor_digest,
            root,
            &custody,
        )?;
        custody.calls.set(0);
        let capsule = &publication.publication.situation.capsule;
        let mut sessions = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
            max_symbols_per_session: 0,
            ..ReferenceSessionLimits::default()
        });
        let session = sessions.open(
            AgentSessionParams {
                session_id: capsule.session_id.clone(),
                mission_id: capsule.mission_id.clone(),
                principal_id: capsule.principal_id.clone(),
                capabilities: BTreeSet::from([
                    "capability:preview".to_owned(),
                    "capability:source".to_owned(),
                ]),
                privacy_scope: BTreeSet::from([descriptor.privacy_class.clone()]),
                current_anchor: capsule.anchor.clone(),
                view_id: "AVIEW-001".to_owned(),
                token_budget: binding
                    .estimated_cost
                    .tokens
                    .checked_mul(4)
                    .ok_or(ContractError::NotFound)?,
                symbol_table_generation: 0,
                last_acknowledged_situation_fingerprint: None,
                created_at_ns: 900,
                expires_at_ns: 20_000,
            },
            basis,
            TimestampNs(900),
        )?;
        let read = ContextSlotRead {
            session_id: session.session_id.clone(),
            generation: session.symbol_table_generation,
            expected_publication_digest: publication.bound_publication_digest,
            slot_id: binding.slot_id.clone(),
            requested_level: slot_level,
            allow_lower_level: false,
            budget: binding.estimated_cost,
            purpose: HydrationPurpose::IncidentAdjudication,
            continuation: None,
            issued_at: NOW,
        };
        Ok(Self {
            publication,
            descriptor,
            catalog,
            sessions,
            session,
            read,
            custody,
            metadata,
        })
    }

    fn deliver(
        &mut self,
        now: TimestampNs,
    ) -> Result<BoundContextHydration, ContextHydrationError> {
        self.sessions.hydrate_context_slot_from_source(
            &self.session.principal_id,
            &self.publication,
            &self.read,
            &mut self.catalog,
            &self.custody,
            now,
        )
    }

    fn remaining(&mut self, now: TimestampNs) -> TestResult<u64> {
        Ok(self.sessions.remaining_token_budget(
            &self.session.principal_id,
            &self.session.session_id,
            now,
        )?)
    }

    fn refresh(
        &mut self,
        capabilities: BTreeSet<String>,
        privacy_scope: BTreeSet<String>,
    ) -> TestResult {
        self.session = self.sessions.refresh(
            &self.session.principal_id,
            &self.session.session_id,
            SessionRefresh {
                expected_session_digest: self.session.session_digest(),
                current_anchor: self.session.current_anchor.clone(),
                capabilities,
                privacy_scope,
            },
            NOW,
        )?;
        self.read.generation = self.session.symbol_table_generation;
        Ok(())
    }
}

#[test]
fn live_source_has_exact_binding_two_anchors_and_no_payload_cache() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H3)?;
    let cached = f.catalog.stored_payload_bytes();
    let mut direct = f.catalog.clone();
    let delivery = f.deliver(NOW)?;
    delivery.verify_for(&f.publication, &f.session)?;
    let source_binding = f
        .catalog
        .source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or(ContractError::NotFound)?;
    delivery.verify_source_for(&f.publication, &f.session, source_binding)?;
    assert_eq!(
        delivery
            .response
            .artifact
            .as_ref()
            .ok_or(ContractError::NotFound)?
            .payload,
        SOURCE
    );
    assert_eq!(
        delivery.request.anchor.commit_sequence + 1,
        f.session.current_anchor.commit_sequence
    );
    let response = direct.hydrate_context_slot_from_source(
        &f.publication,
        &f.read.slot_id,
        &delivery.request,
        &f.custody,
        NOW,
    )?;
    assert_eq!(response, delivery.response);
    assert_eq!(f.custody.calls.get(), 2);
    assert_eq!(f.catalog.stored_payload_bytes(), cached);
    assert_eq!(
        f.remaining(NOW)?,
        f.session.token_budget - delivery.response.receipt.cost.tokens
    );
    Ok(())
}

#[test]
fn preview_entrypoints_have_identical_proofs_without_source_io() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H2)?;
    let mut sessions = f.sessions.clone();
    let mut catalog = f.catalog.clone();
    let cached = sessions.hydrate_context_slot(
        &f.session.principal_id,
        &f.publication,
        &f.read,
        &mut catalog,
        NOW,
    )?;
    let live = f.deliver(NOW)?;
    assert_eq!(live, cached);
    live.verify_for(&f.publication, &f.session)?;
    let source_binding = f
        .catalog
        .source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or(ContractError::NotFound)?;
    assert!(matches!(
        live.verify_source_for(&f.publication, &f.session, source_binding),
        Err(ContextHydrationError::Session(
            ReferenceSessionError::Hydration(HydrationError::LevelUnavailable)
        ))
    ));
    assert_eq!(f.custody.calls.get(), 0);
    assert_eq!(
        f.catalog.issued_cursor_count(),
        catalog.issued_cursor_count()
    );
    Ok(())
}

#[test]
fn missing_revoked_and_superseded_slots_do_not_disclose_or_spend() -> TestResult {
    for scenario in 0..4 {
        let mut f = Fixture::new(HydrationLevel::H3)?;
        match scenario {
            0 => f.read.slot_id = "slot:missing".to_owned(),
            1 => f.refresh(BTreeSet::new(), f.session.privacy_scope.clone())?,
            2 => f.refresh(f.session.capabilities.clone(), BTreeSet::new())?,
            _ => {
                let mut newer = f.descriptor.clone();
                newer.anchor.commit_sequence += 1;
                newer.published_at = NOW;
                newer.descriptor_digest = newer.computed_descriptor_digest();
                f.catalog.register_descriptor(newer)?;
            }
        }
        let error = f
            .deliver(NOW)
            .err()
            .ok_or(ContractError::EvidenceRequired)?;
        assert!(matches!(error, ContextHydrationError::SlotUnavailable));
        assert_eq!(error.to_string(), "context slot unavailable");
        assert_eq!(f.custody.calls.get(), 0);
        assert_eq!(f.remaining(NOW)?, f.session.token_budget);
        assert_eq!(f.catalog.issued_cursor_count(), 0);
    }
    Ok(())
}

#[test]
fn principal_root_generation_time_and_integrity_refusals_precede_io() -> TestResult {
    for scenario in 0..6 {
        let mut f = Fixture::new(HydrationLevel::H3)?;
        let mut principal = f.session.principal_id.clone();
        match scenario {
            0 => principal = PrincipalId::parse("principal:other")?,
            1 => f.read.expected_publication_digest = ContentDigest::sha256(b"other publication"),
            2 => f.read.generation += 1,
            3 => f.read.issued_at = TimestampNs(NOW.0 + 1),
            4 => {
                f.publication
                    .expansion_bindings
                    .bindings
                    .first_mut()
                    .ok_or(ContractError::NotFound)?
                    .purpose
                    .push_str(" forged");
            }
            _ => f.read.requested_level = HydrationLevel::H2,
        }
        assert!(
            f.sessions
                .hydrate_context_slot_from_source(
                    &principal,
                    &f.publication,
                    &f.read,
                    &mut f.catalog,
                    &f.custody,
                    NOW,
                )
                .is_err()
        );
        assert_eq!(f.custody.calls.get(), 0);
        assert_eq!(f.remaining(NOW)?, f.session.token_budget);
        assert_eq!(f.catalog.issued_cursor_count(), 0);
    }
    Ok(())
}

#[test]
fn source_grant_full_vector_and_cumulative_budget_are_checked_before_io() -> TestResult {
    for scenario in 0..3 {
        let mut f = Fixture::new(HydrationLevel::H3)?;
        match scenario {
            0 => f.refresh(
                BTreeSet::from(["capability:preview".to_owned()]),
                f.session.privacy_scope.clone(),
            )?,
            1 => f.read.budget.bytes -= 1,
            _ => f.read.budget.tokens = f.session.token_budget + 1,
        }
        assert!(f.deliver(NOW).is_err());
        assert_eq!(f.custody.calls.get(), 0);
        assert_eq!(f.remaining(NOW)?, f.session.token_budget);
    }
    let mut f = Fixture::new(HydrationLevel::H3)?;
    for _ in 0..4 {
        f.deliver(NOW)?;
    }
    assert_eq!(f.remaining(NOW)?, 0);
    assert!(matches!(
        f.deliver(NOW),
        Err(ContextHydrationError::Session(
            ReferenceSessionError::BudgetExceeded
        ))
    ));
    assert_eq!(f.custody.calls.get(), 4);
    Ok(())
}

#[test]
fn failed_source_continuation_preserves_cursor_and_charge_for_retry() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H2)?;
    let preview = f.deliver(NOW)?;
    let cursor = preview
        .response
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    let remaining = f.remaining(NOW)?;
    f.read.continuation = Some(cursor.clone());
    f.read.requested_level = HydrationLevel::H3;
    assert!(matches!(
        f.sessions.hydrate_context_slot_from_source(
            &f.session.principal_id,
            &f.publication,
            &f.read,
            &mut f.catalog,
            &WrongBytes,
            NOW,
        ),
        Err(ContextHydrationError::Source(
            SourceHydrationError::SourceMismatch
        ))
    ));
    assert_eq!(f.remaining(NOW)?, remaining);
    assert!(
        !f.catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(ContractError::NotFound)?
            .consumed
    );
    let delivered = f.deliver(NOW)?;
    delivered.verify_for(&f.publication, &f.session)?;
    assert!(
        f.catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(ContractError::NotFound)?
            .consumed
    );
    assert_eq!(
        f.remaining(NOW)?,
        remaining - delivered.response.receipt.cost.tokens
    );
    assert!(matches!(
        f.deliver(NOW),
        Err(ContextHydrationError::Session(
            ReferenceSessionError::Hydration(HydrationError::ContinuationAlreadyConsumed)
        ))
    ));
    assert_eq!(f.custody.calls.get(), 1);
    Ok(())
}

#[test]
fn tombstone_revokes_previously_disclosed_source_without_cached_resurrection() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H3)?;
    f.deliver(NOW)?;
    let remaining = f.remaining(NOW)?;
    let witness = f
        .custody
        .objects
        .put_verified(b"authorized deletion witness")?;
    let prior = Generation::parse_positive(1)?;
    f.custody.objects.tombstone(
        f.descriptor.subject_digest,
        TombstoneRecord::new(
            ObjectId::parse("object:context-source")?,
            prior.next()?,
            prior,
            TombstoneReason::Deleted,
            Some(witness),
            f.descriptor.subject_digest,
        )?,
    )?;
    f.read.allow_lower_level = true;
    assert!(matches!(
        f.deliver(TimestampNs(NOW.0 + 1)),
        Err(ContextHydrationError::Source(SourceHydrationError::Object(
            _
        )))
    ));
    assert_eq!(f.remaining(TimestampNs(NOW.0 + 1))?, remaining);
    assert_eq!(f.custody.calls.get(), 2);
    Ok(())
}

#[test]
fn corrupt_provenance_is_not_hidden_by_a_preview_downgrade() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H3)?;
    f.custody.objects.corrupt_for_test(f.metadata)?;
    f.read.allow_lower_level = true;
    let error = f
        .deliver(NOW)
        .err()
        .ok_or(ContractError::EvidenceRequired)?;
    assert!(matches!(
        error,
        ContextHydrationError::Source(SourceHydrationError::Object(_))
    ));
    assert_eq!(error.to_string(), "context source custody unavailable");
    assert_eq!(f.remaining(NOW)?, f.session.token_budget);
    assert_eq!(f.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn retention_expiry_is_verified_zero_cost_unavailability_without_io() -> TestResult {
    let mut f = Fixture::new(HydrationLevel::H3)?;
    let now = TimestampNs(10_000);
    let delivery = f.deliver(now)?;
    delivery.verify_for(&f.publication, &f.session)?;
    assert!(delivery.response.artifact.is_none());
    assert_eq!(
        delivery.response.receipt.availability,
        HandleAvailability::Expired
    );
    assert_eq!(delivery.response.receipt.cost, BudgetVector::ZERO);
    assert_eq!(f.custody.calls.get(), 0);
    assert_eq!(f.remaining(now)?, f.session.token_budget);
    Ok(())
}

#[test]
fn identical_bytes_from_another_publication_do_not_replace_trusted_source_provenance() -> TestResult
{
    let mut f = Fixture::new(HydrationLevel::H3)?;
    let delivery = f.deliver(NOW)?;
    let original = f
        .catalog
        .source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or(ContractError::NotFound)?
        .clone();
    let metadata = f
        .custody
        .objects
        .put_verified(b"different publication provenance")?;
    let root = f
        .custody
        .objects
        .publish_manifest(ObjectManifest::new(
            "other-source-publication",
            [f.descriptor.subject_digest],
            Some(metadata),
        )?)?
        .root;
    assert_ne!(root, original.publication_root());
    let mut other = ReferenceHydrationCatalog::new();
    other.register_descriptor(f.descriptor.clone())?;
    let other_binding = other.bind_source_object(
        &f.descriptor.handle_id,
        f.descriptor.descriptor_digest,
        root,
        &f.custody,
    )?;
    assert_eq!(original.subject_digest(), other_binding.subject_digest());
    assert!(matches!(
        delivery.verify_source_for(&f.publication, &f.session, &other_binding),
        Err(ContextHydrationError::Source(
            SourceHydrationError::SourceMismatch
        ))
    ));
    delivery.verify_source_for(&f.publication, &f.session, &original)?;
    Ok(())
}
