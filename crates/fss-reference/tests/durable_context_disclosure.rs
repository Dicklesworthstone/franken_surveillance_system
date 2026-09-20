#![forbid(unsafe_code)]
//! Public-API capture -> event -> context -> durable H2/H3 disclosure -> restart regressions.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{AgentSession, AgentSessionParams, BudgetVector, CapsuleId, CaptureInterval,
    Completeness, ContentDigest, ContextExpansionBindingSet, ContractBasis, ContractBasisRegistryBytes,
    EventId, Generation, HandleAvailability, HydrationArtifact, HydrationLevel, HydrationPurpose,
    LaboratoryAccess, MissionId, ObjectId, PrincipalId, ProbabilityInterval, ResourcePressure,
    SemanticHandle, SemanticHandleSpec, SensorId, SessionId, TimestampNs, TombstoneReason, TombstoneRecord};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_reference::agent_session::checkpoint::journal::DurableSessionLimits;
use fss_reference::agent_session::checkpoint::journal::disclosure::DurableDisclosureStore;
use fss_reference::agent_session::context_hydration::ContextSlotRead;
use fss_reference::{BoundReferenceSituationPublication, DeliveryPlan, MockModelScript, MockModelSpec,
    MockSemanticLabel, PublishedSourceReader, ReferenceExpansionBindingSpec, ReferenceHydrationCatalog,
    ReferenceModelObservation, ReferenceProjectionSpec, ReferenceSituationRequest, SessionRefresh,
    SourceHydrationError, VirtualCameraSpec, compile_reference_situation, evaluate_unknown_presence,
    execute_mock_model, project_reference_situation, publish_reference_event, run_reference_capture};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-durable-context-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

struct Custody { objects: InMemoryObjectStore, reads: Cell<usize> }
impl PublishedSourceReader for Custody {
    fn read_published_source(&self, root: ContentDigest, subject: ContentDigest, ceiling: u64)
        -> Result<Vec<u8>, SourceHydrationError>
    {
        self.reads.set(self.reads.get() + 1);
        self.objects.read_published_source(root, subject, ceiling)
    }
}

struct Fixture {
    directory: Directory,
    publication: BoundReferenceSituationPublication,
    session: AgentSession,
    descriptor: SemanticHandle,
    blueprint: ReferenceHydrationCatalog,
    custody: Custody,
    source: Vec<u8>,
    read: ContextSlotRead,
    limits: DurableSessionLimits,
}

impl Fixture {
    fn new() -> TestResult<(Self, DurableDisclosureStore)> {
        let directory = Directory::new()?;
        let mut ledger = DurableReferenceLedger::open(directory.0.join("authority.journal"),
            "site:durable-context", IncompleteTailPolicy::Reject)?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024));
        let camera = VirtualCameraSpec {
            capture_id: CapsuleId::parse("capture:durable-context")?,
            sensor_id: SensorId::parse("sensor:durable-context")?, seed: 71,
            packet_count: 3, packet_bytes: 32, start_ns: 100, period_ns: 100, uncertainty_ns: 1,
        };
        let capture = run_reference_capture(&camera, &DeliveryPlan::identity(camera.packet_count)?,
            &mut objects, &mut ledger)?;
        let source_anchor = ledger.current().anchor.clone();
        let source = capture.source_packets.first().ok_or("missing source packet")?.bytes.clone();
        let subject = objects.put_verified(&source)?;
        let source_root = objects.publish_manifest(ObjectManifest::new("context-source", [subject], None)?)?.root;
        let model = MockModelSpec::new("mock:durable-context:v1", MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike, probability: ProbabilityInterval::new(0.9, 1.0)?,
        })?;
        let observation = ReferenceModelObservation::new(execute_mock_model(&model, &capture, &mut objects)?,
            "power:durable-context", CaptureInterval::new(
                capture.source_packets.first().ok_or("missing source")?.capture.earliest,
                capture.source_packets.last().ok_or("missing source")?.capture.latest)?)?;
        let decision = evaluate_unknown_presence(EventId::parse("event:durable-context")?, vec![observation])?;
        let event = publish_reference_event(&decision, &mut objects, &mut ledger)?;
        let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs", "durable-context:test"));
        let situation = compile_reference_situation(ReferenceSituationRequest {
            mission_id: MissionId::parse("mission:durable-context")?,
            session_id: SessionId::parse("session:durable-context")?,
            principal_id: PrincipalId::parse("principal:owner")?,
            objective_id: "objective:durable-context".to_owned(), revision: 1, contract_basis: basis.clone(),
            previous_anchor: None, predecessor_publication: None, decision: &decision, event_receipt: &event,
            alert_plan: None, alert_outcome: None, coverage_witness: None,
            available_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
            created_at: TimestampNs(1_000),
        }, &ledger)?;
        let publication = project_reference_situation(situation, &ReferenceProjectionSpec {
            view_id: "AVIEW-001".to_owned(),
            available_resources: BudgetVector::builder().latency_ms(100_000).tokens(100_000)
                .bytes(10_000_000).model_calls(100).cpu_millis(100_000).accelerator_millis(100_000)
                .energy_millijoules(10_000_000).network_bytes(10_000_000).storage_operations(10_000)
                .privacy_exposure(10.0).operator_attention_seconds(10_000.0).build()?,
            reserved_resources: BudgetVector::ZERO, pressure: ResourcePressure::Elevated,
            degraded_dimensions: BTreeSet::from(["model_calls".to_owned()]), target_tokens: 100_000,
        })?;
        // This full projection does not quote receipt-owned omitted items. Evidence slots remain.
        assert!(publication.compression_receipt.expansion_handles.is_empty());
        let quote = BudgetVector::builder().bytes(1_024).tokens(512).build()?;
        let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3]);
        let descriptor = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis.clone(), anchor: source_anchor,
            subject_id: "source:durable-context".to_owned(), subject_digest: subject,
            semantic_type: "source_object".to_owned(), source_id: camera.sensor_id.as_str().to_owned(),
            capture_interval: None, spatial_scope: None, privacy_class: "private:property".to_owned(),
            applied_transform: None, availability: HandleAvailability::Available,
            retention_until: TimestampNs(10_000),
            required_capabilities: levels.iter().map(|level| (*level, BTreeSet::from([
                if *level == HydrationLevel::H3 { "capability:source".to_owned() } else { "capability:preview".to_owned() }
            ]))).collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(), levels,
            laboratory_access: LaboratoryAccess::Unavailable, debug_capability: None,
            derivative_handles: BTreeSet::new(), published_at: TimestampNs(1_000),
        })?;
        let slots = ContextExpansionBindingSet::required_slots(&publication.context_pack, &publication.compression_receipt);
        assert!(!slots.is_empty());
        let specs = slots.into_iter().map(|slot_id| ReferenceExpansionBindingSpec {
            slot_id, descriptor: descriptor.clone(), hydration_level: HydrationLevel::H2,
            purpose: "Inspect the exact retained packet behind the reference event.".to_owned(),
        }).collect();
        let publication = BoundReferenceSituationPublication::publish(publication, specs)?;
        let custody = Custody { objects, reads: Cell::new(0) };
        let mut blueprint = ReferenceHydrationCatalog::new();
        blueprint.register_descriptor(descriptor.clone())?;
        blueprint.register_artifact(&descriptor.handle_id, descriptor.descriptor_digest,
            HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"bounded source preview".to_vec(),
                [subject], Completeness::Complete, None)?)?;
        blueprint.bind_source_object(&descriptor.handle_id, descriptor.descriptor_digest, source_root, &custody)?;
        custody.reads.set(0);
        let mut limits = DurableSessionLimits::default();
        limits.sessions.max_symbols_per_session = 0;
        let mut owner = DurableDisclosureStore::create(directory.0.join("sessions.journal"), limits, blueprint.clone())?;
        let capsule = &publication.publication.situation.capsule;
        let session = owner.open_session(AgentSessionParams {
            session_id: capsule.session_id.clone(), mission_id: capsule.mission_id.clone(),
            principal_id: capsule.principal_id.clone(),
            capabilities: BTreeSet::from(["capability:preview".to_owned(), "capability:source".to_owned()]),
            privacy_scope: BTreeSet::from([descriptor.privacy_class.clone()]), current_anchor: capsule.anchor.clone(),
            view_id: "AVIEW-001".to_owned(), token_budget: 5_000, symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None, created_at_ns: 900, expires_at_ns: 20_000,
        }, basis, TimestampNs(900))?;
        let slot = publication.expansion_bindings.bindings.first().ok_or("missing slot")?;
        let read = ContextSlotRead {
            session_id: session.session_id.clone(), generation: session.symbol_table_generation,
            expected_publication_digest: publication.bound_publication_digest, slot_id: slot.slot_id.clone(),
            requested_level: HydrationLevel::H2, allow_lower_level: false, budget: quote,
            purpose: HydrationPurpose::IncidentAdjudication, continuation: None, issued_at: TimestampNs(1_001),
        };
        Ok((Self { directory, publication, session, descriptor, blueprint, custody, source, read, limits }, owner))
    }
    fn path(&self) -> PathBuf { self.directory.0.join("sessions.journal") }
    fn advance(&mut self, owner: &mut DurableDisclosureStore) -> TestResult {
        let delivery = owner.hydrate_context_slot(&self.session.principal_id, &self.publication, &self.read, TimestampNs(1_001))?;
        delivery.response.verify_for(&self.publication, &self.session)?;
        self.read.continuation = Some(delivery.response.response.receipt.continuation.ok_or("missing H3 continuation")?);
        self.read.requested_level = HydrationLevel::H3;
        self.read.issued_at = TimestampNs(1_002);
        Ok(())
    }
}

#[test]
fn compiled_context_recovers_source_continuation_and_admission_without_session_aliases() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    f.advance(&mut owner)?;
    assert_eq!(f.custody.reads.get(), 0);
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    let result = owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002))?;
    let binding = owner.catalog().source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or("missing source binding")?;
    result.response.verify_source_for(&f.publication, &f.session, binding)?;
    assert_ne!(result.response.request.anchor, f.session.current_anchor);
    assert_eq!(result.response.response.artifact.as_ref().ok_or("missing source")?.payload, f.source);
    let request = result.response.request.request_digest;
    let admission_root = result.committed_root;
    drop(result); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), admission_root, f.limits, f.blueprint.clone())?;
    let admissions = owner.admissions(&f.session.principal_id, &f.session.session_id, request, 1, TimestampNs(1_002))?;
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].0, admission_root);
    assert_eq!(admissions[0].1.charged_tokens(), 512);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 3_976);
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_003)).is_err());
    assert_eq!(f.custody.reads.get(), 1);
    assert_eq!(owner.catalog().stored_payload_bytes(), f.blueprint.stored_payload_bytes());
    let journal = std::fs::read(f.path())?;
    assert!(!journal.windows(f.source.len()).any(|bytes| bytes == f.source));
    Ok(())
}

#[test]
fn recovered_context_cursor_does_not_restore_a_revoked_source_grant() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    f.advance(&mut owner)?;
    f.session = owner.refresh(&f.session.principal_id, &f.session.session_id, SessionRefresh {
        expected_session_digest: f.session.session_digest(), current_anchor: f.session.current_anchor.clone(),
        capabilities: BTreeSet::from(["capability:preview".to_owned()]), privacy_scope: f.session.privacy_scope.clone(),
    }, TimestampNs(1_002))?;
    f.read.generation = f.session.symbol_table_generation;
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002)).is_err());
    assert_eq!(f.custody.reads.get(), 0);
    assert!(!owner.catalog().issued_cursor(&f.read.continuation.as_ref().ok_or("missing cursor")?.cursor_digest)
        .ok_or("lost cursor")?.consumed);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 4_488);
    Ok(())
}

#[test]
fn recovered_context_cannot_resurrect_deleted_source_or_charge_a_failed_read() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    f.advance(&mut owner)?;
    let root = owner.committed_root(); drop(owner);
    let witness = f.custody.objects.put_verified(b"authorized deletion witness")?;
    let prior = Generation::parse_positive(1)?;
    f.custody.objects.tombstone(f.descriptor.subject_digest, TombstoneRecord::new(ObjectId::parse("object:source")?,
        prior.next()?, prior, TombstoneReason::Deleted, Some(witness), f.descriptor.subject_digest)?)?;
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002)).is_err());
    assert_eq!(f.custody.reads.get(), 1);
    assert!(!owner.catalog().issued_cursor(&f.read.continuation.as_ref().ok_or("missing cursor")?.cursor_digest)
        .ok_or("lost cursor")?.consumed);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 4_488);
    assert_eq!(owner.catalog().stored_payload_bytes(), f.blueprint.stored_payload_bytes());
    Ok(())
}


#[path = "durable_context_disclosure/workspace.rs"]
mod workspace;
