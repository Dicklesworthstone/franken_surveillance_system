#![forbid(unsafe_code)]
//! Cold disclosure recovery must not forget the original source's custody profile.
//! Fixtures use private synthetic deployments and the existing joint disclosure journal.

mod file_import_fault_support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use file_import_fault_support::{cx, fresh_dir, open, standard};
use fss_core::{
    AgentSessionParams, BudgetVector, CaptureInterval, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, HandleAvailability, HydrationArtifact, HydrationLevel,
    HydrationPurpose, HydrationRequest, HydrationRequestSpec, LaboratoryAccess, MissionId,
    PrincipalId, SemanticHandle, SemanticHandleSpec, TimestampNs,
};
use fss_object::{HostSpoolIo, InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_publication::SlotName;
use fss_reference::agent_session::checkpoint::journal::DurableSessionLimits;
use fss_reference::agent_session::checkpoint::journal::disclosure::DurableDisclosureStore;
use fss_reference::deletion::belief::hydration::{DeletionAwareSourceReader, DeploymentSourceLimits};
use fss_reference::{
    PublishedSourceReader, ReferenceDeployment, ReferenceHydrationCatalog, SessionBindingRequest,
    SourceHydrationError,
};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"original private source; recovery must not journal or invent these bytes";
const OTHER: &[u8] = b"independent still-authorized source";
const META: &[u8] = b"source provenance metadata";
const MAX_CHECKPOINT: usize = 64 * 1024;

struct Fixture {
    deployment: ReferenceDeployment,
    directory: PathBuf,
    slot: SlotName,
    manifest: ObjectManifest,
    handle: SemanticHandle,
}

fn handle(deployment: &ReferenceDeployment, subject: &[u8], name: &str) -> Value<SemanticHandle> {
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(512).build()?;
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "source-recovery:test",
        )),
        anchor: deployment.current_anchor().clone(),
        subject_id: format!("subject:{name}"),
        subject_digest: ContentDigest::sha256(subject),
        semantic_type: "source_object".to_owned(),
        source_id: "sensor:source".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| (*level, if *level == HydrationLevel::H3 {
            BTreeSet::from(["capability:source".to_owned()])
        } else { BTreeSet::new() })).collect(),
        estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

fn setup(label: &str) -> Value<Fixture> {
    let directory = fresh_dir(&format!("source-binding-recovery-{label}"))?;
    let mut deployment = open(&directory.join("deployment"), standard())?;
    let context = cx(label)?;
    let slot = SlotName::parse("source")?;
    let staged = deployment.stage_and_publish(&slot, &[SOURCE, OTHER, META], &context)?;
    deployment.publish_and_commit(&slot, &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &context)?;
    let handle = handle(&deployment, SOURCE, "original")?;
    Ok(Fixture { deployment, directory, slot, manifest: staged.manifest, handle })
}

fn preview(handle: &SemanticHandle) -> Value<HydrationArtifact> {
    Ok(HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"preview".to_vec(),
        [handle.subject_digest], Completeness::Complete, None)?)
}

fn unbound(handle: &SemanticHandle) -> Value<ReferenceHydrationCatalog> {
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, preview(handle)?)?;
    Ok(catalog)
}

fn bind(f: &Fixture, handle: &SemanticHandle, catalog: &mut ReferenceHydrationCatalog) -> Value {
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &handle.anchor, DeploymentSourceLimits::default(), &|| false);
    catalog.bind_deployment_source_object(&handle.handle_id, handle.descriptor_digest, &reader)?;
    Ok(())
}

fn bound(f: &Fixture) -> Value<ReferenceHydrationCatalog> {
    let mut catalog = unbound(&f.handle)?;
    bind(f, &f.handle, &mut catalog)?;
    Ok(catalog)
}

fn request(handle: &SemanticHandle, level: HydrationLevel) -> Value<HydrationRequest> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: fss_core::SessionId::parse("session:source-recovery")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:source".to_owned()]),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::builder().bytes(1024).tokens(512).build()?,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10),
    })?)
}

struct WeakReader { store: InMemoryObjectStore, reads: Cell<usize> }
impl PublishedSourceReader for WeakReader {
    fn read_published_source(&self, root: ContentDigest, subject: ContentDigest, maximum: u64)
        -> Result<Vec<u8>, SourceHydrationError> {
        self.reads.set(self.reads.get() + 1);
        self.store.read_published_source(root, subject, maximum)
    }
}

fn weak(f: &Fixture) -> Value<WeakReader> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    for bytes in [SOURCE, OTHER, META] { store.put_verified(bytes)?; }
    assert_eq!(store.publish_manifest(f.manifest.clone())?.root, f.manifest.root());
    Ok(WeakReader { store, reads: Cell::new(0) })
}

#[test]
fn recovery_refuses_a_preconstructed_weaker_binding_even_when_all_bytes_match() -> Value {
    let f = setup("weaker")?;
    let original = bound(&f)?;
    let checkpoint = original.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?;
    let memory = weak(&f)?;
    let mut rebuilt = unbound(&f.handle)?;
    rebuilt.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &memory)?;
    let before = rebuilt.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?;
    assert!(rebuilt.restore_cursor_checkpoint(&checkpoint, MAX_CHECKPOINT, TimestampNs(20)).is_err());
    assert_eq!(rebuilt.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?, before);
    assert_eq!(memory.reads.get(), 1); // Only the original weak registration, not recovery.
    Ok(())
}

#[test]
fn recovery_rejects_cached_h3_substitutes_both_before_and_after_checkpoint_restore() -> Value {
    let f = setup("cached")?;
    let mut original = bound(&f)?;
    let checkpoint = original.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    let artifact = original.hydrate_from_source(&request(&f.handle, HydrationLevel::H3)?,
        &reader, TimestampNs(20))?.artifact.ok_or("missing original")?;
    let mut cached = unbound(&f.handle)?;
    cached.register_artifact(&f.handle.handle_id, f.handle.descriptor_digest, artifact.clone())?;
    let bytes = cached.stored_payload_bytes();
    assert!(cached.restore_cursor_checkpoint(&checkpoint, MAX_CHECKPOINT, TimestampNs(20)).is_err());
    assert_eq!(cached.stored_payload_bytes(), bytes);
    let mut missing = ReferenceHydrationCatalog::new();
    missing.restore_cursor_checkpoint(&checkpoint, MAX_CHECKPOINT, TimestampNs(20))?;
    missing.register_descriptor(f.handle.clone())?;
    assert!(missing.register_artifact(&f.handle.handle_id, f.handle.descriptor_digest, artifact).is_err());
    assert_eq!(missing.stored_payload_bytes(), 0);
    assert!(missing.hydrate(&request(&f.handle, HydrationLevel::H3)?, TimestampNs(21)).is_err());
    Ok(())
}

#[test]
fn absent_sources_can_be_rebuilt_later_but_the_wrong_profile_refuses_before_io() -> Value {
    let f = setup("late-bind")?;
    let original = bound(&f)?;
    let checkpoint = original.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?;
    let binding = original.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .ok_or("missing original binding")?;
    let mut missing = ReferenceHydrationCatalog::new();
    missing.restore_cursor_checkpoint(&checkpoint, MAX_CHECKPOINT, TimestampNs(20))?;
    assert_eq!(missing.source_binding_requirement(f.handle.descriptor_digest), Some(binding.custody_binding_digest()));
    assert!(missing.source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    missing.register_descriptor(f.handle.clone())?;
    let memory = weak(&f)?;
    assert!(missing.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &memory).is_err());
    assert_eq!(memory.reads.get(), 0);
    assert!(missing.source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    bind(&f, &f.handle, &mut missing)?;
    assert_eq!(missing.source_binding(&f.handle.handle_id, f.handle.descriptor_digest), Some(binding));
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    assert_eq!(missing.hydrate_from_source(&request(&f.handle, HydrationLevel::H3)?,
        &reader, TimestampNs(21))?.artifact.ok_or("source missing")?.payload, SOURCE);
    Ok(())
}

#[test]
fn absent_historical_sources_do_not_disable_independent_current_sources_or_forget_history() -> Value {
    let f = setup("independent")?;
    let original = bound(&f)?;
    let checkpoint = original.checkpoint_cursors(TimestampNs(20), MAX_CHECKPOINT)?;
    let original_pin = original.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .ok_or("missing original")?.custody_binding_digest();
    let mut rebuilt = ReferenceHydrationCatalog::new();
    rebuilt.restore_cursor_checkpoint(&checkpoint, MAX_CHECKPOINT, TimestampNs(20))?;
    let other = handle(&f.deployment, OTHER, "independent")?;
    rebuilt.register_descriptor(other.clone())?;
    bind(&f, &other, &mut rebuilt)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &other.anchor, DeploymentSourceLimits::default(), &|| false);
    assert_eq!(rebuilt.hydrate_from_source(&request(&other, HydrationLevel::H3)?,
        &reader, TimestampNs(21))?.artifact.ok_or("no independent source")?.payload, OTHER);
    assert!(rebuilt.descriptor(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    let later = rebuilt.checkpoint_cursors(TimestampNs(200), MAX_CHECKPOINT)?;
    let mut reopened = ReferenceHydrationCatalog::new();
    reopened.restore_cursor_checkpoint(&later, MAX_CHECKPOINT, TimestampNs(200))?;
    assert_eq!(reopened.source_binding_requirement(f.handle.descriptor_digest), Some(original_pin));
    assert!(reopened.source_binding_requirement(other.descriptor_digest).is_some());
    assert_eq!(reopened.stored_payload_bytes(), 0);
    Ok(())
}

fn params(handle: &SemanticHandle) -> Value<AgentSessionParams> {
    let request = request(handle, HydrationLevel::H3)?;
    Ok(AgentSessionParams {
        session_id: request.session_id,
        mission_id: MissionId::parse("mission:source-recovery")?,
        principal_id: PrincipalId::parse("principal:source-owner")?,
        capabilities: request.available_capabilities,
        privacy_scope: request.authorized_privacy_classes,
        current_anchor: handle.anchor.clone(),
        view_id: "AVIEW-001".to_owned(), token_budget: 2048,
        symbol_table_generation: 0, last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0, expires_at_ns: 1000,
    })
}

#[test]
fn journaled_preview_pins_source_custody_and_cold_reopen_preserves_charge_and_cursor() -> Value {
    let f = setup("durable-cursor")?;
    let original = bound(&f)?;
    let session = params(&f.handle)?;
    let path = f.directory.join("disclosure.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, original)?;
    owner.open_session(session.clone(), f.handle.contract_basis.clone(), TimestampNs(10))?;
    let alias = owner.bind(&session.principal_id, &SessionBindingRequest {
        session_id: session.session_id.clone(), generation: 0,
        handle_id: f.handle.handle_id.clone(), descriptor_digest: f.handle.descriptor_digest,
    }, TimestampNs(10))?;
    let response = owner.hydrate(&session.principal_id, &alias,
        &request(&f.handle, HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = response.response.receipt.continuation.ok_or("no H3 continuation")?;
    let pin = owner.committed_root();
    drop(owner);
    let disk = fs::read(&path)?;

    let memory = weak(&f)?;
    let mut downgraded = unbound(&f.handle)?;
    downgraded.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &memory)?;
    assert!(DurableDisclosureStore::open_existing(&path, pin, limits, downgraded).is_err());
    assert_eq!(fs::read(&path)?, disk);

    // The owner remains usable when original custody is unavailable. Its pin constrains later
    // registration, rather than requiring a repair, payload resurrection, or a weaker cache.
    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, ReferenceHydrationCatalog::new())?;
    assert_eq!(owner.remaining_token_budget(&session.principal_id, &session.session_id, TimestampNs(20))?, 1536);
    assert!(!owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    owner.register_descriptor(f.handle.clone())?;
    owner.register_artifact(&f.handle.handle_id, f.handle.descriptor_digest, preview(&f.handle)?)?;
    let memory = weak(&f)?;
    assert!(owner.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &memory).is_err());
    assert_eq!(memory.reads.get(), 0);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    owner.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &reader)?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.continuation = Some(cursor.clone());
    req.issued_at = TimestampNs(21);
    req.request_digest = req.computed_digest();
    req.request_id = format!("hydration-request:{}", req.request_digest);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    let delivered = owner.hydrate_from_source(&session.principal_id, &alias, &req, &reader, TimestampNs(22))?;
    assert_eq!(delivered.response.artifact.ok_or("missing source")?.payload, SOURCE);
    assert_eq!(delivered.admission.consumed_cursor(), Some(cursor.cursor_digest));
    let pin = owner.committed_root();
    drop(owner);

    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, bound(&f)?)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    assert!(owner.hydrate_from_source(&session.principal_id, &alias, &req, &reader, TimestampNs(23)).is_err());
    assert!(!reader.attempted());
    assert_eq!(owner.remaining_token_budget(&session.principal_id, &session.session_id, TimestampNs(23))?, 1024);
    assert_eq!(owner.admissions(&session.principal_id, &session.session_id, req.request_digest, 8, TimestampNs(23))?.len(), 1);
    assert!(!fs::read(&path)?.windows(SOURCE.len()).any(|bytes| bytes == SOURCE));
    Ok(())
}
