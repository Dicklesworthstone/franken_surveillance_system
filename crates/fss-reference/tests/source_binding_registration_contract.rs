#![forbid(unsafe_code)]
//! Durable registration must fence deployment custody before the first evidence disclosure.
//! Only synthetic private deployment trees are used by these regression contracts.

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
    PrincipalId, SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
};
use fss_object::{HostSpoolIo, InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_publication::SlotName;
use fss_reference::agent_session::checkpoint::journal::DurableSessionLimits;
use fss_reference::agent_session::checkpoint::journal::disclosure::{
    DurableDisclosureStore, JournaledSourceBinding,
};
use fss_reference::deletion::belief::hydration::{DeletionAwareSourceReader, DeploymentSourceLimits};
use fss_reference::{
    PublishedSourceReader, ReferenceDeployment, ReferenceHydrationCatalog, SessionBindingRequest,
    SourceHydrationError,
};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"private registration source: never save this payload in a session journal";
const OTHER: &[u8] = b"independent volatile source must not become implicitly durable";
const META: &[u8] = b"required original provenance metadata";
const TOKENS: u64 = 3;
const SESSION_TOKENS: u64 = 12;

struct Fixture {
    deployment: ReferenceDeployment,
    directory: PathBuf,
    slot: SlotName,
    alias_slot: SlotName,
    manifest: ObjectManifest,
    handle: SemanticHandle,
}

fn handle(deployment: &ReferenceDeployment, bytes: &[u8], name: &str) -> Value<SemanticHandle> {
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(TOKENS).build()?;
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "source-registration:test",
        )),
        anchor: deployment.current_anchor().clone(),
        subject_id: format!("subject:{name}"),
        subject_digest: ContentDigest::sha256(bytes),
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
    let directory = fresh_dir(&format!("source-registration-{label}"))?;
    let mut deployment = open(&directory.join("deployment"), standard())?;
    let context = cx(label)?;
    let slot = SlotName::parse("source")?;
    let staged = deployment.stage_and_publish(&slot, &[SOURCE, OTHER, META], &context)?;
    deployment.publish_and_commit(&slot, &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &context)?;
    // Both slots exist before any descriptor is created: refusal below is not stale-anchor drift.
    let alias_slot = SlotName::parse("source-alias")?;
    deployment.publish_and_commit(&alias_slot, &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &context)?;
    let handle = handle(&deployment, SOURCE, "original")?;
    Ok(Fixture { deployment, directory, slot, alias_slot, manifest: staged.manifest, handle })
}

fn blueprint(handle: &SemanticHandle) -> Value<ReferenceHydrationCatalog> {
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest,
        HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"preview".to_vec(),
            [handle.subject_digest], Completeness::Complete, None)?)?;
    Ok(catalog)
}

fn register(f: &Fixture, owner: &mut DurableDisclosureStore, now: i128) -> Value<JournaledSourceBinding> {
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    let receipt = owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest,
        f.manifest.root(), &reader, TimestampNs(now))?;
    assert!(reader.attempted());
    Ok(receipt)
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
fn no_source(path: &PathBuf) -> Value {
    let journal = fs::read(path)?;
    for bytes in [SOURCE, OTHER] {
        assert!(!journal.windows(bytes.len()).any(|window| window == bytes));
    }
    Ok(())
}

#[test]
fn durable_registration_fences_weaker_and_equal_content_aliases_before_any_disclosure() -> Value {
    let f = setup("profile")?;
    let path = f.directory.join("sessions.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, blueprint(&f.handle)?)?;
    let registered = register(&f, &mut owner, 10)?;
    let expected = registered.binding.custody_binding_digest();
    assert!(registered.binding.deployment_authority().is_some());
    assert_eq!(owner.catalog().issued_cursor_count(), 0);
    drop(owner);
    let original_bytes = fs::read(&path)?;
    let memory = weak(&f)?;
    let mut weaker = blueprint(&f.handle)?;
    weaker.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.manifest.root(), &memory)?;
    assert!(DurableDisclosureStore::open_existing(&path, registered.committed_root, limits, weaker).is_err());
    assert_eq!(fs::read(&path)?, original_bytes);
    let mut owner = DurableDisclosureStore::open_existing(
        &path, registered.committed_root, limits, ReferenceHydrationCatalog::new(),
    )?;
    assert_eq!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest), Some(expected));
    owner.register_descriptor(f.handle.clone())?;
    let reads = memory.reads.get();
    assert!(owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest,
        f.manifest.root(), &memory, TimestampNs(11)).is_err());
    assert_eq!(memory.reads.get(), reads);
    let alias = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.alias_slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    assert!(owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest,
        f.manifest.root(), &alias, TimestampNs(11)).is_err());
    assert!(!alias.attempted());
    assert_eq!(owner.committed_root(), registered.committed_root);
    let restored = register(&f, &mut owner, 11)?;
    assert_eq!(restored.binding, registered.binding);
    no_source(&path)
}

fn request(handle: &SemanticHandle, level: HydrationLevel) -> Value<HydrationRequest> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:registration")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:source".to_owned()]),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::builder().bytes(1024).tokens(TOKENS).build()?,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10),
    })?)
}

#[test]
fn registration_and_charged_disclosures_interleave_without_resetting_cursors_or_balances() -> Value {
    let f = setup("interleaved")?;
    let path = f.directory.join("sessions.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, blueprint(&f.handle)?)?;
    let registered = register(&f, &mut owner, 10)?;
    let source_request = request(&f.handle, HydrationLevel::H3)?;
    let params = AgentSessionParams {
        session_id: source_request.session_id.clone(),
        mission_id: MissionId::parse("mission:registration")?,
        principal_id: PrincipalId::parse("principal:registration")?,
        capabilities: source_request.available_capabilities.clone(),
        privacy_scope: source_request.authorized_privacy_classes.clone(),
        current_anchor: f.handle.anchor.clone(),
        view_id: "AVIEW-001".to_owned(),
        token_budget: SESSION_TOKENS,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1,
        expires_at_ns: 1000,
    };
    owner.open_session(params.clone(), f.handle.contract_basis.clone(), TimestampNs(11))?;
    let alias = owner.bind(&params.principal_id, &SessionBindingRequest {
        session_id: params.session_id.clone(), generation: 0,
        handle_id: f.handle.handle_id.clone(), descriptor_digest: f.handle.descriptor_digest,
    }, TimestampNs(11))?;
    assert!(owner.admissions(&params.principal_id, &params.session_id,
        source_request.request_digest, 8, TimestampNs(11))?.is_empty());
    let preview = owner.hydrate(&params.principal_id, &alias,
        &request(&f.handle, HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = preview.response.receipt.continuation.ok_or("no source continuation")?;
    register(&f, &mut owner, 21)?;
    assert!(!owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id,
        TimestampNs(21))?, SESSION_TOKENS - TOKENS);
    let pin = owner.committed_root();
    drop(owner);

    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, blueprint(&f.handle)?)?;
    // Reconstruct absent source under its saved requirement. This retry is not a disclosure.
    register(&f, &mut owner, 22)?;
    let mut source_request = source_request;
    source_request.continuation = Some(cursor.clone());
    source_request.issued_at = TimestampNs(21);
    source_request.request_digest = source_request.computed_digest();
    source_request.request_id = format!("hydration-request:{}", source_request.request_digest);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    let delivery = owner.hydrate_from_source(&params.principal_id, &alias,
        &source_request, &reader, TimestampNs(23))?;
    registered.binding.validate_response(&source_request, &f.handle, &delivery.response)?;
    assert_eq!(delivery.response.artifact.as_ref().ok_or("no original bytes")?.payload, SOURCE);
    assert_eq!(delivery.admission.charged_tokens(), TOKENS);
    register(&f, &mut owner, 24)?;
    assert!(owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost consumed cursor")?.consumed);
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id,
        TimestampNs(24))?, SESSION_TOKENS - 2 * TOKENS);
    assert_eq!(owner.admissions(&params.principal_id, &params.session_id,
        source_request.request_digest, 8, TimestampNs(24))?.len(), 1);
    let pin = owner.committed_root();
    drop(owner);

    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, blueprint(&f.handle)?)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| false);
    assert!(owner.hydrate_from_source(&params.principal_id, &alias,
        &source_request, &reader, TimestampNs(25)).is_err());
    assert!(!reader.attempted());
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id,
        TimestampNs(25))?, SESSION_TOKENS - 2 * TOKENS);
    no_source(&path)
}

#[test]
fn registration_does_not_implicitly_pin_other_volatile_source_bindings() -> Value {
    let f = setup("one-selected")?;
    let other = handle(&f.deployment, OTHER, "other")?;
    let mut catalog = blueprint(&f.handle)?;
    catalog.register_descriptor(other.clone())?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &other.anchor, DeploymentSourceLimits::default(), &|| false);
    catalog.bind_deployment_source_object(&other.handle_id, other.descriptor_digest, &reader)?;
    let path = f.directory.join("sessions.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, catalog)?;
    let registered = register(&f, &mut owner, 10)?;
    assert!(owner.catalog().source_binding(&other.handle_id, other.descriptor_digest).is_some());
    assert!(owner.catalog().source_binding_requirement(other.descriptor_digest).is_none());
    drop(owner);
    let owner = DurableDisclosureStore::open_existing(&path, registered.committed_root,
        limits, ReferenceHydrationCatalog::new())?;
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some());
    assert!(owner.catalog().source_binding_requirement(other.descriptor_digest).is_none());
    no_source(&path)
}

#[test]
fn cancelled_registration_has_no_requirement_or_successful_journal_record() -> Value {
    let f = setup("cancelled")?;
    let path = f.directory.join("sessions.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, blueprint(&f.handle)?)?;
    let initial = owner.committed_root();
    let original = fs::read(&path)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot,
        &f.handle.anchor, DeploymentSourceLimits::default(), &|| true);
    assert!(owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest,
        f.manifest.root(), &reader, TimestampNs(10)).is_err());
    assert!(reader.attempted());
    assert!(reader.custody_usage().is_none());
    assert_eq!(owner.committed_root(), initial);
    assert_eq!(fs::read(&path)?, original);
    assert!(!owner.needs_reconciliation());
    assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    drop(owner);
    let owner = DurableDisclosureStore::open_existing(&path, initial, limits,
        ReferenceHydrationCatalog::new())?;
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_none());
    Ok(())
}

#[test]
fn fresh_registration_rejects_corrupt_unused_metadata_and_never_repairs_it() -> Value {
    let f = setup("metadata")?;
    let path = f.directory.join("sessions.journal");
    let mut owner = DurableDisclosureStore::create(&path, DurableSessionLimits::default(),
        blueprint(&f.handle)?)?;
    let initial = owner.committed_root();
    let object = f.deployment.publisher().spool().object_path(ContentDigest::sha256(META));
    let mut damaged = fs::read(&object)?;
    *damaged.last_mut().ok_or("empty metadata envelope")? ^= 1;
    fs::write(&object, &damaged)?;
    assert!(register(&f, &mut owner, 10).is_err());
    assert_eq!(owner.committed_root(), initial);
    assert!(!owner.needs_reconciliation());
    assert_eq!(fs::read(&object)?, damaged);
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_none());
    assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    no_source(&path)
}
