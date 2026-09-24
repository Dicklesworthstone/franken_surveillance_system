#![forbid(unsafe_code)]
//! Native source custody, reopen, fault, and in-memory differential tests.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, SemanticHandle,
    SemanticHandleSpec, SessionId, TimestampNs,
};
use fss_object::{
    FaultInjectingSpoolIo, InMemoryObjectStore, ObjectLimits, ObjectManifest, SpoolFaultPlan,
    SpoolIo, SpoolIoCall, SpoolLimits,
};
use fss_publication::{
    LOCAL_ROOTS_DIR, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    PublishCutPoint, ROOT_RECORD_SUFFIX, SlotName,
};
use fss_reference::{ReferenceHydrationCatalog, SourceHydrationError};

type TestResult = Result<(), Box<dyn Error>>;
const SOURCE: &[u8] = b"original on-disk camera packet";
const METADATA: &[u8] = b"exact source provenance and capture metadata";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let parent = Path::new(env!("CARGO_TARGET_TMPDIR")).join("local_source_hydration");
        fs::create_dir_all(&parent)?;
        for attempt in 0..64 {
            let path = parent.join(format!("{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity exhausted".into())
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

struct Fixture {
    // Drop the lock owner before removing its exclusively owned test directory.
    publisher: LocalRootPublisher,
    directory: TestDirectory,
    io: Arc<FaultInjectingSpoolIo>,
    catalog: ReferenceHydrationCatalog,
    handle: SemanticHandle,
    manifest: ObjectManifest,
    slot: SlotName,
    metadata: ContentDigest,
}

fn fixture(name: &str, plan: SpoolFaultPlan) -> Result<Fixture, Box<dyn Error>> {
    let directory = TestDirectory::create(name)?;
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let capability: Arc<dyn SpoolIo> = io.clone();
    let mut publisher = LocalRootPublisher::open_with_io(&directory.0, limits(), capability)?;
    let source = publisher.stage_object(SOURCE)?;
    let metadata = publisher.stage_object(METADATA)?;
    let manifest = ObjectManifest::new("source", [source], Some(metadata))?;
    let slot = SlotName::parse("source")?;
    publisher.publish(&slot, &manifest)?;
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(512).build()?;
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s",
            b"o",
            b"v",
            b"c",
            b"e",
            b"cost",
            "source-local:test",
        )),
        anchor: LedgerAnchor::genesis("site:source-local"),
        subject_id: "subject:source".to_owned(),
        subject_digest: source,
        semantic_type: "source_object".to_owned(),
        source_id: "sensor:source".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels
            .iter()
            .map(|level| {
                let required = if *level == HydrationLevel::H3 {
                    BTreeSet::from(["capability:source".to_owned()])
                } else {
                    BTreeSet::new()
                };
                (*level, required)
            })
            .collect(),
        estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    catalog.register_artifact(
        &handle.handle_id,
        handle.descriptor_digest,
        HydrationArtifact::publish(
            HydrationLevel::H2,
            "text/plain",
            b"bounded preview".to_vec(),
            [handle.subject_digest],
            Completeness::Complete,
            None,
        )?,
    )?;
    catalog.bind_local_source_object(
        &handle.handle_id,
        handle.descriptor_digest,
        manifest.root(),
        &publisher,
        io.as_ref(),
    )?;
    Ok(Fixture {
        publisher,
        directory,
        io,
        catalog,
        handle,
        manifest,
        slot,
        metadata,
    })
}

fn request(
    handle: &SemanticHandle,
    level: HydrationLevel,
) -> Result<HydrationRequest, Box<dyn Error>> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:local-source")?,
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

fn reseal(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

fn call_counts(io: &FaultInjectingSpoolIo) -> Vec<u64> {
    SpoolIoCall::ALL
        .iter()
        .map(|call| io.calls(*call))
        .collect()
}

fn corrupt(path: &Path) -> TestResult {
    let mut bytes = fs::read(path)?;
    *bytes.last_mut().ok_or("empty fault target")? ^= 1;
    fs::write(path, bytes)?;
    Ok(())
}

#[test]
fn disk_and_memory_custody_produce_identical_receipts_without_writes() -> TestResult {
    let mut f = fixture("differential", SpoolFaultPlan::new())?;
    let mut memory = InMemoryObjectStore::new(ObjectLimits::new(16, 65536));
    memory.put_verified(SOURCE)?;
    memory.put_verified(METADATA)?;
    memory.publish_manifest(f.manifest.clone())?;
    let mut oracle = f.catalog.clone();
    let req = request(&f.handle, HydrationLevel::H3)?;
    let cached = f.catalog.stored_payload_bytes();
    let before = call_counts(f.io.as_ref());
    let disk =
        f.catalog
            .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20))?;
    let reference = oracle.hydrate_from_source(&req, &memory, TimestampNs(20))?;
    assert_eq!(disk, reference);
    disk.validate_for(&req, &f.handle)?;
    assert_eq!(
        disk.artifact.as_ref().ok_or("missing artifact")?.payload,
        SOURCE
    );
    assert_eq!(f.catalog.stored_payload_bytes(), cached);
    for (index, call) in SpoolIoCall::ALL.iter().enumerate() {
        if call.is_mutating() {
            assert_eq!(f.io.calls(*call), before[index], "unexpected {call}");
        }
    }
    Ok(())
}

#[test]
fn reopening_disk_custody_preserves_binding_and_exact_source_bytes() -> TestResult {
    let f = fixture("reopen", SpoolFaultPlan::new())?;
    let Fixture {
        publisher,
        directory,
        io,
        mut catalog,
        handle,
        manifest,
        slot,
        ..
    } = f;
    let binding = catalog
        .source_binding(&handle.handle_id, handle.descriptor_digest)
        .cloned()
        .ok_or("missing binding")?;
    drop(publisher);
    let capability: Arc<dyn SpoolIo> = io.clone();
    let reopened = LocalRootPublisher::open_with_io(&directory.0, limits(), capability)?;
    assert_eq!(
        reopened.root(&slot).ok_or("missing recovered root")?.state,
        LocalPublicationState::Durable
    );
    assert_eq!(
        binding,
        catalog.bind_local_source_object(
            &handle.handle_id,
            handle.descriptor_digest,
            manifest.root(),
            &reopened,
            io.as_ref(),
        )?
    );
    let req = request(&handle, HydrationLevel::H3)?;
    let result =
        catalog.hydrate_from_local_source(&req, &reopened, io.as_ref(), TimestampNs(20))?;
    assert_eq!(result.artifact.ok_or("missing source")?.payload, SOURCE);
    drop(reopened);
    Ok(())
}

#[test]
fn denials_and_expiry_perform_zero_local_io() -> TestResult {
    let mut f = fixture("denials", SpoolFaultPlan::new())?;
    let before = call_counts(f.io.as_ref());
    for case in 0..3 {
        let mut req = request(&f.handle, HydrationLevel::H3)?;
        match case {
            0 => req.available_capabilities.clear(),
            1 => req.authorized_privacy_classes.clear(),
            _ => req.budget = BudgetVector::builder().bytes(1024).tokens(511).build()?,
        }
        reseal(&mut req);
        assert!(
            f.catalog
                .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20),)
                .is_err()
        );
    }
    let req = request(&f.handle, HydrationLevel::H3)?;
    let expired =
        f.catalog
            .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(100))?;
    assert_eq!(expired.receipt.availability, HandleAvailability::Expired);
    assert!(expired.artifact.is_none());
    assert_eq!(before, call_counts(f.io.as_ref()));
    Ok(())
}

#[test]
fn corrupt_root_source_or_metadata_blocks_a_previously_successful_read() -> TestResult {
    for case in 0..3 {
        let mut f = fixture(&format!("corrupt-{case}"), SpoolFaultPlan::new())?;
        let req = request(&f.handle, HydrationLevel::H3)?;
        f.catalog
            .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20))?;
        let target = match case {
            0 => f
                .directory
                .0
                .join(LOCAL_ROOTS_DIR)
                .join(format!("{}{ROOT_RECORD_SUFFIX}", f.slot)),
            1 => f.publisher.spool().object_path(f.handle.subject_digest),
            _ => f.publisher.spool().object_path(f.metadata),
        };
        corrupt(&target)?;
        assert!(
            f.catalog
                .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(21),)
                .is_err()
        );
        assert!(matches!(
            f.catalog.hydrate(&req, TimestampNs(21)),
            Err(HydrationError::LevelUnavailable)
        ));
    }
    Ok(())
}

#[test]
fn staged_root_and_out_of_scope_source_are_not_disclosable() -> TestResult {
    let mut f = fixture("scope", SpoolFaultPlan::new())?;
    let staged = ObjectManifest::new("staged", [f.handle.subject_digest], None)?;
    f.publisher
        .stage_manifest(&SlotName::parse("staged")?, &staged)?;
    let other = f.publisher.stage_object(b"unrelated bytes")?;
    let unrelated = ObjectManifest::new("unrelated", [other], None)?;
    f.publisher
        .publish(&SlotName::parse("other")?, &unrelated)?;
    for root in [staged.root(), unrelated.root()] {
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(f.handle.clone())?;
        assert!(matches!(
            catalog.bind_local_source_object(
                &f.handle.handle_id,
                f.handle.descriptor_digest,
                root,
                &f.publisher,
                f.io.as_ref(),
            ),
            Err(SourceHydrationError::NotReachable)
        ));
        assert!(
            catalog
                .source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn disappearing_nested_publication_cannot_shrink_the_source_closure() -> TestResult {
    let mut f = fixture("nested", SpoolFaultPlan::new())?;
    let parent = ObjectManifest::new("parent", [f.manifest.root()], None)?;
    f.publisher.publish(&SlotName::parse("parent")?, &parent)?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(f.handle.clone())?;
    catalog.bind_local_source_object(
        &f.handle.handle_id,
        f.handle.descriptor_digest,
        parent.root(),
        &f.publisher,
        f.io.as_ref(),
    )?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    catalog.hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20))?;
    fs::remove_file(
        f.directory
            .0
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}", f.slot)),
    )?;
    assert!(matches!(
        catalog.hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(21),),
        Err(SourceHydrationError::SnapshotChanged)
    ));
    Ok(())
}

#[test]
fn an_indeterminate_publication_marker_blocks_source_disclosure() -> TestResult {
    let mut f = fixture("marker", SpoolFaultPlan::new())?;
    fs::write(
        f.directory
            .0
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}.indeterminate", f.slot)),
        b"uncertain root",
    )?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    assert!(matches!(
        f.catalog
            .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20),),
        Err(SourceHydrationError::SnapshotChanged)
    ));
    Ok(())
}

#[test]
fn poisoned_owner_cannot_lend_source_authority() -> TestResult {
    let mut f = fixture("poison", SpoolFaultPlan::new())?;
    let pending = ObjectManifest::new("pending", [f.handle.subject_digest], None)?;
    f.publisher
        .inject_crash_at(PublishCutPoint::AfterRootRename);
    assert!(
        f.publisher
            .publish(&SlotName::parse("pending")?, &pending)
            .is_err()
    );
    assert!(f.publisher.is_poisoned());
    let before = call_counts(f.io.as_ref());
    let req = request(&f.handle, HydrationLevel::H3)?;
    assert!(matches!(
        f.catalog
            .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(20),),
        Err(SourceHydrationError::Publication(_))
    ));
    assert_eq!(before, call_counts(f.io.as_ref()));
    Ok(())
}

fn continued_request(f: &mut Fixture) -> Result<HydrationRequest, Box<dyn Error>> {
    let preview = request(&f.handle, HydrationLevel::H2)?;
    let cursor = f
        .catalog
        .hydrate(&preview, TimestampNs(20))?
        .receipt
        .continuation
        .ok_or("missing H3 continuation")?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.issued_at = TimestampNs(21);
    req.continuation = Some(cursor);
    reseal(&mut req);
    Ok(req)
}

#[test]
fn faults_before_and_after_payload_read_preserve_the_input_continuation() -> TestResult {
    let mut baseline = fixture("fault-baseline", SpoolFaultPlan::new())?;
    let req = continued_request(&mut baseline)?;
    let before = baseline.io.calls(SpoolIoCall::Read);
    baseline.catalog.hydrate_from_local_source(
        &req,
        &baseline.publisher,
        baseline.io.as_ref(),
        TimestampNs(22),
    )?;
    let after = baseline.io.calls(SpoolIoCall::Read);
    assert!(after > before + 1);
    // First read fails preflight; last read fails the post-payload custody revalidation.
    for (index, occurrence) in [before + 1, after].into_iter().enumerate() {
        let plan = SpoolFaultPlan::new().fail(SpoolIoCall::Read, occurrence, io::ErrorKind::Other);
        let mut f = fixture(&format!("fault-{index}"), plan)?;
        assert_eq!(f.io.calls(SpoolIoCall::Read), before);
        let req = continued_request(&mut f)?;
        let cursor = req
            .continuation
            .as_ref()
            .ok_or("missing cursor")?
            .cursor_digest;
        assert!(
            f.catalog
                .hydrate_from_local_source(&req, &f.publisher, f.io.as_ref(), TimestampNs(22),)
                .is_err()
        );
        assert!(f.io.all_fired());
        assert!(
            !f.catalog
                .issued_cursor(&cursor)
                .ok_or("lost cursor")?
                .consumed
        );
        let result = f.catalog.hydrate_from_local_source(
            &req,
            &f.publisher,
            f.io.as_ref(),
            TimestampNs(23),
        )?;
        assert_eq!(result.artifact.ok_or("missing source")?.payload, SOURCE);
        assert!(
            f.catalog
                .issued_cursor(&cursor)
                .ok_or("lost cursor")?
                .consumed
        );
    }
    Ok(())
}
