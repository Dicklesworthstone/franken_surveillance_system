#![forbid(unsafe_code)]
//! Real H3 disclosure through durable authority, committed deletions and unchanged request gates.
//! Fault injection touches only these tests' synthetic deployments, never operator data.

mod file_import_fault_support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use file_import_fault_support::{cx, fixture, fresh_dir, open, request as import_request, standard};
use fss_core::{
    BatchId, BudgetVector, CaptureInterval, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, HandleAvailability, HydrationArtifact, HydrationLevel,
    HydrationPurpose, HydrationRequest, HydrationRequestSpec, LaboratoryAccess, SemanticHandle,
    SemanticHandleSpec, SessionId, TimestampNs,
};
use fss_object::{FaultInjectingSpoolIo, HostSpoolIo, ObjectManifest, SpoolFaultPlan, SpoolIoCall};
use fss_publication::custody_audit::belief_snapshot::durable::DurableBeliefError;
use fss_publication::{LOCAL_ROOTS_DIR, ROOT_RECORD_SUFFIX, SlotName};
use fss_reference::deletion::belief::hydration::{DeletionAwareSourceReader, DeploymentSourceLimits};
use fss_reference::deletion::{
    DeletionError, STAGE_DELETION_AUTHORITY_BATCH_APPENDED, commit_deletion, plan_deletion,
};
use fss_reference::{
    DeploymentLimits, FileIngestAdapter, ReferenceDeployment, ReferenceHydrationCatalog,
    SourceHydrationError,
};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"original authorized source packet";
const METADATA: &[u8] = b"independent required provenance metadata";

struct Fixture {
    deployment: ReferenceDeployment,
    root: PathBuf,
    slot: SlotName,
    manifest: ObjectManifest,
}

fn setup(label: &str) -> Value<Fixture> {
    let root = fresh_dir(&format!("deployment-hydration-{label}"))?.join("deployment");
    let mut deployment = open(&root, standard())?;
    let context = cx(label)?;
    let slot = SlotName::parse("source")?;
    let staged = deployment.stage_and_publish(&slot, &[SOURCE, METADATA], &context)?;
    deployment.publish_and_commit(
        &slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
        &context,
    )?;
    Ok(Fixture { deployment, root, slot, manifest: staged.manifest })
}

fn descriptor(deployment: &ReferenceDeployment, subject: ContentDigest) -> Value<SemanticHandle> {
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(512).build()?;
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "source-deployment:test",
        )),
        anchor: deployment.current_anchor().clone(),
        subject_id: "subject:source".to_owned(),
        subject_digest: subject,
        semantic_type: "source_object".to_owned(),
        source_id: "sensor:source".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| {
            let required = if *level == HydrationLevel::H3 {
                BTreeSet::from(["capability:source".to_owned()])
            } else {
                BTreeSet::new()
            };
            (*level, required)
        }).collect(),
        estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

fn catalog(handle: &SemanticHandle) -> Value<ReferenceHydrationCatalog> {
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    catalog.register_artifact(
        &handle.handle_id,
        handle.descriptor_digest,
        HydrationArtifact::publish(
            HydrationLevel::H2, "text/plain", b"bounded preview".to_vec(),
            [handle.subject_digest], Completeness::Complete, None,
        )?,
    )?;
    Ok(catalog)
}

fn request(handle: &SemanticHandle) -> Value<HydrationRequest> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:deployment-source")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H3,
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

fn bind(f: &Fixture, handle: &SemanticHandle, catalog: &mut ReferenceHydrationCatalog) -> Value {
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false,
    );
    let binding = catalog.bind_deployment_source_object(
        &handle.handle_id, handle.descriptor_digest, &reader,
    )?;
    assert_eq!(binding.subject_digest(), handle.subject_digest);
    assert!(reader.attempted());
    Ok(())
}

fn tree(root: &Path) -> Value<BTreeMap<PathBuf, ContentDigest>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                result.insert(entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?));
            }
        }
    }
    Ok(result)
}

fn no_io(io: &FaultInjectingSpoolIo) {
    for call in SpoolIoCall::ALL {
        assert_eq!(io.calls(call), 0, "unexpected {call}");
    }
}

#[test]
fn cold_deployment_disclosure_retains_ordinary_receipts_without_source_caching_or_writes() -> Value {
    let f = setup("cold")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let binding = catalog.source_binding(&handle.handle_id, handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let Fixture { deployment, root, slot, .. } = f;
    drop(deployment);
    let deployment = open(&root, standard())?;
    let before = tree(&root)?;
    let cached = catalog.stored_payload_bytes();
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &deployment, &io, &slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    let req = request(&handle)?;
    let response = catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20))?;
    binding.validate_response(&req, &handle, &response)?;
    assert_eq!(response.artifact.ok_or("no source")?.payload, SOURCE);
    let usage = reader.custody_usage().ok_or("capture unaccounted")?;
    assert!(usage.charged_read_bytes > 0 && usage.io_calls > 0);
    assert!(usage.retained_bytes > SOURCE.len() as u64);
    assert_eq!(catalog.stored_payload_bytes(), cached);
    for call in SpoolIoCall::ALL {
        if call.is_mutating() { assert_eq!(io.calls(call), 0, "unexpected {call}"); }
    }
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn capability_privacy_quote_and_expiry_checks_precede_even_deletion_admission() -> Value {
    let f = setup("grants")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    for case in 0..3 {
        let mut req = request(&handle)?;
        match case {
            0 => req.available_capabilities.clear(),
            1 => req.authorized_privacy_classes.clear(),
            _ => req.budget = BudgetVector::builder().bytes(1024).tokens(511).build()?,
        }
        reseal(&mut req);
        let reader = DeletionAwareSourceReader::new(
            &f.deployment, &io, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
        );
        assert!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)).is_err());
        assert!(!reader.attempted());
        assert_eq!(reader.deletion_usage().record_reads, 0);
        assert!(reader.custody_usage().is_none());
    }
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    let expired = catalog.hydrate_from_deployment_source(&request(&handle)?, &reader, TimestampNs(100))?;
    assert_eq!(expired.receipt.availability, HandleAvailability::Expired);
    assert!(expired.artifact.is_none());
    assert!(!reader.attempted());
    let mut preview = request(&handle)?;
    preview.requested_level = HydrationLevel::H2;
    reseal(&mut preview);
    let response = catalog.hydrate_from_deployment_source(&preview, &reader, TimestampNs(20))?;
    assert_eq!(response.artifact.ok_or("no preview")?.level, HydrationLevel::H2);
    assert!(!reader.attempted());
    no_io(&io);
    Ok(())
}

#[test]
fn cancellation_and_second_attempt_cannot_disclose_or_refill_a_reader() -> Value {
    let f = setup("cancel")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let flag = AtomicBool::new(true);
    let cancelled = || flag.load(Ordering::Acquire);
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &cancelled,
    );
    let req = request(&handle)?;
    assert!(matches!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::Cancelled)));
    let used = reader.deletion_usage();
    flag.store(false, Ordering::Release);
    assert!(matches!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::Limit("source disclosure attempts"))));
    assert_eq!(reader.deletion_usage(), used);
    no_io(&io);
    Ok(())
}

#[test]
fn current_source_bytes_do_not_rescue_a_stale_authority_descriptor() -> Value {
    let mut f = setup("stale")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    f.deployment.append_batch(BatchId::parse("batch:advance")?, vec![], vec![], &cx("advance")?)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(catalog.hydrate_from_deployment_source(&request(&handle)?, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::AuthorityChanged)));
    assert_eq!(reader.deletion_usage().record_reads, 0);
    no_io(&io);
    Ok(())
}

#[test]
fn closure_retention_budget_counts_metadata_and_accepts_only_the_exact_boundary() -> Value {
    let f = setup("bounds")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let req = request(&handle)?;
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20))?;
    let bytes = reader.custody_usage().ok_or("no cost")?.retained_bytes;
    let exact = DeploymentSourceLimits { max_retained_bytes: bytes, ..Default::default() };
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor, exact, &|| false,
    );
    assert!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)).is_ok());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits { max_retained_bytes: bytes - 1, ..exact }, &|| false,
    );
    assert!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)).is_err());
    assert!(reader.custody_usage().is_none());
    assert!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)).is_err());
    Ok(())
}

#[test]
fn corrupt_unused_sibling_is_not_silently_ignored_or_downgraded_to_a_preview() -> Value {
    let f = setup("sibling")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let path = f.deployment.publisher().spool().object_path(ContentDigest::sha256(METADATA));
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty object")? ^= 1;
    fs::write(&path, &bytes)?;
    let before = tree(&f.root)?;
    let cached = catalog.stored_payload_bytes();
    let mut req = request(&handle)?;
    req.allow_lower_level = true;
    reseal(&mut req);
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(catalog.hydrate_from_deployment_source(&req, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::Capture(_))));
    assert_eq!(catalog.stored_payload_bytes(), cached);
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

#[test]
fn another_slot_with_the_same_root_cannot_replace_the_exact_selected_record() -> Value {
    let mut f = setup("alias")?;
    let alias = SlotName::parse("source-alias")?;
    f.deployment.publish_and_commit(
        &alias, &f.manifest, CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &cx("alias")?,
    )?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let path = f.deployment.publisher().root_dir().join(LOCAL_ROOTS_DIR)
        .join(format!("{}{ROOT_RECORD_SUFFIX}", f.slot));
    fs::remove_file(&path)?;
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    assert!(catalog.hydrate_from_deployment_source(&request(&handle)?, &reader, TimestampNs(20)).is_err());
    assert!(!path.exists());
    // The remaining alias has its own current ledger authority and exact native record.
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &alias, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    let response = catalog.hydrate_from_deployment_source(&request(&handle)?, &reader, TimestampNs(20))?;
    assert_eq!(response.artifact.ok_or("no alias source")?.payload, SOURCE);
    Ok(())
}

#[test]
fn locally_published_but_unledgered_source_cannot_acquire_a_deployment_binding() -> Value {
    let root = fresh_dir("deployment-hydration-unledgered")?.join("deployment");
    let mut deployment = open(&root, standard())?;
    let slot = SlotName::parse("unledgered")?;
    deployment.stage_and_publish(&slot, &[SOURCE], &cx("unledgered")?)?;
    let handle = descriptor(&deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &deployment, &io, &slot, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(catalog.bind_deployment_source_object(&handle.handle_id, handle.descriptor_digest, &reader),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::Selection)));
    assert!(catalog.source_binding(&handle.handle_id, handle.descriptor_digest).is_none());
    no_io(&io);
    Ok(())
}

fn pending_deletion(cold: bool) -> Value {
    let dir = fresh_dir(if cold { "hydrate-cold-header" } else { "hydrate-live-header" })?;
    let root = dir.join("deployment");
    let limits = DeploymentLimits { batch_entries_max: 16, manifest_children_max: 8, ..standard() };
    let mut deployment = open(&root, limits)?;
    let context = cx("hydrate-header-setup")?;
    let survivor = SlotName::parse("survivor")?;
    let staged = deployment.stage_and_publish(&survivor, &[SOURCE], &context)?;
    deployment.publish_and_commit(&survivor, &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &context)?;
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let input = dir.join("input.mjpeg");
    fs::write(&input, frame.repeat(40))?;
    let retained = FileIngestAdapter::ingest(
        import_request(&input, frame.len() as u64, 8)?, &context, &mut deployment,
    )?;
    let subject = ContentDigest::sha256(&frame);
    // Partitioned imports keep payload custody in independently published parts. The aggregate
    // root contains only metadata; its typed part references are not native source reachability.
    assert!(!retained.manifest.part_roots.is_empty());
    assert!(!deployment.publisher().root_closure(&retained.root_slot)
        .ok_or("no import closure")?.contains(&subject));
    let victim = deployment.publisher().visible_roots().find(|entry| {
        retained.manifest.part_roots.contains(&entry.root)
            && deployment.publisher().root_closure(&entry.slot)
                .is_some_and(|closure| closure.contains(&subject))
    }).ok_or("no source publication part")?;
    let victim_root = victim.root;
    let victim = victim.slot.clone();
    let plan = plan_deletion(&deployment, retained.import_identity, &context)?;
    assert!(plan.blockers.is_empty());
    assert!(plan.tombstones.len() > limits.batch_entries_max);
    assert!(plan.retractions.iter().any(|retraction| {
        retraction.slot == victim.as_str() && retraction.root == victim_root
    }));
    assert!(plan.deletable.iter().any(|object| object.digest == subject));
    let stop = cx("hydrate-header-stop")?;
    stop.set_cancel_at_checkpoint_occurrence(STAGE_DELETION_AUTHORITY_BATCH_APPENDED, 1);
    assert!(matches!(commit_deletion(&mut deployment, plan.digest()?,
        plan.approval_digest("operator:hydrate-header")?, "operator:hydrate-header", &stop),
        Err(DeletionError::Cancelled { .. })));
    if cold {
        drop(deployment);
        deployment = open(&root, limits)?;
    }
    for object in &plan.deletable {
        assert!(deployment.publisher().object_name_present(object.digest));
    }
    let handle = descriptor(&deployment, subject)?;
    assert_eq!(deployment.publisher().spool().read(handle.subject_digest)?, frame);
    let mut catalog = catalog(&handle)?;
    // Deliberately reproduce the old publication-only binding in the test. This is not the new
    // production registration path: it shows why still-present bytes are insufficient authority.
    catalog.bind_local_source_object(&handle.handle_id, handle.descriptor_digest,
        victim_root, deployment.publisher(), &HostSpoolIo)?;
    let before = tree(&root)?;
    let cached = catalog.stored_payload_bytes();
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &deployment, &io, &victim, &handle.anchor, DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(catalog.hydrate_from_deployment_source(&request(&handle)?, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error)) if matches!(*error, DurableBeliefError::Selection)));
    assert_eq!(reader.deletion_usage().record_reads, 1);
    assert!(reader.custody_usage().is_none());
    no_io(&io);
    assert_eq!(catalog.stored_payload_bytes(), cached);
    let survivor_handle = descriptor(&deployment, ContentDigest::sha256(SOURCE))?;
    let mut survivor_catalog = ReferenceHydrationCatalog::new();
    survivor_catalog.register_descriptor(survivor_handle.clone())?;
    let reader = DeletionAwareSourceReader::new(
        &deployment, &HostSpoolIo, &survivor, &survivor_handle.anchor,
        DeploymentSourceLimits::default(), &|| false,
    );
    survivor_catalog.bind_deployment_source_object(&survivor_handle.handle_id,
        survivor_handle.descriptor_digest, &reader)?;
    let reader = DeletionAwareSourceReader::new(
        &deployment, &HostSpoolIo, &survivor, &survivor_handle.anchor,
        DeploymentSourceLimits::default(), &|| false,
    );
    let response = survivor_catalog.hydrate_from_deployment_source(
        &request(&survivor_handle)?, &reader, TimestampNs(20),
    )?;
    assert_eq!(response.artifact.ok_or("no survivor")?.payload, SOURCE);
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn committed_header_blocks_live_h3_without_unlinking_or_disabling_unrelated_sources() -> Value {
    pending_deletion(false)
}

#[test]
fn cold_reopen_does_not_turn_unfinished_deletion_into_source_disclosure_permission() -> Value {
    pending_deletion(true)
}
