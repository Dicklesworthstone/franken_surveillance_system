#![forbid(unsafe_code)]
//! Deployment scope must survive generic, session-owned and cold-reopened disclosure paths.

use std::cell::Cell;

use super::*;
use fss_core::{AgentSessionParams, MissionId, PrincipalId};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::agent_session::checkpoint::journal::DurableSessionLimits;
use fss_reference::agent_session::checkpoint::journal::disclosure::{
    DisclosureError, DurableDisclosureStore,
};
use fss_reference::deletion::belief::hydration::DeploymentSourceAuthority;
use fss_reference::{PublishedSourceReader, SessionBindingRequest};

fn memory_copy(f: &Fixture) -> Value<InMemoryObjectStore> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
    for child in f.manifest.children() {
        store.put_verified(&f.deployment.publisher().spool().read(*child)?)?;
    }
    store.publish_manifest(f.manifest.clone())?;
    Ok(store)
}

struct Probe<'a> {
    inner: &'a dyn PublishedSourceReader,
    observations: Cell<usize>,
    reads: Cell<usize>,
    lose_authority_after_read: bool,
}

impl<'a> Probe<'a> {
    fn new(inner: &'a dyn PublishedSourceReader) -> Self {
        Self {
            inner,
            observations: Cell::new(0),
            reads: Cell::new(0),
            lose_authority_after_read: false,
        }
    }
}

impl PublishedSourceReader for Probe<'_> {
    fn validate_source_descriptor(
        &self,
        descriptor: &SemanticHandle,
    ) -> Result<(), SourceHydrationError> {
        self.inner.validate_source_descriptor(descriptor)
    }

    fn deployment_authority_for(
        &self,
        descriptor: &SemanticHandle,
        root: ContentDigest,
    ) -> Result<Option<DeploymentSourceAuthority>, SourceHydrationError> {
        self.observations.set(self.observations.get() + 1);
        if self.lose_authority_after_read && self.reads.get() != 0 {
            Ok(None)
        } else {
            self.inner.deployment_authority_for(descriptor, root)
        }
    }

    fn read_published_source(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        ceiling: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.reads.set(self.reads.get() + 1);
        self.inner.read_published_source(root, subject, ceiling)
    }
}

#[test]
fn generic_reads_cannot_weaken_deployment_custody_even_with_exact_surviving_bytes() -> Value {
    let f = setup("authority-memory")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let saved = catalog.source_binding(&handle.handle_id, handle.descriptor_digest)
        .cloned().ok_or("no binding")?;
    assert!(saved.deployment_authority().is_some());
    let memory = memory_copy(&f)?;
    // This is a valid publication of the exact bytes, not a deliberately broken reader.
    assert_eq!(memory.read_published_source(f.manifest.root(), handle.subject_digest, 1024)?, SOURCE);
    let probe = Probe::new(&memory);
    let cached = catalog.stored_payload_bytes();
    for source_present in [true, false] {
        if !source_present {
            fs::remove_file(f.deployment.publisher().spool().object_path(handle.subject_digest))?;
        }
        for allow_lower in [false, true] {
            let mut req = request(&handle)?;
            req.allow_lower_level = allow_lower;
            reseal(&mut req);
            assert!(matches!(catalog.hydrate_from_source(&req, &probe, TimestampNs(20)),
                Err(SourceHydrationError::SourceMismatch)));
            assert_eq!(probe.reads.get(), 0);
            assert_eq!(catalog.stored_payload_bytes(), cached);
            assert_eq!(catalog.source_binding(&handle.handle_id, handle.descriptor_digest), Some(&saved));
        }
    }
    assert!(matches!(catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), &probe), Err(SourceHydrationError::BindingConflict)));
    assert_eq!(probe.reads.get(), 0);
    Ok(())
}

#[test]
fn standalone_local_publisher_cannot_replace_deployment_deletion_authority() -> Value {
    let f = setup("authority-local")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    assert!(matches!(catalog.hydrate_from_local_source(&request(&handle)?,
        f.deployment.publisher(), &io, TimestampNs(20)), Err(SourceHydrationError::SourceMismatch)));
    assert!(matches!(catalog.bind_local_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), f.deployment.publisher(), &io), Err(SourceHydrationError::BindingConflict)));
    no_io(&io);
    Ok(())
}

#[test]
fn generic_registration_and_delivery_validate_the_descriptor_against_the_reader_anchor() -> Value {
    let mut f = setup("authority-anchor")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut bound = catalog(&handle)?;
    bind(&f, &handle, &mut bound)?;
    f.deployment.append_batch(BatchId::parse("batch:authority-advance")?, vec![], vec![],
        &cx("authority-advance")?)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    // Preserve the shared descriptor hook while adding immutable deployment scope.
    // A reader at the new head cannot accept this old descriptor through a generic call.
    let reader = DeletionAwareSourceReader::new(&f.deployment, &io, &f.slot,
        f.deployment.current_anchor(), DeploymentSourceLimits::default(), &|| false);
    let mut unbound = catalog(&handle)?;
    assert!(matches!(unbound.bind_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), &reader), Err(SourceHydrationError::Deployment(error))
        if matches!(*error, DurableBeliefError::AuthorityChanged)));
    assert!(unbound.source_binding(&handle.handle_id, handle.descriptor_digest).is_none());
    assert!(matches!(bound.hydrate_from_source(&request(&handle)?, &reader, TimestampNs(20)),
        Err(SourceHydrationError::Deployment(error))
        if matches!(*error, DurableBeliefError::AuthorityChanged)));
    assert!(!reader.attempted());
    assert_eq!(reader.deletion_usage().record_reads, 0);
    no_io(&io);
    Ok(())
}

#[test]
fn exact_binding_retries_do_not_retarget_equal_root_aliases() -> Value {
    let mut f = setup("authority-rebind")?;
    let alias = SlotName::parse("authority-alias")?;
    f.deployment.publish_and_commit(&alias, &f.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &cx("authority-alias")?)?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let original = catalog.source_binding(&handle.handle_id, handle.descriptor_digest)
        .cloned().ok_or("no binding")?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let alias_reader = DeletionAwareSourceReader::new(&f.deployment, &io, &alias, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    assert!(matches!(catalog.bind_deployment_source_object(&handle.handle_id,
        handle.descriptor_digest, &alias_reader), Err(SourceHydrationError::BindingConflict)));
    assert!(!alias_reader.attempted());
    no_io(&io);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let retry = catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), &reader)?;
    assert_eq!(retry, original);
    assert!(reader.attempted());
    Ok(())
}

#[test]
fn ordinary_h3_receipts_commit_the_exact_slot_record_and_journal_head() -> Value {
    let mut f = setup("authority-receipt")?;
    let alias = SlotName::parse("receipt-alias")?;
    f.deployment.publish_and_commit(&alias, &f.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?, &cx("receipt-alias")?)?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut original_catalog = catalog(&handle)?;
    bind(&f, &handle, &mut original_catalog)?;
    let binding = original_catalog.source_binding(&handle.handle_id, handle.descriptor_digest)
        .cloned().ok_or("no binding")?;
    let authority = binding.deployment_authority().ok_or("no authority")?;
    assert_eq!(Some(authority.store_pin()), f.deployment.ledger().store_pin());
    assert_eq!(authority.journal_root(), f.deployment.ledger().journal_root());
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let req = request(&handle)?;
    let response = original_catalog.hydrate_from_source(&req, &reader, TimestampNs(20))?;
    binding.validate_response(&req, &handle, &response)?;
    let artifact = response.artifact.as_ref().ok_or("no source")?;
    assert!(artifact.proof_roots.contains(&authority.journal_root()));
    assert!(artifact.proof_roots.contains(&authority.publication_record()));
    assert!(!artifact.proof_roots.contains(&authority.store_pin()));

    let mut alias_catalog = catalog(&handle)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &alias, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let alias_binding = alias_catalog.bind_deployment_source_object(&handle.handle_id,
        handle.descriptor_digest, &reader)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &alias, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let alias_response = alias_catalog.hydrate_from_source(&req, &reader, TimestampNs(20))?;
    alias_binding.validate_response(&req, &handle, &alias_response)?;
    assert_eq!(artifact.payload, alias_response.artifact.as_ref().ok_or("no alias source")?.payload);
    assert_ne!(binding.artifact_digest(), alias_binding.artifact_digest());
    assert!(matches!(binding.validate_response(&req, &handle, &alias_response),
        Err(SourceHydrationError::SourceMismatch)));
    Ok(())
}

fn copy_fixture_tree(source: &Path, target: &Path) -> Value {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_fixture_tree(&entry.path(), &target.join(entry.file_name()))?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        } else {
            return Err("non-regular synthetic fixture entry".into());
        }
    }
    Ok(())
}

#[test]
fn a_byte_identical_copied_deployment_does_not_replace_the_bound_journal_file() -> Value {
    let f = setup("authority-copy")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let Fixture { deployment, root, slot, .. } = f;
    drop(deployment);
    let copied_root = root.with_file_name("copied-deployment");
    copy_fixture_tree(&root, &copied_root)?;
    let original = open(&root, standard())?;
    let copied = open(&copied_root, standard())?;
    assert_eq!(original.current_anchor(), copied.current_anchor());
    assert_eq!(original.ledger().journal_root(), copied.ledger().journal_root());
    assert_ne!(original.ledger().store_pin(), copied.ledger().store_pin());
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(&copied, &io, &slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    assert!(matches!(catalog.hydrate_from_source(&request(&handle)?, &reader, TimestampNs(20)),
        Err(SourceHydrationError::SourceMismatch)));
    assert!(!reader.attempted());
    no_io(&io);
    let reader = DeletionAwareSourceReader::new(&original, &HostSpoolIo, &slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let response = catalog.hydrate_from_source(&request(&handle)?, &reader, TimestampNs(20))?;
    assert_eq!(response.artifact.ok_or("no original source")?.payload, SOURCE);
    Ok(())
}

#[test]
fn grants_quotes_expiry_and_cached_previews_precede_authority_observation() -> Value {
    let f = setup("authority-admission")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let probe = Probe::new(&reader);
    for case in 0..3 {
        let mut req = request(&handle)?;
        match case {
            0 => req.available_capabilities.clear(),
            1 => req.authorized_privacy_classes.clear(),
            _ => req.budget = BudgetVector::builder().bytes(1024).tokens(511).build()?,
        }
        reseal(&mut req);
        assert!(catalog.hydrate_from_source(&req, &probe, TimestampNs(20)).is_err());
    }
    assert!(catalog.hydrate_from_source(&request(&handle)?, &probe, TimestampNs(100))?.artifact.is_none());
    let mut preview = request(&handle)?;
    preview.requested_level = HydrationLevel::H2;
    reseal(&mut preview);
    assert_eq!(catalog.hydrate_from_source(&preview, &probe, TimestampNs(20))?
        .artifact.ok_or("no preview")?.level, HydrationLevel::H2);
    assert_eq!(probe.observations.get(), 0);
    assert_eq!(probe.reads.get(), 0);
    assert!(!reader.attempted());
    Ok(())
}

#[test]
fn changing_reader_authority_during_registration_cannot_install_a_binding() -> Value {
    let f = setup("authority-bind-drift")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    let cached = catalog.stored_payload_bytes();
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let mut probe = Probe::new(&reader);
    probe.lose_authority_after_read = true;
    assert!(matches!(catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), &probe), Err(SourceHydrationError::SourceMismatch)));
    assert_eq!(probe.reads.get(), 1);
    assert!(reader.custody_usage().is_some());
    assert!(catalog.source_binding(&handle.handle_id, handle.descriptor_digest).is_none());
    assert_eq!(catalog.stored_payload_bytes(), cached);
    Ok(())
}

#[test]
fn authority_drift_after_payload_read_never_consumes_the_input_cursor_or_falls_back() -> Value {
    let f = setup("authority-disclose-drift")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    bind(&f, &handle, &mut catalog)?;
    let mut preview = request(&handle)?;
    preview.requested_level = HydrationLevel::H2;
    reseal(&mut preview);
    let cursor = catalog.hydrate(&preview, TimestampNs(20))?.receipt.continuation.ok_or("no cursor")?;
    let mut req = request(&handle)?;
    req.continuation = Some(cursor.clone());
    req.issued_at = TimestampNs(21);
    reseal(&mut req);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let mut probe = Probe::new(&reader);
    probe.lose_authority_after_read = true;
    let cached = catalog.stored_payload_bytes();
    assert!(matches!(catalog.hydrate_from_source(&req, &probe, TimestampNs(21)),
        Err(SourceHydrationError::SourceMismatch)));
    assert_eq!(probe.reads.get(), 1);
    assert!(!catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert_eq!(catalog.stored_payload_bytes(), cached);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    assert_eq!(catalog.hydrate_from_source(&req, &reader, TimestampNs(22))?
        .artifact.ok_or("no source")?.payload, SOURCE);
    assert!(catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    // Explicit downgrade permission does not hide an authority change after a successful read.
    let mut req = request(&handle)?;
    req.allow_lower_level = true;
    reseal(&mut req);
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let mut probe = Probe::new(&reader);
    probe.lose_authority_after_read = true;
    assert!(matches!(catalog.hydrate_from_source(&req, &probe, TimestampNs(23)),
        Err(SourceHydrationError::SourceMismatch)));
    Ok(())
}

#[test]
fn legacy_standalone_binding_keeps_its_receipt_contract_without_implicit_promotion() -> Value {
    let f = setup("authority-legacy")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut catalog = catalog(&handle)?;
    let memory = memory_copy(&f)?;
    let binding = catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest,
        f.manifest.root(), &memory)?;
    assert!(binding.deployment_authority().is_none());
    let req = request(&handle)?;
    let standalone = catalog.hydrate_from_source(&req, &memory, TimestampNs(20))?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let stricter = catalog.hydrate_from_source(&req, &reader, TimestampNs(20))?;
    assert_eq!(standalone, stricter);
    binding.validate_response(&req, &handle, &stricter)?;
    assert_eq!(catalog.source_binding(&handle.handle_id, handle.descriptor_digest), Some(&binding));
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    assert!(matches!(catalog.bind_deployment_source_object(&handle.handle_id,
        handle.descriptor_digest, &reader), Err(SourceHydrationError::BindingConflict)));
    assert!(!reader.attempted());
    Ok(())
}

#[test]
fn durable_generic_disclosure_preserves_scope_charges_and_single_use_history_across_restart() -> Value {
    let f = setup("authority-durable")?;
    let handle = descriptor(&f.deployment, ContentDigest::sha256(SOURCE))?;
    let mut blueprint = catalog(&handle)?;
    bind(&f, &handle, &mut blueprint)?;
    let req = request(&handle)?;
    let params = AgentSessionParams {
        session_id: req.session_id.clone(),
        mission_id: MissionId::parse("mission:authority-source")?,
        principal_id: PrincipalId::parse("principal:authority-owner")?,
        capabilities: req.available_capabilities.clone(),
        privacy_scope: req.authorized_privacy_classes.clone(),
        current_anchor: handle.anchor.clone(),
        view_id: "AVIEW-001".to_owned(),
        token_budget: 2_048,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 1_000,
    };
    let path = f.root.with_file_name("disclosure.journal");
    let limits = DurableSessionLimits::default();
    let mut owner = DurableDisclosureStore::create(&path, limits, blueprint)?;
    owner.open_session(params.clone(), handle.contract_basis.clone(), TimestampNs(10))?;
    let alias = owner.bind(&params.principal_id, &SessionBindingRequest {
        session_id: params.session_id.clone(), generation: 0,
        handle_id: handle.handle_id.clone(), descriptor_digest: handle.descriptor_digest,
    }, TimestampNs(10))?;
    let mut preview = req.clone();
    preview.requested_level = HydrationLevel::H2;
    reseal(&mut preview);
    let cursor = owner.hydrate(&params.principal_id, &alias, &preview, TimestampNs(20))?
        .response.receipt.continuation.ok_or("no durable cursor")?;
    let mut req = req;
    req.continuation = Some(cursor.clone());
    req.issued_at = TimestampNs(21);
    reseal(&mut req);
    let memory = memory_copy(&f)?;
    let probe = Probe::new(&memory);
    assert!(matches!(owner.hydrate_from_source(&params.principal_id, &alias, &req,
        &probe, TimestampNs(21)), Err(DisclosureError::Source(_))));
    assert_eq!(probe.reads.get(), 0);
    assert!(!owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id, TimestampNs(21))?, 1_536);
    assert!(owner.admissions(&params.principal_id, &params.session_id, req.request_digest, 10,
        TimestampNs(21))?.is_empty());
    let pin = owner.committed_root();
    drop(owner);

    let mut rebuilt = catalog(&handle)?;
    bind(&f, &handle, &mut rebuilt)?;
    let blueprint = rebuilt.clone();
    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, rebuilt)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    let delivered = owner.hydrate_from_source(&params.principal_id, &alias, &req,
        &reader, TimestampNs(22))?;
    assert_eq!(delivered.admission.charged_tokens(), 512);
    assert_eq!(delivered.admission.consumed_cursor(), Some(cursor.cursor_digest));
    let binding = owner.catalog().source_binding(&handle.handle_id, handle.descriptor_digest)
        .ok_or("no restored binding")?;
    binding.validate_response(&req, &handle, &delivered.response)?;
    assert_eq!(delivered.response.artifact.as_ref().ok_or("no source")?.payload, SOURCE);
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id, TimestampNs(22))?, 1_024);
    let pin = owner.committed_root();
    drop(owner);

    let mut owner = DurableDisclosureStore::open_existing(&path, pin, limits, blueprint)?;
    let reader = DeletionAwareSourceReader::new(&f.deployment, &HostSpoolIo, &f.slot, &handle.anchor,
        DeploymentSourceLimits::default(), &|| false);
    assert!(owner.hydrate_from_source(&params.principal_id, &alias, &req, &reader, TimestampNs(23)).is_err());
    assert!(!reader.attempted());
    assert_eq!(owner.remaining_token_budget(&params.principal_id, &params.session_id, TimestampNs(23))?, 1_024);
    assert_eq!(owner.admissions(&params.principal_id, &params.session_id, req.request_digest, 10,
        TimestampNs(23))?.len(), 1);
    assert!(!fs::read(&path)?.windows(SOURCE.len()).any(|window| window == SOURCE));
    Ok(())
}
