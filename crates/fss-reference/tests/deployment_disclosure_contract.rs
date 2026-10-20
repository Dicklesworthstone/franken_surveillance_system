#![forbid(unsafe_code)]
//! Deployment custody must not lose its anchor fence when passed through a trait object,
//! session projection or the joint durable charge/cursor owner. All media are synthetic.

mod file_import_fault_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use file_import_fault_support::{cx, fresh_dir, open, standard};
use fss_core::{
    AgentSessionParams, BudgetVector, CaptureInterval, Completeness, ContentDigest,
    ContractBasis, ContractBasisRegistryBytes, HandleAvailability, HydrationArtifact,
    HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec,
    LaboratoryAccess, MissionId, PrincipalId, SemanticHandle, SemanticHandleSpec,
    SessionId, TimestampNs,
};
use fss_object::{FaultInjectingSpoolIo, HostSpoolIo, SpoolFaultPlan, SpoolIoCall};
use fss_publication::SlotName;
use fss_publication::custody_audit::belief_snapshot::durable::DurableBeliefError;
use fss_reference::agent_session::checkpoint::journal::DurableSessionLimits;
use fss_reference::agent_session::checkpoint::journal::disclosure::{
    DisclosureError, DurableDisclosureStore,
};
use fss_reference::agent_session::hydration::SessionSourceHydrationError;
use fss_reference::deletion::belief::hydration::{
    DeletionAwareSourceReader, DeploymentSourceLimits,
};
use fss_reference::{
    ReferenceDeployment, ReferenceHydrationCatalog, ReferenceSessionStore,
    SessionBindingRequest, SourceHydrationError,
};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"private synthetic source that must never enter the session journal";
const TOKENS: u64 = 3;
const SESSION_TOKENS: u64 = 12;

struct Fixture {
    deployment: ReferenceDeployment,
    directory: PathBuf,
    slot: SlotName,
    root: ContentDigest,
    handle: SemanticHandle,
    catalog: ReferenceHydrationCatalog,
}

fn setup(label: &str) -> Value<Fixture> {
    let directory = fresh_dir(&format!("deployment-disclosure-{label}"))?;
    let mut deployment = open(&directory.join("deployment"), standard())?;
    let context = cx(label)?;
    let slot = SlotName::parse("source")?;
    let staged = deployment.stage_and_publish(&slot, &[SOURCE, b"required metadata"], &context)?;
    deployment.publish_and_commit(
        &slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
        &context,
    )?;
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(TOKENS).build()?;
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "deployment-disclosure:test",
        )),
        anchor: deployment.current_anchor().clone(),
        subject_id: "subject:source".to_owned(),
        subject_digest: ContentDigest::sha256(SOURCE),
        semantic_type: "source_object".to_owned(),
        source_id: "sensor:source".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| {
            (*level, if *level == HydrationLevel::H3 {
                BTreeSet::from(["capability:source".to_owned()])
            } else {
                BTreeSet::new()
            })
        }).collect(),
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
            HydrationLevel::H2, "text/plain", b"preview".to_vec(),
            [handle.subject_digest], Completeness::Complete, None,
        )?,
    )?;
    {
        let reader = DeletionAwareSourceReader::new(
            &deployment, &HostSpoolIo, &slot, &handle.anchor,
            DeploymentSourceLimits::default(), &|| false,
        );
        catalog.bind_deployment_source_object(&handle.handle_id, handle.descriptor_digest, &reader)?;
    }
    Ok(Fixture { deployment, directory, slot, root: staged.manifest.root(), handle, catalog })
}

fn advance(f: &mut Fixture) -> Value {
    let context = cx("advance-unrelated-authority")?;
    let slot = SlotName::parse("unrelated")?;
    let staged = f.deployment.stage_and_publish(&slot, &[b"unrelated new evidence"], &context)?;
    f.deployment.publish_and_commit(
        &slot, &staged.manifest,
        CaptureInterval::new(TimestampNs(3), TimestampNs(4))?, &context,
    )?;
    assert_ne!(f.deployment.current_anchor(), &f.handle.anchor);
    Ok(())
}

fn params(handle: &SemanticHandle) -> Value<AgentSessionParams> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse("session:deployment-disclosure")?,
        mission_id: MissionId::parse("mission:deployment-disclosure")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: BTreeSet::from(["capability:source".to_owned()]),
        privacy_scope: BTreeSet::from([handle.privacy_class.clone()]),
        current_anchor: handle.anchor.clone(),
        view_id: "AVIEW-001".to_owned(),
        token_budget: SESSION_TOKENS,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1,
        expires_at_ns: 1000,
    })
}

fn request(handle: &SemanticHandle, level: HydrationLevel) -> Value<HydrationRequest> {
    let session = params(handle)?;
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: session.session_id,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: session.capabilities,
        authorized_privacy_classes: session.privacy_scope,
        budget: BudgetVector::builder().bytes(1024).tokens(TOKENS).build()?,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10),
    })?)
}

fn binding(handle: &SemanticHandle) -> Value<SessionBindingRequest> {
    Ok(SessionBindingRequest {
        session_id: params(handle)?.session_id,
        generation: 0,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
    })
}

fn reseal(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

fn no_io(io: &FaultInjectingSpoolIo) {
    for call in SpoolIoCall::ALL {
        assert_eq!(io.calls(*call), 0, "unexpected {call}");
    }
}

fn assert_anchor_error(error: SourceHydrationError) {
    assert!(matches!(error,
        SourceHydrationError::Deployment(ref error)
            if matches!(error.as_ref(), DurableBeliefError::AuthorityChanged)
    ), "{error:?}");
}

#[test]
fn trait_object_registration_cannot_bind_an_old_descriptor_to_a_new_authority_head() -> Value {
    let mut f = setup("generic-bind")?;
    advance(&mut f)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, f.deployment.current_anchor(),
        DeploymentSourceLimits::default(), &|| false,
    );
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(f.handle.clone())?;
    let result = catalog.bind_source_object(
        &f.handle.handle_id, f.handle.descriptor_digest, f.root, &reader,
    );
    assert_anchor_error(result.err().ok_or("old descriptor was admitted")?);
    assert!(catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    assert!(!reader.attempted());
    no_io(&io);
    Ok(())
}

#[test]
fn trait_object_delivery_preserves_cursor_and_refuses_scope_drift_without_fallback() -> Value {
    let mut f = setup("generic-delivery")?;
    let preview = f.catalog.hydrate(&request(&f.handle, HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = preview.receipt.continuation.ok_or("no H3 continuation")?;
    advance(&mut f)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    for continued in [false, true] {
        let mut req = request(&f.handle, HydrationLevel::H3)?;
        req.allow_lower_level = !continued;
        req.issued_at = TimestampNs(21);
        req.continuation = continued.then(|| cursor.clone());
        reseal(&mut req);
        let reader = DeletionAwareSourceReader::new(
            &f.deployment, &io, &f.slot, f.deployment.current_anchor(),
            DeploymentSourceLimits::default(), &|| false,
        );
        let result = f.catalog.hydrate_from_source(&req, &reader, TimestampNs(30));
        assert_anchor_error(result.err().ok_or("authority failure silently became delivery")?);
        assert!(!reader.attempted());
        assert!(!f.catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    }
    no_io(&io);
    Ok(())
}

#[test]
fn stored_session_projection_does_not_override_the_readers_current_authority() -> Value {
    let mut f = setup("session-generic")?;
    let input = params(&f.handle)?;
    let mut sessions = ReferenceSessionStore::default();
    sessions.open(input.clone(), f.handle.contract_basis.clone(), TimestampNs(10))?;
    let alias = sessions.bind(&input.principal_id, &binding(&f.handle)?, &f.catalog, TimestampNs(10))?;
    advance(&mut f)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, f.deployment.current_anchor(),
        DeploymentSourceLimits::default(), &|| false,
    );
    let result = sessions.hydrate_from_source(
        &input.principal_id, &alias, &request(&f.handle, HydrationLevel::H3)?,
        &mut f.catalog, &reader, TimestampNs(30),
    );
    assert!(matches!(result, Err(SessionSourceHydrationError::Source(
        SourceHydrationError::Deployment(_)
    ))));
    assert_eq!(sessions.remaining_token_budget(&input.principal_id, &input.session_id, TimestampNs(30))?, SESSION_TOKENS);
    assert!(!reader.attempted());
    no_io(&io);
    Ok(())
}

#[test]
fn durable_scope_refusal_survives_reopen_without_charge_or_cursor_consumption() -> Value {
    let mut f = setup("durable-generic")?;
    let input = params(&f.handle)?;
    let path = f.directory.join("disclosure.fssj");
    let mut owner = DurableDisclosureStore::create(&path, DurableSessionLimits::default(), f.catalog.clone())?;
    owner.open_session(input.clone(), f.handle.contract_basis.clone(), TimestampNs(10))?;
    let alias = owner.bind(&input.principal_id, &binding(&f.handle)?, TimestampNs(10))?;
    let preview = owner.hydrate(
        &input.principal_id, &alias, &request(&f.handle, HydrationLevel::H2)?, TimestampNs(20),
    )?;
    let cursor = preview.response.receipt.continuation.ok_or("no continuation")?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.issued_at = TimestampNs(21);
    req.continuation = Some(cursor.clone());
    reseal(&mut req);
    advance(&mut f)?;
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, f.deployment.current_anchor(),
        DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(owner.hydrate_from_source(
        &input.principal_id, &alias, &req, &reader, TimestampNs(30),
    ), Err(DisclosureError::Source(SessionSourceHydrationError::Source(
        SourceHydrationError::Deployment(_)
    )))));
    assert!(!reader.attempted());
    no_io(&io);
    let pin = owner.committed_root();
    drop(owner);
    let mut reopened = DurableDisclosureStore::open_existing(
        &path, pin, DurableSessionLimits::default(), f.catalog.clone(),
    )?;
    assert_eq!(reopened.remaining_token_budget(&input.principal_id, &input.session_id, TimestampNs(30))?, SESSION_TOKENS - TOKENS);
    assert!(!reopened.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert!(reopened.admissions(&input.principal_id, &input.session_id, req.request_digest, 8, TimestampNs(30))?.is_empty());
    assert!(!fs::read(path)?.windows(SOURCE.len()).any(|bytes| bytes == SOURCE));
    Ok(())
}

#[test]
fn current_generic_source_still_delivers_exact_bytes_and_denials_precede_scope_checks() -> Value {
    let mut f = setup("current-and-denied")?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &HostSpoolIo, &f.slot, &f.handle.anchor,
        DeploymentSourceLimits::default(), &|| false,
    );
    let response = f.catalog.hydrate_from_source(&req, &reader, TimestampNs(20))?;
    f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .ok_or("no binding")?.validate_response(&req, &f.handle, &response)?;
    assert_eq!(response.artifact.ok_or("no source")?.payload, SOURCE);
    drop(reader);
    advance(&mut f)?;
    let mut denied = req;
    denied.available_capabilities.clear();
    reseal(&mut denied);
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, f.deployment.current_anchor(),
        DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(f.catalog.hydrate_from_source(&denied, &reader, TimestampNs(30)),
        Err(SourceHydrationError::Hydration(_))));
    assert!(!reader.attempted());
    no_io(&io);
    Ok(())
}

#[test]
fn missing_descriptor_refuses_without_inspecting_deployment_custody() -> Value {
    let f = setup("missing-descriptor")?;
    let mut catalog = ReferenceHydrationCatalog::new();
    let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
    let reader = DeletionAwareSourceReader::new(
        &f.deployment, &io, &f.slot, &f.handle.anchor,
        DeploymentSourceLimits::default(), &|| false,
    );
    assert!(matches!(catalog.bind_deployment_source_object(
        &f.handle.handle_id, f.handle.descriptor_digest, &reader,
    ), Err(SourceHydrationError::Hydration(HydrationError::DescriptorNotFound))));
    assert!(!reader.attempted());
    no_io(&io);
    Ok(())
}
