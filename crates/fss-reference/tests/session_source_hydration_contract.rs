#![forbid(unsafe_code)]
//! Session authority, live source custody, and cumulative disclosure accounting (FSS-210).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    AgentSessionParams, BudgetVector, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, Generation, HandleAvailability, HydrationArtifact,
    HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec,
    LaboratoryAccess, LedgerAnchor, MissionId, ObjectId, PrincipalId, SemanticHandle,
    SemanticHandleSpec, SessionId, TimestampNs, TombstoneReason, TombstoneRecord,
};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_reference::agent_session::hydration::SessionSourceHydrationError as DeliveryError;
use fss_reference::{
    PublishedSourceReader, ReferenceHydrationCatalog, ReferenceSessionError,
    ReferenceSessionStore, SessionAlias, SessionBindingRequest, SessionRefresh,
    SourceHydrationError,
};

type TestResult = Result<(), Box<dyn Error>>;
const SOURCE: &[u8] = b"original private camera source; never a cached preview";

struct Fixture {
    sessions: ReferenceSessionStore,
    catalog: ReferenceHydrationCatalog,
    store: InMemoryObjectStore,
    params: AgentSessionParams,
    descriptor: SemanticHandle,
    alias: SessionAlias,
    metadata: ContentDigest,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
    let source = store.put_verified(SOURCE)?;
    let metadata = store.put_verified(b"source provenance")?;
    let root = store.publish_manifest(ObjectManifest::new("source", [source], Some(metadata))?)?.root;
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1024).tokens(512).build()?;
    let descriptor = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "session-source:test",
        )),
        anchor: LedgerAnchor::genesis("site:session-source"),
        subject_id: "subject:source".to_owned(), subject_digest: source,
        semantic_type: "source_object".to_owned(), source_id: "sensor:source".to_owned(),
        capture_interval: None, spatial_scope: None, privacy_class: "private:property".to_owned(),
        applied_transform: None, availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| {
            let capability = if *level == HydrationLevel::H3 { "capability:source" }
                else { "capability:preview" };
            (*level, BTreeSet::from([capability.to_owned()]))
        }).collect(),
        estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
        levels, laboratory_access: LaboratoryAccess::Unavailable, debug_capability: None,
        derivative_handles: BTreeSet::new(), published_at: TimestampNs(1),
    })?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(descriptor.clone())?;
    catalog.register_artifact(&descriptor.handle_id, descriptor.descriptor_digest,
        HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"bounded preview".to_vec(),
            [source], Completeness::Complete, None)?)?;
    catalog.bind_source_object(&descriptor.handle_id, descriptor.descriptor_digest, root, &store)?;
    let params = AgentSessionParams {
        session_id: SessionId::parse("session:source")?, mission_id: MissionId::parse("mission:source")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: BTreeSet::from(["capability:preview".to_owned(), "capability:source".to_owned()]),
        privacy_scope: BTreeSet::from([descriptor.privacy_class.clone()]),
        current_anchor: descriptor.anchor.clone(), view_id: "AVIEW-001".to_owned(),
        token_budget: 2048, symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None, created_at_ns: 0, expires_at_ns: 1000,
    };
    let mut sessions = ReferenceSessionStore::default();
    sessions.open(params.clone(), descriptor.contract_basis.clone(), TimestampNs(10))?;
    let alias = sessions.bind(&params.principal_id, &SessionBindingRequest {
        session_id: params.session_id.clone(), generation: 0,
        handle_id: descriptor.handle_id.clone(), descriptor_digest: descriptor.descriptor_digest,
    }, &catalog, TimestampNs(10))?;
    Ok(Fixture { sessions, catalog, store, params, descriptor, alias, metadata })
}

fn request(f: &Fixture, level: HydrationLevel) -> Result<HydrationRequest, Box<dyn Error>> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: f.descriptor.contract_basis.clone(), session_id: f.params.session_id.clone(),
        handle_id: f.descriptor.handle_id.clone(), expected_descriptor_digest: f.descriptor.descriptor_digest,
        expected_subject_digest: f.descriptor.subject_digest, anchor: f.descriptor.anchor.clone(),
        requested_level: level, allow_lower_level: false,
        available_capabilities: f.params.capabilities.clone(), authorized_privacy_classes: f.params.privacy_scope.clone(),
        budget: BudgetVector::builder().bytes(1024).tokens(512).build()?,
        purpose: HydrationPurpose::Routine, continuation: None, issued_at: TimestampNs(10),
    })?)
}

fn reseal(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

struct Counted<'a> { store: &'a InMemoryObjectStore, calls: Cell<usize> }
impl PublishedSourceReader for Counted<'_> {
    fn read_published_source(&self, root: ContentDigest, subject: ContentDigest, ceiling: u64)
        -> Result<Vec<u8>, SourceHydrationError>
    {
        self.calls.set(self.calls.get() + 1);
        self.store.read_published_source(root, subject, ceiling)
    }
}

struct WrongBytes;
impl PublishedSourceReader for WrongBytes {
    fn read_published_source(&self, _: ContentDigest, _: ContentDigest, _: u64)
        -> Result<Vec<u8>, SourceHydrationError>
    { Ok(b"not the bound source".to_vec()) }
}

#[test]
fn original_bytes_have_exact_custody_binding_and_no_second_payload_cache() -> TestResult {
    let mut f = fixture()?;
    let req = request(&f, HydrationLevel::H3)?;
    let cached = f.catalog.stored_payload_bytes();
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    for now in [20, 21] {
        let response = f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
            &mut f.catalog, &reader, TimestampNs(now))?;
        let binding = f.catalog.source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
            .ok_or("missing trusted binding")?;
        binding.validate_response(&req, &f.descriptor, &response)?;
        assert_eq!(response.artifact.as_ref().ok_or("missing source")?.payload, SOURCE);
    }
    assert_eq!(reader.calls.get(), 2);
    assert_eq!(f.catalog.stored_payload_bytes(), cached);
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id,
        TimestampNs(21))?, 1024);
    assert!(matches!(f.sessions.hydrate(&f.params.principal_id, &f.alias, &req, &mut f.catalog,
        TimestampNs(21)), Err(ReferenceSessionError::Hydration(HydrationError::LevelUnavailable))));
    Ok(())
}

#[test]
fn cached_and_source_entrypoints_agree_for_lower_level_receipts_and_charges() -> TestResult {
    let mut f = fixture()?;
    let mut sessions = f.sessions.clone();
    let mut catalog = f.catalog.clone();
    let req = request(&f, HydrationLevel::H2)?;
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    let cached = sessions.hydrate(&f.params.principal_id, &f.alias, &req, &mut catalog, TimestampNs(20))?;
    let source = f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &reader, TimestampNs(20))?;
    assert_eq!(cached, source);
    assert_eq!(reader.calls.get(), 0);
    assert_eq!(catalog.issued_cursor_count(), f.catalog.issued_cursor_count());
    assert_eq!(sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id, TimestampNs(20))?,
        f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id, TimestampNs(20))?);
    Ok(())
}

#[test]
fn missing_wrong_principal_closed_and_expired_sessions_never_read_source() -> TestResult {
    for scenario in 0..4 {
        let mut f = fixture()?;
        let req = request(&f, HydrationLevel::H3)?;
        let mut alias = f.alias.clone();
        let mut principal = f.params.principal_id.clone();
        let now = if scenario == 3 { 1000 } else { 20 };
        match scenario {
            0 => alias.session_id = SessionId::parse("session:missing")?,
            1 => principal = PrincipalId::parse("principal:other")?,
            2 => f.sessions.close(&principal, &alias.session_id, TimestampNs(20))?,
            _ => {}
        }
        let reader = Counted { store: &f.store, calls: Cell::new(0) };
        assert!(matches!(f.sessions.hydrate_from_source(&principal, &alias, &req, &mut f.catalog,
            &reader, TimestampNs(now)), Err(DeliveryError::Session(ReferenceSessionError::Unavailable))));
        assert_eq!(reader.calls.get(), 0);
    }
    Ok(())
}

#[test]
fn resealed_forged_identity_basis_time_and_grants_are_not_authority() -> TestResult {
    for scenario in 0..9 {
        let mut f = fixture()?;
        let mut req = request(&f, HydrationLevel::H3)?;
        match scenario {
            0 => req.session_id = SessionId::parse("session:other")?,
            1 => req.handle_id = "handle:other".to_owned(),
            2 => req.expected_descriptor_digest = ContentDigest::sha256(b"other descriptor"),
            3 => req.expected_subject_digest = ContentDigest::sha256(b"other source"),
            4 => req.anchor.commit_sequence += 1,
            5 => req.issued_at = TimestampNs(21),
            6 => req.issued_at = TimestampNs(-1),
            7 => { req.available_capabilities.insert("capability:forged".to_owned()); }
            _ => { req.authorized_privacy_classes.insert("private:other".to_owned()); }
        }
        reseal(&mut req);
        let reader = Counted { store: &f.store, calls: Cell::new(0) };
        assert!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
            &mut f.catalog, &reader, TimestampNs(20)).is_err());
        assert_eq!(reader.calls.get(), 0);
        assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id,
            TimestampNs(20))?, 2048);
    }
    Ok(())
}

#[test]
fn full_request_allowance_and_cumulative_charges_are_checked_before_io() -> TestResult {
    let mut f = fixture()?;
    let req = request(&f, HydrationLevel::H3)?;
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    for _ in 0..4 {
        f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req, &mut f.catalog,
            &reader, TimestampNs(20))?;
    }
    // Exact open retries cannot replenish a spent session allowance.
    f.sessions.open(f.params.clone(), f.descriptor.contract_basis.clone(), TimestampNs(20))?;
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &reader, TimestampNs(20)), Err(DeliveryError::Session(ReferenceSessionError::BudgetExceeded))));
    assert_eq!(reader.calls.get(), 4);
    let mut g = fixture()?;
    let mut excess = request(&g, HydrationLevel::H3)?;
    excess.budget.tokens = 2049;
    reseal(&mut excess);
    let reader = Counted { store: &g.store, calls: Cell::new(0) };
    assert!(matches!(g.sessions.hydrate_from_source(&g.params.principal_id, &g.alias, &excess,
        &mut g.catalog, &reader, TimestampNs(20)), Err(DeliveryError::Session(ReferenceSessionError::BudgetExceeded))));
    assert_eq!(reader.calls.get(), 0);
    Ok(())
}

#[test]
fn narrowed_request_can_explicitly_fall_back_without_reading_source() -> TestResult {
    let mut f = fixture()?;
    let mut req = request(&f, HydrationLevel::H3)?;
    req.available_capabilities.remove("capability:source");
    reseal(&mut req);
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    assert!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &reader, TimestampNs(20)).is_err());
    req.allow_lower_level = true;
    reseal(&mut req);
    let response = f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &reader, TimestampNs(20))?;
    assert_eq!(response.artifact.as_ref().ok_or("missing preview")?.level, HydrationLevel::H2);
    assert_eq!(reader.calls.get(), 0);
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id,
        TimestampNs(20))?, 1536);
    Ok(())
}

#[test]
fn source_quote_byte_and_token_refusals_do_not_touch_custody() -> TestResult {
    for bytes in [true, false] {
        let mut f = fixture()?;
        let mut req = request(&f, HydrationLevel::H3)?;
        if bytes { req.budget.bytes = 1023; } else { req.budget.tokens = 511; }
        reseal(&mut req);
        let reader = Counted { store: &f.store, calls: Cell::new(0) };
        assert!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
            &mut f.catalog, &reader, TimestampNs(20)).is_err());
        assert_eq!(reader.calls.get(), 0);
    }
    Ok(())
}

#[test]
fn source_failure_preserves_cursor_and_tokens_but_success_consumes_both() -> TestResult {
    let mut f = fixture()?;
    let preview = request(&f, HydrationLevel::H2)?;
    let first = f.sessions.hydrate(&f.params.principal_id, &f.alias, &preview,
        &mut f.catalog, TimestampNs(20))?;
    let cursor = first.receipt.continuation.ok_or("missing H3 continuation")?;
    let mut req = request(&f, HydrationLevel::H3)?;
    req.continuation = Some(cursor.clone()); req.issued_at = TimestampNs(21); reseal(&mut req);
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &WrongBytes, TimestampNs(22)), Err(DeliveryError::Source(SourceHydrationError::SourceMismatch))));
    assert!(!f.catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id,
        TimestampNs(22))?, 1536);
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req, &mut f.catalog, &reader, TimestampNs(22))?;
    assert!(f.catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &reader, TimestampNs(23)),
        Err(DeliveryError::Source(SourceHydrationError::Hydration(HydrationError::ContinuationAlreadyConsumed)))));
    assert_eq!(reader.calls.get(), 1);
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id, TimestampNs(23))?, 1024);
    Ok(())
}

#[test]
fn tombstoned_source_cannot_be_retrieved_from_prior_disclosure() -> TestResult {
    let mut f = fixture()?;
    let req = request(&f, HydrationLevel::H3)?;
    f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req, &mut f.catalog, &f.store, TimestampNs(20))?;
    let witness = f.store.put_verified(b"authorized deletion witness")?;
    let prior = Generation::parse_positive(1)?;
    f.store.tombstone(f.descriptor.subject_digest, TombstoneRecord::new(ObjectId::parse("object:source")?,
        prior.next()?, prior, TombstoneReason::Deleted, Some(witness), f.descriptor.subject_digest)?)?;
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &f.store, TimestampNs(21)), Err(DeliveryError::Source(SourceHydrationError::Object(_)))));
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id, TimestampNs(21))?, 1536);
    Ok(())
}

#[test]
fn corrupt_related_metadata_is_not_a_successful_preview_downgrade() -> TestResult {
    let mut f = fixture()?;
    f.store.corrupt_for_test(f.metadata)?;
    let mut req = request(&f, HydrationLevel::H3)?;
    req.allow_lower_level = true; reseal(&mut req);
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
        &mut f.catalog, &f.store, TimestampNs(20)), Err(DeliveryError::Source(SourceHydrationError::Object(_)))));
    assert_eq!(f.sessions.remaining_token_budget(&f.params.principal_id, &f.params.session_id, TimestampNs(20))?, 2048);
    Ok(())
}

#[test]
fn retention_and_symbol_rotation_refuse_before_source_access() -> TestResult {
    for rotate in [false, true] {
        let mut f = fixture()?;
        let req = request(&f, HydrationLevel::H3)?;
        if rotate { f.sessions.rotate_symbols(&f.params.principal_id, &f.params.session_id, 0, TimestampNs(20))?; }
        let reader = Counted { store: &f.store, calls: Cell::new(0) };
        let now = if rotate { 20 } else { 100 };
        assert!(f.sessions.hydrate_from_source(&f.params.principal_id, &f.alias, &req,
            &mut f.catalog, &reader, TimestampNs(now)).is_err());
        assert_eq!(reader.calls.get(), 0);
    }
    Ok(())
}

#[test]
fn revoked_source_grant_stays_revoked_after_fresh_symbol_binding() -> TestResult {
    let mut f = fixture()?;
    let mut req = request(&f, HydrationLevel::H3)?;
    let current = f.sessions.session(&f.params.principal_id, &f.params.session_id, TimestampNs(20))?;
    let mut caps = current.capabilities.clone(); caps.remove("capability:source");
    let narrowed = f.sessions.refresh(&f.params.principal_id, &f.params.session_id, SessionRefresh {
        expected_session_digest: current.session_digest(), current_anchor: current.current_anchor,
        capabilities: caps.clone(), privacy_scope: current.privacy_scope,
    }, TimestampNs(20))?;
    let alias = f.sessions.bind(&f.params.principal_id, &SessionBindingRequest {
        session_id: f.params.session_id.clone(), generation: narrowed.symbol_table_generation,
        handle_id: f.descriptor.handle_id.clone(), descriptor_digest: f.descriptor.descriptor_digest,
    }, &f.catalog, TimestampNs(20))?;
    let reader = Counted { store: &f.store, calls: Cell::new(0) };
    assert!(matches!(f.sessions.hydrate_from_source(&f.params.principal_id, &alias, &req,
        &mut f.catalog, &reader, TimestampNs(20)), Err(DeliveryError::Session(ReferenceSessionError::GrantEscalation))));
    req.available_capabilities = caps; reseal(&mut req);
    assert!(f.sessions.hydrate_from_source(&f.params.principal_id, &alias, &req,
        &mut f.catalog, &reader, TimestampNs(20)).is_err());
    assert_eq!(reader.calls.get(), 0);
    Ok(())
}
