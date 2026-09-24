#![forbid(unsafe_code)]
//! Source custody, disclosure, and continuation integration for FSS-210.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, Generation, HandleAvailability, HydrationArtifact, HydrationError,
    HydrationLevel, HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, HydrationResponse, LaboratoryAccess,
    LedgerAnchor, ObjectId, SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
    TombstoneReason, TombstoneRecord,
};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest};
use fss_reference::{
    PublishedSourceReader, ReferenceHydrationCatalog, SOURCE_OBJECT_CONTENT_TYPE,
    SourceHydrationError,
};

type TestResult = Result<(), Box<dyn Error>>;
const SOURCE: &[u8] = b"exact original encoded source bytes";

struct Fixture {
    catalog: ReferenceHydrationCatalog,
    store: InMemoryObjectStore,
    handle: SemanticHandle,
    root: ContentDigest,
    metadata: ContentDigest,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
    let subject = store.put_verified(SOURCE)?;
    let metadata = store.put_verified(b"capture metadata with source provenance")?;
    let root = store.publish_manifest(ObjectManifest::new("source", [subject], Some(metadata))?)?.root;
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().bytes(1_024).tokens(512).build()?;
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "source-hydration:test",
        )),
        anchor: LedgerAnchor::genesis("site:source-hydration"),
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
            let grant = if *level == HydrationLevel::H3 { "capability:source" } else { "capability:preview" };
            (*level, BTreeSet::from([grant.to_owned()]))
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
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, preview(&handle)?)?;
    Ok(Fixture { catalog, store, handle, root, metadata })
}

fn preview(handle: &SemanticHandle) -> Result<HydrationArtifact, HydrationError> {
    HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"decision preview".to_vec(),
        [handle.subject_digest], Completeness::Complete, None)
}

fn request(handle: &SemanticHandle, level: HydrationLevel) -> Result<HydrationRequest, Box<dyn Error>> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:source")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:preview".to_owned(), "capability:source".to_owned()]),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::builder().bytes(1_024).tokens(512).build()?,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10).max(handle.published_at),
    })?)
}

fn reseal(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

fn bind(fixture: &mut Fixture) -> TestResult {
    fixture.catalog.bind_source_object(&fixture.handle.handle_id, fixture.handle.descriptor_digest,
        fixture.root, &fixture.store)?;
    Ok(())
}

struct ReaderProbe {
    calls: Cell<usize>,
    bytes: Vec<u8>,
}

impl ReaderProbe {
    fn new(bytes: &[u8]) -> Self { Self { calls: Cell::new(0), bytes: bytes.to_vec() } }
}

impl PublishedSourceReader for ReaderProbe {
    fn read_published_source(&self, _: ContentDigest, _: ContentDigest, _: u64)
        -> Result<Vec<u8>, SourceHydrationError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.bytes.clone())
    }
}

#[test]
fn exact_source_round_trip_has_custody_roots_and_no_payload_cache() -> TestResult {
    let mut f = fixture()?;
    let cached = f.catalog.stored_payload_bytes();
    bind(&mut f)?;
    let binding = f.catalog.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.root, &f.store)?;
    assert_eq!(binding.subject_digest(), ContentDigest::sha256(SOURCE));
    assert_eq!(binding.publication_root(), f.root);
    assert_eq!(binding.payload_bytes(), SOURCE.len() as u64);
    let req = request(&f.handle, HydrationLevel::H3)?;
    let response = f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?;
    response.validate_for(&req, &f.handle)?;
    let artifact = response.artifact.as_ref().ok_or("missing source")?;
    assert_eq!(artifact.payload, SOURCE);
    assert_eq!(artifact.payload_digest, f.handle.subject_digest);
    assert_eq!(artifact.content_type, SOURCE_OBJECT_CONTENT_TYPE);
    assert!(artifact.proof_roots.contains(&f.root));
    assert!(artifact.proof_roots.contains(&f.handle.descriptor_digest));
    assert_eq!(artifact.artifact_digest, binding.artifact_digest());
    assert_eq!(response.receipt.completeness, Completeness::Complete);
    assert_eq!(response, f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?);
    assert_eq!(f.catalog.stored_payload_bytes(), cached);
    assert!(matches!(f.catalog.hydrate(&req, TimestampNs(20)), Err(HydrationError::LevelUnavailable)));
    Ok(())
}

#[test]
fn denied_privacy_capability_budget_and_future_time_do_not_read_source() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let probe = ReaderProbe::new(SOURCE);
    for case in 0..4 {
        let mut req = request(&f.handle, HydrationLevel::H3)?;
        match case {
            0 => req.authorized_privacy_classes.clear(),
            1 => { req.available_capabilities.remove("capability:source"); }
            2 => req.budget = BudgetVector::builder().bytes(1_024).tokens(511).build()?,
            _ => req.issued_at = TimestampNs(21),
        }
        reseal(&mut req);
        assert!(f.catalog.hydrate_from_source(&req, &probe, TimestampNs(20)).is_err());
    }
    assert_eq!(probe.calls.get(), 0);
    Ok(())
}

#[test]
fn expiry_and_deleted_descriptor_return_typed_unavailability_without_io() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let probe = ReaderProbe::new(SOURCE);
    let req = request(&f.handle, HydrationLevel::H3)?;
    let expired = f.catalog.hydrate_from_source(&req, &probe, TimestampNs(100))?;
    assert!(expired.artifact.is_none());
    assert_eq!(expired.receipt.availability, HandleAvailability::Expired);
    let mut deleted = f.handle.clone();
    deleted.anchor.commit_sequence += 1;
    deleted.published_at = TimestampNs(30);
    deleted.availability = HandleAvailability::Deleted;
    deleted.descriptor_digest = deleted.computed_descriptor_digest();
    f.catalog.register_descriptor(deleted.clone())?;
    assert!(matches!(f.catalog.hydrate_from_source(&req, &probe, TimestampNs(40)),
        Err(SourceHydrationError::Hydration(HydrationError::Contract(ContractError::StaleAnchor)))));
    let unavailable = f.catalog.hydrate_from_source(&request(&deleted, HydrationLevel::H3)?, &probe, TimestampNs(40))?;
    assert!(unavailable.artifact.is_none());
    assert_eq!(unavailable.receipt.availability, HandleAvailability::Deleted);
    assert_eq!(probe.calls.get(), 0);
    Ok(())
}

#[test]
fn source_continuation_uses_existing_single_use_ledger_and_survives_read_failure() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let cached = f.catalog.stored_payload_bytes();
    let first = f.catalog.hydrate(&request(&f.handle, HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = first.receipt.continuation.ok_or("missing H3 continuation")?;
    assert_eq!(cursor.position, 3);
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.continuation = Some(cursor.clone());
    req.issued_at = TimestampNs(21);
    reseal(&mut req);
    let wrong = ReaderProbe::new(b"substituted source");
    assert!(matches!(f.catalog.hydrate_from_source(&req, &wrong, TimestampNs(22)),
        Err(SourceHydrationError::SourceMismatch)));
    assert!(!f.catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    let delivered = f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(22))?;
    delivered.validate_for(&req, &f.handle)?;
    assert!(f.catalog.issued_cursor(&cursor.cursor_digest).ok_or("lost consumed cursor")?.consumed);
    let probe = ReaderProbe::new(SOURCE);
    assert!(matches!(f.catalog.hydrate_from_source(&req, &probe, TimestampNs(23)),
        Err(SourceHydrationError::Hydration(HydrationError::ContinuationAlreadyConsumed))));
    assert_eq!(probe.calls.get(), 0);
    assert_eq!(f.catalog.stored_payload_bytes(), cached);
    Ok(())
}

#[test]
fn unissued_continuation_and_cross_session_request_do_not_read_source() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let mut unissued = f.catalog.clone();
    let cursor = f.catalog.hydrate(&request(&f.handle, HydrationLevel::H2)?, TimestampNs(20))?
        .receipt.continuation.ok_or("missing continuation")?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.continuation = Some(cursor);
    req.issued_at = TimestampNs(21);
    reseal(&mut req);
    let probe = ReaderProbe::new(SOURCE);
    assert!(matches!(unissued.hydrate_from_source(&req, &probe, TimestampNs(22)),
        Err(SourceHydrationError::Hydration(HydrationError::ContinuationUnissued))));
    req.session_id = SessionId::parse("session:other")?;
    reseal(&mut req);
    assert!(f.catalog.hydrate_from_source(&req, &probe, TimestampNs(22)).is_err());
    assert_eq!(probe.calls.get(), 0);
    Ok(())
}

#[test]
fn tombstoned_source_cannot_be_disclosed_from_a_prior_success() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?;
    let witness = f.store.put_verified(b"owner-authorized deletion witness")?;
    let prior = Generation::parse_positive(1)?;
    let tombstone = TombstoneRecord::new(ObjectId::parse("obj-source")?, prior.next()?, prior,
        TombstoneReason::Deleted, Some(witness), f.handle.subject_digest)?;
    f.store.tombstone(f.handle.subject_digest, tombstone)?;
    assert!(matches!(f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(21)),
        Err(SourceHydrationError::Object(_))));
    assert!(matches!(f.catalog.hydrate(&req, TimestampNs(21)), Err(HydrationError::LevelUnavailable)));
    Ok(())
}

#[test]
fn corrupt_metadata_invalidates_complete_source_closure() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    f.store.corrupt_for_test(f.metadata)?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.allow_lower_level = true;
    reseal(&mut req);
    assert!(matches!(f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20)),
        Err(SourceHydrationError::Object(ObjectError::Corrupt(_)))));
    Ok(())
}

#[test]
fn staged_or_unrelated_objects_are_not_source_publications() -> TestResult {
    let mut f = fixture()?;
    let staged = ObjectManifest::new("unpublished", [f.handle.subject_digest], None)?;
    assert!(f.catalog.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest,
        staged.root(), &f.store).is_err());
    let other = f.store.put_verified(b"unrelated evidence")?;
    let other_root = f.store.publish_manifest(ObjectManifest::new("other", [other], None)?)?.root;
    assert!(matches!(f.catalog.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest,
        other_root, &f.store), Err(SourceHydrationError::NotReachable)));
    assert!(f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    Ok(())
}

#[test]
fn nested_published_roots_work_but_opaque_manifest_shaped_bytes_do_not_expand() -> TestResult {
    let mut f = fixture()?;
    let nested_root = f.store.publish_manifest(ObjectManifest::new("parent", [f.root], None)?)?.root;
    f.catalog.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, nested_root, &f.store)?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    assert!(f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?.artifact.is_some());
    let mut g = fixture()?;
    let hidden = ObjectManifest::new("opaque", [g.handle.subject_digest], None)?;
    use fss_core::CanonicalEncode;
    let opaque = g.store.put_verified(&hidden.canonical_bytes())?;
    let outer = g.store.publish_manifest(ObjectManifest::new("opaque-parent", [opaque], None)?)?.root;
    assert!(matches!(g.catalog.bind_source_object(&g.handle.handle_id, g.handle.descriptor_digest,
        outer, &g.store), Err(SourceHydrationError::NotReachable)));
    Ok(())
}

#[test]
fn transformed_descriptors_and_conflicting_cache_registration_fail_closed() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let artifact = HydrationArtifact::publish(HydrationLevel::H3, "text/plain", SOURCE.to_vec(),
        [f.handle.subject_digest, f.handle.descriptor_digest], Completeness::Complete, None)?;
    assert!(f.catalog.register_artifact(&f.handle.handle_id, f.handle.descriptor_digest, artifact.clone()).is_err());
    let mut g = fixture()?;
    g.catalog.register_artifact(&g.handle.handle_id, g.handle.descriptor_digest, artifact)?;
    assert!(matches!(g.catalog.bind_source_object(&g.handle.handle_id, g.handle.descriptor_digest, g.root, &g.store),
        Err(SourceHydrationError::BindingConflict)));
    let mut transformed = f.handle.clone();
    transformed.applied_transform = Some("privacy:masked".to_owned());
    // The applied transform is part of the stable identity core, so a transformed descriptor
    // is a distinct handle: re-derive its id exactly as SemanticHandle::new does.
    transformed.handle_id = format!("semantic-handle:{}", transformed.identity_digest());
    transformed.descriptor_digest = transformed.computed_descriptor_digest();
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(transformed.clone())?;
    assert!(matches!(catalog.bind_source_object(&transformed.handle_id, transformed.descriptor_digest, f.root, &f.store),
        Err(SourceHydrationError::TransformedSource)));
    Ok(())
}

#[test]
fn explicit_capability_downgrade_never_reads_raw_source() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.available_capabilities.remove("capability:source");
    req.allow_lower_level = true;
    reseal(&mut req);
    let probe = ReaderProbe::new(SOURCE);
    let response = f.catalog.hydrate_from_source(&req, &probe, TimestampNs(20))?;
    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H2));
    assert_eq!(response.receipt.completeness, Completeness::Partial);
    assert_eq!(probe.calls.get(), 0);
    Ok(())
}

#[test]
fn source_binding_cannot_be_retargeted_and_reader_cannot_exceed_quote() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let probe = ReaderProbe::new(SOURCE);
    assert!(matches!(f.catalog.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest,
        ContentDigest::sha256(b"another root"), &probe), Err(SourceHydrationError::BindingConflict)));
    assert_eq!(probe.calls.get(), 0);
    let oversized = ReaderProbe::new(&[1; 1_025]);
    assert!(matches!(f.catalog.hydrate_from_source(&request(&f.handle, HydrationLevel::H3)?, &oversized, TimestampNs(20)),
        Err(SourceHydrationError::Hydration(HydrationError::BudgetExceeded))));
    assert_eq!(f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .ok_or("lost binding")?.publication_root(), f.root);
    Ok(())
}

// A malicious producer can reseal internal hashes and copy genuine source proof roots.
// These tests use the ordinary public receipt API, rather than invalid digest fixtures.
fn forged_response(
    req: &HydrationRequest,
    handle: &SemanticHandle,
    artifact: HydrationArtifact,
) -> Result<HydrationResponse, Box<dyn Error>> {
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.extend([
        artifact.artifact_digest,
        handle.subject_digest,
        handle.descriptor_digest,
        req.request_digest,
    ]);
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: req.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: req.requested_level,
        delivered_level: Some(artifact.level),
        availability: HandleAvailability::Available,
        cost: handle.estimated_cost(artifact.level).ok_or("missing quote")?,
        completeness: artifact.completeness_for(req.requested_level),
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-and-source-custody".to_owned()]),
        issued_at: TimestampNs(20),
    })?;
    Ok(HydrationResponse { artifact: Some(artifact), receipt })
}

#[test]
fn consumer_verifies_exact_source_against_trusted_binding() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    let response = f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?;
    binding.validate_response(&req, &f.handle, &response)?;
    Ok(())
}

#[test]
fn consumer_rejects_substituted_bytes_even_with_self_consistent_receipt_and_genuine_roots() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H3,
        SOURCE_OBJECT_CONTENT_TYPE,
        b"substituted source with copied genuine proof roots".to_vec(),
        [f.handle.subject_digest, f.handle.descriptor_digest, f.root],
        Completeness::Complete,
        None,
    )?;
    let response = forged_response(&req, &f.handle, artifact)?;
    // Internal consistency is not source identity. This passes the legacy generic contract.
    response.validate_for(&req, &f.handle)?;
    assert!(matches!(binding.validate_response(&req, &f.handle, &response),
        Err(SourceHydrationError::SourceMismatch)));
    Ok(())
}

#[test]
fn consumer_rejects_retargeted_or_missing_custody_roots() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let req = request(&f.handle, HydrationLevel::H3)?;
    for extra_root in [None, Some(ContentDigest::sha256(b"forged custody root"))] {
        let mut roots = BTreeSet::from([f.handle.subject_digest, f.handle.descriptor_digest]);
        roots.extend(extra_root);
        let artifact = HydrationArtifact::publish(HydrationLevel::H3, SOURCE_OBJECT_CONTENT_TYPE,
            SOURCE.to_vec(), roots, Completeness::Complete, None)?;
        let response = forged_response(&req, &f.handle, artifact)?;
        response.validate_for(&req, &f.handle)?;
        assert!(matches!(binding.validate_response(&req, &f.handle, &response),
            Err(SourceHydrationError::SourceMismatch)));
    }
    Ok(())
}

#[test]
fn consumer_does_not_confuse_a_preview_or_expired_receipt_with_source_evidence() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let mut req = request(&f.handle, HydrationLevel::H3)?;
    req.available_capabilities.remove("capability:source");
    req.allow_lower_level = true;
    reseal(&mut req);
    let preview = f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(20))?;
    assert_eq!(preview.receipt.delivered_level, Some(HydrationLevel::H2));
    assert!(matches!(binding.validate_response(&req, &f.handle, &preview),
        Err(SourceHydrationError::Hydration(HydrationError::LevelUnavailable))));
    let expired = f.catalog.hydrate_from_source(&req, &f.store, TimestampNs(100))?;
    assert!(matches!(binding.validate_response(&req, &f.handle, &expired),
        Err(SourceHydrationError::Hydration(HydrationError::LevelUnavailable))));
    Ok(())
}

#[test]
fn consumer_rejects_source_rebinding_to_another_descriptor_revision() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let mut revised = f.handle.clone();
    revised.anchor.commit_sequence += 1;
    revised.published_at = TimestampNs(5);
    revised.descriptor_digest = revised.computed_descriptor_digest();
    revised.verify()?;
    let req = request(&revised, HydrationLevel::H3)?;
    let artifact = HydrationArtifact::publish(HydrationLevel::H3, SOURCE_OBJECT_CONTENT_TYPE,
        SOURCE.to_vec(), [revised.subject_digest, revised.descriptor_digest, f.root],
        Completeness::Complete, None)?;
    let response = forged_response(&req, &revised, artifact)?;
    response.validate_for(&req, &revised)?;
    assert!(matches!(binding.validate_response(&req, &revised, &response),
        Err(SourceHydrationError::SourceMismatch)));
    Ok(())
}

#[test]
fn consumer_rejects_privacy_transform_claims_on_original_source() -> TestResult {
    let mut f = fixture()?;
    bind(&mut f)?;
    let binding = f.catalog.source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .cloned().ok_or("missing binding")?;
    let mut transformed = f.handle.clone();
    transformed.applied_transform = Some("privacy:masked".to_owned());
    // The applied transform is part of the stable identity core, so a transformed descriptor
    // is a distinct handle: re-derive its id exactly as SemanticHandle::new does.
    transformed.handle_id = format!("semantic-handle:{}", transformed.identity_digest());
    transformed.descriptor_digest = transformed.computed_descriptor_digest();
    let req = request(&transformed, HydrationLevel::H3)?;
    let artifact = HydrationArtifact::publish(HydrationLevel::H3, SOURCE_OBJECT_CONTENT_TYPE,
        SOURCE.to_vec(), [transformed.subject_digest, transformed.descriptor_digest, f.root],
        Completeness::Complete, transformed.applied_transform.clone())?;
    let response = forged_response(&req, &transformed, artifact)?;
    response.validate_for(&req, &transformed)?;
    assert!(matches!(binding.validate_response(&req, &transformed, &response),
        Err(SourceHydrationError::TransformedSource)));
    Ok(())
}
