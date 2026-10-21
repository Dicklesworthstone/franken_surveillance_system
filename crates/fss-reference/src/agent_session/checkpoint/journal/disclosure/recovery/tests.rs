#![forbid(unsafe_code)]
//! Faults affect only exclusive synthetic journals. Refused recovery must preserve the torn bytes.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use fss_core::{
    BudgetVector, Completeness, ContractBasisRegistryBytes, HandleAvailability, HydrationArtifact,
    HydrationLevel, HydrationPurpose, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor,
    MissionId, SemanticHandle, SemanticHandleSpec,
};
use fss_ledger::AppendPhase;
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use crate::{ReferenceHydrationLimits, SourceHydrationError, SourceObjectBinding};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"synthetic source retained only by its custody owner";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Value<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-disclosure-recovery-admission-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Reader {
    objects: InMemoryObjectStore,
    calls: Cell<usize>,
}
impl PublishedSourceReader for Reader {
    fn read_published_source(
        &self, root: ContentDigest, subject: ContentDigest, ceiling: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.calls.set(self.calls.get() + 1);
        self.objects.read_published_source(root, subject, ceiling)
    }
}

struct Fixture {
    directory: Directory,
    handle: SemanticHandle,
    root: ContentDigest,
    alternate: ContentDigest,
    reader: Reader,
    unbound: ReferenceHydrationCatalog,
    binding: SourceObjectBinding,
}
impl Fixture {
    fn new() -> Value<(Self, DurableDisclosureStore)> {
        let directory = Directory::new()?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::default());
        let subject = objects.put_verified(SOURCE)?;
        let root = objects.publish_manifest(ObjectManifest::new("original", [subject], None)?)?.root;
        let alternate = objects.publish_manifest(ObjectManifest::new("other", [subject], None)?)?.root;
        let reader = Reader { objects, calls: Cell::new(0) };
        let levels = BTreeSet::from([
            HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
        ]);
        let quote = BudgetVector::builder().bytes(1024).tokens(2).build()?;
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
                b"s", b"o", b"v", b"c", b"e", b"cost", "recovery-admission:test",
            )),
            anchor: LedgerAnchor::genesis("site:recovery-admission"),
            subject_id: "subject:original".to_owned(),
            subject_digest: subject,
            semantic_type: "source_object".to_owned(),
            source_id: "sensor:fixture".to_owned(),
            capture_interval: None,
            spatial_scope: None,
            privacy_class: "private:property".to_owned(),
            applied_transform: None,
            availability: HandleAvailability::Available,
            retention_until: TimestampNs(100),
            required_capabilities: levels.iter().map(|level| (*level, BTreeSet::new())).collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
            levels,
            laboratory_access: LaboratoryAccess::Unavailable,
            debug_capability: None,
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        })?;
        let mut unbound = ReferenceHydrationCatalog::new();
        unbound.register_descriptor(handle.clone())?;
        unbound.register_artifact(&handle.handle_id, handle.descriptor_digest,
            HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"preview".to_vec(),
                [subject], Completeness::Complete, None)?)?;
        let mut owner = DurableDisclosureStore::create(
            directory.0.join("sessions.fssj"), DurableSessionLimits::default(), unbound.clone(),
        )?;
        let registered = owner.bind_source_object_durable(
            &handle.handle_id, handle.descriptor_digest, root, &reader, TimestampNs(10),
        )?;
        Ok((Self {
            directory, handle, root, alternate, reader, unbound, binding: registered.binding,
        }, owner))
    }

    fn path(&self) -> PathBuf { self.directory.0.join("sessions.fssj") }

    fn bound(&self, root: ContentDigest) -> Value<ReferenceHydrationCatalog> {
        let mut catalog = self.unbound.clone();
        catalog.bind_source_object(
            &self.handle.handle_id, self.handle.descriptor_digest, root, &self.reader,
        )?;
        Ok(catalog)
    }

    fn tear(&self, owner: &mut DurableDisclosureStore) -> Value<ContentDigest> {
        let root = owner.committed_root();
        owner.sessions.journal.fail_after_phase(AppendPhase::BodySync);
        assert!(owner.bind_source_object_durable(
            &self.handle.handle_id, self.handle.descriptor_digest, self.root,
            &self.reader, TimestampNs(30),
        ).is_err());
        assert!(owner.needs_reconciliation());
        assert_eq!(owner.committed_root(), root);
        Ok(root)
    }

    fn recover(
        &self, root: ContentDigest, catalog: ReferenceHydrationCatalog,
    ) -> Result<(DurableDisclosureStore, super::super::super::coordination::SessionRecoveryReceipt), DisclosureError> {
        DurableDisclosureStore::recover_existing(
            self.path(), root, DurableSessionLimits::default(), IncompleteTailPolicy::Truncate, catalog,
        )
    }

    fn request(&self, level: HydrationLevel) -> Value<HydrationRequest> {
        Ok(HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: self.handle.contract_basis.clone(),
            session_id: SessionId::parse("session:recovery-admission")?,
            handle_id: self.handle.handle_id.clone(),
            expected_descriptor_digest: self.handle.descriptor_digest,
            expected_subject_digest: self.handle.subject_digest,
            anchor: self.handle.anchor.clone(),
            requested_level: level,
            allow_lower_level: false,
            available_capabilities: BTreeSet::new(),
            authorized_privacy_classes: BTreeSet::from([self.handle.privacy_class.clone()]),
            budget: BudgetVector::builder().bytes(1024).tokens(2).build()?,
            purpose: HydrationPurpose::Routine,
            continuation: None,
            issued_at: TimestampNs(12),
        })?)
    }

    fn session(&self, owner: &mut DurableDisclosureStore) -> Value<(PrincipalId, SessionAlias)> {
        let request = self.request(HydrationLevel::H2)?;
        let principal = PrincipalId::parse("principal:recovery-owner")?;
        owner.open_session(AgentSessionParams {
            session_id: request.session_id.clone(),
            mission_id: MissionId::parse("mission:recovery")?,
            principal_id: principal.clone(),
            capabilities: request.available_capabilities,
            privacy_scope: request.authorized_privacy_classes,
            current_anchor: self.handle.anchor.clone(),
            view_id: "AVIEW-001".to_owned(), token_budget: 20, symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0, expires_at_ns: 1000,
        }, self.handle.contract_basis.clone(), TimestampNs(11))?;
        let alias = owner.bind(&principal, &SessionBindingRequest {
            session_id: request.session_id, generation: 0,
            handle_id: self.handle.handle_id.clone(), descriptor_digest: self.handle.descriptor_digest,
        }, TimestampNs(11))?;
        Ok((principal, alias))
    }
}

#[test]
fn mismatched_source_recovery_preserves_torn_bytes_then_admits_exact_reconstruction() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let wrong = f.bound(f.alternate)?;
    let before = fs::read(f.path())?;
    let calls = f.reader.calls.get();
    assert!(matches!(f.recover(root, wrong), Err(DisclosureError::Cursors(_))));
    assert_eq!(fs::read(f.path())?, before);
    assert_eq!(f.reader.calls.get(), calls);
    let exact = f.bound(f.root)?;
    let calls = f.reader.calls.get();
    let (recovered, receipt) = f.recover(root, exact)?;
    assert_eq!(f.reader.calls.get(), calls);
    assert_eq!(recovered.catalog().source_binding_requirement(f.handle.descriptor_digest),
        Some(f.binding.custody_binding_digest()));
    assert_eq!(receipt.observed_file_digest(), ContentDigest::sha256(&before));
    let retained = usize::try_from(receipt.restored().committed_bytes)?;
    assert!(retained < before.len());
    assert_eq!(receipt.discarded_tail_digest(), Some(ContentDigest::sha256(&before[retained..])));
    assert_eq!(receipt.discarded_bytes(), (before.len() - retained) as u64);
    assert_eq!(fs::read(f.path())?, before[..retained]);
    Ok(())
}

#[test]
fn cached_h3_replacement_cannot_authorize_recovery_truncation() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let mut catalog = f.unbound.clone();
    catalog.register_artifact(&f.handle.handle_id, f.handle.descriptor_digest,
        HydrationArtifact::publish(HydrationLevel::H3, crate::SOURCE_OBJECT_CONTENT_TYPE,
            SOURCE.to_vec(), [f.root, f.handle.descriptor_digest], Completeness::Complete, None)?)?;
    let before = fs::read(f.path())?;
    assert!(matches!(f.recover(root, catalog), Err(DisclosureError::Cursors(_))));
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}

#[test]
fn reconstructed_metadata_capacity_refuses_before_any_tail_is_discarded() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let before = fs::read(f.path())?;
    let catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 0, ..Default::default()
    });
    assert!(matches!(f.recover(root, catalog),
        Err(DisclosureError::Cursors(HydrationError::CapacityExceeded))));
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}

#[test]
fn an_unjournaled_cursor_cannot_be_laundered_by_recovery_of_a_registration() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let mut catalog = f.bound(f.root)?;
    let cursor = catalog.hydrate(&f.request(HydrationLevel::H2)?, TimestampNs(12))?
        .receipt.continuation.ok_or("no unjournaled cursor")?;
    assert!(catalog.issued_cursor(&cursor.cursor_digest).is_some());
    let before = fs::read(f.path())?;
    assert!(matches!(f.recover(root, catalog), Err(DisclosureError::Cursors(_))));
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}

#[test]
fn missing_source_is_permitted_but_its_recovered_requirement_is_not_forgotten() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let calls = f.reader.calls.get();
    let (mut recovered, receipt) = f.recover(root, ReferenceHydrationCatalog::new())?;
    assert!(receipt.discarded_bytes() > 0);
    assert_eq!(f.reader.calls.get(), calls);
    assert_eq!(recovered.catalog().stored_payload_bytes(), 0);
    assert!(recovered.catalog().descriptor(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    assert_eq!(recovered.catalog().source_binding_requirement(f.handle.descriptor_digest),
        Some(f.binding.custody_binding_digest()));
    recovered.register_descriptor(f.handle.clone())?;
    assert!(recovered.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest,
        f.alternate, &f.reader).is_err());
    assert_eq!(f.reader.calls.get(), calls);
    recovered.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.root, &f.reader)?;
    assert_eq!(f.reader.calls.get(), calls + 1);
    Ok(())
}

#[test]
fn consumed_cursor_and_charges_survive_recovery_without_another_source_read() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let (principal, alias) = f.session(&mut owner)?;
    let cursor = owner.hydrate(&principal, &alias, &f.request(HydrationLevel::H2)?, TimestampNs(12))?
        .response.receipt.continuation.ok_or("no continuation")?;
    let mut request = f.request(HydrationLevel::H3)?;
    request.issued_at = TimestampNs(13);
    request.continuation = Some(cursor.clone());
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
    owner.hydrate_from_source(&principal, &alias, &request, &f.reader, TimestampNs(13))?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let exact = f.bound(f.root)?;
    let calls = f.reader.calls.get();
    let (mut recovered, _) = f.recover(root, exact)?;
    assert_eq!(f.reader.calls.get(), calls);
    assert!(recovered.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert_eq!(recovered.remaining_token_budget(&principal, &request.session_id, TimestampNs(14))?, 16);
    assert!(recovered.hydrate_from_source(&principal, &alias, &request, &f.reader, TimestampNs(14)).is_err());
    assert_eq!(f.reader.calls.get(), calls);
    assert_eq!(recovered.admissions(&principal, &request.session_id, request.request_digest, 4,
        TimestampNs(14))?.len(), 1);
    assert!(!fs::read(f.path())?.windows(SOURCE.len()).any(|window| window == SOURCE));
    Ok(())
}

#[test]
fn reject_policy_and_wrong_root_preserve_the_same_unfinished_file() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = f.tear(&mut owner)?;
    drop(owner);
    let before = fs::read(f.path())?;
    assert!(matches!(DurableDisclosureStore::recover_existing(
        f.path(), root, DurableSessionLimits::default(), IncompleteTailPolicy::Reject,
        ReferenceHydrationCatalog::new(),
    ), Err(DisclosureError::Durability(DurableSessionError::Journal(JournalError::IncompleteTail { .. })))));
    assert_eq!(fs::read(f.path())?, before);
    assert!(matches!(f.recover(ContentDigest::sha256(b"foreign root"), ReferenceHydrationCatalog::new()),
        Err(DisclosureError::Durability(DurableSessionError::RootMismatch))));
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}

#[test]
fn complete_but_semantically_invalid_history_is_not_repaired_or_adopted() -> Value {
    let (f, mut owner) = Fixture::new()?;
    owner.sessions.journal.append(SESSION_CHECKPOINT_RECORD_KIND, b"not a session checkpoint")?;
    let root = owner.sessions.journal.last_root();
    owner.sessions.journal.fail_after_phase(AppendPhase::BodySync);
    assert!(owner.sessions.journal.append(SESSION_CHECKPOINT_RECORD_KIND, b"unfinished").is_err());
    drop(owner);
    let before = fs::read(f.path())?;
    assert!(f.recover(root, ReferenceHydrationCatalog::new()).is_err());
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}

#[test]
fn fully_committed_registration_still_requires_its_new_root_and_compatible_catalog() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let old = owner.committed_root();
    owner.sessions.journal.fail_after_phase(AppendPhase::CommitSync);
    assert!(owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest,
        f.root, &f.reader, TimestampNs(30)).is_err());
    drop(owner);
    // The fault fixture knows a complete commit trailer exists. Production callers must obtain
    // independent authorization of this root; inspection alone is not an authorization source.
    let inspection = DurableSessionStore::inspect(f.path(), DurableSessionLimits::default())?;
    assert_ne!(inspection.root, old);
    assert!(inspection.incomplete_tail.is_none());
    let before = fs::read(f.path())?;
    assert!(f.recover(old, ReferenceHydrationCatalog::new()).is_err());
    assert!(matches!(f.recover(inspection.root, f.bound(f.alternate)?), Err(DisclosureError::Cursors(_))));
    assert_eq!(fs::read(f.path())?, before);
    let (recovered, receipt) = f.recover(inspection.root, ReferenceHydrationCatalog::new())?;
    assert_eq!(receipt.discarded_bytes(), 0);
    assert_eq!(recovered.committed_root(), inspection.root);
    assert_eq!(fs::read(f.path())?, before);
    Ok(())
}
