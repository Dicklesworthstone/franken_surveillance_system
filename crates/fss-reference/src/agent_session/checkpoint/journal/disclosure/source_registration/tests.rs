#![forbid(unsafe_code)]
//! Real journal faults; synthetic source bytes. No deployed operator files are touched.

use super::*;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContractBasisRegistryBytes, HydrationLevel, LaboratoryAccess, LedgerAnchor,
    SemanticHandle, SemanticHandleSpec,
};
use fss_ledger::AppendPhase;
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

const SOURCE: &[u8] = b"private registration fixture: never a journal payload";
type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Value<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-source-registration-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive test directory unavailable".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

struct Reader {
    store: InMemoryObjectStore,
    calls: Cell<usize>,
    wrong: Cell<bool>,
}
impl PublishedSourceReader for Reader {
    fn read_published_source(&self, root: ContentDigest, subject: ContentDigest, max: u64)
        -> Result<Vec<u8>, crate::SourceHydrationError>
    {
        self.calls.set(self.calls.get() + 1);
        if self.wrong.get() { return Ok(b"incorrect source".to_vec()); }
        self.store.read_published_source(root, subject, max)
    }
}

struct Fixture {
    _directory: Directory,
    path: PathBuf,
    handle: SemanticHandle,
    root: ContentDigest,
    alternate: ContentDigest,
    reader: Reader,
    catalog: ReferenceHydrationCatalog,
}
impl Fixture {
    fn new() -> Value<Self> {
        let directory = Directory::new()?;
        let path = directory.0.join("sessions.journal");
        let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 65536));
        let subject = store.put_verified(SOURCE)?;
        let root = store.publish_manifest(ObjectManifest::new("original", [subject], None)?)?.root;
        let alternate = store.publish_manifest(ObjectManifest::new("alternate", [subject], None)?)?.root;
        let levels = BTreeSet::from([
            HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
        ]);
        let quote = BudgetVector::builder().bytes(1024).tokens(3).build()?;
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
                b"s", b"o", b"v", b"c", b"e", b"cost", "registration:test",
            )),
            anchor: LedgerAnchor::genesis("site:registration"),
            subject_id: "subject:registration".to_owned(),
            subject_digest: subject,
            semantic_type: "source_object".to_owned(),
            source_id: "sensor:registration".to_owned(),
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
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(handle.clone())?;
        Ok(Self {
            _directory: directory, path, handle, root, alternate,
            reader: Reader { store, calls: Cell::new(0), wrong: Cell::new(false) }, catalog,
        })
    }
    fn owner(&self, limits: DurableSessionLimits) -> Value<DurableDisclosureStore> {
        Ok(DurableDisclosureStore::create(&self.path, limits, self.catalog.clone())?)
    }
    fn bind(&self, owner: &mut DurableDisclosureStore, now: i128) -> Result<JournaledSourceBinding, DisclosureError> {
        owner.bind_source_object_durable(
            &self.handle.handle_id, self.handle.descriptor_digest, self.root, &self.reader, TimestampNs(now),
        )
    }
    fn no_payload(&self) -> Value {
        assert!(!std::fs::read(&self.path)?.windows(SOURCE.len()).any(|window| window == SOURCE));
        Ok(())
    }
}

#[test]
fn first_registration_is_durable_before_any_session_or_disclosure() -> Value {
    let f = Fixture::new()?;
    let limits = DurableSessionLimits::default();
    let mut owner = f.owner(limits)?;
    let initial = owner.committed_root();
    let registered = f.bind(&mut owner, 10)?;
    assert_ne!(initial, registered.committed_root);
    let pin = registered.binding.custody_binding_digest();
    assert_eq!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest), Some(pin));
    assert_eq!(owner.catalog().issued_cursor_count(), 0);
    assert_eq!(owner.sessions.memory.checkpoint(limits.max_checkpoint_bytes)?.as_bytes(),
        ReferenceSessionStore::default().checkpoint(limits.max_checkpoint_bytes)?.as_bytes());
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        &f.path, registered.committed_root, limits, ReferenceHydrationCatalog::new(),
    )?;
    assert_eq!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest), Some(pin));
    assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    assert_eq!(f.reader.calls.get(), 1);
    owner.register_descriptor(f.handle.clone())?;
    let before = owner.committed_root();
    assert!(owner.bind_source_object_durable(
        &f.handle.handle_id, f.handle.descriptor_digest, f.alternate, &f.reader, TimestampNs(11),
    ).is_err());
    assert_eq!(f.reader.calls.get(), 1);
    assert_eq!(owner.committed_root(), before);
    let retried = f.bind(&mut owner, 11)?;
    assert_eq!(retried.binding, registered.binding);
    assert_ne!(retried.committed_root, before);
    assert_eq!(f.reader.calls.get(), 2);
    f.no_payload()
}

#[test]
fn source_refusal_and_bad_time_do_not_publish_registration() -> Value {
    let f = Fixture::new()?;
    let mut owner = f.owner(DurableSessionLimits::default())?;
    let root = owner.committed_root();
    let bytes = std::fs::read(&f.path)?;
    f.reader.wrong.set(true);
    assert!(f.bind(&mut owner, 10).is_err());
    assert!(!owner.needs_reconciliation());
    assert_eq!(owner.committed_root(), root);
    assert_eq!(std::fs::read(&f.path)?, bytes);
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_none());
    assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
    f.reader.wrong.set(false);
    f.bind(&mut owner, 20)?;
    let root = owner.committed_root();
    let calls = f.reader.calls.get();
    for now in [0, 19, 100] { assert!(f.bind(&mut owner, now).is_err()); }
    assert_eq!(owner.committed_root(), root);
    assert_eq!(f.reader.calls.get(), calls);
    f.no_payload()
}

#[test]
fn pending_append_reconciliation_recovers_only_committed_requirements_without_source_io() -> Value {
    for (phase, committed) in [(AppendPhase::BodySync, false), (AppendPhase::CommitSync, true)] {
        let f = Fixture::new()?;
        let limits = DurableSessionLimits::default();
        let mut owner = f.owner(limits)?;
        let initial = owner.committed_root();
        owner.sessions.journal.fail_after_phase(phase);
        assert!(f.bind(&mut owner, 10).is_err());
        assert!(owner.needs_reconciliation());
        assert_eq!(owner.committed_root(), initial);
        assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
        assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_none());
        assert!(f.bind(&mut owner, 11).is_err());
        assert_eq!(f.reader.calls.get(), 1);
        let outcome = owner.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert!(matches!((outcome, committed), (SessionAppendRecovery::Committed, true) | (SessionAppendRecovery::NotCommitted, false)));
        assert_eq!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some(), committed);
        assert!(owner.catalog().source_binding(&f.handle.handle_id, f.handle.descriptor_digest).is_none());
        assert_eq!(f.reader.calls.get(), 1);
        let pin = owner.committed_root();
        drop(owner);
        let reopened = DurableDisclosureStore::open_existing(&f.path, pin, limits, ReferenceHydrationCatalog::new())?;
        assert_eq!(reopened.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some(), committed);
        assert_eq!(reopened.catalog().issued_cursor_count(), 0);
        f.no_payload()?;
    }
    Ok(())
}

#[test]
fn cold_append_recovery_does_not_mistake_a_lost_acknowledgement_for_no_registration() -> Value {
    for (phase, committed) in [(AppendPhase::BodySync, false), (AppendPhase::CommitSync, true)] {
        let f = Fixture::new()?;
        let limits = DurableSessionLimits::default();
        let mut owner = f.owner(limits)?;
        let initial = owner.committed_root();
        owner.sessions.journal.fail_after_phase(phase);
        assert!(f.bind(&mut owner, 10).is_err());
        drop(owner);
        let inspected = DurableSessionStore::inspect(&f.path, limits)?;
        assert_eq!(inspected.root != initial, committed);
        let (owner, _) = DurableDisclosureStore::recover_existing(
            &f.path, inspected.root, limits, IncompleteTailPolicy::Truncate, ReferenceHydrationCatalog::new(),
        )?;
        assert_eq!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some(), committed);
        assert_eq!(f.reader.calls.get(), 1);
        f.no_payload()?;
    }
    Ok(())
}

#[test]
fn known_full_registration_journal_refuses_before_source_read() -> Value {
    let f = Fixture::new()?;
    let mut owner = f.owner(DurableSessionLimits { max_records: 1, ..Default::default() })?;
    let initial = owner.committed_root();
    let bytes = std::fs::read(&f.path)?;
    assert!(matches!(f.bind(&mut owner, 10), Err(DisclosureError::Durability(DurableSessionError::CapacityExceeded))));
    assert_eq!(f.reader.calls.get(), 0);
    assert_eq!(owner.committed_root(), initial);
    assert_eq!(std::fs::read(&f.path)?, bytes);
    Ok(())
}

#[test]
fn registration_codec_refuses_truncation_trailing_data_and_changed_session_checkpoint() -> Value {
    let prior = ReferenceSessionStore::default();
    let limits = DurableSessionLimits::default();
    let checkpoint = prior.checkpoint(limits.max_checkpoint_bytes)?;
    let descriptor = ContentDigest::sha256(b"descriptor");
    let binding = ContentDigest::sha256(b"binding");
    let cursors = CursorCheckpoint::register_source(None, descriptor, binding, TimestampNs(10), 4096)?;
    let payload = encode_registration(checkpoint.digest(), checkpoint.as_bytes(), &cursors, descriptor, binding, TimestampNs(10))?;
    for end in 0..payload.len() {
        let bytes = &payload[..end];
        assert!(restore_record(bytes, ContentDigest::sha256(bytes), Some(&prior), &mut None, limits).is_err());
    }
    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(restore_record(&trailing, ContentDigest::sha256(&trailing), Some(&prior), &mut None, limits).is_err());
    for case in 0..3 {
        let mut session = checkpoint.as_bytes().to_vec();
        if case == 0 { session.push(0); }
        let forged = encode_registration(
            if case == 1 { binding } else { checkpoint.digest() }, &session, &cursors,
            descriptor, binding, TimestampNs(if case == 2 { 11 } else { 10 }),
        )?;
        assert!(restore_record(&forged, ContentDigest::sha256(&forged), Some(&prior), &mut None, limits).is_err());
    }
    let mut history = None;
    restore_record(&payload, ContentDigest::sha256(&payload), Some(&prior), &mut history, limits)?;
    assert!(history.is_some());
    assert!(restore_record(&payload, binding, Some(&prior), &mut None, limits).is_err());
    Ok(())
}
