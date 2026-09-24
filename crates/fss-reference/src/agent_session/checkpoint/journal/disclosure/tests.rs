#![forbid(unsafe_code)]
//! Process-restart and append-fault tests over real reference custody and the real journal.

use std::cell::Cell;
use std::collections::BTreeSet;
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

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"original private footage must never enter the disclosure journal";

struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-disclosure-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("exclusive fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Reader {
    objects: InMemoryObjectStore,
    calls: Cell<usize>,
    wrong: Cell<bool>,
}
impl PublishedSourceReader for Reader {
    fn read_published_source(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        ceiling: u64,
    ) -> Result<Vec<u8>, crate::SourceHydrationError> {
        self.calls.set(self.calls.get() + 1);
        if self.wrong.get() {
            return Ok(b"wrong source".to_vec());
        }
        self.objects.read_published_source(root, subject, ceiling)
    }
}

struct Fixture {
    directory: Directory,
    params: AgentSessionParams,
    handle: SemanticHandle,
    reader: Reader,
    blueprint: ReferenceHydrationCatalog,
    alias: SessionAlias,
    quote: BudgetVector,
}
impl Fixture {
    fn new(
        tokens: u64,
        limits: DurableSessionLimits,
    ) -> TestResult<(Self, DurableDisclosureStore)> {
        let directory = Directory::new()?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
        let source = objects.put_verified(SOURCE)?;
        let metadata = objects.put_verified(b"original provenance")?;
        let root = objects
            .publish_manifest(ObjectManifest::new("source", [source], Some(metadata))?)?
            .root;
        let reader = Reader {
            objects,
            calls: Cell::new(0),
            wrong: Cell::new(false),
        };
        let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s",
            b"o",
            b"v",
            b"c",
            b"e",
            b"cost",
            "durable-disclosure:test",
        ));
        let levels = BTreeSet::from([
            HydrationLevel::H0,
            HydrationLevel::H1,
            HydrationLevel::H2,
            HydrationLevel::H3,
        ]);
        let quote = BudgetVector::builder()
            .bytes(1_024)
            .tokens(tokens)
            .build()?;
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis.clone(),
            anchor: LedgerAnchor::genesis("site:disclosure"),
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
                    (
                        *level,
                        BTreeSet::from([if *level == HydrationLevel::H3 {
                            "capability:source".to_owned()
                        } else {
                            "capability:preview".to_owned()
                        }]),
                    )
                })
                .collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
            levels,
            laboratory_access: LaboratoryAccess::Unavailable,
            debug_capability: None,
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        })?;
        let mut blueprint = ReferenceHydrationCatalog::new();
        blueprint.register_descriptor(handle.clone())?;
        blueprint.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            HydrationArtifact::publish(
                HydrationLevel::H2,
                "text/plain",
                b"bounded preview".to_vec(),
                [source],
                Completeness::Complete,
                None,
            )?,
        )?;
        blueprint.bind_source_object(&handle.handle_id, handle.descriptor_digest, root, &reader)?;
        reader.calls.set(0);
        let params = AgentSessionParams {
            session_id: SessionId::parse("session:disclosure")?,
            mission_id: MissionId::parse("mission:disclosure")?,
            principal_id: PrincipalId::parse("principal:owner")?,
            capabilities: BTreeSet::from([
                "capability:source".to_owned(),
                "capability:preview".to_owned(),
            ]),
            privacy_scope: BTreeSet::from([handle.privacy_class.clone()]),
            current_anchor: handle.anchor.clone(),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 2_048,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 1_000,
        };
        let mut owner = DurableDisclosureStore::create(
            directory.0.join("sessions.journal"),
            limits,
            blueprint.clone(),
        )?;
        owner.open_session(params.clone(), basis, TimestampNs(10))?;
        let alias = owner.bind(
            &params.principal_id,
            &SessionBindingRequest {
                session_id: params.session_id.clone(),
                generation: 0,
                handle_id: handle.handle_id.clone(),
                descriptor_digest: handle.descriptor_digest,
            },
            TimestampNs(10),
        )?;
        Ok((
            Self {
                directory,
                params,
                handle,
                reader,
                blueprint,
                alias,
                quote,
            },
            owner,
        ))
    }
    fn path(&self) -> PathBuf {
        self.directory.0.join("sessions.journal")
    }
    fn request(&self, level: HydrationLevel) -> TestResult<HydrationRequest> {
        Ok(HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: self.handle.contract_basis.clone(),
            session_id: self.params.session_id.clone(),
            handle_id: self.handle.handle_id.clone(),
            expected_descriptor_digest: self.handle.descriptor_digest,
            expected_subject_digest: self.handle.subject_digest,
            anchor: self.handle.anchor.clone(),
            requested_level: level,
            allow_lower_level: false,
            available_capabilities: self.params.capabilities.clone(),
            authorized_privacy_classes: self.params.privacy_scope.clone(),
            budget: self.quote,
            purpose: HydrationPurpose::Routine,
            continuation: None,
            issued_at: TimestampNs(10),
        })?)
    }
    fn remaining(&self, owner: &mut DurableDisclosureStore, now: i128) -> TestResult<u64> {
        Ok(owner.remaining_token_budget(
            &self.params.principal_id,
            &self.params.session_id,
            TimestampNs(now),
        )?)
    }
    fn preview(
        &self,
        owner: &mut DurableDisclosureStore,
    ) -> TestResult<fss_core::ContinuationCursor> {
        Ok(owner
            .hydrate(
                &self.params.principal_id,
                &self.alias,
                &self.request(HydrationLevel::H2)?,
                TimestampNs(20),
            )?
            .response
            .receipt
            .continuation
            .ok_or("missing source continuation")?)
    }
    fn continuation(&self, cursor: fss_core::ContinuationCursor) -> TestResult<HydrationRequest> {
        let mut request = self.request(HydrationLevel::H3)?;
        request.continuation = Some(cursor);
        request.issued_at = TimestampNs(21);
        reseal(&mut request);
        Ok(request)
    }
    fn no_source_in_journal(&self) -> TestResult {
        let bytes = std::fs::read(self.path())?;
        assert!(!bytes.windows(SOURCE.len()).any(|window| window == SOURCE));
        Ok(())
    }
}
fn reseal(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

#[test]
fn restart_retains_issuance_charges_and_consumption_without_rereading_or_caching_source()
-> TestResult {
    let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
    let cursor = f.preview(&mut owner)?;
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        f.path(),
        root,
        DurableSessionLimits::default(),
        f.blueprint.clone(),
    )?;
    assert_eq!(f.remaining(&mut owner, 20)?, 1_536);
    assert!(
        !owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("lost issuance")?
            .consumed
    );
    let request = f.continuation(cursor.clone())?;
    let delivered = owner.hydrate_from_source(
        &f.params.principal_id,
        &f.alias,
        &request,
        &f.reader,
        TimestampNs(22),
    )?;
    owner
        .catalog()
        .source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
        .ok_or("missing source binding")?
        .validate_response(&request, &f.handle, &delivered.response)?;
    assert_eq!(
        delivered
            .response
            .artifact
            .as_ref()
            .ok_or("missing source")?
            .payload,
        SOURCE
    );
    assert_eq!(f.reader.calls.get(), 1);
    assert_eq!(
        owner.catalog().stored_payload_bytes(),
        f.blueprint.stored_payload_bytes()
    );
    let root = owner.committed_root();
    drop(delivered);
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        f.path(),
        root,
        DurableSessionLimits::default(),
        f.blueprint.clone(),
    )?;
    assert_eq!(f.remaining(&mut owner, 22)?, 1_024);
    assert!(
        owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("lost consumption")?
            .consumed
    );
    assert!(
        owner
            .hydrate_from_source(
                &f.params.principal_id,
                &f.alias,
                &request,
                &f.reader,
                TimestampNs(23)
            )
            .is_err()
    );
    assert_eq!(f.reader.calls.get(), 1);
    assert_eq!(f.remaining(&mut owner, 23)?, 1_024);
    f.no_source_in_journal()?;
    Ok(())
}

#[test]
fn all_append_fault_phases_reconcile_charge_and_cursor_together_without_redelivery() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
        let cursor = f.preview(&mut owner)?;
        let request = f.continuation(cursor.clone())?;
        owner.sessions.journal.fail_after_phase(phase);
        assert!(
            owner
                .hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &request,
                    &f.reader,
                    TimestampNs(22)
                )
                .is_err()
        );
        assert!(owner.needs_reconciliation());
        assert!(
            !owner
                .catalog()
                .issued_cursor(&cursor.cursor_digest)
                .ok_or("missing cursor")?
                .consumed
        );
        assert_eq!(f.reader.calls.get(), 1);
        assert!(
            owner
                .hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &request,
                    &f.reader,
                    TimestampNs(23)
                )
                .is_err()
        );
        assert_eq!(f.reader.calls.get(), 1);
        let outcome = owner.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert_eq!(
            outcome,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        assert_eq!(
            owner
                .catalog()
                .issued_cursor(&cursor.cursor_digest)
                .ok_or("missing cursor")?
                .consumed,
            committed
        );
        assert_eq!(
            f.remaining(&mut owner, 23)?,
            if committed { 1_024 } else { 1_536 }
        );
        let admissions = owner.admissions(
            &f.params.principal_id,
            &f.params.session_id,
            request.request_digest,
            10,
            TimestampNs(23),
        )?;
        assert_eq!(admissions.len(), usize::from(committed));
        assert_eq!(f.reader.calls.get(), 1);
        f.no_source_in_journal()?;
    }
    Ok(())
}

#[test]
fn cold_recovery_requires_exact_root_and_preserves_committed_cursor_tombstones() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitSync, true),
    ] {
        let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
        let cursor = f.preview(&mut owner)?;
        let request = f.continuation(cursor.clone())?;
        let old_root = owner.committed_root();
        owner.sessions.journal.fail_after_phase(phase);
        assert!(
            owner
                .hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &request,
                    &f.reader,
                    TimestampNs(22)
                )
                .is_err()
        );
        drop(owner);
        let inspection = DurableSessionStore::inspect(f.path(), DurableSessionLimits::default())?;
        assert_eq!(inspection.root != old_root, committed);
        // The deterministic fault fixture knows whether the commit trailer was written.
        let bytes = std::fs::read(f.path())?;
        if committed {
            assert!(
                DurableDisclosureStore::recover_existing(
                    f.path(),
                    old_root,
                    DurableSessionLimits::default(),
                    IncompleteTailPolicy::Truncate,
                    f.blueprint.clone()
                )
                .is_err()
            );
            assert_eq!(std::fs::read(f.path())?, bytes);
        }
        let (mut owner, _) = DurableDisclosureStore::recover_existing(
            f.path(),
            inspection.root,
            DurableSessionLimits::default(),
            IncompleteTailPolicy::Truncate,
            f.blueprint.clone(),
        )?;
        assert_eq!(
            owner
                .catalog()
                .issued_cursor(&cursor.cursor_digest)
                .ok_or("missing replay protection")?
                .consumed,
            committed
        );
        assert_eq!(
            f.remaining(&mut owner, 23)?,
            if committed { 1_024 } else { 1_536 }
        );
        assert_eq!(f.reader.calls.get(), 1);
        f.no_source_in_journal()?;
    }
    Ok(())
}

#[test]
fn zero_token_same_clock_disclosure_still_journals_and_recovers_its_cursor() -> TestResult {
    let (f, mut owner) = Fixture::new(0, DurableSessionLimits::default())?;
    let _ = owner.session(
        &f.params.principal_id,
        &f.params.session_id,
        TimestampNs(20),
    )?;
    let old_root = owner.committed_root();
    let cursor = f.preview(&mut owner)?;
    assert_ne!(owner.committed_root(), old_root);
    let root = owner.committed_root();
    drop(owner);
    let owner = DurableDisclosureStore::open_existing(
        f.path(),
        root,
        DurableSessionLimits::default(),
        f.blueprint.clone(),
    )?;
    assert!(
        !owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("zero-price issuance lost")?
            .consumed
    );
    Ok(())
}

#[test]
fn refusal_persists_clock_but_preserves_cursor_and_charge() -> TestResult {
    let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
    let cursor = f.preview(&mut owner)?;
    let request = f.continuation(cursor.clone())?;
    f.reader.wrong.set(true);
    assert!(
        owner
            .hydrate_from_source(
                &f.params.principal_id,
                &f.alias,
                &request,
                &f.reader,
                TimestampNs(22)
            )
            .is_err()
    );
    assert!(!owner.needs_reconciliation());
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(
        f.path(),
        root,
        DurableSessionLimits::default(),
        f.blueprint.clone(),
    )?;
    assert_eq!(f.remaining(&mut owner, 22)?, 1_536);
    assert!(
        !owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("cursor lost on refusal")?
            .consumed
    );
    f.reader.wrong.set(false);
    assert!(
        owner
            .hydrate_from_source(
                &f.params.principal_id,
                &f.alias,
                &request,
                &f.reader,
                TimestampNs(21)
            )
            .is_err()
    );
    assert_eq!(f.reader.calls.get(), 1);
    owner.hydrate_from_source(
        &f.params.principal_id,
        &f.alias,
        &request,
        &f.reader,
        TimestampNs(22),
    )?;
    assert_eq!(f.remaining(&mut owner, 22)?, 1_024);
    Ok(())
}

#[test]
fn journal_capacity_withholds_source_and_preserves_predecessor_after_reopen() -> TestResult {
    let limits = DurableSessionLimits {
        max_records: 4,
        ..DurableSessionLimits::default()
    };
    let (f, mut owner) = Fixture::new(512, limits)?;
    let cursor = f.preview(&mut owner)?;
    let request = f.continuation(cursor.clone())?;
    let before = std::fs::read(f.path())?;
    let root = owner.committed_root();
    assert!(matches!(
        owner.hydrate_from_source(
            &f.params.principal_id,
            &f.alias,
            &request,
            &f.reader,
            TimestampNs(22)
        ),
        Err(DisclosureError::Durability(
            DurableSessionError::CapacityExceeded
        ))
    ));
    assert!(owner.needs_reconciliation());
    assert_eq!(std::fs::read(f.path())?, before);
    assert!(
        !owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("missing cursor")?
            .consumed
    );
    drop(owner);
    let owner = DurableDisclosureStore::open_existing(f.path(), root, limits, f.blueprint.clone())?;
    assert!(
        !owner
            .catalog()
            .issued_cursor(&cursor.cursor_digest)
            .ok_or("lost cursor")?
            .consumed
    );
    f.no_source_in_journal()?;
    Ok(())
}

#[test]
fn repeated_noncontinuation_admissions_are_distinct_and_lookup_is_session_scoped() -> TestResult {
    let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
    let request = f.request(HydrationLevel::H3)?;
    let first = owner.hydrate_from_source(
        &f.params.principal_id,
        &f.alias,
        &request,
        &f.reader,
        TimestampNs(20),
    )?;
    let second = owner.hydrate_from_source(
        &f.params.principal_id,
        &f.alias,
        &request,
        &f.reader,
        TimestampNs(20),
    )?;
    assert_ne!(first.committed_root, second.committed_root);
    assert_eq!(first.response, second.response);
    let saved = owner.admissions(
        &f.params.principal_id,
        &f.params.session_id,
        request.request_digest,
        2,
        TimestampNs(20),
    )?;
    assert_eq!(saved.len(), 2);
    assert_eq!(
        saved.iter().map(|(_, a)| a.charged_tokens()).sum::<u64>(),
        1_024
    );
    assert!(
        owner
            .admissions(
                &f.params.principal_id,
                &f.params.session_id,
                request.request_digest,
                1,
                TimestampNs(20)
            )
            .is_err()
    );
    assert!(
        owner
            .admissions(
                &PrincipalId::parse("principal:other")?,
                &f.params.session_id,
                request.request_digest,
                2,
                TimestampNs(20)
            )
            .is_err()
    );
    assert_eq!(f.reader.calls.get(), 2);
    f.no_source_in_journal()?;
    Ok(())
}

#[test]
fn resealed_charge_forgery_cannot_replace_the_replayed_session_transition() -> TestResult {
    let (f, mut owner) = Fixture::new(512, DurableSessionLimits::default())?;
    let prior = owner.sessions.memory.clone();
    f.preview(&mut owner)?;
    let report = read_report(&f.path(), DurableSessionLimits::default())?;
    let record = report.records().last().ok_or("missing disclosure record")?;
    let saved = decode(record.payload(), DurableSessionLimits::default())?;
    let mut forged = saved.admission.clone();
    forged.tokens = 0;
    let payload = encode(
        saved.before,
        saved.session_checkpoint,
        saved.cursors,
        &forged,
    )?;
    assert!(
        restore_record(
            &payload,
            ContentDigest::sha256(&payload),
            Some(&prior),
            &mut None,
            DurableSessionLimits::default()
        )
        .is_err()
    );
    Ok(())
}
