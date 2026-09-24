#![forbid(unsafe_code)]
//! Work-claim commands committed in the SAME journal as their session authority.
//!
//! Recovery re-executes the reference coordinator and compares exact response and session-state
//! fingerprints. Serialized owners, fences, and results are never adopted as authority. These
//! private reference records are not another public `fss/1` operation or a canonical world ledger.

use std::path::Path;

use fss_core::{ContentDigest, PrincipalId, SessionId, TimestampNs};

use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    SessionJournalInspection,
};
use crate::agent_session::ReferenceSessionStore;
use crate::agent_session::work_claims::{
    ReferenceWorkClaimStore, WorkClaimError, WorkClaimLimits, WorkClaimRecovery, WorkClaimRequest,
    WorkClaimRevision, WorkClaimUpdate,
};

mod codec;
mod recovery;

/// Session-admitted case lifecycle with immutable evidence-preserving revisions.
pub mod investigations;

pub use recovery::SessionRecoveryReceipt;

/// One-way initialization of bounded coordination within an existing session journal.
pub const COORDINATION_INIT_RECORD_KIND: u16 = 0x5749;
/// Replayable coordination command, session-state witnesses, and exact outcome fingerprint.
pub const COORDINATION_COMMAND_RECORD_KIND: u16 = 0x5743;
/// Hard bound on a complete private command record, independent of configured journal capacity.
pub const MAX_COORDINATION_RECORD_BYTES: usize = 1024 * 1024;

/// Typed reference coordination request. Principal, session, and time come from the runtime.
///
/// The digest in a mutation is a precondition, not permission. Domain capability/privacy/basis
/// checks still occur inside the owning reference state machine before a revision is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinationCommand {
    /// Reserve an already compiled, authorized, exact work scope.
    Acquire(WorkClaimRequest),
    /// Inspect the current authorized head without extending its lease.
    Inspect {
        /// Stable claim identity.
        claim_id: String,
    },
    /// Read a retained audit revision, never restore it as the current writer.
    InspectRevision {
        /// Stable claim identity.
        claim_id: String,
        /// Exact historical revision.
        revision: ContentDigest,
    },
    /// Change the live owner's exact current revision.
    Update {
        /// Stable claim identity.
        claim_id: String,
        /// Full revision CAS precondition.
        expected: ContentDigest,
        /// Typed update; cannot supply a replacement owner or fence.
        change: WorkClaimUpdate,
    },
    /// Explicitly expire, transfer, or reclaim through the same authority checks as live work.
    Recover {
        /// Stable claim identity.
        claim_id: String,
        /// Full revision CAS precondition.
        expected: ContentDigest,
        /// Typed recovery request; never settles an external effect obligation.
        recovery: WorkClaimRecovery,
    },
}

#[derive(Debug)]
pub(super) struct CoordinationState {
    pub(super) claims: ReferenceWorkClaimStore,
    pub(super) limits: WorkClaimLimits,
    pub(super) cases: Option<investigations::ReferenceInvestigationStore>,
}

impl CoordinationState {
    fn fork(&self) -> Self {
        Self {
            claims: self.claims.fork_for_transaction(),
            limits: self.limits,
            cases: self.cases.clone(),
        }
    }
}

impl DurableSessionStore {
    /// Enables coordination once and commits its exact ceilings before acknowledging success.
    ///
    /// An identical retry is a no-op; a different limit set or reset is refused. Existing session
    /// checkpoints remain readable, but old session-only readers MUST reject the new record kinds.
    /// Call only through the trusted, exclusive journal owner, not a raw agent transport.
    pub fn enable_coordination(
        &mut self,
        limits: WorkClaimLimits,
    ) -> Result<(), DurableSessionError> {
        self.preflight()?;
        if let Some(existing) = &self.coordination {
            return if existing.limits == limits {
                Ok(())
            } else {
                Err(DurableSessionError::InvalidHistory)
            };
        }
        let checkpoint = self.memory.checkpoint(self.limits.max_checkpoint_bytes)?;
        let payload = codec::encode_initialization(limits, checkpoint.digest())?;
        self.commit_candidate(PendingSession {
            memory: self.memory.clone(),
            checkpoint,
            coordination: Some(CoordinationState {
                claims: ReferenceWorkClaimStore::with_limits(limits),
                limits,
                cases: None,
            }),
            record: Some((COORDINATION_INIT_RECORD_KIND, payload)),
        })
    }

    /// Opens exact existing session AND claim history under independently supplied ceilings.
    ///
    /// Never initializes missing coordination state, repairs a tail, changes stored limits, or
    /// trusts a root found in the same file. The runtime must protect and independently pin roots.
    pub fn open_existing_with_coordination(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits,
    ) -> Result<Self, DurableSessionError> {
        Self::open_with_coordination_ceiling(
            path.as_ref(),
            expected_root,
            limits,
            Some(claim_ceilings),
        )
    }

    /// Replays the complete bounded prefix without modifying its bytes or adopting a new root.
    pub fn inspect_with_coordination(
        path: impl AsRef<Path>,
        limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits,
    ) -> Result<SessionJournalInspection, DurableSessionError> {
        Self::inspect_with_coordination_ceiling(path.as_ref(), limits, Some(claim_ceilings))
    }

    /// Commits one coordination command, including refusal-side authority mutations, atomically.
    ///
    /// The result is withheld until its record is synchronized. An uncertain append fences BOTH
    /// session and work operations; `reconcile_pending` never redelivers the withheld response.
    /// Reads are journaled too because they can advance clocks or create expiry tombstones.
    /// Journal capacity is consumed even by a no-op, and exhaustion never discards lease history.
    pub fn coordinate(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        command: CoordinationCommand,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, DurableSessionError> {
        self.preflight()?;
        let request = codec::Request {
            principal: principal.clone(),
            session: session_id.clone(),
            command,
            now,
        };
        // Hard bounds before copying any stores or executing session admission.
        let request_bytes = codec::encode_request(&request)?;
        let mut state = self
            .coordination
            .as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?
            .fork();
        let mut memory = self.memory.clone();
        let result = apply(&request, &mut memory, &mut state.claims);
        let staged = (|| -> Result<PendingSession, DurableSessionError> {
            let checkpoint = memory.checkpoint(self.limits.max_checkpoint_bytes)?;
            let payload = codec::encode_record(
                &request_bytes,
                self.checkpoint_digest,
                checkpoint.digest(),
                codec::outcome_digest(&result)?,
            )?;
            Ok(PendingSession {
                memory,
                checkpoint,
                coordination: Some(state),
                record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
            })
        })();
        let pending = match staged {
            Ok(pending) => pending,
            Err(error) => {
                self.fenced = true;
                return Err(error);
            }
        };
        self.commit_candidate(pending)?;
        result.map_err(DurableSessionError::WorkClaim)
    }
}

fn apply(
    request: &codec::Request,
    sessions: &mut ReferenceSessionStore,
    claims: &mut ReferenceWorkClaimStore,
) -> Result<WorkClaimRevision, WorkClaimError> {
    let codec::Request {
        principal,
        session,
        command,
        now,
    } = request;
    match command {
        CoordinationCommand::Acquire(input) => {
            claims.acquire(sessions, principal, session, input.clone(), *now)
        }
        CoordinationCommand::Inspect { claim_id } => {
            claims.inspect(sessions, principal, session, claim_id, *now)
        }
        CoordinationCommand::InspectRevision { claim_id, revision } => {
            claims.inspect_revision(sessions, principal, session, claim_id, *revision, *now)
        }
        CoordinationCommand::Update {
            claim_id,
            expected,
            change,
        } => {
            let current = claims.inspect(sessions, principal, session, claim_id, *now)?;
            if current.digest() != *expected {
                return Err(WorkClaimError::StaleRevision);
            }
            claims.update(sessions, principal, session, &current, *change, *now)
        }
        CoordinationCommand::Recover {
            claim_id,
            expected,
            recovery,
        } => {
            let current = claims.inspect(sessions, principal, session, claim_id, *now)?;
            if current.digest() != *expected {
                return Err(WorkClaimError::StaleRevision);
            }
            claims.recover(
                sessions,
                principal,
                session,
                &current,
                recovery.clone(),
                *now,
            )
        }
    }
}

pub(super) fn restore_initialization(
    payload: &[u8],
    session_digest: ContentDigest,
    ceilings: WorkClaimLimits,
) -> Result<CoordinationState, DurableSessionError> {
    let limits = codec::decode_initialization(payload, session_digest, ceilings)?;
    Ok(CoordinationState {
        claims: ReferenceWorkClaimStore::with_limits(limits),
        limits,
        cases: None,
    })
}

pub(super) fn replay_command(
    payload: &[u8],
    sessions: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if investigations::journal::is_record(payload)? {
        return investigations::journal::replay_record(payload, sessions, state, limits);
    }
    let record = codec::decode_record(payload)?;
    if sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.before {
        return Err(DurableSessionError::InvalidHistory);
    }
    let result = apply(&record.request, sessions, &mut state.claims);
    if codec::outcome_digest(&result)? != record.outcome
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.after
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

pub mod source_hydration {
    #![forbid(unsafe_code)]
    //! Live source reads through session authority, not caller-asserted hydration grants.
    //!
    //! The published-source reader remains the custody owner. This bridge reuses ordinary session
    //! admission, source bindings, full-vector quotes, and single-use catalog continuations. It
    //! does not cache source bytes, mint capabilities, or promote a citation into physical knowledge.

    use std::fmt;

    use fss_core::{HydrationRequest, HydrationResponse, PrincipalId, TimestampNs};

    use crate::agent_session::SessionAlias;
    use crate::{PublishedSourceReader, ReferenceHydrationCatalog};

    pub use crate::agent_session::hydration::SessionSourceHydrationError;

    /// Persistence uncertainty is not a source-delivery refusal and never permits a blind retry.
    #[derive(Debug)]
    pub enum DurableSourceHydrationError {
        /// The shared session journal could not commit or requires reconciliation.
        Durability(super::super::DurableSessionError),
        /// Admission or custody refused; any session watermark/tombstone changes were committed.
        Refused(SessionSourceHydrationError),
    }

    impl fmt::Display for DurableSourceHydrationError {
        fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
            output.write_str(match self {
                Self::Durability(_) => "durable source hydration persistence failed",
                Self::Refused(_) => "durable source hydration refused",
            })
        }
    }

    impl std::error::Error for DurableSourceHydrationError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Durability(error) => Some(error),
                Self::Refused(error) => Some(error),
            }
        }
    }

    impl From<super::super::DurableSessionError> for DurableSourceHydrationError {
        fn from(error: super::super::DurableSessionError) -> Self {
            Self::Durability(error)
        }
    }

    impl super::super::DurableSessionStore {
        /// Withholds source bytes and catalog changes until their session charge is durable.
        ///
        /// This works for session-only journals and for the existing joint session/work/case
        /// journal; no coordination initialization or new durable record kind is required. It
        /// preserves the coordinator and its cases while committing a normal session checkpoint.
        ///
        /// Refusals persist any session clock/tombstone changes before returning. Failed checkpoint
        /// preparation or append fences the shared owner; source bytes and staged catalog changes
        /// are dropped, not published. Reconciliation may install a charge but never redelivers the
        /// response, rereads source, refunds a committed charge, or automatically retries delivery.
        /// An explicit later retry rechecks live custody and can incur another charge.
        ///
        /// Source payloads never enter the journal or a second catalog cache. Catalog cursor
        /// tombstones remain separately owned state, as with the existing cached durable hydrator;
        /// this does not make the catalog durable or make an old disclosure prove current custody.
        pub fn hydrate_from_source(
            &mut self,
            principal: &PrincipalId,
            alias: &SessionAlias,
            request: &HydrationRequest,
            catalog: &mut ReferenceHydrationCatalog,
            reader: &dyn PublishedSourceReader,
            now: TimestampNs,
        ) -> Result<HydrationResponse, DurableSourceHydrationError> {
            use super::super::{DurableSessionError, PendingSession};

            self.preflight()?;
            let mut candidate = self.memory.clone();
            let mut staged_catalog = catalog.clone();
            let result = candidate.hydrate_from_source(
                principal,
                alias,
                request,
                &mut staged_catalog,
                reader,
                now,
            );
            // Even a failed read may have advanced a clock or closed an expired session.
            let checkpoint = match candidate.checkpoint(self.limits.max_checkpoint_bytes) {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    self.fenced = true;
                    return Err(DurableSessionError::from(error).into());
                }
            };
            if checkpoint.digest() != self.checkpoint_digest {
                self.commit_candidate(PendingSession {
                    memory: candidate,
                    checkpoint,
                    coordination: None,
                    record: None,
                })?;
            }
            // The response, its source bytes, and cursor mutations escape only after durable commit.
            let response = result.map_err(DurableSourceHydrationError::Refused)?;
            *catalog = staged_catalog;
            Ok(response)
        }
    }

    #[cfg(test)]
    mod tests {
        #![forbid(unsafe_code)]
        use std::cell::Cell;
        use std::collections::BTreeSet;
        use std::error::Error;

        use fss_core::{
            AgentSessionParams, BudgetVector, Completeness, ContentDigest, ContractBasis,
            ContractBasisRegistryBytes, Generation, HandleAvailability, HydrationArtifact,
            HydrationError, HydrationLevel, HydrationPurpose, HydrationRequestSpec,
            LaboratoryAccess, LedgerAnchor, MissionId, ObjectId, SemanticHandle,
            SemanticHandleSpec, SessionId, TombstoneReason, TombstoneRecord,
        };
        use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

        use super::*;
        use crate::SourceHydrationError;
        use crate::agent_session::{
            ReferenceSessionError, ReferenceSessionStore, SessionBindingRequest, SessionRefresh,
        };

        type TestResult = Result<(), Box<dyn Error>>;
        const SOURCE: &[u8] = b"source bytes retained only by the publication owner";
        const TOKENS: u64 = 512;

        struct Fixture {
            sessions: ReferenceSessionStore,
            params: AgentSessionParams,
            alias: SessionAlias,
            catalog: ReferenceHydrationCatalog,
            store: InMemoryObjectStore,
            handle: SemanticHandle,
            root: ContentDigest,
            metadata: ContentDigest,
        }

        fn fixture() -> Result<Fixture, Box<dyn Error>> {
            let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
                b"s",
                b"o",
                b"v",
                b"c",
                b"e",
                b"cost",
                "session-source:test",
            ));
            let anchor = LedgerAnchor::genesis("site:session-source");
            let params = AgentSessionParams {
                session_id: SessionId::parse("session:source")?,
                mission_id: MissionId::parse("mission:source")?,
                principal_id: PrincipalId::parse("principal:owner")?,
                capabilities: BTreeSet::from([
                    "capability:preview".to_owned(),
                    "capability:source".to_owned(),
                ]),
                privacy_scope: BTreeSet::from(["private:property".to_owned()]),
                current_anchor: anchor.clone(),
                view_id: "AVIEW-001".to_owned(),
                token_budget: 3 * TOKENS,
                symbol_table_generation: 0,
                last_acknowledged_situation_fingerprint: None,
                created_at_ns: 0,
                expires_at_ns: 1_000,
            };
            let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
            let subject = store.put_verified(SOURCE)?;
            let metadata = store.put_verified(b"capture provenance")?;
            let root = store
                .publish_manifest(ObjectManifest::new("source", [subject], Some(metadata))?)?
                .root;
            let levels = BTreeSet::from([
                HydrationLevel::H0,
                HydrationLevel::H1,
                HydrationLevel::H2,
                HydrationLevel::H3,
            ]);
            let quote = BudgetVector::builder()
                .bytes(1_024)
                .tokens(TOKENS)
                .build()?;
            let handle = SemanticHandle::publish(SemanticHandleSpec {
                contract_basis: basis.clone(),
                anchor,
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
                required_capabilities: levels
                    .iter()
                    .map(|level| {
                        let grant = if *level == HydrationLevel::H3 {
                            "capability:source"
                        } else {
                            "capability:preview"
                        };
                        (*level, BTreeSet::from([grant.to_owned()]))
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
                    b"decision preview".to_vec(),
                    [handle.subject_digest],
                    Completeness::Complete,
                    None,
                )?,
            )?;
            catalog.bind_source_object(
                &handle.handle_id,
                handle.descriptor_digest,
                root,
                &store,
            )?;
            let mut sessions = ReferenceSessionStore::default();
            sessions.open(params.clone(), basis, TimestampNs(10))?;
            let alias = sessions.bind(
                &params.principal_id,
                &binding_request(&params, &handle),
                &catalog,
                TimestampNs(10),
            )?;
            Ok(Fixture {
                sessions,
                params,
                alias,
                catalog,
                store,
                handle,
                root,
                metadata,
            })
        }

        fn binding_request(
            params: &AgentSessionParams,
            handle: &SemanticHandle,
        ) -> SessionBindingRequest {
            SessionBindingRequest {
                session_id: params.session_id.clone(),
                generation: 0,
                handle_id: handle.handle_id.clone(),
                descriptor_digest: handle.descriptor_digest,
            }
        }

        fn request(f: &Fixture, level: HydrationLevel) -> Result<HydrationRequest, Box<dyn Error>> {
            Ok(HydrationRequest::publish(HydrationRequestSpec {
                contract_basis: f.handle.contract_basis.clone(),
                session_id: f.params.session_id.clone(),
                handle_id: f.handle.handle_id.clone(),
                expected_descriptor_digest: f.handle.descriptor_digest,
                expected_subject_digest: f.handle.subject_digest,
                anchor: f.handle.anchor.clone(),
                requested_level: level,
                allow_lower_level: false,
                available_capabilities: f.params.capabilities.clone(),
                authorized_privacy_classes: f.params.privacy_scope.clone(),
                budget: BudgetVector::builder()
                    .bytes(1_024)
                    .tokens(TOKENS)
                    .build()?,
                purpose: HydrationPurpose::Routine,
                continuation: None,
                issued_at: TimestampNs(10),
            })?)
        }

        fn reseal(request: &mut HydrationRequest) {
            request.request_digest = request.computed_digest();
            request.request_id = format!("hydration-request:{}", request.request_digest);
        }

        struct ReaderProbe {
            calls: Cell<usize>,
            bytes: Vec<u8>,
        }
        impl ReaderProbe {
            fn new(bytes: &[u8]) -> Self {
                Self {
                    calls: Cell::new(0),
                    bytes: bytes.to_vec(),
                }
            }
        }
        impl PublishedSourceReader for ReaderProbe {
            fn read_published_source(
                &self,
                _: ContentDigest,
                _: ContentDigest,
                _: u64,
            ) -> Result<Vec<u8>, SourceHydrationError> {
                self.calls.set(self.calls.get() + 1);
                Ok(self.bytes.clone())
            }
        }

        fn remaining(f: &mut Fixture, now: i128) -> Result<u64, ReferenceSessionError> {
            f.sessions.remaining_token_budget(
                &f.params.principal_id,
                &f.params.session_id,
                TimestampNs(now),
            )
        }

        #[test]
        fn source_delivery_uses_session_budget_and_never_populates_h3_cache() -> TestResult {
            let mut f = fixture()?;
            let req = request(&f, HydrationLevel::H3)?;
            let cached = f.catalog.stored_payload_bytes();
            for expected in [2 * TOKENS, TOKENS, 0] {
                let result = f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(20),
                )?;
                f.catalog
                    .source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
                    .ok_or("missing source binding")?
                    .validate_response(&req, &f.handle, &result)?;
                assert_eq!(
                    result.artifact.as_ref().ok_or("missing source")?.payload,
                    SOURCE
                );
                assert_eq!(remaining(&mut f, 20)?, expected);
                assert_eq!(f.catalog.stored_payload_bytes(), cached);
            }
            let probe = ReaderProbe::new(SOURCE);
            assert!(matches!(
                f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &probe,
                    TimestampNs(20)
                ),
                Err(SessionSourceHydrationError::Session(
                    ReferenceSessionError::BudgetExceeded
                ))
            ));
            assert_eq!(probe.calls.get(), 0);
            assert!(matches!(
                f.catalog.hydrate(&req, TimestampNs(20)),
                Err(HydrationError::LevelUnavailable)
            ));
            Ok(())
        }

        #[test]
        fn session_and_request_denials_precede_reader_and_cursor_mutation() -> TestResult {
            for case in 0..12 {
                let mut f = fixture()?;
                let mut req = request(&f, HydrationLevel::H3)?;
                let mut principal = f.params.principal_id.clone();
                let mut alias = f.alias.clone();
                match case {
                    0 => principal = PrincipalId::parse("principal:other")?,
                    1 => alias.generation += 1,
                    2 => alias.slot += 1,
                    3 => req.session_id = SessionId::parse("session:other")?,
                    4 => req.expected_subject_digest = ContentDigest::sha256(b"wrong subject"),
                    5 => req.anchor.commit_sequence += 1,
                    6 => {
                        req.available_capabilities
                            .insert("capability:ungranted".to_owned());
                    }
                    7 => {
                        req.authorized_privacy_classes
                            .insert("private:other".to_owned());
                    }
                    8 => req.issued_at = TimestampNs(21),
                    9 => {
                        req.budget = BudgetVector::builder()
                            .tokens(4 * TOKENS)
                            .bytes(1_024)
                            .build()?
                    }
                    10 => {
                        req.available_capabilities.remove("capability:source");
                    }
                    _ => {
                        req.budget = BudgetVector::builder()
                            .tokens(TOKENS)
                            .bytes(1_023)
                            .build()?
                    }
                }
                reseal(&mut req);
                let probe = ReaderProbe::new(SOURCE);
                let cursors = f.catalog.issued_cursor_count();
                assert!(
                    f.sessions
                        .hydrate_from_source(
                            &principal,
                            &alias,
                            &req,
                            &mut f.catalog,
                            &probe,
                            TimestampNs(20)
                        )
                        .is_err(),
                    "case {case}"
                );
                assert_eq!(probe.calls.get(), 0, "case {case}");
                assert_eq!(f.catalog.issued_cursor_count(), cursors);
                assert_eq!(remaining(&mut f, 20)?, 3 * TOKENS);
            }
            Ok(())
        }

        #[test]
        fn revoked_grants_and_stale_aliases_cannot_reach_source() -> TestResult {
            let mut f = fixture()?;
            let req = request(&f, HydrationLevel::H3)?;
            let current = f.sessions.session(
                &f.params.principal_id,
                &f.params.session_id,
                TimestampNs(20),
            )?;
            f.sessions.refresh(
                &f.params.principal_id,
                &f.params.session_id,
                SessionRefresh {
                    expected_session_digest: current.session_digest(),
                    current_anchor: current.current_anchor,
                    capabilities: BTreeSet::from(["capability:preview".to_owned()]),
                    privacy_scope: current.privacy_scope,
                },
                TimestampNs(20),
            )?;
            let probe = ReaderProbe::new(SOURCE);
            assert!(
                f.sessions
                    .hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(20)
                    )
                    .is_err()
            );
            let current = f.sessions.session(
                &f.params.principal_id,
                &f.params.session_id,
                TimestampNs(20),
            )?;
            let mut binding = binding_request(&f.params, &f.handle);
            binding.generation = current.symbol_table_generation;
            let alias = f.sessions.bind(
                &f.params.principal_id,
                &binding,
                &f.catalog,
                TimestampNs(20),
            )?;
            assert!(matches!(
                f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &alias,
                    &req,
                    &mut f.catalog,
                    &probe,
                    TimestampNs(20)
                ),
                Err(SessionSourceHydrationError::Session(
                    ReferenceSessionError::GrantEscalation
                ))
            ));
            assert_eq!(probe.calls.get(), 0);
            Ok(())
        }

        #[test]
        fn source_continuation_shares_cached_cursor_ledger_and_spend() -> TestResult {
            let mut f = fixture()?;
            let preview = request(&f, HydrationLevel::H2)?;
            let cursor = f
                .sessions
                .hydrate(
                    &f.params.principal_id,
                    &f.alias,
                    &preview,
                    &mut f.catalog,
                    TimestampNs(20),
                )?
                .receipt
                .continuation
                .ok_or("missing H3 cursor")?;
            let mut req = request(&f, HydrationLevel::H3)?;
            req.continuation = Some(cursor.clone());
            req.issued_at = TimestampNs(21);
            reseal(&mut req);
            let wrong = ReaderProbe::new(b"substituted bytes");
            assert!(matches!(
                f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &wrong,
                    TimestampNs(22)
                ),
                Err(SessionSourceHydrationError::Source(
                    SourceHydrationError::SourceMismatch
                ))
            ));
            assert!(
                !f.catalog
                    .issued_cursor(&cursor.cursor_digest)
                    .ok_or("missing cursor")?
                    .consumed
            );
            assert_eq!(remaining(&mut f, 22)?, 2 * TOKENS);
            f.sessions.hydrate_from_source(
                &f.params.principal_id,
                &f.alias,
                &req,
                &mut f.catalog,
                &f.store,
                TimestampNs(22),
            )?;
            assert_eq!(remaining(&mut f, 22)?, TOKENS);
            assert!(
                f.catalog
                    .issued_cursor(&cursor.cursor_digest)
                    .ok_or("missing cursor")?
                    .consumed
            );
            let probe = ReaderProbe::new(SOURCE);
            assert!(matches!(
                f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &probe,
                    TimestampNs(23)
                ),
                Err(SessionSourceHydrationError::Source(
                    SourceHydrationError::Hydration(HydrationError::ContinuationAlreadyConsumed)
                ))
            ));
            assert_eq!(probe.calls.get(), 0);
            Ok(())
        }

        #[test]
        fn explicit_preview_downgrade_never_reads_or_claims_source() -> TestResult {
            let mut f = fixture()?;
            let mut req = request(&f, HydrationLevel::H3)?;
            req.available_capabilities.remove("capability:source");
            req.allow_lower_level = true;
            reseal(&mut req);
            let probe = ReaderProbe::new(SOURCE);
            let result = f.sessions.hydrate_from_source(
                &f.params.principal_id,
                &f.alias,
                &req,
                &mut f.catalog,
                &probe,
                TimestampNs(20),
            )?;
            assert_eq!(
                result.artifact.as_ref().ok_or("missing preview")?.level,
                HydrationLevel::H2
            );
            assert_eq!(probe.calls.get(), 0);
            assert_eq!(remaining(&mut f, 20)?, 2 * TOKENS);
            assert!(
                f.catalog
                    .source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
                    .ok_or("missing binding")?
                    .validate_response(&req, &f.handle, &result)
                    .is_err()
            );
            Ok(())
        }

        #[test]
        fn tombstoned_source_root_or_closure_cannot_be_served_after_success() -> TestResult {
            for which in 0..3 {
                let mut f = fixture()?;
                let req = request(&f, HydrationLevel::H3)?;
                f.sessions.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(20),
                )?;
                let target = match which {
                    0 => f.handle.subject_digest,
                    1 => f.root,
                    _ => f.metadata,
                };
                let witness = f.store.put_verified(b"authorized deletion witness")?;
                let prior = Generation::parse_positive(1)?;
                f.store.tombstone(
                    target,
                    TombstoneRecord::new(
                        ObjectId::parse("obj-source")?,
                        prior.next()?,
                        prior,
                        TombstoneReason::Deleted,
                        Some(witness),
                        target,
                    )?,
                )?;
                assert!(
                    f.sessions
                        .hydrate_from_source(
                            &f.params.principal_id,
                            &f.alias,
                            &req,
                            &mut f.catalog,
                            &f.store,
                            TimestampNs(21)
                        )
                        .is_err()
                );
                assert_eq!(remaining(&mut f, 21)?, 2 * TOKENS);
                assert!(matches!(
                    f.catalog.hydrate(&req, TimestampNs(21)),
                    Err(HydrationError::LevelUnavailable)
                ));
            }
            Ok(())
        }

        #[test]
        fn retention_expiry_and_session_close_refuse_source_before_io() -> TestResult {
            for now in [100, 1_000] {
                let mut f = fixture()?;
                let req = request(&f, HydrationLevel::H3)?;
                let probe = ReaderProbe::new(SOURCE);
                assert!(
                    f.sessions
                        .hydrate_from_source(
                            &f.params.principal_id,
                            &f.alias,
                            &req,
                            &mut f.catalog,
                            &probe,
                            TimestampNs(now)
                        )
                        .is_err()
                );
                assert_eq!(probe.calls.get(), 0);
            }
            let mut f = fixture()?;
            let req = request(&f, HydrationLevel::H3)?;
            f.sessions.close(
                &f.params.principal_id,
                &f.params.session_id,
                TimestampNs(20),
            )?;
            let probe = ReaderProbe::new(SOURCE);
            assert!(
                f.sessions
                    .hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(21)
                    )
                    .is_err()
            );
            assert_eq!(probe.calls.get(), 0);
            Ok(())
        }

        #[test]
        fn old_cached_path_keeps_its_error_and_does_not_charge_missing_h3() -> TestResult {
            let mut f = fixture()?;
            let req = request(&f, HydrationLevel::H3)?;
            assert!(matches!(
                f.sessions.hydrate(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    TimestampNs(20)
                ),
                Err(ReferenceSessionError::Hydration(
                    HydrationError::LevelUnavailable
                ))
            ));
            assert_eq!(remaining(&mut f, 20)?, 3 * TOKENS);
            Ok(())
        }
        mod durable {
            use super::*;
            use std::path::PathBuf;
            use std::sync::atomic::{AtomicU64, Ordering};

            use crate::agent_session::checkpoint::journal::coordination::CoordinationCommand;
            use crate::agent_session::checkpoint::journal::coordination::investigations::{
                InvestigationCommand, InvestigationLimits,
            };
            use crate::agent_session::checkpoint::journal::{
                DurableSessionError, DurableSessionLimits, DurableSessionStore,
                SessionAppendRecovery,
            };
            use crate::agent_session::work_claims::{WorkClaimLimits, WorkClaimRequest};
            use fss_core::{
                CaseHypothesis, CaseId, InvestigationLifecycle, InvestigationState,
                InvestigationStateParams, KnowledgeState,
            };
            use fss_ledger::{AppendPhase, IncompleteTailPolicy};

            static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

            // Match the existing journal fault suites: never overwrite or delete a prior test artifact.
            fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
                for _ in 0..128 {
                    let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
                    let path = std::env::temp_dir().join(format!(
                        "fss-source-session-{}-{serial}.journal",
                        std::process::id(),
                    ));
                    if !path.exists() {
                        return Ok(path);
                    }
                }
                Err("test journal path capacity exhausted".into())
            }

            fn opened(
                limits: DurableSessionLimits,
            ) -> Result<(Fixture, DurableSessionStore), Box<dyn Error>> {
                let mut f = fixture()?;
                f.params.capabilities.extend([
                    "CAP-AGENT-WORK-CLAIM-001".to_owned(),
                    "CAP-AGENT-INVESTIGATE-001".to_owned(),
                ]);
                let mut durable = DurableSessionStore::create(unused_path()?, limits)?;
                durable.open(
                    f.params.clone(),
                    f.handle.contract_basis.clone(),
                    TimestampNs(10),
                )?;
                let alias = durable.bind(
                    &f.params.principal_id,
                    &binding_request(&f.params, &f.handle),
                    &f.catalog,
                    TimestampNs(10),
                )?;
                assert_eq!(alias, f.alias);
                Ok((f, durable))
            }

            fn budget(
                store: &mut DurableSessionStore,
                f: &Fixture,
                now: i128,
            ) -> Result<u64, DurableSessionError> {
                store.remaining_token_budget(
                    &f.params.principal_id,
                    &f.params.session_id,
                    TimestampNs(now),
                )
            }

            fn assert_no_source_in_journal(store: &DurableSessionStore) -> TestResult {
                let bytes = std::fs::read(store.path())?;
                assert!(!bytes.windows(SOURCE.len()).any(|window| window == SOURCE));
                Ok(())
            }

            #[test]
            fn committed_source_charge_reopens_without_persisting_source_payload() -> TestResult {
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                let req = request(&f, HydrationLevel::H3)?;
                let result = store.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(20),
                )?;
                f.catalog
                    .source_binding(&f.handle.handle_id, f.handle.descriptor_digest)
                    .ok_or("missing binding")?
                    .validate_response(&req, &f.handle, &result)?;
                assert_eq!(budget(&mut store, &f, 20)?, 2 * TOKENS);
                assert_no_source_in_journal(&store)?;
                let path = store.path().to_path_buf();
                let root = store.committed_root();
                drop(store);
                let mut store = DurableSessionStore::open_existing(
                    path,
                    root,
                    DurableSessionLimits::default(),
                )?;
                assert_eq!(budget(&mut store, &f, 20)?, 2 * TOKENS);
                store.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(21),
                )?;
                assert_eq!(budget(&mut store, &f, 21)?, TOKENS);
                store.verify_storage()?;
                assert_no_source_in_journal(&store)?;
                Ok(())
            }

            #[test]
            fn uncertain_source_delivery_fences_owner_and_preserves_catalog_until_reconciliation()
            -> TestResult {
                for (phase, committed) in [
                    (AppendPhase::BodyWrite, false),
                    (AppendPhase::BodySync, false),
                    (AppendPhase::CommitWrite, true),
                    (AppendPhase::CommitSync, true),
                ] {
                    let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                    store.enable_coordination(WorkClaimLimits::default())?;
                    store.enable_investigations(InvestigationLimits::default())?;
                    let preview = request(&f, HydrationLevel::H2)?;
                    let cursor = store
                        .hydrate(
                            &f.params.principal_id,
                            &f.alias,
                            &preview,
                            &mut f.catalog,
                            TimestampNs(20),
                        )?
                        .receipt
                        .continuation
                        .ok_or("missing H3 cursor")?;
                    let mut req = request(&f, HydrationLevel::H3)?;
                    req.continuation = Some(cursor.clone());
                    req.issued_at = TimestampNs(21);
                    reseal(&mut req);
                    let probe = ReaderProbe::new(SOURCE);
                    let cursors = f.catalog.issued_cursor_count();
                    let cached = f.catalog.stored_payload_bytes();
                    store.journal.fail_after_phase(phase);
                    assert!(matches!(
                        store.hydrate_from_source(
                            &f.params.principal_id,
                            &f.alias,
                            &req,
                            &mut f.catalog,
                            &probe,
                            TimestampNs(22)
                        ),
                        Err(DurableSourceHydrationError::Durability(
                            DurableSessionError::Journal(_)
                        ))
                    ));
                    assert!(store.needs_reconciliation());
                    assert_eq!(probe.calls.get(), 1);
                    assert_eq!(f.catalog.issued_cursor_count(), cursors);
                    assert_eq!(f.catalog.stored_payload_bytes(), cached);
                    assert!(
                        !f.catalog
                            .issued_cursor(&cursor.cursor_digest)
                            .ok_or("missing cursor")?
                            .consumed
                    );
                    assert!(matches!(
                        store.hydrate_from_source(
                            &f.params.principal_id,
                            &f.alias,
                            &req,
                            &mut f.catalog,
                            &probe,
                            TimestampNs(23)
                        ),
                        Err(DurableSourceHydrationError::Durability(
                            DurableSessionError::ReconciliationRequired
                        ))
                    ));
                    assert!(matches!(
                        store.session(
                            &f.params.principal_id,
                            &f.params.session_id,
                            TimestampNs(23)
                        ),
                        Err(DurableSessionError::ReconciliationRequired)
                    ));
                    assert!(matches!(
                        store.coordinate(
                            &f.params.principal_id,
                            &f.params.session_id,
                            CoordinationCommand::Inspect {
                                claim_id: "claim:absent".to_owned()
                            },
                            TimestampNs(23)
                        ),
                        Err(DurableSessionError::ReconciliationRequired)
                    ));
                    assert!(
                        store
                            .investigate(
                                &f.params.principal_id,
                                &f.params.session_id,
                                InvestigationCommand::Inspect {
                                    case_id: "case:absent".to_owned(),
                                    revision: None
                                },
                                TimestampNs(23)
                            )
                            .is_err()
                    );
                    assert_eq!(probe.calls.get(), 1);
                    if !committed {
                        let before = std::fs::read(store.path())?;
                        assert!(
                            store
                                .reconcile_pending(IncompleteTailPolicy::Reject)
                                .is_err()
                        );
                        assert_eq!(std::fs::read(store.path())?, before);
                    }
                    assert_eq!(
                        store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
                        if committed {
                            SessionAppendRecovery::Committed
                        } else {
                            SessionAppendRecovery::NotCommitted
                        }
                    );
                    assert_eq!(
                        probe.calls.get(),
                        1,
                        "recovery must never reread or redeliver source"
                    );
                    assert_eq!(
                        budget(&mut store, &f, 23)?,
                        if committed { TOKENS } else { 2 * TOKENS }
                    );
                    assert!(
                        !f.catalog
                            .issued_cursor(&cursor.cursor_digest)
                            .ok_or("missing cursor")?
                            .consumed
                    );
                    // This is an explicit retry, not a recovery side effect; it checks custody and charges again.
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(23),
                    )?;
                    assert_eq!(probe.calls.get(), 2);
                    assert!(
                        f.catalog
                            .issued_cursor(&cursor.cursor_digest)
                            .ok_or("missing cursor")?
                            .consumed
                    );
                    assert_eq!(
                        budget(&mut store, &f, 23)?,
                        if committed { 0 } else { TOKENS }
                    );
                    store.verify_storage()?;
                    assert_no_source_in_journal(&store)?;
                }
                Ok(())
            }

            #[test]
            fn cold_recovery_preserves_complete_lost_ack_charge_and_never_adopts_old_root()
            -> TestResult {
                for (phase, committed) in [
                    (AppendPhase::BodyWrite, false),
                    (AppendPhase::BodySync, false),
                    (AppendPhase::CommitWrite, true),
                    (AppendPhase::CommitSync, true),
                ] {
                    let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                    let req = request(&f, HydrationLevel::H3)?;
                    let old = store.committed_root();
                    store.journal.fail_after_phase(phase);
                    assert!(
                        store
                            .hydrate_from_source(
                                &f.params.principal_id,
                                &f.alias,
                                &req,
                                &mut f.catalog,
                                &f.store,
                                TimestampNs(20)
                            )
                            .is_err()
                    );
                    let path = store.path().to_path_buf();
                    drop(store);
                    let inspection =
                        DurableSessionStore::inspect(&path, DurableSessionLimits::default())?;
                    let before = std::fs::read(&path)?;
                    if committed {
                        assert_ne!(inspection.root, old);
                        assert!(matches!(
                            DurableSessionStore::recover_existing(
                                &path,
                                old,
                                DurableSessionLimits::default(),
                                IncompleteTailPolicy::Truncate
                            ),
                            Err(DurableSessionError::RootMismatch)
                        ));
                    } else {
                        assert_eq!(inspection.root, old);
                        assert!(
                            DurableSessionStore::recover_existing(
                                &path,
                                old,
                                DurableSessionLimits::default(),
                                IncompleteTailPolicy::Reject
                            )
                            .is_err()
                        );
                    }
                    assert_eq!(std::fs::read(&path)?, before);
                    // Test fixture independently knows which exact record reached the commit marker.
                    let (mut recovered, receipt) = DurableSessionStore::recover_existing(
                        &path,
                        inspection.root,
                        DurableSessionLimits::default(),
                        IncompleteTailPolicy::Truncate,
                    )?;
                    assert_eq!(receipt.discarded_bytes() > 0, !committed);
                    assert_eq!(
                        budget(&mut recovered, &f, 21)?,
                        if committed { 2 * TOKENS } else { 3 * TOKENS }
                    );
                    assert_no_source_in_journal(&recovered)?;
                }
                Ok(())
            }

            #[test]
            fn failed_custody_read_persists_clock_without_charging_tokens() -> TestResult {
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                let req = request(&f, HydrationLevel::H3)?;
                let old = store.committed_root();
                let wrong = ReaderProbe::new(b"substituted source");
                assert!(matches!(
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &wrong,
                        TimestampNs(20)
                    ),
                    Err(DurableSourceHydrationError::Refused(
                        SessionSourceHydrationError::Source(SourceHydrationError::SourceMismatch)
                    ))
                ));
                assert_ne!(store.committed_root(), old);
                let path = store.path().to_path_buf();
                let root = store.committed_root();
                drop(store);
                let mut store = DurableSessionStore::open_existing(
                    path,
                    root,
                    DurableSessionLimits::default(),
                )?;
                let probe = ReaderProbe::new(SOURCE);
                assert!(matches!(
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(19)
                    ),
                    Err(DurableSourceHydrationError::Refused(
                        SessionSourceHydrationError::Session(
                            ReferenceSessionError::ClockRegression
                        )
                    ))
                ));
                assert_eq!(probe.calls.get(), 0);
                assert_eq!(budget(&mut store, &f, 20)?, 3 * TOKENS);
                Ok(())
            }

            #[test]
            fn expired_session_refusal_is_durable_and_performs_no_source_read() -> TestResult {
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                let req = request(&f, HydrationLevel::H3)?;
                let old = store.committed_root();
                let probe = ReaderProbe::new(SOURCE);
                assert!(matches!(
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(1_000)
                    ),
                    Err(DurableSourceHydrationError::Refused(
                        SessionSourceHydrationError::Session(ReferenceSessionError::Unavailable)
                    ))
                ));
                assert_eq!(probe.calls.get(), 0);
                assert_ne!(store.committed_root(), old);
                let path = store.path().to_path_buf();
                let root = store.committed_root();
                drop(store);
                let mut store = DurableSessionStore::open_existing(
                    path,
                    root,
                    DurableSessionLimits::default(),
                )?;
                assert!(
                    store
                        .open(f.params, f.handle.contract_basis, TimestampNs(10))
                        .is_err()
                );
                Ok(())
            }

            #[test]
            fn journal_capacity_withholds_payload_and_does_not_publish_cursor_consumption()
            -> TestResult {
                let limits = DurableSessionLimits {
                    max_records: 4,
                    ..DurableSessionLimits::default()
                };
                let (mut f, mut store) = opened(limits)?;
                let preview = request(&f, HydrationLevel::H2)?;
                let cursor = store
                    .hydrate(
                        &f.params.principal_id,
                        &f.alias,
                        &preview,
                        &mut f.catalog,
                        TimestampNs(20),
                    )?
                    .receipt
                    .continuation
                    .ok_or("missing H3 cursor")?;
                let mut req = request(&f, HydrationLevel::H3)?;
                req.continuation = Some(cursor.clone());
                req.issued_at = TimestampNs(21);
                reseal(&mut req);
                let before = std::fs::read(store.path())?;
                assert!(matches!(
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &f.store,
                        TimestampNs(22)
                    ),
                    Err(DurableSourceHydrationError::Durability(
                        DurableSessionError::CapacityExceeded
                    ))
                ));
                assert!(store.needs_reconciliation());
                assert_eq!(std::fs::read(store.path())?, before);
                assert!(
                    !f.catalog
                        .issued_cursor(&cursor.cursor_digest)
                        .ok_or("missing cursor")?
                        .consumed
                );
                let probe = ReaderProbe::new(SOURCE);
                assert!(
                    store
                        .hydrate_from_source(
                            &f.params.principal_id,
                            &f.alias,
                            &req,
                            &mut f.catalog,
                            &probe,
                            TimestampNs(23)
                        )
                        .is_err()
                );
                assert_eq!(probe.calls.get(), 0);
                Ok(())
            }

            #[test]
            fn source_checkpoint_preserves_interleaved_work_and_investigation_history() -> TestResult
            {
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                store.enable_coordination(WorkClaimLimits::default())?;
                store.enable_investigations(InvestigationLimits::default())?;
                let record = InvestigationState::new(InvestigationStateParams {
                    investigation_id: "case:source".to_owned(),
                    contract_basis: f.handle.contract_basis.clone(),
                    mission_id: f.params.mission_id.clone(),
                    revision: 1,
                    state: InvestigationLifecycle::Draft,
                    question: "Which original source should be examined?".to_owned(),
                    decision_informed: "Inspect evidence without claiming an observation"
                        .to_owned(),
                    basis_anchor: f.handle.anchor.clone(),
                    hypotheses: ["hypothesis:a", "hypothesis:b"]
                        .into_iter()
                        .map(|id| CaseHypothesis {
                            hypothesis_id: id.to_owned(),
                            description: id.to_owned(),
                            epistemic_state: KnowledgeState::Unknown,
                            predictions: vec![],
                            evidence: vec![],
                            contradictions: vec![],
                        })
                        .collect(),
                    knowns: vec![],
                    unknowns: vec![],
                    discriminators: vec![],
                    probes: vec![],
                    stop_rules: vec!["bounded examination".to_owned()],
                    decision_deadline_ns: 90,
                })?;
                let case = store.investigate(
                    &f.params.principal_id,
                    &f.params.session_id,
                    InvestigationCommand::Open {
                        record: Box::new(record),
                        privacy_class: f.handle.privacy_class.clone(),
                    },
                    TimestampNs(10),
                )?;
                let claim = store.coordinate(
                    &f.params.principal_id,
                    &f.params.session_id,
                    CoordinationCommand::Acquire(WorkClaimRequest {
                        claim_id: "claim:source".to_owned(),
                        case_id: CaseId::parse("case:source")?,
                        work_root: ContentDigest::sha256(b"examine source"),
                        privacy_class: f.handle.privacy_class.clone(),
                        expires_at: TimestampNs(80),
                        dependencies: BTreeSet::new(),
                    }),
                    TimestampNs(10),
                )?;
                let req = request(&f, HydrationLevel::H3)?;
                store.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(20),
                )?;
                let path = store.path().to_path_buf();
                let root = store.committed_root();
                drop(store);
                let mut store = DurableSessionStore::open_existing_with_coordination(
                    path,
                    root,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                )?;
                assert_eq!(budget(&mut store, &f, 20)?, 2 * TOKENS);
                assert_eq!(
                    store.investigate(
                        &f.params.principal_id,
                        &f.params.session_id,
                        InvestigationCommand::Inspect {
                            case_id: "case:source".to_owned(),
                            revision: None
                        },
                        TimestampNs(20)
                    )?,
                    case
                );
                assert_eq!(
                    store.coordinate(
                        &f.params.principal_id,
                        &f.params.session_id,
                        CoordinationCommand::Inspect {
                            claim_id: "claim:source".to_owned()
                        },
                        TimestampNs(20)
                    )?,
                    claim
                );
                store.verify_storage()?;
                Ok(())
            }

            #[test]
            fn source_disclosure_does_not_turn_existing_cached_hydration_into_a_source_cache()
            -> TestResult {
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                let req = request(&f, HydrationLevel::H3)?;
                store.hydrate_from_source(
                    &f.params.principal_id,
                    &f.alias,
                    &req,
                    &mut f.catalog,
                    &f.store,
                    TimestampNs(20),
                )?;
                let old = store.committed_root();
                assert!(matches!(
                    store.hydrate(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        TimestampNs(20)
                    ),
                    Err(DurableSessionError::Session(
                        ReferenceSessionError::Hydration(HydrationError::LevelUnavailable)
                    ))
                ));
                assert_eq!(store.committed_root(), old);
                assert_eq!(budget(&mut store, &f, 20)?, 2 * TOKENS);
                Ok(())
            }

            #[test]
            fn externally_changed_journal_fences_before_source_io() -> TestResult {
                use std::io::Write;
                let (mut f, mut store) = opened(DurableSessionLimits::default())?;
                let req = request(&f, HydrationLevel::H3)?;
                let probe = ReaderProbe::new(SOURCE);
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(store.path())?;
                file.write_all(b"unexpected foreign tail")?;
                file.sync_all()?;
                let cursors = f.catalog.issued_cursor_count();
                assert!(matches!(
                    store.hydrate_from_source(
                        &f.params.principal_id,
                        &f.alias,
                        &req,
                        &mut f.catalog,
                        &probe,
                        TimestampNs(20)
                    ),
                    Err(DurableSourceHydrationError::Durability(
                        DurableSessionError::Journal(_)
                    ))
                ));
                assert!(store.needs_reconciliation());
                assert_eq!(probe.calls.get(), 0);
                assert_eq!(f.catalog.issued_cursor_count(), cursors);
                Ok(())
            }
        }
    }
}
