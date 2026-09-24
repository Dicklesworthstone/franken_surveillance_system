#![forbid(unsafe_code)]
//! One exclusive owner commits session charges AND catalog replay protection before disclosure.
//!
//! This uses the existing session journal, not a second canonical evidence history. Descriptors
//! and source custody remain externally rebuilt authority. Source bytes never enter this journal.

use std::fmt;
use std::path::Path;

use fss_core::{
    AgentSession, AgentSessionParams, CanonicalDecoder, CanonicalEncoder, ContentDigest,
    ContractBasis, HydrationError, HydrationRequest, HydrationResponse, PrincipalId, SessionId,
    TimestampNs,
};
use fss_ledger::IncompleteTailPolicy;
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;

use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    ReferenceSessionStore, SESSION_CHECKPOINT_RECORD_KIND, SessionAppendRecovery, read_report,
};
use crate::agent_session::context_hydration::{
    BoundContextHydration, ContextHydrationError, ContextSlotRead,
};
use crate::agent_session::hydration::SessionSourceHydrationError;
use crate::agent_session::{
    ReferenceSessionError, SessionAlias, SessionBindingRequest, SessionRefresh,
};
use crate::hydration::cursor_checkpoint::{CursorCheckpoint, MAX_RECORDS};
use crate::{BoundReferenceSituationPublication, PublishedSourceReader, ReferenceHydrationCatalog};

// Workspace operations share this exclusive session owner, never a second handle.
mod workspace;

const DOMAIN: &str = "fss.reference_session_disclosure.v1";
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Refusal is distinct from uncertain persistence. Display never emits private record identities.
#[derive(Debug)]
pub enum DisclosureError {
    /// Persistence refused or the shared owner is fenced; reconcile before retrying.
    Durability(DurableSessionError),
    /// Session or cached-hydration admission refused.
    Session(ReferenceSessionError),
    /// Session-projected source admission or live custody refused.
    Source(SessionSourceHydrationError),
    /// Exact context-publication admission or live custody refused.
    Context(ContextHydrationError),
    /// The supplied catalog cannot be reconciled with the trusted replay-protection checkpoint.
    Cursors(HydrationError),
}
impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Durability(_) => "disclosure persistence requires inspection or reconciliation",
            Self::Session(_) => "disclosure session refused",
            Self::Source(_) => "disclosure source refused",
            Self::Context(_) => "disclosure context refused",
            Self::Cursors(_) => "disclosure replay protection refused",
        })
    }
}
impl std::error::Error for DisclosureError {}
impl From<DurableSessionError> for DisclosureError {
    fn from(e: DurableSessionError) -> Self {
        Self::Durability(e)
    }
}
impl From<HydrationError> for DisclosureError {
    fn from(e: HydrationError) -> Self {
        Self::Cursors(e)
    }
}

/// Historical admission metadata, not confirmation that a remote recipient received bytes.
///
/// The root must be independently trusted. This receipt cannot authorize another disclosure or
/// replace a fresh custody check; an uncertain transport acknowledgement never refunds its charge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureAdmission {
    principal: PrincipalId,
    session: SessionId,
    request: ContentDigest,
    response: ContentDigest,
    context: Option<ContentDigest>,
    tokens: u64,
    observed_at: TimestampNs,
    consumed: Option<ContentDigest>,
    issued: Option<ContentDigest>,
}
impl DisclosureAdmission {
    /// Exact request whose result was admitted.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// Exact ordinary hydration receipt, without retaining its payload.
    #[must_use]
    pub const fn response_digest(&self) -> ContentDigest {
        self.response
    }
    /// Quoted tokens committed for this invocation; retries can have separate admissions.
    #[must_use]
    pub const fn charged_tokens(&self) -> u64 {
        self.tokens
    }
    /// Trusted service time at the admission boundary.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Single-use cursor consumed by this invocation, when evidence was delivered.
    #[must_use]
    pub const fn consumed_cursor(&self) -> Option<ContentDigest> {
        self.consumed
    }
}

/// Response released only after its session charge and cursor snapshot are synchronized together.
#[derive(Debug)]
pub struct JournaledDisclosure<T> {
    /// Independently verifiable ordinary protocol result; no new payload dialect is introduced.
    pub response: T,
    /// Historical admission metadata, not transport acknowledgement.
    pub admission: DisclosureAdmission,
    /// Exact journal root after the atomic admission record.
    pub committed_root: ContentDigest,
}

/// Exclusive session/catalog owner for crash-recoverable evidence disclosure.
///
/// Do not alternate this owner with legacy `DurableSessionStore` hydration on the same journal.
/// The catalog cannot be mutably borrowed: all cursor mutations pass the atomic boundary below.
/// Runtime authentication, exclusive path ownership, current descriptor reconstruction, and an
/// independently pinned journal root remain required. This synchronous reference wrapper does
/// not create an authentication service, production storage engine, or distributed transaction.
#[derive(Debug)]
pub struct DurableDisclosureStore {
    sessions: DurableSessionStore,
    catalog: ReferenceHydrationCatalog,
}

impl DurableDisclosureStore {
    /// Creates a new exclusive journal. An existing file or unjournaled cursors are never adopted.
    pub fn create(
        path: impl AsRef<Path>,
        limits: DurableSessionLimits,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<Self, DisclosureError> {
        if catalog.issued_cursor_count() != 0 {
            return Err(HydrationError::WrongContinuation.into());
        }
        Ok(Self {
            sessions: DurableSessionStore::create(path, limits)?,
            catalog,
        })
    }

    /// Reopens a complete exact journal and restores cursor metadata into rebuilt current custody.
    /// The checkpoint does not supply descriptors, artifacts, grants, or source bytes to the catalog.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<Self, DisclosureError> {
        let mut owner = Self {
            sessions: DurableSessionStore::open_existing(path, expected_root, limits)?,
            catalog,
        };
        owner.synchronize_catalog(None)?;
        Ok(owner)
    }

    /// Explicitly recovers a torn final append using the existing root-pinned recovery protocol.
    pub fn recover_existing(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        policy: IncompleteTailPolicy,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<(Self, super::coordination::SessionRecoveryReceipt), DisclosureError> {
        let (sessions, receipt) =
            DurableSessionStore::recover_existing(path, expected_root, limits, policy)?;
        let mut owner = Self { sessions, catalog };
        owner.synchronize_catalog(None)?;
        Ok((owner, receipt))
    }

    /// Latest confirmed root; a fenced owner may have a later, indeterminate disk tip.
    #[must_use]
    pub fn committed_root(&self) -> ContentDigest {
        self.sessions.committed_root()
    }
    /// True when all disclosure is withheld pending journal recovery.
    #[must_use]
    pub fn needs_reconciliation(&self) -> bool {
        self.sessions.needs_reconciliation()
    }
    /// Read-only access to exact descriptors and trusted source bindings, never mutation authority.
    #[must_use]
    pub fn catalog(&self) -> &ReferenceHydrationCatalog {
        &self.catalog
    }

    /// Opens a projected session under the existing durable session contract.
    pub fn open_session(
        &mut self,
        params: AgentSessionParams,
        basis: ContractBasis,
        now: TimestampNs,
    ) -> Result<AgentSession, DisclosureError> {
        Ok(self.sessions.open(params, basis, now)?)
    }
    /// Reads the session and persists its service clock/expiry mutations.
    pub fn session(
        &mut self,
        principal: &PrincipalId,
        id: &SessionId,
        now: TimestampNs,
    ) -> Result<AgentSession, DisclosureError> {
        Ok(self.sessions.session(principal, id, now)?)
    }
    /// Binds an exact authorized descriptor, without changing any hydration cursor.
    pub fn bind(
        &mut self,
        principal: &PrincipalId,
        request: &SessionBindingRequest,
        now: TimestampNs,
    ) -> Result<SessionAlias, DisclosureError> {
        Ok(self.sessions.bind(principal, request, &self.catalog, now)?)
    }
    /// Narrows authority or rebases through the existing session CAS checks.
    pub fn refresh(
        &mut self,
        principal: &PrincipalId,
        id: &SessionId,
        change: SessionRefresh,
        now: TimestampNs,
    ) -> Result<AgentSession, DisclosureError> {
        Ok(self.sessions.refresh(principal, id, change, now)?)
    }
    /// Closes a session without erasing its charges or consumed cursor tombstones.
    pub fn close(
        &mut self,
        principal: &PrincipalId,
        id: &SessionId,
        now: TimestampNs,
    ) -> Result<(), DisclosureError> {
        Ok(self.sessions.close(principal, id, now)?)
    }
    /// Returns the remaining cumulative grant, never replenishing it during recovery.
    pub fn remaining_token_budget(
        &mut self,
        principal: &PrincipalId,
        id: &SessionId,
        now: TimestampNs,
    ) -> Result<u64, DisclosureError> {
        Ok(self.sessions.remaining_token_budget(principal, id, now)?)
    }

    /// Publishes an authority-projected descriptor revision using existing no-rollback rules.
    /// Descriptor custody is external; reconstruct its current revisions before reopening.
    pub fn register_descriptor(
        &mut self,
        descriptor: fss_core::SemanticHandle,
    ) -> Result<(), DisclosureError> {
        self.sessions.preflight()?;
        Ok(self.catalog.register_descriptor(descriptor)?)
    }
    /// Registers an authority-projected preview. Source-bound H3 cannot be replaced by a cache.
    pub fn register_artifact(
        &mut self,
        handle: &str,
        descriptor: ContentDigest,
        artifact: fss_core::HydrationArtifact,
    ) -> Result<(), DisclosureError> {
        self.sessions.preflight()?;
        Ok(self
            .catalog
            .register_artifact(handle, descriptor, artifact)?)
    }

    /// Binds exact source custody under an already registered current descriptor.
    /// The returned binding is metadata, not permission for an agent to read the source.
    pub fn bind_source_object(
        &mut self,
        handle: &str,
        descriptor: ContentDigest,
        publication_root: ContentDigest,
        reader: &dyn PublishedSourceReader,
    ) -> Result<crate::SourceObjectBinding, DisclosureError> {
        self.sessions.preflight()?;
        self.catalog
            .bind_source_object(handle, descriptor, publication_root, reader)
            .map_err(|e| DisclosureError::Source(SessionSourceHydrationError::Source(e)))
    }

    /// Delivers cached evidence with atomic charge/issuance/consumption publication.
    pub fn hydrate(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<HydrationResponse>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let response = sessions
                .hydrate(principal, alias, request, catalog, now)
                .map_err(DisclosureError::Session)?;
            let admission = admission(principal, request, &response, None);
            Ok((response, admission))
        })
    }

    /// Reads live source through explicit custody, withholding bytes until the joint commit.
    pub fn hydrate_from_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<HydrationResponse>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let response = sessions
                .hydrate_from_source(principal, alias, request, catalog, reader, now)
                .map_err(DisclosureError::Source)?;
            let admission = admission(principal, request, &response, None);
            Ok((response, admission))
        })
    }

    /// Reads through an existing local publisher without opening another custody owner.
    #[allow(clippy::too_many_arguments)] // explicit independent custody and session authorities
    pub fn hydrate_from_local_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<HydrationResponse>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let response = sessions
                .hydrate_from_local_source(principal, alias, request, catalog, publisher, io, now)
                .map_err(DisclosureError::Source)?;
            let admission = admission(principal, request, &response, None);
            Ok((response, admission))
        })
    }

    /// Expands cached context through the same atomic persistence boundary as original source.
    pub fn hydrate_context_slot(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<BoundContextHydration>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let result = sessions
                .hydrate_context_slot(principal, publication, read, catalog, now)
                .map_err(DisclosureError::Context)?;
            let admission = admission(
                principal,
                &result.request,
                &result.response,
                Some(result.delivery_digest),
            );
            Ok((result, admission))
        })
    }

    /// Expands an exact context slot using live session grants and live source custody.
    pub fn hydrate_context_slot_from_source(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<BoundContextHydration>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let result = sessions
                .hydrate_context_slot_from_source(
                    principal,
                    publication,
                    read,
                    catalog,
                    reader,
                    now,
                )
                .map_err(DisclosureError::Context)?;
            let admission = admission(
                principal,
                &result.request,
                &result.response,
                Some(result.delivery_digest),
            );
            Ok((result, admission))
        })
    }

    /// Uses the existing lock-owning local publisher and its explicit I/O capability.
    #[allow(clippy::too_many_arguments)] // separate custody, session and publication authorities
    pub fn hydrate_context_slot_from_local_source(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
        now: TimestampNs,
    ) -> Result<JournaledDisclosure<BoundContextHydration>, DisclosureError> {
        self.deliver(now, |sessions, catalog| {
            let result = sessions
                .hydrate_context_slot_from_local_source(
                    principal,
                    publication,
                    read,
                    catalog,
                    publisher,
                    io,
                    now,
                )
                .map_err(DisclosureError::Context)?;
            let admission = admission(
                principal,
                &result.request,
                &result.response,
                Some(result.delivery_digest),
            );
            Ok((result, admission))
        })
    }

    /// Resolves a pending append and installs only its durable cursor state, never its payload.
    pub fn reconcile_pending(
        &mut self,
        policy: IncompleteTailPolicy,
    ) -> Result<SessionAppendRecovery, DisclosureError> {
        let outcome = self.sessions.reconcile_pending(policy)?;
        if let Err(error) = self.synchronize_catalog(None) {
            self.sessions.fenced = true;
            return Err(error);
        }
        Ok(outcome)
    }

    /// Lists every committed invocation of an exact request for the live owning session.
    ///
    /// This reconciles lost acknowledgements without rereading source or returning stored bytes.
    /// Repeated non-continuation requests are separate admissions, not idempotent free deliveries.
    /// The caller must set a bounded output ceiling; overflow refuses rather than truncating.
    pub fn admissions(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        request: ContentDigest,
        max_results: usize,
        now: TimestampNs,
    ) -> Result<Vec<(ContentDigest, DisclosureAdmission)>, DisclosureError> {
        if max_results > self.sessions.limits.max_records {
            return Err(DurableSessionError::CapacityExceeded.into());
        }
        self.sessions.session(principal, session, now)?;
        self.sessions.verify_storage()?;
        let report = read_report(self.sessions.path(), self.sessions.limits)?;
        if report.last_root() != self.sessions.committed_root()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let mut results = Vec::new();
        for record in report.records() {
            if record.kind() == SESSION_CHECKPOINT_RECORD_KIND && is_record(record.payload()) {
                let saved = decode(record.payload(), self.sessions.limits)?;
                if saved.admission.principal == *principal
                    && saved.admission.session == *session
                    && saved.admission.request == request
                {
                    if results.len() >= max_results {
                        return Err(DurableSessionError::CapacityExceeded.into());
                    }
                    results.push((record.root(), saved.admission));
                }
            }
        }
        Ok(results)
    }

    fn synchronize_catalog(&mut self, now: Option<TimestampNs>) -> Result<(), DisclosureError> {
        self.sessions.verify_storage()?;
        let report = read_report(self.sessions.path(), self.sessions.limits)?;
        // Read-only verification is not adoption: this owner already holds the independently
        // trusted tip. A second read must agree before it can supply replay-protection metadata.
        if report.last_root() != self.sessions.committed_root()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let latest = report.records().iter().rev().find(|record| {
            record.kind() == SESSION_CHECKPOINT_RECORD_KIND && is_record(record.payload())
        });
        if let Some(record) = latest {
            let saved = decode(record.payload(), self.sessions.limits)?;
            if now.is_some_and(|now| now < saved.admission.observed_at) {
                return Err(DisclosureError::Session(
                    ReferenceSessionError::ClockRegression,
                ));
            }
            self.catalog.restore_cursor_checkpoint(
                saved.cursors,
                MAX_RECORD_BYTES,
                saved.admission.observed_at,
            )?;
        } else if self.catalog.issued_cursor_count() != 0 {
            return Err(HydrationError::WrongContinuation.into());
        }
        Ok(())
    }

    fn deliver<T>(
        &mut self,
        now: TimestampNs,
        operation: impl FnOnce(
            &mut ReferenceSessionStore,
            &mut ReferenceHydrationCatalog,
        ) -> Result<(T, DisclosureAdmission), DisclosureError>,
    ) -> Result<JournaledDisclosure<T>, DisclosureError> {
        self.sessions.preflight()?;
        self.synchronize_catalog(Some(now))?;
        let mut memory = self.sessions.memory.clone();
        let mut catalog = self.catalog.clone();
        let result = operation(&mut memory, &mut catalog);
        let checkpoint = match memory.checkpoint(self.sessions.limits.max_checkpoint_bytes) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.sessions.fenced = true;
                return Err(DurableSessionError::from(error).into());
            }
        };
        match result {
            Err(error) => {
                // Preserve clock and expiry mutations, but never publish staged cursor state.
                if checkpoint.digest() != self.sessions.checkpoint_digest {
                    self.sessions.commit_candidate(PendingSession {
                        memory,
                        checkpoint,
                        coordination: None,
                        record: None,
                    })?;
                }
                Err(error)
            }
            Ok((response, admission)) => {
                let prepared = (|| -> Result<Vec<u8>, DisclosureError> {
                    let cursors = catalog.checkpoint_cursors(now, MAX_RECORD_BYTES)?;
                    let payload = encode(
                        self.sessions.checkpoint_digest,
                        checkpoint.as_bytes(),
                        &cursors,
                        &admission,
                    )?;
                    // Validate the same semantic reconstruction that cold recovery will use.
                    let mut cursor_history = None;
                    let report = read_report(self.sessions.path(), self.sessions.limits)?;
                    if report.last_root() != self.sessions.committed_root()
                        || report.incomplete_tail().is_some()
                    {
                        return Err(DurableSessionError::RootMismatch.into());
                    }
                    for record in report.records() {
                        if record.kind() == SESSION_CHECKPOINT_RECORD_KIND
                            && is_record(record.payload())
                        {
                            let saved = decode(record.payload(), self.sessions.limits)?;
                            cursor_history = Some(CursorCheckpoint::decode(
                                saved.cursors,
                                MAX_RECORD_BYTES,
                                MAX_RECORDS,
                            )?);
                        }
                    }
                    restore_record(
                        &payload,
                        ContentDigest::sha256(&payload),
                        Some(&self.sessions.memory),
                        &mut cursor_history,
                        self.sessions.limits,
                    )?;
                    Ok(payload)
                })();
                let payload = match prepared {
                    Ok(payload) => payload,
                    Err(error) => {
                        self.sessions.fenced = true;
                        return Err(error);
                    }
                };
                // Even a zero-token, same-clock disclosure gets a record: it can issue a cursor.
                self.sessions.commit_candidate(PendingSession {
                    memory,
                    checkpoint,
                    coordination: None,
                    record: Some((SESSION_CHECKPOINT_RECORD_KIND, payload)),
                })?;
                self.catalog = catalog;
                Ok(JournaledDisclosure {
                    response,
                    admission,
                    committed_root: self.sessions.committed_root(),
                })
            }
        }
    }
}

fn admission(
    principal: &PrincipalId,
    request: &HydrationRequest,
    response: &HydrationResponse,
    context: Option<ContentDigest>,
) -> DisclosureAdmission {
    DisclosureAdmission {
        principal: principal.clone(),
        session: request.session_id.clone(),
        request: request.request_digest,
        response: response.receipt.receipt_digest,
        context,
        tokens: response.receipt.cost.tokens,
        observed_at: response.receipt.issued_at,
        consumed: request
            .continuation
            .as_ref()
            .filter(|_| response.artifact.is_some())
            .map(|c| c.cursor_digest),
        issued: response
            .receipt
            .continuation
            .as_ref()
            .map(|c| c.cursor_digest),
    }
}

struct SavedDisclosure<'a> {
    before: ContentDigest,
    session_checkpoint: &'a [u8],
    cursors: &'a [u8],
    admission: DisclosureAdmission,
}

fn is_record(payload: &[u8]) -> bool {
    let mut prefix = CanonicalEncoder::new();
    prefix.text(DOMAIN);
    payload.starts_with(&prefix.finish())
}
fn digest_option(e: &mut CanonicalEncoder, digest: Option<ContentDigest>) {
    e.bool(digest.is_some());
    if let Some(digest) = digest {
        e.digest(digest);
    }
}
fn read_digest_option(
    d: &mut CanonicalDecoder<'_>,
) -> Result<Option<ContentDigest>, DurableSessionError> {
    Ok(if d.bool()? { Some(d.digest()?) } else { None })
}
fn encode(
    before: ContentDigest,
    checkpoint: &[u8],
    cursors: &[u8],
    a: &DisclosureAdmission,
) -> Result<Vec<u8>, DurableSessionError> {
    if checkpoint
        .len()
        .checked_add(cursors.len())
        .is_none_or(|n| n > MAX_RECORD_BYTES - 16_384)
    {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.digest(before);
    e.bytes(checkpoint);
    e.bytes(cursors);
    e.text(a.principal.as_str());
    e.text(a.session.as_str());
    e.digest(a.request);
    e.digest(a.response);
    digest_option(&mut e, a.context);
    e.u64(a.tokens);
    e.i128(a.observed_at.0);
    digest_option(&mut e, a.consumed);
    digest_option(&mut e, a.issued);
    Ok(e.finish_checked()?)
}
fn decode(
    payload: &[u8],
    limits: DurableSessionLimits,
) -> Result<SavedDisclosure<'_>, DurableSessionError> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(payload);
    if d.text()? != DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let before = d.digest()?;
    let session_checkpoint = d.bytes()?;
    if session_checkpoint.len() > limits.max_checkpoint_bytes {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let cursors = d.bytes()?;
    let principal = PrincipalId::parse(d.text()?)?;
    let session = SessionId::parse(d.text()?)?;
    let request = d.digest()?;
    let response = d.digest()?;
    let context = read_digest_option(&mut d)?;
    let tokens = d.u64()?;
    let observed_at = TimestampNs(d.i128()?);
    let consumed = read_digest_option(&mut d)?;
    let issued = read_digest_option(&mut d)?;
    d.ensure_finished()?;
    Ok(SavedDisclosure {
        before,
        session_checkpoint,
        cursors,
        admission: DisclosureAdmission {
            principal,
            session,
            request,
            response,
            context,
            tokens,
            observed_at,
            consumed,
            issued,
        },
    })
}

/// Extends the existing checkpoint record kind with a fail-closed versioned disclosure envelope.
/// Legacy snapshots are still decoded by their unchanged owner, and old readers refuse envelopes.
pub(super) fn restore_record(
    payload: &[u8],
    payload_digest: ContentDigest,
    previous: Option<&ReferenceSessionStore>,
    cursor_history: &mut Option<CursorCheckpoint>,
    limits: DurableSessionLimits,
) -> Result<ReferenceSessionStore, DurableSessionError> {
    if !is_record(payload) {
        return Ok(ReferenceSessionStore::restore_checkpoint(
            payload,
            payload_digest,
            limits.sessions,
            limits.max_checkpoint_bytes,
        )?);
    }
    if ContentDigest::sha256(payload) != payload_digest {
        return Err(DurableSessionError::RootMismatch);
    }
    let saved = decode(payload, limits)?;
    let prior = previous.ok_or(DurableSessionError::InvalidHistory)?;
    if saved.before != prior.checkpoint(limits.max_checkpoint_bytes)?.digest() {
        return Err(DurableSessionError::InvalidHistory);
    }
    let cursors = CursorCheckpoint::decode(saved.cursors, MAX_RECORD_BYTES, MAX_RECORDS)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    if cursors.captured_at != saved.admission.observed_at {
        return Err(DurableSessionError::InvalidHistory);
    }
    if let Some(old) = cursor_history.as_ref() {
        cursors
            .validate_successor(old)
            .map_err(|_| DurableSessionError::InvalidHistory)?;
    }
    let mut expected = prior.clone();
    let a = &saved.admission;
    let entry = expected
        .live_entry(&a.principal, &a.session, a.observed_at)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    entry.spent_tokens = entry
        .spent_tokens
        .checked_add(a.tokens)
        .filter(|spent| *spent <= entry.session.token_budget)
        .ok_or(DurableSessionError::InvalidHistory)?;
    let restored = ReferenceSessionStore::restore_checkpoint(
        saved.session_checkpoint,
        ContentDigest::sha256(saved.session_checkpoint),
        limits.sessions,
        limits.max_checkpoint_bytes,
    )?;
    if restored.checkpoint(limits.max_checkpoint_bytes)?.digest()
        != expected.checkpoint(limits.max_checkpoint_bytes)?.digest()
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    cursors
        .validate_disclosure(cursor_history.as_ref(), &a.session, a.consumed, a.issued)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    *cursor_history = Some(cursors);
    Ok(restored)
}

#[cfg(test)]
mod tests;
