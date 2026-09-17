//! Executable session lifecycle and session-local semantic symbols.
//!
//! The runtime must authenticate the principal and project grants before opening a session.
//! This store does not authenticate transport credentials or mint effect authority. Symbols are
//! compression only: they resolve to an exact published descriptor, never to an implicit latest
//! revision. All clock inputs must come from the runtime, not from an agent request.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    AgentSession, AgentSessionParams, ContentDigest, ContractBasis, ContractError,
    HandleAvailability, HydrationError, HydrationLevel, LedgerAnchor, PrincipalId, SemanticHandle,
    SessionId, TimestampNs,
};

use crate::ReferenceHydrationCatalog;

/// Storage ceilings, including closed-session tombstones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceSessionLimits {
    /// Maximum retained session identities. Identities are never recycled.
    pub max_sessions: usize,
    /// Maximum symbols in each current generation.
    pub max_symbols_per_session: usize,
    /// Maximum capabilities plus privacy grants in a session.
    pub max_grants_per_session: usize,
    /// Maximum aggregate UTF-8 bytes in those grants.
    pub max_grant_bytes_per_session: usize,
}

impl Default for ReferenceSessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 1_024,
            max_symbols_per_session: 256,
            max_grants_per_session: 256,
            max_grant_bytes_per_session: 16_384,
        }
    }
}

/// A short symbol is meaningful only together with its session and generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAlias {
    /// Owning session, not an authority grant.
    pub session_id: SessionId,
    /// Exact symbol-table generation.
    pub generation: u64,
    /// Monotone slot within the generation; zero is never issued.
    pub slot: u64,
}

/// Exact raw identity to retain in an audit record rather than archiving an alias alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSessionHandle {
    /// Immutable semantic subject handle.
    pub handle_id: String,
    /// Exact descriptor revision, including its delivery policy.
    pub descriptor_digest: ContentDigest,
    /// Exact immutable subject bytes.
    pub subject_digest: ContentDigest,
}

/// Explicit binding request. A stale digest never silently follows a new descriptor.
#[derive(Clone, Debug)]
pub struct SessionBindingRequest {
    /// Session whose symbol table is modified.
    pub session_id: SessionId,
    /// Optimistic generation precondition.
    pub generation: u64,
    /// Raw published semantic handle, not another alias.
    pub handle_id: String,
    /// Exact published descriptor revision.
    pub descriptor_digest: ContentDigest,
}

/// Authority-projected resume input. Resume can narrow grants but cannot extend the lease.
#[derive(Clone, Debug)]
pub struct SessionRefresh {
    /// Exact session state read by the caller, preventing lost updates.
    pub expected_session_digest: ContentDigest,
    /// Current anchor verified by the calling authority.
    pub current_anchor: LedgerAnchor,
    /// A subset of the existing capability grants.
    pub capabilities: BTreeSet<String>,
    /// A subset of the existing privacy grants.
    pub privacy_scope: BTreeSet<String>,
}

/// Fail-closed session admission results. Refusals never carry private handle identities.
#[derive(Debug)]
pub enum ReferenceSessionError {
    /// Unknown, wrong-principal, closed, or expired session (deliberately indistinguishable).
    Unavailable,
    /// The runtime clock moved backwards for this session.
    ClockRegression,
    /// The symbol table was explicitly invalidated.
    StaleGeneration,
    /// Unknown symbol, superseded descriptor, or otherwise stale exact reference.
    StaleAlias,
    /// Authority lineage, anchor, contract basis, or optimistic state no longer matches.
    StaleBasis,
    /// Requested authority exceeds the stored session projection.
    GrantEscalation,
    /// Subject is no longer available for delivery.
    HandleUnavailable,
    /// A bounded store ceiling would be exceeded.
    CapacityExceeded,
    /// A monotone counter cannot advance without wrapping.
    GenerationExhausted,
    /// Core session contract validation failed.
    Contract(ContractError),
    /// Exact hydration admission failed.
    Hydration(HydrationError),
}

impl fmt::Display for ReferenceSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "session unavailable",
            Self::ClockRegression => "session clock regressed",
            Self::StaleGeneration => "symbol generation is stale; refresh the session",
            Self::StaleAlias => "symbol is stale; explicitly bind an authorized raw handle",
            Self::StaleBasis => "session authority basis is stale",
            Self::GrantEscalation => "session grants do not authorize the request",
            Self::HandleUnavailable => "session handle unavailable",
            Self::CapacityExceeded => "session storage capacity exceeded",
            Self::GenerationExhausted => "session generation exhausted",
            Self::Contract(_) => "invalid session contract",
            Self::Hydration(_) => "session hydration refused",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReferenceSessionError {}

impl From<ContractError> for ReferenceSessionError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<HydrationError> for ReferenceSessionError {
    fn from(error: HydrationError) -> Self {
        Self::Hydration(error)
    }
}

#[derive(Clone, Debug)]
struct SessionEntry {
    session: AgentSession,
    opening_digest: ContentDigest,
    basis: ContractBasis,
    symbols: BTreeMap<u64, ResolvedSessionHandle>,
    next_slot: u64,
    last_observed_at: TimestampNs,
    closed: bool,
}

/// Bounded in-process session authority reference, not a production durable/authentication store.
///
/// Closed and expired identities remain tombstoned, preventing old aliases from becoming valid
/// after ID reuse. Callers must retain resolved raw identities in their durable audit records.
#[derive(Clone, Debug)]
pub struct ReferenceSessionStore {
    sessions: BTreeMap<SessionId, SessionEntry>,
    limits: ReferenceSessionLimits,
}

impl Default for ReferenceSessionStore {
    fn default() -> Self {
        Self::with_limits(ReferenceSessionLimits::default())
    }
}

impl ReferenceSessionStore {
    /// Creates a store with explicit ceilings. Zero means no capacity, not unlimited capacity.
    #[must_use]
    pub fn with_limits(limits: ReferenceSessionLimits) -> Self {
        Self {
            sessions: BTreeMap::new(),
            limits,
        }
    }

    /// Opens an authority-projected session, or returns the current state of an exact open retry.
    ///
    /// A lost-acknowledgement retry never resets symbols, widens grants, extends expiry, or reopens
    /// a tombstone. Different parameters cannot overwrite an existing session identity.
    pub fn open(
        &mut self,
        params: AgentSessionParams,
        basis: ContractBasis,
        now: TimestampNs,
    ) -> Result<AgentSession, ReferenceSessionError> {
        let grant_count = params
            .capabilities
            .len()
            .checked_add(params.privacy_scope.len())
            .ok_or(ReferenceSessionError::CapacityExceeded)?;
        let grant_bytes = params
            .capabilities
            .iter()
            .chain(&params.privacy_scope)
            .try_fold(0_usize, |sum, value| sum.checked_add(value.len()))
            .ok_or(ReferenceSessionError::CapacityExceeded)?;
        if grant_count > self.limits.max_grants_per_session
            || grant_bytes > self.limits.max_grant_bytes_per_session
        {
            return Err(ReferenceSessionError::CapacityExceeded);
        }
        if basis.semantic_protocol != "fss/1" {
            return Err(ReferenceSessionError::StaleBasis);
        }
        let session = AgentSession::new(params)?;
        let opening_digest = session.session_digest();
        if let Some(existing) = self.sessions.get(&session.session_id) {
            if existing.opening_digest != opening_digest || existing.basis != basis {
                return Err(ReferenceSessionError::Unavailable);
            }
            return Ok(self
                .live_entry(&session.principal_id, &session.session_id, now)?
                .session
                .clone());
        }
        if now.0 < session.created_at_ns || now.0 >= session.expires_at_ns {
            return Err(ReferenceSessionError::Unavailable);
        }
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(ReferenceSessionError::CapacityExceeded);
        }
        self.sessions.insert(
            session.session_id.clone(),
            SessionEntry {
                session: session.clone(),
                opening_digest,
                basis,
                symbols: BTreeMap::new(),
                next_slot: 0,
                last_observed_at: now,
                closed: false,
            },
        );
        Ok(session)
    }

    /// Reads current session state after principal, lease, and monotone-clock checks.
    pub fn session(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        now: TimestampNs,
    ) -> Result<AgentSession, ReferenceSessionError> {
        Ok(self.live_entry(principal, session_id, now)?.session.clone())
    }

    /// Binds an exact current descriptor. Exact retries reuse a slot without consuming capacity.
    pub fn bind(
        &mut self,
        principal: &PrincipalId,
        request: &SessionBindingRequest,
        catalog: &ReferenceHydrationCatalog,
        now: TimestampNs,
    ) -> Result<SessionAlias, ReferenceSessionError> {
        let capacity = self.limits.max_symbols_per_session;
        let entry = self.live_entry(principal, &request.session_id, now)?;
        Self::check_generation(entry, request.generation)?;
        let descriptor = catalog
            .current_descriptor(&request.handle_id)
            .filter(|descriptor| descriptor.descriptor_digest == request.descriptor_digest)
            .ok_or(ReferenceSessionError::StaleAlias)?;
        Self::check_descriptor(entry, descriptor, now)?;
        let binding = ResolvedSessionHandle {
            handle_id: descriptor.handle_id.clone(),
            descriptor_digest: descriptor.descriptor_digest,
            subject_digest: descriptor.subject_digest,
        };
        if let Some((&slot, _)) = entry.symbols.iter().find(|(_, value)| **value == binding) {
            return Ok(SessionAlias {
                session_id: request.session_id.clone(),
                generation: request.generation,
                slot,
            });
        }
        if entry.symbols.len() >= capacity {
            return Err(ReferenceSessionError::CapacityExceeded);
        }
        let slot = entry
            .next_slot
            .checked_add(1)
            .ok_or(ReferenceSessionError::GenerationExhausted)?;
        entry.symbols.insert(slot, binding);
        entry.next_slot = slot;
        Ok(SessionAlias {
            session_id: request.session_id.clone(),
            generation: request.generation,
            slot,
        })
    }

    /// Resolves a symbol only after rechecking the current descriptor and session grants.
    ///
    /// A new descriptor invalidates the old symbol even when the immutable subject is unchanged.
    /// No failure returns a raw target or automatically binds a replacement.
    pub fn resolve(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        catalog: &ReferenceHydrationCatalog,
        now: TimestampNs,
    ) -> Result<ResolvedSessionHandle, ReferenceSessionError> {
        let entry = self.live_entry(principal, &alias.session_id, now)?;
        Self::check_generation(entry, alias.generation)?;
        let binding = entry
            .symbols
            .get(&alias.slot)
            .ok_or(ReferenceSessionError::StaleAlias)?;
        let descriptor = catalog
            .current_descriptor(&binding.handle_id)
            .filter(|descriptor| {
                descriptor.descriptor_digest == binding.descriptor_digest
                    && descriptor.subject_digest == binding.subject_digest
            })
            .ok_or(ReferenceSessionError::StaleAlias)?;
        Self::check_descriptor(entry, descriptor, now)?;
        Ok(binding.clone())
    }

    /// Explicitly invalidates all symbols without renewing the session lease or authority.
    pub fn rotate_symbols(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        expected_generation: u64,
        now: TimestampNs,
    ) -> Result<AgentSession, ReferenceSessionError> {
        let entry = self.live_entry(principal, session_id, now)?;
        Self::check_generation(entry, expected_generation)?;
        Self::invalidate_symbols(entry)?;
        Ok(entry.session.clone())
    }

    /// Resumes on an authority-verified anchor with equal or narrower grants.
    ///
    /// Changed authority always invalidates symbols and acknowledged situation state. Equal
    /// inputs are a no-op. Expired sessions, rollback, equal-sequence forks, cross-epoch movement,
    /// and authority escalation are refused; they require an explicitly new session instead.
    pub fn refresh(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        refresh: SessionRefresh,
        now: TimestampNs,
    ) -> Result<AgentSession, ReferenceSessionError> {
        let entry = self.live_entry(principal, session_id, now)?;
        if entry.session.session_digest() != refresh.expected_session_digest {
            return Err(ReferenceSessionError::StaleBasis);
        }
        if !refresh.capabilities.is_subset(&entry.session.capabilities)
            || !refresh.privacy_scope.is_subset(&entry.session.privacy_scope)
        {
            return Err(ReferenceSessionError::GrantEscalation);
        }
        let old = &entry.session.current_anchor;
        let new = &refresh.current_anchor;
        if old != new
            && (old.site_lineage != new.site_lineage
                || old.ledger_epoch != new.ledger_epoch
                || new.commit_sequence <= old.commit_sequence
                || new.adapter_registry_epoch < old.adapter_registry_epoch)
        {
            return Err(ReferenceSessionError::StaleBasis);
        }
        if old == new
            && entry.session.capabilities == refresh.capabilities
            && entry.session.privacy_scope == refresh.privacy_scope
        {
            return Ok(entry.session.clone());
        }
        Self::invalidate_symbols(entry)?;
        entry.session.current_anchor = refresh.current_anchor;
        entry.session.capabilities = refresh.capabilities;
        entry.session.privacy_scope = refresh.privacy_scope;
        Ok(entry.session.clone())
    }

    /// Closes a session without granting, retrying, or cancelling any external effect.
    ///
    /// Repeated closes by the same authenticated principal are harmless. The tombstone is kept.
    pub fn close(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        now: TimestampNs,
    ) -> Result<(), ReferenceSessionError> {
        let entry = self
            .sessions
            .get_mut(session_id)
            .filter(|entry| &entry.session.principal_id == principal)
            .ok_or(ReferenceSessionError::Unavailable)?;
        if now < entry.last_observed_at {
            return Err(ReferenceSessionError::ClockRegression);
        }
        entry.last_observed_at = now;
        entry.closed = true;
        entry.symbols.clear();
        Ok(())
    }

    fn live_entry(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        now: TimestampNs,
    ) -> Result<&mut SessionEntry, ReferenceSessionError> {
        let entry = self
            .sessions
            .get_mut(session_id)
            .filter(|entry| &entry.session.principal_id == principal && !entry.closed)
            .ok_or(ReferenceSessionError::Unavailable)?;
        if now < entry.last_observed_at {
            return Err(ReferenceSessionError::ClockRegression);
        }
        entry.last_observed_at = now;
        if now.0 >= entry.session.expires_at_ns {
            entry.closed = true;
            entry.symbols.clear();
            return Err(ReferenceSessionError::Unavailable);
        }
        Ok(entry)
    }

    fn check_generation(entry: &SessionEntry, generation: u64) -> Result<(), ReferenceSessionError> {
        if entry.session.symbol_table_generation != generation {
            return Err(ReferenceSessionError::StaleGeneration);
        }
        Ok(())
    }

    fn invalidate_symbols(entry: &mut SessionEntry) -> Result<(), ReferenceSessionError> {
        let generation = entry
            .session
            .symbol_table_generation
            .checked_add(1)
            .ok_or(ReferenceSessionError::GenerationExhausted)?;
        entry.session.symbol_table_generation = generation;
        entry.session.last_acknowledged_situation_fingerprint = None;
        entry.symbols.clear();
        entry.next_slot = 0;
        Ok(())
    }

    fn check_descriptor(
        entry: &SessionEntry,
        descriptor: &SemanticHandle,
        now: TimestampNs,
    ) -> Result<(), ReferenceSessionError> {
        descriptor.verify()?;
        if descriptor.contract_basis != entry.basis
            || descriptor.anchor != entry.session.current_anchor
            || descriptor.published_at > now
        {
            return Err(ReferenceSessionError::StaleBasis);
        }
        let required = descriptor
            .required_capabilities
            .get(&HydrationLevel::H0)
            .ok_or(ReferenceSessionError::GrantEscalation)?;
        if !required.is_subset(&entry.session.capabilities)
            || !entry.session.privacy_scope.contains(&descriptor.privacy_class)
        {
            return Err(ReferenceSessionError::GrantEscalation);
        }
        if descriptor.availability_at(now) != HandleAvailability::Available {
            return Err(ReferenceSessionError::HandleUnavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use fss_core::{BudgetVector, ContractBasisRegistryBytes, LaboratoryAccess, MissionId, SemanticHandleSpec};

    type TestResult = Result<(), Box<dyn Error>>;

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
                "fss-reference:session-test",
            ).with_accepted_nightly("nightly-2026-08-31"),
        )
    }

    fn params() -> Result<AgentSessionParams, ContractError> {
        Ok(AgentSessionParams {
            session_id: SessionId::parse("session:test")?,
            mission_id: MissionId::parse("mission:test")?,
            principal_id: PrincipalId::parse("principal:owner")?,
            capabilities: BTreeSet::from(["capability:hydrate:H0".to_owned()]),
            privacy_scope: BTreeSet::from(["private:property".to_owned()]),
            current_anchor: LedgerAnchor::genesis("site:session-test"),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 100,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 1_000,
        })
    }

    fn descriptor(subject: &str) -> Result<SemanticHandle, Box<dyn Error>> {
        let cost = BudgetVector::builder().tokens(1).build()?;
        SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis(),
            anchor: LedgerAnchor::genesis("site:session-test"),
            subject_id: subject.to_owned(),
            subject_digest: ContentDigest::sha256(subject.as_bytes()),
            semantic_type: "evidence_bundle".to_owned(),
            source_id: "sensor:owner-camera".to_owned(),
            capture_interval: None,
            spatial_scope: None,
            privacy_class: "private:property".to_owned(),
            applied_transform: None,
            availability: HandleAvailability::Available,
            retention_until: TimestampNs(900),
            levels: HydrationLevel::ALL.into_iter().collect(),
            required_capabilities: HydrationLevel::ALL.into_iter().map(|level| {
                (level, BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]))
            }).collect(),
            estimated_costs: HydrationLevel::ALL.into_iter().map(|level| (level, cost)).collect(),
            laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
            debug_capability: Some("capability:hydrate:debug".to_owned()),
            derivative_handles: BTreeSet::new(),
            published_at: TimestampNs(1),
        }).map_err(Into::into)
    }

    fn bind(
        store: &mut ReferenceSessionStore,
        session: &AgentSession,
        descriptor: &SemanticHandle,
        catalog: &ReferenceHydrationCatalog,
    ) -> Result<SessionAlias, ReferenceSessionError> {
        store.bind(&session.principal_id, &SessionBindingRequest {
            session_id: session.session_id.clone(),
            generation: session.symbol_table_generation,
            handle_id: descriptor.handle_id.clone(),
            descriptor_digest: descriptor.descriptor_digest,
        }, catalog, TimestampNs(10))
    }

    #[test]
    fn open_retry_keeps_generation_and_original_expiry() -> TestResult {
        let mut store = ReferenceSessionStore::default();
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        let rotated = store.rotate_symbols(&session.principal_id, &session.session_id, 0, TimestampNs(20))?;
        let retry = store.open(params()?, basis(), TimestampNs(50))?;
        assert_eq!(retry, rotated);
        assert_eq!(retry.expires_at_ns, 1_000);
        assert_eq!(retry.symbol_table_generation, 1);
        Ok(())
    }

    #[test]
    fn close_and_expiry_never_reopen_even_after_clock_rollback() -> TestResult {
        let mut store = ReferenceSessionStore::default();
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(1_000)), Err(ReferenceSessionError::Unavailable)));
        assert!(matches!(store.open(params()?, basis(), TimestampNs(10)), Err(ReferenceSessionError::Unavailable)));
        store.close(&session.principal_id, &session.session_id, TimestampNs(1_001))?;
        store.close(&session.principal_id, &session.session_id, TimestampNs(1_002))?;
        assert!(matches!(store.open(params()?, basis(), TimestampNs(1_003)), Err(ReferenceSessionError::Unavailable)));
        Ok(())
    }

    #[test]
    fn wrong_principal_and_unknown_session_have_same_refusal() -> TestResult {
        let mut store = ReferenceSessionStore::default();
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        let other = PrincipalId::parse("principal:other")?;
        assert!(matches!(store.session(&other, &session.session_id, TimestampNs(10)), Err(ReferenceSessionError::Unavailable)));
        assert!(matches!(store.session(&other, &SessionId::parse("session:absent")?, TimestampNs(10)), Err(ReferenceSessionError::Unavailable)));
        assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(9)), Err(ReferenceSessionError::ClockRegression)));
        Ok(())
    }

    #[test]
    fn exact_binding_retry_and_generation_invalidation() -> TestResult {
        let mut store = ReferenceSessionStore::default();
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        let descriptor = descriptor("evidence:first")?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(descriptor.clone())?;
        let alias = bind(&mut store, &session, &descriptor, &catalog)?;
        assert_eq!(alias, bind(&mut store, &session, &descriptor, &catalog)?);
        let raw = store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10))?;
        assert_eq!(raw.handle_id, descriptor.handle_id);
        store.rotate_symbols(&session.principal_id, &session.session_id, 0, TimestampNs(10))?;
        assert!(matches!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10)), Err(ReferenceSessionError::StaleGeneration)));
        assert_eq!(raw.descriptor_digest, descriptor.descriptor_digest);
        Ok(())
    }

    #[test]
    fn symbol_capacity_does_not_evict_or_rebind_existing_symbols() -> TestResult {
        let mut store = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
            max_symbols_per_session: 1, ..ReferenceSessionLimits::default()
        });
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        let first = descriptor("evidence:first")?;
        let second = descriptor("evidence:second")?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(first.clone())?;
        catalog.register_descriptor(second.clone())?;
        let alias = bind(&mut store, &session, &first, &catalog)?;
        assert!(matches!(bind(&mut store, &session, &second, &catalog), Err(ReferenceSessionError::CapacityExceeded)));
        assert_eq!(alias, bind(&mut store, &session, &first, &catalog)?);
        assert_eq!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10))?.handle_id, first.handle_id);
        Ok(())
    }

    #[test]
    fn session_tombstones_and_grant_bytes_are_bounded() -> TestResult {
        let mut store = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
            max_sessions: 1, ..ReferenceSessionLimits::default()
        });
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        store.close(&session.principal_id, &session.session_id, TimestampNs(10))?;
        let mut another = params()?;
        another.session_id = SessionId::parse("session:another")?;
        assert!(matches!(store.open(another, basis(), TimestampNs(10)), Err(ReferenceSessionError::CapacityExceeded)));
        let mut no_bytes = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
            max_grant_bytes_per_session: 0, ..ReferenceSessionLimits::default()
        });
        assert!(matches!(no_bytes.open(params()?, basis(), TimestampNs(10)), Err(ReferenceSessionError::CapacityExceeded)));
        Ok(())
    }

    #[test]
    fn refresh_cannot_escalate_or_renew_and_invalidates_old_symbols() -> TestResult {
        let mut store = ReferenceSessionStore::default();
        let session = store.open(params()?, basis(), TimestampNs(10))?;
        let descriptor = descriptor("evidence:first")?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(descriptor.clone())?;
        let alias = bind(&mut store, &session, &descriptor, &catalog)?;
        let mut capabilities = session.capabilities.clone();
        capabilities.insert("capability:hydrate:H3".to_owned());
        let refresh = SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor.clone(),
            capabilities,
            privacy_scope: session.privacy_scope.clone(),
        };
        assert!(matches!(store.refresh(&session.principal_id, &session.session_id, refresh, TimestampNs(10)), Err(ReferenceSessionError::GrantEscalation)));
        assert!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10)).is_ok());
        let refresh = SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor.clone(),
            capabilities: BTreeSet::new(),
            privacy_scope: session.privacy_scope.clone(),
        };
        let narrowed = store.refresh(&session.principal_id, &session.session_id, refresh, TimestampNs(10))?;
        assert_eq!(narrowed.expires_at_ns, session.expires_at_ns);
        assert_eq!(narrowed.symbol_table_generation, 1);
        assert!(matches!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10)), Err(ReferenceSessionError::StaleGeneration)));
        assert!(store.open(params()?, basis(), TimestampNs(10))?.capabilities.is_empty());
        Ok(())
    }

    #[test]
    fn generation_overflow_is_atomic() -> TestResult {
        let mut input = params()?;
        input.symbol_table_generation = u64::MAX;
        let mut store = ReferenceSessionStore::default();
        let session = store.open(input, basis(), TimestampNs(10))?;
        assert!(matches!(store.rotate_symbols(&session.principal_id, &session.session_id, u64::MAX, TimestampNs(10)), Err(ReferenceSessionError::GenerationExhausted)));
        assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(10))?, session);
        Ok(())
    }
}
