use std::error::Error;

use fss_core::{
    BudgetVector, ContractBasisRegistryBytes, HandleAvailability, HydrationLevel,
    LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};

use super::*;
use crate::agent_session::{ReferenceSessionError, SessionBindingRequest, SessionRefresh};
use crate::ReferenceHydrationCatalog;

type TestResult = Result<(), Box<dyn Error>>;

pub(super) fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
        "fss-reference:checkpoint-test",
    ))
}

pub(super) fn params() -> Result<AgentSessionParams, ContractError> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse("session:checkpoint")?,
        mission_id: MissionId::parse("mission:checkpoint")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: BTreeSet::from(["capability:hydrate:H0".to_owned()]),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: LedgerAnchor::genesis("site:checkpoint"),
        view_id: "AVIEW-001".to_owned(),
        token_budget: 100,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 1_000,
    })
}

fn opened() -> Result<(ReferenceSessionStore, AgentSession), Box<dyn Error>> {
    let mut store = ReferenceSessionStore::default();
    let session = store.open(params()?, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn restore(store: &ReferenceSessionStore) -> Result<ReferenceSessionStore, SessionCheckpointError> {
    let checkpoint = store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    ReferenceSessionStore::restore_checkpoint(
        checkpoint.as_bytes(), checkpoint.digest(), ReferenceSessionLimits::default(),
        MAX_SESSION_CHECKPOINT_BYTES,
    )
}

pub(super) fn register(catalog: &mut ReferenceHydrationCatalog, subject: &str) -> Result<SemanticHandle, Box<dyn Error>> {
    let cost = BudgetVector::builder().tokens(1).bytes(32).build()?;
    let descriptor = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: LedgerAnchor::genesis("site:checkpoint"),
        subject_id: subject.to_owned(),
        subject_digest: ContentDigest::sha256(subject.as_bytes()),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:camera".to_owned(),
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
    })?;
    catalog.register_descriptor(descriptor.clone())?;
    Ok(descriptor)
}

#[test]
fn empty_and_populated_checkpoints_are_byte_exact() -> TestResult {
    for store in [ReferenceSessionStore::default(), opened()?.0] {
        let first = store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
        let second = restore(&store)?.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
        assert_eq!(first, second);
        assert_eq!(first.digest(), ContentDigest::sha256(first.as_bytes()));
    }
    Ok(())
}

#[test]
fn live_aliases_survive_but_still_require_current_catalog_and_owner() -> TestResult {
    let (mut store, session) = opened()?;
    let mut catalog = ReferenceHydrationCatalog::new();
    let first = register(&mut catalog, "evidence:first")?;
    let request = SessionBindingRequest {
        session_id: session.session_id.clone(), generation: 0,
        handle_id: first.handle_id.clone(), descriptor_digest: first.descriptor_digest,
    };
    let alias = store.bind(&session.principal_id, &request, &catalog, TimestampNs(20))?;
    let mut store = restore(&store)?;
    assert_eq!(store.bind(&session.principal_id, &request, &catalog, TimestampNs(21))?, alias);
    assert_eq!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(22))?.subject_digest,
        first.subject_digest);
    assert!(matches!(store.resolve(&PrincipalId::parse("principal:other")?, &alias, &catalog, TimestampNs(23)),
        Err(ReferenceSessionError::Unavailable)));
    assert!(matches!(store.resolve(&session.principal_id, &alias, &ReferenceHydrationCatalog::new(), TimestampNs(24)),
        Err(ReferenceSessionError::StaleAlias)));
    let second = register(&mut catalog, "evidence:second")?;
    let next = store.bind(&session.principal_id, &SessionBindingRequest {
        handle_id: second.handle_id, descriptor_digest: second.descriptor_digest, ..request
    }, &catalog, TimestampNs(25))?;
    assert_eq!(next.slot, 2);
    Ok(())
}

#[test]
fn restart_retains_charges_acknowledgement_and_clock_watermark() -> TestResult {
    let (mut store, session) = opened()?;
    let entry = store.sessions.get_mut(&session.session_id).ok_or("missing entry")?;
    entry.spent_tokens = 73;
    entry.session.last_acknowledged_situation_fingerprint = Some(ContentDigest::sha256(b"situation"));
    store.session(&session.principal_id, &session.session_id, TimestampNs(50))?;
    let mut store = restore(&store)?;
    let entry = store.sessions.get(&session.session_id).ok_or("missing entry")?;
    assert_eq!(entry.spent_tokens, 73);
    assert_eq!(entry.session.last_acknowledged_situation_fingerprint, Some(ContentDigest::sha256(b"situation")));
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(49)),
        Err(ReferenceSessionError::ClockRegression)));
    Ok(())
}

#[test]
fn expired_failed_read_is_retained_as_an_unreopenable_tombstone() -> TestResult {
    let (mut store, session) = opened()?;
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(1_000)),
        Err(ReferenceSessionError::Unavailable)));
    let mut store = restore(&store)?;
    assert!(matches!(store.open(params()?, basis(), TimestampNs(10)), Err(ReferenceSessionError::Unavailable)));
    assert_eq!(store.sessions.len(), 1);
    Ok(())
}

#[test]
fn close_cannot_be_undone_by_a_lost_acknowledgement_retry() -> TestResult {
    let (mut store, session) = opened()?;
    store.close(&session.principal_id, &session.session_id, TimestampNs(20))?;
    let mut store = restore(&store)?;
    store.close(&session.principal_id, &session.session_id, TimestampNs(21))?;
    assert!(matches!(store.open(params()?, basis(), TimestampNs(22)), Err(ReferenceSessionError::Unavailable)));
    Ok(())
}

#[test]
fn opening_identity_and_rotated_generation_survive_restart() -> TestResult {
    let (mut store, session) = opened()?;
    let rotated = store.rotate_symbols(&session.principal_id, &session.session_id, 0, TimestampNs(20))?;
    let mut store = restore(&store)?;
    assert_eq!(store.open(params()?, basis(), TimestampNs(30))?, rotated);
    assert_eq!(rotated.symbol_table_generation, 1);
    Ok(())
}

#[test]
fn narrowed_authority_is_not_widened_by_open_retry_after_restart() -> TestResult {
    let (mut store, session) = opened()?;
    let refreshed = store.refresh(&session.principal_id, &session.session_id, SessionRefresh {
        expected_session_digest: session.session_digest(),
        current_anchor: session.current_anchor.clone(),
        capabilities: BTreeSet::new(), privacy_scope: BTreeSet::new(),
    }, TimestampNs(20))?;
    let mut store = restore(&store)?;
    let retried = store.open(params()?, basis(), TimestampNs(30))?;
    assert_eq!(retried, refreshed);
    assert!(retried.capabilities.is_empty());
    assert!(retried.privacy_scope.is_empty());
    Ok(())
}

#[test]
fn stale_checkpoint_cannot_match_the_pinned_successor() -> TestResult {
    let (mut store, session) = opened()?;
    let old = store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    store.close(&session.principal_id, &session.session_id, TimestampNs(20))?;
    let current = store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    assert!(matches!(ReferenceSessionStore::restore_checkpoint(old.as_bytes(), current.digest(),
        ReferenceSessionLimits::default(), MAX_SESSION_CHECKPOINT_BYTES),
        Err(SessionCheckpointError::IntegrityMismatch)));
    Ok(())
}

#[test]
fn every_truncated_prefix_and_trailing_byte_is_refused() -> TestResult {
    let checkpoint = opened()?.0.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    for end in 0..checkpoint.as_bytes().len() {
        let bytes = &checkpoint.as_bytes()[..end];
        assert!(ReferenceSessionStore::restore_checkpoint(bytes, ContentDigest::sha256(bytes),
            ReferenceSessionLimits::default(), MAX_SESSION_CHECKPOINT_BYTES).is_err(), "prefix {end}");
    }
    let mut bytes = checkpoint.as_bytes().to_vec();
    bytes.push(0);
    assert!(ReferenceSessionStore::restore_checkpoint(&bytes, ContentDigest::sha256(&bytes),
        ReferenceSessionLimits::default(), MAX_SESSION_CHECKPOINT_BYTES).is_err());
    Ok(())
}

#[test]
fn quotas_and_exact_byte_boundary_are_enforced() -> TestResult {
    let store = opened()?.0;
    let checkpoint = store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    let size = checkpoint.as_bytes().len();
    assert_eq!(store.checkpoint(size)?, checkpoint);
    assert!(matches!(store.checkpoint(size - 1), Err(SessionCheckpointError::CapacityExceeded)));
    assert!(matches!(store.checkpoint(0), Err(SessionCheckpointError::CapacityExceeded)));
    for ceilings in [
        ReferenceSessionLimits { max_sessions: 0, ..ReferenceSessionLimits::default() },
        ReferenceSessionLimits { max_symbols_per_session: 0, ..ReferenceSessionLimits::default() },
        ReferenceSessionLimits { max_grants_per_session: 0, ..ReferenceSessionLimits::default() },
        ReferenceSessionLimits { max_grant_bytes_per_session: 0, ..ReferenceSessionLimits::default() },
    ] {
        assert!(matches!(ReferenceSessionStore::restore_checkpoint(checkpoint.as_bytes(), checkpoint.digest(),
            ceilings, MAX_SESSION_CHECKPOINT_BYTES), Err(SessionCheckpointError::CapacityExceeded)));
    }
    Ok(())
}

#[test]
fn unsorted_or_duplicate_grants_are_not_silently_normalized() -> TestResult {
    for values in [["b", "a"], ["a", "a"]] {
        let mut encoder = CanonicalEncoder::new();
        encoder.u32(2);
        for value in values { encoder.text(value); }
        let bytes = encoder.finish_checked()?;
        assert!(matches!(decode_grants(&mut CanonicalDecoder::new(&bytes), &mut 2, &mut 10),
            Err(SessionCheckpointError::InvalidState)));
    }
    Ok(())
}

#[test]
fn invalid_accounting_is_not_sealed() -> TestResult {
    let (mut store, session) = opened()?;
    store.sessions.get_mut(&session.session_id).ok_or("missing entry")?.spent_tokens = 101;
    assert!(matches!(store.checkpoint(MAX_SESSION_CHECKPOINT_BYTES), Err(SessionCheckpointError::InvalidState)));
    Ok(())
}
