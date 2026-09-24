use std::error::Error;

use fss_core::{
    BudgetVector, Completeness, ContractBasisRegistryBytes, HydrationArtifact, HydrationPurpose,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, MissionId, SemanticHandleSpec,
};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:session-test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

fn anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:session-test");
    anchor.commit_sequence = 7;
    anchor
}

fn params() -> Result<AgentSessionParams, ContractError> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse("session:test")?,
        mission_id: MissionId::parse("mission:test")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: BTreeSet::from(["capability:hydrate:H0".to_owned()]),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: anchor(),
        view_id: "AVIEW-001".to_owned(),
        token_budget: 100,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 1_000,
    })
}

fn descriptor(subject: &str) -> Result<SemanticHandle, Box<dyn Error>> {
    let cost = BudgetVector::builder().tokens(1).bytes(32).build()?;
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(),
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
        required_capabilities: HydrationLevel::ALL
            .into_iter()
            .map(|level| {
                (
                    level,
                    BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
                )
            })
            .collect(),
        estimated_costs: HydrationLevel::ALL
            .into_iter()
            .map(|level| (level, cost))
            .collect(),
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

struct Fixture {
    store: ReferenceSessionStore,
    session: AgentSession,
    descriptor: SemanticHandle,
    catalog: ReferenceHydrationCatalog,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        Self::with_params(params()?, ReferenceSessionLimits::default())
    }

    fn with_params(
        input: AgentSessionParams,
        limits: ReferenceSessionLimits,
    ) -> Result<Self, Box<dyn Error>> {
        let mut store = ReferenceSessionStore::with_limits(limits);
        let session = store.open(input, basis(), TimestampNs(10))?;
        let descriptor = descriptor("evidence:first")?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(descriptor.clone())?;
        for level in [HydrationLevel::H0, HydrationLevel::H1] {
            let artifact = HydrationArtifact::publish(
                level,
                "application/fss+json",
                b"{}".to_vec(),
                [descriptor.subject_digest],
                Completeness::Complete,
                None,
            )?;
            catalog.register_artifact(
                &descriptor.handle_id,
                descriptor.descriptor_digest,
                artifact,
            )?;
        }
        Ok(Self {
            store,
            session,
            descriptor,
            catalog,
        })
    }

    fn binding(&self) -> SessionBindingRequest {
        SessionBindingRequest {
            session_id: self.session.session_id.clone(),
            generation: self.session.symbol_table_generation,
            handle_id: self.descriptor.handle_id.clone(),
            descriptor_digest: self.descriptor.descriptor_digest,
        }
    }

    fn bind(&mut self, now: TimestampNs) -> Result<SessionAlias, ReferenceSessionError> {
        self.store.bind(
            &self.session.principal_id,
            &self.binding(),
            &self.catalog,
            now,
        )
    }

    fn request(
        &self,
        level: HydrationLevel,
        tokens: u64,
    ) -> Result<HydrationRequestSpec, Box<dyn Error>> {
        Ok(HydrationRequestSpec {
            contract_basis: basis(),
            session_id: self.session.session_id.clone(),
            handle_id: self.descriptor.handle_id.clone(),
            expected_descriptor_digest: self.descriptor.descriptor_digest,
            expected_subject_digest: self.descriptor.subject_digest,
            anchor: self.session.current_anchor.clone(),
            requested_level: level,
            allow_lower_level: false,
            available_capabilities: self.session.capabilities.clone(),
            authorized_privacy_classes: self.session.privacy_scope.clone(),
            budget: BudgetVector::builder().tokens(tokens).bytes(64).build()?,
            purpose: HydrationPurpose::Qualification,
            continuation: None,
            issued_at: TimestampNs(10),
        })
    }

    fn refresh(&self) -> SessionRefresh {
        SessionRefresh {
            expected_session_digest: self.session.session_digest(),
            current_anchor: self.session.current_anchor.clone(),
            capabilities: self.session.capabilities.clone(),
            privacy_scope: self.session.privacy_scope.clone(),
        }
    }
}

#[test]
fn open_retry_keeps_generation_and_original_expiry() -> TestResult {
    let mut fixture = Fixture::new()?;
    let rotated = fixture.store.rotate_symbols(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        0,
        TimestampNs(20),
    )?;
    let retry = fixture.store.open(params()?, basis(), TimestampNs(50))?;
    assert_eq!(retry, rotated);
    assert_eq!(retry.expires_at_ns, 1_000);
    assert_eq!(retry.symbol_table_generation, 1);
    Ok(())
}

#[test]
fn close_and_expiry_never_reopen_even_after_clock_rollback() -> TestResult {
    let mut fixture = Fixture::new()?;
    assert!(matches!(
        fixture.store.session(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            TimestampNs(1_000),
        ),
        Err(ReferenceSessionError::Unavailable)
    ));
    assert!(matches!(
        fixture.store.open(params()?, basis(), TimestampNs(10)),
        Err(ReferenceSessionError::Unavailable)
    ));
    for now in [TimestampNs(1_001), TimestampNs(1_002)] {
        fixture.store.close(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            now,
        )?;
    }
    assert!(matches!(
        fixture.store.open(params()?, basis(), TimestampNs(1_003)),
        Err(ReferenceSessionError::Unavailable)
    ));
    Ok(())
}

#[test]
fn wrong_principal_and_unknown_session_have_same_refusal() -> TestResult {
    let mut fixture = Fixture::new()?;
    let other = PrincipalId::parse("principal:other")?;
    for id in [
        fixture.session.session_id.clone(),
        SessionId::parse("session:absent")?,
    ] {
        assert!(matches!(
            fixture.store.session(&other, &id, TimestampNs(10)),
            Err(ReferenceSessionError::Unavailable)
        ));
    }
    assert!(matches!(
        fixture.store.session(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            TimestampNs(9),
        ),
        Err(ReferenceSessionError::ClockRegression)
    ));
    Ok(())
}

#[test]
fn exact_binding_retry_and_generation_invalidation() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    assert_eq!(alias, fixture.bind(TimestampNs(10))?);
    let raw = fixture.store.resolve(
        &fixture.session.principal_id,
        &alias,
        &fixture.catalog,
        TimestampNs(10),
    )?;
    assert_eq!(raw.handle_id, fixture.descriptor.handle_id);
    fixture.store.rotate_symbols(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        0,
        TimestampNs(10),
    )?;
    assert!(matches!(
        fixture.store.resolve(
            &fixture.session.principal_id,
            &alias,
            &fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::StaleGeneration)
    ));
    assert_eq!(raw.descriptor_digest, fixture.descriptor.descriptor_digest);
    Ok(())
}

#[test]
fn symbol_capacity_does_not_evict_or_rebind_existing_symbols() -> TestResult {
    let mut fixture = Fixture::with_params(
        params()?,
        ReferenceSessionLimits {
            max_symbols_per_session: 1,
            ..ReferenceSessionLimits::default()
        },
    )?;
    let alias = fixture.bind(TimestampNs(10))?;
    let second = descriptor("evidence:second")?;
    fixture.catalog.register_descriptor(second.clone())?;
    let mut request = fixture.binding();
    request.handle_id = second.handle_id;
    request.descriptor_digest = second.descriptor_digest;
    assert!(matches!(
        fixture.store.bind(
            &fixture.session.principal_id,
            &request,
            &fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::CapacityExceeded)
    ));
    assert_eq!(alias, fixture.bind(TimestampNs(10))?);
    Ok(())
}

#[test]
fn session_tombstones_and_grant_bytes_are_bounded() -> TestResult {
    let mut fixture = Fixture::with_params(
        params()?,
        ReferenceSessionLimits {
            max_sessions: 1,
            ..ReferenceSessionLimits::default()
        },
    )?;
    fixture.store.close(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        TimestampNs(10),
    )?;
    let mut another = params()?;
    another.session_id = SessionId::parse("session:another")?;
    assert!(matches!(
        fixture.store.open(another, basis(), TimestampNs(10)),
        Err(ReferenceSessionError::CapacityExceeded)
    ));
    let mut no_bytes = ReferenceSessionStore::with_limits(ReferenceSessionLimits {
        max_grant_bytes_per_session: 0,
        ..ReferenceSessionLimits::default()
    });
    assert!(matches!(
        no_bytes.open(params()?, basis(), TimestampNs(10)),
        Err(ReferenceSessionError::CapacityExceeded)
    ));
    Ok(())
}

#[test]
fn refresh_cannot_escalate_or_renew_and_invalidates_old_symbols() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let mut refresh = fixture.refresh();
    refresh
        .capabilities
        .insert("capability:hydrate:H3".to_owned());
    assert!(matches!(
        fixture.store.refresh(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            refresh,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::GrantEscalation)
    ));
    assert!(
        fixture
            .store
            .resolve(
                &fixture.session.principal_id,
                &alias,
                &fixture.catalog,
                TimestampNs(10),
            )
            .is_ok()
    );
    let mut refresh = fixture.refresh();
    refresh.capabilities.clear();
    let narrowed = fixture.store.refresh(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        refresh,
        TimestampNs(10),
    )?;
    assert_eq!(narrowed.expires_at_ns, fixture.session.expires_at_ns);
    assert_eq!(narrowed.symbol_table_generation, 1);
    assert!(matches!(
        fixture.store.resolve(
            &fixture.session.principal_id,
            &alias,
            &fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::StaleGeneration)
    ));
    assert!(
        fixture
            .store
            .open(params()?, basis(), TimestampNs(10))?
            .capabilities
            .is_empty()
    );
    Ok(())
}

#[test]
fn generation_overflow_is_atomic() -> TestResult {
    let mut input = params()?;
    input.symbol_table_generation = u64::MAX;
    let mut fixture = Fixture::with_params(input, ReferenceSessionLimits::default())?;
    let alias = fixture.bind(TimestampNs(10))?;
    assert!(matches!(
        fixture.store.rotate_symbols(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            u64::MAX,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::GenerationExhausted)
    ));
    assert!(
        fixture
            .store
            .resolve(
                &fixture.session.principal_id,
                &alias,
                &fixture.catalog,
                TimestampNs(10),
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn absent_and_ungranted_handles_are_indistinguishable() -> TestResult {
    let mut input = params()?;
    input.privacy_scope.clear();
    let mut fixture = Fixture::with_params(input, ReferenceSessionLimits::default())?;
    assert!(matches!(
        fixture.bind(TimestampNs(10)),
        Err(ReferenceSessionError::StaleAlias)
    ));
    let mut absent = fixture.binding();
    absent.handle_id = "semantic-handle:absent".to_owned();
    assert!(matches!(
        fixture.store.bind(
            &fixture.session.principal_id,
            &absent,
            &fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::StaleAlias)
    ));
    Ok(())
}

#[test]
fn superseded_alias_requires_explicit_refresh_and_rebinding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let archived = fixture.store.resolve(
        &fixture.session.principal_id,
        &alias,
        &fixture.catalog,
        TimestampNs(10),
    )?;
    let mut next = fixture.descriptor.clone();
    next.anchor.commit_sequence += 1;
    next.published_at = TimestampNs(11);
    next.descriptor_digest = next.computed_descriptor_digest();
    fixture.catalog.register_descriptor(next.clone())?;
    assert!(matches!(
        fixture.store.resolve(
            &fixture.session.principal_id,
            &alias,
            &fixture.catalog,
            TimestampNs(11),
        ),
        Err(ReferenceSessionError::StaleAlias)
    ));
    let mut refresh = fixture.refresh();
    refresh.current_anchor = next.anchor.clone();
    fixture.session = fixture.store.refresh(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        refresh,
        TimestampNs(11),
    )?;
    fixture.descriptor = next;
    let replacement = fixture.bind(TimestampNs(11))?;
    let resolved = fixture.store.resolve(
        &fixture.session.principal_id,
        &replacement,
        &fixture.catalog,
        TimestampNs(11),
    )?;
    assert_eq!(resolved.handle_id, archived.handle_id);
    assert_ne!(resolved.descriptor_digest, archived.descriptor_digest);
    assert_eq!(replacement.generation, alias.generation + 1);
    Ok(())
}

#[test]
fn refresh_rejects_rollback_cross_lineage_and_equal_sequence_forks() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut rollback = fixture.session.current_anchor.clone();
    rollback.commit_sequence -= 1;
    let mut fork = fixture.session.current_anchor.clone();
    fork.adapter_registry_epoch += 1;
    let foreign = LedgerAnchor::genesis("site:foreign");
    for current_anchor in [rollback, fork, foreign] {
        let mut refresh = fixture.refresh();
        refresh.current_anchor = current_anchor;
        assert!(matches!(
            fixture.store.refresh(
                &fixture.session.principal_id,
                &fixture.session.session_id,
                refresh,
                TimestampNs(10),
            ),
            Err(ReferenceSessionError::StaleBasis)
        ));
    }
    Ok(())
}

#[test]
fn refresh_uses_exact_optimistic_state_and_equal_inputs_are_noop() -> TestResult {
    let mut fixture = Fixture::new()?;
    let unchanged = fixture.refresh();
    assert_eq!(
        fixture.store.refresh(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            unchanged,
            TimestampNs(10),
        )?,
        fixture.session
    );
    let mut stale = fixture.refresh();
    stale.expected_session_digest = ContentDigest::sha256(b"stale-session-state");
    assert!(matches!(
        fixture.store.refresh(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            stale,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::StaleBasis)
    ));
    Ok(())
}

#[test]
fn exact_hydration_preserves_canonical_receipt_and_charges_tokens() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let request = HydrationRequest::publish(fixture.request(HydrationLevel::H0, 10)?)?;
    let response = fixture.store.hydrate(
        &fixture.session.principal_id,
        &alias,
        &request,
        &mut fixture.catalog,
        TimestampNs(10),
    )?;
    assert_eq!(response.receipt.request_digest, request.request_digest);
    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H0));
    assert_eq!(response.receipt.cost.tokens, 1);
    assert_eq!(
        fixture.store.remaining_token_budget(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            TimestampNs(10),
        )?,
        fixture.session.token_budget - 1
    );
    Ok(())
}

#[test]
fn hydration_cannot_self_grant_capabilities_or_privacy() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    for widen_privacy in [false, true] {
        let mut spec = fixture.request(HydrationLevel::H0, 10)?;
        if widen_privacy {
            spec.authorized_privacy_classes
                .insert("private:other-site".to_owned());
        } else {
            spec.available_capabilities
                .insert("capability:hydrate:H3".to_owned());
        }
        let request = HydrationRequest::publish(spec)?;
        assert!(matches!(
            fixture.store.hydrate(
                &fixture.session.principal_id,
                &alias,
                &request,
                &mut fixture.catalog,
                TimestampNs(10),
            ),
            Err(ReferenceSessionError::GrantEscalation)
        ));
    }
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    assert_eq!(
        fixture.store.remaining_token_budget(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            TimestampNs(10),
        )?,
        fixture.session.token_budget
    );
    Ok(())
}

#[test]
fn hydration_rejects_cross_session_references_before_cursor_mutation() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let mut spec = fixture.request(HydrationLevel::H0, 10)?;
    spec.session_id = SessionId::parse("session:another")?;
    let request = HydrationRequest::publish(spec)?;
    assert!(matches!(
        fixture.store.hydrate(
            &fixture.session.principal_id,
            &alias,
            &request,
            &mut fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::StaleAlias)
    ));
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn hydration_rejects_modified_request_seals_without_spending() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let mut request = HydrationRequest::publish(fixture.request(HydrationLevel::H0, 10)?)?;
    request.expected_subject_digest = ContentDigest::sha256(b"forged-subject");
    assert!(matches!(
        fixture.store.hydrate(
            &fixture.session.principal_id,
            &alias,
            &request,
            &mut fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::Hydration(_))
    ));
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}

#[test]
fn cumulative_budget_survives_rotation_and_lost_ack_open_retry() -> TestResult {
    let mut input = params()?;
    input.token_budget = 2;
    let original = input.clone();
    let mut fixture = Fixture::with_params(input, ReferenceSessionLimits::default())?;
    let alias = fixture.bind(TimestampNs(10))?;
    for tokens in [2, 1] {
        let request = HydrationRequest::publish(fixture.request(HydrationLevel::H0, tokens)?)?;
        fixture.store.hydrate(
            &fixture.session.principal_id,
            &alias,
            &request,
            &mut fixture.catalog,
            TimestampNs(10),
        )?;
    }
    fixture.session = fixture.store.rotate_symbols(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        0,
        TimestampNs(10),
    )?;
    let retry = fixture.store.open(original, basis(), TimestampNs(10))?;
    assert_eq!(retry.symbol_table_generation, 1);
    let alias = fixture.bind(TimestampNs(10))?;
    let request = HydrationRequest::publish(fixture.request(HydrationLevel::H0, 1)?)?;
    let cursors = fixture.catalog.issued_cursor_count();
    assert!(matches!(
        fixture.store.hydrate(
            &fixture.session.principal_id,
            &alias,
            &request,
            &mut fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::BudgetExceeded)
    ));
    assert_eq!(fixture.catalog.issued_cursor_count(), cursors);
    assert_eq!(
        fixture.store.remaining_token_budget(
            &fixture.session.principal_id,
            &fixture.session.session_id,
            TimestampNs(10),
        )?,
        0
    );
    Ok(())
}

#[test]
fn progressive_hydration_uses_existing_exact_cursor_protocol() -> TestResult {
    let mut input = params()?;
    input
        .capabilities
        .insert("capability:hydrate:H1".to_owned());
    let mut fixture = Fixture::with_params(input, ReferenceSessionLimits::default())?;
    let alias = fixture.bind(TimestampNs(10))?;
    let first = HydrationRequest::publish(fixture.request(HydrationLevel::H0, 10)?)?;
    let response = fixture.store.hydrate(
        &fixture.session.principal_id,
        &alias,
        &first,
        &mut fixture.catalog,
        TimestampNs(10),
    )?;
    assert!(response.receipt.continuation.is_some());
    let mut spec = fixture.request(HydrationLevel::H1, 10)?;
    spec.continuation = response.receipt.continuation;
    let next = HydrationRequest::publish(spec)?;
    let response = fixture.store.hydrate(
        &fixture.session.principal_id,
        &alias,
        &next,
        &mut fixture.catalog,
        TimestampNs(10),
    )?;
    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H1));
    assert!(
        fixture
            .store
            .hydrate(
                &fixture.session.principal_id,
                &alias,
                &next,
                &mut fixture.catalog,
                TimestampNs(10),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn closing_session_blocks_previously_issued_hydration() -> TestResult {
    let mut fixture = Fixture::new()?;
    let alias = fixture.bind(TimestampNs(10))?;
    let request = HydrationRequest::publish(fixture.request(HydrationLevel::H0, 10)?)?;
    fixture.store.close(
        &fixture.session.principal_id,
        &fixture.session.session_id,
        TimestampNs(10),
    )?;
    assert!(matches!(
        fixture.store.hydrate(
            &fixture.session.principal_id,
            &alias,
            &request,
            &mut fixture.catalog,
            TimestampNs(10),
        ),
        Err(ReferenceSessionError::Unavailable)
    ));
    assert_eq!(fixture.catalog.issued_cursor_count(), 0);
    Ok(())
}
