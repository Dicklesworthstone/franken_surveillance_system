#![forbid(unsafe_code)]
//! Synthetic capture -> retained publication -> session hydration -> expiry/recovery regression.

use fss_core::{
    AgentSessionParams, BudgetVector, CapsuleId, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, HandleAvailability, HydrationLevel, HydrationPurpose,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, MissionId, PrincipalId,
    SemanticHandle, SemanticHandleSpec, SensorId, SessionId, TimestampNs,
};
use fss_object::retention::checkpoint::RetentionRecoveryBudget;
use fss_object::retention::{
    RetentionAuthorization, RetentionBudget, RetentionLimits, RetentionRule, RetentionStore,
};
use fss_object::{ObjectLimits, ObjectManifest};
use fss_reference::agent_session::hydration::SessionSourceHydrationError;
use fss_reference::{
    ReferenceHydrationCatalog, ReferenceSessionStore, SessionAlias, SessionBindingRequest,
    SourceHydrationError, VirtualCameraSpec, generate_source,
};
use std::collections::BTreeSet;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
const POLICY: &[u8] = b"policy:retention-source-test";
fn rule(until: i128) -> RetentionRule {
    RetentionRule {
        retain_until: TimestampNs(until),
        reason: "rule:synthetic-source-window".to_owned(),
    }
}
fn budget() -> RetentionBudget {
    RetentionBudget {
        max_objects: 128,
        max_deleted_bytes: 1_000_000,
        max_staging_bytes: 1_000_000,
    }
}
struct Fixture {
    retained: RetentionStore,
    catalog: ReferenceHydrationCatalog,
    sessions: ReferenceSessionStore,
    principal: PrincipalId,
    alias: SessionAlias,
    request: HydrationRequest,
    descriptor: SemanticHandle,
    root: ContentDigest,
    witness: ContentDigest,
    bytes: Vec<u8>,
}
fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut retained = RetentionStore::new(
        ContentDigest::sha256(POLICY),
        ObjectLimits::new(128, 1_000_000),
        RetentionLimits::default(),
    );
    let packet = generate_source(&VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:retention-test")?,
        sensor_id: SensorId::parse("sensor:retention-test")?,
        seed: 9,
        packet_count: 1,
        packet_bytes: 32,
        start_ns: 0,
        period_ns: 10,
        uncertainty_ns: 1,
    })?
    .pop()
    .ok_or("missing synthetic packet")?;
    let subject = retained.put_source(&packet.bytes, rule(10))?;
    assert_eq!(subject, packet.digest);
    let metadata = retained.put_source(b"synthetic capture provenance", rule(10))?;
    let root = retained.publish_manifest(
        ObjectManifest::new("synthetic-source", [subject], Some(metadata))?,
        rule(10),
    )?;
    let witness =
        retained.put_source(b"runtime-approved retention deletion witness", rule(10_000))?;
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
    ]);
    let quote = BudgetVector::builder().tokens(128).bytes(4096).build()?;
    let descriptor = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s",
            b"o",
            b"v",
            b"c",
            b"e",
            b"cost",
            "retention-source:test",
        )),
        anchor: LedgerAnchor::genesis("site:retention-source-test"),
        subject_id: "subject:synthetic-packet".to_owned(),
        subject_digest: subject,
        semantic_type: "source_object".to_owned(),
        source_id: "source:synthetic-retention".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        // Intentionally longer than storage's rule: a stale Available descriptor is NOT custody.
        retention_until: TimestampNs(1000),
        required_capabilities: levels
            .iter()
            .map(|level| (*level, BTreeSet::from(["capability:source".to_owned()])))
            .collect(),
        estimated_costs: levels.iter().map(|level| (*level, quote)).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(descriptor.clone())?;
    catalog.bind_source_object(
        &descriptor.handle_id,
        descriptor.descriptor_digest,
        root,
        retained.custody(),
    )?;
    let principal = PrincipalId::parse("principal:retention-owner")?;
    let session_id = SessionId::parse("session:retention-source")?;
    let capabilities = BTreeSet::from(["capability:source".to_owned()]);
    let privacy_scope = BTreeSet::from([descriptor.privacy_class.clone()]);
    let mut sessions = ReferenceSessionStore::default();
    sessions.open(
        AgentSessionParams {
            session_id: session_id.clone(),
            mission_id: MissionId::parse("mission:retention-source")?,
            principal_id: principal.clone(),
            capabilities: capabilities.clone(),
            privacy_scope: privacy_scope.clone(),
            current_anchor: descriptor.anchor.clone(),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 4096,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 10_000,
        },
        descriptor.contract_basis.clone(),
        TimestampNs(2),
    )?;
    let alias = sessions.bind(
        &principal,
        &SessionBindingRequest {
            session_id: session_id.clone(),
            generation: 0,
            handle_id: descriptor.handle_id.clone(),
            descriptor_digest: descriptor.descriptor_digest,
        },
        &catalog,
        TimestampNs(2),
    )?;
    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: descriptor.contract_basis.clone(),
        session_id,
        handle_id: descriptor.handle_id.clone(),
        expected_descriptor_digest: descriptor.descriptor_digest,
        expected_subject_digest: descriptor.subject_digest,
        anchor: descriptor.anchor.clone(),
        requested_level: HydrationLevel::H3,
        allow_lower_level: false,
        available_capabilities: capabilities,
        authorized_privacy_classes: privacy_scope,
        budget: quote,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at: TimestampNs(2),
    })?;
    Ok(Fixture {
        retained,
        catalog,
        sessions,
        principal,
        alias,
        request,
        descriptor,
        root,
        witness,
        bytes: packet.bytes,
    })
}
impl Fixture {
    fn deliver(
        &mut self,
        now: i128,
    ) -> Result<fss_core::HydrationResponse, SessionSourceHydrationError> {
        self.sessions.hydrate_from_source(
            &self.principal,
            &self.alias,
            &self.request,
            &mut self.catalog,
            self.retained.custody(),
            TimestampNs(now),
        )
    }
    fn expire(&mut self) -> Result<(), Box<dyn Error>> {
        let plan = self.retained.prepare_expiry(TimestampNs(20), budget())?;
        let authorization = RetentionAuthorization {
            policy_digest: ContentDigest::sha256(POLICY),
            plan_digest: plan.digest(),
            witness: self.witness,
            permitted_objects: plan.selected().iter().copied().collect(),
            issued_at: TimestampNs(20),
            expires_at: TimestampNs(100),
        };
        let receipt = self
            .retained
            .execute_expiry(&plan, &authorization, TimestampNs(20))?;
        assert_eq!(receipt.deleted().len(), 3); // source, provenance, and publication root
        Ok(())
    }
}

#[test]
fn expired_source_cannot_be_redelivered_or_charged_from_a_stale_available_descriptor() -> TestResult
{
    let mut f = fixture()?;
    let first = f.deliver(5)?;
    assert_eq!(
        first.artifact.as_ref().ok_or("missing source")?.payload,
        f.bytes
    );
    f.catalog
        .source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or("missing source binding")?
        .validate_response(&f.request, &f.descriptor, &first)?;
    let remaining =
        f.sessions
            .remaining_token_budget(&f.principal, &f.alias.session_id, TimestampNs(5))?;
    f.expire()?;
    assert!(matches!(
        f.deliver(21),
        Err(SessionSourceHydrationError::Source(
            SourceHydrationError::Object(_)
        ))
    ));
    assert_eq!(
        f.sessions
            .remaining_token_budget(&f.principal, &f.alias.session_id, TimestampNs(21))?,
        remaining
    );
    assert_eq!(f.catalog.stored_payload_bytes(), 0);
    assert!(
        f.retained
            .custody()
            .is_tombstoned(f.descriptor.subject_digest)
    );
    // An old proof remains historical evidence, never authorization for another read.
    f.catalog
        .source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or("missing source binding")?
        .validate_response(&f.request, &f.descriptor, &first)?;
    Ok(())
}

#[test]
fn held_capture_remains_retrievable_until_explicit_release_then_all_local_children_expire()
-> TestResult {
    let mut f = fixture()?;
    f.retained.add_hold(
        f.retained.state_digest()?,
        "hold:incident",
        f.root,
        f.witness,
    )?;
    let plan = f.retained.prepare_expiry(TimestampNs(20), budget())?;
    assert!(plan.selected().is_empty());
    assert_eq!(plan.blocked_due().len(), 3);
    assert_eq!(
        f.deliver(20)?
            .artifact
            .ok_or("missing held source")?
            .payload,
        f.bytes
    );
    f.retained
        .release_hold(f.retained.state_digest()?, "hold:incident", f.witness)?;
    f.expire()?;
    assert!(f.deliver(21).is_err());
    assert_eq!(f.retained.custody().published_manifest_count(), 0);
    Ok(())
}

#[test]
fn recovery_preserves_tombstones_against_an_unchanged_hydration_catalog() -> TestResult {
    let mut f = fixture()?;
    f.deliver(5)?;
    f.expire()?;
    let cp = f.retained.checkpoint(1_000_000)?;
    let restored = RetentionStore::restore_checkpoint(
        cp.as_bytes(),
        cp.digest(),
        ContentDigest::sha256(POLICY),
        f.retained.custody(),
        RetentionLimits::default(),
        RetentionRecoveryBudget {
            max_checkpoint_bytes: 1_000_000,
            max_custody_bytes: 1_000_000,
        },
    )?;
    f.retained = restored;
    assert!(matches!(
        f.deliver(21),
        Err(SessionSourceHydrationError::Source(
            SourceHydrationError::Object(_)
        ))
    ));
    assert_eq!(f.catalog.stored_payload_bytes(), 0);
    assert!(f.retained.put_source(&f.bytes, rule(10)).is_err());
    Ok(())
}
