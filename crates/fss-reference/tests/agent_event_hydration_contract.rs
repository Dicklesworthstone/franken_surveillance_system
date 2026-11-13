#![forbid(unsafe_code)]
//! Real retained event metadata, native H0/H1 artifacts and conservative epistemic projection.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    H0Identity, H1CellContext, H1SemanticSynopsis, HandleAvailability, HydrationError,
    HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec, KnowledgeState,
    OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec, SessionId, TimestampNs,
};
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::LOCAL_SPOOL_DIR;
use fss_reference::agent_event_hydration::{
    EVENT_HYDRATION_CAPABILITY, EVENT_HYDRATION_H0_TOKENS, EVENT_HYDRATION_H1_TOKENS,
    EVENT_HYDRATION_QUERY_CAPABILITY, EventHydrationBuildError, EventHydrationCatalog,
    MAX_EVENT_HYDRATION_READ_BYTES, MAX_EVENT_HYDRATION_READ_OBJECTS,
    build_event_hydration_catalog, event_hydration_cost,
};
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, OrientLimits, OrientRequest, orient_deployment,
};
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:event-hydration-contract";
const PRINCIPAL: &str = "principal:event-hydration-contract";
const SOURCE: &[u8] = b"PRIVATE_SOURCE_BYTES_MUST_NEVER_ENTER_METADATA_HYDRATION";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for sequence in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-event-hydration-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory bound exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    root: PathBuf,
    event: EventHypothesis,
    cx: ReplayCx,
    _authority: ContextAuthority,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, state: EventState, contradictory: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:event-hydration-contract".to_owned(),
            operation_id: OperationId::parse("operation:event-hydration-contract")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 10,
            budgets: event_hydration_cost(HydrationLevel::H1)?,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut evidence = vec![EventEvidence {
            digest: ContentDigest::sha256(SOURCE),
            class: EvidenceClass::Assertion,
            failure_domain: "sensor:event-hydration-contract".to_owned(),
            supports: contradictory,
            relation: if contradictory {
                EvidenceEdgeRelation::Supports
            } else {
                EvidenceEdgeRelation::DerivedFrom
            },
            capsule_digest: None,
            identity_digest: None,
        }];
        if contradictory {
            evidence.push(EventEvidence {
                digest: ContentDigest::sha256(b"contradictory-source"),
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:contradictory-contract".to_owned(),
                supports: false,
                relation: EvidenceEdgeRelation::Contradicts,
                capsule_digest: None,
                identity_digest: None,
            });
            deployment.stage_payload(b"contradictory-source")?;
        }
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse("event:hydration-contract")?,
            revision: 1,
            supersedes: None,
            state,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some("Finite synthetic source only".to_owned()),
            zone_ids: vec!["front-door".to_owned()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence,
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"event-hydration-policy"),
                fingerprint: ContentDigest::sha256(b"event-hydration-decision"),
                abstained: true,
                abstention_reason: Some(
                    "Metadata fixture makes no physical determination".to_owned(),
                ),
            },
        };
        deployment.stage_payload(SOURCE)?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        drop(deployment);
        Ok(Self {
            root,
            event,
            cx,
            _authority: authority,
            _directory: directory,
        })
    }

    fn snapshot(&self) -> Test<DeploymentSnapshot> {
        let owner = ImmutableRetainedSource::open(
            &self.root,
            ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: MAX_EVENT_HYDRATION_READ_BYTES,
                max_read_objects: MAX_EVENT_HYDRATION_READ_OBJECTS,
            },
            &self.cx,
        )?;
        owner.revalidate()?;
        Ok(owner.snapshot().clone())
    }

    fn build(&self) -> Test<EventHydrationCatalog> {
        let snapshot = self.snapshot()?;
        build(&snapshot, &self.event)
    }
}

fn orientation(snapshot: &DeploymentSnapshot) -> Test<DeploymentOrientation> {
    Ok(orient_deployment(
        snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse(PRINCIPAL)?,
            budget_tokens: None,
        },
        &OrientLimits::default(),
    )?)
}

fn build(snapshot: &DeploymentSnapshot, event: &EventHypothesis) -> Test<EventHydrationCatalog> {
    Ok(build_event_hydration_catalog(
        snapshot,
        &orientation(snapshot)?,
        &event.event_id,
        event.revision_digest(),
        TimestampNs(1000),
    )?)
}

fn request(built: &EventHydrationCatalog, level: HydrationLevel) -> Test<HydrationRequest> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: built.descriptor.contract_basis.clone(),
        session_id: SessionId::parse("session:event-hydration-contract")?,
        handle_id: built.descriptor.handle_id.clone(),
        expected_descriptor_digest: built.descriptor.descriptor_digest,
        expected_subject_digest: built.descriptor.subject_digest,
        anchor: built.descriptor.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: [
            EVENT_HYDRATION_CAPABILITY.to_owned(),
            EVENT_HYDRATION_QUERY_CAPABILITY.to_owned(),
        ]
        .into(),
        authorized_privacy_classes: ["private:property".to_owned()].into(),
        budget: event_hydration_cost(HydrationLevel::H1)?,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: built.descriptor.published_at,
    })?)
}

#[test]
fn exact_revision_rebuilds_typed_artifacts_and_complete_native_provenance() -> Test {
    let fixture = Fixture::new("roundtrip", EventState::Hypothesized, false)?;
    let mut built = fixture.build()?;
    let rebuilt = fixture.build()?;
    assert_eq!(built.descriptor, rebuilt.descriptor);
    assert_eq!(built.synopsis, rebuilt.synopsis);
    assert_eq!(
        built.event_handle,
        "fss://event/event:hydration-contract/revision/1"
    );
    assert_eq!(built.descriptor.subject_id, built.event_handle);
    assert_eq!(
        built.descriptor.subject_digest,
        fixture.event.revision_digest()
    );
    assert_eq!(
        built.descriptor.levels,
        BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1])
    );
    assert!(
        built
            .descriptor
            .handle_id
            .starts_with("semantic-handle:sha256:")
    );
    let grants = BTreeSet::from([
        EVENT_HYDRATION_CAPABILITY.to_owned(),
        EVENT_HYDRATION_QUERY_CAPABILITY.to_owned(),
    ]);
    assert!(
        built
            .descriptor
            .required_capabilities
            .values()
            .all(|required| required == &grants)
    );

    let h0_request = request(&built, HydrationLevel::H0)?;
    let h0 = built
        .catalog
        .hydrate(&h0_request, built.descriptor.published_at)?;
    h0.validate_for(&h0_request, &built.descriptor)?;
    assert_eq!(h0.receipt.cost.tokens, EVENT_HYDRATION_H0_TOKENS);
    let identity = h0.artifact.as_ref().ok_or("missing H0 artifact")?;
    assert_eq!(
        H0Identity::from_canonical_bytes(&identity.payload)?,
        built.identity
    );
    identity.validate_h0_identity_for(&built.descriptor)?;
    assert_eq!(
        identity,
        &fss_core::HydrationArtifact::publish_h0_identity(&built.descriptor)?
    );
    assert_eq!(
        h0_request.validate_delivery(&built.descriptor, identity, built.descriptor.published_at)?,
        event_hydration_cost(HydrationLevel::H0)?
    );
    assert_eq!(
        identity.content_type,
        fss_core::HydrationArtifact::H0_CONTENT_TYPE
    );
    assert_eq!(
        identity.proof_roots,
        BTreeSet::from([
            built.descriptor.subject_digest,
            built.descriptor.descriptor_digest,
            identity.payload_digest,
        ])
    );

    let h1_request = request(&built, HydrationLevel::H1)?;
    let h1 = built
        .catalog
        .hydrate(&h1_request, built.descriptor.published_at)?;
    h1.validate_for(&h1_request, &built.descriptor)?;
    assert_eq!(h1.receipt.cost.tokens, EVENT_HYDRATION_H1_TOKENS);
    let synopsis = h1.artifact.as_ref().ok_or("missing H1 artifact")?;
    assert_eq!(
        H1SemanticSynopsis::from_canonical_bytes(&synopsis.payload)?,
        built.synopsis
    );
    assert!(
        synopsis
            .proof_roots
            .contains(&built.explanation.event.event_root)
    );
    assert!(
        synopsis
            .proof_roots
            .contains(&fixture.event.revision_digest())
    );
    assert!(
        !synopsis
            .payload
            .windows(SOURCE.len())
            .any(|bytes| bytes == SOURCE)
    );
    assert!(built.synopsis.quality().belief_interval().is_none());
    assert!(built.synopsis.quality().calibration_digest().is_none());
    assert!(built.synopsis.has_omissions());
    Ok(())
}

#[test]
fn unknown_conflicted_and_indeterminate_physical_claims_are_not_promoted() -> Test {
    for (label, state, contradictory, expected) in [
        (
            "unknown",
            EventState::Hypothesized,
            false,
            KnowledgeState::Unknown,
        ),
        (
            "conflicted",
            EventState::Hypothesized,
            true,
            KnowledgeState::Conflicted,
        ),
        (
            "indeterminate",
            EventState::Indeterminate,
            false,
            KnowledgeState::Indeterminate,
        ),
    ] {
        let fixture = Fixture::new(label, state, contradictory)?;
        let built = fixture.build()?;
        let physical = built
            .explanation
            .cells
            .iter()
            .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
            .ok_or("physical claim missing")?;
        assert_eq!(physical.knowledge_state(), expected, "{label}");
        assert!(built.synopsis.facts().iter().any(|fact| {
            fact.statement.contains("claim-state")
                && fact
                    .statement
                    .contains(&format!("knowledge state {}", expected.as_str()))
        }));
        let cells = built
            .synopsis
            .to_knowledge_cells(&H1CellContext::new(built.descriptor.anchor))?;
        assert!(
            cells
                .iter()
                .all(|cell| cell.statement().starts_with("Retained event metadata ("))
        );
        assert!(built.explanation.worlds.iter().any(|world| world.protected));
        if contradictory {
            assert!(!physical.contradictions().is_empty());
            assert!(
                built
                    .synopsis
                    .facts()
                    .iter()
                    .any(|fact| fact.statement.contains("claim-contradiction"))
            );
        }
    }
    Ok(())
}

#[test]
fn stale_revision_effect_prefix_and_session_lifetime_refuse_whole_catalog() -> Test {
    let fixture = Fixture::new("stale", EventState::Hypothesized, false)?;
    let snapshot = fixture.snapshot()?;
    let orient = orientation(&snapshot)?;
    let attempt = |snapshot: &DeploymentSnapshot, revision, until| {
        build_event_hydration_catalog(snapshot, &orient, &fixture.event.event_id, revision, until)
    };
    assert!(matches!(
        attempt(
            &snapshot,
            ContentDigest::sha256(b"other revision"),
            TimestampNs(1000)
        ),
        Err(EventHydrationBuildError::RevisionChanged)
    ));
    assert!(matches!(
        attempt(&snapshot, fixture.event.revision_digest(), TimestampNs(-1)),
        Err(EventHydrationBuildError::Expired)
    ));
    let mut changed = snapshot.clone();
    changed.effect_journal_root = ContentDigest::sha256(b"changed effect prefix");
    assert!(matches!(
        attempt(&changed, fixture.event.revision_digest(), TimestampNs(1000)),
        Err(EventHydrationBuildError::BasisChanged)
    ));
    changed = snapshot;
    changed.ledger_tail_uncommitted = true;
    assert!(matches!(
        attempt(&changed, fixture.event.revision_digest(), TimestampNs(1000)),
        Err(EventHydrationBuildError::BasisChanged)
    ));
    Ok(())
}

#[test]
fn metadata_remains_available_without_disclosing_or_verifying_original_payload() -> Test {
    let fixture = Fixture::new("source-absent", EventState::Hypothesized, false)?;
    let digest = ContentDigest::sha256(SOURCE);
    let path = fixture
        .root
        .join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(
            digest
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
    fs::remove_file(path)?;
    let mut built = fixture.build()?;
    assert_eq!(built.descriptor.availability, HandleAvailability::Available);
    assert!(built.synopsis.facts().iter().any(|fact| {
        fact.statement
            .contains("does not read original source evidence")
    }));
    for level in [HydrationLevel::H2, HydrationLevel::H3, HydrationLevel::H4] {
        let requested = request(&built, level)?;
        assert!(matches!(
            built
                .catalog
                .hydrate(&requested, built.descriptor.published_at),
            Err(HydrationError::LevelUnavailable)
        ));
    }
    Ok(())
}

#[test]
fn descriptor_binds_privacy_epoch_and_never_supplies_missing_grants() -> Test {
    let fixture = Fixture::new("authority", EventState::Hypothesized, false)?;
    let mut snapshot = fixture.snapshot()?;
    // Pure projection fixture: build a mutually consistent snapshot and orientation at a
    // distinct privacy generation. Runtime current-authority admission is tested by the owner.
    snapshot.anchor.privacy_epoch = 17;
    let mut built = build(&snapshot, &fixture.event)?;
    assert_eq!(built.descriptor.anchor.privacy_epoch, 17);
    let mut denied = request(&built, HydrationLevel::H0)?;
    denied
        .available_capabilities
        .remove(EVENT_HYDRATION_CAPABILITY);
    // Rebuild the native request rather than relying on a forged request digest.
    denied = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: denied.contract_basis,
        session_id: denied.session_id,
        handle_id: denied.handle_id,
        expected_descriptor_digest: denied.expected_descriptor_digest,
        expected_subject_digest: denied.expected_subject_digest,
        anchor: denied.anchor,
        requested_level: denied.requested_level,
        allow_lower_level: denied.allow_lower_level,
        available_capabilities: denied.available_capabilities,
        authorized_privacy_classes: denied.authorized_privacy_classes,
        budget: denied.budget,
        purpose: denied.purpose,
        continuation: None,
        issued_at: denied.issued_at,
    })?;
    assert!(matches!(
        built
            .catalog
            .hydrate(&denied, built.descriptor.published_at),
        Err(HydrationError::CapabilityDenied)
    ));
    let granted = request(&built, HydrationLevel::H0)?;
    let response = built
        .catalog
        .hydrate(&granted, built.descriptor.published_at)?;
    assert_eq!(response.receipt.anchor.privacy_epoch, 17);
    assert_eq!(built.catalog.issued_cursor_count(), 1);
    Ok(())
}
