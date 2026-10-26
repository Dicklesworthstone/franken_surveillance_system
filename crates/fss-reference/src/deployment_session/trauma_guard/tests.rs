#![forbid(unsafe_code)]
//! Native publication and owner-isolation contracts for advisory operational memory.

use super::*;
use std::error::Error;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentFeedbackProposal, BudgetVector, CanonicalEncode, ContextAuthority, EpisodeOutcome,
    ExecutionEpisode, LedgerAnchor, MissionId, OperationId, RequestedDisposition,
    RootAuthoritySpec, SessionId, TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "fss-trauma-memory-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::SeqCst),
        ));
        fs::create_dir_all(&path)?;
        // Publication uses the real agent writer admission, which requires a valid deployment
        // layout and clean authority journal even when no session has been opened.
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:trauma-memory-fixture".to_owned(),
            operation_id: OperationId::parse("operation:trauma-memory-fixture")?,
            principal: "operator:trauma-memory-fixture".to_owned(),
            capabilities: vec![crate::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"trauma-memory-tests"),
            generation: 1,
        })?;
        // Scope authority to the deployment root so initialization sees an empty root.
        let cx = crate::ReplayCx::from_context_authority(&authority, &path)?;
        drop(crate::ReferenceDeployment::open(
            &path,
            "site:memory-tests",
            &cx,
        )?);
        Ok(Self(path))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn owner() -> TestResult<PrincipalId> {
    Ok(PrincipalId::parse("principal:memory-owner")?)
}

fn proposal(principal: &PrincipalId, identity: &str) -> TestResult<AgentFeedbackProposal> {
    Ok(AgentFeedbackProposal::new(
        format!("feedback:{identity}"),
        principal.clone(),
        SessionId::parse(&format!("session:{identity}"))?,
        LedgerAnchor::genesis("site:memory-tests"),
        target_json(&FeedbackTarget::Event("event:memory-target".to_owned())),
        FeedbackProposalKind::HardNegativeCandidate,
        "Historical report; not a current-world fact.",
        vec![ContentDigest::sha256(identity.as_bytes()).to_text()],
        Vec::new(),
        RequestedDisposition::RecordOnly,
        FeedbackPrivacyClass::Private,
        10,
    )?)
}

fn publish_feedback(root: &Path, proposal: &AgentFeedbackProposal) -> TestResult<ContentDigest> {
    Ok(crate::deployment_session::publish_record(
        root,
        &memory_slot("feedback", &proposal.feedback_id)?,
        "agent-feedback",
        &proposal.try_canonical_bytes()?,
        &[b"{}".to_vec()],
        None,
    )?
    .root)
}

fn failed_episode(principal: &PrincipalId, identity: &str) -> TestResult<EpisodeRecord> {
    let plan_id = format!("plan:{identity}");
    let anchor = LedgerAnchor::genesis("site:memory-tests");
    Ok(EpisodeRecord {
        plan_id: plan_id.clone(),
        mission_id: MissionId::parse("mission:memory-tests")?,
        principal: principal.clone(),
        operation_id: format!("operation:{identity}"),
        terminal_state: TerminalOutcome::Failed,
        recorded_at: TimestampNs(10),
        episode: ExecutionEpisode::new(
            EpisodeRecord::identity(&plan_id),
            SessionId::parse("session:memory-tests")?,
            "mission:memory-tests",
            anchor.clone(),
            anchor,
            ContentDigest::sha256(b"missing historical plan").to_text(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            EpisodeOutcome {
                state: EpisodeOutcomeState::Failed,
                success_predicates: Vec::new(),
                failed_predicates: vec!["delivery".to_owned()],
                indeterminate_predicates: Vec::new(),
            },
            "{}",
            Vec::new(),
            vec!["Applicability is unverified.".to_owned()],
            ContentDigest::sha256(b"historical decision").to_text(),
        )?,
    })
}

fn publish_episode(root: &Path, record: &EpisodeRecord) -> TestResult<ContentDigest> {
    Ok(crate::deployment_session::publish_record(
        root,
        &memory_slot("episode", &record.episode.episode_id)?,
        "agent-episode",
        &record.to_bytes(),
        &[b"{}".to_vec()],
        None,
    )?
    .root)
}

fn publish_plan_for(
    root: &Path,
    episode: &EpisodeRecord,
) -> TestResult<(PlanRecord, ContentDigest)> {
    let rendering = b"{}";
    let plan = PlanRecord {
        plan_id: episode.plan_id.clone(),
        session_id: episode.episode.session_id.clone(),
        mission_id: episode.mission_id.clone(),
        principal: episode.principal.clone(),
        anchor_token: "anchor:historical-fixture".to_owned(),
        intent: "alert".to_owned(),
        event_id: "event:repeated-delivery-failure".to_owned(),
        event_revision: ContentDigest::sha256(b"historical event revision"),
        route: crate::deployment_session::plan::AlertRoute {
            relay: "127.0.0.1:9".to_owned(),
            path: "/private-relay-path".to_owned(),
            plaintext_approval: ContentDigest::sha256(b"historical route approval"),
            deadline_ms: 100,
        },
        operation_id: episode.operation_id.clone(),
        obligation_id: "obligation:fixture".to_owned(),
        plan_approval: ContentDigest::sha256(b"historical plan approval"),
        control_plan_digest: ContentDigest::sha256(rendering),
        case: None,
        created_at: TimestampNs(0),
    };
    let root = crate::deployment_session::plan::publish_plan(root, &plan, rendering)?;
    Ok((plan, root))
}

#[test]
fn decay_weight_halves_deterministically_at_each_half_life() {
    let t0 = 1_000_000_000_000_i128;
    assert_eq!(
        compute_decay_weight_ppm(t0, t0, TRAUMA_HALF_LIFE_NS),
        1_000_000
    );
    assert_eq!(
        compute_decay_weight_ppm(t0 + TRAUMA_HALF_LIFE_NS, t0, TRAUMA_HALF_LIFE_NS),
        500_000
    );
    assert_eq!(
        compute_decay_weight_ppm(t0 + 2 * TRAUMA_HALF_LIFE_NS, t0, TRAUMA_HALF_LIFE_NS),
        250_000
    );
    assert_eq!(
        compute_decay_weight_ppm(t0 + TRAUMA_HALF_LIFE_NS / 2, t0, TRAUMA_HALF_LIFE_NS),
        750_000
    );
}

#[test]
fn owners_are_excluded_before_threshold_grouping_but_own_history_survives_sessions() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    let foreign = PrincipalId::parse("principal:foreign-memory")?;
    let foreign_a = publish_feedback(&fixture.0, &proposal(&foreign, "foreign-a")?)?;
    let foreign_b = publish_feedback(&fixture.0, &proposal(&foreign, "foreign-b")?)?;
    let own_a = proposal(&owner, "own-a")?;
    let own_a_root = publish_feedback(&fixture.0, &own_a)?;
    assert!(derive_trauma_guard_warnings(&fixture.0, &owner, 10)?.is_empty());
    let own_b = proposal(&owner, "own-b")?;
    let own_b_root = publish_feedback(&fixture.0, &own_b)?;
    let warnings = derive_trauma_guard_warnings(&fixture.0, &owner, 10)?;
    assert_eq!(warnings.len(), 1);
    let warning = &warnings[0];
    warning.validate()?;
    assert_eq!(warning.negative_count, 2);
    assert_eq!(
        warning.cited_record_ids,
        vec![own_a.feedback_id, own_b.feedback_id]
    );
    assert_eq!(warning.decay_weight_ppm, 2_000_000);
    assert!(warning.cited_evidence_digests.contains(&own_a_root));
    assert!(warning.cited_evidence_digests.contains(&own_b_root));
    assert!(!warning.cited_evidence_digests.contains(&foreign_a));
    assert!(!warning.cited_evidence_digests.contains(&foreign_b));
    assert!(!warning.summary().contains("foreign"));
    assert!(!warning.active_policy_mutation);
    let aged = derive_trauma_guard_warnings(&fixture.0, &owner, 10 + TRAUMA_HALF_LIFE_NS)?;
    assert_eq!(aged[0].warning_id, warning.warning_id);
    assert_eq!(aged[0].decay_weight_ppm, 1_000_000);
    assert_ne!(aged[0].canonical_digest(), warning.canonical_digest());
    Ok(())
}

#[test]
fn corrupt_memory_is_refused_even_when_inspection_omits_its_visible_root() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    let first = proposal(&owner, "corrupt-a")?;
    let second = proposal(&owner, "corrupt-b")?;
    publish_feedback(&fixture.0, &first)?;
    publish_feedback(&fixture.0, &second)?;
    assert_eq!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10)?.len(),
        1
    );
    let digest = ContentDigest::sha256(&second.try_canonical_bytes()?);
    let object = fixture
        .0
        .join(PUBLICATIONS_RELPATH)
        .join("spool")
        .join("objects")
        .join(hex(digest));
    assert!(object.is_file());
    fs::write(&object, b"corrupt retained metadata")?;
    assert!(matches!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    Ok(())
}

#[test]
fn missing_directory_is_empty_but_a_non_directory_is_an_explicit_refusal() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    assert!(derive_trauma_guard_warnings(&fixture.0, &owner, 10)?.is_empty());
    fs::create_dir_all(fixture.0.join("agent"))?;
    fs::write(
        fixture.0.join(PUBLICATIONS_RELPATH),
        b"not a publication directory",
    )?;
    assert!(matches!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    Ok(())
}

#[test]
fn foreign_failed_episode_is_excluded_before_missing_plan_resolution() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    let foreign = PrincipalId::parse("principal:foreign-memory")?;
    publish_episode(&fixture.0, &failed_episode(&foreign, "foreign-failure")?)?;
    assert!(derive_trauma_guard_warnings(&fixture.0, &owner, 10)?.is_empty());
    publish_episode(&fixture.0, &failed_episode(&owner, "owned-failure")?)?;
    assert!(matches!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    Ok(())
}

#[test]
fn failed_episodes_bind_exact_plan_metadata_and_preserve_all_source_roots() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    let mut expected_roots = BTreeSet::new();
    for identity in ["failure-one", "failure-two"] {
        let mut episode = failed_episode(&owner, identity)?;
        let (plan, publication_root) = publish_plan_for(&fixture.0, &episode)?;
        let metadata = ContentDigest::sha256(&plan.to_bytes());
        assert_ne!(metadata, publication_root);
        episode.episode.plan_digest = metadata.to_text();
        episode.episode.decision_digest = plan.control_plan_digest.to_text();
        expected_roots.extend([
            metadata,
            publication_root,
            plan.control_plan_digest,
            publish_episode(&fixture.0, &episode)?,
        ]);
    }
    let warnings = derive_trauma_guard_warnings(&fixture.0, &owner, 10)?;
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].negative_count, 2);
    assert_eq!(warnings[0].cause_class, AttributionCauseClass::Execution);
    assert_eq!(
        warnings[0]
            .cited_evidence_digests
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        expected_roots
    );
    assert!(!warnings[0].summary().contains("127.0.0.1"));
    assert!(!warnings[0].summary().contains("private-relay-path"));

    // A publication root cannot be substituted for the exact metadata digest that the native
    // episode producer binds, even when every object separately verifies.
    let mut mismatch = failed_episode(&owner, "failure-mismatch")?;
    let (_, publication_root) = publish_plan_for(&fixture.0, &mismatch)?;
    mismatch.episode.plan_digest = publication_root.to_text();
    publish_episode(&fixture.0, &mismatch)?;
    assert!(matches!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    Ok(())
}

#[test]
fn unsupported_privacy_and_source_materialization_exhaustion_are_not_empty_history() -> TestResult {
    let fixture = Fixture::new()?;
    let owner = owner()?;
    let mut restricted = proposal(&owner, "restricted")?;
    restricted.privacy_class = FeedbackPrivacyClass::Restricted;
    let root = publish_feedback(&fixture.0, &restricted)?;
    assert!(matches!(
        derive_trauma_guard_warnings(&fixture.0, &owner, 10),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    let mut reader = MemoryReader {
        directory: fixture.0.join(PUBLICATIONS_RELPATH),
        remaining_bytes: 1,
    };
    assert!(reader.record(root).is_err());
    Ok(())
}
