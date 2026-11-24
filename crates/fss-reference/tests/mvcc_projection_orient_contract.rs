#![forbid(unsafe_code)]
//! Integration & differential contract tests verifying Track A3 (`fss-x4a.31.1.3`):
//! - Decoupling `orient` / `query` / `follow` from full-spool `fss doctor` scans;
//! - Epistemic separation between `projection_caught_up` and `DoctorScrubReceipt` (`NeverScrubbed`
//!   never falsely claims `"healthy"`);
//! - Bit-exact `SituationCapsule` and `decisionFingerprint` parity between full-replay
//!   `ReferenceDeployment` and MVCC `ProjectionBridge::orient_decoupled` once scrubbed;
//! - Delete-and-rebuild bit-exact equivalence;
//! - Structured JSONL trace output.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AgentView, BudgetVector, CaptureInterval, ContentDigest, DecisionPath, EventHypothesis,
    EventId, EventKind, EventState, OperationId, PrincipalId, ProbabilityInterval, TimestampNs,
};
use fss_projection_store::{
    EventQueryFilter, FootageQueryFilter, ProjectionRecoveryMode, ProjectionStore, ScrubVerdict,
};
use fss_reference::agent_orient::projection_bridge::{
    PROJECTION_SUBDIR, ProjectionBridge, ScrubStatus,
};
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::doctor::DoctorVerdict;
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mvcc-orient-contract";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-mvcc-orient-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err("could not allocate temp directory".into())
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_cx(root: &std::path::Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:mvcc-orient".to_owned(),
        operation_id: OperationId::parse("operation:mvcc-orient")?,
        principal: "principal:mvcc-orient".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8_192)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn make_event(idx: u64) -> TestResult<EventHypothesis> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:mvcc-orient:{idx:04}"))?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(
            TimestampNs(1_000_000 * i128::from(idx + 1)),
            TimestampNs(1_000_000 * i128::from(idx + 2)),
        )?,
        uncertainty_reason: Some("synthetic motion hypothesis".to_owned()),
        zone_ids: vec![format!("zone:{}", idx % 3)],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.2, 0.8)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"mvcc-orient-policy"),
            fingerprint: ContentDigest::sha256(format!("mvcc-orient-fp-{idx}").as_bytes()),
            abstained: true,
            abstention_reason: Some("reference event".to_owned()),
        },
    };
    event.verify()?;
    Ok(event)
}

#[test]
fn decoupled_mvcc_orient_preserves_epistemic_honesty_matches_full_replay_and_rebuilds_bit_exact()
-> TestResult {
    let temp = TempRoot::new("parity")?;
    let root = temp.0.join("deployment");
    let cx = make_cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    for idx in 0..6_u64 {
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: make_event(idx)?,
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
    }
    drop(deployment);
    cx.drain_and_finalize();

    let limits = OrientLimits::default();
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:mvcc-orient")?,
        budget_tokens: None,
    };

    // 1. Fresh open catches up from canonical ledger; scrub status MUST be NeverScrubbed
    // (never falsely claiming Healthy without a verified scrub receipt!).
    let bridge = ProjectionBridge::open_or_catch_up(&root, &limits)?;
    let unscrubbed_health = bridge.health_view();
    assert!(unscrubbed_health.projection_caught_up);
    assert_eq!(unscrubbed_health.scrub_status, ScrubStatus::NeverScrubbed);
    assert!(unscrubbed_health.scrub_receipt.is_none());
    assert_eq!(
        unscrubbed_health.scrub_status.to_doctor_state(),
        (DoctorVerdict::AttentionRequired, false)
    );

    let (summary, summary_trace) = bridge.orient_summary();
    assert_eq!(summary.total_events, 6);
    assert!(summary.scrub_receipt.is_none());
    let jsonl = summary_trace.to_jsonl();
    assert!(jsonl.contains("\"op\":\"orient_summary\""), "{jsonl}");
    assert!(jsonl.contains("\"mvcc_read_us\":"), "{jsonl}");

    let (unscrubbed_orient, _, _) = bridge.orient_decoupled(&request, &limits)?;
    assert!(
        unscrubbed_orient
            .degradation
            .iter()
            .any(|note| note.contains("full spool doctor was not run")),
        "unscrubbed decoupled orient must state conservative attention verdict explicitly: {:?}",
        unscrubbed_orient.degradation
    );

    // 2. Indexed query_events & follow_since operate O(page)/O(delta) against MVCC store.
    let (ev_page, ev_trace) = bridge.query_events(&EventQueryFilter::default(), 32);
    assert_eq!(ev_page.entries.len(), 6);
    assert!(ev_trace.to_jsonl().contains("\"op\":\"query_events\""));

    let (footage_page, footage_trace) = bridge.query_footage(&FootageQueryFilter::default(), 32);
    assert_eq!(footage_page.entries.len(), 0);
    assert!(
        footage_trace
            .to_jsonl()
            .contains("\"op\":\"query_footage\"")
    );

    let (follow_page, follow_trace) = bridge.follow_since(3, 32)?;
    assert_eq!(follow_page.commits.len(), 3);
    assert!(follow_trace.to_jsonl().contains("\"op\":\"follow_since\""));

    // 3. Explicit out-of-band doctor scrub records an anchor-bound receipt reflecting real doctor state.
    let expected_full_verdict = fss_reference::doctor::inspect_deployment(&root).verdict;
    let receipt = bridge.scrub_and_record_receipt(TimestampNs(99_000_000))?;
    let expected_scrub_verdict = match expected_full_verdict {
        DoctorVerdict::Healthy => ScrubVerdict::Clean,
        DoctorVerdict::AttentionRequired => ScrubVerdict::Degraded,
        DoctorVerdict::Unreadable | DoctorVerdict::NotADeployment => ScrubVerdict::Failed,
    };
    assert_eq!(receipt.verdict, expected_scrub_verdict);
    let expected_scrub_status = match expected_scrub_verdict {
        ScrubVerdict::Clean => ScrubStatus::VerifiedCurrent,
        ScrubVerdict::Degraded => ScrubStatus::ScrubDegraded,
        ScrubVerdict::Failed => ScrubStatus::ScrubFailed,
    };
    let scrubbed_health = bridge.health_view();
    assert_eq!(scrubbed_health.scrub_status, expected_scrub_status);

    // 4. Bit-exact SituationCapsule + decisionFingerprint parity vs full-replay ReferenceDeployment!
    let full_snapshot = read_deployment(&root, &limits)?;
    let full_orient = orient_deployment(&full_snapshot, &request, &limits)?;
    let (decoupled_orient, _, decoupled_trace) = bridge.orient_decoupled(&request, &limits)?;
    assert_eq!(
        decoupled_orient.capsule().decision_fingerprint()?,
        full_orient.capsule().decision_fingerprint()?,
        "decoupled scrubbed orient must match full-replay decisionFingerprint bit-for-bit"
    );
    assert_eq!(
        decoupled_orient.publication.publication_digest, full_orient.publication.publication_digest,
        "decoupled scrubbed orient must match full-replay publication_digest bit-for-bit"
    );
    assert!(
        decoupled_trace
            .to_jsonl()
            .contains("\"op\":\"orient_decoupled\"")
    );

    // 5. Reopening hits LoadedCurrent with 0 replayed ledger batches and retains scrub receipt!
    let reopened = ProjectionBridge::open_or_catch_up(&root, &limits)?;
    assert_eq!(
        reopened.health_view().recovery_mode,
        ProjectionRecoveryMode::LoadedCurrent
    );
    assert_eq!(reopened.health_view().replayed_batches, 0);
    assert_eq!(reopened.health_view().scrub_status, expected_scrub_status);

    // 6. Deleting projections/mvcc and rebuilding yields bit-identical MVCC state_digest!
    let before_digest = reopened.store().snapshot_latest().state_digest();
    assert!(root.join(PROJECTION_SUBDIR).exists());
    let rebuilt = ProjectionBridge::rebuild_from_canonical(&root, &limits)?;
    assert_eq!(
        rebuilt.store().snapshot_latest().state_digest(),
        before_digest,
        "deleted projection store must rebuild to bit-identical state_digest"
    );
    assert_eq!(
        rebuilt.health_view().scrub_status,
        ScrubStatus::NeverScrubbed,
        "freshly rebuilt derived state must NOT fabricate a scrub receipt"
    );
    Ok(())
}

#[test]
fn decoupled_orient_does_not_scan_spool_and_detects_stale_scrub_on_new_commits() -> TestResult {
    let temp = TempRoot::new("stale-scrub")?;
    let root = temp.0.join("deployment");
    let cx = make_cx(&root)?;
    let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    drop(deployment);

    let limits = OrientLimits::default();
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:mvcc-orient")?,
        budget_tokens: None,
    };
    let bridge = ProjectionBridge::open_or_catch_up(&root, &limits)?;
    let receipt = bridge.scrub_and_record_receipt(TimestampNs(100_000_000))?;
    assert_eq!(receipt.verdict, ScrubVerdict::Clean);
    assert_eq!(
        bridge.health_view().scrub_status,
        ScrubStatus::VerifiedCurrent
    );

    // Clean deployment matches Healthy full-replay orient bit-for-bit!
    let full_snapshot = read_deployment(&root, &limits)?;
    let full_orient = orient_deployment(&full_snapshot, &request, &limits)?;
    let (decoupled_orient, _, _) = bridge.orient_decoupled(&request, &limits)?;
    assert_eq!(
        decoupled_orient.capsule().decision_fingerprint()?,
        full_orient.capsule().decision_fingerprint()?
    );

    // Append an event -> ledger advances past the Clean scrub receipt anchor!
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    deployment.publish_event(
        &ReferencePolicyDecision {
            event: make_event(11)?,
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    drop(deployment);
    cx.drain_and_finalize();

    // Incremental catch-up replays ONLY the 1 new batch and classifies the prior scrub as Stale!
    let caught_up = ProjectionBridge::open_or_catch_up(&root, &limits)?;
    assert_eq!(
        caught_up.health_view().recovery_mode,
        ProjectionRecoveryMode::CaughtUpFromSnapshot
    );
    assert_eq!(caught_up.health_view().replayed_batches, 1);
    assert_eq!(
        caught_up.health_view().scrub_status,
        ScrubStatus::VerifiedStale { behind_commits: 1 }
    );
    assert_eq!(
        caught_up.health_view().scrub_status.to_doctor_state(),
        (DoctorVerdict::AttentionRequired, false)
    );
    Ok(())
}
