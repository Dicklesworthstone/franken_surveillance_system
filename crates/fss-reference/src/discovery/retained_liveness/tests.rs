#![forbid(unsafe_code)]
//! Durable outage history, exact retries and the public orientation/follow boundary.
use super::*;
use crate::agent_orient::{OrientLimits, read_deployment};
use crate::discovery::{DeviceCandidate, HostObs, classify_host, dispatch};
use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retained-liveness";
struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-liveness-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(path);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("temporary directory capacity exhausted")?;
        let root = directory.join("deployment");
        let cx = context(root.clone())?;
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            directory,
            root,
            cx,
        })
    }
    fn inventory(&self) -> Test<Vec<RetainedSensorLiveness>> {
        Ok(read_deployment(&self.root, &OrientLimits::default())?.sensor_liveness)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn context(root: PathBuf) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:liveness-test".into(),
        operation_id: OperationId::parse("operation:liveness-test")?,
        principal: "principal:liveness-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(16 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root)?)
}
fn enrollment(last: u8, sensor: &str) -> Test<DeviceEnrollment> {
    Ok(DeviceEnrollment::with_thresholds(
        Ipv4Addr::new(192, 168, 4, last),
        SensorId::parse(sensor)?,
        DeviceClass::Onvif,
        (10, 20),
    )?)
}
fn report(enrollments: &[DeviceEnrollment], fresh: bool) -> DiscoverReport {
    DiscoverReport {
        candidates: enrollments
            .iter()
            .map(|enrollment| {
                let host = HostObs {
                    ip: enrollment.endpoint(),
                    mac: "00:11:22:33:44:55".into(),
                    oui_vendor: Some("cached vendor".into()),
                    open_ports: if fresh { vec![554] } else { Vec::new() },
                    rtt_ms: None,
                };
                let brand = classify_host(&host, &[], None);
                let dispatch = dispatch(&brand);
                DeviceCandidate {
                    host,
                    brand,
                    dispatch,
                }
            })
            .collect(),
        ..DiscoverReport::default()
    }
}
#[test]
fn canonical_decoder_refuses_invented_or_intra_sweep_unobserved_history() -> Test {
    let binding = enrollment(10, "sensor:a")?;
    let mut current = SensorLivenessRecord {
        site: SITE.into(),
        enrollment: binding.clone(),
        generation: 1,
        previous: None,
        sweep_started_ns: 100,
        observed_at_ns: 105,
        last_seen_ns: Some(100),
        last_seen_until_ns: Some(105),
        last_unobserved_ns: None,
        tcp_ports: vec![554],
        beacon_commands: Vec::new(),
    };
    assert_eq!(current.state(), WatchState::Observable);
    SensorLivenessRecord::from_bytes(&current.to_bytes())?;
    // The first retained sweep cannot claim a prior unobserved evaluation.
    current.last_unobserved_ns = Some(99);
    assert!(matches!(
        SensorLivenessRecord::from_bytes(&current.to_bytes()),
        Err(LivenessError::Corrupt)
    ));

    let previous = SensorLivenessRecord {
        site: SITE.into(),
        enrollment: binding,
        generation: 1,
        previous: None,
        sweep_started_ns: 90,
        observed_at_ns: 100,
        last_seen_ns: None,
        last_seen_until_ns: None,
        last_unobserved_ns: Some(100),
        tcp_ports: Vec::new(),
        beacon_commands: Vec::new(),
    };
    SensorLivenessRecord::from_bytes(&previous.to_bytes())?;
    current.generation = 2;
    current.previous = Some(previous.digest());
    current.last_unobserved_ns = Some(100);
    // Adjacent nonoverlapping sweeps legitimately share the previous completion.
    SensorLivenessRecord::from_bytes(&current.to_bytes())?;
    for impossible in [101, 105] {
        current.last_unobserved_ns = Some(impossible);
        assert!(matches!(
            SensorLivenessRecord::from_bytes(&current.to_bytes()),
            Err(LivenessError::Corrupt)
        ));
    }
    Ok(())
}

#[test]
fn cold_restart_keeps_outages_and_network_return_does_not_erase_them() -> Test {
    let f = Fixture::new("restart")?;
    let enrolled = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        100,
        &f.cx,
    )?;
    let stale = retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, false),
        110,
        &f.cx,
    )?;
    assert_eq!(
        stale[0].record.state(),
        WatchState::Silent { silent_for_ns: 10 }
    );
    let dark = retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, false),
        120,
        &f.cx,
    )?;
    assert_eq!(
        dark[0].record.state(),
        WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }
    );
    drop(deployment);
    assert_eq!(f.inventory()?, dark);
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    let restored = retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        130,
        &f.cx,
    )?;
    assert_eq!(restored[0].record.state(), WatchState::Observable);
    assert_eq!(restored[0].record.last_seen_ns(), Some(130));
    assert_eq!(restored[0].record.last_response_latest_ns(), Some(130));
    assert_eq!(restored[0].record.last_unobserved_ns(), Some(120));
    assert_eq!(restored[0].record.fresh_until_ns(), Some(140));
    assert_eq!(
        restored[0].record.previous_digest(),
        Some(dark[0].record.digest())
    );
    assert_eq!(restored[0].record.generation(), 4);
    drop(deployment);
    assert_eq!(f.inventory()?, restored);
    Ok(())
}
#[test]
fn a_long_sweep_cannot_move_an_early_response_to_the_completion_time() -> Test {
    let f = Fixture::new("long-sweep")?;
    let enrolled = vec![enrollment(10, "sensor:a")?];
    let fresh = report(&enrolled, true);
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    let long = retain_discovery_window(&mut deployment, &enrolled, &fresh, 100, 130, &f.cx)?;
    let record = &long[0].record;
    assert!(record.fresh_sighting());
    assert_eq!(record.last_seen_ns(), Some(100));
    assert_eq!(record.last_response_latest_ns(), Some(130));
    assert_eq!(record.fresh_until_ns(), Some(110));
    assert_eq!(
        record.state(),
        WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }
    );
    assert_eq!(record.last_unobserved_ns(), Some(130));
    assert_eq!(
        retain_discovery_window(&mut deployment, &enrolled, &fresh, 100, 130, &f.cx)?,
        long
    );
    assert!(matches!(
        retain_discovery_window(&mut deployment, &enrolled, &fresh, 101, 130, &f.cx),
        Err(LivenessError::ClockOrReplayConflict)
    ));
    let quiet = retain_discovery_window(
        &mut deployment,
        &enrolled,
        &report(&enrolled, false),
        130,
        135,
        &f.cx,
    )?;
    assert_eq!(quiet[0].record.last_seen_ns(), Some(100));
    assert_eq!(quiet[0].record.last_response_latest_ns(), Some(130));
    let short = retain_discovery_window(&mut deployment, &enrolled, &fresh, 140, 145, &f.cx)?;
    assert_eq!(short[0].record.state(), WatchState::Observable);
    assert_eq!(short[0].record.fresh_until_ns(), Some(150));
    assert_eq!(short[0].record.last_unobserved_ns(), Some(135));
    drop(deployment);
    assert_eq!(f.inventory()?, short);
    Ok(())
}
#[test]
fn exact_retry_resumes_a_partially_committed_multi_sensor_sweep() -> Test {
    let f = Fixture::new("partial-retry")?;
    let enrolled = vec![enrollment(10, "sensor:a")?, enrollment(11, "sensor:b")?];
    let fresh = report(&enrolled, true);
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_liveness:commit", 2);
    assert!(matches!(
        retain_discovery_sweep(&mut deployment, &enrolled, &fresh, 100, &f.cx),
        Err(LivenessError::Cancelled)
    ));
    // Both exact roots are already visible; only the first has a liveness authority delta.
    // Retrying the second must reverify publication without restaging its visible manifest.
    assert_eq!(deployment.publisher().visible_roots().count(), 2);
    assert_eq!(
        deployment
            .ledger()
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .filter(|delta| delta.family == FAMILY_SENSOR_LIVENESS)
            .count(),
        1
    );
    drop(deployment);
    let first = f.inventory()?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].record.enrollment().sensor().as_str(), "sensor:a");
    let retry_cx = context(f.root.clone())?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &retry_cx)?;
    let complete = retain_discovery_sweep(&mut deployment, &enrolled, &fresh, 100, &retry_cx)?;
    assert_eq!(complete.len(), 2);
    assert_eq!(complete[0], first[0]);
    assert!(complete.iter().all(|entry| entry.record.generation() == 1));
    let anchor = deployment.current_anchor().clone();
    assert_eq!(
        retain_discovery_sweep(&mut deployment, &enrolled, &fresh, 100, &retry_cx)?,
        complete
    );
    assert_eq!(deployment.current_anchor(), &anchor);
    assert!(matches!(
        retain_discovery_sweep(
            &mut deployment,
            &enrolled,
            &report(&enrolled, false),
            100,
            &retry_cx
        ),
        Err(LivenessError::ClockOrReplayConflict)
    ));
    assert_eq!(deployment.current_anchor(), &anchor);
    drop(deployment);
    retry_cx.drain_and_finalize();
    Ok(())
}
#[test]
fn pending_publication_retry_reverifies_custody_and_does_not_repair_corruption() -> Test {
    let f = Fixture::new("pending-corruption")?;
    let enrolled = vec![enrollment(10, "sensor:a")?];
    let fresh = report(&enrolled, true);
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_liveness:commit", 1);
    assert!(matches!(
        retain_discovery_sweep(&mut deployment, &enrolled, &fresh, 100, &f.cx),
        Err(LivenessError::Cancelled)
    ));
    let pending = deployment
        .publisher()
        .visible_roots()
        .next()
        .ok_or("pending root missing")?
        .clone();
    let record_path = deployment
        .publisher()
        .root_dir()
        .join(fss_publication::LOCAL_ROOTS_DIR)
        .join(format!(
            "{}{}",
            pending.slot,
            fss_publication::ROOT_RECORD_SUFFIX
        ));
    let anchor = deployment.current_anchor().clone();
    // Mutate the test-owned record after this publisher admitted it. Its cached slot
    // metadata must never permit the exact retry to skip on-disk custody verification.
    fs::write(&record_path, b"corrupt pending root")?;
    let retry_cx = context(f.root.clone())?;
    assert!(retain_discovery_sweep(&mut deployment, &enrolled, &fresh, 100, &retry_cx).is_err());
    assert_eq!(deployment.current_anchor(), &anchor);
    assert_eq!(fs::read(&record_path)?, b"corrupt pending root");
    assert!(
        !deployment
            .ledger()
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .any(|delta| delta.family == FAMILY_SENSOR_LIVENESS)
    );
    retry_cx.drain_and_finalize();
    Ok(())
}
#[test]
fn rebound_or_conflicting_enrollment_is_rejected_before_any_publication() -> Test {
    let f = Fixture::new("binding")?;
    let enrolled = vec![enrollment(10, "sensor:a")?];
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        100,
        &f.cx,
    )?;
    let anchor = deployment.current_anchor().clone();
    for conflict in [enrollment(11, "sensor:a")?, enrollment(10, "sensor:b")?] {
        assert!(matches!(
            retain_discovery_sweep(
                &mut deployment,
                &[conflict],
                &DiscoverReport::default(),
                110,
                &f.cx
            ),
            Err(LivenessError::EnrollmentChanged)
        ));
        assert_eq!(deployment.current_anchor(), &anchor);
    }
    assert!(matches!(
        retain_discovery_sweep(
            &mut deployment,
            &enrolled,
            &DiscoverReport::default(),
            99,
            &f.cx
        ),
        Err(LivenessError::ClockOrReplayConflict)
    ));
    assert_eq!(deployment.current_anchor(), &anchor);
    let mut forged = enrolled[0].clone();
    forged.sensor = SensorId::parse("sensor:forged")?;
    let delta = EvidenceDelta {
        delta_id: "delta:forged-liveness".into(),
        family: "unreserved".into(),
        object_id: forged.object_id()?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval {
            earliest: TimestampNs(0),
            latest: TimestampNs(0),
        },
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(b"unretained"),
        witness_digest: None,
        operation_id: None,
    };
    assert!(matches!(
        deployment.append_batch(
            BatchId::parse("batch:forged-liveness")?,
            vec![delta],
            vec![],
            &f.cx
        ),
        Err(crate::ReferenceError::ReservedDeltaFamily { .. })
    ));
    assert_eq!(deployment.current_anchor(), &anchor);
    Ok(())
}
#[test]
fn inventory_corruption_never_falls_back_to_an_older_healthy_generation() -> Test {
    let f = Fixture::new("corrupt")?;
    let enrolled = vec![enrollment(10, "sensor:a")?];
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        100,
        &f.cx,
    )?;
    let latest = retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &DiscoverReport::default(),
        120,
        &f.cx,
    )?;
    let result = read_liveness_inventory(deployment.ledger().batches(), |digest, max| {
        if digest == latest[0].record.digest() {
            return Ok(b"corrupt".to_vec());
        }
        Ok(deployment.publisher().spool().read_bounded(digest, max)?)
    });
    assert!(result.is_err());
    Ok(())
}
#[test]
fn orient_and_follow_pin_network_state_and_keep_the_unobserved_sweep_after_return() -> Test {
    use crate::agent_follow::{
        AnchorToken, DEFAULT_FOLLOW_MAX_ENTRIES, FollowRequest, follow_deployment,
        snapshot_anchor_token,
    };
    use crate::agent_orient::liveness::is_sensor_liveness_claim;
    use crate::agent_orient::{DeploymentHistory, OrientRequest, orient_deployment};
    use fss_core::{AgentView, KnowledgeState, MeaningfulDeltaClass, PrincipalId};
    let f = Fixture::new("orient-follow")?;
    let enrolled = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        100,
        &f.cx,
    )?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, false),
        120,
        &f.cx,
    )?;
    drop(deployment);
    let limits = OrientLimits::default();
    let before = read_deployment(&f.root, &limits)?;
    let since =
        AnchorToken::parse(&snapshot_anchor_token(&before)).ok_or("invalid anchor token")?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &f.cx)?;
    retain_discovery_sweep(
        &mut deployment,
        &enrolled,
        &report(&enrolled, true),
        130,
        &f.cx,
    )?;
    drop(deployment);
    let history = DeploymentHistory::read(&f.root, &limits)?;
    assert_eq!(
        history.snapshot_at(before.position)?.sensor_liveness,
        before.sensor_liveness
    );
    let snapshot = history.snapshot_at(history.head())?;
    let principal = PrincipalId::parse("principal:liveness-test")?;
    let view = orient_deployment(
        &snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: principal.clone(),
            budget_tokens: None,
        },
        &limits,
    )?;
    view.publication.verify()?;
    let claim = view
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| is_sensor_liveness_claim(cell.claim_id()))
        .ok_or("liveness claim missing")?;
    assert_eq!(claim.knowledge_state(), KnowledgeState::Known);
    for literal in [
        "Historical network observation",
        "sweep_started_ns=130",
        "sweep_completed_ns=130",
        "last_response_earliest_ns=130",
        "last_response_latest_ns=130",
        "conservative_grace_until_ns=140",
        "last_unobserved_ns=120",
        "cannot establish pixel continuity",
    ] {
        assert!(claim.statement().contains(literal), "{}", claim.statement());
    }
    assert!(
        !view
            .capsule()
            .frame
            .world_envelope
            .certified_core_claim_ids
            .contains(claim.claim_id())
    );
    assert!(
        view.capsule()
            .frame
            .at_risk
            .iter()
            .any(|risk| risk.contains("last_unobserved_ns=120"))
    );
    assert!(snapshot.operations.is_empty());
    let follow = follow_deployment(
        &history,
        &since,
        &FollowRequest {
            view: AgentView::Brief,
            principal,
            max_entries: DEFAULT_FOLLOW_MAX_ENTRIES,
            continuation: None,
        },
    )?;
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::SensorHealth)
    );
    assert!(
        !follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageRecovery)
    );
    assert!(follow.delta.silence_certificate.is_none());
    Ok(())
}
