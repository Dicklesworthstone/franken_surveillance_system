#![forbid(unsafe_code)]
//! Historical native diagnostics gate both alert surfaces and preserve uncommitted work.
//! Every event comes from real retained JPEG decoding, tracking and two-camera corroboration.

use super::*;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, EffectState, EventId, EventState, OperationId, OperationReceipt, SensorId,
};
use fss_reference::ingest::historical_health::{HistoricalHealthRecord, HistoricalHealthRetention};
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::sensor_health::HealthFinding;
use fss_reference::{
    MAX_ALERT_HEALTH_OBJECT_BYTES, ReferenceDeployment, ReferenceError, ReferencePolicyAction,
    ReferencePolicyDecision, ReplayCx, check_alert_historical_health,
};

const MOVING_FRAMES: usize = 14;
const FROZEN_TAIL: usize = 12;

#[derive(Clone, Copy)]
enum Tail {
    Frozen,
    Refused,
}

impl Tail {
    fn count(self) -> usize {
        match self {
            Self::Frozen => FROZEN_TAIL,
            Self::Refused => 1,
        }
    }

    fn tolerant(self) -> bool {
        matches!(self, Self::Refused)
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:native-alert-health".into(),
        operation_id: OperationId::parse("operation:native-alert-health")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn with_deployment<T>(
    root: &Path,
    work: impl FnOnce(&mut ReferenceDeployment, &ReplayCx) -> TestResult<T>,
) -> TestResult<T> {
    let cx = context(root)?;
    let result = (|| {
        let mut deployment = ReferenceDeployment::open(root, SITE, &cx)?;
        work(&mut deployment, &cx)
    })();
    cx.drain_and_finalize();
    result
}

fn import_bytes(
    directory: &OwnedDirectory,
    label: &str,
    sensor: &str,
    capture_start: u128,
    bytes: &[u8],
) -> TestResult<ContentDigest> {
    let input = directory.0.join(format!("{label}.mjpeg"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args([
            "--receive-time-ns",
            &now_ns()?.to_string(),
            "--media-format",
            "mjpeg",
        ])
        .args(["--capture-start-ns", &capture_start.to_string()])
        .args(["--capture-uncertainty-ns", "1000000", "--assumed-fps", "10"])
        .output()?;
    success(&output);
    let identity = String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("retained import identity")?;
    fs::remove_file(input)?;
    Ok(ContentDigest::parse(&identity)?)
}

struct Fixture {
    directory: OwnedDirectory,
    event_id: String,
    revision: ContentDigest,
    east: ContentDigest,
    capture_start: u128,
    tail: Tail,
}

impl Fixture {
    fn new(label: &str, tail: Tail) -> TestResult<Self> {
        let directory = OwnedDirectory::new(label)?;
        let capture_start = now_ns()? - 10_000_000_000;
        let mut east_bytes = scene(true)?;
        let last = east_bytes
            .windows(2)
            .rposition(|marker| marker == [0xff, 0xd8])
            .ok_or("last native JPEG")?;
        let mut tail_frame = east_bytes[last..].to_vec();
        if tail.tolerant() {
            let sof = tail_frame
                .windows(2)
                .position(|marker| marker == [0xff, 0xc0])
                .ok_or("baseline JPEG frame header")?;
            tail_frame[sof + 1] = 0xc2;
        }
        for _ in 0..tail.count() {
            east_bytes.extend_from_slice(&tail_frame);
        }
        let east = import_bytes(
            &directory,
            "east",
            "sensor:east",
            capture_start,
            &east_bytes,
        )?;
        let west = import_bytes(
            &directory,
            "west",
            "sensor:west",
            capture_start,
            &scene(false)?,
        )?;
        let east_arg = format!("east:{east}");
        let west_arg = format!("west:{west}");
        let west_ground = format!("west:{MIRROR}");
        let corroborate = |extra: &[&str]| -> TestResult<Output> {
            let mut args = vec![
                "--camera",
                east_arg.as_str(),
                "--camera",
                west_arg.as_str(),
                "--ground",
                "east:1,0,0,0,1,0,0,0,1",
                "--ground",
                west_ground.as_str(),
                "--zone",
                "door:56,0,40,48",
                "--interpretation",
                "gray",
                "--time-gate-ns",
                "250000000",
                "--distance-gate",
                "16",
            ];
            if tail.tolerant() {
                args.push("--tolerate-decode-refusals");
            }
            args.extend_from_slice(extra);
            event(&directory.root(), "corroborate", &args)
        };
        let preview = corroborate(&[])?;
        success(&preview);
        let approval = report_field(&preview, "proposal_digest")?;
        let published = corroborate(&["--approve", &approval])?;
        success(&published);
        let event_id = report_field(&published, "event_id")?;
        let revision = with_deployment(&directory.root(), |deployment, _| {
            let (event, receipt) =
                deployment.current_event_authority(&EventId::parse(&event_id)?)?;
            assert_eq!(event.state, EventState::Corroborated);
            assert!(
                event
                    .evidence
                    .iter()
                    .filter(|edge| edge.supports && edge.capsule_digest.is_some())
                    .count()
                    >= 2,
                "the regression requires real source capsules from both cameras",
            );
            assert!(
                event.interval.latest.0
                    < i128::try_from(capture_start)? + MOVING_FRAMES as i128 * 100_000_000
                        - 1_000_000,
                "the supported event precedes the diagnostic-only tail",
            );
            Ok(receipt.event_revision_digest)
        })?;
        Ok(Self {
            directory,
            event_id,
            revision,
            east,
            capture_start,
            tail,
        })
    }

    fn root(&self) -> PathBuf {
        self.directory.root()
    }

    fn retain(
        &self,
        import: ContentDigest,
        first: usize,
        count: usize,
        tolerant: bool,
    ) -> TestResult<(HistoricalHealthRetention, HistoricalHealthRecord)> {
        with_deployment(&self.root(), |deployment, cx| {
            let effects = deployment.effects().last_root();
            let report = LongWatchReport::analyze_screened(
                deployment,
                &WatchPlan {
                    import_identity: import,
                    interpretation: ComponentInterpretation::Grayscale,
                    first_segment: first,
                    segment_count: count,
                    zones: vec![WatchZone {
                        zone_id: "native-view".into(),
                        x: 0,
                        y: 0,
                        width: 96,
                        height: 48,
                    }],
                    detector: WatchDetectorConfig::default(),
                    tracker: WatchTrackerConfig::default(),
                },
                WatchOptions {
                    tolerate_decode_refusals: tolerant,
                },
                &LongDwellLimits::default(),
                cx,
            )?;
            let diagnostic = report
                .health_diagnostic()
                .ok_or("native health diagnostic")?;
            let record = diagnostic.record().clone();
            let retained = diagnostic.retain(deployment, diagnostic.approval_digest(), cx)?;
            assert_eq!(deployment.effects().last_root(), effects);
            let (_, current) =
                deployment.current_event_authority(&EventId::parse(&self.event_id)?)?;
            assert_eq!(current.event_revision_digest, self.revision);
            Ok((retained, record))
        })
    }

    fn retain_adverse(&self) -> TestResult<(HistoricalHealthRetention, HistoricalHealthRecord)> {
        let result = self.retain(
            self.east,
            0,
            MOVING_FRAMES + self.tail.count(),
            self.tail.tolerant(),
        )?;
        match self.tail {
            Tail::Frozen => {
                assert!(result.1.summary().complete());
                assert!(result.1.summary().findings().iter().any(|finding| {
                    finding.finding == HealthFinding::ExactFrameRepetition
                        && finding.first_segment >= MOVING_FRAMES as u64
                }));
            }
            Tail::Refused => {
                assert!(!result.1.summary().complete());
                assert_eq!(result.1.summary().frames_screened(), MOVING_FRAMES);
                assert!(result.1.summary().findings().is_empty());
            }
        }
        Ok(result)
    }

    fn snapshot(&self) -> TestResult<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root().join("ledger/journal.fssj"))?,
            fs::read(self.root().join("effects/journal.fssj"))?,
        ))
    }
}

fn native_alert(fixture: &Fixture, relay: &Relay, extra: &[&str]) -> TestResult<Output> {
    let address = relay.address.to_string();
    let plaintext = plaintext_approval();
    let mut args = vec![
        "--event-id",
        &fixture.event_id,
        "--relay",
        &address,
        "--path",
        "/fss/alert",
        "--plaintext-approval",
        &plaintext,
        "--deadline-ms",
        "5000",
    ];
    args.extend_from_slice(extra);
    event(&fixture.root(), "alert", &args)
}

fn native_refused(output: Output) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a refusal must not release a proposed or prepared report"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("refusal_id=ERR-ALERT-NOT-ELIGIBLE-001"),
        "{error}",
    );
}

fn agent_refused(answer: (Option<i32>, Value)) -> TestResult {
    assert_eq!(answer.0, Some(5), "{:?}", answer.1);
    assert_eq!(text(&answer.1, &["errorId"])?, "ERR-ALERT-NOT-ELIGIBLE-001");
    Ok(())
}

fn operation(root: &Path, id: &str) -> TestResult<OperationReceipt> {
    with_deployment(root, |deployment, _| {
        Ok(deployment
            .effects()
            .operation(&OperationId::parse(id)?)
            .ok_or("retained alert operation")?
            .clone())
    })
}

#[test]
fn native_frozen_and_incomplete_sources_refuse_both_preview_and_approved_preparation() -> TestResult
{
    for (label, tail) in [
        ("alert-health-frozen", Tail::Frozen),
        ("alert-health-incomplete", Tail::Refused),
    ] {
        let fixture = Fixture::new(label, tail)?;
        let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
        let agent = Agent::open(&fixture.directory)?;
        let initial = native_alert(&fixture, &relay, &[])?;
        success(&initial);
        let native_approval = report_field(&initial, "plan_digest")?;
        let (code, planned) = agent.plan(&fixture.event_id, relay.address, &[])?;
        assert_eq!(code, Some(0), "{planned:?}");
        let (_, plan_approval, _) = approvals(&planned)?;
        fixture.retain_adverse()?;
        let before = fixture.snapshot()?;

        native_refused(native_alert(&fixture, &relay, &[])?);
        native_refused(native_alert(
            &fixture,
            &relay,
            &["--approve", &native_approval],
        )?);
        agent_refused(agent.plan(&fixture.event_id, relay.address, &[])?)?;
        agent_refused(agent.plan(
            &fixture.event_id,
            relay.address,
            &["--approve", &plan_approval],
        )?)?;
        assert_eq!(fixture.snapshot()?, before);
        assert_eq!(relay.connections(), 0);
        assert_eq!(relay.requests()?, 0);
    }
    Ok(())
}

#[test]
fn health_after_preparation_refuses_both_dispatch_surfaces_and_preserves_explicit_cancellation()
-> TestResult {
    let fixture = Fixture::new("alert-health-prepared", Tail::Frozen)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let agent = Agent::open(&fixture.directory)?;
    let (code, planned) = agent.plan(&fixture.event_id, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let operation_id = operation_of(&planned)?;
    let (code, prepared) =
        agent.plan(&fixture.event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (_, _, dispatch) = approvals(&prepared)?;
    let original = operation(&fixture.root(), &operation_id)?;
    assert_eq!(original.state, EffectState::Prepared);
    assert!(original.committed_at.is_none());

    fixture.retain_adverse()?;
    let before = fixture.snapshot()?;
    agent_refused(agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?)?;
    native_refused(native_alert(
        &fixture,
        &relay,
        &["--approve", &approval, "--dispatch", &dispatch],
    )?);
    assert_eq!(fixture.snapshot()?, before);
    assert_eq!(operation(&fixture.root(), &operation_id)?, original);
    assert_eq!(relay.connections(), 0);
    assert_eq!(relay.requests()?, 0);

    // A health refusal does not invent cancellation evidence or hide the prepared operation.
    let (code, inspected) = agent.run("cancel", &["--operation", &operation_id])?;
    assert_eq!(code, Some(0), "{inspected:?}");
    assert_eq!(text(&inspected, &["payload", "state"])?, "prepared");
    assert_eq!(fixture.snapshot()?, before);
    let cancellation = texts(&inspected, &["proofPointers"])?[0].clone();
    let (code, cancelled) = agent.run(
        "cancel",
        &["--operation", &operation_id, "--approve", &cancellation],
    )?;
    assert_eq!(code, Some(0), "{cancelled:?}");
    assert_eq!(text(&cancelled, &["payload", "state"])?, "cancelled");
    assert_eq!(
        operation(&fixture.root(), &operation_id)?.state,
        EffectState::Cancelled
    );
    let historical = native_alert(&fixture, &relay, &[])?;
    success(&historical);
    assert_eq!(report_field(&historical, "effect_state")?, "cancelled");
    assert_eq!(relay.connections(), 0);
    Ok(())
}

#[test]
fn unrelated_import_and_disjoint_source_scan_do_not_block_an_eligible_native_alert() -> TestResult {
    let fixture = Fixture::new("alert-health-unrelated", Tail::Frozen)?;
    let (_, disjoint) = fixture.retain(fixture.east, MOVING_FRAMES, FROZEN_TAIL, false)?;
    assert!(disjoint.summary().publication_blocked());
    let frame = encode_jpeg(
        96,
        48,
        &vec![88; 96 * 48],
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?;
    let foreign = import_bytes(
        &fixture.directory,
        "other-import-same-sensor",
        "sensor:east",
        fixture.capture_start,
        &frame.repeat(FROZEN_TAIL),
    )?;
    assert_ne!(foreign, fixture.east);
    let (_, other_import) = fixture.retain(foreign, 0, FROZEN_TAIL, false)?;
    assert!(other_import.summary().publication_blocked());
    assert_eq!(other_import.sensor_id(), &SensorId::parse("sensor:east")?);

    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    success(&native_alert(&fixture, &relay, &[])?);
    let agent = Agent::open(&fixture.directory)?;
    let (code, planned) = agent.plan(&fixture.event_id, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let (code, prepared) =
        agent.plan(&fixture.event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (_, _, dispatch) = approvals(&prepared)?;
    let (code, accepted) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(0), "{accepted:?}");
    assert_eq!(text(&accepted, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(relay.requests()?, 1);
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn later_clear_screen_and_missing_or_corrupt_metadata_cannot_restore_alert_eligibility()
-> TestResult {
    let fixture = Fixture::new("alert-health-retained-context", Tail::Frozen)?;
    let (adverse, _) = fixture.retain_adverse()?;
    let (_, clear) = fixture.retain(fixture.east, 0, MOVING_FRAMES, false)?;
    assert_eq!(clear.status(), "no_findings");
    assert!(clear.summary().complete());
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let agent = Agent::open(&fixture.directory)?;
    let before = fixture.snapshot()?;
    native_refused(native_alert(&fixture, &relay, &[])?);
    agent_refused(agent.plan(&fixture.event_id, relay.address, &[])?)?;

    let path = with_deployment(&fixture.root(), |deployment, _| {
        Ok(deployment
            .publisher()
            .spool()
            .object_path(adverse.record_digest))
    })?;
    let original = fs::read(&path)?;
    for missing in [false, true] {
        if missing {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"damaged retained native diagnostic")?;
        }
        native_refused(native_alert(&fixture, &relay, &[])?);
        agent_refused(agent.plan(&fixture.event_id, relay.address, &[])?)?;
        assert_eq!(fixture.snapshot()?, before);
    }
    fs::write(path, original)?;
    native_refused(native_alert(&fixture, &relay, &[])?);
    assert_eq!(fixture.snapshot()?, before);
    assert_eq!(relay.connections(), 0);
    Ok(())
}

#[test]
fn a_new_privacy_generation_cannot_relabel_carried_forward_native_support_as_unscreened()
-> TestResult {
    let fixture = Fixture::new("alert-health-carried-privacy", Tail::Frozen)?;
    let (_, record) = fixture.retain_adverse()?;
    assert_eq!(record.privacy_generation(), None);
    with_deployment(&fixture.root(), |deployment, cx| {
        let (original, _) =
            deployment.current_event_authority(&EventId::parse(&fixture.event_id)?)?;
        let policy =
            PrivacyMaskPolicy::new(SensorId::parse("sensor:east")?, [96, 48], &[[0, 0, 2, 2]])?;
        let approval = preview_mask(deployment, &policy)?.approval;
        declare_mask(deployment, &policy, approval, cx)?;
        let mut revised = original.clone();
        revised.supersedes = Some(original.revision_digest());
        revised.revision += 1;
        assert_eq!(revised.evidence, original.evidence);
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: revised.clone(),
                action: ReferencePolicyAction::PrepareAlert,
            },
            cx,
        )?;
        let effects = deployment.effects().last_root();
        let ledger = deployment.current_anchor().clone();
        let refusal = check_alert_historical_health(deployment.ledger(), &revised, |digest| {
            deployment
                .publisher()
                .spool()
                .read_bounded(digest, MAX_ALERT_HEALTH_OBJECT_BYTES)
                .map_err(|error| {
                    ReferenceError::from(fss_publication::LocalPublicationError::Spool(error))
                })
        });
        assert!(
            matches!(
                refusal,
                Err(ReferenceError::AlertSourceHealth("support_withheld"))
            ),
            "{refusal:?}",
        );
        assert_eq!(deployment.effects().last_root(), effects);
        assert_eq!(deployment.current_anchor(), &ledger);
        Ok(())
    })?;
    Ok(())
}
