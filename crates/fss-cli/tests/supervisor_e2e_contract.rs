#![forbid(unsafe_code)]
//! End-to-end contract tests for the bounded multi-camera supervisor loop (`fss-becce` / `fss-wbt3y` /
//! `GOAL-003` / `NS-1`).
//!
//! Verifies:
//! 1. 3-camera deterministic simulation (`east`, `west`, and degraded/occluded `south` per `NS-1`)
//!    reaching corroborated alert readiness within `<= 1.5s` latency over `fss-event supervise`.
//! 2. Optional-stopping Ville maximal inequality bound and `NEG-004` single-domain / shared
//!    common-cause non-corroboration across sequential windows.
//! 3. Cooperative `request -> drain -> finalize` cancellation leaving zero orphan obligations and
//!    zero uncommitted staging artifacts.
//! 4. Failure-first refusals: `WorkBudgetExceeded`, `CorruptInput`, `StaleAuthorityAnchor`, and
//!    `InsufficientCameras` / `DuplicateSensor`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use fss_cli::json_input::parse;
use fss_cli::supervisor::{
    ERR_SUPERVISOR_BUDGET_EXCEEDED, ERR_SUPERVISOR_CORRUPT_INPUT, ERR_SUPERVISOR_DUPLICATE_SENSOR,
    ERR_SUPERVISOR_INSUFFICIENT_CAMERAS, ERR_SUPERVISOR_STALE_ANCHOR, SupervisorCameraSpec,
    SupervisorPlan, SupervisorWindowObservation, SupervisorWindowSpec, run_supervisor,
};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_fusion::{EProcessConfig, ScoreCalibration};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:supervisor-e2e";

fn emit_log(step: &str, case: &str, outcome: &str) {
    println!(
        "{{\"bead\":\"fss-wbt3y\",\"step\":\"{step}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"verdict\":\"valid\"}}"
    );
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        let base = std::env::temp_dir().canonicalize()?;
        for attempt in 0..100_u32 {
            let path = base.join(format!(
                "fss-supervisor-e2e-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_cx(dir: &OwnedDirectory) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:supervisor-test".into(),
        operation_id: OperationId::parse("operation:supervisor-test")?,
        principal: "principal:supervisor-test".into(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, dir.root())?)
}

fn initialize_deployment(dir: &OwnedDirectory) -> TestResult<ReferenceDeployment> {
    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let pixels = vec![64_u8; 32 * 32];
    let frame = encode_jpeg(32, 32, &pixels, &config)?;
    let input = dir.0.join("seed.mjpeg");
    fs::write(&input, frame)?;

    let out = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(dir.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args([
            "--sensor",
            "sensor:east",
            "--stream",
            "stream:east",
            "--receive-time-ns",
            "1000000000",
            "--media-format",
            "mjpeg",
        ])
        .output()?;
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let cx = make_cx(dir)?;
    Ok(ReferenceDeployment::open(&dir.root(), SITE, &cx)?)
}

fn sample_calibration() -> ScoreCalibration {
    ScoreCalibration::from_counts(
        "cal:yolox-nano:site-v1",
        &[0, 500_000, 850_000],
        &[(5, 500), (20, 80), (180, 2)],
    )
    .expect("valid sample calibration")
}

fn three_cameras() -> Vec<SupervisorCameraSpec> {
    vec![
        SupervisorCameraSpec {
            camera_id: "east".to_owned(),
            sensor_id: "sensor:east".to_owned(),
            failure_domains: BTreeSet::new(),
        },
        SupervisorCameraSpec {
            camera_id: "west".to_owned(),
            sensor_id: "sensor:west".to_owned(),
            failure_domains: BTreeSet::new(),
        },
        SupervisorCameraSpec {
            camera_id: "south".to_owned(),
            sensor_id: "sensor:south".to_owned(),
            failure_domains: BTreeSet::new(),
        },
    ]
}

#[test]
fn ns1_multi_camera_supervisor_corroborates_under_1500ms_and_cli_matches() -> TestResult {
    let dir = OwnedDirectory::new("ns1-corroborate")?;
    let deployment = initialize_deployment(&dir)?;
    let cal = sample_calibration();
    let ev_east = ContentDigest::sha256(b"east-window-0-detection");
    let ev_west = ContentDigest::sha256(b"west-window-1-detection");

    let mut w0_obs = BTreeMap::new();
    w0_obs.insert(
        "east".to_owned(),
        SupervisorWindowObservation::CalibratedDetection {
            score_ppm: 920_000,
            label: "person".to_owned(),
            evidence_digest: ev_east,
        },
    );
    w0_obs.insert(
        "south".to_owned(),
        SupervisorWindowObservation::HealthDegraded {
            reason: "flat_dark_field".to_owned(),
        },
    );

    let mut w1_obs = BTreeMap::new();
    w1_obs.insert(
        "west".to_owned(),
        SupervisorWindowObservation::CalibratedDetection {
            score_ppm: 910_000,
            label: "person".to_owned(),
            evidence_digest: ev_west,
        },
    );
    w1_obs.insert(
        "south".to_owned(),
        SupervisorWindowObservation::Occluded {
            reason: "foliage_occlusion".to_owned(),
        },
    );

    let plan = SupervisorPlan {
        site_lineage: SITE.to_owned(),
        hypothesis_id: "hyp:zone:door:entry".to_owned(),
        expected_authority_root: Some(deployment.current_anchor().state_root),
        cameras: three_cameras(),
        windows: vec![
            SupervisorWindowSpec {
                window_index: 0,
                timestamp_ns: 1_000_000_000,
                observations: w0_obs,
            },
            SupervisorWindowSpec {
                window_index: 1,
                timestamp_ns: 1_200_000_000,
                observations: w1_obs,
            },
        ],
        calibration: cal.clone(),
        eprocess_config: EProcessConfig {
            alert_threshold_mban: 1_800,
            floor_mban: 0,
            ceiling_mban: 10_000,
            min_independent_clusters: 2,
        },
        max_work_units: 1_000,
        work_units_per_camera_window: 10,
        tolerate_corrupt_segments: false,
        cancel_after_window: None,
        stop_on_corroborated_alert: true,
    };

    let cx = make_cx(&dir)?;
    let report = run_supervisor(&deployment, Some(&dir.root()), &cx, &plan)?;

    assert_eq!(report.status, "corroborated_alert_warranted");
    assert_eq!(report.windows_evaluated, 2);
    assert_eq!(report.corroborated_at_window, Some(1));
    assert_eq!(report.independent_supporting_clusters, 2);
    assert!(report.final_accumulated_llr.lo() >= 1_800);
    assert!(
        report.ville_false_alarm_bound_ppm <= report.threshold_ville_bound_ppm,
        "Ville false-alarm bound {} must be <= threshold bound {}",
        report.ville_false_alarm_bound_ppm,
        report.threshold_ville_bound_ppm
    );
    assert!(
        report.elapsed_ns <= 1_500_000_000,
        "NS-1 supervisor loop latency {} ns exceeded 1.5s budget",
        report.elapsed_ns
    );
    emit_log("ns1_simulation", "three_camera_with_degraded_south", "ok");

    // Verify CLI `fss-event supervise --plan` execution produces the exact same receipt_digest
    let plan_json = format!(
        r#"{{"schema":"fss.supervisor_plan.v1","hypothesis_id":"hyp:zone:door:entry","expected_authority_root":"{}","max_work_units":1000,"work_units_per_camera_window":10,"tolerate_corrupt_segments":false,"stop_on_corroborated_alert":true,"eprocess":{{"alert_threshold_mban":1800,"floor_mban":0,"ceiling_mban":10000,"min_independent_clusters":2}},"score_calibration":{{"schema":"fss.score_calibration.v1","generation":"{}","digest":"{}","bins":[{{"lo_ppm":0,"true_positives":5,"false_positives":500}},{{"lo_ppm":500000,"true_positives":20,"false_positives":80}},{{"lo_ppm":850000,"true_positives":180,"false_positives":2}}]}},"cameras":[{{"camera_id":"east","sensor_id":"sensor:east","failure_domains":[]}},{{"camera_id":"west","sensor_id":"sensor:west","failure_domains":[]}},{{"camera_id":"south","sensor_id":"sensor:south","failure_domains":[]}}],"windows":[{{"window_index":0,"timestamp_ns":1000000000,"observations":{{"east":{{"kind":"calibrated_detection","score_ppm":920000,"label":"person","evidence_digest":"{}"}},"south":{{"kind":"health_degraded","reason":"flat_dark_field"}}}}}},{{"window_index":1,"timestamp_ns":1200000000,"observations":{{"west":{{"kind":"calibrated_detection","score_ppm":910000,"label":"person","evidence_digest":"{}"}},"south":{{"kind":"occluded","reason":"foliage_occlusion"}}}}}}]}}"#,
        deployment.current_anchor().state_root.to_text(),
        cal.generation,
        cal.digest.to_text(),
        ev_east.to_text(),
        ev_west.to_text()
    );
    let plan_file = dir.0.join("plan.json");
    let report_out = dir.0.join("report_out.json");
    fs::write(&plan_file, plan_json)?;
    // Drop open deployment lock before spawning child CLI process on the same root!
    drop(deployment);

    let cli_out = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--root"])
        .arg(dir.root())
        .args(["--site", SITE, "--plan"])
        .arg(&plan_file)
        .arg("--report-out")
        .arg(&report_out)
        .output()?;
    assert!(
        cli_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&cli_out.stderr)
    );
    let parsed_cli = parse(String::from_utf8(cli_out.stdout)?.trim_end())?;
    let cli_receipt = parsed_cli
        .object()
        .and_then(|o| o.get("receipt_digest"))
        .and_then(|v| v.text())
        .ok_or("missing receipt_digest")?;
    assert_eq!(cli_receipt, report.receipt_digest.to_text());
    assert!(report_out.is_file());
    emit_log("cli_supervise", "receipt_digest_parity", "ok");

    Ok(())
}

#[test]
fn shared_failure_domain_and_optional_stopping_preserve_ville_and_neg_004() -> TestResult {
    let dir = OwnedDirectory::new("neg004-ville")?;
    let deployment = initialize_deployment(&dir)?;
    let cal = sample_calibration();
    let ev = ContentDigest::sha256(b"shared-switch-detection");

    // Both east and west share `network:poe-switch-a`: must form 1 cluster and never corroborate!
    let shared_domain: BTreeSet<String> = ["network:poe-switch-a".to_owned()].into_iter().collect();
    let cameras = vec![
        SupervisorCameraSpec {
            camera_id: "east".to_owned(),
            sensor_id: "sensor:east".to_owned(),
            failure_domains: shared_domain.clone(),
        },
        SupervisorCameraSpec {
            camera_id: "west".to_owned(),
            sensor_id: "sensor:west".to_owned(),
            failure_domains: shared_domain,
        },
    ];

    let mut windows = Vec::new();
    for idx in 0..5_u64 {
        let mut obs = BTreeMap::new();
        obs.insert(
            "east".to_owned(),
            SupervisorWindowObservation::CalibratedDetection {
                score_ppm: 920_000,
                label: "person".to_owned(),
                evidence_digest: ev,
            },
        );
        obs.insert(
            "west".to_owned(),
            SupervisorWindowObservation::CalibratedDetection {
                score_ppm: 920_000,
                label: "person".to_owned(),
                evidence_digest: ev,
            },
        );
        windows.push(SupervisorWindowSpec {
            window_index: idx,
            timestamp_ns: 1_000_000_000 + idx * 100_000_000,
            observations: obs,
        });
    }

    let plan = SupervisorPlan {
        site_lineage: SITE.to_owned(),
        hypothesis_id: "hyp:shared-switch".to_owned(),
        expected_authority_root: None,
        cameras,
        windows,
        calibration: cal,
        eprocess_config: EProcessConfig::default(),
        max_work_units: 1_000,
        work_units_per_camera_window: 10,
        tolerate_corrupt_segments: false,
        cancel_after_window: None,
        stop_on_corroborated_alert: true,
    };

    let cx = make_cx(&dir)?;
    let report = run_supervisor(&deployment, Some(&dir.root()), &cx, &plan)?;

    assert_eq!(report.status, "completed_monitoring");
    assert_eq!(report.corroborated_at_window, None);
    assert_eq!(report.independent_supporting_clusters, 1);
    assert!(report.final_accumulated_llr.lo() >= 1_800);
    emit_log(
        "optional_stopping_neg004",
        "shared_poe_switch_never_corroborates",
        "ok",
    );

    Ok(())
}

#[test]
fn cooperative_cancellation_drains_cleanly_and_failure_cases_refuse() -> TestResult {
    let dir = OwnedDirectory::new("cancel-and-failures")?;
    let deployment = initialize_deployment(&dir)?;
    let cal = sample_calibration();
    let ev = ContentDigest::sha256(b"window-detection");

    let mut obs = BTreeMap::new();
    obs.insert(
        "east".to_owned(),
        SupervisorWindowObservation::CalibratedDetection {
            score_ppm: 900_000,
            label: "person".to_owned(),
            evidence_digest: ev,
        },
    );

    let base_plan = SupervisorPlan {
        site_lineage: SITE.to_owned(),
        hypothesis_id: "hyp:cancel-test".to_owned(),
        expected_authority_root: Some(deployment.current_anchor().state_root),
        cameras: three_cameras(),
        windows: vec![
            SupervisorWindowSpec {
                window_index: 0,
                timestamp_ns: 1_000_000_000,
                observations: obs.clone(),
            },
            SupervisorWindowSpec {
                window_index: 1,
                timestamp_ns: 1_100_000_000,
                observations: obs,
            },
        ],
        calibration: cal,
        eprocess_config: EProcessConfig::default(),
        max_work_units: 1_000,
        work_units_per_camera_window: 10,
        tolerate_corrupt_segments: false,
        cancel_after_window: Some(1),
        stop_on_corroborated_alert: true,
    };

    let cx = make_cx(&dir)?;

    // 1. Cooperative cancellation after window 0 (`request -> drain -> finalize`)
    let cancelled_report = run_supervisor(&deployment, Some(&dir.root()), &cx, &base_plan)?;
    assert_eq!(cancelled_report.status, "cancelled_drained");
    assert_eq!(cancelled_report.windows_evaluated, 1);
    let receipt = cancelled_report
        .cancellation
        .expect("cancellation receipt present");
    assert_eq!(receipt.requested_at_window, 1);
    assert_eq!(receipt.drained_in_flight_windows, 1);
    assert!(receipt.finalized_cleanly);
    assert!(receipt.zero_orphan_obligations);
    assert!(receipt.zero_staging_artifacts);
    emit_log(
        "cooperative_cancellation",
        "request_drain_finalize_clean",
        "cancelled",
    );

    // 2. Failure-first: WorkBudgetExceeded refusal
    let mut budget_plan = base_plan.clone();
    budget_plan.cancel_after_window = None;
    budget_plan.max_work_units = 20; // 3 cameras * 10 = 30 > 20
    let budget_err = run_supervisor(&deployment, Some(&dir.root()), &cx, &budget_plan)
        .expect_err("must refuse when WorkBudget is exceeded");
    assert_eq!(budget_err.stable_id(), ERR_SUPERVISOR_BUDGET_EXCEEDED);
    emit_log("failure_budget", "work_budget_exceeded", "budget_exhausted");

    // 3. Failure-first: CorruptInput refusal
    let mut corrupt_plan = base_plan.clone();
    corrupt_plan.cancel_after_window = None;
    corrupt_plan.windows[0].observations.insert(
        "west".to_owned(),
        SupervisorWindowObservation::CorruptSegment {
            reason: "truncated_nal_unit".to_owned(),
        },
    );
    let corrupt_err = run_supervisor(&deployment, Some(&dir.root()), &cx, &corrupt_plan)
        .expect_err("must refuse corrupt segment in strict mode");
    assert_eq!(corrupt_err.stable_id(), ERR_SUPERVISOR_CORRUPT_INPUT);
    emit_log("failure_corrupt", "truncated_segment_refused", "error");

    // 4. Failure-first: StaleAuthorityAnchor refusal
    let mut stale_plan = base_plan.clone();
    stale_plan.cancel_after_window = None;
    stale_plan.expected_authority_root = Some(ContentDigest::sha256(b"stale-anchor"));
    let stale_err = run_supervisor(&deployment, Some(&dir.root()), &cx, &stale_plan)
        .expect_err("must refuse stale authority anchor");
    assert_eq!(stale_err.stable_id(), ERR_SUPERVISOR_STALE_ANCHOR);
    emit_log("failure_stale_anchor", "stale_contract_basis_refused", "error");

    // 5. Failure-first: InsufficientCameras & DuplicateSensor (NEG-004)
    let mut single_cam_plan = base_plan.clone();
    single_cam_plan.cameras.truncate(1);
    let single_err = run_supervisor(&deployment, Some(&dir.root()), &cx, &single_cam_plan)
        .expect_err("must refuse single camera");
    assert_eq!(single_err.stable_id(), ERR_SUPERVISOR_INSUFFICIENT_CAMERAS);

    let mut dup_sensor_plan = base_plan;
    dup_sensor_plan.cameras[1].sensor_id = "sensor:east".to_owned();
    let dup_err = run_supervisor(&deployment, Some(&dir.root()), &cx, &dup_sensor_plan)
        .expect_err("must refuse duplicate sensor binding");
    assert_eq!(dup_err.stable_id(), ERR_SUPERVISOR_DUPLICATE_SENSOR);
    emit_log("failure_neg004", "single_or_duplicate_sensor_refused", "error");

    Ok(())
}
