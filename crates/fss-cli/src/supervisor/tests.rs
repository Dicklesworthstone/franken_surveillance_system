#![forbid(unsafe_code)]
//! A camera alias must select exactly one sensor; no supplied observation may disappear.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use std::error::Error;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:supervisor-admission";

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        let base = std::env::temp_dir().canonicalize()?;
        for attempt in 0..100 {
            let path = base.join(format!(
                "fss-supervisor-admission-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    _directory: Directory,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:supervisor-admission".into(),
            operation_id: OperationId::parse("operation:supervisor-admission")?,
            principal: "principal:supervisor-admission".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().bytes(1024 * 1024).build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            deployment,
            cx,
            _directory: directory,
        })
    }

    fn plan(&self) -> TestResult<SupervisorPlan> {
        let calibration = ScoreCalibration::from_counts(
            "cal:supervisor-admission",
            &[0, 500_000, 850_000],
            &[(5, 500), (20, 80), (180, 2)],
        )?;
        let first_lo = calibration.bin(900_000).ok_or("score bin")?.llr.lo() * 2;
        Ok(SupervisorPlan {
            site_lineage: SITE.to_owned(),
            hypothesis_id: "hyp:supervisor-admission".into(),
            expected_authority_root: Some(self.deployment.current_anchor().state_root),
            cameras: ["east", "west"]
                .into_iter()
                .map(|alias| SupervisorCameraSpec {
                    camera_id: alias.to_owned(),
                    sensor_id: format!("sensor:{alias}"),
                    failure_domains: BTreeSet::new(),
                })
                .collect(),
            windows: vec![SupervisorWindowSpec {
                window_index: 0,
                timestamp_ns: 1_000_000_000,
                observations: ["east", "west"]
                    .into_iter()
                    .map(|alias| {
                        (
                            alias.to_owned(),
                            SupervisorWindowObservation::CalibratedDetection {
                                score_ppm: 900_000,
                                label: "person".into(),
                                evidence_digest: ContentDigest::sha256(alias.as_bytes()),
                            },
                        )
                    })
                    .collect(),
            }],
            calibration,
            eprocess_config: EProcessConfig {
                alert_threshold_mban: first_lo + 1,
                ceiling_mban: 100_000,
                ..EProcessConfig::default()
            },
            max_work_units: 100,
            work_units_per_camera_window: 10,
            tolerate_corrupt_segments: false,
            cancel_after_window: None,
            stop_on_corroborated_alert: true,
        })
    }

    fn assert_admission_error(&self, plan: &SupervisorPlan, reason: &str) {
        let expected = Err(SupervisorError::InvalidCalibration(reason.to_owned()));
        assert_eq!(
            run_supervisor(&self.deployment, None, &self.cx, plan).map(|_| ()),
            expected
        );
        assert_eq!(
            run_unique_source_supervisor(&self.deployment, None, &self.cx, plan, 2).map(|_| ()),
            expected
        );
    }
}

#[test]
fn duplicate_aliases_cannot_silently_replace_a_distinct_sensor() -> TestResult {
    let fixture = Fixture::new("duplicate-alias")?;
    for reverse in [false, true] {
        let mut plan = fixture.plan()?;
        plan.cameras[1].camera_id = "east".to_owned();
        plan.windows[0].observations.remove("west");
        if reverse {
            plan.cameras.reverse();
        }
        fixture.assert_admission_error(&plan, "camera_id aliases must be unique");

        // Refuse the ambiguous binding before a cancellation report, a budget refusal or
        // score evaluation can mask it. No usable sensor was selected by this invalid plan.
        plan.cancel_after_window = Some(0);
        plan.max_work_units = 0;
        plan.windows[0].observations.insert(
            "east".into(),
            SupervisorWindowObservation::CalibratedDetection {
                score_ppm: 1_000_001,
                label: "person".into(),
                evidence_digest: ContentDigest::sha256(b"invalid-score"),
            },
        );
        fixture.assert_admission_error(&plan, "camera_id aliases must be unique");
    }
    Ok(())
}

#[test]
fn unknown_observation_alias_is_refused_even_beyond_an_early_stop() -> TestResult {
    let fixture = Fixture::new("unknown-alias")?;
    let mut plan = fixture.plan()?;
    let mut later = plan.windows[0].clone();
    later.window_index = 1;
    later.timestamp_ns += 100_000_000;
    later.observations.insert(
        "west-typo".into(),
        SupervisorWindowObservation::CorruptSegment {
            reason: "must not silently drop this source".into(),
        },
    );
    plan.windows.push(later);
    plan.eprocess_config.alert_threshold_mban -= 1;
    fixture.assert_admission_error(&plan, "observation camera_id must name a configured camera");
    plan.cancel_after_window = Some(0);
    fixture.assert_admission_error(&plan, "observation camera_id must name a configured camera");
    Ok(())
}

#[test]
fn valid_two_camera_inputs_keep_canonical_reports_in_both_profiles() -> TestResult {
    let fixture = Fixture::new("valid-pair")?;
    let plan = fixture.plan()?;
    let first_lo = plan.calibration.bin(900_000).ok_or("score bin")?.llr.lo() * 2;
    let legacy = run_supervisor(&fixture.deployment, None, &fixture.cx, &plan)?;
    let unique = run_unique_source_supervisor(&fixture.deployment, None, &fixture.cx, &plan, 2)?;
    for report in [&legacy, unique.report()] {
        assert_eq!(report.status, "completed_monitoring");
        assert_eq!(report.windows_evaluated, 1);
        assert_eq!(report.work_units_consumed, 20);
        assert_eq!(report.independent_supporting_clusters, 2);
        assert_eq!(report.final_accumulated_llr.lo(), first_lo);
    }
    assert_eq!(unique.sources_seen(), 2);

    let mut reordered = plan;
    reordered.cameras.reverse();
    let reversed = run_supervisor(&fixture.deployment, None, &fixture.cx, &reordered)?;
    let reversed_unique =
        run_unique_source_supervisor(&fixture.deployment, None, &fixture.cx, &reordered, 2)?;
    assert_eq!(legacy.receipt_digest, reversed.receipt_digest);
    assert_eq!(legacy.transcript_digest, reversed.transcript_digest);
    assert_eq!(unique.receipt_digest(), reversed_unique.receipt_digest());
    Ok(())
}
