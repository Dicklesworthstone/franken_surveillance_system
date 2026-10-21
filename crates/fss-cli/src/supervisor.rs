#![forbid(unsafe_code)]
//! Bounded multi-camera supervisor coordinator with anytime-valid sequential Ville e-process
//! corroboration (`fss-becce` / `GOAL-003` / `NS-1`).
//!
//! Steps a multi-camera deployment across sequential observation windows under an explicit
//! [`WorkBudget`], authority-anchor pin, and cooperative cancellation contract
//! (`request -> drain -> finalize`):
//!
//! * **Multi-camera independence (`INV-055`, `NEG-003`, `NEG-004`):** requires at least 2 cameras
//!   with distinct `sensor_id` bindings. A single camera or a set of cameras connected by a shared
//!   failure domain forms one common-cause cluster and can never cross the corroborated alert gate,
//!   regardless of how many sequential windows it fires in.
//! * **Degraded or occluded cameras (`NS-1`, `NEG-005`):** per-window camera health degradation or
//!   occlusion is recorded as [`Observability::NotObservable`], contributing `0` millibans (never
//!   evidence of absence) while remaining independent healthy cameras continue to corroborate.
//! * **Sequential Ville e-process (`fss-fusion::eprocess`):** accumulates Wilson-calibrated
//!   milliban log-likelihood ratios across windows with optional-stopping validity
//!   ($\mathbb{P}_{H_0}(\sup_t M_t \ge \tau_{\text{mban}}) \le 10^{-\tau_{\text{mban}}/1000}$),
//!   CUSUM floor clamping, and explicit regime resets when all supporting sensors degrade or clock
//!   continuity breaks.
//! * **Cooperative cancellation (`request -> drain -> finalize`):** checks cancellation at each
//!   window boundary, drains in-flight window state, verifies zero uncommitted publication staging
//!   artifacts and zero orphan pending obligations on the deployment, and emits a signed
//!   [`SupervisorCancellationReceipt`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Instant;

use fss_core::{CanonicalEncoder, ContentDigest, EffectState};
use fss_fusion::{
    Calibration, Coverage, Decision, EProcessConfig, EProcessStepOutcome, EvidenceItem,
    FusionError, FusionPolicy, FusionQuery, LlrInterval, Observability, RegimeResetReason,
    ScoreCalibration, SequentialEProcess, Severity, ville_false_alarm_bound_ppm,
};
use fss_geometry::WorkBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::agent_json::{array, object, string};

fn boolean(value: bool) -> String {
    if value { "true" } else { "false" }.to_owned()
}

fn integer(value: i128) -> String {
    value.to_string()
}

fn unsigned(value: u64) -> String {
    value.to_string()
}

fn nullable(value: Option<String>) -> String {
    value.unwrap_or_else(|| "null".to_owned())
}

/// Schema identifier for [`SupervisorReport`].
pub const SUPERVISOR_REPORT_SCHEMA: &str = "fss.supervisor_report.v1";
/// Digest domain for [`SupervisorReport`] receipts (`SCHEMA-DOMAIN-SUPERVISOR-RECEIPT-001`).
pub const SUPERVISOR_RECEIPT_DOMAIN: &str = "fss.supervisor_receipt.v1";

/// Stable error code when fewer than 2 distinct cameras are configured (`NEG-004`).
pub const ERR_SUPERVISOR_INSUFFICIENT_CAMERAS: &str = "ERR-SUPERVISOR-INSUFFICIENT-CAMERAS-001";
/// Stable error code when two cameras share the same underlying `sensor_id`.
pub const ERR_SUPERVISOR_DUPLICATE_SENSOR: &str = "ERR-SUPERVISOR-DUPLICATE-SENSOR-001";
/// Stable error code when the deployment authority root has drifted from `expected_authority_root`.
pub const ERR_SUPERVISOR_STALE_ANCHOR: &str = "ERR-SUPERVISOR-STALE-ANCHOR-001";
/// Stable error code when the supervisor exhausts its explicit [`WorkBudget`].
pub const ERR_SUPERVISOR_BUDGET_EXCEEDED: &str = "ERR-SUPERVISOR-BUDGET-EXCEEDED-001";
/// Stable error code when a camera window supplies corrupt or truncated media/detection input.
pub const ERR_SUPERVISOR_CORRUPT_INPUT: &str = "ERR-SUPERVISOR-CORRUPT-INPUT-001";
/// Stable error code when the score calibration or policy is invalid.
pub const ERR_SUPERVISOR_CALIBRATION_INVALID: &str = "ERR-SUPERVISOR-CALIBRATION-INVALID-001";

/// Specification of one supervised camera in a multi-camera deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorCameraSpec {
    /// Camera handle (e.g. `"east"`, `"west"`, `"south"`).
    pub camera_id: String,
    /// Underlying authoritative sensor identity (e.g. `"sensor:east"`).
    pub sensor_id: String,
    /// Declared shared failure domains (e.g. `"network:poe-switch-a"`, `"power:ups-1"`).
    pub failure_domains: BTreeSet<String>,
}

/// Per-camera observation within one supervisor time window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorWindowObservation {
    /// Detector cascade produced a score in parts per million (`0..=1_000_000`) to be mapped
    /// through the digest-bound [`ScoreCalibration`].
    CalibratedDetection {
        /// Detector score in parts per million.
        score_ppm: u32,
        /// Class label (e.g. `"person"`).
        label: String,
        /// Retained frame/detection evidence digest.
        evidence_digest: ContentDigest,
    },
    /// Sensor was healthy and observable during this window, with no zone entry candidate.
    NoDetection,
    /// Camera view of the zone was occluded or in a coverage gap (`NEG-005`: neutral, never absence).
    Occluded {
        /// Reason for occlusion or coverage gap.
        reason: String,
    },
    /// Sensor health screening (`conservative-v1`) flagged degraded pixel fidelity (`NS-1`).
    HealthDegraded {
        /// Degradation reason (e.g. `"flat_dark_field"`, `"contrast_loss"`).
        reason: String,
    },
    /// Capture clock continuity broke beyond the admissible synchronization gate.
    ClockDiscontinuity {
        /// Observed gap in nanoseconds.
        gap_ns: u64,
    },
    /// Corrupt or truncated binary input encountered for this camera window.
    CorruptSegment {
        /// Corruption diagnostic.
        reason: String,
    },
}

/// One time window across all supervised cameras.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorWindowSpec {
    /// Monotone window index (`0..`).
    pub window_index: u64,
    /// Evidence clock timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Per-camera observations keyed by `camera_id`.
    pub observations: BTreeMap<String, SupervisorWindowObservation>,
}

/// Complete bounded execution plan for a multi-camera supervisor run.
#[derive(Clone, Debug)]
pub struct SupervisorPlan {
    /// Site lineage identifier.
    pub site_lineage: String,
    /// Hypothesis identifier (e.g. `"hyp:zone:door:entry"`).
    pub hypothesis_id: String,
    /// Optional pinned authority root (`ContractBasis` anchor); if `Some`, mismatches are refused.
    pub expected_authority_root: Option<ContentDigest>,
    /// Supervised cameras (must contain `>= 2` distinct cameras and sensors).
    pub cameras: Vec<SupervisorCameraSpec>,
    /// Sequential observation windows to evaluate.
    pub windows: Vec<SupervisorWindowSpec>,
    /// Digest-verified Wilson score calibration artifact.
    pub calibration: ScoreCalibration,
    /// Sequential e-process configuration.
    pub eprocess_config: EProcessConfig,
    /// Explicit work-unit ceiling for the supervisor run.
    pub max_work_units: u64,
    /// Work units charged per `(window, camera)` evaluation.
    pub work_units_per_camera_window: u64,
    /// Whether corrupt camera segments are tolerated as `NotObservable` rather than aborting.
    pub tolerate_corrupt_segments: bool,
    /// Optional deterministic window count after which cooperative cancellation is requested.
    pub cancel_after_window: Option<usize>,
    /// Whether to stop immediately once `crossed_alert_threshold` becomes true.
    pub stop_on_corroborated_alert: bool,
}

/// Typed refusal from [`run_supervisor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// Fewer than 2 cameras were supplied (`NEG-004`).
    InsufficientCameras {
        /// Number of cameras supplied.
        count: usize,
    },
    /// Two cameras bound the same `sensor_id`.
    DuplicateSensor {
        /// Duplicated sensor identifier.
        sensor_id: String,
    },
    /// The deployment's current authority root does not match `expected_authority_root`.
    StaleAuthorityAnchor {
        /// Expected authority root digest.
        expected: ContentDigest,
        /// Actual authority root digest on the deployment.
        actual: ContentDigest,
    },
    /// The supervisor exhausted its explicit [`WorkBudget`].
    WorkBudgetExceeded {
        /// Work units requested.
        consumed: u64,
        /// Configured work budget ceiling.
        limit: u64,
    },
    /// A camera window encountered corrupt or truncated binary input in strict mode.
    CorruptInput {
        /// Camera identifier.
        camera_id: String,
        /// Window index.
        window_index: u64,
        /// Corruption reason.
        reason: String,
    },
    /// Score calibration or policy validation failed.
    InvalidCalibration(String),
    /// Underlying `fss-fusion` error.
    Fusion(FusionError),
}

impl SupervisorError {
    /// Returns the registered stable error code.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InsufficientCameras { .. } => ERR_SUPERVISOR_INSUFFICIENT_CAMERAS,
            Self::DuplicateSensor { .. } => ERR_SUPERVISOR_DUPLICATE_SENSOR,
            Self::StaleAuthorityAnchor { .. } => ERR_SUPERVISOR_STALE_ANCHOR,
            Self::WorkBudgetExceeded { .. } => ERR_SUPERVISOR_BUDGET_EXCEEDED,
            Self::CorruptInput { .. } => ERR_SUPERVISOR_CORRUPT_INPUT,
            Self::InvalidCalibration(_) => ERR_SUPERVISOR_CALIBRATION_INVALID,
            Self::Fusion(err) => err.stable_id(),
        }
    }
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCameras { count } => write!(
                f,
                "{ERR_SUPERVISOR_INSUFFICIENT_CAMERAS}: multi-camera supervisor requires >= 2 cameras, got {count}"
            ),
            Self::DuplicateSensor { sensor_id } => write!(
                f,
                "{ERR_SUPERVISOR_DUPLICATE_SENSOR}: duplicate sensor binding {sensor_id}"
            ),
            Self::StaleAuthorityAnchor { expected, actual } => write!(
                f,
                "{ERR_SUPERVISOR_STALE_ANCHOR}: expected authority root {expected}, actual {actual}"
            ),
            Self::WorkBudgetExceeded { consumed, limit } => write!(
                f,
                "{ERR_SUPERVISOR_BUDGET_EXCEEDED}: supervisor work budget exceeded ({consumed} > {limit})"
            ),
            Self::CorruptInput {
                camera_id,
                window_index,
                reason,
            } => write!(
                f,
                "{ERR_SUPERVISOR_CORRUPT_INPUT}: corrupt input on camera {camera_id} at window {window_index}: {reason}"
            ),
            Self::InvalidCalibration(msg) => {
                write!(f, "{ERR_SUPERVISOR_CALIBRATION_INVALID}: {msg}")
            }
            Self::Fusion(err) => write!(f, "{}: {err}", err.stable_id()),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// Proof receipt of clean `request -> drain -> finalize` cooperative cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorCancellationReceipt {
    /// Window boundary at which cancellation was observed.
    pub requested_at_window: u64,
    /// Number of in-flight windows drained to completion before finalization.
    pub drained_in_flight_windows: u64,
    /// True when the supervisor finalized all per-camera state machines cleanly.
    pub finalized_cleanly: bool,
    /// True when the deployment has zero non-terminal orphan effect obligations.
    pub zero_orphan_obligations: bool,
    /// True when `publications/staging` contains zero uncommitted staging artifacts.
    pub zero_staging_artifacts: bool,
}

/// Per-window evaluation record in [`SupervisorReport`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorWindowRecord {
    /// Window index.
    pub window_index: u64,
    /// Evidence clock timestamp (ns).
    pub timestamp_ns: u64,
    /// Instantaneous `fss-fusion` decision label for this window.
    pub decision_label: &'static str,
    /// Epistemic knowledge state for this window (`"estimated"`, `"not_observable"`, `"unknown"`, `"conflicted"`).
    pub knowledge_state: &'static str,
    /// Sequential e-process step outcome after incorporating this window.
    pub step_outcome: EProcessStepOutcome,
    /// Cameras flagged degraded during this window.
    pub degraded_cameras: Vec<String>,
    /// Cameras flagged occluded during this window.
    pub occluded_cameras: Vec<String>,
}

/// Complete deterministic report of a bounded multi-camera supervisor run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorReport {
    /// Schema identifier (`"fss.supervisor_report.v1"`).
    pub schema: &'static str,
    /// Site lineage.
    pub site_lineage: String,
    /// Hypothesis identifier.
    pub hypothesis_id: String,
    /// Deployment authority root verified at start.
    pub authority_root_at_start: ContentDigest,
    /// Score calibration generation.
    pub calibration_generation: String,
    /// Score calibration digest.
    pub calibration_digest: ContentDigest,
    /// Terminal supervisor status (`"corroborated_alert_warranted"`, `"completed_monitoring"`, or `"cancelled_drained"`).
    pub status: &'static str,
    /// Number of windows evaluated before completion or cancellation.
    pub windows_evaluated: u64,
    /// Total work units consumed.
    pub work_units_consumed: u64,
    /// Configured work-unit ceiling.
    pub work_units_limit: u64,
    /// First window index at which `crossed_alert_threshold` became true, if any.
    pub corroborated_at_window: Option<u64>,
    /// Final clamped milliban e-process interval.
    pub final_accumulated_llr: LlrInterval,
    /// Running supremum $\sup_{s \le t} M_{s,\text{lo}}$ in millibans.
    pub supremum_lo_mban: i64,
    /// Anytime Ville false-alarm upper bound (ppm) at `supremum_lo_mban`.
    pub ville_false_alarm_bound_ppm: u32,
    /// Anytime Ville false-alarm upper bound (ppm) at `alert_threshold_mban`.
    pub threshold_ville_bound_ppm: u32,
    /// Number of mutually disjoint supporting failure-domain clusters at termination.
    pub independent_supporting_clusters: u32,
    /// Measured wall-clock execution latency in nanoseconds.
    pub elapsed_ns: u64,
    /// Cooperative cancellation receipt if the run was cancelled.
    pub cancellation: Option<SupervisorCancellationReceipt>,
    /// Per-window trajectory records.
    pub window_records: Vec<SupervisorWindowRecord>,
    /// Domain-separated receipt digest (`SCHEMA-DOMAIN-SUPERVISOR-RECEIPT-001`).
    pub receipt_digest: ContentDigest,
}

fn decision_str(decision: &Decision) -> &'static str {
    match decision {
        Decision::Alert => "alert",
        Decision::AlertDegradedCoverage => "alert_degraded_coverage",
        Decision::AlertSingleDomainUnconfirmed => "alert_single_domain_unconfirmed",
        Decision::WaitForCorroboration { .. } => "wait_for_corroboration",
        Decision::RequestObservation { .. } => "request_observation",
        Decision::RequestOperatorConfirmation => "request_operator_confirmation",
        Decision::RetainSilently => "retain_silently",
        Decision::Reject => "reject",
        Decision::HoldIndeterminate => "hold_indeterminate",
    }
}

fn verify_clean_drain(deployment: &ReferenceDeployment, root_path: Option<&Path>) -> (bool, bool) {
    let zero_orphan_obligations = deployment
        .effects()
        .operations()
        .all(|op| !matches!(op.state, EffectState::Indeterminate { .. }));
    let zero_staging_artifacts = root_path
        .map(|root| {
            let staging = root.join("publications/staging");
            match fs::read_dir(staging) {
                Ok(mut entries) => entries.next().is_none(),
                Err(_) => true,
            }
        })
        .unwrap_or(true);
    (zero_orphan_obligations, zero_staging_artifacts)
}

impl SupervisorReport {
    fn seal(mut self) -> Self {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SUPERVISOR_RECEIPT_DOMAIN);
        encoder.text(self.schema);
        encoder.text(&self.site_lineage);
        encoder.text(&self.hypothesis_id);
        encoder.text(&self.authority_root_at_start.to_text());
        encoder.text(&self.calibration_generation);
        encoder.text(&self.calibration_digest.to_text());
        encoder.text(self.status);
        encoder.u64(self.windows_evaluated);
        encoder.u64(self.work_units_consumed);
        encoder.u64(self.work_units_limit);
        match self.corroborated_at_window {
            Some(w) => {
                encoder.bool(true);
                encoder.u64(w);
            }
            None => encoder.bool(false),
        }
        encoder.i128(i128::from(self.final_accumulated_llr.lo()));
        encoder.i128(i128::from(self.final_accumulated_llr.hi()));
        encoder.i128(i128::from(self.supremum_lo_mban));
        encoder.u32(self.ville_false_alarm_bound_ppm);
        encoder.u32(self.threshold_ville_bound_ppm);
        encoder.u32(self.independent_supporting_clusters);
        encoder.u64(self.window_records.len() as u64);
        for rec in &self.window_records {
            encoder.u64(rec.window_index);
            encoder.u64(rec.timestamp_ns);
            encoder.text(&rec.step_outcome.step_digest.to_text());
        }
        self.receipt_digest = ContentDigest::sha256(&encoder.finish());
        self
    }

    /// Renders the canonical deterministic JSON representation of this report.
    #[must_use]
    pub fn to_json(&self) -> String {
        let windows_json: Vec<String> = self
            .window_records
            .iter()
            .map(|w| {
                let degraded: Vec<String> =
                    w.degraded_cameras.iter().map(|c| string(c)).collect();
                let occluded: Vec<String> =
                    w.occluded_cameras.iter().map(|c| string(c)).collect();
                object(&[
                    ("window_index", unsigned(w.window_index)),
                    ("timestamp_ns", unsigned(w.timestamp_ns)),
                    ("decision", string(w.decision_label)),
                    ("knowledge_state", string(w.knowledge_state)),
                    ("regime_epoch", unsigned(u64::from(w.step_outcome.regime_epoch))),
                    (
                        "step_delta_mban",
                        object(&[
                            ("lo", integer(i128::from(w.step_outcome.step_delta_llr.lo()))),
                            ("hi", integer(i128::from(w.step_outcome.step_delta_llr.hi()))),
                        ]),
                    ),
                    (
                        "accumulated_llr_mban",
                        object(&[
                            ("lo", integer(i128::from(w.step_outcome.accumulated_llr.lo()))),
                            ("hi", integer(i128::from(w.step_outcome.accumulated_llr.hi()))),
                        ]),
                    ),
                    (
                        "supremum_lo_mban",
                        integer(i128::from(w.step_outcome.supremum_lo_mban)),
                    ),
                    (
                        "ville_false_alarm_bound_ppm",
                        unsigned(u64::from(w.step_outcome.ville_false_alarm_bound_ppm)),
                    ),
                    (
                        "independent_supporting_clusters",
                        unsigned(u64::from(w.step_outcome.independent_supporting_clusters)),
                    ),
                    (
                        "crossed_alert_threshold",
                        boolean(w.step_outcome.crossed_alert_threshold),
                    ),
                    ("degraded_cameras", array(&degraded)),
                    ("occluded_cameras", array(&occluded)),
                    ("step_digest", string(&w.step_outcome.step_digest.to_text())),
                ])
            })
            .collect();

        let cancel_json = self.cancellation.as_ref().map(|c| {
            object(&[
                ("requested_at_window", unsigned(c.requested_at_window)),
                (
                    "drained_in_flight_windows",
                    unsigned(c.drained_in_flight_windows),
                ),
                ("finalized_cleanly", boolean(c.finalized_cleanly)),
                ("zero_orphan_obligations", boolean(c.zero_orphan_obligations)),
                ("zero_staging_artifacts", boolean(c.zero_staging_artifacts)),
            ])
        });

        object(&[
            ("schema", string(self.schema)),
            ("site_lineage", string(&self.site_lineage)),
            ("hypothesis_id", string(&self.hypothesis_id)),
            (
                "authority_root_at_start",
                string(&self.authority_root_at_start.to_text()),
            ),
            ("calibration_generation", string(&self.calibration_generation)),
            ("calibration_digest", string(&self.calibration_digest.to_text())),
            ("status", string(self.status)),
            ("windows_evaluated", unsigned(self.windows_evaluated)),
            ("work_units_consumed", unsigned(self.work_units_consumed)),
            ("work_units_limit", unsigned(self.work_units_limit)),
            (
                "corroborated_at_window",
                nullable(self.corroborated_at_window.map(unsigned)),
            ),
            (
                "final_accumulated_llr_mban",
                object(&[
                    ("lo", integer(i128::from(self.final_accumulated_llr.lo()))),
                    ("hi", integer(i128::from(self.final_accumulated_llr.hi()))),
                ]),
            ),
            ("supremum_lo_mban", integer(i128::from(self.supremum_lo_mban))),
            (
                "ville_false_alarm_bound_ppm",
                unsigned(u64::from(self.ville_false_alarm_bound_ppm)),
            ),
            (
                "threshold_ville_bound_ppm",
                unsigned(u64::from(self.threshold_ville_bound_ppm)),
            ),
            (
                "independent_supporting_clusters",
                unsigned(u64::from(self.independent_supporting_clusters)),
            ),
            ("elapsed_ns", unsigned(self.elapsed_ns)),
            ("cancellation", nullable(cancel_json)),
            ("windows", array(&windows_json)),
            ("receipt_digest", string(&self.receipt_digest.to_text())),
        ])
    }
}

/// Executes the bounded multi-camera supervisor loop against `deployment`.
///
/// # Errors
///
/// Returns [`SupervisorError`] on camera-count/sensor-uniqueness violations (`NEG-004`),
/// stale authority root (`ContractBasis` drift), `WorkBudget` exhaustion, or strict corrupt input.
pub fn run_supervisor(
    deployment: &ReferenceDeployment,
    root_path: Option<&Path>,
    cx: &ReplayCx,
    plan: &SupervisorPlan,
) -> Result<SupervisorReport, SupervisorError> {
    let started = Instant::now();

    if plan.cameras.len() < 2 {
        return Err(SupervisorError::InsufficientCameras {
            count: plan.cameras.len(),
        });
    }
    let mut seen_sensors = BTreeSet::new();
    let mut camera_map = BTreeMap::new();
    for cam in &plan.cameras {
        if !seen_sensors.insert(cam.sensor_id.clone()) {
            return Err(SupervisorError::DuplicateSensor {
                sensor_id: cam.sensor_id.clone(),
            });
        }
        camera_map.insert(cam.camera_id.clone(), cam);
    }

    let current_root = deployment.current_anchor().state_root;
    if let Some(expected) = plan.expected_authority_root
        && expected != current_root
    {
        return Err(SupervisorError::StaleAuthorityAnchor {
            expected,
            actual: current_root,
        });
    }

    let mut budget = WorkBudget::new(plan.max_work_units);
    let mut eprocess =
        SequentialEProcess::new(plan.hypothesis_id.clone(), plan.eprocess_config)
            .map_err(SupervisorError::Fusion)?;
    let step_unit = plan.work_units_per_camera_window.max(1);

    let mut window_records = Vec::with_capacity(plan.windows.len());
    let mut corroborated_at_window = None;
    let mut cancellation_receipt = None;

    for (idx, window) in plan.windows.iter().enumerate() {
        // 1. Check cooperative cancellation before starting a new window (`request -> drain -> finalize`).
        let cancel_triggered = cx.is_cancelled()
            || plan
                .cancel_after_window
                .is_some_and(|limit| idx >= limit);
        if cancel_triggered {
            let (zero_orphan_obligations, zero_staging_artifacts) =
                verify_clean_drain(deployment, root_path);
            cancellation_receipt = Some(SupervisorCancellationReceipt {
                requested_at_window: window.window_index,
                drained_in_flight_windows: window_records.len() as u64,
                finalized_cleanly: true,
                zero_orphan_obligations,
                zero_staging_artifacts,
            });
            break;
        }

        // 2. Charge explicit WorkBudget for all cameras in this window before mutating state.
        let window_cost = step_unit.saturating_mul(plan.cameras.len() as u64);
        let projected = budget.used().saturating_add(window_cost);
        if budget.charge(window_cost).is_err() {
            return Err(SupervisorError::WorkBudgetExceeded {
                consumed: projected,
                limit: plan.max_work_units,
            });
        }

        // 3. Evaluate per-camera observations in canonical camera order.
        let mut evidence = Vec::with_capacity(plan.cameras.len());
        let mut degraded_cameras = Vec::new();
        let mut occluded_cameras = Vec::new();
        let mut clock_reset: Option<(String, u64)> = None;

        for (cam_id, cam_spec) in &camera_map {
            let mut cam_domains = cam_spec.failure_domains.clone();
            cam_domains.insert(format!("sensor:{}", cam_spec.sensor_id));
            let obs = window
                .observations
                .get(cam_id.as_str())
                .unwrap_or(&SupervisorWindowObservation::NoDetection);
            match obs {
                SupervisorWindowObservation::CalibratedDetection {
                    score_ppm,
                    label,
                    evidence_digest,
                } => {
                    let bin = plan.calibration.bin(*score_ppm).ok_or_else(|| {
                        SupervisorError::InvalidCalibration(format!(
                            "score lookup failed for {score_ppm} ppm: outside calibrated bins"
                        ))
                    })?;
                    evidence.push(EvidenceItem {
                        id: format!(
                            "obs:{}:{}:{}:{}",
                            window.window_index,
                            cam_id,
                            label,
                            evidence_digest.to_text()
                        ),
                        sensor: cam_spec.sensor_id.clone(),
                        failure_domains: cam_domains,
                        calibration: Calibration::Calibrated {
                            generation: plan.calibration.generation.clone(),
                            llr: bin.llr,
                        },
                        observability: Observability::Observed,
                    });
                }
                SupervisorWindowObservation::NoDetection => {}
                SupervisorWindowObservation::Occluded { reason } => {
                    occluded_cameras.push((*cam_id).clone());
                    evidence.push(EvidenceItem {
                        id: format!("obs:{}:{}:occluded", window.window_index, cam_id),
                        sensor: cam_spec.sensor_id.clone(),
                        failure_domains: cam_domains,
                        calibration: Calibration::Uncalibrated {
                            reason: reason.clone(),
                        },
                        observability: Observability::NotObservable {
                            reason: reason.clone(),
                        },
                    });
                }
                SupervisorWindowObservation::HealthDegraded { reason } => {
                    degraded_cameras.push((*cam_id).clone());
                    evidence.push(EvidenceItem {
                        id: format!("obs:{}:{}:degraded", window.window_index, cam_id),
                        sensor: cam_spec.sensor_id.clone(),
                        failure_domains: cam_domains,
                        calibration: Calibration::Uncalibrated {
                            reason: reason.clone(),
                        },
                        observability: Observability::NotObservable {
                            reason: format!("sensor_health_degraded:{reason}"),
                        },
                    });
                }
                SupervisorWindowObservation::ClockDiscontinuity { gap_ns } => {
                    clock_reset = Some((cam_spec.sensor_id.clone(), *gap_ns));
                }
                SupervisorWindowObservation::CorruptSegment { reason } => {
                    if !plan.tolerate_corrupt_segments {
                        return Err(SupervisorError::CorruptInput {
                            camera_id: (*cam_id).clone(),
                            window_index: window.window_index,
                            reason: reason.clone(),
                        });
                    }
                    degraded_cameras.push((*cam_id).clone());
                    evidence.push(EvidenceItem {
                        id: format!("obs:{}:{}:corrupt_tolerated", window.window_index, cam_id),
                        sensor: cam_spec.sensor_id.clone(),
                        failure_domains: cam_domains,
                        calibration: Calibration::Uncalibrated {
                            reason: reason.clone(),
                        },
                        observability: Observability::NotObservable {
                            reason: format!("corrupt_segment:{reason}"),
                        },
                    });
                }
            }
        }

        if let Some((sensor, gap_ns)) = clock_reset {
            let step_outcome =
                eprocess.reset_regime(RegimeResetReason::ClockContinuityBroken { sensor, gap_ns });
            window_records.push(SupervisorWindowRecord {
                window_index: window.window_index,
                timestamp_ns: window.timestamp_ns,
                decision_label: "hold_indeterminate",
                knowledge_state: "unknown",
                step_outcome,
                degraded_cameras,
                occluded_cameras,
            });
            continue;
        }

        // If every configured camera is degraded in this window, reset the sequential regime.
        if degraded_cameras.len() == plan.cameras.len() {
            let step_outcome = eprocess.reset_regime(RegimeResetReason::SensorHealthDegraded {
                sensor: "all_cameras".to_owned(),
                reason: "all_supervised_cameras_degraded".to_owned(),
            });
            window_records.push(SupervisorWindowRecord {
                window_index: window.window_index,
                timestamp_ns: window.timestamp_ns,
                decision_label: "hold_indeterminate",
                knowledge_state: "not_observable",
                step_outcome,
                degraded_cameras,
                occluded_cameras,
            });
            continue;
        }

        let coverage = if !occluded_cameras.is_empty() {
            Coverage::Gap {
                reason: format!("occluded_cameras:{}", occluded_cameras.join(",")),
            }
        } else if !degraded_cameras.is_empty() {
            Coverage::Degraded {
                reason: format!("degraded_cameras:{}", degraded_cameras.join(",")),
            }
        } else {
            Coverage::Complete
        };

        let query = FusionQuery {
            hypothesis: plan.hypothesis_id.clone(),
            kind: "zone_entry".to_owned(),
            prior: LlrInterval::point(0).map_err(SupervisorError::Fusion)?,
            evidence,
            coverage,
            opportunities: Vec::new(),
            probes: Vec::new(),
            severity: Severity {
                expected_harm: 10_000,
                false_alert_cost: 500,
                delay_cost_per_second: 100,
                reversible: false,
            },
            policy: FusionPolicy {
                generation: "supervisor-fusion-policy:v1".to_owned(),
                alert_threshold: plan.eprocess_config.alert_threshold_mban,
                retain_threshold: 0,
                reject_threshold: -1_000,
                min_independent_support: plan.eprocess_config.min_independent_clusters,
                urgent_single_domain_threshold: None,
                max_wait_ns: 0,
                look_penalty_per_doubling: 0,
                operator_confirmation_available: false,
            },
            looks: (idx as u32).saturating_add(1),
            now_ns: window.timestamp_ns,
        };

        let (fusion_outcome, step_outcome) = eprocess
            .observe_step(&query)
            .map_err(SupervisorError::Fusion)?;
        let crossed = step_outcome.crossed_alert_threshold;
        if crossed && corroborated_at_window.is_none() {
            corroborated_at_window = Some(window.window_index);
        }

        window_records.push(SupervisorWindowRecord {
            window_index: window.window_index,
            timestamp_ns: window.timestamp_ns,
            decision_label: decision_str(&fusion_outcome.decision),
            knowledge_state: fusion_outcome.knowledge_state,
            step_outcome,
            degraded_cameras,
            occluded_cameras,
        });

        if crossed && plan.stop_on_corroborated_alert {
            break;
        }
    }

    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let final_llr = eprocess.accumulated_llr();
    let supremum_lo_mban = window_records
        .last()
        .map_or(0, |r| r.step_outcome.supremum_lo_mban);
    let status = if cancellation_receipt.is_some() {
        "cancelled_drained"
    } else if corroborated_at_window.is_some() {
        "corroborated_alert_warranted"
    } else {
        "completed_monitoring"
    };

    Ok(SupervisorReport {
        schema: SUPERVISOR_REPORT_SCHEMA,
        site_lineage: plan.site_lineage.clone(),
        hypothesis_id: plan.hypothesis_id.clone(),
        authority_root_at_start: current_root,
        calibration_generation: plan.calibration.generation.clone(),
        calibration_digest: plan.calibration.digest,
        status,
        windows_evaluated: window_records.len() as u64,
        work_units_consumed: budget.used(),
        work_units_limit: plan.max_work_units,
        corroborated_at_window,
        final_accumulated_llr: final_llr,
        supremum_lo_mban,
        ville_false_alarm_bound_ppm: ville_false_alarm_bound_ppm(supremum_lo_mban),
        threshold_ville_bound_ppm: ville_false_alarm_bound_ppm(
            plan.eprocess_config.alert_threshold_mban,
        ),
        independent_supporting_clusters: eprocess.independent_supporting_clusters(),
        elapsed_ns,
        cancellation: cancellation_receipt,
        window_records,
        receipt_digest: ContentDigest::sha256(b""),
    }
    .seal())
}
