#![forbid(unsafe_code)]
//! Deterministic reference surveillance laboratory scenarios running on `ReferenceDeployment`.
//!
//! Every scenario drives the real pure-Rust stack:
//! - Virtual camera source packets wrapped into `SensorCapsule::from_source_bytes`;
//! - Root-last publication committed to the durable authority ledger (`publish_and_commit`);
//! - Perception findings evaluated by `evaluate_unknown_presence`;
//! - Reference events published via `ReferenceDeployment::publish_event`;
//! - Alert lifecycle prepared, dispatched through the simulated alert provider, and reconciled;
//! - Guarded situation projection compiled and sealed into a root-closed `HandoffCapsule`;
//! - Clean reconciliation and zero unreferenced objects verified on reopen.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::file_activity::{self, FileActivityOptions, FileActivityReport};
use crate::scene::{GeometricCoverage, LabScene};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, Completeness, ContentDigest,
    ContractBasis, ContractBasisRegistryBytes, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EffectState, EventEvidence, EventHypothesis, EventId, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, HandoffId, IdempotencyKey, MissionId, ObligationId,
    ObligationState, OperationId, PrincipalId, ProbabilityInterval, SensorCapsule, SensorId,
    SensorSourceBytesSpec, SessionId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{LedgerCutPoint, PublishCutPoint, SlotName};
use fss_reference::{
    AppendPhase, DurableEffectError, MockModelOutcome, MockModelResult, MockModelScript,
    MockModelSpec, MockSemanticLabel, PrepareAlertParams, ReferenceAlertPlan, ReferenceDeployment,
    ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReferenceProviderBehavior, ReferenceSituationRequest, ReplayCx, ReplayIoAuthority,
    policy_decision_path, rehydrate_reference_alert_plan,
};

const SCENARIO_START: u64 = 0;
const SCENARIO_END: u64 = 5;

/// Closed enumeration of supported laboratory scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioKind {
    /// Complete coverage certifying physical absence of an unknown person.
    Quiet,
    /// Benign wildlife detection with no alert effect.
    Raccoon,
    /// Corroborated multi-domain intrusion with verified alert delivery.
    Intrusion,
    /// Single-sensor detection with an observability gap preserving a protected residual.
    Sneaky,
    /// Lost alert delivery acknowledgement resolved by provider reconciliation.
    LostAcknowledgement,
    /// Corrupted source packet detected by spool verification and withheld from evidence.
    CorruptSource,
    /// Recorded single-camera JPEG frames scored by the real scalar executor (fss-2h5zq.51).
    FileActivity,
}

impl ScenarioKind {
    /// Parses a scenario kind from CLI string name.
    pub fn parse(value: &str) -> Result<Self, ScenarioError> {
        match value {
            "quiet" => Ok(Self::Quiet),
            "raccoon" => Ok(Self::Raccoon),
            "intrusion" => Ok(Self::Intrusion),
            "sneaky" => Ok(Self::Sneaky),
            "lost-ack" => Ok(Self::LostAcknowledgement),
            "corrupt-source" => Ok(Self::CorruptSource),
            "file-activity" => Ok(Self::FileActivity),
            _ => Err(ScenarioError::UnknownScenario(value.to_owned())),
        }
    }

    /// Stable scenario name string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Raccoon => "raccoon",
            Self::Intrusion => "intrusion",
            Self::Sneaky => "sneaky",
            Self::LostAcknowledgement => "lost-ack",
            Self::CorruptSource => "corrupt-source",
            Self::FileActivity => "file-activity",
        }
    }
}

/// Scenario runtime errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioError {
    /// Unknown scenario name requested.
    UnknownScenario(String),
    /// Contract or core plane error.
    Core(String),
    /// Reference deployment or publication error.
    Reference(String),
    /// Virtual packet encoding or decoding error.
    Packet(&'static str),
    /// Time math overflow.
    TimeOverflow,
    /// A crash-matrix fault the scenario driver itself injected fired at the named fault point;
    /// the run stops there as an in-process stand-in for process death.
    InjectedCrash(&'static str),
    /// The lab scene could not be imported or assessed.
    Geometry(String),
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScenario(name) => write!(f, "unknown scenario {name}"),
            Self::Core(msg) => write!(f, "core contract failure: {msg}"),
            Self::Reference(msg) => write!(f, "reference deployment failure: {msg}"),
            Self::Packet(msg) => write!(f, "virtual camera packet error: {msg}"),
            Self::TimeOverflow => f.write_str("scenario time overflow"),
            Self::InjectedCrash(point) => write!(f, "injected crash at {point}"),
            Self::Geometry(msg) => write!(f, "lab scene geometry failure: {msg}"),
        }
    }
}

impl std::error::Error for ScenarioError {}

impl From<fss_core::ContractError> for ScenarioError {
    fn from(err: fss_core::ContractError) -> Self {
        Self::Core(err.to_string())
    }
}

impl From<fss_reference::ReferenceError> for ScenarioError {
    fn from(err: fss_reference::ReferenceError) -> Self {
        Self::Reference(err.to_string())
    }
}

impl From<DurableEffectError> for ScenarioError {
    fn from(err: DurableEffectError) -> Self {
        Self::Reference(err.to_string())
    }
}

/// One in-process fault the crash matrix arms on a scenario run (fss-2h5zq.15).
///
/// Every variant drives a seam the owning crate already exposes for fault injection; none of them
/// is process death or power loss (fss-publication's `process_death_crash_harness` covers real
/// process death).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Injection {
    /// No fault: the ordinary scenario.
    None,
    /// `LocalRootPublisher::inject_crash_at` on the final `slot-sources` publication.
    PublishCrash(PublishCutPoint),
    /// `LedgeredRootPublisher::inject_crash_at` on the final `slot-sources` publication.
    LedgerCrash(LedgerCutPoint),
    /// `DurableReferenceLedger::fail_journal_after_phase` on the next authority append, which is
    /// the `slot-sources` root reachability batch.
    LedgerAppendFailure(AppendPhase),
    /// The alert provider loses the acknowledgement after delivery, and the run stops before
    /// reconciliation.
    CrashAfterLostAck,
    /// The alert operation is durably committed through the effect journal, and the run stops
    /// before the provider is called.
    CrashAfterCommitBeforeDispatch,
    /// Cooperative cancellation requested at the named `DEPLOYMENT_CANCEL_STAGES` checkpoint.
    CancelAt(&'static str),
}

impl Injection {
    /// Requests cancellation on `cx` when this injection cancels at `stage`.
    ///
    /// The deployment polls `cx` at the entry of the operation that owns `stage`, so requesting
    /// it immediately before that call is a cancellation arriving while the run is at the stage.
    fn cancel_before(self, stage: &'static str, cx: &ReplayCx) {
        if self == Self::CancelAt(stage) {
            cx.request_cancellation();
        }
    }
}

/// Registered `DEPLOYMENT_CANCEL_STAGES` names the scenario driver polls, spelled exactly as
/// `fss_reference` registers them (the crash-matrix tests check them against the registry).
pub mod stage {
    /// `STAGE_DEPLOYMENT_OPEN`.
    pub const DEPLOYMENT_OPEN: &str = "deployment_open";
    /// `STAGE_EVALUATE_POLICY`.
    pub const EVALUATE_POLICY: &str = "evaluate_policy";
    /// `STAGE_PUBLISH_EVENT`.
    pub const PUBLISH_EVENT: &str = "publish_event";
    /// `STAGE_DISPATCH_ALERT`.
    pub const DISPATCH_ALERT: &str = "dispatch_alert";
    /// `STAGE_PUBLISH_ROOT`.
    pub const PUBLISH_ROOT: &str = "publish_root";
    /// `STAGE_COMPILE_SITUATION`.
    pub const COMPILE_SITUATION: &str = "compile_situation";
    /// `STAGE_SEAL_HANDOFF`.
    pub const SEAL_HANDOFF: &str = "seal_handoff";

    /// Whether `stage` names a publication cut point the publisher polls through the
    /// deployment's cancellation bridge.
    #[must_use]
    pub fn is_publish_cut(stage: &str) -> bool {
        matches!(
            stage,
            "after_children_verified"
                | "after_manifest_body"
                | "after_root_temp_write"
                | "after_root_rename"
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    CorruptSource { sensor: &'static str, tick: u64 },
    LoseAlertAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationClass {
    Empty,
    Raccoon,
    UnknownPerson,
}

struct VirtualCamera {
    sensor: &'static str,
    failure_domain: &'static str,
}

impl VirtualCamera {
    const fn new(sensor: &'static str, failure_domain: &'static str) -> Self {
        Self {
            sensor,
            failure_domain,
        }
    }

    fn capture(
        &self,
        tick: u64,
        class: ObservationClass,
        confidence_basis_points: u16,
    ) -> Result<Vec<u8>, ScenarioError> {
        encode_packet(
            self.sensor,
            self.failure_domain,
            tick,
            class,
            confidence_basis_points,
        )
    }
}

/// Control action classes presented in agent-facing affordances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlClass {
    /// Continuous passive observation.
    Observe,
    /// Targeted epistemic probe.
    Probe,
    /// Consequential external effect.
    Act,
    /// State reconciliation after lost acknowledgement.
    Reconcile,
}

impl ControlClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Probe => "probe",
            Self::Act => "act",
            Self::Reconcile => "reconcile",
        }
    }
}

/// Decision-bearing affordance presented in the situation frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affordance {
    /// Control category.
    pub class: ControlClass,
    /// Typed operation identifier.
    pub operation: String,
    /// Non-empty justification.
    pub reason: String,
    /// Ground zone the affordance targets (rendered only when present).
    pub zone: Option<String>,
}

/// Categorized control envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeClass {
    /// Absence certified by complete continuous coverage.
    CertifiedQuiet,
    /// Known benign activity with no threat.
    BenignActivity,
    /// Material residual preserved across observation gaps or uncorroborated detections.
    ProtectedResidual,
    /// Threat corroborated by independent failure domains.
    CorroboratedThreat,
}

impl EnvelopeClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CertifiedQuiet => "certified_quiet",
            Self::BenignActivity => "benign_activity",
            Self::ProtectedResidual => "protected_residual",
            Self::CorroboratedThreat => "corroborated_threat",
        }
    }
}

/// Machine-readable knowledge classification object in scenario report v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeReport {
    /// Whether absence is affirmatively certified.
    pub absence_certified: bool,
    /// Reason absence could not be certified, if any.
    pub absence_not_certifiable_reason: Option<&'static str>,
    /// Corroboration status: "corroborated", "single_source", "not_corroborated" (several
    /// independent supports the policy did not corroborate), or "not_applicable".
    pub corroboration: &'static str,
    /// Identifiers of any coverage gaps observed.
    pub coverage_gaps: Vec<String>,
}

impl KnowledgeReport {
    /// Renders the knowledge report object into JSON.
    pub fn render_json(&self, output: &mut String) {
        output.push('{');
        output.push_str("\"absence\":");
        if self.absence_certified {
            output.push_str("\"certified\"");
        } else {
            let reason = self.absence_not_certifiable_reason.unwrap_or("unknown");
            output.push_str("{\"not_certifiable\":\"");
            output.push_str(reason);
            output.push_str("\"}");
        }
        push_json_field(output, "corroboration", self.corroboration, false);
        output.push_str(",\"coverage_gaps\":[");
        for (index, gap) in self.coverage_gaps.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(output, gap);
        }
        output.push_str("]}");
    }
}

/// Unified scenario report adhering to schema `fss.lab.scenario.v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    /// Executed scenario.
    pub scenario: ScenarioKind,
    /// Canonical authority ledger commit sequence.
    pub ledger_sequence: u64,
    /// State root of the canonical ledger anchor.
    pub ledger_anchor_root: ContentDigest,
    /// Manifest root of the durable published sources slot.
    pub publication_root: ContentDigest,
    /// Categorized control envelope.
    pub envelope: EnvelopeClass,
    /// Event disposition string label.
    pub event_disposition: &'static str,
    /// Whether absence was certified.
    pub absence_certified: bool,
    /// Whether an indeterminate dispatch was temporarily observed before reconciliation.
    pub transient_indeterminate: bool,
    /// Terminal effect lifecycle state, if an alert was executed.
    pub effect_state: Option<EffectState>,
    /// Terminal obligation state, if an alert was executed.
    pub obligation_state: Option<ObligationState>,
    /// Machine-readable epistemic knowledge object.
    pub knowledge: KnowledgeReport,
    /// Geometry-derived coverage of the intruder path (`sneaky` only; absent from every other
    /// report, so their bytes are unchanged).
    pub geometric_coverage: Option<GeometricCoverage>,
    /// Nondominated affordance frontier.
    pub affordances: Vec<Affordance>,
    /// Discovered warnings and faults.
    pub warnings: Vec<String>,
    /// Fingerprint of the verified situation projection.
    pub situation_digest: ContentDigest,
    /// Content digest of the root-closed handoff capsule.
    pub handoff_digest: ContentDigest,
    /// Executor-backed observations (`file-activity` only; absent from every mock report).
    pub executor: Option<FileActivityReport>,
    /// Operations this run handed to the alert provider (not rendered in the v2 report).
    pub dispatched_operations: Vec<OperationId>,
    /// Delivery and failure records the run's in-memory alert provider holds at the end of the
    /// run (not rendered in the v2 report). The provider starts empty on every open.
    pub provider_effects: usize,
}

impl ScenarioReport {
    /// Renders the complete scenario report into canonical JSON adhering to `fss.lab.scenario.v2`.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut output = String::new();
        output.push('{');
        push_json_field(&mut output, "schema", "fss.lab.scenario.v2", true);
        push_json_field(&mut output, "scenario", self.scenario.as_str(), false);
        push_json_u64(&mut output, "ledger_sequence", self.ledger_sequence);
        push_json_u64(&mut output, "anchor_sequence", self.ledger_sequence);
        push_json_field(
            &mut output,
            "ledger_anchor_root",
            &self.ledger_anchor_root.to_string(),
            false,
        );
        push_json_field(
            &mut output,
            "anchor_root",
            &self.ledger_anchor_root.to_string(),
            false,
        );
        push_json_field(
            &mut output,
            "publication_root",
            &self.publication_root.to_string(),
            false,
        );
        push_json_field(
            &mut output,
            "source_root",
            &self.publication_root.to_string(),
            false,
        );
        push_json_field(&mut output, "envelope", self.envelope.as_str(), false);
        push_json_field(
            &mut output,
            "event_disposition",
            self.event_disposition,
            false,
        );
        output.push_str(",\"absence_certified\":");
        output.push_str(if self.absence_certified {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"transient_indeterminate\":");
        output.push_str(if self.transient_indeterminate {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"effect_state\":");
        match self.effect_state {
            Some(state) => push_json_string(&mut output, effect_state_str(state)),
            None => output.push_str("null"),
        }
        output.push_str(",\"obligation_state\":");
        match self.obligation_state {
            Some(state) => push_json_string(&mut output, obligation_state_str(state)),
            None => output.push_str("null"),
        }
        output.push_str(",\"knowledge\":");
        self.knowledge.render_json(&mut output);
        if let Some(geometry) = &self.geometric_coverage {
            output.push_str(",\"geometric_coverage\":");
            geometry.render_json(&mut output);
        }
        output.push_str(",\"affordances\":[");
        for (index, affordance) in self.affordances.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('{');
            push_json_field(&mut output, "class", affordance.class.as_str(), true);
            push_json_field(&mut output, "operation", &affordance.operation, false);
            push_json_field(&mut output, "reason", &affordance.reason, false);
            if let Some(zone) = &affordance.zone {
                push_json_field(&mut output, "zone", zone, false);
            }
            output.push('}');
        }
        output.push(']');
        output.push_str(",\"warnings\":[");
        for (index, warning) in self.warnings.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(&mut output, warning);
        }
        output.push(']');
        push_json_field(
            &mut output,
            "situation_digest",
            &self.situation_digest.to_string(),
            false,
        );
        push_json_field(
            &mut output,
            "handoff_digest",
            &self.handoff_digest.to_string(),
            false,
        );
        if let Some(executor) = &self.executor {
            output.push_str(",\"executor\":");
            executor.render_json(&mut output);
        }
        output.push_str(",\"crate_generations\":{");
        push_json_field(&mut output, "fss-cli", env!("CARGO_PKG_VERSION"), true);
        push_json_field(&mut output, "fss-core", env!("CARGO_PKG_VERSION"), false);
        push_json_field(
            &mut output,
            "fss-geometry",
            env!("CARGO_PKG_VERSION"),
            false,
        );
        push_json_field(&mut output, "fss-ledger", env!("CARGO_PKG_VERSION"), false);
        push_json_field(
            &mut output,
            "fss-model-ir",
            env!("CARGO_PKG_VERSION"),
            false,
        );
        push_json_field(&mut output, "fss-object", env!("CARGO_PKG_VERSION"), false);
        push_json_field(&mut output, "fss-packet", env!("CARGO_PKG_VERSION"), false);
        push_json_field(
            &mut output,
            "fss-publication",
            env!("CARGO_PKG_VERSION"),
            false,
        );
        push_json_field(
            &mut output,
            "fss-reference",
            env!("CARGO_PKG_VERSION"),
            false,
        );
        push_json_field(&mut output, "fss-tensor", env!("CARGO_PKG_VERSION"), false);
        push_json_field(&mut output, "fss-twin", env!("CARGO_PKG_VERSION"), false);
        output.push_str("}}");
        output
    }
}

/// Executes one laboratory scenario against `ReferenceDeployment` under `root`.
pub fn run_scenario(kind: ScenarioKind, root: &Path) -> Result<ScenarioReport, ScenarioError> {
    run_scenario_with(kind, root, &class_for)
}

/// [`run_scenario`] with the virtual cameras' scene script supplied by the caller, so tests can
/// plant observations; every outcome is still derived by the real pipeline.
fn run_scenario_with(
    kind: ScenarioKind,
    root: &Path,
    classes: &dyn Fn(ScenarioKind, &str, u64) -> ObservationClass,
) -> Result<ScenarioReport, ScenarioError> {
    run_scenario_impl(
        kind,
        root,
        classes,
        FileActivityOptions::reference()?,
        Injection::None,
        &LabScene::REFERENCE,
    )
}

/// `sneaky` in a planted scene (the counterfactual fence) with a caller-supplied presence script.
#[cfg(test)]
fn run_sneaky_in(
    root: &Path,
    scene: &LabScene,
    classes: &dyn Fn(ScenarioKind, &str, u64) -> ObservationClass,
) -> Result<ScenarioReport, ScenarioError> {
    run_scenario_impl(
        ScenarioKind::Sneaky,
        root,
        classes,
        FileActivityOptions::reference()?,
        Injection::None,
        scene,
    )
}

/// `file-activity` with test-only executor options (threshold generation, failure injection).
#[cfg(test)]
fn run_file_activity_with(
    root: &Path,
    options: FileActivityOptions,
) -> Result<ScenarioReport, ScenarioError> {
    run_scenario_impl(
        ScenarioKind::FileActivity,
        root,
        &class_for,
        options,
        Injection::None,
        &LabScene::REFERENCE,
    )
}

/// [`run_scenario`] with one crash-matrix fault armed; with [`Injection::None`] it is the
/// ordinary scenario. See [`run_scenario_impl`].
pub fn run_injected(
    kind: ScenarioKind,
    root: &Path,
    injection: Injection,
) -> Result<ScenarioReport, ScenarioError> {
    run_scenario_impl(
        kind,
        root,
        &class_for,
        FileActivityOptions::reference()?,
        injection,
        &LabScene::REFERENCE,
    )
}

/// One scenario run, optionally with one crash-matrix fault armed ([`Injection::None`] is the
/// ordinary scenario).
///
/// The run is resumable on a root an earlier, interrupted run left behind: staging, event
/// publication and root publication are idempotent by content, an alert operation the effect
/// journal already holds is rehydrated instead of prepared again, and only a still-`Prepared`
/// operation is dispatched (operation lookup precedes retry), so a rerun never blindly retries an
/// effect.
fn run_scenario_impl(
    kind: ScenarioKind,
    root: &Path,
    classes: &dyn Fn(ScenarioKind, &str, u64) -> ObservationClass,
    file_options: FileActivityOptions,
    injection: Injection,
    scene: &LabScene,
) -> Result<ScenarioReport, ScenarioError> {
    // A recorded file replaces the virtual cameras; it has no live continuity (fss-2h5zq.51).
    let file_source = kind == ScenarioKind::FileActivity;
    let mock_cameras = [
        VirtualCamera::new("cam-front", "front-power-and-network"),
        VirtualCamera::new("cam-side", "side-power-and-network"),
    ];
    let cameras: &[VirtualCamera] = if file_source { &[] } else { &mock_cameras };
    let faults = faults_for(kind);
    // `sneaky` places its cameras in a property scene: what each camera can report, and which
    // path zones no camera observes, follow from geometric visibility (fss-2h5zq.55).
    let mut geometry = if kind == ScenarioKind::Sneaky {
        Some(GeometricCoverage::assess(scene)?)
    } else {
        None
    };
    let cx = make_cx(kind)?;

    injection.cancel_before(stage::DEPLOYMENT_OPEN, &cx);
    let mut deployment = ReferenceDeployment::open(root, "site:lab", &cx)?;
    let mut staged_digests: Vec<ContentDigest> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let mut observations: Vec<ReferenceModelObservation> = Vec::new();
    // Corrupt sources detected in the deployment spool: withheld, never referenced.
    let mut withheld: BTreeSet<ContentDigest> = BTreeSet::new();

    let interval = CaptureInterval::new(
        TimestampNs(0),
        TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        ),
    )?;
    let executor = if file_source {
        let (file_observations, report) =
            file_activity::gather(&mut deployment, &mut staged_digests, interval, file_options)?;
        observations.extend(file_observations);
        Some(report)
    } else {
        None
    };

    for tick in SCENARIO_START..SCENARIO_END {
        let path_zone = geometry
            .as_ref()
            .and_then(|geometry| geometry.zone_at(tick));
        if let Some(zone) = path_zone
            && !zone.observed()
        {
            // No camera observes the zone the path crosses now: a gap, never absence.
            warnings.push(format!("coverage_gap:{}:{tick}", zone.zone));
        }
        for camera in cameras {
            let scripted = classes(kind, camera.sensor, tick);
            // A camera whose view of the path zone is occluded or outside its frustum cannot
            // report what is in the zone; its frame carries no finding.
            let class = match path_zone {
                Some(zone) if !zone.observable_from(camera.sensor) => ObservationClass::Empty,
                _ => scripted,
            };
            let packet_bytes = camera.capture(tick, class, confidence_for(class))?;

            if has_corruption_fault(&faults, camera.sensor, tick) {
                // Verify that the real staging spool detects corrupted bytes on disk.
                withheld.insert(deployment_spool_detects_corruption(
                    &mut deployment,
                    &packet_bytes,
                )?);
                warnings.push(format!("source_corrupt:{}:{tick}", camera.sensor));
                continue;
            }

            let source_digest = deployment.stage_payload(&packet_bytes)?;
            staged_digests.push(source_digest);

            let capsule_id = CapsuleId::parse(format!("capsule:{}:{tick}", camera.sensor))?;
            let sensor_id = SensorId::parse(format!("sensor:{}", camera.sensor))?;
            let stream_id = StreamId::parse(format!("stream:{}", camera.sensor))?;
            let start_ns = (tick as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?;
            let end_ns = start_ns
                .checked_add(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?;
            let capture = CaptureInterval::new(TimestampNs(start_ns), TimestampNs(end_ns))?;

            let spec = SensorSourceBytesSpec {
                capsule_id,
                sensor_id: sensor_id.clone(),
                stream_id,
                sequence: tick,
                capture,
                receive_time: TimestampNs(end_ns),
                clock_basis: ClockBasis::DeviceMonotonic,
                source: &packet_bytes,
                frame_count: 1,
                gap_before: false,
            };
            let capsule = SensorCapsule::from_source_bytes(spec)?;
            let capsule_bytes = capsule.canonical_bytes();
            let capsule_digest = deployment.stage_payload(&capsule_bytes)?;
            staged_digests.push(capsule_digest);

            // Per-scenario model finding derivation.
            if let Some(semantic_label) = semantic_label_for(class) {
                let model_spec = MockModelSpec::new(
                    format!("mock:model:{}:{tick}:v1", camera.sensor),
                    MockModelScript::Fixed {
                        label: semantic_label,
                        probability: ProbabilityInterval::new(0.9, 1.0)?,
                    },
                )?;
                let model_result = MockModelResult {
                    generation_id: model_spec.generation_id().to_string(),
                    sensor_id,
                    model_spec_digest: model_spec.spec_digest(),
                    input_capture_root: source_digest,
                    continuity_digest: capsule_digest,
                    outcome: MockModelOutcome::Finding {
                        label: semantic_label,
                        probability: ProbabilityInterval::new(0.9, 1.0)?,
                    },
                };
                let result_bytes = model_result.canonical_bytes();
                let stored_digest = deployment.stage_payload(&result_bytes)?;
                if stored_digest != model_result.object_digest() {
                    return Err(ScenarioError::Reference(
                        "digest mismatch on model result".to_string(),
                    ));
                }
                staged_digests.push(stored_digest);
                let obs =
                    ReferenceModelObservation::new(model_result, camera.failure_domain, capture)?;
                observations.push(obs);
            }
        }
    }

    // The coverage witness of the path: observed domains are the visible zones only. It is
    // retained with the run's sources; it never certifies absence on its own.
    if let Some(geometry) = geometry.as_mut() {
        let authorized_domain = geometry.authorized_domain();
        let observed_domain = geometry.observed_domain();
        let complete = observed_domain == authorized_domain;
        let witness = CoverageWitness {
            anchor: deployment.current_anchor().clone(),
            authorized_domain,
            observed_domain,
            excluded_domain: BTreeSet::new(),
            continuity: if complete {
                CoverageContinuity::Continuous
            } else {
                CoverageContinuity::Gapped
            },
            completeness: if complete {
                Completeness::Complete
            } else {
                Completeness::Partial
            },
            negative_predicate: "no_unknown_person_present".to_string(),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: deployment.current_anchor().policy_epoch,
            observed_generation: deployment.current_anchor().policy_epoch,
        };
        let witness_digest = deployment.stage_payload(&witness.canonical_bytes())?;
        staged_digests.push(witness_digest);
        geometry.witness_digest = Some(witness_digest);
    }

    // Every outcome below is derived from what the run actually recorded: the real policy's
    // decision over the model observations, and the coverage gaps and corrupt sources. No
    // scenario name selects a result.
    let gaps: Vec<String> = warnings
        .iter()
        .filter_map(|w| {
            w.strip_prefix("coverage_gap:")
                .or_else(|| w.strip_prefix("source_corrupt:"))
                .map(str::to_owned)
        })
        .collect();
    let corrupt = warnings.iter().any(|w| w.starts_with("source_corrupt:"));
    let event_id = EventId::parse(format!("event:lab:{}", kind.as_str()))?;
    let (decision, coverage_witness) = if !observations.is_empty() {
        injection.cancel_before(stage::EVALUATE_POLICY, &cx);
        (
            deployment.evaluate_policy(event_id, observations, &cx)?,
            None,
        )
    } else if gaps.is_empty() && !file_source {
        let event_id_quiet = event_id;
        let authorized_domain = BTreeSet::from([
            "front-power-and-network".to_string(),
            "side-power-and-network".to_string(),
        ]);
        let observed_domain = authorized_domain.clone();
        let witness = CoverageWitness {
            anchor: deployment.current_anchor().clone(),
            authorized_domain: authorized_domain.clone(),
            observed_domain,
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Continuous,
            completeness: Completeness::Complete,
            negative_predicate: "no_unknown_person_present".to_string(),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: deployment.current_anchor().policy_epoch,
            observed_generation: deployment.current_anchor().policy_epoch,
        };

        let witness_bytes = witness.canonical_bytes();
        let witness_digest = deployment.stage_payload(&witness_bytes)?;
        staged_digests.push(witness_digest);

        let event_id = event_id_quiet;
        let mut evidence = Vec::new();
        for domain in &authorized_domain {
            evidence.push(EventEvidence {
                digest: witness_digest,
                class: EvidenceClass::Derived,
                failure_domain: domain.clone(),
                supports: false,
                relation: EvidenceEdgeRelation::Contradicts,
                capsule_digest: None,
                identity_digest: None,
            });
        }

        let decision_path = policy_decision_path(
            &event_id,
            &evidence,
            EventState::Rejected,
            ReferencePolicyAction::Hold,
        );
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id,
            revision: 1,
            supersedes: None,
            state: EventState::Rejected,
            kind: EventKind::UnknownPresence,
            interval,
            uncertainty_reason: None,
            zone_ids: Vec::new(),
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence,
            model_receipts: Vec::new(),
            decision_path,
        };
        event.validate()?;
        let decision = ReferencePolicyDecision {
            event,
            action: ReferencePolicyAction::Hold,
        };

        (decision, Some(witness))
    } else {
        // Nothing was observed, but coverage is incomplete: the event stays hypothesized with no
        // evidence, and absence cannot be certified.
        let decision_path = policy_decision_path(
            &event_id,
            &[],
            EventState::Hypothesized,
            ReferencePolicyAction::Hold,
        );
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval,
            uncertainty_reason: Some(
                if corrupt {
                    "source corrupted"
                } else if file_source {
                    "file source continuity not observable"
                } else {
                    "coverage gap"
                }
                .to_string(),
            ),
            zone_ids: Vec::new(),
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: Vec::new(),
            model_receipts: Vec::new(),
            decision_path,
        };
        event.validate()?;
        (
            ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            None,
        )
    };
    let support_domains: BTreeSet<&str> = decision
        .event
        .evidence
        .iter()
        .filter(|e| e.relation == EvidenceEdgeRelation::Supports)
        .map(|e| e.failure_domain.as_str())
        .collect();
    let contradicting = decision
        .event
        .evidence
        .iter()
        .any(|e| e.relation == EvidenceEdgeRelation::Contradicts);
    let state = decision.event.state;
    let certified = coverage_witness.is_some();
    let envelope = if certified {
        EnvelopeClass::CertifiedQuiet
    } else if state == EventState::Corroborated {
        EnvelopeClass::CorroboratedThreat
    } else if state == EventState::Rejected && gaps.is_empty() {
        EnvelopeClass::BenignActivity
    } else {
        EnvelopeClass::ProtectedResidual
    };
    let event_disposition = match envelope {
        EnvelopeClass::CertifiedQuiet => "quiet",
        EnvelopeClass::CorroboratedThreat => "corroborated_threat",
        EnvelopeClass::BenignActivity => "benign",
        EnvelopeClass::ProtectedResidual => "protected_residual",
    };
    let absence_not_certifiable_reason = if certified {
        None
    } else if file_source {
        // A recording without a continuity witness can never certify absence.
        Some("continuity_not_observable")
    } else if state == EventState::Corroborated {
        Some("threat_present")
    } else if corrupt {
        Some("source_corrupt")
    } else if !gaps.is_empty() {
        Some("coverage_gap")
    } else if !support_domains.is_empty() {
        Some("threat_present")
    } else if contradicting {
        Some("activity_present")
    } else {
        Some("unresolved_evidence")
    };
    let knowledge = KnowledgeReport {
        absence_certified: certified,
        absence_not_certifiable_reason,
        corroboration: match support_domains.len() {
            0 => "not_applicable",
            1 => "single_source",
            _ if state == EventState::Corroborated => "corroborated",
            _ => "not_corroborated",
        },
        coverage_gaps: gaps,
    };

    // Publish event revision through the deployment.
    injection.cancel_before(stage::PUBLISH_EVENT, &cx);
    let event_receipt = deployment.publish_event(&decision, &cx)?;
    staged_digests.push(event_receipt.event_root);
    staged_digests.push(event_receipt.event_object_digest);
    staged_digests.push(event_receipt.event_revision_digest);
    staged_digests.push(event_receipt.lineage_tamper_status.canonical_digest());

    // Alert dispatch and reconciliation for corroborated threat scenarios.
    let mut transient_indeterminate = false;
    let mut alert_plan: Option<ReferenceAlertPlan> = None;
    let mut dispatched_operations: Vec<OperationId> = Vec::new();
    let (effect_state, obligation_state) = if envelope == EnvelopeClass::CorroboratedThreat {
        let channel = "owner-alert".to_owned();
        let t_prepare = TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        );
        let operation_id = OperationId::parse("op:alert:intrusion:1")?;

        // Operation lookup precedes retry: an operation an earlier run prepared is rehydrated from
        // the durable effect journal, never prepared a second time.
        let existing = deployment.effects().operation(&operation_id).cloned();
        let plan = if let Some(operation) = existing {
            let obligation_id = deployment
                .effects()
                .obligations()
                .find(|obligation| obligation.operation_id == operation_id)
                .map(|obligation| obligation.obligation_id.clone())
                .ok_or_else(|| {
                    ScenarioError::Reference("journaled alert has no obligation".to_owned())
                })?;
            rehydrate_reference_alert_plan(
                &operation,
                obligation_id,
                &decision.event,
                &event_receipt,
                deployment.ledger(),
                &channel,
            )?
        } else {
            let (effects, ledger) = deployment.effects_and_ledger();
            effects.prepare_alert(PrepareAlertParams {
                decision: &decision,
                event_receipt: &event_receipt,
                authority: ledger,
                operation_id: operation_id.clone(),
                idempotency_key: IdempotencyKey::parse("idemp:alert:intrusion:1")?,
                obligation_id: ObligationId::parse("ob:alert:intrusion:1")?,
                channel,
                now: t_prepare,
            })?
        };

        let behavior = if faults.contains(&Fault::LoseAlertAcknowledgement)
            || injection == Injection::CrashAfterLostAck
        {
            ReferenceProviderBehavior::LoseAckAfterDelivery
        } else {
            ReferenceProviderBehavior::Deliver
        };

        let t_commit = TimestampNs(t_prepare.0 + 10_000_000);
        let t_outcome = TimestampNs(t_prepare.0 + 20_000_000);
        let journaled_state = deployment
            .effects()
            .operation(&operation_id)
            .map(|operation| operation.state);
        if journaled_state == Some(EffectState::Prepared) {
            injection.cancel_before(stage::DISPATCH_ALERT, &cx);
            if injection == Injection::CrashAfterCommitBeforeDispatch {
                // Exactly the journal step `dispatch_alert` takes before the provider is called.
                deployment.effects_mut().transition(
                    &operation_id,
                    EffectState::Committed,
                    t_commit,
                    None,
                    None,
                )?;
                return Err(ScenarioError::InjectedCrash(
                    "effect.after_commit_before_dispatch",
                ));
            }
            let dispatch_receipt =
                deployment.dispatch_alert(&plan, behavior, t_commit, t_outcome, &cx)?;
            dispatched_operations.push(operation_id.clone());
            if injection == Injection::CrashAfterLostAck {
                return Err(ScenarioError::InjectedCrash("effect.lost_ack"));
            }
            if dispatch_receipt.state == EffectState::Indeterminate {
                transient_indeterminate = true;
                warnings.push("effect_indeterminate:alert-operation-1".to_owned());
            }
        } else if journaled_state == Some(EffectState::Indeterminate) {
            transient_indeterminate = true;
            warnings.push("effect_indeterminate:alert-operation-1".to_owned());
        }

        let t_reconcile = TimestampNs(t_prepare.0 + 30_000_000);
        let provider = deployment.alert_provider().clone();
        deployment
            .effects_mut()
            .reconcile_alert(&plan, t_reconcile, &provider)?;

        let final_state = deployment
            .effects()
            .operation(&plan.intent.operation_id)
            .map(|op| op.state);
        let final_obligation = deployment
            .effects()
            .acknowledge_obligation(&plan.obligation_id)
            .ok()
            .map(|ob| ob.state);

        alert_plan = Some(plan);
        (final_state, final_obligation)
    } else {
        (None, None)
    };

    // Publish and commit all staged objects in slot-sources so reachability is durable and clean.
    staged_digests.sort_unstable();
    staged_digests.dedup();
    let sources_manifest = ObjectManifest::new("slot-sources", staged_digests, None)
        .map_err(|e| ScenarioError::Reference(e.to_string()))?;
    let slot_name =
        SlotName::parse("slot-sources").map_err(|e| ScenarioError::Reference(e.to_string()))?;
    injection.cancel_before(stage::PUBLISH_ROOT, &cx);
    match injection {
        // The publisher polls these through the deployment's cancellation bridge, which reports
        // reaching the stage to `cx`; the target fires there and nowhere else.
        Injection::CancelAt(name) if stage::is_publish_cut(name) => {
            cx.set_cancel_at_checkpoint(name);
        }
        Injection::PublishCrash(point) => deployment.publisher_mut().inject_crash_at(point),
        Injection::LedgerCrash(point) => deployment.inject_ledger_crash_at(point),
        Injection::LedgerAppendFailure(phase) => deployment.fail_ledger_append_after_phase(phase),
        _ => {}
    }
    let slot_receipt =
        deployment.publish_and_commit(&slot_name, &sources_manifest, interval, &cx)?;
    let publication_root = slot_receipt.root;

    // Compile agent situation projection.
    let available_capabilities = BTreeSet::from([
        "capability:evidence.query".to_string(),
        "capability:alert.prepare".to_string(),
        "capability:alert.commit".to_string(),
        "capability:effect.reconcile".to_string(),
        "capability:session.wait".to_string(),
    ]);

    let contract_basis = ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss/1",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    );

    let situation_req = ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:lab")?,
        session_id: SessionId::parse("session:lab")?,
        principal_id: PrincipalId::parse("principal:lab")?,
        objective_id: format!("objective:lab:{}", kind.as_str()),
        revision: 1,
        contract_basis,
        previous_anchor: None,
        predecessor_publication: None,
        decision: &decision,
        event_receipt: &event_receipt,
        alert_plan: alert_plan.as_ref(),
        alert_outcome: None,
        coverage_witness: coverage_witness.as_ref(),
        available_capabilities,
        created_at: TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        ),
    };

    injection.cancel_before(stage::COMPILE_SITUATION, &cx);
    let situation = deployment.compile_situation(situation_req, &cx)?;
    let situation_digest = situation.verify()?;

    injection.cancel_before(stage::SEAL_HANDOFF, &cx);
    let handoff = deployment.seal_handoff(
        &situation,
        HandoffId::parse(format!("handoff:lab:{}", kind.as_str()))?,
        TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        ),
        TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?
                + 3_600_000_000_000,
        ),
        &cx,
    )?;
    let handoff_digest = handoff.handoff_root;

    let provider_effects =
        deployment.alert_provider().message_count() + deployment.alert_provider().failure_count();
    let ledger_sequence = deployment.current_anchor().commit_sequence;
    let ledger_anchor_root = deployment.current_anchor().state_root;
    let absence_certified = knowledge.absence_certified;

    // Verify that the deployment reconciles clean.
    let recon = deployment.reconcile()?;
    if !recon.is_clean() {
        return Err(ScenarioError::Reference(
            "deployment reconciliation was not clean".to_owned(),
        ));
    }

    drop(deployment);

    verify_reopen(root, &cx, &withheld)?;

    let mut affordances = affordances_for(envelope, transient_indeterminate);
    if envelope == EnvelopeClass::ProtectedResidual
        && let Some(geometry) = &geometry
    {
        let probes: Vec<Affordance> = geometry
            .uncovered()
            .map(|zone| Affordance {
                class: ControlClass::Probe,
                operation: "investigate.probe_uncovered_zone".to_owned(),
                reason: format!(
                    "{} on the intruder path at tick {} is observed by no camera ({}); absence \
                     there is unknown",
                    zone.zone,
                    zone.tick,
                    zone.causes()
                ),
                zone: Some(zone.zone.to_owned()),
            })
            .collect();
        affordances.splice(0..0, probes);
    }

    Ok(ScenarioReport {
        scenario: kind,
        ledger_sequence,
        ledger_anchor_root,
        publication_root,
        envelope,
        event_disposition,
        absence_certified,
        transient_indeterminate,
        effect_state,
        obligation_state,
        knowledge,
        geometric_coverage: geometry,
        affordances,
        warnings,
        situation_digest,
        handoff_digest,
        executor,
        dispatched_operations,
        provider_effects,
    })
}

fn faults_for(kind: ScenarioKind) -> Vec<Fault> {
    match kind {
        ScenarioKind::LostAcknowledgement => vec![Fault::LoseAlertAcknowledgement],
        ScenarioKind::CorruptSource => vec![Fault::CorruptSource {
            sensor: "cam-side",
            tick: 2,
        }],
        _ => Vec::new(),
    }
}

fn has_corruption_fault(faults: &[Fault], sensor: &str, tick: u64) -> bool {
    faults.iter().any(|fault| {
        matches!(
            fault,
            Fault::CorruptSource {
                sensor: fault_sensor,
                tick: fault_tick,
            } if *fault_sensor == sensor && *fault_tick == tick
        )
    })
}

fn class_for(kind: ScenarioKind, sensor: &str, tick: u64) -> ObservationClass {
    match kind {
        ScenarioKind::Raccoon if tick == 2 || tick == 3 => ObservationClass::Raccoon,
        ScenarioKind::Intrusion | ScenarioKind::LostAcknowledgement
            if (sensor == "cam-front" && tick == 2) || (sensor == "cam-side" && tick == 3) =>
        {
            ObservationClass::UnknownPerson
        }
        // The intruder is on the property at ticks 2 and 3; the scene geometry decides which
        // camera can see the zone the path crosses.
        ScenarioKind::Sneaky if tick == 2 || tick == 3 => ObservationClass::UnknownPerson,
        _ => ObservationClass::Empty,
    }
}

const fn confidence_for(class: ObservationClass) -> u16 {
    match class {
        ObservationClass::Empty => 10_000,
        ObservationClass::Raccoon => 9_200,
        ObservationClass::UnknownPerson => 9_000,
    }
}

const fn semantic_label_for(class: ObservationClass) -> Option<MockSemanticLabel> {
    match class {
        ObservationClass::Empty => None,
        ObservationClass::Raccoon => Some(MockSemanticLabel::AnimalLike),
        ObservationClass::UnknownPerson => Some(MockSemanticLabel::PersonLike),
    }
}

fn affordances_for(envelope: EnvelopeClass, transient_indeterminate: bool) -> Vec<Affordance> {
    let mut affordances = match envelope {
        EnvelopeClass::CertifiedQuiet => vec![Affordance {
            class: ControlClass::Observe,
            operation: "session.follow".to_owned(),
            reason: "continuous authorized coverage certifies no unknown person".to_owned(),
            zone: None,
        }],
        EnvelopeClass::BenignActivity => vec![Affordance {
            class: ControlClass::Observe,
            operation: "session.follow".to_owned(),
            reason: "activity is classified as a known benign animal".to_owned(),
            zone: None,
        }],
        EnvelopeClass::ProtectedResidual => vec![
            Affordance {
                class: ControlClass::Probe,
                operation: "investigate.hydrate_adjacent_sensor".to_owned(),
                reason: "a material person hypothesis remains without independent corroboration"
                    .to_owned(),
                zone: None,
            },
            Affordance {
                class: ControlClass::Observe,
                operation: "session.follow".to_owned(),
                reason: "wait for a discriminating observation while preserving the residual"
                    .to_owned(),
                zone: None,
            },
        ],
        EnvelopeClass::CorroboratedThreat => vec![Affordance {
            class: ControlClass::Act,
            operation: "commit.owner_intrusion_alert".to_owned(),
            reason: "independent failure domains corroborate an unknown person".to_owned(),
            zone: None,
        }],
    };
    if transient_indeterminate {
        affordances.push(Affordance {
            class: ControlClass::Reconcile,
            operation: "wait.reconcile_alert_delivery".to_owned(),
            reason: "dispatch acknowledgement was lost; operation lookup precedes retry".to_owned(),
            zone: None,
        });
    }
    affordances
}

/// Reopens the deployment and requires a clean recovery, apart from exactly the corrupt sources
/// this run withheld: they must be the only unreferenced objects and the only corrupt ones.
fn verify_reopen(
    root: &Path,
    cx: &ReplayCx,
    withheld: &BTreeSet<ContentDigest>,
) -> Result<(), ScenarioError> {
    // Reopen deployment to verify zero unreferenced objects and clean state on recovery.
    let reopened = ReferenceDeployment::reopen(root, "site:lab", cx)?;
    // The only unreferenced objects allowed are the corrupt sources this run withheld.
    let unreferenced: BTreeSet<ContentDigest> = reopened
        .recovery_report()
        .unreferenced_objects
        .iter()
        .copied()
        .collect();
    if &unreferenced != withheld {
        return Err(ScenarioError::Reference(format!(
            "unreferenced objects detected on reopen: {:?}",
            reopened.recovery_report().unreferenced_objects
        )));
    }
    let recon2 = reopened.recovery_report();
    // Clean apart from the exactly withheld corrupt sources: the spool reports exactly those as
    // corrupt on reopen, and nothing else is corrupt, orphaned or foreign.
    let corrupt: BTreeSet<ContentDigest> = recon2.spool.corrupt.iter().map(|c| c.digest).collect();
    if !(&corrupt == withheld
        && recon2.spool.orphaned_staging.is_empty()
        && recon2.spool.foreign.is_empty()
        && recon2.broken_roots.is_empty()
        && recon2.orphaned_temps.is_empty()
        && recon2.foreign.is_empty())
    {
        return Err(ScenarioError::Reference(
            "recovery report on reopen was not clean".to_owned(),
        ));
    }

    Ok(())
}

fn deployment_spool_detects_corruption(
    deployment: &mut ReferenceDeployment,
    bytes: &[u8],
) -> Result<ContentDigest, ScenarioError> {
    // The corrupt source is staged in this deployment's own spool, damaged on disk, and must be
    // refused by the same verified read every consumer uses. It is then never referenced.
    let digest = deployment.stage_payload(bytes)?;
    let object_file = deployment.publisher().spool().object_path(digest);
    let mut file_bytes =
        fs::read(&object_file).map_err(|e| ScenarioError::Reference(e.to_string()))?;
    let last = file_bytes
        .last_mut()
        .ok_or(ScenarioError::Packet("empty staged source"))?;
    *last ^= 0xff;
    fs::write(&object_file, file_bytes).map_err(|e| ScenarioError::Reference(e.to_string()))?;
    if deployment.publisher().spool().read(digest).is_err() {
        Ok(digest)
    } else {
        Err(ScenarioError::Packet("spool corruption was not detected"))
    }
}

/// The laboratory's replay context for `scenario`: fixed authority, no deadline.
pub fn make_cx(scenario: ScenarioKind) -> Result<ReplayCx, ScenarioError> {
    let spec = fss_core::RootAuthoritySpec {
        trace_id: format!("trace:lab:{}", scenario.as_str()),
        operation_id: OperationId::parse(format!("op:lab:{}", scenario.as_str()))
            .map_err(|e| ScenarioError::Core(e.to_string()))?,
        principal: "operator:lab".to_string(),
        capabilities: vec![
            fss_reference::ADP_REPLAY_ROW_ID.to_string(),
            "capability:evidence.query".to_string(),
            "capability:alert.prepare".to_string(),
            "capability:alert.commit".to_string(),
            "capability:effect.reconcile".to_string(),
            "capability:session.wait".to_string(),
        ],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"fss.lab.anchor_universe.v1"),
        generation: 1,
    };
    let root_auth = fss_core::ContextAuthority::new_root(spec)
        .map_err(|e| ScenarioError::Core(e.to_string()))?;
    let scratch_root = std::env::temp_dir().join(format!(
        "fss-lab-cx-{}-{}",
        scenario.as_str(),
        std::process::id()
    ));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)
        .map_err(|e| ScenarioError::Reference(e.to_string()))?;
    Ok(ReplayCx::new(io))
}

fn encode_packet(
    sensor: &str,
    failure_domain: &str,
    tick: u64,
    class: ObservationClass,
    confidence_basis_points: u16,
) -> Result<Vec<u8>, ScenarioError> {
    let sensor_length = u16::try_from(sensor.len())
        .map_err(|_| ScenarioError::Packet("sensor identity is too long"))?;
    let domain_length = u16::try_from(failure_domain.len())
        .map_err(|_| ScenarioError::Packet("failure domain is too long"))?;
    let mut bytes = Vec::with_capacity(4 + 2 + sensor.len() + 2 + failure_domain.len() + 8 + 1 + 2);
    bytes.extend_from_slice(b"FSS1");
    bytes.extend_from_slice(&sensor_length.to_be_bytes());
    bytes.extend_from_slice(sensor.as_bytes());
    bytes.extend_from_slice(&domain_length.to_be_bytes());
    bytes.extend_from_slice(failure_domain.as_bytes());
    bytes.extend_from_slice(&tick.to_be_bytes());
    bytes.push(match class {
        ObservationClass::Empty => 0,
        ObservationClass::Raccoon => 1,
        ObservationClass::UnknownPerson => 2,
    });
    bytes.extend_from_slice(&confidence_basis_points.to_be_bytes());
    Ok(bytes)
}

fn effect_state_str(value: EffectState) -> &'static str {
    value.as_str()
}

fn obligation_state_str(value: ObligationState) -> &'static str {
    match value {
        ObligationState::Pending => "pending",
        ObligationState::Verified => "verified",
        ObligationState::Indeterminate => "indeterminate",
        ObligationState::Failed => "failed",
        ObligationState::Cancelled => "cancelled",
    }
}

fn push_json_u64(output: &mut String, key: &str, value: u64) {
    output.push(',');
    push_json_string(output, key);
    output.push(':');
    output.push_str(&value.to_string());
}

fn push_json_field(output: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        output.push(',');
    }
    push_json_string(output, key);
    output.push(':');
    push_json_string(output, value);
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(value));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::{
        ControlClass, EnvelopeClass, ObservationClass, ScenarioKind, class_for, make_cx,
        run_file_activity_with, run_scenario, run_scenario_with, run_sneaky_in, verify_reopen,
    };
    use crate::scene::LabScene;
    use fss_core::{EffectState, ObligationState};
    use fss_reference::ReferenceDeployment;
    use std::collections::BTreeSet;

    fn temp_test_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fss-lab-scen-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn quiet_requires_and_earns_certified_absence() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_test_root("quiet");
        let report = run_scenario(ScenarioKind::Quiet, &root)?;
        assert_eq!(report.envelope, EnvelopeClass::CertifiedQuiet);
        assert!(report.absence_certified);
        assert!(report.knowledge.absence_certified);
        assert!(report.effect_state.is_none());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn raccoon_is_benign_without_alert_effect() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_test_root("raccoon");
        let report = run_scenario(ScenarioKind::Raccoon, &root)?;
        assert_eq!(report.envelope, EnvelopeClass::BenignActivity);
        assert!(!report.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("activity_present")
        );
        assert!(report.effect_state.is_none());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn independent_intrusion_observations_verify_alert() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_test_root("intrusion");
        let report = run_scenario(ScenarioKind::Intrusion, &root)?;
        assert_eq!(report.envelope, EnvelopeClass::CorroboratedThreat);
        assert_eq!(report.effect_state, Some(EffectState::Verified));
        assert_eq!(report.obligation_state, Some(ObligationState::Verified));
        assert_eq!(report.knowledge.corroboration, "corroborated");
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn reopen_refuses_any_unreferenced_object_it_did_not_withhold()
    -> Result<(), Box<dyn std::error::Error>> {
        // Review mutant M2: a clean run, then one extra staged object nothing references.
        let root = temp_test_root("reopen-planted");
        run_scenario(ScenarioKind::Quiet, &root)?;
        let cx = make_cx(ScenarioKind::Quiet)?;
        assert!(verify_reopen(&root, &cx, &BTreeSet::new()).is_ok());
        let planted = {
            let mut deployment = ReferenceDeployment::reopen(&root, "site:lab", &cx)?;
            deployment.stage_payload(b"planted unreferenced object")?
        };
        assert!(verify_reopen(&root, &cx, &BTreeSet::new()).is_err());
        // Declaring it withheld is not enough when it is not corrupt.
        assert!(verify_reopen(&root, &cx, &BTreeSet::from([planted])).is_err());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn a_person_planted_in_quiet_is_never_certified_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        // Review mutant M8: the quiet scene with one unknown person on cam-front.
        let root = temp_test_root("quiet-planted");
        let report = run_scenario_with(ScenarioKind::Quiet, &root, &|_, sensor, tick| {
            if sensor == "cam-front" && tick == 2 {
                ObservationClass::UnknownPerson
            } else {
                ObservationClass::Empty
            }
        })?;
        assert!(!report.absence_certified);
        assert!(!report.knowledge.absence_certified);
        assert_ne!(report.envelope, EnvelopeClass::CertifiedQuiet);
        assert_eq!(report.knowledge.corroboration, "single_source");
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("threat_present")
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn sneaky_with_a_person_on_both_cameras_is_corroborated()
    -> Result<(), Box<dyn std::error::Error>> {
        // Review mutant M7: a second, independent camera also sees the person. Since
        // fss-2h5zq.55 a camera can only see the person where the scene lets it, so the second
        // view needs the fence moved out of cam-side's sight line.
        let both = |_: ScenarioKind, sensor: &str, tick: u64| {
            if (sensor == "cam-front" && tick == 2) || (sensor == "cam-side" && tick == 3) {
                ObservationClass::UnknownPerson
            } else {
                ObservationClass::Empty
            }
        };
        let root = temp_test_root("sneaky-both");
        let report = run_sneaky_in(&root, &LabScene::FENCE_MOVED, &both)?;
        assert_eq!(report.knowledge.corroboration, "corroborated");
        assert_eq!(report.envelope, EnvelopeClass::CorroboratedThreat);
        assert!(!report.absence_certified);
        let _ = std::fs::remove_dir_all(&root);

        // The same planted script behind the reference fence: cam-side cannot report a person
        // in a zone it cannot see, so the run stays single-source.
        let root = temp_test_root("sneaky-both-occluded");
        let occluded = run_scenario_with(ScenarioKind::Sneaky, &root, &both)?;
        assert_eq!(occluded.knowledge.corroboration, "single_source");
        assert_eq!(occluded.envelope, EnvelopeClass::ProtectedResidual);
        assert!(!occluded.absence_certified);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// One `CAPLOG` line with the geometric visibility counts of a sneaky report.
    fn log_geometry(step: &str, report: &super::ScenarioReport) {
        if let Some(geometry) = &report.geometric_coverage {
            let mut json = String::new();
            geometry.render_json(&mut json);
            println!(
                "CAPLOG {{\"bead\":\"fss-2h5zq.55\",\"step\":\"{step}\",\"corroboration\":\"{}\",\"geometric_coverage\":{json}}}",
                report.knowledge.corroboration
            );
        }
    }

    #[test]
    fn sneaky_gap_is_derived_from_occlusion_not_a_scripted_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_core::{CanonicalDecode as _, Completeness, CoverageContinuity, CoverageWitness};

        let root = temp_test_root("sneaky-geometry");
        let report = run_scenario(ScenarioKind::Sneaky, &root)?;
        log_geometry("sneaky_reference", &report);
        let geometry = report
            .geometric_coverage
            .as_ref()
            .ok_or("sneaky has no geometric coverage")?;

        // The side passage (tick 3) is occluded from cam-side and outside cam-front's frustum.
        let gap = geometry.zone_at(3).ok_or("no path zone at tick 3")?;
        assert_eq!(gap.zone, "zone:side-passage");
        assert!(!gap.observed());
        for view in &gap.views {
            let v = &view.visibility;
            match view.camera {
                "cam-side" => {
                    assert_eq!(view.state(), "occluded");
                    assert_eq!((v.samples, v.visible, v.occluded), (64, 0, 64));
                }
                "cam-front" => {
                    assert_eq!(view.state(), "outside_frustum");
                    assert_eq!((v.samples, v.visible, v.outside_frustum), (64, 0, 64));
                }
                other => return Err(format!("unexpected camera {other}").into()),
            }
            assert_eq!(v.claim(), "frustum_and_mesh_occlusion");
        }
        // The front walk (tick 2) is fully visible from cam-front only.
        let walk = geometry.zone_at(2).ok_or("no path zone at tick 2")?;
        assert!(walk.observable_from("cam-front"));
        assert!(!walk.observable_from("cam-side"));

        // The gap is the uncovered zone, not a dropped camera.
        assert_eq!(report.warnings, ["coverage_gap:zone:side-passage:3"]);
        assert_eq!(report.knowledge.coverage_gaps, ["zone:side-passage:3"]);
        assert!(
            !report
                .warnings
                .iter()
                .any(|warning| warning.starts_with("coverage_gap:cam-"))
        );
        // Absence is never certified; the only person finding is cam-front's.
        assert!(!report.absence_certified);
        assert!(!report.knowledge.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("coverage_gap")
        );
        assert_eq!(report.knowledge.corroboration, "single_source");
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);

        // The probe names the uncovered zone and why it is uncovered.
        let probe = report.affordances.first().ok_or("no affordances")?;
        assert_eq!(probe.class, ControlClass::Probe);
        assert_eq!(probe.operation, "investigate.probe_uncovered_zone");
        assert_eq!(probe.zone.as_deref(), Some("zone:side-passage"));
        assert!(
            probe.reason.contains("cam-side occluded"),
            "{}",
            probe.reason
        );
        assert!(
            probe.reason.contains("cam-front outside_frustum"),
            "{}",
            probe.reason
        );

        // The retained coverage witness observes the visible zones only.
        let witness_digest = geometry.witness_digest.ok_or("no witness digest")?;
        let cx = make_cx(ScenarioKind::Sneaky)?;
        let reopened = ReferenceDeployment::reopen(&root, "site:lab", &cx)?;
        let witness = CoverageWitness::from_canonical_bytes(
            &reopened.publisher().spool().read(witness_digest)?,
        )?;
        assert_eq!(
            witness.observed_domain,
            BTreeSet::from(["zone:front-walk".to_owned()])
        );
        assert_eq!(
            witness.authorized_domain,
            BTreeSet::from(["zone:front-walk".to_owned(), "zone:side-passage".to_owned()])
        );
        assert_eq!(witness.completeness, Completeness::Partial);
        assert_eq!(witness.continuity, CoverageContinuity::Gapped);
        assert!(!witness.certifies_absence());
        drop(reopened);

        let json = report.render_json();
        assert!(json.contains(&format!(
            "\"geometric_coverage\":{{\"basis_digest\":\"{}\",\"mesh_digest\":\"{}\"",
            geometry.basis_digest, geometry.mesh_digest
        )));
        assert!(
            json.contains("\"zone\":\"zone:side-passage\",\"tick\":3,\"state\":\"not_observable\"")
        );
        assert!(json.contains("\"zone\":\"zone:side-passage\"}"));
        assert!(json.contains("\"schema\":\"fss.lab.scenario.v2\""));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn moving_the_fence_removes_the_gap_and_corroborates() -> Result<(), Box<dyn std::error::Error>>
    {
        use fss_core::{EventId, EvidenceEdgeRelation};

        let reference_root = temp_test_root("sneaky-reference");
        let reference = run_scenario(ScenarioKind::Sneaky, &reference_root)?;
        let root = temp_test_root("sneaky-fence-moved");
        // The same presence script as the reference run: only the scene differs.
        let moved = run_sneaky_in(&root, &LabScene::FENCE_MOVED, &class_for)?;
        log_geometry("sneaky_fence_moved", &moved);
        let geometry = moved
            .geometric_coverage
            .as_ref()
            .ok_or("no geometric coverage")?;
        let passage = geometry.zone_at(3).ok_or("no path zone at tick 3")?;
        assert!(passage.observed());
        assert!(passage.observable_from("cam-side"));
        assert_eq!(geometry.uncovered().count(), 0);
        assert_eq!(geometry.observed_domain(), geometry.authorized_domain());
        let reference_geometry = reference
            .geometric_coverage
            .as_ref()
            .ok_or("no reference geometry")?;
        assert_ne!(geometry.basis_digest, reference_geometry.basis_digest);
        assert_ne!(geometry.mesh_digest, reference_geometry.mesh_digest);

        // No gap, and cam-side's tick-3 observation enters the policy: two independent failure
        // domains corroborate.
        assert!(moved.warnings.is_empty(), "{:?}", moved.warnings);
        assert!(moved.knowledge.coverage_gaps.is_empty());
        assert_eq!(reference.knowledge.corroboration, "single_source");
        assert_eq!(moved.knowledge.corroboration, "corroborated");
        assert_eq!(moved.envelope, EnvelopeClass::CorroboratedThreat);
        assert!(!moved.absence_certified);
        assert_eq!(
            moved.knowledge.absence_not_certifiable_reason,
            Some("threat_present")
        );
        assert!(
            !moved
                .affordances
                .iter()
                .any(|affordance| affordance.zone.is_some())
        );
        let cx = make_cx(ScenarioKind::Sneaky)?;
        let reopened = ReferenceDeployment::reopen(&root, "site:lab", &cx)?;
        let (event, _) = reopened.current_event_authority(&EventId::parse("event:lab:sneaky")?)?;
        let supporting: BTreeSet<&str> = event
            .evidence
            .iter()
            .filter(|edge| edge.relation == EvidenceEdgeRelation::Supports)
            .map(|edge| edge.failure_domain.as_str())
            .collect();
        assert_eq!(
            supporting,
            BTreeSet::from(["front-power-and-network", "side-power-and-network"])
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(&reference_root);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn an_occluded_camera_cannot_report_a_planted_person() -> Result<(), Box<dyn std::error::Error>>
    {
        // Only cam-side is scripted to see a person, at the two ticks the path crosses zones it
        // cannot see: no finding survives, and the gap still blocks any absence claim.
        let root = temp_test_root("sneaky-side-only");
        let report = run_scenario_with(ScenarioKind::Sneaky, &root, &|_, sensor, tick| {
            if sensor == "cam-side" && (tick == 2 || tick == 3) {
                ObservationClass::UnknownPerson
            } else {
                ObservationClass::Empty
            }
        })?;
        assert_eq!(report.knowledge.corroboration, "not_applicable");
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(!report.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("coverage_gap")
        );
        assert_eq!(report.knowledge.coverage_gaps, ["zone:side-passage:3"]);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn sneaky_intrusion_remains_protected_when_coverage_has_a_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_test_root("sneaky");
        let report = run_scenario(ScenarioKind::Sneaky, &root)?;
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(!report.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("coverage_gap")
        );
        assert_eq!(report.knowledge.corroboration, "single_source");
        assert!(
            report
                .affordances
                .iter()
                .any(|affordance| affordance.operation.starts_with("investigate."))
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn lost_ack_is_reconciled_without_duplicate_dispatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_test_root("lost-ack");
        let report = run_scenario(ScenarioKind::LostAcknowledgement, &root)?;
        assert!(report.transient_indeterminate);
        assert_eq!(report.effect_state, Some(EffectState::Verified));
        assert_eq!(report.obligation_state, Some(ObligationState::Verified));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn corrupted_source_destroys_coverage_not_truthfulness()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_test_root("corrupt-source");
        let report = run_scenario(ScenarioKind::CorruptSource, &root)?;
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(!report.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("source_corrupt")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.starts_with("source_corrupt:"))
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn replay_is_byte_identical() -> Result<(), Box<dyn std::error::Error>> {
        for scenario in [
            ScenarioKind::Quiet,
            ScenarioKind::Raccoon,
            ScenarioKind::Intrusion,
            ScenarioKind::Sneaky,
            ScenarioKind::LostAcknowledgement,
            ScenarioKind::CorruptSource,
        ] {
            let root1 = temp_test_root(&format!("{}-1", scenario.as_str()));
            let root2 = temp_test_root(&format!("{}-2", scenario.as_str()));
            let first = run_scenario(scenario, &root1)?.render_json();
            let second = run_scenario(scenario, &root2)?.render_json();
            let _ = std::fs::remove_dir_all(&root1);
            let _ = std::fs::remove_dir_all(&root2);
            assert_eq!(
                first,
                second,
                "scenario {} drifted across roots",
                scenario.as_str()
            );
        }
        Ok(())
    }

    fn file_activity_executor(
        report: &super::ScenarioReport,
    ) -> Result<&crate::file_activity::FileActivityReport, Box<dyn std::error::Error>> {
        Ok(report
            .executor
            .as_ref()
            .ok_or("file-activity report has no executor section")?)
    }

    #[test]
    fn file_activity_runs_the_real_executor_on_decoded_pixels()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_core::{ContentDigest, EventId, EventState, EvidenceEdgeRelation};
        use fss_reference::executor_activity::{
            ActivityThresholdPolicy, ContinuityNotObservableReason, ExecutorContinuity,
            ExecutorModelOutcome,
        };

        let root = temp_test_root("file-activity");
        let report = run_scenario(ScenarioKind::FileActivity, &root)?;
        let executor = file_activity_executor(&report)?;
        let threshold = ActivityThresholdPolicy::reference()?.threshold();
        assert_eq!(executor.policy.generation(), 1);
        assert_eq!(executor.observations.len(), 2);
        let quiet = &executor.observations[0];
        let changed = &executor.observations[1];
        println!(
            "CAPLOG {{\"bead\":\"fss-2h5zq.51\",\"step\":\"file_activity_scores\",\"frame1\":{:?},\"frame2\":{:?},\"threshold\":{threshold}}}",
            quiet.result.outcome.score(),
            changed.result.outcome.score()
        );
        // Frame 1 repeats the reference: below threshold, which is not absence.
        assert!(matches!(
            quiet.result.outcome,
            ExecutorModelOutcome::NoActivity { .. }
        ));
        assert_eq!(quiet.result.outcome.score(), Some(0.0));
        // Frame 2 has real content: the executor-computed score crosses the threshold.
        assert!(matches!(
            changed.result.outcome,
            ExecutorModelOutcome::Activity { .. }
        ));
        assert!(
            changed
                .result
                .outcome
                .score()
                .is_some_and(|score| score > threshold)
        );

        // One camera: never corroborated, never certified absent, no alert effect.
        assert_eq!(report.knowledge.corroboration, "single_source");
        assert_ne!(report.envelope, EnvelopeClass::CorroboratedThreat);
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(!report.absence_certified);
        assert!(!report.knowledge.absence_certified);
        assert_eq!(
            report.knowledge.absence_not_certifiable_reason,
            Some("continuity_not_observable")
        );
        assert!(report.effect_state.is_none());
        assert!(report.obligation_state.is_none());

        // Every bound digest resolves to retained bytes in the deployment left on disk.
        let cx = make_cx(ScenarioKind::FileActivity)?;
        let reopened = ReferenceDeployment::reopen(&root, "site:lab", &cx)?;
        let spool = reopened.publisher().spool();
        let resolves = |digest: ContentDigest| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let bytes = spool.read(digest)?;
            assert_eq!(ContentDigest::sha256(&bytes), digest);
            Ok(bytes)
        };
        resolves(executor.reference_decode_receipt)?;
        for observation in &executor.observations {
            let result = &observation.result;
            assert_eq!(observation.result_digest, result.object_digest());
            assert_eq!(resolves(observation.result_digest)?, {
                use fss_core::CanonicalEncode as _;
                result.canonical_bytes()
            });
            resolves(result.invocation_receipt_object)?;
            resolves(result.decode_receipt_digest)?;
            assert_eq!(
                result.reference_decode_receipt_digest,
                executor.reference_decode_receipt
            );
            resolves(result.reference_capture_root)?;
            resolves(result.capsule_digest)?;
            let source = resolves(result.input_capture_root)?;
            assert_eq!(
                &source[..2],
                &[0xff, 0xd8],
                "source bytes are the JPEG frame"
            );
            assert_eq!(
                result.continuity,
                ExecutorContinuity::NotObservable {
                    reason: ContinuityNotObservableReason::FileSource
                }
            );
            assert!(result.reference_only);
            assert!(!result.supports_absence_claim());
        }

        // The published event revision names exactly these executor results.
        let (event, _) =
            reopened.current_event_authority(&EventId::parse("event:lab:file-activity")?)?;
        assert_eq!(event.state, EventState::Witnessed);
        assert_ne!(event.state, EventState::Corroborated);
        let mut expected: Vec<ContentDigest> = executor
            .observations
            .iter()
            .map(|observation| observation.result_digest)
            .collect();
        expected.sort();
        assert_eq!(event.model_receipts, expected);
        for edge in &event.evidence {
            let supporting = edge.digest == changed.result_digest;
            assert_eq!(
                edge.relation,
                if supporting {
                    EvidenceEdgeRelation::Supports
                } else {
                    EvidenceEdgeRelation::DerivedFrom
                }
            );
            assert_ne!(edge.relation, EvidenceEdgeRelation::Contradicts);
        }

        let json = report.render_json();
        assert!(json.contains("\"scenario\":\"file-activity\""));
        assert!(json.contains("\"continuity\":{\"not_observable\":\"file_source\"}"));
        assert!(json.contains("\"score_calibrated\":false"));
        assert!(json.contains(&format!(
            "\"invocation_receipt_digest\":\"{}\"",
            changed.result.invocation_receipt_digest
        )));
        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn file_activity_executor_failure_is_an_abstention() -> Result<(), Box<dyn std::error::Error>> {
        use fss_reference::executor_activity::{
            ActivityThresholdPolicy, ExecutorAbstentionReason, ExecutorModelOutcome,
        };
        use fss_reference::model_receipt::ReceiptOutcome;

        let root = temp_test_root("file-activity-starved");
        let report = run_file_activity_with(
            &root,
            crate::file_activity::FileActivityOptions {
                policy: ActivityThresholdPolicy::reference()?,
                starve_frame: Some(2),
            },
        )?;
        let executor = file_activity_executor(&report)?;
        match executor.observations[1].result.outcome {
            ExecutorModelOutcome::Abstained {
                reason,
                receipt_outcome,
            } => {
                assert_eq!(reason, ExecutorAbstentionReason::ExecutorFailed);
                assert_ne!(receipt_outcome, ReceiptOutcome::Ok);
            }
            other => return Err(format!("starved frame produced {other:?}").into()),
        }
        // Abstention is not a no-detection: nothing is certified, rejected or benign.
        assert!(!report.absence_certified);
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert_ne!(report.envelope, EnvelopeClass::BenignActivity);
        assert_eq!(report.knowledge.corroboration, "not_applicable");
        assert!(
            report
                .render_json()
                .contains("\"abstention\":\"executor_failed\"")
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn file_activity_threshold_policy_generation_is_reported_and_governs()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_reference::executor_activity::{ActivityThresholdPolicy, ExecutorModelOutcome};

        let reference_root = temp_test_root("file-activity-reference");
        let reference = run_scenario(ScenarioKind::FileActivity, &reference_root)?;
        let observed = file_activity_executor(&reference)?.observations[1]
            .result
            .outcome
            .score()
            .ok_or("no score")?;
        // A later policy generation whose threshold equals the observed score: not strictly
        // greater, so no activity; still never absence.
        let root = temp_test_root("file-activity-strict");
        let strict = ActivityThresholdPolicy::new(2, observed)?;
        let report = run_file_activity_with(
            &root,
            crate::file_activity::FileActivityOptions {
                policy: strict,
                starve_frame: None,
            },
        )?;
        let executor = file_activity_executor(&report)?;
        assert_eq!(executor.policy.generation(), 2);
        assert!(
            executor
                .observations
                .iter()
                .all(|o| matches!(o.result.outcome, ExecutorModelOutcome::NoActivity { .. }))
        );
        assert_eq!(
            executor.observations[1].result.outcome.score(),
            Some(observed)
        );
        assert!(!report.absence_certified);
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(
            report
                .render_json()
                .contains("\"threshold_policy\":{\"generation\":2,")
        );
        let _ = std::fs::remove_dir_all(&reference_root);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn file_activity_replay_is_byte_identical() -> Result<(), Box<dyn std::error::Error>> {
        let root1 = temp_test_root("file-activity-1");
        let root2 = temp_test_root("file-activity-2");
        let first = run_scenario(ScenarioKind::FileActivity, &root1)?.render_json();
        let second = run_scenario(ScenarioKind::FileActivity, &root2)?.render_json();
        let _ = std::fs::remove_dir_all(&root1);
        let _ = std::fs::remove_dir_all(&root2);
        assert_eq!(first, second);
        Ok(())
    }
}
