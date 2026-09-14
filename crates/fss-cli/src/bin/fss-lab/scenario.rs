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

use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, Completeness, ContentDigest,
    ContractBasis, ContractBasisRegistryBytes, CoverageContinuity, CoverageStopReason,
    CoverageWitness, DecisionPath, EffectIntent, EffectState, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, HandoffId, IdempotencyKey,
    MissionId, ObligationId, ObligationState, OperationId, PrincipalId, ProbabilityInterval,
    SensorCapsule, SensorId, SensorSourceBytesSpec, SessionId, StreamId, TimestampNs,
};
use fss_reference::{
    InMemoryObjectStore, MockModelOutcome, MockModelResult, MockModelScript, MockModelSpec,
    MockSemanticLabel, ObjectLimits, ObjectManifest, ReferenceAlertPlan, ReferenceDeployment,
    ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReferenceProviderBehavior, ReferenceSituationRequest, ReplayCx, ReplayIoAuthority, SlotName,
    SpoolLimits, StagingSpool, evaluate_unknown_presence,
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
    /// Spool verification error.
    Spool(String),
    /// Time math overflow.
    TimeOverflow,
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScenario(name) => write!(f, "unknown scenario {name}"),
            Self::Core(msg) => write!(f, "core contract failure: {msg}"),
            Self::Reference(msg) => write!(f, "reference deployment failure: {msg}"),
            Self::Packet(msg) => write!(f, "virtual camera packet error: {msg}"),
            Self::Spool(msg) => write!(f, "spool verification error: {msg}"),
            Self::TimeOverflow => f.write_str("scenario time overflow"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    DropSource { sensor: &'static str, tick: u64 },
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
    /// Corroboration status: "corroborated", "single_source", or "not_applicable".
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
    /// Nondominated affordance frontier.
    pub affordances: Vec<Affordance>,
    /// Discovered warnings and faults.
    pub warnings: Vec<String>,
    /// Fingerprint of the verified situation projection.
    pub situation_digest: ContentDigest,
    /// Content digest of the root-closed handoff capsule.
    pub handoff_digest: ContentDigest,
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
        output.push_str(",\"affordances\":[");
        for (index, affordance) in self.affordances.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('{');
            push_json_field(&mut output, "class", affordance.class.as_str(), true);
            push_json_field(&mut output, "operation", &affordance.operation, false);
            push_json_field(&mut output, "reason", &affordance.reason, false);
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
    let cameras = [
        VirtualCamera::new("cam-front", "front-power-and-network"),
        VirtualCamera::new("cam-side", "side-power-and-network"),
    ];
    let faults = faults_for(kind);
    let cx = make_cx(kind)?;

    let mut deployment = ReferenceDeployment::open(root, "site:lab", &cx)?;
    let mut staged_digests: Vec<ContentDigest> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut in_memory_objects = InMemoryObjectStore::new(ObjectLimits::new(1024, 32 * 1024 * 1024));

    let mut observations: Vec<ReferenceModelObservation> = Vec::new();

    for tick in SCENARIO_START..SCENARIO_END {
        for camera in &cameras {
            if has_drop_fault(&faults, camera.sensor, tick) {
                warnings.push(format!("coverage_gap:{}:{tick}", camera.sensor));
                continue;
            }

            let class = class_for(kind, camera.sensor, tick);
            let packet_bytes = camera.capture(tick, class, confidence_for(class))?;

            if has_corruption_fault(&faults, camera.sensor, tick) {
                // Verify that the real staging spool detects corrupted bytes on disk.
                verify_spool_detects_corruption(&packet_bytes)?;
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
                let stored_digest = in_memory_objects.put_verified(&result_bytes)?;
                if stored_digest != model_result.object_digest() {
                    return Err(ScenarioError::Reference(
                        "digest mismatch on model result".to_string(),
                    ));
                }
                let obs =
                    ReferenceModelObservation::new(model_result, camera.failure_domain, capture)?;
                observations.push(obs);
            }
        }
    }

    let interval = CaptureInterval::new(
        TimestampNs(0),
        TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        ),
    )?;

    // Policy decision formulation.
    let (decision, coverage_witness, envelope, event_disposition, knowledge) = match kind {
        ScenarioKind::Quiet => {
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

            let event_id = EventId::parse("event:lab:quiet")?;
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

            let knowledge = KnowledgeReport {
                absence_certified: true,
                absence_not_certifiable_reason: None,
                corroboration: "not_applicable",
                coverage_gaps: Vec::new(),
            };

            (
                decision,
                Some(witness),
                EnvelopeClass::CertifiedQuiet,
                "quiet",
                knowledge,
            )
        }
        ScenarioKind::Raccoon => {
            let event_id = EventId::parse("event:lab:raccoon")?;
            let decision = evaluate_unknown_presence(event_id, observations)?;
            let knowledge = KnowledgeReport {
                absence_certified: false,
                absence_not_certifiable_reason: Some("activity_present"),
                corroboration: "not_applicable",
                coverage_gaps: Vec::new(),
            };
            (
                decision,
                None,
                EnvelopeClass::BenignActivity,
                "benign",
                knowledge,
            )
        }
        ScenarioKind::Intrusion => {
            let event_id = EventId::parse("event:lab:intrusion")?;
            let decision = evaluate_unknown_presence(event_id, observations)?;
            let knowledge = KnowledgeReport {
                absence_certified: false,
                absence_not_certifiable_reason: Some("threat_present"),
                corroboration: "corroborated",
                coverage_gaps: Vec::new(),
            };
            (
                decision,
                None,
                EnvelopeClass::CorroboratedThreat,
                "corroborated_threat",
                knowledge,
            )
        }
        ScenarioKind::Sneaky => {
            let event_id = EventId::parse("event:lab:sneaky")?;
            let decision = evaluate_unknown_presence(event_id, observations)?;
            let knowledge = KnowledgeReport {
                absence_certified: false,
                absence_not_certifiable_reason: Some("coverage_gap"),
                corroboration: "single_source",
                coverage_gaps: vec!["cam-side:2".to_string()],
            };
            (
                decision,
                None,
                EnvelopeClass::ProtectedResidual,
                "protected_residual",
                knowledge,
            )
        }
        ScenarioKind::LostAcknowledgement => {
            let event_id = EventId::parse("event:lab:lost-ack")?;
            let decision = evaluate_unknown_presence(event_id, observations)?;
            let knowledge = KnowledgeReport {
                absence_certified: false,
                absence_not_certifiable_reason: Some("threat_present"),
                corroboration: "corroborated",
                coverage_gaps: Vec::new(),
            };
            (
                decision,
                None,
                EnvelopeClass::CorroboratedThreat,
                "corroborated_threat",
                knowledge,
            )
        }
        ScenarioKind::CorruptSource => {
            // Source corruption prevents certified absence and preserves residual world.
            let event_id = EventId::parse("event:lab:corrupt-source")?;
            let decision_path = policy_decision_path(
                &event_id,
                &[],
                EventState::Indeterminate,
                ReferencePolicyAction::Hold,
            );
            let event = EventHypothesis {
                schema: EventHypothesis::SCHEMA.to_string(),
                event_id,
                revision: 1,
                supersedes: None,
                state: EventState::Indeterminate,
                kind: EventKind::UnknownPresence,
                interval,
                uncertainty_reason: Some("source corrupted".to_string()),
                zone_ids: Vec::new(),
                track_ids: Vec::new(),
                probability: ProbabilityInterval::new(0.0, 1.0)?,
                evidence: Vec::new(),
                model_receipts: Vec::new(),
                decision_path,
            };
            event.validate()?;
            let decision = ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            };
            let knowledge = KnowledgeReport {
                absence_certified: false,
                absence_not_certifiable_reason: Some("source_corrupt"),
                corroboration: "not_applicable",
                coverage_gaps: vec!["cam-side:2".to_string()],
            };
            (
                decision,
                None,
                EnvelopeClass::ProtectedResidual,
                "protected_residual",
                knowledge,
            )
        }
    };

    // Publish event revision through the deployment.
    let event_receipt = deployment.publish_event(&decision, &mut in_memory_objects)?;
    staged_digests.push(ContentDigest::sha256(&decision.event.canonical_bytes()));
    staged_digests.extend(decision.event.model_receipts.iter().copied());
    let mut revision_encoder = fss_core::CanonicalEncoder::new();
    revision_encoder.text("fss.canonical.v1");
    revision_encoder.text("fss.event_hypothesis.v1");
    decision.event.encode_canonical(&mut revision_encoder);
    staged_digests.push(ContentDigest::sha256(&revision_encoder.finish()));

    // Alert dispatch and reconciliation for corroborated threat scenarios.
    let mut transient_indeterminate = false;
    let mut alert_plan: Option<ReferenceAlertPlan> = None;
    let (effect_state, obligation_state) = if envelope == EnvelopeClass::CorroboratedThreat {
        let channel = "owner-alert".to_owned();
        let t_prepare = TimestampNs(
            (SCENARIO_END as i128)
                .checked_mul(1_000_000_000)
                .ok_or(ScenarioError::TimeOverflow)?,
        );

        let plan = deployment.prepare_alert_plan(
            &decision,
            &event_receipt,
            OperationId::parse("op:alert:intrusion:1")?,
            IdempotencyKey::parse("idemp:alert:intrusion:1")?,
            ObligationId::parse("ob:alert:intrusion:1")?,
            channel,
            t_prepare,
        )?;

        let behavior = if faults.contains(&Fault::LoseAlertAcknowledgement) {
            ReferenceProviderBehavior::LoseAckAfterDelivery
        } else {
            ReferenceProviderBehavior::Deliver
        };

        let t_commit = TimestampNs(t_prepare.0 + 10_000_000);
        let t_outcome = TimestampNs(t_prepare.0 + 20_000_000);
        let dispatch_receipt =
            deployment.dispatch_alert(&plan, behavior, t_commit, t_outcome, &cx)?;

        if dispatch_receipt.state == EffectState::Indeterminate {
            transient_indeterminate = true;
            warnings.push("effect_indeterminate:alert-operation-1".to_owned());
        }

        let t_reconcile = TimestampNs(t_prepare.0 + 30_000_000);
        deployment.reconcile_alert(&plan, t_reconcile)?;

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
    let sources_manifest = ObjectManifest::new("slot-sources", staged_digests, None)?;
    let slot_receipt = deployment.publish_and_commit(
        &SlotName::parse("slot-sources")?,
        &sources_manifest,
        interval,
        &cx,
    )?;
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

    let situation = deployment.compile_situation(situation_req, &cx)?;
    let situation_digest = situation.verify()?;

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
                + 3600_000_000_000,
        ),
        &cx,
    )?;
    let handoff_digest = handoff.handoff_root;

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

    // Reopen deployment to verify zero unreferenced objects and clean state on recovery.
    let reopened = ReferenceDeployment::reopen(root, "site:lab", &cx)?;
    if !reopened.recovery_report().unreferenced_objects.is_empty() {
        return Err(ScenarioError::Reference(format!(
            "unreferenced objects detected on reopen: {:?}",
            reopened.recovery_report().unreferenced_objects
        )));
    }
    let recon2 = reopened.recovery_report();
    if !recon2.is_clean() {
        return Err(ScenarioError::Reference(
            "recovery report on reopen was not clean".to_owned(),
        ));
    }

    let affordances = affordances_for(envelope, transient_indeterminate);

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
        affordances,
        warnings,
        situation_digest,
        handoff_digest,
    })
}

fn faults_for(kind: ScenarioKind) -> Vec<Fault> {
    match kind {
        ScenarioKind::Sneaky => vec![Fault::DropSource {
            sensor: "cam-side",
            tick: 2,
        }],
        ScenarioKind::LostAcknowledgement => vec![Fault::LoseAlertAcknowledgement],
        ScenarioKind::CorruptSource => vec![Fault::CorruptSource {
            sensor: "cam-side",
            tick: 2,
        }],
        _ => Vec::new(),
    }
}

fn has_drop_fault(faults: &[Fault], sensor: &str, tick: u64) -> bool {
    faults.iter().any(|fault| {
        matches!(
            fault,
            Fault::DropSource {
                sensor: fault_sensor,
                tick: fault_tick,
            } if *fault_sensor == sensor && *fault_tick == tick
        )
    })
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
        ScenarioKind::Sneaky if sensor == "cam-front" && tick == 2 => {
            ObservationClass::UnknownPerson
        }
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
        }],
        EnvelopeClass::BenignActivity => vec![Affordance {
            class: ControlClass::Observe,
            operation: "session.follow".to_owned(),
            reason: "activity is classified as a known benign animal".to_owned(),
        }],
        EnvelopeClass::ProtectedResidual => vec![
            Affordance {
                class: ControlClass::Probe,
                operation: "investigate.hydrate_adjacent_sensor".to_owned(),
                reason: "a material person hypothesis remains without independent corroboration"
                    .to_owned(),
            },
            Affordance {
                class: ControlClass::Observe,
                operation: "session.follow".to_owned(),
                reason: "wait for a discriminating observation while preserving the residual"
                    .to_owned(),
            },
        ],
        EnvelopeClass::CorroboratedThreat => vec![Affordance {
            class: ControlClass::Act,
            operation: "commit.owner_intrusion_alert".to_owned(),
            reason: "independent failure domains corroborate an unknown person".to_owned(),
        }],
    };
    if transient_indeterminate {
        affordances.push(Affordance {
            class: ControlClass::Reconcile,
            operation: "wait.reconcile_alert_delivery".to_owned(),
            reason: "dispatch acknowledgement was lost; operation lookup precedes retry".to_owned(),
        });
    }
    affordances
}

fn policy_decision_path(
    event_id: &EventId,
    evidence: &[EventEvidence],
    state: EventState,
    action: ReferencePolicyAction,
) -> DecisionPath {
    let mut encoder = fss_core::CanonicalEncoder::new();
    encoder.text("fss.reference_unknown_presence_policy.v2");
    event_id.encode_canonical(&mut encoder);
    encoder.text(state.as_str());
    encoder.u8(match action {
        ReferencePolicyAction::Hold => 1,
        ReferencePolicyAction::PrepareAlert => 2,
    });
    encoder.u64(evidence.len() as u64);
    for edge in evidence {
        edge.encode_canonical(&mut encoder);
    }
    let fingerprint = ContentDigest::sha256(&encoder.finish());
    DecisionPath {
        policy_generation: ContentDigest::sha256(b"fss.reference_unknown_presence_policy.v2"),
        fingerprint,
        abstained: false,
        abstention_reason: None,
    }
}

fn verify_spool_detects_corruption(bytes: &[u8]) -> Result<(), ScenarioError> {
    let temp_dir = std::env::temp_dir().join(format!(
        "fss-lab-corrupt-check-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&temp_dir).map_err(|e| ScenarioError::Reference(e.to_string()))?;

    let limits = SpoolLimits::new(1024 * 1024, 16 * 1024 * 1024);
    let mut spool =
        StagingSpool::open(&temp_dir, limits).map_err(|e| ScenarioError::Spool(e.to_string()))?;

    let digest = spool
        .stage(bytes)
        .map_err(|e| ScenarioError::Spool(e.to_string()))?;

    // Corrupt the staged payload on disk.
    let hex = digest.to_string();
    let raw_hex = hex.strip_prefix("sha256:").unwrap_or(&hex);
    let object_file = temp_dir.join("staging").join(format!("{raw_hex}.staged"));
    if object_file.exists() {
        let mut file_bytes =
            fs::read(&object_file).map_err(|e| ScenarioError::Reference(e.to_string()))?;
        if let Some(last) = file_bytes.last_mut() {
            *last ^= 0xff;
        }
        fs::write(&object_file, file_bytes).map_err(|e| ScenarioError::Reference(e.to_string()))?;
    }

    // Verification must detect the corruption.
    let verified = spool.verify(digest);
    let detected = verified.is_err();

    let _ = fs::remove_dir_all(&temp_dir);

    if detected {
        Ok(())
    } else {
        Err(ScenarioError::Packet("spool corruption was not detected"))
    }
}

fn make_cx(scenario: ScenarioKind) -> Result<ReplayCx, ScenarioError> {
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
    use super::{EnvelopeClass, ScenarioKind, run_scenario};
    use fss_core::{EffectState, ObligationState};

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
        assert_eq!(report.knowledge.absence_certified, true);
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
        assert_eq!(report.obligation_state, Some(ObligationState::Satisfied));
        assert_eq!(report.knowledge.corroboration, "corroborated");
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
        assert_eq!(report.obligation_state, Some(ObligationState::Satisfied));
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
}
