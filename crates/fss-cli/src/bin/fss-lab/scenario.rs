use std::collections::BTreeSet;
use std::fmt;

use crate::digest::{CanonicalWriter, Digest, DigestError};
use crate::effects::{
    DispatchOutcome, EffectCoordinator, EffectError, EffectState, ObligationState,
    ReconciliationObservation,
};
use crate::ledger::{
    AbsenceCertificate, CoverageCertificate, CoverageInterval, EventAssessment, EventDisposition,
    EvidenceAnchor, EvidenceLedger, LedgerError, Observation, ObservationClass, RecordKind,
    assess_event, certify_absence,
};
use crate::spool::{SourceKey, SourceSpool, SpoolError};

const SCENARIO_START: u64 = 0;
const SCENARIO_END: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioKind {
    Quiet,
    Raccoon,
    Intrusion,
    Sneaky,
    LostAcknowledgement,
    CorruptSource,
}

impl ScenarioKind {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioError {
    Digest(DigestError),
    Spool(SpoolError),
    Ledger(LedgerError),
    Effect(EffectError),
    UnknownScenario(String),
    Packet(&'static str),
    TimeOverflow,
    MissingCoverageCertificate,
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "digest failure: {error}"),
            Self::Spool(error) => write!(formatter, "source spool failure: {error}"),
            Self::Ledger(error) => write!(formatter, "evidence ledger failure: {error}"),
            Self::Effect(error) => write!(formatter, "effect failure: {error}"),
            Self::UnknownScenario(value) => write!(formatter, "unknown scenario {value}"),
            Self::Packet(reason) => write!(formatter, "invalid virtual camera packet: {reason}"),
            Self::TimeOverflow => formatter.write_str("scenario time overflow"),
            Self::MissingCoverageCertificate => {
                formatter.write_str("certified quiet requires a coverage certificate")
            }
        }
    }
}

impl std::error::Error for ScenarioError {}

impl From<DigestError> for ScenarioError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

impl From<SpoolError> for ScenarioError {
    fn from(error: SpoolError) -> Self {
        Self::Spool(error)
    }
}

impl From<LedgerError> for ScenarioError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<EffectError> for ScenarioError {
    fn from(error: EffectError) -> Self {
        Self::Effect(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VirtualCamera {
    sensor: String,
    failure_domain: String,
}

impl VirtualCamera {
    fn new(sensor: &str, failure_domain: &str) -> Self {
        Self {
            sensor: sensor.to_owned(),
            failure_domain: failure_domain.to_owned(),
        }
    }

    fn capture(
        &self,
        tick: u64,
        class: ObservationClass,
        confidence_basis_points: u16,
    ) -> Result<Vec<u8>, ScenarioError> {
        encode_packet(
            &self.sensor,
            &self.failure_domain,
            tick,
            class,
            confidence_basis_points,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedPacket {
    sensor: String,
    failure_domain: String,
    tick: u64,
    class: ObservationClass,
    confidence_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Fault {
    DropSource { sensor: String, tick: u64 },
    CorruptSource { sensor: String, tick: u64 },
    LoseAlertAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlClass {
    Observe,
    Probe,
    Act,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affordance {
    pub class: ControlClass,
    pub operation: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeClass {
    CertifiedQuiet,
    BenignActivity,
    ProtectedResidual,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    pub scenario: ScenarioKind,
    pub anchor: EvidenceAnchor,
    pub source_root: Digest,
    pub event: EventAssessment,
    pub envelope: EnvelopeClass,
    pub absence: Option<AbsenceCertificate>,
    pub effect_state: Option<EffectState>,
    pub obligation_state: Option<ObligationState>,
    pub transient_indeterminate: bool,
    pub affordances: Vec<Affordance>,
    pub warnings: Vec<String>,
    pub situation_digest: Digest,
    pub handoff_digest: Digest,
}

impl ScenarioReport {
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut output = String::new();
        output.push('{');
        push_json_field(&mut output, "schema", "fss.lab.scenario.v1", true);
        push_json_field(&mut output, "scenario", self.scenario.as_str(), false);
        push_json_u64(&mut output, "anchor_sequence", self.anchor.sequence);
        push_json_u64(&mut output, "anchor_time", self.anchor.observed_at);
        push_json_field(
            &mut output,
            "anchor_root",
            &self.anchor.root.to_hex(),
            false,
        );
        push_json_field(
            &mut output,
            "source_root",
            &self.source_root.to_hex(),
            false,
        );
        push_json_field(&mut output, "envelope", self.envelope.as_str(), false);
        push_json_field(
            &mut output,
            "event_disposition",
            event_disposition_str(self.event.disposition),
            false,
        );
        output.push_str(",\"absence_certified\":");
        output.push_str(if self.absence.is_some() {
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
            &self.situation_digest.to_hex(),
            false,
        );
        push_json_field(
            &mut output,
            "handoff_digest",
            &self.handoff_digest.to_hex(),
            false,
        );
        output.push('}');
        output
    }
}

pub fn run_scenario(kind: ScenarioKind) -> Result<ScenarioReport, ScenarioError> {
    let cameras = [
        VirtualCamera::new("cam-front", "front-power-and-network"),
        VirtualCamera::new("cam-side", "side-power-and-network"),
    ];
    let faults = faults_for(kind);
    let mut spool = SourceSpool::default();
    let mut ledger = EvidenceLedger::default();
    let mut effects = EffectCoordinator::default();
    let mut observations = Vec::new();
    let mut coverage_intervals = Vec::new();
    let mut warnings = Vec::new();

    for tick in SCENARIO_START..SCENARIO_END {
        for camera in &cameras {
            if has_drop_fault(&faults, &camera.sensor, tick) {
                warnings.push(format!("source_gap:{}:{tick}", camera.sensor));
                continue;
            }
            let class = class_for(kind, &camera.sensor, tick);
            let bytes = camera.capture(tick, class, confidence_for(class))?;
            let key = SourceKey::new(camera.sensor.clone(), tick);
            let published = if has_corruption_fault(&faults, &camera.sensor, tick) {
                spool.stage(key.clone(), bytes)?;
                spool.inject_corruption(&key)?;
                match spool.verify(&key) {
                    Ok(_) => return Err(ScenarioError::Packet("corruption was not detected")),
                    Err(SpoolError::Corrupt(_)) => {
                        warnings.push(format!("source_corrupt:{}:{tick}", camera.sensor));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            } else {
                spool.ingest(key, bytes)?
            };
            ledger.append(
                tick,
                RecordKind::SourcePublished,
                vec![published.digest],
                published.publication_root.as_bytes().as_slice(),
            )?;
            let decoded = decode_packet(&published.bytes)?;
            if decoded.sensor != camera.sensor || decoded.failure_domain != camera.failure_domain {
                return Err(ScenarioError::Packet("camera identity mismatch"));
            }
            let observation = Observation {
                sensor: decoded.sensor,
                failure_domain: decoded.failure_domain,
                at: decoded.tick,
                class: decoded.class,
                confidence_basis_points: decoded.confidence_basis_points,
                source_digest: published.digest,
            };
            let observation_digest = observation.digest()?;
            ledger.append(
                tick,
                RecordKind::Observation,
                vec![published.digest],
                observation_digest.as_bytes().as_slice(),
            )?;
            observations.push(observation);
            let end = tick.checked_add(1).ok_or(ScenarioError::TimeOverflow)?;
            coverage_intervals.push(CoverageInterval::new(
                camera.sensor.clone(),
                camera.failure_domain.clone(),
                tick,
                end,
                true,
            )?);
        }
    }

    let required_sensors: BTreeSet<String> =
        cameras.iter().map(|camera| camera.sensor.clone()).collect();
    let coverage = match CoverageCertificate::build(
        &required_sensors,
        &coverage_intervals,
        SCENARIO_START,
        SCENARIO_END,
    ) {
        Ok(certificate) => {
            ledger.append(
                SCENARIO_END,
                RecordKind::Coverage,
                observations
                    .iter()
                    .map(|observation| observation.source_digest)
                    .collect(),
                certificate.digest.as_bytes().as_slice(),
            )?;
            Some(certificate)
        }
        Err(LedgerError::MissingCoverage(sensor)) => {
            warnings.push(format!("coverage_missing:{sensor}"));
            None
        }
        Err(LedgerError::CoverageGap { sensor, at }) => {
            warnings.push(format!("coverage_gap:{sensor}:{at}"));
            None
        }
        Err(error) => return Err(error.into()),
    };

    let event = assess_event(&observations, SCENARIO_START, SCENARIO_END)?;
    ledger.append(
        SCENARIO_END,
        RecordKind::Event,
        event.supporting_observations.clone(),
        event.digest.as_bytes().as_slice(),
    )?;
    let envelope = match event.disposition {
        EventDisposition::QuietCertified if coverage.is_some() => EnvelopeClass::CertifiedQuiet,
        EventDisposition::QuietCertified => EnvelopeClass::ProtectedResidual,
        EventDisposition::BenignKnown => EnvelopeClass::BenignActivity,
        EventDisposition::ProtectedResidual => EnvelopeClass::ProtectedResidual,
        EventDisposition::CorroboratedThreat => EnvelopeClass::CorroboratedThreat,
    };
    let absence = if envelope == EnvelopeClass::CertifiedQuiet {
        let certificate = coverage
            .clone()
            .ok_or(ScenarioError::MissingCoverageCertificate)?;
        let absence = certify_absence(
            ObservationClass::UnknownPerson,
            certificate,
            &observations,
            ledger.anchor(),
        )?;
        ledger.append(
            SCENARIO_END,
            RecordKind::Absence,
            vec![absence.coverage.digest],
            absence.digest.as_bytes().as_slice(),
        )?;
        Some(absence)
    } else {
        None
    };

    let mut transient_indeterminate = false;
    let (effect_state, obligation_state) = if envelope == EnvelopeClass::CorroboratedThreat {
        let prepared = effects.prepare(
            "alert-operation-1",
            "scenario-alert-key-1",
            "alert-delivery-obligation-1",
            "send_owner_intrusion_alert",
            "owner delivery receipt is observed",
        )?;
        ledger.append(
            SCENARIO_END,
            RecordKind::Effect,
            vec![event.digest],
            prepared.digest.as_bytes().as_slice(),
        )?;
        let dispatch_outcome = if faults
            .iter()
            .any(|fault| matches!(fault, Fault::LoseAlertAcknowledgement))
        {
            DispatchOutcome::LostAcknowledgement
        } else {
            DispatchOutcome::Acknowledged
        };
        let mut operation = effects.dispatch("scenario-alert-key-1", dispatch_outcome)?;
        ledger.append(
            SCENARIO_END,
            RecordKind::Effect,
            vec![operation.digest],
            effects.root().as_bytes().as_slice(),
        )?;
        if operation.state == EffectState::Indeterminate {
            transient_indeterminate = true;
            warnings.push("effect_indeterminate:alert-operation-1".to_owned());
            operation = effects.reconcile(
                "scenario-alert-key-1",
                ReconciliationObservation::AppliedAndVerified,
            )?;
            ledger.append(
                SCENARIO_END,
                RecordKind::Effect,
                vec![operation.digest],
                effects.root().as_bytes().as_slice(),
            )?;
        } else {
            operation = effects.verify("scenario-alert-key-1")?;
            ledger.append(
                SCENARIO_END,
                RecordKind::Effect,
                vec![operation.digest],
                effects.root().as_bytes().as_slice(),
            )?;
        }
        let obligation = effects
            .obligation("alert-delivery-obligation-1")
            .ok_or(ScenarioError::Packet("missing alert obligation"))?;
        ledger.append(
            SCENARIO_END,
            RecordKind::Obligation,
            vec![obligation.digest],
            effects.root().as_bytes().as_slice(),
        )?;
        (Some(operation.state), Some(obligation.state))
    } else {
        (None, None)
    };

    let affordances = affordances_for(envelope, transient_indeterminate);
    let situation_digest = situation_digest(
        kind,
        ledger.anchor(),
        spool.root(),
        event.digest,
        absence.as_ref().map(|value| value.digest),
        effects.root(),
        envelope,
        &affordances,
        &warnings,
    )?;
    ledger.append(
        SCENARIO_END,
        RecordKind::Situation,
        vec![event.digest, situation_digest],
        situation_digest.as_bytes().as_slice(),
    )?;
    let handoff_digest = seal_handoff(
        ledger.anchor(),
        spool.root(),
        situation_digest,
        event.digest,
        absence.as_ref().map(|value| value.digest),
        effects.root(),
    )?;
    ledger.append(
        SCENARIO_END,
        RecordKind::Handoff,
        vec![situation_digest, handoff_digest],
        handoff_digest.as_bytes().as_slice(),
    )?;

    Ok(ScenarioReport {
        scenario: kind,
        anchor: ledger.anchor(),
        source_root: spool.root(),
        event,
        envelope,
        absence,
        effect_state,
        obligation_state,
        transient_indeterminate,
        affordances,
        warnings,
        situation_digest,
        handoff_digest,
    })
}

fn faults_for(kind: ScenarioKind) -> Vec<Fault> {
    match kind {
        ScenarioKind::Sneaky => vec![Fault::DropSource {
            sensor: "cam-side".to_owned(),
            tick: 2,
        }],
        ScenarioKind::LostAcknowledgement => vec![Fault::LoseAlertAcknowledgement],
        ScenarioKind::CorruptSource => vec![Fault::CorruptSource {
            sensor: "cam-side".to_owned(),
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
                tick: fault_tick
            } if fault_sensor == sensor && *fault_tick == tick
        )
    })
}

fn has_corruption_fault(faults: &[Fault], sensor: &str, tick: u64) -> bool {
    faults.iter().any(|fault| {
        matches!(
            fault,
            Fault::CorruptSource {
                sensor: fault_sensor,
                tick: fault_tick
            } if fault_sensor == sensor && *fault_tick == tick
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
        ObservationClass::Homeowner => 9_500,
        ObservationClass::Raccoon => 9_200,
        ObservationClass::UnknownPerson => 9_000,
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

#[allow(clippy::too_many_arguments)]
fn situation_digest(
    kind: ScenarioKind,
    anchor: EvidenceAnchor,
    source_root: Digest,
    event_digest: Digest,
    absence_digest: Option<Digest>,
    effect_root: Digest,
    envelope: EnvelopeClass,
    affordances: &[Affordance],
    warnings: &[String],
) -> Result<Digest, ScenarioError> {
    let mut writer = CanonicalWriter::new("fss-situation-capsule-v1")?;
    writer.push_str(kind.as_str())?;
    writer.push_u64(anchor.sequence);
    writer.push_u64(anchor.observed_at);
    writer.push_digest(anchor.root);
    writer.push_digest(source_root);
    writer.push_digest(event_digest);
    writer.push_bool(absence_digest.is_some());
    if let Some(digest) = absence_digest {
        writer.push_digest(digest);
    }
    writer.push_digest(effect_root);
    writer.push_str(envelope.as_str())?;
    writer.push_u64(u64::try_from(affordances.len()).map_err(|_| DigestError::FieldTooLarge)?);
    for affordance in affordances {
        writer.push_str(affordance.class.as_str())?;
        writer.push_str(&affordance.operation)?;
        writer.push_str(&affordance.reason)?;
    }
    writer.push_u64(u64::try_from(warnings.len()).map_err(|_| DigestError::FieldTooLarge)?);
    for warning in warnings {
        writer.push_str(warning)?;
    }
    Ok(writer.digest()?)
}

fn seal_handoff(
    anchor: EvidenceAnchor,
    source_root: Digest,
    situation_digest: Digest,
    event_digest: Digest,
    absence_digest: Option<Digest>,
    effect_root: Digest,
) -> Result<Digest, ScenarioError> {
    if source_root == Digest::ZERO
        || situation_digest == Digest::ZERO
        || event_digest == Digest::ZERO
    {
        return Err(ScenarioError::Packet(
            "handoff children must publish before the handoff root",
        ));
    }
    let mut writer = CanonicalWriter::new("fss-handoff-capsule-v1")?;
    writer.push_u64(anchor.sequence);
    writer.push_u64(anchor.observed_at);
    writer.push_digest(anchor.root);
    writer.push_digest(source_root);
    writer.push_digest(situation_digest);
    writer.push_digest(event_digest);
    writer.push_bool(absence_digest.is_some());
    if let Some(digest) = absence_digest {
        writer.push_digest(digest);
    }
    writer.push_digest(effect_root);
    Ok(writer.digest()?)
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
        ObservationClass::Homeowner => 1,
        ObservationClass::Raccoon => 2,
        ObservationClass::UnknownPerson => 3,
    });
    bytes.extend_from_slice(&confidence_basis_points.to_be_bytes());
    Ok(bytes)
}

fn decode_packet(bytes: &[u8]) -> Result<DecodedPacket, ScenarioError> {
    if bytes.len() < 4 || &bytes[..4] != b"FSS1" {
        return Err(ScenarioError::Packet("bad magic"));
    }
    let mut cursor = 4;
    let sensor = read_string(bytes, &mut cursor)?;
    let failure_domain = read_string(bytes, &mut cursor)?;
    let tick = read_u64(bytes, &mut cursor)?;
    let class = match read_u8(bytes, &mut cursor)? {
        0 => ObservationClass::Empty,
        1 => ObservationClass::Homeowner,
        2 => ObservationClass::Raccoon,
        3 => ObservationClass::UnknownPerson,
        _ => return Err(ScenarioError::Packet("unknown observation class")),
    };
    let confidence_basis_points = read_u16(bytes, &mut cursor)?;
    if confidence_basis_points > 10_000 {
        return Err(ScenarioError::Packet(
            "confidence exceeds 10000 basis points",
        ));
    }
    if cursor != bytes.len() {
        return Err(ScenarioError::Packet("trailing bytes"));
    }
    Ok(DecodedPacket {
        sensor,
        failure_domain,
        tick,
        class,
        confidence_basis_points,
    })
}

fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, ScenarioError> {
    let length = usize::from(read_u16(bytes, cursor)?);
    let end = cursor
        .checked_add(length)
        .ok_or(ScenarioError::Packet("string length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ScenarioError::Packet("truncated string"))?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| ScenarioError::Packet("invalid UTF-8"))
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ScenarioError> {
    let value = *bytes
        .get(*cursor)
        .ok_or(ScenarioError::Packet("truncated u8"))?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(ScenarioError::Packet("cursor overflow"))?;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ScenarioError> {
    let end = cursor
        .checked_add(2)
        .ok_or(ScenarioError::Packet("cursor overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ScenarioError::Packet("truncated u16"))?;
    *cursor = end;
    Ok(u16::from_be_bytes(
        value.try_into().map_err(|_| ScenarioError::Packet("u16"))?,
    ))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ScenarioError> {
    let end = cursor
        .checked_add(8)
        .ok_or(ScenarioError::Packet("cursor overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ScenarioError::Packet("truncated u64"))?;
    *cursor = end;
    Ok(u64::from_be_bytes(
        value.try_into().map_err(|_| ScenarioError::Packet("u64"))?,
    ))
}

fn event_disposition_str(value: EventDisposition) -> &'static str {
    match value {
        EventDisposition::QuietCertified => "quiet",
        EventDisposition::BenignKnown => "benign",
        EventDisposition::ProtectedResidual => "protected_residual",
        EventDisposition::CorroboratedThreat => "corroborated_threat",
    }
}

fn effect_state_str(value: EffectState) -> &'static str {
    match value {
        EffectState::Prepared => "prepared",
        EffectState::Dispatching => "dispatching",
        EffectState::AppliedAwaitingVerification => "applied_awaiting_verification",
        EffectState::Verified => "verified",
        EffectState::CancelRequested => "cancel_requested",
        EffectState::Cancelled => "cancelled",
        EffectState::Failed => "failed",
        EffectState::Indeterminate => "indeterminate",
    }
}

fn obligation_state_str(value: ObligationState) -> &'static str {
    match value {
        ObligationState::Pending => "pending",
        ObligationState::Satisfied => "satisfied",
        ObligationState::Failed => "failed",
        ObligationState::Indeterminate => "indeterminate",
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
    use crate::effects::{EffectState, ObligationState};

    #[test]
    fn quiet_requires_and_earns_certified_absence() {
        let report = run_scenario(ScenarioKind::Quiet).expect("quiet");
        assert_eq!(report.envelope, EnvelopeClass::CertifiedQuiet);
        assert!(report.absence.is_some());
        assert!(report.effect_state.is_none());
    }

    #[test]
    fn raccoon_is_benign_without_alert_effect() {
        let report = run_scenario(ScenarioKind::Raccoon).expect("raccoon");
        assert_eq!(report.envelope, EnvelopeClass::BenignActivity);
        assert!(report.effect_state.is_none());
    }

    #[test]
    fn independent_intrusion_observations_verify_alert() {
        let report = run_scenario(ScenarioKind::Intrusion).expect("intrusion");
        assert_eq!(report.envelope, EnvelopeClass::CorroboratedThreat);
        assert_eq!(report.effect_state, Some(EffectState::Verified));
        assert_eq!(report.obligation_state, Some(ObligationState::Satisfied));
    }

    #[test]
    fn sneaky_intrusion_remains_protected_when_coverage_has_a_gap() {
        let report = run_scenario(ScenarioKind::Sneaky).expect("sneaky");
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(report.absence.is_none());
        assert!(
            report
                .affordances
                .iter()
                .any(|affordance| affordance.operation.starts_with("investigate."))
        );
    }

    #[test]
    fn lost_ack_is_reconciled_without_duplicate_dispatch() {
        let report = run_scenario(ScenarioKind::LostAcknowledgement).expect("lost ack");
        assert!(report.transient_indeterminate);
        assert_eq!(report.effect_state, Some(EffectState::Verified));
        assert_eq!(report.obligation_state, Some(ObligationState::Satisfied));
    }

    #[test]
    fn corrupted_source_destroys_coverage_not_truthfulness() {
        let report = run_scenario(ScenarioKind::CorruptSource).expect("corrupt source");
        assert_eq!(report.envelope, EnvelopeClass::ProtectedResidual);
        assert!(report.absence.is_none());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.starts_with("source_corrupt:"))
        );
    }

    #[test]
    fn replay_is_byte_identical() {
        for scenario in [
            ScenarioKind::Quiet,
            ScenarioKind::Raccoon,
            ScenarioKind::Intrusion,
            ScenarioKind::Sneaky,
            ScenarioKind::LostAcknowledgement,
            ScenarioKind::CorruptSource,
        ] {
            let first = run_scenario(scenario).expect("first").render_json();
            let second = run_scenario(scenario).expect("second").render_json();
            assert_eq!(first, second, "scenario {} drifted", scenario.as_str());
        }
    }
}
