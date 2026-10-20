#![forbid(unsafe_code)]
//! Explicit owner-enrolled network observations in the canonical evidence history.
//! Cached ARP/OUI metadata never refreshes liveness. Response times are bounded by the
//! discovery sweep, and conservative aging includes its duration. Network responses
//! establish neither authenticated identity nor decoded pixels or media continuity.

use super::census::REGISTERED_PORTS;
use super::watchdog::{DeviceClass, DeviceWatchdog, WatchOfflineReason, WatchState};
use super::{DiscoverReport, DiscoverySighting};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    BatchId, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane, SensorId,
    TimestampNs,
};
use fss_publication::SlotName;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

/// Reserved authority family, distinct from media continuity.
pub const FAMILY_SENSOR_LIVENESS: &str = "sensor_liveness";
/// Reserved stable sensor namespace.
pub const LIVENESS_OBJECT_PREFIX: &str = "object:sensor-liveness:";
/// Canonical observation compatibility domain.
pub const LIVENESS_RECORD_DOMAIN: &str = "fss.sensor_liveness_record.v1";
/// Source-attributed protocol responses extend v1 without changing old payloads.
pub const LIVENESS_RECORD_DOMAIN_V2: &str = "fss.sensor_liveness_record.v2";
/// Canonical immutable owner-binding compatibility domain.
pub const LIVENESS_ENROLLMENT_DOMAIN: &str = "fss.sensor_liveness_enrollment.v1";
/// Maximum retained enrollment inventory.
pub const MAX_LIVENESS_SENSORS: usize = 64;
/// Maximum canonical record bytes.
pub const MAX_LIVENESS_RECORD_BYTES: usize = 4096;

/// Explicit binding; a network address never becomes a stable sensor identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceEnrollment {
    endpoint: Ipv4Addr,
    sensor: SensorId,
    class: DeviceClass,
    grace_ns: u64,
    hard_ns: u64,
}
impl DeviceEnrollment {
    /// Uses the existing watchdog class thresholds.
    pub fn new(
        endpoint: Ipv4Addr,
        sensor: SensorId,
        class: DeviceClass,
    ) -> Result<Self, LivenessError> {
        Self::with_thresholds(endpoint, sensor, class, class.default_thresholds_ns())
    }
    /// Declares a silence policy which later sweeps must preserve exactly.
    pub fn with_thresholds(
        endpoint: Ipv4Addr,
        sensor: SensorId,
        class: DeviceClass,
        thresholds: (u64, u64),
    ) -> Result<Self, LivenessError> {
        let (grace_ns, hard_ns) = thresholds;
        if endpoint.is_unspecified()
            || endpoint.is_multicast()
            || endpoint.is_broadcast()
            || sensor.as_str().len() > 256
            || grace_ns == 0
            || hard_ns <= grace_ns
        {
            return Err(LivenessError::InvalidEnrollment);
        }
        Ok(Self {
            endpoint,
            sensor,
            class,
            grace_ns,
            hard_ns,
        })
    }
    /// Owner-named endpoint.
    pub const fn endpoint(&self) -> Ipv4Addr {
        self.endpoint
    }
    /// Stable sensor identity.
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }
    /// Explicit class; discovery never silently replaces it.
    pub const fn class(&self) -> DeviceClass {
        self.class
    }
    /// Grace and hard-silence durations.
    pub const fn thresholds_ns(&self) -> (u64, u64) {
        (self.grace_ns, self.hard_ns)
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(LIVENESS_ENROLLMENT_DOMAIN);
        e.text(&self.endpoint.to_string());
        e.text(self.sensor.as_str());
        e.text(self.class.as_str());
        e.u64(self.grace_ns);
        e.u64(self.hard_ns);
    }
    /// Digest of the exact owner binding and silence policy.
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        ContentDigest::sha256(&e.finish())
    }
    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, LivenessError> {
        if d.text()? != LIVENESS_ENROLLMENT_DOMAIN {
            return Err(LivenessError::Corrupt);
        }
        let endpoint = d.text()?.parse().map_err(|_| LivenessError::Corrupt)?;
        let sensor = SensorId::parse(d.text()?)?;
        let class = parse_device_class(d.text()?).ok_or(LivenessError::Corrupt)?;
        Self::with_thresholds(endpoint, sensor, class, (d.u64()?, d.u64()?))
    }
    fn object_id(&self) -> Result<ObjectId, LivenessError> {
        Ok(ObjectId::parse(format!(
            "{LIVENESS_OBJECT_PREFIX}{}",
            hex(ContentDigest::sha256(self.sensor.as_str().as_bytes()))
        ))?)
    }
}
/// Parses the existing watchdog class vocabulary.
pub fn parse_device_class(value: &str) -> Option<DeviceClass> {
    Some(match value {
        "tutk" => DeviceClass::Tutk,
        "tuya" => DeviceClass::Tuya,
        "onvif" => DeviceClass::Onvif,
        "battery_event_driven" => DeviceClass::BatteryEventDriven,
        "unknown" => DeviceClass::Unknown,
        "provisioned_agent" => DeviceClass::ProvisionedAgent,
        _ => return None,
    })
}

/// A failure never permits a healthy fallback or inferred source continuity.
#[derive(Debug)]
pub enum LivenessError {
    /// Ambiguous, duplicate or malformed owner binding.
    InvalidEnrollment,
    /// An existing sensor or endpoint would be rebound.
    EnrollmentChanged,
    /// Time regressed, windows overlap, or an exact retry changed.
    ClockOrReplayConflict,
    /// A record, inventory, or generation bound was exceeded.
    Limit,
    /// Cancellation; inspect the committed prefix before retry.
    Cancelled,
    /// Canonical bytes, lineage or custody disagree with authority.
    Corrupt,
    /// Owning canonical contract rejected a value.
    Contract(ContractError),
    /// Owning deployment boundary refused progress.
    Deployment(crate::ReferenceError),
    /// An exact retained object is unavailable.
    Storage(fss_object::SpoolError),
}
impl std::fmt::Display for LivenessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnrollment => f.write_str("invalid or ambiguous liveness enrollment"),
            Self::EnrollmentChanged => {
                f.write_str("liveness enrollment changed; preserve retained owner binding")
            }
            Self::ClockOrReplayConflict => {
                f.write_str("liveness clock/window regressed or exact retry changed")
            }
            Self::Limit => f.write_str("liveness work or record bound exceeded"),
            Self::Cancelled => {
                f.write_str("liveness publication cancelled; inspect committed prefix before retry")
            }
            Self::Corrupt => f.write_str("liveness metadata or retained publication is corrupt"),
            Self::Contract(e) => write!(f, "liveness contract: {e}"),
            Self::Deployment(e) => write!(f, "liveness deployment: {e}"),
            Self::Storage(e) => write!(f, "liveness custody: {e}"),
        }
    }
}
impl std::error::Error for LivenessError {}
impl From<ContractError> for LivenessError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
impl From<crate::ReferenceError> for LivenessError {
    fn from(e: crate::ReferenceError) -> Self {
        Self::Deployment(e)
    }
}
impl From<fss_object::SpoolError> for LivenessError {
    fn from(e: fss_object::SpoolError) -> Self {
        Self::Storage(e)
    }
}

/// Canonical host observation, with response uncertainty bounded by the sweep window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorLivenessRecord {
    site: String,
    enrollment: DeviceEnrollment,
    generation: u64,
    previous: Option<ContentDigest>,
    sweep_started_ns: u64,
    observed_at_ns: u64,
    last_seen_ns: Option<u64>,
    last_seen_until_ns: Option<u64>,
    last_unobserved_ns: Option<u64>,
    tcp_ports: Vec<u16>,
    beacon_commands: Vec<u32>,
    protocol_responses: Vec<DiscoverySighting>,
}
impl SensorLivenessRecord {
    /// Immutable owner binding.
    pub fn enrollment(&self) -> &DeviceEnrollment {
        &self.enrollment
    }
    /// Start of this sweep window.
    pub const fn sweep_started_ns(&self) -> u64 {
        self.sweep_started_ns
    }
    /// Completion of this sweep, not an exact endpoint-response time.
    pub const fn observed_at_ns(&self) -> u64 {
        self.observed_at_ns
    }
    /// Earliest possible last response; conservative aging uses this lower bound.
    pub const fn last_seen_ns(&self) -> Option<u64> {
        self.last_seen_ns
    }
    /// Latest possible time of that same last response.
    pub const fn last_response_latest_ns(&self) -> Option<u64> {
        self.last_seen_until_ns
    }
    /// Last unobservable evaluation, retained even after network rediscovery.
    pub const fn last_unobserved_ns(&self) -> Option<u64> {
        self.last_unobserved_ns
    }
    /// Conservative class-grace deadline; not a promise of media continuity.
    pub fn fresh_until_ns(&self) -> Option<u64> {
        self.last_seen_ns?.checked_add(self.enrollment.grace_ns)
    }
    /// Per-sensor authority generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact predecessor payload.
    pub const fn previous_digest(&self) -> Option<ContentDigest> {
        self.previous
    }
    /// Source-attributed protocol responses in this sweep, ordered by stable spelling.
    /// These are responses from the enrolled endpoint, not advertised remote targets.
    pub fn protocol_responses(&self) -> &[DiscoverySighting] {
        &self.protocol_responses
    }
    /// Whether this sweep has an actual TCP, beacon, or source-attributed protocol response.
    pub fn fresh_sighting(&self) -> bool {
        !self.tcp_ports.is_empty()
            || !self.beacon_commands.is_empty()
            || !self.protocol_responses.is_empty()
    }
    /// Network state at sweep completion; even Observable proves no media continuity.
    pub fn state(&self) -> WatchState {
        let mut watchdog = DeviceWatchdog::new();
        watchdog.register(
            "enrolled",
            self.enrollment.class,
            Some(self.enrollment.thresholds_ns()),
        );
        if let Some(last) = self.last_seen_ns {
            watchdog.observe("enrolled", last);
        }
        watchdog.evaluate(self.observed_at_ns);
        watchdog
            .state_of("enrolled")
            .cloned()
            .unwrap_or(WatchState::NotObservable {
                reason: WatchOfflineReason::NeverObserved,
            })
    }
    /// Canonical bytes independent of report JSON.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(if self.protocol_responses.is_empty() {
            LIVENESS_RECORD_DOMAIN
        } else {
            LIVENESS_RECORD_DOMAIN_V2
        });
        e.text(&self.site);
        self.enrollment.encode(&mut e);
        e.u64(self.generation);
        e.bool(self.previous.is_some());
        if let Some(previous) = self.previous {
            e.digest(previous);
        }
        e.u64(self.sweep_started_ns);
        e.u64(self.observed_at_ns);
        for time in [
            self.last_seen_ns,
            self.last_seen_until_ns,
            self.last_unobserved_ns,
        ] {
            e.bool(time.is_some());
            if let Some(time) = time {
                e.u64(time);
            }
        }
        e.u64(self.tcp_ports.len() as u64);
        for port in &self.tcp_ports {
            e.u32(u32::from(*port));
        }
        e.u64(self.beacon_commands.len() as u64);
        for command in &self.beacon_commands {
            e.u32(*command);
        }
        if !self.protocol_responses.is_empty() {
            e.u64(self.protocol_responses.len() as u64);
            for response in &self.protocol_responses {
                e.text(response.as_str());
            }
        }
        e.finish()
    }
    /// Exact payload identity.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Strict bounded decoding rejects impossible time, state, and generation combinations.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LivenessError> {
        if bytes.len() > MAX_LIVENESS_RECORD_BYTES {
            return Err(LivenessError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        let has_protocol_responses = match d.text()? {
            LIVENESS_RECORD_DOMAIN => false,
            LIVENESS_RECORD_DOMAIN_V2 => true,
            _ => return Err(LivenessError::Corrupt),
        };
        let site = d.text()?.to_owned();
        crate::reference_deployment::validate_site_lineage(&site)?;
        if site.len() > 256 {
            return Err(LivenessError::Limit);
        }
        let enrollment = DeviceEnrollment::decode(&mut d)?;
        let generation = d.u64()?;
        let previous = if d.bool()? { Some(d.digest()?) } else { None };
        let sweep_started_ns = d.u64()?;
        let observed_at_ns = d.u64()?;
        let last_seen_ns = if d.bool()? { Some(d.u64()?) } else { None };
        let last_seen_until_ns = if d.bool()? { Some(d.u64()?) } else { None };
        let last_unobserved_ns = if d.bool()? { Some(d.u64()?) } else { None };
        let port_count = d.u64()?;
        if port_count > REGISTERED_PORTS.len() as u64 {
            return Err(LivenessError::Limit);
        }
        let mut tcp_ports = Vec::new();
        for _ in 0..port_count {
            let port = u16::try_from(d.u32()?).map_err(|_| LivenessError::Corrupt)?;
            if !REGISTERED_PORTS.contains(&port)
                || tcp_ports.last().is_some_and(|last| *last >= port)
            {
                return Err(LivenessError::Corrupt);
            }
            tcp_ports.push(port);
        }
        let beacon_count = d.u64()?;
        if beacon_count > 256 {
            return Err(LivenessError::Limit);
        }
        let mut beacon_commands = Vec::new();
        for _ in 0..beacon_count {
            let command = d.u32()?;
            if beacon_commands.last().is_some_and(|last| *last >= command) {
                return Err(LivenessError::Corrupt);
            }
            beacon_commands.push(command);
        }
        let mut protocol_responses: Vec<DiscoverySighting> = Vec::new();
        if has_protocol_responses {
            let count = d.u64()?;
            if count == 0 {
                return Err(LivenessError::Corrupt);
            }
            if count > DiscoverySighting::COUNT as u64 {
                return Err(LivenessError::Limit);
            }
            for _ in 0..count {
                let response = DiscoverySighting::parse(d.text()?).ok_or(LivenessError::Corrupt)?;
                if protocol_responses
                    .last()
                    .is_some_and(|last| last.as_str() >= response.as_str())
                {
                    return Err(LivenessError::Corrupt);
                }
                protocol_responses.push(response);
            }
        }
        d.ensure_finished()?;
        let record = Self {
            site,
            enrollment,
            generation,
            previous,
            sweep_started_ns,
            observed_at_ns,
            last_seen_ns,
            last_seen_until_ns,
            last_unobserved_ns,
            tcp_ports,
            beacon_commands,
            protocol_responses,
        };
        if generation == 0
            || (generation == 1) != previous.is_none()
            || sweep_started_ns > observed_at_ns
            || last_seen_ns.is_some() != last_seen_until_ns.is_some()
            || last_seen_ns
                .zip(last_seen_until_ns)
                .is_some_and(|(earliest, latest)| earliest > latest || latest > observed_at_ns)
            || last_unobserved_ns.is_some_and(|time| time > observed_at_ns)
            || (record.fresh_sighting()
                && (last_seen_ns != Some(sweep_started_ns)
                    || last_seen_until_ns != Some(observed_at_ns)))
            || (!record.fresh_sighting()
                && last_seen_until_ns.is_some_and(|time| time > sweep_started_ns))
            || (generation == 1 && !record.fresh_sighting() && last_seen_ns.is_some())
            || (record.state() != WatchState::Observable
                && last_unobserved_ns != Some(observed_at_ns))
            || (record.state() == WatchState::Observable
                && (last_unobserved_ns == Some(observed_at_ns)
                    || last_unobserved_ns
                        .is_some_and(|time| generation == 1 || time > sweep_started_ns)))
            || record.to_bytes() != bytes
        {
            return Err(LivenessError::Corrupt);
        }
        Ok(record)
    }
    fn validity(&self) -> CaptureInterval {
        CaptureInterval {
            earliest: TimestampNs(i128::from(self.sweep_started_ns)),
            latest: TimestampNs(i128::from(self.observed_at_ns)),
        }
    }
    fn delta(&self, root: ContentDigest) -> Result<EvidenceDelta, LivenessError> {
        Ok(EvidenceDelta {
            delta_id: format!("delta:sensor-liveness:{}", hex(self.digest())),
            family: FAMILY_SENSOR_LIVENESS.into(),
            object_id: self.enrollment.object_id()?,
            prior_generation: self
                .generation
                .checked_sub(1)
                .filter(|generation| *generation > 0),
            new_generation: self.generation,
            validity: self.validity(),
            plane: Plane::Authority,
            payload_digest: self.digest(),
            witness_digest: Some(root),
            operation_id: None,
        })
    }
}

/// Latest verified network observation and its root-last publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSensorLiveness {
    /// Latest observation at the selected committed prefix.
    pub record: SensorLivenessRecord,
    /// Root-last custody manifest.
    pub root: ContentDigest,
    /// Anchor of the liveness update.
    pub anchor: LedgerAnchor,
}
/// Read-only validation before network, directory creation or mutable deployment open.
pub fn validate_enrollments(
    enrollments: &[DeviceEnrollment],
    retained: &[RetainedSensorLiveness],
) -> Result<(), LivenessError> {
    if enrollments.is_empty()
        || enrollments.len() > MAX_LIVENESS_SENSORS
        || retained.len() > MAX_LIVENESS_SENSORS
    {
        return Err(LivenessError::Limit);
    }
    let mut sensors = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for enrollment in enrollments {
        if !sensors.insert(enrollment.sensor.as_str()) || !endpoints.insert(enrollment.endpoint) {
            return Err(LivenessError::InvalidEnrollment);
        }
        for old in retained {
            let prior = &old.record.enrollment;
            if (prior.sensor == enrollment.sensor || prior.endpoint == enrollment.endpoint)
                && prior != enrollment
            {
                return Err(LivenessError::EnrollmentChanged);
            }
        }
    }
    let new_count = enrollments
        .iter()
        .filter(|enrollment| {
            !retained
                .iter()
                .any(|old| old.record.enrollment.sensor == enrollment.sensor)
        })
        .count();
    if retained.len() + new_count > MAX_LIVENESS_SENSORS {
        return Err(LivenessError::Limit);
    }
    Ok(())
}

/// Reads the latest metadata from a verified ledger prefix. The callback owns bytes and
/// deletion authority. At most two bounded objects per sensor are read; no media is opened.
pub fn read_liveness_inventory(
    batches: &[EvidenceDeltaBatch],
    mut read: impl FnMut(ContentDigest, usize) -> Result<Vec<u8>, LivenessError>,
) -> Result<Vec<RetainedSensorLiveness>, LivenessError> {
    let mut latest =
        BTreeMap::<String, (&EvidenceDeltaBatch, &EvidenceDelta, Option<ContentDigest>)>::new();
    for batch in batches {
        for delta in &batch.deltas {
            if delta.family != FAMILY_SENSOR_LIVENESS {
                if delta.object_id.as_str().starts_with(LIVENESS_OBJECT_PREFIX) {
                    return Err(LivenessError::Corrupt);
                }
                continue;
            }
            let key = delta.object_id.as_str().to_owned();
            let previous = latest.get(&key).map(|(_, prior, _)| *prior);
            if Some(delta.new_generation)
                != previous.map_or(Some(1), |prior| prior.new_generation.checked_add(1))
                || delta.prior_generation != previous.map(|prior| prior.new_generation)
            {
                return Err(LivenessError::Corrupt);
            }
            latest.insert(
                key,
                (batch, delta, previous.map(|prior| prior.payload_digest)),
            );
            if latest.len() > MAX_LIVENESS_SENSORS {
                return Err(LivenessError::Limit);
            }
        }
    }
    let mut inventory = Vec::with_capacity(latest.len());
    let mut endpoints = BTreeSet::new();
    for (_, (batch, delta, previous)) in latest {
        let bytes = read(delta.payload_digest, MAX_LIVENESS_RECORD_BYTES)?;
        let record = SensorLivenessRecord::from_bytes(&bytes)?;
        let root = delta.witness_digest.ok_or(LivenessError::Corrupt)?;
        let slot = record_slot(record.digest())?;
        let manifest = fss_object::ObjectManifest::new(slot.as_str(), [record.digest()], None)
            .map_err(crate::ReferenceError::from)?;
        let mut children = vec![record.digest(), root];
        children.sort_unstable();
        if record.digest() != delta.payload_digest
            || record.previous != previous
            || record.site != batch.new_anchor.site_lineage
            || record.site != batch.basis_anchor.site_lineage
            || record.delta(root)? != *delta
            || batch.deltas != [delta.clone()]
            || batch.children != children
            || batch.batch_id != record_batch(record.digest())?
            || root != manifest.root()
            || read(root, MAX_LIVENESS_RECORD_BYTES)? != manifest.canonical_bytes()
            || !endpoints.insert(record.enrollment.endpoint)
        {
            return Err(LivenessError::Corrupt);
        }
        let published = batches.iter().any(|candidate| {
            candidate.new_anchor.commit_sequence < batch.new_anchor.commit_sequence
                && candidate.deltas.iter().any(|entry| {
                    entry.family == fss_publication::ROOT_REACHABILITY_FAMILY
                        && entry.object_id.as_str() == format!("object:local-root:{slot}")
                        && entry.payload_digest == root
                })
        });
        if !published {
            return Err(LivenessError::Corrupt);
        }
        inventory.push(RetainedSensorLiveness {
            record,
            root,
            anchor: batch.new_anchor.clone(),
        });
    }
    Ok(inventory)
}
fn fresh_evidence(
    report: &DiscoverReport,
    endpoint: Ipv4Addr,
) -> (BTreeSet<u16>, BTreeSet<u32>, Vec<DiscoverySighting>) {
    let ports = report
        .candidates
        .iter()
        .filter(|candidate| candidate.host.ip == endpoint)
        .flat_map(|candidate| candidate.host.open_ports.iter().copied())
        .filter(|port| REGISTERED_PORTS.contains(port))
        .collect();
    let commands = report
        .beacons
        .iter()
        .filter_map(|(source, command)| {
            source
                .parse::<SocketAddr>()
                .ok()
                .filter(|address| address.ip() == std::net::IpAddr::V4(endpoint))
                .map(|_| *command)
        })
        .collect();
    let mut responses: Vec<_> = report
        .current_responses
        .iter()
        .filter(|response| response.endpoint == endpoint)
        .map(|response| response.kind)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    responses.sort_unstable_by_key(|response| response.as_str());
    (ports, commands, responses)
}
/// Concrete fresh endpoint evidence, excluding cached metadata and unattributed probe counts.
pub fn has_fresh_sighting(report: &DiscoverReport, endpoint: Ipv4Addr) -> bool {
    let (ports, commands, responses) = fresh_evidence(report, endpoint);
    !ports.is_empty() || !commands.is_empty() || !responses.is_empty()
}
/// Retains a zero-duration replay/fixture observation. Live discovery uses the actual
/// interval through retain_discovery_window.
pub fn retain_discovery_sweep(
    deployment: &mut ReferenceDeployment,
    enrollments: &[DeviceEnrollment],
    report: &DiscoverReport,
    observed_at_ns: u64,
    cx: &ReplayCx,
) -> Result<Vec<RetainedSensorLiveness>, LivenessError> {
    retain_discovery_window(
        deployment,
        enrollments,
        report,
        observed_at_ns,
        observed_at_ns,
        cx,
    )
}
/// Publishes a complete owner-scoped sweep. Responses are bounded by its start/completion
/// interval, and age starts at the earliest possible response. All bindings, windows and
/// retry evidence are checked before staging. Later windows must not overlap.
/// The deployment lock covers this call only, never network discovery or waiting.
pub fn retain_discovery_window(
    deployment: &mut ReferenceDeployment,
    enrollments: &[DeviceEnrollment],
    report: &DiscoverReport,
    sweep_started_ns: u64,
    observed_at_ns: u64,
    cx: &ReplayCx,
) -> Result<Vec<RetainedSensorLiveness>, LivenessError> {
    checkpoint(cx, "sensor_liveness:prepare")?;
    if sweep_started_ns > observed_at_ns {
        return Err(LivenessError::ClockOrReplayConflict);
    }
    if report.candidates.len() > super::census::MAX_SUBNET_HOSTS as usize
        || report.beacons.len() > 256
        || report.current_responses.len()
            > super::census::MAX_SUBNET_HOSTS as usize * DiscoverySighting::COUNT
    {
        return Err(LivenessError::Limit);
    }
    let retained = read_liveness_inventory(deployment.ledger().batches(), |digest, max| {
        checkpoint(cx, "sensor_liveness:read")?;
        Ok(deployment.publisher().spool().read_bounded(digest, max)?)
    })?;
    validate_enrollments(enrollments, &retained)?;
    let mut records = Vec::with_capacity(enrollments.len());
    for enrollment in enrollments {
        let previous = retained
            .iter()
            .find(|old| old.record.enrollment.sensor == enrollment.sensor);
        let (ports, commands, responses) = fresh_evidence(report, enrollment.endpoint);
        let seen = !ports.is_empty() || !commands.is_empty() || !responses.is_empty();
        if let Some(old) = previous {
            if observed_at_ns < old.record.observed_at_ns {
                return Err(LivenessError::ClockOrReplayConflict);
            }
            if observed_at_ns == old.record.observed_at_ns {
                if sweep_started_ns != old.record.sweep_started_ns
                    || old.record.tcp_ports != ports.iter().copied().collect::<Vec<_>>()
                    || old.record.beacon_commands != commands.iter().copied().collect::<Vec<_>>()
                    || old.record.protocol_responses != responses
                {
                    return Err(LivenessError::ClockOrReplayConflict);
                }
                records.push((old.record.clone(), Some(old.clone())));
                continue;
            }
            if sweep_started_ns < old.record.observed_at_ns {
                return Err(LivenessError::ClockOrReplayConflict);
            }
        }
        let mut record = SensorLivenessRecord {
            site: deployment.site_lineage().to_owned(),
            enrollment: enrollment.clone(),
            generation: previous
                .map_or(Some(1), |old| old.record.generation.checked_add(1))
                .ok_or(LivenessError::Limit)?,
            previous: previous.map(|old| old.record.digest()),
            sweep_started_ns,
            observed_at_ns,
            last_seen_ns: if seen {
                Some(sweep_started_ns)
            } else {
                previous.and_then(|old| old.record.last_seen_ns)
            },
            last_seen_until_ns: if seen {
                Some(observed_at_ns)
            } else {
                previous.and_then(|old| old.record.last_seen_until_ns)
            },
            last_unobserved_ns: previous.and_then(|old| old.record.last_unobserved_ns),
            tcp_ports: ports.into_iter().collect(),
            beacon_commands: commands.into_iter().collect(),
            protocol_responses: responses,
        };
        if record.state() != WatchState::Observable {
            record.last_unobserved_ns = Some(observed_at_ns);
        }
        SensorLivenessRecord::from_bytes(&record.to_bytes())?;
        records.push((record, None));
    }
    records.sort_by(|(a, _), (b, _)| a.enrollment.sensor.cmp(&b.enrollment.sensor));
    let mut result = Vec::with_capacity(records.len());
    for (record, already_retained) in records {
        if let Some(old) = already_retained {
            result.push(old);
            continue;
        }
        checkpoint(cx, "sensor_liveness:stage")?;
        let bytes = record.to_bytes();
        let slot = record_slot(record.digest())?;
        let manifest = fss_object::ObjectManifest::new(slot.as_str(), [record.digest()], None)
            .map_err(crate::ReferenceError::from)?;
        let root = manifest.root();
        // Cancellation after root publication can leave this exact slot staged or visible
        // before its liveness delta is appended. Restaging a visible manifest is a conflict.
        // Reuse its metadata and let publication reverify the exact root and every reference.
        // Broken or conflicting custody is refused, never silently replaced on retry.
        if deployment.publisher().is_broken_slot(&slot) {
            return Err(LivenessError::Corrupt);
        }
        if let Some(existing) = deployment.publisher().root(&slot) {
            if existing.root != root {
                return Err(LivenessError::Corrupt);
            }
        } else if deployment.stage_payload(&bytes)? != record.digest() {
            return Err(LivenessError::Corrupt);
        }
        deployment.publish_and_commit(&slot, &manifest, record.validity(), cx)?;
        checkpoint(cx, "sensor_liveness:commit")?;
        let mut children = vec![record.digest(), root];
        children.sort_unstable();
        let anchor = deployment.append_sensor_liveness_batch(
            record_batch(record.digest())?,
            vec![record.delta(root)?],
            children,
            cx,
        )?;
        result.push(RetainedSensorLiveness {
            record,
            root,
            anchor,
        });
    }
    Ok(result)
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), LivenessError> {
    cx.checkpoint(stage).map_err(|_| LivenessError::Cancelled)
}
fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn record_slot(digest: ContentDigest) -> Result<SlotName, LivenessError> {
    SlotName::parse(&format!("liveness-{}", hex(digest))).map_err(|_| LivenessError::Corrupt)
}
fn record_batch(digest: ContentDigest) -> Result<BatchId, LivenessError> {
    Ok(BatchId::parse(format!(
        "batch:sensor-liveness:{}",
        hex(digest)
    ))?)
}

#[cfg(test)]
mod tests;
