//! The on-camera FSS agent's self-description and liveness contract (LAB-
//! PROVISION-001).
//!
//! Once the bundle is flashed, the on-camera agent reports **who it is**
//! (which family, which digest-pinned software generation, which tailnet
//! status, which standards endpoints it exposes) and a **liveness/coverage**
//! heartbeat. This module defines those types deterministically and sans-IO:
//!
//! * [`CameraAgentReport`] — the full self-description, digest-pinned.
//! * [`AgentHeartbeat`] — the compact per-interval beat (digest, sequence,
//!   coverage).
//! * [`HeartbeatTracker`] — the consumer-side state machine that turns a
//!   stream of beats into a [`Liveness`] and, crucially, turns *silence into
//!   a typed transition* (Silent → Dark) rather than a silent absence.
//!   Sequence anomalies stay here. The DISC-5 dark-camera watchdog does not
//!   read this type directly: `fss_reference::discovery::liveness` feeds each
//!   received beat in as a sighting and each missed interval into the
//!   watchdog's own clock.
//!
//! A transition is evidence: `WentSilent`, `WentDark`, `Restored`,
//! `DuplicateSequence`, and `SequenceReset` are all distinct, observable
//! states — never flattened into "no data".

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError,
};

use crate::family::CameraFamily;

/// Health of the on-camera agent process.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AgentHealth {
    /// Fully healthy.
    Nominal = 1,
    /// Running but degraded (e.g. swap thrashing, retrying).
    Degraded = 2,
    /// The agent believes it is failing to meet its contract.
    Failing = 3,
}

impl AgentHealth {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Degraded => "degraded",
            Self::Failing => "failing",
        }
    }
}

impl fmt::Display for AgentHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for AgentHealth {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for AgentHealth {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Nominal),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Failing),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// The agent's tailnet status.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TailnetStatus {
    /// Connected to the tailnet.
    Connected = 1,
    /// Dialing the control plane.
    Connecting = 2,
    /// Was connected; is now down.
    Disconnected = 3,
    /// tailscaled is not running / not enabled.
    Disabled = 4,
}

impl TailnetStatus {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Connecting => "connecting",
            Self::Disconnected => "disconnected",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for TailnetStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for TailnetStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for TailnetStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Connected),
            2 => Ok(Self::Connecting),
            3 => Ok(Self::Disconnected),
            4 => Ok(Self::Disabled),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// What the camera can currently observe (orthogonal to liveness).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AgentCoverageState {
    /// The lens is actively observing (light, moving, or a valid frame).
    Observable = 1,
    /// The lens is up but sees nothing meaningful (dark / static).
    Silent = 2,
    /// The lens is not currently observable (powered off, covered, or off).
    NotObservable = 3,
}

impl AgentCoverageState {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observable => "observable",
            Self::Silent => "silent",
            Self::NotObservable => "not_observable",
        }
    }
}

impl fmt::Display for AgentCoverageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for AgentCoverageState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for AgentCoverageState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Observable),
            2 => Ok(Self::Silent),
            3 => Ok(Self::NotObservable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// The liveness of the camera's heartbeat stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Liveness {
    /// Beats are arriving on schedule.
    Live = 1,
    /// A beat was missed; not yet dark.
    Silent = 2,
    /// Beats have been missed for the full grace window.
    Dark = 3,
}

impl Liveness {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Silent => "silent",
            Self::Dark => "dark",
        }
    }
}

impl fmt::Display for Liveness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for Liveness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for Liveness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Live),
            2 => Ok(Self::Silent),
            3 => Ok(Self::Dark),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// A standards endpoint the agent exposes (RTSP, ONVIF, or HTTP).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardsEndpoint {
    protocol: &'static str,
    uri: String,
}

impl StandardsEndpoint {
    /// The allowed protocols.
    const PROTOCOLS: [&'static str; 3] = ["rtsp", "onvif", "http"];

    /// Builds an endpoint, validating the protocol and URI.
    pub fn new(protocol: &'static str, uri: impl Into<String>) -> Result<Self, AgentError> {
        let uri = uri.into();
        if !Self::PROTOCOLS.contains(&protocol) {
            return Err(AgentError::BadEndpointProtocol(protocol.to_owned()));
        }
        if uri.is_empty() {
            return Err(AgentError::EmptyEndpointUri);
        }
        Ok(Self { protocol, uri })
    }

    /// The protocol identifier (`rtsp`, `onvif`, or `http`).
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        self.protocol
    }

    /// The endpoint URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    fn canonical_row(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(self.protocol);
        encoder.text(&self.uri);
        encoder.finish()
    }
}

fn parse_endpoint(protocol: &str) -> Result<&'static str, AgentError> {
    for known in StandardsEndpoint::PROTOCOLS {
        if known == protocol {
            return Ok(known);
        }
    }
    Err(AgentError::BadEndpointProtocol(protocol.to_owned()))
}

/// The on-camera agent's full self-description, digest-pinned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraAgentReport {
    device_family: CameraFamily,
    agent_generation: String,
    health: AgentHealth,
    tailnet_status: TailnetStatus,
    endpoints: Vec<StandardsEndpoint>,
    coverage: AgentCoverageState,
    report_digest: ContentDigest,
}

impl CameraAgentReport {
    /// Builds a report, validating the generation and endpoints and computing
    /// the report digest.
    pub fn new(
        device_family: CameraFamily,
        agent_generation: impl Into<String>,
        health: AgentHealth,
        tailnet_status: TailnetStatus,
        endpoints: Vec<StandardsEndpoint>,
        coverage: AgentCoverageState,
    ) -> Result<Self, AgentError> {
        let agent_generation = agent_generation.into();
        if agent_generation.is_empty() {
            return Err(AgentError::EmptyGeneration);
        }
        if agent_generation == "latest" {
            return Err(AgentError::LatestGeneration);
        }
        if endpoints.is_empty() {
            return Err(AgentError::NoEndpoints);
        }
        let report_digest = Self::digest_of(
            device_family,
            &agent_generation,
            health,
            tailnet_status,
            &endpoints,
            coverage,
        );
        Ok(Self {
            device_family,
            agent_generation,
            health,
            tailnet_status,
            endpoints,
            coverage,
            report_digest,
        })
    }

    /// The camera family the agent runs on.
    #[must_use]
    pub const fn device_family(&self) -> CameraFamily {
        self.device_family
    }

    /// The digest-pinned software generation the agent is running.
    #[must_use]
    pub fn agent_generation(&self) -> &str {
        &self.agent_generation
    }

    /// The agent's self-reported health.
    #[must_use]
    pub const fn health(&self) -> AgentHealth {
        self.health
    }

    /// The agent's tailnet status.
    #[must_use]
    pub const fn tailnet_status(&self) -> TailnetStatus {
        self.tailnet_status
    }

    /// The standards endpoints the agent exposes.
    #[must_use]
    pub fn endpoints(&self) -> &[StandardsEndpoint] {
        &self.endpoints
    }

    /// The camera's current coverage state.
    #[must_use]
    pub const fn coverage(&self) -> AgentCoverageState {
        self.coverage
    }

    /// The digest binding the report.
    #[must_use]
    pub const fn report_digest(&self) -> ContentDigest {
        self.report_digest
    }

    /// Whether the stored digest still matches the report (no drift).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.report_digest == self.computed_digest()
    }

    /// Recomputes the report digest from the current fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        Self::digest_of(
            self.device_family,
            &self.agent_generation,
            self.health,
            self.tailnet_status,
            &self.endpoints,
            self.coverage,
        )
    }

    fn digest_of(
        device_family: CameraFamily,
        agent_generation: &str,
        health: AgentHealth,
        tailnet_status: TailnetStatus,
        endpoints: &[StandardsEndpoint],
        coverage: AgentCoverageState,
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(device_family as u8);
        encoder.text(agent_generation);
        encoder.u8(health as u8);
        encoder.u8(tailnet_status as u8);
        encoder.u32(endpoints.len() as u32);
        for endpoint in endpoints {
            encoder.bytes(&endpoint.canonical_row());
        }
        encoder.u8(coverage as u8);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for CameraAgentReport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.device_family as u8);
        encoder.text(&self.agent_generation);
        encoder.u8(self.health as u8);
        encoder.u8(self.tailnet_status as u8);
        encoder.u32(self.endpoints.len() as u32);
        for endpoint in &self.endpoints {
            encoder.bytes(&endpoint.canonical_row());
        }
        encoder.u8(self.coverage as u8);
        encoder.digest(self.report_digest);
    }
}

impl CanonicalDecode for CameraAgentReport {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let device_family = CameraFamily::decode_canonical(decoder)?;
        let agent_generation = decoder.text()?.to_owned();
        let health = AgentHealth::decode_canonical(decoder)?;
        let tailnet_status = TailnetStatus::decode_canonical(decoder)?;
        let count = decoder.u32()?;
        let mut endpoints = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let row = decoder.bytes()?;
            let mut row_decoder = CanonicalDecoder::new(row);
            let protocol_text = row_decoder.text()?;
            let protocol =
                parse_endpoint(protocol_text).map_err(|_| ContractError::InvalidIdentifier)?;
            let uri = row_decoder.text()?.to_owned();
            row_decoder.ensure_finished()?;
            endpoints.push(
                StandardsEndpoint::new(protocol, uri)
                    .map_err(|_| ContractError::InvalidIdentifier)?,
            );
        }
        let coverage = AgentCoverageState::decode_canonical(decoder)?;
        let report_digest = decoder.digest()?;
        decoder.ensure_finished()?;
        let report = Self::new(
            device_family,
            agent_generation,
            health,
            tailnet_status,
            endpoints,
            coverage,
        )
        .map_err(|_| ContractError::InvalidIdentifier)?;
        if report.report_digest != report_digest {
            return Err(ContractError::InvalidDigest);
        }
        Ok(report)
    }
}

/// A compact per-interval heartbeat from the on-camera agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentHeartbeat {
    report_digest: ContentDigest,
    sequence: u64,
    coverage: AgentCoverageState,
    heartbeat_digest: ContentDigest,
}

impl AgentHeartbeat {
    /// Builds a heartbeat, computing its digest from the report digest,
    /// sequence, and coverage.
    #[must_use]
    pub fn new(report_digest: ContentDigest, sequence: u64, coverage: AgentCoverageState) -> Self {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(report_digest);
        encoder.u64(sequence);
        encoder.u8(coverage as u8);
        let heartbeat_digest = ContentDigest::sha256(&encoder.finish());
        Self {
            report_digest,
            sequence,
            coverage,
            heartbeat_digest,
        }
    }

    /// The report digest this heartbeat is a beat of.
    #[must_use]
    pub const fn report_digest(&self) -> ContentDigest {
        self.report_digest
    }

    /// The monotonic beat sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The coverage state at this beat.
    #[must_use]
    pub const fn coverage(&self) -> AgentCoverageState {
        self.coverage
    }

    /// The digest binding the heartbeat.
    #[must_use]
    pub const fn heartbeat_digest(&self) -> ContentDigest {
        self.heartbeat_digest
    }
}

/// A typed change in liveness (or sequence) — a transition is evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessTransition {
    /// State unchanged (still live, or already dark).
    Steady,
    /// A beat was missed; went from Live to Silent.
    WentSilent,
    /// The full grace window elapsed with no beat; went to Dark.
    WentDark,
    /// A beat arrived after silence/dark; back to Live.
    Restored,
    /// A beat repeated the last sequence (stuck or replayed agent).
    DuplicateSequence {
        /// The repeated sequence number.
        sequence: u64,
    },
    /// The sequence went backwards (the agent rebooted).
    SequenceReset {
        /// The previously-seen (higher) sequence.
        from: u64,
        /// The reset (lower) sequence.
        to: u64,
    },
}

/// Consumer-side liveness state machine over a heartbeat stream.
///
/// It turns the absence of a beat into a typed transition rather than a
/// silent gap. It does not own the DISC-5 dark-camera clock. Callers that
/// also track discovery sightings pass each beat and each missed interval
/// through `fss_reference::discovery::liveness`.
#[derive(Clone, Debug)]
pub struct HeartbeatTracker {
    grace: u64,
    last_sequence: Option<u64>,
    last_coverage: AgentCoverageState,
    liveness: Liveness,
    missed: u64,
    seen: u64,
}

impl HeartbeatTracker {
    /// Creates a tracker; a camera is declared Dark only after `grace`
    /// consecutive missed intervals. `grace` is clamped to at least 1.
    #[must_use]
    pub const fn new(grace: u64) -> Self {
        Self {
            grace: if grace < 1 { 1 } else { grace },
            last_sequence: None,
            last_coverage: AgentCoverageState::NotObservable,
            liveness: Liveness::Live,
            missed: 0,
            seen: 0,
        }
    }

    /// The grace window (missed intervals before Dark).
    #[must_use]
    pub const fn grace(&self) -> u64 {
        self.grace
    }

    /// The current liveness.
    #[must_use]
    pub const fn liveness(&self) -> Liveness {
        self.liveness
    }

    /// The number of beats seen.
    #[must_use]
    pub const fn seen(&self) -> u64 {
        self.seen
    }

    /// The number of consecutive missed intervals.
    #[must_use]
    pub const fn missed(&self) -> u64 {
        self.missed
    }

    /// The last observed coverage state.
    #[must_use]
    pub const fn last_coverage(&self) -> AgentCoverageState {
        self.last_coverage
    }

    /// The last seen sequence, if any beat has been observed.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Records a beat. Returns the resulting transition.
    pub fn note_beat(&mut self, heartbeat: &AgentHeartbeat) -> LivenessTransition {
        let sequence = heartbeat.sequence();
        let prev = self.last_sequence;
        self.last_sequence = Some(sequence);
        self.last_coverage = heartbeat.coverage();
        self.seen += 1;
        self.missed = 0;
        match prev {
            Some(p) if p == sequence => LivenessTransition::DuplicateSequence { sequence },
            Some(p) if p > sequence => LivenessTransition::SequenceReset {
                from: p,
                to: sequence,
            },
            _ => {
                let restored = self.liveness != Liveness::Live;
                self.liveness = Liveness::Live;
                if restored {
                    LivenessTransition::Restored
                } else {
                    LivenessTransition::Steady
                }
            }
        }
    }

    /// Records that one interval elapsed with no beat. Returns the transition.
    pub fn note_interval_elapsed(&mut self) -> LivenessTransition {
        if self.liveness == Liveness::Dark {
            return LivenessTransition::Steady;
        }
        self.missed += 1;
        if self.missed >= self.grace {
            self.liveness = Liveness::Dark;
            LivenessTransition::WentDark
        } else if self.liveness == Liveness::Live {
            self.liveness = Liveness::Silent;
            LivenessTransition::WentSilent
        } else {
            LivenessTransition::Steady
        }
    }
}

/// Typed failures building an agent report or endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentError {
    /// The agent generation is empty.
    EmptyGeneration,
    /// The agent generation is the forbidden `latest` alias.
    LatestGeneration,
    /// The report exposes no endpoints.
    NoEndpoints,
    /// An endpoint protocol is not one of `rtsp`/`onvif`/`http`.
    BadEndpointProtocol(String),
    /// An endpoint URI is empty.
    EmptyEndpointUri,
    /// A canonical encode/decode failed.
    Canonical(ContractError),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGeneration => f.write_str("agent generation is empty"),
            Self::LatestGeneration => f.write_str("agent generation must not be 'latest'"),
            Self::NoEndpoints => f.write_str("agent report exposes no endpoints"),
            Self::BadEndpointProtocol(protocol) => {
                write!(f, "unknown endpoint protocol: {protocol}")
            }
            Self::EmptyEndpointUri => f.write_str("endpoint uri is empty"),
            Self::Canonical(e) => write!(f, "agent canonical failure: {e}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<ContractError> for AgentError {
    fn from(value: ContractError) -> Self {
        Self::Canonical(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> Result<CameraAgentReport, AgentError> {
        let onvif = StandardsEndpoint::new("onvif", "http://cam/onvif");
        let rtsp = StandardsEndpoint::new("rtsp", "rtsp://cam:554/udp");
        let (onvif, rtsp) = match (onvif, rtsp) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return Err(e),
        };
        CameraAgentReport::new(
            CameraFamily::Yi,
            "fss-agent/1",
            AgentHealth::Nominal,
            TailnetStatus::Connected,
            vec![onvif, rtsp],
            AgentCoverageState::Observable,
        )
    }

    #[test]
    fn report_verifies_and_round_trips() {
        let report = sample_report();
        let report = match report {
            Ok(r) => r,
            Err(_) => return,
        };
        assert!(report.verify());
        let bytes = report.canonical_bytes();
        assert_eq!(Ok(report), CameraAgentReport::from_canonical_bytes(&bytes));
    }

    #[test]
    fn report_rejects_latest_generation_and_no_endpoints() {
        let onvif = StandardsEndpoint::new("onvif", "http://cam/onvif");
        let onvif = match onvif {
            Ok(e) => e,
            Err(_) => return,
        };
        let latest = CameraAgentReport::new(
            CameraFamily::Yi,
            "latest",
            AgentHealth::Nominal,
            TailnetStatus::Connected,
            vec![onvif],
            AgentCoverageState::Observable,
        );
        assert!(matches!(latest, Err(AgentError::LatestGeneration)));

        let no_endpoints = CameraAgentReport::new(
            CameraFamily::Yi,
            "fss-agent/1",
            AgentHealth::Nominal,
            TailnetStatus::Connected,
            Vec::new(),
            AgentCoverageState::Observable,
        );
        assert!(matches!(no_endpoints, Err(AgentError::NoEndpoints)));
    }

    #[test]
    fn endpoint_validates_protocol() {
        assert!(StandardsEndpoint::new("rtsp", "rtsp://x").is_ok());
        assert!(matches!(
            StandardsEndpoint::new("ftp", "ftp://x"),
            Err(AgentError::BadEndpointProtocol(_))
        ));
        assert!(matches!(
            StandardsEndpoint::new("rtsp", ""),
            Err(AgentError::EmptyEndpointUri)
        ));
    }

    #[test]
    fn heartbeat_digest_is_deterministic() {
        let digest = ContentDigest::sha256(b"report");
        let a = AgentHeartbeat::new(digest, 1, AgentCoverageState::Observable);
        let b = AgentHeartbeat::new(digest, 1, AgentCoverageState::Observable);
        let c = AgentHeartbeat::new(digest, 2, AgentCoverageState::Observable);
        assert_eq!(a.heartbeat_digest(), b.heartbeat_digest());
        assert_ne!(a.heartbeat_digest(), c.heartbeat_digest());
    }

    #[test]
    fn tracker_goes_live_to_silent_to_dark_with_grace() {
        let digest = ContentDigest::sha256(b"report");
        let mut tracker = HeartbeatTracker::new(3);
        assert_eq!(tracker.liveness(), Liveness::Live);

        let first = tracker.note_beat(&AgentHeartbeat::new(digest, 1, AgentCoverageState::Silent));
        assert_eq!(first, LivenessTransition::Steady);
        assert_eq!(tracker.liveness(), Liveness::Live);

        let went_silent = tracker.note_interval_elapsed();
        assert_eq!(went_silent, LivenessTransition::WentSilent);
        assert_eq!(tracker.liveness(), Liveness::Silent);

        let still_silent = tracker.note_interval_elapsed();
        assert_eq!(still_silent, LivenessTransition::Steady);
        assert_eq!(tracker.liveness(), Liveness::Silent);

        let went_dark = tracker.note_interval_elapsed();
        assert_eq!(went_dark, LivenessTransition::WentDark);
        assert_eq!(tracker.liveness(), Liveness::Dark);
        assert_eq!(tracker.missed(), 3);
    }

    #[test]
    fn tracker_restores_after_dark() {
        let digest = ContentDigest::sha256(b"report");
        let mut tracker = HeartbeatTracker::new(1);
        let _ = tracker.note_interval_elapsed();
        assert_eq!(tracker.liveness(), Liveness::Dark);
        let restored =
            tracker.note_beat(&AgentHeartbeat::new(digest, 1, AgentCoverageState::Silent));
        assert_eq!(restored, LivenessTransition::Restored);
        assert_eq!(tracker.liveness(), Liveness::Live);
        assert_eq!(tracker.missed(), 0);
    }

    #[test]
    fn tracker_flags_duplicate_and_reset_sequences() {
        let digest = ContentDigest::sha256(b"report");
        let mut tracker = HeartbeatTracker::new(5);
        let _ = tracker.note_beat(&AgentHeartbeat::new(digest, 1, AgentCoverageState::Silent));
        let duplicate =
            tracker.note_beat(&AgentHeartbeat::new(digest, 1, AgentCoverageState::Silent));
        assert_eq!(
            duplicate,
            LivenessTransition::DuplicateSequence { sequence: 1 }
        );
        let reset = tracker.note_beat(&AgentHeartbeat::new(digest, 0, AgentCoverageState::Silent));
        assert_eq!(reset, LivenessTransition::SequenceReset { from: 1, to: 0 });
    }
}
