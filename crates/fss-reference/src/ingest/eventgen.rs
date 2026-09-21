#![forbid(unsafe_code)]
//! Zone-gated event generation from confirmed perception tracks.
//!
//! Bridges the perception pipeline (foreground detection → Kalman tracking →
//! zone membership) to the canonical event plane by producing
//! [`EventHypothesis`] values — no new event types. Every generated event:
//!
//! - passes the `CAP-OBSERVE-EVENT-001` capability gate before publication;
//! - carries one [`EventEvidence`] edge whose digest is the decoded-frame
//!   content digest (evidence-linked, not a bare claim);
//! - records the camera failure domain so cross-camera corroboration can
//!   never silently trust a single shared failure domain;
//! - binds a deterministic decision-path fingerprint over
//!   (zone, track, timestamp, frame digest);
//! - deduplicates repeat emissions per (zone, track) within a cooldown
//!   window so one physical intrusion is one event, not one event per frame.
//!
//! All arithmetic is deterministic; identical inputs produce identical
//! events, byte for byte.

use std::collections::HashMap;

use fss_core::abstraction::runtime_authority::RuntimeGrant;
use fss_core::event::{
    DecisionPath, EventDecodeError, EventEvidence, EventHypothesis, EventKind, EventState,
    EventTransitionParams, EvidenceEdgeRelation, ProbabilityInterval, MAX_ZONE_ID_LEN,
};
use fss_core::{CaptureInterval, ContentDigest, EvidenceClass, EventId, TimestampNs};

use crate::ingest::cross_camera::AssociatedPair;
use crate::ingest::tracker::{TrackStatus, TrackedTarget};

/// A registered coverage zone that maps contained tracks to an event kind.
#[derive(Clone, Debug)]
pub struct ZoneSpec {
    /// Stable zone identifier (alphanumeric, `-`, `_` only; `:` reserved for
    /// event-id composition).
    pub zone_id: String,
    /// Axis-aligned zone bounds in track coordinates: `(x, y, width, height)`.
    pub bounds: (f64, f64, f64, f64),
    /// Semantic class assigned to events generated from this zone.
    pub kind: EventKind,
}

impl ZoneSpec {
    /// Returns true when the point lies inside the zone bounds (inclusive).
    #[must_use]
    pub fn contains(&self, x: f64, y: f64) -> bool {
        let (zx, zy, zw, zh) = self.bounds;
        zw > 0.0
            && zh > 0.0
            && x >= zx
            && x <= zx + zw
            && y >= zy
            && y <= zy + zh
    }
}

/// Generator configuration.
#[derive(Clone, Copy, Debug)]
pub struct ZoneEventConfig {
    /// Content digest of the active policy generation. Bound into every
    /// generated decision path.
    pub policy_generation: ContentDigest,
    /// Minimum cooldown (nanoseconds) between repeated events for the same
    /// (zone, track) pair. Must be positive.
    pub dedup_cooldown_ns: i64,
    /// Conservative lower probability bound for generated hypotheses.
    /// Must lie in `[0, 1]`.
    pub min_probability: f64,
    /// Maximum retained dedup keys. One physical episode stays one event
    /// only while its (zone, track) cooldown entry is retained; the bound
    /// keeps the generator's state bounded over long sessions. Must be
    /// at least 1.
    pub max_dedup_entries: usize,
}

/// Typed event-generation failure.
#[derive(Clone, Debug)]
pub enum ZoneEventError {
    /// Configuration validation failed.
    InvalidConfig(&'static str),
    /// Zone registration input was malformed.
    InvalidZoneSpec(&'static str),
    /// The presented authority grant does not carry CAP-OBSERVE-EVENT-001.
    CapabilityDenied {
        /// Required grant id.
        required: &'static str,
    },
    /// Observation referenced a zone that was never registered.
    UnregisteredZone(String),
    /// Observation time regressed below an already-accepted emission time.
    ClockReversed,
    /// The bounded dedup state is full of entries still inside their
    /// cooldown; nothing may be silently forgotten (a forgotten entry could
    /// let one physical episode emit again).
    Limit,
    /// The assembled hypothesis violated an event-plane invariant.
    EventContract(Box<EventDecodeError>),
    /// Corroboration was attempted with the same failure domain that already
    /// supports the event: one camera can never corroborate itself.
    SameFailureDomain(String),
    /// Corroborating evidence digest duplicates an existing evidence digest.
    DuplicateEvidenceDigest,
    /// The event lineage refused the transition (state machine, tamper,
    /// duplicate evidence, or depth rules).
    Lineage(Box<fss_core::event::EventTransitionError>),
}

impl std::fmt::Display for ZoneEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(why) => write!(f, "invalid zone event config: {why}"),
            Self::InvalidZoneSpec(why) => write!(f, "invalid zone spec: {why}"),
            Self::CapabilityDenied { required } => {
                write!(f, "authority grant lacks required capability {required}")
            }
            Self::UnregisteredZone(zone) => write!(f, "unregistered coverage zone '{zone}'"),
            Self::ClockReversed => write!(f, "observation time regressed below a prior emission"),
            Self::Limit => write!(f, "dedup state is bounded and full within the cooldown"),
            Self::EventContract(err) => write!(f, "generated event failed contract: {err}"),
            Self::SameFailureDomain(domain) => {
                write!(f, "corroboration refused: failure domain '{domain}' already supports the event")
            }
            Self::DuplicateEvidenceDigest => {
                write!(f, "corroborating evidence digest duplicates existing evidence")
            }
            Self::Lineage(err) => write!(f, "event lineage refused transition: {err}"),
        }
    }
}
impl std::error::Error for ZoneEventError {}

/// Generates deduplicated, evidence-linked [`EventHypothesis`] values from
/// confirmed tracks entering registered coverage zones.
#[derive(Clone, Debug)]
pub struct ZoneEventGenerator {
    config: ZoneEventConfig,
    zones: Vec<ZoneSpec>,
    last_emitted: HashMap<(String, u64), TimestampNs>,
    /// Highest accepted emission time; observations below it are refused
    /// rather than silently absorbed into a cooldown window.
    clock: Option<i128>,
    event_seq: u64,
}

impl ZoneEventGenerator {
    /// Schema constant mirrored from [`EventHypothesis::SCHEMA`].
    pub const SCHEMA: &'static str = EventHypothesis::SCHEMA;

    /// Validates the configuration.
    ///
    /// # Errors
    /// Returns [`ZoneEventError::InvalidConfig`] on non-positive cooldown or
    /// out-of-range probability bounds.
    pub fn new(config: ZoneEventConfig) -> Result<Self, ZoneEventError> {
        if config.dedup_cooldown_ns <= 0 {
            return Err(ZoneEventError::InvalidConfig("dedup_cooldown_ns must be positive"));
        }
        if !(0.0..=1.0).contains(&config.min_probability) {
            return Err(ZoneEventError::InvalidConfig("min_probability must be in [0, 1]"));
        }
        if config.max_dedup_entries == 0 {
            return Err(ZoneEventError::InvalidConfig(
                "max_dedup_entries must be at least 1"));
        }
        Ok(Self {
            config,
            zones: Vec::new(),
            last_emitted: HashMap::new(),
            clock: None,
            event_seq: 0,
        })
    }

    /// Registers a coverage zone.
    ///
    /// # Errors
    /// Returns [`ZoneEventError::InvalidZoneSpec`] when the zone id is empty,
    /// longer than [`MAX_ZONE_ID_LEN`], contains `:` (reserved), has
    /// non-plain characters, or has non-positive bounds.
    pub fn register_zone(&mut self, spec: ZoneSpec) -> Result<(), ZoneEventError> {
        if spec.zone_id.is_empty() || spec.zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(ZoneEventError::InvalidZoneSpec("zone_id length out of bounds"));
        }
        if spec.zone_id.contains(':')
            || !spec
                .zone_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ZoneEventError::InvalidZoneSpec(
                "zone_id must be alphanumeric with '-' and '_' only",
            ));
        }
        let (_, _, zw, zh) = spec.bounds;
        if zw <= 0.0 || zh <= 0.0 {
            return Err(ZoneEventError::InvalidZoneSpec("zone bounds must be positive"));
        }
        if self.zones.iter().any(|z| z.zone_id == spec.zone_id) {
            return Err(ZoneEventError::InvalidZoneSpec("duplicate zone_id registration"));
        }
        self.zones.push(spec);
        Ok(())
    }

    /// Returns the first registered zone containing the track center, if any.
    #[must_use]
    pub fn zone_for_target(&self, target: &TrackedTarget) -> Option<&ZoneSpec> {
        self.zones.iter().find(|z| z.contains(target.cx, target.cy))
    }

    /// Observes one tracked target against one coverage zone.
    ///
    /// Returns `Ok(None)` when the track is not confirmed, lies outside the
    /// zone's dwell interest, or is within the dedup cooldown. Returns the
    /// fresh hypothesis otherwise.
    ///
    /// # Errors
    /// - [`ZoneEventError::CapabilityDenied`] when `grant` is not
    ///   [`RuntimeGrant::ObserveEvent`];
    /// - [`ZoneEventError::UnregisteredZone`] when `zone_id` was never
    ///   registered;
    /// - [`ZoneEventError::EventContract`] when the assembled hypothesis
    ///   fails event-plane verification (a bug, never an input condition).
    // 8 args carry the full publication record: authority, track, zone,
    // failure domain, time, evidence digest, and probability ceiling. A
    // params struct would hide which argument is the authority.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        grant: RuntimeGrant,
        target: &TrackedTarget,
        zone_id: &str,
        failure_domain: &str,
        ts: TimestampNs,
        frame_digest: ContentDigest,
        upper_probability: f64,
    ) -> Result<Option<EventHypothesis>, ZoneEventError> {
        // Capability gate first: no authority, no publication.
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied {
                required: RuntimeGrant::ObserveEvent.as_str(),
            });
        }
        if failure_domain.is_empty() {
            return Err(ZoneEventError::InvalidConfig("failure_domain must not be empty"));
        }
        let zone = self
            .zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .ok_or_else(|| ZoneEventError::UnregisteredZone(zone_id.to_string()))?;

        // Perception gate: only confirmed tracks evidence events. Tentative
        // tracks are uncorroborated tracker state.
        if target.status != TrackStatus::Confirmed {
            return Ok(None);
        }
        // Geometry gate: track center must lie inside the zone.
        if !zone.contains(target.cx, target.cy) {
            return Ok(None);
        }

        // Dedup gate: one physical presence episode is one event. State is
        // bounded: before inserting, entries that can no longer suppress
        // anything (their cooldown elapsed against the monotonic clock) are
        // dropped; if the bound is still full, the refusal is explicit
        // instead of forgetting a still-live cooldown.
        if self.clock.is_some_and(|accepted| ts.0 < accepted) {
            return Err(ZoneEventError::ClockReversed);
        }
        let key = (zone_id.to_string(), target.id);
        if let Some(last) = self.last_emitted.get(&key)
            && ts.0 - last.0 < i128::from(self.config.dedup_cooldown_ns)
        {
            return Ok(None);
        }
        if self.last_emitted.len() >= self.config.max_dedup_entries {
            let cooldown = i128::from(self.config.dedup_cooldown_ns);
            self.last_emitted.retain(|_, last| ts.0 - last.0 < cooldown);
            if self.last_emitted.len() >= self.config.max_dedup_entries {
                return Err(ZoneEventError::Limit);
            }
        }
        self.clock = Some(ts.0);
        self.last_emitted.insert(key, ts);

        self.event_seq += 1;
        let event = self.assemble(zone, target, failure_domain, ts, frame_digest, upper_probability)?;
        Ok(Some(event))
    }

    /// Number of events generated so far (stable generation order).
    #[must_use]
    pub const fn generated_count(&self) -> u64 {
        self.event_seq
    }

    /// Advances a lineage from [`EventState::Hypothesized`] to
    /// [`EventState::Witnessed`] by attaching the originating camera's
    /// continued observation of the tracked object.
    ///
    /// # Errors
    /// Capability, contract, and lineage-transition failures are typed.
    pub fn witness(
        &self,
        grant: RuntimeGrant,
        lineage: &mut fss_core::event::EventLineage,
        _target: &TrackedTarget,
        failure_domain: &str,
        ts: TimestampNs,
        frame_digest: ContentDigest,
    ) -> Result<(), ZoneEventError> {
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied {
                required: RuntimeGrant::ObserveEvent.as_str(),
            });
        }
        if failure_domain.is_empty() {
            return Err(ZoneEventError::InvalidConfig("failure_domain must not be empty"));
        }
        let current = lineage.current().clone();
        let edge = EventEvidence {
            digest: frame_digest,
            class: EvidenceClass::Observed,
            failure_domain: failure_domain.to_string(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        };
        let mut evidence = current.evidence.clone();
        if evidence.iter().any(|e| e.digest == frame_digest) {
            return Err(ZoneEventError::DuplicateEvidenceDigest);
        }
        evidence.push(edge);
        let params = EventTransitionParams {
            target_state: EventState::Witnessed,
            kind: current.kind,
            interval: expand_interval(current.interval, ts),
            uncertainty_reason: None,
            zone_ids: current.zone_ids.clone(),
            track_ids: current.track_ids.clone(),
            probability: current.probability,
            evidence,
            model_receipts: current.model_receipts.clone(),
            decision_path: self.chain_fingerprint(&current, ts, frame_digest),
            urgent_single_sensor: false,
        };
        lineage
            .transition(params)
            .map_err(|err| ZoneEventError::Lineage(Box::new(err)))?;
        Ok(())
    }

    /// Advances a lineage to [`EventState::Corroborated`] using an
    /// [`AssociatedPair`] from the cross-camera associator.
    ///
    /// The corroborating observation MUST originate from a failure domain
    /// that does not yet support the event: one camera can never corroborate
    /// itself. The second camera's track identifier is added to the event's
    /// correlated-track list for full provenance.
    ///
    /// # Errors
    /// - [`ZoneEventError::SameFailureDomain`] when the corroborating camera
    ///   shares a failure domain with an existing supporting edge;
    /// - [`ZoneEventError::DuplicateEvidenceDigest`] when the corroborating
    ///   frame digest already appears in the lineage;
    /// - plus capability and lineage-transition failures.
    // 9 args carry the full corroboration record: authority, lineage, the
    // cross-camera association, the corroborating camera's domain, time,
    // frame digest, and confidence ceiling. A params struct would hide the
    // authority argument.
    #[allow(clippy::too_many_arguments)]
    pub fn corroborate(
        &self,
        grant: RuntimeGrant,
        lineage: &mut fss_core::event::EventLineage,
        pair: &AssociatedPair,
        corroborating_failure_domain: &str,
        ts: TimestampNs,
        corroborating_frame_digest: ContentDigest,
        upper_probability: f64,
    ) -> Result<(), ZoneEventError> {
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied {
                required: RuntimeGrant::ObserveEvent.as_str(),
            });
        }
        if corroborating_failure_domain.is_empty() {
            return Err(ZoneEventError::InvalidConfig("failure_domain must not be empty"));
        }
        let current = lineage.current().clone();
        // Fail fast on the prohibited shortcut: self-corroboration.
        let existing_domains: Vec<&str> = current
            .evidence
            .iter()
            .filter(|edge| edge.counts_as_support())
            .map(|edge| edge.failure_domain.as_str())
            .collect();
        if existing_domains.contains(&corroborating_failure_domain) {
            return Err(ZoneEventError::SameFailureDomain(
                corroborating_failure_domain.to_string(),
            ));
        }
        if current
            .evidence
            .iter()
            .any(|e| e.digest == corroborating_frame_digest)
        {
            return Err(ZoneEventError::DuplicateEvidenceDigest);
        }
        let edge = EventEvidence {
            digest: corroborating_frame_digest,
            class: EvidenceClass::Observed,
            failure_domain: corroborating_failure_domain.to_string(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        };
        let mut evidence = current.evidence.clone();
        evidence.push(edge);

        // Correlated tracks gain the second camera's track label.
        let mut track_ids = current.track_ids.clone();
        let second_track = format!("track:{}", pair.second.track_id);
        if !track_ids.contains(&second_track) {
            track_ids.push(second_track);
        }

        let upper = upper_probability.clamp(current.probability.lower, 1.0);
        let probability = ProbabilityInterval::new(current.probability.lower, upper)
            .map_err(|err| {
                ZoneEventError::EventContract(Box::new(EventDecodeError::Contract(err)))
            })?;

        let params = EventTransitionParams {
            target_state: EventState::Corroborated,
            kind: current.kind,
            interval: expand_interval(current.interval, ts),
            uncertainty_reason: None,
            zone_ids: current.zone_ids.clone(),
            track_ids,
            probability,
            evidence,
            model_receipts: current.model_receipts.clone(),
            decision_path: self.chain_fingerprint(&current, ts, corroborating_frame_digest),
            urgent_single_sensor: false,
        };
        lineage
            .transition(params)
            .map_err(|err| ZoneEventError::Lineage(Box::new(err)))?;
        Ok(())
    }

    fn chain_fingerprint(
        &self,
        current: &EventHypothesis,
        ts: TimestampNs,
        frame_digest: ContentDigest,
    ) -> DecisionPath {
        let mut fp_input = Vec::new();
        fp_input.extend_from_slice(&current.decision_path.fingerprint.bytes());
        fp_input.extend_from_slice(&ts.0.to_le_bytes());
        fp_input.extend_from_slice(&frame_digest.bytes());
        DecisionPath {
            policy_generation: self.config.policy_generation,
            fingerprint: ContentDigest::sha256(&fp_input),
            abstained: false,
            abstention_reason: None,
        }
    }

    fn assemble(
        &self,
        zone: &ZoneSpec,
        target: &TrackedTarget,
        failure_domain: &str,
        ts: TimestampNs,
        frame_digest: ContentDigest,
        upper_probability: f64,
    ) -> Result<EventHypothesis, ZoneEventError> {
        // Deterministic event identity: zone, track, sequence.
        let event_id = EventId::parse(format!(
            "event:zonegen-{}-t{}-{}",
            zone.zone_id, target.id, self.event_seq
        ))
        .map_err(|err| {
            ZoneEventError::EventContract(Box::new(EventDecodeError::Contract(err)))
        })?;

        // Deterministic decision fingerprint over all decision inputs.
        let mut fp_input = Vec::new();
        fp_input.extend_from_slice(zone.zone_id.as_bytes());
        fp_input.extend_from_slice(&target.id.to_le_bytes());
        fp_input.extend_from_slice(&ts.0.to_le_bytes());
        fp_input.extend_from_slice(&frame_digest.bytes());
        let fingerprint = ContentDigest::sha256(&fp_input);

        let upper = upper_probability.clamp(self.config.min_probability, 1.0);
        let probability = ProbabilityInterval::new(self.config.min_probability, upper)
            .map_err(|err| {
                ZoneEventError::EventContract(Box::new(EventDecodeError::Contract(err)))
            })?;

        // The decoded frame is the observation evidence; the edge records the
        // camera failure domain so corroboration can never silently trust a
        // single shared domain.
        let evidence = EventEvidence {
            digest: frame_digest,
            class: EvidenceClass::Observed,
            failure_domain: failure_domain.to_string(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        };

        let hypothesis = EventHypothesis {
            schema: Self::SCHEMA.to_string(),
            event_id,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: zone.kind,
            interval: CaptureInterval::point(ts),
            uncertainty_reason: None,
            zone_ids: vec![zone.zone_id.clone()],
            track_ids: vec![format!("track:{}", target.id)],
            probability,
            evidence: vec![evidence],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: self.config.policy_generation,
                fingerprint,
                abstained: false,
                abstention_reason: None,
            },
        };
        hypothesis
            .verify()
            .map_err(|err| ZoneEventError::EventContract(Box::new(err)))?;
        Ok(hypothesis)
    }
}

/// Widens `[earliest, latest]` to include `ts` (non-decreasing interval).
fn expand_interval(interval: CaptureInterval, ts: TimestampNs) -> CaptureInterval {
    CaptureInterval {
        earliest: TimestampNs(interval.earliest.0.min(ts.0)),
        latest: TimestampNs(interval.latest.0.max(ts.0)),
    }
}

#[cfg(test)]
mod tests {
    // Tests fail loudly by design: unwrap/expect are the idiomatic
    // test-failure signals, not production error handling.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn policy_digest() -> ContentDigest {
        ContentDigest::sha256(b"policy-generation-test-v1")
    }

    fn config() -> ZoneEventConfig {
        ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 1_000_000_000, // 1 s
            min_probability: 0.4,
            max_dedup_entries: 64,
        }
    }

    fn frame_digest() -> ContentDigest {
        ContentDigest::sha256(b"frame-bytes-0001")
    }

    fn confirmed_track() -> TrackedTarget {
        TrackedTarget {
            id: 7,
            status: TrackStatus::Confirmed,
            cx: 50.0,
            cy: 60.0,
            vx: 1.0,
            vy: 0.0,
            box_w: 20.0,
            box_h: 40.0,
            hits: 6,
            misses: 0,
        }
    }

    fn generator() -> ZoneEventGenerator {
        let mut zonegen = ZoneEventGenerator::new(config()).unwrap();
        zonegen.register_zone(ZoneSpec {
            zone_id: "driveway".to_string(),
            bounds: (0.0, 0.0, 100.0, 100.0),
            kind: EventKind::UnknownPresence,
        })
        .unwrap();
        zonegen
    }

    fn ts(secs: i64) -> TimestampNs {
        TimestampNs(i128::from(secs) * 1_000_000_000)
    }

    #[test]
    fn confirmed_track_in_registered_zone_generates_event() {
        let mut zonegen = generator();
        let event = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &confirmed_track(),
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap()
            .expect("confirmed track in zone must generate");
        assert_eq!(event.kind, EventKind::UnknownPresence);
        assert_eq!(event.state, EventState::Hypothesized);
        assert_eq!(event.revision, 1);
        assert_eq!(event.zone_ids, vec!["driveway"]);
        assert_eq!(event.track_ids, vec!["track:7"]);
        assert_eq!(event.evidence.len(), 1);
        assert_eq!(event.evidence[0].digest, frame_digest());
        assert_eq!(event.evidence[0].failure_domain, "cam-a");
        assert!(event.evidence[0].supports);
        assert_eq!(event.decision_path.policy_generation, policy_digest());
    }

    #[test]
    fn tentative_track_does_not_generate() {
        let mut zonegen = generator();
        let mut track = confirmed_track();
        track.status = TrackStatus::Tentative;
        let event = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(event.is_none(), "unconfirmed tracks must not evidence events");
    }

    #[test]
    fn track_outside_zone_does_not_generate() {
        let mut zonegen = generator();
        let mut track = confirmed_track();
        track.cx = 150.0; // outside 0..100 bounds
        let event = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn capability_gate_denies_wrong_grant() {
        let mut zonegen = generator();
        let err = zonegen
            .observe(
                RuntimeGrant::ObserveStatus,
                &confirmed_track(),
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap_err();
        assert!(matches!(err, ZoneEventError::CapabilityDenied { .. }));
        assert_eq!(zonegen.generated_count(), 0, "denied publication must not consume a sequence");
    }

    #[test]
    fn dedup_suppresses_repeat_within_cooldown() {
        let mut zonegen = generator();
        let track = confirmed_track();
        let first = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(first.is_some());
        // Same track, same zone, 100 ms later: suppressed.
        let repeat = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                TimestampNs(ts(10).0 + 100_000_000),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(repeat.is_none(), "repeat within cooldown must dedup");
        // After the cooldown a new episode may publish.
        let later = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(12),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(later.is_some(), "post-cooldown re-entry must generate");
    }

    #[test]
    fn distinct_zones_track_pairs_do_not_cross_dedup() {
        let mut zonegen = generator();
        zonegen.register_zone(ZoneSpec {
            zone_id: "porch".to_string(),
            bounds: (0.0, 0.0, 100.0, 100.0),
            kind: EventKind::PerimeterBreach,
        })
        .unwrap();
        let track = confirmed_track();
        let a = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap();
        let b = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "porch",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(a.is_some() && b.is_some(), "different zones dedup independently");
        assert_eq!(a.unwrap().kind, EventKind::UnknownPresence);
        assert_eq!(b.unwrap().kind, EventKind::PerimeterBreach);
    }

    #[test]
    fn unregistered_zone_is_error() {
        let mut zonegen = generator();
        let err = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &confirmed_track(),
                "nowhere",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap_err();
        assert!(matches!(err, ZoneEventError::UnregisteredZone(_)));
    }

    #[test]
    fn decision_fingerprint_is_deterministic_and_input_sensitive() {
        let mut gen_a = generator();
        let mut gen_b = generator();
        let track = confirmed_track();
        let e1 = gen_a
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap()
            .unwrap();
        let e2 = gen_b
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            e1.decision_path.fingerprint, e2.decision_path.fingerprint,
            "identical inputs must produce identical fingerprints"
        );
        // Different frame bytes must change the fingerprint.
        let e3 = gen_a
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(20),
                ContentDigest::sha256(b"frame-bytes-0002"),
                0.9,
            )
            .unwrap()
            .unwrap();
        assert_ne!(e1.decision_path.fingerprint, e3.decision_path.fingerprint);
    }

    #[test]
    fn probability_interval_is_bounded_and_ordered() {
        let mut zonegen = generator();
        let event = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &confirmed_track(),
                "driveway",
                "cam-a",
                ts(10),
                frame_digest(),
                0.9,
            )
            .unwrap()
            .unwrap();
        assert_eq!(event.probability.lower, 0.4);
        assert_eq!(event.probability.upper, 0.9);
        // Upper clamped to [min, 1].
        let clamped = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &confirmed_track(),
                "driveway",
                "cam-a",
                ts(20),
                frame_digest(),
                5.0,
            )
            .unwrap()
            .unwrap();
        assert_eq!(clamped.probability.upper, 1.0);
    }

    #[test]
    fn zone_registration_validates_input() {
        let mut zonegen = ZoneEventGenerator::new(config()).unwrap();
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: String::new(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "bad:colon".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "flat".to_string(),
                bounds: (0.0, 0.0, 0.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "dup".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_ok());
        // Second registration of the same id must be refused.
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "dup".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "ok_zone-1".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_ok());
        assert!(zonegen
            .register_zone(ZoneSpec {
                zone_id: "ok_zone-1".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
    }

    #[test]
    fn config_validates_bounds() {
        assert!(ZoneEventGenerator::new(ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 0,
            min_probability: 0.4,
            max_dedup_entries: 64,
        })
        .is_err());
        assert!(ZoneEventGenerator::new(ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 1,
            min_probability: 1.5,
            max_dedup_entries: 64,
        })
        .is_err());
        assert!(ZoneEventGenerator::new(ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 1,
            min_probability: 0.4,
            max_dedup_entries: 0,
        })
        .is_err());
    }

    // --- Corroboration tests -------------------------------------------------

    use fss_core::event::EventLineage;

    use crate::ingest::cross_camera::CameraObservation;

    /// camera-A observation at (50, 60), camera-B at (51, 60): same object.
    fn associated_pair() -> AssociatedPair {
        AssociatedPair {
            first: CameraObservation {
                camera_id: "cam-a".to_string(),
                track_id: 7,
                timestamp_ns: 1_000_000_000,
                ground_x: 50.0,
                ground_y: 60.0,
            },
            second: CameraObservation {
                camera_id: "cam-b".to_string(),
                track_id: 3,
                timestamp_ns: 1_010_000_000,
                ground_x: 51.0,
                ground_y: 60.0,
            },
            confidence: 0.94,
        }
    }

    /// Emits a genesis event and attaches the originating camera's witness.
    fn witnessed_lineage() -> (ZoneEventGenerator, EventLineage) {
        let mut zonegen = generator();
        let genesis = zonegen
            .observe(
                RuntimeGrant::ObserveEvent,
                &confirmed_track(),
                "driveway",
                "cam-a",
                ts(1),
                frame_digest(),
                0.9,
            )
            .unwrap()
            .unwrap();
        let mut lineage = EventLineage::new(genesis).unwrap();
        zonegen
            .witness(
                RuntimeGrant::ObserveEvent,
                &mut lineage,
                &confirmed_track(),
                "cam-a",
                ts(2),
                ContentDigest::sha256(b"frame-bytes-cam-a-later"),
            )
            .expect("same-camera witness must advance to Witnessed");
        (zonegen, lineage)
    }

    #[test]
    fn witness_advances_hypothesized_to_witnessed() {
        let (_zonegen, lineage) = witnessed_lineage();
        assert_eq!(lineage.current_state(), EventState::Witnessed);
        assert_eq!(lineage.current_revision(), 2);
        assert!(lineage.current().supersedes.is_some(), "revision 2 supersedes genesis");
        assert_eq!(lineage.current().evidence.len(), 2);
        assert_eq!(lineage.len(), 2, "lineage keeps immutable history");
        assert_eq!(lineage.current().interval.earliest, TimestampNs(ts(1).0));
    }

    #[test]
    fn corroborate_advances_witnessed_to_corroborated() {
        let (zonegen, mut lineage) = witnessed_lineage();
        zonegen
            .corroborate(
                RuntimeGrant::ObserveEvent,
                &mut lineage,
                &associated_pair(),
                "cam-b",
                ts(3),
                ContentDigest::sha256(b"frame-bytes-cam-b"),
                0.95,
            )
            .expect("independent-domain corroboration must succeed");
        assert_eq!(lineage.current_state(), EventState::Corroborated);
        assert_eq!(lineage.current_revision(), 3);
        let current = lineage.current();
        assert_eq!(current.evidence.len(), 3);
        let domains: Vec<&str> =
            current.evidence.iter().map(|e| e.failure_domain.as_str()).collect();
        assert!(domains.contains(&"cam-a") && domains.contains(&"cam-b"));
        assert!(
            current.track_ids.contains(&"track:3".to_string()),
            "second camera's track id must join the correlated tracks"
        );
        assert_eq!(current.probability.upper, 0.95, "corroboration may raise confidence");
    }

    #[test]
    fn corroboration_refuses_same_failure_domain() {
        let (zonegen, mut lineage) = witnessed_lineage();
        let err = zonegen
            .corroborate(
                RuntimeGrant::ObserveEvent,
                &mut lineage,
                &associated_pair(),
                "cam-a", // same domain as the supporting evidence
                ts(3),
                ContentDigest::sha256(b"different-bytes-same-camera"),
                0.95,
            )
            .expect_err("one camera must never corroborate itself");
        assert!(matches!(&err, ZoneEventError::SameFailureDomain(d) if d == "cam-a"));
        assert_eq!(lineage.current_state(), EventState::Witnessed, "refusal leaves state");
    }

    #[test]
    fn corroboration_refuses_duplicate_frame_digest() {
        let (zonegen, mut lineage) = witnessed_lineage();
        let err = zonegen
            .corroborate(
                RuntimeGrant::ObserveEvent,
                &mut lineage,
                &associated_pair(),
                "cam-b",
                ts(3),
                frame_digest(), // already the genesis evidence digest
                0.95,
            )
            .expect_err("duplicate evidence digest must be refused");
        assert!(matches!(err, ZoneEventError::DuplicateEvidenceDigest));
    }

    #[test]
    fn corroboration_requires_capability() {
        let (zonegen, mut lineage) = witnessed_lineage();
        let err = zonegen
            .corroborate(
                RuntimeGrant::ObserveStatus,
                &mut lineage,
                &associated_pair(),
                "cam-b",
                ts(3),
                ContentDigest::sha256(b"frame-bytes-cam-b"),
                0.95,
            )
            .expect_err("wrong grant must not authorize corroboration");
        assert!(matches!(err, ZoneEventError::CapabilityDenied { .. }));
        assert_eq!(lineage.current_state(), EventState::Witnessed);
    }

    #[test]
    fn corroborated_lineage_survives_full_contract_verification() {
        let (zonegen, mut lineage) = witnessed_lineage();
        zonegen
            .corroborate(
                RuntimeGrant::ObserveEvent,
                &mut lineage,
                &associated_pair(),
                "cam-b",
                ts(3),
                ContentDigest::sha256(b"frame-bytes-cam-b"),
                0.95,
            )
            .unwrap();
        for revision in lineage.history() {
            revision.verify().expect("every lineage revision passes contract");
        }
        assert_eq!(lineage.highest_canonical_state(), Some(EventState::Corroborated));
    }
}
