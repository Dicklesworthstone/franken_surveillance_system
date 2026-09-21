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
    EvidenceEdgeRelation, ProbabilityInterval, MAX_ZONE_ID_LEN,
};
use fss_core::{CaptureInterval, ContentDigest, EvidenceClass, EventId, TimestampNs};

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
    /// The assembled hypothesis violated an event-plane invariant.
    EventContract(Box<EventDecodeError>),
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
            Self::EventContract(err) => write!(f, "generated event failed contract: {err}"),
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
        Ok(Self {
            config,
            zones: Vec::new(),
            last_emitted: HashMap::new(),
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
    /// freshly generated hypothesis otherwise.
    ///
    /// # Errors
    /// - [`ZoneEventError::CapabilityDenied`] when `grant` is not
    ///   [`RuntimeGrant::ObserveEvent`];
    /// - [`ZoneEventError::UnregisteredZone`] when `zone_id` was never
    ///   registered;
    /// - [`ZoneEventError::EventContract`] when the assembled hypothesis
    ///   fails event-plane verification (a bug, never an input condition).
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

        // Dedup gate: one physical presence episode is one event.
        let key = (zone_id.to_string(), target.id);
        if let Some(last) = self.last_emitted.get(&key)
            && ts.0 - last.0 < self.config.dedup_cooldown_ns
        {
            return Ok(None);
        }
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
        let event_id = EventId::parse(&format!(
            "event:zonegen-{}-t{}-{}",
            zone.zone_id, target.id, self.event_seq
        ))
        .map_err(|err| ZoneEventError::EventContract(Box::new(err)))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_digest() -> ContentDigest {
        ContentDigest::sha256(b"policy-generation-test-v1")
    }

    fn config() -> ZoneEventConfig {
        ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 1_000_000_000, // 1 s
            min_probability: 0.4,
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
        let mut gen = ZoneEventGenerator::new(config()).unwrap();
        gen.register_zone(ZoneSpec {
            zone_id: "driveway".to_string(),
            bounds: (0.0, 0.0, 100.0, 100.0),
            kind: EventKind::UnknownPresence,
        })
        .unwrap();
        gen
    }

    fn ts(secs: i64) -> TimestampNs {
        TimestampNs(secs * 1_000_000_000)
    }

    #[test]
    fn confirmed_track_in_registered_zone_generates_event() {
        let mut gen = generator();
        let event = gen
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
        let mut gen = generator();
        let mut track = confirmed_track();
        track.status = TrackStatus::Tentative;
        let event = gen
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
        let mut gen = generator();
        let mut track = confirmed_track();
        track.cx = 150.0; // outside 0..100 bounds
        let event = gen
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
        let mut gen = generator();
        let err = gen
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
        assert_eq!(gen.generated_count(), 0, "denied publication must not consume a sequence");
    }

    #[test]
    fn dedup_suppresses_repeat_within_cooldown() {
        let mut gen = generator();
        let track = confirmed_track();
        let first = gen
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
        let repeat = gen
            .observe(
                RuntimeGrant::ObserveEvent,
                &track,
                "driveway",
                "cam-a",
                ts(10) + TimestampNs(100_000_000),
                frame_digest(),
                0.9,
            )
            .unwrap();
        assert!(repeat.is_none(), "repeat within cooldown must dedup");
        // After the cooldown a new episode may publish.
        let later = gen
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
        let mut gen = generator();
        gen.register_zone(ZoneSpec {
            zone_id: "porch".to_string(),
            bounds: (0.0, 0.0, 100.0, 100.0),
            kind: EventKind::PerimeterBreach,
        })
        .unwrap();
        let track = confirmed_track();
        let a = gen
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
        let b = gen
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
        let mut gen = generator();
        let err = gen
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
        let mut gen = generator();
        let event = gen
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
        let clamped = gen
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
        let mut gen = ZoneEventGenerator::new(config()).unwrap();
        assert!(gen
            .register_zone(ZoneSpec {
                zone_id: String::new(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(gen
            .register_zone(ZoneSpec {
                zone_id: "bad:colon".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(gen
            .register_zone(ZoneSpec {
                zone_id: "flat".to_string(),
                bounds: (0.0, 0.0, 0.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        assert!(gen
            .register_zone(ZoneSpec {
                zone_id: "dup".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_err());
        // First registration succeeded, duplicate must fail, so "dup" is free.
        assert!(gen
            .register_zone(ZoneSpec {
                zone_id: "ok_zone-1".to_string(),
                bounds: (0.0, 0.0, 1.0, 1.0),
                kind: EventKind::Unclassified,
            })
            .is_ok());
        assert!(gen
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
        })
        .is_err());
        assert!(ZoneEventGenerator::new(ZoneEventConfig {
            policy_generation: policy_digest(),
            dedup_cooldown_ns: 1,
            min_probability: 1.5,
        })
        .is_err());
    }
}
