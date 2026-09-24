#![forbid(unsafe_code)]
//! Bounded zone-gated hypotheses from confirmed perception tracks.
//!
//! A candidate is not a calibrated presence claim or an alert. Generation does not
//! establish source custody: publication must separately retain and verify evidence.
//! Refusals never consume a sequence or a cooldown, and no old deduplication entry
//! is silently evicted. Only elapsed cooldowns can be reclaimed against the monotonic
//! admission clock; stale observations can never revive a reclaimed cooldown.

use std::collections::BTreeMap;

use fss_core::abstraction::runtime_authority::RuntimeGrant;
use fss_core::event::{
    DecisionPath, EventDecodeError, EventEvidence, EventHypothesis, EventKind, EventState,
    EvidenceEdgeRelation, MAX_FAILURE_DOMAIN_LEN, MAX_ZONE_ID_LEN, ProbabilityInterval,
};
use fss_core::{CaptureInterval, ContentDigest, EventId, EvidenceClass, TimestampNs};

use crate::ingest::tracker::{TrackStatus, TrackedTarget};

/// Maximum registered zones; registration never silently drops an earlier zone.
pub const MAX_EVENT_ZONES: usize = 64;
/// Maximum distinct (source, zone, track) cooldowns in one generator episode.
pub const MAX_EVENT_TRACKS: usize = 4096;

/// An owner-selected image-coordinate zone, not a calibration certificate.
#[derive(Clone, Debug)]
pub struct ZoneSpec {
    /// Stable zone identifier, using ASCII alphanumeric, `-` or `_` only.
    pub zone_id: String,
    /// Axis-aligned `(x, y, width, height)` in the track's declared coordinates.
    pub bounds: (f64, f64, f64, f64),
    /// Candidate semantics selected by the owner, not inferred by the tracker.
    pub kind: EventKind,
}
impl ZoneSpec {
    /// Tests a finite point against the finite, positive zone, including its boundary.
    #[must_use]
    pub fn contains(&self, x: f64, y: f64) -> bool {
        let (zx, zy, zw, zh) = self.bounds;
        [x, y, zx, zy, zw, zh, zx + zw, zy + zh]
            .iter()
            .all(|v| v.is_finite())
            && zw > 0.0
            && zh > 0.0
            && x >= zx
            && x <= zx + zw
            && y >= zy
            && y <= zy + zh
    }
}

/// Explicit owner-selected hypothesis policy; scores are not independently calibrated.
#[derive(Clone, Copy, Debug)]
pub struct ZoneEventConfig {
    /// Exact active policy identity bound to every decision.
    pub policy_generation: ContentDigest,
    /// Positive minimum separation in nanoseconds between emitted source intervals.
    pub dedup_cooldown_ns: i64,
    /// Owner-selected lower hypothesis bound in `[0, 1]`.
    pub min_probability: f64,
    /// Owner-narrowable dedup capacity, from one through MAX_EVENT_TRACKS.
    pub max_dedup_entries: usize,
}

/// Source-scoped input to interval-aware event generation. These are caller-supplied
/// cognition/source claims; the generator does not grant custody or calibration.
#[derive(Clone, Copy, Debug)]
pub struct ZoneObservation<'a> {
    /// Owner-resolved camera/stream/clock generation; never a shared failure domain.
    pub source_generation: &'a str,
    /// Actual current tracker observation, not a coasting prediction.
    pub target: &'a TrackedTarget,
    /// Exact registered zone to evaluate.
    pub zone_id: &'a str,
    /// Shared failure-domain identity retained for later corroboration accounting.
    pub failure_domain: &'a str,
    /// Conservative source-capture bounds, not the host receive timestamp.
    pub capture: CaptureInterval,
    /// Exact decoded-frame evidence object identity; custody is checked on publication.
    pub frame_digest: ContentDigest,
    /// Owner-selected uncalibrated hypothesis upper bound; finite values are clamped.
    pub upper_probability: f64,
}

/// Typed refusal. All variants leave the generator unchanged.
#[derive(Clone, Debug)]
pub enum ZoneEventError {
    /// Invalid policy, score, source identifier or observation numeric value.
    InvalidConfig(&'static str),
    /// Invalid, non-finite, duplicate or oversized zone declaration.
    InvalidZoneSpec(&'static str),
    /// The caller did not present the event-observation grant.
    CapabilityDenied {
        /// Required registered capability identifier.
        required: &'static str,
    },
    /// No zone with this identifier was registered.
    UnregisteredZone(String),
    /// The requested complete state cannot fit; no cooldown entry was discarded.
    CapacityExceeded(&'static str),
    /// A source interval regressed or its separation is not representable.
    TimeOrder,
    /// Observation regressed below the last successful emission on this clock basis.
    ClockReversed,
    /// Configured dedup capacity is full of still-live entries.
    Limit,
    /// The event count cannot advance without wrapping.
    SequenceExhausted,
    /// The hypothesis did not satisfy the existing event contract.
    EventContract(Box<EventDecodeError>),
    /// Existing lineage API: the proposed supporting failure domain already supports it.
    SameFailureDomain(String),
    /// Existing lineage API: the proposed evidence digest is already retained.
    DuplicateEvidenceDigest,
    /// Existing lineage API: the event owner refused the transition.
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
            Self::CapacityExceeded(kind) => write!(f, "zone event capacity exceeded: {kind}"),
            Self::ClockReversed => f.write_str("observation time regressed below a prior emission"),
            Self::Limit => f.write_str("dedup state is bounded and full within the cooldown"),
            Self::TimeOrder => f.write_str("zone event source time regressed or overflowed"),
            Self::SequenceExhausted => f.write_str("zone event sequence exhausted"),
            Self::SameFailureDomain(domain) => write!(
                f,
                "corroboration refused: failure domain '{domain}' already supports the event"
            ),
            Self::DuplicateEvidenceDigest => {
                f.write_str("corroborating evidence digest duplicates existing evidence")
            }
            Self::Lineage(err) => write!(f, "event lineage refused transition: {err}"),
            Self::EventContract(err) => write!(f, "generated event failed contract: {err}"),
        }
    }
}
impl std::error::Error for ZoneEventError {}

/// One bounded, replayable generation episode. It performs no I/O or alert effect.
#[derive(Clone, Debug)]
pub struct ZoneEventGenerator {
    config: ZoneEventConfig,
    zones: Vec<ZoneSpec>,
    last_emitted: BTreeMap<(String, String, u64), CaptureInterval>,
    event_seq: u64,
    clock: Option<i128>,
}
impl ZoneEventGenerator {
    /// Existing canonical event schema; no additional event taxonomy is introduced.
    pub const SCHEMA: &'static str = EventHypothesis::SCHEMA;

    /// Validates immutable policy before allocating episode state.
    pub fn new(config: ZoneEventConfig) -> Result<Self, ZoneEventError> {
        if config.dedup_cooldown_ns <= 0 {
            return Err(ZoneEventError::InvalidConfig(
                "dedup_cooldown_ns must be positive",
            ));
        }
        if !(0.0..=1.0).contains(&config.min_probability) {
            return Err(ZoneEventError::InvalidConfig(
                "min_probability must be in [0, 1]",
            ));
        }
        if config.max_dedup_entries == 0 || config.max_dedup_entries > MAX_EVENT_TRACKS {
            return Err(ZoneEventError::InvalidConfig(
                "max_dedup_entries out of bounds",
            ));
        }
        if config.policy_generation.bytes() == [0; 32] {
            return Err(ZoneEventError::InvalidConfig(
                "policy generation must be nonzero",
            ));
        }
        Ok(Self {
            config,
            zones: Vec::new(),
            last_emitted: BTreeMap::new(),
            event_seq: 0,
            clock: None,
        })
    }

    /// Registers a finite, positive zone without replacing any existing declaration.
    pub fn register_zone(&mut self, spec: ZoneSpec) -> Result<(), ZoneEventError> {
        if spec.zone_id.is_empty() || spec.zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(ZoneEventError::InvalidZoneSpec(
                "zone_id length out of bounds",
            ));
        }
        if !spec
            .zone_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(ZoneEventError::InvalidZoneSpec(
                "zone_id must be alphanumeric with '-' and '_' only",
            ));
        }
        let (x, y, w, h) = spec.bounds;
        if ![x, y, w, h, x + w, y + h].iter().all(|v| v.is_finite()) || w <= 0.0 || h <= 0.0 {
            return Err(ZoneEventError::InvalidZoneSpec(
                "zone bounds must be finite and positive",
            ));
        }
        if self.zones.iter().any(|z| z.zone_id == spec.zone_id) {
            return Err(ZoneEventError::InvalidZoneSpec(
                "duplicate zone_id registration",
            ));
        }
        if self.zones.len() == MAX_EVENT_ZONES {
            return Err(ZoneEventError::CapacityExceeded("zones"));
        }
        self.zones.push(spec);
        Ok(())
    }

    /// Returns the first registered zone containing the finite target center, if any.
    #[must_use]
    pub fn zone_for_target(&self, target: &TrackedTarget) -> Option<&ZoneSpec> {
        self.zones.iter().find(|z| z.contains(target.cx, target.cy))
    }

    /// Compatibility point-time entry point. Use one generator per source stream.
    /// Sources sharing a failure domain must use [`Self::observe_interval`] with
    /// distinct source-generation identities; failure domains are not camera IDs.
    #[allow(clippy::too_many_arguments)] // Preserve the existing public point-time API.
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
        self.observe_interval(
            grant,
            ZoneObservation {
                source_generation: failure_domain,
                target,
                zone_id,
                failure_domain,
                capture: CaptureInterval::point(ts),
                frame_digest,
                upper_probability,
            },
        )
    }

    /// Observes a target in an explicitly named camera/stream generation and clock basis.
    /// The source identity must change on reconnect, sequence reset or coordinate/clock
    /// changes. Capture uncertainty is preserved and cooldown uses the guaranteed gap
    /// from the previous latest bound to this earliest bound, never point estimates.
    /// Sources must share one monotonically admitted clock basis (merge inputs by earliest
    /// capture bound). A repeated or overlapping interval is not an independent event.
    pub fn observe_interval(
        &mut self,
        grant: RuntimeGrant,
        observation: ZoneObservation<'_>,
    ) -> Result<Option<EventHypothesis>, ZoneEventError> {
        let ZoneObservation {
            source_generation,
            target,
            zone_id,
            failure_domain,
            capture,
            frame_digest,
            upper_probability,
        } = observation;
        if grant != RuntimeGrant::ObserveEvent {
            return Err(ZoneEventError::CapabilityDenied {
                required: RuntimeGrant::ObserveEvent.as_str(),
            });
        }
        if failure_domain.is_empty() || failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
            return Err(ZoneEventError::InvalidConfig(
                "failure_domain length out of bounds",
            ));
        }
        if source_generation.is_empty()
            || source_generation.len() > 128
            || !source_generation.bytes().all(|c| c.is_ascii_graphic())
        {
            return Err(ZoneEventError::InvalidConfig(
                "source generation must be bounded printable ASCII",
            ));
        }
        if !upper_probability.is_finite() || frame_digest.bytes() == [0; 32] {
            return Err(ZoneEventError::InvalidConfig(
                "score must be finite and evidence nonzero",
            ));
        }
        if capture.earliest > capture.latest {
            return Err(ZoneEventError::TimeOrder);
        }
        if ![
            target.cx,
            target.cy,
            target.vx,
            target.vy,
            target.box_w,
            target.box_h,
        ]
        .iter()
        .all(|v| v.is_finite())
            || target.box_w <= 0.0
            || target.box_h <= 0.0
        {
            return Err(ZoneEventError::InvalidConfig(
                "track geometry must be finite and positive",
            ));
        }
        let zone = self
            .zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .ok_or_else(|| ZoneEventError::UnregisteredZone(zone_id.to_string()))?;
        if target.status != TrackStatus::Confirmed
            || target.misses != 0
            || !zone.contains(target.cx, target.cy)
        {
            return Ok(None);
        }
        if self
            .clock
            .is_some_and(|accepted| capture.earliest.0 < accepted)
        {
            return Err(ZoneEventError::ClockReversed);
        }
        let key = (
            source_generation.to_string(),
            zone_id.to_string(),
            target.id,
        );
        if let Some(last) = self.last_emitted.get(&key) {
            if capture.earliest < last.earliest || capture.latest < last.latest {
                return Err(ZoneEventError::TimeOrder);
            }
            let gap = capture
                .earliest
                .0
                .checked_sub(last.latest.0)
                .ok_or(ZoneEventError::TimeOrder)?;
            if gap < i128::from(self.config.dedup_cooldown_ns) {
                return Ok(None);
            }
        }
        // Select expired entries without mutating state. A subsequent contract refusal
        // must not prune history, consume a sequence, or advance the admission clock.
        let mut expired = Vec::new();
        if !self.last_emitted.contains_key(&key)
            && self.last_emitted.len() >= self.config.max_dedup_entries
        {
            for (old_key, last) in &self.last_emitted {
                let gap = capture
                    .earliest
                    .0
                    .checked_sub(last.latest.0)
                    .ok_or(ZoneEventError::TimeOrder)?;
                if gap >= i128::from(self.config.dedup_cooldown_ns) {
                    expired.push(old_key.clone());
                }
            }
            if self.last_emitted.len() - expired.len() >= self.config.max_dedup_entries {
                return Err(ZoneEventError::Limit);
            }
        }
        let sequence = self
            .event_seq
            .checked_add(1)
            .ok_or(ZoneEventError::SequenceExhausted)?;
        let event = self.assemble(zone, observation, sequence)?;
        // Commit state only after every fallible contract operation has succeeded.
        for old_key in expired {
            self.last_emitted.remove(&old_key);
        }
        self.last_emitted.insert(key, capture);
        self.clock = Some(capture.earliest.0);
        self.event_seq = sequence;
        Ok(Some(event))
    }

    /// Successfully generated events only; refused inputs never advance this count.
    #[must_use]
    pub const fn generated_count(&self) -> u64 {
        self.event_seq
    }

    fn assemble(
        &self,
        zone: &ZoneSpec,
        observation: ZoneObservation<'_>,
        sequence: u64,
    ) -> Result<EventHypothesis, ZoneEventError> {
        let ZoneObservation {
            target,
            failure_domain,
            capture,
            frame_digest,
            upper_probability,
            ..
        } = observation;
        let contract =
            |err| ZoneEventError::EventContract(Box::new(EventDecodeError::Contract(err)));
        let event_id = EventId::parse(format!(
            "event:zonegen-{}-t{}-{}",
            zone.zone_id, target.id, sequence
        ))
        .map_err(contract)?;
        let mut fp_input = Vec::new();
        fp_input.extend_from_slice(zone.zone_id.as_bytes());
        fp_input.extend_from_slice(&target.id.to_le_bytes());
        fp_input.extend_from_slice(&capture.earliest.0.to_le_bytes());
        fp_input.extend_from_slice(&frame_digest.bytes());
        let probability = ProbabilityInterval::new(
            self.config.min_probability,
            upper_probability.clamp(self.config.min_probability, 1.0),
        )
        .map_err(contract)?;
        let hypothesis = EventHypothesis {
            schema: Self::SCHEMA.to_string(),
            event_id,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: zone.kind,
            interval: capture,
            uncertainty_reason: None,
            zone_ids: vec![zone.zone_id.clone()],
            track_ids: vec![format!("track:{}", target.id)],
            probability,
            evidence: vec![EventEvidence {
                digest: frame_digest,
                class: EvidenceClass::Observed,
                failure_domain: failure_domain.to_string(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: None,
                identity_digest: None,
            }],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: self.config.policy_generation,
                fingerprint: ContentDigest::sha256(&fp_input),
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
#[path = "eventgen/admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "eventgen/legacy_tests.rs"]
mod tests;

#[path = "eventgen/lineage.rs"]
mod lineage;
