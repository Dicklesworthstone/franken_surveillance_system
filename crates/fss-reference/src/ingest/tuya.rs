//! AOSU/Tuya homebase → FSS evidence semantics (LAB-AOSU-6, bead
//! fss-x4a.21.3.6).
//!
//! Maps homebase/cam outputs into `EvidenceDelta` batches with the lane's
//! honesty invariants encoded in types, not comments:
//!
//! * **Vendor-derived is never ground truth.** Every event candidate
//!   payload carries `"provenance": "vendor_derived"` and
//!   `"ground_truth": false`. A vendor motion claim is an observation of a
//!   CLAIM, preserved with its raw dps bytes; only downstream cognition may
//!   promote it, against corroboration.
//! * **Battery cams are event-driven.** Their coverage is `Gapped` at
//!   best — blind intervals between wake-ups are first-class. This module
//!   has no code path that emits `CoverageContinuity::Continuous` for a
//!   battery cam; the type-level rule mirrors DEVICE_ADAPTER_MATRIX §3.
//! * **Offline cams are `not_observable`, never "clear".** A cam with no
//!   current session surfaces as [`CamObservability::NotObservable`] and is
//!   carried in the coverage witness's `excluded_domain`. Absence of events
//!   from an offline cam is never evidence of absence.
//! * **Unmapped dps stay raw.** dps schema truth comes from owner MITM
//!   evidence (LAB-AOSU-1). Until a `(model, dp)` pair is registry-qualified
//!   the mapper preserves the raw token and reports
//!   [`EventKind::UnknownDp`] — it never invents an interpretation.
//!
//! Sans-IO like the client beneath it: the owner pumps decoded session
//! frames and time in, and takes committed batches plus digest-keyed
//! payload custody out. Live traffic lands with LAB-AOSU-2; until then the
//! `fss-tuya` simulator drives this mapper in tests (INTEROPERABILITY_LAB
//! §5).

use std::collections::BTreeMap;

use std::collections::BTreeSet;

use fss_core::{
    BatchId, ContentDigest, ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness,
    EvidenceDelta, LedgerAnchor, ObjectId, Plane, ReferenceLedger,
};
use fss_core::{CaptureInterval, Completeness};

/// Provenance class carried by every payload this module emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VendorProvenance {
    /// The device claimed an event (motion/PIR/alarm). A claim, not truth.
    VendorDerived,
    /// The device reported its own state (dps health/heartbeat).
    DeviceStateReport,
    /// The device reported why a recording exists (wake trigger).
    WakeTriggerReport,
}

impl VendorProvenance {
    /// Stable JSON spelling embedded in payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VendorDerived => "vendor_derived",
            Self::DeviceStateReport => "device_state_report",
            Self::WakeTriggerReport => "wake_trigger_report",
        }
    }
}

/// One inventory entry (from the owner inventory; see the bead text).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CamInventoryEntry {
    /// Stable cam identity (owner-named, e.g. "rear-door").
    pub cam_id: String,
    /// Vendor model string (e.g. "C8S2EA11").
    pub model: String,
    /// Battery-powered ⇒ event-driven coverage rules apply.
    pub battery: bool,
}

/// Why a cam is not observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfflineReason {
    /// No session and no traffic within the offline window.
    Offline,
    /// Battery cam asleep between wake-ups (expected blind interval).
    Asleep,
    /// Never observed since mapper start.
    NeverObserved,
}

impl OfflineReason {
    /// Stable string form for payloads and domains.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Asleep => "asleep",
            Self::NeverObserved => "never_observed",
        }
    }
}

/// Per-cam observability: the honest acquisition-state surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CamObservability {
    /// Currently session-linked (for a battery cam: inside a wake window).
    Observable,
    /// Not observable; never collapses to "clear".
    NotObservable {
        /// Why.
        reason: OfflineReason,
    },
}

/// Recognized event kinds. Recognition comes only from the dps registry;
/// anything else is preserved raw as [`EventKind::UnknownDp`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Motion claim (camera-side VMD or AI).
    Motion,
    /// PIR claim (hardware sensor).
    Pir,
    /// Generic alarm claim.
    Alarm,
    /// Battery-low report.
    BatteryLow,
    /// Unmapped dp id — preserved, never interpreted.
    UnknownDp(String),
}

impl EventKind {
    /// Stable JSON spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Motion => "motion",
            Self::Pir => "pir",
            Self::Alarm => "alarm",
            Self::BatteryLow => "battery_low",
            Self::UnknownDp(id) => id.as_str(),
        }
    }

    /// Whether this kind is an unmapped placeholder.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::UnknownDp(_))
    }
}

/// Provenance of one dps-schema registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryProvenance {
    /// From the laboratory simulator fixtures — development-grade only.
    Laboratory,
    /// From owner MITM evidence (LAB-AOSU-1) — the only production-grade
    /// class. No such entries exist yet; when one lands it cites its
    /// capture.
    OwnerMitmQualified,
}

/// When a dp value qualifies as the event (value-blind recognition turns
/// `"104":"idle"` into a motion claim — that must never happen).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DpValueRule {
    /// Every value qualifies (use ONLY for pure event signals).
    AnyValue,
    /// Only these exact scalar tokens qualify (e.g. `"motion"`, `1`).
    ActiveTokens(&'static [&'static str]),
    /// Integer values strictly below this bound qualify (battery-low).
    NumericBelow(u64),
}

/// One `(model, dp)` → meaning registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpMeaning {
    /// The event semantics, if this dp carries one.
    pub event: Option<EventKind>,
    /// Which values qualify as the event.
    pub rule: DpValueRule,
    /// Human-readable stable name (e.g. "arm_state").
    pub name: &'static str,
    /// Where this knowledge came from.
    pub provenance: RegistryProvenance,
}

impl DpMeaning {
    /// Whether this raw token qualifies as the event under the rule.
    #[must_use]
    pub fn qualifies(&self, token: &str) -> bool {
        match &self.rule {
            DpValueRule::AnyValue => true,
            DpValueRule::ActiveTokens(tokens) => tokens.contains(&token),
            DpValueRule::NumericBelow(bound) => token
                .trim()
                .parse::<u64>()
                .map(|v| v < *bound)
                .unwrap_or(false),
        }
    }
}

/// The dps-schema registry. Starts with laboratory fixture entries only —
/// deliberately. Owner MITM captures qualify real entries over time.
#[derive(Clone, Debug, Default)]
pub struct DpsRegistry {
    entries: BTreeMap<(String, String), DpMeaning>,
}

impl DpsRegistry {
    /// Registry containing only the laboratory simulator-fixture mappings
    /// (model `fsssimhomebase00`), every entry marked
    /// [`RegistryProvenance::Laboratory`].
    #[must_use]
    pub fn laboratory_fixtures() -> Self {
        let mut entries = BTreeMap::new();
        let model = "fsssimhomebase00".to_string();
        let lab = RegistryProvenance::Laboratory;
        entries.insert(
            (model.clone(), "104".to_string()),
            DpMeaning {
                event: Some(EventKind::Motion),
                rule: DpValueRule::ActiveTokens(&["\"motion\""]),
                name: "motion_state",
                provenance: lab,
            },
        );
        entries.insert(
            (model.clone(), "115".to_string()),
            DpMeaning {
                event: Some(EventKind::Pir),
                rule: DpValueRule::ActiveTokens(&["1", "true"]),
                name: "pir_flag",
                provenance: lab,
            },
        );
        entries.insert(
            (model, "102".to_string()),
            DpMeaning {
                event: Some(EventKind::BatteryLow),
                rule: DpValueRule::NumericBelow(20),
                name: "battery_pct",
                provenance: lab,
            },
        );
        Self { entries }
    }

    /// Looks up one `(model, dp)` pair.
    #[must_use]
    pub fn lookup(&self, model: &str, dp: &str) -> Option<&DpMeaning> {
        self.entries.get(&(model.to_string(), dp.to_string()))
    }
}

/// Wake trigger for a video segment (why the recording exists).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeTrigger {
    /// PIR wake.
    Pir,
    /// Motion/VMD wake.
    Motion,
    /// Owner manual live-view/recording.
    Manual,
    /// Scheduled recording.
    Schedule,
    /// Trigger unknown — recorded, not guessed.
    Unknown,
}

impl WakeTrigger {
    /// Stable JSON spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pir => "pir",
            Self::Motion => "motion",
            Self::Manual => "manual",
            Self::Schedule => "schedule",
            Self::Unknown => "unknown",
        }
    }
}

/// Mapper configuration.
#[derive(Clone, Debug)]
pub struct TuyaMapperConfig {
    /// Site lineage for the reference ledger.
    pub site_lineage: String,
    /// Homebase identity (e.g. "h2e").
    pub homebase_id: String,
    /// Cam inventory (owner inventory of record).
    pub cams: Vec<CamInventoryEntry>,
    /// dps registry (defaults to laboratory fixtures).
    pub registry: DpsRegistry,
    /// Frames without traffic longer than this mark a cam offline (ns).
    pub offline_window_ns: u64,
}

/// Typed mapper errors.
#[derive(Debug)]
pub enum TuyaMapError {
    /// fss-core contract violation.
    Contract(ContractError),
    /// Input JSON structurally unusable (kept non-secret-bearing).
    Malformed(&'static str),
    /// Cam identity not in the owner inventory.
    UnknownCam(String),
}

impl core::fmt::Display for TuyaMapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Contract(e) => write!(f, "contract error: {e}"),
            Self::Malformed(m) => write!(f, "malformed input: {m}"),
            Self::UnknownCam(c) => write!(f, "cam not in inventory: {c}"),
        }
    }
}

impl std::error::Error for TuyaMapError {}

impl From<ContractError> for TuyaMapError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}

/// Minimal flat-JSON-object parse for dps payloads: `{"dps":{"1":true,
/// "102":85}}` → raw `(dp, token)` pairs preserving the exact value token
/// text. Nested/non-flat structures are rejected — they never occur in dps
/// status reports, and rejecting beats guessing.
fn parse_flat_dps(json: &str) -> Result<Vec<(String, String)>, TuyaMapError> {
    let body = json.trim();
    let inner = body
        .strip_prefix('{')
        .and_then(|b| b.strip_suffix('}'))
        .ok_or(TuyaMapError::Malformed("not an object"))?;
    let dps_key = inner
        .strip_prefix("\"dps\":")
        .ok_or(TuyaMapError::Malformed("missing dps key"))?;
    let dps = dps_key
        .trim()
        .strip_prefix('{')
        .and_then(|b| b.strip_suffix('}'))
        .ok_or(TuyaMapError::Malformed("dps not an object"))?;
    let mut out = Vec::new();
    for pair in split_top_level(dps) {
        let (k, v) = pair
            .split_once(':')
            .ok_or(TuyaMapError::Malformed("pair missing colon"))?;
        let key = k
            .trim()
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .ok_or(TuyaMapError::Malformed("bad dp key"))?;
        out.push((key.to_string(), v.trim().to_string()));
    }
    Ok(out)
}

/// Escapes a string for embedding in a JSON string value.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Whether a raw dps token is valid standalone JSON (scalar or balanced
/// object/array with string-aware depth tracking). Garbage is never embedded
/// verbatim into custody JSON.
fn token_is_valid_json(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() {
        return false;
    }
    // scalars
    if t == "true" || t == "false" || t == "null" {
        return true;
    }
    if t.starts_with('"') {
        // string: must end with an unescaped closing quote
        return t.len() >= 2 && t.ends_with('"');
    }
    if t.parse::<f64>().is_ok() || (t.starts_with('-') && t[1..].parse::<f64>().is_ok()) {
        return true;
    }
    // compound: balanced braces/brackets with string awareness
    if t.starts_with('{') || t.starts_with('[') {
        let mut depth = 0i32;
        let mut in_str = false;
        let mut escape = false;
        for c in t.chars() {
            if in_str {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return false;
            }
        }
        return depth == 0 && !in_str && (t.ends_with('}') || t.ends_with(']'));
    }
    false
}

/// The custody-safe form of a raw dps token: verbatim when it is valid JSON,
/// an escaped JSON string otherwise (preserved, valid, never interpreted).
fn json_token_or_string(token: &str) -> String {
    if token_is_valid_json(token) {
        token.trim().to_string()
    } else {
        json_string(token)
    }
}

/// Splits a flat JSON object body on top-level commas (strings may contain
/// commas; dps values are flat scalars so depth tracking + string awareness
/// suffices).
fn split_top_level(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    let mut start = 0;
    for (i, c) in body.char_indices() {
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        out.push(&body[start..]);
    }
    out
}

/// One cam's tracked observation state.
#[derive(Clone, Debug)]
struct CamTracker {
    observability: CamObservability,
    events_seen: u64,
}

/// The LAB-AOSU-6 mapper: decoded Tuya session frames → evidence deltas.
pub struct TuyaEventMapper {
    cfg: TuyaMapperConfig,
    ledger: ReferenceLedger,
    custody: BTreeMap<ContentDigest, Vec<u8>>,
    pending: Vec<(EvidenceDelta, ContentDigest)>,
    trackers: BTreeMap<String, CamTracker>,
    generations: BTreeMap<ObjectId, u64>,
    batch_seq: u64,
}

impl TuyaEventMapper {
    /// Creates the mapper with every inventory cam starting
    /// `NotObservable { NeverObserved }` — silence is never "clear".
    #[must_use]
    pub fn new(cfg: TuyaMapperConfig) -> Self {
        let trackers = cfg
            .cams
            .iter()
            .map(|c| {
                (
                    c.cam_id.clone(),
                    CamTracker {
                        observability: CamObservability::NotObservable {
                            reason: OfflineReason::NeverObserved,
                        },
                        events_seen: 0,
                    },
                )
            })
            .collect();
        Self {
            ledger: ReferenceLedger::new(cfg.site_lineage.clone()),
            cfg,
            custody: BTreeMap::new(),
            pending: Vec::new(),
            trackers,
            generations: BTreeMap::new(),
            batch_seq: 0,
        }
    }

    /// The reference ledger (committed batches).
    #[must_use]
    pub fn ledger(&self) -> &ReferenceLedger {
        &self.ledger
    }

    /// Digest-keyed payload custody (owner spills to durable publication).
    #[must_use]
    pub fn custody(&self, digest: &ContentDigest) -> Option<&[u8]> {
        self.custody.get(digest).map(Vec::as_slice)
    }

    /// Current observability for one inventory cam.
    #[must_use]
    pub fn observability(&self, cam_id: &str) -> Option<&CamObservability> {
        self.trackers.get(cam_id).map(|t| &t.observability)
    }

    /// Stages one delta with ledger-correct per-object generations:
    /// new objects start at generation 1; existing objects advance by one.
    /// Two-stage transaction: generations are provisional (computed from the
    /// committed ledger plus pending rows for the same object) and only
    /// become durable at a successful commit. A second staging for the same
    /// object before commit COALESCES — the pending row is replaced (the
    /// ledger admits at most one delta per object per batch).
    fn stage_delta(
        &mut self,
        family: &str,
        object_id: ObjectId,
        validity: CaptureInterval,
        payload: Vec<u8>,
    ) -> ContentDigest {
        let digest = ContentDigest::sha256(&payload);
        // Coalesce FIRST: the ledger admits one delta per object per batch,
        // so a restaged object replaces its pending row — after removal the
        // pending count for this object is zero by construction.
        self.pending.retain(|(d, _)| d.object_id != object_id);
        // Generations are provisional until commit: committed ledger
        // generation + 1 (pending rows never persist a generation).
        let committed = self.generations.get(&object_id).copied();
        let (prior_generation, new_generation) = match committed {
            Some(g) => (Some(g), g + 1),
            None => (None, 1),
        };
        let delta = EvidenceDelta {
            delta_id: format!("delta:{family}:{}:g{new_generation}", object_id.as_str()),
            family: family.to_string(),
            object_id: object_id.clone(),
            prior_generation,
            new_generation,
            validity,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        // NOTE: generations/custody/pending are NOT mutated into durable
        // state here; the provisional generation map is updated eagerly but
        // commit_pending rebuilds deltas from pending rows only on success,
        // and on failure the caller can discard the mapper — see commit.
        self.custody.insert(digest, payload);
        self.pending.push((delta, digest));
        digest
    }

    /// Commits all staged deltas as one batch. No-op `Ok(None)` when empty.
    pub fn commit_pending(&mut self) -> Result<Option<BatchId>, TuyaMapError> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        self.batch_seq += 1;
        let batch_id = BatchId::parse(format!(
            "batch:aosu:{}:c{}",
            self.cfg.homebase_id, self.batch_seq
        ))
        .map_err(|_| TuyaMapError::Malformed("batch id"))?;
        // Transactional: nothing leaves pending until append succeeds, and
        // the durable generation map advances only for committed objects.
        let children: Vec<ContentDigest> = self.pending.iter().map(|(_, d)| *d).collect();
        let deltas: Vec<EvidenceDelta> = self.pending.iter().map(|(d, _)| d.clone()).collect();
        let batch = self.ledger.prepare_batch(batch_id, deltas, children)?;
        let id = batch.batch_id.clone();
        self.ledger.append(batch)?;
        for (d, _) in self.pending.drain(..) {
            self.generations.insert(d.object_id, d.new_generation);
        }
        Ok(Some(id))
    }

    /// Maps one decoded dps STATUS report (homebase health) into a
    /// device-state delta. Raw dps are preserved verbatim in the payload.
    pub fn map_device_state(
        &mut self,
        model: &str,
        dps_json: &str,
        observed: CaptureInterval,
    ) -> Result<ContentDigest, TuyaMapError> {
        let pairs = parse_flat_dps(dps_json)?;
        let mut raw = String::new();
        for (i, (dp, tok)) in pairs.iter().enumerate() {
            if i > 0 {
                raw.push(',');
            }
            raw.push_str(&format!("\"{dp}\":{tok}"));
        }
        let _ = model; // model tags registry lookups, not the state payload
        let payload = format!(
            "{{\"type\":\"aosu_device_state\",\"version\":1,\"homebase\":\"{}\",\"dps\":{{{}}},\"observed\":{{\"earliest\":{},\"latest\":{}}},\"provenance\":\"{}\",\"ground_truth\":false}}",
            self.cfg.homebase_id,
            raw,
            observed.earliest.0,
            observed.latest.0,
            VendorProvenance::DeviceStateReport.as_str()
        );
        let object_id =
            ObjectId::parse(format!("object:aosu-device-state:{}", self.cfg.homebase_id))
                .map_err(|_| TuyaMapError::Malformed("object id"))?;
        Ok(self.stage_delta(
            "aosu_device_state",
            object_id,
            observed,
            payload.into_bytes(),
        ))
    }

    /// Maps one vendor event report (from a STATUS frame carrying event
    /// dps) into per-recognized-dp event candidates. Unmapped dps are
    /// preserved as [`EventKind::UnknownDp`] candidates — visible, raw,
    /// and never interpreted.
    pub fn map_event_report(
        &mut self,
        cam_id: &str,
        model: &str,
        dps_json: &str,
        observed: CaptureInterval,
    ) -> Result<Vec<ContentDigest>, TuyaMapError> {
        if !self.trackers.contains_key(cam_id) {
            return Err(TuyaMapError::UnknownCam(cam_id.to_string()));
        }
        let pairs = parse_flat_dps(dps_json)?;
        let mut digests = Vec::new();
        for (dp, token) in &pairs {
            // Value-aware recognition: a registered dp only yields an event
            // candidate when the value qualifies under its rule — "idle"
            // never becomes a motion claim. Non-qualifying values are plain
            // state (carried by device-state reports), not events.
            let kind = match self.cfg.registry.lookup(model, dp) {
                Some(meaning) => match &meaning.event {
                    Some(e) if meaning.qualifies(token) => e.clone(),
                    Some(_) => continue,
                    None => EventKind::UnknownDp(dp.clone()),
                },
                None => EventKind::UnknownDp(dp.clone()),
            };
            let safe_token = json_token_or_string(token);
            let payload = format!(
                "{{\"type\":\"aosu_event_candidate\",\"version\":1,\"cam_id\":{},\"event_kind\":\"{}\",\"dp_id\":{},\"raw\":{},\"observed\":{{\"earliest\":{},\"latest\":{}}},\"provenance\":\"{}\",\"ground_truth\":false}}",
                json_string(cam_id),
                kind.as_str(),
                json_string(dp),
                safe_token,
                observed.earliest.0,
                observed.latest.0,
                VendorProvenance::VendorDerived.as_str()
            );
            let object_id = ObjectId::parse(format!("object:aosu-event:{cam_id}:dp{dp}"))
                .map_err(|_| TuyaMapError::Malformed("object id"))?;
            digests.push(self.stage_delta(
                "aosu_event_candidate",
                object_id,
                observed,
                payload.into_bytes(),
            ));
        }
        // Observability/event evidence only moves when something was
        // actually staged — an empty report is a sighting at most, never
        // event evidence and never coverage.
        if !digests.is_empty() {
            if let Some(tracker) = self.trackers.get_mut(cam_id) {
                tracker.events_seen += 1;
                tracker.observability = CamObservability::Observable;
            }
        }
        Ok(digests)
    }

    /// Maps one video-segment reference with exact wake/trigger provenance.
    /// `segment_ref` is the custody handle the segment bytes live under
    /// (import identity or capsule id), never the bytes themselves.
    pub fn map_video_segment(
        &mut self,
        cam_id: &str,
        trigger: WakeTrigger,
        segment_ref: &str,
        span: CaptureInterval,
        wake_latency_ms: Option<u64>,
    ) -> Result<ContentDigest, TuyaMapError> {
        if !self.trackers.contains_key(cam_id) {
            return Err(TuyaMapError::UnknownCam(cam_id.to_string()));
        }
        let latency = wake_latency_ms
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "null".to_string());
        let payload = format!(
            "{{\"type\":\"aosu_video_segment\",\"version\":1,\"cam_id\":\"{cam_id}\",\"wake\":{{\"trigger\":\"{}\",\"latency_ms\":{latency}}},\"segment_ref\":\"{segment_ref}\",\"span\":{{\"earliest\":{},\"latest\":{}}},\"provenance\":\"{}\",\"ground_truth\":false}}",
            trigger.as_str(),
            span.earliest.0,
            span.latest.0,
            VendorProvenance::WakeTriggerReport.as_str()
        );
        let object_id = ObjectId::parse(format!("object:aosu-segment:{cam_id}:{segment_ref}"))
            .map_err(|_| TuyaMapError::Malformed("object id"))?;
        Ok(self.stage_delta("aosu_video_segment", object_id, span, payload.into_bytes()))
    }

    /// Marks a cam offline/asleep (no traffic within the window). The state
    /// change is itself recorded as device-state evidence when it CHANGES —
    /// silently dropping offline is how "clear" lies are born.
    pub fn mark_not_observable(
        &mut self,
        cam_id: &str,
        reason: OfflineReason,
        observed: CaptureInterval,
    ) -> Result<Option<ContentDigest>, TuyaMapError> {
        let Some(tracker) = self.trackers.get_mut(cam_id) else {
            return Err(TuyaMapError::UnknownCam(cam_id.to_string()));
        };
        let next = CamObservability::NotObservable {
            reason: reason.clone(),
        };
        if tracker.observability == next {
            return Ok(None);
        }
        tracker.observability = next;
        // Persist the transition as device-state evidence: the payload names
        // the cam, the reason, and the exact observation window.
        let payload = format!(
            "{{\"type\":\"aosu_device_state\",\"version\":1,\"homebase\":\"{}\",\"cam_id\":{},\"transition\":\"not_observable\",\"reason\":\"{}\",\"observed\":{{\"earliest\":{},\"latest\":{}}},\"provenance\":\"{}\",\"ground_truth\":false}}",
            self.cfg.homebase_id,
            json_string(cam_id),
            reason.as_str(),
            observed.earliest.0,
            observed.latest.0,
            VendorProvenance::DeviceStateReport.as_str()
        );
        let object_id =
            ObjectId::parse(format!("object:aosu-device-state:{}", self.cfg.homebase_id))
                .map_err(|_| TuyaMapError::Malformed("object id"))?;
        Ok(Some(self.stage_delta(
            "aosu_device_state",
            object_id,
            observed,
            payload.into_bytes(),
        )))
    }

    /// Constructs the coverage witness for a negative-read over one cam's
    /// event domain. HARD RULES:
    /// * battery cams: continuity is `Gapped` when events were seen,
    ///   `Unknown` otherwise — never `Continuous` (so a battery-cam witness
    ///   can never `certify_absence`, by construction);
    /// * a `NotObservable` cam appears in `excluded_domain` with its reason,
    ///   its domain is removed from `observed_domain`, completeness is
    ///   `NotObservable`, and observed generation is 0.
    #[must_use]
    pub fn coverage_witness(
        &self,
        cam_id: &str,
        negative_predicate: impl Into<String>,
        authorized_domain: BTreeSet<String>,
        authorized_generation: u64,
        anchor: LedgerAnchor,
        stop_reason: CoverageStopReason,
    ) -> Option<CoverageWitness> {
        let entry = self.cfg.cams.iter().find(|c| c.cam_id == cam_id)?;
        let tracker = self.trackers.get(cam_id)?;
        let mut observed = authorized_domain.clone();
        let mut excluded = BTreeSet::new();
        let (continuity, completeness, observed_generation) = match &tracker.observability {
            CamObservability::NotObservable { reason } => {
                // Exact cam-domain matching: "rear" must never evict
                // "rear-door:events". A domain names the cam exactly or as
                // "{cam}:<aspect>".
                let cam_prefix = format!("{cam_id}:");
                observed.retain(|d| d != cam_id && !d.starts_with(&cam_prefix));
                excluded.insert(format!("{cam_id}:{}", reason.as_str()));
                (CoverageContinuity::Unknown, Completeness::NotObservable, 0)
            }
            CamObservability::Observable => {
                // Battery cams are event-driven with structural blind
                // intervals: Gapped at best, never Continuous — a battery
                // witness can never `certify_absence`, by construction.
                // A mains cam with an observed event stream may certify.
                let continuity = if tracker.events_seen == 0 {
                    CoverageContinuity::Unknown
                } else if entry.battery {
                    CoverageContinuity::Gapped
                } else {
                    CoverageContinuity::Continuous
                };
                (continuity, Completeness::Complete, authorized_generation)
            }
        };
        Some(CoverageWitness {
            anchor,
            authorized_domain,
            observed_domain: observed,
            excluded_domain: excluded,
            continuity,
            completeness,
            negative_predicate: negative_predicate.into(),
            stop_reason,
            authorized_generation,
            observed_generation,
        })
    }
}
