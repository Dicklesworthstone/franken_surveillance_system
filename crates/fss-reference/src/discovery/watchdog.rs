//! Device-liveness watchdog (DISC-5, bead fss-niak9): typed dark-camera
//! transitions fed by the discovery plane's existing observations.
//!
//! The surveillance-relevant truth this module protects: **a camera that
//! stops answering is itself the first tamper signal**, and a battery cam
//! between wake-ups is *asleep*, not offline. Silence is never represented
//! as "clear" — a device we cannot currently observe is `NotObservable` with
//! a typed reason, and every state transition is recorded evidence.
//!
//! Sans-IO and deterministic: callers feed sightings and the current time
//! in; the watchdog emits state-change records out. No sockets, no clock of
//! its own, no async. Alert dispatch (webhook etc.) is a separate lane that
//! consumes [`DeviceStateChange`].

use std::collections::BTreeMap;

/// Protocol class of the device, as classified by discovery.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeviceClass {
    /// TUTK/IOTC (Wyze-class) — mains-powered, expected chatty.
    Tutk,
    /// Tuya LAN (AOSU-class homebase/devices).
    Tuya,
    /// ONVIF/WS-Discovery responder (standards-class).
    Onvif,
    /// Battery-powered event-driven device (long sleep windows are normal).
    BatteryEventDriven,
    /// Unclassified device.
    Unknown,
    /// A camera running the FSS provision agent stack — mains-like chatty
    /// heartbeats by design (fss-provision, LAB-PROVISION-001).
    ProvisionedAgent,
}

impl DeviceClass {
    /// Stable string form for records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tutk => "tutk",
            Self::Tuya => "tuya",
            Self::Onvif => "onvif",
            Self::BatteryEventDriven => "battery_event_driven",
            Self::Unknown => "unknown",
            Self::ProvisionedAgent => "provisioned_agent",
        }
    }

    /// Default silence thresholds (ns) when the caller does not override:
    /// grace window (Silent) and hard silence (NotObservable).
    /// Battery cams sleep long by design; their thresholds are hours, and a
    /// battery cam in a sleep window is `Asleep`, never `Offline`.
    #[must_use]
    pub const fn default_thresholds_ns(self) -> (u64, u64) {
        const MINUTE: u64 = 60_000_000_000;
        const HOUR: u64 = 60 * MINUTE;
        match self {
            // Mains-powered chatty devices: silence is suspicious fast.
            Self::Tutk => (2 * MINUTE, 10 * MINUTE),
            Self::Tuya => (2 * MINUTE, 10 * MINUTE),
            Self::Onvif => (5 * MINUTE, 30 * MINUTE),
            // Event-driven: a full day of quiet is normal.
            Self::BatteryEventDriven => (6 * HOUR, 48 * HOUR),
            Self::Unknown => (10 * MINUTE, 60 * MINUTE),
            // Our own agent beats on a short cadence; silence is suspicious fast.
            Self::ProvisionedAgent => (2 * MINUTE, 10 * MINUTE),
        }
    }
}

/// Why a device is not observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchOfflineReason {
    /// Passed the hard-silence threshold for its class.
    SilentBeyondThreshold,
    /// Never produced a sighting since the watchdog started.
    NeverObserved,
}

impl WatchOfflineReason {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SilentBeyondThreshold => "silent_beyond_threshold",
            Self::NeverObserved => "never_observed",
        }
    }
}

/// Observability state of one device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchState {
    /// Seen within the grace window.
    Observable,
    /// Past the grace window but not yet the hard threshold: suspicious,
    /// NOT yet an offline declaration.
    Silent {
        /// How long (ns) since the last sighting.
        silent_for_ns: u64,
    },
    /// Battery cam inside a normal sleep window (between events).
    Asleep {
        /// How long (ns) since the last sighting.
        silent_for_ns: u64,
    },
    /// Not observable. Never means "clear": absence of sightings is not
    /// evidence of absence of events.
    NotObservable {
        /// Why.
        reason: WatchOfflineReason,
    },
}

impl WatchState {
    /// Stable string form for records.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observable => "observable",
            Self::Silent { .. } => "silent",
            Self::Asleep { .. } => "asleep",
            Self::NotObservable { .. } => "not_observable",
        }
    }
}

/// One recorded state transition (the watchdog's output evidence).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceStateChange {
    /// Device identity (the caller's stable key: IP or MAC).
    pub device_id: String,
    /// Device class.
    pub class: DeviceClass,
    /// Previous state.
    pub from: WatchState,
    /// New state.
    pub to: WatchState,
    /// When the transition was evaluated (caller-supplied time).
    pub at_ns: u64,
}

impl DeviceStateChange {
    /// Canonical record text (deterministic, digestible downstream).
    /// The device identity is JSON-escaped: callers' ids are IPs/MACs today,
    /// but the library never trusts the alphabet. `not_observable` records
    /// carry the offline reason; `silent`/`asleep` records carry the
    /// duration — a consumer never has to guess which offline it was.
    #[must_use]
    pub fn to_record(&self) -> String {
        fn state_detail(st: &WatchState) -> String {
            match st {
                WatchState::NotObservable { reason } => {
                    format!(",\"reason\":\"{}\"", reason.as_str())
                }
                WatchState::Silent { silent_for_ns } | WatchState::Asleep { silent_for_ns } => {
                    format!(",\"silent_for_ns\":{silent_for_ns}")
                }
                WatchState::Observable => String::new(),
            }
        }
        format!(
            "{{\"type\":\"device_state_change\",\"device\":\"{}\",\"class\":\"{}\",\"from\":\"{}\"{},\"to\":\"{}\"{},\"at_ns\":{}}}",
            json_escape(&self.device_id),
            self.class.as_str(),
            self.from.as_str(),
            state_detail(&self.from),
            self.to.as_str(),
            state_detail(&self.to),
            self.at_ns
        )
    }
}

#[derive(Clone, Debug)]
struct Tracked {
    class: DeviceClass,
    last_seen_ns: Option<u64>,
    state: WatchState,
    thresholds: (u64, u64),
    /// Thresholds came from the caller, not the class defaults — a class
    /// upgrade must not clobber them.
    thresholds_overridden: bool,
}

/// True when two states are the same VARIANT (the counter payloads of
/// `Silent`/`Asleep` move every evaluation; a transition is a record only
/// when the variant changes).
fn same_state_variant(a: &WatchState, b: &WatchState) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Escapes a string for embedding in a JSON string value.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The sans-IO device-liveness watchdog.
pub struct DeviceWatchdog {
    devices: BTreeMap<String, Tracked>,
    changes: Vec<DeviceStateChange>,
}

impl DeviceWatchdog {
    /// An empty watchdog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
            changes: Vec::new(),
        }
    }

    /// Registers a device (idempotent). `thresholds` overrides the class
    /// defaults: `(grace_ns, hard_silence_ns)`.
    ///
    /// Reclassification: a device first seen as `Unknown` upgrades to a
    /// concrete class (and that class's default thresholds) when discovery
    /// later identifies it. A device already at a concrete class keeps it —
    /// classification flip-flops are not honored silently. Caller-supplied
    /// threshold overrides always survive.
    pub fn register(
        &mut self,
        device_id: &str,
        class: DeviceClass,
        thresholds: Option<(u64, u64)>,
    ) {
        match self.devices.entry(device_id.to_string()) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(Tracked {
                    class,
                    last_seen_ns: None,
                    state: WatchState::NotObservable {
                        reason: WatchOfflineReason::NeverObserved,
                    },
                    thresholds: thresholds.unwrap_or_else(|| class.default_thresholds_ns()),
                    thresholds_overridden: thresholds.is_some(),
                });
            }
            std::collections::btree_map::Entry::Occupied(mut o) => {
                let entry = o.get_mut();
                if entry.class == DeviceClass::Unknown && class != DeviceClass::Unknown {
                    entry.class = class;
                    if !entry.thresholds_overridden {
                        entry.thresholds = class.default_thresholds_ns();
                    }
                }
                if let Some(t) = thresholds {
                    entry.thresholds = t;
                    entry.thresholds_overridden = true;
                }
            }
        }
    }

    /// Records a sighting of a device at `now_ns`. A registered device
    /// transitions to `Observable`; an UNREGISTERED device is still tracked
    /// (unknown class) — a sighting of something we never registered is
    /// itself notable, and dropping it would hide exactly that.
    pub fn observe(&mut self, device_id: &str, now_ns: u64) {
        let entry = self
            .devices
            .entry(device_id.to_string())
            .or_insert_with(|| Tracked {
                class: DeviceClass::Unknown,
                last_seen_ns: None,
                state: WatchState::NotObservable {
                    reason: WatchOfflineReason::NeverObserved,
                },
                thresholds: DeviceClass::Unknown.default_thresholds_ns(),
                thresholds_overridden: false,
            });
        // A late response cannot resurrect a device which has since gone dark.
        // Keep both the newest sighting and its already-evaluated state.
        if entry.last_seen_ns.is_some_and(|last| now_ns <= last) {
            return;
        }
        entry.last_seen_ns = Some(entry.last_seen_ns.map_or(now_ns, |prev| prev.max(now_ns)));
        let new_state = WatchState::Observable;
        if entry.state != new_state {
            let change = DeviceStateChange {
                device_id: device_id.to_string(),
                class: entry.class,
                from: entry.state.clone(),
                to: new_state.clone(),
                at_ns: now_ns,
            };
            entry.state = new_state;
            self.changes.push(change);
        }
    }

    /// Evaluates all tracked devices against `now_ns`, emitting a
    /// [`DeviceStateChange`] only when a device's state VARIANT changes.
    /// (The `Silent`/`Asleep` counter payloads refresh in place every
    /// evaluation; recording those as transitions would churn the evidence
    /// stream with non-events.) Pure: no I/O, no clock of its own.
    pub fn evaluate(&mut self, now_ns: u64) {
        // Single pass: refresh the stored state for every tracked device
        // (counter payloads move with time), collecting records only where
        // the state VARIANT changed.
        let mut new_records: Vec<DeviceStateChange> = Vec::new();
        for (id, entry) in self.devices.iter_mut() {
            let Some(last) = entry.last_seen_ns else {
                continue; // NeverObserved stays as-is; nothing to age.
            };
            // Backward evaluation (now before the last sighting) is a caller
            // clock violation; saturating_sub would make the device look
            // freshly seen. Hold the state and skip instead.
            if now_ns < last {
                continue;
            }
            let silent_for = now_ns - last;
            let (grace, hard) = entry.thresholds;
            let new_state = if silent_for < grace {
                WatchState::Observable
            } else if silent_for < hard {
                match entry.class {
                    DeviceClass::BatteryEventDriven => WatchState::Asleep {
                        silent_for_ns: silent_for,
                    },
                    _ => WatchState::Silent {
                        silent_for_ns: silent_for,
                    },
                }
            } else {
                WatchState::NotObservable {
                    reason: WatchOfflineReason::SilentBeyondThreshold,
                }
            };
            let variant_changed = !same_state_variant(&new_state, &entry.state);
            if variant_changed {
                new_records.push(DeviceStateChange {
                    device_id: id.clone(),
                    class: entry.class,
                    from: entry.state.clone(),
                    to: new_state.clone(),
                    at_ns: now_ns,
                });
            }
            // Always refresh: the latest silent_for_ns is the current state.
            entry.state = new_state;
        }
        self.changes.append(&mut new_records);
    }

    /// Current state of one device (`None` if never registered or seen).
    #[must_use]
    pub fn state_of(&self, device_id: &str) -> Option<&WatchState> {
        self.devices.get(device_id).map(|t| &t.state)
    }

    /// All transitions recorded so far (the evidence stream).
    #[must_use]
    pub fn changes(&self) -> &[DeviceStateChange] {
        &self.changes
    }

    /// Drains the transition buffer (the caller archives them).
    pub fn drain_changes(&mut self) -> Vec<DeviceStateChange> {
        std::mem::take(&mut self.changes)
    }
}

impl Default for DeviceWatchdog {
    fn default() -> Self {
        Self::new()
    }
}
