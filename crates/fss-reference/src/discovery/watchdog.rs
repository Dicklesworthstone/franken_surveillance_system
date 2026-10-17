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
    #[must_use]
    pub fn to_record(&self) -> String {
        format!(
            "{{\"type\":\"device_state_change\",\"device\":\"{}\",\"class\":\"{}\",\"from\":\"{}\",\"to\":\"{}\",\"at_ns\":{}}}",
            self.device_id,
            self.class.as_str(),
            self.from.as_str(),
            self.to.as_str(),
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
    pub fn register(
        &mut self,
        device_id: &str,
        class: DeviceClass,
        thresholds: Option<(u64, u64)>,
    ) {
        self.devices.entry(device_id.to_string()).or_insert_with(|| Tracked {
            class,
            last_seen_ns: None,
            state: WatchState::NotObservable {
                reason: WatchOfflineReason::NeverObserved,
            },
            thresholds: thresholds.unwrap_or_else(|| class.default_thresholds_ns()),
        });
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
            });
        entry.last_seen_ns = Some(now_ns);
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

    /// Evaluates all tracked devices against `now_ns`, emitting transitions
    /// for any state changes. Pure: no I/O, no clock of its own.
    pub fn evaluate(&mut self, now_ns: u64) {
        let ids: Vec<String> = self.devices.keys().cloned().collect();
        for id in ids {
            let entry = self.devices.get(&id).expect("present").clone();
            let Some(last) = entry.last_seen_ns else {
                continue; // NeverObserved stays as-is; nothing to age.
            };
            let silent_for = now_ns.saturating_sub(last);
            let (grace, hard) = entry.thresholds;
            let new_state = if silent_for < grace {
                WatchState::Observable
            } else if silent_for < hard {
                match entry.class {
                    DeviceClass::BatteryEventDriven => WatchState::Asleep { silent_for_ns: silent_for },
                    _ => WatchState::Silent { silent_for_ns: silent_for },
                }
            } else {
                WatchState::NotObservable {
                    reason: WatchOfflineReason::SilentBeyondThreshold,
                }
            };
            if new_state != entry.state {
                let change = DeviceStateChange {
                    device_id: id.clone(),
                    class: entry.class,
                    from: entry.state.clone(),
                    to: new_state.clone(),
                    at_ns: now_ns,
                };
                if let Some(slot) = self.devices.get_mut(&id) {
                    slot.state = new_state;
                }
                self.changes.push(change);
            }
        }
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
