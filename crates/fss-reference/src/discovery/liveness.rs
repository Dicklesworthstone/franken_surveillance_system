//! The producer/consumer link between an on-camera [`HeartbeatTracker`] and
//! the DISC-5 [`DeviceWatchdog`].
//!
//! A received [`AgentHeartbeat`] is a sighting: the device spoke at a
//! caller-supplied time, including when the sequence is duplicated or reset.
//! A missed interval is not a sighting. [`note_agent_silence`] advances the
//! tracker's missed-interval count and asks the watchdog to age every device
//! it already has against that same timestamp. The two clocks agree only
//! when the caller passes watchdog thresholds of `(interval, grace *
//! interval)` and calls silence once per interval.

use fss_provision::{AgentHeartbeat, HeartbeatTracker, LivenessTransition};

use super::watchdog::{DeviceClass, DeviceWatchdog};

/// Records one received agent heartbeat.
///
/// `thresholds` is `(grace_ns, hard_silence_ns)` for this device. `None`
/// keeps the class defaults. Passing the same override on later beats is
/// idempotent.
pub fn note_agent_beat(
    watchdog: &mut DeviceWatchdog,
    tracker: &mut HeartbeatTracker,
    device_id: &str,
    class: DeviceClass,
    at_ns: u64,
    heartbeat: &AgentHeartbeat,
    thresholds: Option<(u64, u64)>,
) -> LivenessTransition {
    let transition = tracker.note_beat(heartbeat);
    watchdog.register(device_id, class, thresholds);
    watchdog.observe(device_id, at_ns);
    transition
}

/// Records one missed heartbeat interval at `at_ns`.
///
/// This does not invent a sighting. A camera that has never spoken stays
/// `NotObservable { NeverObserved }` on the watchdog; the tracker still
/// counts the miss.
pub fn note_agent_silence(
    watchdog: &mut DeviceWatchdog,
    tracker: &mut HeartbeatTracker,
    at_ns: u64,
) -> LivenessTransition {
    let transition = tracker.note_interval_elapsed();
    watchdog.evaluate(at_ns);
    transition
}
