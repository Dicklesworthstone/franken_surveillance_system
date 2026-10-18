#![forbid(unsafe_code)]
//! The producer→consumer seam between `fss-provision`'s agent heartbeats
//! and the DISC-5 device-liveness watchdog (`fss-niak9`, LAB-PROVISION-001).
//!
//! Composition contract: the provision agent's `HeartbeatTracker` owns the
//! CAMERA-side liveness of the provisioned node (beats produced on-device);
//! the watchdog owns the HOST-side observability of the same camera from
//! sightings (host receives beats). Each machine owns its own thresholds and
//! grace windows — this module translates EVENTS (a heartbeat arrived) into
//! sightings, never STATES (there is no honest conversion of the camera's
//! internal grace accounting into host durations, and fabricating one would
//! hide exactly the information loss the honesty rules forbid).

use fss_provision::agent::AgentHeartbeat;

use crate::discovery::watchdog::{DeviceClass, DeviceWatchdog};

/// Registers a provisioned camera under its agent class (idempotent,
/// upgrade-honoring) and records one heartbeat as a host-side sighting.
/// `at_ns` is the HOST receive time of the beat (the watchdog's time base
/// is host-local by design).
pub fn observe_agent_heartbeat(
    watchdog: &mut DeviceWatchdog,
    camera_id: &str,
    _heartbeat: &AgentHeartbeat,
    host_received_ns: u64,
) {
    watchdog.register(camera_id, DeviceClass::ProvisionedAgent, None);
    watchdog.observe(camera_id, host_received_ns);
}
