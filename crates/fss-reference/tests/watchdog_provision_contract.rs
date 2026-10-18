#![forbid(unsafe_code)]
//! Contract tests for the provision→watchdog seam: provision agent
//! heartbeats become host-side sightings under the ProvisionedAgent class;
//! registration is idempotent; the ProvisionedAgent class carries
//! mains-like thresholds; and class stability holds across registrations.

use fss_core::ContentDigest;
use fss_provision::agent::{AgentCoverageState, AgentHeartbeat};
use fss_reference::discovery::watchdog::{DeviceClass, DeviceWatchdog, WatchState};
use fss_reference::discovery::watchdog_provision::observe_agent_heartbeat;

const MIN: u64 = 60_000_000_000;

fn heartbeat(seq: u64) -> AgentHeartbeat {
    AgentHeartbeat::new(
        ContentDigest::sha256(b"report:test-agent"),
        seq,
        AgentCoverageState::Observable,
    )
}

#[test]
fn heartbeat_registers_under_agent_class_and_marks_observable() {
    let mut w = DeviceWatchdog::new();
    observe_agent_heartbeat(&mut w, "yi-cam-1", &heartbeat(1), 1_000);
    assert_eq!(w.state_of("yi-cam-1"), Some(&WatchState::Observable));
    // The ProvisionedAgent class uses mains-like thresholds (2 min grace):
    // past grace without beats, the device walks to Silent.
    w.evaluate(1_000 + 3 * MIN);
    assert!(matches!(
        w.state_of("yi-cam-1"),
        Some(WatchState::Silent { .. })
    ));
}

#[test]
fn registration_is_idempotent_and_class_stable() {
    let mut w = DeviceWatchdog::new();
    observe_agent_heartbeat(&mut w, "yi-cam-1", &heartbeat(1), 1_000);
    // Repeated heartbeats: no churn, no duplicate registration effects.
    observe_agent_heartbeat(&mut w, "yi-cam-1", &heartbeat(2), 2_000);
    observe_agent_heartbeat(&mut w, "yi-cam-1", &heartbeat(3), 3_000);
    assert_eq!(w.state_of("yi-cam-1"), Some(&WatchState::Observable));
    assert_eq!(w.changes().len(), 1, "one never-observed→observable transition");
    // The class is discoverable via threshold behavior (provisioned agents
    // go offline at 10 min like mains devices, not 48h like battery cams).
    w.evaluate(1_000 + 11 * MIN);
    assert!(matches!(
        w.state_of("yi-cam-1"),
        Some(WatchState::NotObservable { .. })
    ));
}

#[test]
fn provisioned_class_string_is_stable() {
    assert_eq!(DeviceClass::ProvisionedAgent.as_str(), "provisioned_agent");
}
