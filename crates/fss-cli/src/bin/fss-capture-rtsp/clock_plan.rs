#![forbid(unsafe_code)]
//! Pure, opt-in admission for a same-capture node observation clock.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use fss_cli::agent_json::{object, string};
use fss_cli::native_clock::{MAX_NETWORK_BYTES, MAX_RECEIVE_POLLS};
use fss_core::CanonicalEncoder;
use fss_reference::rtsp::recording_clock::{
    MAX_CLOCK_BRACKETS, MAX_CLOCK_INDEX_BYTES, MAX_CLOCK_WINDOWS,
};
use fss_reference::site::clock_proof::{LOCAL_NTP_CLOCK_POLICY, LOCAL_NTP_LIMITS};

/// Explicit reservation for the bounded live table, retained packet coordinates,
/// and canonical clock index while the immutable index is being prepared.
pub(crate) const MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const STORAGE_OPERATIONS: u64 = 64 * MAX_CLOCK_WINDOWS as u64 + 128;
const POLICY: &str = "fss.rtsp_capture_node_clock.v1:one-loopback-ntp-exchange:unauthenticated:\
read-admission-brackets:same-task-epoch:terminal-before-drain:root-last-original-closure:\
no-camera-exposure-claim:no-adjustment:no-refresh";

#[derive(Clone, Copy, Debug)]
pub(crate) struct ClockPlan {
    pub(crate) peer: SocketAddr,
}
impl ClockPlan {
    pub(crate) fn parse(
        values: &BTreeMap<&str, &str>,
        timeout_ns: u64,
        max_windows: usize,
    ) -> Result<Option<Self>, &'static str> {
        let Some(value) = values.get("--clock-ntp-peer") else {
            return Ok(None);
        };
        let peer: SocketAddr = value.parse().map_err(|_| "literal clock peer required")?;
        if !peer.ip().is_loopback()
            || peer.port() == 0
            || matches!(peer, SocketAddr::V6(peer) if peer.scope_id() != 0 || peer.flowinfo() != 0)
            || peer.to_string() != *value
        {
            return Err("clock peer must be a canonical loopback IP and nonzero port");
        }
        if timeout_ns > LOCAL_NTP_CLOCK_POLICY.max_age_ns || max_windows > MAX_CLOCK_WINDOWS {
            return Err("clock capture requires timeout at most 60000 ms and at most 64 windows");
        }
        Ok(Some(Self { peer }))
    }

    pub(crate) fn encode(self, e: &mut CanonicalEncoder) {
        e.text(POLICY);
        e.text(&self.peer.to_string());
        for (_, value) in self.bounds() {
            e.u64(value);
        }
    }

    fn bounds(self) -> [(&'static str, u64); 12] {
        [
            (
                "max_sample_bracket_ns",
                LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns,
            ),
            (
                "assumed_max_drift_ppb",
                LOCAL_NTP_CLOCK_POLICY.max_drift_ppb,
            ),
            ("max_age_ns", LOCAL_NTP_CLOCK_POLICY.max_age_ns),
            ("max_exchange_ns", LOCAL_NTP_LIMITS.max_exchange_ns),
            ("max_offset_ns", LOCAL_NTP_LIMITS.max_offset_ns),
            ("max_uncertainty_ns", LOCAL_NTP_LIMITS.max_uncertainty_ns),
            ("max_receive_polls", MAX_RECEIVE_POLLS),
            ("max_network_bytes", MAX_NETWORK_BYTES),
            ("max_brackets", MAX_CLOCK_BRACKETS as u64),
            ("max_index_bytes", MAX_CLOCK_INDEX_BYTES as u64),
            ("reserved_memory_bytes", MEMORY_BYTES),
            ("reserved_storage_operations", STORAGE_OPERATIONS),
        ]
    }

    pub(crate) fn preview(self) -> String {
        let numbers: Vec<_> = self
            .bounds()
            .into_iter()
            .map(|(key, value)| (key, value.to_string()))
            .collect();
        object(&[
            ("policy", string(POLICY)),
            ("peer", string(&self.peer.to_string())),
            ("source", string("unauthenticated_loopback_ntp_claim")),
            ("time_basis", string("node_read_admission_bracket")),
            ("bounds", object(&numbers)),
            ("max_windows", MAX_CLOCK_WINDOWS.to_string()),
            ("exchanges_per_attempt", "1".into()),
            ("camera_capture_time", string("unknown")),
            ("server_authenticated", "false".into()),
            ("adjust_host_clock", "false".into()),
            ("refresh_automatically", "false".into()),
            ("coverage_certified", "false".into()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_endpoint_is_explicit_loopback_and_bounded_to_its_lifetime() {
        for peer in [
            "localhost:123",
            "192.0.2.1:123",
            "127.0.0.1:0",
            "[::1%1]:123",
            "127.0.0.1:0123",
        ] {
            assert!(
                ClockPlan::parse(
                    &BTreeMap::from([("--clock-ntp-peer", peer)]),
                    30_000_000_000,
                    32
                )
                .is_err()
            );
        }
        let values = BTreeMap::from([("--clock-ntp-peer", "127.0.0.1:123")]);
        assert!(
            ClockPlan::parse(&values, 60_000_000_000, 64)
                .unwrap()
                .is_some()
        );
        assert!(ClockPlan::parse(&values, 60_000_000_001, 64).is_err());
        assert!(ClockPlan::parse(&values, 30_000_000_000, 65).is_err());
        assert!(
            ClockPlan::parse(&BTreeMap::new(), 600_000_000_000, 128)
                .unwrap()
                .is_none()
        );
    }
}
