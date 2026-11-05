#![forbid(unsafe_code)]
//! One approved, bounded local-daemon exchange and sampled node-clock continuity.
//!
//! All clock and socket boundaries use the probe's existing owned runtime scope.
//! No daemon discovery, DNS, retries, clock adjustment or detached work occurs.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{CanonicalEncoder, RuntimeGrant};
use fss_packet::ntp::SntpRequest;
use fss_reference::site::ClockWitness;
use fss_reference::site::clock::{ClockCorrelation, HostClockSample};
use fss_reference::site::clock_proof::{
    LOCAL_NTP_CLOCK_POLICY, LOCAL_NTP_LIMITS, LocalNtpClockProof,
};

use super::{runtime, runtime_error};
use crate::json_output::{object, string};
use crate::site_probe::plan::MAX_STEPS;

const MAX_POLLS: u64 = 1024;
const NETWORK: &str = "ERR-SITE-CLOCK-NETWORK-001";
const SAMPLE: &str = "ERR-SITE-CLOCK-SAMPLE-001";
const PROOF: &str = "ERR-SITE-CLOCK-PROOF-001";
const DEADLINE: &str = "ERR-SITE-CLOCK-DEADLINE-001";
const REPLY: &str = "ERR-SITE-CLOCK-REPLY-001";
const CONTINUITY: &str = "ERR-SITE-CLOCK-CONTINUITY-001";

/// Approval binds every native limit and the meaning of the resulting evidence.
pub(in crate::site_probe) fn encode_policy(encoder: &mut CanonicalEncoder) {
    encoder.text("unauthenticated-loopback-ntp:basic-v4:one-exchange:no-leap-policy:v1");
    encoder.u64(LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns);
    encoder.u64(LOCAL_NTP_CLOCK_POLICY.max_drift_ppb);
    encoder.u64(LOCAL_NTP_CLOCK_POLICY.max_age_ns);
    encoder.u64(LOCAL_NTP_LIMITS.max_exchange_ns);
    encoder.u64(LOCAL_NTP_LIMITS.max_offset_ns);
    encoder.u64(LOCAL_NTP_LIMITS.max_uncertainty_ns);
    encoder.u64(MAX_POLLS);
    encoder.u64(MAX_STEPS);
    encoder.u64(48);
    encoder.u64(49);
}

pub(in crate::site_probe) fn preview(peer: SocketAddr) -> String {
    object(&[
        ("source", string("unauthenticated_loopback_ntp_claim")),
        ("peer", string(&peer.to_string())),
        ("exchanges", "1".into()),
        (
            "max_exchange_ns",
            LOCAL_NTP_LIMITS.max_exchange_ns.to_string(),
        ),
        ("max_offset_ns", LOCAL_NTP_LIMITS.max_offset_ns.to_string()),
        (
            "max_uncertainty_ns",
            LOCAL_NTP_LIMITS.max_uncertainty_ns.to_string(),
        ),
        (
            "max_sample_bracket_ns",
            LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns.to_string(),
        ),
        (
            "assumed_max_drift_ppb",
            LOCAL_NTP_CLOCK_POLICY.max_drift_ppb.to_string(),
        ),
        ("max_age_ns", LOCAL_NTP_CLOCK_POLICY.max_age_ns.to_string()),
        ("max_receive_polls", MAX_POLLS.to_string()),
        (
            "observation_basis",
            string("first_picture_node_processing_bracket"),
        ),
        ("camera_capture_time", "false".into()),
        ("server_authenticated", "false".into()),
        ("adjust_host_clock", "false".into()),
        ("retry_automatically", "false".into()),
    ])
}

fn sample(scope: &runtime::Scope<'_, '_>) -> Result<HostClockSample, &'static str> {
    let monotonic_before_ns = scope.now().map_err(runtime_error)?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH);
    // Recheck the live task even when the wall clock could not be represented.
    let monotonic_after_ns = scope.now().map_err(runtime_error)?;
    if monotonic_after_ns
        .checked_sub(monotonic_before_ns)
        .ok_or(CONTINUITY)?
        > LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns
    {
        return Err(SAMPLE);
    }
    let wall_clock_unix_ns =
        u64::try_from(wall.map_err(|_| SAMPLE)?.as_nanos()).map_err(|_| SAMPLE)?;
    Ok(HostClockSample {
        monotonic_before_ns,
        wall_clock_unix_ns,
        monotonic_after_ns,
    })
}

fn network<T>(
    scope: &runtime::Scope<'_, '_>,
    operation: impl FnOnce() -> io::Result<T>,
) -> Result<io::Result<T>, &'static str> {
    scope
        .admit(RuntimeGrant::AdapterNet, false)
        .map_err(runtime_error)?;
    let result = operation();
    scope
        .admit(RuntimeGrant::AdapterNet, false)
        .map_err(runtime_error)?;
    Ok(result)
}

pub(super) struct NativeClock {
    proof: LocalNtpClockProof,
    correlation: ClockCorrelation,
    /// Bounded read/processing brackets indexed by the exact admission coordinate
    /// carried through the native RTP observer; never by media or RTCP time.
    observations: BTreeMap<u64, u64>,
}

impl NativeClock {
    pub(super) fn begin(
        peer: SocketAddr,
        deadline_ns: u64,
        scope: &runtime::Scope<'_, '_>,
    ) -> Result<Self, &'static str> {
        if !peer.ip().is_loopback()
            || peer.port() == 0
            || matches!(peer, SocketAddr::V6(peer) if peer.scope_id() != 0 || peer.flowinfo() != 0)
        {
            return Err(PROOF);
        }
        let bind = SocketAddr::new(
            match peer.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            0,
        );
        let socket = network(scope, || UdpSocket::bind(bind))?.map_err(|_| NETWORK)?;
        network(scope, || socket.connect(peer))?.map_err(|_| NETWORK)?;
        network(scope, || socket.set_nonblocking(true))?.map_err(|_| NETWORK)?;
        let sent_before = sample(scope)?;
        let request = SntpRequest::new(sent_before.wall_clock_unix_ns).map_err(|_| PROOF)?;
        let exchange_deadline = sent_before
            .monotonic_before_ns
            .checked_add(LOCAL_NTP_LIMITS.max_exchange_ns)
            .ok_or(DEADLINE)?
            .min(deadline_ns);
        let sent = network(scope, || socket.send(request.wire_bytes()))?.map_err(|_| NETWORK)?;
        let sent_after = sample(scope)?;
        scope.network_bytes(sent as u64).map_err(runtime_error)?;
        if sent != request.wire_bytes().len() {
            return Err(NETWORK);
        }
        // One extra byte makes both extended and truncated oversized datagrams
        // distinguishable from the only admitted exact basic-mode reply.
        let mut received = [0_u8; 49];
        for _ in 0..MAX_POLLS {
            let received_before = sample(scope)?;
            if received_before.monotonic_after_ns >= exchange_deadline {
                return Err(DEADLINE);
            }
            let result = network(scope, || socket.recv(&mut received))?;
            let received_after = sample(scope)?;
            if let Ok(length) = &result {
                scope.network_bytes(*length as u64).map_err(runtime_error)?;
            }
            if received_after.monotonic_after_ns >= exchange_deadline {
                return Err(DEADLINE);
            }
            match result {
                Ok(length) => {
                    let reply: [u8; 48] = received
                        .get(..length)
                        .ok_or(REPLY)?
                        .try_into()
                        .map_err(|_| REPLY)?;
                    let proof = LocalNtpClockProof {
                        peer,
                        request: *request.wire_bytes(),
                        reply,
                        sent_before,
                        sent_after,
                        received_before,
                        received_after,
                        observation_start_ns: received_after.monotonic_after_ns,
                        observation_end_ns: received_after.monotonic_after_ns,
                        terminal: received_after,
                        policy: LOCAL_NTP_CLOCK_POLICY,
                    };
                    let correlation = proof.correlation().map_err(|_| PROOF)?;
                    return Ok(Self {
                        proof,
                        correlation,
                        observations: BTreeMap::new(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    scope.wait(exchange_deadline).map_err(runtime_error)?;
                }
                Err(_) => return Err(NETWORK),
            }
        }
        Err(DEADLINE)
    }

    fn checked_sample(
        &mut self,
        scope: &runtime::Scope<'_, '_>,
    ) -> Result<HostClockSample, &'static str> {
        let current = sample(scope)?;
        self.correlation
            .observe_later_sample(current)
            .map_err(|_| CONTINUITY)?;
        Ok(current)
    }

    pub(super) fn before_step(
        &mut self,
        scope: &runtime::Scope<'_, '_>,
    ) -> Result<u64, &'static str> {
        Ok(self.checked_sample(scope)?.monotonic_after_ns)
    }

    pub(super) fn after_step(
        &mut self,
        start: u64,
        scope: &runtime::Scope<'_, '_>,
    ) -> Result<(), &'static str> {
        let end = self.checked_sample(scope)?.monotonic_after_ns;
        if start > end || self.observations.len() as u64 >= MAX_STEPS {
            return Err(CONTINUITY);
        }
        self.observations
            .entry(start)
            .and_modify(|prior| *prior = (*prior).max(end))
            .or_insert(end);
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        first_picture_observed_at_ns: u64,
        scope: &runtime::Scope<'_, '_>,
    ) -> Result<(ClockWitness, LocalNtpClockProof), &'static str> {
        let terminal = self.checked_sample(scope)?;
        self.proof.observation_start_ns = first_picture_observed_at_ns;
        self.proof.observation_end_ns = *self
            .observations
            .get(&first_picture_observed_at_ns)
            .ok_or(CONTINUITY)?;
        self.proof.terminal = terminal;
        let witness = self.proof.reconstruct().map_err(|_| PROOF)?;
        Ok((witness, self.proof))
    }
}
