#![forbid(unsafe_code)]
//! Bounded, explicitly scoped Ubiquiti v1 LAN discovery over Asupersync UDP.
//!
//! One query is sent to the supplied local destination. Replies are
//! unauthenticated candidate observations; this module does not enroll,
//! configure, log into, or take over any device. A timeout or packet limit
//! never proves that the rest of the network lacks cameras.

use super::metered::MeteredClock;
use asupersync::{Cx, net::UdpSocket, time::timeout_at};
use fss_core::{BudgetVector, RuntimeGrant, TimestampNs};
use fss_packet::unifi_discovery::{self, DeviceKind, Reply};
use fss_runtime::execution::{ExecutionError, TaskCx};
use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

const MAX_PACKETS: usize = 128;
const MAX_WINDOW: Duration = Duration::from_secs(30);
const MAX_RESOURCE: usize = 1024;

/// Payload-free discovery refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid scope, resource, time window or packet limit.
    Configuration,
    /// The explicit runtime or canonical task refused admission.
    Authority,
    /// The runtime has no scoped timer driver.
    NoTimer,
    /// Bounded report allocation failed before probing.
    Allocation,
    /// Socket setup, send, or receive failed without exposing an address.
    Io(io::ErrorKind),
    /// UDP did not report that the complete query was accepted locally.
    IncompleteSend,
    /// Socket setup did not finish before the bounded deadline.
    SetupDeadline,
    /// The send was interrupted or timed out and may have been emitted.
    IndeterminateSend,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi discovery refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One private or loopback network interface and bounded discovery attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct Config {
    bind: Ipv4Addr,
    mask: u32,
    target: SocketAddrV4,
    broadcast: bool,
    resource: String,
    window: Duration,
    max_packets: usize,
}
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("window", &self.window)
            .field("max_packets", &self.max_packets)
            .finish_non_exhaustive()
    }
}
impl Config {
    /// Construct one scoped query. The destination is a unicast address in
    /// the interface subnet, its directed broadcast, or the limited broadcast
    /// address; no subnet sweep
    /// is performed. The owner must authorize this particular interface and
    /// network resource before invoking the probe.
    pub fn new(
        bind: Ipv4Addr,
        prefix: u8,
        target: SocketAddrV4,
        resource: &str,
        window: Duration,
        max_packets: usize,
    ) -> Result<Self, Error> {
        if !(1..=32).contains(&prefix)
            || !(bind.is_private() || bind.is_loopback() || bind.is_link_local())
            || bind.is_unspecified()
            || bind.is_multicast()
            || target.port() == 0
            || target.ip().is_unspecified()
            || target.ip().is_multicast()
            || resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || window.is_zero()
            || window > MAX_WINDOW
            || !(1..=MAX_PACKETS).contains(&max_packets)
        {
            return Err(Error::Configuration);
        }
        let mask = u32::MAX << (32 - prefix);
        if *target.ip() != Ipv4Addr::BROADCAST
            && (u32::from(*target.ip()) & mask) != (u32::from(bind) & mask)
        {
            return Err(Error::Configuration);
        }
        // /31 and /32 have no directed broadcast address. Do not treat their
        // last address as a multi-source destination.
        let broadcast = *target.ip() == Ipv4Addr::BROADCAST
            || (prefix <= 30 && u32::from(*target.ip()) == (u32::from(bind) | !mask));
        Ok(Self {
            bind,
            mask,
            target,
            broadcast,
            resource: resource.to_owned(),
            window,
            max_packets,
        })
    }
    fn in_scope(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == (u32::from(self.bind) & self.mask)
            && (self.broadcast || ip == *self.target.ip())
    }
}

/// A single unauthenticated UVC-family claim tied to its datagram source.
#[derive(Clone, Eq, PartialEq)]
pub struct CameraCandidate {
    source: SocketAddrV4,
    platform: String,
    firmware: Option<String>,
    mac: Option<[u8; 6]>,
    source_advertised: bool,
}
impl CameraCandidate {
    /// Network source of this response; not cryptographically authenticated.
    pub fn source(&self) -> SocketAddrV4 {
        self.source
    }
    /// Untrusted platform claim.
    pub fn platform(&self) -> &str {
        &self.platform
    }
    /// Untrusted firmware claim.
    pub fn firmware(&self) -> Option<&str> {
        self.firmware.as_deref()
    }
    /// Untrusted MAC claim, if present.
    pub fn mac(&self) -> Option<[u8; 6]> {
        self.mac
    }
    /// The packet listed its observed source IP in an interface claim.
    pub fn source_advertised(&self) -> bool {
        self.source_advertised
    }
}
impl fmt::Debug for CameraCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CameraCandidate")
            .field("source_advertised", &self.source_advertised)
            .finish_non_exhaustive()
    }
}

/// How a bounded discovery window ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    /// The configured time window elapsed; absence is not established.
    WindowElapsed,
    /// The configured datagram count was reached; unobserved replies may remain.
    PacketLimit,
    /// Runtime cancellation was observed after sending the query.
    Cancelled,
    /// The canonical task deadline limited the discovery window.
    AuthorityDeadline,
    /// The canonical network-byte budget could not admit another receive.
    BudgetExhausted,
    /// The canonical authority refused further receive admission.
    AuthorityStopped,
}

/// Observed results and their explicit capture limit.
#[derive(Debug)]
pub struct Report {
    /// Unauthenticated camera candidates; repeated matching replies are deduplicated.
    pub cameras: Vec<CameraCandidate>,
    /// Total datagrams consumed, including malformed and out-of-scope packets.
    pub datagrams: usize,
    /// Datagrams rejected as malformed or unsupported.
    pub malformed: usize,
    /// Datagrams received from outside the configured address/port scope.
    pub out_of_scope: usize,
    /// How observation stopped.
    pub stop: Stop,
}

/// Potential inconsistencies among untrusted claims in one bounded window.
/// Absence of a conflict does not authenticate a device or authorize setup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClaimAssessment {
    /// The candidate did not provide a usable unicast hardware address.
    pub missing_or_invalid_mac: bool,
    /// The same source IP asserted different hardware addresses.
    pub conflicting_macs_at_address: bool,
    /// One hardware address appeared at different source IP addresses.
    pub same_mac_at_multiple_addresses: bool,
    /// The same source and hardware address gave different platform or firmware claims.
    pub conflicting_metadata: bool,
    /// The datagram did not advertise its actual source address.
    pub source_not_advertised: bool,
}

impl Report {
    /// Assess one candidate against this report, without treating a MAC or IP
    /// as identity. A moving device can produce conflicts during a window;
    /// callers must preserve that uncertainty rather than choose a winner.
    #[must_use]
    pub fn assess_claims(&self, index: usize) -> Option<ClaimAssessment> {
        let candidate = self.cameras.get(index)?;
        let valid_mac = |mac: [u8; 6]| mac != [0; 6] && mac[0] & 1 == 0;
        let mut result = ClaimAssessment {
            missing_or_invalid_mac: !candidate.mac.is_some_and(valid_mac),
            source_not_advertised: !candidate.source_advertised,
            ..ClaimAssessment::default()
        };
        for other in &self.cameras {
            let same_ip = candidate.source.ip() == other.source.ip();
            if let (Some(mac), Some(other_mac)) = (candidate.mac, other.mac) {
                if valid_mac(mac) && valid_mac(other_mac) {
                    result.conflicting_macs_at_address |= same_ip && mac != other_mac;
                    result.same_mac_at_multiple_addresses |= !same_ip && mac == other_mac;
                    result.conflicting_metadata |= same_ip
                        && mac == other_mac
                        && (candidate.platform != other.platform
                            || candidate.firmware != other.firmware);
                }
            }
        }
        Some(result)
    }
}

/// Send one scoped v1 query and collect a finite set of untrusted camera claims.
///
/// The supplied `now` is the current observation in the task's canonical clock
/// domain, co-observed with this runtime context. Elapsed runtime time advances
/// subsequent task admissions. The caller must supervise the enclosing region
/// and join and supply a completion time in the same clock domain. Socket receive cancellation can
/// discard an arriving datagram, so no terminal state establishes absence.
pub async fn discover(
    owner: &TaskCx<'_>,
    runtime_cx: &Cx,
    now: TimestampNs,
    config: &Config,
) -> Result<Report, Error> {
    runtime_cx.checkpoint().map_err(|_| Error::Authority)?;
    if !runtime_cx.has_timer() {
        return Err(Error::NoTimer);
    }
    // Use the earlier runtime sample for the window cap: a delay in creating
    // the mapping must not extend the caller's canonical deadline.
    let runtime_start = runtime_cx.now();
    let clock = MeteredClock::new(owner, runtime_cx, now).map_err(|_| Error::Authority)?;
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            clock.now().map_err(|_| Error::Authority)?,
            &BudgetVector::ZERO,
        )
        .map_err(|_| Error::Authority)?;
    let mut window = config.window;
    let mut authority_limited = false;
    if let Some(deadline) = owner.context().deadline {
        let remaining = deadline
            .0
            .checked_sub(now.0)
            .filter(|&n| n > 0)
            .ok_or(Error::Authority)?;
        let nanos = u64::try_from(remaining).unwrap_or(u64::MAX);
        let remaining = Duration::from_nanos(nanos);
        authority_limited = remaining <= window;
        window = window.min(remaining);
    }
    let mut cameras = Vec::new();
    cameras
        .try_reserve_exact(config.max_packets)
        .map_err(|_| Error::Allocation)?;
    let deadline = runtime_start + window;
    let mut socket = timeout_at(deadline, UdpSocket::bind(SocketAddrV4::new(config.bind, 0)))
        .await
        .map_err(|_| Error::SetupDeadline)?
        .map_err(|e| Error::Io(e.kind()))?;
    socket
        .set_broadcast(true)
        .map_err(|e| Error::Io(e.kind()))?;
    if runtime_cx.now() >= deadline {
        return Err(Error::SetupDeadline);
    }
    let mut send_cost = BudgetVector::ZERO;
    send_cost.network_bytes = unifi_discovery::V1_QUERY.len() as u64;
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            clock.now().map_err(|_| Error::Authority)?,
            &send_cost,
        )
        .map_err(|_| Error::Authority)?;
    runtime_cx.checkpoint().map_err(|_| Error::Authority)?;
    if runtime_cx.now() >= deadline {
        return Err(Error::SetupDeadline);
    }
    let sent = match timeout_at(
        deadline,
        socket.send_to(&unifi_discovery::V1_QUERY, config.target),
    )
    .await
    {
        Err(_) => return Err(Error::IndeterminateSend),
        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            return Err(Error::IndeterminateSend);
        }
        Ok(Err(error)) => return Err(Error::Io(error.kind())),
        Ok(Ok(sent)) => sent,
    };
    if sent != unifi_discovery::V1_QUERY.len() {
        return Err(Error::IncompleteSend);
    }
    let mut report = Report {
        cameras,
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: if authority_limited {
            Stop::AuthorityDeadline
        } else {
            Stop::WindowElapsed
        },
    };
    let mut buffer = [0_u8; unifi_discovery::MAX_DATAGRAM + 1];
    loop {
        if runtime_cx.checkpoint().is_err() {
            report.stop = Stop::Cancelled;
            break;
        }
        if report.datagrams == config.max_packets {
            report.stop = Stop::PacketLimit;
            break;
        }
        // Do not debit a fresh receive after its observation window has
        // already closed. The preselected stop also preserves whether the
        // task deadline or the configured window was the limiting boundary.
        if runtime_cx.now() >= deadline {
            break;
        }
        let mut receive_cost = BudgetVector::ZERO;
        receive_cost.network_bytes = buffer.len() as u64;
        let current = match clock.now() {
            Ok(current) => current,
            Err(_) => {
                report.stop = if runtime_cx.is_cancelled() {
                    Stop::Cancelled
                } else {
                    Stop::AuthorityStopped
                };
                break;
            }
        };
        if let Err(error) = owner.checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            current,
            &receive_cost,
        ) {
            report.stop = match error {
                ExecutionError::Budget(_) => Stop::BudgetExhausted,
                ExecutionError::Deadline { .. } => Stop::AuthorityDeadline,
                _ => Stop::AuthorityStopped,
            };
            break;
        }
        let (len, source) = match timeout_at(deadline, socket.recv_from(&mut buffer)).await {
            Err(_) => {
                if runtime_cx.is_cancelled() {
                    report.stop = Stop::Cancelled;
                }
                break;
            }
            Ok(Err(error))
                if error.kind() == io::ErrorKind::Interrupted && runtime_cx.is_cancelled() =>
            {
                report.stop = Stop::Cancelled;
                break;
            }
            Ok(Err(error)) => return Err(Error::Io(error.kind())),
            Ok(Ok(value)) => value,
        };
        report.datagrams += 1;
        // A receive can become ready at the same time as timeout, cancellation,
        // or authority expiry. Count its consumption but do not admit a claim
        // after the corresponding boundary.
        if runtime_cx.is_cancelled() {
            report.stop = Stop::Cancelled;
            break;
        }
        if runtime_cx.now() >= deadline {
            break;
        }
        let current = match clock.now() {
            Ok(current) => current,
            Err(_) => {
                report.stop = if runtime_cx.is_cancelled() {
                    Stop::Cancelled
                } else {
                    Stop::AuthorityStopped
                };
                break;
            }
        };
        if let Err(error) = owner.checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            current,
            &BudgetVector::ZERO,
        ) {
            report.stop = match error {
                ExecutionError::Deadline { .. } => Stop::AuthorityDeadline,
                ExecutionError::Budget(_) => Stop::BudgetExhausted,
                _ => Stop::AuthorityStopped,
            };
            break;
        }
        let SocketAddr::V4(source) = source else {
            report.out_of_scope += 1;
            continue;
        };
        if !config.in_scope(*source.ip()) || source.port() != config.target.port() {
            report.out_of_scope += 1;
            continue;
        }
        let Ok(reply) = Reply::parse(&buffer[..len]) else {
            report.malformed += 1;
            continue;
        };
        if reply.kind() != DeviceKind::CameraCandidate {
            continue;
        }
        let Some(platform) = reply.platform() else {
            continue;
        };
        let candidate = CameraCandidate {
            source,
            platform: platform.to_owned(),
            firmware: reply.firmware().map(str::to_owned),
            mac: reply.mac(),
            source_advertised: reply.addresses().any(|a| a.ipv4 == source.ip().octets()),
        };
        if !report.cameras.iter().any(|old| {
            old.source == candidate.source
                && old.mac == candidate.mac
                && old.platform == candidate.platform
                && old.firmware == candidate.firmware
                && old.source_advertised == candidate.source_advertised
        }) {
            report.cameras.push(candidate);
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_broadcast_and_point_to_point_scopes_are_distinct() -> Result<(), Error> {
        let make = |prefix, ip| {
            Config::new(
                Ipv4Addr::new(192, 168, 1, 4),
                prefix,
                SocketAddrV4::new(ip, 10001),
                "fixture:network",
                Duration::from_secs(1),
                4,
            )
        };
        let broadcast = make(24, Ipv4Addr::new(192, 168, 1, 255))?;
        assert!(broadcast.in_scope(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(!broadcast.in_scope(Ipv4Addr::new(192, 168, 2, 20)));
        let point_to_point = make(31, Ipv4Addr::new(192, 168, 1, 5))?;
        assert!(!point_to_point.in_scope(Ipv4Addr::new(192, 168, 1, 4)));
        assert!(point_to_point.in_scope(Ipv4Addr::new(192, 168, 1, 5)));
        Ok(())
    }

    #[test]
    fn repeated_mac_at_different_addresses_remains_ambiguous() {
        let make = |ip, mac| CameraCandidate {
            source: SocketAddrV4::new(ip, 10001),
            platform: "UVC G4".into(),
            firmware: None,
            mac,
            source_advertised: true,
        };
        let report = Report {
            cameras: vec![
                make(Ipv4Addr::new(192, 168, 1, 4), Some([0x10, 2, 3, 4, 5, 6])),
                make(Ipv4Addr::new(192, 168, 1, 5), Some([0x10, 2, 3, 4, 5, 6])),
                make(Ipv4Addr::new(192, 168, 1, 6), Some([0x01, 2, 3, 4, 5, 6])),
            ],
            datagrams: 3,
            malformed: 0,
            out_of_scope: 0,
            stop: Stop::WindowElapsed,
        };
        assert!(
            report
                .assess_claims(0)
                .unwrap()
                .same_mac_at_multiple_addresses
        );
        assert!(
            report
                .assess_claims(1)
                .unwrap()
                .same_mac_at_multiple_addresses
        );
        assert!(report.assess_claims(2).unwrap().missing_or_invalid_mac);
    }
}
