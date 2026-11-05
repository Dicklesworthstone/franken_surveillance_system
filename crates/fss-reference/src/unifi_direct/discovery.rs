#![forbid(unsafe_code)]
//! Bounded, explicitly scoped Ubiquiti v1 LAN discovery over Asupersync UDP.
//!
//! One query is sent to the supplied local destination. Replies are
//! unauthenticated candidate observations; this module does not enroll,
//! configure, log into, or take over any device. A timeout or packet limit
//! never proves that the rest of the network lacks cameras.

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
    /// the interface subnet or the limited broadcast address; no subnet sweep
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
        Ok(Self {
            bind,
            mask,
            target,
            resource: resource.to_owned(),
            window,
            max_packets,
        })
    }
    fn in_scope(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == (u32::from(self.bind) & self.mask)
            && (*self.target.ip() == Ipv4Addr::BROADCAST || ip == *self.target.ip())
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

/// Send one scoped v1 query and collect a finite set of untrusted camera claims.
///
/// The supplied `now` is the current observation in the task's canonical clock
/// domain. The caller must maintain its clock relationship to the runtime timer
/// and supervise the enclosing region and join. Socket receive cancellation can
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
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            now,
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
    let deadline = runtime_cx.now() + window;
    let mut socket = timeout_at(deadline, UdpSocket::bind(SocketAddrV4::new(config.bind, 0)))
        .await
        .map_err(|_| Error::SetupDeadline)?
        .map_err(|e| Error::Io(e.kind()))?;
    socket
        .set_broadcast(true)
        .map_err(|e| Error::Io(e.kind()))?;
    let mut send_cost = BudgetVector::ZERO;
    send_cost.network_bytes = unifi_discovery::V1_QUERY.len() as u64;
    owner
        .checkpoint_for(RuntimeGrant::AdapterNet, &config.resource, now, &send_cost)
        .map_err(|_| Error::Authority)?;
    runtime_cx.checkpoint().map_err(|_| Error::Authority)?;
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
        if let Err(error) = owner.checkpoint_for(
            RuntimeGrant::AdapterNet,
            &config.resource,
            now,
            &receive_cost,
        ) {
            report.stop = if matches!(error, ExecutionError::Budget(_)) {
                Stop::BudgetExhausted
            } else {
                Stop::AuthorityStopped
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
