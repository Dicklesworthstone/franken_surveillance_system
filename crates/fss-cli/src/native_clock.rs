#![forbid(unsafe_code)]
//! One explicitly owned local-daemon exchange and bounded host-clock monitoring.
//!
//! The owner supplies its existing monotonic coordinate, authority checks,
//! network accounting and bounded wait. No daemon discovery, DNS, retries,
//! clock adjustment, detached work or fresh monotonic origin is introduced.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use fss_packet::ntp::SntpRequest;
use fss_reference::site::clock::{ClockCorrelation, HostClockSample};
use fss_reference::site::clock_proof::{
    LOCAL_NTP_CLOCK_POLICY, LOCAL_NTP_LIMITS, LocalNtpExchange,
};

/// Maximum receive attempts, including nonblocking polls without a datagram.
pub const MAX_RECEIVE_POLLS: u64 = 1024;
/// Maximum admitted UDP payload bytes: one request and an oversized-reply guard.
pub const MAX_NETWORK_BYTES: u64 = 48 + 49;

/// A socket operation failed or the single request was not sent in full.
pub const ERR_NATIVE_CLOCK_NETWORK: &str = "ERR-NATIVE-CLOCK-NETWORK-001";
/// A host sample could not be represented inside the fixed bracket bound.
pub const ERR_NATIVE_CLOCK_SAMPLE: &str = "ERR-NATIVE-CLOCK-SAMPLE-001";
/// The supplied endpoint or exact NTP evidence failed the native profile.
pub const ERR_NATIVE_CLOCK_PROOF: &str = "ERR-NATIVE-CLOCK-PROOF-001";
/// The owner deadline, exchange deadline or receive-poll bound was exhausted.
pub const ERR_NATIVE_CLOCK_DEADLINE: &str = "ERR-NATIVE-CLOCK-DEADLINE-001";
/// A response was not exactly one basic-mode 48-byte datagram.
pub const ERR_NATIVE_CLOCK_REPLY: &str = "ERR-NATIVE-CLOCK-REPLY-001";
/// Sampled host-clock progression or the synchronization lifetime was refused.
pub const ERR_NATIVE_CLOCK_CONTINUITY: &str = "ERR-NATIVE-CLOCK-CONTINUITY-001";
/// The owner already finalized its terminal sample.
pub const ERR_NATIVE_CLOCK_CLOSED: &str = "ERR-NATIVE-CLOCK-CLOSED-001";

/// Existing native ownership at every clock, socket and wait boundary.
///
/// Implementations must use one stable monotonic epoch for this exchange and all
/// source coordinates that will be projected through it. Each callback checks
/// the current task's authority, cancellation and finite budget. `wait` must be
/// bounded by the supplied absolute deadline; the sampler checks it again on
/// return. This interface does not itself grant access to the selected peer.
pub trait ClockIo {
    /// Admit and read the owner's current monotonic coordinate.
    fn now(&self) -> Result<u64, &'static str>;
    /// Revalidate the owner's explicit capability for the selected NTP endpoint.
    fn network_admit(&self) -> Result<(), &'static str>;
    /// Record the exact number of admitted UDP payload bytes before revalidating
    /// authority or budget. A refused post-I/O check must retain the consumed
    /// count: these bytes have already crossed the socket boundary.
    fn network_bytes(&self, bytes: u64) -> Result<(), &'static str>;
    /// Perform one owned bounded wait following a nonblocking receive poll.
    fn wait(&self, deadline_ns: u64) -> Result<(), &'static str>;
}

#[derive(Clone, Copy)]
enum State {
    Active,
    Finished,
    Poisoned(&'static str),
}

/// One checked exchange and its same-session sampled host-clock progression.
///
/// The UDP socket closes before construction returns. A sample failure poisons
/// this owner permanently, including failures of authority or clock access.
/// Finishing also prevents further I/O. Retained exchange bytes remain readable
/// for diagnostics but never certify a source, camera exposure, server identity
/// or uninterrupted host-clock continuity.
pub struct SynchronizedClock {
    exchange: LocalNtpExchange,
    correlation: ClockCorrelation,
    deadline_ns: u64,
    state: State,
}

impl fmt::Debug for SynchronizedClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SynchronizedClock")
            .field("active", &matches!(self.state, State::Active))
            .finish_non_exhaustive()
    }
}

impl SynchronizedClock {
    /// Send exactly one basic-mode request to the explicitly authorized loopback
    /// endpoint and receive at most one datagram. Every socket operation and wall
    /// read is bracketed by owner checks. The absolute caller deadline can only
    /// shorten the one-second exchange cap; it is never extended by polling.
    pub fn begin(
        peer: SocketAddr,
        deadline_ns: u64,
        io: &dyn ClockIo,
    ) -> Result<Self, &'static str> {
        if !peer.ip().is_loopback()
            || peer.port() == 0
            || matches!(peer, SocketAddr::V6(peer) if peer.scope_id() != 0 || peer.flowinfo() != 0)
        {
            return Err(ERR_NATIVE_CLOCK_PROOF);
        }
        let bind = SocketAddr::new(
            match peer.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            0,
        );
        let socket = network(io, deadline_ns, || UdpSocket::bind(bind))?
            .map_err(|_| ERR_NATIVE_CLOCK_NETWORK)?;
        network(io, deadline_ns, || socket.connect(peer))?.map_err(|_| ERR_NATIVE_CLOCK_NETWORK)?;
        network(io, deadline_ns, || socket.set_nonblocking(true))?
            .map_err(|_| ERR_NATIVE_CLOCK_NETWORK)?;
        let sent_before = host_sample(io, deadline_ns)?;
        let request =
            SntpRequest::new(sent_before.wall_clock_unix_ns).map_err(|_| ERR_NATIVE_CLOCK_PROOF)?;
        let exchange_deadline = sent_before
            .monotonic_before_ns
            .checked_add(LOCAL_NTP_LIMITS.max_exchange_ns)
            .ok_or(ERR_NATIVE_CLOCK_DEADLINE)?
            .min(deadline_ns);
        let sent = counted_network(io, exchange_deadline, || socket.send(request.wire_bytes()))?
            .map_err(|_| ERR_NATIVE_CLOCK_NETWORK)?;
        let sent_after = host_sample(io, exchange_deadline)?;
        if sent != request.wire_bytes().len() {
            return Err(ERR_NATIVE_CLOCK_NETWORK);
        }
        // A 49-byte buffer distinguishes every extended or truncated oversized
        // datagram from the only supported exact 48-byte reply.
        let mut received = [0_u8; 49];
        for _ in 0..MAX_RECEIVE_POLLS {
            let received_before = host_sample(io, exchange_deadline)?;
            let result = counted_network(io, exchange_deadline, || socket.recv(&mut received))?;
            let received_after = host_sample(io, exchange_deadline)?;
            match result {
                Ok(length) => {
                    let reply: [u8; 48] = received
                        .get(..length)
                        .ok_or(ERR_NATIVE_CLOCK_REPLY)?
                        .try_into()
                        .map_err(|_| ERR_NATIVE_CLOCK_REPLY)?;
                    let exchange = LocalNtpExchange {
                        peer,
                        request: *request.wire_bytes(),
                        reply,
                        sent_before,
                        sent_after,
                        received_before,
                        received_after,
                        policy: LOCAL_NTP_CLOCK_POLICY,
                    };
                    let correlation = exchange.correlation().map_err(|_| ERR_NATIVE_CLOCK_PROOF)?;
                    return Ok(Self {
                        exchange,
                        correlation,
                        deadline_ns,
                        state: State::Active,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    checked_now(io, exchange_deadline)?;
                    io.wait(exchange_deadline)?;
                    checked_now(io, exchange_deadline)?;
                }
                Err(_) => return Err(ERR_NATIVE_CLOCK_NETWORK),
            }
        }
        Err(ERR_NATIVE_CLOCK_DEADLINE)
    }

    /// Exact exchange from this owner; later sample success is a separate claim.
    #[must_use]
    pub const fn exchange(&self) -> LocalNtpExchange {
        self.exchange
    }

    /// Check one later host sample against both the original synchronization and
    /// previous sample. Any failure permanently prevents subsequent work.
    pub fn sample(&mut self, io: &dyn ClockIo) -> Result<HostClockSample, &'static str> {
        match self.state {
            State::Finished => return Err(ERR_NATIVE_CLOCK_CLOSED),
            State::Poisoned(error) => return Err(error),
            State::Active => {}
        }
        let result = host_sample(io, self.deadline_ns).and_then(|sample| {
            self.correlation
                .observe_later_sample(sample)
                .map_err(|_| ERR_NATIVE_CLOCK_CONTINUITY)?;
            Ok(sample)
        });
        if let Err(error) = result {
            self.state = State::Poisoned(error);
        }
        result
    }

    /// Take the final checked sample and permanently close this owner to I/O.
    pub fn finish(&mut self, io: &dyn ClockIo) -> Result<HostClockSample, &'static str> {
        let terminal = self.sample(io)?;
        self.state = State::Finished;
        Ok(terminal)
    }
}

fn checked_now(io: &dyn ClockIo, deadline_ns: u64) -> Result<u64, &'static str> {
    let now = io.now()?;
    if now >= deadline_ns {
        return Err(ERR_NATIVE_CLOCK_DEADLINE);
    }
    Ok(now)
}

fn host_sample(io: &dyn ClockIo, deadline_ns: u64) -> Result<HostClockSample, &'static str> {
    let monotonic_before_ns = checked_now(io, deadline_ns)?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH);
    // Validate the owner after the wall read even when the wall value is invalid.
    let monotonic_after_ns = checked_now(io, deadline_ns)?;
    let span = monotonic_after_ns
        .checked_sub(monotonic_before_ns)
        .ok_or(ERR_NATIVE_CLOCK_CONTINUITY)?;
    if span > LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns {
        return Err(ERR_NATIVE_CLOCK_SAMPLE);
    }
    let wall_clock_unix_ns = u64::try_from(wall.map_err(|_| ERR_NATIVE_CLOCK_SAMPLE)?.as_nanos())
        .map_err(|_| ERR_NATIVE_CLOCK_SAMPLE)?;
    Ok(HostClockSample {
        monotonic_before_ns,
        wall_clock_unix_ns,
        monotonic_after_ns,
    })
}

fn network<T>(
    io: &dyn ClockIo,
    deadline_ns: u64,
    operation: impl FnOnce() -> io::Result<T>,
) -> Result<io::Result<T>, &'static str> {
    io.network_admit()?;
    checked_now(io, deadline_ns)?;
    let result = operation();
    io.network_admit()?;
    checked_now(io, deadline_ns)?;
    Ok(result)
}

fn counted_network(
    io: &dyn ClockIo,
    deadline_ns: u64,
    operation: impl FnOnce() -> io::Result<usize>,
) -> Result<io::Result<usize>, &'static str> {
    io.network_admit()?;
    checked_now(io, deadline_ns)?;
    let result = operation();
    // Successful I/O has already consumed payload bytes. Record them before any
    // post-boundary refusal can hide the consumption, and run both post checks
    // even when accounting or the operation itself reports an error. These are
    // final accounting/checks, never admission for another socket operation.
    let accounting = match &result {
        Ok(length) => io.network_bytes(*length as u64),
        Err(_) => Ok(()),
    };
    let authority = io.network_admit();
    let time = checked_now(io, deadline_ns);
    accounting?;
    authority?;
    time?;
    Ok(result)
}
