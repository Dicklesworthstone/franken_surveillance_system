#![forbid(unsafe_code)]
//! Caller-provided protected transport and WebSocket upgrade for a fleet route.
//!
//! The transport provider is an explicit trust boundary. This module does not
//! implement TLS, approve a crypto provider, or authenticate a physical camera.
//! The supplied handshake must retain the original routed I/O in the returned
//! stream and must drop it if the handshake is interrupted. A route, source
//! address or MAC claim alone does not establish camera identity.

use std::{fmt, future::Future, io, time::Duration};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
    time::timeout_at,
};

use super::{
    Controller,
    controller_listener::{GuardedIo, Routed},
    metered::{MAX_POLL_BYTES, MeteredIo},
    owner::{self, PeerAdmission},
    receive,
    upgrade::ProtocolPolicy,
};

/// A payload-free upgrade failure. No result establishes a camera identity.
#[derive(Debug)]
pub enum Error {
    /// Context, byte bound or wait is invalid before the transport starts.
    Configuration,
    /// The shared handshake and upgrade deadline elapsed.
    Deadline,
    /// The caller-selected protected transport failed.
    Transport(io::ErrorKind),
    /// The plaintext meter could not be admitted.
    Meter(io::ErrorKind),
    /// The WebSocket upgrade or peer admission failed.
    Upgrade(owner::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi routed upgrade stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

struct RouteAdmission<'a, A> {
    mac: [u8; 6],
    independent: &'a A,
}
impl<A: PeerAdmission> PeerAdmission for RouteAdmission<'_, A> {
    fn permits(&self, claimed_mac: [u8; 6]) -> bool {
        claimed_mac == self.mac && self.independent.permits(claimed_mac)
    }
}

/// Upgrade one routed connection through a caller-qualified transport.
///
/// The `handshake` closure must return a protected stream that still owns the
/// exact supplied route. The type system does not prove this obligation or
/// qualify the transport provider; a caller must not use an untrusted factory.
/// One deadline covers both the handshake and the WebSocket upgrade. Dropping
/// an interrupted handshake must drop its route; it is never retried here.
/// Both encrypted I/O and plaintext use the route's existing admission gate
/// and task clock, and the claimed WebSocket MAC must match the selected route
/// as well as the caller's independent peer policy.
/// An already-cancelled context or revoked route is refused before invoking
/// the handshake factory.
#[allow(clippy::too_many_arguments)]
pub async fn upgrade_routed<'scope, 'task, 'policy, A, F, H, IO>(
    cx: &'scope Cx,
    route: Routed<'scope, 'task, 'policy>,
    handshake: F,
    protocol: ProtocolPolicy,
    admission: &A,
    controller: Controller,
    max_poll: usize,
    wait: Duration,
) -> Result<receive::Session<'scope, 'task, GuardedIo<'policy, IO>>, Error>
where
    'policy: 'scope,
    A: PeerAdmission,
    F: FnOnce(Routed<'scope, 'task, 'policy>) -> H,
    H: Future<Output = io::Result<IO>>,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if !route.matches_context(cx)
        || wait.is_zero()
        || wait > Duration::from_secs(30)
        || !(1..=MAX_POLL_BYTES).contains(&max_poll)
    {
        return Err(Error::Configuration);
    }
    let gate = route.gate();
    cx.checkpoint()
        .map_err(|_| Error::Transport(io::ErrorKind::Interrupted))?;
    gate.check()
        .map_err(|error| Error::Transport(error.kind()))?;
    let clock = route.clock();
    let resource = route.resource().to_owned();
    let claimed = route.claimed_mac();
    let deadline = cx.now() + wait;
    let protected = timeout_at(deadline, handshake(route))
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|error| Error::Transport(error.kind()))?;
    let plaintext = MeteredIo::with_clock(gate.wrap(protected), clock, &resource, max_poll)
        .map_err(|error| Error::Meter(error.kind()))?;
    let remaining = Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
    if remaining.is_zero() {
        return Err(Error::Deadline);
    }
    let restricted = RouteAdmission {
        mac: claimed,
        independent: admission,
    };
    owner::accept_guarded(
        plaintext,
        protocol,
        &restricted,
        gate,
        controller,
        remaining,
    )
    .await
    .map_err(Error::Upgrade)
}
