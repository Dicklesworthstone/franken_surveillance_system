#![forbid(unsafe_code)]
//! Caller-driven, bounded concurrent upgrades for an existing UniFi fleet.
//!
//! The supplied protected transport is a trust boundary; this module does not
//! implement or qualify TLS, authenticate a physical camera, or issue effects.

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};

use super::{
    Controller, Identity, TimeSyncPolicy,
    controller_listener::{GuardedIo, Routed},
    controller_upgrade,
    discovery::{
        fleet::{RouteError, Router, RouterEvent},
        pump, scan,
    },
    metered::MAX_POLL_BYTES,
    owner::PeerAdmission,
    receive,
    upgrade::ProtocolPolicy,
};

const MAX_HANDSHAKES: usize = 128;

/// An explicitly selected protected transport implementation.
///
/// Implementors must retain the exact supplied route inside the returned
/// stream and drop it when a handshake is interrupted. This contract is not
/// enforced by the type system; the caller must qualify and trust the provider.
/// Neither a successful handshake nor a MAC claim proves physical identity.
pub trait Transport<'scope, 'task, 'policy>: Clone {
    /// Protected I/O that owns the routed connection after a handshake.
    type Stream: AsyncRead + AsyncWrite + Unpin + 'scope;
    /// An owned, cancellation-droppable handshake.
    type Handshake: Future<Output = io::Result<Self::Stream>> + 'scope;
    /// Start no detached work; the returned future owns the supplied route.
    fn handshake(&self, cx: &'scope Cx, route: Routed<'scope, 'task, 'policy>) -> Self::Handshake;
}

/// Session owning a routed and caller-protected controller connection.
pub type Session<'scope, 'task, 'policy, IO> =
    receive::Session<'scope, 'task, GuardedIo<'policy, IO>>;

type Handshake<'fleet, 'scope, 'task, 'policy, IO> = Pin<
    Box<
        dyn Future<Output = Result<Session<'scope, 'task, 'policy, IO>, controller_upgrade::Error>>
            + 'fleet,
    >,
>;

/// Refusal before any route or transport was accepted.
#[derive(Debug)]
pub enum ConfigurationError {
    /// Capacity, byte limit or deadline is outside its bound.
    Invalid,
    /// Bounded handshake storage could not be reserved.
    Allocation,
}

/// Refused configuration with the original owned inputs available to recover.
#[must_use = "recover or explicitly retire the returned router and transport"]
pub struct ConfigurationRefusal<'fleet, 'report, 'scope, 'task, 'policy, P> {
    /// Payload-free reason the acceptor was not created.
    pub reason: ConfigurationError,
    /// Original router, including any routes or accept in flight.
    pub router: Router<'fleet, 'report, 'scope, 'task, 'policy>,
    /// Original caller-selected protected transport.
    pub transport: P,
    /// Original controller identity.
    pub identity: Identity,
}

impl<P> fmt::Debug for ConfigurationRefusal<'_, '_, '_, '_, '_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationRefusal")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// One completed upgrade or payload-free refusal.
#[must_use = "handle or retire the returned session or refusal"]
pub enum Event<'scope, 'task, 'policy, IO> {
    /// An upgraded session that owns its route's active slot.
    Session {
        /// Index of the caller-enrolled camera entry.
        index: usize,
        /// Caller-owned upgraded connection.
        session: Session<'scope, 'task, 'policy, IO>,
    },
    /// A route was refused before transport admission.
    RouteRefused {
        /// Enrollment index when routing identified one.
        index: Option<usize>,
        /// Payload-free routing refusal.
        reason: RouteError,
    },
    /// The handshake capacity was full and this route was closed.
    HandshakeCapacity {
        /// Enrollment index associated with the closed route.
        index: usize,
    },
    /// The transport or WebSocket upgrade failed.
    HandshakeFailed {
        /// Enrollment index associated with the attempted route.
        index: usize,
        /// Payload-free transport or upgrade failure.
        reason: controller_upgrade::Error,
    },
}

/// Owns pending handshakes and a router without spawning detached tasks.
/// Dropping `next` preserves in-flight work. Dropping the owner drops those
/// handshakes and closes their routes; callers must supervise returned sessions.
pub struct Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, P>
where
    A: PeerAdmission,
    P: Transport<'scope, 'task, 'policy>,
{
    router: Router<'fleet, 'report, 'scope, 'task, 'policy>,
    cx: &'scope Cx,
    admission: &'fleet A,
    transport: P,
    identity: Identity,
    time_sync: TimeSyncPolicy,
    protocol: ProtocolPolicy,
    max_poll: usize,
    wait: Duration,
    capacity: usize,
    handshakes: Vec<(usize, Handshake<'fleet, 'scope, 'task, 'policy, P::Stream>)>,
}

impl<'fleet, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, 'policy: 'fleet, A, P>
    Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, P>
where
    'policy: 'scope,
    A: PeerAdmission + 'fleet,
    P: Transport<'scope, 'task, 'policy> + 'fleet,
{
    /// Bind an existing router and caller-qualified transport with finite limits.
    /// Peer admission must be independent, bounded and nonblocking; a network
    /// source address or claimed MAC is not authenticated physical identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        router: Router<'fleet, 'report, 'scope, 'task, 'policy>,
        cx: &'scope Cx,
        admission: &'fleet A,
        transport: P,
        identity: Identity,
        time_sync: TimeSyncPolicy,
        protocol: ProtocolPolicy,
        max_poll: usize,
        wait: Duration,
        capacity: usize,
    ) -> Result<Self, ConfigurationRefusal<'fleet, 'report, 'scope, 'task, 'policy, P>> {
        if !(1..=MAX_HANDSHAKES).contains(&capacity)
            || !(1..=MAX_POLL_BYTES).contains(&max_poll)
            || wait.is_zero()
            || wait > Duration::from_secs(30)
        {
            return Err(ConfigurationRefusal {
                reason: ConfigurationError::Invalid,
                router,
                transport,
                identity,
            });
        }
        let mut handshakes = Vec::new();
        if handshakes.try_reserve_exact(capacity).is_err() {
            return Err(ConfigurationRefusal {
                reason: ConfigurationError::Allocation,
                router,
                transport,
                identity,
            });
        }
        Ok(Self {
            router,
            cx,
            admission,
            transport,
            identity,
            time_sync,
            protocol,
            max_poll,
            wait,
            capacity,
            handshakes,
        })
    }

    /// Number of currently owned transport or upgrade handshakes.
    pub fn handshake_len(&self) -> usize {
        self.handshakes.len()
    }

    /// Drop unfinished handshakes and return their router to the caller.
    pub fn into_router(self) -> Router<'fleet, 'report, 'scope, 'task, 'policy> {
        self.router
    }

    /// Check that this acceptor and scanner use the same fleet and context.
    pub fn matches_scanner(&self, scanner: &scan::Scanner<'_, '_, 'scope, 'task>) -> bool {
        self.router.matches_scanner(scanner) && scanner.matches_context(self.cx)
    }

    /// Drive the owned handshakes and router until one event is available.
    pub async fn next(&mut self) -> Event<'scope, 'task, 'policy, P::Stream> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Poll every pending handshake before accepting another routed socket.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Event<'scope, 'task, 'policy, P::Stream>> {
        for i in 0..self.handshakes.len() {
            if let Poll::Ready(result) = self.handshakes[i].1.as_mut().poll(cx) {
                let (index, finished) = self.handshakes.swap_remove(i);
                drop(finished);
                return Poll::Ready(match result {
                    Ok(session) => Event::Session { index, session },
                    Err(reason) => Event::HandshakeFailed { index, reason },
                });
            }
        }
        match self.router.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(RouterEvent::Refused { index, reason }) => {
                Poll::Ready(Event::RouteRefused { index, reason })
            }
            Poll::Ready(RouterEvent::Ready(route)) => {
                let index = route.enrollment_index();
                if self.handshakes.len() == self.capacity {
                    drop(route);
                    return Poll::Ready(Event::HandshakeCapacity { index });
                }
                let controller =
                    Controller::new_with_time_sync_policy(self.identity.clone(), 1, self.time_sync)
                        .expect("fixed first controller message ID is valid");
                let (owner_cx, admission, transport, protocol, max_poll, wait) = (
                    self.cx,
                    self.admission,
                    self.transport.clone(),
                    self.protocol,
                    self.max_poll,
                    self.wait,
                );
                self.handshakes.push((
                    index,
                    Box::pin(async move {
                        controller_upgrade::upgrade_routed(
                            owner_cx,
                            route,
                            |route| transport.handshake(owner_cx, route),
                            protocol,
                            admission,
                            controller,
                            max_poll,
                            wait,
                        )
                        .await
                    }),
                ));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl<'fleet, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, 'policy: 'fleet + 'scope, A, P>
    pump::Driver<'scope, 'task> for Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, P>
where
    A: PeerAdmission + 'fleet,
    P: Transport<'scope, 'task, 'policy> + 'fleet,
{
    type Event = Event<'scope, 'task, 'policy, P::Stream>;
    fn matches_scanner(&self, scanner: &scan::Scanner<'_, '_, 'scope, 'task>) -> bool {
        Acceptor::matches_scanner(self, scanner)
    }
    fn poll_driver(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event> {
        self.poll_next(cx)
    }
}
