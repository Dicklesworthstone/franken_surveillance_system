#![forbid(unsafe_code)]
//! Experimental, bounded router and TLS/upgrade pump; not a camera service.
//!
//! The caller must poll this owner, supervise sessions, and independently
//! authenticate and authorize peers. No task is spawned or effect retried.

use asupersync::Cx;
use fss_reference::unifi_direct::{
    Controller, Identity, TimeSyncPolicy,
    discovery::fleet::{RouteError, Router, RouterEvent},
    owner::PeerAdmission,
    upgrade::ProtocolPolicy,
};
use rustls::ServerConfig;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use crate::setup_upgrade::{self, FleetSession};

const MAX_HANDSHAKES: usize = 128;
type Handshake<'fleet, 'scope, 'task, 'policy> = Pin<
    Box<
        dyn Future<Output = Result<FleetSession<'scope, 'task, 'policy>, setup_upgrade::Error>>
            + 'fleet,
    >,
>;

/// Failure to construct the bounded pump, before any connection is accepted.
#[derive(Debug)]
pub enum ConfigurationError {
    /// A handshake bound, byte limit or deadline was outside the accepted range.
    Invalid,
    /// Reserving bounded handshake state failed.
    Allocation,
}

/// One completed upgrade or payload-free rejection. No event settles an effect.
#[must_use = "handle or retire the returned session or rejection"]
pub enum Event<'scope, 'task, 'policy> {
    /// A routed and upgraded laboratory session. The caller owns its active slot.
    Session {
        index: usize,
        session: FleetSession<'scope, 'task, 'policy>,
    },
    /// Router rejected a connection before its TLS handshake.
    RouteRefused {
        index: Option<usize>,
        reason: RouteError,
    },
    /// The bounded handshake pool was full and the routed socket was closed.
    HandshakeCapacity { index: usize },
    /// TLS, protocol upgrade, or the bounded handshake deadline failed.
    HandshakeFailed {
        index: usize,
        reason: setup_upgrade::Error,
    },
}

/// Caller-owned concurrent handshake state, with no detached background work.
///
/// Dropping `next` retains this owner's pending handshakes; dropping the owner
/// cancels them and releases the router. Deadlines make progress only while the
/// owner is polled. The result is experimental and does not authenticate a
/// physical camera, reconcile effects, start media, or provide a service.
pub struct FleetAcceptor<'fleet, 'report, 'scope, 'task, 'policy, A: PeerAdmission> {
    router: Router<'fleet, 'report, 'scope, 'task, 'policy>,
    cx: &'scope Cx,
    admission: &'fleet A,
    tls: Arc<ServerConfig>,
    identity: Identity,
    time_sync: TimeSyncPolicy,
    protocol: ProtocolPolicy,
    max_poll: usize,
    wait: Duration,
    capacity: usize,
    handshakes: Vec<(usize, Handshake<'fleet, 'scope, 'task, 'policy>)>,
}

impl<
    'fleet,
    'report: 'fleet,
    'scope: 'fleet,
    'task: 'fleet,
    'policy: 'fleet,
    A: PeerAdmission + 'fleet,
> FleetAcceptor<'fleet, 'report, 'scope, 'task, 'policy, A>
where
    'policy: 'scope,
{
    /// Create an owner with an explicit finite handshake limit and deadline.
    /// Admission must be independent, bounded and nonblocking. A MAC or source
    /// address alone is not evidence of physical peer identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        router: Router<'fleet, 'report, 'scope, 'task, 'policy>,
        cx: &'scope Cx,
        admission: &'fleet A,
        tls: Arc<ServerConfig>,
        identity: Identity,
        time_sync: TimeSyncPolicy,
        protocol: ProtocolPolicy,
        max_poll: usize,
        wait: Duration,
        capacity: usize,
    ) -> Result<Self, ConfigurationError> {
        if !(1..=MAX_HANDSHAKES).contains(&capacity)
            || !(1..=fss_reference::unifi_direct::metered::MAX_POLL_BYTES).contains(&max_poll)
            || wait.is_zero()
            || wait > Duration::from_secs(30)
        {
            return Err(ConfigurationError::Invalid);
        }
        let mut handshakes = Vec::new();
        handshakes
            .try_reserve_exact(capacity)
            .map_err(|_| ConfigurationError::Allocation)?;
        Ok(Self {
            router,
            cx,
            admission,
            tls,
            identity,
            time_sync,
            protocol,
            max_poll,
            wait,
            capacity,
            handshakes,
        })
    }

    /// Number of owned in-flight TLS or WebSocket handshakes.
    pub fn handshake_len(&self) -> usize {
        self.handshakes.len()
    }

    /// Retire in-flight handshakes and return the router to the caller.
    pub fn into_router(self) -> Router<'fleet, 'report, 'scope, 'task, 'policy> {
        self.router
    }

    /// Drive all current handshakes and the router until one event is ready.
    pub async fn next(&mut self) -> Event<'scope, 'task, 'policy> {
        poll_fn(|context| self.poll_next(context)).await
    }

    /// Poll all in-flight handshakes before accepting one more routed connection.
    pub fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Event<'scope, 'task, 'policy>> {
        for i in 0..self.handshakes.len() {
            if let Poll::Ready(result) = self.handshakes[i].1.as_mut().poll(context) {
                let (index, finished) = self.handshakes.swap_remove(i);
                drop(finished);
                return Poll::Ready(match result {
                    Ok(session) => Event::Session { index, session },
                    Err(reason) => Event::HandshakeFailed { index, reason },
                });
            }
        }
        match self.router.poll_next(context) {
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
                // The fixed initial ID is within the controller's documented range.
                let controller =
                    Controller::new_with_time_sync_policy(self.identity.clone(), 1, self.time_sync)
                        .expect("fixed first controller message ID is valid");
                let (cx, admission, tls, protocol, max_poll, wait) = (
                    self.cx,
                    self.admission,
                    self.tls.clone(),
                    self.protocol,
                    self.max_poll,
                    self.wait,
                );
                self.handshakes.push((
                    index,
                    Box::pin(async move {
                        setup_upgrade::upgrade_routed(
                            cx, route, tls, protocol, admission, controller, max_poll, wait,
                        )
                        .await
                    }),
                ));
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
