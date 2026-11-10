#![forbid(unsafe_code)]
//! Experimental composition of camera setup, controller TLS and WebSocket upgrade.
//!
//! This module does not authenticate a physical camera, qualify the TLS provider,
//! reconcile a handoff, or start media. The caller must independently authorize
//! the peer and retain the caller-owned setup trace and effect journal.

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout_at,
};
use fss_reference::unifi_direct::{
    Controller, camera_http, controller_listener, handoff, listener,
    metered::MeteredIo,
    owner::{self, PeerAdmission},
    receive, setup,
    upgrade::ProtocolPolicy,
};
use rustls::{ServerConfig, ServerConnection};
use std::{fmt, io, sync::Arc, time::Duration};

use crate::server::Server;

const MAX_PROTOCOL_WAIT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 8;

/// Wire-metered, policy-guarded controller connection.
pub type Wire<'scope, 'task, 'policy> =
    MeteredIo<'scope, 'task, controller_listener::GuardedIo<'policy, TcpStream>>;

/// TLS plaintext guarded by the same admission gate as the encrypted wire.
pub type Plaintext<'scope, 'task, 'policy> =
    controller_listener::GuardedIo<'policy, Server<Wire<'scope, 'task, 'policy>>>;

/// An upgraded controller session; it is not proof of camera identity or adoption.
pub type Session<'scope, 'task, 'policy> =
    receive::Session<'scope, 'task, Plaintext<'scope, 'task, 'policy>>;

/// Decrypted TLS over the fleet-owned camera route.
pub type FleetPlaintext<'scope, 'task, 'policy> = controller_listener::GuardedIo<
    'policy,
    Server<controller_listener::Routed<'scope, 'task, 'policy>>,
>;

/// A fleet-routed, upgraded laboratory session, which owns its active slot.
pub type FleetSession<'scope, 'task, 'policy> =
    receive::Session<'scope, 'task, FleetPlaintext<'scope, 'task, 'policy>>;

/// Payload-free failure. A setup outcome or committed effect may remain in the trace.
#[derive(Debug)]
pub enum Error {
    /// Context or bounded protocol wait is invalid before setup begins.
    Configuration,
    /// TLS server configuration was rejected before setup begins.
    TlsConfiguration,
    /// Setup or accepting the camera connection stopped.
    Setup(setup::AcceptError),
    /// TLS or WebSocket preparation exhausted the shared protocol deadline.
    Deadline,
    /// TLS handshake failed after the accepted connection was consumed.
    Tls(io::ErrorKind),
    /// A subsequent listener accept failed without replaying the handoff.
    RetryListener(listener::Error),
    /// A retry source did not match the selected discovery claim.
    RetryPeerMismatch,
    /// The outer plaintext meter could not be admitted.
    Meter(io::ErrorKind),
    /// The HTTP/WebSocket upgrade or peer admission failed.
    Upgrade(owner::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "experimental UniFi setup and upgrade stopped: {self:?}")
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

/// Upgrade one previously routed fleet connection through laboratory TLS.
///
/// The connection owns its active slot through TLS and the returned session;
/// interruption or any failure drops it. One deadline covers handshake and
/// upgrade. The claimed MAC must match the selected inventory entry as well as
/// the caller's independent admission decision. Source and MAC claims do not
/// authenticate a physical camera; this TLS configuration is not a qualified
/// production provider or proof of the peer's identity.
#[allow(clippy::too_many_arguments)]
pub async fn upgrade_routed<'scope, 'task, 'policy, A: PeerAdmission>(
    cx: &'scope Cx,
    route: controller_listener::Routed<'scope, 'task, 'policy>,
    tls_config: Arc<ServerConfig>,
    protocol_policy: ProtocolPolicy,
    admission: &A,
    controller: Controller,
    max_poll: usize,
    wait: Duration,
) -> Result<FleetSession<'scope, 'task, 'policy>, Error>
where
    'policy: 'scope,
{
    if !route.matches_context(cx)
        || wait.is_zero()
        || wait > MAX_PROTOCOL_WAIT
        || !(1..=fss_reference::unifi_direct::metered::MAX_POLL_BYTES).contains(&max_poll)
    {
        return Err(Error::Configuration);
    }
    let connection = ServerConnection::new(tls_config).map_err(|_| Error::TlsConfiguration)?;
    let gate = route.gate();
    let clock = route.clock();
    let resource = route.resource().to_owned();
    let claimed = route.claimed_mac();
    let deadline = cx.now() + wait;
    let tls = timeout_at(deadline, Server::new(connection, route).handshake(cx))
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|error| Error::Tls(error.kind()))?;
    let plaintext = MeteredIo::with_clock(gate.wrap(tls), clock, &resource, max_poll)
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
        protocol_policy,
        &restricted,
        gate,
        controller,
        remaining,
    )
    .await
    .map_err(Error::Upgrade)
}

/// Perform one admitted setup and use its accepted socket for TLS and upgrade.
///
/// The listener, camera owner, task clock, resource and source claim are checked
/// by `setup_and_accept`. The same connection gate wraps both wire and plaintext.
/// A `Previous` controller readback may still reach this function's TLS stage;
/// it remains an unresolved effect, not evidence of a successful handoff.
/// `trace` remains caller-owned across failure or cancellation, and no automatic
/// replay or effect settlement is performed. TLS and upgrade share one bounded
/// deadline after setup and accept. The admission callback must independently
/// bind the claimed MAC to an authorized peer and be bounded and nonblocking.
#[allow(clippy::too_many_arguments)]
pub async fn setup_and_upgrade<'scope, 'task, 'policy, IO, A>(
    cx: &'scope Cx,
    setup_owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &mut controller_listener::Listener<'scope, 'task, 'policy>,
    expected_port: u16,
    camera: &mut camera_http::Owner<'_, '_, '_, IO>,
    cfg: &setup::Config<'_>,
    framing: handoff::Framing,
    max_poll: usize,
    accept_wait: Duration,
    protocol_wait: Duration,
    trace: &mut setup::AcceptTrace,
    tls_config: Arc<ServerConfig>,
    protocol_policy: ProtocolPolicy,
    admission: &A,
    controller: Controller,
) -> Result<Session<'scope, 'task, 'policy>, Error>
where
    'policy: 'scope,
    IO: AsyncRead + AsyncWrite + Unpin,
    A: PeerAdmission,
{
    setup_and_upgrade_with_retries(
        cx,
        setup_owner,
        listener,
        expected_port,
        camera,
        cfg,
        framing,
        max_poll,
        accept_wait,
        protocol_wait,
        1,
        trace,
        tls_config,
        protocol_policy,
        admission,
        controller,
    )
    .await
}

/// Like [`setup_and_upgrade`], but retry only an early TLS EOF on a fresh
/// connection from the selected discovery source. The setup effect is never
/// replayed. All retries share one protocol deadline and a bounded count.
#[allow(clippy::too_many_arguments)]
pub async fn setup_and_upgrade_with_retries<'scope, 'task, 'policy, IO, A>(
    cx: &'scope Cx,
    setup_owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &mut controller_listener::Listener<'scope, 'task, 'policy>,
    expected_port: u16,
    camera: &mut camera_http::Owner<'_, '_, '_, IO>,
    cfg: &setup::Config<'_>,
    framing: handoff::Framing,
    max_poll: usize,
    accept_wait: Duration,
    protocol_wait: Duration,
    max_connections: usize,
    trace: &mut setup::AcceptTrace,
    tls_config: Arc<ServerConfig>,
    protocol_policy: ProtocolPolicy,
    admission: &A,
    controller: Controller,
) -> Result<Session<'scope, 'task, 'policy>, Error>
where
    'policy: 'scope,
    IO: AsyncRead + AsyncWrite + Unpin,
    A: PeerAdmission,
{
    if !std::ptr::eq(cx, setup_owner.cx)
        || protocol_wait.is_zero()
        || protocol_wait > MAX_PROTOCOL_WAIT
        || !(1..=MAX_CONNECTIONS).contains(&max_connections)
    {
        return Err(Error::Configuration);
    }
    let selected = *cfg
        .report
        .cameras
        .get(cfg.index)
        .ok_or(Error::Configuration)?
        .source()
        .ip();
    // Refuse invalid TLS configuration before any camera-management effect.
    let server = ServerConnection::new(tls_config.clone()).map_err(|_| Error::TlsConfiguration)?;
    let accepted = setup_owner
        .setup_and_accept(
            listener,
            expected_port,
            camera,
            cfg,
            framing,
            max_poll,
            accept_wait,
            trace,
        )
        .await
        .map_err(Error::Setup)?;
    let deadline = cx.now() + protocol_wait;
    let (mut wire, mut gate) = (accepted.io, accepted.gate);
    let mut server = Some(server);
    let mut attempts = 0;
    let tls = loop {
        attempts += 1;
        let connection = match server.take() {
            Some(connection) => connection,
            None => {
                ServerConnection::new(tls_config.clone()).map_err(|_| Error::TlsConfiguration)?
            }
        };
        match timeout_at(deadline, Server::new(connection, wire).handshake(cx)).await {
            Err(_) => return Err(Error::Deadline),
            Ok(Ok(tls)) => break tls,
            Ok(Err(error))
                if error.kind() == io::ErrorKind::UnexpectedEof && attempts < max_connections =>
            {
                let remaining =
                    Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                if remaining.is_zero() {
                    return Err(Error::Deadline);
                }
                let (next, next_gate) = listener
                    .accept_next(max_poll, remaining)
                    .await
                    .map_err(Error::RetryListener)?;
                if *next_gate.source().ip() != selected {
                    return Err(Error::RetryPeerMismatch);
                }
                wire = next;
                gate = next_gate;
            }
            Ok(Err(error)) => return Err(Error::Tls(error.kind())),
        }
    };
    let resource = format!("camera:{}", cfg.camera.to_text());
    let plaintext = MeteredIo::with_clock(gate.wrap(tls), setup_owner.clock, &resource, max_poll)
        .map_err(|error| Error::Meter(error.kind()))?;
    let remaining = Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
    if remaining.is_zero() {
        return Err(Error::Deadline);
    }
    owner::accept_guarded(
        plaintext,
        protocol_policy,
        admission,
        gate,
        controller,
        remaining,
    )
    .await
    .map_err(Error::Upgrade)
}
