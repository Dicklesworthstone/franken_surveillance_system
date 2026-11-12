#![forbid(unsafe_code)]
//! Experimental setup-to-controller composition with caller-owned TLS leases.
//!
//! This does not authenticate physical camera identity, admit the TLS provider
//! for production, or reconcile a camera-management effect.

use crate::owned::{self, offload::Lease};
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

/// Task-metered, peer-guarded TCP input.
pub type Wire<'scope, 'task, 'policy> =
    MeteredIo<'scope, 'task, controller_listener::GuardedIo<'policy, TcpStream>>;
/// The task-scoped TLS stream guarded by the same peer admission.
pub type Plaintext<'scope, 'task, 'policy> = controller_listener::GuardedIo<
    'policy,
    owned::Session<'scope, 'task, Wire<'scope, 'task, 'policy>>,
>;
/// A caller-owned controller session, not proof of device identity or adoption.
pub type Session<'scope, 'task, 'policy> =
    receive::Session<'scope, 'task, Plaintext<'scope, 'task, 'policy>>;

/// Payload-free refusal. The caller retains the setup trace and effect journal.
#[derive(Debug)]
pub enum Error {
    /// Invalid configuration or a mismatched entropy lease, before setup.
    Configuration,
    /// Setup or the first accepted connection failed.
    Setup(setup::AcceptError),
    /// The shared controller handshake and upgrade deadline expired.
    Deadline,
    /// TLS handshake failed; its connection and consumed lease were retired.
    Tls(io::ErrorKind),
    /// A later connection could not be accepted.
    RetryListener(listener::Error),
    /// A retry did not originate from the selected source claim.
    RetryPeerMismatch,
    /// The plaintext meter could not be admitted.
    Meter(io::ErrorKind),
    /// The HTTP/WebSocket upgrade or peer policy refused the connection.
    Upgrade(owner::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scoped setup and controller upgrade stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Set up once and upgrade the accepted controller socket through task-scoped
/// TLS. Only an early TLS EOF may accept a fresh socket; setup is never replayed.
/// Each attempt consumes one caller-supplied, already-drained entropy lease.
/// On failure or cancellation, the caller retains unused leases and `trace`;
/// an observed handoff is not automatically reconciled. The source and MAC are
/// claims, so independent peer identity and effect authority remain required.
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
    leases: &mut [Option<Lease<'scope, 'task>>],
    protocol_policy: ProtocolPolicy,
    admission: &A,
    controller: Controller,
) -> Result<Session<'scope, 'task, 'policy>, Error>
where
    'policy: 'scope,
    IO: AsyncRead + AsyncWrite + Unpin,
    A: PeerAdmission,
{
    let resource = format!("camera:{}", cfg.camera.to_text());
    if !std::ptr::eq(cx, setup_owner.cx)
        || protocol_wait.is_zero()
        || protocol_wait > Duration::from_secs(30)
        || accept_wait.is_zero()
        || accept_wait > Duration::from_secs(30)
        || !(1..=fss_reference::unifi_direct::metered::MAX_POLL_BYTES).contains(&max_poll)
        || !(1..=8).contains(&leases.len())
        || tls_config.send_tls13_tickets != 0
        || tls_config.scoped_random.is_some()
        || tls_config.scoped_kx.is_some()
        || leases.iter().any(|lease| {
            lease.as_ref().is_none_or(|lease| {
                !lease.matches(setup_owner.task, cx, &setup_owner.clock, &resource)
            })
        })
        || ServerConnection::new(tls_config.clone()).is_err()
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
    let mut attempt = 0;
    let tls = loop {
        let lease = leases[attempt].take().ok_or(Error::Configuration)?;
        attempt += 1;
        match timeout_at(
            deadline,
            owned::Session::accept_with_lease((*tls_config).clone(), wire, lease),
        )
        .await
        {
            Err(_) => return Err(Error::Deadline),
            Ok(Ok(tls)) => break tls,
            Ok(Err(error))
                if error.kind() == io::ErrorKind::UnexpectedEof && attempt < leases.len() =>
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
