#![forbid(unsafe_code)]
//! Experimental, task-bound setup using a one-use entropy lease.
//!
//! Certificate digest equality binds supplied DER to the caller's enrollment;
//! neither that enrollment nor the discovery source proves physical identity.
//! The caller retains credentials, the setup trace, and effect reconciliation.

use crate::{
    camera_tls_owned,
    owned::offload::{Acquisition, Lease},
};
use asupersync::{time::sleep_until, types::Time};
use fss_core::{ContentDigest, OperationId};
use fss_reference::unifi_direct::{
    camera_http, controller_listener,
    discovery::fleet::{self, Fleet, State},
    handoff,
    metered::MeteredIo,
    setup,
};
use rustls::crypto::CryptoProvider;
use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Payload-free setup failure. A caller-owned trace and journal remain authoritative.
#[derive(Debug)]
pub enum Error {
    /// Retry bounds, timer, acquisition set, or trace state was invalid.
    RetryConfiguration,
    /// Enrollment, certificate, resource, source, lease, or listener did not match.
    Binding,
    /// The task was cancelled before connection.
    Interrupted,
    /// Caller-supplied camera admission or login authority refused the attempt.
    Authority,
    /// The retained, drained entropy acquisition could not produce a lease.
    Entropy(io::ErrorKind),
    /// Task-bound pinned camera transport failed.
    Transport(camera_tls_owned::Error),
    /// The task-metered stream could not be wrapped.
    Meter(io::ErrorKind),
    /// The camera HTTP owner could not be constructed.
    Http(camera_http::Error),
    /// The tracked fleet setup failed; reconcile its caller-owned trace.
    Setup(fleet::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "experimental enrolled-camera setup stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Bounded preflight retries; never covers camera-management effects.
#[derive(Clone, Copy, Debug)]
pub struct PreflightRetryPolicy {
    attempts: usize,
    delay: Duration,
}
impl PreflightRetryPolicy {
    /// Admit one to four attempts with a fixed 10 ms to 30 s delay.
    pub fn new(attempts: usize, delay: Duration) -> Result<Self, Error> {
        if !(1..=4).contains(&attempts)
            || !(Duration::from_millis(10)..=Duration::from_secs(30)).contains(&delay)
        {
            return Err(Error::RetryConfiguration);
        }
        Ok(Self { attempts, delay })
    }
}

/// Caller-owned progress that survives a dropped borrowing wait.
#[derive(Default)]
pub struct PreflightRetryTrace {
    attempts: AtomicUsize,
    retries: AtomicUsize,
}
impl PreflightRetryTrace {
    /// Number of attempts entered; does not report an effect outcome.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Acquire)
    }
    /// Number of bounded retry waits entered.
    pub fn retries(&self) -> usize {
        self.retries.load(Ordering::Acquire)
    }
}

fn retryable_preflight(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport(camera_tls_owned::Error::Deadline)
            | Error::Transport(camera_tls_owned::Error::Transport(
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
            ))
    )
}

/// Drive an already-started acquisition and then run setup. The caller retains
/// the acquisition and trace across a dropped future. On interruption it must
/// abort and join an acquisition that is not yet drained before dropping its
/// owner. The caller must bound acquisition time separately from `wait`, which
/// limits network operations. This function does not start or detach a worker
/// and does not authenticate enrollment provenance.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_acquisition<'scope, 'task>(
    fleet: &Fleet<'_>,
    index: usize,
    owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &controller_listener::Listener<'_, '_, '_>,
    http_authority: &dyn camera_http::Authority,
    peer: SocketAddrV4,
    certificate_der: &[u8],
    credential_handle: ContentDigest,
    credential: &[u8],
    resource: &'scope str,
    acquisition: &mut Acquisition<'scope, 'task>,
    provider: Arc<CryptoProvider>,
    fence: u64,
    destination: Ipv4Addr,
    operation: &OperationId,
    framing: handoff::Framing,
    wait: Duration,
    trace: &mut setup::Trace,
) -> Result<setup::Outcome, Error> {
    owner.cx.checkpoint().map_err(|_| Error::Interrupted)?;
    if !acquisition.matches(owner.task, owner.cx, &owner.clock, resource) {
        return Err(Error::Binding);
    }
    let lease = acquisition
        .join()
        .await
        .map_err(|error| Error::Entropy(error.kind()))?;
    run(
        fleet,
        index,
        owner,
        listener,
        http_authority,
        peer,
        certificate_der,
        credential_handle,
        credential,
        resource,
        lease,
        provider,
        fence,
        destination,
        operation,
        framing,
        wait,
        trace,
    )
    .await
}

/// Retry only transient TCP/TLS connection failures before any HTTP request
/// or fleet setup attempt. Every attempt consumes a separate caller-owned
/// acquisition; the caller must abort and join unused or interrupted owners.
/// The operation ID is reused only because these failures occur before the
/// fleet reserves it. A setup error, pin or signature failure, cancellation,
/// authorization refusal, or prepared effect is never retried here. Dropping
/// this borrowing wait leaves acquisitions and both traces caller-owned.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_preflight_retries<'scope, 'task>(
    fleet: &Fleet<'_>,
    index: usize,
    owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &controller_listener::Listener<'_, '_, '_>,
    http_authority: &dyn camera_http::Authority,
    peer: SocketAddrV4,
    certificate_der: &[u8],
    credential_handle: ContentDigest,
    credential: &[u8],
    resource: &'scope str,
    acquisitions: &mut [Acquisition<'scope, 'task>],
    provider: Arc<CryptoProvider>,
    fence: u64,
    destination: Ipv4Addr,
    operation: &OperationId,
    framing: handoff::Framing,
    wait: Duration,
    setup_trace: &mut setup::Trace,
    retry_trace: &PreflightRetryTrace,
    policy: PreflightRetryPolicy,
) -> Result<setup::Outcome, Error> {
    if acquisitions.len() != policy.attempts
        || !owner.cx.has_timer()
        || retry_trace.retries() != 0
        || setup_trace.operation().is_some()
        || acquisitions
            .iter()
            .any(|a| !a.matches(owner.task, owner.cx, &owner.clock, resource))
    {
        return Err(Error::RetryConfiguration);
    }
    if retry_trace
        .attempts
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::RetryConfiguration);
    }
    for (index_in_set, acquisition) in acquisitions.iter_mut().enumerate() {
        if index_in_set != 0 {
            retry_trace
                .attempts
                .store(index_in_set + 1, Ordering::Release);
        }
        let result = run_with_acquisition(
            fleet,
            index,
            owner,
            listener,
            http_authority,
            peer,
            certificate_der,
            credential_handle,
            credential,
            resource,
            acquisition,
            provider.clone(),
            fence,
            destination,
            operation,
            framing,
            wait,
            setup_trace,
        )
        .await;
        let retryable = matches!(&result, Err(error) if retryable_preflight(error));
        if !retryable
            || index_in_set + 1 == policy.attempts
            || setup_trace.operation().is_some()
            || !matches!(fleet.state(index), Some(State::Ready { .. }))
        {
            return result;
        }
        retry_trace.retries.fetch_add(1, Ordering::AcqRel);
        let delay =
            u64::try_from(policy.delay.as_nanos()).map_err(|_| Error::RetryConfiguration)?;
        let due = owner
            .cx
            .now()
            .as_nanos()
            .checked_add(delay)
            .ok_or(Error::RetryConfiguration)?;
        loop {
            crate::owned::admitted(
                owner.task,
                owner.cx,
                owner.clock,
                resource,
                &fss_core::BudgetVector::ZERO,
            )
            .map_err(|e| {
                if e.kind() == io::ErrorKind::Interrupted {
                    Error::Interrupted
                } else {
                    Error::Authority
                }
            })?;
            let now = owner.cx.now().as_nanos();
            if now >= due {
                break;
            }
            sleep_until(Time::from_nanos(due.min(now.saturating_add(100_000_000)))).await;
        }
    }
    Err(Error::RetryConfiguration)
}

/// Setup outcome and, when applicable, the separately retained deadline
/// settlement result. An error in settlement must not be mistaken for a
/// successful cancellation or permission to retry.
#[must_use]
pub struct DeadlineRecoveredSetup {
    pub outcome: Result<setup::Outcome, Error>,
    pub deadline_recovery: Option<Result<ContentDigest, fleet::DeadlineSettlementError>>,
}

/// Run the bounded preflight path and retain evidence before cancelling an
/// exact, witnessed pre-commit deadline. The HTTPS session has been dropped
/// before settlement. A successful settlement makes the operation eligible
/// for the existing bounded fleet retry queue; this function does not start a
/// new attempt. The caller retains the trace, spool, and recovery result.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_preflight_retries_and_deadline_recovery<'scope, 'task>(
    fleet: &Fleet<'_>,
    index: usize,
    owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &controller_listener::Listener<'_, '_, '_>,
    http_authority: &dyn camera_http::Authority,
    peer: SocketAddrV4,
    certificate_der: &[u8],
    credential_handle: ContentDigest,
    credential: &[u8],
    resource: &'scope str,
    acquisitions: &mut [Acquisition<'scope, 'task>],
    provider: Arc<CryptoProvider>,
    fence: u64,
    destination: Ipv4Addr,
    operation: &OperationId,
    framing: handoff::Framing,
    wait: Duration,
    setup_trace: &mut setup::Trace,
    retry_trace: &PreflightRetryTrace,
    policy: PreflightRetryPolicy,
    spool: &mut fss_object::StagingSpool,
    storage_resource: &str,
) -> DeadlineRecoveredSetup {
    let outcome = run_with_preflight_retries(
        fleet, index, owner, listener, http_authority, peer, certificate_der,
        credential_handle, credential, resource, acquisitions, provider, fence,
        destination, operation, framing, wait, setup_trace, retry_trace, policy,
    ).await;
    let deadline_recovery = if matches!(
        &outcome,
        Err(Error::Setup(fleet::Error::Setup(setup::Error::Deadline)))
    ) && setup_trace.has_precommit_deadline() {
        Some(fleet.settle_expired_setup(index, owner, setup_trace, spool, storage_resource))
    } else {
        None
    };
    DeadlineRecoveredSetup { outcome, deadline_recovery }
}

/// Connect and run the existing tracked setup for an enrolled ready camera.
/// The supplied lease is already acquired and drained: dropping this future
/// drops the connection and lease, while `trace` and the effect journal remain
/// caller-owned. No credential or camera address is included in errors.
#[allow(clippy::too_many_arguments)]
pub async fn run<'scope, 'task>(
    fleet: &Fleet<'_>,
    index: usize,
    owner: &mut setup::Owner<'_, 'scope, 'task>,
    listener: &controller_listener::Listener<'_, '_, '_>,
    http_authority: &dyn camera_http::Authority,
    peer: SocketAddrV4,
    certificate_der: &[u8],
    credential_handle: ContentDigest,
    credential: &[u8],
    resource: &'scope str,
    lease: Lease<'scope, 'task>,
    provider: Arc<CryptoProvider>,
    fence: u64,
    destination: Ipv4Addr,
    operation: &OperationId,
    framing: handoff::Framing,
    wait: Duration,
    trace: &mut setup::Trace,
) -> Result<setup::Outcome, Error> {
    owner.cx.checkpoint().map_err(|_| Error::Interrupted)?;
    let enrollment = fleet.enrollment(index).ok_or(Error::Binding)?;
    let State::Ready { candidate } = fleet.state(index).ok_or(Error::Binding)? else {
        return Err(Error::Binding);
    };
    let report = fleet.latest_report();
    let claimed = report.cameras.get(candidate).ok_or(Error::Binding)?;
    if report.select_mac_claim(enrollment.mac()).ok() != Some(candidate)
        || *claimed.source().ip() != *peer.ip()
        || certificate_der.is_empty()
        || certificate_der.len() > 8192
        || ContentDigest::sha256(certificate_der) != enrollment.certificate()
        || credential_handle != enrollment.credential()
        || resource != format!("camera:{}", enrollment.camera().to_text())
        || !lease.matches(owner.task, owner.cx, &owner.clock, resource)
        || listener.local_addr().ip() != &destination
        || listener.local_addr().port() == 0
        || fence == 0
    {
        return Err(Error::Binding);
    }
    if !owner.admission.permits(
        claimed,
        enrollment.camera(),
        enrollment.peer_admission(),
        enrollment.generation(),
        fence,
    ) || !http_authority.permits(
        *peer.ip(),
        enrollment.generation(),
        camera_http::Operation::Login,
    ) {
        return Err(Error::Authority);
    }
    let tls = camera_tls_owned::connect_with_lease(
        owner.cx,
        owner.task,
        owner.clock,
        peer,
        certificate_der,
        resource,
        wait,
        provider,
        lease,
    )
    .await
    .map_err(Error::Transport)?;
    let io = MeteredIo::with_clock(tls, owner.clock, resource, 4096)
        .map_err(|error| Error::Meter(error.kind()))?;
    let mut camera = camera_http::Owner::new(
        io,
        owner.task,
        owner.cx,
        owner.clock,
        http_authority,
        *peer.ip(),
        enrollment.generation(),
        resource,
    )
    .map_err(Error::Http)?;
    fleet
        .setup_one(
            index,
            owner,
            listener,
            listener.local_addr().port(),
            &mut camera,
            enrollment.certificate(),
            credential_handle,
            credential,
            fence,
            destination,
            operation,
            framing,
            wait,
            trace,
        )
        .await
        .map_err(Error::Setup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_retry_does_not_retry_security_or_effect_failures() {
        assert!(retryable_preflight(&Error::Transport(
            camera_tls_owned::Error::Deadline
        )));
        assert!(retryable_preflight(&Error::Transport(
            camera_tls_owned::Error::Transport(io::ErrorKind::ConnectionRefused)
        )));
        assert!(!retryable_preflight(&Error::Transport(
            camera_tls_owned::Error::Handshake
        )));
        assert!(!retryable_preflight(&Error::Transport(
            camera_tls_owned::Error::Authority
        )));
        assert!(!retryable_preflight(&Error::Transport(
            camera_tls_owned::Error::Limit
        )));
        assert!(!retryable_preflight(&Error::Authority));
        assert!(!retryable_preflight(&Error::Entropy(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!retryable_preflight(&Error::Interrupted));
    }
}
