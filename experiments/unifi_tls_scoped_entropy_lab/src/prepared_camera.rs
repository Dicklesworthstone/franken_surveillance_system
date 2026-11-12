#![forbid(unsafe_code)]
//! Retained, one-shot camera setup work for the experimental fleet supervisor.
//!
//! The factory constructs an unpolled future and binds its queue operation ID
//! to the same ID passed to camera setup. The caller still supplies the
//! enrollment, credential, certificate, authorities and durable owners.

use crate::{
    camera_setup::{self, Error, PreflightRetryPolicy, PreflightRetryTrace},
    owned::offload::Acquisition,
    prepared_setup::PreparedSetup,
};
use fss_core::{ContentDigest, OperationId};
use fss_reference::unifi_direct::{
    camera_http, controller_listener,
    discovery::fleet::{Enrollment, Fleet},
    handoff, setup,
};
use rustls::crypto::CryptoProvider;
use std::{
    cell::RefCell,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

/// Caller-retained evidence and entropy-worker owner for one operation.
/// A started attempt cannot be reused even if its future was dropped.
#[must_use = "retain the trace, recovery result, and entropy worker until reconciled"]
pub struct Attempt<'scope, 'task> {
    operation: OperationId,
    trace: setup::Trace,
    preflight: PreflightRetryTrace,
    acquisition: Vec<Acquisition<'scope, 'task>>,
    recovery: Option<
        Result<
            ContentDigest,
            fss_reference::unifi_direct::discovery::fleet::DeadlineSettlementError,
        >,
    >,
    started: bool,
}

impl<'scope, 'task> Attempt<'scope, 'task> {
    /// Retain a new, one-shot operation and its empty trace.
    pub fn new(operation: OperationId) -> Self {
        Self {
            operation,
            trace: setup::Trace::default(),
            preflight: PreflightRetryTrace::default(),
            acquisition: Vec::new(),
            recovery: None,
            started: false,
        }
    }
    /// Operation identity used both in the queue completion and the setup call.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    /// Whether polling has entered this attempt, not proof that an effect ran.
    pub fn started(&self) -> bool {
        self.started
    }
    /// Retained setup trace, including any outstanding effect obligation.
    pub fn trace(&self) -> &setup::Trace {
        &self.trace
    }
    /// Configure preflight before the work is polled.
    pub fn trace_mut(&mut self) -> Result<&mut setup::Trace, Error> {
        if self.started {
            Err(Error::RetryConfiguration)
        } else {
            Ok(&mut self.trace)
        }
    }
    /// Whether each entropy worker has been joined.
    pub fn workers_drained(&self) -> bool {
        self.acquisition.iter().all(Acquisition::is_drained)
    }
    /// Number of entropy workers created for this attempt.
    pub fn worker_count(&self) -> usize {
        self.acquisition.len()
    }
    /// Transfer any separately retained deadline-settlement result.
    pub fn take_recovery(
        &mut self,
    ) -> Option<
        Result<
            ContentDigest,
            fss_reference::unifi_direct::discovery::fleet::DeadlineSettlementError,
        >,
    > {
        self.recovery.take()
    }
    /// Request cancellation and join any unfinished entropy workers after the
    /// setup future has been retired. Dropping this wait retains the owner for
    /// another join. It does not reconcile an interrupted camera effect.
    pub async fn abort_and_drain(&mut self) -> io::Result<()> {
        for acquisition in &mut self.acquisition {
            if !acquisition.is_drained() {
                acquisition.abort();
                let _ = acquisition.join().await;
                if !acquisition.is_drained() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
            }
        }
        Ok(())
    }
}

/// Caller-supplied bindings for one camera attempt. None of the network claims
/// or certificate bytes alone prove a physical device's identity.
#[derive(Clone)]
pub struct Parameters<'work, 'report, 'scope, 'task, 'policy> {
    pub fleet: &'work Fleet<'report>,
    pub index: usize,
    pub enrollment: Enrollment,
    pub listener: &'work controller_listener::Listener<'scope, 'task, 'policy>,
    pub http_authority: &'work dyn camera_http::Authority,
    pub peer: SocketAddrV4,
    pub certificate_der: &'work [u8],
    pub credential_handle: ContentDigest,
    pub credential: &'work [u8],
    pub resource: &'scope str,
    pub provider: Arc<CryptoProvider>,
    pub fence: u64,
    pub destination: Ipv4Addr,
    pub framing: handoff::Framing,
    pub wait: Duration,
    pub storage_resource: &'work str,
}

/// Construct an unpolled setup future. Polling starts at most one owned
/// entropy acquisition; dropping the future leaves that worker, trace and
/// any prepared effect in the caller-retained `attempt` and `owner`.
/// Busy owners are refused before acquiring entropy. The caller must drain an
/// interrupted worker and reconcile any effect before permitting other work.
pub fn prepare<'work, 'owner, 'report, 'scope, 'task, 'policy>(
    params: Parameters<'work, 'report, 'scope, 'task, 'policy>,
    owner: Rc<RefCell<setup::Owner<'owner, 'scope, 'task>>>,
    spool: Rc<RefCell<fss_object::StagingSpool>>,
    attempt: Rc<RefCell<Attempt<'scope, 'task>>>,
) -> Result<PreparedSetup<'work, Result<setup::Outcome, Error>>, Error>
where
    'owner: 'work,
    'report: 'work,
    'scope: 'work,
    'task: 'scope,
    'policy: 'scope,
{
    if params.fleet.enrollment(params.index) != Some(params.enrollment) {
        return Err(Error::Binding);
    }
    let operation = attempt
        .try_borrow()
        .map_err(|_| Error::Busy)?
        .operation
        .clone();
    let queued_operation = operation.clone();
    let (index, enrollment) = (params.index, params.enrollment);
    let work = Box::pin(async move {
        let mut owner = owner.try_borrow_mut().map_err(|_| Error::Busy)?;
        let mut spool = spool.try_borrow_mut().map_err(|_| Error::Busy)?;
        let mut attempt = attempt.try_borrow_mut().map_err(|_| Error::Busy)?;
        if attempt.started {
            return Err(Error::RetryConfiguration);
        }
        attempt.started = true;
        attempt
            .acquisition
            .try_reserve_exact(1)
            .map_err(|_| Error::RetryConfiguration)?;
        let acquisition =
            Acquisition::begin(owner.task, owner.cx, owner.clock, params.resource, 128)
                .map_err(|error| Error::Entropy(error.kind()))?;
        attempt.acquisition.push(acquisition);
        let Attempt {
            trace,
            preflight,
            acquisition,
            recovery,
            ..
        } = &mut *attempt;
        let policy = PreflightRetryPolicy::new(1, Duration::from_millis(10))?;
        let result = camera_setup::run_with_preflight_retries_and_deadline_recovery(
            params.fleet,
            params.index,
            &mut owner,
            params.listener,
            params.http_authority,
            params.peer,
            params.certificate_der,
            params.credential_handle,
            params.credential,
            params.resource,
            acquisition,
            params.provider,
            params.fence,
            params.destination,
            &operation,
            params.framing,
            params.wait,
            trace,
            preflight,
            policy,
            &mut spool,
            params.storage_resource,
        )
        .await;
        *recovery = result.deadline_recovery;
        result.outcome
    });
    Ok(PreparedSetup::new(
        index,
        enrollment,
        queued_operation,
        work,
    ))
}
