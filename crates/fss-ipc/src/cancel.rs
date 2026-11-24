#![forbid(unsafe_code)]
//! Cooperative request cancellation tokens backed by atomic flags and detached Asupersync `Cx`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fss_core::PrincipalId;

/// Why an in-flight IPC request cancellation token fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    /// The client explicitly issued `IpcRequest::CancelRequest`.
    ClientCancelRequest,
    /// The client closed or reset its Unix socket while the request was active.
    PeerDisconnected,
    /// The local daemon began cooperative shutdown/drain.
    ServerShutdown,
    /// A request or connection deadline expired.
    Timeout,
}

struct CancelState {
    cancelled: AtomicBool,
    cx: asupersync::cx::Cx<asupersync::cx::cap::None>,
    reason: Mutex<Option<CancelReason>>,
}

/// Cooperative cancellation handle propagated into `DaemonIpcHandler` callbacks.
///
/// Bridges an atomic fast path with an owned detached Asupersync cancellation context
/// (`asupersync::Cx::detached_cancel_context`) so both synchronous and async handlers observe
/// cancellation deterministically.
#[derive(Clone)]
pub struct RequestCancelToken {
    inner: Arc<CancelState>,
}

impl Default for RequestCancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestCancelToken {
    /// Creates an active, uncancelled request token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelState {
                cancelled: AtomicBool::new(false),
                cx: asupersync::Cx::detached_cancel_context(),
                reason: Mutex::new(None),
            }),
        }
    }

    /// Fires cooperative cancellation with the first-recorded reason winning.
    pub fn cancel(&self, reason: CancelReason) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            if let Ok(mut guard) = self.inner.reason.lock() {
                *guard = Some(reason);
            }
            self.inner
                .cx
                .cancel_fast(asupersync::types::CancelKind::User);
        }
    }

    /// Returns true once cooperative cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire) || self.inner.cx.is_cancelled()
    }

    /// Returns the recorded cancellation reason, if cancelled.
    #[must_use]
    pub fn reason(&self) -> Option<CancelReason> {
        self.inner.reason.lock().ok().and_then(|guard| *guard)
    }

    /// Borrows the underlying detached Asupersync cancellation context.
    #[must_use]
    pub fn asupersync_cx(&self) -> &asupersync::cx::Cx<asupersync::cx::cap::None> {
        &self.inner.cx
    }
}

/// Per-connection uncontended active-request cancel table.
///
/// Normal requests only touch their own connection slot, avoiding global lock contention across
/// concurrent client connections.
pub(crate) struct ConnectionCancelSlot {
    principal: PrincipalId,
    active: Mutex<Vec<(u64, RequestCancelToken)>>,
}

impl ConnectionCancelSlot {
    pub(crate) fn new(principal: PrincipalId) -> Self {
        Self {
            principal,
            active: Mutex::new(Vec::with_capacity(4)),
        }
    }

    pub(crate) fn register(&self, req_id: u64, token: RequestCancelToken) {
        if let Ok(mut guard) = self.active.lock() {
            guard.push((req_id, token));
        }
    }

    pub(crate) fn remove(&self, req_id: u64) {
        if let Ok(mut guard) = self.active.lock()
            && let Some(pos) = guard.iter().position(|(id, _)| *id == req_id)
        {
            guard.swap_remove(pos);
        }
    }

    pub(crate) fn cancel_request(&self, target_request_id: u64, reason: CancelReason) -> bool {
        let tokens: Vec<RequestCancelToken> = match self.active.lock() {
            Ok(guard) => guard
                .iter()
                .filter(|(id, _)| *id == target_request_id)
                .map(|(_, tok)| tok.clone())
                .collect(),
            Err(_) => Vec::new(),
        };
        let found = !tokens.is_empty();
        for token in tokens {
            token.cancel(reason);
        }
        found
    }

    pub(crate) fn cancel_all(&self, reason: CancelReason) {
        let tokens: Vec<RequestCancelToken> = match self.active.lock() {
            Ok(guard) => guard.iter().map(|(_, tok)| tok.clone()).collect(),
            Err(_) => Vec::new(),
        };
        for token in tokens {
            token.cancel(reason);
        }
    }
}

#[derive(Default)]
pub(crate) struct CancelRegistry {
    connections: Mutex<BTreeMap<u64, Arc<ConnectionCancelSlot>>>,
}

impl CancelRegistry {
    pub(crate) fn register_connection(
        &self,
        conn_id: u64,
        principal: PrincipalId,
    ) -> Arc<ConnectionCancelSlot> {
        let slot = Arc::new(ConnectionCancelSlot::new(principal));
        if let Ok(mut guard) = self.connections.lock() {
            guard.insert(conn_id, Arc::clone(&slot));
        }
        slot
    }

    pub(crate) fn remove_connection(&self, conn_id: u64) {
        if let Ok(mut guard) = self.connections.lock() {
            guard.remove(&conn_id);
        }
    }

    pub(crate) fn cancel_for_principal(
        &self,
        principal: &PrincipalId,
        target_request_id: u64,
        reason: CancelReason,
    ) -> bool {
        let slots: Vec<Arc<ConnectionCancelSlot>> = match self.connections.lock() {
            Ok(guard) => guard
                .values()
                .filter(|slot| &slot.principal == principal)
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        };
        let mut found = false;
        for slot in slots {
            if slot.cancel_request(target_request_id, reason) {
                found = true;
            }
        }
        found
    }

    pub(crate) fn cancel_all(&self, reason: CancelReason) {
        let slots: Vec<Arc<ConnectionCancelSlot>> = match self.connections.lock() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => Vec::new(),
        };
        for slot in slots {
            slot.cancel_all(reason);
        }
    }
}
