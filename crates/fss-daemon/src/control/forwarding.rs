#![forbid(unsafe_code)]
//! Exact-request admission and replay for forwarded canonical delta batches.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fss_core::{CanonicalEncoder, ContentDigest, ERR_OP_RECONCILIATION_REQUIRED_001};
use fss_ipc::{ERR_IPC_FRAME_TOO_LARGE_001, MAX_REQUEST_PAYLOAD_BYTES};

use super::{
    ControlPlaneShared, DeltaPriority, ERR_IPC_SERVER_SHUTDOWN_001, ERR_IPC_WIRE_CORRUPT_001,
    ForwardBatchReceipt, IpcResponse, MeaningfulDeltaClass, RequestContext, make_refused,
};

const MAX_FORWARDED_BATCHES: usize = 1_024;
const REQUEST_DOMAIN: &str = "fss.daemon.forwarded_request.v1";
const ERR_IDEMPOTENCY_CONFLICT: &str = "ERR-IDEMPOTENCY-CONFLICT-001";

#[derive(Default)]
pub(super) struct ForwardedBatches {
    entries: Mutex<BTreeMap<ContentDigest, CachedForward>>,
}

struct CachedForward {
    request_digest: ContentDigest,
    state: ForwardState,
}

#[derive(Clone, Copy)]
enum ForwardState {
    InFlight,
    Committed(ForwardBatchReceipt),
    ReconciliationRequired,
}

impl ForwardedBatches {
    pub(super) fn submit(
        &self,
        shared: &ControlPlaneShared,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        batch_bytes: &[u8],
        approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        if ctx.is_cancelled() {
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        if batch_bytes.len() > MAX_REQUEST_PAYLOAD_BYTES {
            return make_refused(
                ctx.request_id,
                ERR_IPC_FRAME_TOO_LARGE_001,
                "forwarded batch exceeds the bounded IPC request size",
                false,
            );
        }
        let Some(request_digest) = request_digest(shared, ctx, batch_bytes, approval_digest) else {
            return make_refused(
                ctx.request_id,
                ERR_IPC_WIRE_CORRUPT_001,
                "forwarded request context exceeds canonical encoding bounds",
                false,
            );
        };
        let durable = shared.forward_writer.supports_durable_idempotency();
        {
            let Ok(mut entries) = self.entries.lock() else {
                return unavailable(ctx.request_id, "forwarded replay state is unavailable");
            };
            if ctx.is_cancelled() {
                return IpcResponse::Cancelled {
                    request_id: ctx.request_id,
                };
            }
            if let Some(previous) = entries.get(&idempotency_key) {
                if previous.request_digest != request_digest {
                    return conflict(ctx.request_id);
                }
                return match previous.state {
                    ForwardState::Committed(receipt) => committed(ctx.request_id, receipt),
                    ForwardState::InFlight => make_refused(
                        ctx.request_id,
                        ERR_OP_RECONCILIATION_REQUIRED_001,
                        "the exact forwarded request is in flight; retry only the same key and request to observe its receipt",
                        true,
                    ),
                    ForwardState::ReconciliationRequired => unavailable(
                        ctx.request_id,
                        "a previous forwarding attempt has no verified receipt; reconcile its outcome before any new write",
                    ),
                };
            }
            if shared.is_shutdown_requested() {
                return shutting_down(ctx.request_id);
            }
            if entries.len() >= MAX_FORWARDED_BATCHES {
                let evictable = if durable {
                    entries.iter().find_map(|(key, entry)| {
                        (!matches!(entry.state, ForwardState::InFlight)).then_some(*key)
                    })
                } else {
                    None
                };
                if let Some(key) = evictable {
                    // The durable writer retains the key, complete request binding, and outcome.
                    entries.remove(&key);
                } else {
                    return make_refused(
                        ctx.request_id,
                        "ERR-BUDGET-EXHAUSTED-001",
                        if durable {
                            "all forwarded request slots are in flight; retry the same request after a slot settles"
                        } else {
                            "forwarded replay capacity is full and this writer has no durable replay support; existing records cannot be evicted safely"
                        },
                        durable,
                    );
                }
            }
            entries.insert(
                idempotency_key,
                CachedForward {
                    request_digest,
                    state: ForwardState::InFlight,
                },
            );
        }

        // Never hold the shared admission mutex across storage I/O. The reservation
        // gives duplicate callers an explicit in-flight result without a second write.
        let mut reservation = ForwardReservation {
            entries: &self.entries,
            key: idempotency_key,
            request_digest,
            durable,
            finished: false,
        };
        if ctx.is_cancelled() {
            reservation.finish(None);
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        if shared.is_shutdown_requested() {
            reservation.finish(None);
            return shutting_down(ctx.request_id);
        }
        match shared.forward_writer.forward_delta_batch_idempotent(
            idempotency_key,
            request_digest,
            batch_bytes,
        ) {
            Ok(receipt) => {
                if !reservation.finish(Some(ForwardState::Committed(receipt))) {
                    return unavailable(
                        ctx.request_id,
                        "forwarded write completed but its replay state is unavailable",
                    );
                }
                if !receipt.replayed {
                    shared.publish_delta_summary(
                        receipt.commit_sequence,
                        ContentDigest::sha256(batch_bytes),
                        MeaningfulDeltaClass::MaterialState,
                        DeltaPriority::Normal,
                        format!("forwarded_batch seq={}", receipt.commit_sequence),
                    );
                }
                // A verified committed write remains committed even if cancellation
                // arrives during storage I/O or before the response reaches the client.
                committed(ctx.request_id, receipt)
            }
            Err(err) => {
                // Durable writers own both reservations and terminal outcomes. Removing
                // this volatile slot allows them to answer the next exact observation.
                // A legacy writer has no such proof, so its uncertain key stays blocked.
                let next = (!durable).then_some(ForwardState::ReconciliationRequired);
                reservation.finish(next);
                if err.error_id() == ERR_IDEMPOTENCY_CONFLICT {
                    return conflict(ctx.request_id);
                }
                unavailable(
                    ctx.request_id,
                    &format!(
                        "forwarded write has no verified receipt (cause {}); reconcile its outcome before any new write",
                        err.error_id()
                    ),
                )
            }
        }
    }
}

/// A panic after dispatch must not restore permission to repeat an uncertain write.
struct ForwardReservation<'a> {
    entries: &'a Mutex<BTreeMap<ContentDigest, CachedForward>>,
    key: ContentDigest,
    request_digest: ContentDigest,
    durable: bool,
    finished: bool,
}

impl ForwardReservation<'_> {
    fn finish(&mut self, state: Option<ForwardState>) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let Some(entry) = entries.get_mut(&self.key) else {
            return false;
        };
        if entry.request_digest != self.request_digest
            || !matches!(entry.state, ForwardState::InFlight)
        {
            return false;
        }
        if let Some(state) = state {
            entry.state = state;
        } else {
            entries.remove(&self.key);
        }
        self.finished = true;
        true
    }
}

impl Drop for ForwardReservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let next = (!self.durable).then_some(ForwardState::ReconciliationRequired);
            self.finish(next);
        }
    }
}

fn request_digest(
    shared: &ControlPlaneShared,
    ctx: &RequestContext,
    batch_bytes: &[u8],
    approval_digest: Option<ContentDigest>,
) -> Option<ContentDigest> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(REQUEST_DOMAIN);
    encoder.digest(shared.deployment_root_digest);
    encoder.text(&ctx.deployment_id);
    encoder.digest(ctx.contract_basis_digest);
    encoder.text(ctx.principal.as_str());
    let mut capabilities: Vec<_> = ctx
        .granted_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    capabilities.sort_unstable();
    capabilities.dedup();
    encoder.u64(u64::try_from(capabilities.len()).ok()?);
    for capability in capabilities {
        encoder.text(capability);
    }
    encoder.bytes(batch_bytes);
    encoder.bool(approval_digest.is_some());
    if let Some(approval) = approval_digest {
        encoder.digest(approval);
    }
    // A failed encoder returns empty bytes from finish(); never hash that as a request.
    let canonical = encoder.finish_checked().ok()?;
    Some(ContentDigest::sha256(&canonical))
}

fn committed(request_id: u64, receipt: ForwardBatchReceipt) -> IpcResponse {
    IpcResponse::DeltaBatchCommitted {
        request_id,
        commit_sequence: receipt.commit_sequence,
        history_root: receipt.history_root,
        state_root: receipt.state_root,
    }
}

fn conflict(request_id: u64) -> IpcResponse {
    make_refused(
        request_id,
        ERR_IDEMPOTENCY_CONFLICT,
        "idempotency key is already bound to different batch bytes or approval and authorization context",
        false,
    )
}

fn unavailable(request_id: u64, reason: &str) -> IpcResponse {
    make_refused(
        request_id,
        ERR_OP_RECONCILIATION_REQUIRED_001,
        reason,
        false,
    )
}

fn shutting_down(request_id: u64) -> IpcResponse {
    make_refused(
        request_id,
        ERR_IPC_SERVER_SHUTDOWN_001,
        "daemon is draining for shutdown",
        true,
    )
}

#[cfg(test)]
mod tests;
