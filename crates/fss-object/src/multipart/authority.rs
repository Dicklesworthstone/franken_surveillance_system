#![forbid(unsafe_code)]
//! Resource-specific admission for each actual multipart transport operation.

use fss_core::{
    BudgetVector, RegionId, RegionKind, RegionTree, RegionTreeIdentity, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;

use super::{MultipartError, TransportOperation, UploadIntent};

/// Caller-supplied execution authority and time. Construction grants no I/O;
/// each protocol operation checks and charges it before calling the transport.
pub struct UploadIo<'a> {
    /// Actual owned object-store child, never a synthesized capability record.
    pub authority: &'a mut AuthorityCx,
    /// The exact canonical tree that owns the child and its cancellation state.
    pub tree: &'a RegionTree,
    /// Current time supplied by the caller's clock boundary.
    pub now: TimestampNs,
}

/// An admitted call's explicit I/O context. Only this module can construct one.
pub struct TransportCx<'a> {
    authority: &'a mut AuthorityCx,
    tree: &'a RegionTree,
    resource: &'a str,
    operation: TransportOperation,
    now: TimestampNs,
}

impl TransportCx<'_> {
    /// Owning child authority, for the transport's own effect boundary.
    #[must_use]
    pub fn authority(&self) -> &AuthorityCx {
        self.authority
    }
    /// Exact admitted resource, not an arbitrary destination chosen by the adapter.
    #[must_use]
    pub fn resource(&self) -> &str {
        self.resource
    }
    /// Protocol operation admitted for this call.
    #[must_use]
    pub const fn operation(&self) -> TransportOperation {
        self.operation
    }
    /// Caller time at admission.
    #[must_use]
    pub const fn now(&self) -> TimestampNs {
        self.now
    }
    /// Recheck owner, capability, deadline and cancellation before transport I/O.
    /// Cleanup observes existing effects after cancellation; it cannot publish a root.
    pub fn checkpoint(&mut self, now: TimestampNs) -> Result<(), MultipartError> {
        if now < self.now {
            return Err(MultipartError::ClockRegression);
        }
        check(
            self.authority,
            self.tree,
            self.resource,
            self.operation,
            now,
        )?;
        self.now = now;
        Ok(())
    }

    /// Admit framing, response buffers and other transport-specific byte costs
    /// before performing that I/O. Payload bytes were already charged by the
    /// protocol; the adapter must not silently omit or double-charge them.
    pub fn charge_io(
        &mut self,
        now: TimestampNs,
        memory_bytes: u64,
        network_bytes: u64,
    ) -> Result<(), MultipartError> {
        self.checkpoint(now)?;
        let mut cost = BudgetVector::ZERO;
        cost.bytes = memory_bytes;
        cost.network_bytes = network_bytes;
        self.authority
            .budget_mut(self.tree)
            .map_err(authority)?
            .spend_vector(&cost)
            .map_err(authority)
    }
}

fn authority(error: impl std::fmt::Display) -> MultipartError {
    MultipartError::Authority(error.to_string())
}

fn check(
    cx: &AuthorityCx,
    tree: &RegionTree,
    resource: &str,
    operation: TransportOperation,
    now: TimestampNs,
) -> Result<(), MultipartError> {
    let cancelled = cx.is_cancel_requested(tree).map_err(authority)?;
    if cx.kind() != RegionKind::ObjectStore {
        return Err(MultipartError::OwnerMismatch);
    }
    cx.require_grant_for(RuntimeGrant::AdapterNet, resource)
        .map_err(authority)?;
    let grant = if operation == TransportOperation::Complete {
        RuntimeGrant::ObjectPublish
    } else {
        RuntimeGrant::ObjectStage
    };
    cx.require_grant_for(grant, resource).map_err(authority)?;
    if !matches!(
        operation,
        TransportOperation::Abort | TransportOperation::Reconcile
    ) {
        if cancelled {
            return Err(MultipartError::CancellationRequested);
        }
        let node = tree.get(cx.region()).map_err(authority)?;
        if node
            .authority
            .deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(MultipartError::Deadline);
        }
    }
    Ok(())
}

pub(super) fn validate_binding(
    io: &UploadIo<'_>,
    owner: &Option<(RegionTreeIdentity, RegionId)>,
    observed_at: TimestampNs,
) -> Result<(), MultipartError> {
    // Even terminal receipt retrieval must not use an unknown or forged tree.
    io.authority
        .is_cancel_requested(io.tree)
        .map_err(authority)?;
    if io.authority.kind() != RegionKind::ObjectStore {
        return Err(MultipartError::OwnerMismatch);
    }
    if owner.as_ref().is_some_and(|(tree, region)| {
        tree != io.tree.owner_identity() || region != io.authority.region()
    }) {
        return Err(MultipartError::OwnerMismatch);
    }
    if io.now < observed_at {
        return Err(MultipartError::ClockRegression);
    }
    Ok(())
}

pub(super) fn validate_owner(
    io: &UploadIo<'_>,
    intent: &UploadIntent,
    operation: TransportOperation,
    owner: &Option<(RegionTreeIdentity, RegionId)>,
    observed_at: TimestampNs,
) -> Result<(), MultipartError> {
    validate_binding(io, owner, observed_at)?;
    if io
        .tree
        .get(io.authority.region())
        .map_err(authority)?
        .authority
        .operation_id
        != *intent.operation()
    {
        return Err(MultipartError::OwnerMismatch);
    }
    check(io.authority, io.tree, intent.resource(), operation, io.now)
}

pub(super) fn admit<'a>(
    io: UploadIo<'a>,
    intent: &'a UploadIntent,
    operation: TransportOperation,
    payload_bytes: u64,
    owner: &mut Option<(RegionTreeIdentity, RegionId)>,
    observed_at: &mut TimestampNs,
) -> Result<TransportCx<'a>, MultipartError> {
    validate_owner(&io, intent, operation, owner, *observed_at)?;
    // New work leaves one request for explicit abort or read-only reconciliation.
    // Reconciliation may spend the final request to establish an already-terminal
    // outcome; unknown results never replenish the bounded allowance.
    if !matches!(
        operation,
        TransportOperation::Abort | TransportOperation::Reconcile
    ) && io.authority.budget().remaining().storage_operations < 2
    {
        return Err(MultipartError::CleanupReserve);
    }
    let mut cost = BudgetVector::ZERO;
    cost.bytes = payload_bytes;
    cost.network_bytes = payload_bytes;
    cost.storage_operations = 1;
    io.authority
        .budget_mut(io.tree)
        .map_err(authority)?
        .spend_vector(&cost)
        .map_err(authority)?;
    if owner.is_none() {
        *owner = Some((
            io.tree.owner_identity().clone(),
            io.authority.region().clone(),
        ));
    }
    *observed_at = io.now;
    Ok(TransportCx {
        authority: io.authority,
        tree: io.tree,
        resource: intent.resource(),
        operation,
        now: io.now,
    })
}
