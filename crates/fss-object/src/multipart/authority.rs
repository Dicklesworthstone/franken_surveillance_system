#![forbid(unsafe_code)]
//! Resource-specific admission for each actual multipart transport operation.

use fss_core::{
    BudgetVector, RegionId, RegionKind, RegionTree, RegionTreeIdentity, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;

use super::recovery::TransportPersistence;
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
    resource: String,
    operation: TransportOperation,
    now: TimestampNs,
    persistence: Option<&'a mut dyn TransportPersistence>,
    durable_upload_owner: bool,
    read_only_observation: bool,
}

impl<'a> TransportCx<'a> {
    /// Owning child authority, for the transport's own effect boundary.
    #[must_use]
    pub fn authority(&self) -> &AuthorityCx {
        self.authority
    }
    /// Exact admitted resource, not an arbitrary destination chosen by the adapter.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
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
    /// Current forward-work deadline for bounding one blocking I/O offer.
    /// Cleanup may outlive that deadline and must supply its own finite bound.
    pub fn deadline(&self) -> Result<Option<TimestampNs>, MultipartError> {
        if !self.read_only_observation
            && matches!(
                self.operation,
                TransportOperation::Abort | TransportOperation::Reconcile
            )
        {
            return Ok(None);
        }
        Ok(self
            .tree
            .get(self.authority.region())
            .map_err(authority)?
            .authority
            .deadline)
    }
    /// Whether this call's admissions are persisted before I/O.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.persistence.is_some()
    }
    /// Whether the validated journal also carries the StagedUpload owner recipe,
    /// including all narrowed resource grants and its drain obligation.
    /// Protocol-only legacy checkpoints preserve only the protocol's three grants.
    #[must_use]
    pub fn has_durable_upload_owner(&self) -> bool {
        self.persistence.is_some() && self.durable_upload_owner
    }
    /// A separately authorized observation of an immutable, locally settled
    /// upload. This context cannot admit staging, publication or abort and its
    /// own finite deadline and cancellation remain effective during the read.
    #[must_use]
    pub const fn is_read_only_observation(&self) -> bool {
        self.read_only_observation
    }
    /// Recheck owner, capability, deadline and cancellation before transport I/O.
    /// Cleanup observes existing effects after cancellation; it cannot publish a root.
    pub fn checkpoint(&mut self, now: TimestampNs) -> Result<(), MultipartError> {
        if now < self.now {
            return Err(MultipartError::ClockRegression);
        }
        // Observing a later clock boundary is not undone by a deadline/cancellation refusal.
        // The session retains this time even when the transport returns an error afterward.
        self.now = now;
        let result = if self.read_only_observation {
            check_observation(self.authority, self.tree, &self.resource, now)
        } else {
            check(
                self.authority,
                self.tree,
                &self.resource,
                self.operation,
                now,
            )
        };
        // Even refused later time/cancellation observations must survive reopen.
        // An adapter cannot turn a failed journal append into another I/O attempt.
        self.persist()?;
        result
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
            .map_err(authority)?;
        // Returning admission is the effect boundary: the budget charge must
        // already be durable before the transport may perform its extra I/O.
        self.persist()
    }

    pub(super) fn tree(&self) -> &RegionTree {
        self.tree
    }

    pub(super) fn cancelled(&self) -> bool {
        // An invalidated authority is never a reason to forget cancellation.
        self.authority
            .is_cancel_requested(self.tree)
            .unwrap_or(true)
    }

    pub(super) fn with_persistence<'call>(
        self,
        persistence: Option<&'call mut dyn TransportPersistence>,
        durable_upload_owner: bool,
    ) -> TransportCx<'call>
    where
        'a: 'call,
    {
        TransportCx {
            authority: self.authority,
            tree: self.tree,
            resource: self.resource,
            operation: self.operation,
            now: self.now,
            persistence,
            durable_upload_owner,
            read_only_observation: self.read_only_observation,
        }
    }

    fn persist(&mut self) -> Result<(), MultipartError> {
        let cancelled = self.cancelled();
        if let Some(persistence) = &mut self.persistence {
            persistence.record(*self.authority.budget().consumed(), self.now, cancelled)?;
        }
        Ok(())
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
    validate_lifetime(cx, tree, now)?;
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

fn validate_lifetime(
    cx: &AuthorityCx,
    tree: &RegionTree,
    now: TimestampNs,
) -> Result<(), MultipartError> {
    let node = tree.get(cx.region()).map_err(authority)?;
    if now < node.created_at
        || node.drain_requested_at.is_some_and(|at| now < at)
        || node.closed_at.is_some_and(|at| now < at)
    {
        return Err(MultipartError::ClockRegression);
    }
    Ok(())
}

pub(super) fn validate_binding(
    io: &UploadIo<'_>,
    intent: &UploadIntent,
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
    if owner.as_ref().is_some_and(|(tree, region)| {
        tree != io.tree.owner_identity() || region != io.authority.region()
    }) {
        return Err(MultipartError::OwnerMismatch);
    }
    if io.now < observed_at {
        return Err(MultipartError::ClockRegression);
    }
    validate_lifetime(io.authority, io.tree, io.now)?;
    Ok(())
}

pub(super) fn validate_owner(
    io: &UploadIo<'_>,
    intent: &UploadIntent,
    operation: TransportOperation,
    owner: &Option<(RegionTreeIdentity, RegionId)>,
    observed_at: TimestampNs,
) -> Result<(), MultipartError> {
    validate_binding(io, intent, owner, observed_at)?;
    check(io.authority, io.tree, intent.resource(), operation, io.now)
}

pub(super) fn admit<'a>(
    io: UploadIo<'a>,
    intent: &UploadIntent,
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
        resource: intent.resource().to_owned(),
        operation,
        now: io.now,
        persistence: None,
        durable_upload_owner: false,
        read_only_observation: false,
    })
}

fn check_observation(
    cx: &AuthorityCx,
    tree: &RegionTree,
    resource: &str,
    now: TimestampNs,
) -> Result<(), MultipartError> {
    let cancelled = cx.is_cancel_requested(tree).map_err(authority)?;
    validate_lifetime(cx, tree, now)?;
    if cx.kind() != RegionKind::ObjectStore {
        return Err(MultipartError::OwnerMismatch);
    }
    if cancelled {
        return Err(MultipartError::CancellationRequested);
    }
    let node = tree.get(cx.region()).map_err(authority)?;
    if node.state != fss_core::RegionState::Active {
        return Err(MultipartError::OwnerMismatch);
    }
    if node
        .authority
        .deadline
        .is_none_or(|deadline| now >= deadline)
    {
        return Err(MultipartError::Deadline);
    }
    for grant in [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ObserveStatus,
    ] {
        cx.require_grant_for(grant, resource).map_err(authority)?;
    }
    // A read-only observer never carries a spare effect grant, even when a
    // caller supplied a more powerful parent. These three are the entire set.
    if cx.grants().len() != 3 {
        return Err(MultipartError::OwnerMismatch);
    }
    Ok(())
}

/// Restricted construction used only by the independently owned completion
/// observation. It never restores or mutates the old upload's authority.
pub(crate) fn admit_observation<'a>(
    io: UploadIo<'a>,
    resource: &str,
) -> Result<TransportCx<'a>, MultipartError> {
    check_observation(io.authority, io.tree, resource, io.now)?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 1;
    io.authority
        .budget_mut(io.tree)
        .map_err(authority)?
        .spend_vector(&cost)
        .map_err(authority)?;
    Ok(TransportCx {
        authority: io.authority,
        tree: io.tree,
        resource: resource.to_owned(),
        operation: TransportOperation::Reconcile,
        now: io.now,
        persistence: None,
        durable_upload_owner: false,
        read_only_observation: true,
    })
}
