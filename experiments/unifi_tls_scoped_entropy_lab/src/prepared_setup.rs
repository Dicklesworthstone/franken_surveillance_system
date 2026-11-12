#![forbid(unsafe_code)]
//! Bounded, caller-prepared setup work for the experimental fleet supervisor.
//!
//! The queue supplies work only when its caller asks for an already-ready,
//! owner-enrolled camera. It does not create credentials, authenticate a
//! discovery claim, reconcile an effect, or authorize a retry.

use crate::fleet_leased::RetryCompletion;
use fss_core::OperationId;
use fss_reference::unifi_direct::discovery::{
    fleet::{Enrollment, Fleet, State},
    pump::CameraWork,
};
use std::io;

const MAX_PENDING: usize = 128;
const MAX_OPERATIONS: usize = 2048;

/// One caller-constructed future and the operation identity it is meant to run.
/// The queue cannot prove that the future actually uses this identity.
#[must_use = "retain or explicitly retire the unstarted setup work"]
pub struct PreparedSetup<'work, W> {
    index: usize,
    enrollment: Enrollment,
    operation: OperationId,
    work: CameraWork<'work, W>,
}

impl<'work, W> PreparedSetup<'work, W> {
    /// Bind unpolled work to an inventory claim and a fresh operation identity.
    pub fn new(
        index: usize,
        enrollment: Enrollment,
        operation: OperationId,
        work: CameraWork<'work, W>,
    ) -> Self {
        Self {
            index,
            enrollment,
            operation,
            work,
        }
    }

    /// Inventory index supplied by the caller.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Operation identity supplied by the caller.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Recover the unpolled future and its original binding.
    pub fn into_parts(self) -> (usize, Enrollment, OperationId, CameraWork<'work, W>) {
        (self.index, self.enrollment, self.operation, self.work)
    }
}

/// A prepared attempt was not admitted to the queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The supplied enrollment does not match the bound fleet.
    Binding,
    /// This operation identity was already admitted by this queue.
    DuplicateOperation,
    /// The pending or lifetime operation bound is exhausted.
    Capacity,
}

/// One bounded owner of preconstructed attempts across a fleet.
///
/// An admitted operation identity stays reserved even after its future is
/// handed off. `into_pending` returns every remaining future for explicit
/// retirement; dropping the queue drops them. This process-local reservation
/// is not durable restart protection and does not coordinate other owners.
#[must_use = "retire all unstarted setup futures"]
pub struct Queue<'fleet, 'report, 'work, W> {
    fleet: &'fleet Fleet<'report>,
    pending: Vec<PreparedSetup<'work, W>>,
    operations: Vec<OperationId>,
    pending_limit: usize,
    operation_limit: usize,
}

impl<'fleet, 'report, 'work, W: 'work> Queue<'fleet, 'report, 'work, W> {
    /// Reserve fixed pending and lifetime operation bounds before admitting work.
    pub fn new(
        fleet: &'fleet Fleet<'report>,
        pending_limit: usize,
        operation_limit: usize,
    ) -> io::Result<Self> {
        if !(1..=MAX_PENDING).contains(&pending_limit)
            || !(pending_limit..=MAX_OPERATIONS).contains(&operation_limit)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(pending_limit)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(operation_limit)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(Self {
            fleet,
            pending,
            operations,
            pending_limit,
            operation_limit,
        })
    }

    /// Admit unpolled work, or return the exact item unchanged on refusal.
    pub fn enqueue(
        &mut self,
        item: PreparedSetup<'work, W>,
    ) -> Result<(), (Refusal, PreparedSetup<'work, W>)> {
        if self.fleet.enrollment(item.index) != Some(item.enrollment) {
            return Err((Refusal::Binding, item));
        }
        if self.operations.contains(&item.operation) {
            return Err((Refusal::DuplicateOperation, item));
        }
        if self.pending.len() == self.pending_limit || self.operations.len() == self.operation_limit
        {
            return Err((Refusal::Capacity, item));
        }
        self.operations.push(item.operation.clone());
        self.pending.push(item);
        Ok(())
    }

    /// Pending unpolled attempts.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no unpolled attempts remain.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Supply the oldest pending attempt for this exact ready enrollment.
    /// A refusal leaves every queued future and identity unchanged. This can be
    /// used as `|index, enrollment| queue.take(index, enrollment)` in the
    /// fleet supervisor. No future is polled by this method.
    pub fn take(
        &mut self,
        index: usize,
        enrollment: Enrollment,
    ) -> io::Result<CameraWork<'work, RetryCompletion<W>>> {
        if self.fleet.enrollment(index) != Some(enrollment) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if !matches!(self.fleet.state(index), Some(State::Ready { .. })) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let position = self
            .pending
            .iter()
            .position(|item| item.index == index && item.enrollment == enrollment)
            .ok_or(io::ErrorKind::NotFound)?;
        let item = self.pending.remove(position);
        Ok(Box::pin(async move {
            RetryCompletion {
                operation: item.operation,
                output: item.work.await,
            }
        }))
    }

    /// Return all unstarted work to its owner, in admission order.
    pub fn into_pending(self) -> Vec<PreparedSetup<'work, W>> {
        self.pending
    }
}
