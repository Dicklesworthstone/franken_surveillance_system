#![forbid(unsafe_code)]
//! Independently approved storage grace, never an extension of network or decode authority.
//!
//! The native recorder still owns the source, cancellation transitions and every byte/work
//! allowance. Letting its next admission observe an expired network lease permits it to retire
//! an already accepted read before publishing it. After network expiry, this adapter cannot
//! enable parser acknowledgement or a camera connection. It never grants a capability, renews
//! a budget or ignores owner cancellation.

use super::super::plan::MAX_STORAGE_DRAIN_NS;
use super::{
    HttpCameraDenial, HttpRecordingAccess, Owner, PublishCancellation, PublishCutPoint, STORAGE_CAPS,
};

pub(super) struct StorageLease<'owner, 'context> {
    owner: &'owner Owner<'context>,
    deadline: u64,
}

impl<'owner, 'context> StorageLease<'owner, 'context> {
    pub(super) fn new(
        owner: &'owner Owner<'context>,
        grace_ns: u64,
    ) -> Result<Self, HttpCameraDenial> {
        if grace_ns > MAX_STORAGE_DRAIN_NS {
            return Err(HttpCameraDenial::Deadline);
        }
        let deadline = owner
            .deadline
            .checked_add(grace_ns)
            .ok_or(HttpCameraDenial::Deadline)?;
        Ok(Self { owner, deadline })
    }

    /// A single absolute storage lease, established when the original owner clock starts.
    /// It is not restarted when a read, timeout, retry or publication is observed.
    fn now(&self) -> Result<u64, HttpCameraDenial> {
        self.owner
            .cx
            .checkpoint("capture_reconnect:storage_drain")
            .map_err(|_| HttpCameraDenial::Cancelled)?;
        if self.owner.authority.cancellation_reason.is_some() {
            return Err(HttpCameraDenial::Cancelled);
        }
        if !STORAGE_CAPS
            .iter()
            .all(|cap| self.owner.authority.has_capability(cap))
        {
            return Err(HttpCameraDenial::Unauthorized);
        }
        let now = self.owner.clock.now_ns().ok_or(HttpCameraDenial::Deadline)?;
        if now >= self.deadline {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(now)
    }

    pub(super) fn access(&self) -> Result<HttpRecordingAccess<'_>, HttpCameraDenial> {
        if self.deadline == self.owner.deadline {
            // No opt-in uses the original admission and cancellation path.
            return self.owner.access();
        }
        Ok(HttpRecordingAccess {
            now_ns: self.now()?,
            camera: self.owner, // unchanged network/decode lease and capabilities
            storage: self,
        })
    }

    pub(super) fn pause(&self, not_before: Option<u64>) -> Result<(), HttpCameraDenial> {
        if self.deadline == self.owner.deadline {
            return self.owner.pause(not_before);
        }
        let now = self.now()?;
        let left = self.owner.deadline.saturating_sub(now);
        if left == 0 {
            // Do not sleep on the storage grace. Let the native source observe its true,
            // expired network clock on the next bounded poll and retire held input.
            return Ok(());
        }
        match not_before {
            None => self.owner.clock.await_peer(left),
            Some(due) => self
                .owner
                .clock
                .sleep(due.saturating_sub(now).min(10_000_000).min(left)),
        }
        // Check cancellation, capabilities and the storage lease after every wait. In
        // particular, do not catch a generic Deadline denial: it can mean an unrepresentable
        // clock, not merely an expired network lease. Such a clock failure stays terminal.
        self.now().map(|_| ())
    }
}

impl PublishCancellation for StorageLease<'_, '_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.now().is_err()
    }
}
