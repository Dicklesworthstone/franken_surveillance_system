#![forbid(unsafe_code)]
//! One non-refillable allowance for indexed object reads through an open spool owner.

use std::sync::atomic::{AtomicU64, Ordering};

use super::SpoolError;

/// Cumulative indexed-read admission since this owner's first explicit read cap.
///
/// Bytes are conservative reservations for stored object envelopes, including the header and
/// one trailing-byte probe. They are never refunded, even if an admitted read fails. Opening
/// recovery, directory scans, metadata and open syscalls, and non-indexed staging writes are
/// outside this allowance. `None` means no cap has been installed and accounting is inactive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpoolReadBudgetUsage {
    /// Reserved stored-envelope read bytes, including failed admitted reads.
    pub used_bytes: u64,
    /// Admitted indexed-read attempts, including missing/corrupt object refusals.
    pub used_read_attempts: u64,
    /// Remaining stored-envelope byte allowance; `None` before explicit admission.
    pub remaining_bytes: Option<u64>,
    /// Remaining indexed-read attempts; `None` before explicit admission.
    pub remaining_read_attempts: Option<u64>,
}

#[derive(Debug, Default)]
pub(super) struct ReadBudget {
    bytes: Option<u64>,
    attempts: Option<u64>,
    used_bytes: AtomicU64,
    used_attempts: AtomicU64,
}

impl ReadBudget {
    pub(super) fn tighten(
        &mut self,
        bytes: u64,
        attempts: u64,
    ) -> Result<SpoolReadBudgetUsage, SpoolError> {
        self.bytes = Some(self.bytes.map_or(bytes, |old| old.min(bytes)));
        self.attempts = Some(self.attempts.map_or(attempts, |old| old.min(attempts)));
        // A bound below work already admitted is still installed, so a failed tightening
        // cannot accidentally restore or refill an earlier allowance.
        self.reserve_bytes(0)?;
        reserve(
            &self.used_attempts,
            self.attempts,
            0,
            "indexed_read_attempts",
        )?;
        Ok(self.usage())
    }

    pub(super) fn usage(&self) -> SpoolReadBudgetUsage {
        let used_bytes = self.used_bytes.load(Ordering::Relaxed);
        let used_read_attempts = self.used_attempts.load(Ordering::Relaxed);
        SpoolReadBudgetUsage {
            used_bytes,
            used_read_attempts,
            remaining_bytes: self.bytes.map(|n| n.saturating_sub(used_bytes)),
            remaining_read_attempts: self.attempts.map(|n| n.saturating_sub(used_read_attempts)),
        }
    }

    pub(super) fn is_capped(&self) -> bool {
        self.bytes.is_some()
    }

    pub(super) fn attempt(&self) -> Result<(), SpoolError> {
        reserve(
            &self.used_attempts,
            self.attempts,
            1,
            "indexed_read_attempts",
        )
    }

    pub(super) fn reserve_bytes(&self, bytes: u64) -> Result<(), SpoolError> {
        reserve(
            &self.used_bytes,
            self.bytes,
            bytes,
            "stored_object_read_bytes",
        )
    }
}

fn reserve(
    used: &AtomicU64,
    maximum: Option<u64>,
    requested: u64,
    resource: &'static str,
) -> Result<(), SpoolError> {
    let Some(maximum) = maximum else {
        return Ok(());
    };
    used.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current
            .checked_add(requested)
            .filter(|next| *next <= maximum)
    })
    .map(|_| ())
    .map_err(|current| SpoolError::ReadBudgetExceeded {
        resource,
        current,
        requested,
        maximum,
    })
}
