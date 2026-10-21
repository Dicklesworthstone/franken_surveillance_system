#![forbid(unsafe_code)]
//! Admission of reconstructed custody precedes any cold-recovery write.
//!
//! A valid journal prefix alone is not enough to admit a rebuilt disclosure catalog. In
//! particular, `Truncate` must not discard a torn append and then discover that the caller's
//! catalog weakens a persisted source binding or cannot restore its replay protection.

use super::*;
use crate::agent_session::work_claims::WorkClaimLimits;
use fss_ledger::{JournalError, RecoveryReport};

mod coordinated;

impl DurableDisclosureStore {
    /// Recovers a torn final append only after admitting the rebuilt catalog read-only.
    ///
    /// The independently supplied root, complete bounded session/disclosure/registration history,
    /// tail policy, source-custody requirements and cursor compatibility are checked before the
    /// recovery owner opens a writable file. Catalog refusal leaves the complete file, including
    /// its unfinished suffix, untouched. Missing sources may remain absent; a weaker reconstructed
    /// binding, cached H3 replacement or conflicting cursor cannot authorize truncation.
    ///
    /// The existing native recovery owner still rechecks the committed prefix on the descriptor
    /// it will trim, synchronizes it and verifies it again. This is not a filesystem transaction:
    /// an I/O failure or external mutation after admission can still require explicit inspection.
    /// Exclusive protected path ownership and an independently trusted root remain mandatory.
    /// No source reader is called, no session is charged and no response is redelivered here.
    /// Coordination history still requires the explicit coordinated entry point and its ceilings.
    pub fn recover_existing(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        policy: IncompleteTailPolicy,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<(Self, super::super::coordination::SessionRecoveryReceipt), DisclosureError> {
        recover_profile(path.as_ref(), expected_root, limits, None, policy, catalog)
    }
}

/// Both profiles use identical pre-write catalog admission. An absent claim ceiling is never
/// inferred from journal bytes; the legacy profile must continue rejecting coordination records.
fn recover_profile(
    path: &Path,
    expected_root: ContentDigest,
    limits: DurableSessionLimits,
    claim_ceilings: Option<WorkClaimLimits>,
    policy: IncompleteTailPolicy,
    mut catalog: ReferenceHydrationCatalog,
) -> Result<(DurableDisclosureStore, super::super::coordination::SessionRecoveryReceipt), DisclosureError> {
    let report = read_report(path, limits)?;
    if report.last_root() != expected_root {
        return Err(DurableSessionError::RootMismatch.into());
    }
    let _ = super::super::replay(&report, limits, claim_ceilings)?;
    if policy == IncompleteTailPolicy::Reject
        && let Some(offset) = report.incomplete_tail()
    {
        return Err(DurableSessionError::Journal(JournalError::IncompleteTail { offset }).into());
    }
    // Only caller-owned, not-yet-returned memory is changed here. All persisted source and
    // cursor requirements are admitted before any synchronization or truncation is requested.
    restore_catalog(&mut catalog, &report, limits, None)?;
    drop(report);
    let (sessions, receipt) = match claim_ceilings {
        Some(ceilings) => DurableSessionStore::recover_existing_with_coordination(
            path, expected_root, limits, ceilings, policy,
        )?,
        None => DurableSessionStore::recover_existing(path, expected_root, limits, policy)?,
    };
    let mut owner = DurableDisclosureStore { sessions, catalog };
    owner.synchronize_catalog(None)?;
    Ok((owner, receipt))
}

/// One reconstruction rule for live synchronization and pre-write cold admission. Callers own
/// journal verification and root checks. This helper neither opens files nor authenticates roots.
pub(super) fn restore_catalog(
    catalog: &mut ReferenceHydrationCatalog,
    report: &RecoveryReport,
    limits: DurableSessionLimits,
    now: Option<TimestampNs>,
) -> Result<(), DisclosureError> {
    let latest = report.records().iter().rev().find(|record| {
        record.kind() == SESSION_CHECKPOINT_RECORD_KIND
            && source_registration::has_catalog_snapshot(record.payload())
    });
    if let Some(record) = latest {
        let (cursors, observed_at) =
            source_registration::catalog_snapshot(record.payload(), limits)?;
        if now.is_some_and(|now| now < observed_at) {
            return Err(DisclosureError::Session(ReferenceSessionError::ClockRegression));
        }
        catalog.restore_cursor_checkpoint(cursors, MAX_RECORD_BYTES, observed_at)?;
    } else if catalog.issued_cursor_count() != 0 {
        return Err(HydrationError::WrongContinuation.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
