#![forbid(unsafe_code)]
//! Immutable historical source selection over the existing fully verified append chain.
//!
//! A source prefix can remain an input to an older reconstruction recipe after more
//! observations arrive. Selection never truncates storage, rewinds a writable owner,
//! includes later observations in the old interpretation, or weakens chain recovery.

use super::*;

/// Exact read-only input together with the full head observed while it was recovered.
///
/// The hidden archive contains only the selected metadata. The current namespace is
/// first completely recovered under independent limits; later originals are verified,
/// not silently ignored. No payload is cached here. Current reads still use the normal
/// root/metadata/payload verifier. Neither identity grants disclosure or proves EOF.
/// There is deliberately no mutable archive access or conversion to a writable owner.
#[derive(Debug)]
pub struct DatagramPrefix {
    archive: DatagramArchive,
    observed_head: DatagramPin,
}

impl DatagramPrefix {
    /// Verify the complete current source chain, then freeze the exact selected prefix.
    ///
    /// `selected` must match every field of an actual chain position, including byte
    /// count and root; a count alone is not a selection. The empty prefix must be the
    /// scope's exact empty identity. The resource and live cancellation capabilities
    /// cover the WHOLE current namespace, including descendants. Broken, missing,
    /// corrupt, tombstoned or unresolved later records therefore still refuse recovery.
    /// No repair, fallback, storage write, or source reacquisition is performed here.
    pub fn recover(
        publisher: &LocalRootPublisher,
        scope: DatagramScope,
        limits: DatagramArchiveLimits,
        selected: DatagramPin,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        limits.validate()?;
        if selected.scope != scope.digest()? || selected.head.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(DatagramArchiveError::Sequence);
        }
        if selected.datagrams > limits.max_datagrams as u64
            || selected.payload_bytes > limits.max_payload_bytes
        {
            return Err(DatagramArchiveError::Limit);
        }
        // Ordinary recovery proves all predecessor links, source bytes and the exact
        // selected position. It also rejects hidden holes and unresolved later writes.
        let mut archive =
            DatagramArchive::recover(publisher, scope, limits, Some(selected), cancel, budget)?;
        let observed_head = archive.pin();
        let count = usize::try_from(selected.datagrams).map_err(|_| DatagramArchiveError::Limit)?;
        // This consumes a freshly recovered private index, NEVER the live append owner.
        // No original payloads or root records are changed; only this read view is cut.
        archive.records.truncate(count);
        if archive.pin() != selected {
            return Err(DatagramArchiveError::Sequence);
        }
        probe(cancel)?;
        budget.charge(0)?;
        Ok(Self {
            archive,
            observed_head,
        })
    }

    /// Exactly selected original input. This remains fixed if the camera keeps recording.
    pub fn pin(&self) -> DatagramPin {
        self.archive.pin()
    }

    /// Complete source head verified AT RECOVERY, not a live pointer or selected input.
    /// Later observations are not added to recipe hashes, outputs or source-count claims.
    pub fn observed_head(&self) -> DatagramPin {
        self.observed_head
    }

    /// Existing read-only source APIs and native replay integration. No mutation escape.
    pub fn archive(&self) -> &DatagramArchive {
        &self.archive
    }

    /// Re-read and hash one selected observation. Access beyond this prefix is refused.
    pub fn read(
        &self,
        ordinal: u64,
        publisher: &LocalRootPublisher,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<RetainedDatagram> {
        self.archive.read(ordinal, publisher, cancel, budget)
    }

    /// Revalidate current full custody without changing the selected input or observed head.
    ///
    /// Growth is allowed only after the exact previously observed head. Rollback or a
    /// fork above the selected prefix is refused too: an old recipe is not permission
    /// to forget later work this owner has already seen. Returns the newly verified
    /// complete head; the caller must not relabel it as the recipe's input. This checks
    /// integrity, not authentication against replacement of all independently trusted pins.
    pub fn revalidate(
        &self,
        publisher: &LocalRootPublisher,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<DatagramPin> {
        let current = DatagramArchive::recover(
            publisher,
            self.archive.scope.clone(),
            self.archive.limits,
            Some(self.observed_head),
            cancel,
            budget,
        )?;
        let selected = self.pin();
        let found = if selected.datagrams == 0 {
            Some(current.empty)
        } else {
            usize::try_from(selected.datagrams - 1)
                .ok()
                .and_then(|index| current.records.get(index))
                .map(|record| record.pin)
        };
        if found != Some(selected) {
            return Err(DatagramArchiveError::Sequence);
        }
        probe(cancel)?;
        budget.charge(0)?;
        Ok(current.pin())
    }
}

#[cfg(test)]
mod tests;
