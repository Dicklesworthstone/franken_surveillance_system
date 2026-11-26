#![forbid(unsafe_code)]
//! Validate a projection before canonical commitment, retaining its exact writer ownership
//! until the already-computed successor is published.

use std::sync::{Arc, MutexGuard};

use fss_core::EvidenceDeltaBatch;

use super::recovery::advance_snapshot_in_place;
use super::{MvccProjectionStore, MvccWriterState};
use crate::error::ProjectionError;
use crate::payloads::PayloadResolver;
use crate::schema::ProjectionAnchor;
use crate::snapshot::ProjectionSnapshot;
use crate::wal::{PreparedWalBatch, write_snapshot_atomic};

/// Internal preparation owns the writer lock across ledger commitment. Dropping it before
/// publication performs no projection write and makes no candidate visible to readers.
pub(crate) struct PreparedProjectionBatch<'a> {
    store: &'a MvccProjectionStore,
    wal_batch: PreparedWalBatch,
    writer: MutexGuard<'a, MvccWriterState>,
    next: Arc<ProjectionSnapshot>,
}

impl MvccProjectionStore {
    pub(crate) fn prepare_delta_batch<'a>(
        &'a self,
        batch: &EvidenceDeltaBatch,
        payload_resolver: &dyn PayloadResolver,
    ) -> Result<PreparedProjectionBatch<'a>, ProjectionError> {
        let writer = self
            .writer
            .lock()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        let current = {
            let guard = self
                .read_state
                .read()
                .map_err(|_| ProjectionError::LockPoisoned)?;
            Arc::clone(&guard.latest)
        };
        let mut next = (*current).clone();
        advance_snapshot_in_place(&mut next, batch, payload_resolver)?;
        let wal_batch = PreparedWalBatch::encode(batch)?;
        Ok(PreparedProjectionBatch {
            store: self,
            wal_batch,
            writer,
            next: Arc::new(next),
        })
    }
}

impl PreparedProjectionBatch<'_> {
    pub(crate) fn publish(mut self) -> Result<ProjectionAnchor, ProjectionError> {
        self.writer.wal.append_prepared_batch(&self.wal_batch)?;
        let anchor = self.next.anchor;
        {
            let mut guard = self
                .store
                .read_state
                .write()
                .map_err(|_| ProjectionError::LockPoisoned)?;
            guard.publish(Arc::clone(&self.next));
        }

        if self.writer.config.snapshot_stride > 0
            && self.writer.wal.frames_written() >= self.writer.config.snapshot_stride
        {
            let maintenance =
                write_snapshot_atomic(&self.writer.dir, &self.next, self.writer.config.durability)
                    .and_then(|_| self.writer.wal.reset_empty());
            if let Err(source) = maintenance {
                // The new head and WAL are already published. Never turn an optional
                // compaction failure into permission to repeat the canonical mutation.
                return Err(ProjectionError::AppliedMaintenanceFailed {
                    anchor,
                    source: Box::new(source),
                });
            }
        }
        Ok(anchor)
    }
}
