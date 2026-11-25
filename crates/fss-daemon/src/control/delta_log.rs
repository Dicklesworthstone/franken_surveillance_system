#![forbid(unsafe_code)]
//! Bounded live-summary history with explicit loss and commit-cursor truncation boundaries.
//!
//! Bus sequence numbers are local to one daemon lifetime. The public IPC v1 cursor contains
//! only a commit sequence, so it cannot represent a partially delivered same-commit group.
//! Such a split requires resnapshotting rather than a false clean continuation.

use std::collections::VecDeque;

use fss_core::ContentDigest;
use fss_ipc::StreamEndReason;

use super::MAX_DELTA_BUS_EVENTS;

#[derive(Clone, Debug)]
pub(super) struct BufferedDeltaEvent {
    pub(super) bus_seq: u64,
    pub(super) commit_sequence: u64,
    pub(super) delta_digest: ContentDigest,
    pub(super) summary_canonical: Vec<u8>,
}

/// In-process position of an attached subscriber; never serialized as a public cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DeltaBusCursor {
    bus_seq: u64,
    commit_sequence: u64,
}

impl DeltaBusCursor {
    pub(super) fn advance(&mut self, bus_seq: u64, commit_sequence: u64) {
        self.bus_seq = bus_seq;
        self.commit_sequence = self.commit_sequence.max(commit_sequence);
    }
}

pub(super) struct DeltaBusBatch {
    pub(super) events: Vec<BufferedDeltaEvent>,
    pub(super) end_reason: Option<StreamEndReason>,
}

/// All replay metadata is guarded by the same mutex as the retained summaries.
pub(super) struct BufferedDeltaLog {
    events: VecDeque<BufferedDeltaEvent>,
    // History from before startup is not retained in this ephemeral summary bus. Eviction
    // can only move this floor forward; a cursor at the floor is an exclusive lower bound.
    replay_floor_commit_sequence: u64,
    tail_bus_seq: u64,
    exhausted: bool,
}

impl BufferedDeltaLog {
    pub(super) fn new(initial_commit_sequence: u64) -> Self {
        Self {
            events: VecDeque::with_capacity(256),
            replay_floor_commit_sequence: initial_commit_sequence,
            tail_bus_seq: 0,
            exhausted: false,
        }
    }

    pub(super) fn push(
        &mut self,
        commit_sequence: u64,
        delta_digest: ContentDigest,
        summary_canonical: Vec<u8>,
    ) {
        let Some(bus_seq) = self.tail_bus_seq.checked_add(1) else {
            // Never wrap a subscriber's position back into an apparently valid history.
            self.exhausted = true;
            return;
        };
        if self.events.len() >= MAX_DELTA_BUS_EVENTS
            && let Some(evicted) = self.events.pop_front()
        {
            self.replay_floor_commit_sequence = self
                .replay_floor_commit_sequence
                .max(evicted.commit_sequence);
        }
        self.tail_bus_seq = bus_seq;
        self.events.push_back(BufferedDeltaEvent {
            bus_seq,
            commit_sequence,
            delta_digest,
            summary_canonical,
        });
    }

    /// Opens the commit-only cursor against this lifetime's retained summary history.
    ///
    /// The caller reads the published head while holding this log's mutex. Summary
    /// publications insert their event before advancing that head under the same mutex.
    /// Status snapshots may independently advance the ledger head for commits without
    /// a live summary; they do not establish a new replay floor.
    pub(super) fn start(
        &self,
        since_commit_sequence: u64,
        head_commit_sequence: u64,
    ) -> Result<DeltaBusCursor, StreamEndReason> {
        if self.exhausted
            || since_commit_sequence > head_commit_sequence
            || since_commit_sequence < self.replay_floor_commit_sequence
        {
            return Err(StreamEndReason::CursorStale);
        }
        let bus_seq = self
            .events
            .iter()
            .find(|event| event.commit_sequence > since_commit_sequence)
            .map_or(self.tail_bus_seq, |event| event.bus_seq - 1);
        Ok(DeltaBusCursor {
            bus_seq,
            commit_sequence: since_commit_sequence,
        })
    }

    /// Copies at most the remaining request allowance, refusing a gap before returning data.
    pub(super) fn read_after(
        &self,
        cursor: DeltaBusCursor,
        maximum: u32,
    ) -> Result<DeltaBusBatch, StreamEndReason> {
        self.check_cursor(cursor)?;
        let maximum = usize::try_from(maximum).unwrap_or(usize::MAX);
        if maximum == 0 {
            return Ok(DeltaBusBatch {
                events: Vec::new(),
                end_reason: Some(StreamEndReason::BatchLimitReached),
            });
        }
        let events: Vec<_> = self
            .events
            .iter()
            .filter(|event| event.bus_seq > cursor.bus_seq)
            .take(maximum)
            .cloned()
            .collect();
        let end_reason = if events.len() == maximum {
            let mut end_cursor = cursor;
            for event in &events {
                end_cursor.advance(event.bus_seq, event.commit_sequence);
            }
            Some(self.finish(end_cursor, StreamEndReason::BatchLimitReached))
        } else {
            None
        };
        Ok(DeltaBusBatch { events, end_reason })
    }

    /// Rechecks continuation after socket writes, which may have allowed new publications
    /// or eviction while the subscriber delivered its previously copied batch.
    pub(super) fn finish(
        &self,
        cursor: DeltaBusCursor,
        clean_reason: StreamEndReason,
    ) -> StreamEndReason {
        // A v1 continuation cannot name any unreturned event at or below the greatest
        // commit already emitted. Check all remaining rows, including reordered commits.
        if self.check_cursor(cursor).is_err()
            || self.events.iter().any(|event| {
                event.bus_seq > cursor.bus_seq && event.commit_sequence <= cursor.commit_sequence
            })
        {
            StreamEndReason::CursorStale
        } else {
            clean_reason
        }
    }

    pub(super) fn has_pending(&self, cursor: DeltaBusCursor) -> Result<bool, StreamEndReason> {
        self.check_cursor(cursor)?;
        Ok(self.tail_bus_seq > cursor.bus_seq)
    }

    fn check_cursor(&self, cursor: DeltaBusCursor) -> Result<(), StreamEndReason> {
        if self.exhausted
            || cursor.bus_seq > self.tail_bus_seq
            || self.events.front().is_some_and(|first| {
                // Subtraction is safe: bus identities start at one and never wrap.
                cursor.bus_seq < first.bus_seq - 1
            })
        {
            return Err(StreamEndReason::CursorStale);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../control_delta_tests.rs"]
mod tests;
