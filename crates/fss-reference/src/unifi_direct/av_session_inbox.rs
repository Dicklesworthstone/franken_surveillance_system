#![forbid(unsafe_code)]
//! Bounded, in-memory session handoff for an asynchronous owner.
//!
//! This inbox does not persist data, grant retention or disclosure authority,
//! prove source coverage, or reserve operation IDs across process restarts.

use std::collections::VecDeque;

use fss_core::OperationId;

use super::{
    av_unknown_worker_guard::{
        Advance, Drive, SessionDecision, SessionEvent, SessionObserver, Step,
    },
    pipeline, recording, supervisor,
};

/// Invalid bounds, operation-ID namespace, or queue allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The requested bounds or operation-ID namespace are invalid.
    Configuration,
    /// The bounded event queue could not be allocated.
    Allocation,
}

/// Caller-owned events with a bound on their exact source payload lengths.
///
/// The namespace and initial sequence must be reserved uniquely by the caller;
/// this in-memory counter does not provide restart-safe effect idempotency.
#[must_use = "drain or explicitly account for every retained event"]
pub struct Inbox {
    events: VecDeque<(SessionEvent, usize)>,
    max_events: usize,
    source_bytes: usize,
    max_source_bytes: usize,
    operation_prefix: String,
    next_sequence: Option<u64>,
}

impl Inbox {
    /// Create an empty bounded inbox. At most 1,024 events and 64 MiB of
    /// source payload may be retained; metadata and allocation overhead are
    /// not included in the source-payload count.
    pub fn new(
        operation_prefix: &str,
        first_sequence: u64,
        max_events: usize,
        max_source_bytes: usize,
    ) -> Result<Self, Error> {
        if operation_prefix.is_empty()
            || operation_prefix.len() > 111
            || !(1..=1_024).contains(&max_events)
            || !(1..=64 * 1024 * 1024).contains(&max_source_bytes)
            || OperationId::parse(format!("{operation_prefix}:ffffffffffffffff")).is_err()
        {
            return Err(Error::Configuration);
        }
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(max_events)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            events,
            max_events,
            source_bytes: 0,
            max_source_bytes,
            operation_prefix: operation_prefix.to_owned(),
            next_sequence: Some(first_sequence),
        })
    }

    /// Number of retained events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether all accepted events have been transferred to the caller.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Exact sum of retained source payload lengths, excluding metadata.
    pub fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    /// Next unissued sequence, or `None` after the counter is exhausted.
    pub fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    /// Transfer the oldest complete event without performing I/O.
    pub fn take(&mut self) -> Option<SessionEvent> {
        let (event, bytes) = self.events.pop_front()?;
        self.source_bytes -= bytes;
        Some(event)
    }
}

impl SessionObserver for Inbox {
    fn next_operation(&mut self) -> Option<OperationId> {
        let sequence = self.next_sequence?;
        let operation =
            OperationId::parse(format!("{}:{sequence:016x}", self.operation_prefix)).ok()?;
        self.next_sequence = sequence.checked_add(1);
        Some(operation)
    }

    fn observe(&mut self, event: SessionEvent) -> Result<SessionDecision, SessionEvent> {
        let Some((bytes, important)) = event_size(&event) else {
            return Err(event);
        };
        let Some(total) = self.source_bytes.checked_add(bytes) else {
            return Err(event);
        };
        if self.events.len() == self.max_events || total > self.max_source_bytes {
            return Err(event);
        }
        self.source_bytes = total;
        self.events.push_back((event, bytes));
        Ok(if important || self.events.len() == self.max_events {
            SessionDecision::Yield
        } else {
            SessionDecision::Continue
        })
    }
}

fn supervisor_size(step: &supervisor::Step) -> Option<(usize, bool)> {
    match step {
        supervisor::Step::CameraEvent(frame) | supervisor::Step::StartupRequest(frame) => {
            Some((frame.source().len(), true))
        }
        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {
            record,
            ..
        })) => Some((record.bytes().len(), true)),
        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment))) => {
            let mut bytes = segment.fragment().bytes().len();
            for record in segment.source().iter().chain(segment.lookahead_copies()) {
                bytes = bytes.checked_add(record.bytes().len())?;
            }
            Some((bytes, true))
        }
        supervisor::Step::Media(
            pipeline::Step::Recording(recording::Push::Buffered) | pipeline::Step::Progress { .. },
        )
        | supervisor::Step::Observation(_)
        | supervisor::Step::Idle => Some((0, false)),
        supervisor::Step::TimeSyncWritten { .. } => Some((0, true)),
        _ => None,
    }
}

fn event_size(event: &SessionEvent) -> Option<(usize, bool)> {
    match event {
        SessionEvent::Audio(_) => Some((0, true)),
        SessionEvent::Advance(Advance::Source(Step::SourceQueued)) => Some((0, false)),
        SessionEvent::Advance(Advance::Source(Step::Supervisor(step))) => supervisor_size(step),
        SessionEvent::Advance(Advance::ArchiveStarted | Advance::Archive(Drive::Archive(_))) => {
            Some((0, true))
        }
        SessionEvent::Advance(Advance::Archive(Drive::Control { step, completion })) => {
            let (bytes, important) = supervisor_size(step)?;
            Some((bytes, important || completion.is_some()))
        }
        _ => None,
    }
}
