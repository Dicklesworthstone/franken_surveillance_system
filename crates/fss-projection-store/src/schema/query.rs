#![forbid(unsafe_code)]
//! Query filters, cursors, and paginated anchor-pinned responses for [`crate::ProjectionStore`].

use fss_core::{ContentDigest, EventId, EventKind, EventState, SensorId, StreamId};

use crate::error::ProjectionError;
use crate::schema::{
    FollowCommitSummary, FootageAdapterKind, ProjectedEventSummary, ProjectedFootageImport,
    ProjectionAnchor,
};

/// Conjunctive query predicates over materialized latest events.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventQueryFilter {
    /// Exact event identity filter.
    pub event_id: Option<EventId>,
    /// Exact lifecycle state filter.
    pub state: Option<EventState>,
    /// Exact event kind filter.
    pub kind: Option<EventKind>,
    /// Exact spatial zone membership filter.
    pub zone: Option<String>,
    /// Exact sensor membership filter.
    pub sensor_id: Option<SensorId>,
    /// Inclusive lower bound for closed-interval overlap (`event.interval.latest >= from_ns`).
    pub from_ns: Option<i128>,
    /// Inclusive upper bound for closed-interval overlap (`event.interval.earliest <= through_ns`).
    pub through_ns: Option<i128>,
    /// If `Some(true)`, match only tampered events; if `Some(false)`, exclude tampered events.
    pub tamper_open: Option<bool>,
    /// Exclusive lower cursor (`event_id > cursor`) for deterministic pagination.
    pub after_event_id: Option<EventId>,
}

impl EventQueryFilter {
    /// Rejects inverted time ranges before touching indexes.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self
            .from_ns
            .zip(self.through_ns)
            .is_some_and(|(from, through)| from > through)
        {
            return Err(ProjectionError::InvalidRequest(
                "inverted event query time interval",
            ));
        }
        Ok(())
    }

    /// Evaluates every predicate against `event`.
    #[must_use]
    pub fn matches(&self, event: &ProjectedEventSummary) -> bool {
        self.event_id
            .as_ref()
            .is_none_or(|id| id == &event.event_id)
            && self.state.is_none_or(|s| s == event.state)
            && self.kind.is_none_or(|k| k == event.kind)
            && self
                .zone
                .as_ref()
                .is_none_or(|z| event.zones.binary_search(z).is_ok())
            && self
                .sensor_id
                .as_ref()
                .is_none_or(|s| event.sensor_ids.binary_search(s).is_ok())
            && self.from_ns.is_none_or(|t| event.interval.latest.0 >= t)
            && self
                .through_ns
                .is_none_or(|t| event.interval.earliest.0 <= t)
            && self
                .tamper_open
                .is_none_or(|flag| flag == event.tamper_open)
            && self
                .after_event_id
                .as_ref()
                .is_none_or(|cursor| &event.event_id > cursor)
    }
}

/// Paginated event query response pinned to one [`ProjectionAnchor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQueryPage {
    /// Exact anchor of the snapshot that answered this query.
    pub anchor: ProjectionAnchor,
    /// Matching events in strictly increasing `event_id` order.
    pub entries: Vec<ProjectedEventSummary>,
    /// True when more matching events exist past this page.
    pub has_more: bool,
    /// Cursor (`last.event_id`) to pass as `after_event_id` for the next page.
    pub next_cursor: Option<EventId>,
}

/// Exact continuation cursor matching the canonical footage range index order
/// `(sensor_id, stream_id, start_ns, end_ns, import_id)`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FootageRangeCursor {
    /// Originating sensor identity.
    pub sensor_id: SensorId,
    /// Logical stream generation identity.
    pub stream_id: StreamId,
    /// Inclusive lower capture timestamp (`capture_interval.earliest.0`).
    pub start_ns: i128,
    /// Inclusive upper capture timestamp (`capture_interval.latest.0`).
    pub end_ns: i128,
    /// Stable import content digest.
    pub import_id: ContentDigest,
}

impl FootageRangeCursor {
    /// Derives the canonical range cursor from a projected footage import.
    #[must_use]
    pub fn from_import(import: &ProjectedFootageImport) -> Self {
        Self {
            sensor_id: import.sensor_id.clone(),
            stream_id: import.stream_id.clone(),
            start_ns: import.capture_interval.earliest.0,
            end_ns: import.capture_interval.latest.0,
            import_id: import.import_id,
        }
    }
}

/// Conjunctive query predicates over unified RTSP/HTTP/File/TUTK footage imports.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FootageQueryFilter {
    /// Exact sensor identity filter.
    pub sensor: Option<SensorId>,
    /// Exact stream generation filter.
    pub stream: Option<StreamId>,
    /// Exact adapter protocol family filter (`Rtsp`, `Http`, `File`, `Tutk`).
    pub adapter_kind: Option<FootageAdapterKind>,
    /// Inclusive lower bound for closed-interval overlap (`import.capture_interval.latest >= from_ns`).
    pub from_ns: Option<i128>,
    /// Inclusive upper bound for closed-interval overlap (`import.capture_interval.earliest <= through_ns`).
    pub through_ns: Option<i128>,
    /// When true, include only imports that reached completion.
    pub completed_only: bool,
    /// Exclusive lower cursor in canonical range order for deterministic pagination.
    pub after_cursor: Option<FootageRangeCursor>,
}

impl FootageQueryFilter {
    /// Rejects inverted time ranges before touching indexes.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self
            .from_ns
            .zip(self.through_ns)
            .is_some_and(|(from, through)| from > through)
        {
            return Err(ProjectionError::InvalidRequest(
                "inverted footage query time interval",
            ));
        }
        Ok(())
    }

    /// Evaluates every predicate against `import`.
    #[must_use]
    pub fn matches(&self, import: &ProjectedFootageImport) -> bool {
        self.sensor.as_ref().is_none_or(|s| s == &import.sensor_id)
            && self.stream.as_ref().is_none_or(|s| s == &import.stream_id)
            && self.adapter_kind.is_none_or(|k| k == import.adapter_kind)
            && self
                .from_ns
                .is_none_or(|t| import.capture_interval.latest.0 >= t)
            && self
                .through_ns
                .is_none_or(|t| import.capture_interval.earliest.0 <= t)
            && (!self.completed_only || import.completed)
            && self
                .after_cursor
                .as_ref()
                .is_none_or(|cursor| FootageRangeCursor::from_import(import) > *cursor)
    }
}

/// Paginated unified footage import response pinned to one [`ProjectionAnchor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FootageQueryPage {
    /// Exact anchor of the snapshot that answered this query.
    pub anchor: ProjectionAnchor,
    /// Matching footage imports in canonical `(sensor_id, stream_id, start_ns, end_ns, import_id)` order.
    pub entries: Vec<ProjectedFootageImport>,
    /// True when more matching imports exist past this page.
    pub has_more: bool,
    /// Cursor for deterministic continuation to the next page.
    pub next_cursor: Option<FootageRangeCursor>,
}

/// Result of an `O(delta)` `follow_since(after_sequence, max_entries)` scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowDeltaPage {
    /// Store head anchor observed for this follow read.
    pub head_anchor: ProjectionAnchor,
    /// Exclusive lower sequence requested by the caller.
    pub after_sequence: u64,
    /// Per-commit summaries in strictly increasing `commit_sequence` order.
    pub commits: Vec<FollowCommitSummary>,
    /// True when additional commits exist beyond the returned slice.
    pub has_more: bool,
    /// Highest `commit_sequence` returned (`after_sequence` when `commits` is empty).
    pub next_after_sequence: u64,
}
