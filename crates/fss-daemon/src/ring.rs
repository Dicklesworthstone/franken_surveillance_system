#![forbid(unsafe_code)]
//! Bounded per-camera fan-out ring buffer with explicit deterministic backpressure shedding
//! and multi-consumer cursors (zero unbounded RAM growth).
//!
//! Semantic plane: `"support"`.
//!
//! One upstream camera stream enqueues each immutable `Arc<T>` frame ONCE into a
//! [`BoundedFrameRing`]. Independent consumers (`ingest`, `perception`, `live_preview`) advance
//! their own [`RingConsumerCursor`] without duplicating pixel buffers or opening additional
//! camera connections. When a slow consumer or disk backpressure fills the ring beyond
//! `max_frames` or `max_bytes`, oldest frames are deterministically evicted and accounted for
//! in explicit `dropped_frames`, `dropped_bytes`, and [`ResourcePressure`] signals.

use std::collections::VecDeque;
use std::sync::Arc;

use fss_core::ResourcePressure;

use crate::error::DaemonError;

/// Trait supplying exact memory accounting bytes for items stored in [`BoundedFrameRing`].
pub trait RingMetered {
    /// Returns the accounted in-memory byte footprint of this frame (encoded + decoded buffers).
    fn ring_bytes(&self) -> usize;
    /// Returns the strictly increasing per-generation sequence number of this frame.
    fn frame_sequence(&self) -> u64;
}

/// Independent consumer cursor reading from a shared [`BoundedFrameRing`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RingConsumerCursor {
    /// Stream generation currently being consumed.
    pub generation: u64,
    /// Next expected per-generation frame sequence number (`1`-based).
    pub next_sequence: u64,
    /// Cumulative frames skipped due to ring backpressure shedding ahead of this consumer.
    pub lagged_frames: u64,
}

impl RingConsumerCursor {
    /// Creates a new cursor positioned at the start of `generation`.
    #[must_use]
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            next_sequence: 1,
            lagged_frames: 0,
        }
    }

    /// Resets the cursor to a newly opened stream generation without bridging prior gaps.
    pub fn reset_for_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.next_sequence = 1;
    }
}

/// Outcome emitted on every [`BoundedFrameRing::push`] operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingPushOutcome {
    /// True if the new frame was retained in the ring; false if it alone exceeded `max_bytes`.
    pub admitted: bool,
    /// Number of oldest frames shed to satisfy `max_frames` or `max_bytes`.
    pub shed_frames: u64,
    /// Total accounted bytes evicted by shedding.
    pub shed_bytes: u64,
    /// Current ring pressure classification after the push.
    pub pressure: ResourcePressure,
    /// Current retained frame count after the push.
    pub queue_depth: usize,
    /// Current retained memory bytes after the push.
    pub current_bytes: usize,
}

/// Explicit consumer lag gap observed when the ring shed frames faster than a consumer drained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerLagGap {
    /// First missing sequence number (inclusive).
    pub from_sequence: u64,
    /// Last missing sequence number (inclusive).
    pub to_sequence: u64,
    /// Number of frames missing before the returned batch.
    pub skipped_frames: u64,
}

/// Point-in-time accounting snapshot of one camera's [`BoundedFrameRing`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingStats {
    /// Active stream generation.
    pub generation: u64,
    /// Configured maximum retained frame count.
    pub max_frames: usize,
    /// Configured maximum retained byte ceiling.
    pub max_bytes: usize,
    /// Currently retained frame count.
    pub current_frames: usize,
    /// Currently retained byte footprint.
    pub current_bytes: usize,
    /// High-water retained frame count observed across the ring's lifetime.
    pub peak_frames: usize,
    /// High-water retained byte footprint observed across the ring's lifetime.
    pub peak_bytes: usize,
    /// Cumulative frames admitted into the ring.
    pub total_enqueued: u64,
    /// Cumulative frames shed due to capacity backpressure.
    pub dropped_frames: u64,
    /// Cumulative bytes shed due to capacity backpressure.
    pub dropped_bytes: u64,
    /// Current ring pressure classification.
    pub pressure: ResourcePressure,
}

#[derive(Debug)]
struct RingEntry<T> {
    generation: u64,
    sequence: u64,
    bytes: usize,
    item: Arc<T>,
}

/// Strictly bounded per-camera frame ring buffer shared across multiple zero-copy consumers.
#[derive(Debug)]
pub struct BoundedFrameRing<T: RingMetered> {
    max_frames: usize,
    max_bytes: usize,
    generation: u64,
    entries: VecDeque<RingEntry<T>>,
    last_admitted: Option<(u64, Arc<T>)>,
    current_bytes: usize,
    peak_frames: usize,
    peak_bytes: usize,
    total_enqueued: u64,
    dropped_frames: u64,
    dropped_bytes: u64,
}

impl<T: RingMetered> BoundedFrameRing<T> {
    /// Constructs a validated bounded ring enforcing both `max_frames` and `max_bytes`.
    pub fn new(max_frames: usize, max_bytes: usize) -> Result<Self, DaemonError> {
        if max_frames == 0 {
            return Err(DaemonError::InvalidConfig {
                detail: "ring max_frames must be >= 1".to_owned(),
            });
        }
        if max_bytes == 0 {
            return Err(DaemonError::InvalidConfig {
                detail: "ring max_bytes must be >= 1".to_owned(),
            });
        }
        Ok(Self {
            max_frames,
            max_bytes,
            generation: 1,
            entries: VecDeque::with_capacity(max_frames.min(256)),
            last_admitted: None,
            current_bytes: 0,
            peak_frames: 0,
            peak_bytes: 0,
            total_enqueued: 0,
            dropped_frames: 0,
            dropped_bytes: 0,
        })
    }

    /// Starts a fresh stream generation, clearing any buffered frames from the prior generation
    /// without bridging gaps.
    pub fn start_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.entries.clear();
        self.last_admitted = None;
        self.current_bytes = 0;
    }

    /// Enqueues a single frame while strictly maintaining `len <= max_frames` and
    /// `current_bytes <= max_bytes`.
    ///
    /// If the ring is full, oldest frames are deterministically evicted and counted in
    /// `dropped_frames` / `dropped_bytes`. If the single incoming frame itself exceeds
    /// `max_bytes`, it is shed immediately rather than growing heap memory past the bound.
    pub fn push(&mut self, item: Arc<T>) -> RingPushOutcome {
        let frame_bytes = item.ring_bytes().max(1);
        if frame_bytes > self.max_bytes {
            self.dropped_frames = self.dropped_frames.saturating_add(1);
            self.dropped_bytes = self.dropped_bytes.saturating_add(frame_bytes as u64);
            return RingPushOutcome {
                admitted: false,
                shed_frames: 1,
                shed_bytes: frame_bytes as u64,
                pressure: ResourcePressure::Critical,
                queue_depth: self.entries.len(),
                current_bytes: self.current_bytes,
            };
        }

        let mut shed_frames = 0_u64;
        let mut shed_bytes = 0_u64;
        while self.entries.len() >= self.max_frames
            || self.current_bytes.saturating_add(frame_bytes) > self.max_bytes
        {
            if let Some(evicted) = self.entries.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(evicted.bytes);
                self.dropped_frames = self.dropped_frames.saturating_add(1);
                self.dropped_bytes = self.dropped_bytes.saturating_add(evicted.bytes as u64);
                shed_frames = shed_frames.saturating_add(1);
                shed_bytes = shed_bytes.saturating_add(evicted.bytes as u64);
            } else {
                break;
            }
        }

        let seq = item.frame_sequence();
        self.last_admitted = Some((self.generation, Arc::clone(&item)));
        self.entries.push_back(RingEntry {
            generation: self.generation,
            sequence: seq,
            bytes: frame_bytes,
            item,
        });
        self.current_bytes = self.current_bytes.saturating_add(frame_bytes);
        self.total_enqueued = self.total_enqueued.saturating_add(1);
        self.peak_frames = self.peak_frames.max(self.entries.len());
        self.peak_bytes = self.peak_bytes.max(self.current_bytes);

        let pressure = if shed_frames > 0 {
            self.classify_pressure().max(ResourcePressure::Constrained)
        } else {
            self.classify_pressure()
        };

        RingPushOutcome {
            admitted: true,
            shed_frames,
            shed_bytes,
            pressure,
            queue_depth: self.entries.len(),
            current_bytes: self.current_bytes,
        }
    }

    /// Reads up to `max_items` unread frames for `cursor`, advancing `cursor.next_sequence` and
    /// surfacing an explicit [`ConsumerLagGap`] whenever shedding skipped frames ahead of `cursor`.
    pub fn read_for_cursor(
        &self,
        cursor: &mut RingConsumerCursor,
        max_items: usize,
    ) -> (Vec<Arc<T>>, Option<ConsumerLagGap>) {
        if cursor.generation != self.generation {
            cursor.reset_for_generation(self.generation);
        }
        if max_items == 0 || self.entries.is_empty() {
            return (Vec::new(), None);
        }

        let mut gap: Option<ConsumerLagGap> = None;
        if let Some(oldest) = self.entries.front()
            && oldest.generation == self.generation
            && oldest.sequence > cursor.next_sequence
        {
            let skipped = oldest.sequence.saturating_sub(cursor.next_sequence);
            gap = Some(ConsumerLagGap {
                from_sequence: cursor.next_sequence,
                to_sequence: oldest.sequence.saturating_sub(1),
                skipped_frames: skipped,
            });
            cursor.lagged_frames = cursor.lagged_frames.saturating_add(skipped);
            cursor.next_sequence = oldest.sequence;
        }

        let mut out = Vec::new();
        for entry in &self.entries {
            if out.len() >= max_items {
                break;
            }
            if entry.generation == self.generation && entry.sequence >= cursor.next_sequence {
                out.push(Arc::clone(&entry.item));
                cursor.next_sequence = entry.sequence.saturating_add(1);
            }
        }
        (out, gap)
    }

    /// Reclaims oldest frames already consumed past `min_consumer_next_seq` so steady-state
    /// memory stays minimal while unconsumed frames remain bounded under backpressure.
    pub fn reclaim_consumed_before(&mut self, min_consumer_next_seq: u64) -> usize {
        let mut reclaimed = 0_usize;
        while let Some(front) = self.entries.front() {
            if front.generation == self.generation && front.sequence < min_consumer_next_seq {
                if let Some(evicted) = self.entries.pop_front() {
                    self.current_bytes = self.current_bytes.saturating_sub(evicted.bytes);
                    reclaimed += 1;
                }
            } else {
                break;
            }
        }
        reclaimed
    }

    /// Returns the most recently admitted frame in the current generation, if any.
    #[must_use]
    pub fn latest(&self) -> Option<Arc<T>> {
        self.last_admitted
            .as_ref()
            .filter(|(g, _)| *g == self.generation)
            .map(|(_, item)| Arc::clone(item))
    }

    /// Returns the current retained frame count (`<= max_frames`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the ring holds zero frames.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns current retained byte footprint (`<= max_bytes`).
    #[must_use]
    pub const fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Returns the current ring pressure classification based on frame and byte occupancy.
    #[must_use]
    pub fn classify_pressure(&self) -> ResourcePressure {
        let frame_pct = (self.entries.len().saturating_mul(100)) / self.max_frames.max(1);
        let byte_pct = (self.current_bytes.saturating_mul(100)) / self.max_bytes.max(1);
        let max_pct = frame_pct.max(byte_pct);
        if max_pct >= 95 {
            ResourcePressure::Critical
        } else if max_pct >= 80 {
            ResourcePressure::Constrained
        } else if max_pct >= 50 {
            ResourcePressure::Elevated
        } else {
            ResourcePressure::Nominal
        }
    }

    /// Returns a point-in-time [`RingStats`] snapshot.
    #[must_use]
    pub fn stats(&self) -> RingStats {
        RingStats {
            generation: self.generation,
            max_frames: self.max_frames,
            max_bytes: self.max_bytes,
            current_frames: self.entries.len(),
            current_bytes: self.current_bytes,
            peak_frames: self.peak_frames,
            peak_bytes: self.peak_bytes,
            total_enqueued: self.total_enqueued,
            dropped_frames: self.dropped_frames,
            dropped_bytes: self.dropped_bytes,
            pressure: self.classify_pressure(),
        }
    }
}
