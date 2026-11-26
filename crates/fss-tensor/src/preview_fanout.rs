#![forbid(unsafe_code)]
//! Deterministic live preview bounded fan-out (`FSS-057`, bead `fss-x4a.12.6`).
//!
//! Distributes zero-copy immutable [`FrameLease`]s from a [`FramePool`] (`FSS-119`) to a bounded
//! set of authorized live-preview subscribers under explicit queue caps, drop-oldest-unviewed
//! backpressure, [`MediaDegradationRung`] (`FSS-121`) cadence decimation, privacy-mask egress
//! enforcement, and strict generation fencing (`INV-010`, `INV-041`, `INV-043`).
//!
//! Core invariants:
//! - Slow or stalled preview viewers NEVER block raw source custody recording or leak frame-pool
//!   leases: when a viewer's bounded queue is full, the oldest unviewed lease is deterministically
//!   released back to the [`FramePool`] and counted in `dropped_frames`.
//! - Privacy-restricted viewers (`requires_privacy_masked = true`) NEVER receive an unmasked
//!   frame (refused/counted explicitly as `privacy_filtered_frames`, never silently exposed).
//! - Under `MediaDegradationRung::Rung4PauseDerivedCognition` or `Rung5EmergencySourceBackpressure`,
//!   live preview fan-out pauses explicitly (`preview_stride == 0`) and records `pressure_shed_frames`.
//! - Zero `unsafe`, zero global locks/singletons, deterministic sans-IO, canonical receipts, and
//!   cooperative cancellation before mutating subscriber queues.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::buffer_accounting::MAX_OWNER_ID_BYTES;
use crate::frame_pool::{FrameLease, FramePool, FramePoolError, FrameSlotId};
use crate::media_pressure::MediaDegradationRung;

/// Registered digest domain for canonical live-preview fan-out receipts
/// (`SCHEMA-DOMAIN-TENSOR-PREVIEW-FANOUT-001`).
pub const PREVIEW_FANOUT_RECEIPT_DOMAIN: &str = "fss.tensor.preview_fanout_receipt.v1";

/// Canonical binary format version for [`PreviewFanoutReceipt`].
pub const PREVIEW_FANOUT_FORMAT_VERSION: u32 = 1;

/// Maximum subscribers configurable on one fan-out hub.
pub const MAX_PREVIEW_SUBSCRIBERS: usize = 64;

/// Maximum queued unread frame leases configurable per subscriber.
pub const MAX_SUBSCRIBER_QUEUE_DEPTH: usize = 32;

/// Hard policy governing one [`PreviewFanoutHub`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewFanoutPolicy {
    /// Clean non-empty stream/hub identifier.
    pub stream_id: String,
    /// Hard ceiling on simultaneous preview subscribers (`1..=64`).
    pub max_subscribers: usize,
    /// Hard ceiling on queued unread leases per subscriber (`1..=32`).
    pub max_queue_depth: usize,
    /// Active pinned stream generation (`!= 0`).
    pub active_generation: Generation,
}

impl PreviewFanoutPolicy {
    /// Bounded default policy for `stream_id`.
    #[must_use]
    pub fn bounded_default(stream_id: impl Into<String>, active_generation: Generation) -> Self {
        Self {
            stream_id: stream_id.into(),
            max_subscribers: 8,
            max_queue_depth: 4,
            active_generation,
        }
    }

    /// Fails closed on empty/malformed IDs, zero caps, or zero generation.
    pub fn validate(&self) -> Result<(), PreviewFanoutError> {
        if self.stream_id.is_empty()
            || self.stream_id.len() > MAX_OWNER_ID_BYTES
            || self
                .stream_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(PreviewFanoutError::InvalidPolicy);
        }
        if self.max_subscribers == 0
            || self.max_subscribers > MAX_PREVIEW_SUBSCRIBERS
            || self.max_queue_depth == 0
            || self.max_queue_depth > MAX_SUBSCRIBER_QUEUE_DEPTH
            || self.active_generation.0 == 0
        {
            return Err(PreviewFanoutError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Explicit viewer authorization and privacy projection scope for one preview subscriber.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewSubscriberSpec {
    /// Clean non-empty subscriber identifier.
    pub subscriber_id: String,
    /// Viewer priority tier (`0` = highest priority operator, larger = lower priority).
    pub priority_tier: u8,
    /// If `true`, viewer is strictly restricted to privacy-masked frames only.
    pub requires_privacy_masked: bool,
    /// Explicit authority grant digest authorizing live preview egress.
    pub authority_grant_digest: ContentDigest,
}

/// Typed offer describing one pooled frame slot submitted for live preview fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreviewFrameOffer {
    /// Pooled frame slot holding the immutable decoded pixels.
    pub slot_id: FrameSlotId,
    /// Generation fence pinned to the frame slot.
    pub generation: Generation,
    /// Whether privacy masking has already been applied to this frame.
    pub frame_is_privacy_masked: bool,
    /// Current active media degradation rung controlling preview cadence/shedding.
    pub rung: MediaDegradationRung,
    /// Monotonic observation timestamp in nanoseconds.
    pub now_ns: TimestampNs,
}

/// Outcome of publishing one pooled frame across all active preview subscribers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FanoutPublishOutcome {
    /// Number of subscribers that received a zero-copy [`FrameLease`].
    pub delivered_count: usize,
    /// Number of older unviewed leases evicted/returned to [`FramePool`] due to full queues.
    pub evicted_oldest_count: usize,
    /// Number of subscribers skipped because frame lacked required privacy masking.
    pub privacy_filtered_count: usize,
    /// Number of subscribers skipped due to pressure ladder stride/pause shedding.
    pub pressure_shed_count: usize,
    /// Number of subscribers skipped because the frame slot hit `max_leases_per_frame`.
    pub lease_cap_skipped_count: usize,
}

/// Typed fail-closed refusal for live preview fan-out operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviewFanoutError {
    /// Policy bounds or stream identity are invalid.
    InvalidPolicy,
    /// Subscriber identifier is malformed.
    InvalidSubscriberId,
    /// Subscriber with this ID is already registered.
    DuplicateSubscriber(String),
    /// Subscriber count ceiling reached.
    SubscriberCapExceeded {
        /// Current count.
        active: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Referenced subscriber is not registered.
    UnknownSubscriber(String),
    /// Frame or generation disagrees with hub's active generation fence.
    StaleGeneration {
        /// Active generation.
        expected: Generation,
        /// Supplied generation.
        actual: Generation,
    },
    /// Underlying frame pool refused an operation.
    Pool(FramePoolError),
    /// Cooperative cancellation observed before mutating queues.
    Cancelled,
}

impl fmt::Display for PreviewFanoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid live preview fan-out policy"),
            Self::InvalidSubscriberId => write!(f, "invalid preview subscriber identifier"),
            Self::DuplicateSubscriber(id) => write!(f, "duplicate preview subscriber '{id}'"),
            Self::SubscriberCapExceeded { active, max } => {
                write!(f, "preview subscriber cap reached ({active}/{max})")
            }
            Self::UnknownSubscriber(id) => write!(f, "unknown preview subscriber '{id}'"),
            Self::StaleGeneration { expected, actual } => write!(
                f,
                "preview generation mismatch: expected {}, got {}",
                expected.0, actual.0
            ),
            Self::Pool(err) => write!(f, "preview fan-out pool error: {err}"),
            Self::Cancelled => write!(f, "preview fan-out operation cancelled"),
        }
    }
}

impl std::error::Error for PreviewFanoutError {}

/// Canonical, content-addressed witness receipt of live preview fan-out state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewFanoutReceipt {
    /// Format version (`PREVIEW_FANOUT_FORMAT_VERSION`).
    pub format_version: u32,
    /// Owning stream identifier.
    pub stream_id: String,
    /// Active generation fence.
    pub active_generation: Generation,
    /// Capture timestamp.
    pub captured_at_ns: TimestampNs,
    /// Number of currently subscribed viewers.
    pub active_subscribers: u64,
    /// Total unread leases currently held across all subscriber queues.
    pub queued_leases: u64,
    /// Cumulative frames offered to `publish_frame`.
    pub total_frames_offered: u64,
    /// Cumulative leases delivered into subscriber queues.
    pub total_deliveries: u64,
    /// Cumulative oldest-unviewed leases dropped and returned to `FramePool` under backpressure.
    pub total_dropped_oldest: u64,
    /// Cumulative deliveries withheld by privacy-mask enforcement.
    pub total_privacy_filtered: u64,
    /// Cumulative deliveries shed by `MediaDegradationRung`.
    pub total_pressure_shed: u64,
    /// Current degradation rung last observed.
    pub last_rung: MediaDegradationRung,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl PreviewFanoutReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PREVIEW_FANOUT_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.stream_id);
        encoder.u64(self.active_generation.0);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.active_subscribers);
        encoder.u64(self.queued_leases);
        encoder.u64(self.total_frames_offered);
        encoder.u64(self.total_deliveries);
        encoder.u64(self.total_dropped_oldest);
        encoder.u64(self.total_privacy_filtered);
        encoder.u64(self.total_pressure_shed);
        self.last_rung.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for PreviewFanoutReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.stream_id);
        encoder.u64(self.active_generation.0);
        encoder.i128(self.captured_at_ns.0);
        encoder.u64(self.active_subscribers);
        encoder.u64(self.queued_leases);
        encoder.u64(self.total_frames_offered);
        encoder.u64(self.total_deliveries);
        encoder.u64(self.total_dropped_oldest);
        encoder.u64(self.total_privacy_filtered);
        encoder.u64(self.total_pressure_shed);
        self.last_rung.encode_canonical(encoder);
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for PreviewFanoutReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != PREVIEW_FANOUT_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let stream_id = decoder.text()?.to_owned();
        if stream_id.is_empty()
            || stream_id.len() > MAX_OWNER_ID_BYTES
            || stream_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let active_generation = Generation(decoder.u64()?);
        if active_generation.0 == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        let captured_at_ns = TimestampNs(decoder.i128()?);
        let active_subscribers = decoder.u64()?;
        let queued_leases = decoder.u64()?;
        let total_frames_offered = decoder.u64()?;
        let total_deliveries = decoder.u64()?;
        let total_dropped_oldest = decoder.u64()?;
        let total_privacy_filtered = decoder.u64()?;
        let total_pressure_shed = decoder.u64()?;
        let last_rung = MediaDegradationRung::decode_canonical(decoder)?;
        let receipt_digest = decoder.digest()?;

        if active_subscribers > MAX_PREVIEW_SUBSCRIBERS as u64
            || queued_leases > active_subscribers.saturating_mul(MAX_SUBSCRIBER_QUEUE_DEPTH as u64)
            || total_dropped_oldest > total_deliveries
            || queued_leases > total_deliveries.saturating_sub(total_dropped_oldest)
            || (total_frames_offered == 0
                && (total_deliveries > 0 || total_privacy_filtered > 0 || total_pressure_shed > 0))
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            stream_id,
            active_generation,
            captured_at_ns,
            active_subscribers,
            queued_leases,
            total_frames_offered,
            total_deliveries,
            total_dropped_oldest,
            total_privacy_filtered,
            total_pressure_shed,
            last_rung,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

#[derive(Debug)]
struct SubscriberState {
    spec: PreviewSubscriberSpec,
    queue: VecDeque<FrameLease>,
    delivered: u64,
    dropped_oldest: u64,
}

/// Deterministic bounded live-preview fan-out hub backed by [`FramePool`] leases.
#[derive(Debug)]
pub struct PreviewFanoutHub {
    policy: PreviewFanoutPolicy,
    subscribers: BTreeMap<String, SubscriberState>,
    total_frames_offered: u64,
    total_deliveries: u64,
    total_dropped_oldest: u64,
    total_privacy_filtered: u64,
    total_pressure_shed: u64,
    last_rung: MediaDegradationRung,
}

fn validate_sub_id(id: &str) -> Result<(), PreviewFanoutError> {
    if id.is_empty()
        || id.len() > MAX_OWNER_ID_BYTES
        || id
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(PreviewFanoutError::InvalidSubscriberId);
    }
    Ok(())
}

impl PreviewFanoutHub {
    /// Creates a new bounded fan-out hub after validating all caps.
    pub fn new(policy: PreviewFanoutPolicy) -> Result<Self, PreviewFanoutError> {
        policy.validate()?;
        Ok(Self {
            policy,
            subscribers: BTreeMap::new(),
            total_frames_offered: 0,
            total_deliveries: 0,
            total_dropped_oldest: 0,
            total_privacy_filtered: 0,
            total_pressure_shed: 0,
            last_rung: MediaDegradationRung::Rung0Nominal,
        })
    }

    /// Registers one authorized preview subscriber within `max_subscribers`.
    pub fn subscribe(&mut self, spec: PreviewSubscriberSpec) -> Result<(), PreviewFanoutError> {
        validate_sub_id(&spec.subscriber_id)?;
        if self.subscribers.contains_key(&spec.subscriber_id) {
            return Err(PreviewFanoutError::DuplicateSubscriber(spec.subscriber_id));
        }
        if self.subscribers.len() >= self.policy.max_subscribers {
            return Err(PreviewFanoutError::SubscriberCapExceeded {
                active: self.subscribers.len(),
                max: self.policy.max_subscribers,
            });
        }
        self.subscribers.insert(
            spec.subscriber_id.clone(),
            SubscriberState {
                spec,
                queue: VecDeque::with_capacity(self.policy.max_queue_depth),
                delivered: 0,
                dropped_oldest: 0,
            },
        );
        Ok(())
    }

    /// Unsubscribes `subscriber_id` and returns every queued [`FrameLease`] cleanly to `pool`
    /// so zero pool leases ever leak on viewer disconnect or cancellation.
    pub fn unsubscribe(
        &mut self,
        subscriber_id: &str,
        pool: &mut FramePool,
        now_ns: TimestampNs,
    ) -> Result<usize, PreviewFanoutError> {
        // Pre-validate pool ownership before removing subscriber so a wrong-pool call fails
        // atomically without mutating hub state or dropping queued leases.
        let Some(existing) = self.subscribers.get(subscriber_id) else {
            return Err(PreviewFanoutError::UnknownSubscriber(
                subscriber_id.to_owned(),
            ));
        };
        if existing
            .queue
            .iter()
            .any(|lease| lease.pool_id() != pool.policy().pool_id)
        {
            return Err(PreviewFanoutError::Pool(FramePoolError::PoolMismatch));
        }
        let Some(mut removed) = self.subscribers.remove(subscriber_id) else {
            return Err(PreviewFanoutError::UnknownSubscriber(
                subscriber_id.to_owned(),
            ));
        };
        let mut drained = 0;
        while let Some(lease) = removed.queue.pop_front() {
            pool.release_lease(lease, now_ns)
                .map_err(PreviewFanoutError::Pool)?;
            drained += 1;
        }
        Ok(drained)
    }

    /// Fans out one pooled frame slot across all active subscribers using zero-copy [`FrameLease`]s,
    /// obeying `offer.rung` cadence decimation, viewer privacy-mask restrictions, and bounded
    /// per-viewer drop-oldest-unviewed queues.
    pub fn publish_frame(
        &mut self,
        pool: &mut FramePool,
        offer: PreviewFrameOffer,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<FanoutPublishOutcome, PreviewFanoutError> {
        if is_cancelled() {
            return Err(PreviewFanoutError::Cancelled);
        }
        if offer.generation != self.policy.active_generation {
            return Err(PreviewFanoutError::StaleGeneration {
                expected: self.policy.active_generation,
                actual: offer.generation,
            });
        }
        // Fail closed before mutating offer counters if the target slot does not exist in `pool`.
        if pool.slot_active_leases(offer.slot_id).is_none() {
            return Err(PreviewFanoutError::Pool(FramePoolError::UnknownSlot(
                offer.slot_id,
            )));
        }

        let frame_ordinal = self.total_frames_offered;
        let stride = offer.rung.preview_stride();

        // Check cancellation before committing offer or mutating subscriber queues.
        if is_cancelled() {
            return Err(PreviewFanoutError::Cancelled);
        }

        self.total_frames_offered = self.total_frames_offered.saturating_add(1);
        self.last_rung = offer.rung;

        let mut outcome = FanoutPublishOutcome {
            delivered_count: 0,
            evicted_oldest_count: 0,
            privacy_filtered_count: 0,
            pressure_shed_count: 0,
            lease_cap_skipped_count: 0,
        };

        // Iterate subscribers in deterministic priority_tier, then subscriber_id order so high-
        // priority operators always win lease slots first under tight max_leases_per_frame.
        let mut ordered_ids: Vec<(u8, String)> = self
            .subscribers
            .iter()
            .map(|(id, st)| (st.spec.priority_tier, id.clone()))
            .collect();
        ordered_ids.sort();

        for (_prio, sub_id) in ordered_ids {
            let Some(sub) = self.subscribers.get_mut(&sub_id) else {
                continue;
            };
            // Privacy gate FIRST: an unmasked frame never reaches a privacy-restricted viewer.
            if sub.spec.requires_privacy_masked && !offer.frame_is_privacy_masked {
                outcome.privacy_filtered_count += 1;
                self.total_privacy_filtered = self.total_privacy_filtered.saturating_add(1);
                continue;
            }
            // Pressure ladder shedding: stride==0 pauses preview; stride>1 decimates cadence;
            // at Rung2/Rung3 lower-priority viewers (priority_tier > 0) are shed first.
            if stride == 0
                || (stride > 1
                    && (sub.spec.priority_tier > 0
                        || !frame_ordinal.is_multiple_of(u64::from(stride))))
            {
                outcome.pressure_shed_count += 1;
                self.total_pressure_shed = self.total_pressure_shed.saturating_add(1);
                continue;
            }

            // Acquire zero-copy immutable lease from pool BEFORE evicting oldest so if the pool
            // refuses (e.g., max_leases_per_frame), we don't drop the viewer's previous good frame.
            let lease = match pool.acquire_lease(offer.slot_id, offer.generation, || false) {
                Ok(l) => l,
                Err(FramePoolError::LeaseCapExceeded { .. }) => {
                    outcome.lease_cap_skipped_count += 1;
                    continue;
                }
                Err(err) => return Err(PreviewFanoutError::Pool(err)),
            };

            if sub.queue.len() >= self.policy.max_queue_depth
                && let Some(oldest) = sub.queue.pop_front()
            {
                if let Err(err) = pool.release_lease(oldest, offer.now_ns) {
                    let _ = pool.release_lease(lease, offer.now_ns);
                    return Err(PreviewFanoutError::Pool(err));
                }
                sub.dropped_oldest = sub.dropped_oldest.saturating_add(1);
                outcome.evicted_oldest_count += 1;
                self.total_dropped_oldest = self.total_dropped_oldest.saturating_add(1);
            }
            sub.queue.push_back(lease);
            sub.delivered = sub.delivered.saturating_add(1);
            outcome.delivered_count += 1;
            self.total_deliveries = self.total_deliveries.saturating_add(1);
        }

        Ok(outcome)
    }

    /// Pops the next unread immutable [`FrameLease`] for `subscriber_id` (caller must return it
    /// to `FramePool::release_lease` after rendering).
    pub fn recv_next(
        &mut self,
        subscriber_id: &str,
    ) -> Result<Option<FrameLease>, PreviewFanoutError> {
        let sub = self
            .subscribers
            .get_mut(subscriber_id)
            .ok_or_else(|| PreviewFanoutError::UnknownSubscriber(subscriber_id.to_owned()))?;
        Ok(sub.queue.pop_front())
    }

    /// Advances the active generation monotonically and drains every queued stale-generation
    /// lease cleanly back to `pool` so zero leases remain pinned across generation switches.
    pub fn advance_generation(
        &mut self,
        next_generation: Generation,
        pool: &mut FramePool,
        now_ns: TimestampNs,
    ) -> Result<usize, PreviewFanoutError> {
        if next_generation.0 <= self.policy.active_generation.0 {
            return Err(PreviewFanoutError::StaleGeneration {
                expected: self.policy.active_generation,
                actual: next_generation,
            });
        }
        // Pre-validate every queued lease belongs to `pool` before mutating queues or generation.
        if self.subscribers.values().any(|sub| {
            sub.queue
                .iter()
                .any(|lease| lease.pool_id() != pool.policy().pool_id)
        }) {
            return Err(PreviewFanoutError::Pool(FramePoolError::PoolMismatch));
        }
        let mut drained = 0;
        for sub in self.subscribers.values_mut() {
            while let Some(lease) = sub.queue.pop_front() {
                pool.release_lease(lease, now_ns)
                    .map_err(PreviewFanoutError::Pool)?;
                drained += 1;
            }
        }
        self.policy.active_generation = next_generation;
        Ok(drained)
    }

    /// Number of queued unread leases for one subscriber (`None` if unknown).
    #[must_use]
    pub fn subscriber_queue_len(&self, subscriber_id: &str) -> Option<usize> {
        self.subscribers.get(subscriber_id).map(|s| s.queue.len())
    }

    /// Total queued unread leases across all subscribers.
    #[must_use]
    pub fn total_queued_leases(&self) -> usize {
        self.subscribers.values().map(|s| s.queue.len()).sum()
    }

    /// Produces a canonical, content-addressed witness receipt of fan-out hub state.
    #[must_use]
    pub fn receipt(&self, captured_at_ns: TimestampNs) -> PreviewFanoutReceipt {
        let mut receipt = PreviewFanoutReceipt {
            format_version: PREVIEW_FANOUT_FORMAT_VERSION,
            stream_id: self.policy.stream_id.clone(),
            active_generation: self.policy.active_generation,
            captured_at_ns,
            active_subscribers: self.subscribers.len() as u64,
            queued_leases: self.total_queued_leases() as u64,
            total_frames_offered: self.total_frames_offered,
            total_deliveries: self.total_deliveries,
            total_dropped_oldest: self.total_dropped_oldest,
            total_privacy_filtered: self.total_privacy_filtered,
            total_pressure_shed: self.total_pressure_shed,
            last_rung: self.last_rung,
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }
}
