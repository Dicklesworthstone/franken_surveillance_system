#![forbid(unsafe_code)]
//! Bounded, disposable preview fan-out over the native source-linked MP4 remux.
//!
//! The capture owner stages one derivative while its original recording is pending, then
//! calls [`PreviewHub::publish_durable`] only after observing the matching native durable
//! publication receipt. This module does not publish or read source custody, authenticate
//! viewers, apply masks, decode pixels, read clocks, or perform I/O. Its fixed authority
//! callback must represent explicit permission to expose the exact unredacted local stream.
//!
//! Each ring entry contains one initialization segment and one independently IDR-led media
//! fragment. Whole-entry eviction can skip a slow reader to a new window, but an evicted
//! partial response must be disconnected. Returned slices borrow the owner, so a reader
//! cannot keep an `Arc` alive to defeat the ring's byte bound.
//!
//! Byte offers reserve the client and whole-session allowance before exposure. `advance`
//! records an observed successful write and refunds its unused offer before checking the
//! post-write authority/time boundary. An unacknowledged offer stays charged on eviction,
//! expiry, disconnect, or close; an uncertain write is never refunded as if it sent nothing.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::ops::Range;

use fss_core::{ContentDigest, DigestAlgorithm};

use super::recording::hevc::HEVC_RECORDING_KIND;
use super::recording::{PreparedRecording, RECORDING_KIND, RecordingScope};

/// Exact codec family of the existing source-verified recording owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewCodec {
    /// Native `avc1` samples and `avcC` initialization.
    Avc,
    /// Native `hev1` samples and `hvcC` initialization; not relabelled `hvc1`.
    Hevc,
}
impl PreviewCodec {
    /// Stable report spelling, not a client decoder support claim.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
    fn recording_kind(self) -> &'static str {
        match self {
            Self::Avc => RECORDING_KIND,
            Self::Hevc => HEVC_RECORDING_KIND,
        }
    }
}

/// One exact owner-selected source epoch and finite local disclosure scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewScope {
    /// Sensor, logical stream, generation, source anchor and receive-clock identity.
    pub recording: RecordingScope,
    /// Must match the sealed recording's native manifest kind.
    pub codec: PreviewCodec,
    /// Explicit media tick rate, not inferred capture time or frame rate.
    pub time_scale: u32,
    /// Exact caller-selected decode clock; never mixed across generations.
    pub decode_clock: ContentDigest,
    /// Binding to the explicit unredacted local disclosure approval, not a mask claim.
    pub privacy_binding: ContentDigest,
    /// Exclusive monotonic session expiry in the caller's clock coordinates.
    pub expires_at_ns: u64,
}

/// Independent fixed memory, reader, age and lifetime disclosure ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreviewLimits {
    /// Simultaneously registered clients, including an in-progress response.
    pub max_clients: usize,
    /// Total successful subscriptions over the entire session; disconnect does not reset it.
    pub max_subscriptions: u64,
    /// Whole retained preview windows, separate from the single staging candidate.
    pub max_fragments: usize,
    /// Sum of retained initialization plus media bytes, excluding the single candidate.
    pub max_ring_bytes: usize,
    /// Initialization plus media bytes of one preview window or staging candidate.
    pub max_fragment_bytes: usize,
    /// Initialization bytes of one window; checked before box inspection or copying.
    pub max_initialization_bytes: usize,
    /// Maximum age since staging, not since a delayed durable publication acknowledgement.
    pub max_fragment_age_ns: u64,
    /// Payload exposure allowance per subscription. HTTP framing is accounted by the gateway.
    pub max_client_bytes: u64,
    /// Whole-session payload allowance shared by every subscription and reconnect.
    pub max_total_bytes: u64,
}
impl Default for PreviewLimits {
    fn default() -> Self {
        Self {
            max_clients: 8,
            max_subscriptions: 256,
            max_fragments: 4,
            max_ring_bytes: 8 * 1024 * 1024,
            max_fragment_bytes: 2 * 1024 * 1024,
            max_initialization_bytes: 64 * 1024,
            max_fragment_age_ns: 5_000_000_000,
            max_client_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}
impl PreviewLimits {
    /// Reject invalid relationships and unreasonable hard maxima before allocating.
    pub fn validate(self) -> Result<(), PreviewError> {
        if !(1..=64).contains(&self.max_clients)
            || !(1..=65_536).contains(&self.max_subscriptions)
            || self.max_subscriptions < self.max_clients as u64
            || !(1..=64).contains(&self.max_fragments)
            || !(1..=64 * 1024 * 1024).contains(&self.max_ring_bytes)
            || !(1..=8 * 1024 * 1024).contains(&self.max_fragment_bytes)
            || self.max_fragment_bytes > self.max_ring_bytes
            || !(1..=1024 * 1024).contains(&self.max_initialization_bytes)
            || self.max_initialization_bytes > self.max_fragment_bytes
            || self.max_fragment_age_ns == 0
            || self.max_fragment_age_ns > 60_000_000_000
            || self.max_client_bytes == 0
            || self.max_client_bytes > self.max_total_bytes
            || self.max_total_bytes > 4 * 1024 * 1024 * 1024
        {
            return Err(PreviewError::InvalidLimits);
        }
        Ok(())
    }
}

/// Explicit current authority; the hub never turns source possession into viewer permission.
pub trait PreviewAuthority {
    /// Recheck the exact source/privacy scope, revocation and caller-clock deadline.
    fn checkpoint(&self, scope: &PreviewScope, now_ns: u64) -> Result<(), PreviewError>;
}

/// Payload-free, stable refusal distinctions. None of these reclassifies capture outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewError {
    /// A fixed bound is zero, excessive, or inconsistent with another bound.
    InvalidLimits,
    /// Source, privacy, codec, initialization, or media-clock identity differs.
    Scope,
    /// Native initialization does not have the supported bounded MP4 box structure.
    MalformedInitialization,
    /// The caller's monotonic clock moved backwards.
    ClockRegression,
    /// A session or the addressed subscriber reached its exclusive deadline.
    Expired,
    /// Current explicit authority does not cover the requested disclosure.
    Unauthorized,
    /// Previously issued disclosure authority has been revoked.
    Revoked,
    /// The authority owner is cancelling or draining its operation.
    Cancelled,
    /// The per-client or whole-session payload allowance is exhausted.
    Budget,
    /// All simultaneous subscriber slots are in use.
    ClientLimit,
    /// The lifetime subscription allowance is exhausted.
    SubscriptionLimit,
    /// The subscriber is absent, disconnected, or already reaped.
    UnknownSubscriber,
    /// The exact requested window is absent or a partial response lost its window.
    Evicted,
    /// A recording's decode interval overlaps or precedes a previously admitted interval.
    Reordered,
    /// Another source window already occupies the single staging slot.
    Pending,
    /// The owner's supplied durable root differs from the staged source root.
    PublicationMismatch,
    /// The owner explicitly closed this preview session.
    Closed,
    /// Reserving the bounded derivative storage failed.
    Allocation,
    /// The requested sequence, byte offset, or write count differs from the current offer.
    Cursor,
    /// No payload reservation exists to acknowledge as a write.
    NoOffer,
    /// A checked lifetime sequence or accounting ordinal cannot advance.
    SequenceExhausted,
}
impl PreviewError {
    /// Stable report reason without media, paths, addresses or credentials.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimits => "invalid_limits",
            Self::Scope => "scope_mismatch",
            Self::MalformedInitialization => "malformed_initialization",
            Self::ClockRegression => "clock_regression",
            Self::Expired => "expired",
            Self::Unauthorized => "unauthorized",
            Self::Revoked => "revoked",
            Self::Cancelled => "cancelled",
            Self::Budget => "byte_budget",
            Self::ClientLimit => "client_limit",
            Self::SubscriptionLimit => "subscription_limit",
            Self::UnknownSubscriber => "unknown_subscriber",
            Self::Evicted => "window_evicted",
            Self::Reordered => "reordered_window",
            Self::Pending => "candidate_pending",
            Self::PublicationMismatch => "publication_root_mismatch",
            Self::Closed => "closed",
            Self::Allocation => "allocation_refused",
            Self::Cursor => "cursor_mismatch",
            Self::NoOffer => "no_byte_offer",
            Self::SequenceExhausted => "sequence_exhausted",
        }
    }
}
impl fmt::Display for PreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for PreviewError {}

/// Optional preview work omitted while original recording ownership stays unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewSkip {
    /// The derivative exceeds a preview bound; original recording ownership is unaffected.
    Oversize,
    /// Durable source acknowledgement arrived after the staged preview's age limit.
    Expired,
    /// No derivative was staged for the acknowledged original recording.
    NotStaged,
}
impl PreviewSkip {
    /// Stable omission reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oversize => "oversize",
            Self::Expired => "expired",
            Self::NotStaged => "not_staged",
        }
    }
}

/// Staging is local derivative residence only, never client visibility or source durability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StageOutcome {
    /// One derivative occupies the staging slot and remains invisible to clients.
    Staged {
        /// Original recording manifest root.
        root: ContentDigest,
        /// Initialization plus media residence, excluding original source custody.
        bytes: usize,
    },
    /// An identical retry kept the existing derivative and its original age.
    AlreadyStaged {
        /// Original recording manifest root.
        root: ContentDigest,
    },
    /// An optional derivative was omitted without affecting source capture.
    Skipped {
        /// Original recording manifest root.
        root: ContentDigest,
        /// Explicit omission reason.
        reason: PreviewSkip,
    },
}

/// Content identities and media-clock information, with no payload or camera credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewMetadata {
    /// Monotonic session-local window identity, assigned only at durable publication.
    pub sequence: u64,
    /// Original source-linked recording manifest root supplied by its recording owner.
    pub root: ContentDigest,
    /// Identity of the exact native MP4 initialization bytes.
    pub initialization_digest: ContentDigest,
    /// Identity of the exact native MP4 media fragment bytes.
    pub media_digest: ContentDigest,
    /// Initialization prefix length within the complete response body.
    pub initialization_bytes: usize,
    /// Media suffix length within the complete response body.
    pub media_bytes: usize,
    /// Number of source-verified samples in this independent recording window.
    pub samples: usize,
    /// Half-open decode interval expressed in this scope's explicit media ticks.
    pub decode_interval: Range<u64>,
    /// Explicit media ticks per second; never inferred from network arrival time.
    pub time_scale: u32,
    /// Native sample format carried by the initialization and media fragment.
    pub codec: PreviewCodec,
    /// Exact avcC/hvcC codec parameter and MP4 type; no browser compatibility promise.
    pub mime: String,
    /// Caller-clock instant when this source-verified window became the candidate.
    pub admitted_at_ns: u64,
    /// Caller-clock instant when the owner supplied the matching durable acknowledgement.
    pub published_at_ns: u64,
}
impl PreviewMetadata {
    /// Complete independently playable body: initialization followed by media.
    pub fn body_bytes(&self) -> usize {
        self.initialization_bytes + self.media_bytes
    }
}

/// The owner observed durable source custody; publication can still omit an expired preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    /// The derivative entered the bounded ring after a matching owner acknowledgement.
    Published(PreviewMetadata),
    /// An identical acknowledgement kept the existing sequence and age.
    AlreadyPublished {
        /// Existing session-local publication sequence.
        sequence: u64,
    },
    /// Source durability was acknowledged but no preview became visible.
    Skipped {
        /// Original recording manifest root.
        root: ContentDigest,
        /// Explicit omission reason.
        reason: PreviewSkip,
    },
}

/// In-memory client identity, neither authentication nor an externally durable handle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubscriberId(u64);
impl SubscriberId {
    /// Session-local ordinal for bounded diagnostics.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A slow reader sees its skipped whole windows before the next independently decodable one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviewRead {
    /// This subscriber is waiting for its next durable window.
    Empty,
    /// Exact metadata for the current independently playable window.
    Fragment(PreviewMetadata),
    /// Whole unread windows were evicted; this poll acknowledges that discontinuity.
    Gap {
        /// Count of complete windows skipped since the last acknowledgement.
        skipped: u64,
        /// New cursor, which may still be waiting for publication.
        next_sequence: u64,
    },
    /// The optional preview owner has closed and dropped all media.
    Closed,
}

/// Bounded accounting; charged bytes include offers whose write result was never acknowledged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreviewStatus {
    /// Currently registered subscribers, including an in-progress response.
    pub clients: usize,
    /// Complete published windows still resident.
    pub queued_fragments: usize,
    /// Initialization plus media bytes in the ring.
    pub queued_bytes: usize,
    /// Bytes in the single unpublished candidate, separate from the ring limit.
    pub candidate_bytes: usize,
    /// Lifetime successful subscriptions, including disconnected clients.
    pub subscriptions: u64,
    /// Lifetime newly staged candidates, excluding identical retries.
    pub staged: u64,
    /// Lifetime newly published windows, excluding identical acknowledgements.
    pub published: u64,
    /// Derivatives omitted for oversize or age expiry.
    pub skipped: u64,
    /// Complete windows removed for age or ring capacity.
    pub evicted: u64,
    /// Successful writes plus still-reserved or unacknowledged byte offers.
    pub charged_bytes: u64,
    /// Exact successful byte counts supplied through `advance`, even after revocation.
    pub written_bytes: u64,
    /// Explicit close or overall session expiry has dropped all preview residence.
    pub closed: bool,
}

struct Window {
    metadata: PreviewMetadata,
    initialization: Vec<u8>,
    media: Vec<u8>,
}
impl Window {
    fn byte_len(&self) -> usize {
        self.initialization.len() + self.media.len()
    }
    fn part(&self, offset: usize) -> Result<&[u8], PreviewError> {
        if offset < self.initialization.len() {
            return Ok(&self.initialization[offset..]);
        }
        self.media
            .get(offset - self.initialization.len()..)
            .ok_or(PreviewError::Cursor)
    }
}

#[derive(Clone, Copy)]
struct Offer {
    sequence: u64,
    offset: usize,
    length: usize,
}
struct Subscriber {
    sequence: u64,
    offset: usize,
    expires_at_ns: u64,
    remaining: u64,
    skipped: u64,
    evicted_partial: bool,
    offer: Option<Offer>,
}

/// Sole owner of the fixed preview ring, staging candidate and all client cursors.
pub struct PreviewHub {
    scope: PreviewScope,
    limits: PreviewLimits,
    ring: VecDeque<Window>,
    candidate: Option<Window>,
    clients: BTreeMap<SubscriberId, Subscriber>,
    last_ns: u64,
    next_sequence: u64,
    initialization_digest: Option<ContentDigest>,
    last_decode_end: Option<u64>,
    counters: PreviewStatus,
}
impl fmt::Debug for PreviewHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreviewHub")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl PreviewHub {
    /// Validate exact scope and all limits before allocating or accepting a source derivative.
    pub fn new(
        scope: PreviewScope,
        limits: PreviewLimits,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<Self, PreviewError> {
        limits.validate()?;
        if scope.recording.generation == 0
            || scope.time_scale == 0
            || [
                scope.recording.anchor,
                scope.recording.receive_clock,
                scope.decode_clock,
                scope.privacy_binding,
            ]
            .into_iter()
            .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
        {
            return Err(PreviewError::Scope);
        }
        if now_ns >= scope.expires_at_ns {
            return Err(PreviewError::Expired);
        }
        authority.checkpoint(&scope, now_ns)?;
        let mut ring = VecDeque::new();
        ring.try_reserve_exact(limits.max_fragments)
            .map_err(|_| PreviewError::Allocation)?;
        Ok(Self {
            scope,
            limits,
            ring,
            candidate: None,
            clients: BTreeMap::new(),
            last_ns: now_ns,
            next_sequence: 1,
            initialization_digest: None,
            last_decode_end: None,
            counters: PreviewStatus::default(),
        })
    }

    /// Fixed scope is configuration, not a newly issued access grant.
    pub fn scope(&self) -> &PreviewScope {
        &self.scope
    }
    /// Exact immutable bounds used by this owner.
    pub const fn limits(&self) -> PreviewLimits {
        self.limits
    }
    /// Payload-free diagnostic accounting; no media/source identity is returned.
    pub fn status(&self) -> PreviewStatus {
        PreviewStatus {
            clients: self.clients.len(),
            queued_fragments: self.ring.len(),
            candidate_bytes: self.candidate.as_ref().map_or(0, Window::byte_len),
            ..self.counters
        }
    }

    fn checkpoint(
        &mut self,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<(), PreviewError> {
        if self.counters.closed {
            return Err(PreviewError::Closed);
        }
        if now_ns < self.last_ns {
            return Err(PreviewError::ClockRegression);
        }
        if now_ns >= self.scope.expires_at_ns {
            self.close();
            return Err(PreviewError::Expired);
        }
        authority.checkpoint(&self.scope, now_ns)?;
        self.last_ns = now_ns;
        self.clients
            .retain(|_, client| now_ns < client.expires_at_ns);
        while self
            .ring
            .front()
            .is_some_and(|w| now_ns - w.metadata.admitted_at_ns >= self.limits.max_fragment_age_ns)
        {
            self.evict_front();
        }
        Ok(())
    }

    fn checkpoint_client(
        &mut self,
        id: SubscriberId,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<(), PreviewError> {
        let expiry = self.clients.get(&id).map(|client| client.expires_at_ns);
        self.checkpoint(now_ns, authority)?;
        match expiry {
            Some(expires_at_ns) if now_ns >= expires_at_ns => Err(PreviewError::Expired),
            Some(_) => Ok(()),
            None => Err(PreviewError::UnknownSubscriber),
        }
    }

    /// Stage only remux derivatives. The caller keeps the original source/recording unchanged.
    /// A matching retry does not refresh candidate age, budgets or source generation.
    pub fn stage(
        &mut self,
        recording: &PreparedRecording,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<StageOutcome, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        let root = recording.manifest().root();
        let summary = recording.summary();
        if summary.scope != self.scope.recording
            || summary.time_scale != self.scope.time_scale
            || recording.manifest().kind() != self.scope.codec.recording_kind()
            || summary.decode_interval.start >= summary.decode_interval.end
        {
            return Err(PreviewError::Scope);
        }
        if let Some(candidate) = &self.candidate {
            return if candidate.metadata.root == root {
                Ok(StageOutcome::AlreadyStaged { root })
            } else {
                Err(PreviewError::Pending)
            };
        }
        if self
            .last_decode_end
            .is_some_and(|end| summary.decode_interval.start < end)
        {
            return Err(PreviewError::Reordered);
        }
        let objects = recording.objects();
        let bytes = objects
            .initialization
            .len()
            .checked_add(objects.media.len())
            .ok_or(PreviewError::InvalidLimits)?;
        if bytes > self.limits.max_fragment_bytes
            || objects.initialization.len() > self.limits.max_initialization_bytes
        {
            self.counters.skipped = self
                .counters
                .skipped
                .checked_add(1)
                .ok_or(PreviewError::SequenceExhausted)?;
            self.last_decode_end = Some(summary.decode_interval.end);
            return Ok(StageOutcome::Skipped {
                root,
                reason: PreviewSkip::Oversize,
            });
        }
        let initialization_digest = ContentDigest::sha256(objects.initialization);
        if self
            .initialization_digest
            .is_some_and(|pinned| pinned != initialization_digest)
        {
            return Err(PreviewError::Scope);
        }
        let mime = initialization_mime(objects.initialization, self.scope.codec)?;
        let initialization = copy_bounded(objects.initialization)?;
        let media = copy_bounded(objects.media)?;
        let staged = self
            .counters
            .staged
            .checked_add(1)
            .ok_or(PreviewError::SequenceExhausted)?;
        self.candidate = Some(Window {
            initialization,
            media,
            metadata: PreviewMetadata {
                sequence: 0,
                root,
                initialization_digest,
                media_digest: ContentDigest::sha256(objects.media),
                initialization_bytes: objects.initialization.len(),
                media_bytes: objects.media.len(),
                samples: summary.samples,
                decode_interval: summary.decode_interval.clone(),
                time_scale: summary.time_scale,
                codec: self.scope.codec,
                mime,
                admitted_at_ns: now_ns,
                published_at_ns: 0,
            },
        });
        self.initialization_digest = Some(initialization_digest);
        self.last_decode_end = Some(summary.decode_interval.end);
        self.counters.staged = staged;
        Ok(StageOutcome::Staged { root, bytes })
    }

    /// Publish the staged preview ONLY after the caller checks the native durable receipt/root.
    /// This method cannot itself prove filesystem durability and never grants access authority.
    pub fn publish_durable(
        &mut self,
        root: ContentDigest,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<PublishOutcome, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        if let Some(existing) = self.ring.iter().find(|w| w.metadata.root == root) {
            return Ok(PublishOutcome::AlreadyPublished {
                sequence: existing.metadata.sequence,
            });
        }
        let Some(candidate) = self.candidate.as_ref() else {
            return Ok(PublishOutcome::Skipped {
                root,
                reason: PreviewSkip::NotStaged,
            });
        };
        if candidate.metadata.root != root {
            return Err(PreviewError::PublicationMismatch);
        }
        if now_ns - candidate.metadata.admitted_at_ns >= self.limits.max_fragment_age_ns {
            self.counters.skipped = self
                .counters
                .skipped
                .checked_add(1)
                .ok_or(PreviewError::SequenceExhausted)?;
            self.candidate = None;
            return Ok(PublishOutcome::Skipped {
                root,
                reason: PreviewSkip::Expired,
            });
        }
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(PreviewError::SequenceExhausted)?;
        let published = self
            .counters
            .published
            .checked_add(1)
            .ok_or(PreviewError::SequenceExhausted)?;
        let mut window = self.candidate.take().ok_or(PreviewError::Pending)?;
        while self.ring.len() >= self.limits.max_fragments
            || self.counters.queued_bytes + window.byte_len() > self.limits.max_ring_bytes
        {
            self.evict_front();
        }
        window.metadata.sequence = self.next_sequence;
        window.metadata.published_at_ns = now_ns;
        let metadata = window.metadata.clone();
        self.counters.queued_bytes += window.byte_len();
        self.ring.push_back(window);
        self.next_sequence = next;
        self.counters.published = published;
        Ok(PublishOutcome::Published(metadata))
    }

    fn evict_front(&mut self) {
        if let Some(window) = self.ring.pop_front() {
            let sequence = window.metadata.sequence;
            self.counters.queued_bytes -= window.byte_len();
            self.counters.evicted += 1;
            for client in self.clients.values_mut() {
                if client.sequence <= sequence {
                    if client.offset != 0 || client.offer.is_some() {
                        client.evicted_partial = true;
                    } else {
                        client.skipped += sequence + 1 - client.sequence;
                        client.sequence = sequence + 1;
                    }
                }
            }
        }
    }

    /// Newest unexpired published window; metadata is subject to the same current authority.
    pub fn latest(
        &mut self,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<Option<PreviewMetadata>, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        Ok(self.ring.back().map(|w| w.metadata.clone()))
    }

    /// Look up exactly one manifest-selected published window, never substitute a newer one.
    pub fn metadata(
        &mut self,
        sequence: u64,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<PreviewMetadata, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        self.ring
            .iter()
            .find(|w| w.metadata.sequence == sequence)
            .map(|w| w.metadata.clone())
            .ok_or(PreviewError::Evicted)
    }

    /// Subscribe at the newest available window, or wait for the next publication.
    pub fn subscribe(
        &mut self,
        expires_at_ns: u64,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<SubscriberId, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        let sequence = self
            .ring
            .back()
            .map_or(self.next_sequence, |w| w.metadata.sequence);
        self.register(sequence, expires_at_ns, now_ns)
    }

    /// Subscribe to one exact still-resident window selected from a prior manifest.
    pub fn subscribe_at(
        &mut self,
        sequence: u64,
        expires_at_ns: u64,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<SubscriberId, PreviewError> {
        self.checkpoint(now_ns, authority)?;
        if !self.ring.iter().any(|w| w.metadata.sequence == sequence) {
            return Err(PreviewError::Evicted);
        }
        self.register(sequence, expires_at_ns, now_ns)
    }

    fn register(
        &mut self,
        sequence: u64,
        expires_at_ns: u64,
        now_ns: u64,
    ) -> Result<SubscriberId, PreviewError> {
        if expires_at_ns <= now_ns || expires_at_ns > self.scope.expires_at_ns {
            return Err(PreviewError::Expired);
        }
        if self.clients.len() >= self.limits.max_clients {
            return Err(PreviewError::ClientLimit);
        }
        if self.counters.subscriptions >= self.limits.max_subscriptions {
            return Err(PreviewError::SubscriptionLimit);
        }
        if self.counters.charged_bytes >= self.limits.max_total_bytes {
            return Err(PreviewError::Budget);
        }
        let next = self.counters.subscriptions + 1;
        let id = SubscriberId(next);
        self.clients.insert(
            id,
            Subscriber {
                sequence,
                offset: 0,
                expires_at_ns,
                remaining: self.limits.max_client_bytes,
                skipped: 0,
                evicted_partial: false,
                offer: None,
            },
        );
        self.counters.subscriptions = next;
        Ok(id)
    }

    /// Poll the client's next whole window or acknowledge its explicit slow-reader gap.
    pub fn next(
        &mut self,
        id: SubscriberId,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<PreviewRead, PreviewError> {
        if self.counters.closed {
            return Ok(PreviewRead::Closed);
        }
        self.checkpoint_client(id, now_ns, authority)?;
        let client = self
            .clients
            .get_mut(&id)
            .ok_or(PreviewError::UnknownSubscriber)?;
        if client.evicted_partial {
            return Err(PreviewError::Evicted);
        }
        if client.skipped != 0 {
            let skipped = std::mem::take(&mut client.skipped);
            return Ok(PreviewRead::Gap {
                skipped,
                next_sequence: client.sequence,
            });
        }
        Ok(self
            .ring
            .iter()
            .find(|w| w.metadata.sequence == client.sequence)
            .map_or(PreviewRead::Empty, |w| {
                PreviewRead::Fragment(w.metadata.clone())
            }))
    }

    /// Reserve at most one contiguous initialization/media slice BEFORE a network write.
    /// Offset is in initialization+media concatenation and must equal this client's cursor.
    /// Repeat the same offer after WouldBlock, or `advance(..., 0, ...)` to release it.
    #[allow(clippy::too_many_arguments)]
    pub fn chunk(
        &mut self,
        id: SubscriberId,
        sequence: u64,
        offset: usize,
        max_bytes: usize,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<&[u8], PreviewError> {
        self.checkpoint_client(id, now_ns, authority)?;
        if max_bytes == 0 {
            return Err(PreviewError::InvalidLimits);
        }
        let client = self
            .clients
            .get_mut(&id)
            .ok_or(PreviewError::UnknownSubscriber)?;
        if client.evicted_partial {
            return Err(PreviewError::Evicted);
        }
        if client.sequence != sequence || client.offset != offset || client.skipped != 0 {
            return Err(PreviewError::Cursor);
        }
        let window = self
            .ring
            .iter()
            .find(|w| w.metadata.sequence == sequence)
            .ok_or(PreviewError::Evicted)?;
        let part = window.part(offset)?;
        if part.is_empty() {
            return Err(PreviewError::Cursor);
        }
        let length = if let Some(offer) = client.offer {
            if offer.sequence != sequence || offer.offset != offset {
                return Err(PreviewError::Cursor);
            }
            offer.length.min(max_bytes)
        } else {
            let available = client
                .remaining
                .min(self.limits.max_total_bytes - self.counters.charged_bytes);
            let length = part
                .len()
                .min(max_bytes)
                .min(usize::try_from(available).unwrap_or(usize::MAX));
            if length == 0 {
                return Err(PreviewError::Budget);
            }
            client.remaining -= length as u64;
            self.counters.charged_bytes += length as u64;
            client.offer = Some(Offer {
                sequence,
                offset,
                length,
            });
            length
        };
        Ok(&part[..length])
    }

    /// Record an observed successful write, including zero-byte WouldBlock, then recheck authority.
    /// If this returns Expired/Revoked/Cancelled/ClockRegression, written bytes remain accounted.
    /// Never call this with guessed bytes after an ambiguous I/O result; disconnect instead.
    pub fn advance(
        &mut self,
        id: SubscriberId,
        sequence: u64,
        bytes_written: usize,
        now_ns: u64,
        authority: &dyn PreviewAuthority,
    ) -> Result<(), PreviewError> {
        let client = self
            .clients
            .get_mut(&id)
            .ok_or(PreviewError::UnknownSubscriber)?;
        let offer = client.offer.ok_or(PreviewError::NoOffer)?;
        if offer.sequence != sequence
            || client.sequence != sequence
            || client.offset != offer.offset
            || bytes_written > offer.length
        {
            return Err(PreviewError::Cursor);
        }
        let refund = (offer.length - bytes_written) as u64;
        client.remaining += refund;
        self.counters.charged_bytes -= refund;
        self.counters.written_bytes += bytes_written as u64;
        client.offer = None;
        client.offset += bytes_written;
        let was_evicted = client.evicted_partial;
        let expires_at_ns = client.expires_at_ns;
        if !was_evicted
            && self
                .ring
                .iter()
                .find(|w| w.metadata.sequence == sequence)
                .is_some_and(|w| client.offset == w.byte_len())
        {
            client.sequence = sequence + 1;
            client.offset = 0;
        }
        self.checkpoint(now_ns, authority)?;
        if now_ns >= expires_at_ns {
            return Err(PreviewError::Expired);
        }
        if was_evicted
            || self
                .clients
                .get(&id)
                .is_some_and(|client| client.evicted_partial)
        {
            return Err(PreviewError::Evicted);
        }
        Ok(())
    }

    /// Release one client without authority. Unacknowledged byte offers stay charged.
    pub fn disconnect(&mut self, id: SubscriberId) -> bool {
        self.clients.remove(&id).is_some()
    }

    /// Drop optional preview media and clients even after revocation; never touch source custody.
    pub fn close(&mut self) {
        self.candidate = None;
        self.ring.clear();
        self.clients.clear();
        self.counters.queued_bytes = 0;
        self.counters.closed = true;
    }
}

fn copy_bounded(bytes: &[u8]) -> Result<Vec<u8>, PreviewError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| PreviewError::Allocation)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

// Only the native muxer's fixed bounded box hierarchy is admitted here. A byte-pattern scan
// could mistake bytes inside SPS/PPS/metadata for a configuration record, so walk real boxes.
fn child_box<'a>(bytes: &'a [u8], name: &[u8; 4]) -> Result<&'a [u8], PreviewError> {
    let mut offset = 0;
    let mut found = None;
    let mut count = 0;
    while offset < bytes.len() {
        count += 1;
        if count > 128 {
            return Err(PreviewError::MalformedInitialization);
        }
        let header = bytes
            .get(offset..offset + 8)
            .ok_or(PreviewError::MalformedInitialization)?;
        let length = u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| PreviewError::MalformedInitialization)?,
        ) as usize;
        if length < 8 {
            return Err(PreviewError::MalformedInitialization);
        }
        let end = offset
            .checked_add(length)
            .ok_or(PreviewError::MalformedInitialization)?;
        let body = bytes
            .get(offset + 8..end)
            .ok_or(PreviewError::MalformedInitialization)?;
        if &header[4..8] == name && found.replace(body).is_some() {
            return Err(PreviewError::MalformedInitialization);
        }
        offset = end;
    }
    found.ok_or(PreviewError::MalformedInitialization)
}

fn initialization_mime(bytes: &[u8], codec: PreviewCodec) -> Result<String, PreviewError> {
    let mut body = bytes;
    for name in [b"moov", b"trak", b"mdia", b"minf", b"stbl", b"stsd"] {
        body = child_box(body, name)?;
    }
    if body.get(..8) != Some(&[0, 0, 0, 0, 0, 0, 0, 1]) {
        return Err(PreviewError::MalformedInitialization);
    }
    let entry = child_box(
        &body[8..],
        match codec {
            PreviewCodec::Avc => b"avc1",
            PreviewCodec::Hevc => b"hev1",
        },
    )?;
    let children = entry
        .get(78..)
        .ok_or(PreviewError::MalformedInitialization)?;
    let parameter = match codec {
        PreviewCodec::Avc => {
            let avcc = child_box(children, b"avcC")?;
            if avcc.len() < 7 || avcc[0] != 1 {
                return Err(PreviewError::MalformedInitialization);
            }
            format!("avc1.{:02X}{:02X}{:02X}", avcc[1], avcc[2], avcc[3])
        }
        PreviewCodec::Hevc => {
            let hvcc = child_box(children, b"hvcC")?;
            if hvcc.len() < 23 || hvcc[0] != 1 {
                return Err(PreviewError::MalformedInitialization);
            }
            // ISO/IEC 14496-15 E.3 / ETSI TS 126 244 A.2.2: compatibility flags reverse
            // bit order; profile space and tier remain distinct; omit trailing zero constraints.
            // https://www.etsi.org/deliver/etsi_ts/126200_126299/126244/13.03.00_60/ts_126244v130300p.pdf
            let space = match hvcc[1] >> 6 {
                0 => "",
                1 => "A",
                2 => "B",
                _ => "C",
            };
            let compatibility = u32::from_be_bytes(
                hvcc[2..6]
                    .try_into()
                    .map_err(|_| PreviewError::MalformedInitialization)?,
            )
            .reverse_bits();
            let tier = if hvcc[1] & 0x20 == 0 { 'L' } else { 'H' };
            let mut value = format!(
                "hev1.{space}{}.{compatibility:X}.{tier}{}",
                hvcc[1] & 0x1f,
                hvcc[12]
            );
            let constraints = &hvcc[6..12];
            if let Some(last) = constraints.iter().rposition(|b| *b != 0) {
                for byte in &constraints[..=last] {
                    value.push_str(&format!(".{byte:02X}"));
                }
            }
            value
        }
    };
    Ok(format!("video/mp4; codecs=\"{parameter}\""))
}
