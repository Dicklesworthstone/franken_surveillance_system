#![forbid(unsafe_code)]
//! Bounded reconstruction of uncompressed ONVIF metadata over RTP.
//!
//! The RTP marker terminates one XML document; changing RTP timestamps do not
//! terminate it. Reconstruction begins only after an observed marker boundary.
//! The owner retains original packets and independently validates the completed
//! bytes with an XML/ONVIF parser. No sender authenticity or coverage is inferred.

use std::{fmt, ops::Range};

use crate::{PacketError, RtpPacket, StreamKey};

mod receiver;
pub use receiver::{
    OnvifMetadataReceiveAdmission, OnvifMetadataReceiveCancellation, OnvifMetadataReceiveError,
    OnvifMetadataReceivePoll, OnvifMetadataReceiver,
};

/// Maximum complete document, matching the bounded ONVIF metadata interpretation lane.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// Maximum contributing packets in a complete document.
pub const MAX_DOCUMENT_FRAGMENTS: usize = 4096;

/// Independent reconstruction bounds, in addition to the RTP reorder queue limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnvifMetadataLimits {
    /// Nonzero document byte ceiling, at most 256 KiB.
    pub max_document_bytes: usize,
    /// Nonzero fragment ceiling, at most 4096; empty payloads also count.
    pub max_fragment_packets: usize,
    /// Nonzero fixed lifetime from first ordered delivery, at most 60 seconds.
    pub max_pending_age_ns: u64,
}
impl Default for OnvifMetadataLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: MAX_DOCUMENT_BYTES,
            max_fragment_packets: MAX_DOCUMENT_FRAGMENTS,
            max_pending_age_ns: 2_000_000_000,
        }
    }
}

impl OnvifMetadataLimits {
    /// Validate the independently bounded document policy without allocating or doing I/O.
    pub fn validate(self) -> Result<(), OnvifMetadataError> {
        if !(1..=MAX_DOCUMENT_BYTES).contains(&self.max_document_bytes)
            || !(1..=MAX_DOCUMENT_FRAGMENTS).contains(&self.max_fragment_packets)
            || !(1..=60_000_000_000).contains(&self.max_pending_age_ns)
        {
            return Err(OnvifMetadataError::Configuration);
        }
        Ok(())
    }
}

/// Payload-free rejection of a reconstruction configuration or ordered packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnvifMetadataError {
    /// Invalid negotiated owner binding, dynamic payload type, or reconstruction limit.
    Configuration,
    /// Wrong stream, payload type, or extended/raw sequence correspondence.
    StreamMismatch,
    /// Supplied ordered packet sequence does not increase.
    Sequence,
    /// Supplied processing time reversed.
    ClockReversed,
    /// Deadline or sequence arithmetic is exhausted.
    Exhausted,
    /// The complete document would exceed its byte bound.
    ByteLimit,
    /// The document would exceed its fragment bound.
    FragmentLimit,
    /// A bounded allocation failed.
    Allocation,
    /// A marker closed a zero-byte document, which is not XML.
    EmptyDocument,
    /// Defensive reparsing of an immutable admitted packet failed.
    Packet(PacketError),
}
impl fmt::Display for OnvifMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ONVIF metadata reconstruction refusal: {self:?}")
    }
}
impl std::error::Error for OnvifMetadataError {}

/// Explicit retirement of derivative bytes, never proof of network or scene absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnvifMetadataDiscardReason {
    /// Ordered delivery skipped one or more sequence positions.
    Gap,
    /// The fixed reconstruction deadline was reached.
    Deadline,
    /// The next payload exceeded the document byte ceiling.
    ByteLimit,
    /// The next packet exceeded the document fragment ceiling.
    FragmentLimit,
    /// A bounded reconstruction allocation failed.
    Allocation,
    /// An empty candidate ended at a marker.
    EmptyDocument,
    /// Accepted input drained without a closing marker.
    EndOfInput,
    /// The owner explicitly cancelled acquisition.
    Cancelled,
    /// A confirmed source restart requires a new owner generation.
    RestartRequired,
    /// RTP framing was malformed; the affected receiver is closed.
    InvalidPacket,
    /// One queued sequence was supplied with conflicting original bytes.
    ConflictingPacket,
    /// The owner observed a captured prefix rather than a complete source datagram.
    TruncatedSource,
}

/// Historical evidence of an observed marker immediately preceding a document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnvifMetadataBoundary {
    /// Extended sequence of the preceding marker packet; retain this packet too.
    pub sequence: u64,
    /// Uninterpreted raw RTP timestamp on that marker packet.
    pub timestamp: u32,
    /// Owner-supplied receive observation, not a camera capture time.
    pub received_ns: u64,
}

/// Exact original packet-to-document mapping, excluding RTP extensions and padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifMetadataSourceSpan {
    /// Extended sequence in this owner generation; maps to the first admitted source record.
    pub sequence: u64,
    /// Exact copied range in the complete original datagram.
    pub wire_range: Range<usize>,
    /// Corresponding range in the reconstructed document.
    pub document_range: Range<usize>,
    /// Raw timestamp for this packet; it may differ between fragments of one document.
    pub timestamp: u32,
    /// Original receive observation, which may reverse after sequence reordering.
    pub received_ns: u64,
}

/// Complete marker-delimited bytes with intact transport boundaries, not validated XML.
#[derive(Eq, PartialEq)]
pub struct OnvifMetadataDocument {
    key: StreamKey,
    boundary: OnvifMetadataBoundary,
    bytes: Vec<u8>,
    sources: Vec<OnvifMetadataSourceSpan>,
    started_ns: u64,
    completed_ns: u64,
    first_sequence: u64,
    last_sequence: u64,
}
impl OnvifMetadataDocument {
    /// Exact concatenated payload bytes; XML/schema validity is a separate owner check.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact owner ingress, generation and SSRC.
    pub fn key(&self) -> StreamKey {
        self.key
    }
    /// Observed predecessor marker that establishes a known document start.
    pub fn boundary(&self) -> OnvifMetadataBoundary {
        self.boundary
    }
    /// Exact copied source ranges in increasing extended-sequence order.
    pub fn sources(&self) -> &[OnvifMetadataSourceSpan] {
        &self.sources
    }
    /// First contributing packet; every complete document has at least one.
    pub fn first_sequence(&self) -> u64 {
        self.first_sequence
    }
    /// Closing marker packet; every complete document has at least one.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
    /// Owner processing observation at the first ordered fragment, not a capture time.
    pub fn started_ns(&self) -> u64 {
        self.started_ns
    }
    /// Owner processing observation at the closing marker.
    pub fn completed_ns(&self) -> u64 {
        self.completed_ns
    }
}
impl fmt::Debug for OnvifMetadataDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnvifMetadataDocument")
            .field("key", &self.key)
            .field("boundary", &self.boundary)
            .field("byte_len", &self.bytes.len())
            .field("fragments", &self.sources.len())
            .field("started_ns", &self.started_ns)
            .field("completed_ns", &self.completed_ns)
            .finish_non_exhaustive()
    }
}

/// One retired incomplete candidate. Original source packets remain the owner's custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnvifMetadataDiscard {
    /// Exact owner epoch of these derivative bytes.
    pub key: StreamKey,
    /// Why no complete document was emitted.
    pub reason: OnvifMetadataDiscardReason,
    /// Previously observed start boundary; incomplete candidates still retain its attribution.
    pub boundary: OnvifMetadataBoundary,
    /// First contributing extended sequence.
    pub first_sequence: u64,
    /// Last contributing extended sequence, before the refused/current packet if any.
    pub last_sequence: u64,
    /// Number of derivative bytes retired.
    pub byte_len: usize,
    /// Number of contributing packets, including empty payload fragments.
    pub fragments: usize,
}

/// Reconstruction refusal plus any candidate it retired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifMetadataFailure {
    /// Payload-free rejection category.
    pub reason: OnvifMetadataError,
    /// Previous candidate retirement, when reconstruction had begun.
    pub discarded: Option<OnvifMetadataDiscard>,
}
impl fmt::Display for OnvifMetadataFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reason.fmt(f)
    }
}
impl std::error::Error for OnvifMetadataFailure {}

/// Meaning of one ordered source packet's reconstruction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnvifMetadataStatus {
    /// Packet discarded while waiting for an observed document boundary.
    SeekingBoundary,
    /// Marker observed; this partial/unknown document is discarded, next packet may start one.
    BoundaryObserved,
    /// An incomplete bounded candidate is retained.
    FragmentPending,
    /// One complete transport document is returned for separate XML interpretation.
    Complete,
}

/// Bounded reconstruction result for exactly one ordered original datagram.
#[derive(Debug, Eq, PartialEq)]
pub struct OnvifMetadataOutput {
    /// Explicit synchronization and completeness state.
    pub status: OnvifMetadataStatus,
    /// Present only for `Complete`; empty or incomplete bytes are never published.
    pub document: Option<OnvifMetadataDocument>,
}

struct Assembler {
    key: StreamKey,
    payload_type: u8,
    limits: OnvifMetadataLimits,
    boundary: Option<OnvifMetadataBoundary>,
    pending: Option<OnvifMetadataDocument>,
    last_sequence: Option<u64>,
    last_now_ns: u64,
}
impl Assembler {
    fn new(
        key: StreamKey,
        payload_type: u8,
        limits: OnvifMetadataLimits,
    ) -> Result<Self, OnvifMetadataFailure> {
        if key.ingress == 0
            || key.generation == 0
            || !(96..=127).contains(&payload_type)
            || limits.validate().is_err()
        {
            return Err(OnvifMetadataFailure {
                reason: OnvifMetadataError::Configuration,
                discarded: None,
            });
        }
        Ok(Self {
            key,
            payload_type,
            limits,
            boundary: None,
            pending: None,
            last_sequence: None,
            last_now_ns: 0,
        })
    }

    fn pending_bytes(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, |document| document.bytes.len())
    }

    fn next_deadline_ns(&self) -> Option<u64> {
        self.pending
            .as_ref()?
            .started_ns
            .checked_add(self.limits.max_pending_age_ns)
    }

    fn expire(
        &mut self,
        now_ns: u64,
    ) -> Result<Option<OnvifMetadataDiscard>, OnvifMetadataFailure> {
        if now_ns < self.last_now_ns {
            return Err(OnvifMetadataFailure {
                reason: OnvifMetadataError::ClockReversed,
                discarded: None,
            });
        }
        self.last_now_ns = now_ns;
        if self
            .next_deadline_ns()
            .is_some_and(|deadline| now_ns >= deadline)
        {
            Ok(self.discard(OnvifMetadataDiscardReason::Deadline))
        } else {
            Ok(None)
        }
    }

    fn discard(&mut self, reason: OnvifMetadataDiscardReason) -> Option<OnvifMetadataDiscard> {
        self.boundary = None;
        self.pending
            .take()
            .filter(|document| !document.sources.is_empty())
            .map(|document| OnvifMetadataDiscard {
                key: document.key,
                reason,
                boundary: document.boundary,
                first_sequence: document.first_sequence(),
                last_sequence: document.last_sequence(),
                byte_len: document.bytes.len(),
                fragments: document.sources.len(),
            })
    }

    fn boundary(packet: RtpPacket<'_>, sequence: u64, received_ns: u64) -> OnvifMetadataBoundary {
        OnvifMetadataBoundary {
            sequence,
            timestamp: packet.timestamp(),
            received_ns,
        }
    }

    fn refuse_packet(
        &mut self,
        reason: OnvifMetadataError,
        retirement: OnvifMetadataDiscardReason,
        packet: RtpPacket<'_>,
        sequence: u64,
        received_ns: u64,
    ) -> OnvifMetadataFailure {
        let discarded = self.discard(retirement);
        if packet.marker() {
            self.boundary = Some(Self::boundary(packet, sequence, received_ns));
        }
        OnvifMetadataFailure { reason, discarded }
    }

    fn push(
        &mut self,
        key: StreamKey,
        sequence: u64,
        packet: RtpPacket<'_>,
        received_ns: u64,
        now_ns: u64,
    ) -> Result<OnvifMetadataOutput, OnvifMetadataFailure> {
        let invalid = if key != self.key
            || packet.ssrc() != key.ssrc
            || packet.payload_type() != self.payload_type
            || sequence as u16 != packet.sequence()
        {
            Some(OnvifMetadataError::StreamMismatch)
        } else if now_ns < self.last_now_ns || received_ns > now_ns {
            Some(OnvifMetadataError::ClockReversed)
        } else if self.last_sequence.is_some_and(|last| sequence <= last) {
            Some(OnvifMetadataError::Sequence)
        } else if self
            .last_sequence
            .is_some_and(|last| last.checked_add(1) != Some(sequence))
        {
            // The composed reorder owner always emits a Gap first. Refuse any internal
            // missing gap rather than construct an apparently complete document.
            Some(OnvifMetadataError::Sequence)
        } else {
            None
        };
        if let Some(reason) = invalid {
            return Err(OnvifMetadataFailure {
                reason,
                discarded: self.discard(OnvifMetadataDiscardReason::Gap),
            });
        }
        self.last_sequence = Some(sequence);
        self.last_now_ns = now_ns;
        let Some(boundary) = self.boundary else {
            let status = if packet.marker() {
                self.boundary = Some(Self::boundary(packet, sequence, received_ns));
                OnvifMetadataStatus::BoundaryObserved
            } else {
                OnvifMetadataStatus::SeekingBoundary
            };
            return Ok(OnvifMetadataOutput {
                status,
                document: None,
            });
        };
        if self.pending.is_none() {
            if now_ns.checked_add(self.limits.max_pending_age_ns).is_none() {
                return Err(self.refuse_packet(
                    OnvifMetadataError::Exhausted,
                    OnvifMetadataDiscardReason::Deadline,
                    packet,
                    sequence,
                    received_ns,
                ));
            }
            self.pending = Some(OnvifMetadataDocument {
                key,
                boundary,
                bytes: Vec::new(),
                sources: Vec::new(),
                started_ns: now_ns,
                completed_ns: now_ns,
                first_sequence: sequence,
                last_sequence: sequence,
            });
        }
        let document = self.pending.as_mut().ok_or(OnvifMetadataFailure {
            reason: OnvifMetadataError::Configuration,
            discarded: None,
        })?;
        let start = document.bytes.len();
        let Some(end) = start
            .checked_add(packet.payload().len())
            .filter(|end| *end <= self.limits.max_document_bytes)
        else {
            return Err(self.refuse_packet(
                OnvifMetadataError::ByteLimit,
                OnvifMetadataDiscardReason::ByteLimit,
                packet,
                sequence,
                received_ns,
            ));
        };
        if document.sources.len() >= self.limits.max_fragment_packets {
            return Err(self.refuse_packet(
                OnvifMetadataError::FragmentLimit,
                OnvifMetadataDiscardReason::FragmentLimit,
                packet,
                sequence,
                received_ns,
            ));
        }
        if document
            .bytes
            .try_reserve_exact(packet.payload().len())
            .is_err()
            || document.sources.try_reserve_exact(1).is_err()
        {
            return Err(self.refuse_packet(
                OnvifMetadataError::Allocation,
                OnvifMetadataDiscardReason::Allocation,
                packet,
                sequence,
                received_ns,
            ));
        }
        document.bytes.extend_from_slice(packet.payload());
        document.last_sequence = sequence;
        document.sources.push(OnvifMetadataSourceSpan {
            sequence,
            wire_range: packet.payload_range(),
            document_range: start..end,
            timestamp: packet.timestamp(),
            received_ns,
        });
        if !packet.marker() {
            return Ok(OnvifMetadataOutput {
                status: OnvifMetadataStatus::FragmentPending,
                document: None,
            });
        }
        if document.bytes.is_empty() {
            return Err(self.refuse_packet(
                OnvifMetadataError::EmptyDocument,
                OnvifMetadataDiscardReason::EmptyDocument,
                packet,
                sequence,
                received_ns,
            ));
        }
        let mut document = self.pending.take().ok_or(OnvifMetadataFailure {
            reason: OnvifMetadataError::Configuration,
            discarded: None,
        })?;
        document.completed_ns = now_ns;
        self.boundary = Some(Self::boundary(packet, sequence, received_ns));
        Ok(OnvifMetadataOutput {
            status: OnvifMetadataStatus::Complete,
            document: Some(document),
        })
    }

    fn gap(&mut self) -> Option<OnvifMetadataDiscard> {
        self.last_sequence = None;
        self.discard(OnvifMetadataDiscardReason::Gap)
    }
}
