//! Deterministic delivery schedule and transport-fault accounting.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};

use crate::{ReferenceError, SourcePacket};

/// Maximum delivery directives in one reference plan.
pub const MAX_DELIVERY_DIRECTIVES: usize = 262_144;

/// Mutation applied to one delivered copy without changing source truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMutation {
    /// Deliver exact source bytes.
    Exact,
    /// Flip the low bit of the first source byte.
    FlipFirstBit,
}

impl DeliveryMutation {
    fn tag(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::FlipFirstBit => 1,
        }
    }
}

/// One ordered delivery instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryDirective {
    /// Source sequence to deliver.
    pub source_sequence: u64,
    /// Exact mutation applied to this delivery copy.
    pub mutation: DeliveryMutation,
}

impl DeliveryDirective {
    /// Exact source delivery.
    #[must_use]
    pub const fn exact(source_sequence: u64) -> Self {
        Self {
            source_sequence,
            mutation: DeliveryMutation::Exact,
        }
    }

    /// Corrupted delivery copy.
    #[must_use]
    pub const fn corrupt(source_sequence: u64) -> Self {
        Self {
            source_sequence,
            mutation: DeliveryMutation::FlipFirstBit,
        }
    }
}

/// Explicit ordered transport schedule.
///
/// Omitting a source sequence models loss, repeating one models duplication, changing directive
/// order models reordering, and `FlipFirstBit` models payload corruption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryPlan {
    directives: Vec<DeliveryDirective>,
}

impl DeliveryPlan {
    /// Creates a bounded ordered plan.
    pub fn new(directives: Vec<DeliveryDirective>) -> Result<Self, ReferenceError> {
        if directives.len() > MAX_DELIVERY_DIRECTIVES {
            return Err(ReferenceError::InvalidSpec("delivery_directives"));
        }
        Ok(Self { directives })
    }

    /// Creates an exact once, source-ordered plan.
    pub fn identity(packet_count: u32) -> Result<Self, ReferenceError> {
        if packet_count == 0 || packet_count > crate::MAX_VIRTUAL_PACKETS {
            return Err(ReferenceError::InvalidSpec("packet_count"));
        }
        Self::new(
            (1..=u64::from(packet_count))
                .map(DeliveryDirective::exact)
                .collect(),
        )
    }

    /// Ordered delivery directives.
    #[must_use]
    pub fn directives(&self) -> &[DeliveryDirective] {
        &self.directives
    }

    /// Validates every directive before source/object mutation begins.
    pub fn validate_against(&self, packet_count: u32) -> Result<(), ReferenceError> {
        if packet_count == 0 || packet_count > crate::MAX_VIRTUAL_PACKETS {
            return Err(ReferenceError::InvalidSpec("packet_count"));
        }
        let maximum = u64::from(packet_count);
        for directive in &self.directives {
            if directive.source_sequence == 0 || directive.source_sequence > maximum {
                return Err(ReferenceError::UnknownSourceSequence(
                    directive.source_sequence,
                ));
            }
        }
        Ok(())
    }

    /// Applies exact ordered transport directives to immutable source packets.
    pub fn apply(
        &self,
        source: &[SourcePacket],
    ) -> Result<(Vec<DeliveryPacket>, DeliveryContinuity), ReferenceError> {
        let source_by_sequence: BTreeMap<_, _> =
            source.iter().map(|packet| (packet.sequence, packet)).collect();
        let mut deliveries = Vec::with_capacity(self.directives.len());
        let mut counts = BTreeMap::<u64, u64>::new();
        let mut first_seen = BTreeSet::new();
        let mut first_seen_order = Vec::new();
        let mut corrupted = BTreeSet::new();

        for (index, directive) in self.directives.iter().enumerate() {
            let packet = source_by_sequence
                .get(&directive.source_sequence)
                .copied()
                .ok_or(ReferenceError::UnknownSourceSequence(
                    directive.source_sequence,
                ))?;
            let mut bytes = packet.bytes.clone();
            if directive.mutation == DeliveryMutation::FlipFirstBit {
                if let Some(first) = bytes.first_mut() {
                    *first ^= 1;
                }
            }
            let observed_digest = ContentDigest::sha256(&bytes);
            if observed_digest != packet.digest {
                corrupted.insert(packet.sequence);
            }
            *counts.entry(packet.sequence).or_default() += 1;
            if first_seen.insert(packet.sequence) {
                first_seen_order.push(packet.sequence);
            }
            deliveries.push(DeliveryPacket {
                delivery_index: u64::try_from(index)
                    .map_err(|_| ReferenceError::ArithmeticOverflow)?
                    .checked_add(1)
                    .ok_or(ReferenceError::ArithmeticOverflow)?,
                source_sequence: packet.sequence,
                source_digest: packet.digest,
                observed_digest,
                bytes,
                mutation: directive.mutation,
            });
        }

        let expected_count =
            u64::try_from(source.len()).map_err(|_| ReferenceError::ArithmeticOverflow)?;
        let missing_sequences: Vec<_> = (1..=expected_count)
            .filter(|sequence| !counts.contains_key(sequence))
            .collect();
        let duplicate_sequences: Vec<_> = counts
            .iter()
            .filter_map(|(sequence, count)| (*count > 1).then_some(*sequence))
            .collect();
        let corrupted_sequences: Vec<_> = corrupted.into_iter().collect();
        let reordered = first_seen_order
            .windows(2)
            .any(|pair| pair[0] >= pair[1]);
        let delivered_count =
            u64::try_from(deliveries.len()).map_err(|_| ReferenceError::ArithmeticOverflow)?;
        let exact_once_ordered = missing_sequences.is_empty()
            && duplicate_sequences.is_empty()
            && corrupted_sequences.is_empty()
            && !reordered
            && delivered_count == expected_count;

        Ok((
            deliveries,
            DeliveryContinuity {
                expected_count,
                delivered_count,
                missing_sequences,
                duplicate_sequences,
                corrupted_sequences,
                reordered,
                exact_once_ordered,
            },
        ))
    }
}

/// One observed transport delivery tied back to immutable source truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryPacket {
    /// Monotone one-based arrival index.
    pub delivery_index: u64,
    /// Source sequence this copy claims to carry.
    pub source_sequence: u64,
    /// Immutable digest of bytes before transport faults.
    pub source_digest: ContentDigest,
    /// Digest of bytes actually delivered.
    pub observed_digest: ContentDigest,
    /// Exact delivered bytes.
    pub bytes: Vec<u8>,
    /// Mutation responsible for the delivered copy.
    pub mutation: DeliveryMutation,
}

/// Explicit continuity and integrity witness for one delivery plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryContinuity {
    /// Number of source packets expected.
    pub expected_count: u64,
    /// Number of delivery copies observed.
    pub delivered_count: u64,
    /// Source sequences with no delivery.
    pub missing_sequences: Vec<u64>,
    /// Source sequences delivered more than once.
    pub duplicate_sequences: Vec<u64>,
    /// Source sequences with at least one corrupted delivery.
    pub corrupted_sequences: Vec<u64>,
    /// Whether first observations arrived out of source order.
    pub reordered: bool,
    /// Whether the observed transport was exact, once, complete, and source ordered.
    pub exact_once_ordered: bool,
}

impl DeliveryContinuity {
    /// Stable witness identity.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.virtual_delivery_continuity.v1")
    }
}

impl CanonicalEncode for DeliveryContinuity {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.expected_count);
        encoder.u64(self.delivered_count);
        encode_sequences(&self.missing_sequences, encoder);
        encode_sequences(&self.duplicate_sequences, encoder);
        encode_sequences(&self.corrupted_sequences, encoder);
        encoder.bool(self.reordered);
        encoder.bool(self.exact_once_ordered);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliveryTrace {
    deliveries: Vec<DeliveryPacketSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeliveryPacketSummary {
    delivery_index: u64,
    source_sequence: u64,
    source_digest: ContentDigest,
    observed_digest: ContentDigest,
    mutation: DeliveryMutation,
}

impl DeliveryTrace {
    pub(crate) fn from_packets(deliveries: &[DeliveryPacket]) -> Self {
        Self {
            deliveries: deliveries
                .iter()
                .map(|packet| DeliveryPacketSummary {
                    delivery_index: packet.delivery_index,
                    source_sequence: packet.source_sequence,
                    source_digest: packet.source_digest,
                    observed_digest: packet.observed_digest,
                    mutation: packet.mutation,
                })
                .collect(),
        }
    }
}

impl CanonicalEncode for DeliveryTrace {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.virtual_delivery_trace.v1");
        encoder.u64(self.deliveries.len() as u64);
        for delivery in &self.deliveries {
            encoder.u64(delivery.delivery_index);
            encoder.u64(delivery.source_sequence);
            encoder.digest(delivery.source_digest);
            encoder.digest(delivery.observed_digest);
            encoder.u8(delivery.mutation.tag());
        }
    }
}

fn encode_sequences(values: &[u64], encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.u64(*value);
    }
}
