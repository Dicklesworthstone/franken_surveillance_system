#![forbid(unsafe_code)]
//! Integration contract tests for deterministic packet fault injector (FSS-015).
//!
//! Verifies:
//! - Deterministic seeded fault schedules (loss, bounded reordering, duplication, gaps)
//! - Bit-identical replay from identical seeds
//! - Injected gaps certified by typed [`InjectedGapWitness`] to prevent treating missing data as absence
//! - Bounded buffers and limits tested at exactly bound and bound+1
//! - Generic packet type operation (compatible with 7.1 [`SourcePacket`] and 7.2 custom fixtures)
//! - Zero ambient state, zero defaults, strictly typed errors
//!
//! Behavioral tests run on the real 7.1 [`SourcePacket`]; [`MockFramePacket`] is kept only to
//! prove the injector is generic over custom packet types.

use std::error::Error;

use fss_core::{CapsuleId, CaptureInterval, ContentDigest, ContractError, SensorId, TimestampNs};
use fss_reference::{
    DeterministicFaultPrng, FaultInjectionJournal, FaultStreamItem, InjectedFaultEvidence,
    InjectedGapWitness, MAX_BUFFER_CAPACITY, MAX_DUPLICATE_COPIES, MAX_GAP_LENGTH,
    MAX_REORDER_WINDOW, MAX_SCHEDULE_RULES, PacketFaultError, PacketFaultInjector,
    PacketFaultSchedule, SequencedPacket, SourcePacket, StochasticFaultProfile, VirtualCameraSpec,
    generate_source, inject_packets, inject_stream,
};

/// Nominal frame period of the custom mock packets.
const MOCK_FRAME_PERIOD_NS: i128 = 33_333_333;

/// Custom mock packet verifying genericity over packet types (for 7.2 fixtures).
///
/// Mirrors [`SourcePacket`]: the capture interval is validated once at construction and stored,
/// so an inverted interval surfaces as a typed [`ContractError`] instead of being flattened into
/// an absent interval on an [`InjectedGapWitness`].
#[derive(Clone, Debug, Eq, PartialEq)]
struct MockFramePacket {
    sensor_id: SensorId,
    sequence: u64,
    capture: CaptureInterval,
    frame_payload: Vec<u8>,
}

impl MockFramePacket {
    fn new(
        sensor_id: SensorId,
        sequence: u64,
        earliest: TimestampNs,
        latest: TimestampNs,
        frame_payload: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let capture = CaptureInterval::new(earliest, latest)?;
        Ok(Self {
            sensor_id,
            sequence,
            capture,
            frame_payload,
        })
    }
}

impl SequencedPacket for MockFramePacket {
    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn sensor_id(&self) -> &SensorId {
        &self.sensor_id
    }

    fn capture_interval(&self) -> Option<CaptureInterval> {
        Some(self.capture)
    }

    fn content_digest(&self) -> Option<ContentDigest> {
        Some(ContentDigest::sha256(&self.frame_payload))
    }
}

fn create_mock_packets(count: u64) -> Result<Vec<MockFramePacket>, Box<dyn Error>> {
    let sensor = SensorId::parse("sensor:mock:cam1")?;
    let mut packets = Vec::new();
    for seq in 1..=count {
        let earliest = 1_000_000_000 + i128::from(seq) * MOCK_FRAME_PERIOD_NS;
        packets.push(MockFramePacket::new(
            sensor.clone(),
            seq,
            TimestampNs(earliest),
            TimestampNs(earliest + MOCK_FRAME_PERIOD_NS),
            format!("frame-payload-data-{seq}").into_bytes(),
        )?);
    }
    Ok(packets)
}

/// Generates `count` real 7.1 source packets from a deterministic virtual camera.
fn source_packets(count: u32) -> Result<Vec<SourcePacket>, Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:fault:contract")?,
        sensor_id: SensorId::parse("sensor:cam:fault-contract")?,
        seed: 0x5eed,
        packet_count: count,
        packet_bytes: 32,
        start_ns: 1_000_000_000,
        period_ns: 33_333_333,
        uncertainty_ns: 500_000,
    };
    Ok(generate_source(&spec)?)
}

/// Compact, order-preserving view of an emitted stream.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Shape {
    Packet(u64),
    Duplicate(u64),
    Gap(u64, u64),
}

fn shape<P: SequencedPacket>(items: &[FaultStreamItem<P>]) -> Vec<Shape> {
    items
        .iter()
        .map(|item| match item {
            FaultStreamItem::Packet {
                packet,
                is_duplicate: false,
                ..
            } => Shape::Packet(packet.sequence()),
            FaultStreamItem::Packet {
                packet,
                is_duplicate: true,
                ..
            } => Shape::Duplicate(packet.sequence()),
            FaultStreamItem::InjectedGap(witness) => {
                Shape::Gap(witness.start_sequence, witness.end_sequence)
            }
        })
        .collect()
}

fn packet_sequences<P: SequencedPacket>(items: &[FaultStreamItem<P>]) -> Vec<u64> {
    items
        .iter()
        .filter_map(|item| item.as_packet().map(SequencedPacket::sequence))
        .collect()
}

/// Returns `(delay_steps, emitted_at_delivery_index)` of the reorder evidence for `sequence`.
fn reorder_evidence(
    journal: &FaultInjectionJournal,
    sequence: u64,
) -> Result<(usize, u64), Box<dyn Error>> {
    journal
        .fault_evidence
        .iter()
        .find_map(|fault| match fault {
            InjectedFaultEvidence::Reorder {
                sequence: seq,
                delay_steps,
                emitted_at_delivery_index,
                ..
            } if *seq == sequence => Some((*delay_steps, *emitted_at_delivery_index)),
            _ => None,
        })
        .ok_or_else(|| format!("missing reorder evidence for sequence {sequence}").into())
}

#[test]
fn fault_injector_deterministic_loss_rule() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(101, 8)?;
    schedule.add_drop_rule(3, "simulated_wireless_packet_drop")?;
    schedule.add_drop_rule(5, "crc_checksum_error_discard")?;

    let packets = source_packets(6)?;
    let (delivered, journal) = inject_packets(packets, schedule)?;

    // Sequences 3 and 5 dropped -> 4 delivered
    assert_eq!(delivered.len(), 4);
    assert_eq!(delivered[0].sequence, 1);
    assert_eq!(delivered[1].sequence, 2);
    assert_eq!(delivered[2].sequence, 4);
    assert_eq!(delivered[3].sequence, 6);

    // Journal verifies typed loss evidence
    assert_eq!(journal.lost_sequences, vec![3, 5]);
    assert_eq!(journal.total_input_packets, 6);
    assert_eq!(journal.total_delivered_packets, 4);

    let drop_faults: Vec<_> = journal
        .fault_evidence
        .iter()
        .filter(|f| matches!(f, InjectedFaultEvidence::Loss { .. }))
        .collect();
    assert_eq!(drop_faults.len(), 2);
    match &drop_faults[0] {
        InjectedFaultEvidence::Loss {
            sequence, reason, ..
        } => {
            assert_eq!(*sequence, 3);
            assert_eq!(reason, "simulated_wireless_packet_drop");
        }
        other => return Err(format!("expected Loss fault, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_deterministic_duplication_rule() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(202, 8)?;
    // Duplicate sequence 2 by 2 extra copies (total 3 copies)
    schedule.add_duplicate_rule(2, 2)?;

    let packets = source_packets(3)?;
    let (delivered, journal) = inject_packets(packets, schedule)?;

    // 1 original, 3 of seq 2, 1 of seq 3 -> total 5
    assert_eq!(delivered.len(), 5);
    assert_eq!(delivered[0].sequence, 1);
    assert_eq!(delivered[1].sequence, 2);
    assert_eq!(delivered[2].sequence, 2);
    assert_eq!(delivered[3].sequence, 2);
    assert_eq!(delivered[4].sequence, 3);

    assert_eq!(journal.duplicated_sequences, vec![2]);
    assert_eq!(journal.total_input_packets, 3);
    assert_eq!(journal.total_delivered_packets, 5);

    Ok(())
}

#[test]
fn fault_injector_deterministic_reorder_rule() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(303, 8)?;
    // Delay sequence 2 by 2 steps
    schedule.add_reorder_rule(2, 2)?;

    let packets = source_packets(5)?;
    let (delivered, journal) = inject_packets(packets, schedule)?;

    // Seq 2 delayed by 2 steps:
    // Packet 1 emitted
    // Packet 2 delayed (remaining=2)
    // Packet 3 emitted (remaining=1)
    // Packet 4 emitted (remaining=0 -> seq 2 emitted after 4)
    // Packet 5 emitted
    assert_eq!(delivered.len(), 5);
    assert_eq!(delivered[0].sequence, 1);
    assert_eq!(delivered[1].sequence, 3);
    assert_eq!(delivered[2].sequence, 4);
    assert_eq!(delivered[3].sequence, 2);
    assert_eq!(delivered[4].sequence, 5);

    assert_eq!(journal.reordered_sequences, vec![2]);
    Ok(())
}

#[test]
fn fault_injector_injected_gap_witness_distinguishes_absence() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(404, 8)?;
    schedule.add_gap(3, 5, "simulated_camera_occlusion_test")?;

    let packets = source_packets(7)?;
    let first_gap_capture = packets[2].capture;
    let (stream_items, journal) = inject_stream(packets, schedule)?;

    // Stream must produce:
    // seq 1: Packet
    // seq 2: Packet
    // InjectedGap witness for 3..=5
    // seq 6: Packet
    // seq 7: Packet
    assert_eq!(stream_items.len(), 5);
    assert!(matches!(stream_items[0], FaultStreamItem::Packet { .. }));

    let p0 = stream_items[0]
        .as_packet()
        .ok_or("expected packet at index 0")?;
    let p1 = stream_items[1]
        .as_packet()
        .ok_or("expected packet at index 1")?;
    assert_eq!(p0.sequence, 1);
    assert_eq!(p1.sequence, 2);

    // Item 2 is the typed InjectedGap witness!
    match &stream_items[2] {
        FaultStreamItem::InjectedGap(witness) => {
            let witness: &InjectedGapWitness = witness;
            assert_eq!(witness.start_sequence, 3);
            assert_eq!(witness.end_sequence, 5);
            assert_eq!(witness.packet_count(), 3);
            assert_eq!(witness.reason, "simulated_camera_occlusion_test");
            assert_eq!(witness.schedule_seed, 404);
            assert!(witness.contains_sequence(3));
            assert!(witness.contains_sequence(4));
            assert!(witness.contains_sequence(5));
            assert!(!witness.contains_sequence(6));

            // Witness has valid non-zero content digest
            assert_ne!(witness.witness_digest, ContentDigest::sha256(&[]));

            // The witness carries the real 7.1 capture interval of the first gapped packet.
            assert_eq!(witness.interval, Some(first_gap_capture));
        }
        other => return Err(format!("expected InjectedGap item, got {other:?}").into()),
    }

    let p3 = stream_items[3]
        .as_packet()
        .ok_or("expected packet at index 3")?;
    let p4 = stream_items[4]
        .as_packet()
        .ok_or("expected packet at index 4")?;
    assert_eq!(p3.sequence, 6);
    assert_eq!(p4.sequence, 7);

    // Journal contains the gap witness
    assert_eq!(journal.gap_witnesses.len(), 1);
    assert_eq!(journal.gap_witnesses[0].start_sequence, 3);
    assert_eq!(journal.gap_witnesses[0].end_sequence, 5);

    Ok(())
}

#[test]
fn fault_injector_seeded_stochastic_bit_identical_replay() -> Result<(), Box<dyn Error>> {
    let seed = 0x9a8b_7c6d_5e4f_3210_u64;
    let make_schedule = |s: u64| -> Result<PacketFaultSchedule, Box<dyn Error>> {
        let mut sched = PacketFaultSchedule::new(s, 8, 128)?;
        let profile = StochasticFaultProfile::new(
            150_000, // 15% loss
            100_000, // 10% dup
            2,       // up to 2 duplicates
            200_000, // 20% reorder
            4,       // up to 4 steps reorder
        )?;
        sched.set_stochastic_profile(profile)?;
        Ok(sched)
    };

    let packets = source_packets(50)?;

    let (items_a, journal_a) = inject_stream(packets.clone(), make_schedule(seed)?)?;
    let (items_b, journal_b) = inject_stream(packets.clone(), make_schedule(seed)?)?;

    // Must be BIT-IDENTICAL across runs from the same seed
    assert_eq!(items_a, items_b);
    assert_eq!(journal_a, journal_b);
    assert_eq!(journal_a.journal_digest, journal_b.journal_digest);
    assert_eq!(journal_a.fault_evidence, journal_b.fault_evidence);

    // Varying seed produces distinct output
    let (_items_diff, journal_diff) = inject_stream(packets, make_schedule(seed ^ 0x5555)?)?;
    assert_ne!(journal_a.journal_digest, journal_diff.journal_digest);

    Ok(())
}

#[test]
fn fault_injector_bounds_reorder_window_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    // Exactly at bound: succeeds
    let at_bound = PacketFaultSchedule::new(1, MAX_REORDER_WINDOW, MAX_BUFFER_CAPACITY);
    assert!(at_bound.is_ok());

    // Bound + 1: fails with typed error
    let above_bound = PacketFaultSchedule::new(1, MAX_REORDER_WINDOW + 1, MAX_BUFFER_CAPACITY);
    match above_bound {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_REORDER_WINDOW + 1);
            assert_eq!(max, MAX_REORDER_WINDOW);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_bounds_duplicate_copies_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(2, 4)?;

    // Exactly at bound: succeeds
    assert!(
        schedule
            .add_duplicate_rule(10, MAX_DUPLICATE_COPIES)
            .is_ok()
    );

    // Bound + 1: fails with typed error
    match schedule.add_duplicate_rule(11, MAX_DUPLICATE_COPIES + 1) {
        Err(PacketFaultError::DuplicateCopiesExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_DUPLICATE_COPIES + 1);
            assert_eq!(max, MAX_DUPLICATE_COPIES);
        }
        other => return Err(format!("expected DuplicateCopiesExceedsBound, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_bounds_buffer_capacity_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    // Exactly at bound: succeeds
    let at_bound = PacketFaultSchedule::new(3, 4, MAX_BUFFER_CAPACITY);
    assert!(at_bound.is_ok());

    // Bound + 1: fails with typed error
    let above_bound = PacketFaultSchedule::new(3, 4, MAX_BUFFER_CAPACITY + 1);
    match above_bound {
        Err(PacketFaultError::BufferCapacityExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_BUFFER_CAPACITY + 1);
            assert_eq!(max, MAX_BUFFER_CAPACITY);
        }
        other => return Err(format!("expected BufferCapacityExceedsBound, got {other:?}").into()),
    }

    // Now test runtime queue capacity overflow at bound and bound+1
    // Create schedule with buffer capacity of 2
    let mut small_buf_sched = PacketFaultSchedule::new(4, 8, 2)?;
    small_buf_sched.add_reorder_rule(1, 4)?;
    small_buf_sched.add_reorder_rule(2, 4)?;
    small_buf_sched.add_reorder_rule(3, 4)?;

    let mut injector = PacketFaultInjector::new(small_buf_sched);
    let packets = source_packets(3)?;

    // Pushing packet 1: buffered (count=1 <= 2)
    assert!(injector.push(packets[0].clone()).is_ok());
    // Pushing packet 2: buffered (count=2 <= 2, exactly at bound)
    assert!(injector.push(packets[1].clone()).is_ok());
    // Pushing packet 3: buffer would reach 3 > 2 (bound + 1) -> fails with BufferCapacityExceeded
    match injector.push(packets[2].clone()) {
        Err(PacketFaultError::BufferCapacityExceeded { current, capacity }) => {
            assert_eq!(current, 2);
            assert_eq!(capacity, 2);
        }
        other => return Err(format!("expected BufferCapacityExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_bounds_schedule_rules_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(5, 4)?;

    // Fill up to exactly MAX_SCHEDULE_RULES
    for seq in 1..=MAX_SCHEDULE_RULES as u64 {
        schedule.add_drop_rule(seq, "bulk_drop")?;
    }

    // Adding rule MAX_SCHEDULE_RULES + 1: fails with ScheduleCapacityExceeded
    match schedule.add_drop_rule((MAX_SCHEDULE_RULES + 1) as u64, "overflow_drop") {
        Err(PacketFaultError::ScheduleCapacityExceeded { current, max }) => {
            assert_eq!(current, MAX_SCHEDULE_RULES);
            assert_eq!(max, MAX_SCHEDULE_RULES);
        }
        other => return Err(format!("expected ScheduleCapacityExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_bounds_gap_length_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(6, 4)?;

    // Gap of length exactly MAX_GAP_LENGTH: succeeds
    assert!(schedule.add_gap(1, MAX_GAP_LENGTH, "max_gap").is_ok());

    // Gap of length MAX_GAP_LENGTH + 1: fails with GapLengthExceedsBound
    match schedule.add_gap(1, MAX_GAP_LENGTH + 1, "excess_gap") {
        Err(PacketFaultError::GapLengthExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_GAP_LENGTH + 1);
            assert_eq!(max, MAX_GAP_LENGTH);
        }
        other => return Err(format!("expected GapLengthExceedsBound, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_injector_works_with_7_1_virtual_source_packets() -> Result<(), Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: fss_core::CapsuleId::parse("capture:fault:71")?,
        sensor_id: SensorId::parse("sensor:cam:driveway")?,
        seed: 0x7171,
        packet_count: 8,
        packet_bytes: 64,
        start_ns: 1_000_000_000,
        period_ns: 33_333_333,
        uncertainty_ns: 500_000,
    };

    let source_packets = generate_source(&spec)?;
    assert_eq!(source_packets.len(), 8);

    let mut schedule = PacketFaultSchedule::with_deterministic_rules(710, 4)?;
    schedule.add_drop_rule(2, "wireless_glitch")?;
    schedule.add_duplicate_rule(4, 1)?;
    schedule.add_reorder_rule(6, 2)?;

    let (injected_items, journal) = inject_stream(source_packets, schedule)?;

    // Verify 7.1 SourcePacket items are processed with exact digests and metadata preserved
    let mut seen_sequences = Vec::new();
    for item in &injected_items {
        if let FaultStreamItem::Packet {
            packet,
            is_duplicate,
            ..
        } = item
        {
            seen_sequences.push((packet.sequence, *is_duplicate));
            // Verify packet digest matches payload
            assert_eq!(packet.digest, ContentDigest::sha256(&packet.bytes));
            assert_eq!(packet.sensor_id, spec.sensor_id);
        }
    }

    // Sequence 2 dropped
    assert!(!seen_sequences.iter().any(|(s, _)| *s == 2));
    // Sequence 4 duplicated
    let dup_4_count = seen_sequences.iter().filter(|(s, _)| *s == 4).count();
    assert_eq!(dup_4_count, 2);

    assert_eq!(journal.lost_sequences, vec![2]);
    assert_eq!(journal.duplicated_sequences, vec![4]);
    assert_eq!(journal.reordered_sequences, vec![6]);

    Ok(())
}

#[test]
fn deterministic_prng_seed_zero_and_magic_seed_safety() -> Result<(), Box<dyn Error>> {
    // Verify PRNG does not degenerate on zero or magic seeds
    let mut prng_zero = DeterministicFaultPrng::new(0);
    let mut prng_magic = DeterministicFaultPrng::new(0x9e37_79b9_7f4a_7c15_u64);

    let v0 = prng_zero.next_u64();
    let vm = prng_magic.next_u64();

    assert_ne!(v0, 0);
    assert_ne!(vm, 0);
    assert_ne!(v0, vm);

    // Next draws must not be zero
    for _ in 0..20 {
        assert_ne!(prng_zero.next_u64(), 0);
        assert_ne!(prng_magic.next_u64(), 0);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// review-444 regressions
// ---------------------------------------------------------------------------

/// Seeds that collided under the old XOR initialization, plus edge seeds.
const REVIEW_SEEDS: [u64; 7] = [
    0,
    0x9e37_79b9_7f4a_7c15,
    0x4f82_338b_aed8_9116,
    0xd1b5_4a32_d192_ed03,
    1,
    u64::MAX,
    // Seed whose SplitMix64 state is exactly zero on the first draw.
    0x61c8_8646_80b5_83eb,
];

/// Finding 1: distinct seeds must produce distinct PRNG streams.
#[test]
fn prng_distinct_seeds_produce_distinct_streams() {
    let streams: Vec<Vec<u64>> = REVIEW_SEEDS
        .iter()
        .map(|seed| {
            let mut prng = DeterministicFaultPrng::new(*seed);
            (0..64).map(|_| prng.next_u64()).collect()
        })
        .collect();
    for (i, a) in streams.iter().enumerate() {
        for (j, b) in streams.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a[0], b[0],
                "seeds {:#x} and {:#x} share a first draw",
                REVIEW_SEEDS[i], REVIEW_SEEDS[j]
            );
            assert_ne!(
                a, b,
                "seeds {:#x} and {:#x} share a stream",
                REVIEW_SEEDS[i], REVIEW_SEEDS[j]
            );
        }
    }
}

/// Finding 1: the formerly colliding seeds drive observably different stochastic injections.
#[test]
fn prng_formerly_colliding_seeds_drive_distinct_injections() -> Result<(), Box<dyn Error>> {
    let packets = source_packets(50)?;
    let mut digests = Vec::new();
    for seed in [0, 0x9e37_79b9_7f4a_7c15, 0x4f82_338b_aed8_9116] {
        let mut schedule = PacketFaultSchedule::new(seed, 8, 128)?;
        schedule.set_stochastic_profile(StochasticFaultProfile::new(
            150_000, 100_000, 2, 200_000, 4,
        )?)?;
        let (_items, journal) = inject_stream(packets.clone(), schedule)?;
        digests.push(journal.journal_digest);
    }
    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[0], digests[2]);
    assert_ne!(digests[1], digests[2]);
    Ok(())
}

/// Finding 1: the PRNG can never be stuck at zero, including for the seed whose state passes
/// through zero on its first draw.
#[test]
fn prng_is_never_stuck_at_zero() {
    for seed in REVIEW_SEEDS {
        let mut prng = DeterministicFaultPrng::new(seed);
        let mut previous = prng.next_u64();
        let mut zero_draws = usize::from(previous == 0);
        for _ in 0..1_024 {
            let next = prng.next_u64();
            assert_ne!(next, previous, "seed {seed:#x} repeated a draw");
            zero_draws += usize::from(next == 0);
            previous = next;
        }
        assert!(
            zero_draws <= 1,
            "seed {seed:#x} drew zero {zero_draws} times"
        );
        assert_eq!(prng.draw_count(), 1_025);
        assert_eq!(prng.seed(), seed);
    }
}

/// Finding 2: a push rejected for runtime capacity leaves the injector untouched (no aging, no
/// input count, no displaced held packet), and every packet is still accounted for afterwards.
#[test]
fn push_rejected_at_capacity_is_atomic_and_loses_no_packet() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::new(21, 8, 1)?;
    schedule.add_reorder_rule(1, 3)?;
    schedule.add_reorder_rule(2, 1)?;
    let packets = source_packets(5)?;
    let mut injector = PacketFaultInjector::new(schedule);

    assert!(injector.push(packets[0].clone())?.is_empty());
    assert_eq!(injector.buffered_packet_count(), 1);

    match injector.push(packets[1].clone()) {
        Err(PacketFaultError::BufferCapacityExceeded { current, capacity }) => {
            assert_eq!(current, 1);
            assert_eq!(capacity, 1);
        }
        other => return Err(format!("expected BufferCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(injector.buffered_packet_count(), 1);

    // Packet 1 still needs exactly three accepted pushes; the rejected push did not age it.
    assert_eq!(
        packet_sequences(&injector.push(packets[2].clone())?),
        vec![3]
    );
    assert_eq!(
        packet_sequences(&injector.push(packets[3].clone())?),
        vec![4]
    );
    assert_eq!(
        packet_sequences(&injector.push(packets[4].clone())?),
        vec![5, 1]
    );

    // The caller retries the rejected packet once capacity is free.
    assert!(injector.push(packets[1].clone())?.is_empty());
    let (flushed, journal) = injector.finish()?;
    assert_eq!(packet_sequences(&flushed), vec![2]);

    assert_eq!(journal.total_input_packets, 5);
    assert_eq!(journal.total_delivered_packets, 5);
    assert!(journal.lost_sequences.is_empty());
    assert_eq!(journal.reordered_sequences, vec![1, 2]);
    // Sequence 1 held for its full delay of 3, released after 3, 4, 5 (delivery indices 1..=3).
    assert_eq!(reorder_evidence(&journal, 1)?, (3, 4));
    // Sequence 2 flushed at stream end with no push after its admission.
    assert_eq!(reorder_evidence(&journal, 2)?, (0, 5));
    Ok(())
}

/// Finding 2: with zero runtime capacity every reordered packet is rejected without being
/// counted, delivered, or consuming the stream.
#[test]
fn push_rejected_with_zero_capacity_counts_nothing() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::new(22, 8, 0)?;
    schedule.set_stochastic_profile(StochasticFaultProfile::new(0, 0, 0, 1_000_000, 4)?)?;
    let packets = source_packets(3)?;
    let mut injector = PacketFaultInjector::new(schedule);
    for packet in packets {
        match injector.push(packet) {
            Err(PacketFaultError::BufferCapacityExceeded { current, capacity }) => {
                assert_eq!(current, 0);
                assert_eq!(capacity, 0);
            }
            other => {
                return Err(format!("expected BufferCapacityExceeded, got {other:?}").into());
            }
        }
    }
    let (flushed, journal) = injector.finish()?;
    assert!(flushed.is_empty());
    assert_eq!(journal.total_input_packets, 0);
    assert_eq!(journal.total_delivered_packets, 0);
    assert!(journal.fault_evidence.is_empty());
    Ok(())
}

/// Finding 2 (review premise): a packet maturing on this push frees its slot first, so the
/// review's proposed scenario delivers the matured packet instead of rejecting the push.
#[test]
fn matured_packet_frees_capacity_before_reorder_admission() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::new(100, 8, 1)?;
    schedule.add_reorder_rule(1, 1)?;
    schedule.add_reorder_rule(2, 4)?;
    let mut injector = PacketFaultInjector::new(schedule);
    let packets = source_packets(2)?;

    assert!(injector.push(packets[0].clone())?.is_empty());
    assert_eq!(
        packet_sequences(&injector.push(packets[1].clone())?),
        vec![1]
    );
    assert_eq!(injector.buffered_packet_count(), 1);
    assert_eq!(packet_sequences(&injector.drain()?), vec![2]);
    assert_eq!(injector.buffered_packet_count(), 0);
    Ok(())
}

/// Finding 3: reorder evidence records the real held delay, for both push release and drain.
#[test]
fn reorder_evidence_records_real_delay_steps() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(200, 8)?;
    schedule.add_reorder_rule(1, 3)?;
    schedule.add_reorder_rule(4, 3)?;

    let (items, journal) = inject_stream(source_packets(5)?, schedule)?;
    assert_eq!(
        shape(&items),
        vec![
            Shape::Packet(2),
            Shape::Packet(3),
            Shape::Packet(1),
            Shape::Packet(5),
            Shape::Packet(4),
        ]
    );
    // Sequence 1 matured after its full scheduled delay of 3.
    assert_eq!(reorder_evidence(&journal, 1)?, (3, 3));
    // Sequence 4 was flushed at stream end after being held for one push (sequence 5).
    assert_eq!(reorder_evidence(&journal, 4)?, (1, 5));
    Ok(())
}

/// Finding 4: packets suppressed by a scheduled gap still age the reorder buffer, so a held
/// packet is released after exactly its scheduled delay even across a gap.
#[test]
fn scheduled_gap_keeps_reorder_countdown_running() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(404, 8)?;
    schedule.add_reorder_rule(2, 2)?;
    schedule.add_gap(3, 5, "occlusion")?;

    let packets = source_packets(8)?;
    let first_gap_capture = packets[2].capture;
    let (items, journal) = inject_stream(packets, schedule)?;
    assert_eq!(
        shape(&items),
        vec![
            Shape::Packet(1),
            Shape::Gap(3, 5),
            Shape::Packet(2),
            Shape::Packet(6),
            Shape::Packet(7),
            Shape::Packet(8),
        ]
    );
    assert_eq!(reorder_evidence(&journal, 2)?, (2, 2));
    assert_eq!(journal.lost_sequences, vec![3, 4, 5]);
    assert_eq!(journal.gap_witnesses.len(), 1);
    assert_eq!(journal.gap_witnesses[0].interval, Some(first_gap_capture));
    assert_eq!(journal.total_input_packets, 8);
    assert_eq!(journal.total_delivered_packets, 5);
    assert_eq!(journal.total_emitted_items, 6);
    Ok(())
}

/// Finding 5: an inverted mock capture interval is a typed error, never an absent interval.
#[test]
fn mock_packet_rejects_inverted_capture_interval_with_typed_error() -> Result<(), Box<dyn Error>> {
    let sensor = SensorId::parse("sensor:mock:cam1")?;

    // Degenerate interval (earliest == latest) is the valid boundary.
    let point = MockFramePacket::new(
        sensor.clone(),
        1,
        TimestampNs(1_000),
        TimestampNs(1_000),
        vec![1],
    )?;
    assert_eq!(
        point.capture_interval(),
        Some(CaptureInterval::new(
            TimestampNs(1_000),
            TimestampNs(1_000)
        )?)
    );

    match MockFramePacket::new(sensor, 2, TimestampNs(1_001), TimestampNs(1_000), vec![2]) {
        Err(ContractError::InvertedTimeInterval) => Ok(()),
        other => Err(format!("expected InvertedTimeInterval, got {other:?}").into()),
    }
}

/// Finding 5 / genericity: a custom packet type flows through the injector and its validated
/// capture interval reaches the gap witness.
#[test]
fn fault_injector_is_generic_over_custom_packet_types() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(505, 8)?;
    schedule.add_gap(2, 3, "mock_occlusion")?;
    schedule.add_duplicate_rule(4, 1)?;

    let packets = create_mock_packets(4)?;
    let first_gap_capture = packets[1].capture;
    let (items, journal) = inject_stream(packets, schedule)?;
    assert_eq!(
        shape(&items),
        vec![
            Shape::Packet(1),
            Shape::Gap(2, 3),
            Shape::Packet(4),
            Shape::Duplicate(4),
        ]
    );
    assert_eq!(journal.gap_witnesses[0].interval, Some(first_gap_capture));
    Ok(())
}

/// Finding 6: rules and gaps share one MAX_SCHEDULE_RULES bound (rules filled first).
#[test]
fn schedule_capacity_bounds_rules_and_gaps_combined() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(400, 8)?;
    for seq in 1..MAX_SCHEDULE_RULES as u64 {
        schedule.add_drop_rule(seq, "rule")?;
    }
    // Exactly at bound: the last slot may be a gap.
    schedule.add_gap(10_000, 10_001, "gap_at_bound")?;
    assert_eq!(schedule.schedule_entry_count(), MAX_SCHEDULE_RULES);

    // Bound + 1: both a further gap and a further rule are rejected.
    match schedule.add_gap(20_000, 20_001, "gap_over_bound") {
        Err(PacketFaultError::ScheduleCapacityExceeded { current, max }) => {
            assert_eq!(current, MAX_SCHEDULE_RULES);
            assert_eq!(max, MAX_SCHEDULE_RULES);
        }
        other => return Err(format!("expected ScheduleCapacityExceeded, got {other:?}").into()),
    }
    match schedule.add_reorder_rule(30_000, 1) {
        Err(PacketFaultError::ScheduleCapacityExceeded { current, max }) => {
            assert_eq!(current, MAX_SCHEDULE_RULES);
            assert_eq!(max, MAX_SCHEDULE_RULES);
        }
        other => return Err(format!("expected ScheduleCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(schedule.schedule_entry_count(), MAX_SCHEDULE_RULES);
    Ok(())
}

/// Finding 6: rules and gaps share one MAX_SCHEDULE_RULES bound (gaps filled first).
#[test]
fn schedule_capacity_bounds_gaps_and_rules_combined() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(401, 8)?;
    for index in 1..MAX_SCHEDULE_RULES as u64 {
        schedule.add_gap(index * 2, index * 2, "gap")?;
    }
    // Exactly at bound: the last slot may be a rule.
    schedule.add_duplicate_rule(1, 1)?;
    assert_eq!(schedule.schedule_entry_count(), MAX_SCHEDULE_RULES);

    // Bound + 1: rejected for both entry kinds.
    match schedule.add_drop_rule(3, "rule_over_bound") {
        Err(PacketFaultError::ScheduleCapacityExceeded { current, max }) => {
            assert_eq!(current, MAX_SCHEDULE_RULES);
            assert_eq!(max, MAX_SCHEDULE_RULES);
        }
        other => return Err(format!("expected ScheduleCapacityExceeded, got {other:?}").into()),
    }
    match schedule.add_gap(100_000, 100_000, "gap_over_bound") {
        Err(PacketFaultError::ScheduleCapacityExceeded { current, max }) => {
            assert_eq!(current, MAX_SCHEDULE_RULES);
            assert_eq!(max, MAX_SCHEDULE_RULES);
        }
        other => return Err(format!("expected ScheduleCapacityExceeded, got {other:?}").into()),
    }
    Ok(())
}

/// Finding 7: reorder rule delay at the schedule window and window + 1, plus the zero floor.
#[test]
fn add_reorder_rule_at_and_above_schedule_window() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::new(500, 10, 64)?;
    schedule.add_reorder_rule(1, 10)?;
    match schedule.add_reorder_rule(2, 11) {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, 11);
            assert_eq!(max, 10);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }
    match schedule.add_reorder_rule(3, 0) {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, 0);
            assert_eq!(max, 10);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }

    let mut widest = PacketFaultSchedule::new(501, MAX_REORDER_WINDOW, MAX_BUFFER_CAPACITY)?;
    widest.add_reorder_rule(1, MAX_REORDER_WINDOW)?;
    match widest.add_reorder_rule(2, MAX_REORDER_WINDOW + 1) {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_REORDER_WINDOW + 1);
            assert_eq!(max, MAX_REORDER_WINDOW);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }
    Ok(())
}

/// Finding 7: duplicate rule zero floor and a behavioral run at MAX_DUPLICATE_COPIES.
#[test]
fn duplicate_rule_at_bound_emits_every_copy() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(600, 8)?;
    match schedule.add_duplicate_rule(1, 0) {
        Err(PacketFaultError::DuplicateCopiesExceedsBound { requested, max }) => {
            assert_eq!(requested, 0);
            assert_eq!(max, MAX_DUPLICATE_COPIES);
        }
        other => return Err(format!("expected DuplicateCopiesExceedsBound, got {other:?}").into()),
    }
    schedule.add_duplicate_rule(2, MAX_DUPLICATE_COPIES)?;

    let (items, journal) = inject_stream(source_packets(3)?, schedule)?;
    let mut expected = vec![Shape::Packet(1), Shape::Packet(2)];
    expected.extend((0..MAX_DUPLICATE_COPIES).map(|_| Shape::Duplicate(2)));
    expected.push(Shape::Packet(3));
    assert_eq!(shape(&items), expected);

    let copy_indices: Vec<u32> = journal
        .fault_evidence
        .iter()
        .filter_map(|fault| match fault {
            InjectedFaultEvidence::Duplication {
                sequence: 2,
                copy_index,
                total_copies,
                ..
            } if *total_copies == MAX_DUPLICATE_COPIES => Some(*copy_index),
            _ => None,
        })
        .collect();
    assert_eq!(copy_indices, (1..=MAX_DUPLICATE_COPIES).collect::<Vec<_>>());
    Ok(())
}

/// Finding 7: every StochasticFaultProfile bound at bound and bound + 1.
#[test]
fn stochastic_profile_bounds_at_and_above() -> Result<(), Box<dyn Error>> {
    const PPM_MAX: u32 = 1_000_000;

    // All bounds exactly at their maximum: accepted.
    StochasticFaultProfile::new(
        PPM_MAX,
        PPM_MAX,
        MAX_DUPLICATE_COPIES,
        PPM_MAX,
        MAX_REORDER_WINDOW,
    )?;

    match StochasticFaultProfile::new(0, 0, MAX_DUPLICATE_COPIES + 1, 0, 1) {
        Err(PacketFaultError::DuplicateCopiesExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_DUPLICATE_COPIES + 1);
            assert_eq!(max, MAX_DUPLICATE_COPIES);
        }
        other => return Err(format!("expected DuplicateCopiesExceedsBound, got {other:?}").into()),
    }
    match StochasticFaultProfile::new(0, 0, 1, 0, MAX_REORDER_WINDOW + 1) {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_REORDER_WINDOW + 1);
            assert_eq!(max, MAX_REORDER_WINDOW);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }
    let over_rate = [
        StochasticFaultProfile::new(PPM_MAX + 1, 0, 1, 0, 1),
        StochasticFaultProfile::new(0, PPM_MAX + 1, 1, 0, 1),
        StochasticFaultProfile::new(0, 0, 1, PPM_MAX + 1, 1),
    ];
    for result in over_rate {
        match result {
            Err(PacketFaultError::InvalidPpmRate { rate_ppm }) => {
                assert_eq!(rate_ppm, PPM_MAX + 1);
            }
            other => return Err(format!("expected InvalidPpmRate, got {other:?}").into()),
        }
    }
    Ok(())
}

/// Finding 7: a stochastic profile is bounded by its schedule's reorder window.
#[test]
fn set_stochastic_profile_respects_schedule_reorder_window() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::new(700, 4, 16)?;
    schedule.set_stochastic_profile(StochasticFaultProfile::new(0, 0, 1, 500_000, 4)?)?;
    match schedule.set_stochastic_profile(StochasticFaultProfile::new(0, 0, 1, 500_000, 5)?) {
        Err(PacketFaultError::ReorderWindowExceedsBound { requested, max }) => {
            assert_eq!(requested, 5);
            assert_eq!(max, 4);
        }
        other => return Err(format!("expected ReorderWindowExceedsBound, got {other:?}").into()),
    }
    Ok(())
}

/// Finding 7: runtime buffer capacity at the largest bound that the reorder window can reach
/// (MAX_REORDER_WINDOW - 1 held packets plus one admission) and at bound + 1.
#[test]
fn runtime_buffer_capacity_at_and_above_reachable_bound() -> Result<(), Box<dyn Error>> {
    let capacity = MAX_REORDER_WINDOW - 1;
    let mut schedule = PacketFaultSchedule::new(800, MAX_REORDER_WINDOW, capacity)?;
    for seq in 1..=MAX_REORDER_WINDOW as u64 {
        schedule.add_reorder_rule(seq, MAX_REORDER_WINDOW)?;
    }
    let packets = source_packets(MAX_REORDER_WINDOW as u32)?;
    let mut injector = PacketFaultInjector::new(schedule);

    for packet in packets.iter().take(capacity) {
        assert!(injector.push(packet.clone())?.is_empty());
    }
    // Exactly at bound.
    assert_eq!(injector.buffered_packet_count(), capacity);

    // Bound + 1: rejected, and the held packets are untouched.
    match injector.push(packets[capacity].clone()) {
        Err(PacketFaultError::BufferCapacityExceeded {
            current,
            capacity: limit,
        }) => {
            assert_eq!(current, capacity);
            assert_eq!(limit, capacity);
        }
        other => return Err(format!("expected BufferCapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(injector.buffered_packet_count(), capacity);

    let (flushed, journal) = injector.finish()?;
    assert_eq!(
        packet_sequences(&flushed),
        (1..=capacity as u64).collect::<Vec<_>>()
    );
    assert_eq!(journal.total_input_packets, capacity as u64);
    assert_eq!(journal.total_delivered_packets, capacity as u64);
    Ok(())
}

/// Finding 7: at MAX_BUFFER_CAPACITY with every packet delayed by MAX_REORDER_WINDOW, the
/// buffer peaks at exactly MAX_REORDER_WINDOW, nothing is lost, and every packet released by a
/// push records the full window as its delay.
#[test]
fn runtime_buffer_occupancy_peaks_at_reorder_window_under_max_capacity()
-> Result<(), Box<dyn Error>> {
    const PACKETS: u64 = 300;
    let mut schedule = PacketFaultSchedule::new(900, MAX_REORDER_WINDOW, MAX_BUFFER_CAPACITY)?;
    for seq in 1..=PACKETS {
        schedule.add_reorder_rule(seq, MAX_REORDER_WINDOW)?;
    }
    let mut injector = PacketFaultInjector::new(schedule);
    let mut items = Vec::new();
    let mut peak = 0;
    for packet in source_packets(PACKETS as u32)? {
        items.extend(injector.push(packet)?);
        peak = peak.max(injector.buffered_packet_count());
    }
    assert_eq!(peak, MAX_REORDER_WINDOW);

    let (flushed, journal) = injector.finish()?;
    items.extend(flushed);
    let mut delivered = packet_sequences(&items);
    assert_eq!(delivered.len() as u64, PACKETS);
    delivered.sort_unstable();
    assert_eq!(delivered, (1..=PACKETS).collect::<Vec<_>>());

    let window = MAX_REORDER_WINDOW as u64;
    for seq in 1..=PACKETS {
        let (delay, _) = reorder_evidence(&journal, seq)?;
        let expected = if seq + window <= PACKETS {
            MAX_REORDER_WINDOW
        } else {
            (PACKETS - seq) as usize
        };
        assert_eq!(delay, expected, "sequence {seq}");
    }
    Ok(())
}

/// Finding 7: InjectedGapWitness length at MAX_GAP_LENGTH and MAX_GAP_LENGTH + 1.
#[test]
fn injected_gap_witness_length_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let sensor = SensorId::parse("sensor:cam:fault-contract")?;
    let witness = InjectedGapWitness::new(sensor.clone(), 1, MAX_GAP_LENGTH, None, "max", 1)?;
    assert_eq!(witness.packet_count(), MAX_GAP_LENGTH);
    match InjectedGapWitness::new(sensor, 1, MAX_GAP_LENGTH + 1, None, "over", 1) {
        Err(PacketFaultError::GapLengthExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_GAP_LENGTH + 1);
            assert_eq!(max, MAX_GAP_LENGTH);
        }
        other => return Err(format!("expected GapLengthExceedsBound, got {other:?}").into()),
    }
    Ok(())
}
