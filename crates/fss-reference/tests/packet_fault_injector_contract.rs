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

use std::error::Error;

use fss_core::{CaptureInterval, ContentDigest, SensorId, TimestampNs};
use fss_reference::{
    DeterministicFaultPrng, FaultStreamItem, InjectedFaultEvidence, InjectedGapWitness,
    MAX_BUFFER_CAPACITY, MAX_DUPLICATE_COPIES, MAX_GAP_LENGTH, MAX_REORDER_WINDOW,
    MAX_SCHEDULE_RULES, PacketFaultError, PacketFaultInjector, PacketFaultSchedule,
    SequencedPacket, StochasticFaultProfile, VirtualCameraSpec, generate_source, inject_packets,
    inject_stream,
};

/// Custom mock packet verifying genericity over packet types (for 7.2 fixtures).
#[derive(Clone, Debug, Eq, PartialEq)]
struct MockFramePacket {
    sensor_id: SensorId,
    sequence: u64,
    timestamp_ns: i128,
    frame_payload: Vec<u8>,
}

impl SequencedPacket for MockFramePacket {
    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn sensor_id(&self) -> &SensorId {
        &self.sensor_id
    }

    fn capture_interval(&self) -> Option<CaptureInterval> {
        CaptureInterval::new(
            TimestampNs(self.timestamp_ns),
            TimestampNs(self.timestamp_ns + 33_333_333),
        )
        .ok()
    }

    fn content_digest(&self) -> Option<ContentDigest> {
        Some(ContentDigest::sha256(&self.frame_payload))
    }
}

fn create_mock_packets(count: u64) -> Result<Vec<MockFramePacket>, Box<dyn Error>> {
    let sensor = SensorId::parse("sensor:mock:cam1")?;
    let packets = (1..=count)
        .map(|seq| MockFramePacket {
            sensor_id: sensor.clone(),
            sequence: seq,
            timestamp_ns: 1_000_000_000 + i128::from(seq) * 33_333_333,
            frame_payload: format!("frame-payload-data-{seq}").into_bytes(),
        })
        .collect();
    Ok(packets)
}

#[test]
fn fault_injector_deterministic_loss_rule() -> Result<(), Box<dyn Error>> {
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(101, 8)?;
    schedule.add_drop_rule(3, "simulated_wireless_packet_drop")?;
    schedule.add_drop_rule(5, "crc_checksum_error_discard")?;

    let packets = create_mock_packets(6)?;
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
        InjectedFaultEvidence::Loss { sequence, reason, .. } => {
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

    let packets = create_mock_packets(3)?;
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

    let packets = create_mock_packets(5)?;
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

    let packets = create_mock_packets(7)?;
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

    let packets = create_mock_packets(50)?;

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
    assert!(schedule.add_duplicate_rule(10, MAX_DUPLICATE_COPIES).is_ok());

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
    let packets = create_mock_packets(3)?;

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
        if let FaultStreamItem::Packet { packet, is_duplicate, .. } = item {
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

    // Next draws must not be zero
    for _ in 0..20 {
        assert_ne!(prng_zero.next_u64(), 0);
        assert_ne!(prng_magic.next_u64(), 0);
    }

    Ok(())
}
