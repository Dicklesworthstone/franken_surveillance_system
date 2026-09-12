#![forbid(unsafe_code)]
//! Integration contract tests for deterministic virtual clock and source (FSS-013).

use std::error::Error;
use std::fs;

use fss_core::{CapsuleId, ContentDigest, OperationOutcome, RefusalReason, SensorId, TimestampNs};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryDirective, DeliveryPlan, MAX_SKEW_PPM, PacketFaultSchedule, ReferenceError,
    SourceFaultSchedule, VirtualCameraSpec, VirtualClock, VirtualSource, generate_source,
    generate_source_with_clock, inject_packets, run_reference_capture_with_clock,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::option_env!("CARGO_TARGET_TMPDIR").map(std::path::PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for attempt in 0..64 {
        let dir_name = format!("fss-ref-clock-source-{pid}-{now}-{attempt}-{name}");
        let dir = base.join(dir_name);
        if fs::create_dir(&dir).is_ok() {
            return dir.join(format!("{name}.journal"));
        }
    }
    base.join(format!(
        "fss-ref-clock-source-{pid}-{now}-fallback-{name}.journal"
    ))
}

fn create_spec(
    capture_id_str: &str,
    sensor_id_str: &str,
    seed: u64,
    packet_count: u32,
) -> Result<VirtualCameraSpec, Box<dyn Error>> {
    Ok(VirtualCameraSpec {
        capture_id: CapsuleId::parse(capture_id_str)?,
        sensor_id: SensorId::parse(sensor_id_str)?,
        seed,
        packet_count,
        packet_bytes: 64,
        start_ns: 1_000_000_000,
        period_ns: 33_333_333,
        uncertainty_ns: 500_000,
    })
}

#[test]
fn virtual_clock_deterministic_monotonic_advance() -> Result<(), Box<dyn Error>> {
    let start = TimestampNs(10_000_000_000);
    let mut clock_a = VirtualClock::new(0xdead_beef_cafe_u64, start);
    let mut clock_b = VirtualClock::new(0xdead_beef_cafe_u64, start);

    assert_eq!(clock_a.now(), start);
    assert_eq!(clock_b.now(), start);
    assert_eq!(clock_a.step_count(), 0);
    assert_eq!(clock_b.step_count(), 0);

    let period_ns = 20_000_000_u64;
    let mut prev_time = start;

    for step in 1..=50 {
        let next_a = clock_a.advance(period_ns)?;
        let next_b = clock_b.advance(period_ns)?;

        assert_eq!(next_a, next_b);
        assert!(next_a.0 > prev_time.0);
        assert_eq!(clock_a.step_count(), step);
        assert_eq!(clock_b.step_count(), step);
        prev_time = next_a;
    }

    assert_eq!(clock_a.now().0, start.0 + i128::from(50_u64 * period_ns));
    Ok(())
}

#[test]
fn virtual_clock_rejects_backward_steps_as_typed_faults() -> Result<(), Box<dyn Error>> {
    let anchor = TimestampNs(5_000_000_000);
    let mut clock = VirtualClock::new(42, anchor);

    // 1. step_backward must fail as BackwardStepAttempt and leave clock intact
    match clock.step_backward(1_000_000) {
        Err(ReferenceError::BackwardStepAttempt { current, attempted }) => {
            assert_eq!(current, anchor);
            assert_eq!(attempted, TimestampNs(4_999_000_000));
        }
        other => return Err(format!("expected BackwardStepAttempt, got {other:?}").into()),
    }
    assert_eq!(clock.now(), anchor);

    // 2. inject_backward_step must fail similarly
    match clock.inject_backward_step(500) {
        Err(ReferenceError::BackwardStepAttempt { current, attempted }) => {
            assert_eq!(current, anchor);
            assert_eq!(attempted, TimestampNs(4_999_999_500));
        }
        other => return Err(format!("expected BackwardStepAttempt, got {other:?}").into()),
    }
    assert_eq!(clock.now(), anchor);

    // 3. set_time backwards must fail
    match clock.set_time(TimestampNs(1_000_000_000)) {
        Err(ReferenceError::BackwardStepAttempt { current, attempted }) => {
            assert_eq!(current, anchor);
            assert_eq!(attempted, TimestampNs(1_000_000_000));
        }
        other => return Err(format!("expected BackwardStepAttempt, got {other:?}").into()),
    }
    assert_eq!(clock.now(), anchor);

    // 4. set_time forwards must succeed
    let forward_target = TimestampNs(8_000_000_000);
    let new_now = clock.set_time(forward_target)?;
    assert_eq!(new_now, forward_target);
    assert_eq!(clock.now(), forward_target);

    Ok(())
}

#[test]
fn virtual_clock_skew_and_jitter_injection() -> Result<(), Box<dyn Error>> {
    let start = TimestampNs(1_000_000);
    let mut clock = VirtualClock::new(99, start);

    // Valid skew within bounds
    clock.inject_skew(10_000)?; // +1%
    assert_eq!(clock.skew_ppm(), 10_000);

    let advanced = clock.advance(1_000_000)?;
    // nominal 1_000_000 + 10_000 ppm (10_000 ns) = 1_010_000
    assert_eq!(advanced, TimestampNs(2_010_000));

    // Invalid skew exceeding bounds
    match clock.inject_skew(MAX_SKEW_PPM + 1) {
        Err(ReferenceError::InvalidClockParameter(param)) => {
            assert_eq!(param, "skew_ppm");
        }
        other => return Err(format!("expected InvalidClockParameter, got {other:?}").into()),
    }

    match clock.inject_skew(-MAX_SKEW_PPM - 1) {
        Err(ReferenceError::InvalidClockParameter(param)) => {
            assert_eq!(param, "skew_ppm");
        }
        other => return Err(format!("expected InvalidClockParameter, got {other:?}").into()),
    }

    // Jitter determinism across identical seeds
    let mut clock_j1 = VirtualClock::new(12345, start);
    let mut clock_j2 = VirtualClock::new(12345, start);
    clock_j1.inject_jitter(50_000);
    clock_j2.inject_jitter(50_000);

    for _ in 0..20 {
        let t1 = clock_j1.advance(100_000)?;
        let t2 = clock_j2.advance(100_000)?;
        assert_eq!(t1, t2);
    }

    Ok(())
}

#[test]
fn virtual_clock_pause_injection() -> Result<(), Box<dyn Error>> {
    let start = TimestampNs(500_000_000);
    let mut clock = VirtualClock::new(7, start);

    let paused_time = clock.inject_pause(2_500_000_000)?;
    assert_eq!(paused_time, TimestampNs(3_000_000_000));
    assert_eq!(clock.now(), TimestampNs(3_000_000_000));

    let interval = clock.read_interval(100_000)?;
    assert_eq!(interval.earliest, TimestampNs(3_000_000_000));
    assert_eq!(interval.latest, TimestampNs(3_000_100_000));

    let next = clock.advance(10_000_000)?;
    assert_eq!(next, TimestampNs(3_010_000_000));
    Ok(())
}

#[test]
fn virtual_source_stepwise_emission_and_outcomes() -> Result<(), Box<dyn Error>> {
    let spec = create_spec("capture:stepwise:1", "sensor:front:1", 777, 4)?;
    let mut source = VirtualSource::new(spec.clone())?;

    source.inject_indeterminate_read(2, "optical sensor obstruction detected");
    source.inject_unobservable_read(3, "wireless link signal below threshold");
    source.inject_execution_failure(4, "hardware sensor FIFO buffer overflow");

    // Packet 1: Success
    let outcome1 = source.emit_packet()?;
    match outcome1 {
        OperationOutcome::Success(packet) => {
            assert_eq!(packet.sequence, 1);
            assert_eq!(packet.sensor_id, spec.sensor_id);
            assert_eq!(packet.bytes.len(), spec.packet_bytes);
            assert_eq!(packet.digest, ContentDigest::sha256(&packet.bytes));
            assert_eq!(packet.capture.earliest, TimestampNs(spec.start_ns));
            assert_eq!(
                packet.capture.latest,
                TimestampNs(spec.start_ns + i128::from(spec.uncertainty_ns))
            );
        }
        other => return Err(format!("expected Success for packet 1, got {other:?}").into()),
    }

    // Packet 2: Indeterminate
    let outcome2 = source.emit_packet()?;
    match outcome2 {
        OperationOutcome::Indeterminate(detail) => {
            assert_eq!(detail.phase, "virtual_source_capture");
            assert_eq!(detail.reason, "optical sensor obstruction detected");
            assert!(detail.reconciliation_guidance.contains("resnapshot"));
        }
        other => return Err(format!("expected Indeterminate for packet 2, got {other:?}").into()),
    }

    // Following reconciliation guidance: clear obstruction and re-poll sequence 2
    source.clear_indeterminate_read(2);
    let outcome2_retry = source.emit_packet()?;
    match outcome2_retry {
        OperationOutcome::Success(packet) => {
            assert_eq!(packet.sequence, 2);
        }
        other => {
            return Err(format!("expected Success for packet 2 re-poll, got {other:?}").into());
        }
    }

    // Packet 3: Unobservable
    let outcome3 = source.emit_packet()?;
    match outcome3 {
        OperationOutcome::UnauthorizedOrNotObservable(refusal) => {
            assert_eq!(refusal.reason, RefusalReason::NotObservable);
            assert_eq!(refusal.message, "wireless link signal below threshold");
            assert!(refusal.coverage_witness_required);
        }
        other => {
            return Err(format!(
                "expected UnauthorizedOrNotObservable for packet 3, got {other:?}"
            )
            .into());
        }
    }

    // Packet 4: Execution failure
    let outcome4 = source.emit_packet()?;
    match outcome4 {
        OperationOutcome::Failed(error) => {
            assert!(
                error
                    .message
                    .contains("hardware sensor FIFO buffer overflow")
            );
        }
        other => return Err(format!("expected Failed for packet 4, got {other:?}").into()),
    }

    // Packet 5: Beyond packet_count -> UnknownSourceSequence
    match source.emit_packet() {
        Err(ReferenceError::UnknownSourceSequence(5)) => {}
        other => return Err(format!("expected UnknownSourceSequence(5), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn virtual_source_generate_packets_fails_on_injected_faults() -> Result<(), Box<dyn Error>> {
    let spec = create_spec("capture:faults:1", "sensor:patio:1", 888, 3)?;

    // Indeterminate fault mapped to ReferenceError::IndeterminateSourceCapture
    let mut source_indet = VirtualSource::new(spec.clone())?;
    source_indet.inject_indeterminate_read(2, "stale sensor clock reference");
    match source_indet.generate_packets() {
        Err(ReferenceError::IndeterminateSourceCapture { sequence, reason }) => {
            assert_eq!(sequence, 2);
            assert_eq!(reason, "stale sensor clock reference");
        }
        other => return Err(format!("expected IndeterminateSourceCapture, got {other:?}").into()),
    }

    // Unobservable fault mapped to ReferenceError::UnobservableSourceCapture
    let mut source_unobs = VirtualSource::new(spec.clone())?;
    source_unobs.inject_unobservable_read(1, "camera privacy shutter engaged");
    match source_unobs.generate_packets() {
        Err(ReferenceError::UnobservableSourceCapture { sequence, reason }) => {
            assert_eq!(sequence, 1);
            assert_eq!(reason, "camera privacy shutter engaged");
        }
        other => return Err(format!("expected UnobservableSourceCapture, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn virtual_source_byte_identical_replay_from_seed() -> Result<(), Box<dyn Error>> {
    let spec1 = create_spec("capture:replay:1", "sensor:driveway:1", 0xcafe_babe_u64, 8)?;
    let spec2 = spec1.clone();

    let packets1 = generate_source(&spec1)?;
    let packets2 = generate_source(&spec2)?;

    assert_eq!(packets1.len(), 8);
    assert_eq!(packets2.len(), 8);

    for (p1, p2) in packets1.iter().zip(packets2.iter()) {
        assert_eq!(p1.sequence, p2.sequence);
        assert_eq!(p1.capture, p2.capture);
        assert_eq!(p1.bytes, p2.bytes);
        assert_eq!(p1.digest, p2.digest);
    }

    // Varying seed yields distinct bytes and digests
    let spec_diff_seed = create_spec("capture:replay:1", "sensor:driveway:1", 0xfeed_beef_u64, 8)?;
    let packets_diff = generate_source(&spec_diff_seed)?;
    assert_ne!(packets1[0].bytes, packets_diff[0].bytes);
    assert_ne!(packets1[0].digest, packets_diff[0].digest);

    // Varying sensor yields distinct payloads
    let spec_diff_sensor = create_spec("capture:replay:1", "sensor:garage:1", 0xcafe_babe_u64, 8)?;
    let packets_diff_sensor = generate_source(&spec_diff_sensor)?;
    assert_ne!(packets1[0].bytes, packets_diff_sensor[0].bytes);
    assert_ne!(packets1[0].digest, packets_diff_sensor[0].digest);

    Ok(())
}

#[test]
fn reference_capture_wires_virtual_clock_with_full_custody() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("custody-wired");
    let _ = fs::remove_file(&path);

    let spec = create_spec("capture:wired:1", "sensor:entryway:1", 0x1122_3344_u64, 5)?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:wired", IncompleteTailPolicy::Reject)?;

    let mut clock = VirtualClock::from_spec(&spec);
    let capture = run_reference_capture_with_clock(
        &spec,
        &mut clock,
        None,
        &plan,
        &mut objects,
        &mut ledger,
    )?;

    assert_eq!(capture.source_packets.len(), 5);
    assert_eq!(capture.delivery_packets.len(), 5);
    assert!(capture.continuity.exact_once_ordered);
    assert_eq!(capture.receipt.source_packet_count, 5);
    assert_eq!(capture.receipt.delivered_packet_count, 5);

    // Verify root-last custody in object store
    assert_eq!(
        objects.verify_closure(capture.receipt.capture_root)?,
        capture.receipt.closure_object_count
    );

    // Verify all source packets are stored and verified
    for pkt in &capture.source_packets {
        let stored_bytes = objects.read_verified(pkt.digest)?;
        assert_eq!(stored_bytes, pkt.bytes);
    }

    // Verify authority ledger committed one batch with anchor
    let current_anchor = ledger.current().anchor.clone();
    assert_eq!(current_anchor.commit_sequence, 1);
    assert_eq!(capture.receipt.authority_anchor, current_anchor);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn e2e_multi_camera_surveillance_scenario_with_clock_drift_and_replay() -> Result<(), Box<dyn Error>>
{
    let path_a = temp_journal("scenario-a");
    let path_b = temp_journal("scenario-b");
    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);

    // Extend fss-lab multi-camera pattern (cam-front + cam-side)
    let front_spec = create_spec("capture:e2e:front", "sensor:cam-front", 0x1001, 6)?;
    let side_spec = create_spec("capture:e2e:side", "sensor:cam-side", 0x2002, 6)?;

    // front camera uses nominal clock
    let mut clock_front_a = VirtualClock::from_spec(&front_spec);

    // side camera experiences +2000 ppm clock drift and 100 ns jitter
    let mut clock_side_a = VirtualClock::from_spec(&side_spec);
    clock_side_a.inject_skew(2_000)?;
    clock_side_a.inject_jitter(100);

    let plan = DeliveryPlan::identity(6)?;
    let mut objects_a = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut ledger_a =
        DurableReferenceLedger::open(&path_a, "site:lab-e2e", IncompleteTailPolicy::Reject)?;

    // Execute capture for both cameras into shared ledger and object custody
    let capture_front_a = run_reference_capture_with_clock(
        &front_spec,
        &mut clock_front_a,
        None,
        &plan,
        &mut objects_a,
        &mut ledger_a,
    )?;

    let capture_side_a = run_reference_capture_with_clock(
        &side_spec,
        &mut clock_side_a,
        None,
        &plan,
        &mut objects_a,
        &mut ledger_a,
    )?;

    assert_eq!(ledger_a.current().anchor.commit_sequence, 2);

    // Second run: prove byte-identical replay
    let mut clock_front_b = VirtualClock::from_spec(&front_spec);
    let mut clock_side_b = VirtualClock::from_spec(&side_spec);
    clock_side_b.inject_skew(2_000)?;
    clock_side_b.inject_jitter(100);

    let mut objects_b = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut ledger_b =
        DurableReferenceLedger::open(&path_b, "site:lab-e2e", IncompleteTailPolicy::Reject)?;

    let capture_front_b = run_reference_capture_with_clock(
        &front_spec,
        &mut clock_front_b,
        None,
        &plan,
        &mut objects_b,
        &mut ledger_b,
    )?;

    let capture_side_b = run_reference_capture_with_clock(
        &side_spec,
        &mut clock_side_b,
        None,
        &plan,
        &mut objects_b,
        &mut ledger_b,
    )?;

    assert_eq!(capture_front_a, capture_front_b);
    assert_eq!(capture_side_a, capture_side_b);
    assert_eq!(clock_front_a, clock_front_b);
    assert_eq!(clock_side_a, clock_side_b);
    assert_eq!(ledger_a.batches(), ledger_b.batches());
    assert_eq!(ledger_a.current().anchor, ledger_b.current().anchor);

    // Verify clock skew produced strictly monotonic, drifted capture intervals
    for window in capture_side_a.source_packets.windows(2) {
        assert!(window[1].capture.earliest.0 > window[0].capture.earliest.0);
        assert!(window[1].capture.latest.0 > window[0].capture.latest.0);
    }

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
    Ok(())
}

#[test]
fn test_clock_prng_seed_zero_freeze_degeneracy() -> Result<(), Box<dyn Error>> {
    let magic_seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut clock = VirtualClock::new(magic_seed, TimestampNs(1_000_000));
    clock.inject_jitter(10_000);

    let mut saw_jitter = false;
    for _ in 0..50 {
        let t_before = clock.now();
        let t_after = clock.advance(100_000)?;
        if t_after.0 - t_before.0 > 100_000 {
            saw_jitter = true;
            break;
        }
    }
    assert!(
        saw_jitter,
        "Jitter was permanently suppressed due to PRNG zero state lockup!"
    );
    Ok(())
}

#[test]
fn test_clock_advance_jitter_overflow_no_panic() -> Result<(), Box<dyn Error>> {
    let mut clock = VirtualClock::new(42, TimestampNs(1_000_000));
    clock.inject_jitter(u64::MAX);

    let res = clock.advance(10_000);
    assert!(
        res.is_ok(),
        "advance should not panic on u64::MAX jitter bound"
    );
    Ok(())
}

#[test]
fn test_clock_advance_rejects_non_positive_delta() -> Result<(), Box<dyn Error>> {
    let mut clock = VirtualClock::new(42, TimestampNs(1_000_000));
    let initial_time = clock.now();
    let initial_steps = clock.step_count();

    let res = clock.advance(0);
    assert!(matches!(
        res,
        Err(ReferenceError::BackwardStepAttempt { .. })
    ));
    assert_eq!(clock.now(), initial_time);
    assert_eq!(clock.step_count(), initial_steps);
    Ok(())
}

#[test]
fn test_virtual_source_execution_failure_error_taxonomy() -> Result<(), Box<dyn Error>> {
    let spec = create_spec("capture:fault:1", "sensor:cam:1", 1234, 2)?;
    spec.validate()?;
    let mut source = VirtualSource::new(spec)?;
    source.inject_execution_failure(1, "sensor FIFO overflow");

    let err = source.generate_packets();
    match err {
        Err(ReferenceError::ExecutionFailedSourceCapture { sequence, reason }) => {
            assert_eq!(sequence, 1);
            assert!(reason.contains("sensor FIFO overflow"));
        }
        other => {
            return Err(format!("expected ExecutionFailedSourceCapture, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn test_virtual_source_indeterminate_repoll_does_not_skip_sequence() -> Result<(), Box<dyn Error>> {
    let spec = create_spec("capture:indet:1", "sensor:cam:1", 5678, 3)?;
    spec.validate()?;
    let mut source = VirtualSource::new(spec)?;
    source.inject_indeterminate_read(2, "transient optical flare");

    // Packet 1: Success
    assert!(matches!(
        source.emit_packet()?,
        OperationOutcome::Success(_)
    ));
    assert_eq!(source.current_sequence(), 1);

    // Packet 2: Indeterminate
    let outcome2 = source.emit_packet()?;
    assert!(matches!(outcome2, OperationOutcome::Indeterminate(_)));
    assert_eq!(source.current_sequence(), 2);

    // Re-poll attempt: should retry sequence 2, not jump to sequence 3!
    let repoll = source.emit_packet()?;
    assert!(matches!(repoll, OperationOutcome::Indeterminate(_)));
    assert_eq!(
        source.current_sequence(),
        2,
        "Re-polling indeterminate read must not skip sequence to 3"
    );

    // After resolving fault, re-poll succeeds on sequence 2
    source.clear_indeterminate_read(2);
    let outcome2_resolved = source.emit_packet()?;
    assert!(matches!(outcome2_resolved, OperationOutcome::Success(_)));
    assert_eq!(source.current_sequence(), 2);

    // Next packet advances to sequence 3
    let outcome3 = source.emit_packet()?;
    assert!(matches!(outcome3, OperationOutcome::Success(_)));
    assert_eq!(source.current_sequence(), 3);

    Ok(())
}

#[test]
fn test_clock_skew_quantization_eliminated_via_residual_accumulator() -> Result<(), Box<dyn Error>>
{
    let start = TimestampNs(1_000_000_000);
    // Skew +500 ppm: 500 / 1_000_000.
    // 1000 steps of 1_000 ns (1 µs) = 1_000_000 ns nominal delta.
    // Without residual accumulator, 1_000 * 500 / 1_000_000 = 0 skew offset each step, losing 500 ns.
    // With accumulator, residual accumulates to produce exactly 500 ns skew offset in total.
    let mut clock_stepped = VirtualClock::new(42, start);
    clock_stepped.inject_skew(500)?;
    for _ in 0..1_000 {
        clock_stepped.advance(1_000)?;
    }

    // Compare with a single advance of 1_000_000 ns (1 ms)
    let mut clock_single = VirtualClock::new(42, start);
    clock_single.inject_skew(500)?;
    clock_single.advance(1_000_000)?;

    assert_eq!(
        clock_stepped.now(),
        clock_single.now(),
        "Accumulator must eliminate small-step quantization loss: stepped={:?} vs single={:?}",
        clock_stepped.now(),
        clock_single.now()
    );
    // Total nominal 1_000_000 + 500 skew = 1_000_000_500 ns elapsed from start
    assert_eq!(clock_stepped.now().0, start.0 + 1_000_500);
    assert_eq!(clock_stepped.step_count(), 1_000);
    assert_eq!(clock_single.step_count(), 1);

    Ok(())
}

#[test]
fn test_capture_pipeline_preserves_and_advances_time_authority() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("time-authority");
    let _ = fs::remove_file(&path);

    let spec_1 = create_spec("capture:seq:1", "sensor:cam:1", 100, 3)?;
    let plan = DeliveryPlan::identity(spec_1.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:time-test", IncompleteTailPolicy::Reject)?;

    let mut clock = VirtualClock::from_spec(&spec_1);
    let initial_now = clock.now();
    assert_eq!(clock.step_count(), 0);

    // First capture advances time authority explicitly in place
    let capture_1 = run_reference_capture_with_clock(
        &spec_1,
        &mut clock,
        None,
        &plan,
        &mut objects,
        &mut ledger,
    )?;

    assert_eq!(capture_1.clock, clock);
    assert!(clock.now().0 > initial_now.0);
    assert_eq!(clock.step_count(), 2);
    let intermediate_now = clock.now();

    // Second capture continues with the same mutated clock authority
    let spec_2 = create_spec("capture:seq:2", "sensor:cam:1", 200, 3)?;
    let capture_2 = run_reference_capture_with_clock(
        &spec_2,
        &mut clock,
        None,
        &plan,
        &mut objects,
        &mut ledger,
    )?;

    assert_eq!(capture_2.clock, clock);
    assert!(clock.now().0 > intermediate_now.0);
    assert_eq!(clock.step_count(), 4);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_capture_pipeline_unobservable_fault_outcome() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("unobservable-fault");
    let _ = fs::remove_file(&path);

    let spec = create_spec("capture:unobs:1", "sensor:cam:1", 42, 4)?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:fault-test", IncompleteTailPolicy::Reject)?;

    let mut faults = SourceFaultSchedule::new();
    faults.inject_unobservable(2, "hardware sensor lens obscured");

    let mut clock = VirtualClock::from_spec(&spec);
    let res = run_reference_capture_with_clock(
        &spec,
        &mut clock,
        Some(&faults),
        &plan,
        &mut objects,
        &mut ledger,
    );

    match res {
        Err(ReferenceError::UnobservableSourceCapture { sequence, reason }) => {
            assert_eq!(sequence, 2);
            assert!(reason.contains("hardware sensor lens obscured"));
        }
        other => return Err(format!("expected UnobservableSourceCapture, got {other:?}").into()),
    }

    // Ledger must be completely empty: no batch committed on unobservable source fault
    assert!(ledger.batches().is_empty());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_capture_pipeline_indeterminate_fault_outcome() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("indet-fault");
    let _ = fs::remove_file(&path);

    let spec = create_spec("capture:indet:pipe", "sensor:cam:1", 43, 3)?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:fault-test", IncompleteTailPolicy::Reject)?;

    let mut faults = SourceFaultSchedule::new();
    faults.inject_indeterminate(3, "transient bus glitch");

    let mut clock = VirtualClock::from_spec(&spec);
    let res = run_reference_capture_with_clock(
        &spec,
        &mut clock,
        Some(&faults),
        &plan,
        &mut objects,
        &mut ledger,
    );

    match res {
        Err(ReferenceError::IndeterminateSourceCapture { sequence, reason }) => {
            assert_eq!(sequence, 3);
            assert!(reason.contains("transient bus glitch"));
        }
        other => return Err(format!("expected IndeterminateSourceCapture, got {other:?}").into()),
    }

    assert!(ledger.batches().is_empty());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_capture_pipeline_delivery_gap_fault_witnessed_in_continuity() -> Result<(), Box<dyn Error>>
{
    let path = temp_journal("delivery-gap");
    let _ = fs::remove_file(&path);

    let spec = create_spec("capture:gap:1", "sensor:cam:1", 99, 4)?;
    // Directive intentionally omits sequence 2 to model packet loss/gap
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::exact(3),
        DeliveryDirective::exact(4),
    ])?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:gap-test", IncompleteTailPolicy::Reject)?;

    let mut clock = VirtualClock::from_spec(&spec);
    let capture = run_reference_capture_with_clock(
        &spec,
        &mut clock,
        None,
        &plan,
        &mut objects,
        &mut ledger,
    )?;

    // Source produced 4 packets, delivery received 3
    assert_eq!(capture.source_packets.len(), 4);
    assert_eq!(capture.delivery_packets.len(), 3);
    assert!(!capture.continuity.exact_once_ordered);
    assert_eq!(capture.continuity.missing_sequences, vec![2]);
    assert!(capture.continuity.duplicate_sequences.is_empty());
    assert!(capture.continuity.corrupted_sequences.is_empty());

    // Continuity digest was published to durable ledger
    assert_eq!(ledger.batches().len(), 1);
    assert_eq!(
        ledger.batches()[0].deltas[0].witness_digest,
        Some(capture.receipt.continuity_digest)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_capture_pipeline_delivery_corruption_fault_witnessed_in_continuity()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("delivery-corrupt");
    let _ = fs::remove_file(&path);

    let spec = create_spec("capture:corrupt:1", "sensor:cam:1", 101, 3)?;
    // Directive corrupts packet sequence 2
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::corrupt(2),
        DeliveryDirective::exact(3),
    ])?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:corrupt-test", IncompleteTailPolicy::Reject)?;

    let mut clock = VirtualClock::from_spec(&spec);
    let capture = run_reference_capture_with_clock(
        &spec,
        &mut clock,
        None,
        &plan,
        &mut objects,
        &mut ledger,
    )?;

    assert_eq!(capture.delivery_packets.len(), 3);
    assert_ne!(
        capture.delivery_packets[1].bytes,
        capture.source_packets[1].bytes
    );
    assert!(!capture.continuity.exact_once_ordered);
    assert_eq!(capture.continuity.corrupted_sequences, vec![2]);
    assert!(capture.continuity.missing_sequences.is_empty());

    assert_eq!(ledger.batches().len(), 1);
    assert_eq!(
        ledger.batches()[0].deltas[0].witness_digest,
        Some(capture.receipt.continuity_digest)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_capture_pipeline_packet_fault_injector_schedule_compatibility() -> Result<(), Box<dyn Error>>
{
    let spec = create_spec("capture:injector:1", "sensor:cam:1", 777, 5)?;
    let mut clock = VirtualClock::from_spec(&spec);
    let source_packets = generate_source_with_clock(&spec, &mut clock)?;
    assert_eq!(source_packets.len(), 5);

    // Reuse RusticGoose's 7.3 packet_fault injector over 7.1 SourcePacket
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(0xfeed_cafe, 4)?;
    schedule.add_drop_rule(2, "simulated network loss")?;
    schedule.add_duplicate_rule(4, 1)?;

    let (injected_packets, journal) = inject_packets(source_packets, schedule)?;

    assert_eq!(journal.lost_sequences, vec![2]);
    assert_eq!(journal.duplicated_sequences, vec![4]);
    assert_eq!(journal.total_input_packets, 5);

    let delivered_seqs: Vec<u64> = injected_packets.iter().map(|p| p.sequence).collect();
    // Packet 2 dropped, packet 4 duplicated
    assert_eq!(delivered_seqs, vec![1, 3, 4, 4, 5]);

    Ok(())
}
