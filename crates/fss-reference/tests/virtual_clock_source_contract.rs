#![forbid(unsafe_code)]
//! Integration contract tests for deterministic virtual clock and source (FSS-013).

use std::error::Error;
use std::fs;

use fss_core::{CapsuleId, ContentDigest, OperationOutcome, RefusalReason, SensorId, TimestampNs};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, MAX_SKEW_PPM, ReferenceError, VirtualCameraSpec, VirtualClock, VirtualSource,
    generate_source, run_reference_capture_with_clock,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-ref-clock-source-{}-{name}.journal",
        std::process::id()
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

    // Packet 3: Unobservable
    let outcome3 = source.emit_packet()?;
    match outcome3 {
        OperationOutcome::UnauthorizedOrNotObservable(refusal) => {
            assert_eq!(refusal.reason, RefusalReason::NotObservable);
            assert_eq!(refusal.message, "wireless link signal below threshold");
            assert!(refusal.coverage_witness_required);
        }
        other => {
            return Err(
                format!("expected UnauthorizedOrNotObservable for packet 3, got {other:?}").into(),
            );
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

    let clock = VirtualClock::from_spec(&spec);
    let capture = run_reference_capture_with_clock(&spec, clock, &plan, &mut objects, &mut ledger)?;

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
    let clock_front = VirtualClock::from_spec(&front_spec);

    // side camera experiences +2000 ppm clock drift and 100 ns jitter
    let mut clock_side = VirtualClock::from_spec(&side_spec);
    clock_side.inject_skew(2_000)?;
    clock_side.inject_jitter(100);

    let plan = DeliveryPlan::identity(6)?;
    let mut objects_a = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut ledger_a =
        DurableReferenceLedger::open(&path_a, "site:lab-e2e", IncompleteTailPolicy::Reject)?;

    // Execute capture for both cameras into shared ledger and object custody
    let capture_front_a = run_reference_capture_with_clock(
        &front_spec,
        clock_front.clone(),
        &plan,
        &mut objects_a,
        &mut ledger_a,
    )?;

    let capture_side_a = run_reference_capture_with_clock(
        &side_spec,
        clock_side.clone(),
        &plan,
        &mut objects_a,
        &mut ledger_a,
    )?;

    assert_eq!(ledger_a.current().anchor.commit_sequence, 2);

    // Second run: prove byte-identical replay
    let mut objects_b = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut ledger_b =
        DurableReferenceLedger::open(&path_b, "site:lab-e2e", IncompleteTailPolicy::Reject)?;

    let capture_front_b = run_reference_capture_with_clock(
        &front_spec,
        clock_front,
        &plan,
        &mut objects_b,
        &mut ledger_b,
    )?;

    let capture_side_b = run_reference_capture_with_clock(
        &side_spec,
        clock_side,
        &plan,
        &mut objects_b,
        &mut ledger_b,
    )?;

    assert_eq!(capture_front_a, capture_front_b);
    assert_eq!(capture_side_a, capture_side_b);
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
