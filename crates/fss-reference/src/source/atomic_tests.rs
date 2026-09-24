#![forbid(unsafe_code)]
//! A fallible interval must not silently skip a packet or release an unresolved read.
use super::*;
use fss_core::TimestampNs;

type Test = Result<(), ReferenceError>;

fn spec(start_ns: i128) -> Result<VirtualCameraSpec, ReferenceError> {
    Ok(VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:atomic-source")?,
        sensor_id: SensorId::parse("sensor:atomic-source")?,
        seed: 91,
        packet_count: 3,
        packet_bytes: 17,
        start_ns,
        period_ns: 10,
        uncertainty_ns: 1,
    })
}

fn assert_same_state(actual: &VirtualSource, expected: &VirtualSource) {
    assert_eq!(actual.clock, expected.clock);
    assert_eq!(actual.current_sequence, expected.current_sequence);
    assert_eq!(actual.pending_indeterminate, expected.pending_indeterminate);
    assert_eq!(actual.payload_state, expected.payload_state);
    assert_eq!(actual.spec, expected.spec);
    assert_eq!(actual.indeterminate_faults, expected.indeterminate_faults);
    assert_eq!(actual.unobservable_faults, expected.unobservable_faults);
    assert_eq!(
        actual.execution_failure_faults,
        expected.execution_failure_faults
    );
}

#[test]
fn first_interval_overflow_leaves_sequence_zero_and_payload_unchanged() -> Test {
    let mut source = VirtualSource::new(spec(i128::MAX)?)?;
    let before = source.clone();
    for _ in 0..3 {
        assert!(matches!(
            source.emit_packet(),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert_same_state(&source, &before);
    }
    Ok(())
}

#[test]
fn interval_overflow_rolls_back_the_successful_speculative_clock_step() -> Test {
    let mut source = VirtualSource::new(spec(i128::MAX - 10)?)?;
    assert!(matches!(
        source.emit_packet()?,
        OperationOutcome::Success(_)
    ));
    let before = source.clone();
    // The time step to MAX succeeds; only the interval's upper bound overflows.
    assert!(matches!(
        source.emit_packet(),
        Err(ReferenceError::ArithmeticOverflow)
    ));
    assert_same_state(&source, &before);
    assert_eq!(source.current_sequence(), 1);
    assert_eq!(source.clock().step_count(), 0);
    Ok(())
}

#[test]
fn failed_retry_keeps_an_indeterminate_read_pinned_to_the_same_sequence() -> Test {
    let mut source = VirtualSource::new(spec(i128::MAX)?)?;
    source.inject_indeterminate_read(1, "source interval not established");
    assert!(matches!(
        source.emit_interval()?,
        OperationOutcome::Indeterminate(_)
    ));
    assert!(source.clear_indeterminate_read(1).is_some());
    let before = source.clone();
    assert!(matches!(
        source.emit_interval(),
        Err(ReferenceError::ArithmeticOverflow)
    ));
    assert_same_state(&source, &before);
    assert!(source.pending_indeterminate);
    assert_eq!(source.current_sequence(), 1);
    Ok(())
}

#[test]
fn accepted_fault_outcomes_keep_existing_sequence_and_retry_semantics() -> Test {
    let mut source = VirtualSource::new(spec(0)?)?;
    let mut control = source.clone();
    source.inject_indeterminate_read(1, "await source evidence");
    assert!(matches!(
        source.emit_packet()?,
        OperationOutcome::Indeterminate(_)
    ));
    assert_eq!(source.current_sequence(), 1);
    assert_eq!(source.clock().now(), TimestampNs(0));
    assert!(source.clear_indeterminate_read(1).is_some());
    let OperationOutcome::Success(retried) = source.emit_packet()? else {
        return Err(ReferenceError::InvalidSpec("retry_not_successful"));
    };
    let OperationOutcome::Success(expected) = control.emit_packet()? else {
        return Err(ReferenceError::InvalidSpec("control_not_successful"));
    };
    assert_eq!(retried, expected);
    assert_same_state(&source, &control);
    source.inject_unobservable_read(2, "not observable");
    source.inject_execution_failure(3, "capture failed");
    assert!(matches!(
        source.emit_packet()?,
        OperationOutcome::UnauthorizedOrNotObservable(_)
    ));
    assert_eq!(source.current_sequence(), 2);
    assert_eq!(source.clock().now(), TimestampNs(10));
    assert!(matches!(source.emit_packet()?, OperationOutcome::Failed(_)));
    assert_eq!(source.current_sequence(), 3);
    assert_eq!(source.clock().now(), TimestampNs(20));
    let before = source.clone();
    assert!(matches!(
        source.emit_packet(),
        Err(ReferenceError::UnknownSourceSequence(4))
    ));
    assert_same_state(&source, &before);
    Ok(())
}
