#![forbid(unsafe_code)]
//! Whole-state refusal checks, including the hidden jitter and fractional-skew state.
use super::*;

type Test = Result<(), ReferenceError>;

#[test]
fn timestamp_overflow_does_not_consume_jitter() -> Test {
    let mut clock = VirtualClock::new(17, TimestampNs(i128::MAX));
    clock.inject_skew(123_457)?;
    clock.inject_jitter(u64::MAX);
    let before = clock.clone();
    for _ in 0..3 {
        assert!(matches!(clock.advance(7), Err(ReferenceError::ArithmeticOverflow)));
        assert_eq!(clock, before);
    }
    Ok(())
}

#[test]
fn counter_overflow_does_not_commit_time_residual_or_jitter() -> Test {
    let mut clock = VirtualClock::new(29, TimestampNs(0));
    clock.inject_skew(333_333)?;
    clock.inject_jitter(7);
    clock.step_count = u64::MAX;
    let before = clock.clone();
    assert!(matches!(clock.advance(1), Err(ReferenceError::ArithmeticOverflow)));
    assert_eq!(clock, before);
    Ok(())
}

#[test]
fn rejected_zero_step_does_not_advance_the_random_stream() -> Test {
    let mut clock = VirtualClock::new(41, TimestampNs(100));
    // xorshift(2) is even: jitter modulo 2 is zero, but its state changes.
    clock.prng_state = 2;
    clock.inject_jitter(1);
    let before = clock.clone();
    assert!(matches!(clock.advance(0), Err(ReferenceError::BackwardStepAttempt { .. })));
    assert_eq!(clock, before);
    let mut control = before;
    assert_eq!(clock.advance(1)?, control.advance(1)?);
    assert_eq!(clock, control);
    Ok(())
}

#[test]
fn retry_after_overflow_has_the_same_future_as_an_unattempted_clock() -> Test {
    let mut clock = VirtualClock::new(53, TimestampNs(i128::MAX - 100));
    clock.inject_skew(111_111)?;
    clock.inject_jitter(3);
    let mut control = clock.clone();
    assert!(matches!(clock.advance(1000), Err(ReferenceError::ArithmeticOverflow)));
    for _ in 0..8 {
        assert_eq!(clock.advance(1)?, control.advance(1)?);
        assert_eq!(clock, control);
    }
    Ok(())
}

#[test]
fn successful_steps_preserve_the_original_integer_clock_recurrence() -> Test {
    for seed in [0, 1, 17, u64::MAX] {
        for skew in [-MAX_SKEW_PPM, -1, 0, 1, MAX_SKEW_PPM] {
            for jitter in [0, 1, 17, u64::MAX] {
                let mut clock = VirtualClock::new(seed, TimestampNs(-100));
                clock.inject_skew(skew)?;
                clock.inject_jitter(jitter);
                let mut expected = clock.clone();
                for nominal in 2..34_u64 {
                    let total = i128::from(nominal) * i128::from(skew) + expected.skew_residual;
                    let offset = total / 1_000_000;
                    expected.skew_residual = total % 1_000_000;
                    let noise = if jitter == 0 {
                        0
                    } else {
                        expected.prng_state ^= expected.prng_state << 13;
                        expected.prng_state ^= expected.prng_state >> 7;
                        expected.prng_state ^= expected.prng_state << 17;
                        (u128::from(expected.prng_state) % (u128::from(jitter) + 1)) as i128
                    };
                    expected.current_ns.0 += i128::from(nominal) + offset + noise;
                    expected.step_count += 1;
                    assert_eq!(clock.advance(nominal)?, expected.now());
                    assert_eq!(clock, expected);
                }
            }
        }
    }
    Ok(())
}
