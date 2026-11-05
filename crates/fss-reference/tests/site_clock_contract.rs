#![forbid(unsafe_code)]
//! Independent interval and fault contracts for the VIT-019 site clock owner.

use std::error::Error;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::site::clock::{
    ClockCorrelation, ClockCorrelationError as E, ClockCorrelationPolicy, ClockOffsetInterval,
    HostClockSample, UtcInterval,
};
use fss_reference::site::{ClockOffsetDirection, MAX_CLOCK_UNCERTAINTY_NS};

const EPOCH: u64 = 1_800_000_000_000_000_000;

fn sample() -> HostClockSample {
    HostClockSample {
        monotonic_before_ns: 1_000,
        wall_clock_unix_ns: EPOCH,
        monotonic_after_ns: 1_020,
    }
}

fn policy() -> ClockCorrelationPolicy {
    ClockCorrelationPolicy {
        max_sample_bracket_ns: 100,
        max_drift_ppb: 0,
        max_age_ns: 10_000,
    }
}

fn source() -> ContentDigest {
    ContentDigest::sha256(b"retained, explicitly scoped synchronization fixture")
}

fn correlation() -> Result<ClockCorrelation, E> {
    ClockCorrelation::new(
        sample(),
        ClockOffsetInterval {
            lower_ns: 90,
            upper_ns: 110,
        },
        source(),
        policy(),
    )
}

#[test]
fn bracket_and_offset_uncertainty_compose_without_assuming_midpoint_observation()
-> Result<(), Box<dyn Error>> {
    let clock = correlation()?;
    // The wall read could occur anywhere from 1000 through 1020. At 2020
    // monotonic, local time is EPOCH+[1000,1020], then UTC adds [90,110].
    assert_eq!(
        clock.project(2_020)?,
        UtcInterval {
            earliest_ns: EPOCH + 1_090,
            latest_ns: EPOCH + 1_130,
        }
    );
    let witness = clock.witness_at(2_020)?;
    assert_eq!(witness.monotonic_ns, 2_020);
    assert_eq!(witness.wall_clock_unix_ns, EPOCH + 1_110);
    assert_eq!(witness.ntp_offset_ns, 100);
    assert_eq!(witness.ntp_offset_direction, ClockOffsetDirection::Behind);
    assert_eq!(witness.ntp_uncertainty_ns, 20);
    witness.validate()?;
    assert_eq!(clock.source_digest(), source());
    assert_eq!(clock.origin(), sample());
    assert_eq!(clock.policy(), policy());
    Ok(())
}

#[test]
fn negative_correction_means_local_clock_ahead() -> Result<(), Box<dyn Error>> {
    let clock = ClockCorrelation::new(
        sample(),
        ClockOffsetInterval {
            lower_ns: -110,
            upper_ns: -90,
        },
        source(),
        policy(),
    )?;
    let witness = clock.witness_at(2_020)?;
    assert_eq!(witness.wall_clock_unix_ns, EPOCH + 910);
    assert_eq!(witness.ntp_offset_ns, 100);
    assert_eq!(witness.ntp_offset_direction, ClockOffsetDirection::Ahead);
    assert_eq!(witness.ntp_uncertainty_ns, 20);
    assert_eq!(clock.project(2_020)?.earliest_ns, EPOCH + 890);
    assert_eq!(clock.project(2_020)?.latest_ns, EPOCH + 930);
    Ok(())
}

#[test]
fn symmetric_witness_never_discards_odd_nanosecond_edges() -> Result<(), Box<dyn Error>> {
    let clock = ClockCorrelation::new(
        HostClockSample {
            monotonic_after_ns: 1_001,
            ..sample()
        },
        ClockOffsetInterval {
            lower_ns: 0,
            upper_ns: 1,
        },
        source(),
        policy(),
    )?;
    let bounds = clock.project(2_001)?;
    assert_eq!(bounds.earliest_ns, EPOCH + 1_000);
    assert_eq!(bounds.latest_ns, EPOCH + 1_002);
    let witness = clock.witness_at(2_001)?;
    // The nominal local midpoint and correction midpoint both round downward.
    // Preserve the exact stated zero correction and widen the radius to two.
    assert_eq!(witness.wall_clock_unix_ns, EPOCH + 1_000);
    assert_eq!(witness.ntp_offset_ns, 0);
    assert_eq!(witness.ntp_uncertainty_ns, 2);
    assert!(witness.wall_clock_unix_ns - witness.ntp_uncertainty_ns <= bounds.earliest_ns);
    assert!(witness.wall_clock_unix_ns + witness.ntp_uncertainty_ns >= bounds.latest_ns);
    Ok(())
}

#[test]
fn fractional_drift_rounds_outward_even_below_one_nanosecond() -> Result<(), Box<dyn Error>> {
    let clock = ClockCorrelation::new(
        HostClockSample {
            monotonic_after_ns: 1_000,
            ..sample()
        },
        ClockOffsetInterval {
            lower_ns: -1,
            upper_ns: 1,
        },
        source(),
        ClockCorrelationPolicy {
            max_drift_ppb: 1,
            ..policy()
        },
    )?;
    assert_eq!(clock.witness_at(1_000)?.ntp_uncertainty_ns, 1);
    // One nanosecond of elapsed time at one ppb still requires outward
    // rounding to one full nanosecond on each side of an integer interval.
    assert_eq!(
        clock.project(1_001)?,
        UtcInterval {
            earliest_ns: EPOCH - 1,
            latest_ns: EPOCH + 3,
        }
    );
    assert_eq!(clock.witness_at(1_001)?.ntp_uncertainty_ns, 2);
    Ok(())
}

#[test]
fn every_discrete_bracket_and_offset_world_survives_projection() -> Result<(), Box<dyn Error>> {
    for bracket in 0..=7 {
        for lower in -5..=4 {
            let upper = lower + 3;
            let clock = ClockCorrelation::new(
                HostClockSample {
                    monotonic_after_ns: 1_000 + bracket,
                    ..sample()
                },
                ClockOffsetInterval {
                    lower_ns: lower,
                    upper_ns: upper,
                },
                source(),
                policy(),
            )?;
            let result = clock.project(2_000)?;
            let witness = clock.witness_at(2_000)?;
            for actual_sample_ns in 1_000..=1_000 + bracket {
                for actual_offset in lower..=upper {
                    let truth = u64::try_from(
                        i128::from(EPOCH)
                            + i128::from(2_000 - actual_sample_ns)
                            + i128::from(actual_offset),
                    )?;
                    assert!(result.contains(truth));
                    assert!(witness.wall_clock_unix_ns - witness.ntp_uncertainty_ns <= truth);
                    assert!(witness.wall_clock_unix_ns + witness.ntp_uncertainty_ns >= truth);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn compatible_samples_do_not_narrow_or_refresh_original_synchronization()
-> Result<(), Box<dyn Error>> {
    let mut clock = correlation()?;
    let before = clock.witness_at(5_000)?;
    let later = HostClockSample {
        monotonic_before_ns: 2_020,
        wall_clock_unix_ns: EPOCH + 1_020,
        monotonic_after_ns: 2_040,
    };
    let checked = clock.observe_later_sample(later)?;
    assert_eq!(checked.previous, sample());
    assert_eq!(checked.current, later);
    assert_eq!(checked.from_origin.earliest_ns, EPOCH + 1_000);
    assert_eq!(checked.from_origin.latest_ns, EPOCH + 1_040);
    assert_eq!(clock.last_sample(), later);
    assert_eq!(clock.last_checked_monotonic_ns(), 2_040);
    assert_eq!(clock.witness_at(5_000)?, before);
    assert!(clock.project(11_000).is_ok());
    assert_eq!(clock.project(11_001), Err(E::Expired));
    assert_eq!(
        clock.observe_later_sample(HostClockSample {
            monotonic_before_ns: 11_000,
            monotonic_after_ns: 11_020,
            wall_clock_unix_ns: EPOCH + 10_000,
        }),
        Err(E::Expired)
    );
    assert_eq!(clock.last_sample(), later);
    Ok(())
}

#[test]
fn exact_repeated_sample_is_idempotent_and_adds_no_freshness() -> Result<(), Box<dyn Error>> {
    let mut clock = correlation()?;
    clock.observe_later_sample(sample())?;
    let later = HostClockSample {
        monotonic_before_ns: 2_020,
        wall_clock_unix_ns: EPOCH + 1_020,
        monotonic_after_ns: 2_040,
    };
    clock.observe_later_sample(later)?;
    let before = clock.clone();
    let again = clock.observe_later_sample(later)?;
    assert_eq!(again.previous, again.current);
    assert_eq!(again.from_previous.earliest_ns, later.wall_clock_unix_ns);
    assert_eq!(again.from_previous.latest_ns, later.wall_clock_unix_ns);
    assert_eq!(clock, before);
    Ok(())
}

#[test]
fn forward_and_backward_wall_steps_invalidate_all_projections() -> Result<(), Box<dyn Error>> {
    for delta in [-500_i64, 500] {
        let mut clock = correlation()?;
        let changed = HostClockSample {
            monotonic_before_ns: 2_020,
            wall_clock_unix_ns: u64::try_from(i128::from(EPOCH) + 1_020 + i128::from(delta))?,
            monotonic_after_ns: 2_040,
        };
        assert_eq!(
            clock.observe_later_sample(changed),
            Err(E::WallClockDiscontinuity)
        );
        assert!(clock.is_invalidated());
        assert_eq!(clock.last_sample(), sample());
        assert_eq!(clock.project(1_020), Err(E::Invalidated));
        assert_eq!(clock.witness_at(5_000), Err(E::Invalidated));
        assert_eq!(clock.observe_later_sample(sample()), Err(E::Invalidated));
    }
    Ok(())
}

#[test]
fn monotonic_regression_or_overlapping_new_samples_permanently_refuse() -> Result<(), Box<dyn Error>>
{
    for before_ns in [0, 1_000, 1_019] {
        let mut clock = correlation()?;
        assert_eq!(
            clock.observe_later_sample(HostClockSample {
                monotonic_before_ns: before_ns,
                monotonic_after_ns: before_ns + 20,
                wall_clock_unix_ns: EPOCH + 1,
            }),
            Err(E::MonotonicDiscontinuity)
        );
        assert!(clock.is_invalidated());
        assert_eq!(clock.project(2_000), Err(E::Invalidated));
    }
    Ok(())
}

#[test]
fn monotonic_regression_inside_a_later_sample_permanently_invalidates() -> Result<(), Box<dyn Error>>
{
    let mut clock = correlation()?;
    assert_eq!(
        clock.observe_later_sample(HostClockSample {
            monotonic_before_ns: 2_040,
            monotonic_after_ns: 2_039,
            wall_clock_unix_ns: EPOCH + 1_030,
        }),
        Err(E::MonotonicDiscontinuity)
    );
    assert!(clock.is_invalidated());
    assert_eq!(clock.last_sample(), sample());
    assert_eq!(clock.project(1_020), Err(E::Invalidated));
    assert_eq!(clock.witness_at(5_000), Err(E::Invalidated));
    assert_eq!(clock.observe_later_sample(sample()), Err(E::Invalidated));
    Ok(())
}

#[test]
fn declared_slew_is_allowed_but_one_nanosecond_outside_it_is_a_discontinuity()
-> Result<(), Box<dyn Error>> {
    let origin = HostClockSample {
        monotonic_before_ns: 0,
        monotonic_after_ns: 0,
        wall_clock_unix_ns: EPOCH,
    };
    let mut clock = ClockCorrelation::new(
        origin,
        ClockOffsetInterval {
            lower_ns: -1,
            upper_ns: 1,
        },
        source(),
        ClockCorrelationPolicy {
            max_drift_ppb: 1_000_000,
            max_age_ns: 3_000_000_000,
            ..policy()
        },
    )?;
    clock.observe_later_sample(HostClockSample {
        monotonic_before_ns: 1_000_000_000,
        monotonic_after_ns: 1_000_000_000,
        wall_clock_unix_ns: EPOCH + 1_001_000_000,
    })?;
    assert_eq!(
        clock.observe_later_sample(HostClockSample {
            monotonic_before_ns: 2_000_000_000,
            monotonic_after_ns: 2_000_000_000,
            wall_clock_unix_ns: EPOCH + 2_002_000_001,
        }),
        Err(E::WallClockDiscontinuity)
    );
    Ok(())
}

#[test]
fn before_sync_and_expired_queries_fail_without_reinterpreting_a_clock_origin()
-> Result<(), Box<dyn Error>> {
    let clock = correlation()?;
    for at in [0, 999, 1_000, 1_019] {
        assert_eq!(clock.project(at), Err(E::BeforeSynchronization));
    }
    assert_eq!(clock.project(u64::MAX), Err(E::Expired));
    Ok(())
}

#[test]
fn malformed_samples_and_policies_never_reach_arithmetic() {
    let offset = ClockOffsetInterval {
        lower_ns: -1,
        upper_ns: 1,
    };
    for sample in [
        HostClockSample {
            monotonic_after_ns: 999,
            ..sample()
        },
        HostClockSample {
            monotonic_after_ns: 1_101,
            ..sample()
        },
        HostClockSample {
            wall_clock_unix_ns: 0,
            ..sample()
        },
    ] {
        assert_eq!(
            ClockCorrelation::new(sample, offset, source(), policy()),
            Err(E::InvalidSample)
        );
    }
    for policy in [
        ClockCorrelationPolicy {
            max_sample_bracket_ns: 0,
            ..policy()
        },
        ClockCorrelationPolicy {
            max_age_ns: 0,
            ..policy()
        },
        ClockCorrelationPolicy {
            max_drift_ppb: 1_000_000_000,
            ..policy()
        },
        ClockCorrelationPolicy {
            max_sample_bracket_ns: 10_001,
            ..policy()
        },
    ] {
        assert_eq!(
            ClockCorrelation::new(sample(), offset, source(), policy),
            Err(E::InvalidPolicy)
        );
    }
}

#[test]
fn scalar_offset_or_unknown_source_cannot_invent_clock_precision() {
    for offset in [
        ClockOffsetInterval {
            lower_ns: 0,
            upper_ns: 0,
        },
        ClockOffsetInterval {
            lower_ns: 1,
            upper_ns: 0,
        },
        ClockOffsetInterval {
            lower_ns: 10,
            upper_ns: 10,
        },
    ] {
        assert_eq!(
            ClockCorrelation::new(sample(), offset, source(), policy()),
            Err(E::InvalidOffsetInterval)
        );
    }
    for digest in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
        ContentDigest::new_laboratory(DigestAlgorithm::Sha256, [1; 32]),
    ] {
        assert_eq!(
            ClockCorrelation::new(
                sample(),
                ClockOffsetInterval {
                    lower_ns: -1,
                    upper_ns: 1
                },
                digest,
                policy()
            ),
            Err(E::InvalidSourceDigest)
        );
    }
}

#[test]
fn uncertainty_and_integer_limits_refuse_instead_of_clipping() -> Result<(), Box<dyn Error>> {
    let excess = i64::try_from(MAX_CLOCK_UNCERTAINTY_NS)?;
    assert_eq!(
        ClockCorrelation::new(
            sample(),
            ClockOffsetInterval {
                lower_ns: -excess,
                upper_ns: excess
            },
            source(),
            policy()
        ),
        Err(E::UncertaintyLimit)
    );
    assert_eq!(
        ClockCorrelation::new(
            sample(),
            ClockOffsetInterval {
                lower_ns: i64::MIN,
                upper_ns: i64::MIN + 1
            },
            source(),
            policy()
        ),
        Err(E::ArithmeticOverflow)
    );
    assert_eq!(
        ClockCorrelation::new(
            HostClockSample {
                wall_clock_unix_ns: u64::MAX,
                ..sample()
            },
            ClockOffsetInterval {
                lower_ns: 0,
                upper_ns: 1
            },
            source(),
            policy(),
        ),
        Err(E::ArithmeticOverflow)
    );
    let near_limit = ClockCorrelation::new(
        HostClockSample {
            wall_clock_unix_ns: u64::MAX - 1_000,
            ..sample()
        },
        ClockOffsetInterval {
            lower_ns: -1,
            upper_ns: 1,
        },
        source(),
        policy(),
    )?;
    assert_eq!(near_limit.project(3_000), Err(E::ArithmeticOverflow));
    Ok(())
}
