#![forbid(unsafe_code)]
//! Renewal preserves a live controller's ownership; invalid expiry arithmetic is atomic.

use fss_core::TimestampNs;
use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};

type Test = Result<(), LeaseError>;
const RESOURCE: &str = "device:ptz:porch";

#[test]
fn shorter_renewal_preserves_the_deadline_and_excludes_a_competing_controller() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(1_000), TimestampNs(100))?;

    leases.renew(&holder.id, 10, TimestampNs(200))?;

    assert_eq!(leases.get(&holder.id), Some(&holder));
    assert_eq!(leases.current_fence(RESOURCE), Some(holder.fence));
    // The shortened request would have expired at 210, but the original grant
    // still owns the resource and the effect-path gate must agree with the record.
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(500))?;
    assert!(matches!(
        leases.acquire(RESOURCE, "controller:b", Some(100), TimestampNs(500)),
        Err(LeaseError::Held { fence, .. }) if fence == holder.fence
    ));
    Ok(())
}

#[test]
fn renewal_extends_both_indexes_without_reissuing_the_identity_or_fence() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;

    leases.renew(&holder.id, 200, TimestampNs(50))?;
    let mut expected = holder.clone();
    expected.expires_at = Some(TimestampNs(250));
    assert_eq!(leases.get(&holder.id), Some(&expected));
    assert_eq!(leases.current_fence(RESOURCE), Some(holder.fence));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(249))?;
    assert!(matches!(
        leases.acquire(RESOURCE, "controller:b", Some(100), TimestampNs(249)),
        Err(LeaseError::Held { .. })
    ));

    let takeover = leases.acquire(RESOURCE, "controller:b", Some(100), TimestampNs(250))?;
    assert_eq!(takeover.fence, holder.fence + 1);
    assert_eq!(
        leases.get(&holder.id).map(|lease| lease.state),
        Some(LeaseState::Expired)
    );
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(251)),
        Err(LeaseError::StaleFence { .. })
    ));
    Ok(())
}

#[test]
fn delayed_renewal_retry_cannot_undo_a_later_extension() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
    leases.renew(&holder.id, 100, TimestampNs(50))?;
    let first = leases.get(&holder.id).cloned();
    leases.renew(&holder.id, 100, TimestampNs(50))?;
    assert_eq!(leases.get(&holder.id), first.as_ref());

    leases.renew(&holder.id, 300, TimestampNs(60))?;
    let extended = leases.get(&holder.id).cloned();
    // A delayed retry is evaluated in the caller's time domain. It must not
    // overwrite the extension that another successful renewal already made.
    leases.renew(&holder.id, 100, TimestampNs(50))?;
    assert_eq!(leases.get(&holder.id), extended.as_ref());
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(359))?;
    Ok(())
}

#[test]
fn backward_caller_time_cannot_shorten_a_live_lease_or_resurrect_observed_expiry() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(100))?;
    leases.renew(&holder.id, 200, TimestampNs(120))?;
    let extended = leases.get(&holder.id).cloned();
    leases.renew(&holder.id, 15, TimestampNs(90))?;
    assert_eq!(leases.get(&holder.id), extended.as_ref());
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(319))?;

    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(320)),
        Err(LeaseError::LeaseExpired { .. })
    ));
    assert!(matches!(
        leases.renew(&holder.id, 1_000, TimestampNs(90)),
        Err(LeaseError::NotActive {
            state: LeaseState::Expired,
            ..
        })
    ));
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(90)),
        Err(LeaseError::LeaseExpired { .. })
    ));
    Ok(())
}

#[test]
fn zero_duration_renewal_does_not_expire_an_existing_finite_lease() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
    leases.renew(&holder.id, 0, TimestampNs(20))?;
    assert_eq!(leases.get(&holder.id), Some(&holder));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(99))?;
    Ok(())
}

#[test]
fn renewal_can_assign_an_initial_deadline_to_a_lease_without_expiry() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", None, TimestampNs(0))?;
    leases.renew(&holder.id, 100, TimestampNs(50))?;
    assert_eq!(
        leases.get(&holder.id).and_then(|lease| lease.expires_at),
        Some(TimestampNs(150))
    );
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(149))?;
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(150)),
        Err(LeaseError::LeaseExpired { .. })
    ));
    Ok(())
}

#[test]
fn overflowing_acquisition_does_not_create_a_resource_or_consume_a_fence() -> Test {
    let mut leases = LeaseRegistry::new();
    for (now, ttl) in [
        (i128::MAX, 1),
        (i128::MAX - 4, 5),
        (i128::MAX - 1, u64::MAX),
    ] {
        assert!(
            leases
                .acquire(RESOURCE, "controller:a", Some(ttl), TimestampNs(now))
                .is_err()
        );
        assert_eq!(leases.current_fence(RESOURCE), None);
        assert_eq!(leases.get(&format!("lease:{RESOURCE}:1")), None);
    }
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
    assert_eq!(holder.fence, 1);
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(99))?;
    Ok(())
}

#[test]
fn overflowing_takeover_does_not_partially_expire_or_replace_the_prior_holder() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
    assert!(
        leases
            .acquire(RESOURCE, "controller:b", Some(1), TimestampNs(i128::MAX))
            .is_err()
    );
    assert_eq!(leases.get(&holder.id), Some(&holder));
    assert_eq!(leases.current_fence(RESOURCE), Some(holder.fence));
    assert_eq!(leases.get(&format!("lease:{RESOURCE}:2")), None);

    // Invalid request arithmetic does not evaluate lifecycle time. A later valid
    // request still expires the old holder and issues the next unused fence.
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(99))?;
    let takeover = leases.acquire(RESOURCE, "controller:b", Some(100), TimestampNs(100))?;
    assert_eq!(takeover.fence, holder.fence + 1);
    assert_eq!(
        leases.get(&holder.id).map(|lease| lease.state),
        Some(LeaseState::Expired)
    );
    Ok(())
}

#[test]
fn overflowing_acquisition_after_release_leaves_the_terminal_record_unchanged() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", None, TimestampNs(0))?;
    leases.release(&holder.id)?;
    let released = leases.get(&holder.id).cloned();
    assert!(
        leases
            .acquire(
                RESOURCE,
                "controller:b",
                Some(2),
                TimestampNs(i128::MAX - 1)
            )
            .is_err()
    );
    assert_eq!(leases.get(&holder.id), released.as_ref());
    assert_eq!(leases.current_fence(RESOURCE), Some(holder.fence));
    let takeover = leases.acquire(RESOURCE, "controller:b", None, TimestampNs(1))?;
    assert_eq!(takeover.fence, holder.fence + 1);
    Ok(())
}

#[test]
fn overflowing_renewal_preserves_the_previous_expiry_and_effect_gate() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(
        RESOURCE,
        "controller:a",
        Some(8),
        TimestampNs(i128::MAX - 10),
    )?;
    assert!(
        leases
            .renew(&holder.id, 20, TimestampNs(i128::MAX - 5))
            .is_err()
    );
    assert_eq!(leases.get(&holder.id), Some(&holder));
    assert_eq!(leases.current_fence(RESOURCE), Some(holder.fence));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX - 3))?;
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX - 2)),
        Err(LeaseError::LeaseExpired { expired_at: TimestampNs(value), .. }) if value == i128::MAX - 2
    ));
    Ok(())
}

#[test]
fn overflowing_renewal_does_not_assign_a_deadline_to_an_unbounded_lease() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", None, TimestampNs(0))?;
    assert!(leases.renew(&holder.id, 1, TimestampNs(i128::MAX)).is_err());
    assert_eq!(leases.get(&holder.id), Some(&holder));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX))?;
    Ok(())
}

#[test]
fn overflowing_renewal_does_not_partially_expire_a_finite_lease() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
    assert!(leases.renew(&holder.id, 1, TimestampNs(i128::MAX)).is_err());
    assert_eq!(leases.get(&holder.id), Some(&holder));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(99))?;
    assert!(matches!(
        leases.renew(&holder.id, 1, TimestampNs(100)),
        Err(LeaseError::NotActive {
            state: LeaseState::Expired,
            ..
        })
    ));
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(99)),
        Err(LeaseError::LeaseExpired { .. })
    ));
    Ok(())
}

#[test]
fn overflow_refusal_names_the_resource_and_exact_requested_time() -> Test {
    let mut leases = LeaseRegistry::new();
    let expected = LeaseError::ExpiryOverflow {
        resource: RESOURCE.to_string(),
        now: TimestampNs(i128::MAX - 1),
        ttl_ns: 2,
    };
    assert_eq!(
        leases.acquire(
            RESOURCE,
            "controller:a",
            Some(2),
            TimestampNs(i128::MAX - 1)
        ),
        Err(expected.clone())
    );
    let holder = leases.acquire(RESOURCE, "controller:a", None, TimestampNs(0))?;
    assert_eq!(
        leases.renew(&holder.id, 2, TimestampNs(i128::MAX - 1)),
        Err(expected.clone())
    );
    assert_eq!(
        expected.to_string(),
        format!(
            "lease expiry overflow on '{RESOURCE}': {:?} + 2 ns",
            TimestampNs(i128::MAX - 1)
        )
    );
    Ok(())
}

#[test]
fn largest_representable_deadline_remains_exclusive() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(
        RESOURCE,
        "controller:a",
        Some(10),
        TimestampNs(i128::MAX - 10),
    )?;
    assert_eq!(holder.expires_at, Some(TimestampNs(i128::MAX)));
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX - 1))?;
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX)),
        Err(LeaseError::LeaseExpired {
            expired_at: TimestampNs(i128::MAX),
            ..
        })
    ));
    Ok(())
}

#[test]
fn renewal_accepts_the_exact_representable_upper_boundary() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(
        RESOURCE,
        "controller:a",
        Some(9),
        TimestampNs(i128::MAX - 10),
    )?;
    leases.renew(&holder.id, 5, TimestampNs(i128::MAX - 5))?;
    assert_eq!(
        leases.get(&holder.id).and_then(|lease| lease.expires_at),
        Some(TimestampNs(i128::MAX))
    );
    leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX - 1))?;
    assert!(matches!(
        leases.check_fence(RESOURCE, holder.fence, TimestampNs(i128::MAX)),
        Err(LeaseError::LeaseExpired { .. })
    ));
    Ok(())
}

#[test]
fn signed_caller_time_and_maximum_duration_remain_supported() -> Test {
    let mut leases = LeaseRegistry::new();
    let holder = leases.acquire(
        RESOURCE,
        "controller:a",
        Some(u64::MAX),
        TimestampNs(i128::MIN),
    )?;
    let expected = TimestampNs(i128::MIN + i128::from(u64::MAX));
    assert_eq!(holder.expires_at, Some(expected));
    leases.renew(&holder.id, u64::MAX, TimestampNs(i128::MIN + 1))?;
    assert_eq!(
        leases.get(&holder.id).and_then(|lease| lease.expires_at),
        Some(TimestampNs(expected.0 + 1))
    );
    leases.check_fence(RESOURCE, holder.fence, expected)?;
    Ok(())
}

#[test]
fn shortened_renewal_does_not_prevent_expiry_at_the_original_deadline() -> Test {
    for observe_by_renewal in [false, true] {
        let mut leases = LeaseRegistry::new();
        let holder = leases.acquire(RESOURCE, "controller:a", Some(100), TimestampNs(0))?;
        leases.renew(&holder.id, 10, TimestampNs(20))?;
        if observe_by_renewal {
            assert!(matches!(
                leases.renew(&holder.id, 100, TimestampNs(100)),
                Err(LeaseError::NotActive {
                    state: LeaseState::Expired,
                    ..
                })
            ));
        } else {
            assert!(matches!(
                leases.check_fence(RESOURCE, holder.fence, TimestampNs(100)),
                Err(LeaseError::LeaseExpired { .. })
            ));
        }
        assert_eq!(
            leases.get(&holder.id).and_then(|lease| lease.expires_at),
            Some(TimestampNs(100))
        );
        assert_eq!(
            leases.get(&holder.id).map(|lease| lease.state),
            Some(LeaseState::Expired)
        );
        assert!(matches!(
            leases.renew(&holder.id, 100, TimestampNs(50)),
            Err(LeaseError::NotActive {
                state: LeaseState::Expired,
                ..
            })
        ));
    }
    Ok(())
}
