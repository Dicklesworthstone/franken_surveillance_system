//! Contract and property test suite for conservative time-interval arithmetic (FSS-003).
//!
//! Enforces:
//! - Explicit unknown/indeterminate outcomes on interval union, intersection, containment, and before/after
//! - Never collapsing an uncovered gap into a point
//! - Checked i128 nanosecond arithmetic that fails closed on overflow
//! - Rejection of clock-basis mismatches
//! - Monotone uncertainty widening (an operation may never narrow an interval)
//! - Canonical encoding and decoding round-trips
//! - Generative property tests over deterministic pseudo-random intervals
//! - Zero unwrap/expect/panic (all tests return Result)

#![forbid(unsafe_code)]

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, CaptureIntervalWithBasis,
    ClockBasis, ContractError, IntervalContainment, IntervalUnion, TemporalPrecedence,
    TimeIntervalError, TimestampNs,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// -----------------------------------------------------------------------------
// 0. PinkCoast Cross-Review Defect Tests (F1–F5)
// -----------------------------------------------------------------------------

#[test]
fn pinkcoast_f1_checked_shift_rigid_translation_cannot_narrow() -> TestResult {
    let interval = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let shifted = interval.checked_shift(50)?;
    assert_eq!(shifted.uncertainty_ns(), interval.uncertainty_ns());
    assert_eq!(shifted.earliest, TimestampNs(150));
    assert_eq!(shifted.latest, TimestampNs(250));

    let shifted_neg = interval.checked_shift(-30)?;
    assert_eq!(shifted_neg.uncertainty_ns(), interval.uncertainty_ns());
    assert_eq!(shifted_neg.earliest, TimestampNs(70));
    assert_eq!(shifted_neg.latest, TimestampNs(170));

    assert!(shifted.uncertainty_ns() >= interval.uncertainty_ns());
    assert!(shifted_neg.uncertainty_ns() >= interval.uncertainty_ns());
    Ok(())
}

#[test]
fn pinkcoast_f2_abuts_containment_union_agreement() -> TestResult {
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(201), TimestampNs(300))?;

    assert_eq!(a.intersection(b), None);
    assert!(a.abuts(b));
    assert!(b.abuts(a));
    assert_eq!(a.classify_containment(b), IntervalContainment::Abutting);
    assert_eq!(b.classify_containment(a), IntervalContainment::Abutting);

    let u = a.union(b);
    assert!(
        u.is_contiguous(),
        "union reports contiguous while containment reports abutting"
    );
    assert_eq!(u.gap_ns(), 0);
    let contig = u.into_contiguous()?;
    assert_eq!(contig.earliest, TimestampNs(100));
    assert_eq!(contig.latest, TimestampNs(300));

    let c = CaptureInterval::new(TimestampNs(205), TimestampNs(300))?;
    assert!(!a.abuts(c));
    assert_eq!(
        a.classify_containment(c),
        IntervalContainment::Disjoint { gap_ns: 4 }
    );
    Ok(())
}

#[test]
fn pinkcoast_f3_touching_intervals_precedence_before_or_at() -> TestResult {
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(200), TimestampNs(300))?;

    assert!(!a.abuts(b));
    assert!(a.overlaps(b));
    assert_eq!(
        a.intersection(b),
        Some(CaptureInterval::point(TimestampNs(200)))
    );

    let prec_ab = a.temporal_precedence(b);
    assert_eq!(
        prec_ab,
        TemporalPrecedence::BeforeOrAt {
            point: TimestampNs(200)
        }
    );
    assert!(prec_ab.is_before_or_at());
    assert!(prec_ab.is_weakly_before());
    assert!(!prec_ab.is_indeterminate());

    let prec_ba = b.temporal_precedence(a);
    assert_eq!(
        prec_ba,
        TemporalPrecedence::AfterOrAt {
            point: TimestampNs(200)
        }
    );
    assert!(prec_ba.is_after_or_at());
    assert!(prec_ba.is_weakly_after());
    assert!(!prec_ba.is_indeterminate());
    Ok(())
}

#[test]
fn pinkcoast_f4_rng_span_abs_diff_no_overflow_on_full_i128_range() -> TestResult {
    let min = i128::MIN;
    let max = i128::MAX;
    let span = max.abs_diff(min);
    assert_eq!(span, u128::MAX);

    let mut rng = DeterministicRng::new(42);
    let sample = rng.next_i128_range(min, max);
    assert!(sample >= min && sample <= max);
    Ok(())
}

#[test]
fn pinkcoast_f5_clock_basis_unknown_tag_returns_unknown_identity() -> TestResult {
    for bad_tag in [0_u8, 5_u8, 99_u8, 255_u8] {
        let err = ClockBasis::from_canonical_bytes(&[bad_tag]);
        assert_eq!(err, Err(ContractError::UnknownClockBasis(bad_tag)));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// 1. Explicit Unknown / Indeterminate Outcomes: Union
// -----------------------------------------------------------------------------

#[test]
fn interval_union_contiguous_when_overlapping() -> TestResult {
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(150), TimestampNs(300))?;

    let union = a.union(b);
    assert!(union.is_contiguous());
    assert!(!union.is_disjoint());
    assert_eq!(union.gap_ns(), 0);

    let contiguous = union.into_contiguous()?;
    assert_eq!(contiguous.earliest, TimestampNs(100));
    assert_eq!(contiguous.latest, TimestampNs(300));
    assert_eq!(contiguous.uncertainty_ns(), 200);

    // Symmetric check
    let union_rev = b.union(a);
    assert_eq!(union, union_rev);
    Ok(())
}

#[test]
fn interval_union_contiguous_when_abutting() -> TestResult {
    // [100, 200] and [201, 300] are immediately adjacent in discrete nanoseconds
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(201), TimestampNs(300))?;

    assert!(a.abuts(b));
    assert!(b.abuts(a));

    let union = a.union(b);
    assert!(union.is_contiguous());
    assert_eq!(union.gap_ns(), 0);

    let contiguous = union.into_contiguous()?;
    assert_eq!(contiguous.earliest, TimestampNs(100));
    assert_eq!(contiguous.latest, TimestampNs(300));
    Ok(())
}

#[test]
fn interval_union_preserves_uncovered_gap_never_collapsing() -> TestResult {
    // Intervals [100, 200] and [210, 300] have an uncovered gap of [201, 209] = 9 ns
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(210), TimestampNs(300))?;

    let union = a.union(b);
    assert!(!union.is_contiguous());
    assert!(union.is_disjoint());
    assert_eq!(union.gap_ns(), 9);

    match union {
        IntervalUnion::Disjoint {
            earlier,
            later,
            gap_ns,
        } => {
            assert_eq!(earlier, a);
            assert_eq!(later, b);
            assert_eq!(gap_ns, 9);
        }
        IntervalUnion::Contiguous(_) => {
            return Err("expected disjoint union preserving gap".into());
        }
    }

    // Attempting to coerce a disjoint union into a contiguous interval fails closed
    assert_eq!(
        union.into_contiguous(),
        Err(TimeIntervalError::DisjointIntervals { gap_ns: 9 })
    );

    // Symmetric check
    let union_rev = b.union(a);
    assert_eq!(union, union_rev);
    Ok(())
}

// -----------------------------------------------------------------------------
// 2. Explicit Unknown / Indeterminate Outcomes: Intersection
// -----------------------------------------------------------------------------

#[test]
fn interval_intersection_overlapping_disjoint_and_point() -> TestResult {
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(150), TimestampNs(250))?;
    let c = CaptureInterval::new(TimestampNs(200), TimestampNs(300))?;
    let d = CaptureInterval::new(TimestampNs(201), TimestampNs(300))?;

    // Overlapping: non-empty intersection
    let isect_ab = a.intersection(b);
    assert_eq!(
        isect_ab,
        Some(CaptureInterval::new(TimestampNs(150), TimestampNs(200))?)
    );

    // Single-point touch at boundary
    let isect_ac = a.intersection(c);
    assert_eq!(isect_ac, Some(CaptureInterval::point(TimestampNs(200))));
    if let Some(pt) = isect_ac {
        assert!(pt.is_point());
        assert_eq!(pt.uncertainty_ns(), 0);
    }

    // Disjoint / abutting: no common instant
    assert_eq!(a.intersection(d), None);
    Ok(())
}

// -----------------------------------------------------------------------------
// 3. Explicit Unknown / Indeterminate Outcomes: Containment
// -----------------------------------------------------------------------------

#[test]
fn interval_containment_outcomes() -> TestResult {
    let outer = CaptureInterval::new(TimestampNs(100), TimestampNs(300))?;
    let inner = CaptureInterval::new(TimestampNs(150), TimestampNs(250))?;
    let disjoint = CaptureInterval::new(TimestampNs(400), TimestampNs(500))?;
    let partial_low = CaptureInterval::new(TimestampNs(50), TimestampNs(150))?;
    let partial_high = CaptureInterval::new(TimestampNs(250), TimestampNs(350))?;
    let engulfing = CaptureInterval::new(TimestampNs(50), TimestampNs(350))?;

    // Definite containment
    let c1 = outer.classify_containment(inner);
    assert!(c1.is_definite_contains());
    assert!(!c1.is_indeterminate());
    assert_eq!(c1, IntervalContainment::Contains);

    // Abutting intervals (0ns gap)
    let abutting = CaptureInterval::new(TimestampNs(301), TimestampNs(400))?;
    let c_abut = outer.classify_containment(abutting);
    assert!(c_abut.is_abutting());
    assert!(!c_abut.is_definite_disjoint());
    assert_eq!(c_abut, IntervalContainment::Abutting);

    // Definite disjoint (gap = 400 - 300 - 1 = 99 ns)
    let c2 = outer.classify_containment(disjoint);
    assert!(c2.is_definite_disjoint());
    assert!(!c2.is_abutting());
    assert_eq!(c2, IntervalContainment::Disjoint { gap_ns: 99 });

    // Partial overlap below: true event could be inside or outside -> Indeterminate
    let c3 = outer.classify_containment(partial_low);
    assert!(c3.is_indeterminate());
    assert_eq!(
        c3,
        IntervalContainment::Indeterminate {
            overlap: CaptureInterval::new(TimestampNs(100), TimestampNs(150))?,
        }
    );

    // Partial overlap above: Indeterminate
    let c4 = outer.classify_containment(partial_high);
    assert!(c4.is_indeterminate());
    assert_eq!(
        c4,
        IntervalContainment::Indeterminate {
            overlap: CaptureInterval::new(TimestampNs(250), TimestampNs(300))?,
        }
    );

    // Engulfing (partial overlaps on both ends): Indeterminate
    let c5 = outer.classify_containment(engulfing);
    assert!(c5.is_indeterminate());
    assert_eq!(c5, IntervalContainment::Indeterminate { overlap: outer });
    Ok(())
}

// -----------------------------------------------------------------------------
// 4. Explicit Unknown / Indeterminate Outcomes: Before / After
// -----------------------------------------------------------------------------

#[test]
fn interval_temporal_precedence_outcomes() -> TestResult {
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(250), TimestampNs(350))?;
    let abutting = CaptureInterval::new(TimestampNs(201), TimestampNs(300))?;
    let overlap = CaptureInterval::new(TimestampNs(150), TimestampNs(250))?;
    let identical = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;

    // Strictly Before (gap = 250 - 200 - 1 = 49 ns)
    let p_ab = a.temporal_precedence(b);
    assert!(p_ab.is_definitely_before());
    assert!(!p_ab.is_definitely_after());
    assert!(!p_ab.is_indeterminate());
    assert!(a.is_strictly_before(b));
    assert!(!a.is_strictly_after(b));
    assert_eq!(p_ab, TemporalPrecedence::Before { gap_ns: 49 });

    // Strictly After (gap = 49 ns)
    let p_ba = b.temporal_precedence(a);
    assert!(p_ba.is_definitely_after());
    assert!(b.is_strictly_after(a));
    assert_eq!(p_ba, TemporalPrecedence::After { gap_ns: 49 });

    // Abutting: strictly before with gap_ns = 0
    let p_abut = a.temporal_precedence(abutting);
    assert!(p_abut.is_definitely_before());
    assert_eq!(p_abut, TemporalPrecedence::Before { gap_ns: 0 });

    // Touching intervals (touching at exact boundary point 200ns)
    let touching = CaptureInterval::new(TimestampNs(200), TimestampNs(300))?;
    let p_touch = a.temporal_precedence(touching);
    assert!(p_touch.is_before_or_at());
    assert!(p_touch.is_weakly_before());
    assert!(!p_touch.is_indeterminate());
    assert_eq!(
        p_touch,
        TemporalPrecedence::BeforeOrAt {
            point: TimestampNs(200),
        }
    );
    let p_touch_rev = touching.temporal_precedence(a);
    assert!(p_touch_rev.is_after_or_at());
    assert!(p_touch_rev.is_weakly_after());
    assert_eq!(
        p_touch_rev,
        TemporalPrecedence::AfterOrAt {
            point: TimestampNs(200),
        }
    );

    // Overlapping: precedence of underlying events cannot be collapsed -> Indeterminate
    let p_ov = a.temporal_precedence(overlap);
    assert!(p_ov.is_indeterminate());
    assert!(!p_ov.is_definitely_before());
    assert!(!p_ov.is_definitely_after());
    assert!(!p_ov.is_before_or_at());
    assert!(!p_ov.is_after_or_at());
    assert_eq!(
        p_ov,
        TemporalPrecedence::Indeterminate {
            overlap: CaptureInterval::new(TimestampNs(150), TimestampNs(200))?,
        }
    );

    // Identical intervals: Indeterminate
    let p_id = a.temporal_precedence(identical);
    assert!(p_id.is_indeterminate());
    assert_eq!(p_id, TemporalPrecedence::Indeterminate { overlap: a });
    Ok(())
}

// -----------------------------------------------------------------------------
// 5. Checked i128 Arithmetic Failing Closed on Overflow
// -----------------------------------------------------------------------------

#[test]
fn checked_i128_arithmetic_overflow_fails_closed() -> TestResult {
    let t_max = TimestampNs(i128::MAX);
    let t_min = TimestampNs(i128::MIN);

    // Overflow on checked_add
    assert_eq!(
        t_max.checked_add(1),
        Err(TimeIntervalError::ArithmeticOverflow)
    );
    assert_eq!(
        t_max.checked_add_ns(1),
        Err(ContractError::ArithmeticOverflow)
    );

    // Underflow on checked_sub
    assert_eq!(
        t_min.checked_sub(1),
        Err(TimeIntervalError::ArithmeticOverflow)
    );
    assert_eq!(
        t_min.checked_sub_ns(1),
        Err(ContractError::ArithmeticOverflow)
    );

    // Valid checked_duration_since near boundaries
    let zero = TimestampNs::ZERO;
    assert_eq!(zero.checked_duration_since(TimestampNs(-500))?, 500);

    // Inverted duration fails closed
    assert_eq!(
        TimestampNs(100).checked_duration_since(TimestampNs(200)),
        Err(ContractError::InvertedTimeInterval)
    );

    // Inverted interval construction fails closed
    assert_eq!(
        CaptureInterval::new(TimestampNs(500), TimestampNs(400)),
        Err(ContractError::InvertedTimeInterval)
    );
    assert_eq!(
        CaptureInterval::new_checked(TimestampNs(500), TimestampNs(400)),
        Err(TimeIntervalError::InvertedInterval {
            earliest: 500,
            latest: 400,
        })
    );

    // Overflow during interval checked_shift fails closed
    let interval = CaptureInterval::new(TimestampNs(i128::MAX - 10), TimestampNs(i128::MAX - 5))?;
    assert_eq!(
        interval.checked_shift(10),
        Err(ContractError::ArithmeticOverflow)
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// 6. Clock-Basis Mismatch Rejected
// -----------------------------------------------------------------------------

#[test]
fn clock_basis_mismatch_rejected_across_all_operations() -> TestResult {
    let interval_a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let interval_b = CaptureInterval::new(TimestampNs(150), TimestampNs(250))?;

    let utc = ClockBasis::UtcDisciplined;
    let dev = ClockBasis::DeviceMonotonic;
    let host = ClockBasis::HostMonotonic;
    let est = ClockBasis::Estimated;

    // Direct methods on CaptureInterval with basis
    assert_eq!(
        interval_a.union_with_basis(utc, interval_b, dev),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: dev,
        })
    );
    assert_eq!(
        interval_a.intersection_with_basis(utc, interval_b, host),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: host,
        })
    );
    assert_eq!(
        interval_a.containment_with_basis(utc, interval_b, est),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: est,
        })
    );
    assert_eq!(
        interval_a.temporal_precedence_with_basis(host, interval_b, utc),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: host,
            actual: utc,
        })
    );

    // CaptureIntervalWithBasis encapsulation
    let based_utc = CaptureIntervalWithBasis::new(interval_a, utc);
    let based_dev = CaptureIntervalWithBasis::new(interval_b, dev);
    let based_utc2 = CaptureIntervalWithBasis::new(interval_b, utc);

    // Mismatches reject
    assert_eq!(
        based_utc.union(&based_dev),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: dev,
        })
    );
    assert_eq!(
        based_utc.intersection(&based_dev),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: dev,
        })
    );
    assert_eq!(
        based_utc.containment(&based_dev),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: dev,
        })
    );
    assert_eq!(
        based_utc.temporal_precedence(&based_dev),
        Err(TimeIntervalError::ClockBasisMismatch {
            expected: utc,
            actual: dev,
        })
    );

    // Matching basis succeeds
    let union_ok = based_utc.union(&based_utc2)?;
    assert!(union_ok.is_contiguous());
    let isect_ok = based_utc.intersection(&based_utc2)?;
    assert!(isect_ok.is_some());
    Ok(())
}

// -----------------------------------------------------------------------------
// 7. Monotone Uncertainty Widening (An operation may never narrow an interval)
// -----------------------------------------------------------------------------

#[test]
fn uncertainty_widening_is_strictly_monotone() -> TestResult {
    let orig = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;
    assert_eq!(orig.uncertainty_ns(), 1_000);

    // Symmetric skew widening
    let widened = orig.widen_skew(500)?;
    assert_eq!(widened.earliest, TimestampNs(500));
    assert_eq!(widened.latest, TimestampNs(2_500));
    assert_eq!(widened.uncertainty_ns(), 2_000);
    assert!(widened.uncertainty_ns() >= orig.uncertainty_ns());
    assert!(widened.contains(orig));

    // Zero skew preserves width
    let unchanged = orig.widen_skew(0)?;
    assert_eq!(unchanged, orig);
    assert_eq!(unchanged.uncertainty_ns(), orig.uncertainty_ns());

    // Asymmetric widening
    let asym = orig.widen_asymmetric(100, 300)?;
    assert_eq!(asym.earliest, TimestampNs(900));
    assert_eq!(asym.latest, TimestampNs(2_300));
    assert_eq!(asym.uncertainty_ns(), 1_400);
    assert!(asym.uncertainty_ns() >= orig.uncertainty_ns());

    // Widening with overflow fails closed
    let near_max = CaptureInterval::new(TimestampNs(i128::MAX - 50), TimestampNs(i128::MAX - 10))?;
    assert_eq!(
        near_max.widen_skew(100),
        Err(TimeIntervalError::ArithmeticOverflow)
    );

    let near_min = CaptureInterval::new(TimestampNs(i128::MIN + 10), TimestampNs(i128::MIN + 50))?;
    assert_eq!(
        near_min.widen_skew(100),
        Err(TimeIntervalError::ArithmeticOverflow)
    );

    // Enforce that convex hull is monotone (never narrower than operands)
    let a = CaptureInterval::new(TimestampNs(100), TimestampNs(200))?;
    let b = CaptureInterval::new(TimestampNs(300), TimestampNs(400))?;
    let hull = a.hull(b);
    assert!(hull.uncertainty_ns() >= a.uncertainty_ns());
    assert!(hull.uncertainty_ns() >= b.uncertainty_ns());
    assert!(hull.contains(a));
    assert!(hull.contains(b));

    // Rigid translation preserves width exactly
    let translated = orig.checked_translate(500)?;
    assert_eq!(translated.uncertainty_ns(), orig.uncertainty_ns());
    assert_eq!(translated.earliest, TimestampNs(1_500));
    assert_eq!(translated.latest, TimestampNs(2_500));

    // Rigid checked_shift preserves width exactly
    let shifted = orig.checked_shift(500)?;
    assert_eq!(shifted.uncertainty_ns(), orig.uncertainty_ns());
    assert_eq!(shifted.earliest, TimestampNs(1_500));
    assert_eq!(shifted.latest, TimestampNs(2_500));
    assert!(shifted.uncertainty_ns() >= orig.uncertainty_ns());
    Ok(())
}

// -----------------------------------------------------------------------------
// 8. Canonical Encoding and Decoding Round-Trip
// -----------------------------------------------------------------------------

#[test]
fn canonical_encoding_round_trip_for_all_types() -> TestResult {
    // 1. CaptureInterval
    let interval = CaptureInterval::new(TimestampNs(-50_000), TimestampNs(120_000))?;
    let bytes = interval.canonical_bytes();
    assert_eq!(bytes.len(), 32); // 16 bytes earliest + 16 bytes latest
    let decoded = CaptureInterval::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, interval);

    // 2. ClockBasis variants (1 byte tag each)
    let bases = [
        ClockBasis::UtcDisciplined,
        ClockBasis::DeviceMonotonic,
        ClockBasis::HostMonotonic,
        ClockBasis::Estimated,
    ];
    for basis in bases {
        let b_bytes = basis.canonical_bytes();
        assert_eq!(b_bytes.len(), 1);
        let b_decoded = ClockBasis::from_canonical_bytes(&b_bytes)?;
        assert_eq!(b_decoded, basis);
    }

    // Invalid ClockBasis tags fail closed with UnknownClockBasis
    for bad_tag in [0_u8, 5_u8, 99_u8, 255_u8] {
        assert_eq!(
            ClockBasis::from_canonical_bytes(&[bad_tag]),
            Err(ContractError::UnknownClockBasis(bad_tag))
        );
    }

    // 3. CaptureIntervalWithBasis (32 bytes + 1 byte = 33 bytes)
    let based = CaptureIntervalWithBasis::new(interval, ClockBasis::UtcDisciplined);
    let based_bytes = based.canonical_bytes();
    assert_eq!(based_bytes.len(), 33);
    let based_decoded = CaptureIntervalWithBasis::from_canonical_bytes(&based_bytes)?;
    assert_eq!(based_decoded, based);

    // 4. Inverted canonical bytes rejected
    let mut bad_enc = CanonicalEncoder::new();
    TimestampNs(200).encode_canonical(&mut bad_enc);
    TimestampNs(100).encode_canonical(&mut bad_enc);
    assert_eq!(
        CaptureInterval::from_canonical_bytes(&bad_enc.finish()),
        Err(ContractError::InvertedTimeInterval)
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// 9. Property Tests Over Generated Intervals
// -----------------------------------------------------------------------------

/// Deterministic 64-bit Linear Congruential Generator for reproducible property tests.
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // MMIX LCG parameters by Donald Knuth
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn next_i128_range(&mut self, min: i128, max: i128) -> i128 {
        let diff = max.abs_diff(min);
        if diff == 0 {
            return min;
        }
        let r = ((self.next_u64() as u128) << 64) | (self.next_u64() as u128);
        let offset = r % diff;
        min.saturating_add_unsigned(offset)
    }

    fn next_interval(&mut self, min: i128, max: i128) -> Result<CaptureInterval, ContractError> {
        let t1 = self.next_i128_range(min, max);
        let t2 = self.next_i128_range(min, max);
        let (earliest, latest) = if t1 <= t2 { (t1, t2) } else { (t2, t1) };
        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
    }
}

fn verify_interval_pair_invariants(
    a: CaptureInterval,
    b: CaptureInterval,
    skew: u128,
) -> TestResult {
    // Property 1: Intersection symmetry
    let isect_ab = a.intersection(b);
    let isect_ba = b.intersection(a);
    assert_eq!(isect_ab, isect_ba);

    // Property 2: Intersection subset invariant
    if let Some(isect) = isect_ab {
        assert!(a.contains(isect));
        assert!(b.contains(isect));
        assert!(a.overlaps(b));
        assert!(b.overlaps(a));
    } else {
        assert!(!a.overlaps(b));
        assert!(!b.overlaps(a));
    }

    // Property 3: Convex hull monotonicity and containment
    let hull = a.hull(b);
    assert!(hull.contains(a));
    assert!(hull.contains(b));
    assert!(hull.uncertainty_ns() >= a.uncertainty_ns());
    assert!(hull.uncertainty_ns() >= b.uncertainty_ns());

    // Property 4: Temporal precedence mutual exclusion
    let p_ab = a.temporal_precedence(b);
    let p_ba = b.temporal_precedence(a);

    let def_before = p_ab.is_definitely_before();
    let def_after = p_ab.is_definitely_after();
    let before_or_at = p_ab.is_before_or_at();
    let after_or_at = p_ab.is_after_or_at();
    let indet = p_ab.is_indeterminate();

    // Exactly one of the five states must hold
    let count = (def_before as u8)
        + (def_after as u8)
        + (before_or_at as u8)
        + (after_or_at as u8)
        + (indet as u8);
    assert_eq!(count, 1);

    // Antisymmetry of precedence
    if def_before {
        assert!(p_ba.is_definitely_after());
    } else if def_after {
        assert!(p_ba.is_definitely_before());
    } else if before_or_at {
        assert!(p_ba.is_after_or_at());
        if let (
            TemporalPrecedence::BeforeOrAt { point: pt_ab },
            TemporalPrecedence::AfterOrAt { point: pt_ba },
        ) = (p_ab, p_ba)
        {
            assert_eq!(pt_ab, pt_ba);
        }
    } else if after_or_at {
        assert!(p_ba.is_before_or_at());
        if let (
            TemporalPrecedence::AfterOrAt { point: pt_ab },
            TemporalPrecedence::BeforeOrAt { point: pt_ba },
        ) = (p_ab, p_ba)
        {
            assert_eq!(pt_ab, pt_ba);
        }
    } else {
        assert!(p_ba.is_indeterminate());
    }

    // Property 5: Union consistency
    let u_ab = a.union(b);
    let u_ba = b.union(a);
    assert_eq!(u_ab, u_ba);

    if a.overlaps(b) || a.abuts(b) {
        assert!(u_ab.is_contiguous());
        let contig = u_ab.into_contiguous()?;
        assert!(contig.contains(a));
        assert!(contig.contains(b));
    } else {
        assert!(u_ab.is_disjoint());
        assert!(u_ab.gap_ns() > 0);
    }

    // Property 6: Containment consistency
    let cont_ab = a.classify_containment(b);
    if a.contains(b) {
        assert!(cont_ab.is_definite_contains());
    } else if a.abuts(b) {
        assert!(cont_ab.is_abutting());
    } else if !a.overlaps(b) {
        assert!(cont_ab.is_definite_disjoint());
    } else {
        assert!(cont_ab.is_indeterminate());
    }

    // Property 7: Monotone widening
    if let Ok(widened) = a.widen_skew(skew) {
        assert!(widened.uncertainty_ns() >= a.uncertainty_ns());
        assert!(widened.contains(a));
    }

    // Property 8: Canonical encode/decode round trip
    let encoded = a.canonical_bytes();
    let decoded = CaptureInterval::from_canonical_bytes(&encoded)?;
    assert_eq!(decoded, a);
    Ok(())
}

#[test]
fn property_test_interval_algebra_invariants() -> TestResult {
    let mut rng = DeterministicRng::new(0xDEAD_BEEF_CAFE_BABE);

    let mut part1_count = 0usize;
    let mut part2_count = 0usize;
    let mut part3_count = 0usize;
    let mut part4_count = 0usize;
    let mut part5_count = 0usize;
    let mut part6_count = 0usize;
    let mut part7_count = 0usize;

    // Partition 1: Standard uniform random intervals (300 pairs)
    for _ in 0..300 {
        let a = rng.next_interval(-1_000_000, 1_000_000)?;
        let b = rng.next_interval(-1_000_000, 1_000_000)?;
        let skew = (rng.next_u64() % 10_000) as u128;
        verify_interval_pair_invariants(a, b, skew)?;
        part1_count += 1;
    }

    // Partition 2: Realistic Unix timestamps ~1.72e18 ns (100 pairs)
    let unix_base: i128 = 1_725_000_000_000_000_000;
    for _ in 0..100 {
        let a = rng.next_interval(unix_base, unix_base + 1_000_000_000)?;
        let b = rng.next_interval(unix_base, unix_base + 1_000_000_000)?;
        verify_interval_pair_invariants(a, b, 500)?;
        part2_count += 1;
    }

    // Partition 3: Synthetic abutting pairs [t1, t2] and [t2 + 1, t3] (50 pairs)
    for _ in 0..50 {
        let t1 = rng.next_i128_range(0, 100_000);
        let t2 = t1 + rng.next_i128_range(10, 1_000);
        let t3 = t2 + 1 + rng.next_i128_range(10, 1_000);
        let a = CaptureInterval::new(TimestampNs(t1), TimestampNs(t2))?;
        let b = CaptureInterval::new(TimestampNs(t2 + 1), TimestampNs(t3))?;
        assert!(a.abuts(b));
        verify_interval_pair_invariants(a, b, 100)?;
        part3_count += 1;
    }

    // Partition 4: Synthetic boundary-touching pairs [t1, t2] and [t2, t3] (50 pairs)
    for _ in 0..50 {
        let t1 = rng.next_i128_range(0, 100_000);
        let t2 = t1 + rng.next_i128_range(10, 1_000);
        let t3 = t2 + rng.next_i128_range(10, 1_000);
        let a = CaptureInterval::new(TimestampNs(t1), TimestampNs(t2))?;
        let b = CaptureInterval::new(TimestampNs(t2), TimestampNs(t3))?;
        assert_eq!(
            a.temporal_precedence(b),
            TemporalPrecedence::BeforeOrAt {
                point: TimestampNs(t2),
            }
        );
        verify_interval_pair_invariants(a, b, 100)?;
        part4_count += 1;
    }

    // Partition 5: Concentric intervals (50 pairs)
    for _ in 0..50 {
        let t1 = rng.next_i128_range(0, 10_000);
        let t2 = t1 + 100;
        let t3 = t2 + 500;
        let t4 = t3 + 100;
        let outer = CaptureInterval::new(TimestampNs(t1), TimestampNs(t4))?;
        let inner = CaptureInterval::new(TimestampNs(t2), TimestampNs(t3))?;
        assert!(outer.contains(inner));
        verify_interval_pair_invariants(outer, inner, 100)?;
        part5_count += 1;
    }

    // Partition 6: Point intervals (50 pairs)
    for _ in 0..50 {
        let t1 = rng.next_i128_range(0, 100_000);
        let t2 = rng.next_i128_range(0, 100_000);
        let a = CaptureInterval::point(TimestampNs(t1));
        let b = CaptureInterval::point(TimestampNs(t2));
        assert_eq!(a.uncertainty_ns(), 0);
        assert_eq!(b.uncertainty_ns(), 0);
        verify_interval_pair_invariants(a, b, 50)?;
        part6_count += 1;
    }

    // Partition 7: Boundary values (MIN, MAX, 0, ±1)
    let near_min = CaptureInterval::new(TimestampNs(i128::MIN), TimestampNs(i128::MIN + 1_000))?;
    let near_max = CaptureInterval::new(TimestampNs(i128::MAX - 1_000), TimestampNs(i128::MAX))?;
    verify_interval_pair_invariants(near_min, near_max, 0)?;
    part7_count += 1;

    let neg_one_zero = CaptureInterval::new(TimestampNs(-1), TimestampNs(0))?;
    let zero_pos_one = CaptureInterval::new(TimestampNs(0), TimestampNs(1))?;
    verify_interval_pair_invariants(neg_one_zero, zero_pos_one, 0)?;
    part7_count += 1;

    let zero_point = CaptureInterval::point(TimestampNs::ZERO);
    let one_point = CaptureInterval::point(TimestampNs(1));
    verify_interval_pair_invariants(zero_point, one_point, 0)?;
    part7_count += 1;

    // Assert that each partition ran at least once
    assert!(part1_count > 0, "partition 1 must run at least once");
    assert!(part2_count > 0, "partition 2 must run at least once");
    assert!(part3_count > 0, "partition 3 must run at least once");
    assert!(part4_count > 0, "partition 4 must run at least once");
    assert!(part5_count > 0, "partition 5 must run at least once");
    assert!(part6_count > 0, "partition 6 must run at least once");
    assert!(part7_count > 0, "partition 7 must run at least once");

    Ok(())
}
