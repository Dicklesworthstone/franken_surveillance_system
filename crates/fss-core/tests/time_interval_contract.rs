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

    // Definite disjoint (gap = 400 - 300 - 1 = 99 ns)
    let c2 = outer.classify_containment(disjoint);
    assert!(c2.is_definite_disjoint());
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

    // Overlapping: precedence of underlying events cannot be collapsed -> Indeterminate
    let p_ov = a.temporal_precedence(overlap);
    assert!(p_ov.is_indeterminate());
    assert!(!p_ov.is_definitely_before());
    assert!(!p_ov.is_definitely_after());
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
        Err(ContractError::InvertedTimeInterval)
    );

    // Underflow on checked_sub
    assert_eq!(
        t_min.checked_sub(1),
        Err(TimeIntervalError::ArithmeticOverflow)
    );
    assert_eq!(
        t_min.checked_sub_ns(1),
        Err(ContractError::InvertedTimeInterval)
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
        interval.checked_shift(0, 10),
        Err(ContractError::InvertedTimeInterval)
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

    // Invalid ClockBasis tag fails closed
    let bad_tag = [99_u8];
    assert_eq!(
        ClockBasis::from_canonical_bytes(&bad_tag),
        Err(ContractError::InvalidDigest)
    );

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
        let span = (max - min) as u128;
        let r = ((self.next_u64() as u128) << 64) | (self.next_u64() as u128);
        min + (r % span) as i128
    }

    fn next_interval(&mut self, min: i128, max: i128) -> Result<CaptureInterval, ContractError> {
        let t1 = self.next_i128_range(min, max);
        let t2 = self.next_i128_range(min, max);
        let (earliest, latest) = if t1 <= t2 { (t1, t2) } else { (t2, t1) };
        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
    }
}

#[test]
fn property_test_interval_algebra_invariants() -> TestResult {
    let mut rng = DeterministicRng::new(0xDEAD_BEEF_CAFE_BABE);

    for _ in 0..500 {
        let a = rng.next_interval(-1_000_000, 1_000_000)?;
        let b = rng.next_interval(-1_000_000, 1_000_000)?;

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
        let indet = p_ab.is_indeterminate();

        // Exactly one of the three states must hold
        let count = (def_before as u8) + (def_after as u8) + (indet as u8);
        assert_eq!(count, 1);

        // Antisymmetry of precedence
        if def_before {
            assert!(p_ba.is_definitely_after());
        } else if def_after {
            assert!(p_ba.is_definitely_before());
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

        // Property 6: Monotone widening
        let skew = (rng.next_u64() % 10_000) as u128;
        let widened = a.widen_skew(skew)?;
        assert!(widened.uncertainty_ns() >= a.uncertainty_ns());
        assert!(widened.contains(a));

        // Property 7: Canonical encode/decode round trip
        let encoded = a.canonical_bytes();
        let decoded = CaptureInterval::from_canonical_bytes(&encoded)?;
        assert_eq!(decoded, a);
    }
    Ok(())
}
