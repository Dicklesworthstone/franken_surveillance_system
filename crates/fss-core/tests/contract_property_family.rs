#![forbid(unsafe_code)]
//! TEST-CONTRACT-001: ID/time/event/effect state-machine unit and property
//! tests (registries/TESTS.md, mandatory before GATE-010).
//!
//! Every property is deterministic: exhaustive grids where the domain is
//! small, seeded LCG generation where it is not. Each property emits ONE
//! JSONL line to stdout (`family/property/cases/seed/verdict`) so a
//! qualification lane capture yields a structured proof log; assertions
//! stay the hard gate. Reproduce independently:
//! `cargo test -p fss-core --test contract_property_family -- --nocapture`.

use fss_core::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use fss_core::{CaptureInterval, TimestampNs};
use fss_core::{EffectState, ObligationState, validate_id};
use fss_core::{EventEvidence, EvidenceClass, EvidenceEdgeRelation};

/// Deterministic 64-bit LCG (Knuth constants). Same seed, same sequence.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    /// Bounded pseudo-random value in `0..n`.
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn emit(property: &str, cases: u64, seed: u64) {
    println!(
        "{{\"family\":\"TEST-CONTRACT-001\",\"property\":\"{property}\",\"cases\":{cases},\"seed\":{seed},\"verdict\":\"pass\"}}"
    );
}

// ---------------------------------------------------------------- P1: time

#[test]
fn p1_timestamp_arithmetic_roundtrip_and_symmetry() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0051_5453_3100;
    let mut cases = 0u64;
    let anchors = [
        i128::from(i64::MIN),
        -1,
        0,
        1,
        i128::from(i64::MAX),
        1_000_000_000,
        -1_000_000_000,
    ];
    let deltas = [-2i128, -1, 0, 1, 2, 86_400_000_000_000, -86_400_000_000_000];
    for &a in &anchors {
        for &d in &deltas {
            let t = TimestampNs(a);
            if let (Ok(_up), Ok(back)) = (t.checked_add_ns(d), t.checked_add_ns(-d)) {
                // add/sub inverse: (t - d) + d == t
                assert_eq!(back.checked_add_ns(d)?, t);
            }
            // Overflow must be a typed refusal, never a wrap.
            if t.checked_add_ns(d).is_err() {
                assert!(
                    a.checked_add(d).is_none(),
                    "refusal without real overflow at {a}+{d}"
                );
            }
            // abs_diff symmetric; duration_since non-negative when defined.
            let u = TimestampNs(a ^ 0x5555);
            assert_eq!(t.abs_diff(u), u.abs_diff(t));
            if let Ok(dur) = t.checked_duration_since(u) {
                assert!(u.checked_duration_since(t).is_err() || dur == 0);
            }
            cases += 1;
        }
    }
    // Extreme boundaries refuse instead of panicking.
    assert!(TimestampNs(i128::MAX).checked_add_ns(1).is_err());
    assert!(TimestampNs(i128::MIN).checked_sub_ns(1).is_err());
    cases += 2;
    emit("timestamp-arithmetic", cases, SEED);
    Ok(())
}

#[test]
fn p2_capture_interval_conservative_lattice() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0049_4349_3200;
    const N: u64 = 500;
    let mut rng = Lcg::new(SEED);
    let span = 1_000_000_000_000i128;
    let interval = |rng: &mut Lcg| -> (i128, i128) {
        let a = (rng.below(2 * span as u64) as i128) - span;
        let b = (rng.below(2 * span as u64) as i128) - span;
        if a <= b { (a, b) } else { (b, a) }
    };
    for _ in 0..N {
        let (xlo, xhi) = interval(&mut rng);
        let x = CaptureInterval::new(TimestampNs(xlo), TimestampNs(xhi))?;
        let (ylo, yhi) = interval(&mut rng);
        let y = CaptureInterval::new(TimestampNs(ylo), TimestampNs(yhi))?;
        // Reflexive containment; uncertainty is exactly the width.
        assert!(x.contains(x));
        assert_eq!(x.uncertainty_ns(), (x.latest.0 - x.earliest.0) as u128);
        // Hull: commutative, contains both.
        let (h1, h2) = (x.hull(y), y.hull(x));
        assert_eq!(h1, h2);
        assert!(h1.contains(x) && h1.contains(y));
        // Intersection: commutative, contained in both, consistent with overlap.
        let (i1, i2) = (x.intersection(y), y.intersection(x));
        assert_eq!(i1, i2);
        if let Some(ix) = i1 {
            assert!(x.contains(ix) && y.contains(ix));
            assert!(x.overlaps(y));
        }
        // Conservativity: anything both contain, the intersection contains.
        let probe = TimestampNs((rng.below(2 * span as u64) as i128) - span);
        let in_both = x.contains_timestamp(probe) && y.contains_timestamp(probe);
        if in_both {
            let Some(ix) = x.intersection(y) else {
                return Err("shared point implies nonempty intersection".into());
            };
            assert!(ix.contains_timestamp(probe));
        }
        // Inverted construction is refused (never silently normalized).
        assert!(
            CaptureInterval::new(TimestampNs(10), TimestampNs(9)).is_err(),
            "inverted interval must refuse"
        );
    }
    emit("capture-interval-lattice", N, SEED);
    Ok(())
}

// ------------------------------------------------------- P3: effect machine

#[test]
fn p3_effect_state_machine_exhaustive() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0000_0000_4553;
    let states = [
        EffectState::Prepared,
        EffectState::Committed,
        EffectState::AdapterAccepted,
        EffectState::Observed,
        EffectState::Verified,
        EffectState::Cancelled,
        EffectState::Failed,
        EffectState::Indeterminate,
    ];
    let mut cases = 0u64;
    for &from in &states {
        let mut outgoing = 0u64;
        for &to in &states {
            let legal = from.can_transition_to(to);
            // No self transitions anywhere in the machine.
            if from == to {
                assert!(!legal, "{from:?} must not self-transition");
            }
            if legal {
                outgoing += 1;
            }
            cases += 1;
        }
        // Terminals are exactly the states with no outgoing transition, and
        // is_terminal agrees with that count (no dead non-terminals, no
        // live terminals).
        assert_eq!(
            outgoing == 0,
            from.is_terminal(),
            "{from:?}: dead-state/is_terminal mismatch"
        );
        if !from.is_terminal() {
            assert!(outgoing >= 1, "{from:?} is a dead non-terminal state");
        }
    }
    // The Indeterminate exit set is exactly {Observed, Failed}: an uncertain
    // effect may resolve to an observation or a failure, never to success.
    assert!(EffectState::Indeterminate.can_transition_to(EffectState::Observed));
    assert!(EffectState::Indeterminate.can_transition_to(EffectState::Failed));
    assert!(!EffectState::Indeterminate.can_transition_to(EffectState::Verified));
    cases += 3;
    emit("effect-state-machine", cases, SEED);
    Ok(())
}

// ---------------------------------------------------------- P4: ID grammar

#[test]
fn p4_stable_id_grammar_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0000_0000_4944;
    let mut cases = 0u64;
    // Allowed alphabet: alphanumerics + - _ . :
    let allowed: Vec<char> = "abzABZ09-_.:".chars().collect();
    for &len in &[0usize, 1, 2, 127, 128, 129] {
        for &c in &allowed {
            let id: String = std::iter::repeat_n(c, len).collect();
            let expect_ok = (1..=128).contains(&len);
            assert_eq!(
                validate_id(&id).is_ok(),
                expect_ok,
                "len {len} char {c:?} grammar mismatch"
            );
            cases += 1;
        }
    }
    // Rejected bytes never pass, at any length.
    for bad in [' ', '/', ';', '\0', 'é', '\t', '#', '@'] {
        let id: String = std::iter::repeat_n(bad, 8).collect();
        assert!(validate_id(&id).is_err(), "rejected char {bad:?} passed");
        cases += 1;
    }
    // Mixed: one bad char poisons an otherwise-valid id.
    assert!(validate_id("good:id-1.x").is_ok());
    assert!(validate_id("good id").is_err());
    cases += 2;
    emit("stable-id-grammar", cases, SEED);
    Ok(())
}

// --------------------------------------------------- P5: canonical codecs

#[test]
fn p5_canonical_roundtrips_for_state_enums() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x0000_0000_4352;
    let effects = [
        EffectState::Prepared,
        EffectState::Committed,
        EffectState::AdapterAccepted,
        EffectState::Observed,
        EffectState::Verified,
        EffectState::Cancelled,
        EffectState::Failed,
        EffectState::Indeterminate,
    ];
    let obligations = [
        ObligationState::Pending,
        ObligationState::Verified,
        ObligationState::Failed,
        ObligationState::Indeterminate,
        ObligationState::Cancelled,
    ];
    let mut cases = 0u64;
    for e in effects {
        let mut enc = CanonicalEncoder::new();
        e.encode_canonical(&mut enc);
        let bytes = enc.finish();
        let mut dec = CanonicalDecoder::new(&bytes);
        assert_eq!(EffectState::decode_canonical(&mut dec)?, e);
        cases += 1;
    }
    for o in obligations {
        let mut enc = CanonicalEncoder::new();
        o.encode_canonical(&mut enc);
        let bytes = enc.finish();
        let mut dec = CanonicalDecoder::new(&bytes);
        assert_eq!(ObligationState::decode_canonical(&mut dec)?, o);
        cases += 1;
    }
    emit("canonical-roundtrips", cases, SEED);
    Ok(())
}

// ------------------------------------------ P6: tamper/revision ordering

#[test]
fn p6_restoration_retires_only_strictly_later_revisions() -> Result<(), Box<dyn std::error::Error>>
{
    const SEED: u64 = 0x0000_0000_5245;
    let mut cases = 0u64;
    let mk_evidence = |relation: EvidenceEdgeRelation, identity: [u8; 32]| EventEvidence {
        digest: fss_core::ContentDigest::sha256(&identity),
        class: EvidenceClass::Observed,
        failure_domain: "domain:sensor-a".to_string(),
        supports: false,
        relation,
        capsule_digest: None,
        identity_digest: Some(fss_core::ContentDigest::sha256(b"identity")),
    };
    let tamper = mk_evidence(EvidenceEdgeRelation::SensorTamper, [1u8; 32]);
    let restoration = mk_evidence(EvidenceEdgeRelation::SensorIntegrityRestoration, [2u8; 32]);
    assert!(tamper.reports_sensor_tamper());
    assert!(restoration.reports_integrity_restoration());

    let tamper_window = CaptureInterval::new(TimestampNs(0), TimestampNs(100))?;
    for tamper_rev in [1u64, 5, 50] {
        for restore_rev_delta in [0u64, 1] {
            for restore_start in [0i128, 100, 101] {
                let mut status = fss_core::event::SensorTamperStatus::default();
                fss_core::event::apply_evidence_batch(
                    &mut status,
                    std::slice::from_ref(&tamper),
                    tamper_rev,
                    Some(tamper_window),
                );
                assert!(status.has_open_tamper(), "tamper must open a record");
                let restore_window = CaptureInterval::new(
                    TimestampNs(restore_start),
                    TimestampNs(restore_start + 100),
                )?;
                let restore_rev = tamper_rev + restore_rev_delta;
                fss_core::event::apply_evidence_batch(
                    &mut status,
                    std::slice::from_ref(&restoration),
                    restore_rev,
                    Some(restore_window),
                );
                let retired = !status.has_open_tamper();
                let strictly_later_revision = restore_rev > tamper_rev;
                let strictly_later_capture = restore_start > 100;
                assert_eq!(
                    retired,
                    strictly_later_revision && strictly_later_capture,
                    "retire rule violated: tamper_rev={tamper_rev} restore_rev={restore_rev} restore_start={restore_start}"
                );
                cases += 1;
            }
        }
    }
    emit("restoration-revision-ordering", cases, SEED);
    Ok(())
}
