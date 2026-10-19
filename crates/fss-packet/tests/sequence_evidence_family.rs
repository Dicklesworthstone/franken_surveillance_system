#![forbid(unsafe_code)]
//! FSS-048: RTP/RTCP sequence/timing evidence — property family over the
//! `SequenceTracker` (RFC 3550 A.1 probation, wrap, reorder window,
//! duplicate suppression, restart epochs). Each property emits one JSONL
//! verdict line.

use fss_packet::{
    ContinuityError, PacketLimits, RtpPacket, SequenceClass, SequenceTracker, StreamKey,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-048\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

type DynError = Box<dyn std::error::Error>;

/// Minimal RTP wire bytes for the given sequence (V=2, PT=96, SSRC 7).
fn seq_bytes(sequence: u16) -> [u8; 13] {
    [
        0x80,
        96,
        (sequence >> 8) as u8,
        sequence as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        7,
        0x7c,
    ]
}

/// Observe one sequence on `t` under `KEY` (borrow kept inside the call).
fn obs(
    t: &mut SequenceTracker,
    sequence: u16,
) -> Result<fss_packet::SequenceObservation, DynError> {
    let bytes = seq_bytes(sequence);
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    Ok(t.observe(KEY, packet)?)
}

fn tracker() -> Result<SequenceTracker, DynError> {
    Ok(SequenceTracker::new(KEY, 96)?)
}

fn establish(tracker: &mut SequenceTracker, first: u16) -> Result<(), DynError> {
    obs(tracker, first)?;
    obs(tracker, first.wrapping_add(1))?;
    Ok(())
}

/// P1 PROBATION/BASELINE: a lone packet is probation; a non-sequential
/// second restarts probation; two sequential packets establish the
/// accounting baseline.
#[test]
fn p1_probation_and_baseline() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = tracker()?;
    let first = obs(&mut t, 100)?;
    assert_eq!(first.class, SequenceClass::Probation);
    assert!(!first.is_unique());
    // Non-sequential: probation restarts, still no admission.
    let jump = obs(&mut t, 500)?;
    assert_eq!(jump.class, SequenceClass::Probation);
    // Sequential pair establishes the baseline.
    let base = obs(&mut t, 501)?;
    assert_eq!(base.class, SequenceClass::Baseline);
    assert!(base.is_unique());
    // Probation arrivals are not admitted evidence: the baseline packet is
    // the first unique position.
    assert_eq!(base.stats.unique, 1);
    assert_eq!(base.stats.expected, 1);
    emit("probation-baseline", 3);
    Ok(())
}

/// P2 ADVANCE/DUPLICATE/REORDER/BEFORE-BASELINE dispositions and their
/// exact accounting effects.
#[test]
fn p2_dispositions_and_accounting() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = tracker()?;
    establish(&mut t, 1000)?;
    let before = t.stats();
    // Advance over a gap (1003 admitted; 1002 left missing).
    let adv = obs(&mut t, 1003)?;
    assert_eq!(adv.class, SequenceClass::Advanced);
    assert!(adv.is_unique());
    assert_eq!(t.stats().unique, before.unique + 1);
    assert!(
        t.stats().missing >= 1,
        "the gap at 1002 is provisionally missing"
    );
    // Duplicate of the newest: received grows, unique does not.
    let mid = t.stats();
    let dup = obs(&mut t, 1003)?;
    assert_eq!(dup.class, SequenceClass::Duplicate);
    assert!(!dup.is_unique());
    assert_eq!(t.stats().unique, mid.unique);
    assert_eq!(t.stats().received, mid.received + 1);
    // Reordered: the genuinely missing 1002 recovers; missing decreases.
    let gap = t.stats();
    let re = obs(&mut t, 1002)?;
    assert_eq!(re.class, SequenceClass::Reordered);
    assert!(re.is_unique());
    assert_eq!(t.stats().missing, gap.missing - 1);
    // Before baseline: refused admission, accounting untouched.
    let pre = t.stats();
    let old = obs(&mut t, 999)?;
    assert_eq!(old.class, SequenceClass::BeforeBaseline);
    assert!(!old.is_unique());
    assert_eq!(t.stats(), pre);
    emit("dispositions-accounting", 4);
    Ok(())
}

/// P3 WRAP: sequence numbers crossing the u16 boundary stay sequential
/// with a monotone extended sequence.
#[test]
fn p3_wrap_tracking() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = tracker()?;
    establish(&mut t, 65_534)?;
    let a = obs(&mut t, 0)?; // 65534, 65535 established; 0 is next.
    assert_eq!(a.class, SequenceClass::Advanced);
    let ext_a = a.extended_sequence.ok_or("wrap must map to extended seq")?;
    let b = obs(&mut t, 1)?;
    let ext_b = b.extended_sequence.ok_or("wrap must map to extended seq")?;
    assert!(ext_b > ext_a, "extended sequence is monotone across wrap");
    emit("wrap-tracking", 2);
    Ok(())
}

/// P4 DISCONTINUITY/RESTART: a >3000 jump suspects discontinuity;
/// consecutive discontinuous packets demand a new epoch; restart requires
/// a strictly newer generation and preserves nothing from the old.
#[test]
fn p4_discontinuity_and_restart() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = tracker()?;
    establish(&mut t, 100)?;
    let jump = obs(&mut t, 4_000)?;
    assert_eq!(jump.class, SequenceClass::DiscontinuitySuspected);
    let again = obs(&mut t, 8_000)?;
    assert_eq!(again.class, SequenceClass::DiscontinuitySuspected);
    // Restart with a strictly newer generation: fresh probation.
    let mut fresh = t.restart(
        StreamKey {
            generation: 2,
            ..KEY
        },
        96,
    )?;
    let gen2 = StreamKey {
        generation: 2,
        ..KEY
    };
    let bytes = seq_bytes(50);
    let first = fresh.observe(gen2, RtpPacket::parse(&bytes, PacketLimits::default())?)?;
    assert_eq!(first.class, SequenceClass::Probation, "restart is fresh");
    // Older or same generation refused; different ingress refused.
    assert!(matches!(
        t.restart(
            StreamKey {
                generation: 1,
                ..KEY
            },
            96
        ),
        Err(ContinuityError::GenerationRequired)
    ));
    assert!(matches!(
        t.restart(
            StreamKey {
                ingress: 9,
                generation: 5,
                ..KEY
            },
            96
        ),
        Err(ContinuityError::StreamMismatch)
    ));
    emit("discontinuity-restart", 5);
    Ok(())
}

/// P5 ACCOUNTING INVARIANTS over a seeded mixed stream (advance, gaps,
/// late recovery, duplicates): expected >= unique, missing ==
/// expected - unique, duplicates never inflate unique.
#[test]
fn p5_accounting_invariants() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = 0x0046_3438_u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        seed >> 33
    };
    let mut t = tracker()?;
    establish(&mut t, 1_000)?;
    for step in 0..500u64 {
        let choice = next() % 10;
        let highest = 1_001 + step as u16;
        let seq = match choice {
            0..=5 => highest,             // advance
            6 => highest.wrapping_sub(2), // late recovery (reorder)
            _ => highest.wrapping_sub(1), // duplicate of the last
        };
        obs(&mut t, seq)?;
        let s = t.stats();
        assert!(s.expected >= s.unique, "step {step}: expected >= unique");
        assert_eq!(
            s.missing,
            s.expected - s.unique,
            "step {step}: missing identity"
        );
        assert!(
            s.received >= s.unique,
            "step {step}: duplicates counted in received"
        );
    }
    emit("accounting-invariants", 500);
    Ok(())
}

/// P6 OWNERSHIP: cross-ingress, wrong SSRC, and wrong payload type are
/// refused with the tracker's state bit-for-bit unchanged.
#[test]
fn p6_ownership_refusals_are_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let mut t = tracker()?;
    establish(&mut t, 100)?;
    let snapshot = t.clone();
    let other_key = StreamKey { ingress: 2, ..KEY };
    {
        let bytes = seq_bytes(102);
        let wrong_key_packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
        assert!(matches!(
            t.observe(other_key, wrong_key_packet),
            Err(ContinuityError::StreamMismatch)
        ));
    }
    // Wrong SSRC on the wire.
    let bytes = [0x80, 96, 0, 102, 0, 0, 0, 0, 0, 0, 0, 99, 0x7c];
    let wrong = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert!(matches!(
        t.observe(KEY, wrong),
        Err(ContinuityError::StreamMismatch)
    ));
    // Wrong payload type.
    let bytes = [0x80, 97, 0, 102, 0, 0, 0, 0, 0, 0, 0, 7, 0x7c];
    let wrong_pt = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert!(matches!(
        t.observe(KEY, wrong_pt),
        Err(ContinuityError::PayloadType)
    ));
    assert_eq!(t, snapshot, "refusals leave the tracker untouched");
    emit("ownership-atomicity", 3);
    Ok(())
}
