#![forbid(unsafe_code)]
//! Failure and replay contracts for source-bound sequential transcript identities.

use super::*;
use crate::{Calibration, Coverage, EvidenceItem, FusionPolicy, Observability, Severity};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn observation(id: &str, sensor: &str) -> Result<EvidenceItem, FusionError> {
    Ok(EvidenceItem {
        id: id.to_owned(),
        sensor: sensor.to_owned(),
        failure_domains: [format!("sensor:{sensor}")].into_iter().collect(),
        calibration: Calibration::Calibrated {
            generation: "cal:v1".to_owned(),
            llr: LlrInterval::new(700, 900)?,
        },
        observability: Observability::Observed,
    })
}

fn query(evidence: Vec<EvidenceItem>) -> Result<FusionQuery, FusionError> {
    Ok(FusionQuery {
        hypothesis: "hyp:entry-door".to_owned(),
        kind: "zone_entry".to_owned(),
        prior: LlrInterval::point(0)?,
        evidence,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 10_000,
            false_alert_cost: 500,
            delay_cost_per_second: 100,
            reversible: false,
        },
        policy: FusionPolicy {
            generation: "policy:v1".to_owned(),
            alert_threshold: 1_800,
            retain_threshold: 0,
            reject_threshold: -1_000,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 0,
            look_penalty_per_doubling: 0,
            operator_confirmation_available: false,
        },
        looks: 1,
        now_ns: 1_000_000_000,
    })
}

fn accumulator() -> Result<SequentialEProcess, FusionError> {
    SequentialEProcess::new("hyp:entry-door", EProcessConfig::default())
}

#[test]
fn foreign_hypothesis_refuses_without_changing_any_later_transition() -> TestResult {
    let mut actual = accumulator()?;
    actual.observe_step(&query(vec![observation("east:0", "east")?])?)?;
    let mut untouched = actual.clone();
    let mut foreign = query(vec![observation("west:1", "west")?])?;
    foreign.hypothesis = "hyp:other-incident".to_owned();
    assert!(matches!(
        actual.observe_step(&foreign),
        Err(FusionError::InvalidInput(_))
    ));
    assert_eq!(actual.transcript_head(), untouched.transcript_head());
    assert_eq!(actual.accumulated_llr(), untouched.accumulated_llr());
    assert_eq!(actual.independent_supporting_clusters(), 1);

    foreign.hypothesis = "hyp:entry-door".to_owned();
    assert_eq!(
        actual.observe_step(&foreign)?,
        untouched.observe_step(&foreign)?
    );
    let reset = RegimeResetReason::OperatorReset {
        reason: "reviewed restart".to_owned(),
    };
    assert_eq!(
        actual.reset_regime(reset.clone()),
        untouched.reset_regime(reset)
    );
    Ok(())
}

#[test]
fn invalid_query_does_not_append_a_transcript() -> TestResult {
    let mut actual = accumulator()?;
    let mut untouched = accumulator()?;
    let row = observation("east:0", "east")?;
    let duplicate = query(vec![row.clone(), row.clone()])?;
    assert!(actual.observe_step(&duplicate).is_err());
    assert_eq!(actual.transcript_head(), None);
    let valid = query(vec![row])?;
    assert_eq!(
        actual.observe_step(&valid)?,
        untouched.observe_step(&valid)?
    );
    Ok(())
}

#[test]
fn source_identity_is_bound_even_when_numerics_and_domain_inventory_match() -> TestResult {
    let mut first = accumulator()?;
    let mut substituted = accumulator()?;
    let (fusion_a, a) = first.observe_step(&query(vec![observation("source:a", "east")?])?)?;
    let (fusion_b, b) =
        substituted.observe_step(&query(vec![observation("source:b", "east")?])?)?;
    assert_eq!(
        a.step_digest, b.step_digest,
        "historical v1 remains numerical"
    );
    assert_eq!(
        a.transcript.supporting_domains_digest(),
        b.transcript.supporting_domains_digest()
    );
    assert_ne!(a.transcript.digest(), b.transcript.digest());
    assert_eq!(a.transcript.previous(), None);
    assert_eq!(a.transcript.numerical_step_digest(), a.step_digest);
    assert_eq!(
        a.transcript.input(),
        EProcessStepInput::Observation {
            query_digest: fusion_a.query_digest,
            decision_digest: fusion_a.decision_digest,
        }
    );
    assert_eq!(
        b.transcript.input(),
        EProcessStepInput::Observation {
            query_digest: fusion_b.query_digest,
            decision_digest: fusion_b.decision_digest,
        }
    );

    let common_next = query(vec![observation("source:next", "west")?])?;
    let (_, a_next) = first.observe_step(&common_next)?;
    let (_, b_next) = substituted.observe_step(&common_next)?;
    assert_eq!(a_next.step_digest, b_next.step_digest);
    assert_eq!(a_next.transcript.input(), b_next.transcript.input());
    assert_ne!(
        a_next.transcript.digest(),
        b_next.transcript.digest(),
        "same next input cannot erase different history"
    );
    assert_eq!(a_next.transcript.previous(), Some(a.transcript.digest()));
    assert_eq!(b_next.transcript.previous(), Some(b.transcript.digest()));
    Ok(())
}

#[test]
fn exact_policy_generation_is_bound_without_changing_numeric_compatibility() -> TestResult {
    let mut first = accumulator()?;
    let mut second = accumulator()?;
    let mut input = query(vec![observation("source:a", "east")?])?;
    let (_, a) = first.observe_step(&input)?;
    input.policy.generation = "policy:v2".to_owned();
    let (_, b) = second.observe_step(&input)?;
    assert_eq!(a.step_digest, b.step_digest);
    assert_ne!(a.transcript.digest(), b.transcript.digest());
    Ok(())
}

#[test]
fn deterministic_replay_and_input_permutation_preserve_the_complete_transcript() -> TestResult {
    let mut first = accumulator()?;
    let mut replay = accumulator()?;
    let mut input = query(vec![
        observation("source:west", "west")?,
        observation("source:east", "east")?,
    ])?;
    let a = first.observe_step(&input)?;
    input.evidence.reverse();
    let b = replay.observe_step(&input)?;
    assert_eq!(a, b);
    let reset = RegimeResetReason::ClockContinuityBroken {
        sensor: "east".to_owned(),
        gap_ns: 1_000_000,
    };
    assert_eq!(
        first.reset_regime(reset.clone()),
        replay.reset_regime(reset)
    );
    let next = query(vec![observation("source:next", "east")?])?;
    assert_eq!(first.observe_step(&next)?, replay.observe_step(&next)?);
    assert_eq!(first.transcript_head(), replay.transcript_head());
    Ok(())
}

#[test]
fn support_inventory_is_canonical_but_chronology_is_preserved() -> TestResult {
    let east = query(vec![observation("source:east", "east")?])?;
    let west = query(vec![observation("source:west", "west")?])?;
    let mut first = accumulator()?;
    let mut swapped = accumulator()?;
    first.observe_step(&east)?;
    swapped.observe_step(&west)?;
    let (_, a) = first.observe_step(&west)?;
    let (_, b) = swapped.observe_step(&east)?;
    assert_eq!(a.step_digest, b.step_digest);
    assert_eq!(
        a.transcript.supporting_domains_digest(),
        b.transcript.supporting_domains_digest()
    );
    assert_ne!(a.transcript.digest(), b.transcript.digest());

    let mut other = accumulator()?;
    other.observe_step(&east)?;
    let (_, c) = other.observe_step(&query(vec![observation("source:south", "south")?])?)?;
    assert_eq!(
        a.independent_supporting_clusters,
        c.independent_supporting_clusters
    );
    assert_eq!(a.step_digest, c.step_digest);
    assert_ne!(
        a.transcript.supporting_domains_digest(),
        c.transcript.supporting_domains_digest()
    );
    Ok(())
}

#[test]
fn reset_clears_support_without_erasing_the_evidence_chain() -> TestResult {
    let mut first = accumulator()?;
    let mut substituted = accumulator()?;
    let (_, a) = first.observe_step(&query(vec![observation("source:a", "east")?])?)?;
    let (_, b) = substituted.observe_step(&query(vec![observation("source:b", "east")?])?)?;
    let reason = RegimeResetReason::OperatorReset {
        reason: "reviewed restart".to_owned(),
    };
    let reset_a = first.reset_regime(reason.clone());
    let reset_b = substituted.reset_regime(reason);
    assert_eq!(reset_a.transcript.previous(), Some(a.transcript.digest()));
    assert_eq!(reset_b.transcript.previous(), Some(b.transcript.digest()));
    assert!(matches!(
        reset_a.transcript.input(),
        EProcessStepInput::RegimeReset { .. }
    ));
    assert_eq!(reset_a.regime_epoch, 1);
    assert_eq!(reset_a.accumulated_llr, LlrInterval::point(0)?);
    assert_eq!(reset_a.independent_supporting_clusters, 0);
    assert_eq!(
        reset_a.transcript.supporting_domains_digest(),
        reset_b.transcript.supporting_domains_digest()
    );
    assert_eq!(reset_a.step_digest, reset_b.step_digest);
    assert_ne!(reset_a.transcript.digest(), reset_b.transcript.digest());

    let next = query(vec![observation("source:next", "east")?])?;
    let (_, a_next) = first.observe_step(&next)?;
    let (_, b_next) = substituted.observe_step(&next)?;
    assert_eq!(a_next.step_digest, b_next.step_digest);
    assert_eq!(
        a_next.transcript.previous(),
        Some(reset_a.transcript.digest())
    );
    assert_ne!(a_next.transcript.digest(), b_next.transcript.digest());
    Ok(())
}

#[test]
fn a_first_reset_and_consecutive_resets_have_distinct_linked_identities() -> TestResult {
    let mut process = accumulator()?;
    let reason = RegimeResetReason::OperatorReset {
        reason: "start uncertain".to_owned(),
    };
    let first = process.reset_regime(reason.clone());
    assert_eq!(first.transcript.previous(), None);
    assert!(matches!(
        first.transcript.input(),
        EProcessStepInput::RegimeReset { .. }
    ));
    let second = process.reset_regime(reason);
    assert_eq!(
        second.transcript.previous(),
        Some(first.transcript.digest())
    );
    assert_ne!(first.transcript.digest(), second.transcript.digest());
    assert_eq!(process.transcript_head(), Some(second.transcript.digest()));
    Ok(())
}

#[test]
fn numerical_v1_observation_and_reset_digest_fixtures_are_unchanged() -> TestResult {
    let mut process = accumulator()?;
    let (_, step) = process.observe_step(&query(vec![observation("source:a", "east")?])?)?;
    // Independently encoded from the pre-transcript v1 contract: two length-prefixed texts,
    // index/epoch/config, delta/current/supremum, conditional formulas, count and flags.
    assert_eq!(
        step.step_digest.to_text(),
        "sha256:2aff4ac0818a600d399d60a9b4b2d0e3a94f3291119d23aaef2b76ddcaed70a9"
    );
    let reset = process.reset_regime(RegimeResetReason::OperatorReset {
        reason: "reviewed restart".to_owned(),
    });
    assert_eq!(
        reset.step_digest.to_text(),
        "sha256:cf2e55af6be0ed619faa0f8ca1868f496bda467ada0ff5de2a795cc07d09c64c"
    );
    Ok(())
}

#[test]
fn oversized_legacy_reset_reasons_still_bind_exact_bytes_in_the_transcript() -> TestResult {
    let mut first = accumulator()?;
    let mut second = accumulator()?;
    let prefix = "a".repeat(fss_core::MAX_CANONICAL_TEXT_BYTES);
    let a = first.reset_regime(RegimeResetReason::OperatorReset {
        reason: format!("{prefix}a"),
    });
    let b = second.reset_regime(RegimeResetReason::OperatorReset {
        reason: format!("{prefix}b"),
    });
    assert_eq!(
        a.step_digest, b.step_digest,
        "legacy infallible numerical bytes remain historical"
    );
    assert_ne!(a.transcript.input(), b.transcript.input());
    assert_ne!(a.transcript.digest(), b.transcript.digest());
    Ok(())
}

#[test]
fn oversized_resets_bind_hypothesis_config_and_subsequent_numeric_state() -> TestResult {
    let oversized = "x".repeat(fss_core::MAX_CANONICAL_TEXT_BYTES + 1);
    for reason in [
        RegimeResetReason::OperatorReset {
            reason: oversized.clone(),
        },
        RegimeResetReason::SensorHealthDegraded {
            sensor: oversized.clone(),
            reason: "lens obscured".to_owned(),
        },
        RegimeResetReason::ClockContinuityBroken {
            sensor: oversized.clone(),
            gap_ns: 10_000,
        },
    ] {
        let mut original = accumulator()?;
        let mut other_hypothesis =
            SequentialEProcess::new("hyp:other-door", EProcessConfig::default())?;
        let mut lower_ceiling = SequentialEProcess::new(
            "hyp:entry-door",
            EProcessConfig {
                alert_threshold_mban: 700,
                ceiling_mban: 800,
                ..EProcessConfig::default()
            },
        )?;
        let reset = original.reset_regime(reason.clone());
        let other = other_hypothesis.reset_regime(reason.clone());
        let lower = lower_ceiling.reset_regime(reason);
        assert_eq!(reset.step_digest, ContentDigest::sha256(b""));
        for changed in [&other, &lower] {
            assert_eq!(reset.step_digest, changed.step_digest);
            assert_eq!(reset.transcript.input(), changed.transcript.input());
            assert_eq!(
                reset.transcript.supporting_domains_digest(),
                changed.transcript.supporting_domains_digest()
            );
            assert_ne!(
                reset.transcript.state_digest(),
                changed.transcript.state_digest()
            );
            assert_ne!(reset.transcript.digest(), changed.transcript.digest());
        }

        // The unbounded last-reset text persists into later numerical v1 steps. The new state
        // must still commit different clamps and actual values when both legacy hashes collapse.
        let observed = query(vec![observation("source:post-reset", "east")?])?;
        let (_, next) = original.observe_step(&observed)?;
        let (_, lower_next) = lower_ceiling.observe_step(&observed)?;
        assert_eq!(next.step_digest, reset.step_digest);
        assert_eq!(next.step_digest, lower_next.step_digest);
        assert_eq!(next.transcript.input(), lower_next.transcript.input());
        assert_ne!(next.accumulated_llr, lower_next.accumulated_llr);
        assert_ne!(
            next.transcript.state_digest(),
            lower_next.transcript.state_digest()
        );
        assert_ne!(
            next.transcript.state_digest(),
            reset.transcript.state_digest()
        );
        assert_ne!(next.transcript.digest(), lower_next.transcript.digest());
        assert_eq!(next.transcript.previous(), Some(reset.transcript.digest()));
        assert_eq!(
            lower_next.transcript.previous(),
            Some(lower.transcript.digest())
        );
    }
    Ok(())
}
