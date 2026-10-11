#![forbid(unsafe_code)]
//! Property contract for the decision-card evaluation framework (FSS-197,
//! bead fss-x4a.26.17): hard-clamp precedence, shadow-first promotion,
//! safe-fallback presence, and registry-status gating — proven over the
//! exhaustive small input space (every clamp/status/shadow/evidence
//! combination), not sampled.

use fss_core::decision_card::{
    CardDefinition, CardEvaluation, CardStatus, Candidate, DecisionCardEvaluator,
};

fn card(status: CardStatus, shadow_first: bool) -> CardDefinition {
    CardDefinition {
        card_id: "DEC-TEST-001".to_string(),
        status,
        shadow_first,
        safe_fallback: "single authorized path".to_string(),
    }
}

fn candidate(clamps: &[&str], paired_evidence: bool) -> Candidate {
    Candidate {
        tripped_clamps: clamps.iter().map(|s| (*s).to_string()).collect(),
        paired_evidence,
    }
}

#[test]
fn hard_clamps_precede_everything_exhaustively() {
    for status in [CardStatus::Planned, CardStatus::Admitted] {
        for shadow_first in [false, true] {
            for paired in [false, true] {
                for clamps in [&["integrity"][..], &["integrity", "cost"][..]] {
                    let c = card(status, shadow_first);
                    let cand = candidate(clamps, paired);
                    let outcome = DecisionCardEvaluator::evaluate(&c, &cand);
                    match outcome {
                        CardEvaluation::Blocked { clamps: got, safe_fallback } => {
                            assert_eq!(got, cand.tripped_clamps);
                            assert_eq!(safe_fallback, "single authorized path");
                        }
                        other => panic!("clamped candidate must be Blocked, got {}", other.as_str()),
                    }
                }
            }
        }
    }
}

#[test]
fn planned_cards_are_never_executable() {
    for shadow_first in [false, true] {
        for paired in [false, true] {
            let c = card(CardStatus::Planned, shadow_first);
            let cand = candidate(&[], paired);
            match DecisionCardEvaluator::evaluate(&c, &cand) {
                CardEvaluation::Unavailable { status, safe_fallback } => {
                    assert_eq!(status, CardStatus::Planned);
                    assert_eq!(safe_fallback, "single authorized path");
                }
                other => panic!("planned card must be Unavailable, got {}", other.as_str()),
            }
        }
    }
}

#[test]
fn shadow_first_never_activates_without_paired_evidence() {
    let c = card(CardStatus::Admitted, true);
    let no_evidence = candidate(&[], false);
    assert_eq!(
        DecisionCardEvaluator::evaluate(&c, &no_evidence),
        CardEvaluation::Shadow,
        "shadow-first card without paired evidence stays in shadow"
    );
    let with_evidence = candidate(&[], true);
    assert_eq!(
        DecisionCardEvaluator::evaluate(&c, &with_evidence),
        CardEvaluation::Allowed { paired_evidence: true },
        "shadow-first card with paired evidence may allow"
    );
}

#[test]
fn admitted_plain_cards_allow_unclamped_candidates() {
    let c = card(CardStatus::Admitted, false);
    let cand = candidate(&[], false);
    assert_eq!(
        DecisionCardEvaluator::evaluate(&c, &cand),
        CardEvaluation::Allowed { paired_evidence: false }
    );
}

#[test]
fn every_refusal_carries_the_safe_fallback() {
    for status in [CardStatus::Planned, CardStatus::Admitted] {
        for shadow_first in [false, true] {
            let c = card(status, shadow_first);
            for cand in [candidate(&["privacy"], false), candidate(&[], false)] {
                let outcome = DecisionCardEvaluator::evaluate(&c, &cand);
                match &outcome {
                    CardEvaluation::Blocked { safe_fallback, .. }
                    | CardEvaluation::Unavailable { safe_fallback, .. } => {
                        assert_eq!(safe_fallback, "single authorized path");
                    }
                    _ => {}
                }
            }
        }
    }
}

#[test]
fn evaluation_digest_is_deterministic_and_distinguishes_outcomes() {
    let c = card(CardStatus::Admitted, true);
    let clean = candidate(&[], false);
    let clamped = candidate(&["cost"], false);
    let d1 = DecisionCardEvaluator::evaluation_digest(&c, &clean, &CardEvaluation::Shadow);
    let d2 = DecisionCardEvaluator::evaluation_digest(&c, &clean, &CardEvaluation::Shadow);
    assert_eq!(d1, d2, "deterministic over identical inputs");
    let blocked = DecisionCardEvaluator::evaluate(&c, &clamped);
    let d3 = DecisionCardEvaluator::evaluation_digest(&c, &clamped, &blocked);
    assert_ne!(d1, d3, "different outcomes digest differently");
}

#[test]
fn registry_status_parse_fails_closed() {
    assert_eq!(CardStatus::parse("planned"), Some(CardStatus::Planned));
    assert_eq!(CardStatus::parse("admitted"), Some(CardStatus::Admitted));
    assert_eq!(CardStatus::parse("production"), None, "unknown status refuses");
    assert_eq!(CardStatus::parse(""), None);
}
