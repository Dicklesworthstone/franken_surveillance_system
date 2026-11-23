#![forbid(unsafe_code)]
//! Cancellation of real retained explanations through the same facade used by native MCP work.

// The shared fixture also exposes helpers and objects used by other custody contracts.
#[allow(dead_code)]
#[path = "../custody_review/fixture.rs"]
mod fixture;

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::json_input::{Value, parse};
use fss_core::{CaptureInterval, EventHypothesis, TimestampNs};
use fss_fusion::ScoreCalibration;
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::{ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision};

use super::*;
use crate::{FssCommand, RequestControl, execute_live_fss_with_control};
use fixture::{Fixture, TestResult, inventory};

fn arguments(f: &Fixture) -> TestResult<ExplainArgs> {
    Ok(ExplainArgs {
        root: f.root.clone(),
        at: None,
        target: ExplainTarget::Event(f.event.event_id.clone()),
        principal: PrincipalId::parse(DEFAULT_PRINCIPAL)?,
        view: AgentView::Forensic,
        budget_tokens: None,
        custody: false,
        score_calibration: None,
        fusion_policy: None,
    })
}

fn field<'a>(body: &'a Value, key: &str) -> TestResult<&'a Value> {
    body.object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}

fn cancelled_envelope(body: &str) -> TestResult<Value> {
    let value = parse(body)?;
    assert_eq!(
        field(&value, "outcome")?.text(),
        Some("cancelled"),
        "{body}"
    );
    assert_eq!(field(&value, "operationId")?.text(), Some("AOP-011"));
    assert_eq!(field(&value, "payload")?, &Value::Null);
    assert_eq!(field(&value, "errorId")?, &Value::Null);
    assert!(!body.contains(std::str::from_utf8(fixture::SOURCE)?));
    assert!(!body.contains(std::str::from_utf8(fixture::COUNTER)?));
    assert!(body.contains("no storage was reread"), "{body}");
    Ok(value)
}

fn run(
    args: &ExplainArgs,
    probe: &(dyn Fn() -> bool + Sync),
) -> TestResult<(String, ExitIdentity)> {
    execute_live_fss_with_control(
        FssCommand::Explain(args.clone()),
        &RequestControl::new(probe),
    )
    .ok_or_else(|| "started explanation lost its native outcome".into())
}

fn hypothetical(f: &Fixture) -> TestResult<String> {
    let calibration = ScoreCalibration::from_counts(
        "cal:explain-cancellation:v1",
        &[0, 300_000, 700_000],
        &[(5, 95), (50, 50), (95, 5)],
    )?;
    let bins = calibration
        .bins
        .iter()
        .map(|bin| {
            format!(
                "{{\"lo_ppm\":{},\"hi_ppm\":{},\"true_positives\":{},\"false_positives\":{}}}",
                bin.lo_ppm, bin.hi_ppm, bin.positives, bin.negatives,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"schema\":\"fss.event_counterfactual_request.v1\",\"event_revision_digest\":\"{}\",\"without_domains\":[\"sensor:custody\"],\"score_calibration\":{{\"schema\":\"fss.score_calibration.v1\",\"generation\":\"{}\",\"digest\":\"{}\",\"bins\":[{bins}]}},\"domain_scores_ppm\":{{\"sensor:custody\":900000}}}}",
        f.event.revision_digest().to_text(),
        calibration.generation,
        calibration.digest.to_text(),
    ))
}

fn publish_revision(f: &Fixture) -> TestResult<EventHypothesis> {
    let mut next = f.event.clone();
    next.revision += 1;
    next.supersedes = Some(f.event.revision_digest());
    next.interval = CaptureInterval::new(TimestampNs(2), TimestampNs(3))?;
    next.uncertainty_reason = Some("A changed retained declaration still needs review".to_owned());
    let cx = fixture::context(&f.directory)?;
    ReferenceDeployment::open(&f.root, fixture::SITE, &cx)?.publish_event(
        &ReferencePolicyDecision {
            event: next.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    cx.drain_and_finalize();
    Ok(next)
}

#[test]
fn every_event_explanation_cancels_after_dispatch_before_an_absent_root_read() -> TestResult {
    let f = Fixture::new("explain-control-admission")?;
    let mut args = arguments(&f)?;
    args.root = f.directory.join("never-created");
    let targets = [
        ExplainTarget::Event(f.event.event_id.clone()),
        ExplainTarget::EventWhyNot(f.event.event_id.clone()),
        ExplainTarget::EventCounterfactual {
            event_id: f.event.event_id.clone(),
            scenario: hypothetical(&f)?,
        },
        ExplainTarget::EventComparison {
            event_id: f.event.event_id.clone(),
            from_revision_digest: f.event.revision_digest(),
            to_revision_digest: ContentDigest::sha256(b"next event revision"),
        },
    ];
    let before = inventory(&f.root)?;
    for target in targets {
        args.target = target;
        let calls = AtomicUsize::new(0);
        let cancelled = || calls.fetch_add(1, Ordering::AcqRel) != 0;
        let (body, exit) = run(&args, &cancelled)?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
        assert!(body.contains(crate::ERR_CLI_READ_CANCELLED), "{body}");
        assert!(!body.contains(crate::ERR_DOCTOR_NOT_A_DEPLOYMENT), "{body}");
        assert!(!body.contains("\"ledgerAnchor\""), "{body}");
        assert!(!args.root.exists());
    }
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn why_and_why_not_keep_their_response_and_cancel_current_historical_and_custody_delivery()
-> TestResult {
    let f = Fixture::new("explain-control-modes")?;
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    let token = AnchorToken::parse(&snapshot_anchor_token(&snapshot)).ok_or("anchor")?;
    let before = inventory(&f.root)?;
    for why_not in [false, true] {
        for historical in [false, true] {
            for custody in [false, true] {
                let mut args = arguments(&f)?;
                if why_not {
                    args.target = ExplainTarget::EventWhyNot(f.event.event_id.clone());
                }
                args.at = historical.then(|| token.clone());
                args.custody = custody;
                let observations = AtomicUsize::new(0);
                let never = || {
                    observations.fetch_add(1, Ordering::AcqRel);
                    false
                };
                let original = run(&args, &never)?;
                assert_eq!(original.1, ExitIdentity::SUCCESS, "{}", original.0);
                assert_eq!(original, execute_explain(&args));
                let checkpoints = observations.load(Ordering::Acquire);
                assert!(checkpoints > 5);
                let attempts = AtomicUsize::new(0);
                let cancel_last = || attempts.fetch_add(1, Ordering::AcqRel) >= checkpoints - 1;
                let (body, exit) = run(&args, &cancel_last)?;
                assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
                let cancelled = cancelled_envelope(&body)?;
                assert_eq!(
                    field(&cancelled, "requestId")?,
                    field(&parse(&original.0)?, "requestId")?
                );
                assert_eq!(inventory(&f.root)?, before);
            }
        }
    }
    Ok(())
}

#[test]
fn cancellation_inside_current_and_historical_reads_never_becomes_missing_or_empty_evidence()
-> TestResult {
    let f = Fixture::with_extra("explain-control-mid-read", 4)?;
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    let token = AnchorToken::parse(&snapshot_anchor_token(&snapshot)).ok_or("anchor")?;
    let before = inventory(&f.root)?;
    for historical in [false, true] {
        let mut args = arguments(&f)?;
        args.at = historical.then(|| token.clone());
        args.custody = true;
        let calls = AtomicUsize::new(0);
        let never = || {
            calls.fetch_add(1, Ordering::AcqRel);
            false
        };
        assert_eq!(run(&args, &never)?.1, ExitIdentity::SUCCESS);
        let checkpoints = calls.load(Ordering::Acquire);
        for cut in [2, 4, checkpoints / 2, checkpoints - 2] {
            let observed = AtomicUsize::new(0);
            let cancel = || observed.fetch_add(1, Ordering::AcqRel) >= cut;
            let (body, exit) = run(&args, &cancel)?;
            assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "cut={cut}: {body}");
            assert!(
                body.contains(crate::ERR_CLI_READ_CANCELLED)
                    || body.contains("\"outcome\":\"cancelled\""),
                "cut={cut}: {body}"
            );
            assert!(!body.contains(ERR_AGENT_EVENT_NOT_FOUND), "{body}");
            assert!(!body.contains(crate::ERR_DOCTOR_NOT_A_DEPLOYMENT), "{body}");
            assert!(!body.contains("claim:event-custody:"), "{body}");
        }
    }
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn cancellation_during_explanation_refusal_rendering_withholds_the_refusal() -> TestResult {
    let f = Fixture::new("explain-control-refusal")?;
    let mut missing = arguments(&f)?;
    missing.target = ExplainTarget::Event(EventId::parse("event:not-retained")?);
    let mut budget = arguments(&f)?;
    budget.budget_tokens = Some(1);
    let mut calibration = arguments(&f)?;
    calibration.score_calibration = Some(f.directory.join("not-a-calibration.json"));
    let before = inventory(&f.root)?;
    for args in [missing, budget, calibration] {
        let observations = AtomicUsize::new(0);
        let never = || {
            observations.fetch_add(1, Ordering::AcqRel);
            false
        };
        let (original, exit) = run(&args, &never)?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{original}");
        assert_eq!(
            field(&parse(&original)?, "outcome")?.text(),
            Some("refused")
        );
        let checkpoints = observations.load(Ordering::Acquire);
        let calls = AtomicUsize::new(0);
        let cancel_last = || calls.fetch_add(1, Ordering::AcqRel) >= checkpoints - 1;
        let (body, exit) = run(&args, &cancel_last)?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
        let cancelled = cancelled_envelope(&body)?;
        assert_eq!(
            field(&cancelled, "requestId")?,
            field(&parse(&original)?, "requestId")?
        );
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn late_explanation_cancellation_renders_the_verified_anchor_after_the_store_disappears()
-> TestResult {
    let f = Fixture::new("explain-control-no-reread")?;
    let args = arguments(&f)?;
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    let observations = AtomicUsize::new(0);
    let never = || {
        observations.fetch_add(1, Ordering::AcqRel);
        false
    };
    assert_eq!(run(&args, &never)?.1, ExitIdentity::SUCCESS);
    let checkpoints = observations.load(Ordering::Acquire);
    let calls = AtomicUsize::new(0);
    let moved = AtomicBool::new(false);
    let elsewhere = f.directory.join("moved-deployment");
    let cancel_last = || {
        if calls.fetch_add(1, Ordering::AcqRel) < checkpoints - 1 {
            return false;
        }
        if !moved.load(Ordering::Acquire) {
            moved.store(fs::rename(&f.root, &elsewhere).is_ok(), Ordering::Release);
        }
        true
    };
    let (body, exit) = run(&args, &cancel_last)?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(moved.load(Ordering::Acquire));
    cancelled_envelope(&body)?;
    assert!(
        body.contains(&snapshot.anchor.state_root.to_text()),
        "{body}"
    );
    assert!(!f.root.exists());
    fs::rename(elsewhere, &f.root)?;
    Ok(())
}

#[test]
fn comparison_and_counterfactual_reads_cancel_native_work_and_final_delivery() -> TestResult {
    let f = Fixture::new("explain-control-derived")?;
    let mut counterfactual = arguments(&f)?;
    counterfactual.target = ExplainTarget::EventCounterfactual {
        event_id: f.event.event_id.clone(),
        scenario: hypothetical(&f)?,
    };
    check_derived_cancellation(&f, &counterfactual)?;
    let next = publish_revision(&f)?;
    let mut comparison = arguments(&f)?;
    comparison.target = ExplainTarget::EventComparison {
        event_id: f.event.event_id.clone(),
        from_revision_digest: f.event.revision_digest(),
        to_revision_digest: next.revision_digest(),
    };
    check_derived_cancellation(&f, &comparison)?;
    Ok(())
}

fn check_derived_cancellation(f: &Fixture, args: &ExplainArgs) -> TestResult {
    let before = inventory(&f.root)?;
    let observations = AtomicUsize::new(0);
    let never = || {
        observations.fetch_add(1, Ordering::AcqRel);
        false
    };
    let original = run(args, &never)?;
    assert_eq!(original.1, ExitIdentity::SUCCESS, "{}", original.0);
    assert_eq!(original, execute_explain(args));
    let checkpoints = observations.load(Ordering::Acquire);
    assert!(checkpoints > 5);
    for cut in [2, checkpoints / 2, checkpoints - 1] {
        let calls = AtomicUsize::new(0);
        let cancel = || calls.fetch_add(1, Ordering::AcqRel) >= cut;
        let (body, exit) = run(args, &cancel)?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
        if cut == checkpoints - 1 {
            let cancelled = cancelled_envelope(&body)?;
            assert_eq!(
                field(&cancelled, "requestId")?,
                field(&parse(&original.0)?, "requestId")?
            );
        } else {
            assert!(
                body.contains(crate::ERR_CLI_READ_CANCELLED)
                    || body.contains("\"outcome\":\"cancelled\""),
                "{body}"
            );
        }
        assert!(
            !body.contains("Hypothetical source-loss artifact"),
            "{body}"
        );
        assert!(!body.contains("Recorded adjacent event metadata"), "{body}");
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}
