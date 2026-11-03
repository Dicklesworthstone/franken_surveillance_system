#![forbid(unsafe_code)]
//! Shared-owner replay under caller work, independent of runtime and source custody.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const QUERY: &[u8] = include_bytes!("../../../../fixtures/clock-alignment/validated_sessions.json");
const WORK: u64 = 100_000_000;
type Test = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn replay_uses_the_exact_original_parser_and_one_nonrefillable_parent_budget() -> Test {
    let mut work = WorkBudget::new(WORK);
    work.charge(123)?;
    let query = ClockValidationQuery::parse_pinned(QUERY, ContentDigest::sha256(QUERY), &mut work)?;
    let after_parse = work.used();
    assert_eq!(after_parse, 123 + 4096 + QUERY.len() as u64 * 4);
    assert_eq!(query.cameras().len(), 2);
    assert_eq!(query.projections().len(), 2);
    let replay = query.evaluate(&mut work)?;
    assert_eq!(work.used(), after_parse + replay.report().work_units);
    assert_eq!(replay.report().support.len(), 3);
    assert_eq!(
        replay
            .report()
            .support
            .iter()
            .filter(|s| s.supported_in_every_session())
            .count(),
        1
    );
    for projection in &replay.report().projections {
        assert_eq!(projection.mappings.len(), 3);
    }
    let before_render = work.used();
    let text = replay.render(&mut work)?;
    let output = parse(&text)?;
    let output = output.object().ok_or("response")?;
    assert_eq!(
        output["schema"].text(),
        Some("fss.clock_validation_replay_response.v1")
    );
    let report = output["report"].object().ok_or("report")?;
    assert_eq!(
        report["schema"].text(),
        Some("fss.clock_validation_replay_report.v1")
    );
    assert_eq!(
        report["work_limit"].integer(),
        Some(i128::from(WORK - after_parse))
    );
    assert_eq!(
        report["work_remaining"].integer(),
        Some(i128::from(WORK - before_render))
    );
    assert_eq!(work.used(), before_render);
    assert_eq!(report["clock_activated"].boolean(), Some(false));
    assert_eq!(report["source_custody_verified"].boolean(), Some(false));
    Ok(())
}

#[test]
fn reported_success_wrong_pins_and_short_work_cannot_replace_original_native_replay() -> Test {
    let correct = ContentDigest::sha256(QUERY);
    let mut work = WorkBudget::new(WORK);
    assert_eq!(
        ClockValidationQuery::parse_pinned(QUERY, ContentDigest::sha256(b"wrong"), &mut work)
            .err()
            .ok_or("pin refusal")?
            .code,
        "ERR-CLOCK-ALIGNMENT-INPUT-001"
    );
    let report = analyze_with_probe(QUERY, correct, WORK, &|| false)?.0;
    assert!(
        ClockValidationQuery::parse_pinned(
            report.as_bytes(),
            ContentDigest::sha256(report.as_bytes()),
            &mut work
        )
        .is_err()
    );
    let mut complete = WorkBudget::new(WORK);
    ClockValidationQuery::parse_pinned(QUERY, correct, &mut complete)?.evaluate(&mut complete)?;
    let mut short = WorkBudget::new(complete.used() - 1);
    let query = ClockValidationQuery::parse_pinned(QUERY, correct, &mut short)?;
    assert_eq!(
        query
            .evaluate(&mut short)
            .err()
            .ok_or("shared budget refusal")?
            .code,
        "ERR-CLOCK-ALIGNMENT-LIMIT-001"
    );
    assert!(ClockValidationQuery::parse_pinned(QUERY, correct, &mut WorkBudget::new(1)).is_err());
    Ok(())
}

#[test]
fn cancellation_remains_live_between_parse_replay_and_complete_diagnostics() -> Test {
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let mut work = WorkBudget::with_cancellation_probe(WORK, &probe);
    let query = ClockValidationQuery::parse_pinned(QUERY, ContentDigest::sha256(QUERY), &mut work)?;
    cancelled.store(true, Ordering::SeqCst);
    assert_eq!(
        query
            .evaluate(&mut work)
            .err()
            .ok_or("cancelled replay")?
            .code,
        "ERR-CLOCK-ALIGNMENT-CANCELLED-001"
    );
    cancelled.store(false, Ordering::SeqCst);
    let replay =
        ClockValidationQuery::parse_pinned(QUERY, ContentDigest::sha256(QUERY), &mut work)?
            .evaluate(&mut work)?;
    cancelled.store(true, Ordering::SeqCst);
    assert_eq!(
        replay
            .render(&mut work)
            .err()
            .ok_or("cancelled report")?
            .code,
        "ERR-CLOCK-ALIGNMENT-CANCELLED-001"
    );
    Ok(())
}
