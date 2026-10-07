#![forbid(unsafe_code)]
//! Synthetic regressions for recorded health admission, not physical health qualification.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, TimestampNs};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn context() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-health".to_owned(),
        operation_id: OperationId::parse("operation:recorded-health")?,
        principal: "principal:recorded-health".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-health"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority, std::env::temp_dir().join("fss-recorded-health-context"),
    )?)
}

fn new_screen(frames: usize) -> Result<RecordedHealthScreen, HealthError> {
    RecordedHealthScreen::new(
        frames,
        ContentDigest::sha256(b"recorded-health-import"),
        ContentDigest::sha256(b"recorded-health-root"),
        "sensor:recorded-health",
        ContentDigest::sha256(b"recorded-health-source"),
        BTreeSet::new(),
    )
}

fn frame<'a>(segment: u64, pixels: &'a [u8], gap_before: bool) -> TestResult<HealthFrame<'a>> {
    Ok(HealthFrame {
        source_generation: ContentDigest::sha256(b"recorded-health-source"),
        segment,
        capsule_digest: ContentDigest::sha256(&segment.to_le_bytes()),
        capture: CaptureInterval::new(
            TimestampNs(i128::from(segment) * 100),
            TimestampNs(i128::from(segment) * 100 + 1),
        )?,
        dimensions: [4, 4],
        gap_before,
        pixels,
    })
}

fn constant(value: u8, frames: usize) -> TestResult<RecordedHealthSummary> {
    let cx = context()?;
    let mut screen = new_screen(frames)?;
    let pixels = [value; 16];
    for segment in 0..frames {
        let _ = screen.observe(frame(segment as u64, &pixels, false)?, &cx)?;
    }
    Ok(screen.finish(&[])?)
}

#[test]
fn recorded_health_withdraws_complete_clipping_and_repetition_prefixes() -> TestResult {
    for value in [0, 255] {
        assert!(constant(value, 2)?.affected_segments().is_empty());
        let summary = constant(value, 3)?;
        assert_eq!(summary.affected_segments(), &BTreeSet::from([0, 1, 2]));
        assert!(summary.observations()[0].findings.is_empty());
        assert!(summary.observations()[1].findings.is_empty());
        assert!(!summary.observations()[2].findings.is_empty());
    }
    assert!(constant(80, 7)?.affected_segments().is_empty());
    let summary = constant(80, 8)?;
    assert_eq!(summary.affected_segments(), &(0..8).collect::<BTreeSet<_>>());
    assert_eq!(summary.samples_used(), 128);
    assert!(summary.to_json().contains("\"health_certified\":false"));
    assert!(summary.to_json().contains("\"status\":\"suspected_degradation\""));
    Ok(())
}

#[test]
fn recorded_health_contrast_prefix_excludes_its_textured_baseline() -> TestResult {
    let cx = context()?;
    let mut screen = new_screen(4)?;
    let mut textured = [20; 16];
    textured[8..].fill(180);
    let _ = screen.observe(frame(0, &textured, false)?, &cx)?;
    for segment in 1..4 {
        let _ = screen.observe(frame(segment, &[100; 16], false)?, &cx)?;
    }
    let summary = screen.finish(&[])?;
    assert_eq!(summary.affected_segments(), &BTreeSet::from([1, 2, 3]));
    assert_eq!(
        summary.observations()[3].findings,
        vec![HealthFinding::ContrastCollapse],
    );
    Ok(())
}

#[test]
fn recorded_health_gaps_reset_streaks_without_replenishing_work() -> TestResult {
    let cx = context()?;
    let mut screen = new_screen(8)?;
    for segment in 0..7 {
        let _ = screen.observe(frame(segment, &[80; 16], false)?, &cx)?;
    }
    let _ = screen.observe(frame(8, &[80; 16], true)?, &cx)?;
    let summary = screen.finish(&[8])?;
    assert!(summary.affected_segments().is_empty());
    let last = &summary.observations()[7];
    assert!(last.baseline_reset);
    assert_eq!(last.predecessor_digest, None);
    assert_eq!(last.repeated_frames, 1);
    assert_eq!(summary.samples_used(), 128);
    assert!(summary.to_json().contains("\"status\":\"clear_screen_not_health_evidence\""));
    Ok(())
}

#[test]
fn recorded_health_receipts_reject_changed_findings_runs_work_and_predecessors() -> TestResult {
    let summary = constant(80, 8)?;
    let bytes = summary.to_bytes();
    assert_eq!(RecordedHealthSummary::from_bytes(&bytes)?, summary);
    let mut altered = summary.clone();
    altered.affected_segments.clear();
    assert!(RecordedHealthSummary::from_bytes(&altered.to_bytes()).is_err());
    altered = summary.clone();
    altered.observations[7].findings.clear();
    assert!(RecordedHealthSummary::from_bytes(&altered.to_bytes()).is_err());
    altered = summary.clone();
    altered.observations[7].predecessor_digest = None;
    assert!(RecordedHealthSummary::from_bytes(&altered.to_bytes()).is_err());
    altered = summary.clone();
    altered.samples_used += 1;
    assert!(RecordedHealthSummary::from_bytes(&altered.to_bytes()).is_err());
    for truncated in [&bytes[..0], &bytes[..bytes.len() / 2], &bytes[..bytes.len() - 1]] {
        assert!(RecordedHealthSummary::from_bytes(truncated).is_err());
    }
    assert!(RecordedHealthSummary::from_bytes(&vec![0; MAX_RECORDED_HEALTH_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn recorded_health_bounds_and_cancellation_are_typed_without_partial_receipts() -> TestResult {
    assert!(matches!(new_screen(0), Err(HealthError::Limit)));
    assert!(matches!(new_screen(MAX_HEALTH_FRAMES + 1), Err(HealthError::Limit)));
    let cx = context()?;
    let mut screen = new_screen(2)?;
    let _ = screen.observe(frame(0, &[80; 16], false)?, &cx)?;
    assert_eq!(
        screen.observe(frame(0, &[80; 16], false)?, &cx),
        Err(HealthError::ReplayedSource),
    );
    let _ = screen.observe(frame(1, &[80; 16], false)?, &cx)?;
    assert_eq!(
        screen.observe(frame(2, &[80; 16], true)?, &cx),
        Err(HealthError::Limit),
    );
    assert_eq!(screen.screen.samples_used(), 32);
    assert_eq!(screen.finish(&[])?.observations().len(), 2);

    let cancelled = context()?;
    cancelled.set_cancel_at_checkpoint_occurrence("sensor_health:row", 4);
    let mut screen = new_screen(1)?;
    assert_eq!(
        screen.observe(frame(0, &[80; 16], false)?, &cancelled),
        Err(HealthError::Cancelled),
    );
    assert_eq!(screen.screen.samples_used(), 8);
    assert!(screen.observations.is_empty());
    Ok(())
}

#[test]
fn recorded_health_policy_is_opt_in_and_generation_bound() -> TestResult {
    let plan = ContentDigest::sha256(b"plan");
    assert_eq!(screened_plan_digest(plan, None), plan);
    assert_ne!(
        screened_plan_digest(plan, Some(RecordedHealthPolicy::ConservativeV1)), plan,
    );
    let summary = constant(80, 1)?;
    assert_eq!(summary.policy_digest(), policy_digest());
    assert!(summary.to_json().contains("\"health_certified\":false"));
    Ok(())
}

#[test]
fn recorded_health_display_order_preserves_source_positions_and_runs() -> TestResult {
    let cx = context()?;
    let mut screen = new_screen(8)?;
    let order = [0, 2, 1, 4, 3, 6, 5, 7];
    for segment in order {
        let _ = screen.observe(frame(segment, &[80; 16], false)?, &cx)?;
    }
    let mut summary = screen.finish(&[])?;
    assert_eq!(
        summary.observations().iter().map(|frame| frame.segment).collect::<Vec<_>>(),
        order,
    );
    assert_eq!(summary.affected_segments(), &(0..8).collect::<BTreeSet<_>>());
    assert!(summary.observations().iter().skip(1).all(|frame| !frame.baseline_reset));
    // Segment 2 precedes segment 1 in actual display order; span membership follows that order.
    summary.withdraw_track_span(2, 1)?;
    assert_eq!(summary.withdrawn_track_segments(), &BTreeSet::from([1, 2]));
    summary.validate()?;
    assert_eq!(RecordedHealthSummary::from_bytes(&summary.to_bytes())?, summary);
    Ok(())
}

#[test]
fn recorded_health_undeclared_resets_cannot_erase_a_qualifying_repetition() -> TestResult {
    let mut summary = constant(80, 8)?;
    let last = &mut summary.observations[7];
    last.baseline_reset = true;
    last.predecessor_digest = None;
    last.repeated_frames = 1;
    last.findings.clear();
    summary.affected_segments.clear();
    assert!(RecordedHealthSummary::from_bytes(&summary.to_bytes()).is_err());
    Ok(())
}

#[test]
fn recorded_health_reordered_coverage_is_uncertain_without_absence_witnesses() -> TestResult {
    use crate::ingest::recorded_coverage::{
        CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
        CoverageZoneInput, UncoveredReason, build_coverage_with,
    };
    let cx = context()?;
    let mut screen = new_screen(14)?;
    let order = [0, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 13];
    for (index, segment) in order.into_iter().enumerate() {
        let pixels = [80 + (index % 2) as u8; 16];
        let _ = screen.observe(frame(segment, &pixels, false)?, &cx)?;
    }
    let summary = screen.finish(&[])?;
    assert!(summary.affected_segments().is_empty());
    let frames = summary.observations().iter().map(|frame| CoverageFrame {
        segment: frame.segment as usize,
        capture: frame.capture,
    }).collect::<Vec<_>>();
    let record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Watch,
            import_identity: summary.import_identity(),
            import_root: summary.import_root(),
            sensor_id: "sensor:recorded-health",
            analysis_digest: ContentDigest::sha256(b"health reordered analysis"),
            basis: fss_core::LedgerAnchor::genesis("site:recorded-health"),
            capture_time_label: "operator_assumption",
            segment_gaps: &[false; 14],
            first_segment: 0,
            last_segment: 13,
            frames: &frames,
            confirmation_hits: 3,
            zones: vec![CoverageZoneInput {
                zone_id: "door".to_owned(),
                geometry: "0,0,4,4".to_owned(),
                inside_frame: true,
                pipeline_generation: ContentDigest::sha256(b"health reordered pipeline"),
                entries: Vec::new(),
            }],
        },
        &CoverageExtras {
            sensor_health: Some(summary),
            ..CoverageExtras::default()
        },
    )?;
    assert!(record.witnesses().next().is_none());
    assert_eq!(record.zones[0].uncovered.len(), 1);
    assert_eq!(record.zones[0].uncovered[0].reason, UncoveredReason::CaptureOrderUncertain);
    assert_eq!(record.zones[0].uncovered[0].first_segment, 0);
    assert_eq!(record.zones[0].uncovered[0].last_segment, 13);
    assert_eq!(CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?, record);
    Ok(())
}

#[test]
fn recorded_health_rejects_missing_restarts_and_widened_recovery_witnesses() -> TestResult {
    use crate::ingest::recorded_coverage::{
        CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
        CoverageZoneInput, build_coverage_with, witness_domain, zone_witness_predicate,
    };
    let cx = context()?;
    let mut screen = new_screen(32)?;
    for segment in 0..32 {
        let pixels = [if (12..17).contains(&segment) {
            0
        } else {
            80 + (segment % 2) as u8
        }; 16];
        let _ = screen.observe(frame(segment, &pixels, false)?, &cx)?;
    }
    let summary = screen.finish(&[])?;
    assert_eq!(summary.tracking_restart_segments(), BTreeSet::from([17]));
    let frames = summary
        .observations()
        .iter()
        .map(|frame| CoverageFrame {
            segment: frame.segment as usize,
            capture: frame.capture,
        })
        .collect::<Vec<_>>();
    let input = CoverageInput {
        source: CoverageSource::Watch,
        import_identity: summary.import_identity(),
        import_root: summary.import_root(),
        sensor_id: "sensor:recorded-health",
        analysis_digest: ContentDigest::sha256(b"health recovery analysis"),
        basis: fss_core::LedgerAnchor::genesis("site:recorded-health"),
        capture_time_label: "operator_assumption",
        segment_gaps: &[false; 32],
        first_segment: 0,
        last_segment: 31,
        frames: &frames,
        confirmation_hits: 3,
        zones: vec![CoverageZoneInput {
            zone_id: "door".to_owned(),
            geometry: "0,0,4,4".to_owned(),
            inside_frame: true,
            pipeline_generation: ContentDigest::sha256(b"health recovery pipeline"),
            entries: Vec::new(),
        }],
    };
    let mut extras = CoverageExtras {
        sensor_health: Some(summary),
        ..CoverageExtras::default()
    };
    assert!(build_coverage_with(&input, &extras).is_err());
    extras.restarts = vec![17];
    let record = build_coverage_with(&input, &extras)?;
    assert_eq!(
        record.zones[0]
            .witnesses
            .iter()
            .map(|witness| (witness.first_segment, witness.last_segment))
            .collect::<Vec<_>>(),
        [(4, 9), (21, 29)],
    );
    assert_eq!(
        CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
        record,
    );

    // All forged witness fields are internally consistent, including domains and predicates.
    // Only the retained screen's required latency and recovery warm-up reject these claims.
    for (index, first, last) in [(0, 4, 11), (1, 17, 29)] {
        let mut forged = record.clone();
        let clause = forged
            .sensor_health
            .as_ref()
            .ok_or("missing health receipt")?
            .predicate_clause();
        let zone = &mut forged.zones[0];
        let witness = &mut zone.witnesses[index];
        witness.first_segment = first;
        witness.last_segment = last;
        witness.frames = last - first + 1;
        witness.outer = CaptureInterval::new(
            frames[first as usize].capture.earliest,
            frames[last as usize].capture.latest,
        )?;
        witness.covered = CaptureInterval::new(
            frames[first as usize].capture.latest,
            frames[last as usize].capture.earliest,
        )?;
        let domain = witness_domain(
            forged.source,
            &forged.sensor_id,
            &zone.scope,
            witness.covered,
        );
        witness.witness.authorized_domain = [domain.clone()].into();
        witness.witness.observed_domain = [domain].into();
        witness.witness.negative_predicate = format!(
            "{}{}",
            zone_witness_predicate(
                forged.source,
                &forged.sensor_id,
                &zone.scope,
                zone.pipeline_generation,
                witness.covered,
                zone.visibility.as_ref(),
            ),
            clause,
        );
        assert!(forged.validate().is_err());
        assert!(CoverageRecord::from_bytes(&forged.to_bytes(), forged.digest()).is_err());
    }
    Ok(())
}
