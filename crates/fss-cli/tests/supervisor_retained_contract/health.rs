#![forbid(unsafe_code)]
//! Native event advice must inherit the same finite visual-health constraints as detector advice.

use super::*;

use fss_reference::ingest::historical_health::HistoricalHealthRetention;
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};

pub(super) fn retain_health(
    fixture: &mut Fixture,
    camera: usize,
    frames: usize,
    tolerate_decode_refusals: bool,
) -> TestResult<HistoricalHealthRetention> {
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let effects = deployment.effects().last_root();
    let screened = LongWatchReport::analyze_screened(
        &deployment,
        &WatchPlan {
            import_identity: fixture.cameras[camera].import,
            interpretation: ComponentInterpretation::YCbCr,
            first_segment: 0,
            segment_count: frames,
            zones: vec![WatchZone {
                zone_id: "event-source-view".into(),
                x: 0,
                y: 0,
                width: 64,
                height: 48,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        },
        WatchOptions {
            tolerate_decode_refusals,
        },
        &LongDwellLimits::default(),
        &cx,
    )?;
    let diagnostic = screened
        .health_diagnostic()
        .ok_or("native visual-health diagnostic")?;
    let retained = diagnostic.retain(&mut deployment, diagnostic.approval_digest(), &cx)?;
    fixture.authority = deployment.current_anchor().state_root;
    assert_eq!(deployment.effects().last_root(), effects);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(retained)
}

fn observation(document: &Value) -> TestResult<&Value> {
    let observations = field(document, "observations")?
        .array()
        .ok_or("native observations")?;
    assert_eq!(observations.len(), 1);
    Ok(&observations[0])
}

#[test]
fn event_source_health_withholds_frozen_support_without_losing_rows_or_deduplication() -> TestResult
{
    let mut fixture = Fixture::with_source_frames("event-health", 2, 12, false)?;
    let initial_output = fixture.run(&fixture.plan(&[0], true)?)?;
    success(&initial_output);
    let initial = report(&initial_output)?;
    let initial_observation = observation(&initial)?;
    let initial_health = field(initial_observation, "historical_health")?;
    assert_eq!(text(initial_health, "state")?, "no_matching_diagnostic");
    assert_eq!(
        field(initial_health, "support_withheld")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(initial_health, "current_camera_health_established")?.boolean(),
        Some(false)
    );
    let (historical_request, historical_sources) =
        historical_sources(&fixture, &fixture.discovery(&[0])?)?;
    let original_pin = historical_sources
        .iter()
        .find(|source| source.event_id == fixture.cameras[0].event)
        .ok_or("original selected event")?;
    assert!(original_pin.source_verified && original_pin.health_digest.is_some());
    revalidate_sources(&fixture, &historical_request, &historical_sources)?;

    // Older pending reports remain inspectable but cannot release selected rows whose health
    // interpretation was never pinned, even when no diagnostic happens to exist yet.
    let mut legacy = historical_sources.clone();
    for source in &mut legacy {
        source.health_digest = None;
    }
    assert!(revalidate_sources(&fixture, &historical_request, &legacy).is_err());

    // Another camera's diagnostic does not change this historical source interpretation.
    retain_health(&mut fixture, 1, 12, false)?;
    revalidate_sources(&fixture, &historical_request, &historical_sources)?;
    let retained = retain_health(&mut fixture, 0, 12, false)?;
    let canonical = inventory(&fixture.root)?;
    let error = revalidate_sources(&fixture, &historical_request, &historical_sources)
        .expect_err("new matching diagnostic must invalidate prior event advice");
    assert!(
        error.to_string().contains("health context changed"),
        "{error}"
    );

    let fresh_output = fixture.run(&fixture.plan(&[0], true)?)?;
    success(&fresh_output);
    let fresh = report(&fresh_output)?;
    let current_observation = observation(&fresh)?;
    for key in [
        "identity",
        "capsule_digest",
        "score_f32_bits",
        "inference_identity",
    ] {
        assert_eq!(
            field(current_observation, key)?,
            field(initial_observation, key)?
        );
    }
    let health = field(current_observation, "historical_health")?;
    assert_eq!(text(health, "state")?, "findings");
    assert_eq!(field(health, "support_withheld")?.boolean(), Some(true));
    assert_eq!(
        field(health, "screening_incomplete")?.boolean(),
        Some(false)
    );
    let diagnostics = field(health, "diagnostics")?
        .array()
        .ok_or("diagnostic pins")?;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        text(&diagnostics[0], "record_digest")?,
        retained.record_digest.to_text()
    );
    assert_eq!(
        text(&diagnostics[0], "provenance_root")?,
        retained.provenance_root.to_text()
    );
    assert!(
        field(health, "findings")?
            .array()
            .ok_or("findings")?
            .iter()
            .any(|finding| {
                text(finding, "finding").is_ok_and(|value| value == "exact_frame_repetition")
                    && field(finding, "withheld_first_segment")
                        .is_ok_and(|value| value.integer() == Some(0))
            })
    );
    for (index, window) in field(&fresh, "windows")?
        .array()
        .ok_or("windows")?
        .iter()
        .enumerate()
    {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(1));
        assert_eq!(
            field(window, "new_observations")?.integer(),
            Some(if index == 0 { 1 } else { 0 })
        );
        let outcome = field(window, "outcome")?;
        assert_eq!(field(outcome, "supporting_clusters")?.integer(), Some(0));
        assert_eq!(
            field(outcome, "posterior_log_odds_millibans")?,
            &Value::Array(vec![numeric(0), numeric(0)])
        );
        assert_eq!(field(outcome, "effect_authority")?.boolean(), Some(false));
    }
    let discovered_output = fixture.run_discovered(&fixture.discovery(&[0])?)?;
    success(&discovered_output);
    let discovered = report(&discovered_output)?;
    assert_eq!(
        field(field(&discovered, "supervision")?, "observations")?,
        field(&fresh, "observations")?
    );
    let (fresh_request, fresh_sources) =
        super::historical_sources(&fixture, &fixture.discovery(&[0])?)?;
    let fresh_pin = fresh_sources
        .iter()
        .find(|source| source.event_id == fixture.cameras[0].event)
        .ok_or("fresh selected event")?;
    assert_eq!(fresh_pin.event_root, original_pin.event_root);
    assert_ne!(fresh_pin.health_digest, original_pin.health_digest);
    revalidate_sources(&fixture, &fresh_request, &fresh_sources)?;
    assert_eq!(
        field(&fresh, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    assert_eq!(inventory(&fixture.root)?, canonical);
    Ok(())
}

#[test]
fn event_supervision_distinguishes_clear_finite_screen_from_incomplete_screen() -> TestResult {
    for (name, frames, refused, state, withheld) in [
        (
            "event-clear-health",
            1,
            false,
            "screened_without_findings",
            false,
        ),
        (
            "event-incomplete-health",
            2,
            true,
            "screening_incomplete",
            true,
        ),
    ] {
        // A temporal health screen requires explicit capture hints. Keep a two-frame timed
        // source even for the clear one-frame screen: only its selected first frame is assessed,
        // and the unscreened remainder must not acquire an absence or camera-health claim.
        let mut fixture = Fixture::with_source_frames(name, 1, frames.max(2), refused)?;
        retain_health(&mut fixture, 0, frames, refused)?;
        let output = fixture.run(&fixture.plan(&[0], true)?)?;
        success(&output);
        let document = report(&output)?;
        let health = field(observation(&document)?, "historical_health")?;
        assert_eq!(text(health, "state")?, state);
        assert_eq!(field(health, "support_withheld")?.boolean(), Some(withheld));
        assert_eq!(
            field(health, "screening_incomplete")?.boolean(),
            Some(refused)
        );
        assert_eq!(
            field(health, "current_camera_health_established")?.boolean(),
            Some(false)
        );
        assert!(
            field(health, "findings")?
                .array()
                .ok_or("findings")?
                .is_empty()
        );
        for window in field(&document, "windows")?.array().ok_or("windows")? {
            assert_eq!(
                field(field(window, "outcome")?, "supporting_clusters")?.integer(),
                Some(if withheld { 0 } else { 1 })
            );
        }
        let (request, sources) = historical_sources(&fixture, &fixture.discovery(&[0])?)?;
        assert!(sources[0].health_digest.is_some());
        revalidate_sources(&fixture, &request, &sources)?;
    }
    Ok(())
}
