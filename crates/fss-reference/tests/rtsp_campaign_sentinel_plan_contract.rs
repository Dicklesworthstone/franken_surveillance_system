#![forbid(unsafe_code)]
//! Pure campaign allocation/admission contracts; no model or source I/O can hide a budget refill.

#[path = "rtsp_campaign_watch_contract/fixture.rs"]
mod fixture;

use fixture::{Fixture, Test, digest};
use fss_reference::KernelBackend;
use fss_reference::ingest::rtsp_campaign_sentinel::*;

fn plan(label: &str) -> Test<RtspCampaignSentinelPlan> {
    let fixture = Fixture::new(label, 8)?;
    // Every source owner and temporary store is dropped before returning. The following public
    // allocation/reservation/digest calls must remain pure even with all paths unavailable.
    Ok(RtspCampaignSentinelPlan {
        history: fixture.plan.history,
        history_root: fixture.plan.history_root.clone(),
        bindings: fixture.plan.bindings.clone(),
        interpretation: fixture.plan.interpretation,
        package_digest: digest("independently pinned package for pure campaign admission"),
        backend: KernelBackend::OptimizedCpuV1,
        minimum_score_ppm: None,
        sampling: RtspCampaignSentinelConfig {
            every_frames: 5,
            burst_frames: 3,
            max_inferences: 11,
        },
        retain: false,
    })
}

#[test]
fn round_robin_uses_catalog_counts_and_leaves_partial_allowance_unused() -> Test {
    let plan = plan("sentinel-plan-round-robin")?;
    // Six catalogued frames, not the first native observation's eight durable pictures:
    // only one complete burst fits. Sixteen frames supply three complete scheduled bursts.
    let rows = plan.allocate(&[6, 16, 0, 0])?;
    assert_eq!(
        rows.iter()
            .map(|r| r.admitted_inferences)
            .collect::<Vec<_>>(),
        vec![3, 6, 0, 0]
    );
    assert_eq!(rows[0].eligible_bursts, 1);
    assert_eq!(rows[1].eligible_bursts, 3);
    assert_eq!(rows[1].budget_skipped_bursts, 1);
    assert_eq!(rows[2].eligible_bursts, 0);
    assert_eq!(rows.iter().map(|r| r.admitted_inferences).sum::<usize>(), 9);
    Ok(())
}

#[test]
fn one_global_burst_does_not_refill_later_attempts_or_shrink_short_bursts() -> Test {
    let mut plan = plan("sentinel-plan-one-burst")?;
    plan.sampling.max_inferences = 5;
    let rows = plan.allocate(&[20, 20, 0, 0])?;
    assert_eq!(
        rows.iter()
            .map(|r| r.admitted_inferences)
            .collect::<Vec<_>>(),
        vec![3, 0, 0, 0]
    );
    assert_eq!(rows[1].budget_skipped_bursts, 4);
    let short = plan.allocate(&[2, 2, 0, 0])?;
    assert!(
        short
            .iter()
            .all(|r| r.admitted_inferences == 0 && r.eligible_bursts == 0)
    );
    Ok(())
}

#[test]
fn native_sixty_four_frame_ceiling_never_splits_a_burst_or_hides_skips() -> Test {
    let mut plan = plan("sentinel-plan-native-cap")?;
    plan.sampling = RtspCampaignSentinelConfig {
        every_frames: 3,
        burst_frames: 3,
        max_inferences: MAX_CAMPAIGN_SENTINEL_INFERENCES,
    };
    let rows = plan.allocate(&[300, 300, 0, 0])?;
    for row in &rows[..2] {
        assert_eq!(row.admitted_inferences, 63);
        assert_eq!(row.admitted_bursts, 21);
        assert_eq!(row.budget_skipped_bursts, 79);
    }
    Ok(())
}

#[test]
fn complete_ordered_frame_inventory_and_native_bounds_are_required() -> Test {
    let plan = plan("sentinel-plan-inventory")?;
    assert!(plan.allocate(&[6, 4]).is_err());
    assert!(plan.allocate(&[6, 4, 1, 0]).is_err());
    assert!(plan.allocate(&[65_537, 4, 0, 0]).is_err());
    let mut invalid = plan.clone();
    invalid.sampling.burst_frames = 6;
    assert!(invalid.allocate(&[6, 4, 0, 0]).is_err());
    Ok(())
}

#[test]
fn one_resource_reservation_spans_the_campaign_and_caps_resident_model_outputs() -> Test {
    let mut plan = plan("sentinel-plan-budget")?;
    let mut limits = RtspCampaignSentinelLimits::default();
    let reservation = plan.reservation(&limits)?;
    assert_eq!(reservation.selected_archives, 2);
    assert_eq!(
        reservation.inference.inferences,
        plan.sampling.max_inferences
    );
    assert_eq!(
        reservation.inference.source_chunk_bytes,
        limits.sentinel.maximum_source_chunk_bytes
    );
    assert_eq!(
        reservation.inference.pixel_samples,
        limits.sentinel.maximum_pixel_samples
    );
    assert_eq!(
        reservation.inference.detection_work_units,
        limits.sentinel.package.detection_work_units
    );
    assert_eq!(
        reservation.inference.jpeg_work_units,
        limits.sentinel.package.jpeg_work_units
    );
    assert_eq!(
        reservation.original_verification_bytes,
        3 * reservation.import_original_bytes
    );
    plan.sampling.max_inferences = MAX_CAMPAIGN_SENTINEL_INFERENCES;
    assert!(matches!(
        plan.reservation(&limits),
        Err(RtspCampaignSentinelError::Limit)
    ));
    limits.sentinel.package.run.maximum_output_bytes = 1024 * 1024;
    let admitted = plan.reservation(&limits)?;
    assert_eq!(
        admitted.inference.output_bytes,
        MAX_CAMPAIGN_SENTINEL_OUTPUT_BYTES
    );
    limits.sentinel.package.run.execution.max_macs = u64::MAX;
    assert!(matches!(
        plan.reservation(&limits),
        Err(RtspCampaignSentinelError::Limit)
    ));
    Ok(())
}

#[test]
fn approval_binds_package_backend_sampling_retention_and_every_global_pool() -> Test {
    let plan = plan("sentinel-plan-digest")?;
    let limits = RtspCampaignSentinelLimits::default();
    let original = plan.digest(&limits)?;
    let mut changed = plan.clone();
    changed.retain = true;
    assert_ne!(changed.digest(&limits)?, original);
    changed = plan.clone();
    changed.package_digest = digest("another exact package");
    assert_ne!(changed.digest(&limits)?, original);
    changed = plan.clone();
    changed.backend = KernelBackend::ScalarReference;
    assert_ne!(changed.digest(&limits)?, original);
    changed = plan.clone();
    changed.minimum_score_ppm = Some(0);
    assert_ne!(changed.digest(&limits)?, original);
    changed = plan.clone();
    changed.sampling.max_inferences -= 1;
    assert_ne!(changed.digest(&limits)?, original);
    let mut narrowed = limits;
    narrowed.sentinel.maximum_source_chunk_bytes -= 1;
    assert_ne!(plan.digest(&narrowed)?, original);
    narrowed = limits;
    narrowed.sentinel.maximum_pixel_samples -= 1;
    assert_ne!(plan.digest(&narrowed)?, original);
    narrowed = limits;
    narrowed.sentinel.package.detection_work_units -= 1;
    assert_ne!(plan.digest(&narrowed)?, original);
    Ok(())
}
