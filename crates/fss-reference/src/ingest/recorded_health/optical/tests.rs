#![forbid(unsafe_code)]
//! Optical findings must change admitted tracking/coverage, not merely diagnostic JSON.

use super::*;
use crate::ReplayCx;
use crate::ingest::recorded_health::{
    RecordedHealthPolicy, RecordedHealthScreen, screened_plan_digest,
};
use crate::ingest::sensor_health::{HealthError, HealthFrame, policy_digest};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, OperationId, TimestampNs};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn context() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-optical".to_owned(),
        operation_id: OperationId::parse("operation:recorded-optical")?,
        principal: "principal:recorded-optical".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-optical"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir().join("fss-recorded-optical-context"),
    )?)
}

fn screen(
    frames: usize,
    thresholds: OpticalThresholds,
) -> Result<RecordedHealthScreen, HealthError> {
    RecordedHealthScreen::with_policy(
        frames,
        ContentDigest::sha256(b"optical-import"),
        ContentDigest::sha256(b"optical-root"),
        "sensor:recorded-optical",
        ContentDigest::sha256(b"optical-source"),
        BTreeSet::new(),
        RecordedHealthPolicy::ConservativeOpticalV1(thresholds),
    )
}

fn frame(segment: u64, pixels: &[u8]) -> TestResult<HealthFrame<'_>> {
    Ok(HealthFrame {
        source_generation: ContentDigest::sha256(b"optical-source"),
        segment,
        capsule_digest: ContentDigest::sha256(&segment.to_le_bytes()),
        capture: CaptureInterval::new(
            TimestampNs(i128::from(segment) * 100),
            TimestampNs(i128::from(segment) * 100 + 1),
        )?,
        dimensions: [4, 4],
        gap_before: false,
        pixels,
    })
}

fn sharp(segment: u64) -> [u8; 16] {
    std::array::from_fn(|index| {
        if (index / 4 + index % 4) % 2 == 0 {
            40 + (segment % 2) as u8
        } else {
            200 - (segment % 2) as u8
        }
    })
}

fn recovery_summary() -> TestResult<RecordedHealthSummary> {
    let cx = context()?;
    let mut screen = screen(32, OpticalThresholds::default())?;
    for segment in 0..32 {
        let mut pixels = sharp(segment);
        if (12..14).contains(&segment) {
            pixels.fill(100 + (segment % 2) as u8);
        } else if segment == 14 {
            pixels[..4].fill(255);
        }
        assert_eq!(
            screen.observe(frame(segment, &pixels)?, &cx)?,
            (12..15).contains(&segment),
        );
    }
    Ok(screen.finish(&[])?)
}

#[test]
fn optical_blur_and_glare_immediately_withhold_frames_and_price_every_pass() -> TestResult {
    let summary = recovery_summary()?;
    assert!(
        summary
            .observations()
            .iter()
            .all(|frame| frame.findings.is_empty())
    );
    assert_eq!(summary.affected_segments(), &BTreeSet::from([12, 13, 14]));
    assert_eq!(summary.tracking_restart_segments(), BTreeSet::from([15]));
    assert_eq!(
        summary.optical_observations()[12].findings,
        [OpticalFinding::SevereBlur]
    );
    assert_eq!(
        summary.optical_observations()[14].findings,
        [OpticalFinding::LocalizedHighlightGlare],
    );
    assert_eq!(summary.samples_used(), 32 * 16);
    assert_eq!(summary.optical_sample_reads(), 32 * (2 * 16 + 5 * 4));
    assert_ne!(summary.policy_digest(), policy_digest());
    let json = summary.to_json();
    assert!(json.contains("\"policy\":\"conservative-optical-v1\""));
    assert!(json.contains("\"optical_sample_reads\":1664"));
    assert!(json.contains("\"health_certified\":false"));
    assert_eq!(
        RecordedHealthSummary::from_bytes(&summary.to_bytes())?,
        summary
    );
    Ok(())
}

#[test]
fn optical_coverage_withholds_blind_frames_confirmation_latency_and_recovery_warmup() -> TestResult
{
    use crate::ingest::recorded_coverage::{
        CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
        CoverageZoneInput, build_coverage_with,
    };
    let summary = recovery_summary()?;
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
        sensor_id: "sensor:recorded-optical",
        analysis_digest: ContentDigest::sha256(b"optical-analysis"),
        basis: fss_core::LedgerAnchor::genesis("site:recorded-optical"),
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
            pipeline_generation: ContentDigest::sha256(b"optical-pipeline"),
            entries: Vec::new(),
        }],
    };
    let mut extras = CoverageExtras {
        sensor_health: Some(summary),
        ..CoverageExtras::default()
    };
    // A caller cannot omit the optical recovery restart and obtain immediate negative coverage.
    assert!(build_coverage_with(&input, &extras).is_err());
    extras.restarts = vec![15];
    let record = build_coverage_with(&input, &extras)?;
    assert_eq!(
        record.zones[0]
            .witnesses
            .iter()
            .map(|witness| (witness.first_segment, witness.last_segment))
            .collect::<Vec<_>>(),
        [(4, 9), (19, 29)],
    );
    assert_eq!(
        CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
        record
    );
    Ok(())
}

#[test]
fn optical_receipt_rejects_missing_rebound_reordered_or_forged_measurements() -> TestResult {
    let summary = recovery_summary()?;
    let mut forged = summary.clone();
    forged.optical_observations.pop();
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations.swap(0, 1);
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations[12].source_generation = ContentDigest::sha256(b"foreign-source");
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations[12].luma_digest = ContentDigest::sha256(b"different-mask");
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations[12].findings.clear();
    forged.affected_segments.remove(&12);
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations[14].glare_ppm -= 1;
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_observations[0].interior_pixels += 1;
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.optical_sample_reads -= 1;
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    forged = summary.clone();
    forged.policy = RecordedHealthPolicy::ConservativeOpticalV1(OpticalThresholds {
        min_laplacian_variance_x1000: 0,
        ..OpticalThresholds::default()
    });
    assert!(RecordedHealthSummary::from_bytes(&forged.to_bytes()).is_err());
    let bytes = summary.to_bytes();
    assert!(RecordedHealthSummary::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    Ok(())
}

#[test]
fn optical_thresholds_change_policy_plan_and_receipt_identity() -> TestResult {
    let base = ContentDigest::sha256(b"watch-plan");
    let conservative = RecordedHealthPolicy::ConservativeV1;
    assert_eq!(conservative.digest(), policy_digest());
    assert_eq!(
        conservative.to_bytes(),
        crate::ingest::sensor_health::policy_bytes()
    );
    let defaults = OpticalThresholds::default();
    let original = RecordedHealthPolicy::ConservativeOpticalV1(defaults);
    let mut identities = BTreeSet::from([
        base,
        screened_plan_digest(base, Some(conservative)),
        screened_plan_digest(base, Some(original)),
    ]);
    for thresholds in [
        OpticalThresholds {
            min_laplacian_variance_x1000: 0,
            ..defaults
        },
        OpticalThresholds {
            glare_luma_min: 251,
            ..defaults
        },
        OpticalThresholds {
            max_glare_ppm: 200_000,
            ..defaults
        },
    ] {
        let policy = RecordedHealthPolicy::ConservativeOpticalV1(thresholds);
        assert_ne!(policy.digest(), original.digest());
        assert!(identities.insert(screened_plan_digest(base, Some(policy))));
    }
    let invalid = OpticalThresholds {
        max_glare_ppm: 1_000_001,
        ..defaults
    };
    assert!(matches!(screen(1, invalid), Err(HealthError::InvalidImage)));
    Ok(())
}

#[test]
fn optical_work_allowance_never_resets_at_a_gap_and_cancellation_has_no_partial_receipt()
-> TestResult {
    let cx = context()?;
    let mut bounded = screen(2, OpticalThresholds::default())?;
    bounded.maximum_optical_sample_reads = 52;
    assert!(!bounded.observe(frame(0, &sharp(0))?, &cx)?);
    let pixels = sharp(1);
    let mut second = frame(1, &pixels)?;
    second.gap_before = true;
    assert_eq!(bounded.observe(second, &cx), Err(HealthError::Limit));
    assert_eq!(bounded.optical_sample_reads, 52);

    let cancelled = context()?;
    let mut screen = screen(2, OpticalThresholds::default())?;
    assert!(!screen.observe(frame(0, &sharp(0))?, &cancelled)?);
    cancelled.set_cancel_at_checkpoint_occurrence("sensor_health:optical_laplacian_row", 1);
    assert_eq!(
        screen.observe(frame(1, &sharp(1))?, &cancelled),
        Err(HealthError::Cancelled)
    );
    assert_eq!(screen.observations.len(), 1);
    assert_eq!(screen.optical_observations.len(), 1);
    assert!(screen.finish(&[]).is_err());
    Ok(())
}

#[test]
fn optical_insufficient_resolution_withholds_coverage_without_claiming_tamper() -> TestResult {
    let cx = context()?;
    let mut screen = screen(1, OpticalThresholds::default())?;
    let mut tiny = frame(0, &[80; 8])?;
    tiny.dimensions = [2, 4];
    assert!(screen.observe(tiny, &cx)?);
    let summary = screen.finish(&[])?;
    assert_eq!(summary.affected_segments(), &BTreeSet::from([0]));
    assert_eq!(
        summary.optical_observations()[0].findings,
        [OpticalFinding::InsufficientResolution],
    );
    assert_eq!(summary.optical_sample_reads(), 16);
    assert_eq!(
        RecordedHealthSummary::from_bytes(&summary.to_bytes())?,
        summary
    );
    Ok(())
}
