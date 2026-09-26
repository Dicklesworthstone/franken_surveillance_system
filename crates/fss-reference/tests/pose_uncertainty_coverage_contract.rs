#![forbid(unsafe_code)]
//! Pose-uncertainty propagation into corroborate ground coverage (fss-x8j0v covariance
//! propagation) on real retained recordings:
//!
//! 1. with a tight calibration pose covariance a zone near the frustum edge is `robust` and
//!    covered, and every witness predicate states the sigma-point robustness;
//! 2. with an inflated covariance the same zone is `pose_sensitive`: observable under the nominal
//!    pose, yet it carries no witness (no certified absence, nothing for silence to rest on) and
//!    every non-entry frame is `pose_sensitive`;
//! 3. a centred zone stays `robust` and covered under both covariances;
//! 4. a pose without a covariance (the owner `--pose` path) is recorded
//!    `uncertainty_not_provided`, never robust, and its witnesses say so;
//! 5. candidates and events never depend on the covariance; records are version 5, round-trip
//!    canonically and are bit-identical on rerun; a covariance without a site-calibration
//!    provenance is refused.
//!
//! No-Claim: the covariance is a local linear approximation and sigma-point robustness is not a
//! guarantee.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::ContentDigest;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::ground_visibility::{
    CameraPose, PoseCovariance, PoseRobustnessClass, VisibilityPolicy,
};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationOptions, CorroborationPlan,
    CorroborationReport, GroundHomography, GroundVisibilityPlan, GroundZone,
};
use fss_reference::ingest::recorded_coverage::{
    CoverageRecord, GenerationCurrency, PoseProvenance, PoseUncertainty, UncoveredReason,
    ZoneCoverage,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

/// East sees the ground from above: `x = u`, `y = 48 - v`.
const EAST: [f64; 9] = [1.0, 0.0, 0.0, 0.0, -1.0, 48.0, 0.0, 0.0, 1.0];
/// West is rotated half a turn about the vertical: `x = 96 - u`, `y = v`.
const WEST: [f64; 9] = [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];

fn scene(right: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 {
            let left = if right {
                (index - 3) * 8
            } else {
                80 - (index - 3) * 8
            };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(stream)
}

/// Both cameras hang 10 units above (48, 24) looking straight down (f = 10 px): exactly the
/// homographies above.
fn poses() -> TestResult<[Option<CameraPose>; 2]> {
    let centre = [48.0, 24.0, 10.0];
    let with_centre = |rotation: [[f64; 3]; 3]| -> TestResult<CameraPose> {
        let translation =
            rotation.map(|row| -(row[0] * centre[0] + row[1] * centre[1] + row[2] * centre[2]));
        Ok(CameraPose::from_parameters(
            [96, 48],
            [10.0, 10.0, 48.0, 24.0],
            rotation,
            translation,
        )?)
    };
    Ok([
        Some(with_centre([
            [1.0, 0.0, 0.0],
            [0.0, -1.0, 0.0],
            [0.0, 0.0, -1.0],
        ])?),
        Some(with_centre([
            [-1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, -1.0],
        ])?),
    ])
}

/// Diagonal pose covariance: rotation variance (rad^2) and translation variance (units^2).
fn diagonal(rotation: f64, translation: f64) -> TestResult<PoseCovariance> {
    let mut matrix = [[0.0_f64; 6]; 6];
    for (index, row) in matrix.iter_mut().enumerate() {
        row[index] = if index < 3 { rotation } else { translation };
    }
    Ok(PoseCovariance::new(matrix)?)
}

/// Sigma 1e-4 rad and 0.01 units: every sigma point moves a pixel by a few hundredths.
fn tight() -> TestResult<PoseCovariance> {
    diagonal(1e-8, 1e-4)
}

/// Translation sigma 1 unit: the translation sigma points move pixels by about 3.
fn inflated() -> TestResult<PoseCovariance> {
    diagonal(1e-8, 1.0)
}

fn calibration(handle: u64) -> PoseProvenance {
    PoseProvenance::SiteCalibration {
        calibration_digest: ContentDigest::sha256(b"synthetic site calibration"),
        camera_handle: handle,
        intrinsics_generation: 1,
        extrinsics_generation: 1,
        currency: GenerationCurrency::Unasserted,
    }
}

struct Recordings {
    fixture: Fixture,
    plan: CorroborationPlan,
}

fn recordings(name: &str) -> TestResult<Recordings> {
    let mut fixture = Fixture::new(name)?;
    let east = fixture.ingest(
        &format!("sensor:{name}-east"),
        &scene(true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        &format!("sensor:{name}-west"),
        &scene(false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let zone = |id: &str, [x, y, width, height]: [f64; 4]| GroundZone {
        zone_id: id.to_owned(),
        x,
        y,
        width,
        height,
    };
    let plan = CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".to_owned(),
                import_identity: east,
                homography: GroundHomography { matrix: EAST },
            },
            CorroborationCamera {
                name: "west".to_owned(),
                import_identity: west,
                homography: GroundHomography { matrix: WEST },
            },
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![
            // Ground x 86..95: the outer sample column (x = 94.44) is 1.56 px inside the right
            // image edge of east and the left image edge of west.
            zone("edge", [86.0, 4.0, 9.0, 40.0]),
            // Around the principal point: every sample stays tens of pixels inside.
            zone("centre", [40.0, 16.0, 16.0, 16.0]),
        ],
        gates: CorroborationGates {
            time_gate_ns: 250_000_000,
            distance_gate: 16.0,
        },
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    Ok(Recordings { fixture, plan })
}

fn analyze(
    recordings: &Recordings,
    covariance: [Option<PoseCovariance>; 2],
    provenance: [Option<PoseProvenance>; 2],
) -> TestResult<CorroborationReport> {
    Ok(CorroborationReport::analyze_with_pose_uncertainty(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        &GroundVisibilityPlan {
            policy: VisibilityPolicy::default(),
            poses: poses()?,
            mesh: None,
        },
        &provenance,
        &covariance,
        CorroborationOptions::default(),
        &recordings.fixture.cx,
    )?)
}

fn calibrated(
    recordings: &Recordings,
    covariance: PoseCovariance,
) -> TestResult<CorroborationReport> {
    analyze(
        recordings,
        [Some(covariance), Some(covariance)],
        [Some(calibration(21)), Some(calibration(22))],
    )
}

fn zone<'a>(record: &'a CoverageRecord, id: &str) -> TestResult<&'a ZoneCoverage> {
    record
        .zones
        .iter()
        .find(|zone| zone.zone_id == id)
        .ok_or_else(|| format!("no zone {id}").into())
}

fn record_bytes(report: &CorroborationReport) -> Vec<Vec<u8>> {
    report
        .coverage()
        .iter()
        .map(CoverageRecord::to_bytes)
        .collect()
}

/// Version word of a record (length-prefixed magic `FSSCOV01`: bytes 0..16; version: 16..20).
fn version(record: &CoverageRecord) -> Option<u32> {
    let bytes = record.to_bytes();
    let word: [u8; 4] = bytes.get(16..20)?.try_into().ok()?;
    Some(u32::from_be_bytes(word))
}

#[test]
fn a_zone_near_the_frustum_edge_is_robust_when_tight_and_pose_sensitive_when_inflated() -> TestResult
{
    let recordings = recordings("pose-edge")?;
    let narrow = calibrated(&recordings, tight()?)?;
    let wide = calibrated(&recordings, inflated()?)?;
    assert_eq!(narrow.coverage().len(), 2);
    for (robust, sensitive) in narrow.coverage().iter().zip(wide.coverage()) {
        assert_eq!(version(robust), Some(5));
        assert_eq!(version(sensitive), Some(5));
        assert!(matches!(
            robust.pose_uncertainty,
            Some(PoseUncertainty::SigmaPoints { .. })
        ));
        // Tight: the edge zone is observable, robust and covered; its witnesses say why.
        let edge = zone(robust, "edge")?;
        let visibility = edge.visibility.as_ref().ok_or("edge visibility")?;
        assert!(visibility.observable());
        let robustness = edge.pose_robustness.ok_or("edge robustness")?;
        assert_eq!(robustness.nominal, PoseRobustnessClass::Observable);
        assert!(robustness.robust());
        assert_eq!(robustness.observable, 12);
        assert!(!edge.witnesses.is_empty());
        for witness in &edge.witnesses {
            let predicate = &witness.witness.negative_predicate;
            assert!(
                predicate.contains("; pose robust: 12 of 12 sigma-point perturbations"),
                "{predicate}"
            );
            assert!(predicate.contains("not a guarantee"), "{predicate}");
        }
        // Inflated: the same nominal visibility, but two sigma points (translation X toward the
        // near edge, translation Z toward the ground) push samples out of the frame.
        let edge = zone(sensitive, "edge")?;
        assert_eq!(edge.visibility.as_ref(), Some(visibility));
        let robustness = edge.pose_robustness.ok_or("edge robustness")?;
        assert_eq!(robustness.nominal, PoseRobustnessClass::Observable);
        assert!(!robustness.robust());
        assert!(robustness.observable_but_sensitive());
        assert_eq!((robustness.observable, robustness.outside_frustum), (10, 2));
        assert_eq!(robustness.disagreeing_ppm(), 166_666);
        // Not plainly observable: no witness, so no certified absence over it and nothing for
        // silence to rest on; every frame that is not a named entry is pose_sensitive.
        assert!(edge.witnesses.is_empty());
        assert!(!edge.uncovered.is_empty());
        assert!(edge.uncovered.iter().all(|gap| matches!(
            gap.reason,
            UncoveredReason::PoseSensitive | UncoveredReason::ZoneEntry { .. }
        )));
        assert!(
            edge.uncovered
                .iter()
                .any(|gap| gap.reason == UncoveredReason::PoseSensitive)
        );
        // Every analysed segment is accounted for exactly once.
        let mut segments: Vec<u64> = edge
            .uncovered
            .iter()
            .flat_map(|gap| gap.first_segment..=gap.last_segment)
            .collect();
        segments.sort_unstable();
        assert_eq!(
            segments,
            (sensitive.first_segment..=sensitive.last_segment).collect::<Vec<_>>()
        );
        assert!(
            sensitive
                .witnesses()
                .all(|(zone, _)| zone.zone_id != "edge")
        );
        // The covariance is bound into the analysis identity: distinct ledger objects.
        assert_ne!(robust.identity(), sensitive.identity());
        for record in [robust, sensitive] {
            assert_eq!(
                &CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
                record
            );
        }
    }
    // Candidates and events never depend on the covariance.
    assert_eq!(
        narrow.to_json(0, Some("rerun"), Some("alert")),
        wide.to_json(0, Some("rerun"), Some("alert"))
    );
    // Deterministic: bit-identical records on rerun.
    assert_eq!(
        record_bytes(&calibrated(&recordings, inflated()?)?),
        record_bytes(&wide)
    );
    assert_eq!(
        record_bytes(&calibrated(&recordings, tight()?)?),
        record_bytes(&narrow)
    );
    Ok(())
}

#[test]
fn a_centred_zone_stays_robust_and_covered_under_both_covariances() -> TestResult {
    let recordings = recordings("pose-centre")?;
    for covariance in [tight()?, inflated()?] {
        let report = calibrated(&recordings, covariance)?;
        for record in report.coverage() {
            let centre = zone(record, "centre")?;
            let robustness = centre.pose_robustness.ok_or("centre robustness")?;
            assert!(robustness.robust());
            assert_eq!(robustness.observable, 12);
            assert!(!centre.witnesses.is_empty());
            assert!(
                centre
                    .uncovered
                    .iter()
                    .all(|gap| gap.reason != UncoveredReason::PoseSensitive)
            );
        }
    }
    Ok(())
}

#[test]
fn a_pose_without_a_covariance_is_uncertainty_not_provided_never_robust() -> TestResult {
    let recordings = recordings("pose-owner")?;
    let owner = [
        Some(PoseProvenance::OwnerPoseArgument),
        Some(PoseProvenance::OwnerPoseArgument),
    ];
    let report = analyze(&recordings, [None, None], owner)?;
    // `analyze_with_provenance` (no covariance bound) is exactly the same analysis.
    let provenance_only = CorroborationReport::analyze_with_provenance(
        &recordings.fixture.deployment,
        &recordings.plan,
        &WatchLimits::default(),
        None,
        &GroundVisibilityPlan {
            policy: VisibilityPolicy::default(),
            poses: poses()?,
            mesh: None,
        },
        &owner,
        CorroborationOptions::default(),
        &recordings.fixture.cx,
    )?;
    assert_eq!(record_bytes(&provenance_only), record_bytes(&report));
    for record in report.coverage() {
        assert_eq!(version(record), Some(5));
        assert_eq!(record.pose_uncertainty, Some(PoseUncertainty::NotProvided));
        assert_eq!(
            record.pose_uncertainty.map(|value| value.as_str()),
            Some("uncertainty_not_provided")
        );
        for zone in &record.zones {
            assert!(zone.pose_robustness.is_none(), "never robust");
        }
        // The nominal visibility still yields its witnesses, each saying the pose's robustness
        // was not assessed.
        let edge = zone(record, "edge")?;
        assert!(!edge.witnesses.is_empty());
        for witness in record.witnesses().map(|(_, witness)| witness) {
            assert!(
                witness
                    .witness
                    .negative_predicate
                    .contains("; pose uncertainty_not_provided"),
                "{}",
                witness.witness.negative_predicate
            );
        }
    }
    // Without any provenance nothing is bound: the posed records keep their earlier version.
    let unbound = analyze(&recordings, [None, None], [None, None])?;
    for record in unbound.coverage() {
        assert_eq!(version(record), Some(2));
        assert!(record.pose_uncertainty.is_none());
    }
    // A covariance needs a site-calibration provenance: an owner pose has none.
    let refusal = analyze(&recordings, [Some(tight()?), None], owner)
        .err()
        .ok_or("a covariance on an owner pose must be refused")?;
    assert!(
        refusal.to_string().contains("site-calibration"),
        "{refusal}"
    );
    let refusal = analyze(&recordings, [Some(tight()?), None], [None, None])
        .err()
        .ok_or("a covariance without a provenance must be refused")?;
    assert!(
        refusal.to_string().contains("site-calibration"),
        "{refusal}"
    );
    Ok(())
}
