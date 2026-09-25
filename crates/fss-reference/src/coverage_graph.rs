#![forbid(unsafe_code)]
//! Single points of failure of a deployment's retained coverage (`ALG-BRIDGE-001` over the
//! `SensorCoverageGraph` projection).
//!
//! The projection is compiled read-only from one committed deployment snapshot
//! ([`read_deployment`]): every retained coverage record (`coverage_witness` deltas, decoded and
//! rehashed from the spool) contributes, per zone it names, one (sensor, zone scope, retained
//! witness count) fact. The snapshot's authority anchor pins the whole execution
//! (`GRAPH-INV-001`); the witness names that anchor, the projection digest, the policy, the
//! observed counters (checked against the registered bound before any answer exists), and the
//! decision-path and output digests (`GRAPH-INV-008`).
//!
//! The answer is derived cognition: a zone with a single observer is a structural single point
//! over the retained history, not a statement about current observability, and a zone without a
//! witness is not observable, never evidence of absence. Nothing is written and nothing is
//! authorized.
//!
//! [`coverage_single_points_during`] restricts every sensor--zone edge to witnesses whose
//! certain `covered` bounds contain one caller-declared capture window in its entirety. Merely
//! overlapping outer bounds, disjoint history, and unions of partial witnesses do not qualify.
//! Known zones and sensors with zero qualifying witnesses remain explicit. The query window and
//! whole-witness selection policy are bound into the projection identity and algorithm witness;
//! the existing historical API and its identities are unchanged. This is conditional on retained
//! operator capture hints, not clock calibration, present availability, or an absence proof.

use std::fmt;
use std::path::Path;

use fss_core::{CaptureInterval, ContractError, GraphAlgorithmWitness, LedgerAnchor};
use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::{
    CoverageObservation, CoverageSinglePoints, GraphBudget, GraphError, SensorCoverageProjection,
};

use crate::agent_orient::{DeploymentReadError, DeploymentSnapshot, OrientLimits, read_deployment};
use crate::ingest::recorded_coverage::CoverageRecord;

/// One certified single-points answer with its witness.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageGraphReport {
    /// Site lineage of the deployment.
    pub site: String,
    /// Authority anchor the projection was compiled at.
    pub anchor: LedgerAnchor,
    /// Projection identity carried by the witness.
    pub projection_id: String,
    /// Retained coverage records read.
    pub records: usize,
    /// The immutable projection.
    pub projection: SensorCoverageProjection,
    /// The certified answer.
    pub answer: CoverageSinglePoints,
    /// The registered witness.
    pub witness: GraphAlgorithmWitness,
}

/// Why no answer was produced.
#[derive(Clone, Debug, PartialEq)]
pub enum CoverageGraphError {
    /// The deployment could not be read.
    Read(DeploymentReadError),
    /// The deployment belongs to another site lineage.
    SiteMismatch {
        /// Requested site.
        expected: String,
        /// Site of the deployment.
        actual: String,
    },
    /// The graph run failed closed.
    Graph(GraphError),
    /// The capture window is invalid or the witness could not be constructed.
    Contract(ContractError),
}

impl CoverageGraphError {
    /// Registered refusal identity of a graph failure, if this is one.
    #[must_use]
    pub const fn stable_id(&self) -> Option<&'static str> {
        match self {
            Self::Graph(error) => Some(error.stable_id()),
            _ => None,
        }
    }
}

impl fmt::Display for CoverageGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "deployment read failed: {error}"),
            Self::SiteMismatch { expected, actual } => write!(
                formatter,
                "deployment site lineage {actual:?} is not the requested {expected:?}"
            ),
            Self::Graph(error) => write!(formatter, "graph analysis failed: {error}"),
            Self::Contract(error) => write!(formatter, "coverage query or witness rejected: {error:?}"),
        }
    }
}

impl std::error::Error for CoverageGraphError {}

/// The `(sensor, zone scope, retained witnesses)` facts of a snapshot's retained coverage.
#[must_use]
pub fn coverage_observations(snapshot: &DeploymentSnapshot) -> Vec<CoverageObservation> {
    snapshot
        .coverage
        .iter()
        .flat_map(|retained| {
            retained
                .record
                .zones
                .iter()
                .map(|zone| CoverageObservation {
                    sensor_id: retained.record.sensor_id.clone(),
                    zone_scope: zone.scope.clone(),
                    witnesses: zone.witnesses.len() as u64,
                })
        })
        .collect()
}

/// Compiles the projection of `snapshot` and runs the certified analysis under its registered
/// budget.
///
/// # Errors
///
/// [`CoverageGraphError::Graph`] when the projection is refused or the run fails closed, and
/// [`CoverageGraphError::Contract`] when the witness cannot be built.
pub fn coverage_single_points(
    snapshot: &DeploymentSnapshot,
) -> Result<CoverageGraphReport, CoverageGraphError> {
    analyze_observations(snapshot, coverage_observations(snapshot), None)
}

fn analyze_observations(
    snapshot: &DeploymentSnapshot,
    observations: Vec<CoverageObservation>,
    window: Option<CaptureInterval>,
) -> Result<CoverageGraphReport, CoverageGraphError> {
    let projection = SensorCoverageProjection::build(&snapshot.site_lineage, &observations)
        .map_err(CoverageGraphError::Graph)?;
    let answer = projection
        .single_points(GraphBudget::registered(&projection.graph))
        .map_err(CoverageGraphError::Graph)?;
    let projection_id = projection_identity(&snapshot.anchor, window);
    let witness = answer
        .analysis
        .witness(&projection_id, snapshot.anchor.clone())
        .map_err(CoverageGraphError::Contract)?;
    fss_graph_algorithms::bridges::check_witness_bound(&witness)
        .map_err(CoverageGraphError::Graph)?;
    Ok(CoverageGraphReport {
        site: snapshot.site_lineage.clone(),
        anchor: snapshot.anchor.clone(),
        projection_id,
        records: snapshot.coverage.len(),
        projection,
        answer,
        witness,
    })
}

/// Reads `root` at its committed head without writing anything and answers for `site`.
///
/// # Errors
///
/// [`CoverageGraphError::Read`] for an unreadable deployment,
/// [`CoverageGraphError::SiteMismatch`] for another site, and every [`coverage_single_points`]
/// failure.
pub fn read_coverage_single_points(
    root: &Path,
    site: &str,
) -> Result<CoverageGraphReport, CoverageGraphError> {
    let snapshot =
        read_deployment(root, &OrientLimits::default()).map_err(CoverageGraphError::Read)?;
    if snapshot.site_lineage != site {
        return Err(CoverageGraphError::SiteMismatch {
            expected: site.to_owned(),
            actual: snapshot.site_lineage,
        });
    }
    coverage_single_points(&snapshot)
}

fn projection_identity(anchor: &LedgerAnchor, window: Option<CaptureInterval>) -> String {
    let historical = format!("{PROJECTION_KIND}@commit:{}", anchor.commit_sequence);
    match window {
        None => historical,
        Some(window) => format!(
            "{historical}@capture:{}:{}:whole-witness-v1",
            window.earliest.0, window.latest.0
        ),
    }
}

fn validate_window(window: CaptureInterval) -> Result<CaptureInterval, CoverageGraphError> {
    // Revalidate even when a caller constructed the public interval fields directly.
    CaptureInterval::new(window.earliest, window.latest).map_err(CoverageGraphError::Contract)
}

fn contains_window(covered: CaptureInterval, window: CaptureInterval) -> bool {
    // Comparison only: no subtraction can overflow at the signed timestamp limits.
    covered.earliest <= window.earliest && covered.latest >= window.latest
}

fn observations_in_window<'a>(
    records: impl Iterator<Item = &'a CoverageRecord>,
    window: CaptureInterval,
) -> Vec<CoverageObservation> {
    records
        .flat_map(|record| {
            record.zones.iter().map(move |zone| CoverageObservation {
                sensor_id: record.sensor_id.clone(),
                zone_scope: zone.scope.clone(),
                witnesses: zone
                    .witnesses
                    .iter()
                    .filter(|witness| contains_window(witness.covered, window))
                    .count() as u64,
            })
        })
        .collect()
}

/// Retained coverage facts restricted to one inclusive capture window.
///
/// A witness qualifies only if its certain bounds contain the whole window; neither its
/// uncertainty hull nor a union of partial witnesses suffices. Zero-witness facts are retained.
/// This does not certify that the sensors' operator-declared clocks are calibrated or aligned.
///
/// # Errors
///
/// [`CoverageGraphError::Contract`] when the capture window is inverted.
pub fn coverage_observations_during(
    snapshot: &DeploymentSnapshot,
    window: CaptureInterval,
) -> Result<Vec<CoverageObservation>, CoverageGraphError> {
    let window = validate_window(window)?;
    Ok(observations_in_window(
        snapshot.coverage.iter().map(|retained| &retained.record),
        window,
    ))
}

/// Certified single-point analysis for witnesses covering one common capture window.
///
/// The anchor, inclusive endpoints and `whole-witness-v1` selection policy are bound into the
/// projection identity carried by the algorithm witness. Topologically identical graphs for
/// different windows therefore never share the same algorithm-witness identity.
///
/// # Errors
///
/// Every [`coverage_single_points`] error, and [`CoverageGraphError::Contract`] for an inverted
/// window. No partial projection is returned on failure.
pub fn coverage_single_points_during(
    snapshot: &DeploymentSnapshot,
    window: CaptureInterval,
) -> Result<CoverageGraphReport, CoverageGraphError> {
    let observations = coverage_observations_during(snapshot, window)?;
    analyze_observations(snapshot, observations, Some(window))
}

/// Reads the committed deployment without writes and restricts analysis to a capture window.
///
/// # Errors
///
/// Every [`read_coverage_single_points`] error, and [`CoverageGraphError::Contract`] for an
/// inverted window (rejected before reading the deployment).
pub fn read_coverage_single_points_during(
    root: &Path,
    site: &str,
    window: CaptureInterval,
) -> Result<CoverageGraphReport, CoverageGraphError> {
    let window = validate_window(window)?;
    let snapshot =
        read_deployment(root, &OrientLimits::default()).map_err(CoverageGraphError::Read)?;
    if snapshot.site_lineage != site {
        return Err(CoverageGraphError::SiteMismatch {
            expected: site.to_owned(),
            actual: snapshot.site_lineage,
        });
    }
    coverage_single_points_during(&snapshot, window)
}

#[cfg(test)]
mod window_tests {
    use super::*;
    use crate::ingest::recorded_coverage::{
        CoverageEntry, CoverageFrame, CoverageInput, CoverageSource, CoverageZoneInput,
        OPERATOR_TIME_LABEL, build_coverage,
    };
    use fss_core::{ContentDigest, TimestampNs};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn interval(first: i128, last: i128) -> TestResult<CaptureInterval> {
        Ok(CaptureInterval::new(TimestampNs(first), TimestampNs(last))?)
    }

    fn record(sensor: &str, start: i128, entry: Option<usize>) -> TestResult<CoverageRecord> {
        let frames = (0..20)
            .map(|segment| {
                let time = start + segment as i128 * 10;
                Ok(CoverageFrame {
                    segment,
                    capture: CaptureInterval::new(TimestampNs(time - 1), TimestampNs(time + 1))?,
                })
            })
            .collect::<Result<Vec<_>, ContractError>>()?;
        let digest = ContentDigest::sha256(sensor.as_bytes());
        Ok(build_coverage(&CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: digest,
            import_root: digest,
            sensor_id: sensor,
            analysis_digest: digest,
            basis: LedgerAnchor::genesis("site:window-tests"),
            capture_time_label: OPERATOR_TIME_LABEL,
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 1,
            zones: vec![CoverageZoneInput {
                zone_id: "door".to_owned(),
                pipeline_generation: digest,
                geometry: "0,0,10,10".to_owned(),
                inside_frame: true,
                entries: entry
                    .map(|segment| CoverageEntry {
                        segment,
                        candidate: digest,
                        event_id: None,
                    })
                    .into_iter()
                    .collect(),
            }],
        })?)
    }

    fn answer(records: &[CoverageRecord], window: CaptureInterval) -> TestResult<CoverageSinglePoints> {
        let observations = observations_in_window(records.iter(), window);
        let projection = SensorCoverageProjection::build("site:window-tests", &observations)?;
        Ok(projection.single_points(GraphBudget::registered(&projection.graph))?)
    }

    #[test]
    fn disjoint_sensor_history_is_not_simultaneous_redundancy() -> TestResult {
        let records = [record("sensor:east", 0, None)?, record("sensor:west", 1000, None)?];
        assert!(records.iter().all(|r| r.zones[0].witnesses.len() == 1));
        let result = answer(&records, interval(60, 120)?)?;
        assert_eq!(result.zones.len(), 1);
        assert_eq!(result.zones[0].observers, vec!["sensor:east"]);
        assert_eq!(result.zones[0].single_points_of_failure, vec!["sensor:east"]);
        // The other sensor and the declared zone remain in the projection, not silently dropped.
        assert_eq!(result.sensors.len(), 2);
        let later = answer(&records, interval(1060, 1120)?)?;
        assert_eq!(later.zones[0].observers, vec!["sensor:west"]);
        Ok(())
    }

    #[test]
    fn both_sensors_must_cover_the_entire_requested_window() -> TestResult {
        let records = [record("sensor:east", 0, None)?, record("sensor:west", 20, None)?];
        let overlap = answer(&records, interval(80, 120)?)?;
        assert_eq!(overlap.zones[0].observers, vec!["sensor:east", "sensor:west"]);
        assert!(overlap.zones[0].single_points_of_failure.is_empty());
        let wider = answer(&records, interval(50, 120)?)?;
        assert_eq!(wider.zones[0].single_points_of_failure, vec!["sensor:east"]);
        Ok(())
    }

    #[test]
    fn uncovered_windows_keep_the_zone_explicit() -> TestResult {
        let records = [record("sensor:east", 0, None)?];
        let result = answer(&records, interval(500, 600)?)?;
        assert_eq!(result.zones.len(), 1);
        assert!(result.zones[0].observers.is_empty());
        assert!(result.zones[0].single_points_of_failure.is_empty());
        assert_eq!(result.zones[0].witnesses, 0);
        Ok(())
    }

    #[test]
    fn uncertain_outer_bounds_do_not_authorize_an_edge() -> TestResult {
        let record = record("sensor:east", 0, None)?;
        let witness = &record.zones[0].witnesses[0];
        let whole = observations_in_window([&record].into_iter(), witness.covered);
        assert_eq!(whole[0].witnesses, 1);
        let hull = observations_in_window([&record].into_iter(), witness.outer);
        assert_eq!(hull[0].witnesses, 0);
        let point = interval(witness.covered.earliest.0, witness.covered.earliest.0)?;
        assert_eq!(observations_in_window([&record].into_iter(), point)[0].witnesses, 1);
        Ok(())
    }

    #[test]
    fn partial_witnesses_never_bridge_an_uncovered_interval() -> TestResult {
        let record = record("sensor:east", 0, Some(10))?;
        assert_eq!(record.zones[0].witnesses.len(), 2);
        let facts = observations_in_window([&record].into_iter(), interval(50, 160)?);
        assert_eq!(facts[0].witnesses, 0);
        assert_eq!(
            observations_in_window([&record].into_iter(), interval(50, 70)?)[0].witnesses,
            1
        );
        Ok(())
    }

    #[test]
    fn different_windows_bind_different_witness_identities_even_for_the_same_graph() -> TestResult {
        let records = [record("sensor:east", 0, None)?];
        let answer = answer(&records, interval(60, 120)?)?;
        let anchor = LedgerAnchor::genesis("site:window-tests");
        let first = projection_identity(&anchor, Some(interval(60, 120)?));
        let second = projection_identity(&anchor, Some(interval(70, 110)?));
        assert_ne!(first, second);
        let a = answer.analysis.witness(&first, anchor.clone())?;
        let b = answer.analysis.witness(&second, anchor.clone())?;
        assert_ne!(a.digest(), b.digest());
        fss_graph_algorithms::bridges::check_witness_bound(&a)?;
        assert_eq!(
            projection_identity(&anchor, None),
            format!("{PROJECTION_KIND}@commit:{}", anchor.commit_sequence)
        );
        Ok(())
    }

    #[test]
    fn inverted_window_fails_before_any_deployment_read() {
        let inverted = CaptureInterval {
            earliest: TimestampNs(2),
            latest: TimestampNs(1),
        };
        assert!(matches!(
            read_coverage_single_points_during(Path::new("not-opened"), "site:test", inverted),
            Err(CoverageGraphError::Contract(_))
        ));
    }

    #[test]
    fn containment_does_not_overflow_at_timestamp_extremes() {
        let full = CaptureInterval {
            earliest: TimestampNs(i128::MIN),
            latest: TimestampNs(i128::MAX),
        };
        assert!(contains_window(full, full));
        let point = CaptureInterval {
            earliest: TimestampNs(i128::MAX),
            latest: TimestampNs(i128::MAX),
        };
        assert!(contains_window(full, point));
        assert!(!contains_window(point, full));
    }
}
