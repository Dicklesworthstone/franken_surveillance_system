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

use std::fmt;
use std::path::Path;

use fss_core::{ContractError, GraphAlgorithmWitness, LedgerAnchor};
use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::{
    CoverageObservation, CoverageSinglePoints, GraphBudget, GraphError, SensorCoverageProjection,
};

use crate::agent_orient::{DeploymentReadError, DeploymentSnapshot, OrientLimits, read_deployment};

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
    /// The witness could not be constructed.
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
            Self::Contract(error) => write!(formatter, "witness rejected: {error:?}"),
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
    let observations = coverage_observations(snapshot);
    let projection = SensorCoverageProjection::build(&snapshot.site_lineage, &observations)
        .map_err(CoverageGraphError::Graph)?;
    let answer = projection
        .single_points(GraphBudget::registered(&projection.graph))
        .map_err(CoverageGraphError::Graph)?;
    let projection_id = format!(
        "{PROJECTION_KIND}@commit:{}",
        snapshot.anchor.commit_sequence
    );
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
