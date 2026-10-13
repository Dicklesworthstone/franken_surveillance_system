//! `SensorCoverageGraph` projection and its single points of failure.
//!
//! Nodes are one evidence-plane root (`plane/<site>`), every sensor with retained coverage
//! (`sensor/<id>`), and every zone scope a retained coverage record names (`zone/<scope>`, the
//! scope being `zone:<id>` for an image zone or `ground-zone:<id>` for a ground zone). Edges are:
//!
//! * `plane -- sensor` for every sensor with retained coverage (its evidence reaches the plane);
//! * `sensor -- zone` when the sensor holds at least one retained coverage witness for the zone.
//!
//! A zone is observable through the plane exactly when some sensor witnessed it, so `ALG-BRIDGE-001`
//! rooted at the plane answers "which single sensor loss leaves zone Z without any retained
//! witness": the zones a cut sensor separates from the plane. Each answer is re-derived from the
//! edge set and must agree (a structural invariant of this projection); disagreement fails closed.
//!
//! What the projection does not claim: witness intervals are not intersected (two sensors that
//! witnessed a zone at different times both count), no failure domain other than the sensor
//! itself is modelled (shared network, power, clock or host dependencies are unknown, not absent),
//! an image zone is identified by its operator-assigned scope on every sensor that names it, and a
//! zone with no witness is `not_observable`, never evidence of absence.

/// Incremental admission with cumulative input and canonical-shape limits.
pub mod build;
pub use build::{CoverageBuildLimits, CoverageBuildUsage, CoverageProjectionBuilder};

use std::collections::{BTreeMap, BTreeSet};

use crate::bridges::{BridgeAnalysis, GraphBudget, analyse_bridges};
use crate::graph::{MAX_GRAPH_EDGES, MAX_NODE_ID_LEN, GraphError, UndirectedGraph};

/// Registered projection kind.
pub const PROJECTION_KIND: &str = "SensorCoverageGraph";
/// Node-identity prefix of the evidence-plane root.
pub const PLANE_PREFIX: &str = "plane/";
/// Node-identity prefix of a sensor.
pub const SENSOR_PREFIX: &str = "sensor/";
/// Node-identity prefix of a zone scope.
pub const ZONE_PREFIX: &str = "zone/";

/// One (sensor, zone scope) fact read from retained coverage records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageObservation {
    /// Recording sensor.
    pub sensor_id: String,
    /// Zone scope (`zone:<id>` or `ground-zone:<id>`).
    pub zone_scope: String,
    /// Retained witnesses of this sensor for this zone (0: named but never witnessed).
    pub witnesses: u64,
}

/// The canonical projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorCoverageProjection {
    /// Evidence-plane root node identity.
    pub plane: String,
    /// The immutable graph.
    pub graph: UndirectedGraph,
    /// Retained witnesses per (sensor, zone scope), summed over records.
    pub witnesses: BTreeMap<(String, String), u64>,
}

impl SensorCoverageProjection {
    /// Builds a bounded projection (any input order; duplicate witness counts are summed).
    ///
    /// Uses [`CoverageBuildLimits::default`]. For tighter admission use [`Self::build_with_limits`];
    /// to avoid a collected observation vector use [`CoverageProjectionBuilder`] directly.
    /// Successful graph identities and algorithm answers do not depend on the admission limits.
    ///
    /// # Errors
    /// Invalid identities, exhausted input/shape limits, or inexact witness counts. No partial
    /// graph is returned. Graph traversal has its own separate [`GraphBudget`].
    pub fn build(site: &str, observations: &[CoverageObservation]) -> Result<Self, GraphError> {
        Self::build_with_limits(site, observations, CoverageBuildLimits::default())
    }

    /// Compile all observations under one cumulative admission allowance.
    ///
    /// The row count is checked before inspecting any observation. Further admission checks
    /// run before each mutation; an input failure never becomes a successful prefix result.
    ///
    /// # Errors
    /// Every [`CoverageProjectionBuilder::new`], [`CoverageProjectionBuilder::push`] or
    /// [`CoverageProjectionBuilder::finish`] refusal, including a caller limit above a hard cap.
    pub fn build_with_limits(
        site: &str,
        observations: &[CoverageObservation],
        limits: CoverageBuildLimits,
    ) -> Result<Self, GraphError> {
        let mut builder = CoverageProjectionBuilder::new(site, limits)?;
        if observations.len() > limits.max_observations {
            return Err(GraphError::BudgetExhausted {
                dimension: "coverage_observations",
                limit: limits.max_observations as u64,
            });
        }
        for observation in observations {
            builder.push(observation)?;
        }
        builder.finish()
    }

    /// Revalidate the graph against every public witness fact, including zero-count facts.
    ///
    /// Extra plane-to-zone edges, omitted sensors and substituted topology can preserve the
    /// same articulation points. Validate the entire node and edge sets, not just those cuts.
    /// Borrowed identity sets and binary edge lookups avoid building a second full graph.
    /// This establishes internal consistency only, not authority or provenance of the facts.
    ///
    /// # Errors
    /// Invalid identities, excessive witness facts, or a graph inconsistent with those facts.
    pub fn validate(&self) -> Result<(), GraphError> {
        let site = self
            .plane
            .strip_prefix(PLANE_PREFIX)
            .ok_or_else(inconsistent_projection)?;
        validate_identity(PLANE_PREFIX, site)?;
        if self.witnesses.len() > MAX_GRAPH_EDGES {
            return Err(GraphError::TooLarge);
        }
        let plane = self
            .graph
            .index_of(&self.plane)
            .ok_or_else(inconsistent_projection)?;
        let mut sensors = BTreeSet::new();
        let mut zones = BTreeSet::new();
        let mut positive = 0;
        for ((sensor, zone), count) in &self.witnesses {
            validate_identity(SENSOR_PREFIX, sensor)?;
            validate_identity(ZONE_PREFIX, zone)?;
            sensors.insert(sensor.as_str());
            zones.insert(zone.as_str());
            if *count > 0 {
                positive += 1;
                let a = projection_node(&self.graph, SENSOR_PREFIX, sensor)?;
                let b = projection_node(&self.graph, ZONE_PREFIX, zone)?;
                require_edge(&self.graph, a, b)?;
            }
        }
        // All expected nodes and edges are distinct. Membership plus exact cardinalities
        // proves set equality, so hidden paths or isolated foreign nodes cannot survive.
        if self.graph.node_count() != 1 + sensors.len() + zones.len()
            || self.graph.edge_count() != sensors.len() + positive
        {
            return Err(inconsistent_projection());
        }
        for sensor in sensors {
            let node = projection_node(&self.graph, SENSOR_PREFIX, sensor)?;
            require_edge(&self.graph, plane, node)?;
        }
        for zone in zones {
            projection_node(&self.graph, ZONE_PREFIX, zone)?;
        }
        Ok(())
    }

    /// Runs `ALG-BRIDGE-001` rooted at the plane under `budget` and derives per-zone and
    /// per-sensor resilience, cross-checked against the edge set.
    ///
    /// # Errors
    ///
    /// Any [`analyse_bridges`] failure, or [`GraphError::Inconsistent`] when a derived answer
    /// contradicts the projection's structural invariant. Public projection fields are first
    /// revalidated; inexact witness totals return [`GraphError::ArithmeticOverflow`].
    pub fn single_points(&self, budget: GraphBudget) -> Result<CoverageSinglePoints, GraphError> {
        self.validate()?;
        let analysis = analyse_bridges(&self.graph, Some(&self.plane), budget)?;
        let mut observers: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut totals: BTreeMap<&str, u64> = BTreeMap::new();
        let mut sensors: BTreeSet<&str> = BTreeSet::new();
        for ((sensor, zone), count) in &self.witnesses {
            let (sensor, zone) = (sensor.as_str(), zone.as_str());
            sensors.insert(sensor);
            let entry = observers.entry(zone).or_default();
            if *count > 0 {
                entry.push(sensor.to_owned());
            }
            let total = totals.entry(zone).or_insert(0);
            *total = total
                .checked_add(*count)
                .ok_or(GraphError::ArithmeticOverflow("zone witness count"))?;
        }
        let mut cut_zones: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut sole: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for separation in &analysis.output.vertex_separations {
            let Some(sensor) = separation.node.strip_prefix(SENSOR_PREFIX) else {
                return Err(GraphError::Inconsistent(format!(
                    "cut vertex {} is not a sensor",
                    separation.node
                )));
            };
            for member in &separation.separated {
                let Some(zone) = member.strip_prefix(ZONE_PREFIX) else {
                    return Err(GraphError::Inconsistent(format!(
                        "sensor {sensor} separates non-zone node {member}"
                    )));
                };
                cut_zones
                    .entry(zone.to_owned())
                    .or_default()
                    .push(sensor.to_owned());
                sole.entry(sensor.to_owned())
                    .or_default()
                    .push(zone.to_owned());
            }
        }
        let unreachable: BTreeSet<&str> = analysis
            .output
            .unreachable_from_root
            .iter()
            .map(String::as_str)
            .collect();
        let mut zones = Vec::with_capacity(observers.len());
        for (zone, zone_observers) in &observers {
            let single_points = cut_zones.remove(*zone).unwrap_or_default();
            let expected: &[String] = if zone_observers.len() == 1 {
                zone_observers
            } else {
                &[]
            };
            let node = format!("{ZONE_PREFIX}{zone}");
            if single_points != expected
                || unreachable.contains(node.as_str()) != zone_observers.is_empty()
            {
                return Err(GraphError::Inconsistent(format!(
                    "zone {zone}: cut sensors {single_points:?} disagree with observers {zone_observers:?}"
                )));
            }
            let state = match zone_observers.len() {
                0 => ZoneState::NotObservable,
                1 => ZoneState::SingleObserver,
                _ => ZoneState::MultipleObservers,
            };
            zones.push(ZoneResilience {
                scope: (*zone).to_owned(),
                state,
                observers: zone_observers.clone(),
                single_points_of_failure: single_points,
                witnesses: totals.get(zone).copied().unwrap_or(0),
            });
        }
        if let Some((zone, _)) = cut_zones.into_iter().next() {
            return Err(GraphError::Inconsistent(format!(
                "separated zone {zone} is not a projection zone"
            )));
        }
        let bridged: BTreeSet<&str> = analysis
            .output
            .bridges
            .iter()
            .filter(|(a, _)| *a == self.plane)
            .filter_map(|(_, b)| b.strip_prefix(SENSOR_PREFIX))
            .collect();
        let sensors = sensors
            .into_iter()
            .map(|sensor| SensorResilience {
                sensor_id: sensor.to_owned(),
                sole_observer_of: sole.remove(sensor).unwrap_or_default(),
                uplink_is_bridge: bridged.contains(sensor),
            })
            .collect();
        Ok(CoverageSinglePoints {
            analysis,
            zones,
            sensors,
        })
    }
}

// Refuse before copying an invalid or arbitrarily large caller-controlled identity.
fn validate_identity(prefix: &str, id: &str) -> Result<(), GraphError> {
    if id.is_empty()
        || id.len() > MAX_NODE_ID_LEN - prefix.len()
        || id.chars().any(char::is_control)
    {
        return Err(GraphError::InvalidNodeId(prefix.to_owned()));
    }
    Ok(())
}

fn inconsistent_projection() -> GraphError {
    GraphError::Inconsistent("coverage graph and witness facts differ".to_owned())
}

fn projection_node(graph: &UndirectedGraph, prefix: &str, id: &str) -> Result<u32, GraphError> {
    graph
        .index_of(&format!("{prefix}{id}"))
        .ok_or_else(inconsistent_projection)
}

fn require_edge(graph: &UndirectedGraph, a: u32, b: u32) -> Result<(), GraphError> {
    graph
        .edges()
        .binary_search(&(a.min(b), a.max(b)))
        .map(|_| ())
        .map_err(|_| inconsistent_projection())
}

/// Coverage redundancy of one zone at the anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneState {
    /// No sensor holds a retained witness: not observable (never evidence of absence).
    NotObservable,
    /// Exactly one sensor holds retained witnesses: its loss leaves the zone without any.
    SingleObserver,
    /// Two or more sensors hold retained witnesses (intervals not intersected).
    MultipleObservers,
}

impl ZoneState {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotObservable => "not_observable",
            Self::SingleObserver => "single_observer",
            Self::MultipleObservers => "multiple_observers",
        }
    }
}

/// One zone's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneResilience {
    /// Zone scope.
    pub scope: String,
    /// Redundancy state.
    pub state: ZoneState,
    /// Sensors with at least one retained witness, ascending.
    pub observers: Vec<String>,
    /// Sensors whose single loss leaves the zone without any retained witness, ascending.
    pub single_points_of_failure: Vec<String>,
    /// Retained witnesses over every sensor.
    pub witnesses: u64,
}

/// One sensor's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorResilience {
    /// Sensor identity.
    pub sensor_id: String,
    /// Zones only this sensor witnessed, ascending.
    pub sole_observer_of: Vec<String>,
    /// Whether its plane link is a bridge (no zone it witnessed is witnessed by another sensor).
    pub uplink_is_bridge: bool,
}

/// The complete certified answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageSinglePoints {
    /// The underlying bound-checked `ALG-BRIDGE-001` run.
    pub analysis: BridgeAnalysis,
    /// Every zone, ascending scope.
    pub zones: Vec<ZoneResilience>,
    /// Every sensor, ascending identity.
    pub sensors: Vec<SensorResilience>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GraphBuilder;

    fn observation(sensor: &str, zone: &str, witnesses: u64) -> CoverageObservation {
        CoverageObservation {
            sensor_id: sensor.to_owned(),
            zone_scope: zone.to_owned(),
            witnesses,
        }
    }

    #[test]
    fn single_points_follow_witnesses_and_order_never_matters() -> Result<(), GraphError> {
        let observations = vec![
            observation("sensor:north", "zone:door", 1),
            observation("sensor:north", "zone:gate", 2),
            observation("sensor:south", "zone:door", 1),
            observation("sensor:south", "zone:attic", 0),
            observation("sensor:east", "zone:shed", 1),
        ];
        let projection = SensorCoverageProjection::build("site:a", &observations)?;
        let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
        let states: Vec<(&str, &str, Vec<String>)> = answer
            .zones
            .iter()
            .map(|zone| {
                (
                    zone.scope.as_str(),
                    zone.state.as_str(),
                    zone.single_points_of_failure.clone(),
                )
            })
            .collect();
        assert_eq!(
            states,
            vec![
                ("zone:attic", "not_observable", vec![]),
                ("zone:door", "multiple_observers", vec![]),
                (
                    "zone:gate",
                    "single_observer",
                    vec!["sensor:north".to_owned()]
                ),
                (
                    "zone:shed",
                    "single_observer",
                    vec!["sensor:east".to_owned()]
                ),
            ]
        );
        let bridges: Vec<(&str, bool)> = answer
            .sensors
            .iter()
            .map(|sensor| (sensor.sensor_id.as_str(), sensor.uplink_is_bridge))
            .collect();
        assert_eq!(
            bridges,
            vec![
                ("sensor:east", true),
                ("sensor:north", false),
                ("sensor:south", false)
            ]
        );
        let mut reversed = observations.clone();
        reversed.reverse();
        let again = SensorCoverageProjection::build("site:a", &reversed)?;
        let second = again.single_points(GraphBudget::registered(&again.graph))?;
        assert_eq!(second, answer);
        Ok(())
    }

    #[test]
    fn empty_projection_is_only_the_plane() -> Result<(), GraphError> {
        let projection = SensorCoverageProjection::build("site:a", &[])?;
        assert_eq!(projection.graph.node_count(), 1);
        let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
        assert!(answer.zones.is_empty() && answer.sensors.is_empty());
        assert!(answer.analysis.output.articulation_points.is_empty());
        Ok(())
    }

    #[test]
    fn extra_edges_cannot_bypass_the_sensor_failure_model() -> Result<(), GraphError> {
        let mut projection = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", 1),
                observation("sensor:south", "zone:door", 1),
            ],
        )?;
        let mut builder = GraphBuilder::new();
        for node in [
            "plane/site:a",
            "sensor/sensor:north",
            "sensor/sensor:south",
            "zone/zone:door",
        ] {
            builder.add_node(node);
        }
        for (a, b) in [
            ("plane/site:a", "sensor/sensor:north"),
            ("plane/site:a", "sensor/sensor:south"),
            ("sensor/sensor:north", "zone/zone:door"),
            ("sensor/sensor:south", "zone/zone:door"),
            ("plane/site:a", "zone/zone:door"),
        ] {
            builder.add_edge(a, b);
        }
        projection.graph = builder.build()?;
        // Both the original and substituted graphs have no articulation points. Checking
        // only their cut sets therefore cannot detect this source-free path to the zone.
        let raw = analyse_bridges(
            &projection.graph,
            Some(&projection.plane),
            GraphBudget::registered(&projection.graph),
        )?;
        assert!(raw.output.articulation_points.is_empty());
        assert!(matches!(
            projection.single_points(GraphBudget::registered(&projection.graph)),
            Err(GraphError::Inconsistent(_))
        ));
        Ok(())
    }

    #[test]
    fn zero_witness_sensors_cannot_be_injected_after_projection() -> Result<(), GraphError> {
        let mut projection = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", 1),
                observation("sensor:south", "zone:door", 1),
            ],
        )?;
        projection
            .witnesses
            .insert(("sensor:ghost".to_owned(), "zone:door".to_owned()), 0);
        assert!(matches!(
            projection.validate(),
            Err(GraphError::Inconsistent(_))
        ));
        assert!(matches!(
            projection.single_points(GraphBudget::registered(&projection.graph)),
            Err(GraphError::Inconsistent(_))
        ));
        Ok(())
    }

    #[test]
    fn absent_witness_facts_cannot_hide_graph_members() -> Result<(), GraphError> {
        let mut projection = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", 1),
                observation("sensor:south", "zone:door", 1),
            ],
        )?;
        projection.witnesses.clear();
        assert!(matches!(
            projection.single_points(GraphBudget::registered(&projection.graph)),
            Err(GraphError::Inconsistent(_))
        ));
        Ok(())
    }

    #[test]
    fn duplicate_witness_counts_never_saturate() -> Result<(), GraphError> {
        let exact = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", u64::MAX - 1),
                observation("sensor:north", "zone:door", 1),
            ],
        )?;
        let answer = exact.single_points(GraphBudget::registered(&exact.graph))?;
        assert_eq!(answer.zones[0].witnesses, u64::MAX);
        let mut excess = vec![
            observation("sensor:north", "zone:door", u64::MAX),
            observation("sensor:north", "zone:door", 1),
        ];
        for _ in 0..2 {
            assert_eq!(
                SensorCoverageProjection::build("site:a", &excess),
                Err(GraphError::ArithmeticOverflow("sensor-zone witness count"))
            );
            excess.reverse();
        }
        Ok(())
    }

    #[test]
    fn zone_totals_across_sensors_never_saturate() -> Result<(), GraphError> {
        let projection = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", u64::MAX),
                observation("sensor:south", "zone:door", 1),
            ],
        )?;
        assert_eq!(
            projection.single_points(GraphBudget::registered(&projection.graph)),
            Err(GraphError::ArithmeticOverflow("zone witness count"))
        );
        // Totals are per zone: two individually exact zones need no global u64 sum.
        let separate = SensorCoverageProjection::build(
            "site:a",
            &[
                observation("sensor:north", "zone:door", u64::MAX),
                observation("sensor:south", "zone:gate", u64::MAX),
            ],
        )?;
        assert!(
            separate
                .single_points(GraphBudget::registered(&separate.graph))
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn a_prefixed_but_empty_site_is_not_an_identity() {
        assert_eq!(
            SensorCoverageProjection::build("", &[]),
            Err(GraphError::InvalidNodeId(PLANE_PREFIX.to_owned()))
        );
    }
}
