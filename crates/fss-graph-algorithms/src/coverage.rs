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

use std::collections::{BTreeMap, BTreeSet};

use crate::bridges::{BridgeAnalysis, GraphBudget, analyse_bridges};
use crate::graph::{GraphBuilder, GraphError, UndirectedGraph};

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
    /// Builds the projection of `site` from `observations` (any order; duplicates are summed).
    ///
    /// # Errors
    ///
    /// [`GraphError::InvalidNodeId`] for an empty or oversized site, sensor or zone identity, and
    /// [`GraphError::TooLarge`] beyond the graph limits.
    pub fn build(site: &str, observations: &[CoverageObservation]) -> Result<Self, GraphError> {
        let mut witnesses: BTreeMap<(String, String), u64> = BTreeMap::new();
        let mut sensors = BTreeSet::new();
        let mut zones = BTreeSet::new();
        for observation in observations {
            if observation.sensor_id.is_empty() {
                return Err(GraphError::InvalidNodeId(SENSOR_PREFIX.to_owned()));
            }
            if observation.zone_scope.is_empty() {
                return Err(GraphError::InvalidNodeId(ZONE_PREFIX.to_owned()));
            }
            sensors.insert(observation.sensor_id.clone());
            zones.insert(observation.zone_scope.clone());
            let count = witnesses
                .entry((
                    observation.sensor_id.clone(),
                    observation.zone_scope.clone(),
                ))
                .or_insert(0);
            *count = count.saturating_add(observation.witnesses);
        }
        let plane = format!("{PLANE_PREFIX}{site}");
        let mut builder = GraphBuilder::new();
        builder.add_node(plane.clone());
        for sensor in &sensors {
            builder.add_node(format!("{SENSOR_PREFIX}{sensor}"));
            builder.add_edge(plane.clone(), format!("{SENSOR_PREFIX}{sensor}"));
        }
        for zone in &zones {
            builder.add_node(format!("{ZONE_PREFIX}{zone}"));
        }
        for ((sensor, zone), count) in &witnesses {
            if *count > 0 {
                builder.add_edge(
                    format!("{SENSOR_PREFIX}{sensor}"),
                    format!("{ZONE_PREFIX}{zone}"),
                );
            }
        }
        Ok(Self {
            plane,
            graph: builder.build()?,
            witnesses,
        })
    }

    /// Runs `ALG-BRIDGE-001` rooted at the plane under `budget` and derives per-zone and
    /// per-sensor resilience, cross-checked against the edge set.
    ///
    /// # Errors
    ///
    /// Any [`analyse_bridges`] failure, or [`GraphError::Inconsistent`] when a derived answer
    /// contradicts the projection's structural invariant.
    pub fn single_points(&self, budget: GraphBudget) -> Result<CoverageSinglePoints, GraphError> {
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
            *total = total.saturating_add(*count);
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
}
