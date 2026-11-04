#![forbid(unsafe_code)]
//! Bounded incremental construction of the canonical coverage projection.
//!
//! Input admission is separate from the bridge algorithm's traversal budget. Duplicate and
//! zero-witness rows consume admission work too. Limits never change a successful projection's
//! identity. After any refused push the builder is poisoned: finishing cannot silently certify
//! the accepted prefix as if it were the complete requested input.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::{MAX_GRAPH_EDGES, MAX_GRAPH_NODES, GraphBuilder, GraphError};

use super::{
    CoverageObservation, PLANE_PREFIX, SENSOR_PREFIX, SensorCoverageProjection, ZONE_PREFIX,
    validate_identity,
};

/// Hard ceiling on admitted rows, including duplicates and zero-witness facts.
pub const MAX_COVERAGE_OBSERVATIONS: usize = MAX_GRAPH_EDGES;
/// Hard ceiling on cumulative input identity bytes, including repeated identities.
pub const MAX_COVERAGE_IDENTITY_BYTES: usize = 64 * 1024 * 1024;

/// Independent admission ceilings for one complete projection, never reset per input row.
///
/// These bound input work and canonical shape, not elapsed time or exact allocator usage.
/// All limits may be tightened; no caller can widen the hard graph/input ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageBuildLimits {
    /// Input rows, including duplicates and zero-witness rows.
    pub max_observations: usize,
    /// Unique sensor-zone facts, including zero-witness facts.
    pub max_facts: usize,
    /// Plane plus distinct sensors and zones.
    pub max_nodes: usize,
    /// Sensor uplinks plus positive sensor-zone edges.
    pub max_edges: usize,
    /// Site bytes plus both identity byte lengths for every admitted row; UTF-8 bytes.
    pub max_identity_bytes: usize,
}

impl Default for CoverageBuildLimits {
    fn default() -> Self {
        Self {
            max_observations: MAX_COVERAGE_OBSERVATIONS,
            max_facts: MAX_GRAPH_EDGES,
            max_nodes: MAX_GRAPH_NODES,
            max_edges: MAX_GRAPH_EDGES,
            max_identity_bytes: MAX_COVERAGE_IDENTITY_BYTES,
        }
    }
}

impl CoverageBuildLimits {
    fn validate(self) -> Result<(), GraphError> {
        if self.max_observations > MAX_COVERAGE_OBSERVATIONS
            || self.max_facts > MAX_GRAPH_EDGES
            || self.max_nodes > MAX_GRAPH_NODES
            || self.max_edges > MAX_GRAPH_EDGES
            || self.max_identity_bytes > MAX_COVERAGE_IDENTITY_BYTES
        {
            return Err(GraphError::TooLarge);
        }
        Ok(())
    }
}

/// Counters for successfully admitted input, not a runtime or physical coverage receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageBuildUsage {
    /// Rows admitted, including duplicates and zero-witness rows.
    pub observations: usize,
    /// Unique sensor-zone facts, including those with no witness.
    pub facts: usize,
    /// Plane plus unique sensors and zones.
    pub nodes: usize,
    /// Uplinks plus positive sensor-zone edges.
    pub edges: usize,
    /// Admitted input identity bytes; repeated identities are charged repeatedly.
    pub identity_bytes: usize,
}

/// One pure, bounded, incremental projection compiler. It grants no read/effect authority.
///
/// Callers can feed retained records without allocating an intermediate observation vector.
/// A failed push is terminal; subsequent pushes and `finish` return the original refusal.
#[derive(Debug)]
pub struct CoverageProjectionBuilder {
    plane: String,
    facts: BTreeMap<String, BTreeMap<String, u64>>,
    zones: BTreeSet<String>,
    limits: CoverageBuildLimits,
    usage: CoverageBuildUsage,
    failure: Option<GraphError>,
}

impl CoverageProjectionBuilder {
    /// Admit the site and plane before allocating projection state.
    ///
    /// # Errors
    /// Invalid site, limits above the hard ceilings, or no room for the plane/site identity.
    pub fn new(site: &str, limits: CoverageBuildLimits) -> Result<Self, GraphError> {
        limits.validate()?;
        validate_identity(PLANE_PREFIX, site)?;
        let usage = CoverageBuildUsage {
            observations: 0,
            facts: 0,
            nodes: 1,
            edges: 0,
            identity_bytes: site.len(),
        };
        check_usage(usage, limits)?;
        Ok(Self {
            plane: format!("{PLANE_PREFIX}{site}"),
            facts: BTreeMap::new(),
            zones: BTreeSet::new(),
            limits,
            usage,
            failure: None,
        })
    }

    /// Current successfully admitted counts. Refused input does not enter these counters.
    #[must_use]
    pub const fn usage(&self) -> CoverageBuildUsage {
        self.usage
    }

    /// Admit one observation. All counters and witness sums are checked before mutation.
    ///
    /// # Errors
    /// Exhausted admission dimension, invalid identity, or inexact witness arithmetic. Any
    /// refusal poisons this builder so a caller cannot ignore it and publish a partial graph.
    pub fn push(&mut self, observation: &CoverageObservation) -> Result<(), GraphError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        match self.admit(observation) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    fn admit(&mut self, observation: &CoverageObservation) -> Result<(), GraphError> {
        // Row and byte ceilings are checked before looking up or copying caller identities.
        let mut next = self.usage;
        next.observations += 1; // hard ceilings leave ample usize headroom
        check_limit(
            next.observations,
            self.limits.max_observations,
            "coverage_observations",
        )?;
        validate_identity(SENSOR_PREFIX, &observation.sensor_id)?;
        validate_identity(ZONE_PREFIX, &observation.zone_scope)?;
        next.identity_bytes += observation.sensor_id.len() + observation.zone_scope.len();
        check_limit(
            next.identity_bytes,
            self.limits.max_identity_bytes,
            "coverage_identity_bytes",
        )?;
        let sensor = self.facts.get(observation.sensor_id.as_str());
        let previous = sensor.and_then(|zones| zones.get(observation.zone_scope.as_str()));
        let count = previous
            .copied()
            .unwrap_or(0)
            .checked_add(observation.witnesses)
            .ok_or(GraphError::ArithmeticOverflow("sensor-zone witness count"))?;
        next.facts += usize::from(previous.is_none());
        next.nodes += usize::from(sensor.is_none())
            + usize::from(!self.zones.contains(observation.zone_scope.as_str()));
        next.edges += usize::from(sensor.is_none())
            + usize::from(previous.copied().unwrap_or(0) == 0 && count > 0);
        check_usage(next, self.limits)?;

        // All refusals precede these allocations and mutations. Duplicate input reuses its
        // original keys rather than repeatedly allocating and discarding identity strings.
        if let Some(zones) = self.facts.get_mut(observation.sensor_id.as_str()) {
            if let Some(value) = zones.get_mut(observation.zone_scope.as_str()) {
                *value = count;
            } else {
                zones.insert(observation.zone_scope.clone(), count);
            }
        } else {
            self.facts.insert(
                observation.sensor_id.clone(),
                BTreeMap::from([(observation.zone_scope.clone(), count)]),
            );
        }
        if !self.zones.contains(observation.zone_scope.as_str()) {
            self.zones.insert(observation.zone_scope.clone());
        }
        self.usage = next;
        Ok(())
    }

    /// Consume the complete admitted input into the existing canonical graph representation.
    ///
    /// # Errors
    /// The original push refusal, or a graph invariant failure. Never returns a partial graph.
    pub fn finish(self) -> Result<SensorCoverageProjection, GraphError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut graph = GraphBuilder::new();
        graph.add_node(self.plane.clone());
        for sensor in self.facts.keys() {
            graph.add_node(format!("{SENSOR_PREFIX}{sensor}"));
            graph.add_edge(self.plane.clone(), format!("{SENSOR_PREFIX}{sensor}"));
        }
        for zone in self.zones {
            graph.add_node(format!("{ZONE_PREFIX}{zone}"));
        }
        let mut witnesses = BTreeMap::new();
        for (sensor, zones) in self.facts {
            for (zone, count) in zones {
                if count > 0 {
                    graph.add_edge(
                        format!("{SENSOR_PREFIX}{sensor}"),
                        format!("{ZONE_PREFIX}{zone}"),
                    );
                }
                witnesses.insert((sensor.clone(), zone), count);
            }
        }
        Ok(SensorCoverageProjection {
            plane: self.plane,
            graph: graph.build()?,
            witnesses,
        })
    }
}

fn check_limit(value: usize, limit: usize, dimension: &'static str) -> Result<(), GraphError> {
    if value > limit {
        return Err(GraphError::BudgetExhausted {
            dimension,
            limit: limit as u64,
        });
    }
    Ok(())
}

fn check_usage(usage: CoverageBuildUsage, limits: CoverageBuildLimits) -> Result<(), GraphError> {
    check_limit(
        usage.observations,
        limits.max_observations,
        "coverage_observations",
    )?;
    check_limit(
        usage.identity_bytes,
        limits.max_identity_bytes,
        "coverage_identity_bytes",
    )?;
    check_limit(usage.facts, limits.max_facts, "coverage_facts")?;
    check_limit(usage.nodes, limits.max_nodes, "coverage_nodes")?;
    check_limit(usage.edges, limits.max_edges, "coverage_edges")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GraphBudget;

    fn row(sensor: &str, zone: &str, count: u64) -> CoverageObservation {
        CoverageObservation {
            sensor_id: sensor.to_owned(),
            zone_scope: zone.to_owned(),
            witnesses: count,
        }
    }

    fn small_limits() -> CoverageBuildLimits {
        CoverageBuildLimits {
            max_observations: 4,
            max_facts: 3,
            max_nodes: 5,
            max_edges: 4,
            max_identity_bytes: 64,
        }
    }

    #[test]
    fn streaming_and_slice_builds_preserve_canonical_answers() -> Result<(), GraphError> {
        let mut rows = vec![
            row("a", "x", 0),
            row("b", "x", 2),
            row("a", "x", 3),
            row("a", "y", 0),
        ];
        let slice = SensorCoverageProjection::build("site", &rows)?;
        let mut builder = CoverageProjectionBuilder::new("site", small_limits())?;
        for row in &rows {
            builder.push(row)?;
        }
        assert_eq!(
            builder.usage(),
            CoverageBuildUsage {
                observations: 4,
                facts: 3,
                nodes: 5,
                edges: 4,
                identity_bytes: 12,
            }
        );
        let streaming = builder.finish()?;
        assert_eq!(streaming, slice);
        let mut expected = GraphBuilder::new();
        for node in ["plane/site", "sensor/a", "sensor/b", "zone/x", "zone/y"] {
            expected.add_node(node);
        }
        for (a, b) in [
            ("plane/site", "sensor/a"),
            ("plane/site", "sensor/b"),
            ("sensor/a", "zone/x"),
            ("sensor/b", "zone/x"),
        ] {
            expected.add_edge(a, b);
        }
        assert_eq!(streaming.graph, expected.build()?);
        assert_eq!(
            streaming.witnesses,
            BTreeMap::from([
                (("a".to_owned(), "x".to_owned()), 3),
                (("a".to_owned(), "y".to_owned()), 0),
                (("b".to_owned(), "x".to_owned()), 2),
            ])
        );
        let answer = slice.single_points(GraphBudget::registered(&slice.graph))?;
        rows.reverse();
        let reversed = SensorCoverageProjection::build_with_limits("site", &rows, small_limits())?;
        assert_eq!(reversed, slice);
        assert_eq!(
            reversed.single_points(GraphBudget::registered(&reversed.graph))?,
            answer
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_zero_rows_consume_the_whole_input_allowance() -> Result<(), GraphError> {
        for count in [0, 1] {
            let limits = CoverageBuildLimits {
                max_observations: 1,
                ..small_limits()
            };
            let mut builder = CoverageProjectionBuilder::new("site", limits)?;
            builder.push(&row("a", "x", count))?;
            let error = GraphError::BudgetExhausted {
                dimension: "coverage_observations",
                limit: 1,
            };
            assert_eq!(builder.push(&row("a", "x", count)), Err(error.clone()));
            assert_eq!(builder.usage().observations, 1);
            assert_eq!(builder.finish(), Err(error));
        }
        Ok(())
    }

    #[test]
    fn each_canonical_shape_dimension_is_admitted_before_mutation() -> Result<(), GraphError> {
        for (limits, dimension, limit) in [
            (
                CoverageBuildLimits {
                    max_facts: 0,
                    ..small_limits()
                },
                "coverage_facts",
                0,
            ),
            (
                CoverageBuildLimits {
                    max_nodes: 2,
                    ..small_limits()
                },
                "coverage_nodes",
                2,
            ),
            (
                CoverageBuildLimits {
                    max_edges: 1,
                    ..small_limits()
                },
                "coverage_edges",
                1,
            ),
        ] {
            let mut builder = CoverageProjectionBuilder::new("site", limits)?;
            let before = builder.usage();
            let error = GraphError::BudgetExhausted { dimension, limit };
            assert_eq!(builder.push(&row("a", "x", 1)), Err(error.clone()));
            assert_eq!(builder.usage(), before);
            assert_eq!(builder.push(&row("a", "x", 0)), Err(error.clone()));
            assert_eq!(builder.finish(), Err(error));
        }
        Ok(())
    }

    #[test]
    fn identities_are_charged_in_bytes_including_duplicates() -> Result<(), GraphError> {
        let limits = CoverageBuildLimits {
            max_identity_bytes: 10,
            ..small_limits()
        };
        let mut builder = CoverageProjectionBuilder::new("site", limits)?;
        let unicode = row("é", "x", 0);
        builder.push(&unicode)?;
        builder.push(&unicode)?;
        assert_eq!(builder.usage().identity_bytes, 10);
        assert!(matches!(
            builder.push(&unicode),
            Err(GraphError::BudgetExhausted {
                dimension: "coverage_identity_bytes",
                limit: 10,
            })
        ));
        assert!(builder.finish().is_err());
        Ok(())
    }

    #[test]
    fn poisoned_builder_never_certifies_an_accepted_prefix() -> Result<(), GraphError> {
        let mut builder = CoverageProjectionBuilder::new("site", small_limits())?;
        builder.push(&row("a", "x", 1))?;
        let before = builder.usage();
        let error = GraphError::InvalidNodeId(SENSOR_PREFIX.to_owned());
        assert_eq!(builder.push(&row("", "y", 1)), Err(error.clone()));
        assert_eq!(builder.push(&row("b", "x", 1)), Err(error.clone()));
        assert_eq!(builder.usage(), before);
        assert_eq!(builder.finish(), Err(error));
        Ok(())
    }

    #[test]
    fn exact_witness_overflow_is_terminal_too() -> Result<(), GraphError> {
        let mut builder = CoverageProjectionBuilder::new("site", small_limits())?;
        builder.push(&row("a", "x", u64::MAX))?;
        let before = builder.usage();
        let error = GraphError::ArithmeticOverflow("sensor-zone witness count");
        assert_eq!(builder.push(&row("a", "x", 1)), Err(error.clone()));
        assert_eq!(builder.usage(), before);
        assert_eq!(builder.finish(), Err(error));
        Ok(())
    }

    #[test]
    fn zero_to_positive_transition_consumes_an_edge_once() -> Result<(), GraphError> {
        let limits = CoverageBuildLimits {
            max_edges: 2,
            ..small_limits()
        };
        let mut builder = CoverageProjectionBuilder::new("site", limits)?;
        builder.push(&row("a", "x", 0))?;
        assert_eq!(builder.usage().edges, 1);
        builder.push(&row("a", "x", 1))?;
        assert_eq!(builder.usage().edges, 2);
        builder.push(&row("a", "x", 1))?;
        assert_eq!(builder.usage().edges, 2);
        builder.push(&row("a", "y", 0))?;
        assert_eq!(builder.usage().edges, 2);
        let projection = builder.finish()?;
        projection.validate()?;
        assert_eq!(projection.graph.node_count(), 4);
        Ok(())
    }

    #[test]
    fn empty_projection_needs_only_the_plane_budget() -> Result<(), GraphError> {
        let limits = CoverageBuildLimits {
            max_observations: 0,
            max_facts: 0,
            max_nodes: 1,
            max_edges: 0,
            max_identity_bytes: 4,
        };
        let projection = CoverageProjectionBuilder::new("site", limits)?.finish()?;
        assert_eq!(projection, SensorCoverageProjection::build("site", &[])?);
        assert!(matches!(
            CoverageProjectionBuilder::new(
                "site",
                CoverageBuildLimits {
                    max_nodes: 0,
                    ..limits
                }
            ),
            Err(GraphError::BudgetExhausted {
                dimension: "coverage_nodes",
                limit: 0,
            })
        ));
        Ok(())
    }

    #[test]
    fn caller_limits_cannot_widen_hard_ceilings() {
        for limits in [
            CoverageBuildLimits {
                max_observations: MAX_COVERAGE_OBSERVATIONS + 1,
                ..small_limits()
            },
            CoverageBuildLimits {
                max_identity_bytes: MAX_COVERAGE_IDENTITY_BYTES + 1,
                ..small_limits()
            },
            CoverageBuildLimits {
                max_facts: MAX_GRAPH_EDGES + 1,
                ..small_limits()
            },
            CoverageBuildLimits {
                max_nodes: MAX_GRAPH_NODES + 1,
                ..small_limits()
            },
            CoverageBuildLimits {
                max_edges: MAX_GRAPH_EDGES + 1,
                ..small_limits()
            },
        ] {
            assert!(matches!(
                CoverageProjectionBuilder::new("site", limits),
                Err(GraphError::TooLarge)
            ));
        }
    }

    #[test]
    fn bulk_row_limit_refuses_before_parsing_any_identity() {
        let rows = [row("", "", 0)];
        assert_eq!(
            SensorCoverageProjection::build_with_limits(
                "site",
                &rows,
                CoverageBuildLimits {
                    max_observations: 0,
                    ..small_limits()
                }
            ),
            Err(GraphError::BudgetExhausted {
                dimension: "coverage_observations",
                limit: 0,
            })
        );
    }
}
