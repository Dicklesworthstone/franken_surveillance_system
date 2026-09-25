#![forbid(unsafe_code)]
//! Shared-failure scenarios over an already authorized `SensorCoverageGraph`.
//!
//! Each owner-declared domain is tested independently: all its members fail together.
//! A scenario contracts their observer edges onto one cut vertex, retaining the original
//! members as leaves so the graph digest still binds the complete membership. Combining
//! overlapping domains in one undirected graph would incorrectly turn required power and
//! network dependencies into alternative paths. No independence, current availability,
//! causal probability, or absence claim follows from an omitted domain.

use std::collections::{BTreeMap, BTreeSet};

use crate::coverage::{PLANE_PREFIX, SENSOR_PREFIX, ZONE_PREFIX};
use crate::{
    BridgeAnalysis, CoverageObservation, GraphBudget, GraphBuilder, GraphError,
    SensorCoverageProjection, UndirectedGraph, analyse_bridges,
};

/// Maximum scenarios in one request.
pub const MAX_FAILURE_DOMAINS: usize = 16;
/// Maximum members in one declared domain.
pub const MAX_DOMAIN_MEMBERS: usize = 1024;
/// Maximum bytes in an owner-assigned domain label.
pub const MAX_DOMAIN_ID_BYTES: usize = 64;
/// Maximum sensor/zone facts accepted by the scenario compiler.
pub const MAX_FAILURE_FACTS: usize = 8192;
/// Hard aggregate traversal ceiling, independent of the caller's budget.
pub const MAX_FAILURE_OPERATIONS: u64 = 1_000_000;
/// Hard aggregate emitted-identity ceiling, independent of the caller's budget.
pub const MAX_FAILURE_OUTPUT_ENTRIES: u64 = 100_000;

/// The type of an explicitly declared common dependency (not a measured failure cause).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FailureDomainKind {
    /// Router, switch, access point, uplink, or other shared network dependency.
    Network,
    /// Shared supply, circuit, or battery.
    Power,
    /// Shared clock or synchronization dependency.
    Clock,
    /// Shared recorder, host, or processing dependency.
    Host,
}

impl FailureDomainKind {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Power => "power",
            Self::Clock => "clock",
            Self::Host => "host",
        }
    }
}

/// One bounded, canonical owner assertion. It conveys no authority or completeness claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureDomain {
    kind: FailureDomainKind,
    id: String,
    members: BTreeSet<String>,
}

impl FailureDomain {
    /// Validate a declaration. Duplicate members are refused, not silently merged.
    ///
    /// # Errors
    /// Invalid labels, empty/oversized membership, duplicate members, or invalid sensor IDs.
    pub fn new(kind: FailureDomainKind, id: &str, members: &[String]) -> Result<Self, GraphError> {
        if id.is_empty() || id.len() > MAX_DOMAIN_ID_BYTES || id.chars().any(char::is_control) {
            return Err(GraphError::InvalidNodeId(id.to_owned()));
        }
        if members.is_empty() || members.len() > MAX_DOMAIN_MEMBERS {
            return Err(GraphError::TooLarge);
        }
        let mut canonical = BTreeSet::new();
        for member in members {
            if member.is_empty()
                || SENSOR_PREFIX.len() + member.len() > crate::graph::MAX_NODE_ID_LEN
                || member.chars().any(char::is_control)
            {
                return Err(GraphError::InvalidNodeId(member.clone()));
            }
            if !canonical.insert(member.clone()) {
                return Err(GraphError::DuplicateNode(member.clone()));
            }
        }
        Ok(Self {
            kind,
            id: id.to_owned(),
            members: canonical,
        })
    }

    /// Declared dependency class.
    #[must_use]
    pub const fn kind(&self) -> FailureDomainKind {
        self.kind
    }

    /// Owner-assigned label, scoped to its dependency class.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// All declared members, including sensors with no qualifying witness, in stable order.
    #[must_use]
    pub fn members(&self) -> &BTreeSet<String> {
        &self.members
    }

    /// Cut-vertex identity of this independent scenario.
    #[must_use]
    pub fn node_id(&self) -> String {
        format!("failure/{}/{}", self.kind.as_str(), self.id)
    }
}

/// One exact simultaneous-member-loss answer, conditional on the owner assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureScenario {
    /// Complete declaration used by this scenario.
    pub domain: FailureDomain,
    /// Projection supplied to the registered bridge algorithm; members remain identity leaves.
    pub graph: UndirectedGraph,
    /// Registered algorithm answer and checked complexity counters.
    pub analysis: BridgeAnalysis,
    /// Previously witnessed zones losing every qualifying observer, in stable order.
    /// Already-unwitnessed zones are never classified as newly lost.
    pub lost_zones: Vec<String>,
}

/// All scenarios, or no result if any declaration or budget fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureDomainAnalysis {
    /// Independent scenarios in `(kind, id)` order. Overlapping memberships are permitted.
    pub scenarios: Vec<FailureScenario>,
    /// Aggregate node visits and adjacency scans, not a per-scenario budget reset.
    pub operations: u64,
    /// Aggregate identities emitted by the underlying algorithms.
    pub output_entries: u64,
}

/// Compile and analyze owner-declared common failures against exactly the supplied coverage.
///
/// The caller must first perform authorization and any capture-window selection. This function
/// does not consult other sensors, a clock, or the filesystem. Each scenario uses `ALG-BRIDGE-001`
/// and is independently cross-checked against the original observer sets. To publish a witness,
/// bind its projection ID to the *parent coverage witness digest* as well as this declaration:
/// the parent carries the source graph, authority anchor and capture-window selection.
///
/// # Errors
/// Invalid/duplicate declarations, an unknown member, inconsistent public projection fields,
/// size limits, and aggregate budget exhaustion fail closed with no partial answer.
pub fn analyse_failure_domains(
    projection: &SensorCoverageProjection,
    domains: &[FailureDomain],
    budget: GraphBudget,
) -> Result<FailureDomainAnalysis, GraphError> {
    if domains.len() > MAX_FAILURE_DOMAINS || projection.witnesses.len() > MAX_FAILURE_FACTS {
        return Err(GraphError::TooLarge);
    }
    let site = projection
        .plane
        .strip_prefix(PLANE_PREFIX)
        .ok_or_else(|| GraphError::InvalidNodeId(projection.plane.clone()))?;
    // Public projection fields must not let callers substitute a graph or witness map.
    let facts: Vec<CoverageObservation> = projection
        .witnesses
        .iter()
        .map(|((sensor, zone), count)| CoverageObservation {
            sensor_id: sensor.clone(),
            zone_scope: zone.clone(),
            witnesses: *count,
        })
        .collect();
    let rebuilt = SensorCoverageProjection::build(site, &facts)?;
    if rebuilt != *projection {
        return Err(GraphError::Inconsistent(
            "coverage graph and witness facts differ".to_owned(),
        ));
    }
    let sensors: BTreeSet<&str> = projection
        .witnesses
        .keys()
        .map(|(sensor, _)| sensor.as_str())
        .collect();
    let mut observers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for ((sensor, zone), count) in &projection.witnesses {
        let entry = observers.entry(zone.as_str()).or_default();
        if *count > 0 {
            entry.insert(sensor.as_str());
        }
    }
    let mut ordered = BTreeMap::new();
    for domain in domains {
        if ordered
            .insert((domain.kind, domain.id.as_str()), domain)
            .is_some()
        {
            return Err(GraphError::DuplicateNode(domain.node_id()));
        }
        for member in &domain.members {
            if !sensors.contains(member.as_str()) {
                return Err(GraphError::UnknownNode(format!("{SENSOR_PREFIX}{member}")));
            }
        }
    }
    let ceiling = GraphBudget {
        max_operations: budget.max_operations.min(MAX_FAILURE_OPERATIONS),
        max_output_entries: budget.max_output_entries.min(MAX_FAILURE_OUTPUT_ENTRIES),
    };
    let mut result = FailureDomainAnalysis {
        scenarios: Vec::new(),
        operations: 0,
        output_entries: 0,
    };
    for domain in ordered.into_values() {
        let node = domain.node_id();
        let mut builder = GraphBuilder::new();
        builder
            .add_node(projection.plane.clone())
            .add_node(node.clone());
        builder.add_edge(projection.plane.clone(), node.clone());
        for sensor in &sensors {
            let sensor_node = format!("{SENSOR_PREFIX}{sensor}");
            builder.add_node(sensor_node.clone());
            let parent = if domain.members.contains(*sensor) {
                &node
            } else {
                &projection.plane
            };
            builder.add_edge(parent.clone(), sensor_node);
        }
        let mut lost_zones = Vec::new();
        for (zone, watching) in &observers {
            let zone_node = format!("{ZONE_PREFIX}{zone}");
            builder.add_node(zone_node.clone());
            let mut member_observed = false;
            let mut survivor_observed = false;
            for sensor in watching {
                if domain.members.contains(*sensor) {
                    member_observed = true;
                } else {
                    survivor_observed = true;
                    builder.add_edge(format!("{SENSOR_PREFIX}{sensor}"), zone_node.clone());
                }
            }
            if member_observed {
                builder.add_edge(node.clone(), zone_node);
                if !survivor_observed {
                    lost_zones.push((*zone).to_owned());
                }
            }
        }
        let graph = builder.build()?;
        let remaining = GraphBudget {
            max_operations: ceiling.max_operations - result.operations,
            max_output_entries: ceiling.max_output_entries - result.output_entries,
        };
        let analysis = analyse_bridges(&graph, Some(&projection.plane), remaining)?;
        let mut expected: Vec<String> = domain
            .members
            .iter()
            .map(|sensor| format!("{SENSOR_PREFIX}{sensor}"))
            .chain(lost_zones.iter().map(|zone| format!("{ZONE_PREFIX}{zone}")))
            .collect();
        expected.sort_unstable();
        let actual = analysis
            .output
            .vertex_separations
            .iter()
            .find(|cut| cut.node == node);
        if actual.map(|cut| cut.separated.as_slice()) != Some(expected.as_slice()) {
            return Err(GraphError::Inconsistent(
                "common failure cut disagrees with original observers".to_owned(),
            ));
        }
        result.operations += analysis.operations;
        result.output_entries += analysis.output_entries;
        result.scenarios.push(FailureScenario {
            domain: domain.clone(),
            graph,
            analysis,
            lost_zones,
        });
    }
    Ok(result)
}
