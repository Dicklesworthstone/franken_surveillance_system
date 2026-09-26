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
    let inputs = prepare_failure_inputs(projection, domains)?;
    let ceiling = GraphBudget {
        max_operations: budget.max_operations.min(MAX_FAILURE_OPERATIONS),
        max_output_entries: budget.max_output_entries.min(MAX_FAILURE_OUTPUT_ENTRIES),
    };
    let mut result = FailureDomainAnalysis {
        scenarios: Vec::new(),
        operations: 0,
        output_entries: 0,
    };
    for domain in &inputs.ordered {
        let remaining = GraphBudget {
            max_operations: ceiling.max_operations - result.operations,
            max_output_entries: ceiling.max_output_entries - result.output_entries,
        };
        let loss = analyse_member_loss(
            projection,
            &inputs,
            &domain.node_id(),
            &domain.members,
            remaining,
        )?;
        result.operations += loss.analysis.operations;
        result.output_entries += loss.analysis.output_entries;
        result.scenarios.push(FailureScenario {
            domain: (**domain).clone(),
            graph: loss.graph,
            analysis: loss.analysis,
            lost_zones: loss.lost_zones,
        });
    }
    Ok(result)
}

// Shared by the independent-domain and bounded simultaneous-domain compilers. Keeping one
// validation and one union-loss projection avoids divergent treatment of zero witnesses,
// public-field tampering, unknown sensors, or overlapping dependencies.
pub(crate) struct FailureInputs<'a> {
    pub(crate) sensors: BTreeSet<&'a str>,
    pub(crate) observers: BTreeMap<&'a str, BTreeSet<&'a str>>,
    pub(crate) ordered: Vec<&'a FailureDomain>,
}

pub(crate) fn prepare_failure_inputs<'a>(
    projection: &'a SensorCoverageProjection,
    domains: &'a [FailureDomain],
) -> Result<FailureInputs<'a>, GraphError> {
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
    Ok(FailureInputs {
        sensors,
        observers,
        ordered: ordered.into_values().collect(),
    })
}

pub(crate) struct MemberLoss {
    pub(crate) graph: UndirectedGraph,
    pub(crate) analysis: BridgeAnalysis,
    pub(crate) lost_zones: Vec<String>,
}

pub(crate) fn analyse_member_loss(
    projection: &SensorCoverageProjection,
    inputs: &FailureInputs<'_>,
    node: &str,
    members: &BTreeSet<String>,
    budget: GraphBudget,
) -> Result<MemberLoss, GraphError> {
    let node = node.to_owned();
    let mut builder = GraphBuilder::new();
    builder
        .add_node(projection.plane.clone())
        .add_node(node.clone());
    builder.add_edge(projection.plane.clone(), node.clone());
    for sensor in &inputs.sensors {
        let sensor_node = format!("{SENSOR_PREFIX}{sensor}");
        builder.add_node(sensor_node.clone());
        let parent = if members.contains(*sensor) {
            &node
        } else {
            &projection.plane
        };
        builder.add_edge(parent.clone(), sensor_node);
    }
    let mut lost_zones = Vec::new();
    for (zone, watching) in &inputs.observers {
        let zone_node = format!("{ZONE_PREFIX}{zone}");
        builder.add_node(zone_node.clone());
        let mut member_observed = false;
        let mut survivor_observed = false;
        for sensor in watching {
            if members.contains(*sensor) {
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
    let analysis = analyse_bridges(&graph, Some(&projection.plane), budget)?;
    let mut expected: Vec<String> = members
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
    Ok(MemberLoss {
        graph,
        analysis,
        lost_zones,
    })
}

pub mod combinations {
    #![forbid(unsafe_code)]
    //! Bounded exhaustive combinations of the same owner-declared failure domains.
    //!
    //! Exhaustive, bounded simultaneous failures of owner-declared dependencies.
    //!
    //! Enumerates every nonempty combination of up to `k` declarations, unions its failed sensors,
    //! and runs the existing registered `ALG-BRIDGE-001` loss projection. This is not a new flow,
    //! probabilistic reliability, or general interdiction solver. In particular, overlapping power
    //! and network dependencies are required dependencies, never alternative paths in one graph.
    //!
    //! A complete report identifies the smallest enumerated combination that removes all retained
    //! observers of each zone. No cut within the requested bound is not evidence of independence,
    //! present coverage, or resilience to undeclared failures. Already-unwitnessed zones remain
    //! explicit and are never counted as new losses. Source authorization and capture-window
    //! selection belong to the caller, exactly as for independent failure-domain scenarios.

    use std::collections::{BTreeMap, BTreeSet};

    use fss_core::ContentDigest;

    use crate::coverage::SENSOR_PREFIX;
    use crate::failure_domains::{
        FailureDomain, FailureInputs, MAX_FAILURE_DOMAINS, MAX_FAILURE_OPERATIONS,
        MAX_FAILURE_OUTPUT_ENTRIES, analyse_member_loss, prepare_failure_inputs,
    };
    use crate::{BridgeAnalysis, GraphBudget, GraphBuilder, GraphError, SensorCoverageProjection};

    /// Hard ceiling on the complete scenario family, checked before enumeration or graph runs.
    /// Sixteen declarations admit all 136 singleton/pair scenarios, but not all triples.
    pub const MAX_FAILURE_COMBINATIONS: usize = 256;

    /// What the bounded search establishes about one known zone.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ZoneFailureMinimum {
        /// No qualifying witness existed before any simulated failure.
        InitiallyUnwitnessed,
        /// The first loss in cardinality-then-canonical-declaration order.
        Cut {
            /// Minimum number of declared dependencies whose simultaneous loss removes observers.
            failed_domains: usize,
            /// Index into [`FailureCombinationAnalysis::scenarios`].
            scenario_index: usize,
        },
        /// No enumerated combination removes all observers. Undeclared failures and larger
        /// combinations remain unexamined; this is not an unconditional resilience claim.
        NoCutWithinBound,
    }

    /// One complete simultaneous-loss scenario.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct FailureCombination {
        /// Indices into the report's canonical declarations, in ascending order.
        pub domain_indices: Vec<usize>,
        /// The same selection as a bit mask over at most sixteen canonical declarations.
        pub domain_mask: u16,
        /// Union of selected members; shared sensors occur once, in ascending identity order.
        pub failed_sensors: Vec<String>,
        /// Previously witnessed zones losing every observer, in ascending scope order.
        pub lost_zones: Vec<String>,
        /// Registered, bound-checked bridge analysis of the union-loss projection.
        /// Its input graph is reconstructible from the parent coverage and these declarations;
        /// full per-scenario input graphs are deliberately not retained in memory.
        pub analysis: BridgeAnalysis,
    }

    /// All requested combinations, or no report if any validation, scenario, or budget fails.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct FailureCombinationAnalysis {
        /// Complete declarations once, ordered by `(kind, id)`; members are canonical sets.
        pub domains: Vec<FailureDomain>,
        /// Digest of their canonical incidence graph, including otherwise irrelevant members.
        /// This graph binds declarations only; it is never traversed as a causal/failure graph.
        pub declarations_digest: ContentDigest,
        /// Digest of the parent coverage graph that supplied the exact observer sets.
        pub coverage_digest: ContentDigest,
        /// Requested bound, not silently reduced when a resource limit would be exceeded.
        pub max_failed_domains: usize,
        /// Every combination of sizes `1..=max_failed_domains`, cardinality first, then ascending
        /// tuples of canonical declaration indices. Equal-cardinality minima use this same order.
        pub scenarios: Vec<FailureCombination>,
        /// One explicit result per known zone, including initially-unwitnessed zones.
        pub zones: BTreeMap<String, ZoneFailureMinimum>,
        /// Combinations visited.
        pub scenario_visits: u64,
        /// Selected-domain members inspected while constructing unions, including repetitions.
        pub member_visits: u64,
        /// Sum of the registered bridge traversals' node visits and adjacency scans.
        pub graph_operations: u64,
        /// Sum of scenario visits, member visits, and registered graph operations.
        pub operations: u64,
        /// Declared identities, zone summaries, selected indices, failed sensors, lost zones,
        /// and all underlying bridge-output identities charged against the one output budget.
        pub output_entries: u64,
    }

    impl FailureCombinationAnalysis {
        /// Projection identity to use with a scenario's `analysis.witness` and the parent anchor.
        ///
        /// The parent *witness* digest, not only its graph digest, binds the authority anchor and
        /// capture-window selection. The declaration digest binds even unselected dependencies;
        /// `k` and the selection mask bind this bounded search and its exact scenario.
        ///
        /// # Errors
        /// An index outside this report is refused. The caller must verify that the supplied parent
        /// witness actually belongs to `coverage_digest` before publishing any scenario witness.
        pub fn projection_id(
            &self,
            scenario_index: usize,
            parent_witness_digest: ContentDigest,
        ) -> Result<String, GraphError> {
            let scenario = self.scenarios.get(scenario_index).ok_or_else(|| {
                GraphError::Inconsistent(
                    "failure combination index is outside the report".to_owned(),
                )
            })?;
            Ok(format!(
                "SensorCoverageGraph@failure-combinations:{}:{}:k{}:m{:04x}",
                parent_witness_digest.to_text(),
                self.declarations_digest.to_text(),
                self.max_failed_domains,
                scenario.domain_mask
            ))
        }
    }

    /// Number of scenarios, refused before work if the entire requested family cannot be admitted.
    fn scenario_count(domains: usize, maximum: usize) -> Result<usize, GraphError> {
        if domains > MAX_FAILURE_DOMAINS || maximum == 0 || maximum > domains {
            return Err(GraphError::TooLarge);
        }
        // domains <= 16: every intermediate is bounded by 16 * 2^16 on every target.
        let mut choose = 1_usize;
        let mut total = 0_usize;
        for size in 1..=maximum {
            choose = choose * (domains + 1 - size) / size;
            total += choose;
            if total > MAX_FAILURE_COMBINATIONS {
                return Err(GraphError::TooLarge);
            }
        }
        Ok(total)
    }

    fn charge(
        used: &mut u64,
        amount: u64,
        limit: u64,
        dimension: &'static str,
    ) -> Result<(), GraphError> {
        let next = used.checked_add(amount).ok_or(GraphError::TooLarge)?;
        if next > limit {
            return Err(GraphError::BudgetExhausted { dimension, limit });
        }
        *used = next;
        Ok(())
    }

    // The canonical graph format already owns strict IDs, ordering, and domain-separated hashing.
    // These edges encode owner assertions, not operational paths. Never use this graph to decide
    // whether a surviving power/network path exists: required dependencies do not work that way.
    fn declarations_digest(inputs: &FailureInputs<'_>) -> Result<ContentDigest, GraphError> {
        let mut builder = GraphBuilder::new();
        let mut members = BTreeSet::new();
        for domain in &inputs.ordered {
            let node = domain.node_id();
            builder.add_node(node.clone());
            for member in domain.members() {
                members.insert(member.as_str());
                builder.add_edge(node.clone(), format!("{SENSOR_PREFIX}{member}"));
            }
        }
        for member in members {
            builder.add_node(format!("{SENSOR_PREFIX}{member}"));
        }
        Ok(builder.build()?.digest())
    }

    // Advance a fixed-cardinality combination in lexicographic index order without recursion,
    // materializing the powerset, or scanning combinations outside the admitted bound.
    fn advance(indices: &mut [usize], domains: usize) -> bool {
        for position in (0..indices.len()).rev() {
            if indices[position] < domains - indices.len() + position {
                indices[position] += 1;
                for next in position + 1..indices.len() {
                    indices[next] = indices[next - 1] + 1;
                }
                return true;
            }
        }
        false
    }

    /// Analyze every simultaneous dependency-loss combination up to a caller-declared bound.
    ///
    /// The existing loss compiler contracts the *union* of members onto one cut vertex and checks
    /// the registered bridge answer against the original observer sets. A shared sensor is failed
    /// once. This preserves required-dependency semantics even for overlapping declarations.
    ///
    /// One aggregate budget covers the whole request; it is never reset between scenarios. Hard
    /// ceilings are 16 declarations, 256 scenarios, the existing failure-input limits, one million
    /// charged operations, and 100,000 output entries. Validation/canonical ordering is bounded by
    /// the input ceilings; charged operations are the dominant enumeration/union/traversal work.
    /// Full scenario graphs are temporary, not accumulated. No partial report is returned.
    ///
    /// # Errors
    /// Invalid/duplicate declarations, unknown sensors, tampered public projection fields, invalid
    /// or oversized combination bounds, and any aggregate resource exhaustion fail closed.
    pub fn analyse_failure_combinations(
        projection: &SensorCoverageProjection,
        domains: &[FailureDomain],
        max_failed_domains: usize,
        budget: GraphBudget,
    ) -> Result<FailureCombinationAnalysis, GraphError> {
        let count = scenario_count(domains.len(), max_failed_domains)?;
        let inputs = prepare_failure_inputs(projection, domains)?;
        let ceiling = GraphBudget {
            max_operations: budget.max_operations.min(MAX_FAILURE_OPERATIONS),
            max_output_entries: budget.max_output_entries.min(MAX_FAILURE_OUTPUT_ENTRIES),
        };
        let mut output_entries = 0;
        let metadata_entries = inputs.observers.len()
            + inputs.ordered.len()
            + inputs
                .ordered
                .iter()
                .map(|domain| domain.members().len())
                .sum::<usize>();
        charge(
            &mut output_entries,
            metadata_entries as u64,
            ceiling.max_output_entries,
            "output_entries",
        )?;
        let digest = declarations_digest(&inputs)?;
        let mut zones: BTreeMap<String, ZoneFailureMinimum> = inputs
            .observers
            .iter()
            .map(|(zone, observers)| {
                let state = if observers.is_empty() {
                    ZoneFailureMinimum::InitiallyUnwitnessed
                } else {
                    ZoneFailureMinimum::NoCutWithinBound
                };
                ((*zone).to_owned(), state)
            })
            .collect();
        let mut scenarios = Vec::with_capacity(count);
        let mut operations = 0;
        let mut member_visits = 0;
        let mut graph_operations = 0;
        for size in 1..=max_failed_domains {
            let mut indices: Vec<usize> = (0..size).collect();
            loop {
                charge(&mut operations, 1, ceiling.max_operations, "operations")?;
                let mut members = BTreeSet::new();
                let mut mask = 0_u16;
                for &index in &indices {
                    mask |= 1_u16 << index;
                    for member in inputs.ordered[index].members() {
                        charge(&mut operations, 1, ceiling.max_operations, "operations")?;
                        member_visits += 1;
                        members.insert(member.clone());
                    }
                }
                charge(
                    &mut output_entries,
                    (indices.len() + members.len()) as u64,
                    ceiling.max_output_entries,
                    "output_entries",
                )?;
                let remaining = GraphBudget {
                    max_operations: ceiling.max_operations - operations,
                    max_output_entries: ceiling.max_output_entries - output_entries,
                };
                let node = format!("failure/combined/{mask:04x}");
                let loss = analyse_member_loss(projection, &inputs, &node, &members, remaining)?;
                charge(
                    &mut operations,
                    loss.analysis.operations,
                    ceiling.max_operations,
                    "operations",
                )?;
                graph_operations += loss.analysis.operations;
                charge(
                    &mut output_entries,
                    loss.analysis.output_entries + loss.lost_zones.len() as u64,
                    ceiling.max_output_entries,
                    "output_entries",
                )?;
                for zone in &loss.lost_zones {
                    let state = zones.get_mut(zone).ok_or_else(|| {
                        GraphError::Inconsistent("loss names an unknown zone".to_owned())
                    })?;
                    if *state == ZoneFailureMinimum::InitiallyUnwitnessed {
                        return Err(GraphError::Inconsistent(
                            "an initially unwitnessed zone was counted as a new loss".to_owned(),
                        ));
                    }
                    if *state == ZoneFailureMinimum::NoCutWithinBound {
                        *state = ZoneFailureMinimum::Cut {
                            failed_domains: size,
                            scenario_index: scenarios.len(),
                        };
                    }
                }
                scenarios.push(FailureCombination {
                    domain_indices: indices.clone(),
                    domain_mask: mask,
                    failed_sensors: members.into_iter().collect(),
                    lost_zones: loss.lost_zones,
                    analysis: loss.analysis,
                });
                if !advance(&mut indices, inputs.ordered.len()) {
                    break;
                }
            }
        }
        if scenarios.len() != count {
            return Err(GraphError::Inconsistent(
                "failure combination enumeration was incomplete".to_owned(),
            ));
        }
        Ok(FailureCombinationAnalysis {
            domains: inputs
                .ordered
                .iter()
                .map(|domain| (**domain).clone())
                .collect(),
            declarations_digest: digest,
            coverage_digest: projection.graph.digest(),
            max_failed_domains,
            scenario_visits: scenarios.len() as u64,
            scenarios,
            zones,
            member_visits,
            graph_operations,
            operations,
            output_entries,
        })
    }
}

#[cfg(test)]
mod combination_tests {
    #![forbid(unsafe_code)]
    //! Simultaneous dependency failures: exact observer-set oracle, complete enumeration,
    //! conservative minima, provenance binding, and whole-request resource bounds.

    use std::collections::{BTreeMap, BTreeSet};

    use crate::failure_domains::combinations::{
        FailureCombinationAnalysis, ZoneFailureMinimum, analyse_failure_combinations,
    };
    use crate::failure_domains::{FailureDomain, FailureDomainKind, analyse_failure_domains};
    use crate::{CoverageObservation, GraphBudget, GraphError, SensorCoverageProjection};
    use fss_core::ContentDigest;

    fn budget() -> GraphBudget {
        GraphBudget {
            max_operations: u64::MAX,
            max_output_entries: u64::MAX,
        }
    }

    fn projection(facts: &[(&str, &str, u64)]) -> Result<SensorCoverageProjection, GraphError> {
        let facts: Vec<_> = facts
            .iter()
            .map(|(sensor, zone, witnesses)| CoverageObservation {
                sensor_id: (*sensor).to_owned(),
                zone_scope: (*zone).to_owned(),
                witnesses: *witnesses,
            })
            .collect();
        SensorCoverageProjection::build("site:test", &facts)
    }

    fn domain(id: &str, members: &[&str]) -> Result<FailureDomain, GraphError> {
        FailureDomain::new(
            FailureDomainKind::Power,
            id,
            &members
                .iter()
                .map(|member| (*member).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    fn two_sensor_projection() -> Result<SensorCoverageProjection, GraphError> {
        projection(&[("a", "rear", 1), ("b", "rear", 1)])
    }

    // Oracle operates on the original facts and set union, never on the transformed graph or its
    // bridge result. A zero-observer zone is not newly lost even though the empty set is a subset.
    fn expected_lost(
        projection: &SensorCoverageProjection,
        domains: &[FailureDomain],
        indices: &[usize],
    ) -> Vec<String> {
        let failed: BTreeSet<&str> = indices
            .iter()
            .flat_map(|&index| domains[index].members().iter().map(String::as_str))
            .collect();
        let mut observers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for ((sensor, zone), count) in &projection.witnesses {
            if *count > 0 {
                observers.entry(zone).or_default().insert(sensor);
            }
        }
        observers
            .into_iter()
            .filter(|(_, watching)| !watching.is_empty() && watching.is_subset(&failed))
            .map(|(zone, _)| zone.to_owned())
            .collect()
    }

    #[test]
    fn joint_loss_finds_gap_that_every_independent_scenario_misses() -> Result<(), GraphError> {
        let source = two_sensor_projection()?;
        let domains = [domain("circuit-a", &["a"])?, domain("circuit-b", &["b"])?];
        let independent = analyse_failure_domains(&source, &domains, budget())?;
        assert!(
            independent
                .scenarios
                .iter()
                .all(|scenario| scenario.lost_zones.is_empty())
        );
        let result = analyse_failure_combinations(&source, &domains, 2, budget())?;
        assert_eq!(result.scenarios.len(), 3);
        assert_eq!(result.scenarios[2].domain_indices, vec![0, 1]);
        assert_eq!(result.scenarios[2].failed_sensors, vec!["a", "b"]);
        assert_eq!(result.scenarios[2].lost_zones, vec!["rear"]);
        assert_eq!(
            result.zones["rear"],
            ZoneFailureMinimum::Cut {
                failed_domains: 2,
                scenario_index: 2
            }
        );
        Ok(())
    }

    #[test]
    fn overlapping_required_dependencies_are_unioned_not_alternative_paths()
    -> Result<(), GraphError> {
        let source = projection(&[
            ("a", "rear", 1),
            ("b", "rear", 1),
            ("c", "rear", 1),
            ("spare", "front", 1),
            ("a", "blind", 0),
        ])?;
        let domains = [
            FailureDomain::new(
                FailureDomainKind::Network,
                "switch",
                &["a".into(), "b".into()],
            )?,
            domain("circuit", &["b", "c"])?,
        ];
        let result = analyse_failure_combinations(&source, &domains, 2, budget())?;
        assert_eq!(result.scenarios[2].failed_sensors, vec!["a", "b", "c"]);
        assert_eq!(result.scenarios[2].lost_zones, vec!["rear"]);
        assert_eq!(result.zones["front"], ZoneFailureMinimum::NoCutWithinBound);
        assert_eq!(
            result.zones["blind"],
            ZoneFailureMinimum::InitiallyUnwitnessed
        );
        assert!(
            result
                .scenarios
                .iter()
                .all(|scenario| !scenario.lost_zones.iter().any(|z| z == "blind"))
        );
        Ok(())
    }

    #[test]
    fn no_cut_within_bound_does_not_claim_larger_combinations_were_tested() -> Result<(), GraphError>
    {
        let source = two_sensor_projection()?;
        let domains = [domain("a", &["a"])?, domain("b", &["b"])?];
        let result = analyse_failure_combinations(&source, &domains, 1, budget())?;
        assert_eq!(result.max_failed_domains, 1);
        assert_eq!(result.scenarios.len(), 2);
        assert_eq!(result.zones["rear"], ZoneFailureMinimum::NoCutWithinBound);
        let larger = analyse_failure_combinations(&source, &domains, 2, budget())?;
        assert!(matches!(
            larger.zones["rear"],
            ZoneFailureMinimum::Cut {
                failed_domains: 2,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn minimum_prefers_cardinality_then_canonical_declaration_tuple() -> Result<(), GraphError> {
        let source = two_sensor_projection()?;
        let domains = [
            domain("z", &["a", "b"])?,
            domain("a", &["a", "b"])?,
            domain("m", &["a"])?,
        ];
        let result = analyse_failure_combinations(&source, &domains, 3, budget())?;
        assert_eq!(result.domains[0].id(), "a");
        assert_eq!(
            result.zones["rear"],
            ZoneFailureMinimum::Cut {
                failed_domains: 1,
                scenario_index: 0
            }
        );
        assert_eq!(result.scenarios[0].domain_indices, vec![0]);
        Ok(())
    }

    #[test]
    fn input_permutations_preserve_every_answer_digest_and_counter() -> Result<(), GraphError> {
        let first = projection(&[("a", "rear", 1), ("b", "rear", 2), ("a", "blind", 0)])?;
        let second = projection(&[("a", "blind", 0), ("b", "rear", 2), ("a", "rear", 1)])?;
        let forward = [domain("a", &["a", "b"])?, domain("b", &["b"])?];
        let reverse = [domain("b", &["b"])?, domain("a", &["b", "a"])?];
        assert_eq!(
            analyse_failure_combinations(&first, &forward, 2, budget())?,
            analyse_failure_combinations(&second, &reverse, 2, budget())?
        );
        Ok(())
    }

    #[test]
    fn full_declarations_bind_same_union_and_parent_witness_binds_scope() -> Result<(), GraphError>
    {
        let source = two_sensor_projection()?;
        let first = analyse_failure_combinations(
            &source,
            &[domain("a", &["a"])?, domain("b", &["b"])?],
            2,
            budget(),
        )?;
        let changed = analyse_failure_combinations(
            &source,
            &[domain("a", &["a", "b"])?, domain("b", &["b"])?],
            2,
            budget(),
        )?;
        // Both joint scenarios fail the same sensors and have identical transformed topology.
        assert_eq!(
            first.scenarios[2].analysis.input_digest,
            changed.scenarios[2].analysis.input_digest
        );
        assert_ne!(first.declarations_digest, changed.declarations_digest);
        let parent = ContentDigest::sha256(b"parent coverage witness");
        assert_ne!(
            first.projection_id(2, parent)?,
            changed.projection_id(2, parent)?
        );
        assert_ne!(
            first.projection_id(2, parent)?,
            first.projection_id(2, ContentDigest::sha256(b"other capture window"))?
        );
        assert!(first.projection_id(2, parent)?.len() <= 256);
        assert!(first.projection_id(3, parent).is_err());
        Ok(())
    }

    #[test]
    fn unknown_members_duplicates_and_projection_tampering_are_refused() -> Result<(), GraphError> {
        let source = two_sensor_projection()?;
        assert!(matches!(
            analyse_failure_combinations(&source, &[domain("x", &["unknown"])?], 1, budget()),
            Err(GraphError::UnknownNode(_))
        ));
        let same = domain("x", &["a"])?;
        assert!(matches!(
            analyse_failure_combinations(&source, &[same.clone(), same], 1, budget()),
            Err(GraphError::DuplicateNode(_))
        ));
        let mut changed = source.clone();
        changed.witnesses.insert(("a".into(), "rear".into()), 0);
        assert!(matches!(
            analyse_failure_combinations(&changed, &[domain("x", &["a"])?], 1, budget()),
            Err(GraphError::Inconsistent(_))
        ));
        Ok(())
    }

    #[test]
    fn scenario_ceiling_refuses_the_whole_request_instead_of_truncating() -> Result<(), GraphError>
    {
        let source = projection(&[("a", "rear", 1)])?;
        let domains = (0..16)
            .map(|i| domain(&format!("d{i:02}"), &["a"]))
            .collect::<Result<Vec<_>, _>>()?;
        let result = analyse_failure_combinations(&source, &domains, 2, budget())?;
        assert_eq!(result.scenarios.len(), 136);
        assert!(matches!(
            analyse_failure_combinations(&source, &domains, 3, budget()),
            Err(GraphError::TooLarge)
        ));
        assert!(matches!(
            analyse_failure_combinations(&source, &domains, 0, budget()),
            Err(GraphError::TooLarge)
        ));
        assert!(matches!(
            analyse_failure_combinations(&source, &domains, 17, budget()),
            Err(GraphError::TooLarge)
        ));
        assert!(matches!(
            analyse_failure_combinations(&source, &[], 1, budget()),
            Err(GraphError::TooLarge)
        ));
        Ok(())
    }

    #[test]
    fn operation_and_output_budgets_are_aggregate_and_exact_at_the_boundary()
    -> Result<(), GraphError> {
        let source = two_sensor_projection()?;
        let domains = [domain("a", &["a"])?, domain("b", &["b"])?];
        let result = analyse_failure_combinations(&source, &domains, 2, budget())?;
        assert_eq!(
            result.operations,
            result.scenario_visits + result.member_visits + result.graph_operations
        );
        let exact = GraphBudget {
            max_operations: result.operations,
            max_output_entries: result.output_entries,
        };
        assert_eq!(
            analyse_failure_combinations(&source, &domains, 2, exact)?,
            result
        );
        assert!(matches!(
            analyse_failure_combinations(
                &source,
                &domains,
                2,
                GraphBudget {
                    max_operations: exact.max_operations - 1,
                    ..exact
                }
            ),
            Err(GraphError::BudgetExhausted {
                dimension: "operations",
                ..
            })
        ));
        assert!(matches!(
            analyse_failure_combinations(
                &source,
                &domains,
                2,
                GraphBudget {
                    max_output_entries: exact.max_output_entries - 1,
                    ..exact
                }
            ),
            Err(GraphError::BudgetExhausted {
                dimension: "output_entries",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn all_zero_witness_facts_remain_initially_unwitnessed() -> Result<(), GraphError> {
        let source = projection(&[("a", "rear", 0), ("b", "front", 0)])?;
        let result = analyse_failure_combinations(
            &source,
            &[domain("a", &["a"])?, domain("b", &["b"])?],
            2,
            budget(),
        )?;
        assert!(
            result
                .zones
                .values()
                .all(|state| *state == ZoneFailureMinimum::InitiallyUnwitnessed)
        );
        assert!(
            result
                .scenarios
                .iter()
                .all(|scenario| scenario.lost_zones.is_empty())
        );
        Ok(())
    }

    fn verify_oracle(source: &SensorCoverageProjection, result: &FailureCombinationAnalysis) {
        let masks: Vec<_> = result
            .scenarios
            .iter()
            .map(|scenario| scenario.domain_mask)
            .collect();
        assert_eq!(masks, vec![1, 2, 4, 3, 5, 6, 7]);
        for scenario in &result.scenarios {
            assert_eq!(
                scenario.lost_zones,
                expected_lost(source, &result.domains, &scenario.domain_indices)
            );
        }
        for (zone, state) in &result.zones {
            let first_loss = result.scenarios.iter().position(|scenario| {
                expected_lost(source, &result.domains, &scenario.domain_indices).contains(zone)
            });
            match first_loss {
                Some(index) => assert_eq!(
                    *state,
                    ZoneFailureMinimum::Cut {
                        failed_domains: result.scenarios[index].domain_indices.len(),
                        scenario_index: index,
                    }
                ),
                None if zone == "blind" => {
                    assert_eq!(*state, ZoneFailureMinimum::InitiallyUnwitnessed)
                }
                None => assert_eq!(*state, ZoneFailureMinimum::NoCutWithinBound),
            }
        }
    }

    #[test]
    fn exhaustive_three_sensor_three_domain_memberships_match_set_union_oracle()
    -> Result<(), GraphError> {
        let source = projection(&[
            ("a", "all", 1),
            ("b", "all", 1),
            ("c", "all", 1),
            ("a", "pair", 1),
            ("b", "pair", 1),
            ("c", "single", 1),
            ("a", "blind", 0),
        ])?;
        let names = ["a", "b", "c"];
        for first in 1..8_u8 {
            for second in 1..8_u8 {
                for third in 1..8_u8 {
                    let mut domains = Vec::new();
                    for (index, mask) in [first, second, third].into_iter().enumerate() {
                        let members: Vec<_> = names
                            .iter()
                            .enumerate()
                            .filter(|(bit, _)| mask & (1_u8 << *bit) != 0)
                            .map(|(_, name)| *name)
                            .collect();
                        domains.push(domain(&format!("d{index}"), &members)?);
                    }
                    let result = analyse_failure_combinations(&source, &domains, 3, budget())?;
                    verify_oracle(&source, &result);
                }
            }
        }
        Ok(())
    }
}
