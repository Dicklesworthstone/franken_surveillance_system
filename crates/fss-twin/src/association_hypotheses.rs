#![forbid(unsafe_code)]
//! Exact factorized partial matchings over source-derived association candidates.
//!
//! Enumeration order is not a ranking. An unmatched target may have been missed;
//! an unmatched detection may be clutter, a duplicate, or an unrepresented target.

use crate::ContactObservation;
use crate::association::{AssociationError, AssociationGraph, MAX_ASSOCIATION_ITEMS};
use fss_geometry::WorkBudget;

/// Explicit detector/observation-partition assumption and representation budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignmentPolicy {
    /// Owner's record asserting at most one detection per target in this exposure.
    /// This is a retained assumption reference, not proof that merged blobs cannot occur.
    pub one_to_one_basis: [u8; 32],
    /// 1..=1024 fully materialized alternatives per connected component.
    pub maximum_per_factor: usize,
    /// 1..=4096 materialized alternatives across the complete result.
    pub maximum_materialized: usize,
}

/// One conditional identity link. Constructing it is a proposal, never authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AssignmentLink {
    /// Anonymous source track ID in the bound graph.
    pub track: u64,
    /// Detection-local ID in that graph's exact camera exposure.
    pub detection: u64,
}

/// Complete partial matching within its declared component or selection scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssociationAssignment {
    links: Vec<AssignmentLink>,
    unmatched_tracks: Vec<u64>,
    unmatched_detections: Vec<u64>,
}
impl AssociationAssignment {
    /// One-to-one links, ordered by track ID. No confidence is implied.
    pub fn links(&self) -> &[AssignmentLink] {
        &self.links
    }
    /// Unassigned source tracks, not observations that targets disappeared.
    pub fn unmatched_tracks(&self) -> &[u64] {
        &self.unmatched_tracks
    }
    /// Unassigned proposals, not automatically allocated new identities.
    pub fn unmatched_detections(&self) -> &[u64] {
        &self.unmatched_detections
    }
}

/// A representation ceiling, distinguished from actual work exhaustion or cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImplicitReason {
    /// This component has more alternatives than its explicit-list allowance.
    FactorLimit,
    /// The total result's explicit-list allowance is insufficient for this component.
    TotalLimit,
}

/// Exact representation: either all alternatives or the full matching constraint family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactorAlternatives {
    /// All partial matchings, including the all-unmatched assignment; never a prefix.
    Explicit(Vec<AssociationAssignment>),
    /// ALL partial one-to-one matchings over this factor's complete `allowed_links`.
    /// No enumerated prefix is exposed and no alternative is removed.
    Implicit(ImplicitReason),
}

/// A connected component of mutually competing candidate identity links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssociationFactor {
    tracks: Vec<u64>,
    detections: Vec<u64>,
    allowed_links: Vec<AssignmentLink>,
    alternatives: FactorAlternatives,
}
impl AssociationFactor {
    /// Complete component source scope.
    pub fn tracks(&self) -> &[u64] {
        &self.tracks
    }
    /// Complete component detection scope.
    pub fn detections(&self) -> &[u64] {
        &self.detections
    }
    /// Every possible edge, including unresolved geometry; pair diagnostics remain in the graph.
    pub fn allowed_links(&self) -> &[AssignmentLink] {
        &self.allowed_links
    }
    /// Complete explicit or implicit matching family; never a ranked top-k result.
    pub fn alternatives(&self) -> &FactorAlternatives {
        &self.alternatives
    }
}

/// Coupled association alternatives borrowing the immutable source graph.
/// Factorization is combinatorial, not a claim of statistical independence.
#[derive(Debug)]
pub struct AssociationHypotheses<'a> {
    graph: &'a AssociationGraph,
    policy: AssignmentPolicy,
    factors: Vec<AssociationFactor>,
    joint_count: Option<u128>,
}
impl<'a> AssociationHypotheses<'a> {
    /// Original source receipts, hypotheses, camera frame and all pair diagnostics.
    pub fn graph(&self) -> &'a AssociationGraph {
        self.graph
    }
    /// Retained one-to-one assumption and exact representation policy.
    pub fn policy(&self) -> AssignmentPolicy {
        self.policy
    }
    /// Components whose matching families combine by Cartesian product.
    pub fn factors(&self) -> &[AssociationFactor] {
        &self.factors
    }
    /// Exact count when all factors were enumerated and the product fits u128.
    /// None is unknown, not zero. The empty graph has one empty assignment.
    pub fn joint_count(&self) -> Option<u128> {
        self.joint_count
    }

    /// Check an explicit proposed global partial matching even for implicit factors.
    /// This establishes structural membership only, not physical identity or activation.
    pub fn check_assignment(
        &self,
        links: &[AssignmentLink],
        budget: &mut WorkBudget<'_>,
    ) -> Result<AssociationSelection<'a>, AssociationError> {
        budget.charge(0)?;
        let topology = Topology::from_graph(self.graph, budget)?;
        if links.len() > topology.tracks.len().min(topology.detections.len()) {
            return Err(AssociationError::InvalidInput);
        }
        let mut choices = [None; MAX_ASSOCIATION_ITEMS];
        let mut used = 0_u32;
        for link in links {
            budget.charge(16)?;
            let t = topology
                .tracks
                .binary_search(&link.track)
                .map_err(|_| AssociationError::InvalidInput)?;
            let d = topology
                .detections
                .binary_search(&link.detection)
                .map_err(|_| AssociationError::InvalidInput)?;
            let bit = 1_u32 << d;
            if choices[t].is_some() || used & bit != 0 || topology.forward[t] & bit == 0 {
                return Err(AssociationError::InvalidInput);
            }
            choices[t] = Some(d);
            used |= bit;
        }
        let domain = Domain {
            tracks: (0..topology.tracks.len()).collect(),
            detections: (0..topology.detections.len()).collect(),
        };
        let assignment = materialize(&topology, &domain, &choices, used, budget)?;
        budget.charge(0)?;
        Ok(AssociationSelection {
            graph: self.graph,
            policy: self.policy,
            assignment,
        })
    }
}

/// Proposed assignment bound to its source graph; no tracker has been modified.
#[derive(Debug)]
pub struct AssociationSelection<'a> {
    graph: &'a AssociationGraph,
    policy: AssignmentPolicy,
    assignment: AssociationAssignment,
}
impl AssociationSelection<'_> {
    /// Structurally admissible proposal, including all unmatched input IDs.
    pub fn assignment(&self) -> &AssociationAssignment {
        &self.assignment
    }
    /// Original basis; call `check_current` before later consuming this proposal.
    pub fn graph(&self) -> &AssociationGraph {
        self.graph
    }
    /// The one-to-one assumption under which membership was checked.
    pub fn policy(&self) -> AssignmentPolicy {
        self.policy
    }

    /// Prepare source observations for the explicitly selected links, without ingestion.
    /// Caller must separately retain/admit association evidence, revalidate the graph,
    /// and commit updates through the existing owner. Original contact evidence survives.
    pub fn observations(
        &self,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Vec<ContactObservation>, AssociationError> {
        budget.charge(0)?;
        let mut output = reserved(self.assignment.links.len())?;
        let frame = self.graph.frame();
        for link in &self.assignment.links {
            budget.charge(self.graph.detections().len() as u64 + 1)?;
            let d = self
                .graph
                .detections()
                .iter()
                .find(|d| d.detection().id == link.detection)
                .ok_or(AssociationError::InvalidInput)?
                .detection();
            output.push(ContactObservation {
                evidence: d.evidence,
                track: link.track,
                camera: frame.camera.camera,
                exposure: frame.exposure,
                image_domain: frame.camera.image_domain,
                clock: frame.camera.clock,
                capture: frame.capture,
                pixel_min: d.pixel_min,
                pixel_max: d.pixel_max,
                visible_contact: d.visible_contact,
            });
        }
        budget.charge(0)?;
        Ok(output)
    }
}

/// Factor the complete candidate graph and retain every partial one-to-one matching.
///
/// Connected components prevent exponential cross-products from being materialized.
/// A dense component that exceeds its list ceiling remains an exact implicit family,
/// not a successful truncated list. Real work exhaustion and cancellation still fail.
/// No nearest, cheapest, largest-cardinality, or most likely assignment is selected.
pub fn factorize_associations<'a>(
    graph: &'a AssociationGraph,
    policy: AssignmentPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<AssociationHypotheses<'a>, AssociationError> {
    budget.charge(0)?;
    if policy.one_to_one_basis == [0; 32]
        || !(1..=1024).contains(&policy.maximum_per_factor)
        || !(1..=4096).contains(&policy.maximum_materialized)
    {
        return Err(AssociationError::InvalidInput);
    }
    let topology = Topology::from_graph(graph, budget)?;
    let domains = topology.components(budget)?;
    let mut factors = reserved(domains.len())?;
    let mut materialized = 0;
    let mut joint_count = Some(1_u128);
    for domain in domains {
        let mut tracks = reserved(domain.tracks.len())?;
        let mut detections = reserved(domain.detections.len())?;
        let mut allowed_links = reserved(domain.tracks.len() * domain.detections.len())?;
        for &t in &domain.tracks {
            tracks.push(topology.tracks[t]);
            for &d in &domain.detections {
                budget.charge(1)?;
                if topology.forward[t] & (1_u32 << d) != 0 {
                    allowed_links.push(AssignmentLink {
                        track: topology.tracks[t],
                        detection: topology.detections[d],
                    });
                }
            }
        }
        for &d in &domain.detections {
            detections.push(topology.detections[d]);
        }
        let remaining = policy.maximum_materialized - materialized;
        let limit = remaining.min(policy.maximum_per_factor);
        let alternatives = if let Some(all) = enumerate(&topology, &domain, limit, budget)? {
            materialized += all.len();
            joint_count = joint_count.and_then(|n| n.checked_mul(all.len() as u128));
            FactorAlternatives::Explicit(all)
        } else {
            joint_count = None;
            FactorAlternatives::Implicit(if remaining < policy.maximum_per_factor {
                ImplicitReason::TotalLimit
            } else {
                ImplicitReason::FactorLimit
            })
        };
        factors.push(AssociationFactor {
            tracks,
            detections,
            allowed_links,
            alternatives,
        });
    }
    budget.charge(0)?;
    Ok(AssociationHypotheses {
        graph,
        policy,
        factors,
        joint_count,
    })
}

struct Domain {
    tracks: Vec<usize>,
    detections: Vec<usize>,
}
struct Topology {
    tracks: Vec<u64>,
    detections: Vec<u64>,
    forward: [u32; MAX_ASSOCIATION_ITEMS],
    reverse: [u32; MAX_ASSOCIATION_ITEMS],
}
impl Topology {
    fn from_graph(
        graph: &AssociationGraph,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, AssociationError> {
        let mut tracks = reserved(graph.sources().len())?;
        let mut detections = reserved(graph.detections().len())?;
        tracks.extend(graph.sources().iter().map(|s| s.receipt().scope.track));
        detections.extend(graph.detections().iter().map(|d| d.detection().id));
        let n = detections.len();
        if graph.pairs().len() != tracks.len() * n {
            return Err(AssociationError::InvalidInput);
        }
        let mut value = Self {
            tracks,
            detections,
            forward: [0; MAX_ASSOCIATION_ITEMS],
            reverse: [0; MAX_ASSOCIATION_ITEMS],
        };
        for (i, pair) in graph.pairs().iter().enumerate() {
            budget.charge(1)?;
            if pair.possible() {
                value.forward[i / n] |= 1_u32 << (i % n);
                value.reverse[i % n] |= 1_u32 << (i / n);
            }
        }
        Ok(value)
    }
    fn components(&self, budget: &mut WorkBudget<'_>) -> Result<Vec<Domain>, AssociationError> {
        let n = self.tracks.len();
        let m = self.detections.len();
        let mut seen = [false; 2 * MAX_ASSOCIATION_ITEMS];
        let mut output = reserved(n + m)?;
        for seed in 0..n + m {
            if seen[seed] {
                continue;
            }
            let mut stack = reserved(n + m)?;
            let mut domain = Domain {
                tracks: reserved(n)?,
                detections: reserved(m)?,
            };
            seen[seed] = true;
            stack.push(seed);
            while let Some(node) = stack.pop() {
                budget.charge((n + m + 1) as u64)?;
                if node < n {
                    domain.tracks.push(node);
                    for d in 0..m {
                        if self.forward[node] & (1_u32 << d) != 0 && !seen[n + d] {
                            seen[n + d] = true;
                            stack.push(n + d);
                        }
                    }
                } else {
                    let d = node - n;
                    domain.detections.push(d);
                    for (t, s) in seen[..n].iter_mut().enumerate() {
                        if self.reverse[d] & (1_u32 << t) != 0 && !*s {
                            *s = true;
                            stack.push(t);
                        }
                    }
                }
            }
            domain.tracks.sort_unstable();
            domain.detections.sort_unstable();
            output.push(domain);
        }
        Ok(output)
    }
}

struct Enumerator<'a> {
    topology: &'a Topology,
    domain: &'a Domain,
    choices: [Option<usize>; MAX_ASSOCIATION_ITEMS],
    output: Vec<AssociationAssignment>,
    limit: usize,
}
impl Enumerator<'_> {
    fn visit(
        &mut self,
        depth: usize,
        used: u32,
        budget: &mut WorkBudget<'_>,
    ) -> Result<bool, AssociationError> {
        budget.charge(1)?;
        if depth == self.domain.tracks.len() {
            if self.output.len() == self.limit {
                return Ok(false);
            }
            self.output.push(materialize(
                self.topology,
                self.domain,
                &self.choices,
                used,
                budget,
            )?);
            return Ok(true);
        }
        self.choices[depth] = None;
        if !self.visit(depth + 1, used, budget)? {
            return Ok(false);
        }
        let t = self.domain.tracks[depth];
        for index in 0..self.domain.detections.len() {
            budget.charge(1)?;
            let d = self.domain.detections[index];
            let bit = 1_u32 << d;
            if used & bit == 0 && self.topology.forward[t] & bit != 0 {
                self.choices[depth] = Some(d);
                if !self.visit(depth + 1, used | bit, budget)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
fn enumerate(
    topology: &Topology,
    domain: &Domain,
    limit: usize,
    budget: &mut WorkBudget<'_>,
) -> Result<Option<Vec<AssociationAssignment>>, AssociationError> {
    if limit == 0 {
        return Ok(None);
    }
    let mut search = Enumerator {
        topology,
        domain,
        choices: [None; MAX_ASSOCIATION_ITEMS],
        output: reserved(limit)?,
        limit,
    };
    if search.visit(0, 0, budget)? {
        Ok(Some(search.output))
    } else {
        Ok(None)
    }
}
fn materialize(
    topology: &Topology,
    domain: &Domain,
    choices: &[Option<usize>; MAX_ASSOCIATION_ITEMS],
    used: u32,
    budget: &mut WorkBudget<'_>,
) -> Result<AssociationAssignment, AssociationError> {
    budget.charge((domain.tracks.len() + domain.detections.len()) as u64)?;
    let mut links = reserved(domain.tracks.len())?;
    let mut unmatched_tracks = reserved(domain.tracks.len())?;
    let mut unmatched_detections = reserved(domain.detections.len())?;
    for (i, &t) in domain.tracks.iter().enumerate() {
        if let Some(d) = choices[i] {
            links.push(AssignmentLink {
                track: topology.tracks[t],
                detection: topology.detections[d],
            });
        } else {
            unmatched_tracks.push(topology.tracks[t]);
        }
    }
    for &d in &domain.detections {
        if used & (1_u32 << d) == 0 {
            unmatched_detections.push(topology.detections[d]);
        }
    }
    Ok(AssociationAssignment {
        links,
        unmatched_tracks,
        unmatched_detections,
    })
}
fn reserved<T>(count: usize) -> Result<Vec<T>, AssociationError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| AssociationError::Limit)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn topology(n: usize, m: usize, edges: &[(usize, usize)]) -> Topology {
        let mut value = Topology {
            tracks: (1..=n as u64).collect(),
            detections: (101..101 + m as u64).collect(),
            forward: [0; MAX_ASSOCIATION_ITEMS],
            reverse: [0; MAX_ASSOCIATION_ITEMS],
        };
        for &(t, d) in edges {
            value.forward[t] |= 1_u32 << d;
            value.reverse[d] |= 1_u32 << t;
        }
        value
    }
    fn full(n: usize, m: usize) -> Domain {
        Domain {
            tracks: (0..n).collect(),
            detections: (0..m).collect(),
        }
    }

    #[test]
    fn every_three_by_three_graph_matches_an_independent_edge_subset_oracle()
    -> Result<(), AssociationError> {
        let mut budget = WorkBudget::new(100_000_000);
        for mask in 0_u16..512 {
            let edges: Vec<_> = (0..9)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| (i / 3, i % 3))
                .collect();
            let topo = topology(3, 3, &edges);
            let got =
                enumerate(&topo, &full(3, 3), 34, &mut budget)?.ok_or(AssociationError::Limit)?;
            let actual: BTreeSet<_> = got.iter().map(|a| a.links.clone()).collect();
            assert_eq!(actual.len(), got.len());
            let mut expected = BTreeSet::new();
            for chosen in 0_u16..512 {
                if chosen & !mask != 0 {
                    continue;
                }
                let selected: Vec<_> = (0..9)
                    .filter(|i| chosen & (1 << i) != 0)
                    .map(|i| (i / 3, i % 3))
                    .collect();
                let rows: BTreeSet<_> = selected.iter().map(|e| e.0).collect();
                let columns: BTreeSet<_> = selected.iter().map(|e| e.1).collect();
                if rows.len() == selected.len() && columns.len() == selected.len() {
                    expected.insert(
                        selected
                            .iter()
                            .map(|&(t, d)| AssignmentLink {
                                track: t as u64 + 1,
                                detection: d as u64 + 101,
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
            assert_eq!(actual, expected);
            let mut product = 1;
            for component in topo.components(&mut budget)? {
                product *= enumerate(&topo, &component, 34, &mut budget)?
                    .ok_or(AssociationError::Limit)?
                    .len();
            }
            assert_eq!(product, expected.len());
        }
        Ok(())
    }
    #[test]
    fn exact_list_boundary_does_not_expose_an_incomplete_prefix() -> Result<(), AssociationError> {
        let edges: Vec<_> = (0..3).flat_map(|t| (0..3).map(move |d| (t, d))).collect();
        let topo = topology(3, 3, &edges);
        let mut budget = WorkBudget::new(100000);
        assert_eq!(
            enumerate(&topo, &full(3, 3), 34, &mut budget)?
                .ok_or(AssociationError::Limit)?
                .len(),
            34
        );
        assert!(enumerate(&topo, &full(3, 3), 33, &mut budget)?.is_none());
        Ok(())
    }
    #[test]
    fn independent_pairs_factor_billions_of_assignments_and_use_bit_31()
    -> Result<(), AssociationError> {
        let edges: Vec<_> = (0..32).map(|i| (i, i)).collect();
        let topo = topology(32, 32, &edges);
        let mut budget = WorkBudget::new(100000);
        let domains = topo.components(&mut budget)?;
        assert_eq!(domains.len(), 32);
        let mut count = 1_u128;
        for domain in domains {
            let all = enumerate(&topo, &domain, 2, &mut budget)?.ok_or(AssociationError::Limit)?;
            assert_eq!(all.len(), 2);
            count *= all.len() as u128;
            assert!(all[0].links.is_empty());
            assert_eq!(all[1].links.len(), 1);
        }
        assert_eq!(count, 1_u128 << 32);
        Ok(())
    }
    #[test]
    fn isolated_nodes_have_explicit_unmatched_assignments() -> Result<(), AssociationError> {
        let topo = topology(2, 3, &[]);
        let mut budget = WorkBudget::new(100000);
        let domains = topo.components(&mut budget)?;
        assert_eq!(domains.len(), 5);
        for domain in domains {
            let all = enumerate(&topo, &domain, 1, &mut budget)?.ok_or(AssociationError::Limit)?;
            assert_eq!(all.len(), 1);
            assert!(all[0].links.is_empty());
            assert_eq!(
                all[0].unmatched_tracks.len() + all[0].unmatched_detections.len(),
                1
            );
        }
        Ok(())
    }
    #[test]
    fn real_work_exhaustion_is_not_implicit_representation_success() {
        let topo = topology(2, 2, &[(0, 0), (0, 1), (1, 0), (1, 1)]);
        assert!(enumerate(&topo, &full(2, 2), 100, &mut WorkBudget::new(0)).is_err());
    }
}
