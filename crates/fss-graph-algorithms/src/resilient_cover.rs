#![forbid(unsafe_code)]
//! Select retained evidence providers that cover an explicit objective both normally and
//! after each declared shared-failure domain is lost, one scenario at a time.
//!
//! This is a bounded reduction to `ALG-SETCOVER-001`, not a new confidence estimator.
//! Every (scenario, zone) becomes a separate obligation. A sensor supports an obligation
//! only when it has positive supplied coverage and survives that scenario. The complete
//! declaration and source facts are bound into every obligation identity. The resulting
//! single sensor selection must satisfy all obligations; independently optimal selections
//! for individual scenarios must never be combined as though one deployed selection exists.
//!
//! This API does not execute the selection, disable sensors, infer independence, combine
//! undeclared simultaneous failures, or establish current physical coverage. The caller
//! must authorize the source, select one common window and pin the source witness/anchor.

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::failure_domains::{FailureDomain, MAX_FAILURE_DOMAINS, prepare_failure_inputs};
use crate::set_cover::{
    CoverAnalysis, CoverBudget, CoverError, CoverMethod, CoverSet, MAX_ELEMENTS, SetCoverProblem,
};
use crate::{GraphError, SensorCoverageProjection};

/// Canonical identity of the scenario-reduction input, separate from the expanded solver input.
pub const INPUT_DOMAIN: &str = "fss.graph.resilient_set_cover_input.v1";

/// A required positive witness for one zone in one explicitly bounded scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageObligation {
    id: String,
    zone_scope: String,
    failure_domain: Option<String>,
}
impl CoverageObligation {
    /// Opaque canonical identity used as the set-cover element. Includes the full context digest.
    #[must_use]
    pub fn id(&self) -> &str { &self.id }
    /// Requested zone, never synthesized or removed because its support is absent.
    #[must_use]
    pub fn zone_scope(&self) -> &str { &self.zone_scope }
    /// Failed domain node identity, or `None` for the normal baseline.
    #[must_use]
    pub fn failure_domain(&self) -> Option<&str> { self.failure_domain.as_deref() }
}

/// An immutable, fully bound reduction. A covered result refers to all declared obligations,
/// not just the baseline. `CoverAnalysis` certificates can be decoded with `obligation()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResilientCoverProblem {
    input_digest: ContentDigest,
    domains: Vec<FailureDomain>,
    obligations: Vec<CoverageObligation>,
    expanded: SetCoverProblem,
}
impl ResilientCoverProblem {
    /// Build one selection problem covering the baseline and every individual domain-loss case.
    /// The domain list must be nonempty. Every domain uses the existing validated owner-assertion
    /// type, and its members must be known sensors, including zero-support sensors.
    ///
    /// At most 64 total `(domains + baseline) * zones` obligations are admitted. Oversized input
    /// is refused, never sampled or weakened. Mandatory/excluded sensors and the cardinality
    /// ceiling retain their ordinary set-cover meaning, including a mandatory failed sensor.
    ///
    /// Construction is structurally bounded separately from solver work. It reuses the existing
    /// coverage and domain validators so public projection fields cannot substitute input facts.
    pub fn from_coverage(
        projection: &SensorCoverageProjection,
        zones: &[String],
        domains: &[FailureDomain],
        mandatory: &[String],
        excluded: &[String],
        maximum_sets: usize,
    ) -> Result<Self, CoverError> {
        if domains.is_empty() || zones.is_empty() {
            return Err(CoverError::InvalidConstraints("resilient selection needs explicit zones and failure domains"));
        }
        if domains.len() > MAX_FAILURE_DOMAINS || zones.len() > MAX_ELEMENTS
            || (domains.len() + 1) * zones.len() > MAX_ELEMENTS {
            return Err(GraphError::TooLarge.into());
        }
        let nominal = SetCoverProblem::from_coverage(projection, zones, mandatory, excluded, maximum_sets)?;
        let inputs = prepare_failure_inputs(projection, domains)?;
        let domains: Vec<FailureDomain> = inputs.ordered.iter().map(|d| (**d).clone()).collect();

        let mut encoder = CanonicalEncoder::new();
        encoder.text(INPUT_DOMAIN);
        encoder.digest(nominal.digest());
        // Include all source facts, not only nonzero support for requested zones. Even a
        // redundant declaration, zero-support member or witness-count change must rebind input.
        encoder.text(&projection.plane);
        encoder.u64(projection.witnesses.len() as u64);
        for ((sensor, zone), count) in &projection.witnesses {
            encoder.text(sensor);
            encoder.text(zone);
            encoder.u64(*count);
        }
        encoder.u64(domains.len() as u64);
        for domain in &domains {
            encoder.text(domain.kind().as_str());
            encoder.text(domain.id());
            encoder.u64(domain.members().len() as u64);
            for member in domain.members() { encoder.text(member); }
        }
        let input_digest = ContentDigest::sha256(&encoder.finish());
        let mut obligations = Vec::with_capacity((domains.len() + 1) * nominal.elements().len());
        for (scenario, domain) in std::iter::once(None).chain(domains.iter().map(Some)).enumerate() {
            for (zone_index, zone) in nominal.elements().iter().enumerate() {
                obligations.push(CoverageObligation {
                    // Compact context-bound tokens cannot exceed the graph identity limit even
                    // when a zone and a domain label individually approach their own bounds.
                    id: format!("obligation:{input_digest}:{scenario}:{zone_index}"),
                    zone_scope: zone.clone(),
                    failure_domain: domain.map(FailureDomain::node_id),
                });
            }
        }
        let mut sets = Vec::with_capacity(nominal.sets().len());
        for set in nominal.sets() {
            let mut support = Vec::new();
            for (scenario, domain) in std::iter::once(None).chain(domains.iter().map(Some)).enumerate() {
                if domain.is_some_and(|domain| domain.members().contains(set.id())) { continue; }
                for (zone_index, zone) in nominal.elements().iter().enumerate() {
                    if set.elements().contains(zone) {
                        support.push(obligations[scenario * nominal.elements().len() + zone_index].id.clone());
                    }
                }
            }
            sets.push(CoverSet::new(set.id(), &support)?);
        }
        let elements = obligations.iter().map(|obligation| obligation.id.clone()).collect::<Vec<_>>();
        let expanded = SetCoverProblem::new(&elements, &sets, mandatory, excluded, maximum_sets)?;
        Ok(Self { input_digest, domains, obligations, expanded })
    }

    /// Complete input/reduction identity. The expanded solver also has its own distinct digest.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.input_digest }
    /// Canonical explicit scenarios, in the existing `(kind, id)` order. No joint failures implied.
    #[must_use]
    pub fn domains(&self) -> &[FailureDomain] { &self.domains }
    /// Baseline obligations followed by each declared domain, with zones in canonical order.
    #[must_use]
    pub fn obligations(&self) -> &[CoverageObligation] { &self.obligations }
    /// Resolve a certificate/uncovered element. Unknown or foreign context tokens return `None`.
    #[must_use]
    pub fn obligation(&self, id: &str) -> Option<&CoverageObligation> {
        self.obligations.iter().find(|obligation| obligation.id == id)
    }
    /// Immutable expanded problem, including every scenario and all original hard constraints.
    #[must_use]
    pub const fn expanded_problem(&self) -> &SetCoverProblem { &self.expanded }
    /// Solve one selection for all scenarios. Exact/greedy, unsupported/infeasible/incomplete,
    /// work/output bounds and failure semantics are exactly those of the bounded solver.
    pub fn solve(&self, method: CoverMethod, budget: CoverBudget) -> Result<CoverAnalysis, CoverError> {
        self.expanded.solve(method, budget)
    }
    /// Request-owned cancellation applies to every charged expanded-solver step. No partial
    /// selection or witness is returned on cancellation; input compilation has structural bounds.
    pub fn solve_cancellable(
        &self, method: CoverMethod, budget: CoverBudget, cancelled: &impl Fn() -> bool,
    ) -> Result<CoverAnalysis, CoverError> {
        self.expanded.solve_cancellable(method, budget, cancelled)
    }
}
