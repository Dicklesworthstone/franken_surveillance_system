#![forbid(unsafe_code)]
//! Certified structural analysis of an immutable agent control plan.
//!
//! This is the first concrete `PlanObligationGraph` projection builder over an FSS control-plan
//! record. It deliberately projects topology only: step budgets are opaque canonical JSON and
//! edge priority is signed policy metadata, so neither is reinterpreted as duration, capacity, or
//! cost. Every graph weight is the structural unit `1`; algorithms that ignore weights (SCC and
//! dominators) are therefore admitted, while critical-path/flow semantics remain unsupported.
//!
//! The projection is cognition. It pins the exact plan digest and basis anchor and grants no
//! authority to execute, prepare, commit, cancel, or repair any step.

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{ControlPlan, ContractError, ContentDigest, GraphAlgorithmWitness};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dominators::{self, DominanceDirection, DominanceOutput};
use fss_graph_algorithms::scc::{self, SccOutput};
use fss_graph_algorithms::weighted::{WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::{GraphError};

/// Stable projection kind named by the graph registry.
pub const PLAN_OBLIGATION_PROJECTION_KIND: &str = "PlanObligationGraph";
/// Structural unit: weights have no duration/cost/capacity interpretation.
pub const PLAN_OBLIGATION_STRUCTURAL_UNIT: &str = "structural";

/// Immutable structural projection of one validated control plan.
#[derive(Clone, Debug)]
pub struct PlanObligationProjection {
    plan_digest: ContentDigest,
    projection_id: String,
    graph: WeightedGraph,
    entries: BTreeSet<String>,
}

impl PlanObligationProjection {
    /// Revalidates the public control-plan fields, then canonicalizes its structural transition DAG.
    ///
    /// Multiple conditioned edges with the same ordered endpoints collapse to one structural arc.
    /// Their full conditions/priorities remain bound by `plan_digest` and `projection_id`.
    /// Self-loops are refused by the registered simple-graph policy rather than silently erased.
    pub fn build(plan: &ControlPlan) -> Result<Self, PlanObligationGraphError> {
        let validated = ControlPlan::compile(
            plan.plan_id.clone(),
            plan.objective_id.clone(),
            plan.basis_anchor.clone(),
            plan.situation_frame_digest.clone(),
            plan.world_envelope_digest,
            plan.hypothesis_workspace_digest.clone(),
            plan.capability_projection.clone(),
            plan.budget.clone(),
            plan.steps.clone(),
            plan.edges.clone(),
            plan.entry_steps.clone(),
            plan.terminal_predicates.clone(),
            plan.decision_digest.clone(),
        )?;
        let plan_digest = validated.plan_digest();
        if plan_digest != plan.plan_digest() {
            return Err(PlanObligationGraphError::PlanIdentityMismatch);
        }

        let mut builder = WeightedGraphBuilder::directed(PLAN_OBLIGATION_STRUCTURAL_UNIT);
        for step in &validated.steps {
            builder.add_weighted_node(step.step_id.clone(), 1);
        }
        let mut topology = BTreeSet::new();
        for edge in &validated.edges {
            topology.insert((edge.from.clone(), edge.to.clone()));
        }
        for (from, to) in topology {
            builder.add_arc(from, to, 1);
        }
        let graph = builder.build()?;
        let projection_id = format!(
            "{PLAN_OBLIGATION_PROJECTION_KIND}:{}",
            digest_hex(plan_digest)
        );
        Ok(Self {
            plan_digest,
            projection_id,
            graph,
            entries: validated.entry_steps.into_iter().collect(),
        })
    }

    /// Exact immutable control-plan identity.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }

    /// Projection identity carried in every algorithm witness.
    #[must_use]
    pub fn projection_id(&self) -> &str {
        &self.projection_id
    }

    /// Canonical structural graph. Weight values are structural only.
    #[must_use]
    pub const fn graph(&self) -> &WeightedGraph {
        &self.graph
    }

    /// Declared plan entry steps, in stable identity order.
    pub fn entry_steps(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }

    /// Runs registered exact SCC analysis and seals a witness at the plan's own basis anchor.
    pub fn strongly_connected_components(
        &self,
        plan: &ControlPlan,
    ) -> Result<PlanSccReport, PlanObligationGraphError> {
        self.require_same_plan(plan)?;
        let bound = scc::bound(self.graph.node_count() as u64, self.graph.arc_count() as u64);
        let run = scc::strongly_connected_components(&self.graph, Budget::registered(&bound))?;
        let witness = run.witness(&self.projection_id, plan.basis_anchor.clone())?;
        fss_graph_algorithms::certified::check_witness(&witness, &scc::IDENTITY, &bound)?;
        Ok(PlanSccReport {
            plan_digest: self.plan_digest,
            output: run.output,
            witness,
        })
    }

    /// Runs registered exact dominator analysis from a declared plan entry step.
    ///
    /// Arbitrary internal roots are refused: the query root must be one of the immutable plan's
    /// declared entries, so a caller cannot hide upstream obligations by choosing a later node.
    pub fn dominators_from(
        &self,
        plan: &ControlPlan,
        entry: &str,
    ) -> Result<PlanDominatorReport, PlanObligationGraphError> {
        self.require_same_plan(plan)?;
        if !self.entries.contains(entry) {
            return Err(PlanObligationGraphError::UndeclaredEntry(entry.to_owned()));
        }
        let bound = dominators::bound(self.graph.node_count() as u64, self.graph.arc_count() as u64);
        let run = dominators::dominators(
            &self.graph,
            entry,
            DominanceDirection::Dominators,
            Budget::registered(&bound),
        )?;
        let projection_id = format!("{}:entry:{entry}", self.projection_id);
        let witness = run.witness(&projection_id, plan.basis_anchor.clone())?;
        fss_graph_algorithms::certified::check_witness(
            &witness,
            &dominators::IDENTITY,
            &bound,
        )?;
        Ok(PlanDominatorReport {
            plan_digest: self.plan_digest,
            entry: entry.to_owned(),
            output: run.output,
            witness,
        })
    }

    fn require_same_plan(&self, plan: &ControlPlan) -> Result<(), PlanObligationGraphError> {
        if plan.plan_digest() != self.plan_digest {
            return Err(PlanObligationGraphError::PlanIdentityMismatch);
        }
        Ok(())
    }
}

/// Certified SCC result over one exact plan topology.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanSccReport {
    /// Exact plan identity.
    pub plan_digest: ContentDigest,
    /// Registered SCC answer.
    pub output: SccOutput,
    /// Registered graph-algorithm witness pinned at the plan basis.
    pub witness: GraphAlgorithmWitness,
}

/// Certified dominator result over one declared plan entry.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanDominatorReport {
    /// Exact plan identity.
    pub plan_digest: ContentDigest,
    /// Declared entry used as root.
    pub entry: String,
    /// Registered dominator answer.
    pub output: DominanceOutput,
    /// Registered graph-algorithm witness pinned at the plan basis.
    pub witness: GraphAlgorithmWitness,
}

/// Fail-closed projection or registered algorithm refusal.
#[derive(Debug, PartialEq)]
pub enum PlanObligationGraphError {
    /// The mutable public plan fields no longer satisfy the registered ControlPlan contract.
    Contract(ContractError),
    /// The rebuilt plan identity disagrees with the supplied plan.
    PlanIdentityMismatch,
    /// A dominator query attempted to skip the plan's declared entries.
    UndeclaredEntry(String),
    /// The registered strict graph or algorithm refused the input/run.
    Graph(GraphError),
}

impl fmt::Display for PlanObligationGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "control plan contract refused: {error:?}"),
            Self::PlanIdentityMismatch => f.write_str("control plan identity mismatch"),
            Self::UndeclaredEntry(entry) => write!(f, "undeclared control plan entry: {entry}"),
            Self::Graph(error) => write!(f, "plan obligation graph refused: {error}"),
        }
    }
}
impl std::error::Error for PlanObligationGraphError {}

impl From<ContractError> for PlanObligationGraphError {
    fn from(error: ContractError) -> Self { Self::Contract(error) }
}
impl From<GraphError> for PlanObligationGraphError {
    fn from(error: GraphError) -> Self { Self::Graph(error) }
}

fn digest_hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{
        BudgetVector, ControlEdge, ControlStep, ControlStepKind, LedgerAnchor, StepReversibility,
        StepRisk, StepRobustness,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn step(id: &str) -> ControlStep {
        ControlStep {
            step_id: id.to_owned(),
            kind: ControlStepKind::Compute,
            owner: "owner:test".to_owned(),
            verb: "evaluate".to_owned(),
            robustness_class: StepRobustness::RobustAcrossEnvelope,
            supported_world_ids: vec![],
            unsafe_world_ids: vec![],
            preconditions: vec![],
            read_witnesses: vec![],
            write_witnesses: vec![],
            negative_witnesses: vec![],
            required_capabilities: vec![],
            budget_json: "{}".to_owned(),
            expected_information_gain: 0.0,
            expected_objective_gain: 0.0,
            risk: StepRisk::Low,
            privacy_exposure: 0.0,
            reversibility: StepReversibility::ReadOnly,
            success_transition: vec![],
            failure_transition: vec![],
            cancel_transition: vec![],
            indeterminate_transition: vec![],
            terminal_proof: vec![],
        }
    }

    fn plan(edges: &[(&str, &str)], entries: &[&str]) -> TestResult<ControlPlan> {
        let ids: BTreeSet<_> = edges
            .iter()
            .flat_map(|(a, b)| [*a, *b])
            .chain(entries.iter().copied())
            .collect();
        Ok(ControlPlan::compile(
            "plan:test",
            "objective:test",
            LedgerAnchor::genesis("site:plan-graph"),
            "frame:00000001",
            ContentDigest::sha256(b"world"),
            None,
            vec![],
            BudgetVector::default(),
            ids.into_iter().map(step).collect(),
            edges
                .iter()
                .enumerate()
                .map(|(index, (from, to))| ControlEdge {
                    from: (*from).to_owned(),
                    to: (*to).to_owned(),
                    condition: format!("condition-{index}"),
                    priority: index as i64,
                })
                .collect(),
            entries.iter().map(|value| (*value).to_owned()).collect(),
            vec!["done".to_owned()],
            "decision:00000001",
        )?)
    }

    #[test]
    fn canonical_projection_collapses_parallel_condition_edges_but_binds_full_plan() -> TestResult {
        let plan = plan(&[("a", "b"), ("a", "b"), ("b", "c")], &["a"])?;
        let projection = PlanObligationProjection::build(&plan)?;
        assert_eq!(projection.graph().node_count(), 3);
        assert_eq!(projection.graph().arc_count(), 2);
        assert_eq!(projection.plan_digest(), plan.plan_digest());
        assert!(projection.projection_id().contains("PlanObligationGraph:"));
        Ok(())
    }

    #[test]
    fn scc_reports_control_cycles_without_treating_them_as_execution_authority() -> TestResult {
        let plan = plan(&[("a", "b"), ("b", "c"), ("c", "b"), ("c", "d")], &["a"])?;
        let projection = PlanObligationProjection::build(&plan)?;
        let report = projection.strongly_connected_components(&plan)?;
        let cyclic: Vec<_> = report.output.cyclic().map(|c| c.members.clone()).collect();
        assert_eq!(cyclic, vec![vec!["b".to_owned(), "c".to_owned()]]);
        assert_eq!(report.witness.anchor(), &plan.basis_anchor);
        assert_eq!(report.witness.projection_id(), projection.projection_id());
        Ok(())
    }

    #[test]
    fn dominators_identify_steps_on_every_path_from_declared_entry() -> TestResult {
        let plan = plan(
            &[("entry", "gate"), ("gate", "left"), ("gate", "right"), ("left", "end"), ("right", "end")],
            &["entry"],
        )?;
        let projection = PlanObligationProjection::build(&plan)?;
        let report = projection.dominators_from(&plan, "entry")?;
        assert_eq!(report.output.chain("gate"), Some(vec!["entry".to_owned(), "gate".to_owned()]));
        assert_eq!(report.output.chain("end"), Some(vec!["entry".to_owned(), "gate".to_owned(), "end".to_owned()]));
        assert!(report.output.dominance.contains(&("gate".to_owned(), 3)));
        Ok(())
    }

    #[test]
    fn internal_node_cannot_be_selected_as_a_fake_entry() -> TestResult {
        let plan = plan(&[("a", "b"), ("b", "c")], &["a"])?;
        let projection = PlanObligationProjection::build(&plan)?;
        assert!(matches!(
            projection.dominators_from(&plan, "b"),
            Err(PlanObligationGraphError::UndeclaredEntry(entry)) if entry == "b"
        ));
        Ok(())
    }

    #[test]
    fn self_loop_refuses_under_registered_simple_graph_policy() -> TestResult {
        let plan = plan(&[("a", "a")], &["a"])?;
        assert!(matches!(
            PlanObligationProjection::build(&plan),
            Err(PlanObligationGraphError::Graph(GraphError::SelfLoop(_)))
        ));
        Ok(())
    }

    #[test]
    fn post_build_plan_mutation_cannot_reuse_the_projection_witness() -> TestResult {
        let mut plan = plan(&[("a", "b")], &["a"])?;
        let projection = PlanObligationProjection::build(&plan)?;
        plan.edges.push(ControlEdge {
            from: "b".to_owned(),
            to: "a".to_owned(),
            condition: "mutated".to_owned(),
            priority: 0,
        });
        assert!(matches!(
            projection.strongly_connected_components(&plan),
            Err(PlanObligationGraphError::PlanIdentityMismatch)
        ));
        Ok(())
    }
}
