#![forbid(unsafe_code)]
//! Conditional anonymous handoff paths over owner-declared, source-pinned tracklets.
//!
//! No digest here authenticates custody, permission, a physical identity or a measured cost.
//! One query declares one property/session/privacy/generation/clock scope. A handoff must be
//! strictly forward for the complete capture intervals and satisfy its declared transit bounds
//! for every endpoint choice. Widening an interval can therefore remove admitted edges, never
//! create one. Model generations must agree; a same-camera handoff must also preserve camera
//! and calibration generations. Unavailable tracklets remain explicit isolated members.
//!
//! Splitting each tracklet into an outgoing and incoming assignment item reduces a DAG path
//! cover exactly to the existing certified Murty solver. Unassigned outgoing items pay an end
//! cost; unassigned incoming items pay a birth cost. Every member occurs exactly once in every
//! cover, including singletons. Costs rank conditional hypotheses, not confidence or truth.
//!
//! The admitted DAG plus at-most-one incoming/outgoing constraints retains the exact complete
//! implicit family. The all-singleton member is materialized independently of ranking. Displayed
//! alternatives are an exact ordered prefix, marked complete only when the existing solver
//! proves fewer than the requested count exist. Equality with that count does not prove exhaustion.

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::GraphError;
use crate::assignment::{
    self, Assignment, AssignmentProblem, AssignmentProblemBuilder, KBestOutput, NonAssignment,
};
use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul,
};

/// Maximum tracklets in one exact bounded query.
pub const MAX_TRACKLETS: usize = 32;
/// Maximum explicitly declared ordered non-self pairs.
pub const MAX_TRANSITIONS: usize = MAX_TRACKLETS * (MAX_TRACKLETS - 1);
/// Maximum source handles on a tracklet.
pub const MAX_EVIDENCE: usize = 16;
/// Maximum displayed alternatives. The complete family is also retained implicitly.
pub const MAX_K: u32 = 32;
/// Maximum ASCII identity length.
pub const MAX_ID_BYTES: usize = 256;
/// Maximum ASCII unit length.
pub const MAX_UNIT_BYTES: usize = 64;
/// Shared operation ceiling, including all Murty subproblem solves.
pub const MAX_WORK_UNITS: u64 = 50_000_000;
/// Shared logical-output ceiling, including the complete solver proof and every disposition.
pub const MAX_OUTPUT_ENTRIES: u64 = 32_768;
/// Canonical complete declaration and all pins, costs, transit assumptions and requested prefix.
pub const INPUT_DOMAIN: &str = "fss.graph.continuity_input.v1";
/// Complete implicit family, explicit prefix, dispositions and underlying assignment proof.
pub const OUTPUT_DOMAIN: &str = "fss.graph.continuity_output.v1";
/// Input-bound admission and the exact underlying Murty decision identity.
pub const DECISION_DOMAIN: &str = "fss.graph.continuity_decision_path.v1";

/// Additive operational composition of the registered multi-assignment family.
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MULTIMATCH-001",
    algorithm_name: "k_best_global_assignment",
    tie_break_rule: "declared link plus birth/end cost then canonical outgoing-to-incoming assignment tuple, unassigned last",
    complexity_witness: "input bytes, complete pair dispositions, certified Murty operations and complete path-cover checks",
    output_size_witness: "all tracklets and pair dispositions, exact implicit family, all-singletons, displayed prefix and complete certified assignment output",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-multimatch-001:anonymous-handoff-path-cover:v1",
    tie_break_policy_id: "tie:declared-objective-then-canonical-assignment-tuple-unassigned-last:v1",
    policy_id: "continuity-policy:owner-declared-anonymous-tracklets:single-scope:full-interval-robust-forward-dag:compatible-generations:priced-birth-end:exact-implicit-family:explicit-prefix:no-identity-or-confidence:v1",
    complexity_bound_id: "bound:alg-multimatch-001:complete-pairs-plus-murty-plus-path-cover-certificates:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_DOMAIN,
};

/// One asserted owner-local analysis scope; these pins do not confer or authenticate authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Owner-declared property identity.
    pub property: String,
    /// Local bounded analysis session, not a permanent identity namespace.
    pub session: String,
    /// Exact declared privacy policy generation.
    pub privacy_policy: ContentDigest,
    /// Exact declared analysis generation.
    pub generation: ContentDigest,
    /// Common clock basis for every interval and transit declaration.
    pub clock: ContentDigest,
}

/// Caller-declared support disposition, orthogonal to the solver's costs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackletSupport {
    /// The caller supplies source handles; the kernel does not authenticate their contents.
    Declared,
    /// Source support is missing; retain as an isolated member.
    Missing,
    /// Source support was invalidated; retain as an isolated member.
    Invalidated,
    /// Source support is redacted; retain as an isolated member.
    Redacted,
}

impl TrackletSupport {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Missing => "missing",
            Self::Invalidated => "invalidated",
            Self::Redacted => "redacted",
        }
    }
}

/// One camera-local anonymous tracklet, retained in every hypothesis even without support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tracklet {
    /// Unique query-local identity, not a physical person identity.
    pub id: String,
    /// Declared camera identity.
    pub camera: String,
    /// Immutable declared camera generation.
    pub camera_generation: ContentDigest,
    /// Exact calibration generation; different cameras normally have different calibrations.
    pub calibration: ContentDigest,
    /// Exact model generation; transitions never mix generations.
    pub model: ContentDigest,
    /// Declared source handles. Nonempty for `Declared`, always bounded and duplicate-free.
    pub evidence: Vec<ContentDigest>,
    /// Inclusive bounds on the first capture, in the common signed clock ticks.
    pub start: [i64; 2],
    /// Inclusive bounds on the last capture. At least one start <= end must exist.
    pub end: [i64; 2],
    /// Missing/invalidated/redacted support disables incident transitions, not the member.
    pub support: TrackletSupport,
}

/// One directed pair assumption, never inferred from absent data or an opaque model score.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    /// Existing outgoing tracklet.
    pub from: String,
    /// Existing incoming tracklet, distinct from `from`.
    pub to: String,
    /// Inclusive minimum/maximum transit duration in the common time unit.
    pub transit: [u64; 2],
    /// Nonnegative declared link cost in the common cost unit.
    pub cost: u64,
    /// Exact declared basis for transit/cost/geometry compatibility, not authenticated custody.
    pub basis: ContentDigest,
}

/// Complete bounded declaration. Input list order has no semantic effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityQuery {
    /// Common owner-local scope.
    pub scope: Scope,
    /// Common clock-tick/transit unit.
    pub time_unit: String,
    /// Common declared objective unit.
    pub cost_unit: String,
    /// Price per path start, including singleton starts.
    pub birth_cost: u64,
    /// Price per path end, including singleton ends.
    pub end_cost: u64,
    /// Requested exact ordered prefix, within `1..=MAX_K`.
    pub k: u32,
    /// Every tracklet; no unsupported member is silently removed.
    pub tracklets: Vec<Tracklet>,
    /// Explicit pair assumptions; undeclared pairs are forbidden.
    pub transitions: Vec<Transition>,
}

/// Every applicable reason for rejecting one ordered pair, in this stable order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    /// No explicit pair assumption was supplied.
    Undeclared,
    /// Outgoing tracklet lacks declared support.
    SourceUnavailable,
    /// Incoming tracklet lacks declared support.
    TargetUnavailable,
    /// Different model generations cannot be mixed.
    ModelGenerationMismatch,
    /// One camera changes generation across the pair.
    CameraGenerationMismatch,
    /// One camera changes calibration across the pair.
    CalibrationMismatch,
    /// The complete capture intervals do not prove strict forward order.
    NotStrictlyForward,
    /// At least one allowed endpoint pair violates the declared transit interval.
    TransitNotRobust,
}

impl RejectionReason {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undeclared => "undeclared",
            Self::SourceUnavailable => "source_unavailable",
            Self::TargetUnavailable => "target_unavailable",
            Self::ModelGenerationMismatch => "model_generation_mismatch",
            Self::CameraGenerationMismatch => "camera_generation_mismatch",
            Self::CalibrationMismatch => "calibration_mismatch",
            Self::NotStrictlyForward => "not_strictly_forward",
            Self::TransitNotRobust => "transit_not_robust",
        }
    }
}

/// Complete disposition for one ordered non-self pair; rejected assumptions remain present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionDisposition {
    /// Outgoing identity.
    pub from: String,
    /// Incoming identity.
    pub to: String,
    /// Original declaration if present, including its basis and cost.
    pub declared: Option<Transition>,
    /// Complete minimum/maximum gap; signed `i128` avoids endpoint subtraction overflow.
    pub gap: [i128; 2],
    /// All applicable refusal reasons, never just an opaque low score.
    pub reasons: Vec<RejectionReason>,
    /// Exactly `reasons.is_empty()`; admitted edges define the implicit family.
    pub admitted: bool,
}

/// One admitted edge with its declared cost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionEdge {
    /// Outgoing identity.
    pub from: String,
    /// Incoming identity.
    pub to: String,
    /// Declared objective contribution.
    pub cost: u64,
}

/// One complete conditional anonymous path cover, never a confirmed identity merge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathCover {
    /// Disjoint paths, ordered by their start identities; each path is in capture order.
    pub paths: Vec<Vec<String>>,
    /// Chosen edges in canonical outgoing/incoming identity order.
    pub links: Vec<TransitionEdge>,
    /// Complete sorted path starts, corresponding to unassigned incoming items.
    pub starts: Vec<String>,
    /// Complete sorted path ends, corresponding to unassigned outgoing items.
    pub ends: Vec<String>,
    /// Sum of chosen link costs.
    pub link_cost: u64,
    /// Total price for all path starts, including singleton starts.
    pub birth_cost: u64,
    /// Total price for all path ends, including singleton ends.
    pub end_cost: u64,
    /// Exact sum of the three declared cost components.
    pub total_cost: u64,
}

impl PathCover {
    fn entries(&self) -> u64 {
        5 + (self.paths.len()
            + self.paths.iter().map(Vec::len).sum::<usize>()
            + self.links.len()
            + self.starts.len()
            + self.ends.len()) as u64
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        e.u64(self.paths.len() as u64);
        for path in &self.paths {
            encode_ids(e, path);
        }
        encode_edges(e, &self.links);
        encode_ids(e, &self.starts);
        encode_ids(e, &self.ends);
        for value in [
            self.link_cost,
            self.birth_cost,
            self.end_cost,
            self.total_cost,
        ] {
            e.u64(value);
        }
    }
}

/// Exact complete family: every subset of `edges` with <=1 incoming and <=1 outgoing edge
/// per `members` entry. Robust strict time order makes cycles impossible, so this is precisely
/// every admissible path cover. No ranking, count or probability truncates this representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplicitFamily {
    /// Every original tracklet in canonical order.
    pub members: Vec<String>,
    /// Complete admitted DAG, including edges absent from the displayed prefix.
    pub edges: Vec<TransitionEdge>,
    /// Explicit feasible no-handoff alternative, independently of the displayed prefix.
    pub all_singletons: PathCover,
}

/// Complete source-pinned conditional continuity result, including every pair disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityOutput {
    /// Original owner-declared scope.
    pub scope: Scope,
    /// Declared clock-tick unit.
    pub time_unit: String,
    /// Declared cost unit.
    pub cost_unit: String,
    /// Declared price per path start.
    pub birth_cost: u64,
    /// Declared price per path end.
    pub end_cost: u64,
    /// Complete canonical tracklet declarations and source/support pins.
    pub tracklets: Vec<Tracklet>,
    /// Every ordered non-self pair, including omitted/unsupported/impossible transitions.
    pub transitions: Vec<TransitionDisposition>,
    /// Exact full implicit family and explicit no-handoff member.
    pub family: ImplicitFamily,
    /// Exact prefix in `(declared objective, canonical assignment tuple)` order.
    pub alternatives: Vec<PathCover>,
    /// True only when fewer than the requested number of assignments exist.
    pub displayed_prefix_complete: bool,
    /// Complete existing certified assignment proof over the admitted DAG reduction.
    pub matching: CertifiedRun<KBestOutput>,
}

fn encode_scope(e: &mut CanonicalEncoder, scope: &Scope) {
    e.text(&scope.property);
    e.text(&scope.session);
    for pin in [scope.privacy_policy, scope.generation, scope.clock] {
        e.digest(pin);
    }
}

fn encode_tracklets(e: &mut CanonicalEncoder, tracklets: &[Tracklet]) {
    e.u64(tracklets.len() as u64);
    for item in tracklets {
        e.text(&item.id);
        e.text(&item.camera);
        for pin in [item.camera_generation, item.calibration, item.model] {
            e.digest(pin);
        }
        e.u64(item.evidence.len() as u64);
        for pin in &item.evidence {
            e.digest(*pin);
        }
        for tick in item.start.into_iter().chain(item.end) {
            e.i128(i128::from(tick));
        }
        e.text(item.support.as_str());
    }
}

fn encode_transition(e: &mut CanonicalEncoder, item: &Transition) {
    e.text(&item.from);
    e.text(&item.to);
    e.u64(item.transit[0]);
    e.u64(item.transit[1]);
    e.u64(item.cost);
    e.digest(item.basis);
}

fn encode_edges(e: &mut CanonicalEncoder, edges: &[TransitionEdge]) {
    e.u64(edges.len() as u64);
    for edge in edges {
        e.text(&edge.from);
        e.text(&edge.to);
        e.u64(edge.cost);
    }
}

fn encode_proof(e: &mut CanonicalEncoder, run: &CertifiedRun<KBestOutput>) {
    for (field, value) in run.identity.registry_fields() {
        e.text(field);
        e.text(value);
    }
    for value in [
        run.node_count,
        run.edge_count,
        run.operations,
        run.output_entries,
        run.peak_working_bytes,
    ] {
        e.u64(value);
    }
    for pin in [
        run.input_digest,
        run.output_digest,
        run.decision_path_digest,
    ] {
        e.digest(pin);
    }
    e.u64(run.counters.len() as u64);
    for (counter, count) in &run.counters {
        e.text(counter);
        e.u64(*count);
    }
    run.output.encode(e);
}

fn base_entries(
    tracklets: &[Tracklet],
    transitions: &[TransitionDisposition],
    family: &ImplicitFamily,
) -> u64 {
    64 + tracklets
        .iter()
        .map(|item| 1 + item.evidence.len() as u64)
        .sum::<u64>()
        + transitions
            .iter()
            .map(|item| 1 + item.reasons.len() as u64 + u64::from(item.declared.is_some()))
            .sum::<u64>()
        + family.members.len() as u64
        + family.edges.len() as u64
        + family.all_singletons.entries()
}

impl CertifiedOutput for ContinuityOutput {
    fn entries(&self) -> u64 {
        base_entries(&self.tracklets, &self.transitions, &self.family)
            + self
                .alternatives
                .iter()
                .map(PathCover::entries)
                .sum::<u64>()
            + self.matching.output_entries
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        encode_scope(e, &self.scope);
        e.text(&self.time_unit);
        e.text(&self.cost_unit);
        e.u64(self.birth_cost);
        e.u64(self.end_cost);
        encode_tracklets(e, &self.tracklets);
        e.u64(self.transitions.len() as u64);
        for item in &self.transitions {
            e.text(&item.from);
            e.text(&item.to);
            e.bool(item.declared.is_some());
            if let Some(declared) = &item.declared {
                encode_transition(e, declared);
            }
            e.i128(item.gap[0]);
            e.i128(item.gap[1]);
            e.u64(item.reasons.len() as u64);
            for reason in &item.reasons {
                e.text(reason.as_str());
            }
            e.bool(item.admitted);
        }
        encode_ids(e, &self.family.members);
        encode_edges(e, &self.family.edges);
        self.family.all_singletons.encode(e);
        e.u64(self.alternatives.len() as u64);
        for cover in &self.alternatives {
            cover.encode(e);
        }
        e.bool(self.displayed_prefix_complete);
        encode_proof(e, &self.matching);
    }
}

/// Registered bounds for `n` original tracklets, `m` declared transitions and requested `k`.
#[must_use]
pub fn bound(n: u64, m: u64, k: u64) -> Vec<BoundRow> {
    let square = mul(n, n);
    vec![
        ("input_bytes", mul(4096, add(add(n, m), 1))),
        ("preparation_steps", mul(128, add(add(square, m), 1))),
        (
            "assignment_operations",
            Budget::registered(&assignment::multimatch_bound(mul(2, n), m, k)).max_operations,
        ),
        (
            "certificate_checks",
            mul(64, mul(add(k, 1), add(square, 1))),
        ),
        (
            OUTPUT_ENTRIES,
            add(
                add(128, mul(24, n)),
                add(mul(12, square), mul(k, add(mul(8, n), 8))),
            ),
        ),
    ]
}

fn invalid(reason: &'static str) -> GraphError {
    GraphError::PreconditionFailed(reason.to_owned())
}
fn inconsistent(reason: &'static str) -> GraphError {
    GraphError::Inconsistent(reason.to_owned())
}

fn valid_text(value: &str, maximum: usize, meter: &mut Meter<'_>) -> Result<(), GraphError> {
    meter.tick_n("input_bytes", value.len().min(maximum + 1) as u64)?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
    {
        return Err(invalid(
            "continuity identities and units require bounded ASCII alphanumeric/:_.- text",
        ));
    }
    Ok(())
}

fn valid_pin(pin: ContentDigest, meter: &mut Meter<'_>) -> Result<(), GraphError> {
    meter.tick_n("input_bytes", 33)?;
    if pin.bytes() == [0; 32] || pin.is_laboratory() {
        return Err(invalid(
            "continuity pins require nonzero ordinary content digests; laboratory markers cannot be discarded",
        ));
    }
    Ok(())
}

fn canonical(
    query: &ContinuityQuery,
    meter: &mut Meter<'_>,
) -> Result<(ContinuityQuery, ContentDigest), GraphError> {
    meter.checkpoint()?;
    if query.tracklets.is_empty()
        || query.tracklets.len() > MAX_TRACKLETS
        || query.transitions.len() > MAX_TRANSITIONS
    {
        return Err(GraphError::TooLarge);
    }
    if query.k == 0 || query.k > MAX_K {
        return Err(invalid("continuity k must be within 1..=32"));
    }
    for value in [&query.scope.property, &query.scope.session] {
        valid_text(value, MAX_ID_BYTES, meter)?;
    }
    for value in [&query.time_unit, &query.cost_unit] {
        valid_text(value, MAX_UNIT_BYTES, meter)?;
    }
    for pin in [
        query.scope.privacy_policy,
        query.scope.generation,
        query.scope.clock,
    ] {
        valid_pin(pin, meter)?;
    }
    for item in &query.tracklets {
        for value in [&item.id, &item.camera] {
            valid_text(value, MAX_ID_BYTES, meter)?;
        }
        if item.evidence.len() > MAX_EVIDENCE
            || (item.support == TrackletSupport::Declared && item.evidence.is_empty())
        {
            return Err(invalid(
                "declared tracklets require 1..=16 source handles; other support states allow 0..=16",
            ));
        }
        for pin in [item.camera_generation, item.calibration, item.model]
            .into_iter()
            .chain(item.evidence.iter().copied())
        {
            valid_pin(pin, meter)?;
        }
        if item.start[0] > item.start[1] || item.end[0] > item.end[1] || item.start[0] > item.end[1]
        {
            return Err(invalid(
                "capture bounds must be ordered and admit a start no later than the end",
            ));
        }
    }
    for item in &query.transitions {
        for value in [&item.from, &item.to] {
            valid_text(value, MAX_ID_BYTES, meter)?;
        }
        valid_pin(item.basis, meter)?;
        if item.transit[0] > item.transit[1] {
            return Err(invalid("transit bounds must be ordered"));
        }
        if item.from == item.to {
            return Err(GraphError::SelfLoop(item.from.clone()));
        }
    }
    let count = (query.tracklets.len() + query.transitions.len()) as u64;
    meter.tick_n("preparation_steps", count * (u64::from(count.ilog2()) + 4))?;
    let mut query = query.clone();
    query.tracklets.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    query
        .transitions
        .sort_unstable_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    for item in &mut query.tracklets {
        meter.tick_n("preparation_steps", (item.evidence.len() * 5 + 1) as u64)?;
        item.evidence.sort_unstable();
        if item.evidence.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("duplicate tracklet source handle"));
        }
    }
    if query
        .tracklets
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        return Err(invalid("duplicate tracklet identity"));
    }
    if query
        .transitions
        .windows(2)
        .any(|pair| pair[0].from == pair[1].from && pair[0].to == pair[1].to)
    {
        return Err(invalid("duplicate declared transition"));
    }
    for item in &query.transitions {
        meter.tick_n("preparation_steps", 16)?;
        for id in [&item.from, &item.to] {
            if query
                .tracklets
                .binary_search_by(|item| item.id.cmp(id))
                .is_err()
            {
                return Err(GraphError::UnknownNode(id.clone()));
            }
        }
    }
    let mut e = CanonicalEncoder::new();
    e.text(INPUT_DOMAIN);
    e.text(IDENTITY.implementation_id);
    e.text(IDENTITY.policy_id);
    encode_scope(&mut e, &query.scope);
    e.text(&query.time_unit);
    e.text(&query.cost_unit);
    e.u64(query.birth_cost);
    e.u64(query.end_cost);
    e.u32(query.k);
    encode_tracklets(&mut e, &query.tracklets);
    e.u64(query.transitions.len() as u64);
    for item in &query.transitions {
        encode_transition(&mut e, item);
    }
    if e.has_error() {
        return Err(invalid("continuity input exceeds canonical bounds"));
    }
    let bytes = e.finish();
    meter.tick_n("input_bytes", bytes.len() as u64)?;
    let digest = ContentDigest::sha256(&bytes);
    meter.checkpoint()?;
    Ok((query, digest))
}

fn project(
    query: &ContinuityQuery,
    meter: &mut Meter<'_>,
) -> Result<
    (
        AssignmentProblem,
        Vec<TransitionDisposition>,
        Vec<TransitionEdge>,
    ),
    GraphError,
> {
    let mut builder = AssignmentProblemBuilder::new(&query.cost_unit);
    for item in &query.tracklets {
        builder.add_left(&item.id).add_right(&item.id);
    }
    let mut dispositions = Vec::new();
    let mut edges = Vec::new();
    for from in &query.tracklets {
        for to in &query.tracklets {
            meter.tick_n("preparation_steps", 16)?;
            if from.id == to.id {
                continue;
            }
            let declared = query
                .transitions
                .binary_search_by(|item| (&item.from, &item.to).cmp(&(&from.id, &to.id)))
                .ok()
                .map(|i| query.transitions[i].clone());
            let gap = [
                i128::from(to.start[0]) - i128::from(from.end[1]),
                i128::from(to.start[1]) - i128::from(from.end[0]),
            ];
            let mut reasons = Vec::new();
            if declared.is_none() {
                reasons.push(RejectionReason::Undeclared);
            }
            if from.support != TrackletSupport::Declared {
                reasons.push(RejectionReason::SourceUnavailable);
            }
            if to.support != TrackletSupport::Declared {
                reasons.push(RejectionReason::TargetUnavailable);
            }
            if from.model != to.model {
                reasons.push(RejectionReason::ModelGenerationMismatch);
            }
            if from.camera == to.camera && from.camera_generation != to.camera_generation {
                reasons.push(RejectionReason::CameraGenerationMismatch);
            }
            if from.camera == to.camera && from.calibration != to.calibration {
                reasons.push(RejectionReason::CalibrationMismatch);
            }
            if gap[0] <= 0 {
                reasons.push(RejectionReason::NotStrictlyForward);
            }
            if declared.as_ref().is_some_and(|item| {
                gap[0] < i128::from(item.transit[0]) || gap[1] > i128::from(item.transit[1])
            }) {
                reasons.push(RejectionReason::TransitNotRobust);
            }
            let admitted = reasons.is_empty();
            if admitted {
                let item = declared
                    .as_ref()
                    .ok_or_else(|| inconsistent("admitted pair has no declaration"))?;
                builder.allow(&from.id, &to.id, item.cost);
                edges.push(TransitionEdge {
                    from: from.id.clone(),
                    to: to.id.clone(),
                    cost: item.cost,
                });
            }
            meter.decide(
                u8::from(admitted),
                dispositions.len() as u64,
                reasons.len() as u64,
            );
            dispositions.push(TransitionDisposition {
                from: from.id.clone(),
                to: to.id.clone(),
                declared,
                gap,
                reasons,
                admitted,
            });
        }
    }
    meter.checkpoint()?;
    Ok((builder.build()?, dispositions, edges))
}

fn product(value: u64, count: usize, label: &'static str) -> Result<u64, GraphError> {
    value
        .checked_mul(count as u64)
        .ok_or(GraphError::ArithmeticOverflow(label))
}

fn cover(
    query: &ContinuityQuery,
    problem: &AssignmentProblem,
    assignment: &Assignment,
    meter: &mut Meter<'_>,
) -> Result<PathCover, GraphError> {
    let n = query.tracklets.len();
    let ids = problem.left();
    let find = |id: &String| {
        ids.binary_search(id)
            .map_err(|_| inconsistent("assignment references unknown tracklet"))
    };
    let mut incoming = vec![None; n];
    let mut outgoing = vec![None; n];
    let mut link_cost = 0;
    let mut links = Vec::new();
    for (from, to, cost) in &assignment.pairs {
        meter.tick_n("certificate_checks", 16)?;
        let (a, b) = (find(from)?, find(to)?);
        if a == b
            || incoming[b].is_some()
            || outgoing[a].is_some()
            || problem.cost(a as u32, b as u32) != Some(*cost)
            || query.tracklets[a].end[1] >= query.tracklets[b].start[0]
        {
            return Err(inconsistent(
                "assignment violates the admitted temporal path-cover graph",
            ));
        }
        incoming[b] = Some(a);
        outgoing[a] = Some(b);
        link_cost = checked_add(link_cost, *cost, "continuity link cost")?;
        links.push(TransitionEdge {
            from: from.clone(),
            to: to.clone(),
            cost: *cost,
        });
    }
    let starts: Vec<String> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| incoming[*i].is_none())
        .map(|(_, id)| id.clone())
        .collect();
    let ends: Vec<String> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| outgoing[*i].is_none())
        .map(|(_, id)| id.clone())
        .collect();
    if starts != assignment.unassigned_right
        || ends != assignment.unassigned_left
        || starts.len() != ends.len()
    {
        return Err(inconsistent(
            "assignment does not account for every path boundary",
        ));
    }
    let mut seen = vec![false; n];
    let mut paths = Vec::new();
    for start in &starts {
        let mut next = Some(find(start)?);
        let mut path = Vec::new();
        while let Some(index) = next {
            meter.tick("certificate_checks")?;
            if seen[index] {
                return Err(inconsistent(
                    "path cover repeats a member or contains a cycle",
                ));
            }
            seen[index] = true;
            path.push(ids[index].clone());
            next = outgoing[index];
        }
        paths.push(path);
    }
    meter.tick_n("certificate_checks", (4 * n + 1) as u64)?;
    if seen.contains(&false) {
        return Err(inconsistent("path cover omits a tracklet"));
    }
    let birth_cost = product(query.birth_cost, starts.len(), "continuity birth cost")?;
    let end_cost = product(query.end_cost, ends.len(), "continuity end cost")?;
    let boundary_cost = checked_add(birth_cost, end_cost, "continuity boundary cost")?;
    let total_cost = checked_add(link_cost, boundary_cost, "continuity total cost")?;
    if link_cost != assignment.matched_cost
        || boundary_cost != assignment.non_assignment_cost
        || total_cost != assignment.objective
    {
        return Err(inconsistent(
            "path costs disagree with the certified assignment",
        ));
    }
    Ok(PathCover {
        paths,
        links,
        starts,
        ends,
        link_cost,
        birth_cost,
        end_cost,
        total_cost,
    })
}

fn remaining_output(budget: Budget, used: u64) -> Result<u64, GraphError> {
    budget
        .max_output_entries
        .checked_sub(used)
        .ok_or(GraphError::BudgetExhausted {
            dimension: OUTPUT_ENTRIES,
            limit: budget.max_output_entries,
        })
}

/// Plan complete conditional anonymous paths with no I/O, identity conclusion or effect.
pub fn plan(
    query: &ContinuityQuery,
    budget: Budget,
) -> Result<CertifiedRun<ContinuityOutput>, GraphError> {
    plan_with_cancel(query, budget, &|| false)
}

/// Same complete result under one borrowed cancellation probe and cumulative resource budget.
/// Any cancellation, overflow, bound or budget error returns no prefix or partial witness.
pub fn plan_with_cancel(
    query: &ContinuityQuery,
    budget: Budget,
    cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<ContinuityOutput>, GraphError> {
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, cancelled);
    meter.checkpoint()?;
    if budget.max_operations == 0
        || budget.max_output_entries == 0
        || budget.max_operations > MAX_WORK_UNITS
        || budget.max_output_entries > MAX_OUTPUT_ENTRIES
    {
        return Err(invalid(
            "continuity requires positive allowances within its hard work/output ceilings",
        ));
    }
    let (query, input_digest) = canonical(query, &mut meter)?;
    let (problem, transitions, edges) = project(&query, &mut meter)?;
    let members = problem.left().to_vec();
    let singleton_cost = checked_add(
        product(query.birth_cost, members.len(), "singleton birth cost")?,
        product(query.end_cost, members.len(), "singleton end cost")?,
        "singleton cost",
    )?;
    let singleton = Assignment {
        pairs: Vec::new(),
        unassigned_left: members.clone(),
        unassigned_right: members.clone(),
        matched_cost: 0,
        non_assignment_cost: singleton_cost,
        objective: singleton_cost,
    };
    let family = ImplicitFamily {
        members,
        edges,
        all_singletons: cover(&query, &problem, &singleton, &mut meter)?,
    };
    let base = base_entries(&query.tracklets, &transitions, &family);
    let matching = assignment::k_best_assignments_with_cancel(
        &problem,
        NonAssignment::Priced {
            left: query.end_cost,
            right: query.birth_cost,
        },
        query.k,
        Budget::new(
            budget.max_operations - meter.operations(),
            remaining_output(budget, base)?,
        ),
        cancelled,
    )?;
    meter.tick_n("assignment_operations", matching.operations)?;
    let n = query.tracklets.len() as u64;
    let m = query.transitions.len() as u64;
    let expected_cover_entries: u64 = matching
        .output
        .assignments
        .iter()
        .map(|item| 5 + 4 * n - 2 * item.pairs.len() as u64)
        .sum();
    remaining_output(
        budget,
        base + matching.output_entries + expected_cover_entries,
    )?;
    let mut alternatives = Vec::with_capacity(matching.output.assignments.len());
    for item in &matching.output.assignments {
        alternatives.push(cover(&query, &problem, item, &mut meter)?);
    }
    if alternatives.is_empty() {
        return Err(inconsistent(
            "the always-feasible singleton family produced no assignment",
        ));
    }
    let peak = add(
        mul(8192, add(add(mul(n, n), add(n, m)), 1)),
        add(
            mul(4096, mul(u64::from(query.k), add(n, 1))),
            matching.peak_working_bytes,
        ),
    );
    meter.path().digest(input_digest);
    meter.path().digest(matching.input_digest);
    meter.path().digest(matching.output_digest);
    meter.path().digest(matching.decision_path_digest);
    let output = ContinuityOutput {
        scope: query.scope,
        time_unit: query.time_unit,
        cost_unit: query.cost_unit,
        birth_cost: query.birth_cost,
        end_cost: query.end_cost,
        tracklets: query.tracklets,
        transitions,
        family,
        alternatives,
        displayed_prefix_complete: matching.output.exhausted,
        matching,
    };
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n,
            edge_count: m,
            input_digest,
        },
        output,
        &bound(n, m, u64::from(query.k)),
        peak,
    )
}
