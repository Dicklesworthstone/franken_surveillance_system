# Deep dive: `franken_networkx` as the certified graph-algorithm and canonical-view substrate

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FNX-001`
**Status:** new normative import
**Audit basis:** current README/agent guide, behavioral differential oracle, zero-copy view analysis, algorithm/gauntlet and artifact surfaces inspected 2026-08-31

## 1. Why graph algorithms are operational, not decorative

FSS is composed of graphs whose algorithms directly change observation quality, compute allocation, diagnosis, and plan selection:

- camera/zone visibility and overlap;
- calibration factors and loop closures;
- tracklets and cross-camera association candidates;
- event evidence and causal/common-cause dependencies;
- sensor/network/compute/archive topology;
- capability and privacy projections;
- effect/obligation dependency DAGs;
- retention/deletion reachability;
- agent hypothesis branches.

The import is not “we can call PageRank.” It is a graph-semantics discipline: deterministic containers, stable tie-breaks, snapshot views, typed failures, complexity contracts, differential oracles, adversarial generators, canonical serialization, and evidence-bearing outputs.

## 2. Separate algorithms from storage

Algorithms consume an `AlgorithmInput`/snapshot-view trait rather than concrete graph storage. FSS defines a narrow immutable view:

```text
projection_id
anchor and consumed high-water mark
directedness / multiedge / hyperedge semantics
node and edge identity access
ordered neighbor iteration
weight/time/uncertainty access
capability-filtered domain
revision and invalidation policy
```

The same algorithm can run over the simple reference graph, a Strata optimized representation, a branch overlay, or a persistent FrankenGraphDB view. Storage optimization cannot change answers.

## 3. Canonical graph semantics

Every algorithm family declares:

- projection and authority anchor;
- node/edge/hyperedge identity rules;
- directedness and multiedge semantics;
- weight, interval, missing, and infinity semantics;
- deterministic tie-break policy;
- output ordering;
- numeric/overflow/NaN behavior;
- exact/approximate claim class;
- dominant complexity and resource budget;
- stale-result policy;
- decision-path and output digests.

Equivalent mathematical answers are not operationally equivalent when agents replay plans. A shortest path among equal-cost routes must choose by a registered policy—such as stable edge insertion sequence then stable node key. Raw hash iteration is never a policy.

## 4. Stable external identities and generational handles

Human/agent-visible IDs are opaque stable keys. Internal dense handles include a generation to prevent ABA after removal/reuse. A stale handle cannot silently name a new track, event, camera, or graph node. Serialization uses stable keys plus explicit generation mappings, never process-local indices as durable identity.

This is especially important for short-lived tracks and frame buffers, where rapid recycling would otherwise create subtle cross-event corruption.

## 5. Immutable snapshot views and honest structural sharing

The zero-copy analysis contributes two rules:

1. Structural sharing of immutable snapshots can remove enormous O(V+E) copying and should be used aggressively.
2. The magnitude of a win does not transfer to a different boundary; measure the actual copy before engineering a view.

FSS graph/frame views therefore:

- share immutable roots through reference counting;
- carry snapshot revision/generation;
- refresh by replacing the root rather than mutating through aliases;
- let old readers retain coherent old snapshots;
- invalidate live iterators according to a registered policy;
- never expose a pointer into growable/reused storage;
- freeze, COW, or epoch-invalidate exported numeric buffers;
- prove semantic identity before timing a “zero-copy” arm.

A view is not permission for mutable aliasing. Small results are materialized when that is simpler and faster.

## 6. Algorithm families and concrete FSS roles

### 6.1 Dynamic connectivity and component maintenance

Use for:

- which cameras/zones remain connected by overlapping visibility after failures;
- whether a calibration pose graph is connected;
- network/relay reachability;
- whether event evidence splits into disconnected hypotheses;
- deletion/object graph closure.

Outputs name components, change cause, anchor, and stale policy.

### 6.2 Articulation points, bridges, dominators, and cut structures

Use to identify:

- a camera or overlap zone whose loss disconnects perimeter coverage;
- a Wi-Fi AP, relay, disk, or archive provider that dominates an evidence path;
- a calibration landmark/edge that is a single point of pose connectivity;
- a policy/effect step that dominates all successful completion paths;
- minimum sets of sensors whose failure destroys observability.

Centrality is advisory; articulation/dominator/cut facts can support certified redundancy claims under the named projection.

### 6.3 Shortest, k-shortest, and temporal feasible paths

Use for:

- feasible entity transit between cameras/zones;
- expected next observation and overdue detection;
- operator/drone calibration route guidance;
- archive restoration route/path choice;
- effect dependency and critical path.

Path weights may be intervals. Tie-breaks and uncertainty propagation are explicit. `k` alternatives preserve ambiguity rather than greedily collapsing an association.

### 6.4 Bipartite matching and min-cost flow

Use for:

- detection-to-track assignment;
- tracklet-to-tracklet cross-camera association;
- evidence tasks to compute workers;
- cameras to calibration observations;
- alert channels to providers under capacity and cost;
- archive objects to providers/replicas.

The reference uses exact Hungarian/min-cost flow within bounded sizes; sparse/approximate variants require certificates or heuristic labeling. K-best assignments use a deterministic Murty-style or equivalent enumeration so alternatives remain reproducible.

### 6.5 Max-flow/min-cut and Gomory-Hu structure

Use for:

- network/compute/egress capacity;
- camera coverage redundancy and minimal failure sets;
- smallest set of occlusions/failures separating a protected zone from observation;
- archive/provider resilience;
- privacy boundary leakage paths;
- resource feasibility for a model/event plan.

A cut result is valid only for the declared capacity model and graph generation. It does not prove real-world security outside modeled edges.

### 6.6 Spanning forests and pose-graph backbones

Use to select a low-cost connected calibration backbone, replication topology, or network plan while retaining extra loop-closure edges for validation. The spanning tree is not the complete evidence graph; discarded non-tree edges remain available as consistency checks.

### 6.7 Cycle bases, SCCs, condensation DAGs, and topological order

Use for:

- calibration loop-closure residual diagnosis;
- dependency/effect cycles and deadlocks;
- recurring event/feedback cycles;
- model/data pipeline dependency order;
- release/work-package scheduling;
- causal strongly connected components that invalidate a naive DAG interpretation.

Cycle outputs include canonical orientation/order and witness edges.

### 6.8 Facility location, k-center, p-median, set cover, and submodular selection

Use for:

- camera placement and cheapest coverage improvement;
- selecting calibration viewpoints/landmarks;
- choosing evidence frames/tubes under compute budget;
- selecting a minimal sensor subset while retaining coverage/confidence;
- placing edge compute/cache nodes.

Exact solutions are used for small bounded instances. Greedy/submodular approximations declare guarantees when assumptions hold; otherwise they are heuristic with measured regret.

### 6.9 Personalized PageRank, HITS, centrality, and community

Use for attention, investigation, and anomaly surfacing:

- rank evidence relevant to one event/task;
- locate influential failure domains;
- identify recurring routine/event clusters;
- prioritize graph neighborhoods for an agent.

These outputs never directly authorize alerts or suppress mandatory evidence. Results name seed set, damping/policy, convergence, and approximation class.

### 6.10 D-separation and causal/common-cause analysis

Use to reason about whether two apparent corroborators are conditionally independent given shared camera firmware, model family, lighting, network, or training data. This prevents counting two highly correlated detections as independent evidence.

Causal graphs are modeled assumptions, not discovered physical truth. Outputs include the graph generation and assumptions.

### 6.11 Graph hashing/isomorphism and topology drift

Canonical graph fingerprints and Weisfeiler-Lehman-like summaries can detect scene/topology/configuration drift, deduplicate equivalent branches, and index known failure shapes. Hash equality is not full semantic equality unless the chosen canonicalization proves it.

### 6.12 Hypergraphs and factor graphs

Multi-sensor corroboration, calibration factors, and event constraints often relate more than two entities. FSS represents these as typed factor/hyperedge nodes rather than lossy pairwise expansion when semantics require it. Algorithms declare whether they operate on the bipartite factor projection or native hypergraph.

## 7. Complexity witnesses

Every planning-, calibration-, coverage-, association-, or alert-relevant graph execution emits:

```text
algorithm_id and implementation generation
projection_id and authority anchor
claim class
n, m, hyperedge/factor counts
weight/time policy
stable tie-break policy
observed operation counters
budget consumed and stop reason
approximation/convergence certificate
decision-path digest
output digest
```

Counters detect accidental complexity regressions and adversarial blowups. Failure to record optional performance telemetry cannot change the selected result; it changes the evidence available for a performance claim.

## 8. Behavioral differential oracle

FrankenNetworkX’s accounting separates:

- successful agreement;
- genuine divergence;
- error-only agreement;
- unexercised surface;
- nonbehavioral bindings.

FSS adopts the same honesty. Each algorithm has a simple reference and, where useful, an external lab oracle. Generated fixtures retain exact graph/argument recipes. Canonical comparison preserves contractually ordered paths, exact numeric policies, exception/error classes, mutation state, and output evidence. Unspecified collection order may be normalized only when the FSS semantics manifest says it is unspecified.

## 9. Adversarial graph families

The gauntlet includes:

- empty/singleton/disconnected graphs;
- path, cycle, star, complete, complete bipartite;
- grids, trees, DAG layers, SCC condensations;
- barbell, lollipop, wheel, ladder, dense hubs;
- scale-free/power-law and adversarial high-degree nodes;
- equal-weight/tie-heavy graphs;
- zero/negative/interval/NaN/overflow weights as allowed;
- multiedges, self-loops, temporal overlap edge cases;
- near-disconnected calibration graphs;
- association graphs with many symmetric k-best assignments;
- visibility hypergraphs with common-cause failure nodes;
- dynamic update sequences, deletions, and ABA handle reuse;
- capability projections designed to leak via degree or absence.

Each algorithm registry row names required families.

## 10. CGSE-style canonical graph serialization and self-healing artifacts

Graph artifacts use canonical identity/order, format version, representation fingerprint, schema/projection generation, checksums, and witness metadata. Optional repair sidecars protect long-lived immutable graph generations. Decode success is followed by content and semantic validation; otherwise the artifact is rebuilt from canonical deltas.

The preferred recovery order is:

1. verify and load;
2. repair and reverify;
3. rebuild from canonical authority root;
4. quarantine and fail closed if none succeeds.

A repaired derived graph never overwrites canonical evidence.

## 11. Forge-style compilation of hot graph work

Frequently executed standing queries or algorithms may be compiled into specialized artifacts:

- fixed schema and projection;
- precomputed adjacency layout;
- fused filter/expansion kernels;
- bounded memory plan;
- deterministic output/tie contract;
- source query/algorithm digest;
- qualification and benchmark receipt.

Compilation is default-off until it proves semantic parity and net benefit. Artifacts support inspect/profile/doctor/enable/disable and automatic fallback to the reference path. No JIT code enters a high-authority process without a separate safety case; initial “compile” means data/layout specialization in safe Rust.

## 12. Hardened recovery and resource bounds

Malformed serialized graphs, queries, or model-generated graph structures use explicit stacks and hard limits. Recovery mode emits diagnostics and a decision ledger; it cannot loop indefinitely or produce an exact claim from truncated input. E-process/CUSUM/conformal monitors may detect drift or anomalous failure rates, but the hard resource limits remain authoritative.

## 13. FSS semantic owners

| Imported mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| Algorithm input/view contract | `fss-graph-core` | No algorithm coupled to one storage layout |
| Algorithm registry/semantics | `fss-graph-algorithms` | No undocumented tie/weight behavior |
| Complexity witnesses | `fss-evidence` | No planning result without cost/decision identity |
| Differential oracle/gauntlet | `fss-graph-gauntlet` | No optimized default without agreement evidence |
| Canonical serialization | `fss-graph-format` | No process-local IDs in durable graph |
| Structural sharing/views | `fss-graph-core`, media view owners | No mutable/growable backing under stable view |
| Forge specialization | `fss-graph-forge` | No compiled artifact without reference fallback |

## 14. Superficial imitations that would fail

1. Calling algorithms over hash maps and accepting nondeterministic iteration.
2. Deep-copying every snapshot because it is “safer,” or exporting mutable aliases because it is “zero copy.”
3. Recomputing tie order in a lazy view instead of preserving the kernel’s decision.
4. Using centrality as threat score.
5. Returning one optimal assignment and erasing equivalent alternatives.
6. Claiming parity from error-only tests.
7. Testing random Erdos-Renyi graphs but not adversarial shapes.
8. Omitting capability filtering until after graph expansion.
9. Persisting dense internal handles without generations.
10. Repairing a graph artifact and skipping semantic/output-root verification.
11. Specializing/compiling a hot query without a source digest and fallback.
12. Adding zero-copy complexity before measuring copy cost.

## 15. Admission evidence for `INT-FNX-001`

1. Storage-independent reference view and immutable snapshot behavior.
2. Stable external key/generational handle and ABA tests.
3. Deterministic ordering/tie fixtures for every admitted algorithm family.
4. Differential oracle agreement with divergences, error-only, and unexercised surfaces reported separately.
5. Required adversarial graph families and budget cancellation.
6. Exact/approximate claim enforcement and convergence certificates.
7. Complexity-witness replay and regression locks.
8. Capability noninterference for values, counts, degree, paths, and absence.
9. Snapshot invalidation/live-iterator behavior and old-reader coherence.
10. Canonical serialization round trip, corruption, repair, rebuild, and representation-fingerprint tests.
11. Structural-sharing benchmarks prove semantic equality first and quantify actual removed copies.
12. Forge specialization remains default-off until same-binary parity and performance gates pass.
13. No Python/PyO3 dependency enters the FSS server; external NetworkX is an optional lab oracle only.

## 16. Deliberately rejected imports

- Python compatibility surface inside FSS.
- Algorithm breadth without operational roles and gates.
- Exact claims from heuristic graph analytics.
- Universal zero-copy views.
- Graph JIT in the authority/effect path during early phases.
- Repair symbols for easily rebuilt ephemeral graphs unless measured useful.

## 17. Resulting architectural leap

Graph reasoning becomes reproducible engineering evidence rather than a bag of analytics. FSS can state exactly which graph, algorithm, tie policy, budget, approximation class, and decision path produced a camera placement, association, coverage diagnosis, or failure cut—and can replay that answer after storage and implementation changes.
