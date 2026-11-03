# Robust camera placement (deterministic reference)

`ALG-INTERDICT-001` now includes an additive exact placement mode in
`fss_graph_algorithms::robust_placement`. It answers a practical planning question:
given an existing sensor layout, explicit possible camera additions and an installation
budget, which additions maximize the minimum sensor-loss cost needed to leave an
entry-to-target route unobserved?

This is a counterfactual calculation over the supplied movement and coverage model.
It does not install cameras, validate proposed sight lines, measure current health,
establish sensor independence, or grant effect authority. A missing movement route
means disconnected in the declared graph; it is never reported as infinite security.

## Inputs and result

`PlacementQuery` contains the existing `InterdictionQuery`, a complete finite catalog of
`PlacementCandidate`s, separate explicit installation and sensor-loss unit names, an
installation budget and a maximum number of additions. Each candidate names a fresh
sensor identity, the zones it is assumed to observe and both costs. Zero costs and empty
candidate support have explicit semantics. Sensor identities, costs and all candidate
assumptions remain bound into the input digest, including unaffordable candidates.

`select_robust_placement` and `select_robust_placement_with_cancel` return a
`CertifiedRun<PlacementOutput>`. The output contains selected sensor identities,
installation cost, the baseline and defended exact vulnerability witnesses, and the
number of evaluated feasible placements. The witness includes counters, input/output
digests and a deterministic decision summary. Installation costs and sensor-loss costs
are different units and are never compared to each other.

The empty placement is always considered. The solver maximizes minimum sensor-loss
cost, then minimizes installation cost, addition count and the canonical sensor tuple.
Within each vulnerability calculation it minimizes loss cost, removed-sensor count
and the canonical removal tuple; the path witness uses shortest length and stable
zone ordering. Existing interdiction inputs, outputs and implementation identity are
unchanged.

## Bounds and refusal

The reference admits at most 16 candidate cameras, 20 total declared sensor identities,
256 movement zones and 4096 arcs. It uses the existing `CoverBudget`: all placement
enumeration, nested sensor-loss searches and graph walks share one cumulative work
allowance, capped at 50 million units. Cancellation is checked throughout that work.
The output ceiling is 8192 entries. Every declared loss cost must fit the same `u64`
unit and their total must fit `u64`; installation feasibility uses checked subtraction.

An invalid, oversized, cancelled or exhausted request returns no optimum. There is no
automatic approximation, candidate sampling or partial best-so-far response. Exactness
applies only to the complete supplied catalog and declared model.

The canonical owner contract is
`architecture/robust_placement_reference.json`; the parent registry remains
`architecture/graph_algorithms.json`. This implements a reference slice of bead
`fss-x4a.23.50`, not its aggregate physical or `INT-FNX-001` qualification.

## Operator command

`fss-cover placement` reads the existing deployment coverage owner at its committed
anchor. Every baseline sensor/zone edge requires one retained positive witness covering
the entire requested capture window. It never joins partial intervals or treats zero
witness counts as support. The report separately identifies proposed coverage and the
movement model as `operator_asserted_hypothetical`.

For example, compare a proposed camera at an entrance with the existing retained layout:

```sh
fss-cover placement --root /path/to/deployment --site site:home \
  --during 1401000000:2099000000 \
  --zone ground-zone:entry --zone ground-zone:door \
  --entry ground-zone:entry --target ground-zone:door \
  --move ground-zone:entry=ground-zone:door \
  --candidate sensor:proposed=150:1:ground-zone:entry \
  --installation-budget 200 --max-additions 1 \
  --installation-cost-unit usd --sensor-loss-cost-unit sensor-count
```

The candidate grammar is `SENSOR=INSTALL_COST:LOSS_COST:ZONE[,ZONE...]`.
Movement arcs are directed; declare both directions when both are intended. All zones
must be named with `--zone`. Existing relevant sensors default to loss cost one;
`--sensor-disable-cost SENSOR=N` overrides a known positive baseline observer. Candidate
identities must not collide with any retained sensor, including a currently unsupported
one. Both cost-unit names are required and bound into the exact query.

The command emits one complete `fss.coverage_robust_placement.v1` JSON report, with the
source witness and anchor, baseline observer inventory, all declarations, unsupported
zones, selected cameras, baseline and defended loss/path witnesses and the exact
algorithm certificate. `--expected-coverage sha256:...` can pin a prior source witness.
An exact repeat against unchanged custody has identical output. A stale pin, solver
refusal or insufficient report budget emits no partial report. Query success does not
mean current live coverage or a physical installation has been approved.

CLI input limits are 64 zones and 128 movement arcs in addition to the solver's sensor
and candidate limits. The default cumulative solver budget is two million work units;
`--work-units` can request at most 50 million. `--max-report-bytes` is at most two MiB.
The default timeout is 30 seconds, checked around independently bounded source reads
and throughout solver work; a running filesystem syscall cannot be preempted.

## Shared power, network and host failures

`fss-cover placement --failure-action ID=COST=SENSOR[,SENSOR...]` evaluates proposed
cameras against explicitly declared common dependencies. Repeat the option for multiple
power circuits, switches, recorders, clocks or other shared failures. This selects the
additive `robust_placement::shared_failures` API and a distinct
`fss.coverage_shared_failure_placement.v1` report. A command without this option retains
the original individual-loss API, report and canonical identities.

Every sensor still has its individual disable action and cost. A shared action disables
all its installed members together, at the declared action cost. Selecting two overlapping
actions unions their affected sensors and charges each action once. These costs use
`--sensor-loss-cost-unit`; they are owner assumptions about the loss model, not estimated
failure probabilities. Declaring two different action IDs does not establish statistical
independence.

For example, suppose a retained camera observes an entry and has individual loss cost
10. A cheap proposed camera on the same PoE switch has individual loss cost 20, while
a separately powered candidate has loss cost 10. Ignoring the switch, the cheap camera
increases the minimum loss cost from 10 to 30. If one switch action disables both of
those cameras at cost 1, that addition provides no improvement against the declared
shared failure. The separate candidate instead raises minimum loss cost from 1 to 11.
The native contract test checks this actual change of recommendation and its action/path
witnesses.

```sh
fss-cover placement --root /path/to/deployment --site site:home \
  --during 1401000000:2099000000 \
  --zone zone:entry --zone zone:door \
  --entry zone:entry --target zone:door --move zone:entry=zone:door \
  --sensor-disable-cost sensor:existing=10 \
  --candidate sensor:cheap=1:20:zone:entry \
  --candidate sensor:separate=2:10:zone:door \
  --failure-action power:poe=1=sensor:existing,sensor:cheap \
  --installation-budget 2 --max-additions 1 \
  --installation-cost-unit installation-points --sensor-loss-cost-unit loss-points
```

The example assumes `sensor:existing` has retained whole-window support at `zone:entry`.
Proposed sight lines remain hypothetical. Shared memberships may include candidate cameras
that are unaffordable or ultimately unselected; the input digest still binds them, while
the loss witness disables only installed members. A retained sensor explicitly included
in a shared action can have zero support in the requested movement zones: it enters the
failure catalog with default individual cost one (overridable), without adding any
observer edge. Unknown sensor identities, duplicate action IDs, repeated members, empty
memberships and invalid costs are refused. Individual-sensor and shared-action identities
are separate typed namespaces, so equal raw labels cannot silently collide.

The shared report retains the source anchor and coverage witness, all candidate and
failure declarations, explicit unsupported zones, and both baseline and defended results.
Each result reports `failure_action_loss_cost_units`, typed `failure_actions`, the union
of hypothetical `disabled_sensors`, and a witness `path`. The loss tie-break is minimum
cost, then fewer actions, then the typed identity tuple: individual sensors before shared
actions, lexical within each class. Placement ties still prefer lower installation cost,
fewer additions and the sensor tuple. A zero-cost failure remains an interdiction result;
an already blind path and a disconnected movement graph remain separate outcomes.

There are at most 16 shared actions in addition to the existing 20-sensor catalog and
16-candidate ceiling. All individual and shared action costs, including inactive members,
must sum within `u64`. The exact search considers affordable placements and action subsets
under one cumulative work allowance and cancellation probe. Larger action catalogs can
exhaust that allowance; no incumbent is returned as an optimum. The shared-mode contract
and wire schema are `architecture/shared_failure_placement_reference.json` and
`schemas/coverage_shared_failure_placement.v1.json`.

## Validation

On the pinned `nightly-2026-08-31`, all 11 tests in the focused native suite passed:

```sh
cargo test --offline --locked -j1 -p fss-graph-algorithms \
  --test robust_placement_contract
```

The suite includes 180 seeded comparisons against independent exhaustive placement
enumeration using the existing interdiction oracle, deterministic input/tie behavior,
one-unit-short budgets, cancellation during nested work, exact output limits, cost
unit identity, overflow, malformed inputs, existing blind paths and unreachable graphs.
These results establish the bounded reference behavior; they are not a deployment or
release qualification claim.

The shared-failure suite adds an independent tiny-instance oracle: enumerate simple
entry-to-target paths, then exhaustively cover each path's active observers with string
sets of declared actions. This differs from the production action-subset/bit-mask/BFS
algorithm. Its 160 seeded directed and undirected instances include overlap, zero costs,
multiple entries/targets, disconnected movement and installation ties. Focused cases
also verify the actual PoE recommendation change, inactive-member binding, same-label
namespaces, overflow, exact work/output boundaries and cancellation at every checked point.

```sh
cargo test --offline --locked -j1 -p fss-graph-algorithms \
  --test shared_failure_placement_contract
```

On `nightly-2026-08-31`, the complete graph package passed all 190 tests, including
all 11 shared-failure tests and every existing placement and graph-family certification
test. The shared-failure target also passed after a test-only type-alias cleanup.
Strict package Clippy remains blocked by four pre-existing findings in
`evidence_brief.rs`, `centrality.rs`, `steiner.rs` and `zset.rs`. A separate Clippy run
over the library and new test target passed with only those four existing lint classes
allowed; this is not a claim that the strict whole-package Clippy gate passed.

Twelve focused command tests and a native retained-custody contract exercise the operator
path, including a complete schema check, incorrect solver-witness mutations, repeatable
cold reads, whole-window refusal, stale pins and unchanged deployment files. The new
command cases also check shared-action recommendation changes, zero-support members,
complete deterministic reports, malformed declarations and refusal without partial output.
The process contract covers both report modes against the same actual retained custody:

```sh
cargo test --offline --locked -j1 -p fss-cli --bin fss-cover placement::tests
cargo test --offline --locked -j1 -p fss-cli --test coverage_cli_contract \
  robust_placement_uses_cold_whole_window_custody_without_writing_or_claiming_live_coverage
```

Those native command tests remain unexecuted: earlier attempts hit the shared
environment's memory limit while the pinned compiler built the unchanged Asupersync
dependency. This feature did not repeat that failed heavy build. The new report and
three digest domains are registered. The schema scan has no new-feature findings;
39 pre-existing unrelated catalog errors remain. These results do not upgrade physical,
operator-process or release qualification.
