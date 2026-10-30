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

Six focused command tests and a native retained-custody contract exercise the operator
path, including a complete schema check, incorrect solver-witness mutations, repeatable
cold reads, whole-window refusal, stale pins and unchanged deployment files:

```sh
cargo test --offline --locked -j1 -p fss-cli --bin fss-cover placement::tests
cargo test --offline --locked -j1 -p fss-cli --test coverage_cli_contract \
  robust_placement_uses_cold_whole_window_custody_without_writing_or_claiming_live_coverage
```

Those native command tests have not yet executed: the pinned compiler was killed by the
shared environment's memory limit while compiling the unchanged Asupersync dependency.
The complete schema catalog validates (94 schemas, 453 references). Repository-wide
architecture and semantic-plane audits still report existing unrelated registry gaps;
no qualification status is upgraded by this command.
