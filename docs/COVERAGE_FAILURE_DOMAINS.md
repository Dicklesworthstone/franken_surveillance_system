# Owner-declared common-failure coverage scenarios

`fss-event graph single-points` can now ask whether one shared network, power,
clock, or host dependency would remove every qualifying observer of a zone.
This is a read-only counterfactual over retained coverage, not an automatic
inventory, live-health monitor, absence proof, or independence certificate.

```sh
fss-event graph single-points --root /path/to/deployment --site site:home \
  --during 1000000000:2000000000 \
  --failure-domain network:garage-switch=sensor:driveway,sensor:garage \
  --failure-domain power:garage-circuit=sensor:garage,sensor:side
```

Omit `--during` to analyze retained history, with the existing historical
limitations. With it, every observer must have one retained witness whose
certain bounds cover the **whole** inclusive window. Partial-witness unions
and uncertainty hulls never qualify. Clock coordinates remain operator hints,
not certified synchronization. Sensor IDs come from the base report's `sensors`.

## Interpretation

The existing sensor-only report is unchanged without the new option. With it,
an optional `shared_failure_scenarios` object is appended. Its `scenarios`
array reports each domain's `kind`, `id`, complete `members`, `lost_zones`, cut
vertex, and a separate `fss.graph_algorithm_witness.v1` with its digest.
The original `projection.failure_domains_not_modelled` describes the original
sensor-only projection; the optional scenarios are separate conditional runs.

A zone with two camera witnesses can have no single-camera failure yet lose all
observers when their shared switch fails. A zone already lacking a qualifying
witness is not a newly lost zone. An empty `lost_zones` list does **not** prove
independence: undeclared dependencies remain `unknown_not_absent`, and
`independence` is always `unknown`.

Each declaration says that failure of this dependency makes every listed sensor
unusable for this coverage question. For a clock dependency this means loss of
usable timing evidence, not necessarily loss of physical recording. Declarations
are owner assertions, neither discovered nor verified topology. They are not
persisted, change no policy, and authorize no effects.

## Exact model and witness binding

Each domain is evaluated separately using the existing registered
`ALG-BRIDGE-001` on a `DeviceFailureGraph` scenario. The scenario contracts its
members' observer edges onto a single failure node; the original sensor nodes
remain leaves of that node so every declared member, even an unwitnessed one,
is bound into the graph digest. Unaffected sensors retain their direct paths.

The cut is cross-checked against the original observer sets. Domains are not
combined into one undirected dependency graph: overlapping power and network
requirements would otherwise create false alternate paths. Simultaneous failure
of multiple distinct domains, causal probabilities, and statistical independence
are outside this model. Listing their union as one explicit scenario tests that
specific simultaneous member loss; it does not estimate its probability.

Each scenario witness's projection ID includes the **parent coverage witness
digest**. That binds the original projection, authority anchor, and exact capture
window/selection policy, while the scenario input digest binds the complete
membership and collapsed topology. Identical graphs selected for different
windows therefore do not share scenario-witness identity.

## Bounds and refusals

A request accepts at most 16 domains, each with 1–1024 unique sensor IDs, a
1–64-byte UTF-8 label, and a class of `network`, `power`, `clock`, or `host`.
Labels are scoped by class. Colons are supported in sensor IDs; commas delimit
members. Duplicate declarations/members, empty/control-character identities,
and unknown sensors are refused. No undeclared sensor is fetched or inferred.

The scenario compiler accepts at most 8192 sensor/zone facts. All scenarios
share ceilings of 1,000,000 traversal operations and 100,000 emitted identities;
those budgets do not reset per domain. Scenario-enabled CLI output is capped at
8 MiB before any report bytes are emitted. Invalid inputs or exhausted budgets
produce no partial success report. Base-report limits remain unchanged.

## Validation status

Implementation and contract tests are present; this is **not qualified** under
INT-FNX-001 or a production resilience claim. No registry gate is promoted.

The implementation session executed an independent Python model comparison of
all 512 three-sensor/three-zone incidence graphs against all seven nonempty
failure-member sets: **3,584 cases passed**. This verifies the contraction model,
not Rust compilation or execution. The session environment had no Rust toolchain;
Rust compilation, rustfmt, clippy and the Rust/CLI tests were **not run**.

Run in the repository's pinned toolchain environment:

```sh
python3 crates/fss-graph-algorithms/tests/fixtures/failure_domain_model.py
cargo test -p fss-graph-algorithms --test failure_domains_contract
cargo test -p fss-cli --bin fss-event
cargo test -p fss-cli --test graph_single_points_cli_contract
cargo test -p fss-cli --test shared_failure_domains_cli_contract
```

The new real-binary contract imports synthetic MJPEG recordings, retains coverage
through exact approvals, tests overlapping domains and window exclusions,
checks witness binding and deterministic output, rejects unknown members without
partial output, and verifies that custody files and metadata remain unchanged.
Python is used only as a test JSON/filesystem oracle, never in production.
