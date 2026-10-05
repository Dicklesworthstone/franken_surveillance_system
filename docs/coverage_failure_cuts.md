# Joint dependency failures over retained coverage

`fss-event graph failure-cuts` exposes the existing bounded combination solver to operators.
It reads one committed, rehashed deployment snapshot; it does not record declarations, repair
storage, create effects, or change any existing graph command's analysis.

## Whole-window question

Which combinations of declared dependencies would remove every qualifying observer of a zone?
Use exact sensor IDs from the deployment's coverage report:

```sh
fss-event graph failure-cuts \
  --root /path/to/deployment --site site:home \
  --during 1000000000:2000000000 \
  --max-failed-domains 2 \
  --failure-domain power:circuit-a=sensor:a \
  --failure-domain network:uplink-b=sensor:b
```

The command evaluates both individual failures and their joint failure. If a zone has witnesses
from `sensor:a` and `sensor:b`, neither individual failure necessarily removes its last witness;
the pair can. `minimum_failed_domains` reports the smallest enumerated cut, and `scenario_index`
points to its exact declarations, failed sensors, lost zones, and algorithm witness. Domain
indices refer to the canonical `declarations` array, not argument order. Overlapping memberships
are unioned: a shared sensor fails once, and required dependencies never become alternative paths.

Without `--timeline`, each selected witness must cover the **entire** inclusive capture window.
Partial witnesses, uncertain outer hulls, and camera handovers are not combined into a single
whole-window witness. Signed 128-bit timestamps are emitted as decimal strings, including point
windows, to avoid precision loss in JSON consumers.

## Changes within a window

Append `--timeline` to evaluate that same full family of failures separately at every certain
witness boundary. Each chronological segment includes its own parent witness and minimum cuts.
This preserves periods with one observer, genuine overlap, camera handovers, and unwitnessed
gaps instead of treating disjoint recordings as simultaneous redundancy. One committed anchor
pins all segments; each scenario's witness binds its parent, declarations, search bound, and
selected combination.

`initially_unwitnessed` is not counted as a new failure. An unwitnessed interval may contain an
observed entry or excluded analysis; it proves neither that a sensor failed nor that nothing
happened. `no_cut_within_bound` says only that none of the enumerated declared combinations
removed all qualifying witnesses. Larger combinations and undeclared dependencies remain unknown.
Capture hints are operator assertions, not calibrated clocks. Declarations are not verified
topology, and these reports are not certificates of availability, independence, or absence.

## Resource and output contract

Admission requires an explicit `--max-failed-domains K`, 1 <= K <= the number of declarations.
At most 16 domains, 1024 members per domain, and 256 combinations per segment are admitted;
16 domains with K=2 gives 136 scenarios, while K=3 is refused before snapshot I/O. Timeline
partitioning additionally admits at most 256 segments. The requested family is never sampled
or silently reduced.

One aggregate allowance covers the complete report: at most 1,000,000 charged graph/enumeration
operations, 100,000 output entries, and 8 MiB of JSON. Timeline source/selection work is charged
by the existing timeline reader too. Snapshot reading retains its existing `OrientLimits`;
the graph budget is not a new filesystem-read budget. Every result is buffered before stdout:
a validation, unknown-sensor, witness, work, output, or byte-limit refusal emits no JSON prefix.

The schemas are `fss.coverage_failure_cuts.v1` and `fss.coverage_failure_cut_timeline.v1`.
Both are derived cognition with `implemented_not_qualified` qualification. They reuse
`ALG-BRIDGE-001`; they do not introduce a new reliability or probabilistic failure model.

## Regression commands

Run within the repository's pinned toolchain and required sibling closure:

```sh
cargo test -p fss-cli --bin fss-event graph::cuts
cargo test -p fss-cli --test graph_failure_cuts_cli
```

The tests cover joint-only cuts, initially-unwitnessed zones, canonical ordering, parent binding,
exact aggregate limits, temporal handover/overlap/gaps, mixed-anchor and incomplete-partition
refusals, signed timestamp extremes, and the real CLI's help/pre-I/O refusal contract.
These additions do not themselves establish a qualification receipt.
