# Bounded coverage projection admission

`SensorCoverageProjection::build` now uses the same bounded incremental compiler as
`CoverageProjectionBuilder`. This closes two reference-level gaps in the coverage path:
input accumulation before graph limits are checked, and completion after silently ignoring
an input refusal. This is pure derived analysis, not sensor authentication, current
availability, clock calibration, or an absence certificate.

## Integration

The existing slice API and single-point reports retain their canonical graph bytes,
ordering, witness identities and successful answers for admitted inputs. The default
compiler admits at most 1,048,576 input rows, 1,048,576 distinct sensor-zone facts,
65,536 nodes, 1,048,576 edges and 64 MiB of cumulative input identity bytes. Rows with
zero witnesses and duplicate rows consume the input allowance. Distinct zero-witness
facts still retain their sensor and zone; they do not create sensor-zone edges.

`CoverageBuildLimits` permits independently tightening each ceiling. It cannot widen
the hard profile. Limits and construction counters do not enter a successful graph's
identity. `GraphBudget` remains the independent bound for bridge traversal/output.
These counters are not elapsed time or an exact heap-byte meter.

The streaming API removes the need to collect a second vector of observations:

```rust,ignore
use fss_graph_algorithms::coverage::{CoverageBuildLimits, CoverageProjectionBuilder};

let mut builder = CoverageProjectionBuilder::new(site, CoverageBuildLimits::default())?;
for observation in retained_observations {
    builder.push(&observation)?;
}
let admitted = builder.usage();
let projection = builder.finish()?;
```

The caller still owns source completeness, snapshot pinning, authorization and coverage
window selection. Finishing a builder does not certify that an upstream iterator supplied
all intended records. The existing deployment readers are not changed to streaming I/O by
this API alone.

## Failure semantics

Every push checks its cumulative row/identity/fact/node/edge admission and exact witness
sum before mutation. A refused row poisons the builder. Subsequent pushes and `finish`
return that original refusal; they cannot produce a graph over the accepted prefix.
The usage counters name only successfully admitted input, not attempted or failed work.

Exhaustion uses the existing `ERR-GRAPH-BUDGET-EXHAUSTED-001` identity with a precise
`coverage_observations`, `coverage_identity_bytes`, `coverage_facts`, `coverage_nodes`
or `coverage_edges` dimension. Requests that try to widen a hard cap return the existing
input-invalid error. Duplicate witness-count overflow and per-zone total overflow return
`ERR-GRAPH-NUMERIC-OVERFLOW-001`, never a saturated total.

Before single-point analysis, the projection's public graph and witness map are checked
against the entire expected node/edge sets, including zero-count facts. Extra plane-zone
paths, hidden nodes, injected sensors and omitted facts refuse even when articulation
points happen to be unchanged. This is internal consistency, not cryptographic validation
of the caller's witness assertions.

## Reference checks and remaining qualification

The in-tree tests cover exact and exhausted admission boundaries, duplicate/zero rows,
UTF-8 byte accounting, canonical compatibility against an explicit graph, terminal input
and arithmetic refusals, source-free extra edges, missing facts and extreme witness counts.
No schema or durable encoding is changed. These are reference semantics; camera/site
qualification and performance measurements remain separate obligations.

Focused validation:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-graph-algorithms --lib coverage::
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib coverage_graph::
```

This change does not establish a local DSR release receipt.
