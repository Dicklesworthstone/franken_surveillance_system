# Retained coverage timeline

`fss-event graph timeline` exposes changes within a capture window: handovers between sensors,
simultaneous qualifying witnesses, witness gaps, sensor single points of failure and optional
owner-declared common failures. It reads one committed deployment snapshot and never writes,
repairs, changes policy or authorizes effects.

```sh
fss-event graph timeline \
  --root /path/to/deployment --site site:home \
  --during 1000000000:5000000000

fss-event graph timeline \
  --root /path/to/deployment --site site:home \
  --during 1000000000:5000000000 \
  --failure-domain network:lan=sensor:front,sensor:side \
  --failure-domain power:ups=sensor:front,sensor:side
```

Use sensor identities present in the retained coverage. Domain declarations are owner assertions,
not verified topology. Each domain is evaluated separately, with all its members removed together;
overlapping declarations do not represent alternative routes or joint failures.

## Different questions, separate commands

`graph single-points` is the unchanged historical projection: any retained witness can contribute.
`graph single-points --during A:B` is also unchanged: an edge requires one certain witness covering
the **whole** query window. Partial witness unions never satisfy that command.

`graph timeline --during A:B` partitions the full query at every certain witness boundary. Each
segment uses the existing single-points algorithm, and one witness must cover that whole segment.
For example, sensor A covering `[0,4]` and sensor B covering `[6,10]` produces `[0,4]` with A, `[5,5]`
with no qualifying observer, and `[6,10]` with B. It does not claim two simultaneous observers.
Adjacent `[0,4]` and `[5,10]` witnesses have no invented gap; `[0,5]` and `[5,10]` have a real,
one-nanosecond simultaneous segment at `[5,5]`. Counts changing without a sensor change may still
create a segment because witness multiplicity remains part of the reported evidence.

## Claims that must not be inferred

A witness gap means **no qualifying retained certain coverage witness**. An observed entry can
split a coverage witness, so a gap can contain actual observed activity. It is not automatically a
camera outage, physical blind spot, quiet interval, or absence certificate. Unknown zones are not
discovered by this query. Known zero-witness sensor/zone rows remain visible in every segment.

Only `CoverageRecord` witness `covered` bounds create edges; uncertainty `outer` hulls and excluded
ranges do not. Capture times are operator hints, not calibrated cross-camera clock alignment.
Multiple observers do not certify independence, and historical retained evidence does not certify
current availability. Undeclared power/network/clock/host dependencies remain unknown.

## Output and identity

The buffered JSON format is `fss.coverage_timeline.v1`. It contains the site, one committed anchor,
full inclusive capture window, `certain-boundary-partition-v1` selection, chronological segments,
aggregate usage and explicit claim limits. Every segment contains its inclusive capture window and
a normal `fss.coverage_single_points.v1` result. Optional shared failures are attached to that result.
All capture endpoints are decimal strings, preserving the full signed 128-bit nanosecond range in
JavaScript and other JSON consumers. A query with equal endpoints is valid.

A segment's projection identity is:

```text
SensorCoverageGraph@t1:COMMIT:QUERY_START:QUERY_END:SEGMENT_START:SEGMENT_END
```

`t1` binds the timeline selection policy. Each `GraphAlgorithmWitness` binds this identity, the
same committed anchor, exact projection graph and the registered algorithm output/counters. Shared
failure witnesses bind their parent segment witness digest. Equal graphs in different queries or
segments do not acquire the same contextual witness identity. No new canonical durable format or
universal agent operation is introduced by this read-only CLI report.

## Refusal and resource limits

The runtime caps input at 4,096 records, 4,096 sensor/zone rows and 8,192 certain intervals. Duplicate
rows merge canonically but still count against input admission. Duplicate witnesses retain counts,
not additional observers. All source intervals are validated, even outside the requested window.

The whole query is limited to 256 segments, 2,000,000 source/selection/graph operations and 100,000
output entries. Source copying, core input scans, interval selection and all graph traversals share
that budget; it is never reset per segment or failure domain. Output accounting includes segment
headers and sensor/zone rows as well as registered graph output. A shared-failure batch also retains
its existing per-batch ceiling. JSON is buffered and limited to 8 MiB before writing to stdout.
Algorithm or size refusal emits no partial JSON; an operating-system stdout write failure can still
interrupt delivery. Deployment reads retain their existing independent `OrientLimits`.

The compiler uses ordered maps/sets and O(S * (F + W)) selection work plus registered graph runs,
where S is segment count, F is canonical fact count and W is witness count. No duration subtraction
or unchecked endpoint successor is needed at the signed timestamp extremes. Budget exhaustion is
an explicit refusal, not sampling or a truncated successful result.

## Validation commands and current boundary

```sh
cargo test -p fss-graph-algorithms --test coverage_timeline_contract
cargo test -p fss-reference coverage_timeline
cargo test -p fss-cli --bin fss-event
cargo test -p fss-cli --test coverage_timeline_cli
python3 crates/fss-graph-algorithms/tests/fixtures/coverage_timeline_model.py
```

The implementation session executed the independent Python interval model: 24,389 exhaustive cases,
4,096 seeded cases and signed-i128 boundary cases passed. That is algorithm-design evidence, not
execution of the Rust code. Rust compilation, native tests, rustfmt, Clippy and full local
qualification were **not run** because the editing environment had no Rust toolchain. Added Rust
regressions cover pointwise observers, real retained-record construction, observed-entry exclusions,
identity binding, strict CLI parsing, buffered refusal and shared cumulative budgets. The feature
remains `implemented_not_qualified`; no deployment or resilience claim is promoted.
