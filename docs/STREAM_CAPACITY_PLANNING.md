# Camera-stream capacity and failover planning

`fss-event graph capacity` answers whether an explicitly declared network and recorder
topology can carry the requested camera rates. It first maximizes aggregate delivered
rate, then finds the minimum declared link cost among routings with that delivery.
The report preserves every camera's demand and names the limiting cut when capacity
is insufficient.

This connects the existing certified maximum-flow and minimum-cost-flow algorithms
to an operator query bound to one retained source snapshot and capture window. It is
a read-only planning command; it does not activate cameras or change routing.

## Example

The following declarations request six megabits per second from a retained camera.
The primary link carries four at cost one per rate unit, and the backup carries four
at cost three. The recorder can accept eight.

```sh
fss-event graph capacity \
  --root /srv/fss/site-a --site site:a \
  --during 1000000000:2000000000 \
  --rate-unit megabits-per-second --cost-unit routing-points \
  --node camera-switch --node archive \
  --camera sensor:gate=camera-switch=6 \
  --recorder disk=archive=8 \
  --link primary=camera-switch=archive=4=1 \
  --link backup=camera-switch=archive=4=3
```

If the retained projection names `sensor:gate`, the complete query returns
`fully_routed`: four units use the primary link and two the backup, at total cost ten.
Add `--failed-link primary` to model its loss. Delivery becomes four and shortfall two;
the camera's requested rate remains six. `--failed-node camera-switch` retains that
demand with zero delivery and a shortfall of six.

These numbers follow from the declarations. The command does not measure bitrate,
congestion, packet loss, available storage, codec quality or camera health. Units are
explicit names attached to exact integers, not an automatic network-unit converter.

## Declarations and meaning

| Option | Meaning |
|---|---|
| `--node ID` | One infrastructure attachment or forwarding point, including isolated nodes. |
| `--link ID=FROM=TO=CAPACITY=UNIT_COST` | A named directed link with positive capacity and nonnegative cost per routed rate unit. Distinct names preserve parallel links. |
| `--camera SENSOR=NODE=DEMAND` | One complete positive rate request for a sensor in the retained source projection. |
| `--recorder ID=NODE=CAPACITY` | A recorder endpoint with a positive aggregate acceptance limit. Several endpoints may share a node. |
| `--failed-node ID` | A known node whose incident links and camera/recorder attachments are unavailable. Demands remain present. |
| `--failed-link ID` | A known link whose effective capacity is zero; its declared capacity remains in the report. |
| `--rate-unit UNIT` | Common integer unit for demands, links and recorder capacities. |
| `--cost-unit UNIT` | Unit of cost per routed rate unit; total cost sums flow times link cost. |

All endpoints must name declared nodes. Duplicate node, camera, recorder or link IDs,
unknown failures, self-links, empty units, zero capacities/demands and arithmetic
overflow refuse. Node, camera, link and recorder namespaces are distinct. Opposite
directions require separate declarations.

Flow is integral and **may split across routes**. This is an aggregate capacity model;
a particular RTP/TCP session is not thereby proven to support multipath. During a
shortage, the deterministic minimum-cost allocation has no fairness or camera-priority
guarantee. Recorder capacities cover the explicitly declared acceptance limit rather
than a prediction of disk endurance or future storage availability.

A fully served query can have a cut consisting of its demand-injection arcs. That
cut certifies the requested delivery; it does not measure spare network capacity.

## Retained source and replay

`--root`, `--site` and `--during START_NS:END_NS` are mandatory. The window uses
inclusive signed 128-bit nanoseconds. The existing bounded deployment reader opens
one committed snapshot and verifies the requested site. Every camera sensor must
occur in its retained coverage projection.

The report separately records each selected sensor's zones with a retained witness
covering the **entire** requested window. Partial-window unions do not qualify.
Known sensors with zero qualifying support remain explicit: their declared demand is
neither removed nor treated as evidence of coverage. Capture coordinates are retained
operator hints, not a clock-calibration claim.

`source_coverage_witness_digest` pins this source selection. Supply it on a subsequent
query with `--expected-coverage sha256:HEX`; a changed source/window refuses before
solving. The native query input also binds every topology declaration, cost, rate and
failure, including unused or failed components. The composition witness binds the
source anchor and parent witness digest. Reordering declarations changes no result
bytes; changing a failure, unit or otherwise inactive declaration changes its identity.

## Complete report and bounds

The registered `fss.stream_capacity.v1` JSON contains requested/delivered/missing rate,
minimum total cost, every camera/link/recorder row, a typed source-side partition and
the complete minimum cut. It includes the source witness, composition witness and
both underlying certified solver witnesses with their complete outputs. Final link
flows come from the cost-optimal maximum flow; conservation, capacity limits and
cut saturation are checked before publication.

Exit success means a complete query report, including `capacity_shortfall` when the
declared topology cannot serve every camera. Invalid input, stale source, exhausted
work, cancellation, overflow or an oversized report produces no partial result.

| Bound | Limit |
|---|---:|
| Infrastructure nodes | 256 |
| Named directed links | 1,024 |
| Distinct camera demands | 128 |
| Recorder endpoints | 32 |
| IDs / unit names | 256 / 64 ASCII bytes using letters, digits or `:_.-` |
| Command arguments after `graph` | 8,193; each at most 4,096 bytes |
| Solver work | 2,000,000 default; 50,000,000 hard maximum |
| Complete logical output entries | 32,768, including both solver outputs |
| Complete JSON | 2 MiB default and maximum; `--max-report-bytes` may tighten it |
| Deadline | 30,000 ms default; `--timeout-ms` accepts 1 through 3,600,000 |

One solver allowance covers reduction, both flow algorithms and final certification.
Source reads and their projection have independent existing bounds. Deadline checks
bracket nonpreemptible filesystem reads and run during the single-pass retained-support
selection and throughout both solvers. No complete answer is truncated to fit a bound.

## Validation and limits

The full native graph package passed **208 tests**. Eighteen new capacity contracts
include independent exhaustive integral-flow enumeration on 256 tiny networks, all
single-node/link failure variants on 64 seeded networks, alternative recorder/link
routes, cost ties, zero-cost cycles, namespace separation, checked numeric extremes,
permutations, exact cumulative budgets and cancellation at every checkpoint. Legacy
successful flow outputs, counters and witness identities remain unchanged.

The six CLI adapter tests and one cold retained-custody process test are authored,
including source deletion, byte-identical replay, stale pins, window changes, failure
shortfalls and unchanged storage. **They have not executed in this environment:**
the locked asynchronous dependency exceeds its build memory limit. Independent API
and source review and scoped formatting were completed; native kernel verification
does not qualify the full command/runtime. Strict scoped graph Clippy passes with
only four unchanged baseline lint categories allowed. No live-device or production
throughput qualification is claimed.

The library API is `fss_graph_algorithms::stream_capacity::{analyze, analyze_with_cancel}`.
Its exact identity, reduction, bounds and claim limits are recorded in
`architecture/stream_capacity_reference.json`.
