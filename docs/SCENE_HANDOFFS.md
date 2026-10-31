# Anonymous multi-camera handoff hypotheses

`fss-scene-fuse handoffs` computes globally consistent paths through a bounded inventory
of anonymous tracklets. It supplies the association hypotheses that otherwise have to be
authored before scene reconstruction. It uses the native certified assignment solver,
retains competing explanations, and keeps unmatched or unsupported tracklets visible.

The first profile handles **ordered handoffs between nonoverlapping tracklets**. The existing
scene-fusion command continues to handle explicitly supplied simultaneous multiview
correspondences. A handoff report is derived analysis: source handles, generations, transit
bounds and costs are owner declarations. The command does not fetch or authenticate the
source media, establish a person's identity, publish an event, or activate a policy.

For tracks already retained by native package detection, use
[`fss-scene-fuse retained-handoffs`](RETAINED_HANDOFFS.md). That command reconstructs
the actual assignments and source provenance, derives the camera/model/privacy bindings,
and revalidates custody and the current deployment anchor before returning the same
conditional planner's complete result. Clock alignment, calibration, transit and cost
remain explicit assumptions.

## Run a complete query

The repository includes a complete, synthetic four-tracklet/three-camera query:

```sh
cargo run --offline --locked -p fss-cli --bin fss-scene-fuse -- \
  handoffs \
  --observations tests/fixtures/continuity/three_camera_handoffs.json \
  --report-out handoff-report.json
```

Two gate-camera tracklets compete to explain a yard tracklet followed by a door tracklet.
Both best explanations have declared cost 22. Each retains the other gate tracklet as a
singleton. The report also retains the complete admissible family and the explicit
all-singleton explanation, whose declared cost is 40. Those numbers are objective values,
not calibrated confidence or likelihood.

`--report-out` creates a new private file exclusively. Its complete JSON, including the final
newline, is identical to stdout. An existing destination is refused before analysis and is
never overwritten. Omitting the option writes only stdout. A write failure is explicit and
may leave a partial newly created file; no durable event publication is claimed.

For reproducible file selection, calculate the query's SHA-256 and pass its previously saved
`sha256:HEX` text through `--expected-input`. A byte change, including whitespace, then refuses
before solving. Independently, the native input digest canonicalizes declaration order and
binds every semantic field. Reordering input arrays changes the document pin while preserving
the native result and decision identities.

## Query contract

The exact JSON schema is [`scene_handoffs_query.v1.json`](../schemas/scene_handoffs_query.v1.json).
Unknown fields, duplicate keys, missing fields, trailing input, non-UTF-8 and out-of-range
integers refuse. Numeric fields require JSON integer tokens; quoted, fractional and exponent
spellings are not coerced into clock or cost integers.

Every top-level field is required:

| Field | Meaning |
|---|---|
| `schema` | Literal `fss.scene_handoffs_query.v1`. |
| `scope` | One property, local analysis session, privacy-policy digest, analysis-generation digest and common-clock digest. |
| `time_unit` | Explicit common unit for signed capture ticks and nonnegative transit durations. |
| `cost_unit` | Explicit common unit for transition, birth and end prices. |
| `birth_cost`, `end_cost` | Nonnegative `u64` price for each path start and end, including singletons. |
| `k` | Requested displayed prefix, from 1 through 32. It never bounds the complete implicit family. |
| `tracklets` | Between 1 and 32 complete camera-local declarations. |
| `transitions` | Up to 992 explicit directed non-self pair declarations. Undeclared pairs remain unavailable. |

Scope contains exactly `property`, `session`, `privacy_policy`, `generation` and `clock`.
IDs use 1–256 ASCII letters, digits or `:_.-`; units have the same grammar and at most 64
bytes. All digests in this adapter are nonzero ordinary SHA-256 handles. A digest is a
binding to the caller's assertion, not proof of permission, current calibration or custody.

Each tracklet supplies:

| Field | Meaning |
|---|---|
| `id` | Unique identity within this query; it is not a permanent physical identity. |
| `camera` | Camera identity within the declared property/session. |
| `camera_generation` | Exact device/stream generation declaration. |
| `calibration` | Exact calibration generation declaration. |
| `model` | Exact model generation declaration. |
| `evidence` | Sorted canonically after admission; duplicate handles are refused. |
| `start`, `end` | Two-element inclusive signed `i64` intervals for first and last capture. |
| `support` | `declared`, `missing`, `invalidated` or `redacted`. |

`declared` support needs 1–16 evidence handles. The other states allow 0–16 and retain their
original declarations, but disable every incident transition. An unavailable tracklet remains
a singleton in every answer. Missing support never becomes negative evidence about the world.

Each capture interval must be ordered, and at least one locally valid start no later than end
must exist. The planner preserves the full endpoint bounds. It does not narrow intervals or
turn an event's union interval into invented exact entry/departure timestamps.

Each transition supplies exactly `from`, `to`, `transit`, `cost` and `basis`. The first two
must name distinct existing tracklets. `transit` is an inclusive `[minimum, maximum]` duration
in the declared time unit. `cost` is a nonnegative integer objective contribution. `basis`
pins the caller's transit/cost/geometry assumptions. Duplicate pair declarations, reversed
transit bounds, missing members and self-links refuse.

## Robust timing and generation admission

For a proposed transition from tracklet A to tracklet B, the full gap interval is:

```text
minimum gap = B.start.minimum - A.end.maximum
maximum gap = B.start.maximum - A.end.minimum
```

Admission requires a strictly positive minimum gap and the entire gap interval to fit inside
the declared transit interval. Subtraction uses exact `i128` arithmetic, including at the
signed `i64` limits. These tests apply to all endpoint combinations and therefore also to
every locally valid start/end choice.

This conservative rule has two useful consequences. Every admitted path can satisfy all its
handoffs together, and widening a capture interval cannot create a new admitted edge. Merely
possible pairwise transitions can require mutually incompatible choices for an intermediate
tracklet; that less conservative profile is not implemented here.

`not_strictly_forward` and `transit_not_robust` are **admission failures, not proofs of physical
impossibility**. Overlapping exposures may be valid multiview observations. Wider uncertainty
may leave a physically possible handoff unresolved. All such declarations remain in the
pair-disposition table, so the report does not erase those unknowns.

Model generations must agree across an admitted transition. A same-camera handoff additionally
requires the same camera and calibration generations. Different cameras preserve their own
calibrations separately. This profile has no feature-space migration, inferred clock alignment,
automatic geometry certification or cross-property/session linkage.

## Global objective and complete alternatives

The admitted robust transitions form a directed acyclic graph. Each tracklet becomes one
outgoing assignment item and one incoming assignment item. An allowed pair selects a handoff;
an unmatched outgoing item ends a path, and an unmatched incoming item starts one. The existing
certified Hungarian/Murty implementation minimizes:

```text
sum of selected link costs
  + birth_cost × number of path starts
  + end_cost × number of path ends
```

Equal-cost explanations use the canonical assignment tuple in tracklet identity order, with
unassigned sorting after assigned values. Input array order has no effect. Every returned cover
is checked for complete member coverage, unique predecessor/successor, admitted links, path
boundaries and exact cost decomposition.

The report contains three complementary representations:

1. `alternatives` is the exact first `k` covers under the declared objective and tie-break.
2. `alternative_family` contains every admitted edge and every original member. Its rule is
   every edge subset with at most one predecessor and one successor per member. Because the
   graph is acyclic, this exactly represents **all path covers of the admitted graph**, including
   covers outside the displayed prefix.
3. `alternative_family.all_singletons` materializes the no-handoff explanation independently
   of ranking. It cannot disappear because its objective is less attractive.

`displayed_prefix_complete` is true only when the solver proves fewer than `k` distinct
assignments exist. If the total happens to equal `k`, this field conservatively remains false.
The implicit family is still complete for the admitted robust domain. Neither representation
claims to enumerate all physical possibilities or account for undiscovered tracklets.

## Report, limits and failure behavior

[`scene_handoffs.v1.json`](../schemas/scene_handoffs.v1.json) describes the complete report. It
includes all tracklet declarations, every ordered non-self pair and all its applicable refusal
reasons, source/scope pins, the complete family, ranked covers, and both native solver
certificates. Each certificate carries its implementation/policy/domain identities, input,
output and decision digests, operation counters, logical output count and working-memory
account. This standalone query has no verified deployment anchor; it does not fabricate one.

| Allowance | Default | Hard limit |
|---|---:|---:|
| Input JSON | — | 1 MiB |
| Work units | 2,000,000 | 50,000,000 |
| Logical output entries | 32,768 | 32,768 |
| Displayed alternatives | Query declaration | 32 |
| Complete JSON including newline | 2 MiB | 2 MiB |
| Deadline | 30,000 ms | 3,600,000 ms |

Use `--work-units`, `--timeout-ms` and `--max-report-bytes` to reduce or raise the corresponding
allowances within those hard limits. Preparation, every assignment subproblem, reconstruction
and complete native proof share the work/output budget. The file read has its separate bounded
input allowance. Deadline/cancellation checks bracket the read and run inside native solvers;
the read itself is not preempted mid-system-call.

Exhaustion, overflow, cancellation, stale input pins, malformed input and oversized complete
output refuse the entire answer. No truncated ranking is presented as a complete result.
Exit 0 means this declared query completed, including when all tracklets remain singletons.
Refusal uses the existing scene-fusion structured error surface and exit 2.

## Validation and remaining scope

The native graph package passed 238 tests: the prior 208, 18 new continuity contracts and 12
tests compiling the **actual production** JSON parser, renderer and query adapter against the
real core/graph crates. The independent small oracle enumerates edge subsets rather than calling
the assignment implementation. It covers 256 graph/cost cases and permutations, 96 uncertainty
widenings, every cancellation checkpoint, shared quota boundaries, unsupported source states,
generation mismatches, signed extremes and the full 32-member/992-declaration inventory.

The adapter tests verify the three-camera fixture's cost-22 alternatives and cost-40 singleton
explanation, complete reports and proof fields, byte pins versus canonical ordering, strict input
refusals, output limits and unchanged JSON escaping. The final 12-case target and scoped graph
lint passed after typed error propagation was added. A real invocation of the production adapter
emitted a 9,270-byte report; its complete instance passed the scoped offline schema checker, and
all 12 targeted invalid mutations were rejected. Both schemas passed the repository reference
validator with 102 resolved references and zero new findings. These checks do not depend on a
fabricated report or a substitute solver. The private-file, stale-pin, cancellation,
symlink and no-overwrite wrapper tests are authored separately. Full `fss-cli`/reference process
execution remains unverified in this session because its asynchronous dependency build exceeds
the shared host's memory limit. Pure native adapter execution does not establish that integration
or release qualification.

This work advances plan §16.6 and WP-130 with a bounded automatic association consumer.
Authenticated retained-tracklet projection, calibrated association quality, ambiguous timing
constraint propagation, per-exposure duplication detection and simultaneous visibility fusion
remain separate work. The aggregate association beads remain open.
