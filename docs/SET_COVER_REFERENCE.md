# Bounded evidence and sensor set selection — FSS-160

This is an **authored, unvalidated reference candidate** for the existing
`ALG-SETCOVER-001` row. It does not change that row's `specified` status or claim
`INT-FNX-001` qualification. Its machine-readable subset contract is
`architecture/set_cover_reference.json`. No dependency or runtime is introduced.

## What it computes

Given an explicit protected-element universe, covering sets, mandatory sets,
excluded sets, and a maximum set count, find a subset covering every requested
element. Cost is **one unit per selected set**, not money, confidence, information
value, privacy exposure, risk, or a combined recommendation score.

`ExactSmall` enumerates subsets in cardinality then stable set-identity order.
With at most 20 eligible optional sets it proves a minimum-cardinality solution,
or proves that none exists within the selection limit. Mandatory sets are always
included and count against that limit, including redundant or empty-support sets.
There is no fallback to a heuristic when exact search is too large or out of work.

`Greedy` admits up to 1,024 sets over at most 64 elements. It picks maximum
remaining marginal coverage, breaking ties by stable set identity. A completed
cover need not be optimal. A greedy result reaching its cardinality limit is
`heuristic_incomplete`: an exact solution may still exist. For example, over
{1,2,3,4,5,6}, A={1,2,3,4}, B={1,2,5}, C={3,4,6}, greedy picks A first and needs
three sets; exact selects B,C. At a two-set limit the heuristic cannot certify
infeasibility.

An element with no eligible support is `uncoverable` in **this supplied input**.
It is never dropped, never made observable, and never treated as physical absence.
An `infeasible_within_limit` exact result returns only its mandatory floor, not a
purported best partial cover. A structurally uncoverable request likewise returns
its mandatory floor and lists both all currently uncovered elements and the
irreducibly unsupported ones.

## Evidence and compatibility

Inputs are canonically ordered. Input digests bind the entire explicit universe,
every support, mandatory/excluded identities, and cardinality limit. Exact and
greedy have distinct implementation and policy IDs. Results include an explicit
coverage disposition and one positive support edge per covered element. A witness's
`completed` stop reason means the algorithm finished, **not** that the objective
was covered; consumers must inspect the separate disposition.

The decision-path field is a domain-separated **decision summary** binding the
input, immutable algorithm/tie policy, selection order, counters and output. It is
not a materialized log of every examined subset. The entire path is reproducible
from the canonical input and method. Unused execution budget does not change
result identity. All fields capable of modifying a result or mask are private.

`SetCoverProblem::from_coverage` accepts an already authorized
`SensorCoverageProjection`, rebuilds it to check public-field consistency, and
uses only positive retained witness counts. It preserves zero-support sensors and
unknown requested zones. The caller is responsible for common-window selection
and binding the resulting witness to the parent coverage witness and anchor.

This unit-cost specialization and the exact-small tie policy refine a previously
specified, unimplemented row; they do not change bridge-algorithm bytes or any
existing coverage command. Weighted/multicover, shared-failure-resilient selection,
Pareto affordance ranking and general active-perception planning remain open.

## Work, memory, cancellation and failure

Let n be all sets, e all required elements, and p eligible optional sets.
Construction validates hard limits before unbounded collections can be built;
canonicalization work is structurally bounded separately from solve work.
The solve charges input entries, greedy evaluations, mask updates, subset tests
and result checks. All resulting counters are checked against the machine
contract before any answer is returned. Independent ceilings are 50 million
work units and 8,192 output identities. Larger caller allowances do not raise them.

Exact subset enumeration uses an iterative fixed-cardinality index vector, not
recursion, a global cache or exponential retained state. No complete search
transcript is buffered. The witness's working-byte field is a **conservative
charged workspace bound**, not a measured allocator peak: input is excluded;
bounded index vectors, result construction and canonical encoders are included.
No wall-clock or performance claim is made.

`solve_cancellable` polls a request-owned callback for each charged work item and
before returning. Cancellation is a distinct typed error; neither cancellation
nor exhaustion produces an answer, partial optimum, absence claim or witness.
Invalid constraints, unknown set references and duplicate identities fail closed.
No I/O, threads, camera control, model invocation or authority mutation occurs.

## Authored regression coverage

The public-consumer Rust tests include an independent string-set exhaustive
oracle over 1,500 seeded problems, input reordering, mandatory/excluded inputs,
canonical ties, all 64 bits, empty objectives, zero cardinality, hard ceilings,
exact budget boundaries, cancellation at every probe, witness-parent binding,
unknown zones, and tampered coverage projection rejection.

These Rust tests have **not been compiled or run in the authoring environment**.
The independent Python finite model delivered separately checks algorithmic
semantics only; it cannot establish Rust type correctness, integration behavior
or qualification. Native validation in a full checkout remains required:

```sh
RCH_FAIL_OPEN=0 rch exec -- cargo test -p fss-graph-algorithms --test set_cover_contract
RCH_FAIL_OPEN=0 rch exec -- cargo clippy -p fss-graph-algorithms --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Read-only operator command

`fss-cover` is a narrow operator query, not a new `fss/1` verb or a certified agent
plan surface. It composes the existing `read_coverage_single_points_during` owner
with the set-cover API and returns `fss.coverage_set_selection.v1`:

```sh
# Every selected sensor needs one retained witness covering the WHOLE common window.
fss-cover select --root ./deployment --site site:home \
  --during 1500000000:2100000000 \
  --zone ground-zone:gate --zone ground-zone:door \
  --method exact-small --max-sensors 2

# Preserve an explicit mandatory sensor and exclude one from the candidate set.
fss-cover select --root ./deployment --site site:home \
  --during 1500000000:2100000000 \
  --zone ground-zone:gate --zone ground-zone:door \
  --require-sensor sensor:east --exclude-sensor sensor:west \
  --method greedy --max-sensors 3
```

These are illustrative command shapes, not real deployment timestamps or sensor
identities. Capture endpoints are signed 128-bit nanoseconds and are serialized
as decimal strings. Equal endpoints are permitted. The command does not infer UTC,
clock synchronization or current sensor availability from imported capture hints.

The source witness and its digest are included separately from the selection
witness. The latter's projection identity binds the former's entire witness digest,
including its exact anchor and window. Supply `--expected-coverage` with a previous
`source_coverage_witness_digest` to refuse any changed source basis; unchanged
queries and reordered repeated arguments produce identical report bytes.

Unknown requested zones remain explicit. Unknown mandatory/excluded sensors are
refused. Duplicate, inapplicable, oversized or contradictory arguments are rejected
before a deployment is read. Root paths accept native OS bytes. A source failure,
stale pin, hard bound, cancellation or deadline yields no report. Output delivery
can still fail after a partial stdout write; that is a nonzero exit, never a
complete delivery claim. Exit zero means the **query** finished, not that a full
cover exists: check `objective_covered` and `status`.

Selection cost is sensor count only. The command selects evidence providers; it
does **not** preserve multi-observer redundancy, shared-failure resilience or
independent evidence domains. It must not be used as permission to switch off
unselected cameras. Scope labels on different sensors are owner assignments, not
proof that image regions are geometrically equivalent. No sensor/retention/policy
configuration or event/alert state is modified.

`--work-units` prices the selection solver only. The existing source reader and
bridge projection retain their own structural/work bounds. The cooperative deadline
is checked before/after that read, throughout selection and after rendering;
filesystem calls are not preemptible. Reports are bounded to at most 2 MiB and are
never truncated to satisfy an output limit. No performance SLO is claimed.

The new schema is a candidate operator-report contract, not promotion of the
universal protocol schema catalog. Central registry and qualification status remain
unchanged until native compilation, schema/registry integration checks and the
required admission lanes are completed.

### Native integration harness (authored, not run)

`scripts/set_cover_cli_e2e.py` uses already-built `fss-file`, `fss-event` and
`fss-cover`. It imports embedded synthetic baseline JPEGs, runs actual watch
analysis, retains exact-approved coverage, and exercises the exact/greedy
counterexample through the native binaries. It checks mandatory/excluded sensors,
unknown zones, disjoint time windows, stale source pins, zero-output failures,
byte-determinism, full report schema validation and unchanged deployment bytes and
metadata. Python is a laboratory peer only; it owns no production semantics.

```sh
RCH_FAIL_OPEN=0 rch exec -- cargo test -p fss-cli --bin fss-cover
RCH_FAIL_OPEN=0 rch exec -- cargo build -p fss-cli --bins
python3 -B scripts/set_cover_cli_e2e.py --bin-dir target/debug
```

No native test or compiler command above has succeeded in this authoring
environment. A partial source snapshot cannot substitute for a complete checkout
with its exact sibling/toolchain closure. Before qualification or operational use,
run the native tests, format/Clippy checks, repository integrity generation and
`scripts/qualify.sh` as required by the repository. Do not close FSS-160 from source
presence, the independent Python model, or a green focused test alone.
