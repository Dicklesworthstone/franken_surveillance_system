# Select retained evidence providers across declared failures

`fss-cover select-resilient` connects the existing `ResilientCoverProblem` owner to
the read-only, whole-window coverage reader. It selects **one sensor set** that
covers every requested zone in the baseline and after each declared shared-failure
domain loses all of its members. This is an authored reference candidate, not a
production qualification or an effect grant.

```sh
fss-cover select-resilient --root ./deployment --site site:home \
  --during 1500000000:2100000000 --zone ground-zone:gate \
  --failure-domain power:ups=sensor:a,sensor:b \
  --failure-domain network:switch=sensor:b,sensor:c \
  --method exact-small --max-sensors 2
```

The times and identities above are illustrative. With positive retained gate
coverage from all three sensors, the exact selection is A,C: C survives the power
loss and A survives the network loss. This does **not** claim survival when both
domains fail together. Overlapping memberships do not change the separate-scenario
interpretation. Domain declarations are owner assertions, not discovered physical
independence or a claim that every relevant failure was declared.

## Source and hard constraints

All common `select` options apply: explicit existing root/site, a required common
capture window, explicit `zone:ID` or `ground-zone:ID` targets, mandatory/excluded
sensors, maximum sensor count, exact-small/greedy method, work/output ceilings,
deadline, and optional `--expected-coverage sha256:...` source-witness pin. The
same whole-witness reader is used once; partial-witness unions and evidence from
disjoint intervals cannot supply a surviving witness.

Declare each domain as `--failure-domain KIND:ID=SENSOR[,SENSOR...]`. KIND is
`network`, `power`, `clock`, or `host`. `=` separates the label from membership;
commas separate exact sensor identities. Labels therefore cannot contain `=`, and
member identities containing commas cannot be represented by this command. There
is no whitespace trimming or inferred membership. Duplicate kind/label pairs and
duplicate members are refused. Order of declarations and members does not change
the report. Unknown members are refused against the retained source inventory;
known zero-support sensors remain in that inventory.

At least one domain is required. At most 16 domains and 64 total
`(domains + baseline) * zones` obligations are accepted. Matrix overflow and malformed
arguments are rejected before the source is read. The command never drops a zone,
samples failures, or silently substitutes ordinary selection. Ordinary `select`
continues to reject `--failure-domain` and retains its existing report format.

Mandatory sensors remain selected and count toward cost even when they fail in a
scenario; they provide no support there. Exclusions are never relaxed. Exact-small
retains its 20-eligible-optional-sensor bound; an oversized or exhausted request is
not converted to greedy. Cost is sensor count, not money, confidence, or risk.

## Reading the report

The separate `fss.coverage_resilient_selection.v1` report includes the original
coverage witness and source digest, complete declarations, reduction and expanded
solver input digests, and the resulting selection witness pinned to the original
source witness and anchor. Every requested scenario/zone pair appears once in
`obligations`, in baseline-then-canonical-domain order. Each row contains its bound
obligation token, zone, failed domain (`null` for baseline), status, and sensor.

A `supported` row names the canonical selected surviving witness provider. An
`uncovered` row has no support from the returned selection. An `uncoverable` row
has no eligible surviving provider at all. Unsupported rows have a null sensor;
no provider is invented to make the report look complete. Foreign reduction tokens
and inconsistent result partitions are refused before rendering.

The top-level `status` is independent of whether the algorithm completed:
`covered` means every obligation is supported; `infeasible_within_limit` is an
exact search result; `heuristic_incomplete` is not a proof of infeasibility;
`uncoverable` identifies structural lack of support. Exit zero means a complete
query report, not necessarily a feasible selection. The schema checks report
shape and status/method consistency; it is not a cryptographic verifier or proof
that supplied domain assertions describe the world.

This command does not change retention, policy, cameras, models, event state, or
any authority record. It does not authorize shutting down unselected sensors.
Work units price the expanded solver, not separately bounded source reads or the
reduction. The witness's charged solver workspace is not an allocator measurement
or a memory receipt for the whole command. Deadlines are cooperative; individual
filesystem calls are not preemptible. An oversized report is refused, not truncated.

## Validation boundary

The native unit contracts cover parser isolation, ordering, bounds, exact/greedy
failure distinctions, explicit scenario certificates, mandatory failures, unseen
zones, foreign-context rejection, cancellation and whole-report byte limits.
They are authored but have **not been compiled or executed in the authoring
environment**. Source/lexical and JSON Schema checks cannot substitute for Rust
compilation or native end-to-end execution. The existing registry qualification
status remains unchanged.

```sh
RCH_FAIL_OPEN=0 rch exec -- cargo test -p fss-cli --bin fss-cover
RCH_FAIL_OPEN=0 rch exec -- cargo clippy -p fss-cli --bin fss-cover -- -D warnings
cargo fmt --all -- --check
```
