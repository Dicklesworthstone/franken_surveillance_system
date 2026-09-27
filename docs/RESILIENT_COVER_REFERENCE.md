# Scenario-resilient retained evidence selection — FSS-160

`fss_graph_algorithms::resilient_cover::ResilientCoverProblem` is a library reference
candidate extending the unit-cost set-cover solver with explicit shared-failure
constraints. Native Rust compilation/tests and production qualification have not
run in the authoring environment. The `fss-cover select` operator command still
performs ordinary selection; it does not automatically invoke this API.

## What one selection must satisfy

The same selected sensor set must cover every explicitly requested zone in the
normal baseline and after each owner-declared failure domain is lost. Members of
one domain fail simultaneously; different domain scenarios are evaluated
separately, even when their memberships overlap. No undeclared joint failure,
independence, probability, or completeness claim is inferred.

For example, let A, B and C all support a gate. A shared power loss removes A and B;
a shared network loss removes B and C. The smallest selection satisfying both
separate scenarios is A,C. B alone is not sufficient. The simultaneous loss of
both domains would remove all three sensors, but that is not one of these declared
single-domain scenarios and is not certified by the answer.

Mandatory sensors remain selected and count against the sensor limit even in a
scenario where they fail. They supply no support in that scenario. Exclusions are
never relaxed. Unknown requested zones remain explicit unsupported obligations.
Unknown domain members, duplicate domain identities and tampered coverage
projections are refused using the existing coverage/domain validators.

## Reduction and evidence binding

Each `(scenario, zone)` becomes a separate context-bound set-cover element. A
sensor supports an element only when a positive supplied coverage fact exists and
the sensor is outside that scenario's failed membership. One solver invocation
selects a single sensor set for the entire expanded objective.

The context digest binds all source sensor/zone/count facts, the site plane,
the ordinary objective and hard constraints, and every domain's kind, label and
complete membership. Compact opaque obligation IDs include this context digest;
long zone and domain labels cannot overflow the graph's identity bound. A change
to a redundant declaration or witness count still changes the input identity.
Source order, domain order and member order do not change canonical results.

`problem.obligation(element_id)` resolves a result's support certificate or
uncovered element into its zone and failed-domain identity. `None` for the failed
domain denotes the baseline. A foreign input context cannot resolve its tokens.
The expanded solver input digest is distinct from the reduction context digest;
`problem.expanded_problem()` exposes the immutable expanded objective.

A `Covered` result means all supplied obligations have support in the selected
set. An exact result is minimum cardinality for that supplied problem; a greedy
incomplete result is not an infeasibility proof. Budget exhaustion or cancellation
returns no analysis or witness. The caller must still pin the result witness to
its authorized parent coverage witness and authority anchor. This API itself
performs no authorization, capture-window selection, storage or device control.

## Bounds and integration

At least one zone and one explicit failure domain are required. There are at most
16 domains and **64 total expanded obligations**, including baseline obligations.
For example, one domain permits 32 zones; three domains permit 16. A larger matrix
is refused, never sampled. The existing 1,024-sensor and 20-optional-sensor exact
limits apply. The constructor is structurally bounded; `CoverBudget` prices the
expanded solver, not source reads or input compilation.

The nine authored public-consumer Rust tests cover overlapping dependencies,
mandatory/excluded constraints, unseen zones, full-word boundaries, canonical
reordering, context rebinding, projection tampering, cancellation/work ceilings
and an independent direct-scenario oracle over 1,000 seeded constrained cases.
They have not been executed here. The separate standard-library Python model
checks 12,544 exhaustive small inputs and 5,000 seeded constrained cases against
a direct observer-set oracle; it does not establish Rust correctness.

Native validation in a complete checkout remains required:

```sh
RCH_FAIL_OPEN=0 rch exec -- cargo test -p fss-graph-algorithms --test resilient_cover_contract
RCH_FAIL_OPEN=0 rch exec -- cargo clippy -p fss-graph-algorithms --all-targets -- -D warnings
cargo fmt --all -- --check
python3 -B scripts/resilient_cover_model_check.py
```

No registry qualification or bead closure follows from source presence or model
checks. The machine-readable candidate contract is
`architecture/resilient_set_cover_reference.json`.
