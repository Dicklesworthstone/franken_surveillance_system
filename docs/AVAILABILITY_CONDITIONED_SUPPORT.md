# Availability-conditioned declared support

`fss_graph_algorithms::evidence_brief::availability::analyze_current_availability`
connects exact custody observations to the retained-history support graph. It
answers whether one current event still has a declared path to a checked or
unchecked non-event reference. It never adjudicates that event or changes its
probability, lifecycle, counterevidence, protected alternatives or effect rights.

The two graph views use the existing registered ALG-DOM-001 implementation and
witness contract. The possible-reference view removes known unavailable objects.
The verified-reference view also removes unchecked objects. Both retain exact
historical revisions and only explicit Supports edges. All unavailable objects
are removed simultaneously: losing two alternate sources can exhaust support
even though either source alone was dispensable. A shared source can block many
apparently separate branches. Neither a newer revision nor newly verified
metadata repairs a historical branch that has no declared supporting source.

The result distinguishes `verified_reference_path`, `unchecked_reference_path`,
`no_unblocked_reference_path`, and `no_declared_support`. An unchecked reference
is not a missing reference. The third state includes already unrooted branches;
it does not assert that a newly observed loss caused the failure. The existing
unconditioned support brief remains the baseline for that distinction.

## Observation contract

The caller supplies unique exact digests from one authorized custody observation
and revalidation scope. Missing, corrupt, role-invalid and denied objects are
Unavailable. Access failures and per-object size limits are Unchecked, not proof
of absence. References without an observation default to Unchecked. Canonical
event records validated by the history projection participate as metadata, not
as independent source evidence; an explicit adverse observation still restricts
that exact object vertex. No arbitrary filesystem or network read occurs here.

Observations of manifests or other objects outside the declared support graph
are counted as outside the graph, not declared irrelevant. They must remain in
the caller's custody findings. A path to an intact opaque object does not certify
its embedded semantic references or descendants. A verified-reference path is
not an AND/OR proof, sensor-independence certificate, authenticity determination,
absence certificate, durability upgrade or statement of physical event truth.

Two complete registered runs share the caller's operation and output allowance.
The second receives only the first's remainder. Graph construction is separately
bounded by the existing history projection and 65,536-observation ceiling; it is
not included in algorithm work counters. Duplicate observations, unknown targets,
invalid inputs and budget failures yield no partial result. The caller must bind
the original custody findings and both graph witnesses into its response; the
witnesses certify graph computations, not how storage observations were acquired.
This is non-durable derived cognition in the existing evidence-brief module.

## Validation

Eleven authored Rust contracts cover the states, simultaneous and shared losses,
unchecked intermediate records, unsupported metadata, historical exactness,
counterevidence, unmapped faults, deterministic ordering, duplicate admission,
exact combined budgets, anchor binding, and 256 generated histories against an
independent record-level fixed-point oracle (1,536 target queries).

```sh
cargo test -p fss-graph-algorithms --test evidence_availability_contract
cargo test -p fss-graph-algorithms --test evidence_brief_contract
```

Native compilation, Rust tests, rustfmt and Clippy have not run in this authoring
environment: no Rust toolchain is installed and the attempted network/connected
routes did not provide one. A supplementary Python incidence-graph model passed
45,292 target/view comparisons across 4,096 generated graphs against a separate
record-level oracle, plus 4,096 monotonic-loss checks. Lexical/delimiter checks
are not type checking. None of these substitutes for native execution or closes
a release gate or broad bead.
