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

### Concurrent native validation record

While the agent adapter was being implemented, upstream commit
`79efb63fb7e796ac53f9bbeb28ceabcd01823571` recorded eleven evidence-availability
contracts passing natively on `nightly-2026-08-31`, as part of its combined
80-test run. Its diff preserves the graph implementation and tests from
`e80d46b49206ca10eb3ed64bf13b36bffda458df` unchanged. This is an upstream-reported
native result, not an execution performed in this authoring environment; retained
execution logs were not inspected here. It does not qualify the subsequent
agent-adapter changes or their new tests below.

## Standard checked explanation

The existing checked agent path now joins these observations to its already
compiled history graph:

```sh
cargo run -p fss-cli --bin fss -- explain --json \
  --root /path/to/deployment --event-id event:your-event --custody yes
```

A `claim:event-support:...:availability` proposition carries the resulting state.
The existing unconditioned structural brief and every custody fault, counterevidence
reference, protected world, stored probability and physical knowledge judgment
remain. A verified-reference path does not make a damaged publication intact:
missing counterevidence and faults outside the graph still appear separately.
A missing provenance manifest leaves its undiscovered source references unchecked,
not verified and not automatically missing. Missing the sole declared supporting
source removes its path but does not retract the event or certify physical absence.

The adapter requires the same exact subject, current publication root and FULL
authority anchor, not merely matching state-root text. Its custody observations
already passed the existing before/after authority and deletion recheck; the new
join adds no I/O or permission. The existing `ExplainReceipt` composes the original
support receipt, custody receipt and both additional graph witnesses. The cognitive
and outer decision identities use that receipt. The ordinary payload digest still
binds all rendered bytes. Witnesses and receipts remain non-durable derivation
pointers, not fabricated available media or persisted proof handles.

The initial support projection is moved into the private request-owned review,
not rebuilt or re-read. Both additional runs spend only the remainder of the
original 2,000,000-operation/65,536-output allowance, so ALL FOUR graph runs share
one ceiling. Output states, witness pointers and accounting text pay the same
semantic-byte token estimate and 1,800-token ceiling as the earlier checked path.
Filter construction remains separately bounded by the input graph and observation
ceiling. No unmeasured CPU, clock or allocator consumption is inferred from counts.
A complete result that fails graph or context admission is refused; it is never
replaced with the earlier unchecked explanation. The join stages all changes
before mutating the response, and consumes its private basis once on success.
The existing checkpoint deadline and 256 KiB output limit remain unchanged.

Omitted or disabled `--custody` keeps the same request, receipt and rendering path;
it runs no availability algorithms. The private graph can remain alive until
rendering completes, but it grants no new authority and is not serialized. The
public non-durable `CustodyReview` now exposes its revalidated anchor, and its
error enum has a `SupportGraph` variant for a failed graph contract. Exhaustive
Rust matches on that error enum must handle the addition. No stored format,
registry identity, CLI option, transport or model/dependency changes are introduced.

Seven new adapter contracts cover all eight custody-state mappings, same-graph
reuse, exact remaining budgets, anchor/root mismatch, non-promoting size refusal,
no partial mutation, one-time augmentation and exact semantic admission. Four
new process contracts reuse real event publication and cover standard envelopes,
unchanged disabled behavior, source loss versus damaged counterevidence, matching
budget/decision fields, read-only deterministic retries and unknown descendants.
The existing custody/explanation contracts are preserved. These eleven new native
tests have NOT executed in this environment.

```sh
cargo test -p fss-cli --lib orient_cmd::custody::availability_tests
cargo test -p fss-cli --test explain_availability_cli
cargo test -p fss-cli --test explain_custody_cli
cargo test -p fss-cli --test explain_support_cli_contract
```

Native qualification remains open. The supplementary model and lexical checks
do not establish that the Rust code compiles or that filesystem/process contracts
pass on a deployed system; full workspace or release qualification is not claimed.
