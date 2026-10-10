# Current-event support explanations

`fss_graph_algorithms::evidence_brief::explain_current_support` turns one current
head in an exact `EvidenceHistoryProjection` into a bounded decision-oriented
explanation. It does not replace the event, change its state or probability,
verify source custody, certify independence, or authorize an effect.

The brief distinguishes two questions. A frontier-rooted `ALG-DOM-001` run finds
objects on every declared rooted support path. A second, target-rooted
post-dominator run finds all positive-support ancestors. Both use the same
immutable history graph and authority anchor. The second run receives only the
first run's remaining operation and output allowances. Each carries its existing
registered algorithm witness; an existing AOP-011 `ExplainReceipt` binds both
witnesses and the exact current target. No new durable encoding or digest domain
is introduced. Witness output digests cover the complete registered algorithm
answers, not the brief wrapper.

This distinction exposes failures that a list of direct evidence cannot:

* Two differently labelled branches can share one recording as an indispensable
  object. Different names or multiple edges do not prove independence.
* A valid-looking alternative path does not erase another branch that terminates
  at an unsupported historical claim. Every such leaf remains explicit.
* A historical support revision stays linked to its exact digest, alongside its
  separately identified current head and lifecycle state. Corrections are visible
  even when the old revision is a transitive, non-indispensable dependency.

`unexpanded_support` means non-event references whose bytes this computation did
not hydrate. `bottleneck_objects` means graph vertices, not physical failure
domains. An empty bottleneck list on an unrooted target does not prove redundancy.
Superseded support does not automatically invalidate a dependent event: it is a
review dependency. Contradiction, invalidation, tamper, temporal order and other
non-support relations are preserved by the underlying complete event records but
never become positive paths. Direct relation counts stay explicit.

The caller must project authorization and privacy before building the input.
Compiler admission uses the existing `HistoryLimits`; its catalogue accounting,
source I/O and brief projection costs are separate from the two algorithm runs.
The four result lists share one explicit ceiling of at most 256 identities. A
superseded pair costs two entries, including its current revision. Exhaustion
refuses the entire brief, never truncates a dependency or correction pair.

## Validation

Ten Rust contracts cover shared recordings, unsupported alternatives, transitive
historical corrections, non-support relations, exact combined budgets, target and
anchor binding, complete entry limits, and 256 seeded histories against independent
reverse traversal and repeated node removal. Run:

```sh
cargo test -p fss-graph-algorithms --test evidence_brief_contract
```

Rust compilation, native tests, rustfmt and Clippy have not run in this authoring
environment: no Rust toolchain is installed and the available network routes
could not obtain one. A supplementary Python model was executed over 1,024
histories, with independent traversal and node-removal comparisons; it is not
execution of the Rust implementation. This remains an unqualified reference
increment, with no broad bead or release gate closed.

## Standard agent command

The normal AOP-011 path now includes this analysis:

```sh
cargo run -p fss-cli --bin fss -- explain --json \
  --root /path/to/deployment --event-id event:your-event
```

No new verb, binary, request envelope or permission is introduced. The existing
read-only deployment reader and orientation establish the local reference scope.
Every retained head must still match its committed revision digest and complete
chain tail, and the explanation and orientation must name that same snapshot.
Only then is the historical graph compiled. This path assumes the existing
operator-local authorization model: the principal argument is an audit label,
not authentication or a new multi-tenant privacy filter. Source media remains
outside the allowed metadata projection and is never hydrated by the graph.

The response remains `AgentResponseEnvelope` with an `AgentCognitiveEnvelope`
payload. All original cells, protected worlds, assumptions, invalidators and
next-action objects are preserved. Additional `claim:event-support:...`
propositions describe only structural facts: direct relation counts, exact
unexpanded references, bottlenecks, unsupported branches and historical/current
revision pairs. Current custody and independence remain explicitly unknown to
this computation. The outer physical knowledge state and stored event's
probability, lifecycle and decision path are not upgraded or rewritten.

An existing `ExplainReceipt` composes the original explanation receipt, the
structural receipt, the event publication root and the authority state root.
The outer decision fingerprint and cognitive decision digest use this composite;
the payload digest still binds every emitted payload byte. Graph witness and
receipt digests are recomputable derivation pointers, not newly persisted proof
objects: no fake available H2/H3 handle or unimplemented hydration route is added.
The original two priced evidence handles and domain-owner affordances remain.

### Bounded complete explanation

The two graph runs share 2,000,000 operations and 65,536 output entries. The
compiler retains its existing catalogue ceilings, and at most 256 brief identities
are admitted. The added semantic fields have an 8 KiB ceiling and a separately
reported estimate of `ceil(UTF-8 field bytes / 4)` tokens. This estimate includes
proposition identities/statements/states/provenance/evidence, assumptions, invalidators, warnings,
proof pointers and accounting explanations. It is added to the pre-existing
orientation context charge; the combined charge must fit the registered
`decision_diff` maximum of 1,800. This is an explicit semantic-field estimate,
not a claim to have tokenized the complete serialized response with a model's
tokenizer. Cognitive and outer budget vectors report the same combined charge.

An independent 256 KiB ceiling bounds the whole serialized successful response,
including its final newline. Invalid history, mismatched bindings, failed graph
bounds or an oversized complete explanation produce a registered AOP-011 refusal,
not a successful base explanation with a quietly missing support section. No
list, correction pair, warning or protected alternative is truncated. Unknown-event
and unreadable-root behavior keep their existing paths. Larger forensic inspection
can use the existing `fss-evidence analyze-history` operator command under its own
limits; that is not permission to bypass an agent capability/privacy projection.

Source reads are still bounded by the existing `OrientLimits`. The graph adds no
I/O and no ambient clock, so its hard work budget is not a wall-clock deadline.
Compiler/summary work is cardinality-bounded separately from the registered graph
counters. CPU, full-output tokenization and allocator-peak measurements remain
unavailable and are not inferred from graph work counts. A refused graph produces
no completed graph witness; refusal accounting explicitly retains the original
orientation's known charge rather than claiming the failed graph consumed zero.

### Integration validation

Six focused native adapter tests cover compact risk propositions, unsupported and
superseded evidence, stable identities, explicit unknown custody, semantic-budget
boundaries and no truncation. Two native process contracts use the real
`fss-file import` -> preview/approve `fss-event watch` -> `fss explain` path on a
procedural JPEG scene. They assert standard envelopes, original cells and all
worlds, physical-state preservation, matching combined budget vectors, deterministic
read-only retries, no fabricated source handles and the existing unknown-event
refusal. These tests are authored, not executed in this environment.

```sh
cargo test -p fss-cli --lib orient_cmd::evidence::tests
cargo test -p fss-cli --test explain_support_cli_contract
cargo test -p fss-cli --test orient_cli_contract
```

Native qualification remains open; no release gate, broad bead or source-custody
claim is closed by this integration.
