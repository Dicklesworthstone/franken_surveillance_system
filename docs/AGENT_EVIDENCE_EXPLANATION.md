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
