# Exact historical event support

The additive `evidence_history::EvidenceHistoryProjection` connects current event
heads to exact historical event records, rather than treating every non-current
revision as an unexplained source boundary. The active-only projection remains
unchanged. This implements a further retained-record part of `EvidenceClaimGraph`
and `ALG-DOM-001` (follow-on to `fss-x4a.23.31`), not a new authority plane.

## Interpretation

Supply complete oldest-first lineages from one verified deployment snapshot.
Every lineage, including unused ancestors, is validated using the canonical event
chain verifier. Empty, partial, forked, reordered, duplicate and invalid histories
are refused. All lineage heads are selected. An iterative exact-digest walk then
expands every event record referenced by their evidence, transitively, including
contradictions and neutral relations. Unreferenced ancestors are validated but
not bulk-expanded; their count and compiler cost remain explicit.

Only explicit Supports relations add positive incidence paths. Supersession,
contradiction, tamper, invalidation and derivation do not provide positive support.
The original revision, evidence order, uncertainty and complete record bytes are
retained. An old reference is NEVER redirected to its newer successor. Heads are
reported separately so a referenced old claim cannot masquerade as current truth.

An unsupported historical event now remains structurally unsupported. An event
supported only by that old claim becomes unrooted, rather than appearing rooted
at a supposedly independent reference. When two historical branches depend on the
same recording, dominator analysis exposes that shared artifact. Neither result
establishes truth, corroboration, independent sensors, source availability, physical
absence, an AND/OR proof, or permission to act. Non-event references remain explicitly
unexpanded. Later corrections do not disappear merely because earlier revisions
are followed: every current head remains in the projection.

## Bounds and identity

The catalogue admits at most 128 lineages, 64 revisions per lineage, 8,192 total
revisions, 16,384 evidence edges and 16 MiB of canonical versioned event bytes.
Caller limits may only narrow these ceilings. All edges and bytes, including
unused ancestors and counterevidence, count before graph construction. Dominator
operation and output budgets remain separate and fail closed without fallback.
The existing weighted graph's node/arc limits still apply. The compiler has no I/O
or time source. A caller must separately bound snapshot reads and cancellation.

The graph unit `retained-history-support-incidence:v1` and projection identity
`EvidenceClaimGraph:retained-history-support-incidence:v1` distinguish the policy
from the original active-only v1 graph. Canonical event digests bind every original
field, including relations excluded from positive traversal. Algorithm witnesses
bind the source anchor, graph/query, policy, implementation, output and decisions.
Catalogue-only accounting is NOT covered by the algorithm output digest. No
canonical durable event format, existing witness policy, or generation is rewritten.

## Validation scope

This is an authored reference implementation, not production qualification.
The native contract target covers exact historical references, unsupported
ancestors, shared-artifact bottlenecks, counterevidence, complete-chain refusals,
compiler and algorithm budgets, anchor separation and 256 seeded projections
against the existing independent node-removal oracle with permutation checks.
Rust compilation, native test execution, rustfmt and Clippy were not available in
this authoring environment. Independent Python semantic checks are supplementary,
not execution of the Rust implementation.

```sh
cargo test -p fss-graph-algorithms --test evidence_history_contract
cargo test -p fss-graph-algorithms --test evidence_projection
```

No bead, hardware support claim or release qualification is closed by this code.
Source custody checks and the universal agent-response integration remain separate.
