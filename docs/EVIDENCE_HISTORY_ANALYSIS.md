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

## Operator commands

```sh
cargo run -p fss-cli --bin fss-evidence -- analyze-history \
  --root /path/to/deployment --site site:your-site

cargo run -p fss-cli --bin fss-evidence -- impact \
  --root /path/to/deployment --site site:your-site \
  --artifact sha256:REPLACE_WITH_64_HEX_DIGITS
```

Both commands use the existing read-only deployment reader, verify that the
selected head matches the retained revision-chain tail and committed revision
digest, and pass complete retained lineages to the compiler. They preserve native
filesystem paths, parse all options before I/O, refuse another site's snapshot,
and never create a deployment, take writer locks, repair, retract or dispatch.
Existing `analyze` semantics and report bytes remain unchanged.

`analyze-history` reports the historical graph's structure from its explicitly
unexpanded-reference frontier. `impact` runs the same registered `ALG-DOM-001`
from the exact requested artifact instead. `heads_reachable_from_query_root`
identifies current events with at least one explicit positive-support path from
that artifact, including paths through old revisions. An active revision is
reachable from itself by a zero-length path. Superseded revisions remain separate
from their successors: the current-head mapping and full expanded records are
always reported together.

Impact is **possible positive-support dependence**, not indispensability or proof
of invalidation. A target with alternate support paths still appears. Conversely,
no positive path says nothing about contradictory, invalidating, tamper, ordering,
or other non-support influence. An artifact not present in the expanded graph is
refused, not reported as unaffected. Catalogue-only ancestors are not implicitly
promoted into query roots. Source bytes are not hydrated and source custody,
deletion status and current availability remain unchecked by this diagnostic.

The JSON format is `fss.evidence_support_history.v1`, with an explicit mode and
query root. Every expanded record keeps its complete canonical event JSON, exact
digest, current-head mapping and positive-path result. Catalogue-only revisions
have explicit counts rather than silent disappearance. Both uncommitted-tail flags
and source read counters are retained. A false `positive_path_from_query_root`
is a structural fact in this graph, never physical evidence of absence.

The original analysis options apply: `--expected-witness`, `--max-operations`,
`--max-output-entries`, `--max-report-bytes` and `--timeout-ms`. Impact additionally
requires one `--artifact`; it is refused for `analyze-history`. The original
argument count/byte ceilings apply before forwarding shared options. Complete
reports, including their newline, must fit the byte budget; no record or warning
is dropped. Pins bind the exact query root, mode's projection policy and authority
anchor through the registered witness, not changing filesystem availability.

The increment adds three native impact contracts and nine operator contracts
covering history expansion, exact artifact roots and pins, alternative support,
complete record preservation, strict parsing, native paths, cancellation, missing
sources, wrong sites, corrupt chains and exact output limits. These native tests
are authored but unrun in this environment; the independent Python model is not
a replacement for them.

```sh
cargo test -p fss-cli --bin fss-evidence
```
