# Retained belief provenance: direct payloads and published graphs

This is a reference implementation of the retained-membership portion of `fss-s1gcl` / PROV-002.
A checksum over a belief is not evidence of its conclusion. The verifier independently selects the
current ledger, retained-object owner and registered derivation engine, verifies custody and
membership, supplies exact evidence to that engine, and compares the complete rebuilt belief.
Knowledge-cell projection remains cognition, never effect authority or an absence certificate.

## Entry points

The existing direct paths remain unchanged:

- `fss_core::belief_verification::verify_derived_belief` admits direct current authority payloads.
- `fss_object::belief_verification::decode_and_verify_retained_belief` adds bounded canonical intake
  against `InMemoryObjectStore` without automatically promoting staged bytes.

For transitive published manifests use
`InMemoryObjectStore::decode_and_verify_belief_graph(encoded, ledger, engine, request, max_encoded_bytes)`.
The lower-level `verify_derived_belief_graph` is available through
`fss_core::belief_verification::graph` for independently trusted graph owners implementing
`RetainedBeliefGraph`. The request supplies a nonempty, strictly increasing selection of authorized
current authority-object IDs, cumulative limits and a cooperative cancellation checkpoint.
Neither the selection nor the engine may be chosen by an untrusted offered conclusion.

The object-store adapter follows only explicitly published `ObjectManifest` edges. It cross-checks
canonical bytes against the exact publication, checks both cached and encoded edge counts before
decoder allocation, and refuses deletion-invalidated manifests. An unpublished payload whose bytes
happen to encode a manifest stays opaque. Reading saved bytes does not restore publication.

## What a graph proof establishes

Every object in the complete selected closures is custody-verified and independently SHA-256
rehashed, including unused metadata and siblings. Shared payloads are read once; repeated ancestor
walks are separately accounted. Missing/corrupt siblings, inconsistent publication metadata,
cycles, missing supporting or contradicting roots, stale/forked anchors, cancellation and exhausted
limits refuse before a proof is returned. A cancellation after engine execution also returns no proof.

`VerifiedBeliefEvidence::bindings()` contains only actual direct payload bindings among the
explicitly selected authority objects. Equal payload digests in unselected objects do not disclose
those objects' identities, families or validity. Snapshot usage and its admission budget count only
selected lookups; unrelated table cardinality does not leak through those counters or refusals.
The direct (non-graph) API still uses its independently supplied full-snapshot profile.
`ancestry()` separately carries each selected authority object's exact revision and one deterministic
shortest path through published edges. It does not relabel a leaf with an ancestor's semantic family.
Engines must validate the appropriate family, generation, scope and meaning. Shortest-path witnesses
are not an exhaustive inventory of every path through a shared graph. The depth bound is shortest
edge distance from each selected authority object, not maximum path length of the entire DAG.

A `VerifiedBeliefGraph` carries the existing private `VerifiedDerivedBelief`, ancestry and logical
usage. Neither proof is canonically decodable. Replaying a ledger and copying payloads is not enough:
manifest publication must be explicitly restored by its owner before verification can use its edges.
No intake path repairs, stages, publishes, deletes, or authorizes effects.

## Bounds and limitations

`BeliefGraphLimits` bounds snapshot inspection, offered roots, selected authority objects, unique
read attempts, bytes per object, total bytes, repeated visits, edge inspections, shortest-path depth,
and retained witness entries. Total bytes include ancestors and unused siblings. Refusals retain
`BeliefGraphUsage` rather than resetting consumed work. These are logical admission counters, not
measured native I/O, hash CPU or engine execution costs. Registered engines still own their execution
budgets; cooperative checks cannot preempt an arbitrary engine implementation.

SHA-256, the current `ReferenceLedger`, and `InMemoryObjectStore` are the concrete reference profile.
No persistent deployment graph adapter, production algorithm registry, historical inference profile,
BLAKE3 verifier, or wholesale legacy-caller migration is claimed. Existing structural
`DerivedBelief::new/rebuild/to_knowledge_cell` are not silently upgraded into provenance checks.
The broader bead remains open. Durable belief bytes and existing direct-verifier identities are
unchanged by the graph extension.

## Reproduce the focused tests

```sh
bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance
```

The script uses pinned `nightly-2026-08-31`, locked offline resolution and retained logs. It executes
direct core tests, graph traversal contracts, and object-store direct/graph intake contracts.
Commit `b188e37f7def871c8d38d9d95d0d7621eedf9eca` passed the initial 29 tests (9 direct core,
10 graph, 10 direct object) in supplementary native run `38444948879`. Commit
`dc0695655f1ea7276b7fa21bf2b7c28fbd4fe13a` passed all 41 cases, including the 12 published-manifest
contracts, in native run `38446306780`. The scope-isolation follow-up adds three independent cases
for shared-digest metadata disclosure, scope-bound admission and exact selected alias preservation;
its execution result must be checked separately. The focused
workflow does not replace `scripts/qualify.sh`, the full target matrix or local DSR release authority.
