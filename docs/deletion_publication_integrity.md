# Deletion-invalidated graphs cannot be republished as opaque leaves

The in-memory custody owner distinguishes verified payload bytes from currently valid graph
publication. Deleting a required descendant leaves its ancestors' own bytes available for explicit
historical inspection, but records those ancestors as invalidated and removes their publication.
Previously a new wrapper could name one of those retained ancestors as an opaque child; the closure
walk considered only the current visible-manifest map and could accept the shortened graph.

`InMemoryObjectStore::verify_closure` now refuses every known deletion-invalidated member, including
an invalidated root temporarily reinserted during republication. It also checks that each cached
manifest's root and computed identity match the key before following that manifest's edges. A stale
cache or substituted typed manifest cannot supply a different closure over intact retained bytes.
`published_manifest` applies the same invalidation check to visible entries.

The existing root-last publication rollback remains the sole mutation path. Refusal restores the
candidate's prior absent, staged or verified state and preserves object counts, byte accounting,
visible publications and invalidation history. No repair or deletion-history reset is performed.
The existing `NotVerified` refusal identifies a retained but unusable graph member; it does not
falsely claim that the ancestor payload itself is corrupt or tombstoned.

Never-published bytes that happen to encode a manifest remain opaque. There is no signature
sniffing, implicit publication or invented child reachability. Likewise, a surviving payload can
participate in a genuinely independent valid publication without bringing its invalidated ancestor
back into the graph. `read_verified` and direct byte-custody checks retain their existing scope.

The in-memory `PublishedSourceReader` now invokes the owner's complete closure check before its
source-membership walk. This gives ordinary H3 disclosure the same deletion and cached-edge checks
without treating source presence as graph authority. Deployment-backed disk readers retain their
separate durable journal, slot, deletion-history and native-custody checks.

## Regressions and validation

Seven object-owner tests cover new wrappers in all staging states, repeated ancestor republication,
independent surviving publications, never-published opaque leaves, stale visible entries, invalidated
children in stale cache and substituted descendant edges. Two public reference tests exercise source
disclosure after deletion and the unchanged opaque-leaf contract.

The focused provenance runner now executes the complete object library suite plus the new source
consumer target. The repository qualification command and failure behavior are unchanged:

```sh
bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance
```

Native execution of these new tests has not been observed in the editing environment, which has no
Rust toolchain. Test source and a queued hosted run are not passing-test or release-qualification
evidence. This correction concerns the deterministic in-memory owner and its source reader, not a
claim that all persistent or distributed deletion adapters are complete.
