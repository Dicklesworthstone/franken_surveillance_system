# Source custody survives durable disclosure restart

A source binding already distinguishes a deployment reader from a standalone byte reader and
pins the original authority journal, committed head and selected publication record. That live
check is insufficient if a cold-open caller can reconstruct a weaker catalog after a disclosure.
The existing joint disclosure checkpoint now retains monotone source-custody commitments as well
as issued and consumed continuations. It introduces no second journal and stores no source bytes.

## Existing owner, stronger checkpoint

`ReferenceHydrationCatalog::checkpoint_cursors` emits `fss.hydration_cursor_checkpoint.v2` when
source bindings or previously restored requirements exist. Each source entry pairs an exact
descriptor digest with `SourceObjectBinding::custody_binding_digest()`. The latter commits the
manifest, subject, standalone/deployment distinction and, for a deployment, its original native
journal identity, canonical journal head and publication-record digest. These hashes remain
private recovery metadata, not transferable read grants or current custody proofs.

`DurableDisclosureStore` already synchronizes this checkpoint in the same record as session
charges and cursor issuance/consumption before releasing a response. Thus a successful preview
that offers source continuation also pins the source binding; a successful direct source
disclosure pins it even when no continuation exists. Recovery, pending-append reconciliation and
later disclosures reuse the same checkpoint decoder and monotone-history checks.

The compatibility `bind_source_object` API and initial catalog construction remain in-memory
operations until an enclosing checkpoint commits. `bind_source_object_durable` now provides an
explicit earlier acknowledgement boundary: it commits the selected custody requirement in the
same journal before returning, without a session charge or disclosure. See
[durable source registration](durable_source_registration.md) for replay, capacity and append-fault
semantics. A failed append remains fenced; no operation may invent durability.

## Missing is not permission to replace

Recovery validates all present reconstructed source bindings against the saved requirements. A
weaker reader profile, different selected publication, copied authority journal or separately
cached H3 substitute refuses without changing cursor or source-requirement state. Actual read
admission continues to check the descriptor, principal/session grants, privacy, budget, retention,
current durable authority, committed deletion state and native custody.

A deleted, expired or otherwise unavailable source need not be reconstructed to reopen the session.
Its descriptor and binding may remain absent. The saved requirement survives absence and rejects
later mismatched registration before source I/O. Cached H3 registration for that descriptor also
refuses. The correct owner can reconstruct the binding later only after a fresh successful custody
check. Independently authorized sources remain usable; missing history does not globally disable
the catalog. `source_binding_requirement(descriptor_digest)` exposes the required comparison hash,
not an artifact, descriptor, grant or assertion that original bytes still exist.

Requirements do not expire with cursor leases. Successors may add new requirements but cannot
remove or change existing ones. Admission uses the catalog descriptor ceiling and a 65,536-entry
hard limit; encoded checkpoints remain capped at 8 MiB. Decoder counts and exact encoded sizes
are checked before map/body allocation. Capacity exhaustion refuses rather than dropping history.
The existing bounded cursor, artifact and disclosure-journal limits still apply independently.

## Compatibility and trust

A source-free checkpoint preserves exact v1 bytes. V1 decoding remains supported but makes no
claim about historical source bindings. A v1 checkpoint cannot erase requirements once v2 source
history is present. Older builds reject v2 rather than interpreting it as weaker cursor metadata.
No existing artifact, receipt or source encoding is rewritten.

The complete journal root must still be pinned independently and its namespace protected by its
owner. A checksum supplied with untrusted bytes is not authentication. Reader implementations
and descriptor publication remain trusted application code. This does not retroactively prove
old v1 source history, migrate all CLI readers, apply privacy masks, repair deleted custody,
recall already disclosed bytes, or authorize effects.

## Regression entry points

Eight unit contracts exercise v1 byte compatibility, v2 roundtrip, every truncated prefix and
single-byte corruption, trailing input, strict ordering, count and exact-byte bounds, missing
metadata, no source/grant restoration, monotone pins and replay transition validation.
Five integration contracts use actual synthetic deployment files and the joint disclosure journal.
They cover prebuilt weaker bindings, cached-byte substitution, deferred legitimate reconstruction,
independent surviving sources, and cold session reopen with preserved charges and consumed cursors.

```sh
bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance
```

The runner includes the checkpoint library tests and `source_binding_recovery_contract` alongside
the prior source/deletion/provenance checks. Repository qualification is unchanged. Native Rust
execution was not available in the editing container; written tests and uploaded source hashes
are not passing-test or release-qualification evidence.
