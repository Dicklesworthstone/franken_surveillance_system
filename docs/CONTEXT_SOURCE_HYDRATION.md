# Source-backed context expansion

The FSS-210 reference path now connects an exact published context slot to live
source custody without allocating a session alias or retaining a second H3 cache.
This is a Rust reference API, not a new network authentication service or a claim
that all FSS-210 surfaces and qualification gates are complete.

## Runtime-owned delivery

Register the exact descriptor with `ReferenceHydrationCatalog` and bind its
original source through `bind_source_object` (or the existing local-publisher
binding method). Binding verifies custody and retains only immutable metadata.
Supply a verified `BoundReferenceSituationPublication` that names this exact
revision. Its source descriptor anchor may precede the situation/session anchor;
source identity must not be rewritten to make the anchors equal.

Use `ReferenceSessionStore::hydrate_context_slot_from_source` with the authenticated
principal, publication, `ContextSlotRead`, catalog, authority-owned
`PublishedSourceReader`, and trusted service time. For disk-backed custody use
`hydrate_context_slot_from_local_source`, passing the existing lock-owning
`LocalRootPublisher` and its `SpoolIo` capability. These methods do not reopen or
repair storage. Do not let request-supplied paths or digests select custody owners.

The read supplies the expected publication digest, slot, session generation,
requested level, full budget, purpose, and optional continuation. It does not
supply capabilities, privacy grants, or a replacement source descriptor. These
are projected from live server-owned session state. A fresh read requests the
published slot level; a continuation requests its exact next level.

The lower-level `ReferenceHydrationCatalog::hydrate_context_slot_from_source`
accepts an already projected `HydrationRequest`. It checks the exact slot binding
but is not a substitute for principal authentication or session accounting.

## Admission, custody, and accounting

Session ownership, lease, generation, situation anchor, expected publication,
current exact descriptor, privacy projection, and cumulative token allowance are
checked before source I/O. The catalog then enforces selected-level capabilities,
retention, the full quoted resource vector, and single-use continuation rules.
A source read verifies current root closure, tombstones, exact payload bytes, and
its bound artifact identity.

Failed reads leave tokens unspent and continuations unconsumed. The trusted
session clock still advances on admission attempts. Successful deliveries charge
the receipt's quoted tokens, including repeated non-continuation reads. Quotes
are not measurements of actual runtime consumption. Retention unavailability is
an explicit zero-cost result, not evidence that an event did not occur.

Source corruption, missing custody, or a storage tombstone is a custody error
even when preview downgrade was allowed. These failures must not be concealed by returning a cached
preview. Display messages omit object identities and filesystem paths; underlying
causes belong in authorized diagnostics. H3 source bytes never enter the catalog
payload cache, so a prior disclosure cannot resurrect a tombstoned source.

## Verify the evidence actually delivered

`BoundContextHydration::verify_for` checks the ordinary delivery against the exact
context publication and admitted session snapshot. That protocol deliberately
also admits valid previews and unavailable results.

For a consumer that specifically requires original source evidence, retain the
trusted `SourceObjectBinding` separately and call:

```rust
// All three references come from retained trusted authority, not the response.
delivery.verify_source_for(&publication, &admitted_session, &source_binding)?;
```

This additionally requires complete, untransformed H3 bytes, exact source length
and digest, the bound artifact identity, and the exact source publication root.
A preview, an expired response, or another publication containing identical bytes
cannot be substituted. This is a historical consistency proof, not proof of
current availability or an independently signed authentication credential.

## Regression coverage and boundaries

`crates/fss-reference/tests/context_source_hydration.rs` exercises the public
compiled-publication path, including older source anchors, zero alias capacity,
source/cache preview equivalence, wrong principals, stale roots/generations,
capability and privacy denial, full-vector and cumulative budgets, cursor failure
and retry, source deletion, corrupt provenance, retention expiry, and independent
source-publication verification.

On the repository's accepted Rust toolchain, run:

```sh
cargo test -p fss-reference --test context_source_hydration
cargo test -p fss-reference --test context_slot_hydration
cargo test -p fss-reference --test session_source_hydration_contract
```

Run these tests on the exact committed tree before treating the slice as
validated. The existing local qualification process remains authoritative; hosted
workflow status alone does not qualify a release.

Session charges and catalog cursors remain in-memory reference state. This work
does not make disclosure accounting crash-durable, add a persistent retention
scheduler, authenticate a network transport, or establish CLI/MCP/TUI equivalence.
