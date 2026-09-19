# Source-backed H3 hydration (FSS-210 reference slice)

`ReferenceHydrationCatalog::bind_source_object` binds a current, authority-projected descriptor
whose subject digest is the exact source object to a published custody root. Registration reads
and verifies real source bytes but retains only `SourceObjectBinding` metadata. A different root
or separately cached H3 artifact cannot replace that binding under the same descriptor revision.

`hydrate_from_source` checks the exact descriptor, anchor, contract basis, authenticated caller's
projected grants, privacy class, trusted service time, full quoted resource vector, and input
continuation before calling `PublishedSourceReader`. It returns the existing `HydrationResponse`
and independently verifiable ordinary receipt. The payload is the original object, not a wrapper,
with media type `application/vnd.fss.h3-source-object`; its SHA-256 equals the subject digest. Proof
roots also bind the descriptor and custody publication. Privacy-transformed descriptors cannot be
used to disclose untransformed originals.

The in-memory reader follows the object store's bottom-up publication rule. It rechecks every
reachable object, including metadata and registered nested manifests. Manifest-shaped opaque
leaves are not expanded. Unpublished, corrupt, missing, tombstoned, or unrelated objects are
refused. Authorization and budget denials do not probe the store. Custody failures remain typed
errors, not physical absence, and do not silently fall back to previews.

H2-to-H3 continuation uses the existing issuance ledger. A failed read leaves the predecessor
unconsumed; a successful read consumes it exactly once. H3-to-H4 selection witnesses use retained
artifact digests rather than retained source payloads. H4 still requires its existing laboratory
purpose and grants. Ordinary `hydrate` cannot serve a source binding without a reader. Explicit
policy/budget downgrade may return an existing lower level with partial completeness.

## Bounds and authority

Bindings are bounded by the retained descriptor count. Each returned source is at most 64 MiB,
the descriptor's byte quote, and the remaining catalog payload allowance after cached artifacts.
The reference reader verifies the root closure on every read; this is deliberately a conservative
oracle, not an optimized storage query. Quotes are not measurements of actual CPU, I/O, allocator,
or envelope overhead. Returned bytes belong to the caller and are not stored in the catalog.

The caller owns authentication, publication-root selection, current policy projection, and a
trusted nondecreasing clock. The reader is an explicit custody capability, not an authentication
mechanism. This slice does not implement streaming/ranged source hydration, encrypted remote
custody, graph-complete deletion, persistent cursor recovery, or production qualification.
Existing opaque hydration artifacts remain supported by the ordinary catalog API; this new path
requires an explicit source binding rather than treating an arbitrary H3 payload as custody proof.

## Verification

`cargo test -p fss-reference --test source_hydration_contract` exercises source identity, root
closure, metadata corruption, deletion after disclosure, zero-I/O denial, immutable bindings,
privacy-transform refusal, exact continuation, retry after failure, and non-caching.

The implementation was reviewed and source hashes checked in an environment without Rust/Cargo;
these Rust tests were added but not executed there. Full local DSR qualification and FSS-210
completion remain open.
