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

## Independent consumer verification

A generic `HydrationResponse::validate_for` checks request/receipt admission and internal hashes;
copying a genuine subject digest into an artifact's proof-root set does not prove that its payload
is the original source. Consumers of this path additionally call
`SourceObjectBinding::validate_response(request, descriptor, response)` with the binding and exact
descriptor obtained from their trusted publication/situation. The method verifies actual source
payload identity and length, the exact bound artifact identity, descriptor and publication roots,
H3 level, complete source content, and absence of an applied privacy transform. A preview or an
unavailability receipt cannot pass as disclosed source evidence.

This is independent consistency verification, not authentication of a binding supplied by an
attacker or proof of current remote custody. Old receipts do not establish present availability.
The ordinary receipt protocol and legacy opaque artifact contracts remain unchanged.

## On-disk source publications

`bind_local_source_object` and `hydrate_from_local_source` connect the same contracts to an
existing `LocalRootPublisher`. The caller passes the live lock-owning publisher and its explicit
`SpoolIo` capability; no store is opened, repaired, or mutated by hydration. Reopening the publisher
is a separate recovery operation. Existing binding metadata can then resolve the same on-disk
source without reimporting or duplicating its payload.

The reader compares fresh disk inspection with the live owner's publication identities and
root-record digests, verifies the selected root's complete reachable closure, and compares the
tombstone set. It performs those checks both before and after a bounded, digest-verified source
read. Removing a nested root record cannot quietly turn that manifest into an opaque leaf.
Poisoned owners, staged roots, out-of-scope objects, newly broken roots, indeterminate markers,
and observed deletion-state drift block delivery. Input continuations are not consumed on failure.

Inspection does not establish durability by itself. The selected root must already be `Durable`
in the live owner, which holds its exclusive publication lock for the entire borrow. This is a
conservative whole-store reference reader: drift in other owned publication roots can also block
reads. Its scan/object bounds come from the publisher's limits, separately from the H3 output
byte quote. Actual aggregate I/O/CPU pricing, streaming, canonical-ledger reachability proofs,
cryptographic storage isolation, and persistent catalog/cursor recovery remain unimplemented.
Pre/post inspection detects observed drift; it cannot stop malicious out-of-contract filesystem
writers or revoke bytes already returned to callers. Production qualification remains open.

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
privacy-transform refusal, exact continuation, retry after failure, and non-caching. Six additional
consumer tests exercise genuine responses and self-consistent forged receipts containing copied
source roots, substituted bytes, retargeted custody, descriptor rebinding, and transform claims.

`cargo test -p fss-reference --test local_source_hydration_contract` adds native disk/memory
differential receipts, reopen, no-write disclosure, zero-I/O admission denials, corrupt source
and metadata, lost nested roots, indeterminate publication, poisoned ownership, and pre/post
read fault schedules preserving single-use continuations.

The implementation was reviewed and source hashes checked in an environment without Rust/Cargo;
these Rust tests were added but not executed there. Full local DSR qualification and FSS-210
completion remain open.
