# Canonical object-provider roots and deletion pins

The `fss_object::provider::ObjectStoreProvider` reference protocol binds an active
root to retained canonical `ObjectManifest` bytes. An arbitrary digest or a caller's
child list cannot establish root publication. This strengthens the FSS-061 provider
contract and its FSS-062 conformance oracle; it does not qualify a remote archive or
change the filesystem publication format.

## Activation

The caller constructs an `ObjectManifest`, stages its exact canonical bytes, and
advances both the body and every declared object to `Durable` or later. Activation
then validates, without changing the lattice:

1. The root exists in the provider's object inventory and its body is durable.
2. Its retained bytes rehash to the root and decode as one exact canonical manifest.
3. The supplied child list is nonempty, unique, within `MAX_MANIFEST_CHILDREN`, and
   exactly equals the manifest's direct children. Ordering is immaterial. A typed
   metadata digest is a required child, not an optional annotation.
4. Every object in the declared, registered closure is durable and re-verifies
   against its content identity.
5. Existing immutable manifest bindings agree, with no self-reference or cycle.

Only after all checks succeed does the provider register the immutable binding and
activate the root's pin. Exact retries succeed. A truncated, expanded, duplicated,
or substituted child list refuses, including after the root was deactivated.
Failed activation creates no partial binding or new pin and does not promote
staged bytes to visible or durable custody.

Closure follows the existing object-custody doctrine: explicitly registered
sub-manifests retain their typed edges. A never-activated payload stays opaque,
even when its bytes happen to parse as another manifest. No signature sniffing or
automatic promotion grants graph semantics. An owner that intends a nested graph
activates its manifests from children toward parents. If a previously opaque child
is explicitly activated later, its entire new declared closure must verify before
registration, and active ancestors subsequently preserve those registered edges.

## Deactivation and retirement

Deactivation removes only the selected root's independent pin. It preserves the
manifest binding. An active ancestor still pins that root body and all of its
registered descendants, including when the intermediate root is inactive. Shared
descendants remain protected until every containing active root is deactivated.

Retirement checks provider membership and the union of active closures before
touching custody. The active root body itself is protected as well as its children.
A separate retained, verified deletion witness is required. That witness is audit
evidence supplied by a trusted owner; its digest does not authenticate an agent or
grant external deletion authority.

All independent failure checks precede target verification and deletion. An unknown
provider object cannot be deleted merely because its bytes happen to exist in the
underlying custody store, and a refused deletion cannot make a staged target readable.
Retiring an unpinned descendant leaves its permanent tombstone. A formerly active
ancestor cannot reactivate over it, nor can a new wrapper turn the known invalid
sub-manifest into an opaque leaf. The reference contract covers only this provider's
registered local graph, not other copies, undeclared dependencies, or physical erasure.

Retrievability checks the provider's visibility state before reading custody. This
matters when the provider receives a pre-populated custody store: previously verified
bytes still begin at the provider's `Staged` state and cannot bypass that boundary.
A successful probe remains a point-in-time payload observation. It is not a durable
retrievability history or independent replication proof.

## Bounds and diagnostic behavior

Live root bindings are bounded by the configured object count and retained manifest
payload budget; each binding has at most `MAX_MANIFEST_CHILDREN` edges. Deactivation
preserves these edges. Successful retirement of a manifest body releases its graph
metadata together with payload quota, preventing retired manifests from accumulating
large child vectors outside that quota. The terminal provider record and custody
tombstone remain: direct and nested activation reject a retired identity before any
optional graph lookup, and its bytes cannot be restaged.

Closure and pin checks are iterative. Every reached identity is enqueued once, including
shared subgraphs, so traversal scratch is bounded by object count rather than path count.
Ordered sets add logarithmic lookup cost; byte verification hashes each unique visited
payload once per activation, with additional bounded canonical-manifest verification.

| Refusal | Meaning and next action |
|---|---|
| `UnknownObject` | Stage the exact missing object through this provider before retrying. |
| `RootNotDurable` | The root body is staged, visible, or retired. Finish ordinary publication for a live body; a retired identity cannot be restored. |
| `InvalidRootManifest` | The retained body is not the canonical manifest identified by this root. Inspect the source bytes and construct the intended manifest. |
| `RootChildrenMismatch` | Use the exact manifest children, including metadata, without duplicates or additions. |
| `RootBeforeDurableChildren` | A direct or registered transitive dependency is not durable. Finish its publication or preserve the explicit deletion blocker. |
| `RootCycle` | The prospective registered graph is cyclic. Refuse publication and inspect its construction. |
| `ActiveRootReference` | An active root still contains the selected object. Do not erase it; explicitly deactivate every retaining root through its owner first. |
| `NotRetrievable` | The provider has no visible, verified payload under the requested identity. A lattice label alone is insufficient. |

## Regression and conformance evidence

`provider_root_integrity` covers phantom roots, opaque bodies, root and child
durability, immutable bindings, metadata and duplicate checks, deactivation/retry,
active root bodies, shared and inactive nested roots, deletion invalidation, late
explicit registration, and pre-populated/staged custody failure atomicity. Provider
unit tests additionally corrupt already-durable root and child bytes before activation,
check that invalid witnesses do not verify staged custody, and verify graph metadata
reclamation without erasing terminal retirement evidence.

The conformance oracle now stages a real manifest and checks identity-bound activation,
exact retry, immutable child sets, active-root retirement denial, and reactivation after
child deletion. Its decision digest uses `fss.object_provider_oracle.v2` and binds both
the ordered check verdicts and final object states. Earlier opaque-root scenario digests
are not interchangeable with this strengthened contract.

```sh
cargo test -p fss-object --test provider_root_integrity --test provider_property_family --test oracle_family
cargo test -p fss-object --lib provider::memory::tests
```

These deterministic reference tests do not establish physical fsync guarantees,
remote provider durability, replica independence, archive freshness, or release readiness.
