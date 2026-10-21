# Preserve deployment authority through source-reader substitution

A source content digest does not identify its current authority owner. Two readers can
return identical bytes while checking different deployment histories, publication slots
or deletion state. A deployment-backed H3 binding must therefore retain more than the
source and manifest digests, even when disclosure uses a generic source-reader trait.

## Immutable binding, shared enforcement

`SourceObjectBinding::deployment_authority()` exposes optional comparison metadata:

- The opened authority journal's native store pin, which distinguishes a byte copy from
  the original journal file.
- The exact canonical authority journal root.
- The canonical publication-record digest, which includes the selected slot name,
  manifest root and child count.

The fields of `DeploymentSourceAuthority` are private. The deployment reader supplies
this metadata from its independently selected, opened owners. It is not an authenticated
wire token, a permission grant, proof of current deletion state or a retention lease.
The actual read still verifies the live journal identity and head, committed deletion
history, selected slot authority and complete native object closure.

The ordinary `PublishedSourceReader::validate_source_descriptor` hook remains in place.
The additional `deployment_authority_for` hook is a pure metadata observation. Wrappers
must forward both hooks as well as `read_published_source`. Standalone readers default to
no deployment identity; they cannot serve a binding that already requires one.

Registration refuses a different identity before source I/O. Exact binding retries still
read and revalidate custody. Disclosure compares the selected reader with the retained
binding after ordinary grants, privacy, retention, quote and continuation admission,
before reading source. It compares the metadata again after the read, before installing
an artifact or changing cursor state. Authority failure is not silently downgraded to a
preview. A failed registration leaves no binding; a failed disclosure preserves its
continuation and does not add cached source bytes.

These checks live in the shared catalog path, so generic session, context and durable
session consumers do not need a second implementation. The durable disclosure owner
continues to journal charges and single-use cursor state before releasing a response.
This change does not create a second session journal or persist original source payloads.

## Existing artifact and receipt format

Deployment-bound H3 artifacts include the existing canonical journal root and selected
publication-record digest in their ordinary proof-root set. The artifact digest therefore
commits to the selected history and slot. `SourceObjectBinding::validate_response` checks
those commitments along with the exact source bytes and ordinary receipt validation.
Equal source bytes under another independently authorized slot yield a different artifact
identity and cannot satisfy the original trusted binding.

The filesystem store pin remains local binding metadata and is not added to the artifact.
Neither the proof-root set nor a self-consistent receipt authenticates a remote publisher.
Consumers still need an independently trusted descriptor and binding. Source already
returned to a caller cannot be recalled.

## Compatibility and recovery boundaries

An existing standalone binding has no deployment identity. It can use a stronger reader
for one live read without silently acquiring new proof claims or changing its artifact
identity. Rebinding a retained revision from standalone to deployment authority, or in the
opposite direction, refuses. Reconstruct authority explicitly instead of retargeting an
immutable binding. Cached non-source artifacts keep their existing semantics; this change
does not certify them against committed deletion history.

Reopening the original journal file preserves its native identity on supported platforms.
Copying or restoring it to a different file does not. Another authorized slot can establish
its own binding in an independently reconstructed catalog; it does not replace the binding
in an existing catalog. This is not global denial of every alias of shared content.

Actual catalog bindings remain authority-owned reconstruction inputs, not source objects
restored from the session journal. Once a v2 disclosure checkpoint commits, recovery also
compares rebuilt bindings with the saved monotone custody commitments. Missing sources may
remain unavailable, but later binding or cached-H3 substitution cannot erase that history.
See [source binding recovery](source_binding_recovery.md) for the exact bounds and restart
contract. Initial registration alone remains in memory, and legacy v1 history does not
retroactively prove its former source bindings. Independently trusted journal roots and
fresh native custody checks remain necessary; saved comparison hashes are not read grants.
Existing receipts or continuations are never rewritten to new artifact identities. Adding
authority roots changes newly established deployment artifact identities; incompatible old
continuation state requires the existing explicit recovery/session lifecycle, not an
implicit upgrade or replay-history reset.

This boundary prevents accidental weakening by the application's reader selection. The
trait implementation itself remains trusted application code: a malicious implementation
can lie or copy previously observed metadata. No Rust sandbox or remote attestation is
claimed. Native filesystem observations are not atomic snapshots or full historical scrubs.

## Native regression coverage

`tests/deployment_source_hydration/authority.rs` is included by the existing deployment
source test target. Eleven new tests cover standalone and local-reader substitution,
exact binding retries, equal-root slot aliases, receipt commitments, a copied journal,
pre-I/O admission, metadata drift after a read, continuation preservation, explicit legacy
behavior, and durable session charge/replay protection across cold reopen. The existing
alias regression now requires explicit independent binding instead of silent retargeting.

The existing runner already includes this target; no workflow gates are weakened:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --test deployment_source_hydration_contract \
  --test deployment_disclosure_contract \
  --test local_source_hydration_contract
```

These new tests were written but not compiled or executed in the patch-preparation
environment, which had no Rust compiler or Cargo. Exact base-file hashes and patch
application were checked separately; neither is a native test or release qualification.
