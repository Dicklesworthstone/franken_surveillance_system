# Cold recovery of one HTTP original-read publication

Status: implemented in this change set; native compilation and tests were **not run** in the
implementation environment. This is not a qualification or real-camera claim.

## The missing lifecycle

An in-process recording owner can retry an exact borrowed `PreparedHttpWire` after reopening its
publisher. That is not cold recovery: after process exit the prepared object and original socket
buffer are gone. A prefix pin alone does not expose the full read metadata needed to reconstruct a
manifest that was never staged.

`ingest::http_archive::recovery::HttpWireRecoveryKey` preserves the exact source scope, predecessor
pin, original read receipt and expected next root. It is small, immutable, bounded to 1,024
canonical bytes, and contains no original HTTP headers or JPEG bytes. It is neither authorization
nor proof that a described read happened.

A caller constructs the key from an actual prepared read **before** publication, then preserves it
independently. `to_text` uses strict lowercase `hex:` encoding; decoding rejects unknown versions,
trailing bytes, oversized input, inconsistent scope/ranges/roots and overflowing ordinals.

## Recovery contract

`inspect` and `recover` read the existing archive. Both verify every predecessor root, exact
metadata and original payload. They reject missing or changed ancestors, extra/later source roots,
conflicting roots, broken slots, tombstones, and foreign temporary records. Recovery checks the
saved receive-admission time against the verified predecessor; it is never camera capture time.

The **original read bytes and canonical read metadata must already be staged**. Recovery does not
manufacture either from a key, acquire a replacement response, scan for a plausible head, or skip a
missing predecessor. The original-read archive stages both objects before all four native
publisher crash cuts, including `AfterChildrenVerified`, when its manifest may not yet exist.
A failure earlier in source staging can therefore remain unrecoverable; that is reported, not
silently repaired.

For the exact pending ordinal only, an orphan root temporary file may be present. Inspection does
not discard it. The existing publisher validates its complete bytes against the exact intended
root before reconciling that temporary file and republishing root-last. A mismatching file is
preserved and refused. No general repair or broken-slot override is added.

`inspect` distinguishes `staged` from `durable`. `recover` always re-verifies rather than treating
inspection as a lease. An already-durable exact retry returns the same prefix and does not add a
read. A later root in the same source namespace refuses the old key instead of following history.
The publisher's exclusive lock and existing filesystem threat model remain unchanged.

## Authority, limits and outcome

The API accepts a live `PublishCancellation` storage-authority probe and caller-owned `WorkBudget`.
Every source verification and publication consumes that budget; limits cannot be widened by saved
metadata. Native root publication remains the existing owner. No new ledger, journal, source
namespace, immutable wire format or effect protocol is introduced.

A successful result proves **one exact original read is locally durable**. It does not acknowledge
that read to a parser, reopen a socket, resume capture, declare HTTP/MIME completion, decode pixels,
publish a canonical event, or certify coverage. Original headers/media remain unencrypted custody.
A lost final result may follow successful publication; the same key can reconcile that ambiguity.

Opening `LocalRootPublisher` still performs its documented locking, recovery verification and
directory synchronization. Inspection through an already-open publisher does not itself stage,
unlink or publish anything; this is not a new forensic read-only filesystem API.

## Native regression command

```sh
cargo test -p fss-reference --lib ingest::http_archive:: --locked --offline
cargo test -p fss-reference --test http_rgb_recording --locked --offline
```

The new tests cover all four publication crash cuts with no surviving live owner, exact repeated
cold recovery, genesis, missing bytes/metadata/ancestors, corrupt source, conflicting/later/broken
roots, own and foreign temporary files, cancellation, budget boundaries, strict key decoding and
receive-clock regression. They were added, not executed, in the implementation environment.
