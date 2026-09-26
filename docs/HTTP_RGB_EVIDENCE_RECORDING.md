# Ledgered evidence for live HTTP RGB results

`fss_reference::ingest::http_rgb_evidence::HttpRgbEvidenceRecording` requires
source-closed detector evidence to be durably published **and** canonically ledgered
before a live result and its original JPEG can leave the recording owner. The
existing `HttpRgbRecording` continues to enforce original HTTP durability before
parsing. The two barriers have separate storage owners and authority adapters.

This is an opt-in library owner, not a camera daemon or a new archive format. It
uses `RgbEvidence`, `PreparedRgbArchive`, and `restore_rgb_evidence`; model graph
and weight files remain deduplicated content-addressed objects. No authoritative
incident or alert is automatically published.

## Drive and retain

Attach before any analysis or output transfer. The original recording is then
available only through `recording()` by immutable reference. `poll`, `commit_wire`,
`analyze`, and `resume` retain their existing bounded native behavior. In particular,
`ResultReady` alone does not permit transfer or imply evidence durability.

The owner remembers the exact `RgbFrameAdmission` that reached an accepted stage,
including when analysis returned an error after acceptance. Use
`accepted_admission()` and the held result's `detection_run()` with
`RgbEvidence::capture`, supplying the actual `ImportedRgbModel`, head contract,
and held original JPEG. Then call `RgbEvidence::replay` under the named sensor's
current retained privacy policy. This executes native import/decode/inference/head
projection; a deserialized fingerprint or caller-authored tensor cannot substitute.

`prepare_evidence` checks the actual replay against the live source, capture,
availability, admission evidence, inference, detection and privacy bindings. It
prepares the existing archive without disk mutation and returns an
`HttpRgbEvidencePin`. Save that pin independently before publication. A retry
cannot change its retention decision or result and does not re-encode the envelope.

`commit_evidence` revalidates the live camera and original HTTP custody, then calls
the existing root-last/ledger publisher. A durable root without a canonical ledger
entry is an error. Successful publication is recorded before returning, with no
optional late check that could hide the successful write.

`take_result` requires that exact published pin. It reopens and rehashes the current
source-closed graph through `restore_rgb_evidence`, checking live original-disclosure
authority, deletion state, durable root and ledger linkage. Only then does it transfer
the held live result and original frame. Missing ledger, changed originals, revoked
read permission or denied camera release leave the prepared plan and native results
held. There is no fallible operation after successful ownership transfer.

## Recovery and scope

After a publication failure, retain the exact plan, reopen the existing deployment
through its normal recovery contract, and retry `commit_evidence` with the same pin.
No reconnect, new observation identity or second live inference is required.
`retire()` returns the original recording's full source/processor recovery state,
accepted admission, existing archive plan, its historical publication outcome, and
last delivered pin. Retirement never claims a clean stream end.

The independently supplied work budgets accumulate across prepare/publish/read
operations. Fresh original-prefix verification is charged explicitly; it may scan
all earlier reads, so this path has no throughput or hard-real-time qualification.
The wrapper also uses the recording's bounded poll allowance to check live camera
authority while a completed result backpressures acquisition.

**The RGB archive stores detector replay ingredients, not temporal checkpoints.**
The pin carries the observed tracking and zone fingerprints as replay expectations,
but it does not serialize a tracker episode, authenticate capture time, prove scene
coverage, or qualify model accuracy. Retain every per-result pin independently;
the existing HTTP terminal root continues to describe original-source completion,
not an aggregate perception-history manifest. Original JPEG/model custody remains
unmasked; native derivations continue to use the existing privacy-mask machinery.

## Source-bound cold replay and temporal reconstruction

`http_rgb_evidence_replay::restore_http_rgb_evidence` ties a saved per-result pin
back to an actual frame emitted by the native `HttpWireReplay` parser. Supply the
independently selected final source tip and scope, the native mapped frame, live
original disclosure authority, and the existing derived evidence deployment.
The per-result prefix may precede the final tip, but it must be an exact member of
that verified original-read chain. The original HTTP/MIME ordinal, complete JPEG,
source-span mapping and mapped exposure must match; identical JPEG bytes in a
different part do not substitute for the selected exposure.

Restoration rechecks both original and derived storage and returns
`RestoredHttpRgbEvidence`: owned, source-bound bytes, **not executed inference**.
Its `replay` method revalidates original/model disclosure, checks the named sensor's
current mask policy and generation, and invokes the existing native model importer,
JPEG decoder, preprocessing, scalar inference and complete detector head. Only a
successful match of the actual inference and detector fingerprints returns
`ReplayedHttpRgbEvidence`. Changing an expected fingerprint does not change the
original graph, model output or detection result.

For full temporal reconstruction, initialize the existing `RgbZoneTracker` with
the same independently retained episode/configuration, then feed each replayed
result's actual inference, detector report and preserved admission to `observe`
in original order. Resume unfinished zones through that owner's existing `resume`
contract. `verify_temporal` then checks the reconstructed tracking and zone digests
against the saved pin. It refuses pending stages, stale history and mismatches;
verification never re-assimilates an exposure, resets the episode, alters a pin,
or publishes an event. All four native stage fingerprints must match before a
`VerifiedHttpRgbTemporalReplay` is returned.

Restore and numerical execution are deliberately separate so the same deployment
may first be mutably opened for custody verification and then immutably supply a
`SensorMask`. Restored originals are an authorized point-in-time snapshot, not a
claim that storage and permission can never change. Both operations recheck their
current disclosure adapters. Reconstructing history is read-only and produces no
new ledger entry. The existing native HTTP completion contract still applies:
ending a selected prefix does not fabricate socket EOF.

## Validation

`cargo test -p fss-reference --test http_rgb_evidence_recording`

The integration tests use real loopback HTTP, native source-weight import,
JPEG/model/head execution and durable storage. They cover multi-frame capture,
mandatory ledger-before-transfer, exact-key retries, wrong fingerprints, cold
replay after live owners close, write/read revocation, final camera-release denial,
and root-durable/ledger-missing recovery without rerunning accepted live inference.
The cold test closes the live source/model/output owners, reopens both archives,
re-parses the original HTTP in different-sized read chunks, restores detector
evidence, and reconstructs the original tracking and zones. It checks two identical
JPEGs with distinct source identities, rejects cross-part/rival-prefix substitution,
rechecks read revocation before restore and decode, rejects a changed numerical
fingerprint, and refuses stale/pending temporal history. Repeated verification must
not re-assimilate an exposure or append to the canonical ledger.

Rust compilation, native tests, rustfmt and Clippy were not run in the implementation
environment: no Rust toolchain is installed and network toolchain retrieval is
unavailable. Local structural checks are not a replacement for these native tests.
