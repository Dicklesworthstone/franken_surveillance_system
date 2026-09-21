# Durable native RGB evidence

`ingest::rgb_archive` takes a completed `RgbEvidence` and its actual native
`ReplayedRgbEvidence`, then publishes the ORIGINAL JPEG, permissions, graph,
Safetensors file and recipe through `ReferenceDeployment`. It extends the
portable RGB replay format; it does not add another inference engine or database.

## Owner workflow

1. Capture or restore the source-closed RGB envelope and run its existing native
   `replay`. Prepare `PreparedRgbArchive` with the exact replay and an explicit
   original-retention decision. Keep `pin()` before publication.
2. Implement `RgbArchiveAuthority` using current principal, privacy and retention
   policy. Retention requires original-byte retention approval plus the existing
   object-stage, object-publish and ledger-append capabilities. Reads require
   permission to disclose original images, masks and model assets. There is no
   permissive default. A policy digest alone is not a grant.
3. Call `publish` against the existing exclusive deployment owner. Retention is
   rechecked before source writes and at the publisher's pre-commit cut points.
   Retry the same prepared plan after a lost acknowledgement.
4. On restart, open the deployment and call `restore_rgb_evidence` with the
   independently retained pin. The exact root must be durable AND ledgered.
   Missing, replaced, tombstoned or corrupt source objects refuse recovery.
5. Run `RgbEvidence::replay` again before treating a restored result as inference.
   Archive reads do not deserialize trusted detections or substitute a latest model.

The original components are separate content-addressed objects. Multiple frames
using identical graph/weights/permissions reuse their byte identities. The root
records their exact roles, lengths, retention decision, source recipe and capture
interval. The ordinary object graph supplies deletion/retention closure. No new
ledger delta family is introduced; this uses `local_root_reachability`.

## Failure and cost contract

Preparation does no disk I/O. Bad bindings, finite input limits and insufficient
preparation work cannot publish partial evidence. Storage failure can leave
staged objects or a durable but unledgered root. These are not successful custody
receipts. Restoring such a root fails; an exact authorized publication retry uses
the existing root/ledger reconciliation contract. After the publisher's commit
point its real receipt is returned, rather than hiding committed custody under a
late cancellation error. No staging object is automatically deleted or source
silently resurrected.

Each original is bounded by the source-envelope limits, the complete envelope by
64 MiB, and reads by an independently accepted spool allocation ceiling (at most
32 MiB). Ledger resolution has an independent scan limit. `WorkBudget` reserves
conservative copy/hash/read and tombstone-scan work; `RgbEvidenceBudget` separately
accounts for portable encoding/decoding. Neither is replenished automatically.
Source capture intervals and availability declarations survive unchanged. The
archive does not certify the physical camera, clock, model accuracy or coverage.

## Verification boundary

`cargo test -p fss-reference --test rgb_archive_contract` contains eleven
behavioral regressions: cold native replay, lost ACK, policy denial and revocation,
root-before-ledger failure, pin rebinding, capacity/work refusal, unobservable
inputs, shared models and late original-byte corruption. The numerical fixture
uses real JPEG decoding and convolution but is NOT a trained person detector.
The shared fixture now passes a typed `ContentDigest` admission identity, retaining
its original 32 bytes instead of accidentally hashing them again.

Rust compilation and these tests were not executable in the editing environment;
only source/API and exact content checks were available. No local qualification
or production-readiness claim is made.
