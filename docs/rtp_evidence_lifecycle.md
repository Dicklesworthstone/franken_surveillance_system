# Retained RTP evidence lifecycle

Completed recorded-RTP imports participate in the existing FSS-037 / CAP-DELETE-PREPARE-001 /
CAP-DELETE-COMMIT-001 deletion owner. The lifecycle identity is the exact `rtp-...` published
root, as returned by the RTP importer. It is not the raw recording's content digest. Existing
file-import identities and canonical deletion plan, approval and completion formats are unchanged.

## Admission and closure

`plan_deletion(deployment, rtp_root, cx)` verifies the original recording graph, canonical
recipe, capsule batches and terminal import batch through the existing recovery implementation.
A batch name is only a discovery hint. A root-only pending publication, a forged completion name,
or unreadable source cannot be promoted into a completed import. Malformed media remains
legitimate deletable custody when its exact source and completed import are verifiable.

The ordinary closure walker includes the exact RTP root, report, original chunks, reconstructed
NALs, source envelopes, capsules and any reachable derivatives. No separate unlink loop is added.
Shared objects remain while another retained unit needs them. An unrelated batch whose name
resembles a capsule partition is not automatically a seed. Authority history, privacy policies,
event revisions, blockers, holds and unknown operator copies keep their existing treatment.

Sensor scopes use the sensor in the fully verified original recipe, including recordings with
zero source capsules. They do not infer sensor identity from source addresses or filenames.
Mixed file/RTP sensor scopes use one union closure and one approval, never multiple stale plans.

## Denial before physical removal

A committed deletion record denies source inspection, receipt-based readback, resuming an old
recovery handle and re-publication immediately, even when interrupted before any byte is unlinked.
`RtpImportError::EvidenceDeleted` names the requested root and denying plan. Unreadable deletion
proofs fail closed. A new sensor label cannot resurrect objects that committed deletion forbids.
Previously returned in-memory bytes are not revoked; new decoder steps fence queued output on
changed authority. This is the existing local unlink model, not cryptographic erasure or removal
of original input files, backups or exported reports outside the deployment.

Root recovery charges deletion-proof reads against its existing `max_read_bytes` allowance.
Compatibility publication/readback/recovery-resume proof checks have a separate fixed 512 MiB
allowance per check, bounded by the existing 32 MiB deletion-record size ceiling. Source replay
for lifecycle admission accepts only the native v2 hard ceilings, with at most 256 MiB of source,
65,536 records and 2 GiB of verification reads per import. None of these bounds is reset by a
source decoder restart; source payloads are verified but not pixel-decoded during deletion.

This does not opt RTP recordings into age-based automatic cleanup: their capture-time class
remains unknown. Explicit import/sensor deletion and evidence-preservation decisions are distinct
from an age claim. No active retention, redaction or alert policy is changed.

## Operator API

The existing command accepts the exact RTP root with no new transport or destructive shortcut:

```sh
fss-event delete plan --root DEPLOYMENT --site SITE --import-id sha256:RTP_ROOT
fss-event delete commit --root DEPLOYMENT --site SITE --plan sha256:PLAN --approve sha256:APPROVAL
```

Use the plan and approval printed by the existing command; any intervening authority change
requires a fresh plan. Interrupted commits use the same idempotent recovery protocol. The
original recording, independently exported receipts and motion reports remain outside local
custody and are not removed by this command.

## Validation

`rtpdump_deletion_contract` exercises complete and interrupted deletion, cold denial, exact
retry, shared objects, capsuleless sensor membership, pending roots, malformed tails, source
corruption, fake completion names, unrelated prefixed batches, resurrection attempts and queued
pixel fencing. Source-generation, privacy and prediction-reference semantics are unchanged.
Native tests and their execution source are recorded with each implementation increment; these
contracts are not platform, power-loss or whole-repository release qualification.
