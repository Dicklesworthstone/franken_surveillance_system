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

## Evidence holds and minimum retention

The existing `fss-hold` commands and capability-scoped hold APIs accept the exact completed
RTP root as `--import-id`. They authenticate the same original-source graph before placement
or release; root-looking names and pending publications are not evidence authority. Placement
and release use the same exact approval, current-head revalidation and idempotent retry as
file imports. No new hold format, implicit release, retention setting or clock source is added.

```sh
fss-hold place --root DEPLOYMENT --site SITE --hold-id incident \
  --import-id sha256:RTP_ROOT --reason "Owner incident review"
# Re-run that placement with --approve sha256:APPROVAL from its preview.
fss-hold release --root DEPLOYMENT --site SITE --hold-id incident \
  --import-id sha256:RTP_ROOT --reason "Owner incident review"
# Re-run that release with its own fresh --approve sha256:APPROVAL.
```

An active RTP hold blocks the existing union deletion when that import or its protected
closure would be removed, including a mixed file/RTP sensor scope. An approved release does
not delete anything; a new deletion plan and approval are still required. Deadline holds remain
active until the owner explicitly attests a qualifying time interval and approves expiry.
Hold and release audit records remain readable after the content is eventually deleted.
After a deletion record commits, a new hold cannot resurrect the recording, even before unlink.

## Validation

`rtpdump_deletion_contract` exercises complete and interrupted deletion, cold denial, exact
retry, shared objects, capsuleless sensor membership, pending roots, malformed tails, source
corruption, fake completion names, unrelated prefixed batches, resurrection attempts and queued
pixel fencing. Source-generation, privacy and prediction-reference semantics are unchanged.
Native tests and their execution source are recorded with each implementation increment; these
contracts are not platform, power-loss or whole-repository release qualification.

The implemented hold path adds six integration cases for cold preservation/release, mixed
file/RTP sensor scopes, stale approvals, denial-before-unlink, cancelled/corrupt admission and
explicit approved deadline expiry. Four real-process cases exercise `fss-file`, `fss-hold`,
`fss-event` and `fss-decode-rtp` together, including another camera's shared evidence and no
pixel output after deletion. The original file paths are removed before these lifecycle steps.

Initial execution used pinned nightly-2026-08-31 on the verified `ae78cbc` source archive plus
both lifecycle increments: 176 reference tests passed and one existing alert/deletion test
failed; 37 CLI tests passed. All 21 newly added tests passed. The single failure,
`an_unrelated_import_can_be_deleted_while_the_bound_alert_remains_observed`, reports
`event_authority_stale` and was independently reproduced on the untouched archive. No test
was disabled and no release gate was lowered. The initial targeted Clippy invocation stopped
on six existing `expect_used` errors in unchanged `ingest/tutk.rs`, `discovery/tuya_beacon.rs`
and `discovery/census.rs`; this increment does not suppress those lints.

Publication-time reruns used the SHA-256-verified complete `ac2f355` source archive, including
its motion and RTSP supervision code, plus these lifecycle increments and the same pinned
compiler. Thirty deletion/custody/recovery cases, sixty hold/deletion-proof/motion/receipt
reference cases, and twenty-three real-process lifecycle/motion/receipt CLI cases passed:
113 distinct focused tests, including all 21 new lifecycle cases. The five new Rust files
also pass pinned rustfmt checks. Later neural detector/tracker and RTSP changes were preserved
on main and their module/test declarations merged, but were not part of this native execution
snapshot. These results are not full-head, all-target, all-platform or release qualification.
